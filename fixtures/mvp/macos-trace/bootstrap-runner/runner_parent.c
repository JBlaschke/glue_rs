#define _POSIX_C_SOURCE 200809L
#define _DARWIN_C_SOURCE 1
#include "bootstrap_runner.h"
#include "runner_internal.h"
#include <errno.h>
#include <limits.h>
#include <signal.h>
#include <string.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>
static int child_ends(struct nr_attempt *a) {
 int rc=0;
 for(unsigned i=0;i<3;i++)if(nr_close_owned(a,&a->sources[i],NR_ENDPOINTS))rc=-1;
 a->sources[3]=a->sources[4]=-1;
 for(size_t i=0;i<a->endpoints.owned_count;i++)if(nr_close_owned(a,&a->endpoints.copies[i],NR_ENDPOINTS))rc=-1;
 if(nr_close_owned(a,&a->gate[0],NR_ENDPOINTS))rc=-1;
 if(nr_close_owned(a,&a->status[1],NR_ENDPOINTS))rc=-1;
 return rc;
}
/* Own only the actual child returned by this attempt's fork. A successful wait
 * consumes ownership; never signal it again. ECHILD also forbids later signals. */
static int wait_once(struct nr_attempt *a) {
 int status=0;pid_t n=waitpid(a->child,&status,WNOHANG);int saved=errno;
 if(n==a->child){a->reaped=1;a->wait_status=status;
#ifdef GLUE_OWNED_TRACING
  nr_trace_child_result(a,0,status);
#endif
  return 1;}
 if(n==0)return 0;
 if(n==-1 && saved==EINTR)return 0;
 if(n==-1 && saved==ECHILD){a->lost_child=1;
#ifdef GLUE_OWNED_TRACING
  nr_trace_child_result(a,1,0);
#endif
  return nr_fail(a,NR_WAIT,NR_LOST_CHILD,saved,-1);}
 return nr_fail(a,NR_WAIT,NR_SYSCALL,n==-1?saved:EIO,-1);
}
static int wait_until(struct nr_attempt *a,struct bio_time deadline) {
 for(unsigned step=0;step<20000;step++) {
  /* Check time even for EINTR. Check again after a completed wait before using
   * it as an on-time observation; reaped state still permanently ends ownership. */
  if(nr_before(a,deadline,NR_WAIT))return -1;
  int rc=wait_once(a);
  if(nr_before(a,deadline,NR_WAIT))return -1;
#ifdef GLUE_OWNED_TRACING
  int pumped=nr_trace_pump(a,a->trace.cleanup_attempted?TS_CLEANUP:TS_WAITING);
  if(pumped && !a->trace.cleanup_attempted)return -1;
#endif
  if(rc)return rc>0?0:-1;
  struct timespec nap={0,1000000};
  if(nanosleep(&nap,NULL) && errno!=EINTR)return nr_fail(a,NR_WAIT,NR_SYSCALL,errno,-1);
 }
 return nr_fail(a,NR_WAIT,NR_TIMEOUT,0,-1);
}
int nr_execute(struct nr_attempt *a) {
 if(nr_before(a,a->deadline,NR_FORK))return -1;
 a->child=fork();
 if(a->child<0)return nr_fail(a,NR_FORK,NR_SYSCALL,errno,-1);
 if(!a->child)nr_child(a);
 a->forked=1;
 if(a->child>INT32_MAX)return nr_fail(a,NR_FORK,NR_INVALID,0,-1);
#ifdef GLUE_FD_OBJECTS
 /* Transfer ownership, without duplicating or reopening the actual source refs.
  * The child retains its forked table; numeric closure removes its source aliases. */
 if(a->held_outputs[0]!=-1 || a->held_outputs[1]!=-1 ||
    a->sources[1]<3 || a->sources[2]<3 || a->sources[1]==a->sources[2])
  return nr_fail(a,NR_ENDPOINTS,NR_INVALID,0,-1);
 for(unsigned i=0;i<2;i++){a->held_outputs[i]=a->sources[i+1];a->sources[i+1]=-1;}
#endif
 if(child_ends(a))return -1;
 if(setpgid(a->child,a->child))return nr_fail(a,NR_PROCESS_GROUP,NR_SYSCALL,errno,-1);
 pid_t pg=getpgid(a->child);
 if(pg<0)return nr_fail(a,NR_PROCESS_GROUP,NR_SYSCALL,errno,-1);
 if(pg!=a->child)return nr_fail(a,NR_PROCESS_GROUP,NR_MISMATCH,0,-1);
 struct bw_binding binding={(uint32_t)a->owner,(uint32_t)a->child,{0}};memcpy(binding.request_sha256,a->request_sha,32);
 if(nr_status_init(&a->stream,&binding))return nr_fail(a,NR_STATUS,NR_PROTOCOL,0,-1);
 int rc=nr_status_next(&a->stream,a->status[0],a->deadline,bio_native_operations());
 if(rc || a->stream.wire.last.kind!=BW_READY) {
  if(!rc && a->stream.wire.last.kind==BW_ERROR) {
   /* Retain ERROR+strict EOF before cleanup; this does not authorize a gate. */
   (void)nr_status_next(&a->stream,a->status[0],a->deadline,bio_native_operations());
  }
  return nr_fail(a,NR_READY,a->stream.wire.has_reported_error?NR_REPORTED:NR_PROTOCOL,0,-1);
 }
 a->ready=a->stream.wire.last;
 struct br_ready_context expected;memset(&expected,0,sizeof(expected));expected.binding=binding;
 expected.kept_fds[0]=0;expected.kept_fds[1]=1;expected.kept_fds[2]=2;
 /* Copies were closed in the parent's table, but their captured numbers still
  * form child endpoint declarations. Preserve these before parent close. */
 expected.kept_fds[3]=a->ready_context_fds[0];expected.kept_fds[4]=a->ready_context_fds[1];
 memcpy(expected.signal_policy_sha256,a->policy_sha,32);struct br_error be;
#ifdef GLUE_RUNTIME_PROFILE
 a->ready_fault=rr_ready_compare(&a->request,&expected,&a->ready,&be);
#else
 a->ready_fault=br_ready_compare(&a->request,&expected,&a->ready,&be);
#endif
 if(a->ready_fault!=BR_OK)return nr_fail(a,NR_READY,NR_MISMATCH,0,(int)be.field);
 a->ready_matched=1;
#ifdef GLUE_FD_OBJECTS
 if(nr_before(a,a->deadline,NR_READY))return -1;
 int live=wait_once(a);if(live)return live<0?-1:nr_fail(a,NR_READY,NR_CHILD_STATUS,0,-1);
#ifdef GLUE_RUNTIME_PROFILE
 struct tfo_reference_observation observation;
 int matched=tfo_match_regular_outputs_observed(&a->stream.ready_objects,a->held_outputs,tfo_native_operations(),
                             &a->output_matches,&observation,&a->object_match_error);
 /* Preserve original complete sample prefixes even when matching failed. This
  * is before any trace start or gate operation; never reconstruct observations. */
 if(matched)(void)nr_fail(a,NR_READY,NR_HELPER,a->object_match_error.system_errno,(int)a->object_match_error.reason);
 if(nrw_record_ready(a,&observation))return -1;
 if(matched)return -1;
#else
 if(tfo_match_regular_outputs(&a->stream.ready_objects,a->held_outputs,tfo_native_operations(),
                             &a->output_matches,&a->object_match_error))
  return nr_fail(a,NR_READY,NR_HELPER,a->object_match_error.system_errno,(int)a->object_match_error.reason);
#endif
 if(nr_before(a,a->deadline,NR_READY))return -1;
 a->objects_matched=1;
#endif
#ifdef GLUE_OWNED_TRACING
 if(nr_trace_start(a))return -1;
#endif
 if(nr_before(a,a->deadline,NR_GO))return -1;
#ifdef GLUE_FD_OBJECTS
 if(!a->objects_matched || !a->output_matches.ready)return nr_fail(a,NR_GO,NR_INVALID,0,-1);
 int live_go=wait_once(a);if(live_go)return live_go<0?-1:nr_fail(a,NR_GO,NR_CHILD_STATUS,0,-1);
 if(nr_before(a,a->deadline,NR_GO))return -1;
#endif
 if(a->request.release_action==BR_SEND_GO) {
  uint8_t go[BW_GO_SIZE];
#ifdef GLUE_FD_OBJECTS
  if(bow_go_encode(&binding,go)!=BW_OK)return nr_fail(a,NR_GO,NR_PROTOCOL,0,-1);
#else
  if(bw_go_encode(&binding,go)!=BW_OK)return nr_fail(a,NR_GO,NR_PROTOCOL,0,-1);
#endif
#ifdef GLUE_OWNED_TRACING
  if(nr_trace_claim_go(a))return -1;
  a->go_attempted=1;
  int written=bio_write_record_observed(a->gate[1],go,sizeof(go),a->deadline,bio_native_operations(),&a->trace.observer,&a->go_result,&a->go_error);
  if(written)(void)nr_fail(a,NR_GO,NR_HELPER,a->go_error.system_errno,(int)a->go_error.reason);
  int reported=nr_trace_go_result(a,written);
  int closed=nr_close_owned(a,&a->gate[1],NR_GO);int close_errno=closed?errno:0;a->go_closed=!closed;
  if(nr_trace_gate_result(a,closed,close_errno))reported=-1;
#ifdef GLUE_RUNTIME_TRACING
  if(nrw_record_delivery(a,written,closed,close_errno))reported=-1;
#endif
  if(written || reported || closed)return -1;
#else
  a->go_attempted=1;
  int written=bio_write_record(a->gate[1],go,sizeof(go),a->deadline,bio_native_operations(),&a->go_result,&a->go_error);
#ifdef GLUE_RUNTIME_PROFILE
  /* Preserve the original failed write before a later close can also fail. */
  if(written)(void)nr_fail(a,NR_GO,NR_HELPER,a->go_error.system_errno,(int)a->go_error.reason);
#endif
  int closed=nr_close_owned(a,&a->gate[1],NR_GO);int close_errno=closed?errno:0;
#ifdef GLUE_RUNTIME_PROFILE
  a->go_closed=!closed;
  if(nrw_record_delivery(a,written,closed,close_errno))return -1;
#else
  a->go_closed=1;(void)close_errno;
#endif
  if(written)return nr_fail(a,NR_GO,NR_HELPER,a->go_error.system_errno,(int)a->go_error.reason);
  if(closed)return -1;
#endif
 } else {
#ifdef GLUE_OWNED_TRACING
  int closed=nr_close_owned(a,&a->gate[1],NR_GO);int close_errno=closed?errno:0;a->go_closed=!closed;
  int reported=nr_trace_gate_result(a,closed,close_errno);
#ifdef GLUE_RUNTIME_TRACING
  if(nrw_record_delivery(a,0,closed,close_errno))reported=-1;
#endif
  if(closed || reported)return -1;
#else
#ifdef GLUE_RUNTIME_PROFILE
  int closed=nr_close_owned(a,&a->gate[1],NR_GO);int close_errno=closed?errno:0;a->go_closed=!closed;
  if(nrw_record_delivery(a,0,closed,close_errno))return -1;
  if(closed)return -1;
#else
  if(nr_close_owned(a,&a->gate[1],NR_GO))return -1;
  a->go_closed=1;
#endif
#endif
 }
#ifdef GLUE_OWNED_TRACING
 do {rc=nr_status_next_observed(&a->stream,a->status[0],a->deadline,bio_native_operations(),&a->trace.observer);}while(rc==0);
 if(rc<0 || a->stream.end!=BW_END_ATTEMPT_WITHOUT_REPORTED_EXEC_ERROR) {
  (void)nr_fail(a,NR_STATUS,rc<0?NR_PROTOCOL:a->stream.wire.has_reported_error?NR_REPORTED:NR_INCOMPLETE,0,-1);
  nr_trace_bootstrap_result(a,0);return -1;
 }
 nr_trace_bootstrap_result(a,1);
 if(a->error.stage!=NR_NONE)return -1;
#else
 do {rc=nr_status_next(&a->stream,a->status[0],a->deadline,bio_native_operations());}while(rc==0);
 if(rc<0)return nr_fail(a,NR_STATUS,NR_PROTOCOL,0,-1);
 if(a->stream.end!=BW_END_ATTEMPT_WITHOUT_REPORTED_EXEC_ERROR)
  return nr_fail(a,NR_STATUS,a->stream.wire.has_reported_error?NR_REPORTED:NR_INCOMPLETE,0,-1);
#endif
 if(wait_until(a,a->deadline))return -1;
 if(!WIFEXITED(a->wait_status) || WEXITSTATUS(a->wait_status)!=0)return nr_fail(a,NR_WAIT,NR_CHILD_STATUS,0,-1);
 return 0;
}
void nr_cleanup(struct nr_attempt *a) {
 struct nr_error original=a->error;a->error=(struct nr_error){NR_NONE,NR_NO_ERROR,0,0};
#ifdef GLUE_OWNED_TRACING
 nr_trace_begin_cleanup(a);
#endif
 if(!a->ownership_uncertain) {
#ifdef GLUE_OWNED_TRACING
  if(a->gate[1]>=0) {
   int closed=nr_close_owned(a,&a->gate[1],NR_CLEANUP);int close_errno=closed?errno:0;a->go_closed=!closed;
   (void)nr_trace_gate_result(a,closed,close_errno);
  } else if(a->trace.session_present && !a->trace.session.gate_close_seen) {
   (void)nr_trace_gate_result(a,1,0);
  }
#else
  if(nr_close_owned(a,&a->gate[1],NR_CLEANUP)){}a->go_closed=1;
#endif
  if(a->forked && !a->reaped && !a->lost_child) {
   int observed=wait_once(a);
   if(observed==0) {
#ifdef GLUE_OWNED_TRACING
    if(!nr_trace_claim_kill(a)) {
#endif
    a->kill_attempted=1;
    if(kill(a->child,SIGKILL) && errno!=ESRCH)nr_fail(a,NR_CLEANUP,NR_SYSCALL,errno,-1);
#ifdef GLUE_OWNED_TRACING
    }
    if(a->trace.cleanup_valid)(void)wait_until(a,a->trace.cleanup_deadline);
    else (void)wait_once(a); /* No new budget after a failed clock. */
#else
    struct bio_time cleanup;
    if(!nr_deadline(a,(unsigned)a->request.cleanup_ms,&cleanup))
     (void)wait_until(a,cleanup);
#endif
   }
  }
  (void)child_ends(a);
#ifdef GLUE_FD_OBJECTS
  for(unsigned i=0;i<2;i++)(void)nr_close_owned(a,&a->held_outputs[i],NR_CLEANUP);
#endif
  for(unsigned i=0;i<2;i++){(void)nr_close_owned(a,&a->gate[i],NR_CLEANUP);(void)nr_close_owned(a,&a->status[i],NR_CLEANUP);}
  for(size_t i=0;i<a->admission.owned_count;i++)(void)nr_close_owned(a,&a->admission.components[i].fd,NR_CLEANUP);
#ifdef GLUE_RUNTIME_PROFILE
  (void)nr_close_owned(a,&a->runtime_cwd_fd,NR_CLEANUP);
#endif
 }
#ifdef GLUE_OWNED_TRACING
 nr_trace_close_backend(a);
#endif
 if(a->signals_initialized) {
  a->signals_restored=1;
  if(bs_restore_parent(&a->signals,&a->signal_restore_error))nr_fail(a,NR_CLEANUP,NR_HELPER,a->signal_restore_error.system_errno,(int)a->signal_restore_error.stage);
 }
 a->cleanup_error=a->error;
 if(original.stage!=NR_NONE)a->error=original;
}
int nr_native_run_once(const char *request_path,const char *output_path) {
#ifndef __APPLE__
 (void)request_path;(void)output_path;return 2;
#else
 /* No unsafe native mode exists. Reject before input/output opens or signals. */
 if(getuid()!=0 || geteuid()!=0)return 2;
#ifdef GLUE_RUNTIME_PROFILE
 #if !defined(__aarch64__) && !defined(__arm64__)
 return 2;
 #endif
 const struct nrr_catalog *runtime_catalog=nrr_compiled_catalog();if(!runtime_catalog)return 2;
 struct nr_attempt a;memset(&a,0,sizeof(a));a.runtime_catalog=runtime_catalog;a.runtime_cwd_fd=-1;
#else
 const struct nr_catalog *catalog=nr_compiled_catalog();if(!catalog)return 2;
 struct nr_attempt a;memset(&a,0,sizeof(a));a.catalog=catalog;
#endif
 a.owner=getpid();a.child=-1;a.output_fd=-1;
 for(unsigned i=0;i<5;i++){a.sources[i]=-1;a.endpoints.copies[i]=-1;}
#ifdef GLUE_FD_OBJECTS
 for(unsigned i=0;i<2;i++)a.held_outputs[i]=-1;
#endif
 for(unsigned i=0;i<2;i++){a.gate[i]=-1;a.status[i]=-1;}
 for(unsigned i=0;i<BA_COMPONENT_COUNT;i++)a.admission.components[i].fd=-1;
 if(a.owner<=0 || a.owner>INT32_MAX)return 2;
#ifdef GLUE_RUNTIME_PROFILE
 if(nrr_prepare(&a))return 2;
#endif
 if(nr_clock(&a,&a.start_clock) || a.start_clock>UINT64_MAX-UINT64_C(10000000000))return 2;
 uint64_t limit=a.start_clock+UINT64_C(10000000000);a.deadline=(struct bio_time){limit/1000000000,limit%1000000000};
 a.signals_initialized=1;
 if(bs_prepare_parent(bs_native_operations(),&a.signals,&a.signal_prepare_error))nr_fail(&a,NR_SIGNAL,NR_HELPER,a.signal_prepare_error.system_errno,(int)a.signal_prepare_error.stage);
 if(a.error.stage==NR_NONE && !nr_read_request(&a,request_path)) {
  uint64_t span=a.request.attempt_ms*UINT64_C(1000000);
  if(a.start_clock>UINT64_MAX-span)nr_fail(&a,NR_REQUEST,NR_CLOCK,0,-1);
  else {limit=a.start_clock+span;a.deadline=(struct bio_time){limit/1000000000,limit%1000000000};(void)nr_before(&a,a.deadline,NR_REQUEST);}
 }
 if(a.error.stage==NR_NONE) {
  unsigned char policy[BS_POLICY_CAPACITY];size_t n;struct bs_error se;
  if(bs_policy_bytes(&a.signals,policy,&n,&se) || nr_sha_bytes(policy,n,a.policy_sha))nr_fail(&a,NR_SIGNAL,NR_HELPER,se.system_errno,(int)se.stage);
 }
 if(a.error.stage==NR_NONE)(void)nr_admit(&a);
 if(a.error.stage==NR_NONE)(void)nr_output(&a,output_path);
 if(a.error.stage==NR_NONE)(void)nr_endpoints(&a);
 if(a.error.stage==NR_NONE) {
  a.ready_context_fds[0]=(uint64_t)a.endpoints.copies[TE_GATE_READER];a.ready_context_fds[1]=(uint64_t)a.endpoints.copies[TE_STATUS_WRITER];
  (void)nr_execute(&a);
 }
 nr_cleanup(&a);
 if(a.output_fd>=0 && !a.ownership_uncertain) {
  /* Finalization closes the held output dir before result promotion. Never add
   * a fallible operation here after successful nr_finish_outputs. */
  if(nr_finish_outputs(&a))return 2;
#ifdef GLUE_RUNTIME_PROFILE
  return a.error.stage==NR_NONE&&a.runtime_outputs_valid?0:1;
#else
  return a.error.stage==NR_NONE&&a.probe_matched?0:1;
#endif
 }
#ifdef GLUE_OWNED_TRACING
 (void)nr_trace_parent_closed(&a,1);
#endif
 return 2;
#endif
}
