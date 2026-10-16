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
 if(n==a->child){a->reaped=1;a->wait_status=status;return 1;}
 if(n==0)return 0;
 if(n==-1 && saved==EINTR)return 0;
 if(n==-1 && saved==ECHILD){a->lost_child=1;return nr_fail(a,NR_WAIT,NR_LOST_CHILD,saved,-1);}
 return nr_fail(a,NR_WAIT,NR_SYSCALL,n==-1?saved:EIO,-1);
}
static int wait_until(struct nr_attempt *a,struct bio_time deadline) {
 for(unsigned step=0;step<20000;step++) {
  /* Check time even for EINTR. Check again after a completed wait before using
   * it as an on-time observation; reaped state still permanently ends ownership. */
  if(nr_before(a,deadline,NR_WAIT))return -1;
  int rc=wait_once(a);
  if(nr_before(a,deadline,NR_WAIT))return -1;
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
 a->ready_fault=br_ready_compare(&a->request,&expected,&a->ready,&be);
 if(a->ready_fault!=BR_OK)return nr_fail(a,NR_READY,NR_MISMATCH,0,(int)be.field);
 a->ready_matched=1;
 if(nr_before(a,a->deadline,NR_GO))return -1;
 if(a->request.release_action==BR_SEND_GO) {
  uint8_t go[BW_GO_SIZE];if(bw_go_encode(&binding,go)!=BW_OK)return nr_fail(a,NR_GO,NR_PROTOCOL,0,-1);
  a->go_attempted=1;
  int written=bio_write_record(a->gate[1],go,sizeof(go),a->deadline,bio_native_operations(),&a->go_result,&a->go_error);
  int closed=nr_close_owned(a,&a->gate[1],NR_GO);a->go_closed=1;
  if(written)return nr_fail(a,NR_GO,NR_HELPER,a->go_error.system_errno,(int)a->go_error.reason);
  if(closed)return -1;
 } else {
  if(nr_close_owned(a,&a->gate[1],NR_GO))return -1;
  a->go_closed=1;
 }
 do {rc=nr_status_next(&a->stream,a->status[0],a->deadline,bio_native_operations());}while(rc==0);
 if(rc<0)return nr_fail(a,NR_STATUS,NR_PROTOCOL,0,-1);
 if(a->stream.end!=BW_END_ATTEMPT_WITHOUT_REPORTED_EXEC_ERROR)
  return nr_fail(a,NR_STATUS,a->stream.wire.has_reported_error?NR_REPORTED:NR_INCOMPLETE,0,-1);
 if(wait_until(a,a->deadline))return -1;
 if(!WIFEXITED(a->wait_status) || WEXITSTATUS(a->wait_status)!=0)return nr_fail(a,NR_WAIT,NR_CHILD_STATUS,0,-1);
 return 0;
}
void nr_cleanup(struct nr_attempt *a) {
 struct nr_error original=a->error;a->error=(struct nr_error){NR_NONE,NR_NO_ERROR,0,0};
 if(!a->ownership_uncertain) {
  if(nr_close_owned(a,&a->gate[1],NR_CLEANUP)){}a->go_closed=1;
  if(a->forked && !a->reaped && !a->lost_child) {
   int observed=wait_once(a);
   if(observed==0) {
    a->kill_attempted=1;
    if(kill(a->child,SIGKILL) && errno!=ESRCH)nr_fail(a,NR_CLEANUP,NR_SYSCALL,errno,-1);
    struct bio_time cleanup;
    if(!nr_deadline(a,(unsigned)a->request.cleanup_ms,&cleanup))
     (void)wait_until(a,cleanup);
   }
  }
  (void)child_ends(a);
  for(unsigned i=0;i<2;i++){(void)nr_close_owned(a,&a->gate[i],NR_CLEANUP);(void)nr_close_owned(a,&a->status[i],NR_CLEANUP);}
  for(size_t i=0;i<a->admission.owned_count;i++)(void)nr_close_owned(a,&a->admission.components[i].fd,NR_CLEANUP);
 }
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
 const struct nr_catalog *catalog=nr_compiled_catalog();if(!catalog)return 2;
 struct nr_attempt a;memset(&a,0,sizeof(a));a.catalog=catalog;a.owner=getpid();a.child=-1;a.output_fd=-1;
 for(unsigned i=0;i<5;i++){a.sources[i]=-1;a.endpoints.copies[i]=-1;}
 for(unsigned i=0;i<2;i++){a.gate[i]=-1;a.status[i]=-1;}
 for(unsigned i=0;i<BA_COMPONENT_COUNT;i++)a.admission.components[i].fd=-1;
 if(a.owner<=0 || a.owner>INT32_MAX)return 2;
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
  return a.error.stage==NR_NONE&&a.probe_matched?0:1;
 }
 return 2;
#endif
}
