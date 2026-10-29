#define _POSIX_C_SOURCE 200809L
#define _DARWIN_C_SOURCE 1
#include "runner_internal.h"
#include <errno.h>
#include <inttypes.h>
#include <stdarg.h>
#include <stdio.h>
#include <string.h>
#include <time.h>

static uint64_t ns(struct bio_time d) {return d.seconds*UINT64_C(1000000000)+d.nanoseconds;}
static int fault(struct nr_attempt *a,enum nr_stage stage) {
 int e=a->trace.create_error.system_errno;
 struct otb_snapshot snapshot;
 if(a->trace.backend && !otb_snapshot(a->trace.backend,&snapshot))e=snapshot.first_error.system_errno;
 return nr_fail(a,stage,NR_HELPER,e,(int)a->trace.session.error.reason);
}
int nr_trace_pump(struct nr_attempt *a,enum ts_phase phase) {
 if(!a->trace.session_present || !a->trace.session.started)return 0;
 if(phase==TS_CLEANUP && (!a->trace.cleanup_valid || !a->trace.session.cleanup_bound))return fault(a,NR_CLEANUP);
 int rc=ts_pump(&a->trace.session,phase);
 return rc || (phase!=TS_CLEANUP && a->trace.session.error.reason!=TS_OK)?fault(a,phase==TS_CLEANUP?NR_CLEANUP:NR_TRACE):0;
}
static int progress(void *context,struct bio_time original) {
 struct nr_attempt *a=context;
 if(original.seconds!=a->deadline.seconds || original.nanoseconds!=a->deadline.nanoseconds)
  return nr_fail(a,NR_TRACE,NR_INVALID,0,-1);
 return nr_trace_pump(a,TS_BOOTSTRAP);
}
int nr_trace_start(struct nr_attempt *a) {
 struct nr_trace *t=&a->trace;
#ifdef GLUE_FD_OBJECTS
 if(!a->objects_matched || !a->output_matches.ready)return nr_fail(a,NR_TRACE,NR_INVALID,0,-1);
#endif
 if(t->create_attempted || !a->ready_matched || !a->forked || a->reaped || a->lost_child || a->child<=0)
  return nr_fail(a,NR_TRACE,NR_INVALID,0,-1);
 t->create_attempted=1;
 struct ts_binding b={TS_OWNED_CONTEXT_PROBE,(uint32_t)a->owner,(uint32_t)a->child,{0},{0}};
 memcpy(b.request_sha256,a->request_sha,32);memcpy(b.catalog_sha256,a->catalog_sha,32);
 struct ts_operations operations;
 if(otb_create(&t->backend,a->output_fd,&b,ns(a->deadline),1,&operations,&t->create_error))return fault(a,NR_TRACE);
 int rc=ts_init(&t->session,&b,ns(a->deadline),(unsigned)a->request.cleanup_ms,&operations);
 t->session_present=t->session.configured;
 t->observer=(struct bio_observer){a,progress};
 if(rc || ts_start(&t->session))return fault(a,NR_TRACE);
 for(unsigned step=0;step<TS_MAX_PUMPS;step++) {
  if(nr_trace_pump(a,TS_BOOTSTRAP))return -1;
  if(t->session.provider_ready==1 && t->session.begin_count==1)return 0;
  struct timespec nap={0,1000000};
  if(nanosleep(&nap,NULL) && errno!=EINTR)return nr_fail(a,NR_TRACE,NR_SYSCALL,errno,-1);
 }
 return nr_fail(a,NR_TRACE,NR_TIMEOUT,0,-1);
}
int nr_trace_claim_go(struct nr_attempt *a) {
 return ts_claim_go(&a->trace.session)?fault(a,NR_GO):0;
}
int nr_trace_go_result(struct nr_attempt *a,int failed) {
 int rc=failed?ts_go_failed(&a->trace.session,a->go_result.bytes_moved,a->go_error.system_errno):
               ts_go_result(&a->trace.session,a->go_result.bytes_moved,0);
 return rc?fault(a,NR_GO):0;
}
int nr_trace_gate_result(struct nr_attempt *a,int failed,int saved_errno) {
 struct ts_session *s=&a->trace.session;
 if(!a->trace.session_present || s->gate_close_seen)return 0;
 int rc=failed?ts_gate_close_failed(s,saved_errno):ts_gate_close_result(s,0);
 return rc?fault(a,NR_GO):0;
}
void nr_trace_bootstrap_result(struct nr_attempt *a,int sealed) {
 struct ts_session *s=&a->trace.session;
 if(!a->trace.session_present || s->bootstrap_seen)return;
 int rc=sealed?ts_bootstrap_sealed(s):ts_bootstrap_failed(s,a->stream.used,a->stream.first_io_error.system_errno);
 if(rc)(void)fault(a,NR_STATUS);
}
void nr_trace_child_result(struct nr_attempt *a,int lost,int status) {
 if(a->trace.session_present) {
  if(lost)(void)ts_child_lost(&a->trace.session);
  else (void)ts_child_reaped(&a->trace.session,(uint32_t)status);
 }
}
int nr_trace_claim_kill(struct nr_attempt *a) {
 if(!a->trace.session_present)return 0;
 if(!ts_kill_eligible(&a->trace.session) || ts_claim_kill(&a->trace.session))return fault(a,NR_CLEANUP);
 return 0;
}
void nr_trace_begin_cleanup(struct nr_attempt *a) {
 struct nr_trace *t=&a->trace;
 if(t->cleanup_attempted){(void)nr_fail(a,NR_CLEANUP,NR_INVALID,0,-1);return;}
 t->cleanup_attempted=1;t->cleanup_deadline=a->deadline;
 unsigned budget=(unsigned)a->request.cleanup_ms;
 if(!budget || budget>2000){(void)nr_fail(a,NR_CLEANUP,NR_INVALID,0,-1);budget=1;}
 t->cleanup_valid=!nr_deadline(a,budget,&t->cleanup_deadline);
 if(t->session_present) {
  if(!t->session.bootstrap_seen)nr_trace_bootstrap_result(a,0);
  if(ts_begin_cleanup(&t->session,ns(t->cleanup_deadline)))(void)fault(a,NR_CLEANUP);
 }
}
void nr_trace_close_backend(struct nr_attempt *a) {
 struct nr_trace *t=&a->trace;struct ts_session *s=&t->session;
 if(!t->session_present)return;
 /* A failed cleanup clock/binding must not authorize work against the longer
  * attempt deadline after a transient recovery. Only once-only close remains. */
 int bounded=t->cleanup_valid && s->cleanup_bound;
 if(bounded && s->started && s->child!=TS_CHILD_LIVE && !s->stop_attempted)
  if(ts_stop(s))(void)fault(a,NR_CLEANUP);
 if(bounded && s->stopped && s->child==TS_CHILD_REAPED && !s->drain_attempted)
  if(ts_drain(s))(void)fault(a,NR_CLEANUP);
 if(!s->close_attempted)if(ts_close(s))(void)fault(a,NR_CLEANUP);
}
int nr_trace_parent_closed(struct nr_attempt *a,int unresolved) {
 struct nr_trace *t=&a->trace;
 if(t->finalized)return t->resources_safe?0:-1;
 t->finalized=1;
 if(t->session_present) {
  t->parent_reported=1;
  int rc=unresolved?ts_parent_close_failed(&t->session,0):ts_parent_close_result(&t->session,0);
  if(rc)(void)fault(a,NR_FINALIZE);
 }
 /* Parent reporting performs owner/clock callbacks: context stays alive above.
  * Only pure session observations are permitted after this snapshot/destroy. */
 if(t->backend) {
  t->snapshot_valid=!otb_snapshot(t->backend,&t->snapshot);
  t->destroy_attempted=1;
  t->destroyed=!otb_destroy(&t->backend);
  if(!t->snapshot_valid || !t->destroyed){(void)nr_fail(a,NR_FINALIZE,NR_INCOMPLETE,0,-1);return -1;}
 }
 t->resources_safe=!unresolved && (!t->session_present || ts_finalization_safe(&t->session));
 if(!t->resources_safe)return nr_fail(a,NR_FINALIZE,NR_INCOMPLETE,0,-1);
 return 0;
}
int nr_trace_success(const struct nr_attempt *a) {
 return a->trace.finalized && a->trace.resources_safe && a->trace.session_present && ts_success_eligible(&a->trace.session);
}
struct json {char data[16384];size_t used;int failed;};
static void put(struct json *j,const char *format,...) {
 if(j->failed)return;
 va_list ap;va_start(ap,format);int n=vsnprintf(j->data+j->used,sizeof(j->data)-j->used,format,ap);va_end(ap);
 if(n<0 || (size_t)n>=sizeof(j->data)-j->used){j->failed=1;return;}j->used+=(size_t)n;
}
static void bytes_hex(const uint8_t *p,size_t n,char *out) {
 static const char h[]="0123456789abcdef";
 for(size_t i=0;i<n;i++){out[2*i]=h[p[i]>>4];out[2*i+1]=h[p[i]&15];}out[2*n]=0;
}
static void binding_json(struct json *j,const struct ts_binding *b) {
 char request[65],catalog[65];bytes_hex(b->request_sha256,32,request);bytes_hex(b->catalog_sha256,32,catalog);
 put(j,"{\"fixture\":%u,\"owner_pid\":%u,\"target_pid\":%u,\"request_sha256\":\"%s\",\"catalog_sha256\":\"%s\"}",b->fixture,b->owner_pid,b->target_pid,request,catalog);
}
static void ts_error_json(struct json *j,const struct ts_error *e) {
 put(j,"{\"stage\":%d,\"reason\":%d,\"callback_error\":%d,\"detail\":%zu}",e->stage,e->reason,e->system_errno,e->detail);
}
static void otb_error_json(struct json *j,const struct otb_error *e) {
 size_t n=strnlen(e->message,sizeof(e->message));char message[1027];
 if(n==sizeof(e->message)){j->failed=1;return;}bytes_hex((const uint8_t *)e->message,n,message);
 put(j,"{\"stage\":%d,\"reason\":%d,\"system_errno\":%d,\"libdtrace_code\":%d,\"callback_error\":%d,\"message_hex\":\"%s\"}",e->stage,e->reason,e->system_errno,e->libdtrace_code,e->callback_error,message);
}
int nr_trace_write_sidecar(struct nr_attempt *a) {
 const struct nr_trace *t=&a->trace;const struct ts_session *s=&t->session;const struct otb_snapshot *b=&t->snapshot;
 if(!t->finalized || !t->resources_safe)return nr_fail(a,NR_FINALIZE,NR_INCOMPLETE,0,-1);
 struct json j={{0},0,0};
 put(&j,"{\"schema\":\"glue-owned-trace-session-diagnostic-v1\",\"tracing\":true,\"exec_proved\":false,\"full_acceptance\":false,\"parent_cleanup_deadline_ns\":%" PRIu64 ",\"parent_cleanup_valid\":%d,\"create_attempted\":%d,\"session_present\":%d,\"snapshot_valid\":%d,\"backend_destroyed\":%d,\"finalization_safe\":%d,\"success_eligible\":%d,\"create_error\":",ns(t->cleanup_deadline),t->cleanup_valid,t->create_attempted,t->session_present,t->snapshot_valid,t->destroyed,t->resources_safe,nr_trace_success(a));
 otb_error_json(&j,&t->create_error);put(&j,",\"session\":{\"binding\":");binding_json(&j,&s->binding);
 put(&j,",\"attempt_deadline_ns\":%" PRIu64 ",\"cleanup_deadline_ns\":%" PRIu64 ",\"cleanup_ms\":%u,\"cleanup_attempted\":%d,\"cleanup_bound\":%d,\"error\":",s->attempt_deadline_ns,s->cleanup_deadline_ns,s->cleanup_ms,s->cleanup_attempted,s->cleanup_bound);ts_error_json(&j,&s->error);
 put(&j,",\"cleanup_error\":");ts_error_json(&j,&s->cleanup_error);
 put(&j,",\"configured\":%d,\"initialized\":%d,\"start_attempted\":%d,\"backend_touched\":%d,\"last_ns\":%" PRIu64 ",\"total_pumps\":%u",s->configured,s->initialized,s->start_attempted,s->backend_touched,s->last_ns,s->total_pumps);
 put(&j,",\"child\":%d,\"wait_status\":%u,\"kill_claimed\":%d,\"started\":%d,\"provider_ready\":%u,\"begin\":%u,\"terminal\":%u,\"end\":%u,\"pumps\":[%u,%u,%u],\"events\":%u,\"go_claim_attempted\":%d,\"go_possibly_released\":%d,\"go_result_seen\":%d,\"go_complete\":%d,\"go_bytes\":%zu,\"bootstrap_seen\":%d,\"bootstrap_sealed\":%d,\"bootstrap_prefix_bytes\":%zu,\"gate_close_seen\":%d,\"gate_closed\":%d,\"stop_attempted\":%d,\"stopped\":%d,\"drain_attempted\":%d,\"drained\":%d,\"close_attempted\":%d,\"closed\":%d,\"parent_close_seen\":%d,\"parent_closed\":%d},\"backend\":{\"binding\":",s->child,s->wait_status,s->kill_claimed,s->started,s->provider_ready,s->begin_count,s->terminal_count,s->end_count,s->pump_calls[0],s->pump_calls[1],s->pump_calls[2],s->events,s->go_claim_attempted,s->go_possibly_released,s->go_result_seen,s->go_complete,s->go_bytes,s->bootstrap_seen,s->bootstrap_sealed,s->bootstrap_prefix_bytes,s->gate_close_seen,s->gate_closed,s->stop_attempted,s->stopped,s->drain_attempted,s->drained,s->close_attempted,s->closed,s->parent_close_seen,s->parent_closed);
 binding_json(&j,&b->binding);
 put(&j,",\"original_attempt_deadline_ns\":%" PRIu64 ",\"cleanup_deadline_ns\":%" PRIu64 ",\"first_error\":",b->original_attempt_deadline_ns,b->cleanup_deadline_ns);otb_error_json(&j,&b->first_error);put(&j,",\"close_error\":");otb_error_json(&j,&b->close_error);
 put(&j,",\"writer_close_error\":");otb_error_json(&j,&b->writer_close_error);
 put(&j,",\"writer_close_files\":[\"program.d\",\"probes.tsv\",\"events.jsonl\",\"errors.jsonl\"],\"writer_close_attempted_mask\":%u,\"writer_close_failed_mask\":%u,\"writer_close_errno\":[%d,%d,%d,%d]",b->writer_close_attempted_mask,b->writer_close_failed_mask,b->writer_close_errno[0],b->writer_close_errno[1],b->writer_close_errno[2],b->writer_close_errno[3]);
 put(&j,",\"events\":%" PRIu64 ",\"raw_bytes\":%" PRIu64 ",\"diagnostic_bytes\":%" PRIu64 ",\"inventory_bytes\":%" PRIu64 ",\"drops\":%" PRIu64 ",\"faults\":%" PRIu64 ",\"inventory_probes\":%u,\"expected_matches\":%u,\"enabled_matches\":%u,\"enablings\":%u,\"begin\":%u,\"terminal\":%u,\"end\":%u,\"start_attempted\":%d,\"started\":%d,\"stop_attempted\":%d,\"stopped\":%d,\"drain_attempted\":%d,\"drained\":%d,\"close_attempted\":%d,\"resources_closed\":%d}}\n",b->events,b->raw_bytes,b->diagnostic_bytes,b->inventory_bytes,b->drops,b->faults,b->inventory_probes,b->expected_matches,b->enabled_matches,b->enablings,b->begin_count,b->terminal_count,b->end_count,b->start_attempted,b->started,b->stop_attempted,b->stopped,b->drain_attempted,b->drained,b->close_attempted,b->resources_closed);
 if(j.failed)return nr_fail(a,NR_FINALIZE,NR_INVALID,0,-1);
 return nr_write_new(a,"trace.json",(const uint8_t *)j.data,j.used);
}
