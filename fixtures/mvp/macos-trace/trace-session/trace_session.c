#include "trace_session.h"
#include <limits.h>
#include <string.h>
#define TS_TAG UINT32_C(0x54534331)
#define NS_PER_MS UINT64_C(1000000)

static int fail(struct ts_session *s,enum ts_stage stage,enum ts_reason reason,int e,size_t detail) {
 struct ts_error v={stage,reason,e,detail};
 if(s->error.reason==TS_OK)s->error=v;
 if(s->cleanup_attempted && s->cleanup_error.reason==TS_OK)s->cleanup_error=v;
 return -1;
}
static int owned(struct ts_session *s,enum ts_stage stage) {
 if(!s || s->tag!=TS_TAG)return -1;
 if(!s->configured)return fail(s,stage,TS_INVALID,0,0);
 int e=0;uint32_t pid=s->operations.owner_fn(s->operations.context,&e);
 if(e || pid!=s->binding.owner_pid)return fail(s,stage,TS_WRONG_OWNER,e>0?e:0,pid);
 return 0;
}
static int clock_value(struct ts_session *s,enum ts_stage stage,uint64_t *now) {
 int e=0;*now=0;
 int rc=s->operations.clock_fn(s->operations.context,now,&e);
 if(rc || e)return fail(s,stage,TS_CLOCK,rc==-1&&e>0?e:0,0);
 if(s->clock_seen && *now<s->last_ns)return fail(s,stage,TS_CLOCK_ROLLBACK,0,0);
 s->clock_seen=1;s->last_ns=*now;return 0;
}
static uint64_t deadline(const struct ts_session *s) {
 return s->cleanup_bound?s->cleanup_deadline_ns:s->attempt_deadline_ns;
}
static int before(struct ts_session *s,enum ts_stage stage,uint64_t d) {
 uint64_t now;if(clock_value(s,stage,&now))return -1;
 return now>=d?fail(s,stage,TS_DEADLINE,0,0):0;
}
static int after(struct ts_session *s,enum ts_stage stage,uint64_t d,int rc,int e) {
 int bad=0;
 /* Preserve the backend/sink fault before any later clock fault. */
 if(rc || e){fail(s,stage,rc==-1&&e>0?TS_BACKEND:TS_INVALID,rc==-1&&e>0?e:0,0);bad=1;}
 if(owned(s,stage) || before(s,stage,d))bad=1;
 return bad?-1:0;
}
static int binding_equal(const struct ts_binding *a,const struct ts_binding *b) {
 return a->fixture==b->fixture && a->owner_pid==b->owner_pid && a->target_pid==b->target_pid &&
 !memcmp(a->request_sha256,b->request_sha256,32) && !memcmp(a->catalog_sha256,b->catalog_sha256,32);
}
static int consume(void *context,const struct ts_event *event) {
 struct ts_session *s=context;enum ts_stage st=s->draining?TS_STAGE_DRAIN:TS_STAGE_PUMP;
 if(!s->consuming || !event || s->consume_failed){s->consume_failed=1;return fail(s,st,TS_INVALID,0,0);}
 enum ts_reason reason=TS_EVENT_ORDER;
 if(s->events>=TS_MAX_EVENTS){reason=TS_LIMIT;goto bad;}
 s->events++;
 if(!binding_equal(&s->binding,&event->binding)){reason=TS_BAD_BINDING;goto bad;}
 if(s->end_count)goto bad;
 switch(event->kind) {
 case TS_PROVIDER_READY:
  if(s->provider_ready || s->begin_count || s->go_possibly_released || s->draining)goto bad;
  s->provider_ready=1;return 0;
 case TS_BEGIN:
  if(!s->provider_ready || s->begin_count || s->go_possibly_released || s->draining)goto bad;
  s->begin_count=1;return 0;
 case TS_ACTIVITY:
  if(!s->begin_count || s->terminal_count)goto bad;
  return 0;
 case TS_TERMINAL:
  if(!s->begin_count || s->terminal_count)goto bad;
  s->terminal_count=1;
  if(!s->go_possibly_released){reason=TS_CHILD_FAILURE;goto bad;}
  return 0;
 case TS_END:
  if(!s->draining || !s->stopped || !s->begin_count || !s->terminal_count)goto bad;
  s->end_count=1;return 0;
 case TS_DROP:reason=TS_DROPPED;break;
 case TS_BACKEND_FAULT:reason=TS_BACKEND;break;
 case TS_OUTPUT_FAULT:reason=TS_OUTPUT;break;
 default:break;
 }
bad:
 s->consume_failed=1;return fail(s,st,reason,0,event?(size_t)event->kind:0);
}
int ts_init(struct ts_session *s,const struct ts_binding *b,uint64_t attempt,unsigned cleanup_ms,const struct ts_operations *o) {
 if(!s || !b || !o || s->tag)return -1;
 memset(s,0,sizeof(*s));s->tag=TS_TAG;s->binding=*b;s->operations=*o;
 s->attempt_deadline_ns=attempt;s->cleanup_ms=cleanup_ms;s->child=TS_CHILD_LIVE;
 if(b->fixture!=TS_OWNED_CONTEXT_PROBE || !b->owner_pid || !b->target_pid ||
 b->owner_pid>INT32_MAX || b->target_pid>INT32_MAX || b->owner_pid==b->target_pid ||
 !cleanup_ms || cleanup_ms>2000 || !o->owner_fn || !o->clock_fn || !o->start_fn || !o->pump_fn ||
 !o->stop_fn || !o->drain_fn || !o->close_fn)return fail(s,TS_STAGE_INIT,TS_INVALID,0,0);
 s->configured=1;
 if(owned(s,TS_STAGE_INIT) || before(s,TS_STAGE_INIT,attempt))return -1;
 if(attempt-s->last_ns>UINT64_C(10000000000))return fail(s,TS_STAGE_INIT,TS_INVALID,0,0);
 s->initialized=1;return 0;
}
int ts_start(struct ts_session *s) {
 if(owned(s,TS_STAGE_START))return -1;
 if(!s->initialized || s->start_attempted || s->close_attempted || s->error.reason!=TS_OK || s->cleanup_attempted || s->child!=TS_CHILD_LIVE)
  return fail(s,TS_STAGE_START,TS_INVALID,0,0);
 s->start_attempted=1;
 if(before(s,TS_STAGE_START,s->attempt_deadline_ns))return -1;
 s->backend_touched=1;int e=0;
 int rc=s->operations.start_fn(s->operations.context,&s->binding,s->attempt_deadline_ns,&e);
 s->started=rc==0&&e==0;
 return after(s,TS_STAGE_START,s->attempt_deadline_ns,rc,e);
}
int ts_pump(struct ts_session *s,enum ts_phase phase) {
 if(owned(s,TS_STAGE_PUMP))return -1;
 if(phase<TS_BOOTSTRAP || phase>TS_CLEANUP || !s->started || s->stop_attempted || s->close_attempted ||
 ((phase==TS_CLEANUP)!=!!s->cleanup_bound))return fail(s,TS_STAGE_PUMP,TS_INVALID,0,0);
 if(s->total_pumps>=TS_MAX_PUMPS)return fail(s,TS_STAGE_PUMP,TS_LIMIT,0,0);
 s->total_pumps++;
 s->pump_calls[phase]++;
 uint64_t d=deadline(s);if(before(s,TS_STAGE_PUMP,d))return -1;
 s->consuming=1;s->consume_failed=0;int e=0;
 int rc=s->operations.pump_fn(s->operations.context,phase,d,consume,s,&e);
 s->consuming=0;int bad=s->consume_failed;
 if(after(s,TS_STAGE_PUMP,d,rc,e))bad=1;
 return bad?-1:0;
}
int ts_claim_go(struct ts_session *s) {
 if(owned(s,TS_STAGE_GO))return -1;
 if(s->go_claim_attempted)return fail(s,TS_STAGE_GO,TS_INVALID,0,0);
 s->go_claim_attempted=1;
 if(s->error.reason!=TS_OK || !s->started || s->provider_ready!=1 || s->begin_count!=1 ||
 s->terminal_count || s->child!=TS_CHILD_LIVE || s->cleanup_attempted || s->stop_attempted || s->close_attempted || s->gate_close_seen)
  return fail(s,TS_STAGE_GO,TS_NOT_READY,0,0);
 if(before(s,TS_STAGE_GO,s->attempt_deadline_ns))return -1;
 s->go_possibly_released=1;return 0;
}
static int go_result(struct ts_session *s,size_t bytes,int error,int failed) {
 if(owned(s,TS_STAGE_GO))return -1;
 if(!s->go_possibly_released || s->go_result_seen || bytes>64 || error<0)return fail(s,TS_STAGE_GO,TS_INVALID,0,bytes);
 s->go_result_seen=1;s->go_bytes=bytes;
 int bad=0;
 if(failed || error || bytes!=64){fail(s,TS_STAGE_GO,TS_PARENT_FAILURE,error,bytes);bad=1;}
 if(before(s,TS_STAGE_GO,s->attempt_deadline_ns))bad=1;
 s->go_complete=!bad;return bad?-1:0;
}
int ts_go_result(struct ts_session *s,size_t bytes,int error) {return go_result(s,bytes,error,0);}
int ts_go_failed(struct ts_session *s,size_t bytes,int error) {return go_result(s,bytes,error,1);}
int ts_gate_close_result(struct ts_session *s,int error) {
 if(owned(s,TS_STAGE_PARENT))return -1;
 if(s->gate_close_seen || error<0)return fail(s,TS_STAGE_PARENT,TS_INVALID,0,0);
 s->gate_close_seen=1;s->gate_closed=!error;
 int bad=0;if(error){fail(s,TS_STAGE_PARENT,TS_PARENT_FAILURE,error,0);bad=1;}
 if(before(s,TS_STAGE_PARENT,deadline(s)))bad=1;
 return bad?-1:0;
}
int ts_bootstrap_sealed(struct ts_session *s) {
 if(owned(s,TS_STAGE_BOOTSTRAP))return -1;
 if(s->bootstrap_seen || !s->go_complete || !s->gate_closed)return fail(s,TS_STAGE_BOOTSTRAP,TS_INVALID,0,0);
 s->bootstrap_seen=1;s->bootstrap_prefix_bytes=512;
 if(before(s,TS_STAGE_BOOTSTRAP,s->attempt_deadline_ns))return -1;
 s->bootstrap_sealed=1;return 0;
}
int ts_bootstrap_failed(struct ts_session *s,size_t prefix,int error) {
 if(owned(s,TS_STAGE_BOOTSTRAP))return -1;
 if(s->bootstrap_seen || prefix>TS_STATUS_CAPACITY || error<0)return fail(s,TS_STAGE_BOOTSTRAP,TS_INVALID,0,prefix);
 s->bootstrap_seen=1;s->bootstrap_prefix_bytes=prefix;
 return fail(s,TS_STAGE_BOOTSTRAP,TS_PARENT_FAILURE,error,prefix);
}
int ts_child_reaped(struct ts_session *s,uint32_t status) {
 if(!s || s->tag!=TS_TAG || !s->configured)return -1;
 if(s->child!=TS_CHILD_LIVE)return fail(s,TS_STAGE_WAIT,TS_INVALID,0,0);
 /* Trusted caller reports a consumed actual wait. Permanently retire ownership
  * BEFORE any fallible owner/time observation can fail or later recover. */
 s->child=TS_CHILD_REAPED;s->wait_status=status;int bad=0;
 if(status){fail(s,TS_STAGE_WAIT,TS_CHILD_FAILURE,0,status);bad=1;}
 if(owned(s,TS_STAGE_WAIT) || before(s,TS_STAGE_WAIT,deadline(s)))bad=1;
 return bad?-1:0;
}
int ts_child_lost(struct ts_session *s) {
 if(!s || s->tag!=TS_TAG || !s->configured)return -1;
 if(s->child!=TS_CHILD_LIVE)return fail(s,TS_STAGE_WAIT,TS_INVALID,0,0);
 s->child=TS_CHILD_LOST;fail(s,TS_STAGE_WAIT,TS_LOST_CHILD,0,0);
 (void)owned(s,TS_STAGE_WAIT);return -1;
}
int ts_kill_eligible(const struct ts_session *s) {
 return s && s->tag==TS_TAG && s->configured && s->child==TS_CHILD_LIVE && !s->kill_claimed;
}
int ts_claim_kill(struct ts_session *s) {
 if(owned(s,TS_STAGE_WAIT))return -1;
 if(!ts_kill_eligible(s))return fail(s,TS_STAGE_WAIT,TS_INVALID,0,0);
 s->kill_claimed=1;return 0;
}
int ts_begin_cleanup(struct ts_session *s,uint64_t d) {
 if(owned(s,TS_STAGE_CLEANUP))return -1;
 if(s->cleanup_attempted)return fail(s,TS_STAGE_CLEANUP,TS_INVALID,0,0);
 int bad=s->child==TS_CHILD_LIVE && s->error.reason==TS_OK;
 s->cleanup_attempted=1;
 if(bad)fail(s,TS_STAGE_CLEANUP,TS_INCOMPLETE,0,0);
 uint64_t now;
 if(clock_value(s,TS_STAGE_CLEANUP,&now))return -1;
 if(d<=now || d-now>(uint64_t)s->cleanup_ms*NS_PER_MS)return fail(s,TS_STAGE_CLEANUP,TS_DEADLINE,0,0);
 s->cleanup_deadline_ns=d;s->cleanup_bound=1;return bad?-1:0;
}
int ts_stop(struct ts_session *s) {
 if(owned(s,TS_STAGE_STOP))return -1;
 if(s->stop_attempted)return fail(s,TS_STAGE_STOP,TS_INVALID,0,0);
 s->stop_attempted=1;
 if(s->child==TS_CHILD_LIVE || !s->started || s->close_attempted)return fail(s,TS_STAGE_STOP,TS_INCOMPLETE,0,0);
 uint64_t d=deadline(s);int bad=before(s,TS_STAGE_STOP,d),e=0;
 int rc=s->operations.stop_fn(s->operations.context,d,&e);s->stopped=rc==0&&e==0;
 if(after(s,TS_STAGE_STOP,d,rc,e))bad=-1;
 return bad?-1:0;
}
int ts_drain(struct ts_session *s) {
 if(owned(s,TS_STAGE_DRAIN))return -1;
 if(s->drain_attempted)return fail(s,TS_STAGE_DRAIN,TS_INVALID,0,0);
 s->drain_attempted=1;
 if(!s->stopped || s->child!=TS_CHILD_REAPED || s->close_attempted)return fail(s,TS_STAGE_DRAIN,TS_INCOMPLETE,0,0);
 uint64_t d=deadline(s);if(before(s,TS_STAGE_DRAIN,d))return -1;
 s->consuming=s->draining=1;s->consume_failed=0;int e=0;
 int rc=s->operations.drain_fn(s->operations.context,d,consume,s,&e);
 s->consuming=s->draining=0;int bad=s->consume_failed;
 if(after(s,TS_STAGE_DRAIN,d,rc,e))bad=1;
 if(!s->terminal_count || !s->end_count){fail(s,TS_STAGE_DRAIN,TS_INCOMPLETE,0,0);bad=1;}
 s->drained=!bad;return bad?-1:0;
}
int ts_close(struct ts_session *s) {
 if(owned(s,TS_STAGE_CLOSE))return -1;
 if(s->close_attempted)return fail(s,TS_STAGE_CLOSE,TS_INVALID,0,0);
 s->close_attempted=1;uint64_t d=deadline(s);int bad=before(s,TS_STAGE_CLOSE,d),e=0,rc=0;
 if(s->backend_touched)rc=s->operations.close_fn(s->operations.context,d,&e);
 s->closed=rc==0&&e==0;
 if(after(s,TS_STAGE_CLOSE,d,rc,e))bad=-1;
 return bad?-1:0;
}
int ts_parent_close_result(struct ts_session *s,int error) {
 if(owned(s,TS_STAGE_PARENT))return -1;
 if(s->parent_close_seen || error<0 || s->child!=TS_CHILD_REAPED)return fail(s,TS_STAGE_PARENT,TS_INVALID,0,0);
 s->parent_close_seen=1;s->parent_closed=!error;
 int bad=0;if(error){fail(s,TS_STAGE_PARENT,TS_PARENT_FAILURE,error,0);bad=1;}
 if(before(s,TS_STAGE_PARENT,deadline(s)))bad=1;
 return bad?-1:0;
}
int ts_finalization_safe(const struct ts_session *s) {
 return s && s->tag==TS_TAG && s->child==TS_CHILD_REAPED && s->closed && s->gate_closed && s->parent_closed;
}
int ts_success_eligible(const struct ts_session *s) {
 return ts_finalization_safe(s) && s->error.reason==TS_OK && s->cleanup_error.reason==TS_OK &&
 s->initialized && s->cleanup_bound && s->started && s->provider_ready==1 && s->begin_count==1 && s->go_complete && s->bootstrap_sealed &&
 !s->wait_status && !s->kill_claimed && s->terminal_count==1 && s->end_count==1 && s->stopped && s->drained;
}
