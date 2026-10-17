/* Pure injected callbacks only: no fork, exec, signal, wait, FD or trace API. */
#include "trace_session.h"
#include <assert.h>
#include <errno.h>
#include <stdio.h>
#include <string.h>

struct model {
 struct ts_binding binding; uint32_t owner; uint64_t now, expected_deadline;
 uint64_t start_advance,pump_advance,drain_advance;
 unsigned starts,pumps,stops,drains,closes;
 int start_error,pump_error,stop_error,drain_error,close_error,clock_error,odd_pump,null_event;
 enum ts_event_kind queued[16],final[16];size_t queued_count,final_count;
 unsigned wrong_binding,bulk_events;
};
static uint32_t owner(void *v,int *e){(void)e;return ((struct model*)v)->owner;}
static int clock_now(void *v,uint64_t *now,int *e){struct model*m=v;if(m->clock_error){*e=m->clock_error;return -1;}*now=m->now;return 0;}
static int start(void*v,const struct ts_binding*b,uint64_t d,int*e){struct model*m=v;m->starts++;assert(d==m->expected_deadline);assert(b->owner_pid==100&&b->target_pid==200&&b->fixture==1);assert(!memcmp(b->request_sha256,m->binding.request_sha256,32));assert(!memcmp(b->catalog_sha256,m->binding.catalog_sha256,32));m->now+=m->start_advance;if(m->start_error){*e=m->start_error;return -1;}return 0;}
static int emit(struct model*m,enum ts_event_kind kind,ts_consume_fn consume,void*context){struct ts_event event={kind,m->binding};switch(m->wrong_binding){case 1:event.binding.fixture++;break;case 2:event.binding.owner_pid++;break;case 3:event.binding.target_pid++;break;case 4:event.binding.request_sha256[7]^=1;break;case 5:event.binding.catalog_sha256[17]^=1;break;default:break;}return consume(context,&event);}
static int pump(void*v,enum ts_phase phase,uint64_t d,ts_consume_fn consume,void*context,int*e){struct model*m=v;m->pumps++;assert(phase==TS_BOOTSTRAP||phase==TS_WAITING||phase==TS_CLEANUP);assert(d==m->expected_deadline);m->now+=m->pump_advance;if(m->pump_error){*e=m->pump_error;return -1;}if(m->odd_pump)return 2;if(m->null_event){(void)consume(context,NULL);return 0;}size_t count=m->queued_count;m->queued_count=0;for(size_t i=0;i<count;i++)if(emit(m,m->queued[i],consume,context)){*e=EPROTO;return -1;}for(unsigned i=0;i<m->bulk_events;i++)if(emit(m,TS_ACTIVITY,consume,context)){*e=EPROTO;return -1;}return 0;}
static int stop(void*v,uint64_t d,int*e){struct model*m=v;m->stops++;assert(d==m->expected_deadline);if(m->stop_error){*e=m->stop_error;return -1;}return 0;}
static int drain(void*v,uint64_t d,ts_consume_fn consume,void*context,int*e){struct model*m=v;m->drains++;assert(d==m->expected_deadline);m->now+=m->drain_advance;for(size_t i=0;i<m->final_count;i++)if(emit(m,m->final[i],consume,context)){*e=EPROTO;return -1;}if(m->drain_error){*e=m->drain_error;return -1;}return 0;}
static int close_backend(void*v,uint64_t d,int*e){struct model*m=v;m->closes++;assert(d==m->expected_deadline);if(m->close_error){*e=m->close_error;return -1;}return 0;}
static struct ts_operations operations(struct model*m){struct ts_operations o={m,owner,clock_now,start,pump,stop,drain,close_backend};return o;}
static void initial(struct ts_session*s,struct model*m,unsigned cleanup){memset(s,0,sizeof(*s));memset(m,0,sizeof(*m));m->binding.fixture=1;m->binding.owner_pid=m->owner=100;m->binding.target_pid=200;memset(m->binding.request_sha256,17,32);memset(m->binding.catalog_sha256,34,32);m->now=UINT64_C(100000000);m->expected_deadline=UINT64_C(1000000000);m->final[0]=TS_TERMINAL;m->final[1]=TS_END;m->final_count=2;struct ts_operations o=operations(m);assert(!ts_init(s,&m->binding,m->expected_deadline,cleanup,&o));}
static void setup(struct ts_session*s,struct model*m){initial(s,m,200);assert(!ts_start(s));}
static void enqueue(struct model*m,enum ts_event_kind a,enum ts_event_kind b){m->queued[0]=a;m->queued_count=1;if(b){m->queued[1]=b;m->queued_count=2;}}
static void armed(struct ts_session*s,struct model*m){setup(s,m);enqueue(m,TS_PROVIDER_READY,TS_BEGIN);assert(!ts_pump(s,TS_BOOTSTRAP));}
static void released(struct ts_session*s,struct model*m){armed(s,m);assert(!ts_claim_go(s));assert(s->go_possibly_released);assert(!ts_go_result(s,64,0));assert(!ts_gate_close_result(s,0));assert(!ts_bootstrap_sealed(s));}
static void cleanup(struct ts_session*s,struct model*m){m->expected_deadline=m->now+UINT64_C(100000000);assert(!ts_begin_cleanup(s,m->expected_deadline));}
static void finish(struct ts_session*s,struct model*m){assert(s->child==TS_CHILD_REAPED);cleanup(s,m);assert(!ts_pump(s,TS_CLEANUP));assert(!ts_stop(s));assert(!ts_drain(s));assert(!ts_parent_close_result(s,0));assert(!ts_close(s));}
static int same_error(const struct ts_error*a,const struct ts_error*b){return a->stage==b->stage&&a->reason==b->reason&&a->system_errno==b->system_errno&&a->detail==b->detail;}

static void success(void){struct ts_session s;struct model m;released(&s,&m);enqueue(&m,TS_ACTIVITY,0);assert(!ts_pump(&s,TS_WAITING));assert(!ts_child_reaped(&s,0));assert(!s.terminal_count&&!ts_kill_eligible(&s));assert(!ts_finalization_safe(&s));finish(&s,&m);assert(ts_finalization_safe(&s)&&ts_success_eligible(&s));assert(m.starts==1&&m.stops==1&&m.drains==1&&m.closes==1);assert(s.attempt_deadline_ns==UINT64_C(1000000000));assert(s.pump_calls[TS_BOOTSTRAP]==1&&s.pump_calls[TS_WAITING]==1&&s.pump_calls[TS_CLEANUP]==1);}
static void readiness(void){struct ts_session s;struct model m;
 setup(&s,&m);assert(ts_claim_go(&s)&&!s.go_possibly_released);
 setup(&s,&m);enqueue(&m,TS_PROVIDER_READY,0);assert(!ts_pump(&s,TS_BOOTSTRAP));assert(ts_claim_go(&s)&&!s.go_possibly_released);
 setup(&s,&m);enqueue(&m,TS_BEGIN,0);assert(ts_pump(&s,TS_BOOTSTRAP)&&s.error.reason==TS_EVENT_ORDER);assert(ts_claim_go(&s)&&!s.go_possibly_released);
 armed(&s,&m);enqueue(&m,TS_BEGIN,0);assert(ts_pump(&s,TS_BOOTSTRAP));assert(ts_claim_go(&s)&&!s.go_possibly_released);
 armed(&s,&m);enqueue(&m,TS_PROVIDER_READY,0);assert(ts_pump(&s,TS_BOOTSTRAP));assert(ts_claim_go(&s)&&!s.go_possibly_released);
 for(unsigned which=1;which<=5;which++){setup(&s,&m);m.wrong_binding=which;enqueue(&m,TS_PROVIDER_READY,TS_BEGIN);assert(ts_pump(&s,TS_BOOTSTRAP)&&s.error.reason==TS_BAD_BINDING);assert(ts_claim_go(&s)&&!s.go_possibly_released);}
 setup(&s,&m);enqueue(&m,TS_PROVIDER_READY,TS_BEGIN);m.pump_advance=m.expected_deadline-m.now;assert(ts_pump(&s,TS_BOOTSTRAP)&&s.error.reason==TS_DEADLINE);assert(ts_claim_go(&s)&&!s.go_possibly_released);
 setup(&s,&m);m.now=m.expected_deadline;assert(ts_pump(&s,TS_BOOTSTRAP)&&m.pumps==0);assert(ts_claim_go(&s)&&!s.go_possibly_released);
 setup(&s,&m);enqueue(&m,(enum ts_event_kind)99,0);assert(ts_pump(&s,TS_BOOTSTRAP));
 armed(&s,&m);enqueue(&m,TS_TERMINAL,0);assert(ts_pump(&s,TS_WAITING));assert(ts_claim_go(&s)&&!s.go_possibly_released);
}
static void deadlines(void){struct ts_session s;struct model m;
 setup(&s,&m);m.now++;assert(!ts_pump(&s,TS_WAITING));m.now--;assert(ts_pump(&s,TS_WAITING)&&s.error.reason==TS_CLOCK_ROLLBACK);
 setup(&s,&m);m.clock_error=EIO;assert(ts_pump(&s,TS_BOOTSTRAP)&&s.error.reason==TS_CLOCK);
 setup(&s,&m);m.pump_error=EIO;m.pump_advance=m.expected_deadline-m.now;assert(ts_pump(&s,TS_BOOTSTRAP));assert(s.error.reason==TS_BACKEND&&s.error.system_errno==EIO);
 initial(&s,&m,200);m.start_advance=m.expected_deadline-m.now;assert(ts_start(&s)&&s.started&&s.error.reason==TS_DEADLINE);assert(ts_start(&s)&&m.starts==1);
 initial(&s,&m,25);assert(!ts_start(&s));assert(ts_bootstrap_failed(&s,0,EPROTO));m.expected_deadline=m.now+UINT64_C(26000000);assert(ts_begin_cleanup(&s,m.expected_deadline)&&!s.cleanup_bound);assert(ts_begin_cleanup(&s,m.now+1)&&!s.cleanup_bound);
 initial(&s,&m,25);assert(!ts_start(&s));assert(ts_bootstrap_failed(&s,0,EPROTO));m.expected_deadline=m.now+UINT64_C(10000000);assert(!ts_begin_cleanup(&s,m.expected_deadline));uint64_t fixed=s.cleanup_deadline_ns;assert(!ts_pump(&s,TS_CLEANUP));m.pump_error=EINTR;assert(ts_pump(&s,TS_CLEANUP));assert(s.cleanup_deadline_ns==fixed&&s.attempt_deadline_ns==UINT64_C(1000000000));assert(ts_begin_cleanup(&s,m.now+1)&&s.cleanup_deadline_ns==fixed);
 released(&s,&m);m.expected_deadline=m.now+UINT64_C(100000000);assert(ts_begin_cleanup(&s,m.expected_deadline)&&s.cleanup_bound);assert(s.error.reason==TS_INCOMPLETE);m.now=UINT64_C(1000000001);assert(ts_child_reaped(&s,0));assert(!ts_success_eligible(&s));
 released(&s,&m);assert(!ts_child_reaped(&s,0));cleanup(&s,&m);assert(!ts_stop(&s));assert(!ts_drain(&s));assert(!ts_close(&s));m.now=m.expected_deadline;assert(ts_parent_close_result(&s,0)&&s.parent_closed);assert(ts_finalization_safe(&s)&&!ts_success_eligible(&s));
}
static void go_once(void){struct ts_session s;struct model m;
 const size_t counts[]={0,1,63,64};for(unsigned i=0;i<4;i++){armed(&s,&m);assert(!ts_claim_go(&s));assert(ts_go_result(&s,counts[i],EIO));assert(s.go_possibly_released&&s.go_bytes==counts[i]&&!s.go_complete);assert(ts_claim_go(&s));assert(ts_go_result(&s,64,0)&&s.go_bytes==counts[i]);}
 armed(&s,&m);assert(!ts_claim_go(&s));m.now=m.expected_deadline;assert(ts_go_result(&s,64,0)&&s.go_bytes==64&&!s.go_complete);assert(ts_claim_go(&s));
 armed(&s,&m);assert(!ts_claim_go(&s));assert(ts_go_failed(&s,64,0));assert(s.go_bytes==64&&!s.go_complete&&s.error.reason==TS_PARENT_FAILURE&&s.error.system_errno==0);assert(ts_go_result(&s,64,0));assert(ts_go_failed(&s,64,0));assert(ts_claim_go(&s));
 armed(&s,&m);assert(!ts_gate_close_result(&s,0));assert(ts_claim_go(&s)&&!s.go_possibly_released);
 armed(&s,&m);assert(!ts_claim_go(&s));assert(!ts_go_result(&s,64,0));assert(ts_gate_close_result(&s,EIO));assert(ts_gate_close_result(&s,0)&&!s.gate_closed);
}
static void bootstrap(void){struct ts_session s;struct model m;const size_t prefixes[]={0,1,255,256,511,512,769};
 for(unsigned i=0;i<7;i++){armed(&s,&m);assert(!ts_claim_go(&s));assert(!ts_go_result(&s,64,0));assert(!ts_gate_close_result(&s,0));assert(ts_bootstrap_failed(&s,prefixes[i],EPROTO));assert(s.bootstrap_prefix_bytes==prefixes[i]&&!s.bootstrap_sealed);assert(ts_bootstrap_sealed(&s));assert(ts_claim_go(&s));}
 armed(&s,&m);assert(!ts_claim_go(&s));assert(!ts_go_result(&s,64,0));assert(!ts_gate_close_result(&s,0));assert(ts_bootstrap_failed(&s,257,0));assert(s.error.reason==TS_PARENT_FAILURE&&s.error.system_errno==0&&s.error.detail==257&&s.bootstrap_prefix_bytes==257);assert(ts_bootstrap_sealed(&s));
 armed(&s,&m);assert(!ts_claim_go(&s));assert(!ts_go_result(&s,64,0));assert(!ts_gate_close_result(&s,0));assert(!ts_child_reaped(&s,0));finish(&s,&m);assert(ts_finalization_safe(&s)&&!ts_success_eligible(&s));
}
static void cleanup_pumping(void){struct ts_session s;struct model m;armed(&s,&m);assert(!ts_claim_go(&s));assert(!ts_go_result(&s,64,0));assert(!ts_gate_close_result(&s,0));assert(ts_bootstrap_failed(&s,257,EPROTO));struct ts_error original=s.error;cleanup(&s,&m);m.pump_error=EINTR;assert(ts_pump(&s,TS_CLEANUP));m.pump_error=0;enqueue(&m,TS_ACTIVITY,0);assert(!ts_pump(&s,TS_CLEANUP));assert(!ts_claim_kill(&s)&&!ts_kill_eligible(&s));assert(ts_claim_kill(&s));assert(ts_child_reaped(&s,9));assert(!ts_kill_eligible(&s));assert(!ts_stop(&s));assert(!ts_drain(&s));assert(!ts_parent_close_result(&s,0));assert(!ts_close(&s));assert(same_error(&original,&s.error));assert(s.cleanup_error.reason==TS_BACKEND&&s.cleanup_error.system_errno==EINTR);assert(ts_finalization_safe(&s)&&!ts_success_eligible(&s));}
static void wait_ownership(void){struct ts_session s;struct model m;
 released(&s,&m);m.now=m.expected_deadline;assert(ts_child_reaped(&s,0));assert(s.child==TS_CHILD_REAPED&&!ts_kill_eligible(&s));assert(ts_claim_kill(&s));
 released(&s,&m);m.owner=101;assert(ts_child_reaped(&s,0));assert(s.child==TS_CHILD_REAPED&&s.error.reason==TS_WRONG_OWNER);m.owner=100;assert(!ts_kill_eligible(&s)&&ts_claim_kill(&s));
 released(&s,&m);m.owner=101;assert(ts_child_lost(&s));assert(s.child==TS_CHILD_LOST&&s.error.reason==TS_LOST_CHILD);m.owner=100;assert(!ts_kill_eligible(&s)&&ts_claim_kill(&s));
 released(&s,&m);assert(ts_child_lost(&s));assert(s.child==TS_CHILD_LOST&&!ts_kill_eligible(&s));assert(ts_claim_kill(&s));cleanup(&s,&m);assert(!ts_stop(&s));assert(ts_drain(&s)&&m.drains==0);assert(!ts_close(&s)&&m.closes==1);assert(!ts_finalization_safe(&s));
}
static void backend_faults(void){struct ts_session s;struct model m;
 initial(&s,&m,200);m.start_error=EIO;assert(ts_start(&s)&&m.starts==1&&s.backend_touched);assert(ts_start(&s)&&m.starts==1);assert(ts_bootstrap_failed(&s,0,EPROTO));assert(!ts_gate_close_result(&s,0));assert(ts_child_reaped(&s,9));cleanup(&s,&m);assert(ts_stop(&s)&&m.stops==0);assert(!ts_parent_close_result(&s,0));assert(!ts_close(&s)&&m.closes==1&&ts_finalization_safe(&s));assert(!ts_success_eligible(&s));
 const enum ts_event_kind bad[]={TS_DROP,TS_BACKEND_FAULT,TS_OUTPUT_FAULT};const enum ts_reason reasons[]={TS_DROPPED,TS_BACKEND,TS_OUTPUT};for(unsigned i=0;i<3;i++){armed(&s,&m);enqueue(&m,bad[i],0);assert(ts_pump(&s,TS_BOOTSTRAP)&&s.error.reason==reasons[i]);assert(ts_claim_go(&s)&&!s.go_possibly_released);}
 setup(&s,&m);m.odd_pump=1;assert(ts_pump(&s,TS_BOOTSTRAP)&&s.error.reason==TS_INVALID);
 setup(&s,&m);m.null_event=1;assert(ts_pump(&s,TS_BOOTSTRAP)&&s.error.reason==TS_INVALID&&s.consume_failed);
 released(&s,&m);assert(!ts_child_reaped(&s,0));cleanup(&s,&m);m.stop_error=EIO;assert(ts_stop(&s));assert(ts_stop(&s)&&m.stops==1);assert(ts_drain(&s)&&m.drains==0);assert(!ts_parent_close_result(&s,0));assert(!ts_close(&s));assert(ts_finalization_safe(&s)&&!ts_success_eligible(&s));
 released(&s,&m);assert(!ts_child_reaped(&s,0));cleanup(&s,&m);assert(!ts_stop(&s));m.drain_error=EIO;assert(ts_drain(&s));assert(ts_drain(&s)&&m.drains==1);assert(!ts_parent_close_result(&s,0));assert(!ts_close(&s));assert(ts_finalization_safe(&s)&&!ts_success_eligible(&s));
 released(&s,&m);assert(!ts_child_reaped(&s,0));cleanup(&s,&m);assert(!ts_stop(&s));assert(!ts_drain(&s));assert(!ts_parent_close_result(&s,0));m.close_error=EIO;assert(ts_close(&s));assert(ts_close(&s)&&m.closes==1);assert(!ts_finalization_safe(&s)&&!ts_success_eligible(&s));
 released(&s,&m);assert(!ts_child_reaped(&s,0));cleanup(&s,&m);assert(!ts_stop(&s));m.drain_advance=m.expected_deadline-m.now;assert(ts_drain(&s)&&!s.drained);assert(ts_parent_close_result(&s,0)&&s.parent_closed);assert(ts_close(&s)&&s.closed&&m.closes==1);assert(ts_finalization_safe(&s)&&!ts_success_eligible(&s));
}
static void drain_order(void){struct ts_session s;struct model m;
 released(&s,&m);enqueue(&m,TS_TERMINAL,0);assert(!ts_pump(&s,TS_WAITING));assert(!ts_child_reaped(&s,0));m.final[0]=TS_END;m.final_count=1;finish(&s,&m);assert(ts_success_eligible(&s));
 for(unsigned variant=0;variant<4;variant++){released(&s,&m);assert(!ts_child_reaped(&s,0));cleanup(&s,&m);assert(!ts_stop(&s));if(variant==0)m.final_count=0;else if(variant==1){m.final[0]=TS_END;m.final_count=1;}else if(variant==2){m.final[0]=TS_TERMINAL;m.final[1]=TS_TERMINAL;}else {m.final[0]=TS_TERMINAL;m.final[1]=TS_END;m.final[2]=TS_ACTIVITY;m.final_count=3;}assert(ts_drain(&s)&&!s.drained);assert(!ts_parent_close_result(&s,0));assert(!ts_close(&s));assert(ts_finalization_safe(&s)&&!ts_success_eligible(&s));}
}
static void boundaries(void){struct ts_session s;struct model m;initial(&s,&m,200);struct ts_binding b=m.binding;struct ts_operations o=operations(&m);struct ts_session invalid={0};b.fixture=2;assert(ts_init(&invalid,&b,m.expected_deadline,200,&o)&&!ts_kill_eligible(&invalid));assert(ts_start(&invalid)&&m.starts==0);assert(ts_close(&invalid)&&m.closes==0);
 b=m.binding;memset(&invalid,0,sizeof(invalid));o.clock_fn=NULL;assert(ts_init(&invalid,&b,m.expected_deadline,200,&o));assert(ts_close(&invalid)&&m.closes==0);
 setup(&s,&m);m.owner=101;assert(ts_pump(&s,TS_BOOTSTRAP)&&m.pumps==0&&s.error.reason==TS_WRONG_OWNER);
 initial(&s,&m,200);m.binding.request_sha256[0]^=1;assert(s.binding.request_sha256[0]==17);m.binding.request_sha256[0]^=1;assert(!ts_start(&s));
 setup(&s,&m);assert(ts_start(&s)&&m.starts==1);assert(ts_pump(&s,TS_CLEANUP)&&m.pumps==0);
 armed(&s,&m);for(unsigned i=1;i<TS_MAX_PUMPS;i++)assert(!ts_pump(&s,TS_BOOTSTRAP));assert(ts_pump(&s,TS_BOOTSTRAP)&&m.pumps==TS_MAX_PUMPS&&s.error.reason==TS_LIMIT);
 armed(&s,&m);m.bulk_events=TS_MAX_EVENTS;assert(ts_pump(&s,TS_BOOTSTRAP)&&s.error.reason==TS_LIMIT);
 /* A trusted READY caller already owns this fixed child even when session
  * initialization fails only on owner/time observation. Cleanup must survive. */
 for(unsigned fault=0;fault<3;fault++){initial(&s,&m,200);struct ts_session early={0};o=operations(&m);if(fault==0)m.clock_error=EIO;else if(fault==1)m.now=m.expected_deadline;else m.owner=101;assert(ts_init(&early,&m.binding,m.expected_deadline,200,&o));assert(early.configured&&!early.initialized&&ts_kill_eligible(&early));struct ts_error first=early.error;if(fault==2)assert(ts_claim_kill(&early));m.clock_error=0;m.owner=100;assert(!ts_claim_kill(&early)&&!ts_kill_eligible(&early));(void)ts_gate_close_result(&early,0);assert(ts_child_reaped(&early,9));cleanup(&early,&m);assert(!ts_parent_close_result(&early,0));assert(!ts_close(&early)&&m.closes==0&&m.starts==0);assert(ts_finalization_safe(&early)&&!ts_success_eligible(&early)&&same_error(&first,&early.error));}
}
int main(int argc,char**argv){assert(argc==2);if(!strcmp(argv[1],"success"))success();else if(!strcmp(argv[1],"readiness"))readiness();else if(!strcmp(argv[1],"deadlines"))deadlines();else if(!strcmp(argv[1],"go"))go_once();else if(!strcmp(argv[1],"bootstrap"))bootstrap();else if(!strcmp(argv[1],"cleanup"))cleanup_pumping();else if(!strcmp(argv[1],"wait"))wait_ownership();else if(!strcmp(argv[1],"backend"))backend_faults();else if(!strcmp(argv[1],"drain"))drain_order();else if(!strcmp(argv[1],"boundaries"))boundaries();else return 2;puts(argv[1]);return 0;}
