/* Source-isolated libdtrace boundary controls. Never links or runs libdtrace. */
#define _POSIX_C_SOURCE 200809L
#define _DARWIN_C_SOURCE 1
#include <assert.h>
#include <dtrace.h>
#include <errno.h>
#include <fcntl.h>
#include <stdint.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <sys/stat.h>
#include <time.h>
#include <unistd.h>
static uint64_t model_now=UINT64_C(1000000000);
static int clock_failure,close_failure,write_failure_fd=-1,write_expire_fd=-1,write_zero_fd=-1,write_eintr_fd=-1,owned_closes;
static uint64_t write_expire_time;
static int close_failure_at;
static int model_clock(clockid_t c,struct timespec *t) {
 assert(c==CLOCK_MONOTONIC);
 if(clock_failure==1 || clock_failure==2){errno=clock_failure==2?EOVERFLOW:EIO;return -1;}
 if(clock_failure==3){t->tv_sec=1;t->tv_nsec=1000000000L;return 0;}
 t->tv_sec=(time_t)(model_now/1000000000);t->tv_nsec=(long)(model_now%1000000000);return 0;
}
static int model_close(int fd) {
 owned_closes++;int rc=close(fd);assert(!rc);
 if(close_failure || owned_closes==close_failure_at){close_failure=0;close_failure_at=0;errno=EINTR;return -1;}return 0;
}
static ssize_t model_write(int fd,const void *p,size_t n) {
 if(fd==write_expire_fd){write_expire_fd=-1;model_now=write_expire_time;errno=EINTR;return -1;}
 if(fd==write_zero_fd)return 0;
 if(fd==write_eintr_fd){errno=EINTR;return -1;}
 if(fd==write_failure_fd){errno=ENOSPC;return -1;}return write(fd,p,n);
}
#define clock_gettime model_clock
#define close model_close
#define write model_write
#include "owned_trace_backend.c"
#undef clock_gettime
#undef close
#undef write

static dtrace_probedesc_t probes[19];
static int opened,went,stopped,library_closed,work_calls,open_failure,missing_mach,work_done,work_drop,work_fault;
static unsigned match_count=17;
enum statement_mode { ST_NORMAL,ST_MISSING,ST_EXTRA,ST_DUPLICATE,ST_ALIAS_PROVIDER,
 ST_ID,ST_MODULE,ST_FUNCTION,ST_NAME,ST_UNTERMINATED,ST_NULL,ST_NULL_ECB,ST_BOUND,
 ST_FAIL,ST_EXPIRE,ST_CLOCK,ST_WRONG_HANDLE,ST_WRONG_PROGRAM,ST_EXPIRE_AFTER,ST_EXACT_BOUND };
enum match_mode { MT_NORMAL,MT_EMPTY,MT_ZERO_ID,MT_DUPLICATE_ID,MT_DUPLICATE_NAME,
 MT_WRONG_KIND,MT_INVALID_NAME,MT_UNTERMINATED,MT_BOUND,MT_FAIL,MT_EXPIRE,MT_CLOCK,
 MT_WRONG_HANDLE,MT_BEGIN_PROVIDER,MT_NULL,MT_EXPIRE_AFTER,MT_EXACT_BOUND };
static enum statement_mode statement_mode;
static enum match_mode match_mode;
static dtrace_ecbdesc_t compiled_selectors[19],extra_selector;
static unsigned compiled_calls,statement_calls,probe_iterations,compile_additions,exec_calls;
static int work_override;
static dtrace_handle_drop_f *drop_callback;static dtrace_handle_err_f *error_callback;static void *backend_context;
struct queued {unsigned kind,epid;int bad_action,bad_offset,bad_count,bad_inventory;uint64_t pid,detail,refcount;};
static struct queued queue[32];static unsigned queued_count;
static void make_probes(void) {
 memset(probes,0,sizeof(probes));
 const char *proc_names[]={"create","start","exit","exec-success","exec-failure","lwp-create","lwp-start","lwp-exit","spawn-success","spawn-failure"};
 for(unsigned k=1;k<=18;k++) {
  if(k==14)continue;dtrace_probedesc_t *p=&probes[k];p->dtpd_id=100+k;
  const char *provider=k==1||k==17?"dtrace":k==2||k==3?"syscall":k==15||k==16?"mach_trap":"proc";
  snprintf(p->dtpd_provider,sizeof(p->dtpd_provider),"%s",provider);
  if(k==2||k==3||k==15||k==16)snprintf(p->dtpd_func,sizeof(p->dtpd_func),"%s",k<4?"read":"mach_msg2_trap");
  const char *name=k==1?"BEGIN":k==17?"END":k==18?"exited":k==2||k==15?"entry":k==3||k==16?"return":proc_names[k-4];
  snprintf(p->dtpd_name,sizeof(p->dtpd_name),"%s",name);
 }
 memset(compiled_selectors,0,sizeof(compiled_selectors));
 for(unsigned k=1;k<=18;k++)if(k!=14) {
  compiled_selectors[k].dted_probe=probes[k];
  compiled_selectors[k].dted_probe.dtpd_id=DTRACE_IDNONE;
  compiled_selectors[k].dted_probe.dtpd_func[0]=0;
  if(k==1||k==17)compiled_selectors[k].dted_probe.dtpd_provider[0]=0;
 }
}
dtrace_hdl_t *dtrace_open(int version,int flags,int *error) {
 assert(version==DTRACE_VERSION&&flags==DTRACE_O_LP64);opened++;
 if(open_failure){*error=8123;return NULL;}*error=0;return (dtrace_hdl_t *)(uintptr_t)1;
}
void dtrace_close(dtrace_hdl_t *h) {assert(h==(dtrace_hdl_t *)(uintptr_t)1);library_closed++;}
int dtrace_handle_drop(dtrace_hdl_t *h,dtrace_handle_drop_f *f,void *c) {(void)h;drop_callback=f;backend_context=c;return 0;}
int dtrace_handle_err(dtrace_hdl_t *h,dtrace_handle_err_f *f,void *c) {(void)h;error_callback=f;assert(c==backend_context);return 0;}
int dtrace_setopt(dtrace_hdl_t *h,const char *key,const char *value) {(void)h;assert(key&&value);return 0;}
int dtrace_probe_iter(dtrace_hdl_t *h,const dtrace_probedesc_t *wanted,dtrace_probe_f *f,void *c) {
 assert(compiled_calls==1&&wanted&&!wanted->dtpd_id&&!wanted->dtpd_mod[0]&&!wanted->dtpd_func[0]);probe_iterations++;
 unsigned selected=0;
 for(unsigned k=1;k<=18;k++)if(k!=14) {
  const char *provider=k==1||k==17?"":probes[k].dtpd_provider;
  if(!strcmp(wanted->dtpd_provider,provider)&&!strcmp(wanted->dtpd_name,probes[k].dtpd_name))selected=k;
 }
 assert(selected);
 if(selected==2&&match_mode==MT_FAIL)return -1;
 if((selected==2&&match_mode==MT_EMPTY)||(missing_mach&&(selected==15||selected==16)))return 0;
 dtrace_probedesc_t p=probes[selected];
 if(selected==1&&match_mode==MT_BEGIN_PROVIDER)strcpy(p.dtpd_provider,"other");
 if(selected==2) {
  if(match_mode==MT_ZERO_ID)p.dtpd_id=0;
  if(match_mode==MT_WRONG_KIND)p=probes[3];
  if(match_mode==MT_INVALID_NAME)strcpy(p.dtpd_func,"bad/name");
  if(match_mode==MT_UNTERMINATED)memset(p.dtpd_func,'x',sizeof(p.dtpd_func));
  if(match_mode==MT_EXPIRE)model_now=((struct otb_backend *)backend_context)->view.original_attempt_deadline_ns;
  if(match_mode==MT_CLOCK)clock_failure=1;
 }
 if(f(selected==2&&match_mode==MT_WRONG_HANDLE?NULL:h,selected==2&&match_mode==MT_NULL?NULL:&p,c))return -1;
 if(selected==2&&(match_mode==MT_DUPLICATE_ID||match_mode==MT_DUPLICATE_NAME)) {
  if(match_mode==MT_DUPLICATE_ID)strcpy(p.dtpd_func,"another");else p.dtpd_id+=1000;
  if(f(h,&p,c))return -1;
 }
 if(selected==2&&compile_additions) {
  p=probes[2];p.dtpd_id=900;strcpy(p.dtpd_func,"created_during_compile");if(f(h,&p,c))return -1;
 }
 if(selected==2&&(match_mode==MT_BOUND||match_mode==MT_EXACT_BOUND))for(unsigned i=0;
     i<(match_mode==MT_BOUND?OTB_MAX_PROBES:OTB_MAX_PROBES-17);i++) {
  p=probes[2];p.dtpd_id=1000+i;snprintf(p.dtpd_func,sizeof(p.dtpd_func),"bounded_%u",i);
  if(f(h,&p,c))return -1;
 }
 if(selected==2&&match_mode==MT_EXPIRE_AFTER)model_now=((struct otb_backend *)backend_context)->view.original_attempt_deadline_ns;
 return 0;
}
dtrace_prog_t *dtrace_program_strcompile(dtrace_hdl_t *h,const char *program,dtrace_probespec_t spec,uint_t flags,int argc,char *const argv[]) {
 (void)h;assert(spec==DTRACE_PROBESPEC_NAME&&!flags&&!argc&&!argv);
 assert(strstr(program,"mach_trap:::entry")&&strstr(program,"mach_trap:::return"));
 assert(strstr(program,"p_refcount")&&!strstr(program,"copyinstr")&&!strstr(program,"syscall::open"));
 assert(!probe_iterations);compiled_calls++;
 return (dtrace_prog_t *)(uintptr_t)2;
}
int dtrace_stmt_iter(dtrace_hdl_t *h,dtrace_prog_t *p,dtrace_stmt_f *f,void *c) {
 assert(compiled_calls==1&&p==(dtrace_prog_t *)(uintptr_t)2);statement_calls++;
 if(statement_mode==ST_FAIL)return -1;
 if(statement_mode==ST_DUPLICATE)compiled_selectors[2].dted_probe=compiled_selectors[1].dted_probe;
 if(statement_mode==ST_ALIAS_PROVIDER)strcpy(compiled_selectors[1].dted_probe.dtpd_provider,"dtrace");
 if(statement_mode==ST_ID)compiled_selectors[1].dted_probe.dtpd_id=101;
 if(statement_mode==ST_MODULE)strcpy(compiled_selectors[1].dted_probe.dtpd_mod,"kernel");
 if(statement_mode==ST_FUNCTION)strcpy(compiled_selectors[1].dted_probe.dtpd_func,"function");
 if(statement_mode==ST_NAME)strcpy(compiled_selectors[1].dted_probe.dtpd_name,"ERROR");
 if(statement_mode==ST_UNTERMINATED)memset(compiled_selectors[1].dted_probe.dtpd_name,'x',sizeof(compiled_selectors[1].dted_probe.dtpd_name));
 dtrace_stmtdesc_t statement={0};statement.dtsd_ecbdesc=&compiled_selectors[1];
 if(statement_mode==ST_NULL)return f(h,p,NULL,c);
 if(statement_mode==ST_NULL_ECB){statement.dtsd_ecbdesc=NULL;return f(h,p,&statement,c);}
 if(statement_mode==ST_EXPIRE)model_now=((struct otb_backend *)backend_context)->view.original_attempt_deadline_ns;
 if(statement_mode==ST_CLOCK)clock_failure=1;
 if(statement_mode==ST_BOUND) {
  for(unsigned i=0;i<513;i++)if(f(h,p,&statement,c))return -1;
  assert(0);
 }
 for(unsigned k=1;k<=18;k++)if(k!=14&&!(statement_mode==ST_MISSING&&k==17)) {
  statement.dtsd_ecbdesc=&compiled_selectors[k];
  /* Two action statements share each ECB; neither duplicates its matches. */
  for(unsigned action=0;action<(statement_mode==ST_EXACT_BOUND&&k==1?480u:2u);action++)if(f(statement_mode==ST_WRONG_HANDLE?NULL:h,
      statement_mode==ST_WRONG_PROGRAM?NULL:p,&statement,c))return -1;
 }
 if(statement_mode==ST_EXPIRE_AFTER)model_now=((struct otb_backend *)backend_context)->view.original_attempt_deadline_ns;
 if(statement_mode==ST_EXTRA) {
  extra_selector=compiled_selectors[1];statement.dtsd_ecbdesc=&extra_selector;return f(h,p,&statement,c);
 }
 return 0;
}
int dtrace_program_exec(dtrace_hdl_t *h,dtrace_prog_t *p,dtrace_proginfo_t *info) {(void)h;assert(p==(dtrace_prog_t *)(uintptr_t)2);exec_calls++;info->dpi_matches=match_count;return 0;}
int dtrace_go(dtrace_hdl_t *h) {(void)h;went++;return 0;}
int dtrace_stop(dtrace_hdl_t *h) {(void)h;stopped++;return 0;}
int dtrace_errno(dtrace_hdl_t *h) {(void)h;return 8123;}
const char *dtrace_errmsg(dtrace_hdl_t *h,int e) {(void)h;assert(e==8123);return "model provider unavailable";}
static int deliver(dtrace_consume_probe_f *consume,void *context,const struct queued *q) {
 unsigned kind=q->kind;int leading=kind==1||kind==4||kind==5||kind==7;
 unsigned payloads=kind==2||kind==15?13:kind==3?10:kind==18?8:kind==16?6:5;
 dtrace_eprobedesc_t *d=calloc(1,sizeof(*d)+20*sizeof(dtrace_recdesc_t));assert(d);
 d->dtepd_epid=q->epid?q->epid:1000+kind;d->dtepd_probeid=probes[kind].dtpd_id;d->dtepd_size=16+payloads*8;d->dtepd_nrecs=(int)(payloads+(unsigned)leading);
 unsigned char bytes[128]={0};
 uint64_t values[13]={kind,100, q->pid?q->pid:kind==1||kind==17?(uint64_t)getpid():(uint64_t)getpid()+1000,1,q->detail};
 if(!q->detail && (kind==2||kind==3||kind==5||kind==7||kind==15||kind==16))values[4]=(uint64_t)getpid();
 if(kind==18){values[4]=q->detail?q->detail:(uint64_t)getpid()+1000;values[5]=0;values[6]=0x1234;values[7]=q->refcount?q->refcount:0x1c2;}
 for(unsigned i=0;i<payloads+(unsigned)leading;i++) {
  dtrace_recdesc_t *r=&d->dtepd_rec[i];r->dtrd_action=DTRACEACT_DIFEXPR;r->dtrd_size=leading&&!i?0:8;r->dtrd_offset=leading&&!i?12:16+(i-(leading&&i>0))*8;
 }
 for(unsigned i=0;i<payloads;i++)memcpy(bytes+d->dtepd_rec[i+(unsigned)leading].dtrd_offset,&values[i],8);
 if(q->bad_action)d->dtepd_rec[leading].dtrd_action=2;
 if(q->bad_offset)d->dtepd_rec[leading].dtrd_offset++;
 if(q->bad_count)d->dtepd_nrecs++;
 dtrace_probedesc_t p=probes[kind];if(q->bad_inventory)snprintf(p.dtpd_mod,sizeof(p.dtpd_mod),"changed");
 dtrace_probedata_t data={0};data.dtpda_cpu=0;data.dtpda_edesc=d;data.dtpda_pdesc=&p;data.dtpda_data=(char *)bytes;
 int result=consume(&data,context);free(d);return result;
}
dtrace_workstatus_t dtrace_work(dtrace_hdl_t *h,FILE *out,dtrace_consume_probe_f *consume,dtrace_consume_rec_f *record,void *context) {
 (void)h;assert(!out&&!record);work_calls++;
 if(work_override)return (dtrace_workstatus_t)work_override;
 if(work_drop){dtrace_dropdata_t d={0};d.dtdda_drops=2;d.dtdda_total=2;d.dtdda_msg="model drop";assert(drop_callback(&d,backend_context)==DTRACE_HANDLE_ABORT);return DTRACE_WORKSTATUS_ERROR;}
 if(work_fault){dtrace_errdata_t d={0};d.dteda_fault=3;d.dteda_msg="model fault";assert(error_callback(&d,backend_context)==DTRACE_HANDLE_ABORT);return DTRACE_WORKSTATUS_ERROR;}
 for(unsigned i=0;i<queued_count;i++)if(deliver(consume,context,&queue[i])==DTRACE_CONSUME_ABORT){queued_count=0;return DTRACE_WORKSTATUS_ERROR;}
 queued_count=0;return work_done?DTRACE_WORKSTATUS_DONE:DTRACE_WORKSTATUS_OKAY;
}
struct fixture {struct otb_backend *b;struct ts_operations ops;struct ts_binding binding;int directory;char path[128];uint64_t deadline;unsigned delivered[9];};
static void reset(void) {
 model_now=UINT64_C(1000000000);clock_failure=close_failure=0;write_failure_fd=write_expire_fd=write_zero_fd=write_eintr_fd=-1;owned_closes=0;
 close_failure_at=0;
 opened=went=stopped=library_closed=work_calls=open_failure=missing_mach=work_done=work_drop=work_fault=0;
 queued_count=0;make_probes();
 match_count=17;
 statement_mode=ST_NORMAL;match_mode=MT_NORMAL;
 compiled_calls=statement_calls=probe_iterations=compile_additions=exec_calls=0;
 work_override=0;
}
static void initialize(struct fixture *f) {
 memset(f,0,sizeof(*f));snprintf(f->path,sizeof(f->path),"/private/tmp/glue-otb-model-XXXXXX");assert(mkdtemp(f->path));
 f->directory=open(f->path,O_RDONLY|O_DIRECTORY|O_CLOEXEC);assert(f->directory>=0);
 f->binding=(struct ts_binding){TS_OWNED_CONTEXT_PROBE,(uint32_t)getpid(),(uint32_t)getpid()+1000,{1},{2}};f->deadline=model_now+UINT64_C(5000000000);
 struct otb_error e;assert(!otb_create(&f->b,f->directory,&f->binding,f->deadline,1,&f->ops,&e));
}
static int collector(void *context,const struct ts_event *event) {struct fixture *f=context;assert(!memcmp(&event->binding,&f->binding,sizeof(f->binding)));f->delivered[event->kind]++;return 0;}
static void enqueue(unsigned kind) {assert(queued_count<32);queue[queued_count++]=(struct queued){.kind=kind};}
static void begin(struct fixture *f) {int e=0;assert(!f->ops.start_fn(f->b,&f->binding,f->deadline,&e));assert(!f->delivered[TS_PROVIDER_READY]);enqueue(1);assert(!f->ops.pump_fn(f->b,TS_BOOTSTRAP,f->deadline,collector,f,&e));assert(f->delivered[TS_PROVIDER_READY]==1&&f->delivered[TS_BEGIN]==1);}
static void cleanup(struct fixture *f) {
 int e=0;if(f->b){if(!f->b->view.close_attempted)(void)f->ops.close_fn(f->b,f->deadline,&e);assert(!otb_destroy(&f->b));}assert(!close(f->directory));
 for(unsigned i=0;i<4;i++){char path[256];snprintf(path,sizeof(path),"%s/%s",f->path,file_names[i]);if(unlink(path))assert(errno==ENOENT);}
 assert(!rmdir(f->path));
}
static void readiness_and_full_session(void) {
 reset();struct fixture f;initialize(&f);struct ts_session s={0};assert(!ts_init(&s,&f.binding,f.deadline,200,&f.ops));assert(!ts_start(&s));assert(!s.provider_ready&&!s.begin_count);
 enqueue(1);assert(!ts_pump(&s,TS_BOOTSTRAP));assert(s.provider_ready==1&&s.begin_count==1);assert(!ts_claim_go(&s));assert(!ts_go_result(&s,64,0));assert(!ts_gate_close_result(&s,0));assert(!ts_bootstrap_sealed(&s));
 enqueue(15);enqueue(16);enqueue(7);enqueue(2);enqueue(3);enqueue(18);queue[queued_count-1].refcount=0x1e2;
 assert(!ts_pump(&s,TS_WAITING));assert(!s.terminal_count);assert(!ts_child_reaped(&s,0));assert(!ts_begin_cleanup(&s,model_now+UINT64_C(200000000)));
 assert(!ts_stop(&s));enqueue(18);enqueue(18);queue[queued_count-1].refcount=0x1e2;enqueue(11);enqueue(17);work_done=1;
 assert(!ts_drain(&s));assert(!ts_close(&s));assert(!ts_parent_close_result(&s,0));assert(ts_success_eligible(&s));
 struct otb_snapshot v;assert(!otb_snapshot(f.b,&v));assert(v.begin_count==1&&v.terminal_count==1&&v.end_count==1&&v.drained&&v.resources_closed);assert(v.raw_bytes&&v.events==11);assert(stopped==1&&library_closed==1&&owned_closes==4);cleanup(&f);
}
static void rejected_records(void) {
 for(unsigned which=0;which<7;which++) {
  reset();struct fixture f;initialize(&f);begin(&f);enqueue(which==6?18:2);
  if(which==0)queue[0].bad_action=1;if(which==1)queue[0].bad_offset=1;if(which==2)queue[0].bad_count=1;if(which==3)queue[0].bad_inventory=1;
  if(which==4)queue[0].pid=(uint64_t)getpid()+2000;if(which==5)queue[0].epid=1001;if(which==6)queue[0].detail=(uint64_t)getpid()+2000;
  int e=0;assert(f.ops.pump_fn(f.b,TS_BOOTSTRAP,f.deadline,collector,&f,&e)==-1);assert(e>0);assert(!f.delivered[TS_ACTIVITY]&&!f.delivered[TS_TERMINAL]);cleanup(&f);
 }
 reset();struct fixture f;initialize(&f);begin(&f);enqueue(2);int e=0;assert(!f.ops.pump_fn(f.b,TS_BOOTSTRAP,f.deadline,collector,&f,&e));enqueue(2);queue[0].epid=9999;assert(f.ops.pump_fn(f.b,TS_BOOTSTRAP,f.deadline,collector,&f,&e)==-1);assert(f.b->view.first_error.reason==OTB_BINDING);cleanup(&f);
}
static void start_failures(void) {
 reset();struct fixture f;initialize(&f);open_failure=1;int e=0;assert(f.ops.start_fn(f.b,&f.binding,f.deadline,&e)==-1);assert(e==EIO);assert(f.b->view.first_error.libdtrace_code==8123&&!f.b->view.first_error.system_errno);assert(!f.ops.close_fn(f.b,f.deadline,&e));assert(owned_closes==4&&!library_closed);cleanup(&f);
 reset();initialize(&f);missing_mach=1;assert(f.ops.start_fn(f.b,&f.binding,f.deadline,&e)==-1);assert(!went&&f.b->view.first_error.reason==OTB_INVENTORY);cleanup(&f);
 reset();initialize(&f);match_count=1;assert(f.ops.start_fn(f.b,&f.binding,f.deadline,&e)==-1);assert(!went&&f.b->view.expected_matches==17&&f.b->view.enabled_matches==1&&f.b->view.first_error.reason==OTB_INVENTORY);cleanup(&f);
 reset();initialize(&f);struct ts_binding wrong=f.binding;wrong.request_sha256[0]^=1;assert(f.ops.start_fn(f.b,&wrong,f.deadline,&e)==-1);assert(!opened&&!owned_closes);cleanup(&f);
 reset();initialize(&f);int existing=openat(f.directory,"events.jsonl",O_WRONLY|O_CREAT|O_EXCL,0600);assert(existing>=0);assert(!close(existing));assert(f.ops.start_fn(f.b,&f.binding,f.deadline,&e)==-1);assert(!opened);assert(!f.ops.close_fn(f.b,f.deadline,&e));assert(owned_closes==2);cleanup(&f);
}
static void compiled_match_accounting(void) {
 struct fixture f;int e=0;
 /* Compilation makes another physical syscall probe available. A precompile
  * all-probe inventory cannot pass the model's ordering assertion. */
 reset();initialize(&f);compile_additions=1;match_count=18;
 assert(!f.ops.start_fn(f.b,&f.binding,f.deadline,&e));
 assert(compiled_calls==1&&statement_calls==1&&probe_iterations==17&&exec_calls==1&&went==1);
 assert(f.b->view.inventory_probes==18&&f.b->view.expected_matches==18&&f.b->view.enabled_matches==18);
 assert(!f.delivered[TS_PROVIDER_READY]);cleanup(&f);
 for(unsigned n=16;n<=18;n+=2) {
  reset();initialize(&f);match_count=n;assert(f.ops.start_fn(f.b,&f.binding,f.deadline,&e)==-1);
  assert(exec_calls==1&&!went&&f.b->view.expected_matches==17&&f.b->view.enabled_matches==n);
  assert(f.b->view.first_error.reason==OTB_INVENTORY);cleanup(&f);
 }
 for(enum statement_mode mode=ST_MISSING;mode<=ST_EXPIRE_AFTER;mode++) {
  reset();initialize(&f);statement_mode=mode;
  assert(f.ops.start_fn(f.b,&f.binding,f.deadline,&e)==-1&&e>0);
  assert(!exec_calls&&!went&&!f.b->view.inventory_probes);
  assert(f.b->view.first_error.reason!=OTB_OK);
  clock_failure=0;model_now=UINT64_C(1000000000);cleanup(&f);
 }
 reset();initialize(&f);statement_mode=ST_EXACT_BOUND;
 assert(!f.ops.start_fn(f.b,&f.binding,f.deadline,&e));
 assert(exec_calls==1&&went==1&&probe_iterations==17&&f.b->view.inventory_probes==17);cleanup(&f);
 for(enum match_mode mode=MT_EMPTY;mode<=MT_EXPIRE_AFTER;mode++) {
  reset();initialize(&f);match_mode=mode;
  assert(f.ops.start_fn(f.b,&f.binding,f.deadline,&e)==-1&&e>0);
  assert(!exec_calls&&!went&&f.b->view.first_error.reason!=OTB_OK);
  clock_failure=0;model_now=UINT64_C(1000000000);cleanup(&f);
 }
 reset();initialize(&f);match_mode=MT_EXACT_BOUND;match_count=OTB_MAX_PROBES;
 assert(!f.ops.start_fn(f.b,&f.binding,f.deadline,&e));
 assert(exec_calls==1&&went==1&&f.b->view.inventory_probes==OTB_MAX_PROBES);
 assert(f.b->view.expected_matches==OTB_MAX_PROBES&&f.b->view.enabled_matches==OTB_MAX_PROBES);cleanup(&f);
}
static void bounds_and_faults(void) {
 reset();struct fixture f;initialize(&f);int e=0;assert(!f.ops.start_fn(f.b,&f.binding,f.deadline,&e));f.b->view.raw_bytes=OTB_MAX_RAW_BYTES-1;enqueue(1);assert(f.ops.pump_fn(f.b,TS_BOOTSTRAP,f.deadline,collector,&f,&e)==-1);assert(!f.delivered[TS_PROVIDER_READY]);assert(f.b->view.first_error.reason==OTB_LIMIT&&!f.b->view.first_error.system_errno);cleanup(&f);
 reset();initialize(&f);begin(&f);write_failure_fd=f.b->files[EVENT_FILE];enqueue(2);assert(f.ops.pump_fn(f.b,TS_BOOTSTRAP,f.deadline,collector,&f,&e)==-1);assert(!f.delivered[TS_ACTIVITY]);assert(f.b->view.first_error.system_errno==ENOSPC);write_failure_fd=-1;cleanup(&f);
 reset();initialize(&f);begin(&f);write_expire_fd=f.b->files[EVENT_FILE];write_expire_time=f.deadline;enqueue(2);errno=EBADF;
 assert(f.ops.pump_fn(f.b,TS_BOOTSTRAP,f.deadline,collector,&f,&e)==-1);assert(!f.delivered[TS_ACTIVITY]);assert(f.b->view.first_error.reason==OTB_DEADLINE&&!f.b->view.first_error.system_errno);model_now=UINT64_C(1000000000);cleanup(&f);
 for(unsigned which=0;which<2;which++) {
  reset();initialize(&f);begin(&f);if(which)write_eintr_fd=f.b->files[EVENT_FILE];else write_zero_fd=f.b->files[EVENT_FILE];enqueue(2);
  assert(f.ops.pump_fn(f.b,TS_BOOTSTRAP,f.deadline,collector,&f,&e)==-1);assert(!f.delivered[TS_ACTIVITY]);assert(!f.b->view.first_error.system_errno);
  assert(f.b->view.first_error.reason==(which?OTB_LIMIT:OTB_OUTPUT));write_eintr_fd=write_zero_fd=-1;cleanup(&f);
 }
 for(unsigned which=0;which<2;which++){reset();initialize(&f);begin(&f);work_drop=which==0;work_fault=which==1;assert(f.ops.pump_fn(f.b,TS_BOOTSTRAP,f.deadline,collector,&f,&e)==-1);assert(which?f.b->view.faults==1:f.b->view.drops==2);assert(!f.b->view.first_error.system_errno);cleanup(&f);}
 reset();initialize(&f);begin(&f);work_done=1;assert(f.ops.pump_fn(f.b,TS_BOOTSTRAP,f.deadline,collector,&f,&e)==-1);assert(f.b->view.first_error.reason==OTB_INCOMPLETE);cleanup(&f);
 reset();initialize(&f);begin(&f);work_override=17;
 assert(f.ops.pump_fn(f.b,TS_BOOTSTRAP,f.deadline,collector,&f,&e)==-1);
 assert(f.b->view.first_error.reason==OTB_ORDER&&!f.b->view.first_error.system_errno&&!f.b->view.first_error.libdtrace_code&&e==EPROTO);
 int diagnostic_fd=openat(f.directory,"errors.jsonl",O_RDONLY);assert(diagnostic_fd>=0);char diagnostic_text[2048]={0};ssize_t diagnostic_n=read(diagnostic_fd,diagnostic_text,sizeof(diagnostic_text)-1);assert(diagnostic_n>0);assert(!close(diagnostic_fd));
 assert(strstr(diagnostic_text,"\"kind\":\"work-status\",\"status\":17"));cleanup(&f);
}
static void deadline_and_closure(void) {
 for(unsigned broken_clock=0;broken_clock<2;broken_clock++) {
  reset();struct fixture combined;initialize(&combined);begin(&combined);close_failure_at=4;
  if(broken_clock)clock_failure=1;else model_now=combined.deadline;int combined_error=0;
  assert(combined.ops.close_fn(combined.b,combined.deadline,&combined_error)==-1);
  assert(combined.b->view.first_error.reason==(broken_clock?OTB_CLOCK:OTB_DEADLINE));
  assert(combined.b->view.close_error.reason==(broken_clock?OTB_CLOCK:OTB_DEADLINE));
  assert(combined.b->view.writer_close_error.reason==OTB_POSIX&&combined.b->view.writer_close_error.system_errno==EINTR);
  assert(combined.b->view.writer_close_attempted_mask==15&&combined.b->view.writer_close_failed_mask==8&&combined.b->view.writer_close_errno[3]==EINTR);
  assert(!combined.b->view.resources_closed&&owned_closes==4&&library_closed==1);assert(otb_destroy(&combined.b)==-1);
  free(combined.b);combined.b=NULL;clock_failure=0;model_now=UINT64_C(1000000000);cleanup(&combined);
 }
 for(unsigned malformed=0;malformed<2;malformed++) {
  reset();struct fixture clock_fixture;initialize(&clock_fixture);begin(&clock_fixture);clock_failure=malformed?3:2;int clock_error=0;
  assert(clock_fixture.ops.close_fn(clock_fixture.b,clock_fixture.deadline,&clock_error)==-1);
  assert(clock_fixture.b->view.first_error.reason==OTB_CLOCK&&clock_fixture.b->view.first_error.callback_error==EOVERFLOW);
  assert(clock_fixture.b->view.first_error.system_errno==(malformed?0:EOVERFLOW));
  assert(owned_closes==4&&library_closed==1&&clock_fixture.b->view.resources_closed);clock_failure=0;cleanup(&clock_fixture);
 }
 reset();struct fixture changed;initialize(&changed);begin(&changed);model_now=changed.deadline-UINT64_C(500000000);int changed_error=0;
 assert(changed.ops.pump_fn(changed.b,TS_BOOTSTRAP,changed.deadline+UINT64_C(100000000),collector,&changed,&changed_error)==-1);
 assert(changed.b->view.first_error.reason==OTB_BINDING&&!changed.b->view.cleanup_deadline_ns);cleanup(&changed);
 for(unsigned which=0;which<3;which++) {
  reset();struct fixture f;initialize(&f);begin(&f);if(which==0)model_now=f.deadline;if(which==1)clock_failure=1;if(which==2)model_now--;
  int e=0;assert(f.ops.close_fn(f.b,f.deadline,&e)==-1);assert(e>0&&owned_closes==4&&library_closed==1&&f.b->view.resources_closed);clock_failure=0;model_now=UINT64_C(1000000000);
  assert(f.ops.close_fn(f.b,f.deadline,&e)==-1);assert(owned_closes==4&&library_closed==1);cleanup(&f);
 }
 reset();struct fixture f;initialize(&f);open_failure=1;int e=0;assert(f.ops.start_fn(f.b,&f.binding,f.deadline,&e)==-1);model_now=f.deadline;assert(f.ops.close_fn(f.b,f.deadline,&e)==-1);assert(owned_closes==4&&f.b->view.resources_closed);assert(f.b->view.first_error.reason==OTB_LIBDTRACE&&f.b->view.close_error.reason==OTB_DEADLINE);model_now=UINT64_C(1000000000);cleanup(&f);
 reset();initialize(&f);begin(&f);close_failure=1;assert(f.ops.close_fn(f.b,f.deadline,&e)==-1);assert(owned_closes==4&&library_closed==1&&!f.b->view.resources_closed);assert(otb_destroy(&f.b)==-1);free(f.b);f.b=NULL;assert(!close(f.directory));for(unsigned i=0;i<4;i++){char path[256];snprintf(path,sizeof(path),"%s/%s",f.path,file_names[i]);assert(!unlink(path));}assert(!rmdir(f.path));
 reset();initialize(&f);begin(&f);assert(!f.ops.stop_fn(f.b,f.deadline,&e));work_done=1;assert(f.ops.drain_fn(f.b,f.deadline,collector,&f,&e)==-1);assert(!f.b->view.drained);assert(f.ops.stop_fn(f.b,f.deadline,&e)==-1);assert(stopped==1);cleanup(&f);
 reset();initialize(&f);begin(&f);assert(!f.ops.stop_fn(f.b,f.deadline,&e));assert(f.ops.drain_fn(f.b,f.deadline,collector,&f,&e)==-1);assert(work_calls==4097&&!f.b->view.drained);cleanup(&f);
}
int main(void) {
 readiness_and_full_session();rejected_records();start_failures();compiled_match_accounting();bounds_and_faults();deadline_and_closure();
 puts("owned trace backend boundary controls passed (fake libdtrace only)");return 0;
}
