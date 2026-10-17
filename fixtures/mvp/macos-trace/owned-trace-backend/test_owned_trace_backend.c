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
static int model_clock(clockid_t c,struct timespec *t) {
 assert(c==CLOCK_MONOTONIC);if(clock_failure){errno=EIO;return -1;}
 t->tv_sec=(time_t)(model_now/1000000000);t->tv_nsec=(long)(model_now%1000000000);return 0;
}
static int model_close(int fd) {
 owned_closes++;int rc=close(fd);assert(!rc);
 if(close_failure){close_failure=0;errno=EINTR;return -1;}return 0;
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
 assert(!wanted);for(unsigned k=1;k<=18;k++)if(k!=14 && !(missing_mach&&(k==15||k==16)))if(f(h,&probes[k],c))return -1;return 0;
}
dtrace_prog_t *dtrace_program_strcompile(dtrace_hdl_t *h,const char *program,dtrace_probespec_t spec,uint_t flags,int argc,char *const argv[]) {
 (void)h;assert(spec==DTRACE_PROBESPEC_NAME&&!flags&&!argc&&!argv);
 assert(strstr(program,"mach_trap:::entry")&&strstr(program,"mach_trap:::return"));
 assert(strstr(program,"p_refcount")&&!strstr(program,"copyinstr")&&!strstr(program,"syscall::open"));
 return (dtrace_prog_t *)(uintptr_t)2;
}
int dtrace_program_exec(dtrace_hdl_t *h,dtrace_prog_t *p,dtrace_proginfo_t *info) {(void)h;assert(p==(dtrace_prog_t *)(uintptr_t)2);info->dpi_matches=match_count;return 0;}
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
 if(work_drop){dtrace_dropdata_t d={0};d.dtdda_drops=2;d.dtdda_total=2;d.dtdda_msg="model drop";assert(drop_callback(&d,backend_context)==DTRACE_HANDLE_ABORT);return DTRACE_WORKSTATUS_ERROR;}
 if(work_fault){dtrace_errdata_t d={0};d.dteda_fault=3;d.dteda_msg="model fault";assert(error_callback(&d,backend_context)==DTRACE_HANDLE_ABORT);return DTRACE_WORKSTATUS_ERROR;}
 for(unsigned i=0;i<queued_count;i++)if(deliver(consume,context,&queue[i])==DTRACE_CONSUME_ABORT){queued_count=0;return DTRACE_WORKSTATUS_ERROR;}
 queued_count=0;return work_done?DTRACE_WORKSTATUS_DONE:DTRACE_WORKSTATUS_OKAY;
}
struct fixture {struct otb_backend *b;struct ts_operations ops;struct ts_binding binding;int directory;char path[128];uint64_t deadline;unsigned delivered[9];};
static void reset(void) {
 model_now=UINT64_C(1000000000);clock_failure=close_failure=0;write_failure_fd=write_expire_fd=write_zero_fd=write_eintr_fd=-1;owned_closes=0;
 opened=went=stopped=library_closed=work_calls=open_failure=missing_mach=work_done=work_drop=work_fault=0;
 queued_count=0;make_probes();
 match_count=17;
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
 int e=0;if(!f->b->view.close_attempted)(void)f->ops.close_fn(f->b,f->deadline,&e);
 assert(!otb_destroy(&f->b));assert(!close(f->directory));
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
}
static void deadline_and_closure(void) {
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
 readiness_and_full_session();rejected_records();start_failures();bounds_and_faults();deadline_and_closure();
 puts("owned trace backend boundary controls passed (fake libdtrace only)");return 0;
}
