/* Injected native-record producer controls. All libdtrace functions are stubs;
 * this TU never links libdtrace, starts a provider or signals a process. */
#define _POSIX_C_SOURCE 200809L
#define _DARWIN_C_SOURCE 1
#include <assert.h>
#include <dtrace.h>
#include <errno.h>
#include <fcntl.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>
static uint64_t now=UINT64_C(1000000000);
static int clock_bad,write_bad=-1,partial_fd=-1,partial_seen,close_bad=-1;
static int model_clock(clockid_t c,struct timespec *t){
#ifdef GLUE_STOPPED_STATUS_CLOCK_CALL
 GLUE_STOPPED_STATUS_CLOCK_CALL();
#endif
 assert(c==CLOCK_MONOTONIC);if(clock_bad){errno=EIO;return -1;}t->tv_sec=(time_t)(now/1000000000);t->tv_nsec=(long)(now%1000000000);return 0;}
static ssize_t model_write(int fd,const void *p,size_t n){if(fd==write_bad){errno=ENOSPC;return -1;}if(fd==partial_fd){if(partial_seen++){errno=ENOSPC;return -1;}return write(fd,p,n>9?9:n);}return write(fd,p,n);}
static int model_close(int fd){int rc=close(fd);assert(!rc);
#ifdef GLUE_STOPPED_STATUS_AFTER_CLOSE
 GLUE_STOPPED_STATUS_AFTER_CLOSE(fd);
#endif
 if(fd==close_bad){close_bad=-1;errno=EINTR;return -1;}return 0;}
#define clock_gettime model_clock
#define write model_write
#define close model_close
#include "runtime_trace_backend.c"
#undef clock_gettime
#undef write
#undef close

/* Independent fixed selector inventory, including shared physical matches. */
static const struct {const char *p,*f,*n;} selectors[23]={
 {"","","BEGIN"},{"","","END"},{"syscall","","entry"},{"syscall","","return"},
 {"mach_trap","","entry"},{"mach_trap","","return"},{"proc","","create"},{"proc","","start"},
 {"proc","","exec-success"},{"proc","","exit"},{"proc","","exec-failure"},{"proc","","lwp-create"},
 {"proc","","lwp-start"},{"proc","","lwp-exit"},{"proc","","spawn-success"},{"proc","","spawn-failure"},
 {"proc","","exited"},{"proc","","lwp-start"},{"syscall","proc_info","return"},
 {"syscall","wait4","return"},{"syscall","wait4_nocancel","return"},{"syscall","kill","return"},{"syscall","","return"}};
static dtrace_ecbdesc_t compiled[23];static dtrace_probedesc_t physical[25];static unsigned nphysical;
static int opened,went,closed,destructive,options,compile_calls,selector_bad,match_bad,enabled_bad,destructive_bad,expect_old;
static dtrace_handle_drop_f *drop_cb;static dtrace_handle_err_f *error_cb;static void *cb_arg;
static void names(dtrace_probedesc_t *p,const char *a,const char *f,const char *n,unsigned id){memset(p,0,sizeof(*p));p->dtpd_id=id;snprintf(p->dtpd_provider,sizeof(p->dtpd_provider),"%s",a);snprintf(p->dtpd_func,sizeof(p->dtpd_func),"%s",f);snprintf(p->dtpd_name,sizeof(p->dtpd_name),"%s",n);}
static void setup(void){
 now=UINT64_C(1000000000);clock_bad=partial_seen=0;write_bad=partial_fd=close_bad=-1;
 opened=went=closed=destructive=options=compile_calls=selector_bad=match_bad=enabled_bad=destructive_bad=expect_old=0;nphysical=0;
 for(unsigned i=0;i<23;i++)names(&compiled[i].dted_probe,selectors[i].p,selectors[i].f,selectors[i].n,0);
 for(unsigned i=0;i<17;i++){const char *p=selectors[i].p,*f=selectors[i].f;if(!*p)p="dtrace";if(!strcmp(p,"syscall"))f="execve";else if(!strcmp(p,"mach_trap"))f="mach_msg2_trap";names(&physical[nphysical],p,f,selectors[i].n,100+nphysical);nphysical++;}
 const char *fn[]={"proc_info","wait4","wait4_nocancel","kill"};for(unsigned i=0;i<4;i++)for(unsigned r=0;r<2;r++){names(&physical[nphysical],"syscall",fn[i],r?"return":"entry",100+nphysical);nphysical++;}
 assert(nphysical==25);
}
dtrace_hdl_t *dtrace_open(int v,int f,int *e){assert(v==DTRACE_VERSION&&f==DTRACE_O_LP64);opened++;*e=0;return (void *)(uintptr_t)1;}
void dtrace_close(dtrace_hdl_t *h){assert(h==(void *)(uintptr_t)1);closed++;}
int dtrace_handle_drop(dtrace_hdl_t *h,dtrace_handle_drop_f *f,void *c){(void)h;drop_cb=f;cb_arg=c;return 0;}
int dtrace_handle_err(dtrace_hdl_t *h,dtrace_handle_err_f *f,void *c){(void)h;error_cb=f;assert(c==cb_arg);return 0;}
int dtrace_setopt(dtrace_hdl_t *h,const char *k,const char *v){(void)h;options++;if(!strcmp(k,"destructive")){assert(!strcmp(v,"yes"));destructive++;return destructive_bad?-1:0;}return 0;}
dtrace_prog_t *dtrace_program_strcompile(dtrace_hdl_t *h,const char *s,dtrace_probespec_t spec,uint_t flags,int argc,char *const argv[]){(void)h;assert(spec==DTRACE_PROBESPEC_NAME&&!flags&&!argc&&!argv);if(expect_old)assert(strstr(s,"glue-runtime-images-v2")&&!strstr(s,"raise(")&&!strstr(s,"copyin("));else assert(strstr(s,"glue-stopped-runtime-v1")&&strstr(s,"raise(17)")&&strstr(s,"copyin(self->s4,176)"));compile_calls++;return (void *)(uintptr_t)2;}
int dtrace_stmt_iter(dtrace_hdl_t *h,dtrace_prog_t *p,dtrace_stmt_f *f,void *c){for(unsigned i=0;i<(expect_old?17u:23u);i++){dtrace_stmtdesc_t s={0};s.dtsd_ecbdesc=&compiled[i];if(selector_bad&&i==18)s.dtsd_ecbdesc=&compiled[19];if(f(h,p,&s,c))return -1;if(f(h,p,&s,c))return -1;}return 0;}
int dtrace_probe_iter(dtrace_hdl_t *h,const dtrace_probedesc_t *w,dtrace_probe_f *f,void *c){for(unsigned i=0;i<nphysical;i++){dtrace_probedesc_t *p=&physical[i];if((*w->dtpd_provider&&strcmp(w->dtpd_provider,p->dtpd_provider))||(*w->dtpd_func&&strcmp(w->dtpd_func,p->dtpd_func))||strcmp(w->dtpd_name,p->dtpd_name))continue;if(f(h,p,c))return -1;if(match_bad&&!strcmp(w->dtpd_func,"proc_info")&&f(h,p,c))return -1;}return 0;}
int dtrace_program_exec(dtrace_hdl_t *h,dtrace_prog_t *p,dtrace_proginfo_t *i){(void)h;(void)p;i->dpi_matches=expect_old?25:enabled_bad?34:35;return 0;}
int dtrace_go(dtrace_hdl_t *h){(void)h;went++;return 0;}
int dtrace_stop(dtrace_hdl_t *h){(void)h;return 0;}
int dtrace_errno(dtrace_hdl_t *h){(void)h;return 123;}
const char *dtrace_errmsg(dtrace_hdl_t *h,int e){(void)h;(void)e;return "injected";}
dtrace_workstatus_t dtrace_work(dtrace_hdl_t *h,FILE *o,dtrace_consume_probe_f *p,dtrace_consume_rec_f *r,void *c){(void)h;(void)o;(void)p;(void)r;(void)c;return DTRACE_WORKSTATUS_DONE;}
struct fixture{struct rt_backend *b;struct ts_operations ops;struct ts_binding binding;int dir;char path[128];uint64_t deadline;unsigned delivered[9];};
static const char *retained;
static void retain(struct fixture *f){
 if(!retained)return;const char *files[]={"program.d","probes.tsv","events.jsonl","errors.jsonl"};
 for(unsigned i=0;i<4;i++){int in=openat(f->dir,files[i],O_RDONLY);if(in<0){assert(errno==ENOENT);continue;}char path[1024];int n=snprintf(path,sizeof(path),"%s/%s",retained,files[i]);assert(n>0&&(size_t)n<sizeof(path));int out=open(path,O_WRONLY|O_CREAT|O_EXCL,0600);assert(out>=0);unsigned char buf[4096];ssize_t k;while((k=read(in,buf,sizeof(buf)))>0){ssize_t done=0;while(done<k){ssize_t w=write(out,buf+done,(size_t)(k-done));assert(w>0);done+=w;}}assert(!k&&!close(in)&&!close(out));}
 struct rt_stopped_identity id;assert(!rt_stopped_identity(f->b,&id));char path[1024];int n=snprintf(path,sizeof(path),"%s/typed-identity.json",retained);assert(n>0&&(size_t)n<sizeof(path));FILE *out=fopen(path,"wx");assert(out);fprintf(out,"{\"profile\":%u,\"layout\":%u,\"owner\":%u,\"target\":%u,\"state\":%d,\"events\":%"PRIu64",\"entry_ordinal\":%"PRIu64",\"entry_tid\":%"PRIu64",\"exec_success_ordinal\":%"PRIu64",\"new_tid\":%"PRIu64",\"lwp_start_ordinal\":%"PRIu64",\"marker_ordinal\":%"PRIu64",\"marker_epoch\":%"PRIu64",\"latch_tid\":%"PRIu64",\"signal\":%"PRIu64",\"first_error\":%d,\"native_admission\":false,\"request_sha256\":\"",id.profile_version,id.layout_version,id.binding.owner_pid,id.binding.target_pid,id.state,id.total_events,id.entry_ordinal,id.entry_tid,id.exec_success_ordinal,id.new_tid,id.lwp_start_ordinal,id.marker_ordinal,id.marker_epoch,id.latch_tid,id.signal,id.first_error.reason);for(unsigned i=0;i<32;i++)fprintf(out,"%02x",id.binding.request_sha256[i]);fprintf(out,"\",\"catalog_sha256\":\"");for(unsigned i=0;i<32;i++)fprintf(out,"%02x",id.binding.catalog_sha256[i]);fprintf(out,"\",\"program_sha256\":\"");for(unsigned i=0;i<32;i++)fprintf(out,"%02x",id.program_sha256[i]);fprintf(out,"\"}\n");assert(!fclose(out));
}
static int consumer(void *c,const struct ts_event *e){struct fixture *f=c;assert(!memcmp(&f->binding,&e->binding,sizeof(e->binding)));assert(e->kind<9);f->delivered[e->kind]++;return 0;}
static void init(struct fixture *f){memset(f,0,sizeof(*f));snprintf(f->path,sizeof(f->path),"/private/tmp/glue-stopped-model-XXXXXX");assert(mkdtemp(f->path));f->dir=open(f->path,O_RDONLY|O_DIRECTORY|O_CLOEXEC);assert(f->dir>=0);f->binding=(struct ts_binding){TS_OWNED_RUNTIME_RECIPE,(uint32_t)getpid(),(uint32_t)getpid()+1111,{1},{2}};f->deadline=now+UINT64_C(5000000000);struct rt_error e;assert(!rt_stopped_recipe_create(&f->b,f->dir,&f->binding,f->deadline,1,&f->ops,&e));}
static int start_fixture(struct fixture *f){int e=0;int rc=f->ops.start_fn(f->b,&f->binding,f->deadline,&e);assert((rc==0)==(e==0));return rc;}
static void finish(struct fixture *f){int e=0;clock_bad=0;write_bad=partial_fd=-1;if(f->b->view.start_attempted&&!f->b->view.close_attempted)(void)f->ops.close_fn(f->b,f->deadline,&e);assert(f->b->view.resources_closed||!f->b->view.start_attempted);retain(f);assert(!rt_destroy(&f->b));assert(!close(f->dir));const char *files[]={"program.d","probes.tsv","events.jsonl","errors.jsonl"};for(unsigned i=0;i<4;i++){char p[256];snprintf(p,sizeof(p),"%s/%s",f->path,files[i]);if(unlink(p))assert(errno==ENOENT);}assert(!rmdir(f->path));}
static dtrace_probedesc_t *probe(unsigned k,const char *fn){const char *name=k==1?"BEGIN":k==17?"END":k==2?"entry":k==3||k>=20?"return":k==19?"lwp-start":k==7?"exec-success":k==8?"exec-failure":k==10?"lwp-start":k==18?"exited":NULL;assert(name);for(unsigned i=0;i<nphysical;i++)if(!strcmp(physical[i].dtpd_name,name)&&(!fn||!strcmp(physical[i].dtpd_func,fn)))return &physical[i];assert(0);return NULL;}
struct event{unsigned kind;const char *fn;uint64_t pid,tid,detail,args[8];int bad;};
static int send_event(struct fixture *f,struct event e){
 unsigned k=e.kind,lead=k==1?1:k==2?8:k==7?4:k==8?1:0,ns=k==2?13:k==3||k>=20?10:k==18?8:k==19?7:5,mem=k==20?176:k==21?4:0,tail=k==19?2:0;
 dtrace_eprobedesc_t *d=calloc(1,sizeof(*d)+32*sizeof(dtrace_recdesc_t));assert(d);dtrace_probedesc_t *p=probe(k,e.fn);d->dtepd_epid=1000+k*32+p->dtpd_id;d->dtepd_probeid=p->dtpd_id;d->dtepd_nrecs=(int)(lead+ns+!!mem+tail);d->dtepd_size=16+ns*8+mem;unsigned char raw[272]={0};
 uint64_t v[13]={k,100+f->b->view.events,e.pid?e.pid:(k==1||k==17?f->binding.owner_pid:f->binding.target_pid),e.tid?e.tid:20,e.detail};
 if(!e.detail&&(k==2||k==3||k==7))v[4]=f->binding.owner_pid;
 for(unsigned i=5;i<ns;i++)v[i]=e.args[i-5];
 if(k==18){v[4]=f->binding.target_pid;v[6]=0x1234;v[7]=1;}
 for(unsigned i=0;i<lead;i++){d->dtepd_rec[i].dtrd_action=DTRACEACT_DIFEXPR;d->dtepd_rec[i].dtrd_offset=12;}
 for(unsigned i=0;i<ns;i++){dtrace_recdesc_t *r=&d->dtepd_rec[lead+i];r->dtrd_action=DTRACEACT_DIFEXPR;r->dtrd_size=8;r->dtrd_offset=16+i*8;memcpy(raw+r->dtrd_offset,&v[i],8);}
 if(mem){dtrace_recdesc_t *r=&d->dtepd_rec[lead+ns];r->dtrd_action=DTRACEACT_TRACEMEM;r->dtrd_size=mem;r->dtrd_offset=16+ns*8;for(unsigned i=0;i<mem;i++)raw[r->dtrd_offset+i]=(unsigned char)(i^0xa5);}
 if(tail)for(unsigned i=0;i<2;i++){dtrace_recdesc_t *r=&d->dtepd_rec[lead+ns+i];r->dtrd_action=i?DTRACEACT_DIFEXPR:DTRACEACT_RAISE;r->dtrd_offset=72;}
 if(e.bad==1)d->dtepd_rec[0].dtrd_offset++;if(e.bad==2)d->dtepd_rec[lead].dtrd_action=2;if(e.bad==3)d->dtepd_nrecs--;if(e.bad==4)d->dtepd_size++;if(e.bad==5)d->dtepd_rec[lead+ns].dtrd_size++;if(e.bad==6)d->dtepd_rec[lead+ns].dtrd_action=1;
 dtrace_probedesc_t changed=*p;if(e.bad==7)memset(changed.dtpd_mod,'x',sizeof(changed.dtpd_mod));
 f->b->consume=consumer;f->b->consume_context=f;f->b->callback_deadline=f->deadline;dtrace_probedata_t data={0};data.dtpda_cpu=0;data.dtpda_edesc=d;data.dtpda_pdesc=e.bad==7?&changed:p;data.dtpda_data=(char *)raw;int rc=consume_probe(&data,f->b);free(d);return rc;
}
static void ok(struct fixture *f,struct event e){int rc=send_event(f,e);if(rc!=DTRACE_CONSUME_NEXT)fprintf(stderr,"kind %u fn %s reason %d: %s\n",e.kind,e.fn?e.fn:"",f->b->view.first_error.reason,f->b->view.first_error.message);assert(rc==DTRACE_CONSUME_NEXT);}
static struct rt_stopped_identity identity(struct fixture *f){struct rt_stopped_identity x,y;memset(&x,0xa5,sizeof(x));uint64_t before=now;int calls=options;assert(!rt_stopped_identity(f->b,&x));assert(!rt_stopped_identity(f->b,&y));assert(!memcmp(&x,&y,sizeof(x))&&now==before&&options==calls);assert(!x.native_admission&&!x.quiescence_proved&&!x.state_admission&&!x.exemption_admission);return x;}
static void prefix(struct fixture *f,int reverse){ok(f,(struct event){.kind=1});ok(f,(struct event){.kind=2,.fn="execve",.tid=20});ok(f,(struct event){.kind=7,.tid=21});if(reverse)ok(f,(struct event){.kind=19,.tid=21,.detail=1,.args={21,17}});ok(f,(struct event){.kind=10,.tid=21});if(!reverse)ok(f,(struct event){.kind=19,.tid=21,.detail=1,.args={21,17}});}
static void owner_pair(struct fixture *f,const char *fn,unsigned cid,unsigned kind,const uint64_t args[8],uint64_t rv,unsigned err){struct event e={.kind=2,.fn=fn,.pid=f->binding.owner_pid,.tid=40,.detail=cid};memcpy(e.args,args,sizeof(e.args));ok(f,e);e=(struct event){.kind=kind,.fn=fn,.pid=f->binding.owner_pid,.tid=40,.detail=cid,.args={rv,rv,0,err,err}};ok(f,e);}
static char *read_events(struct fixture *f){int fd=openat(f->dir,"events.jsonl",O_RDONLY);assert(fd>=0);char *s=calloc(1,65536);assert(s);ssize_t n=read(fd,s,65535);assert(n>=0);assert(!close(fd));return s;}
static void run(const char *mode){setup();struct fixture f;init(&f);
 if(!strcmp(mode,"constructor")){struct rt_backend *b=(void *)1;struct ts_operations op;struct rt_error e;struct ts_binding bad=f.binding;memset(bad.request_sha256,0,32);assert(rt_stopped_recipe_create(&b,f.dir,&bad,f.deadline,1,&op,&e)&&!b&&e.reason==RT_ARGUMENT&&!opened);bad=f.binding;bad.fixture=1;assert(rt_stopped_recipe_create(&b,f.dir,&bad,f.deadline,1,&op,&e)&&!b);assert(rt_stopped_recipe_create(&b,f.dir,&f.binding,f.deadline,0,&op,&e)&&!b);struct rt_stopped_identity id=identity(&f);assert(id.state==RT_STOPPED_PENDING&&!id.program_written);struct rt_snapshot old;memset(&old,0xff,sizeof(old));assert(rt_snapshot(f.b,&old));for(size_t i=0;i<sizeof(old);i++)assert(!((unsigned char *)&old)[i]);finish(&f);return;}
 if(!strcmp(mode,"old-options")){assert(!rt_destroy(&f.b));struct rt_error e;expect_old=1;assert(!rt_recipe_images_create(&f.b,f.dir,&f.binding,f.deadline,1,&f.ops,&e));assert(!start_fixture(&f)&&opened==1&&went==1&&options==6&&!destructive);struct rt_snapshot old;assert(!rt_snapshot(f.b,&old)&&old.binding.fixture==2);struct rt_stopped_identity id;memset(&id,0xff,sizeof(id));assert(rt_stopped_identity(f.b,&id));for(size_t i=0;i<sizeof(id);i++)assert(!((unsigned char *)&id)[i]);const char *saved=retained;retained=NULL;finish(&f);retained=saved;return;}
 if(!strcmp(mode,"selector"))selector_bad=1;if(!strcmp(mode,"duplicate-match"))match_bad=1;if(!strcmp(mode,"enabled-count"))enabled_bad=1;if(!strcmp(mode,"destructive-denied"))destructive_bad=1;
 if(selector_bad||match_bad||enabled_bad||destructive_bad){assert(start_fixture(&f));assert(!went&&identity(&f).state==RT_STOPPED_UNUSABLE);assert(destructive==1);finish(&f);return;}
 assert(!start_fixture(&f));assert(opened==1&&went==1&&destructive==1&&options==7&&compile_calls==1);assert(f.b->view.inventory_probes==25&&f.b->view.expected_matches==35);struct rt_stopped_identity id=identity(&f);assert(id.program_written&&id.state==RT_STOPPED_PENDING);unsigned nz=0;for(unsigned i=0;i<32;i++)nz|=id.program_sha256[i];assert(nz);
 if(!strcmp(mode,"layout")){const char *saved=retained;retained=NULL;for(int n=1;n<=6;n++){if(n>1){finish(&f);setup();init(&f);assert(!start_fixture(&f));}ok(&f,(struct event){.kind=1});assert(send_event(&f,(struct event){.kind=n==5||n==6?19:2,.fn=n==5||n==6?NULL:"execve",.tid=21,.detail=n==5||n==6?1:0,.args={21,17},.bad=n})==DTRACE_CONSUME_ABORT);assert(identity(&f).state==RT_STOPPED_UNUSABLE);}retained=saved;finish(&f);return;}
 if(!strcmp(mode,"partial-write")){ok(&f,(struct event){.kind=1});partial_fd=f.b->files[EVENT_FILE];assert(send_event(&f,(struct event){.kind=2,.fn="execve"})==DTRACE_CONSUME_ABORT);id=identity(&f);assert(!id.entry_seen&&id.total_events==1&&id.state==RT_STOPPED_UNUSABLE&&f.b->view.raw_bytes>0);finish(&f);return;}
 if(!strcmp(mode,"wrong-marker-tid")||!strcmp(mode,"wrong-marker-signal")||!strcmp(mode,"wrong-marker-epoch")){
  ok(&f,(struct event){.kind=1});ok(&f,(struct event){.kind=2,.fn="execve",.tid=20});ok(&f,(struct event){.kind=7,.tid=21});
  struct event marker={.kind=19,.tid=21,.detail=1,.args={21,17}};
  if(!strcmp(mode,"wrong-marker-tid"))marker.args[0]=22;if(!strcmp(mode,"wrong-marker-signal"))marker.args[1]=19;if(!strcmp(mode,"wrong-marker-epoch"))marker.detail=2;
  assert(send_event(&f,marker)==DTRACE_CONSUME_ABORT);id=identity(&f);assert(!id.marker_seen&&id.total_events==4&&id.state==RT_STOPPED_UNUSABLE);finish(&f);return;
 }
 prefix(&f,!strcmp(mode,"marker-order"));id=identity(&f);assert(id.state==RT_STOPPED_PREFIX_RECORDED&&id.entry_ordinal==2&&id.entry_tid==20&&id.exec_success_ordinal==3&&id.new_tid==21&&id.marker_epoch==1&&id.signal==17&&id.lwp_seen);assert(id.lwp_start_ordinal!=id.marker_ordinal&&id.marker_timestamp!=id.lwp_start_timestamp);assert(id.common_counts[2]==1&&id.extra_counts[0]==1&&id.total_events==5);
 if(!strcmp(mode,"malformed-name")){
  assert(!stopped_class(NULL,20));
  for(unsigned field=0;field<4;field++){dtrace_probedesc_t bad=*probe(20,"proc_info");char *a[]={bad.dtpd_provider,bad.dtpd_mod,bad.dtpd_func,bad.dtpd_name};size_t n[]={sizeof(bad.dtpd_provider),sizeof(bad.dtpd_mod),sizeof(bad.dtpd_func),sizeof(bad.dtpd_name)};memset(a[field],'x',n[field]);for(unsigned kind=20;kind<=23;kind++)assert(!stopped_class(&bad,kind));}
  uint64_t bytes=f.b->view.raw_bytes;assert(send_event(&f,(struct event){.kind=20,.fn="proc_info",.pid=f.binding.owner_pid,.tid=40,.detail=1,.args={176,176},.bad=7})==DTRACE_CONSUME_ABORT);id=identity(&f);assert(id.first_error.reason==RT_LAYOUT&&id.state==RT_STOPPED_UNUSABLE&&id.marker_seen&&id.total_events==5&&f.b->view.raw_bytes==bytes);finish(&f);return;
 }
 if(!strcmp(mode,"good")||!strcmp(mode,"marker-order")){uint64_t q[8]={3,f.binding.target_pid,1,1,0x12345000,176};owner_pair(&f,"proc_info",1,20,q,176,0);q[1]=f.binding.owner_pid;q[3]=9;owner_pair(&f,"proc_info",2,20,q,UINT64_MAX,EBADF);uint64_t w[8]={f.binding.target_pid,0x12346000,3,0};owner_pair(&f,"wait4",3,21,w,0,0);owner_pair(&f,"wait4_nocancel",4,21,w,UINT64_MAX,EINTR);uint64_t kill[8]={f.binding.target_pid,19,1};owner_pair(&f,"kill",5,22,kill,0,0);q[5]=175;owner_pair(&f,"proc_info",6,23,q,UINT64_MAX,EINVAL);ok(&f,(struct event){.kind=18,.pid=f.binding.owner_pid});unsigned activity=f.delivered[TS_ACTIVITY];w[2]=1;owner_pair(&f,"wait4_nocancel",7,21,w,UINT64_MAX,ECHILD);assert(f.delivered[TS_ACTIVITY]==activity);int e=0;assert(!f.ops.stop_fn(f.b,f.deadline,&e));f.b->draining=1;ok(&f,(struct event){.kind=17});f.b->draining=0;assert(!f.ops.drain_fn(f.b,f.deadline,consumer,&f,&e));assert(f.b->view.drained);id=identity(&f);assert(id.extra_counts[1]==2&&id.extra_counts[2]==3&&id.extra_counts[3]==1&&id.extra_counts[4]==1);char *raw=read_events(&f);assert(strstr(raw,"\"record_bytes\":272")&&strstr(raw,"\"record_bytes\":100")&&strstr(raw,"\"action\":514,\"size\":0,\"offset\":72")&&strstr(raw,"a5a4a7a6"));free(raw);
 }else if(!strcmp(mode,"drop")){dtrace_dropdata_t d={0};d.dtdda_drops=2;d.dtdda_total=2;d.dtdda_msg="model";assert(drop_cb(&d,cb_arg)==DTRACE_HANDLE_ABORT);id=identity(&f);assert(id.drops==2&&id.marker_seen&&id.state==RT_STOPPED_UNUSABLE);
 }else if(!strcmp(mode,"fault")){dtrace_errdata_t e={0};e.dteda_fault=3;e.dteda_msg="model";assert(error_cb(&e,cb_arg)==DTRACE_HANDLE_ABORT);id=identity(&f);assert(id.faults==1&&id.marker_seen&&id.state==RT_STOPPED_UNUSABLE);
 }else if(!strcmp(mode,"late-exec")){ok(&f,(struct event){.kind=2,.fn="execve",.tid=21});id=identity(&f);assert(id.later_exec&&id.state==RT_STOPPED_UNUSABLE);
 }else if(!strcmp(mode,"bad-marker")){assert(send_event(&f,(struct event){.kind=19,.tid=21,.detail=1,.args={21,17}})==DTRACE_CONSUME_ABORT);id=identity(&f);assert(id.marker_seen&&id.state==RT_STOPPED_UNUSABLE&&id.total_events==6);
 }else if(!strcmp(mode,"call-id")){uint64_t q[8]={3,f.binding.target_pid,1,1,0x12345000,176};struct event e={.kind=2,.fn="proc_info",.pid=f.binding.owner_pid,.tid=40,.detail=2};memcpy(e.args,q,sizeof(q));assert(send_event(&f,e)==DTRACE_CONSUME_ABORT);assert(identity(&f).total_events==6);
 }else if(!strcmp(mode,"return-shape")){struct event e={.kind=2,.fn="proc_info",.pid=f.binding.owner_pid,.tid=40,.detail=1,.args={3,f.binding.target_pid,1,1,0x12345000,176}};ok(&f,e);assert(send_event(&f,(struct event){.kind=23,.fn="proc_info",.pid=f.binding.owner_pid,.tid=40,.detail=1,.args={176,176}})==DTRACE_CONSUME_ABORT);assert(identity(&f).total_events==7);
 }else if(!strcmp(mode,"return-function")||!strcmp(mode,"return-error")||!strcmp(mode,"return-duplicate")||!strcmp(mode,"pending-end")){
  struct event e={.kind=2,.fn="proc_info",.pid=f.binding.owner_pid,.tid=40,.detail=1,.args={3,f.binding.target_pid,1,1,0x12345000,176}};ok(&f,e);
  struct event r={.kind=20,.fn="proc_info",.pid=f.binding.owner_pid,.tid=40,.detail=1,.args={176,176}};
  if(!strcmp(mode,"return-function")){r.kind=22;r.fn="kill";}
  if(!strcmp(mode,"return-error")){r.args[3]=EBADF;r.args[4]=EBADF;}
  if(!strcmp(mode,"pending-end")){ok(&f,(struct event){.kind=18,.pid=f.binding.owner_pid});int e=0;assert(!f.ops.stop_fn(f.b,f.deadline,&e));f.b->draining=1;ok(&f,(struct event){.kind=17});f.b->draining=0;assert(f.ops.drain_fn(f.b,f.deadline,consumer,&f,&e));assert(identity(&f).state==RT_STOPPED_UNUSABLE);}
  else{if(!strcmp(mode,"return-duplicate"))ok(&f,r);assert(send_event(&f,r)==DTRACE_CONSUME_ABORT);assert(identity(&f).state==RT_STOPPED_UNUSABLE);}
 }else if(!strcmp(mode,"close-failure")){close_bad=f.b->files[PROGRAM_FILE];int e=0;assert(f.ops.close_fn(f.b,f.deadline,&e));assert(identity(&f).state==RT_STOPPED_UNUSABLE);assert(!f.b->view.resources_closed&&f.b->view.writer_close_failed_mask==1);/* The model actually closed; only modeled ownership is unresolved. */f.b->view.resources_closed=1;
 }else if(!strcmp(mode,"clock-failure")){clock_bad=1;assert(send_event(&f,(struct event){.kind=2,.fn="kill",.pid=f.binding.owner_pid,.tid=40,.detail=1})==DTRACE_CONSUME_ABORT);id=identity(&f);assert(id.total_events==5&&id.marker_seen&&id.state==RT_STOPPED_UNUSABLE);
 }else{fprintf(stderr,"unknown mode %s\n",mode);assert(0);}finish(&f);
}
int main(int argc,char **argv){assert(argc==2||argc==3);retained=argc==3?argv[2]:NULL;run(argv[1]);printf("PASS %s (injected records; no provider action)\n",argv[1]);return 0;}
