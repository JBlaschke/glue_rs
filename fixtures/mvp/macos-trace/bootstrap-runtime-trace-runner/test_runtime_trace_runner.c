/* Actual parent/trace/files/witness/TS/BIO/object codecs with synthetic POSIX
 * and RT boundaries. No callback forks, signals, traces, execs or opens a file. */
#define _POSIX_C_SOURCE 200809L
#define _DARWIN_C_SOURCE 1
#include "runtime_trace_profile.h"
#include "../bootstrap-runner/runner_internal.h"
#include <assert.h>
#include <errno.h>
#include <fcntl.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>
#ifdef __APPLE__
#include <sys/stdio.h>
#endif
#define CHECK(x) do {if(!(x)){fprintf(stderr,"line %d: %s\n",__LINE__,#x);exit(1);}}while(0)
enum scenario { GOOD,NO_READY,HELPER_FAIL,GO_PARTIAL,GO_FULL,GO_AND_CLOSE,STATUS_FULL,
 LOST,REAP_CLOCK,CLEANUP_CLOCK,HELD_OPEN,CWD_OPEN,BACKEND_CLOSE,SNAPSHOT_FAIL,DESTROY_FAIL,
 WITNESS_WRITE,WITNESS_CLOSE,PREFIX_WRITE,DELIVERY_WRITE,SIDECAR_CLOSE,PENDING_CLOSE,OUTPUT_CLOSE,SIMULATED,OVERSIZE,CREATE_FAIL,START_FAIL };
struct retained {const char *name;int fd,created,closed;size_t used,offset;unsigned char bytes[NRR_OUTPUT_BYTES];};
struct rt_backend {struct rt_snapshot snapshot;int alive;};
static struct {
 enum scenario mode;struct nr_attempt *a;struct rt_backend backend;uint64_t now,cleanup;
 unsigned forks,waits,kills,go_calls,go_bytes,pumps,starts,stops,drains,closes,creates,destroys,snapshots,final_snapshots,owner_calls,owner_at_destroy;
 unsigned readiness,zero_reads,deadlines,events,promotion_event,promotions,closed[128],clock_calls,prepare_calls;
 int clock_bad,reaped;unsigned output_closed_at;uint8_t status[1537];size_t status_size,status_offset;
 struct retained files[10];
} m;
static struct retained *named(const char *name){for(unsigned i=0;i<10;i++)if(!strcmp(m.files[i].name,name))return &m.files[i];CHECK(0);return NULL;}
static struct retained *byfd(int fd){for(unsigned i=0;i<10;i++)if(m.files[i].fd==fd)return &m.files[i];return NULL;}
int nr_fail(struct nr_attempt*a,enum nr_stage s,enum nr_reason r,int e,int d){if(a->error.stage==NR_NONE)a->error=(struct nr_error){s,r,e,d};return -1;}
int nr_close_owned(struct nr_attempt*a,int*fd,enum nr_stage s){
 if(*fd<0)return 0;
 int n=*fd;*fd=-1;CHECK(n<128&&++m.closed[n]==1);m.events++;if(n==40)m.output_closed_at=m.events;
 struct retained*f=byfd(n);if(f)f->closed=(int)m.events;
 int bad=(n==19&&m.mode==GO_AND_CLOSE)||(n==40&&m.mode==OUTPUT_CLOSE)||
  (f&&((m.mode==WITNESS_CLOSE&&!strcmp(f->name,"output-witness.bin"))||
       (m.mode==SIDECAR_CLOSE&&!strcmp(f->name,"trace.json"))||
       (m.mode==PENDING_CLOSE&&!strcmp(f->name,"result.pending"))));
 if(bad){errno=EINTR;a->close_failed=1;return nr_fail(a,s,NR_SYSCALL,EINTR,n);}return 0;
}
int nr_clock(struct nr_attempt*a,uint64_t*out){m.clock_calls++;if(m.clock_bad)return nr_fail(a,NR_PREFLIGHT,NR_CLOCK,0,-1);*out=m.now;return 0;}
int nr_before(struct nr_attempt*a,struct bio_time d,enum nr_stage s){if(m.clock_bad)return nr_fail(a,s,NR_CLOCK,0,-1);return m.now>=d.seconds*UINT64_C(1000000000)+d.nanoseconds?nr_fail(a,s,NR_TIMEOUT,0,-1):0;}
int nr_deadline(struct nr_attempt*a,unsigned budget,struct bio_time*out){CHECK(budget==100&&++m.deadlines==1);if(m.mode==CLEANUP_CLOCK||m.clock_bad)return nr_fail(a,NR_CLEANUP,NR_CLOCK,0,-1);m.cleanup=m.now+UINT64_C(100000000);*out=(struct bio_time){m.cleanup/1000000000,m.cleanup%1000000000};return 0;}
/* Explicit deterministic hash stub, not cryptographic/native provenance. */
int nr_sha_bytes(const uint8_t*p,size_t n,uint8_t out[32]){memset(out,0,32);for(size_t i=0;i<n;i++)out[i%32]^=(uint8_t)(p[i]+i);return 0;}
int nr_read_request(struct nr_attempt*a,const char*p){(void)p;return nr_fail(a,NR_REQUEST,NR_UNSUPPORTED,0,-1);}
int nr_admit(struct nr_attempt*a){return nr_fail(a,NR_ADMISSION,NR_UNSUPPORTED,0,-1);}
int nrr_prepare(struct nr_attempt*a){m.prepare_calls++;return nr_fail(a,NR_CATALOG,NR_UNSUPPORTED,0,-1);}
static pid_t fake_fork(void){CHECK(++m.forks==1&&!m.creates);return 200;}
static int fake_setpgid(pid_t p,pid_t g){CHECK(p==200&&g==200);return 0;}
static pid_t fake_getpgid(pid_t p){CHECK(p==200);return 200;}
static pid_t fake_wait(pid_t p,int*out,int flags){
 CHECK(p==200&&flags==WNOHANG);m.waits++;
 if(m.mode==LOST&&m.go_calls){errno=ECHILD;return -1;}
 if(!m.kills&&!(m.status_offset==m.status_size&&m.zero_reads>=(m.mode==SIMULATED?1u:2u)))return 0;
 *out=m.kills?9:m.mode==SIMULATED?120<<8:0;m.reaped=1;if(m.mode==REAP_CLOCK)m.clock_bad=1;return 200;
}
static int fake_kill(pid_t p,int sig){CHECK(p==200&&sig==SIGKILL&&!m.reaped&&++m.kills==1);return 0;}
static int fake_nap(const struct timespec*n,struct timespec*r){(void)n;(void)r;m.now+=1000000;return 0;}
static int fake_restore(struct bs_state*s,struct bs_error*e){memset(e,0,sizeof(*e));s->restore_attempted=s->pipe_restored=s->mask_restored=1;return 0;}
static _Noreturn void fake_child(struct nr_attempt*a){(void)a;abort();}
#ifdef __APPLE__
static uid_t fake_root(void){return 0;}
static int fake_prepare(const struct bs_operations*o,struct bs_state*s,struct bs_error*e){(void)o;(void)s;(void)e;CHECK(0);return -1;}
#endif
static int io_clock(void*c,struct bio_time*out,int*e){(void)c;if(m.clock_bad){*e=EIO;return -1;}*out=(struct bio_time){m.now/1000000000,m.now%1000000000};return 0;}
static int io_stat(void*c,int fd,mode_t*mode,int*e){(void)c;(void)e;CHECK(fd==19||fd==20);*mode=S_IFIFO;return 0;}
static int io_flags(void*c,int fd,int*e){(void)c;(void)e;CHECK(fd==19||fd==20);return O_NONBLOCK|(fd==19?O_WRONLY:O_RDONLY);}
static int io_poll(void*c,int fd,short wanted,int timeout,short*events,int*e){(void)c;(void)e;CHECK((fd==19||fd==20)&&timeout>0);*events=wanted;return 1;}
static ssize_t io_read(void*c,int fd,void*out,size_t n,int*e){(void)c;(void)e;CHECK(fd==20);size_t count=m.status_size-m.status_offset;if(count>n)count=n;memcpy(out,m.status+m.status_offset,count);m.status_offset+=count;if(!count)m.zero_reads++;return (ssize_t)count;}
static ssize_t io_write(void*c,int fd,const void*p,size_t n,int*e){(void)c;(void)e;CHECK(fd==19&&n==64&&++m.go_calls==1&&m.readiness==2);CHECK(m.a->trace.session.go_possibly_released&&m.a->runtime_witness_written);CHECK(!memcmp(p,"GLUEFG02",8));m.go_bytes=m.mode==GO_PARTIAL?13:64;return (ssize_t)m.go_bytes;}
static const struct bio_operations *fake_io(void){static const struct bio_operations o={NULL,io_clock,io_stat,io_flags,io_poll,io_read,io_write};return &o;}
static uint32_t b_owner(void*c,int*e){struct rt_backend*b=c;(void)e;CHECK(b->alive);m.owner_calls++;return 100;}
static int b_clock(void*c,uint64_t*out,int*e){struct rt_backend*b=c;CHECK(b->alive);if(m.clock_bad){*e=EIO;return -1;}*out=m.now;return 0;}
static int b_start(void*c,const struct ts_binding*b,uint64_t d,int*e){struct rt_backend*backend=c;(void)e;CHECK(backend->alive&&b->fixture==2&&b->owner_pid==100&&b->target_pid==200&&d==UINT64_C(2000000000));m.starts++;backend->snapshot.start_attempted=1;if(m.mode==START_FAIL){backend->snapshot.first_error=(struct rt_error){RT_START,RT_LIBDTRACE,0,123,EIO,"injected start failure"};*e=EIO;return -1;}backend->snapshot.started=1;return 0;}
static int b_event(struct rt_backend*b,ts_consume_fn consume,void*ctx,enum ts_event_kind kind){struct ts_event ev={kind,b->snapshot.binding};return consume(ctx,&ev);}
static int b_pump(void*c,enum ts_phase phase,uint64_t d,ts_consume_fn consume,void*ctx,int*e){
 struct rt_backend*b=c;CHECK(b->alive&&d==(phase==TS_CLEANUP?m.cleanup:UINT64_C(2000000000)));m.pumps++;
 if(m.mode==NO_READY||((m.mode==GO_PARTIAL||m.mode==GO_FULL||m.mode==GO_AND_CLOSE)&&m.go_bytes)||
    (m.mode==STATUS_FULL&&m.status_offset==1537)){
  b->snapshot.first_error=(struct rt_error){RT_PUMP,RT_CONSUMER,0,0,EIO,"injected observer fault"};*e=EIO;return -1;
 }
 if(!m.readiness){CHECK(!b_event(b,consume,ctx,TS_PROVIDER_READY));m.readiness=1;}
 else if(m.readiness==1){CHECK(!b_event(b,consume,ctx,TS_BEGIN));m.readiness=2;b->snapshot.begin_count=1;}
 return 0;
}
static int b_stop(void*c,uint64_t d,int*e){struct rt_backend*b=c;(void)e;CHECK(b->alive&&m.a->trace.session.child!=TS_CHILD_LIVE&&d==m.cleanup);m.stops++;b->snapshot.stop_attempted=b->snapshot.stopped=1;b->snapshot.cleanup_deadline_ns=d;return 0;}
static int b_drain(void*c,uint64_t d,ts_consume_fn consume,void*ctx,int*e){struct rt_backend*b=c;(void)e;CHECK(b->alive&&m.reaped&&d==m.cleanup);m.drains++;b->snapshot.drain_attempted=1;
 if(m.go_calls&&m.readiness==2){CHECK(!b_event(b,consume,ctx,TS_TERMINAL));CHECK(!b_event(b,consume,ctx,TS_END));b->snapshot.terminal_count=b->snapshot.end_count=1;}
 b->snapshot.drained=1;b->snapshot.selected_exec_entry_count=b->snapshot.selected_exec_success_count=m.mode==GOOD?2:0;return 0;}
static int b_close(void*c,uint64_t d,int*e){struct rt_backend*b=c;CHECK(b->alive&&d==(m.cleanup?m.cleanup:UINT64_C(2000000000))&&++m.closes==1);b->snapshot.close_attempted=1;b->snapshot.writer_close_attempted_mask=15;
 if(m.mode==BACKEND_CLOSE){b->snapshot.writer_close_failed_mask=8;b->snapshot.writer_close_errno[3]=EINTR;b->snapshot.writer_close_error=(struct rt_error){RT_CLOSE,RT_POSIX,EINTR,0,EIO,"injected close ambiguity"};*e=EIO;return -1;}b->snapshot.resources_closed=1;return 0;}
int rt_recipe_images_create(struct rt_backend**out,int fd,const struct ts_binding*b,uint64_t d,int ready,struct ts_operations*ops,struct rt_error*error){
 CHECK(fd==40&&ready==1&&++m.creates==1&&m.a->ready_matched&&m.a->objects_matched&&m.a->runtime_witness_written&&m.a->runtime_witness_attempted);
 CHECK(named("output-witness.bin")->closed&&b->fixture==2&&b->owner_pid==100&&b->target_pid==200&&d==UINT64_C(2000000000));
 CHECK(!memcmp(b->request_sha256,m.a->request_sha,32)&&!memcmp(b->catalog_sha256,m.a->catalog_sha,32));
 memset(error,0,sizeof(*error));if(m.mode==CREATE_FAIL){*out=NULL;*error=(struct rt_error){RT_CREATE,RT_LIBDTRACE,0,123,EIO,"injected create failure"};return -1;}m.backend.alive=1;m.backend.snapshot.binding=*b;m.backend.snapshot.original_attempt_deadline_ns=d;*out=&m.backend;
 *ops=(struct ts_operations){&m.backend,b_owner,b_clock,b_start,b_pump,b_stop,b_drain,b_close};return 0;
}
int rt_snapshot(const struct rt_backend*b,struct rt_snapshot*out){CHECK(b&&b->alive);m.snapshots++;if(m.a->trace.session.parent_close_seen)m.final_snapshots++;if(m.mode==SNAPSHOT_FAIL&&m.a->trace.session.parent_close_seen)return -1;*out=b->snapshot;return 0;}
int rt_destroy(struct rt_backend**b){CHECK(b&&*b&&(*b)->alive&&m.a->trace.parent_reported&&++m.destroys==1);if(!(*b)->snapshot.resources_closed||m.mode==DESTROY_FAIL)return -1;m.owner_at_destroy=m.owner_calls;(*b)->alive=0;*b=NULL;return 0;}
/* Source-isolated match boundary: the real helper has its separate observed-
 * sampling controls. Parent keeps exact source references and original rows. */
int tfo_match_regular_outputs_observed(const struct tfo_snapshot*s,const int held[2],const struct tfo_operations*o,struct tfo_matches*out,struct tfo_reference_observation*seen,struct tfo_error*e){
 (void)o;CHECK(s->ready&&held[0]==16&&held[1]==17&&!m.creates&&!m.go_calls);memset(out,0,sizeof(*out));memset(seen,0,sizeof(*seen));*e=(struct tfo_error){TFO_STAGE_NONE,TFO_REASON_NONE,0,-1,-1};
 seen->completed_samples=m.mode==HELPER_FAIL?3:4;
 for(unsigned i=0;i<seen->completed_samples;i++){seen->samples[i]=s->entries[1+i%2];seen->samples[i].fd=held[i%2];seen->samples[i].descriptor_flags=1;}
 if(m.mode==HELPER_FAIL){seen->samples[2].status_flags^=2;*e=(struct tfo_error){TFO_STAGE_STABILITY,TFO_REASON_CHANGED,0,1,16};return -1;}
 out->ready=1;return 0;
}
const struct tfo_operations*tfo_native_operations(void){static const struct tfo_operations o={0};return &o;}
static int fake_openat(int fd,const char*name,int flags,...){CHECK(fd==40);struct retained*f=named(name);CHECK(f);if(flags&O_CREAT){CHECK(!f->created);f->created=1;}else CHECK(f->created);f->offset=0;return f->fd;}
static int fake_open(const char*p,int flags,...){(void)p;(void)flags;CHECK(0);return -1;}
static int fake_stat(int fd,struct stat*out){struct retained*f=byfd(fd);CHECK(f&&(fd==41||fd==42));memset(out,0,sizeof(*out));out->st_mode=S_IFREG|0600;out->st_nlink=1;out->st_dev=7;out->st_ino=fd==41?100:101;out->st_size=(off_t)f->used;return 0;}
static ssize_t fake_read(int fd,void*out,size_t n){struct retained*f=byfd(fd);CHECK(f&&(fd==41||fd==42));size_t count=f->used-f->offset;if(count>n)count=n;CHECK(f->offset+count<=sizeof(f->bytes));memcpy(out,f->bytes+f->offset,count);f->offset+=count;return (ssize_t)count;}
static ssize_t fake_write(int fd,const void*p,size_t n){struct retained*f=byfd(fd);CHECK(f&&f->created);m.events++;
 if((m.mode==WITNESS_WRITE&&!strcmp(f->name,"output-witness.bin"))||(m.mode==PREFIX_WRITE&&!strcmp(f->name,"go-prefix.bin"))||(m.mode==DELIVERY_WRITE&&!strcmp(f->name,"gate-delivery.bin"))){errno=ENOSPC;return -1;}
 CHECK(f->used+n<=sizeof(f->bytes));memcpy(f->bytes+f->used,p,n);f->used+=n;return (ssize_t)n;
}
static int fake_pipe(int*fds){(void)fds;CHECK(0);return -1;}
static int fake_fcntl(int fd,int action,...){(void)fd;(void)action;CHECK(0);return -1;}
#ifdef __APPLE__
static int fake_statat(int fd,const char*p,struct stat*s,int flags){(void)fd;(void)p;(void)s;(void)flags;CHECK(0);return -1;}
static int fake_mkdirat(int fd,const char*p,mode_t mode){(void)fd;(void)p;(void)mode;CHECK(0);return -1;}
static int fake_rename(const char*from,const char*to,unsigned flags){CHECK(strstr(from,"/result.pending")&&strstr(to,"/result.json")&&flags==RENAME_EXCL);CHECK(named("result.pending")->closed&&(unsigned)named("result.pending")->closed>m.output_closed_at&&m.output_closed_at>(unsigned)named("trace.json")->closed&&!m.backend.alive);m.promotions++;m.promotion_event=++m.events;return 0;}
#define bs_prepare_parent fake_prepare
#define getuid fake_root
#define geteuid fake_root
#define fstatat fake_statat
#define mkdirat fake_mkdirat
#define renamex_np fake_rename
#endif
#define fork fake_fork
#define setpgid fake_setpgid
#define getpgid fake_getpgid
#define waitpid fake_wait
#define kill fake_kill
#define nanosleep fake_nap
#define bs_restore_parent fake_restore
#define nr_child fake_child
#define bio_native_operations fake_io
#define openat fake_openat
#define open fake_open
#define fstat fake_stat
#define read fake_read
#define write fake_write
#define pipe fake_pipe
#define fcntl fake_fcntl
#include "../bootstrap-runner/runner_parent.c"
#include "../bootstrap-runner/runner_trace.c"
#include "../bootstrap-runner/runner_files.c"
#include "../bootstrap-runtime-runner/runtime_witness.c"
#undef write
static uint32_t be32(const unsigned char*p){return (uint32_t)p[0]<<24|(uint32_t)p[1]<<16|(uint32_t)p[2]<<8|p[3];}
static void initialize(struct nr_attempt*a,enum scenario mode){
 static struct nrr_catalog catalog;static const struct tl_span args[]={{(const uint8_t*)"run",3},{(const uint8_t*)BA_PREFIX"build/app.glue",sizeof(BA_PREFIX"build/app.glue")-1},{(const uint8_t*)"--",2},{(const uint8_t*)"argument with spaces",20}};
 memset(&m,0,sizeof(m));memset(a,0,sizeof(*a));m.a=a;m.mode=mode;m.now=UINT64_C(1000000000);
 const char*names[]={"app.stdout","app.stderr","output-witness.bin","go-prefix.bin","gate-delivery.bin","status.bin","trace.json","launch-plan.bin","result.pending","unused"};
 for(unsigned i=0;i<10;i++){m.files[i].name=names[i];m.files[i].fd=41+(int)i;}
 memcpy(m.files[0].bytes,"\0opaque\n",8);m.files[0].used=mode==OVERSIZE?NRR_OUTPUT_BYTES+1:8;m.files[0].created=1;
 memcpy(m.files[1].bytes,"err",3);m.files[1].used=3;m.files[1].created=1;
 memset(&catalog,0,sizeof(catalog));catalog.launcher_bytes=1;strcpy(catalog.build_id,"build");strcpy(catalog.leaf,"glue");strcpy(catalog.cwd_name,"unrelated");catalog.deployment.root.device=1;catalog.deployment.root.fsid[0]=2;catalog.deployment.data.device=7;catalog.deployment.data.fsid[0]=3;catalog.launch=(struct tl_recipe){TL_AARCH64_DARWIN,args,4,0};
 a->runtime_catalog=&catalog;a->owner=100;a->child=-1;a->output_fd=40;a->runtime_cwd_fd=31;a->held_outputs[0]=a->held_outputs[1]=-1;a->deadline=(struct bio_time){2,0};strcpy(a->output_path,NR_OUTPUT_PREFIX"model");
 CHECK(!nrr_catalog_paths(&catalog,a->executable,a->cwd));struct tl_error le;CHECK(!tl_prepare(&catalog.launch,(struct tl_span){(const uint8_t*)a->executable,strlen(a->executable)},&a->runtime_plan,&le));
 a->request.fixture=a->request.argv_template=2;a->request.credentials.uid=501;a->request.credentials.gid=20;a->request.credentials.group_count=1;a->request.credentials.groups[0]=20;a->request.signal_policy=a->request.stdio_policy=1;a->request.release_action=mode==SIMULATED?BR_SIMULATED_PROVIDER_FAILURE:BR_SEND_GO;a->request.max_live_fds=4096;a->request.attempt_ms=1000;a->request.cleanup_ms=100;a->request.cwd_device=7;a->request.cwd_inode=88;a->request.executable=(struct br_span){(const uint8_t*)a->executable,strlen(a->executable)};a->request.cwd=(struct br_span){(const uint8_t*)a->cwd,strlen(a->cwd)};
 uint8_t canonical[NRR_CATALOG_CAPACITY];size_t used;CHECK(!nrr_catalog_bytes(&catalog,canonical,&used));CHECK(!nr_sha_bytes(canonical,used,a->catalog_sha));memcpy(a->request.catalog_sha256,a->catalog_sha,32);struct br_error re;CHECK(rr_request_encode(&a->request,a->request_wire,&a->request_size,&re)==BR_OK);CHECK(!nr_sha_bytes(a->request_wire,a->request_size,a->request_sha));memset(a->policy_sha,0x33,32);
 for(unsigned i=0;i<5;i++){a->endpoints.copies[i]=10+(int)i;a->sources[i]=15+(int)i;}a->endpoints.owned_count=5;a->gate[0]=18;a->gate[1]=19;a->status[0]=20;a->status[1]=21;a->sources[3]=18;a->sources[4]=21;a->ready_context_fds[0]=13;a->ready_context_fds[1]=14;
 for(unsigned i=0;i<7;i++)a->admission.components[i].fd=22+(int)i;
 a->admission.owned_count=7;a->signals_initialized=1;a->stdout_identity.st_dev=a->stderr_identity.st_dev=7;a->stdout_identity.st_ino=100;a->stderr_identity.st_ino=101;
 struct bw_status s={0};s.binding=(struct bw_binding){100,200,{0}};memcpy(s.binding.request_sha256,a->request_sha,32);s.kind=BW_READY;s.detail=-1;s.mutation_flags=3;s.real_uid=s.effective_uid=501;s.real_gid=s.effective_gid=20;s.group_count=1;s.groups[0]=20;s.cwd_device=7;s.cwd_inode=88;memcpy(s.signal_policy_sha256,a->policy_sha,32);
 struct tfo_snapshot objects={0};objects.ready=1;objects.controller_pid=100;objects.child_pid=200;
 for(unsigned i=0;i<5;i++){s.kept_fds[i]=i<3?i:i+10;objects.entries[i]=(struct tfo_entry){(int)s.kept_fds[i],i<3?0:1,i==1||i==2?0x1000001:i==4?5:i==3?4:0,{7,i+99,1,(uint32_t)(i==0?S_IFCHR:i<3?S_IFREG:S_IFIFO)}};}
 CHECK(bow_status_encode(&s,&objects,m.status)==BW_OK);
 memset(&s,0,sizeof(s));s.binding=(struct bw_binding){100,200,{0}};memcpy(s.binding.request_sha256,a->request_sha,32);s.kind=mode==SIMULATED?BW_ERROR:BW_EXEC_ATTEMPT;s.sequence=1;s.stage=mode==SIMULATED?BW_GO_IO:BW_EXEC;s.detail=-1;s.mutation_flags=3;if(mode==SIMULATED)s.reason=BW_EOF;
 CHECK(bow_status_encode(&s,NULL,m.status+512)==BW_OK);m.status_size=1024;
 if(mode==STATUS_FULL){s.kind=BW_ERROR;s.sequence=2;s.stage=BW_EXEC;s.reason=BW_SYSCALL;s.system_errno=EIO;CHECK(bow_status_encode(&s,NULL,m.status+1024)==BW_OK);m.status[1536]=0xa5;m.status_size=1537;}
}
static void emit_hex(FILE*out,const unsigned char*p,size_t n){static const char h[]="0123456789abcdef";fputc('"',out);for(size_t i=0;i<n;i++){fputc(h[p[i]>>4],out);fputc(h[p[i]&15],out);}fputc('"',out);}
static void emit(int executed,int finished){
 printf("{\"execute\":%d,\"finish\":%d,\"stats\":{\"creates\":%u,\"go_calls\":%u,\"go_bytes\":%u,\"kills\":%u,\"closes\":%u,\"destroys\":%u,\"snapshots\":%u,\"final_snapshots\":%u,\"promotions\":%u,\"status_bytes\":%zu,\"session_prefix\":%zu,\"parent_reported\":%d,\"backend_alive\":%d},\"trace\":%s,\"pending_result\":%s,\"files\":{",executed,finished,m.creates,m.go_calls,m.go_bytes,m.kills,m.closes,m.destroys,m.snapshots,m.final_snapshots,m.promotions,m.a->stream.used,m.a->trace.session.bootstrap_prefix_bytes,m.a->trace.parent_reported,m.backend.alive,named("trace.json")->used?(char*)named("trace.json")->bytes:"null",named("result.pending")->used?(char*)named("result.pending")->bytes:"null");
 int comma=0;for(unsigned i=0;i<8;i++)if(m.files[i].created&&i!=6&&m.files[i].used<=NRR_OUTPUT_BYTES){printf("%s\"%s\":",comma?",":"",m.files[i].name);emit_hex(stdout,m.files[i].bytes,m.files[i].used);comma=1;}puts("}}");
}
int main(int argc,char**argv){
 CHECK(argc==2);unsigned value=(unsigned)strtoul(argv[1],NULL,10);CHECK(value<=START_FAIL);struct nr_attempt a;initialize(&a,(enum scenario)value);
 CHECK(nr_native_run_once("/must-not-read-runtime-trace","/must-not-create-runtime-trace")==2&&!m.creates&&!m.forks&&!m.clock_calls&&!m.prepare_calls);a.error=(struct nr_error){0};
 int executed=nr_execute(&a);struct nr_error original=a.error;nr_cleanup(&a);
 if(original.stage)CHECK(a.error.stage==original.stage&&a.error.reason==original.reason&&a.error.saved_errno==original.saved_errno);
 if(value==HELD_OPEN)a.held_outputs[0]=90;
 if(value==CWD_OPEN)a.runtime_cwd_fd=91;
 int finished=nr_finish_outputs(&a);CHECK(m.go_calls<=1&&m.destroys<=1);
 if(!m.backend.alive&&m.destroys)CHECK(m.owner_calls==m.owner_at_destroy);
 if(value==GOOD){CHECK(!executed&&a.stream.used==1024&&a.trace.session.bootstrap_prefix_bytes==1024&&m.go_calls==1&&m.go_bytes==64&&!m.kills&&a.runtime_witness_written&&a.runtime_delivery_written&&a.trace.destroyed);CHECK(named("output-witness.bin")->used==320&&named("gate-delivery.bin")->used==240&&named("go-prefix.bin")->used==64);CHECK(be32(named("gate-delivery.bin")->bytes+144)==0);}
 if(value==NO_READY||value==HELPER_FAIL||value==WITNESS_WRITE||value==WITNESS_CLOSE||value==CREATE_FAIL||value==START_FAIL)CHECK(!m.go_calls);
 if(value==HELPER_FAIL)CHECK(!m.creates&&named("output-witness.bin")->used==320&&be32(named("output-witness.bin")->bytes+24)==3);
 if(value==GO_PARTIAL||value==GO_FULL||value==GO_AND_CLOSE){CHECK(executed&&a.runtime_delivery_written&&m.go_calls==1&&!a.trace.session.go_complete);CHECK(be32(named("gate-delivery.bin")->bytes+148)==UINT32_MAX);if(value==GO_AND_CLOSE)CHECK(a.error.stage==NR_TRACE&&a.error.saved_errno==0&&be32(named("gate-delivery.bin")->bytes+156)==UINT32_MAX);}
 if(value==CREATE_FAIL)CHECK(!m.starts&&!m.closes&&!m.destroys&&m.kills==1);
 if(value==START_FAIL)CHECK(m.starts==1&&m.closes==1&&m.destroys==1&&!m.stops&&!m.drains);
 if(value==STATUS_FULL)CHECK(a.stream.used==1537&&a.trace.session.bootstrap_prefix_bytes==1537&&!a.trace.session.bootstrap_sealed);
 if(value==LOST||value==REAP_CLOCK)CHECK(!m.kills);
 if(value==LOST)CHECK(a.lost_child&&!m.promotions);
 if(value==CLEANUP_CLOCK)CHECK(!a.trace.cleanup_valid&&!m.stops&&!m.drains&&m.closes==1);
 if(value==HELD_OPEN||value==CWD_OPEN){CHECK(finished&&a.trace.finalized&&a.trace.parent_reported&&m.destroys==1&&!m.promotions);unsigned count=m.destroys,samples=m.snapshots;CHECK(nr_finish_outputs(&a)&&m.destroys==count&&m.snapshots==samples);}
 if(value==BACKEND_CLOSE||value==SNAPSHOT_FAIL||value==DESTROY_FAIL||value==SIDECAR_CLOSE||value==PENDING_CLOSE||value==OUTPUT_CLOSE)CHECK(finished&&!m.promotions);
 if(value==WITNESS_WRITE||value==WITNESS_CLOSE)CHECK(!a.runtime_witness_written&&!m.creates);
 if(value==PREFIX_WRITE||value==DELIVERY_WRITE)CHECK(!a.runtime_delivery_written);
 if(a.trace.finalized){unsigned samples=m.snapshots,destroyed=m.destroys,owners=m.owner_calls;int safe=nr_trace_parent_closed(&a,!a.trace.resources_safe);CHECK((safe==0)==a.trace.resources_safe&&m.snapshots==samples&&m.destroys==destroyed&&m.owner_calls==owners);}
 if(m.promotions)CHECK(m.promotion_event==m.events);
 emit(executed,finished);return 0;
}
