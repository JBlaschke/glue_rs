/* Actual parent/trace/files/TS/BIO/BW code with source-isolated POSIX and backend
 * boundaries. No callback forks, waits, kills, closes, traces or executes. */
#define _POSIX_C_SOURCE 200809L
#define _DARWIN_C_SOURCE 1
#define GLUE_OWNED_TRACING 1
#include "runner_internal.h"
#include <assert.h>
#include <errno.h>
#include <fcntl.h>
#include <signal.h>
#include <stdarg.h>
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
enum mode {GOOD,DENIED,START_FAIL,GO_PARTIAL,GO_FULL,STATUS_FULL,EOF_FAIL,LOST,REAP_CLOCK,CLOSE_FAIL,GATE_FAIL,SIDECAR_FAIL,PENDING_FAIL,DIR_FAIL,SIM,READINESS_FAIL};
struct otb_backend {struct otb_snapshot snapshot;int alive;};
static struct {
 enum mode mode;struct nr_attempt *attempt;struct otb_backend backend;
 uint64_t now,cleanup;unsigned zero_reads,forks,waits,kills,go_writes,go_bytes,deadlines,pumps,starts,stops,drains,closes,owner_calls,destroy_owner_calls;
 int readiness,terminal,clock_bad,wait_done,closed[64],events,sidecar_closed_at,dir_closed_at,pending_closed_at,promoted_at,promotions;
 uint8_t status[768],probe[NP_REPORT_SIZE];size_t status_size,status_offset,probe_offset;
 char receipt[8192],sidecar[16384];
} m;
int nr_fail(struct nr_attempt *a,enum nr_stage stage,enum nr_reason reason,int e,int detail) {
 if(a->error.stage==NR_NONE)a->error=(struct nr_error){stage,reason,e,detail};return -1;
}
int nr_close_owned(struct nr_attempt *a,int *fd,enum nr_stage stage) {
 if(*fd<0)return 0;int f=*fd;*fd=-1;CHECK(f>=0&&f<64&&++m.closed[f]==1);m.events++;
 if(f==45)m.sidecar_closed_at=m.events;if(f==40)m.dir_closed_at=m.events;if(f==44)m.pending_closed_at=m.events;
 if((f==19&&m.mode==GATE_FAIL)||(f==45&&m.mode==SIDECAR_FAIL)||(f==44&&m.mode==PENDING_FAIL)||(f==40&&m.mode==DIR_FAIL)){
  errno=EINTR;a->close_failed=1;return nr_fail(a,stage,NR_SYSCALL,EINTR,f);
 }
 return 0;
}
int nr_clock(struct nr_attempt *a,uint64_t *out) {if(m.clock_bad)return nr_fail(a,NR_PREFLIGHT,NR_CLOCK,0,-1);*out=m.now;return 0;}
int nr_before(struct nr_attempt *a,struct bio_time d,enum nr_stage stage) {
 if(m.clock_bad)return nr_fail(a,stage,NR_CLOCK,0,-1);
 if(m.now>=d.seconds*UINT64_C(1000000000)+d.nanoseconds)return nr_fail(a,stage,NR_TIMEOUT,0,-1);return 0;
}
int nr_deadline(struct nr_attempt *a,unsigned budget,struct bio_time *out) {
 CHECK(budget==100&&++m.deadlines==1);if(m.clock_bad)return nr_fail(a,NR_CLEANUP,NR_CLOCK,0,-1);
 m.cleanup=m.now+UINT64_C(100000000);*out=(struct bio_time){m.cleanup/1000000000,m.cleanup%1000000000};return 0;
}
int nr_sha_bytes(const uint8_t *p,size_t n,uint8_t out[32]) {(void)p;(void)n;memset(out,0,32);return 0;}
int nr_read_request(struct nr_attempt *a,const char *p){(void)p;return nr_fail(a,NR_REQUEST,NR_UNSUPPORTED,0,-1);}
int nr_admit(struct nr_attempt *a){return nr_fail(a,NR_ADMISSION,NR_UNSUPPORTED,0,-1);}
static pid_t model_fork(void){CHECK(++m.forks==1&&!m.backend.alive);return 200;}
static int model_setpgid(pid_t p,pid_t g){CHECK(p==200&&g==200);return 0;}
static pid_t model_getpgid(pid_t p){CHECK(p==200);return 200;}
static pid_t model_wait(pid_t p,int *status,int flags){
 CHECK(p==200&&flags==WNOHANG);m.waits++;
 if(m.mode==LOST){errno=ECHILD;return -1;}
 if(m.mode!=GOOD&&m.mode!=REAP_CLOCK&&m.mode!=SIM&&!m.kills)return 0;
 if(m.waits==1&&m.mode==GOOD)return 0;
 *status=m.mode==SIM?120<<8:0;m.wait_done=1;
 if(m.mode==REAP_CLOCK)m.clock_bad=1;
 return 200;
}
static int model_kill(pid_t p,int sig){CHECK(p==200&&sig==SIGKILL&&!m.wait_done&&++m.kills==1);return 0;}
static int model_nap(const struct timespec *n,struct timespec *r){(void)n;(void)r;m.now+=1000000;return 0;}
static int model_restore(struct bs_state *s,struct bs_error *e){memset(e,0,sizeof(*e));s->restore_attempted=1;s->pipe_restored=s->mask_restored=1;return 0;}
static _Noreturn void model_child(struct nr_attempt *a){(void)a;abort();}
static int io_clock(void *c,struct bio_time *d,int *e){(void)c;if(m.clock_bad){*e=EIO;return -1;}*d=(struct bio_time){m.now/1000000000,m.now%1000000000};return 0;}
static int io_stat(void *c,int fd,mode_t *mode,int *e){(void)c;(void)e;CHECK(fd==19||fd==20);*mode=S_IFIFO;return 0;}
static int io_flags(void *c,int fd,int *e){(void)c;(void)e;CHECK(fd==19||fd==20);return O_NONBLOCK|(fd==19?O_WRONLY:O_RDONLY);}
static int io_poll(void *c,int fd,short wanted,int timeout,short *events,int *e){(void)c;(void)e;CHECK((fd==19||fd==20)&&timeout>0);*events=wanted;return 1;}
static ssize_t io_read(void *c,int fd,void *p,size_t n,int *e){(void)c;(void)e;CHECK(fd==20);size_t amount=m.status_size-m.status_offset;if(amount>n)amount=n;memcpy(p,m.status+m.status_offset,amount);m.status_offset+=amount;if(!amount)m.zero_reads++;return (ssize_t)amount;}
static ssize_t io_write(void *c,int fd,const void *p,size_t n,int *e){(void)c;(void)p;(void)e;CHECK(fd==19&&n==64&&++m.go_writes==1);CHECK(m.attempt->trace.session.go_possibly_released&&m.readiness==2);m.go_bytes=m.mode==GO_PARTIAL?13:64;return (ssize_t)m.go_bytes;}
static const struct bio_operations *model_io(void){static const struct bio_operations o={NULL,io_clock,io_stat,io_flags,io_poll,io_read,io_write};return &o;}
static uint32_t backend_owner(void *c,int *e){struct otb_backend *b=c;(void)e;CHECK(b->alive);m.owner_calls++;return 100;}
static int backend_clock(void *c,uint64_t *now,int *e){struct otb_backend *b=c;CHECK(b->alive);if(m.clock_bad){*e=EIO;return -1;}*now=m.now;return 0;}
static int backend_start(void *c,const struct ts_binding *binding,uint64_t d,int *e){struct otb_backend *b=c;CHECK(b->alive&&binding->target_pid==200&&d==UINT64_C(2000000000));m.starts++;b->snapshot.start_attempted=1;
 if(m.mode==START_FAIL){b->snapshot.first_error=(struct otb_error){OTB_START,OTB_LIBDTRACE,0,123,EIO,"library failure"};*e=EIO;return -1;}b->snapshot.started=1;return 0;}
static void event(struct otb_backend *b,ts_consume_fn consume,void *ctx,enum ts_event_kind kind){struct ts_event ev={kind,b->snapshot.binding};CHECK(consume(ctx,&ev)==0);b->snapshot.events++;}
static int backend_pump(void *c,enum ts_phase phase,uint64_t d,ts_consume_fn consume,void *ctx,int *e){
 struct otb_backend *b=c;CHECK(b->alive);m.pumps++;CHECK(d==(phase==TS_CLEANUP?m.cleanup:UINT64_C(2000000000)));
 if(m.mode==READINESS_FAIL){*e=EIO;return -1;}
 if((m.mode==GO_PARTIAL||m.mode==GO_FULL)&&m.go_bytes){*e=EIO;return -1;}
 if((m.mode==STATUS_FULL&&m.status_offset==512)||(m.mode==EOF_FAIL&&m.zero_reads==2)){*e=EIO;return -1;}
 if(!m.readiness){event(b,consume,ctx,TS_PROVIDER_READY);m.readiness=1;}
 else if(m.readiness==1){event(b,consume,ctx,TS_BEGIN);m.readiness=2;b->snapshot.begin_count=1;}
 return 0;
}
static int backend_stop(void *c,uint64_t d,int *e){struct otb_backend *b=c;(void)e;CHECK(b->alive&&m.attempt->trace.session.child!=TS_CHILD_LIVE);CHECK(d==(m.cleanup?m.cleanup:UINT64_C(2000000000)));m.stops++;b->snapshot.stop_attempted=b->snapshot.stopped=1;b->snapshot.cleanup_deadline_ns=d;return 0;}
static int backend_drain(void *c,uint64_t d,ts_consume_fn consume,void *ctx,int *e){struct otb_backend *b=c;(void)e;CHECK(b->alive&&m.wait_done&&d==m.cleanup);m.drains++;b->snapshot.drain_attempted=1;
 if(m.go_bytes&&m.readiness==2){event(b,consume,ctx,TS_TERMINAL);b->snapshot.terminal_count=1;event(b,consume,ctx,TS_END);b->snapshot.end_count=1;}b->snapshot.drained=1;return 0;}
static int backend_close(void *c,uint64_t d,int *e){struct otb_backend *b=c;CHECK(b->alive);CHECK(d==(m.cleanup?m.cleanup:UINT64_C(2000000000)));CHECK(++m.closes==1);b->snapshot.close_attempted=1;b->snapshot.writer_close_attempted_mask=15;
 if(m.mode==CLOSE_FAIL){b->snapshot.close_error=(struct otb_error){OTB_CLOSE,OTB_CLOCK,0,0,EOVERFLOW,"clock failure"};b->snapshot.writer_close_error=(struct otb_error){OTB_CLOSE,OTB_POSIX,EINTR,0,EIO,"close failure"};b->snapshot.writer_close_failed_mask=8;b->snapshot.writer_close_errno[3]=EINTR;*e=EIO;return -1;}b->snapshot.resources_closed=1;return 0;}
int otb_create(struct otb_backend **out,int fd,const struct ts_binding *binding,uint64_t d,int ready,struct ts_operations *ops,struct otb_error *error){
 CHECK(fd==40&&ready==1&&m.forks==1&&m.attempt->ready_matched&&!m.backend.alive&&d==UINT64_C(2000000000));memset(error,0,sizeof(*error));m.backend.alive=1;m.backend.snapshot.binding=*binding;m.backend.snapshot.original_attempt_deadline_ns=d;*out=&m.backend;
 *ops=(struct ts_operations){&m.backend,backend_owner,backend_clock,backend_start,backend_pump,backend_stop,backend_drain,backend_close};return 0;
}
int otb_snapshot(const struct otb_backend *b,struct otb_snapshot *out){CHECK(b&&b->alive);*out=b->snapshot;return 0;}
int otb_destroy(struct otb_backend **b){CHECK(b&&*b&&(*b)->alive);if((*b)->snapshot.start_attempted&&!(*b)->snapshot.resources_closed)return -1;CHECK(!m.attempt->trace.session_present||m.attempt->trace.session.parent_close_seen);for(unsigned i=0;i<5;i++)CHECK(m.attempt->sources[i]<0);for(size_t i=0;i<m.attempt->admission.owned_count;i++)CHECK(m.attempt->admission.components[i].fd<0);CHECK(m.attempt->signals.pipe_restored&&m.attempt->signals.mask_restored);m.destroy_owner_calls=m.owner_calls;(*b)->alive=0;*b=NULL;return 0;}
static int model_openat(int fd,const char *name,int flags,...){(void)flags;CHECK(fd==40);if(!strcmp(name,"probe.stdout"))return 41;if(!strcmp(name,"probe.stderr"))return 42;if(!strcmp(name,"status.bin"))return 43;if(!strcmp(name,"result.pending"))return 44;if(!strcmp(name,"trace.json")){CHECK(!m.backend.alive);return 45;}CHECK(0);return -1;}
static int model_open(const char *p,int f,...){(void)p;(void)f;CHECK(0);return -1;}
static int model_stat(int fd,struct stat *s){CHECK(fd==41||fd==42);memset(s,0,sizeof(*s));s->st_mode=S_IFREG|0600;s->st_nlink=1;s->st_ino=fd==41?100:101;s->st_size=fd==41?NP_REPORT_SIZE:0;return 0;}
static ssize_t model_read(int fd,void *p,size_t n){CHECK(fd==41||fd==42);if(fd==42)return 0;size_t amount=NP_REPORT_SIZE-m.probe_offset;if(amount>n)amount=n;memcpy(p,m.probe+m.probe_offset,amount);m.probe_offset+=amount;return (ssize_t)amount;}
static ssize_t model_write(int fd,const void *p,size_t n){CHECK(fd==43||fd==44||fd==45);m.events++;if(fd==44){CHECK(m.dir_closed_at&&n<sizeof(m.receipt));memcpy(m.receipt,p,n);m.receipt[n]=0;}if(fd==45){CHECK(!m.backend.alive&&n<sizeof(m.sidecar));memcpy(m.sidecar,p,n);m.sidecar[n]=0;}return (ssize_t)n;}
static int model_pipe(int *p){(void)p;CHECK(0);return -1;}
static int model_fcntl(int fd,int f,...){(void)fd;(void)f;CHECK(0);return -1;}
#ifdef __APPLE__
static int model_statat(int fd,const char *p,struct stat *s,int f){(void)fd;(void)p;(void)s;(void)f;CHECK(0);return -1;}
static int model_mkdirat(int fd,const char *p,mode_t mode){(void)fd;(void)p;(void)mode;CHECK(0);return -1;}
static int model_rename(const char *from,const char *to,unsigned flags){CHECK(strstr(from,"/result.pending")&&strstr(to,"/result.json")&&flags==RENAME_EXCL);CHECK(m.pending_closed_at>m.dir_closed_at&&m.dir_closed_at>m.sidecar_closed_at&&!m.backend.alive);m.promotions++;m.promoted_at=++m.events;return 0;}
#define fstatat model_statat
#define mkdirat model_mkdirat
#define renamex_np model_rename
#endif
#define fork model_fork
#define setpgid model_setpgid
#define getpgid model_getpgid
#define waitpid model_wait
#define kill model_kill
#define nanosleep model_nap
#define bs_restore_parent model_restore
#define nr_child model_child
#define bio_native_operations model_io
#define openat model_openat
#define open model_open
#define fstat model_stat
#define read model_read
#define write model_write
#define pipe model_pipe
#define fcntl model_fcntl
#include "runner_parent.c"
#include "runner_trace.c"
#include "runner_files.c"
static void init(struct nr_attempt *a,enum mode mode){
 static const struct nr_catalog catalog={0};static const uint8_t exe[]="/x/context-probe",cwd[]="/x";
 memset(&m,0,sizeof(m));memset(a,0,sizeof(*a));m.mode=mode;m.now=1000000000;m.attempt=a;a->catalog=&catalog;a->owner=100;a->child=-1;a->output_fd=40;a->deadline=(struct bio_time){2,0};strcpy(a->output_path,NR_OUTPUT_PREFIX "model");
 a->request.fixture=1;a->request.credentials.uid=501;a->request.credentials.gid=20;a->request.credentials.group_count=1;a->request.credentials.groups[0]=20;
 a->request.signal_policy=a->request.stdio_policy=a->request.argv_template=1;a->request.release_action=mode==SIM?BR_SIMULATED_PROVIDER_FAILURE:BR_SEND_GO;a->request.max_live_fds=4096;a->request.attempt_ms=a->request.cleanup_ms=100;a->request.cwd_device=77;a->request.cwd_inode=88;a->request.executable=(struct br_span){exe,sizeof(exe)-1};a->request.cwd=(struct br_span){cwd,sizeof(cwd)-1};
 for(unsigned i=0;i<5;i++){a->endpoints.copies[i]=10+(int)i;a->sources[i]=15+(int)i;}a->endpoints.owned_count=5;a->gate[0]=18;a->gate[1]=19;a->status[0]=20;a->status[1]=21;a->sources[3]=18;a->sources[4]=21;a->ready_context_fds[0]=13;a->ready_context_fds[1]=14;
 for(unsigned i=0;i<8;i++)a->admission.components[i].fd=22+(int)i;a->admission.owned_count=8;a->signals_initialized=1;
 a->stdout_identity.st_ino=100;a->stderr_identity.st_ino=101;a->stdio_flags[1]=a->stdio_flags[2]=1;
 struct bw_status s={0};s.binding=(struct bw_binding){100,200,{0}};s.kind=BW_READY;s.detail=-1;s.mutation_flags=3;s.real_uid=s.effective_uid=501;s.real_gid=s.effective_gid=20;s.group_count=1;s.groups[0]=20;s.cwd_device=77;s.cwd_inode=mode==DENIED?89:88;s.kept_fds[0]=0;s.kept_fds[1]=1;s.kept_fds[2]=2;s.kept_fds[3]=13;s.kept_fds[4]=14;CHECK(bw_status_encode(&s,m.status)==BW_OK);m.status_size=256;
 s=(struct bw_status){0};s.binding=(struct bw_binding){100,200,{0}};s.kind=mode==SIM?BW_ERROR:BW_EXEC_ATTEMPT;s.sequence=1;s.stage=mode==SIM?BW_GO_IO:BW_EXEC;s.detail=-1;s.mutation_flags=3;if(mode==SIM){s.reason=BW_EOF;}
 CHECK(bw_status_encode(&s,m.status+256)==BW_OK);m.status_size=512;
 struct np_report p={0};p.pids[0]=p.pids[2]=200;p.pids[1]=100;p.ids[0]=p.ids[1]=p.post_ids[0]=p.post_ids[1]=501;p.ids[2]=p.ids[3]=p.post_ids[2]=p.post_ids[3]=20;p.group_count=1;p.groups[0]=20;p.cwd_device=77;p.cwd_inode=88;p.fd_count=3;for(unsigned i=0;i<3;i++)p.fds[i]=i;p.status_flags[1]=p.status_flags[2]=1;p.signal_policy=1;p.root_regain_result=-1;p.root_regain_errno=NP_DARWIN_EPERM;CHECK(np_report_encode(&p,m.probe)==NP_OK);
}
static void lifecycle(void){struct nr_attempt a;init(&a,GOOD);CHECK(nr_execute(&a)==0&&a.reaped&&m.go_writes==1&&m.readiness==2);CHECK(a.trace.session.bootstrap_sealed&&a.trace.session.child==TS_CHILD_REAPED);nr_cleanup(&a);CHECK(m.deadlines==1&&m.stops==1&&m.drains==1&&m.closes==1&&m.backend.alive&&m.kills==0);CHECK(nr_finish_outputs(&a)==0&&nr_trace_success(&a)&&a.probe_matched&&m.promotions==1&&m.promoted_at==m.events);CHECK(!m.backend.alive&&m.owner_calls==m.destroy_owner_calls);CHECK(strstr(m.receipt,"glue-owned-traced-bootstrap-diagnostic-v1")&&strstr(m.receipt,"\"tracing\":true")&&strstr(m.receipt,"\"exec_proved\":false"));CHECK(strstr(m.sidecar,"\"parent_closed\":1")&&strstr(m.sidecar,"\"terminal\":1")&&strstr(m.sidecar,"\"success_eligible\":1"));}
static void failures(void){for(enum mode mode=DENIED;mode<=GO_FULL;mode++){struct nr_attempt a;init(&a,mode);CHECK(nr_execute(&a)==-1);struct nr_error first=a.error;nr_cleanup(&a);CHECK(!memcmp(&first,&a.error,sizeof(first))&&m.go_writes<=1&&m.kills==1&&a.reaped&&m.deadlines==1);CHECK(nr_finish_outputs(&a)==0&&m.promotions==1&&!nr_trace_success(&a));if(mode==DENIED)CHECK(!a.trace.create_attempted&&!m.starts&&!m.closes);if(mode==START_FAIL)CHECK(m.closes==1&&!m.stops&&!m.drains&&strstr(m.sidecar,"\"libdtrace_code\":123"));if(mode==GO_PARTIAL||mode==GO_FULL)CHECK(a.trace.session.go_result_seen&&!a.trace.session.go_complete&&a.trace.session.go_bytes==(mode==GO_PARTIAL?13u:64u)&&m.go_writes==1);}}
static void poisoned_status(void){for(enum mode mode=STATUS_FULL;mode<=EOF_FAIL;mode++){struct nr_attempt a;init(&a,mode);CHECK(nr_execute(&a)==-1&&a.stream.failed&&a.stream.used==512&&a.stream.wire.accepted_records==(mode==STATUS_FULL?1u:2u));CHECK(a.trace.session.bootstrap_prefix_bytes==512&&!a.trace.session.bootstrap_sealed);if(mode==EOF_FAIL)CHECK(m.zero_reads==2&&!a.stream.wire.sealed);nr_cleanup(&a);CHECK(a.reaped&&m.kills==1&&m.go_writes==1);CHECK(nr_finish_outputs(&a)==0&&!nr_trace_success(&a));}}
static void wait_ownership(void){struct nr_attempt a;init(&a,LOST);CHECK(nr_execute(&a)==-1&&a.lost_child&&a.trace.session.child==TS_CHILD_LOST);nr_cleanup(&a);CHECK(!m.kills&&m.closes==1);CHECK(nr_finish_outputs(&a)==-1&&!m.promotions&&!m.backend.alive);
 init(&a,REAP_CLOCK);CHECK(nr_execute(&a)==-1&&a.reaped&&a.trace.session.child==TS_CHILD_REAPED);nr_cleanup(&a);CHECK(!m.kills&&m.closes==1&&m.deadlines==1&&a.cleanup_error.stage!=NR_NONE);CHECK(nr_finish_outputs(&a)==0&&!nr_trace_success(&a)&&m.promotions==1&&!m.backend.alive);}
static void closure(void){for(enum mode mode=CLOSE_FAIL;mode<=DIR_FAIL;mode++){struct nr_attempt a;init(&a,mode);(void)nr_execute(&a);nr_cleanup(&a);CHECK(nr_finish_outputs(&a)==-1&&!m.promotions);CHECK(m.closes==1);if(mode>=SIDECAR_FAIL)CHECK(a.trace.session.parent_close_seen&&a.trace.session.parent_closed&&a.trace.destroyed);if(mode!=CLOSE_FAIL)CHECK(!m.backend.alive);else CHECK(a.trace.snapshot.writer_close_failed_mask==8&&a.trace.snapshot.writer_close_errno[3]==EINTR&&a.trace.snapshot.close_error.system_errno==0&&a.trace.snapshot.writer_close_error.system_errno==EINTR);}}
static void simulated(void){struct nr_attempt a;init(&a,SIM);CHECK(nr_execute(&a)==-1&&!m.go_writes&&!a.go_attempted);nr_cleanup(&a);CHECK(a.reaped&&WIFEXITED(a.wait_status)&&WEXITSTATUS(a.wait_status)==120&&!m.kills);CHECK(nr_finish_outputs(&a)==0&&!nr_trace_success(&a));}
static void readiness(void){struct nr_attempt a;init(&a,READINESS_FAIL);CHECK(nr_execute(&a)==-1&&!m.go_writes&&!a.trace.session.go_claim_attempted);nr_cleanup(&a);CHECK(a.reaped&&m.kills==1&&m.closes==1);CHECK(nr_finish_outputs(&a)==0&&!nr_trace_success(&a));}
int main(int argc,char **argv){CHECK(argc==2);if(!strcmp(argv[1],"start-failure-json")){struct nr_attempt a;init(&a,START_FAIL);CHECK(nr_execute(&a)==-1);nr_cleanup(&a);CHECK(nr_finish_outputs(&a)==0);fputs(m.sidecar,stdout);fputs(m.receipt,stdout);return 0;}if(!strcmp(argv[1],"json")){lifecycle();fputs(m.sidecar,stdout);fputs(m.receipt,stdout);return 0;}const struct{const char *name;void(*run)(void);}cases[]={{"lifecycle",lifecycle},{"failures",failures},{"poisoned-status",poisoned_status},{"wait-ownership",wait_ownership},{"closure",closure},{"simulated",simulated},{"readiness",readiness}};for(size_t i=0;i<sizeof(cases)/sizeof(cases[0]);i++)if(!strcmp(argv[1],cases[i].name)){cases[i].run();puts(argv[1]);return 0;}return 2;}
