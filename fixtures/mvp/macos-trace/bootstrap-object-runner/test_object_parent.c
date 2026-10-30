/* Source-isolated real parent path with actual object wire/BIO decoder.
 * All process, descriptor and trace calls are models; no target executes. */
#define _POSIX_C_SOURCE 200809L
#define _DARWIN_C_SOURCE 1
#define GLUE_OWNED_TRACING 1
#include "objects_profile.h"
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
enum scenario {GOOD,BACKING_FAILURE,BAD_ENVELOPE,LEGACY_READY,LATE_MATCH,DEAD_AT_READY,REF_CLOSE_FAILURE,LOST_CHILD,PARTIAL_READY};
static enum scenario scenario;
static int closed[64],killed,waits,go_calls,match_calls,trace_calls,deadline_calls,reads;
static size_t stream_offset,stream_size;
static unsigned char stream_bytes[1024];
static struct nr_attempt *attempt;
int nr_fail(struct nr_attempt*a,enum nr_stage stage,enum nr_reason reason,int e,int detail){if(a->error.stage==NR_NONE)a->error=(struct nr_error){stage,reason,e,detail};
return -1;
}
int nr_clock(struct nr_attempt*a,uint64_t*out){(void)a;
*out=1000000000;
return 0;
}
int nr_sha_bytes(const uint8_t*p,size_t n,uint8_t out[32]){(void)p;
(void)n;
memset(out,0,32);
return 0;
}
int nr_read_request(struct nr_attempt*a,const char*p){(void)a;
(void)p;
return -1;
}
int nr_admit(struct nr_attempt*a){(void)a;
return -1;
}
int nr_output(struct nr_attempt*a,const char*p){(void)a;
(void)p;
return -1;
}
int nr_endpoints(struct nr_attempt*a){(void)a;
return -1;
}
int nr_finish_outputs(struct nr_attempt*a){(void)a;
return -1;
}
int nr_trace_parent_closed(struct nr_attempt*a,int unresolved){(void)a;
(void)unresolved;
return -1;
}
static int model_before(struct nr_attempt*a,struct bio_time t,enum nr_stage s){assert(t.seconds==2&&!t.nanoseconds);
if(scenario==LATE_MATCH&&match_calls)return nr_fail(a,s,NR_TIMEOUT,0,-1);
return 0;
}
static int model_close(struct nr_attempt*a,int*fd,enum nr_stage stage){if(*fd<0)return 0;
int n=*fd;
*fd=-1;
assert(n<64&&++closed[n]==1);
if(scenario==REF_CLOSE_FAILURE&&n==16){a->close_failed=1;
return nr_fail(a,stage,NR_SYSCALL,EINTR,n);
}return 0;
}
static pid_t model_fork(void){return 200;
}
static int model_group_set(pid_t p,pid_t g){assert(p==200&&g==200);
return 0;
}
static pid_t model_group(pid_t p){assert(p==200);
return 200;
}
static pid_t model_wait(pid_t p,int*s,int flags){assert(p==200&&flags==WNOHANG);
waits++;
if(scenario==LOST_CHILD){errno=ECHILD;
return -1;
}if(killed||scenario==DEAD_AT_READY||go_calls){*s=0;
return 200;
}return 0;
}
static int model_kill(pid_t p,int sig){assert(p==200&&sig==SIGKILL&&!killed);
killed=1;
return 0;
}
static int model_nap(const struct timespec*t,struct timespec*r){(void)t;
(void)r;
return 0;
}
static _Noreturn void model_child(struct nr_attempt*a){(void)a;
abort();
}
static int model_restore(struct bs_state*s,struct bs_error*e){memset(e,0,sizeof(*e));
s->pipe_restored=s->mask_restored=1;
return 0;
}
static int io_clock(void*c,struct bio_time*t,int*e){(void)c;
(void)e;
*t=(struct bio_time){1,0};
return 0;
}
static int io_stat(void*c,int fd,mode_t*m,int*e){(void)c;
(void)e;
assert(fd==19||fd==20);
*m=S_IFIFO;
return 0;
}
static int io_flags(void*c,int fd,int*e){(void)c;
(void)e;
return O_NONBLOCK|(fd==19?O_WRONLY:O_RDONLY);
}
static int io_poll(void*c,int fd,short wanted,int timeout,short*events,int*e){(void)c;
(void)fd;
(void)e;
assert(timeout>0);
*events=wanted;
return 1;
}
static ssize_t io_read(void*c,int fd,void*out,size_t n,int*e){(void)c;
(void)e;
assert(fd==20);
reads++;
size_t amount=stream_size-stream_offset;
if(amount>n)amount=n;
memcpy(out,stream_bytes+stream_offset,amount);
stream_offset+=amount;
return (ssize_t)amount;
}
static ssize_t io_write(void*c,int fd,const void*in,size_t n,int*e){(void)c;
(void)e;
assert(fd==19&&n==64&&!go_calls&&match_calls==1&&trace_calls==1&&attempt->objects_matched);
struct bw_binding b;
assert(bow_go_decode(in,n,&attempt->stream.wire.expected,&b)==BW_OK);
go_calls++;
return (ssize_t)n;
}
static const struct bio_operations *model_io(void){static const struct bio_operations o={NULL,io_clock,io_stat,io_flags,io_poll,io_read,io_write};
return &o;
}
static int model_match(const struct tfo_snapshot*s,const int held[2],const struct tfo_operations*ops,struct tfo_matches*out,struct tfo_error*e){(void)ops;
assert(!trace_calls&&!go_calls&&!attempt->reaped&&s->ready&&s->controller_pid==100&&s->child_pid==200&&held[0]==16&&held[1]==17&&!closed[16]&&!closed[17]);
match_calls++;
memset(out,0,sizeof(*out));
memset(e,0,sizeof(*e));
if(scenario==BACKING_FAILURE){e->reason=TFO_REASON_MISMATCH;
return -1;
}out->ready=1;
return 0;
}
static const struct tfo_operations *model_objects(void){return NULL;
}
static int model_progress(void *p,struct bio_time d){struct nr_attempt*a=p;
assert(a->objects_matched&&d.seconds==2&&!d.nanoseconds&&trace_calls==1);
return 0;
}
int nr_trace_start(struct nr_attempt*a){assert(a->objects_matched&&a->output_matches.ready&&!a->go_attempted&&match_calls==1&&trace_calls++==0);
a->trace.observer=(struct bio_observer){a,model_progress};
return 0;
}
int nr_trace_claim_go(struct nr_attempt*a){assert(a->objects_matched&&trace_calls==1);
return 0;
}
int nr_trace_go_result(struct nr_attempt*a,int failed){(void)a;
assert(!failed);
return 0;
}
int nr_trace_gate_result(struct nr_attempt*a,int failed,int e){(void)a;
(void)failed;
(void)e;
return 0;
}
void nr_trace_bootstrap_result(struct nr_attempt*a,int sealed){(void)a;
(void)sealed;
}
void nr_trace_child_result(struct nr_attempt*a,int lost,int status){(void)a;
(void)lost;
(void)status;
}
int nr_trace_pump(struct nr_attempt*a,enum ts_phase p){(void)a;
(void)p;
return 0;
}
void nr_trace_begin_cleanup(struct nr_attempt*a){(void)a;
}
int nr_trace_claim_kill(struct nr_attempt*a){(void)a;
return 0;
}
void nr_trace_close_backend(struct nr_attempt*a){(void)a;
}
#define nr_before model_before
#define nr_close_owned model_close
#define fork model_fork
#define setpgid model_group_set
#define getpgid model_group
#define waitpid model_wait
#define kill model_kill
#define nanosleep model_nap
#define nr_child model_child
#define bs_restore_parent model_restore
#define bio_native_operations model_io
#define tfo_native_operations model_objects
#define tfo_match_regular_outputs model_match
#include "../bootstrap-runner/runner_parent.c"
#undef nr_before
#undef nr_deadline
#undef nr_close_owned
static void setup(struct nr_attempt*a,enum scenario selected){
 memset(a,0,sizeof(*a));
 scenario=selected;
 attempt=a;
 memset(closed,0,sizeof(closed));
 killed=waits=go_calls=match_calls=trace_calls=deadline_calls=reads=0;
 stream_offset=0;
 stream_size=1024;
 a->owner=100;
 a->child=-1;
 a->output_fd=-1;
 a->held_outputs[0]=a->held_outputs[1]=-1;
 a->deadline=(struct bio_time){2,0};
 a->request.fixture=1;
 a->request.credentials.uid=501;
 a->request.credentials.gid=20;
 a->request.credentials.group_count=1;
 a->request.credentials.groups[0]=20;
 a->request.signal_policy=a->request.stdio_policy=a->request.argv_template=1;
 a->request.release_action=1;
 a->request.max_live_fds=4096;
 a->request.attempt_ms=a->request.cleanup_ms=100;
 a->request.cwd_device=77;
 a->request.cwd_inode=88;
 static const unsigned char exe[]="/x/context-probe",cwd[]="/x";
 a->request.executable=(struct br_span){exe,sizeof(exe)-1};
 a->request.cwd=(struct br_span){cwd,sizeof(cwd)-1};
 for(unsigned i=0;i<5;i++){a->endpoints.copies[i]=10+(int)i;
 a->sources[i]=15+(int)i;
 }a->endpoints.owned_count=5;
 a->gate[0]=18;
 a->gate[1]=19;
 a->status[0]=20;
 a->status[1]=21;
 a->sources[3]=18;
 a->sources[4]=21;
 a->ready_context_fds[0]=13;
 a->ready_context_fds[1]=14;
 for(unsigned i=0;i<8;i++)a->admission.components[i].fd=22+(int)i;
 a->admission.owned_count=8;
 struct bw_status ready={0};
 ready.binding=(struct bw_binding){100,200,{0}};
 ready.kind=BW_READY;
 ready.detail=-1;
 ready.mutation_flags=3;
 ready.real_uid=ready.effective_uid=501;
 ready.real_gid=ready.effective_gid=20;
 ready.group_count=1;
 ready.groups[0]=20;
 ready.cwd_device=77;
 ready.cwd_inode=88;
 for(unsigned i=0;i<5;i++)ready.kept_fds[i]=i<3?i:i==3?13:14;
 struct tfo_snapshot objects={0};
 objects.ready=1;
 objects.controller_pid=100;
 objects.child_pid=200;
 for(unsigned i=0;i<5;i++){objects.entries[i].fd=(int)ready.kept_fds[i];
 objects.entries[i].backing=(struct tfo_backing){9,100+i,1,S_IFREG|0600};
 objects.entries[i].status_flags=O_WRONLY;
 }
 assert(bow_status_encode(&ready,&objects,stream_bytes)==BW_OK);
 struct bw_status next={0};
 next.binding=ready.binding;
 next.kind=BW_EXEC_ATTEMPT;
 next.sequence=1;
 next.stage=BW_EXEC;
 next.mutation_flags=3;
 next.detail=-1;
 assert(bow_status_encode(&next,NULL,stream_bytes+512)==BW_OK);
 if(selected==BAD_ENVELOPE)stream_bytes[511]=1;
 if(selected==LEGACY_READY){assert(bw_status_encode(&ready,stream_bytes)==BW_OK);
 stream_size=256;
 }
 if(selected==PARTIAL_READY)stream_size=511;
}
int main(void){struct nr_attempt a;
 setup(&a,GOOD);
 assert(!nr_execute(&a)&&a.reaped&&a.objects_matched&&go_calls==1&&trace_calls==1&&a.stream.used==1024);
 assert(!closed[16]&&!closed[17]);
 nr_cleanup(&a);
 assert(closed[16]==1&&closed[17]==1&&!killed);
 enum scenario denied[]={BACKING_FAILURE,BAD_ENVELOPE,LEGACY_READY,LATE_MATCH,DEAD_AT_READY,PARTIAL_READY};
 for(unsigned i=0;i<sizeof(denied)/sizeof(denied[0]);i++){setup(&a,denied[i]);
 assert(nr_execute(&a)&&!go_calls&&!trace_calls&&!a.objects_matched);
 nr_cleanup(&a);
 assert(closed[16]==1&&closed[17]==1&&a.reaped&&!a.lost_child);
 }
 setup(&a,REF_CLOSE_FAILURE);
 assert(!nr_execute(&a));
 nr_cleanup(&a);
 assert(a.close_failed&&a.cleanup_error.stage==NR_CLEANUP&&closed[16]==1&&closed[17]==1);
 setup(&a,LOST_CHILD);
 assert(nr_execute(&a)&&a.lost_child&&!go_calls&&!trace_calls);
 nr_cleanup(&a);
 assert(!killed&&!a.reaped&&closed[16]==1&&closed[17]==1);
 puts("object-parent full-envelope before-match before-trace before-GO exact-ref-cleanup");
 return 0;
}
