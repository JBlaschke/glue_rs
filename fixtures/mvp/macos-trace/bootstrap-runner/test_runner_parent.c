/* Source-isolated lifecycle model. No callback forks, signals, closes, waits,
 * changes a mask/credential or executes any process. Native CLI never links it. */
#define _POSIX_C_SOURCE 200809L
#define _DARWIN_C_SOURCE 1
#include "runner_internal.h"
#include <assert.h>
#include <errno.h>
#include <signal.h>
#include <stdlib.h>
#include <string.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>
static int mode,closed[64],close_failure,go_calls,killed,wait_calls,status_calls,before_calls;
static int model_close(struct nr_attempt*a,int*fd,enum nr_stage stage){if(*fd<0)return 0;int n=*fd;*fd=-1;assert(n>=0&&n<64);assert(++closed[n]==1);if(n==close_failure)return nr_fail(a,stage,NR_SYSCALL,EIO,n);return 0;}
static int model_before(struct nr_attempt*a,struct bio_time t,enum nr_stage stage){(void)t;before_calls++;if(mode==5&&before_calls>3)return nr_fail(a,stage,NR_TIMEOUT,0,-1);return 0;}
static int model_deadline(struct nr_attempt*a,unsigned ms,struct bio_time*out){(void)a;(void)ms;*out=(struct bio_time){10,0};return 0;}
static pid_t model_fork(void){return 200;}
static int model_setpgid(pid_t p,pid_t g){assert(p==200&&g==200);return 0;}
static pid_t model_getpgid(pid_t p){assert(p==200);return 200;}
static pid_t model_wait(pid_t p,int*s,int flags){assert(p==200&&flags==WNOHANG);wait_calls++;if(mode==4){errno=ECHILD;return -1;}if(mode==5&&wait_calls==1){errno=EINTR;return -1;}if(mode!=0&&!killed)return 0;*s=0;return 200;}
static int model_kill(pid_t p,int sig){assert(p==200&&sig==SIGKILL);assert(!killed);killed=1;return 0;}
static int model_nap(const struct timespec*t,struct timespec*r){(void)t;(void)r;return 0;}
static int model_restore(struct bs_state*s,struct bs_error*e){memset(e,0,sizeof(*e));s->restore_attempted=1;s->pipe_restored=s->mask_restored=1;return 0;}
static _Noreturn void model_child(struct nr_attempt*a){(void)a;abort();}
static int model_write(int fd,const unsigned char*p,size_t n,struct bio_time t,const struct bio_operations*o,struct bio_result*r,struct bio_error*e){(void)p;(void)t;(void)o;assert(fd==19&&n==64);go_calls++;assert(go_calls==1);memset(r,0,sizeof(*r));memset(e,0,sizeof(*e));r->bytes_moved=64;if(mode==1){e->stage=BIO_STAGE_CLOCK;e->reason=BIO_REASON_DEADLINE;return -1;}return 0;}
static int model_next(struct nr_status_stream*s,int fd,struct bio_time t,const struct bio_operations*o){(void)t;(void)o;assert(fd==20);status_calls++;
 if(status_calls==3){s->end=BW_END_ATTEMPT_WITHOUT_REPORTED_EXEC_ERROR;s->ended=1;return 1;}
 struct bw_status b={0};b.binding=s->wire.expected;b.detail=-1;b.mutation_flags=3;
 if(status_calls==1){b.kind=BW_READY;b.real_uid=b.effective_uid=501;b.real_gid=b.effective_gid=20;b.group_count=1;b.groups[0]=20;b.cwd_device=77;b.cwd_inode=88;b.kept_fds[0]=0;b.kept_fds[1]=1;b.kept_fds[2]=2;b.kept_fds[3]=13;b.kept_fds[4]=14;if(mode==2)b.cwd_inode++;}
 else {b.kind=BW_EXEC_ATTEMPT;b.sequence=1;b.stage=BW_EXEC;}
 unsigned char wire[256];assert(bw_status_encode(&b,wire)==BW_OK);assert(bw_state_push(&s->wire,wire,sizeof(wire))==BW_OK);return 0;
}
#define nr_close_owned model_close
#define nr_before model_before
#define nr_deadline model_deadline
#define fork model_fork
#define setpgid model_setpgid
#define getpgid model_getpgid
#define waitpid model_wait
#define kill model_kill
#define nanosleep model_nap
#define bs_restore_parent model_restore
#define nr_child model_child
#define bio_write_record model_write
#define nr_status_next model_next
#include "runner_parent.c"
#undef nr_close_owned
#undef nr_before
#undef nr_deadline
static void init(struct nr_attempt*a,int m){memset(a,0,sizeof(*a));mode=m;memset(closed,0,sizeof(closed));close_failure=-1;go_calls=killed=wait_calls=status_calls=before_calls=0;a->owner=100;a->child=-1;a->output_fd=-1;a->request.fixture=1;a->request.credentials.uid=501;a->request.credentials.gid=20;a->request.credentials.group_count=1;a->request.credentials.groups[0]=20;a->request.signal_policy=a->request.stdio_policy=a->request.argv_template=1;a->request.release_action=1;a->request.max_live_fds=4096;a->request.attempt_ms=100;a->request.cleanup_ms=100;a->request.cwd_device=77;a->request.cwd_inode=88;static const unsigned char exe[]="/x/context-probe",cwd[]="/x";a->request.executable=(struct br_span){exe,sizeof(exe)-1};a->request.cwd=(struct br_span){cwd,sizeof(cwd)-1};for(unsigned i=0;i<5;i++){a->endpoints.copies[i]=10+(int)i;a->sources[i]=15+(int)i;}a->endpoints.owned_count=5;a->gate[0]=18;a->gate[1]=19;a->status[0]=20;a->status[1]=21;a->sources[3]=18;a->sources[4]=21;a->ready_context_fds[0]=13;a->ready_context_fds[1]=14;for(unsigned i=0;i<8;i++)a->admission.components[i].fd=22+(int)i;a->admission.owned_count=8;}
int main(void){struct nr_attempt a;
 init(&a,0);assert(!nr_execute(&a)&&a.reaped&&a.ready_matched&&go_calls==1);nr_cleanup(&a);assert(!killed&&a.error.stage==NR_NONE);
 init(&a,1);assert(nr_execute(&a)&&a.go_attempted&&a.go_result.bytes_moved==64&&go_calls==1);nr_cleanup(&a);assert(killed&&a.reaped&&go_calls==1&&closed[19]==1&&a.error.stage==NR_GO);
 init(&a,2);assert(nr_execute(&a)&&!go_calls&&!a.ready_matched);nr_cleanup(&a);assert(killed&&a.reaped&&a.error.stage==NR_READY);
 init(&a,3);close_failure=19;assert(nr_execute(&a)&&go_calls==1&&closed[19]==1);nr_cleanup(&a);assert(killed&&a.reaped&&closed[19]==1&&a.error.stage==NR_GO);
 init(&a,4);a.child=200;a.forked=1;nr_cleanup(&a);assert(a.lost_child&&!a.reaped&&!killed&&a.error.reason==NR_LOST_CHILD);
 init(&a,5);a.child=200;a.forked=1;nr_cleanup(&a);assert(killed&&wait_calls>=2);
 init(&a,0);a.child=200;a.forked=1;a.reaped=1;nr_cleanup(&a);assert(!wait_calls&&!killed);
 init(&a,0);a.ownership_uncertain=1;a.signals_initialized=1;nr_cleanup(&a);for(unsigned i=0;i<64;i++)assert(!closed[i]);assert(a.signals_restored);
 return 0;}
