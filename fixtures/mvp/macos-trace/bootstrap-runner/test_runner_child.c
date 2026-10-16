/* Source-isolated child wiring controls. All native/helper/IO/exec operations
 * below are model callbacks. _exit becomes longjmp; no process is created. */
#define _POSIX_C_SOURCE 200809L
#define _DARWIN_C_SOURCE 1
#include "runner_internal.h"
#include <assert.h>
#include <errno.h>
#include <setjmp.h>
#include <string.h>
#include <unistd.h>
static jmp_buf escaped;
static int mode,exit_code,tc_calls,cwd_calls,td_calls,release_calls,gate_closes,exec_calls,records;
static struct bw_status seen[3];
static struct bw_binding bound(void){struct bw_binding b={100,200,{0}};return b;}
int nr_before(struct nr_attempt*a,struct bio_time d,enum nr_stage s){(void)a;(void)d;(void)s;return 0;}
const struct tc_operations *tc_native_operations(void){return NULL;}
const struct td_operations *td_native_operations(void){return NULL;}
const struct te_operations *te_native_operations(void){return NULL;}
const struct bio_operations *bio_native_operations(void){return NULL;}
int bs_reset_in_owned_child(struct bs_state*s,struct bs_error*e){(void)s;(void)e;return 0;}
int bs_check_in_owned_child(struct bs_state*s,struct bs_error*e){(void)s;(void)e;assert(tc_calls&&cwd_calls&&td_calls);return 0;}
int bs_release_in_owned_child(struct bs_state*s,struct bs_error*e){(void)s;(void)e;assert(gate_closes==1);release_calls++;return 0;}
int te_map_in_owned_child(const struct te_prepared*p,uint64_t owner,const struct te_operations*o,struct te_error*e){(void)p;(void)o;(void)e;assert(owner==100&&!tc_calls);return 0;}
int tc_drop_in_owned_child(const struct tc_request*r,uint64_t owner,const struct tc_operations*o,struct tc_error*e){(void)r;(void)o;assert(owner==100&&!cwd_calls&&!td_calls);tc_calls++;memset(e,0,sizeof(*e));e->mutation_attempted=mode!=1;if(mode==1||mode==2){e->stage=TC_STAGE_SETUID;e->system_errno=EPERM;return -1;}return 0;}
int td_close_in_owned_child(const struct td_plan*p,uint64_t owner,const struct td_operations*o,struct td_error*e){(void)o;assert(owner==100&&cwd_calls==1&&p->keep[3]==8&&p->keep[4]==9);td_calls++;memset(e,0,sizeof(*e));e->closure_attempted=mode!=4;if(mode==4||mode==5){e->stage=TD_STAGE_CLOSE;e->system_errno=EIO;e->fd=19;return -1;}return 0;}
int bio_write_record(int fd,const unsigned char*p,size_t n,struct bio_time d,const struct bio_operations*o,struct bio_result*r,struct bio_error*e){(void)d;(void)o;assert(fd==9&&n==256&&records<3);struct bw_binding b=bound();assert(bw_status_decode(p,n,&b,&seen[records])==BW_OK);records++;memset(r,0,sizeof(*r));memset(e,0,sizeof(*e));if((mode==10&&seen[records-1].kind==BW_READY)||(mode==11&&seen[records-1].kind==BW_EXEC_ATTEMPT)){r->bytes_moved=13;e->reason=BIO_REASON_DEADLINE;return -1;}r->bytes_moved=n;return 0;}
int bio_read_record(int fd,size_t n,struct bio_time d,const struct bio_operations*o,struct bio_result*r,struct bio_error*e){(void)d;(void)o;assert(fd==8&&n==64&&records==1&&!release_calls);memset(r,0,sizeof(*r));memset(e,0,sizeof(*e));if(mode==6){e->stage=BIO_STAGE_READ;e->reason=BIO_REASON_TRUNCATED;return -1;}struct bw_binding b=bound();assert(bw_go_encode(&b,r->prefix)==BW_OK);r->bytes_moved=64;if(mode==7)r->prefix[12]^=1;return 0;}
int bio_require_eof(int fd,struct bio_time d,const struct bio_operations*o,struct bio_result*r,struct bio_error*e){(void)d;(void)o;assert(fd==8);memset(r,0,sizeof(*r));memset(e,0,sizeof(*e));if(mode==8){e->reason=BIO_REASON_TRAILING;return -1;}return 0;}
static pid_t model_pid(void){return 200;}
static pid_t model_parent(void){return 100;}
static int model_pgroup(pid_t p,pid_t g){assert(p==0&&g==0);return 0;}
static pid_t model_group(void){return 200;}
static uid_t model_uid(void){return 501;}
static gid_t model_gid(void){return 20;}
static int model_groups(int n,gid_t*g){assert(n==16&&tc_calls);g[0]=20;return 1;}
static int model_cwd(const char*p){assert(!strcmp(p,"/closed/build")&&tc_calls==1&&!td_calls);cwd_calls++;if(mode==3){errno=EACCES;return -1;}return 0;}
static int model_stat(const char*p,struct stat*s){assert(!strcmp(p,"."));memset(s,0,sizeof(*s));s->st_mode=S_IFDIR|0555;s->st_dev=77;s->st_ino=88;return 0;}
static int model_close(int fd){assert(fd==8&&!release_calls);gate_closes++;assert(gate_closes==1);if(mode==9){errno=EINTR;return -1;}return 0;}
static int model_exec(const char*p,char*const argv[],char*const env[]){assert(!strcmp(p,"/closed/build/context-probe")&&argv[0]==p&&!strcmp(argv[1],"--request-sha256")&&strlen(argv[2])==64&&!argv[3]&&!env[0]&&release_calls==1&&records==2);exec_calls++;errno=ENOENT;return -1;}
static _Noreturn void model_exit(int code){exit_code=code;longjmp(escaped,1);}
#define getpid model_pid
#define getppid model_parent
#define setpgid model_pgroup
#define getpgrp model_group
#define getuid model_uid
#define geteuid model_uid
#define getgid model_gid
#define getegid model_gid
#define getgroups model_groups
#define chdir model_cwd
#define stat(...) model_stat(__VA_ARGS__)
#define close model_close
#define execve model_exec
#define _exit model_exit
#include "runner_child.c"
static void run(int m){struct nr_attempt a;memset(&a,0,sizeof(a));a.owner=100;a.endpoints.copies[3]=8;a.endpoints.copies[4]=9;a.request.cwd_device=77;a.request.cwd_inode=88;strcpy(a.cwd,"/closed/build");strcpy(a.executable,"/closed/build/context-probe");memset(a.request_hex,'0',64);mode=m;exit_code=tc_calls=cwd_calls=td_calls=release_calls=gate_closes=exec_calls=records=0;memset(seen,0,sizeof(seen));if(!setjmp(escaped))nr_child(&a);}
int main(void){
 run(0);assert(records==3&&seen[0].kind==BW_READY&&seen[1].kind==BW_EXEC_ATTEMPT&&seen[2].kind==BW_ERROR&&seen[2].sequence==2&&seen[2].stage==BW_EXEC&&exec_calls==1&&release_calls==1);
 for(int m=1;m<=2;m++){run(m);assert(records==1&&seen[0].stage==BW_CREDENTIALS&&seen[0].mutation_flags==(unsigned)(m==1?0:1)&&!cwd_calls&&!td_calls&&!release_calls&&!exec_calls);}
 run(3);assert(records==1&&seen[0].stage==BW_CWD&&seen[0].mutation_flags==1&&!td_calls&&!release_calls&&!exec_calls);
 for(int m=4;m<=5;m++){run(m);assert(records==1&&seen[0].stage==BW_DESCRIPTORS&&seen[0].mutation_flags==(unsigned)(m==4?1:3)&&!release_calls&&!exec_calls);}
 for(int m=6;m<=9;m++){run(m);assert(records==2&&seen[1].kind==BW_ERROR&&seen[1].sequence==1&&seen[1].mutation_flags==3&&!release_calls&&!exec_calls);assert(seen[1].stage==(unsigned)(m==6?BW_GO_IO:m==9?BW_GATE_CLOSE:BW_GO_VALIDATE));}
 run(10);assert(records==1&&exit_code==121&&!release_calls&&!exec_calls);
 run(11);assert(records==2&&exit_code==122&&release_calls==1&&!exec_calls);
 return 0;
}
