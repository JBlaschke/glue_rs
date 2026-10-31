/* Source-isolated child wiring controls. All native/helper/IO/exec operations
 * below are model callbacks. _exit becomes longjmp; no process is created. */
#define _POSIX_C_SOURCE 200809L
#define _DARWIN_C_SOURCE 1
#include "objects_profile.h"
#include "../bootstrap-runner/runner_internal.h"
#include "../target-cwd/target_cwd.h"
#include <assert.h>
#include <errno.h>
#include <fcntl.h>
#include <setjmp.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
static jmp_buf escaped;
static int mode,exit_code,tc_calls,cwd_calls,td_calls,release_calls,gate_closes,exec_calls,records,object_calls;
static struct bw_status seen[3];
static struct bw_binding bound(void){struct bw_binding b={100,200,{0}};
return b;
}
int nr_before(struct nr_attempt*a,struct bio_time d,enum nr_stage s){(void)a;
(void)d;
(void)s;
return (mode==14&&object_calls)||(mode==22&&cwd_calls)||(mode==26&&tc_calls&&!cwd_calls)?-1:0;
}
const struct tc_operations *tc_native_operations(void){return NULL;
}
const struct td_operations *td_native_operations(void){return NULL;
}
const struct te_operations *te_native_operations(void){return NULL;
}
const struct bio_operations *bio_native_operations(void){return NULL;
}
const struct tfo_operations *tfo_native_operations(void){return NULL;
}
int tfo_snapshot_in_owned_child(const struct tfo_plan*p,uint64_t owner,const struct tfo_operations*o,struct tfo_snapshot*s,struct tfo_error*e){
 (void)o;
 assert(owner==100&&tc_calls==1&&cwd_calls==1&&td_calls==1&&!records&&!release_calls&&object_calls++==0);
 memset(s,0,sizeof(*s));
 memset(e,0,sizeof(*e));
 s->ready=1;
 s->controller_pid=100;
 s->child_pid=200;
 for(unsigned i=0;i<5;i++){assert(p->keep[i]==(i<3?(int)i:i==3?8:9));
 s->entries[i].fd=p->keep[i];
 s->entries[i].backing=(struct tfo_backing){9,100+i,1,S_IFREG|0600};
 s->entries[i].status_flags=O_WRONLY;
 }
 if(mode==13||mode==15){e->stage=TFO_STAGE_SECOND;
 e->reason=mode==13?TFO_REASON_SYSCALL:TFO_REASON_CHANGED;
 e->system_errno=mode==13?EIO:0;
 e->fd=1;
 return -1;
 }return 0;
}
int bs_reset_in_owned_child(struct bs_state*s,struct bs_error*e){(void)s;
memset(e,0,sizeof(*e));
return 0;
}
int bs_check_in_owned_child(struct bs_state*s,struct bs_error*e){(void)s;
memset(e,0,sizeof(*e));
assert(tc_calls&&cwd_calls&&td_calls);
return 0;
}
int bs_release_in_owned_child(struct bs_state*s,struct bs_error*e){(void)s;
memset(e,0,sizeof(*e));
assert(gate_closes==1);
release_calls++;
return 0;
}
int te_map_in_owned_child(const struct te_prepared*p,uint64_t owner,const struct te_operations*o,struct te_error*e){(void)p;
(void)o;
*e=(struct te_error){TE_STAGE_NONE,TE_REASON_NONE,0,TE_NO_ROLE,-1,0,0};
assert(owner==100&&!tc_calls);
return 0;
}
int tc_drop_in_owned_child(const struct tc_request*r,uint64_t owner,const struct tc_operations*o,struct tc_error*e){(void)r;
(void)o;
assert(owner==100&&!cwd_calls&&!td_calls);
tc_calls++;
memset(e,0,sizeof(*e));
e->mutation_attempted=mode!=1;
if(mode==1||mode==2){e->stage=TC_STAGE_SETUID;
e->system_errno=EPERM;
return -1;
}return 0;
}
int td_close_in_owned_child(const struct td_plan*p,uint64_t owner,const struct td_operations*o,struct td_error*e){(void)o;
assert(owner==100&&cwd_calls==1&&p->keep[3]==8&&p->keep[4]==9);
td_calls++;
memset(e,0,sizeof(*e));
e->closure_attempted=mode!=4;
if(mode==4||mode==5){e->stage=TD_STAGE_CLOSE;
e->system_errno=EIO;
e->fd=19;
return -1;
}return 0;
}
int bio_write_object_status(int fd,const unsigned char p[BIO_OBJECT_STATUS_RECORD_BYTES],struct bio_time d,const struct bio_operations*o,struct bio_object_result*r,struct bio_error*e){
 (void)d;
 (void)o;
 assert(fd==9&&records<3);
 struct bw_binding b=bound();
 struct tfo_snapshot objects;
 assert(bow_status_decode(p,512,&b,&seen[records],&objects)==BW_OK);
 assert(seen[records].kind==BW_READY?objects.ready&&object_calls==1:!objects.ready);
 records++;
 memset(r,0,sizeof(*r));
 memset(e,0,sizeof(*e));
 if((mode==10&&seen[records-1].kind==BW_READY)||(mode==11&&seen[records-1].kind==BW_EXEC_ATTEMPT)||mode==16){r->bytes_moved=mode==16?512:13;
 e->reason=BIO_REASON_DEADLINE;
 return -1;
 }
 r->bytes_moved=512;
 return 0;
}
int bio_read_record(int fd,size_t n,struct bio_time d,const struct bio_operations*o,struct bio_result*r,struct bio_error*e){(void)d;
(void)o;
assert(fd==8&&n==64&&records==1&&!release_calls);
memset(r,0,sizeof(*r));
memset(e,0,sizeof(*e));
if(mode==6){e->stage=BIO_STAGE_READ;
e->reason=BIO_REASON_TRUNCATED;
return -1;
}struct bw_binding b=bound();
assert((mode==12?bw_go_encode(&b,r->prefix):bow_go_encode(&b,r->prefix))==BW_OK);
r->bytes_moved=64;
if(mode==7)r->prefix[12]^=1;
return 0;
}
int bio_require_eof(int fd,struct bio_time d,const struct bio_operations*o,struct bio_result*r,struct bio_error*e){(void)d;
(void)o;
assert(fd==8);
memset(r,0,sizeof(*r));
memset(e,0,sizeof(*e));
if(mode==8){e->reason=BIO_REASON_TRAILING;
return -1;
}return 0;
}
static pid_t model_pid(void){return 200;
}
static pid_t model_parent(void){return 100;
}
static int model_pgroup(pid_t p,pid_t g){assert(p==0&&g==0);
return 0;
}
static pid_t model_group(void){return 200;
}
static uid_t model_uid(void){return 501;
}
static gid_t model_gid(void){return 20;
}
static int model_groups(int n,gid_t*g){assert(n==16&&tc_calls);
g[0]=20;
return 1;
}
const struct tcwd_operations *tcwd_native_operations(void){return NULL;}
int tcwd_select_in_owned_child(const struct tcwd_request *r,uint64_t owner,const struct tcwd_operations *o,
 const struct tcwd_guard *g,struct tcwd_result *out,struct tcwd_error *e){
 (void)o;assert(r->directory_fd==27&&r->device==77&&r->inode==88&&owner==100&&tc_calls==1&&!td_calls&&!records);
 assert(g&&g->before_fn&&g->context);cwd_calls++;memset(out,0,sizeof(*out));memset(e,0,sizeof(*e));
 if(mode!=22){int saved=0;assert(!g->before_fn(g->context,&saved));}
 if(mode==3||mode==17||mode==18||mode==19){
  e->mutation_attempted=mode!=17;e->stage=mode==17?TCWD_STAGE_FIRST:mode==18?TCWD_STAGE_READBACK:mode==19?TCWD_STAGE_AFTER_CHANGE:TCWD_STAGE_CHANGE;
  e->reason=mode==19?TCWD_REASON_DEADLINE:TCWD_REASON_SYSCALL;e->system_errno=mode==19?0:mode==3?EACCES:EIO;return -1;
 }
 out->ready=mode!=23;return 0;
}
int tcwd_error_detail(const struct tcwd_error *e){return (int)e->stage|(e->mutation_attempted?TCWD_MUTATION_DETAIL:0);}
static int model_stat(const char*p,struct stat*s){assert(!strcmp(p,"."));
if(mode==24){errno=EIO;return -1;}
memset(s,0,sizeof(*s));
s->st_mode=S_IFDIR|0555;
s->st_dev=77;
s->st_ino=mode==25?89:88;
return 0;
}
static int model_close(int fd){assert(fd==8&&!release_calls);
gate_closes++;
assert(gate_closes==1);
if(mode==9){errno=EINTR;
return -1;
}return 0;
}
static int model_exec(const char*p,char*const argv[],char*const env[]){assert(!strcmp(p,"/closed/build/context-probe")&&argv[0]==p&&!strcmp(argv[1],"--request-sha256")&&strlen(argv[2])==64&&!argv[3]&&!env[0]&&release_calls==1&&records==2);
exec_calls++;
errno=ENOENT;
return -1;
}
static _Noreturn void model_exit(int code){exit_code=code;
longjmp(escaped,1);
}
#define getpid model_pid
#define getppid model_parent
#define setpgid model_pgroup
#define getpgrp model_group
#define getuid model_uid
#define geteuid model_uid
#define getgid model_gid
#define getegid model_gid
#define getgroups model_groups
#define stat(...) model_stat(__VA_ARGS__)
#define close model_close
#define execve model_exec
#define _exit model_exit
#include "../bootstrap-runner/runner_child.c"
static void run(int m){struct nr_attempt a;
memset(&a,0,sizeof(a));
a.owner=100;
a.admission.ready=1;a.admission.checked_count=a.admission.owned_count=BA_COMPONENT_COUNT;a.admission.components[6].fd=27;
a.endpoints.copies[3]=8;
a.endpoints.copies[4]=9;
a.request.cwd_device=77;
a.request.cwd_inode=88;
strcpy(a.cwd,"/closed/build");
strcpy(a.executable,"/closed/build/context-probe");
memset(a.request_hex,'0',64);
mode=m;
if(m==20)a.admission.ready=0;
if(m==21)a.admission.checked_count--;
exit_code=tc_calls=cwd_calls=td_calls=release_calls=gate_closes=exec_calls=records=object_calls=0;
memset(seen,0,sizeof(seen));
if(!setjmp(escaped))nr_child(&a);
}
int main(void){
 run(0);
 assert(records==3&&seen[0].kind==BW_READY&&seen[1].kind==BW_EXEC_ATTEMPT&&seen[2].kind==BW_ERROR&&seen[2].sequence==2&&seen[2].stage==BW_EXEC&&exec_calls==1&&release_calls==1);
 for(int m=1;m<=2;m++){run(m);
 assert(records==1&&seen[0].stage==BW_CREDENTIALS&&seen[0].mutation_flags==(unsigned)(m==1?0:1)&&!cwd_calls&&!td_calls&&!release_calls&&!exec_calls);
 }
 run(3);
 assert(records==1&&seen[0].stage==BW_CWD&&seen[0].mutation_flags==1&&!td_calls&&!release_calls&&!exec_calls);
 for(int m=4;m<=5;m++){run(m);
 assert(records==1&&seen[0].stage==BW_DESCRIPTORS&&seen[0].mutation_flags==(unsigned)(m==4?1:3)&&!release_calls&&!exec_calls);
 }
 for(int m=6;m<=9;m++){run(m);
 assert(records==2&&seen[1].kind==BW_ERROR&&seen[1].sequence==1&&seen[1].mutation_flags==3&&!release_calls&&!exec_calls);
 assert(seen[1].stage==(unsigned)(m==6?BW_GO_IO:m==9?BW_GATE_CLOSE:BW_GO_VALIDATE));
 }
 run(10);
 assert(records==1&&exit_code==121&&!release_calls&&!exec_calls);
 run(11);
 assert(records==2&&exit_code==122&&release_calls==1&&!exec_calls);
 run(12);
 assert(records==2&&seen[1].stage==BW_GO_VALIDATE&&!release_calls&&!exec_calls&&object_calls==1);
 for(int m=13;m<=15;m++){run(m);
 assert(records==1&&seen[0].kind==BW_ERROR&&seen[0].stage==BW_READY_IO&&!release_calls&&!exec_calls&&object_calls==1);
 }
 run(16);
 assert(records==1&&exit_code==121&&!release_calls&&!exec_calls&&object_calls==1);
 for(int m=17;m<=19;m++){run(m);
 assert(records==1&&seen[0].stage==BW_CWD&&seen[0].mutation_flags==1&&!td_calls&&!object_calls&&!release_calls&&!exec_calls);
 assert(seen[0].detail==(m==17?TCWD_STAGE_FIRST:(m==18?TCWD_STAGE_READBACK:TCWD_STAGE_AFTER_CHANGE)|TCWD_MUTATION_DETAIL));
 assert(seen[0].reason==(unsigned)(m==19?BW_TIMEOUT:BW_SYSCALL));}
 run(22);assert(records==1&&seen[0].stage==BW_CWD&&seen[0].detail==(TCWD_STAGE_FINAL|TCWD_MUTATION_DETAIL)&&!td_calls&&!object_calls&&!exec_calls);
 run(23);assert(records==1&&seen[0].stage==BW_CWD&&seen[0].reason==BW_MISMATCH&&!td_calls&&!exec_calls);
 for(int m=20;m<=21;m++){run(m);assert(records==1&&seen[0].stage==BW_CWD&&seen[0].detail==TCWD_STAGE_REQUEST&&!cwd_calls&&!td_calls&&!exec_calls);}
 for(int m=24;m<=25;m++){run(m);assert(records==1&&seen[0].stage==BW_CWD&&seen[0].detail==(TCWD_STAGE_READBACK|TCWD_MUTATION_DETAIL)&&!td_calls&&!exec_calls);}
 run(26);assert(records==1&&seen[0].stage==BW_CWD&&seen[0].reason==BW_TIMEOUT&&seen[0].detail==TCWD_STAGE_BEFORE_CHANGE&&!cwd_calls&&!td_calls&&!exec_calls);
 puts("object-child capture-after-closure before-READY legacy-GO-refusal failed-capture-no-GO");
 return 0;
}
