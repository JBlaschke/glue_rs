/* Real ordinary file IO with explicitly modeled root-owned metadata and wait
 * state. This is not configured/native root bootstrap or credential evidence. */
#define _POSIX_C_SOURCE 200809L
#define _DARWIN_C_SOURCE 1
#include "runtime_profile.h"
#include "../bootstrap-runner/runner_internal.h"
#include <assert.h>
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>
#include <signal.h>
#include <sys/wait.h>
#ifdef __APPLE__
#include <CommonCrypto/CommonDigest.h>
#endif
static int close_fault;
int nr_fail(struct nr_attempt*a,enum nr_stage s,enum nr_reason r,int e,int d){if(a->error.stage==NR_NONE)a->error=(struct nr_error){s,r,e,d};return -1;}
int nr_before(struct nr_attempt*a,struct bio_time d,enum nr_stage s){(void)a;(void)d;(void)s;return 0;}
int nr_close_owned(struct nr_attempt*a,int*fd,enum nr_stage s){if(*fd<0)return 0;int n=*fd;*fd=-1;int r=close(n);if(close_fault){close_fault=0;a->close_failed=1;return nr_fail(a,s,NR_SYSCALL,EINTR,n);}if(r){a->close_failed=1;return nr_fail(a,s,NR_SYSCALL,errno,n);}return 0;}
int nr_sha_bytes(const uint8_t*p,size_t n,uint8_t out[32]){
#ifdef __APPLE__
 return CC_SHA256(p,(CC_LONG)n,out)==out?0:-1;
#else
 (void)p;(void)n;memset(out,1,32);return 0;
#endif
}
static int model_stat(int fd,struct stat*s){int r=fstat(fd,s);if(!r)s->st_uid=0;return r;}
#define fstat model_stat
#include "../bootstrap-runner/runner_files.c"
#undef fstat
static void put(int dir,const char*name,size_t size,struct stat*identity){int fd=openat(dir,name,O_WRONLY|O_CREAT|O_EXCL|O_CLOEXEC,0600);assert(fd>=0);unsigned char bytes[4096];for(unsigned i=0;i<sizeof(bytes);i++)bytes[i]=(unsigned char)i;while(size){size_t n=size>sizeof(bytes)?sizeof(bytes):size;assert(write(fd,bytes,n)==(ssize_t)n);size-=n;}assert(!fstat(fd,identity)&&!close(fd));}
int main(int argc,char**argv){assert(argc==3);int mode=atoi(argv[1]);assert(strlen(argv[2])<BA_PATH_MAX);assert(!mkdir(argv[2],0700));struct nr_attempt a;memset(&a,0,sizeof(a));
 a.output_fd=open(argv[2],O_RDONLY|O_DIRECTORY|O_CLOEXEC);assert(a.output_fd>=0);strcpy(a.output_path,argv[2]);
 a.runtime_cwd_fd=a.held_outputs[0]=a.held_outputs[1]=-1;a.sources[1]=a.sources[2]=-1;
 struct nrr_catalog c={0};a.runtime_catalog=&c;
 static const struct tl_span args[]={{(const uint8_t*)"run",3}};struct tl_recipe recipe={TL_AARCH64_DARWIN,args,1,0};struct tl_error e;
 assert(!tl_prepare(&recipe,(struct tl_span){(const uint8_t*)"/fixture/glue",13},&a.runtime_plan,&e));
 put(a.output_fd,"app.stdout",mode==1?NRR_OUTPUT_BYTES+1:257,&a.stdout_identity);put(a.output_fd,"app.stderr",19,&a.stderr_identity);
 a.runtime_witness_written=a.runtime_delivery_written=1; /* explicitly modeled prior packet retention */
 a.forked=a.reaped=a.ready_matched=a.objects_matched=a.output_matches.ready=a.go_attempted=a.go_closed=1;a.stream.end=BW_END_ATTEMPT_WITHOUT_REPORTED_EXEC_ERROR;
 a.owner=getpid();pid_t child=fork();assert(child>=0);if(child==0){if(mode==6){kill(getpid(),SIGKILL);_exit(99);}_exit(mode==2?7:0);}
 a.child=child;assert(waitpid(child,&a.wait_status,0)==child);if(mode==2||mode==6)nr_fail(&a,NR_WAIT,NR_CHILD_STATUS,0,-1);
 if(mode==3)a.runtime_cwd_fd=99;
 if(mode==4)close_fault=1;
 if(mode==5)a.go_attempted=0;
 int result=nr_finish_outputs(&a);
 if(mode==3||mode==4){assert(result&&a.error.stage!=NR_NONE);char result_path[512];assert(snprintf(result_path,sizeof(result_path),"%s/result.json",argv[2])>0);assert(access(result_path,F_OK)==-1&&errno==ENOENT);return 0;}
#ifdef __APPLE__
 assert(!result);
#else
 assert(result);
#endif
 assert(a.runtime_outputs_valid==(mode!=1));if(mode==1)assert(a.runtime_stream_oversize[0]&&a.runtime_stream_sizes[0]==NRR_OUTPUT_BYTES+1);
 #ifdef __APPLE__
 if(mode==0)assert(a.error.stage==NR_NONE);else assert(a.error.stage!=NR_NONE);
 #else
 assert(a.error.stage!=NR_NONE);
 #endif
 return 0;
}
