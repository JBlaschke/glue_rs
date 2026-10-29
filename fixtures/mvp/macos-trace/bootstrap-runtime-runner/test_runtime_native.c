/* Ordinary native real nr_execute/nr_child/gate/FD/exec control. Only native
 * protected admission and credential mutation are explicitly MODELED. No root
 * transition, configured bootstrap, glue application or runtime proof occurs. */
#define _POSIX_C_SOURCE 200809L
#define _DARWIN_C_SOURCE 1
#include "runtime_profile.h"
#include "../bootstrap-runner/runner_internal.h"
#include "../target-credentials/target_credentials.h"
#include <assert.h>
#include <errno.h>
#include <fcntl.h>
#include <signal.h>
#include <stdio.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <unistd.h>
static int modeled_credentials(const struct tc_request*r,uint64_t owner,const struct tc_operations*o,struct tc_error*e){
 (void)o;memset(e,0,sizeof(*e));e->mutation_attempted=1;
 assert((uint64_t)getppid()==owner&&(uint64_t)getpid()!=owner&&getuid()==r->uid&&geteuid()==r->uid&&getgid()==r->gid&&getegid()==r->gid);
 gid_t groups[16];int n=getgroups(16,groups);assert(n==(int)r->group_count);for(int i=0;i<n;i++)assert(groups[i]==r->groups[i]);return 0;
}
#define tc_drop_in_owned_child modeled_credentials
#include "../bootstrap-runner/runner_child.c"
#undef tc_drop_in_owned_child

#ifdef __APPLE__
static void channel(int fds[2]){assert(!pipe(fds));for(unsigned i=0;i<2;i++){int f=fcntl(fds[i],F_GETFL),d=fcntl(fds[i],F_GETFD);assert(f>=0&&d>=0&&!fcntl(fds[i],F_SETFL,f|O_NONBLOCK)&&!fcntl(fds[i],F_SETFD,d|FD_CLOEXEC));}}
#endif
int main(int argc,char**argv){assert(argc==3);
#if !defined(__APPLE__)
 (void)argv;return 77;
#else
 if(getuid()==0||geteuid()==0||!getgid())return 77;
 gid_t groups[16];int count=getgroups(16,groups);if(count<1||count>16||groups[0]!=getgid()||!td_native_operations()->supported)return 77;
 assert(strlen(argv[1])<BA_PATH_MAX&&strlen(argv[2])+sizeof("/unrelated")<BA_PATH_MAX);
 struct stat parent_before,parent_after;assert(!stat(".",&parent_before));assert(!mkdir(argv[2],0700));char cwd[BA_PATH_MAX],archive[BA_PATH_MAX],out[BA_PATH_MAX],err[BA_PATH_MAX];
 assert(snprintf(cwd,sizeof(cwd),"%s/unrelated",argv[2])>0&&snprintf(archive,sizeof(archive),"%s/app.glue",argv[2])>0&&snprintf(out,sizeof(out),"%s/app.stdout",argv[2])>0&&snprintf(err,sizeof(err),"%s/app.stderr",argv[2])>0);assert(!mkdir(cwd,0700));
 int archive_fd=open(archive,O_WRONLY|O_CREAT|O_EXCL|O_CLOEXEC,0600);assert(archive_fd>=0&&write(archive_fd,"fixture",7)==7&&!close(archive_fd));
 struct nr_attempt a;memset(&a,0,sizeof(a));a.owner=getpid();a.child=-1;a.output_fd=-1;a.held_outputs[0]=a.held_outputs[1]=-1;
 for(unsigned i=0;i<5;i++)a.sources[i]=a.endpoints.copies[i]=-1;
 for(unsigned i=0;i<2;i++)a.gate[i]=a.status[i]=-1;
 for(unsigned i=0;i<BA_COMPONENT_COUNT;i++)a.admission.components[i].fd=-1;
 a.runtime_cwd_fd=open(cwd,O_RDONLY|O_DIRECTORY|O_CLOEXEC);assert(a.runtime_cwd_fd>=3);struct stat st;assert(!fstat(a.runtime_cwd_fd,&st));
 strcpy(a.executable,argv[1]);strcpy(a.cwd,cwd);a.admission.ready=1;a.admission.checked_count=a.admission.owned_count=BA_COMPONENT_COUNT;
 a.request.fixture=a.request.argv_template=2;a.request.credentials.uid=getuid();a.request.credentials.gid=getgid();a.request.credentials.group_count=(size_t)count;for(int i=0;i<count;i++)a.request.credentials.groups[i]=groups[i];
 a.request.signal_policy=a.request.stdio_policy=a.request.release_action=1;a.request.max_live_fds=4096;a.request.attempt_ms=5000;a.request.cleanup_ms=2000;
 a.request.cwd_device=(uint64_t)(uint32_t)st.st_dev;a.request.cwd_inode=(uint64_t)st.st_ino;a.request.executable=(struct br_span){(const uint8_t*)a.executable,strlen(a.executable)};a.request.cwd=(struct br_span){(const uint8_t*)a.cwd,strlen(a.cwd)};
 struct tl_span arguments[]={{(const uint8_t*)"run",3},{(const uint8_t*)archive,strlen(archive)},{(const uint8_t*)"--",2},{(const uint8_t*)"argument with spaces",20}};struct tl_recipe recipe={TL_AARCH64_DARWIN,arguments,4,0};struct tl_error le;assert(!tl_prepare(&recipe,(struct tl_span){(const uint8_t*)a.executable,strlen(a.executable)},&a.runtime_plan,&le));
 struct bs_error se;a.signals_initialized=1;assert(!bs_prepare_parent(bs_native_operations(),&a.signals,&se));unsigned char policy[BS_POLICY_CAPACITY];size_t used;assert(!bs_policy_bytes(&a.signals,policy,&used,&se)&&!nr_sha_bytes(policy,used,a.policy_sha));
 a.sources[0]=open("/dev/null",O_RDONLY|O_NOFOLLOW|O_CLOEXEC);a.sources[1]=open(out,O_WRONLY|O_CREAT|O_EXCL|O_CLOEXEC,0600);a.sources[2]=open(err,O_WRONLY|O_CREAT|O_EXCL|O_CLOEXEC,0600);assert(a.sources[0]>=3&&a.sources[1]>=3&&a.sources[2]>=3);
 channel(a.gate);channel(a.status);a.sources[3]=a.gate[0];a.sources[4]=a.status[1];struct te_request tr;memcpy(tr.source,a.sources,sizeof(tr.source));assert(!te_prepare_owned_sources(&tr,te_native_operations(),&a.endpoints,&a.endpoint_error));a.ready_context_fds[0]=(uint64_t)a.endpoints.copies[3];a.ready_context_fds[1]=(uint64_t)a.endpoints.copies[4];
 assert(!nr_deadline(&a,5000,&a.deadline));int result=nr_execute(&a);nr_cleanup(&a);assert(!result&&a.reaped&&!a.lost_child&&!a.error.stage&&!a.cleanup_error.stage&&a.runtime_cwd_fd==-1&&a.held_outputs[0]==-1&&a.held_outputs[1]==-1&&a.objects_matched&&a.go_attempted&&a.go_closed&&a.stream.used==1024);
 assert(!stat(".",&parent_after)&&parent_before.st_dev==parent_after.st_dev&&parent_before.st_ino==parent_after.st_ino);
 unsigned char bytes[32];int fd=open(out,O_RDONLY);assert(fd>=0);ssize_t n=read(fd,bytes,sizeof(bytes));assert(n==15&&!memcmp(bytes,"\0fixed-runtime\n",15)&&!close(fd));assert(!stat(err,&st)&&st.st_size==0);
 puts("actual owned child/gate/FD/CWD/exec; modeled admission and credential mutation; empty env literal case argv; parent CWD unchanged");return 0;
#endif
}
