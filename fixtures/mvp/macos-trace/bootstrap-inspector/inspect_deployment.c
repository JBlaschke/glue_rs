#define _POSIX_C_SOURCE 200809L
#define _DEFAULT_SOURCE 1
#define _DARWIN_C_SOURCE 1
#include "../bootstrap-admission/bootstrap_admission.h"
#include <errno.h>
#include <stdio.h>
#include <unistd.h>
#if defined(__APPLE__)
#include <fcntl.h>
#include <grp.h>
#include <inttypes.h>
#include <limits.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/sysctl.h>
#include <time.h>
static int safe_text(char *p,size_t n) {
 if(!memchr(p,0,n) || !p[0])return 0;
 for(size_t i=0;p[i];i++) {
  unsigned char c=(unsigned char)p[i];
  if(!((c>='a'&&c<='z')||(c>='A'&&c<='Z')||(c>='0'&&c<='9')||c==','||c=='.'||c=='-'||c=='_'))return 0;
 } return 1;
}
static int metadata_ok(const struct ba_metadata *m,int data) {
 unsigned wanted=BA_MOUNT_LOCAL|(data?0:BA_MOUNT_ROOTFS);
 return m->populated==7 && m->filesec_uid==m->uid && m->filesec_gid==m->gid &&
 m->filesec_mode==m->mode && m->acl_present==0 && m->uid==0 && S_ISDIR(m->mode) &&
 !(m->mode&(S_IWGRP|S_IWOTH|S_ISUID|S_ISGID)) && m->descriptor_flags>=0 &&
 (m->descriptor_flags&FD_CLOEXEC) && m->status_flags>=0 && (m->status_flags&O_ACCMODE)==O_RDONLY &&
 !(m->status_flags&(O_ASYNC|O_EVTONLY)) && m->mount_policy==wanted && m->mount_owner==0 &&
 memchr(m->filesystem,0,sizeof(m->filesystem)) && memchr(m->mountpoint,0,sizeof(m->mountpoint)) &&
 !strcmp(m->filesystem,"apfs") && !strcmp(m->mountpoint,data?"/System/Volumes/Data":"/");
}
static int same_mount(const struct ba_metadata *a,const struct ba_metadata *b) {
 return a->device==b->device && a->fsid[0]==b->fsid[0] && a->fsid[1]==b->fsid[1];
}
static int inspect(void) {
 const struct ba_operations *o=ba_native_operations();
 uint64_t ids[4]={(uint64_t)getuid(),(uint64_t)geteuid(),(uint64_t)getgid(),(uint64_t)getegid()};
 for(unsigned i=0;i<4;i++)if(!ids[i]||ids[i]>INT32_MAX) { fputs("inspector: ordinary user required\n",stderr);return 1; }
 int count=getgroups(0,NULL);
 if(count<0||count>256) { fputs("inspector: groups unavailable\n",stderr);return 1; }
 gid_t groups[256]={0};int actual=getgroups(256,groups);
 if(actual!=count) { fputs("inspector: groups changed or unavailable\n",stderr);return 1; }
 int compatible=count>0&&count<=16&&ids[0]==ids[1]&&ids[2]==ids[3]&&(uint64_t)groups[0]==ids[2];
 for(int i=0;i<count;i++) { if((uint64_t)groups[i]>INT32_MAX)compatible=0;for(int j=0;j<i;j++)if(groups[i]==groups[j])compatible=0; }
 char model[64]={0},release[64]={0};size_t length=sizeof(model);
 if(sysctlbyname("hw.model",model,&length,NULL,0)||!safe_text(model,sizeof(model)))return 1;
 length=sizeof(release);if(sysctlbyname("kern.osrelease",release,&length,NULL,0)||!safe_text(release,sizeof(release)))return 1;
 static const char *const names[]={"/","System","Volumes","Data","Library"};
 int fds[5]={-1,-1,-1,-1,-1},saved=0,failed=0;size_t owned=0;
 struct ba_metadata m[5];memset(m,0,sizeof(m));
 for(size_t i=0;i<5;i++) {
  int fd=i?o->openat_fn(o->context,fds[i-1],names[i],0,&saved):o->open_root_fn(o->context,&saved);
  if(fd<0) { failed=1;break; }fds[i]=fd;owned++;
  struct ba_probe_error pe={BA_META_NONE,0};
  if(o->inspect_fn(o->context,fd,&m[i],&pe)||!metadata_ok(&m[i],i>=3)) { failed=1;break; }
  if(i>0&&i<3&&!same_mount(&m[0],&m[i])) { failed=1;break; }
  if(i==3&&same_mount(&m[0],&m[3])) { failed=1;break; }
  if(i==4&&!same_mount(&m[3],&m[4])) { failed=1;break; }
 }
 /* No retry on ambiguous close/EINTR; still attempt each other owned FD once. */
 while(owned) { owned--;if(close(fds[owned]))failed=1; }
 if(failed) { fputs("inspector: incomplete component metadata or close\n",stderr);return 1; }
 struct timespec t;if(clock_gettime(CLOCK_REALTIME,&t)||t.tv_sec<0||t.tv_nsec<0||t.tv_nsec>=1000000000)return 1;
 printf("{\"schema\":\"glue-bootstrap-deployment-observation-v1\",\"model\":\"%s\",\"kernel_release\":\"%s\",\"observed_unix_seconds\":%" PRIu64 ",\"observed_nanoseconds\":%ld,\"ids\":[%" PRIu64 ",%" PRIu64 ",%" PRIu64 ",%" PRIu64 "],\"groups\":[",model,release,(uint64_t)t.tv_sec,t.tv_nsec,ids[0],ids[1],ids[2],ids[3]);
 for(int i=0;i<count;i++)printf("%s%" PRIu64,i?",":"",(uint64_t)groups[i]);
 printf("],\"tc_compatible\":%s,\"components\":[",compatible?"true":"false");
 for(size_t i=0;i<5;i++)printf("%s{\"name\":\"%s\",\"device\":%" PRIu64 ",\"inode\":%" PRIu64 ",\"uid\":%u,\"gid\":%u,\"mode\":%u,\"fsid\":[%" PRId32 ",%" PRId32 "],\"mount_flags\":%" PRIu64 ",\"mount_policy\":%u,\"mount_owner\":%u,\"descriptor_flags\":%d,\"status_flags\":%d,\"mountpoint\":\"%s\",\"filesystem\":\"apfs\",\"filesec_population\":7,\"acl_present\":0}",i?",":"",names[i],m[i].device,m[i].inode,m[i].uid,m[i].gid,m[i].mode,m[i].fsid[0],m[i].fsid[1],m[i].mount_flags,m[i].mount_policy,m[i].mount_owner,m[i].descriptor_flags,m[i].status_flags,i>=3?"/System/Volumes/Data":"/");
 fputs("],\"settings_changed\":false,\"executable_admission\":false,\"full_acceptance\":false}\n",stdout);
 return fflush(stdout)==0&&!ferror(stdout)?0:1;
}
#endif
int main(int argc,char **argv) {
 (void)argv;
 if(argc!=1) { fputs("inspector: no arguments accepted\n",stderr);return 2; }
#if defined(__APPLE__)
 return inspect();
#else
 fputs("inspector: native Darwin required\n",stderr);return 1;
#endif
}
