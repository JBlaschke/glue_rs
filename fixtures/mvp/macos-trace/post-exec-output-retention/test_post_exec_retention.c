#define _POSIX_C_SOURCE 200809L
#define _DARWIN_C_SOURCE 1
#define _DEFAULT_SOURCE 1
#include "post_exec_retention_test.h"
#include "observer_fixture.h"
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/stat.h>
#include <unistd.h>
#define A(x) do{if(!(x)){fprintf(stderr,"%s:%d: %s\n",__FILE__,__LINE__,#x);return 1;}}while(0)
struct model {
 pid_t owner;uid_t uid;uint64_t now;
 unsigned clocks,flags,stats,opens,writes,syncs,closes;
 unsigned clock_fail,clock_late,clock_back,after,short_size,eintrs;
 int next_late,bad_call,bad_flags,bad_identity,open_fail,write_fail,sync_fail,close_fail;
 uint8_t bytes[PX_BYTES];size_t used;
};
static struct model model(void){struct model m;memset(&m,0,sizeof(m));m.owner=getpid();m.uid=geteuid();m.now=1000;return m;}
static pid_t owner(void *c){return ((struct model *)c)->owner;}
static uid_t uid(void *c){return ((struct model *)c)->uid;}
static int clock_fn(void *c,uint64_t *out,int *e){struct model *m=c;unsigned n=++m->clocks;
 if(n==m->clock_fail){*e=EIO;return -1;}*out=++m->now;
 if(n==m->clock_late||m->next_late){*out=1000000;m->next_late=0;}
 if(n==m->clock_back){*out=1;}return 0;}
static int flags(void *c,int fd,int cmd,int *e){(void)e;struct model *m=c;m->flags++;
 if((fd!=50&&fd!=51)||(cmd!=F_GETFD&&cmd!=F_GETFL))m->bad_call=1;
 int value=cmd==F_GETFD?FD_CLOEXEC:fd==50?O_RDONLY:O_WRONLY;
 if(m->bad_flags==1&&fd==50&&cmd==F_GETFD)value=0;
 if(m->bad_flags==2&&fd==50&&cmd==F_GETFL)value=O_RDWR;
 if(m->bad_flags==3&&fd==51&&cmd==F_GETFD)value=0;
 if(m->bad_flags==4&&fd==51&&cmd==F_GETFL)value=O_RDONLY;
 if(m->bad_flags==5&&fd==51&&cmd==F_GETFL)value=O_WRONLY|O_APPEND;
 return value;
}
static int stat_fn(void *c,int fd,struct stat *s,int *e){(void)e;struct model *m=c;m->stats++;
 memset(s,0,sizeof(*s));s->st_uid=m->uid;s->st_dev=9;s->st_ino=10;s->st_nlink=fd==50?2:1;
 s->st_mode=(mode_t)(fd==50?S_IFDIR|0700:S_IFREG|0600);
 if(m->bad_identity==1&&fd==50)s->st_uid++;
 if(m->bad_identity==2&&fd==50)s->st_mode=(mode_t)(S_IFDIR|0755);
 if(m->bad_identity==3&&fd==50)s->st_mode=(mode_t)(S_IFREG|0700);
 if(m->bad_identity==4&&fd==51)s->st_uid++;
 if(m->bad_identity==5&&fd==51)s->st_nlink=2;
 if(m->bad_identity==6&&fd==51)s->st_mode=(mode_t)(S_IFDIR|0600);
 if(m->bad_identity==7&&fd==51)s->st_mode=(mode_t)(S_IFREG|0644);
 if(m->bad_identity==8&&fd==51)s->st_size=1;
 return 0;
}
static int open_fn(void *c,int fd,const char *name,int f,mode_t mode,int *e){struct model *m=c;m->opens++;
 if(fd!=50||strcmp(name,PXRET_BASENAME)||mode!=0600||f!=(O_WRONLY|O_CREAT|O_EXCL|O_NOFOLLOW|O_CLOEXEC))m->bad_call=1;
 if(m->after==1){m->next_late=1;}if(m->open_fail){*e=EEXIST;return -1;}return 51;}
static ssize_t write_fn(void *c,int fd,const void *p,size_t n,int *e){struct model *m=c;m->writes++;
 if(fd!=51||n>PX_BYTES-m->used)m->bad_call=1;
 if(m->after==2)m->next_late=1;
 if(m->writes<=m->eintrs){*e=EINTR;return -1;}
 if(m->write_fail){if(m->write_fail==1){*e=EIO;return -1;}if(m->write_fail==2)return 0;return (ssize_t)n+1;}
 if(m->short_size&&n>m->short_size)n=m->short_size;
 memcpy(m->bytes+m->used,p,n);m->used+=n;return (ssize_t)n;}
static int sync_fn(void *c,int fd,int *e){struct model *m=c;m->syncs++;if(fd!=51)m->bad_call=1;
 if(m->after==3){m->next_late=1;}if(m->sync_fail){*e=EIO;return -1;}return 0;}
static int close_fn(void *c,int fd,int *e){struct model *m=c;m->closes++;if(fd!=51)m->bad_call=1;
 if(m->after==4){m->next_late=1;}if(m->close_fail){*e=EINTR;return -1;}return 0;}
static struct px_retention *start(struct model *m,const struct px_observer *o,uint64_t deadline){
 struct px_retention_test_operations ops={m,owner,uid,clock_fn,flags,stat_fn,open_fn,write_fn,sync_fn,close_fn};
 struct px_retention_error e;return px_retention_model_new(o,50,deadline,&ops,&e);
}
static int authority(const struct px_retention_status *s){return s->native_admission||s->state_admission||s->output_authority||s->full_acceptance||s->namespace_durability||s->power_loss_durability;}
static int run(struct model *m,const struct px_observer *o,struct px_retention_status *s){
 struct px_retention *r=start(m,o,1000000);if(!r)return -2;
 struct px_retention_error e;int result=px_retention_write(r,&e);
 if(px_retention_snapshot(r,s)||authority(s)||m->bad_call){px_retention_free(r);return -2;}
 unsigned calls=m->clocks+m->flags+m->stats+m->opens+m->writes+m->syncs+m->closes;
 struct px_retention_status copy=*s;uint8_t bytes[PX_BYTES],expected[PX_BYTES];struct px_error pe;
 if(px_retention_copy_observation(r,bytes)||px_observer_encode(o,expected,&pe)||memcmp(bytes,expected,PX_BYTES))return -2;
 if(px_retention_write(r,&e)!=-1||e.reason!=PXRET_REPLAY)return -2;
 if(px_retention_snapshot(r,s)||memcmp(s,&copy,sizeof(copy)))return -2;
 if(calls!=m->clocks+m->flags+m->stats+m->opens+m->writes+m->syncs+m->closes)return -2;
 px_retention_free(r);return result;
}
static int success(void){struct observer_fixture f;struct px_observer *o=fixture_observer(&f,0,0);A(o);
 struct model m=model();struct px_retention_status s;A(run(&m,o,&s)==0);
 A(s.state==PXRET_FILE_SYNCED&&s.bytes_written==4096&&s.file_synced_content&&s.sync_succeeded&&s.close_succeeded);
 A(m.writes==1&&m.syncs==1&&m.closes==1&&!s.file_ownership_unresolved);
 uint8_t b[4096];struct px_error e;A(px_observer_encode(o,b,&e)==0&&memcmp(b,m.bytes,4096)==0);
 px_observer_free(o);return 0;}
static int bad_observers(void){for(int state=1;state<=4;state++){
 struct observer_fixture f;struct px_observer *o=fixture_observer(&f,state,0);A(o);
 struct model m=model();struct px_retention_status s;A(run(&m,o,&s)==-1);
 A(m.opens==0&&m.writes==0&&m.closes==0&&s.observation_encoded&&!s.file_synced_content);px_observer_free(o);}
 struct observer_fixture f;struct px_observer *o=fixture_observer(&f,0,0);A(o);
 for(unsigned kind=0;kind<3;kind++){struct model m=model();if(kind==0)m.owner++;if(kind==1)m.uid++;
  struct px_retention *r=start(&m,o,kind==2?1000001:1000000);A(r);
  if(kind==1){m.uid++;}struct px_retention_error e;A(px_retention_write(r,&e)==-1);
  A(m.opens==0&&m.writes==0&&m.closes==0);px_retention_free(r);}
 px_observer_free(o);return 0;}
static int metadata(void){struct observer_fixture f;struct px_observer *o=fixture_observer(&f,0,0);A(o);
 for(int k=1;k<=5;k++){struct model m=model();m.bad_flags=k;struct px_retention_status s;A(run(&m,o,&s)==-1);A(m.writes==0&&m.syncs==0);A(m.closes==(unsigned)(k>=3));}
 for(int k=1;k<=8;k++){struct model m=model();m.bad_identity=k;struct px_retention_status s;A(run(&m,o,&s)==-1);A(m.writes==0&&m.syncs==0);A(m.closes==(unsigned)(k>=4));}
 px_observer_free(o);return 0;}
static int short_writes(void){struct observer_fixture f;struct px_observer *o=fixture_observer(&f,0,0);A(o);
 for(unsigned chunk=1;chunk<4096;chunk++){struct model m=model();m.short_size=chunk;struct px_retention_status s;
  unsigned expected=(4096+chunk-1)/chunk;int result=run(&m,o,&s);
  A(result==(expected<=64?0:-1));A(m.writes==(expected<=64?expected:64));A(m.closes==1);
  A(s.bytes_written==(expected<=64?4096:64*chunk));A(m.syncs==(unsigned)(expected<=64));}
 for(unsigned kind=0;kind<2;kind++){struct model m=model();m.eintrs=kind?64:63;struct px_retention_status s;
  A(run(&m,o,&s)==(kind?-1:0));A(m.writes==64&&m.closes==1&&m.syncs==!kind);
  A(s.writes[0].result==-1&&s.writes[0].system_errno==EINTR);}
 px_observer_free(o);puts("short_lengths=4095 eintr_boundaries=2");return 0;}
static int native_failures(void){struct observer_fixture f;struct px_observer *o=fixture_observer(&f,0,0);A(o);
 for(int kind=0;kind<6;kind++){struct model m=model();if(kind==0)m.open_fail=1;
  if(kind>=1&&kind<=3){m.write_fail=kind;}if(kind==4)m.sync_fail=1;if(kind==5)m.close_fail=1;
  struct px_retention_status s;A(run(&m,o,&s)==-1);A(m.closes==(unsigned)(kind!=0));A(!s.file_synced_content);
  if(kind==5)A(s.file_ownership_unresolved&&!s.close_succeeded&&s.close_call.system_errno==EINTR);
  if(kind==4)A(s.sync_call.result==-1&&s.sync_call.system_errno==EIO&&s.bytes_written==4096);
 }
 struct model m=model();m.sync_fail=1;m.close_fail=1;m.after=4;struct px_retention_status s;
 A(run(&m,o,&s)==-1);A(s.first_error.stage==PXRET_SYNC&&s.first_error.system_errno==EIO);
 A(s.sync_call.system_errno==EIO&&s.close_call.system_errno==EINTR&&s.close_call.after_error.reason==PXRET_LATE);
 A(s.file_ownership_unresolved&&!s.close_succeeded&&m.closes==1);
 px_observer_free(o);return 0;}
static int clocks(void){struct observer_fixture f;struct px_observer *o=fixture_observer(&f,0,0);A(o);
 for(unsigned kind=0;kind<3;kind++)for(unsigned n=1;n<=21;n++){
  struct model m=model();if(kind==0)m.clock_fail=n;if(kind==1)m.clock_late=n;if(kind==2)m.clock_back=n;
  struct px_retention_status s;A(run(&m,o,&s)==-1);A(s.clock_faults&&m.closes==s.open_succeeded&&!s.file_synced_content);
  if(s.open_succeeded)A(s.close_call.attempted&&s.close_succeeded);
 }
 for(unsigned stage=1;stage<=4;stage++){struct model m=model();m.after=stage;struct px_retention_status s;A(run(&m,o,&s)==-1);A(s.close_succeeded&&m.closes==1);
  if(stage==1)A(s.open_call.result==51&&s.open_call.after_error.reason==PXRET_LATE&&m.writes==0);
  if(stage==2)A(s.bytes_written==4096&&s.writes[0].result==4096&&s.writes[0].after_error.reason==PXRET_LATE&&m.syncs==0);
  if(stage==3)A(s.sync_succeeded&&s.sync_call.after_error.reason==PXRET_LATE);
  if(stage==4)A(s.close_succeeded&&s.close_call.after_error.reason==PXRET_LATE);
 }
 px_observer_free(o);puts("clock_points=63 after_call_lateness=4");return 0;}
static int arguments(void){struct px_retention_error e;struct px_retention_status s;memset(&s,0xa5,sizeof(s));
 A(px_retention_snapshot(NULL,&s)==-1&&!s.owner_pid&&!s.file_synced_content);
 uint8_t b[4096];memset(b,1,sizeof(b));A(px_retention_copy_observation(NULL,b)==-1);
 for(unsigned i=0;i<4096;i++){A(b[i]==0);}A(px_retention_write(NULL,&e)==-1);
 A(e.stage==PXRET_VALIDATE&&e.reason==PXRET_ARGUMENT&&e.system_errno==0);px_retention_free(NULL);
 struct observer_fixture f;struct px_observer *o=fixture_observer(&f,0,0);A(o);
 A(!px_retention_new(NULL,50,1000000,&e));A(!px_retention_new(o,2,1000000,&e));A(!px_retention_new(o,50,0,&e));A(!px_retention_new(o,50,1000000,NULL));
 struct model m=model();struct px_retention *r=start(&m,o,1000000);A(r);
 A(px_retention_copy_observation(r,b)==-1);A(px_retention_write(r,NULL)==-1);
 A(px_retention_snapshot(r,&s)==0&&s.attempt_consumed&&s.state==PXRET_REFUSED&&s.first_error.reason==PXRET_ARGUMENT);
 A(px_retention_write(r,&e)==-1&&e.reason==PXRET_REPLAY);px_retention_free(r);A(m.opens==0&&m.closes==0);
 px_observer_free(o);return 0;}
static int real_file(const char *path,int kind){struct observer_fixture f;struct px_observer *o=fixture_observer(&f,0,1);A(o);
 int fd=open(path,O_RDONLY|O_DIRECTORY|O_NOFOLLOW|(kind==2?0:O_CLOEXEC));A(fd>=3);
 int oldflags=fcntl(fd,F_GETFD);struct stat old;A(fstat(fd,&old)==0);
 if(kind==1){int initial=openat(fd,PXRET_BASENAME,O_WRONLY|O_CREAT|O_EXCL|O_CLOEXEC,0600);A(initial>=0);A(write(initial,"KEEP",4)==4);A(close(initial)==0);}
 if(kind==3)A(symlinkat("unopened-owned-target",fd,PXRET_BASENAME)==0);
 struct px_retention_error e;struct px_retention *r=px_retention_new(o,fd,f.plan.deadline,&e);A(r);
 int rc=px_retention_write(r,&e);struct px_retention_status s;A(px_retention_snapshot(r,&s)==0&&!authority(&s));
 A(rc==(kind==0?0:-1));if(kind==0){
  uint8_t bytes[4096],expected[4096];int readfd=openat(fd,PXRET_BASENAME,O_RDONLY|O_NOFOLLOW|O_CLOEXEC);A(readfd>=0);
  A(read(readfd,bytes,sizeof(bytes))==4096);char tail;A(read(readfd,&tail,1)==0);A(close(readfd)==0);
  struct px_error pe;A(px_observer_encode(o,expected,&pe)==0&&memcmp(bytes,expected,4096)==0);
  A(s.sync_succeeded&&s.close_succeeded&&s.file_synced_content&&s.file_identity.links==1);
 }else A(!s.open_succeeded&&s.bytes_written==0&&!s.close_call.attempted);
 A(px_retention_write(r,&e)==-1&&e.reason==PXRET_REPLAY);px_retention_free(r);
 A(fcntl(fd,F_GETFD)==oldflags);struct stat after;A(fstat(fd,&after)==0&&after.st_dev==old.st_dev&&after.st_ino==old.st_ino);
 if(kind==1){int rd=openat(fd,PXRET_BASENAME,O_RDONLY|O_CLOEXEC);char keep[4];A(rd>=0&&read(rd,keep,4)==4&&!memcmp(keep,"KEEP",4));A(close(rd)==0);}
 if(kind==3){char link[64];A(readlinkat(fd,PXRET_BASENAME,link,sizeof(link))==21);}
 A(close(fd)==0);px_observer_free(o);puts("file_io=real observer_stop_and_lease=model provider=none signals=none");return 0;}
int main(int argc,char **argv){if(argc<2)return 2;
 if(!strcmp(argv[1],"success")){return success();}if(!strcmp(argv[1],"bad-observers"))return bad_observers();
 if(!strcmp(argv[1],"metadata")){return metadata();}if(!strcmp(argv[1],"short-writes"))return short_writes();
 if(!strcmp(argv[1],"syscalls")){return native_failures();}if(!strcmp(argv[1],"clocks"))return clocks();
 if(!strcmp(argv[1],"arguments"))return arguments();
 if(argc==3){if(!strcmp(argv[1],"real"))return real_file(argv[2],0);if(!strcmp(argv[1],"existing"))return real_file(argv[2],1);
  if(!strcmp(argv[1],"no-cloexec")){return real_file(argv[2],2);}if(!strcmp(argv[1],"symlink"))return real_file(argv[2],3);}
 return 2;}
