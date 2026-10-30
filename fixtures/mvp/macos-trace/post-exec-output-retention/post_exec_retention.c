#define _POSIX_C_SOURCE 200809L
#define _DARWIN_C_SOURCE 1
#define _DEFAULT_SOURCE 1
#include "post_exec_retention.h"
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <time.h>
#include <unistd.h>
#ifdef PXRET_TESTING
#include "post_exec_retention_test.h"
#else
struct px_retention_test_operations {
 void *context;pid_t (*owner_fn)(void *);uid_t (*uid_fn)(void *);
 int (*clock_fn)(void *,uint64_t *,int *);int (*flags_fn)(void *,int,int,int *);
 int (*stat_fn)(void *,int,struct stat *,int *);
 int (*open_fn)(void *,int,const char *,int,mode_t,int *);
 ssize_t (*write_fn)(void *,int,const void *,size_t,int *);
 int (*sync_fn)(void *,int,int *);int (*close_fn)(void *,int,int *);
};
#endif
struct px_retention {
 const struct px_observer *observer;
 struct px_retention_test_operations ops;
 struct px_retention_status status;
 uint8_t observation[PX_BYTES];
};
static uint64_t be(const uint8_t *p,unsigned n){uint64_t v=0;for(unsigned i=0;i<n;i++)v=v*256+p[i];return v;}
static int fault(struct px_retention *s,enum px_retention_stage stage,enum px_retention_reason reason,int saved){
 struct px_retention_error e={stage,reason,saved};
 if(!s->status.faults)s->status.first_error=e;
 s->status.last_error=e;s->status.faults++;s->status.state=PXRET_REFUSED;return -1;
}
static int current(struct px_retention *s,enum px_retention_stage stage){
 if(s->ops.owner_fn(s->ops.context)!=(pid_t)s->status.owner_pid ||
    s->ops.uid_fn(s->ops.context)!=(uid_t)s->status.effective_uid)
  return fault(s,stage,PXRET_OWNER,0);
 if(!px_observer_owns_child(s->observer))return fault(s,stage,PXRET_LEASE,0);
 return 0;
}
static int clock_check(struct px_retention *s,enum px_retention_stage stage,
 uint64_t *out,unsigned *present,struct px_retention_error *record){
 uint64_t now=0;int saved=0;enum px_retention_reason reason=PXRET_OK;
 if(s->ops.clock_fn(s->ops.context,&now,&saved))reason=PXRET_CLOCK;
 else {
  *out=now;*present=1;uint64_t prior=s->status.last_clock_ns;s->status.last_clock_ns=now;
  if(now<prior)reason=PXRET_ROLLBACK;
  else if(now>=s->status.original_deadline_ns)reason=PXRET_LATE;
 }
 if(reason==PXRET_OK)return 0;
 s->status.clock_faults++;*record=(struct px_retention_error){stage,reason,reason==PXRET_CLOCK?saved:0};
 return fault(s,stage,reason,record->system_errno);
}
static int before(struct px_retention *s,enum px_retention_stage stage,struct px_retention_call *c){
 int owner=current(s,stage);
 int timing=clock_check(s,stage,&c->before_ns,&c->before_present,&c->before_error);
 return owner||timing?-1:0;
}
static int after(struct px_retention *s,enum px_retention_stage stage,struct px_retention_call *c){
 int timing=clock_check(s,stage,&c->after_ns,&c->after_present,&c->after_error);
 int owner=current(s,stage);return timing||owner?-1:0;
}
static void returned(struct px_retention_call *c,int64_t value,int saved){
 c->attempted=1;c->result=value;c->system_errno=value<0?saved:0;
}
static void identity(struct px_retention_identity *out,const struct stat *st){
 out->device=(uint64_t)(int64_t)st->st_dev;out->inode=(uint64_t)st->st_ino;
 out->uid=(uint64_t)st->st_uid;out->links=(uint64_t)st->st_nlink;
 out->mode=(uint32_t)st->st_mode;out->size=(int64_t)st->st_size;
}
static int flags_check(struct px_retention *s,int fd,int command,int file){
 enum px_retention_stage stage=file?(command==F_GETFD?PXRET_FILE_FD:PXRET_FILE_FL):
                                  (command==F_GETFD?PXRET_DIR_FD:PXRET_DIR_FL);
 struct px_retention_call *c=file?(command==F_GETFD?&s->status.file_fd_flags:&s->status.file_status_flags):
                                  (command==F_GETFD?&s->status.directory_fd_flags:&s->status.directory_status_flags);
 if(before(s,stage,c))return -1;
 int saved=0,value=s->ops.flags_fn(s->ops.context,fd,command,&saved);returned(c,value,saved);
 if(value<0)fault(s,stage,PXRET_SYSCALL,saved);
 int late=after(s,stage,c);if(value<0||late)return -1;
 if((command==F_GETFD&&!(value&FD_CLOEXEC)) ||
    (command==F_GETFL&&((value&O_ACCMODE)!=(file?O_WRONLY:O_RDONLY)||(value&O_APPEND))))
  return fault(s,stage,PXRET_FLAGS,0);
 return 0;
}
static int stat_check(struct px_retention *s,int fd,int file){
 enum px_retention_stage stage=file?PXRET_FILE_STAT:PXRET_DIR_STAT;
 struct px_retention_call *c=file?&s->status.file_stat:&s->status.directory_stat;
 if(before(s,stage,c))return -1;
 struct stat st;memset(&st,0,sizeof(st));int saved=0,value=s->ops.stat_fn(s->ops.context,fd,&st,&saved);
 returned(c,value,saved);
 if(value==0)identity(file?&s->status.file_identity:&s->status.directory_identity,&st);
 else fault(s,stage,value==-1?PXRET_SYSCALL:PXRET_BAD_RESULT,value==-1?saved:0);
 int late=after(s,stage,c);if(value||late)return -1;
 if(st.st_uid!=(uid_t)s->status.effective_uid ||
    (file?(!S_ISREG(st.st_mode)||st.st_nlink!=1||st.st_size!=0||(st.st_mode&07777)!=0600):
          (!S_ISDIR(st.st_mode)||(st.st_mode&07777)!=0700)))return fault(s,stage,PXRET_IDENTITY,0);
 return 0;
}
static void close_once(struct px_retention *s){
 if(!s->status.open_succeeded||s->status.close_call.attempted)return;
 struct px_retention_call *c=&s->status.close_call;
 /* This acquired descriptor must be resolved once even after a failed before
  * check. Timing failure remains recorded and can never grant eligibility. */
 (void)before(s,PXRET_CLOSE,c);
 int saved=0,value=s->ops.close_fn(s->ops.context,s->status.opened_fd,&saved);
 returned(c,value,saved);
 if(value==0)s->status.close_succeeded=1;
 else {s->status.file_ownership_unresolved=1;
  fault(s,PXRET_CLOSE,value==-1?PXRET_SYSCALL:PXRET_BAD_RESULT,value==-1?saved:0);}
 (void)after(s,PXRET_CLOSE,c);
}
static int observe(struct px_retention *s){
 if(px_observer_encode(s->observer,s->observation,&s->status.observer_error))return fault(s,PXRET_VALIDATE,PXRET_OBSERVATION,0);
 s->status.observation_encoded=1;
 const uint8_t *b=s->observation;
 s->status.child_pid=(uint32_t)be(b+20,4);
 if(be(b+16,4)!=s->status.owner_pid)return fault(s,PXRET_VALIDATE,PXRET_OWNER,0);
 if(current(s,PXRET_VALIDATE))return -1;
 if(memcmp(b,"GLUEPX01",8)||be(b+8,2)!=1||be(b+10,2)!=256||be(b+12,4)!=PX_BYTES||
    be(b+56,2)!=PX_QUERY_COUNT||!be(b+58,2)||be(b+58,2)>PX_WAIT_COUNT||
    be(b+60,2)!=PX_COMPLETE||be(b+62,2)!=PX_OK||be(b+64,4)||
    be(b+68,4)!=(PX_OWNED|PX_STOPPED|PX_ATTEMPTED|PX_MATCHED)||
    be(b+80,2)!=be(b+58,2)||be(b+82,2))return fault(s,PXRET_VALIDATE,PXRET_OBSERVATION,0);
 if(be(b+32,8)!=s->status.original_deadline_ns)return fault(s,PXRET_VALIDATE,PXRET_DEADLINE_BINDING,0);
 s->status.last_clock_ns=be(b+72,8);
 if(s->status.last_clock_ns>=s->status.original_deadline_ns)return fault(s,PXRET_VALIDATE,PXRET_LATE,0);
 return 0;
}
int px_retention_write(struct px_retention *s,struct px_retention_error *e){
 if(e)*e=(struct px_retention_error){PXRET_VALIDATE,PXRET_OK,0};
 if(!s){if(e)*e=(struct px_retention_error){PXRET_VALIDATE,PXRET_ARGUMENT,0};return -1;}
 if(s->status.attempt_consumed){if(e)*e=(struct px_retention_error){PXRET_VALIDATE,PXRET_REPLAY,0};return -1;}
 s->status.attempt_consumed=1;
 if(!e)return fault(s,PXRET_VALIDATE,PXRET_ARGUMENT,0);
 if(observe(s))goto done;
 int directory=s->status.borrowed_directory_fd;
 if(flags_check(s,directory,F_GETFD,0)||flags_check(s,directory,F_GETFL,0)||stat_check(s,directory,0))goto done;
 struct px_retention_call *open=&s->status.open_call;
 if(before(s,PXRET_OPEN,open))goto done;
 int saved=0,fd=s->ops.open_fn(s->ops.context,directory,PXRET_BASENAME,
  O_WRONLY|O_CREAT|O_EXCL|O_NOFOLLOW|O_CLOEXEC,0600,&saved);
 returned(open,fd,saved);
 if(fd>=0){s->status.open_succeeded=1;s->status.opened_fd=fd;}
 else fault(s,PXRET_OPEN,PXRET_SYSCALL,saved);
 if(after(s,PXRET_OPEN,open)||fd<0)goto done;
 if(flags_check(s,fd,F_GETFD,1)||flags_check(s,fd,F_GETFL,1)||stat_check(s,fd,1))goto done;
 while(s->status.bytes_written<PX_BYTES && s->status.write_rows<PXRET_WRITE_LIMIT){
  struct px_retention_call *c=&s->status.writes[s->status.write_rows++];
  if(before(s,PXRET_WRITE,c))goto done;
  size_t left=PX_BYTES-s->status.bytes_written;int write_errno=0;
  ssize_t n=s->ops.write_fn(s->ops.context,fd,s->observation+s->status.bytes_written,left,&write_errno);
  returned(c,(int64_t)n,write_errno);s->status.write_calls++;
  if(n>0&&(uint64_t)n<=left)s->status.bytes_written+=(size_t)n;
  else if(n==0)fault(s,PXRET_WRITE,PXRET_ZERO_WRITE,0);
  else if(n!=-1)fault(s,PXRET_WRITE,PXRET_BAD_RESULT,0);
  else if(write_errno!=EINTR)fault(s,PXRET_WRITE,PXRET_SYSCALL,write_errno);
  if(after(s,PXRET_WRITE,c)||s->status.faults)goto done;
 }
 if(s->status.bytes_written!=PX_BYTES){fault(s,PXRET_WRITE,PXRET_LIMIT,0);goto done;}
 struct px_retention_call *sync=&s->status.sync_call;
 if(before(s,PXRET_SYNC,sync))goto done;
 saved=0;int result=s->ops.sync_fn(s->ops.context,fd,&saved);returned(sync,result,saved);
 if(result==0)s->status.sync_succeeded=1;
 else fault(s,PXRET_SYNC,result==-1?PXRET_SYSCALL:PXRET_BAD_RESULT,result==-1?saved:0);
 (void)after(s,PXRET_SYNC,sync);
done:
 close_once(s);
 if(!s->status.faults&&s->status.sync_succeeded&&s->status.close_succeeded){
  if(!current(s,PXRET_FINAL)){
   if(!before(s,PXRET_FINAL,&s->status.final_check)){s->status.file_synced_content=1;s->status.state=PXRET_FILE_SYNCED;}
  }
 }
 if(!s->status.file_synced_content){s->status.state=PXRET_REFUSED;*e=s->status.first_error;return -1;}
 return 0;
}
static int ops_valid(const struct px_retention_test_operations *o){return o&&o->owner_fn&&o->uid_fn&&o->clock_fn&&o->flags_fn&&o->stat_fn&&o->open_fn&&o->write_fn&&o->sync_fn&&o->close_fn;}
static struct px_retention *create(const struct px_observer *observer,int directory,uint64_t deadline,
 const struct px_retention_test_operations *ops,struct px_retention_error *e){
 if(e)*e=(struct px_retention_error){PXRET_VALIDATE,PXRET_ARGUMENT,0};
 if(!e||!observer||directory<3||!deadline||!ops_valid(ops))return NULL;
 pid_t owner=ops->owner_fn(ops->context);if(owner<=0||(uint64_t)owner>INT32_MAX)return NULL;
 struct px_retention *s=calloc(1,sizeof(*s));if(!s){e->system_errno=ENOMEM;return NULL;}
 s->observer=observer;s->ops=*ops;s->status.owner_pid=(uint32_t)owner;
 s->status.effective_uid=(uint64_t)ops->uid_fn(ops->context);s->status.original_deadline_ns=deadline;
 s->status.borrowed_directory_fd=directory;s->status.opened_fd=-1;s->status.state=PXRET_NEW;
 *e=(struct px_retention_error){PXRET_VALIDATE,PXRET_OK,0};return s;
}
int px_retention_snapshot(const struct px_retention *s,struct px_retention_status *out){
 if(out){memset(out,0,sizeof(*out));}if(!s||!out)return -1;*out=s->status;return 0;
}
int px_retention_copy_observation(const struct px_retention *s,uint8_t out[PX_BYTES]){
 if(out){memset(out,0,PX_BYTES);}if(!s||!out||!s->status.observation_encoded)return -1;memcpy(out,s->observation,PX_BYTES);return 0;
}
void px_retention_free(struct px_retention *s){if(s){memset(s,0,sizeof(*s));free(s);}}
static pid_t native_owner(void *c){(void)c;return getpid();}
static uid_t native_uid(void *c){(void)c;return geteuid();}
static int native_clock(void *c,uint64_t *out,int *e){
 (void)c;struct timespec t;if(clock_gettime(CLOCK_MONOTONIC,&t)){*e=errno;return -1;}
 if(t.tv_sec<0||t.tv_nsec<0||t.tv_nsec>=1000000000L||(uint64_t)t.tv_sec>(UINT64_MAX-(uint64_t)t.tv_nsec)/UINT64_C(1000000000)){*e=EOVERFLOW;return -1;}
 *out=(uint64_t)t.tv_sec*UINT64_C(1000000000)+(uint64_t)t.tv_nsec;return 0;
}
static int native_flags(void *c,int fd,int cmd,int *e){(void)c;int r=fcntl(fd,cmd);if(r<0)*e=errno;return r;}
static int native_stat(void *c,int fd,struct stat *s,int *e){(void)c;int r=fstat(fd,s);if(r<0)*e=errno;return r;}
static int native_open(void *c,int fd,const char *name,int flags,mode_t mode,int *e){(void)c;int r=openat(fd,name,flags,mode);if(r<0)*e=errno;return r;}
static ssize_t native_write(void *c,int fd,const void *p,size_t n,int *e){(void)c;ssize_t r=write(fd,p,n);if(r<0)*e=errno;return r;}
static int native_sync(void *c,int fd,int *e){(void)c;int r=fsync(fd);if(r<0)*e=errno;return r;}
static int native_close(void *c,int fd,int *e){(void)c;int r=close(fd);if(r<0)*e=errno;return r;}
struct px_retention *px_retention_new(const struct px_observer *o,int fd,uint64_t deadline,struct px_retention_error *e){
 const struct px_retention_test_operations ops={NULL,native_owner,native_uid,native_clock,native_flags,native_stat,native_open,native_write,native_sync,native_close};
 return create(o,fd,deadline,&ops,e);
}
#ifdef PXRET_TESTING
struct px_retention *px_retention_model_new(const struct px_observer *o,int fd,uint64_t deadline,
 const struct px_retention_test_operations *ops,struct px_retention_error *e){return create(o,fd,deadline,ops,e);}
#endif
