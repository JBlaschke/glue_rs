#define _POSIX_C_SOURCE 200809L
#define _DEFAULT_SOURCE 1
#define _DARWIN_C_SOURCE 1
#include "bootstrap_signals.h"
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>
#define CHECK(x) do { if(!(x)) { fprintf(stderr,"line %d: %s\n",__LINE__,#x); return 1; } } while(0)
struct fake {
 pid_t pid,ppid; struct sigaction a[BS_SIGNAL_LIMIT]; sigset_t mask,pending; stack_t stack;
 int calls,action_signal,action_setting,mask_failure,pending_failure,stack_failure,mask_sets;
};
static pid_t fp(void *p) { struct fake *f=p;f->calls++;return f->pid; }
static pid_t fpp(void *p) { struct fake *f=p;f->calls++;return f->ppid; }
static int fa(void *p,int n,const struct sigaction *in,struct sigaction *out,int *e) {
 struct fake *f=p;f->calls++;
 if(f->action_signal==n && f->action_setting==(in!=NULL)) { *e=EIO;return -1; }
 if(out)*out=f->a[n];
 if(in)f->a[n]=*in;
 return 0;
}
static int fm(void *p,int how,const sigset_t *in,sigset_t *out,int *e) {
 struct fake *f=p;f->calls++;
 if(how!=SIG_SETMASK) { *e=EINVAL;return -1; }
 if(in)f->mask_sets++;
 if(in && f->mask_failure) { *e=ENOSYS;return -1; }
 if(out)*out=f->mask;
 if(in)f->mask=*in;
 return 0;
}
static int fpend(void *p,sigset_t *out,int *e) {
 struct fake *f=p;f->calls++;if(f->pending_failure) { *e=EACCES;return -1; }*out=f->pending;return 0;
}
static int fs(void *p,const stack_t *in,stack_t *out,int *e) {
 struct fake *f=p;f->calls++;if(f->stack_failure) { *e=ENOMEM;return -1; }
 if(out)*out=f->stack;
 if(in)f->stack=*in;
 return 0;
}
static void handler(int n) { (void)n; }
static void setup(struct fake *f,struct bs_operations *o) {
 memset(f,0,sizeof(*f));f->pid=500;f->ppid=499;
 sigemptyset(&f->mask);sigemptyset(&f->pending);f->stack.ss_flags=SS_DISABLE;
 for(int n=0;n<BS_SIGNAL_LIMIT;n++) { f->a[n].sa_handler=SIG_DFL;sigemptyset(&f->a[n].sa_mask); }
 *o=*bs_native_operations();o->supported=1;o->last_signal=31;o->context=f;
 o->getpid_fn=fp;o->getppid_fn=fpp;o->action_fn=fa;o->mask_fn=fm;o->pending_fn=fpend;o->altstack_fn=fs;
}
static int empty(const sigset_t *m,int last) { for(int n=1;n<=last;n++) if(sigismember(m,n)!=0)return 0;return 1; }
static int arguments(void) {
 struct fake f;struct bs_operations o;struct bs_state s;struct bs_error e;setup(&f,&o);
 CHECK(bs_prepare_parent(NULL,&s,&e)==-1 && e.stage==BS_ARGUMENT && f.calls==0);
 o.pending_fn=NULL;CHECK(bs_prepare_parent(&o,&s,&e)==-1 && e.stage==BS_OPERATIONS && f.calls==0);
 setup(&f,&o);o.supported=0;CHECK(bs_prepare_parent(&o,&s,&e)==-1 && e.reason==BS_UNSUPPORTED && f.calls==0);
 setup(&f,&o);o.last_signal=BS_SIGNAL_LIMIT;CHECK(bs_prepare_parent(&o,&s,&e)==-1 && f.calls==0);
 setup(&f,&o);CHECK(bs_prepare_parent(&o,&s,NULL)==-1 && f.calls==0);return 0;
}
static int unsafe_actions(void) {
 struct fake f;struct bs_operations o;struct bs_state s;struct bs_error e;
 setup(&f,&o);f.a[SIGUSR1].sa_handler=handler;
 CHECK(bs_prepare_parent(&o,&s,&e)==-1 && e.reason==BS_CUSTOM_HANDLER && !s.mask_attempted);
 setup(&f,&o);f.a[SIGCHLD].sa_handler=SIG_IGN;
 CHECK(bs_prepare_parent(&o,&s,&e)==-1 && e.reason==BS_CHILD_POLICY && !s.mask_attempted);
 setup(&f,&o);f.a[SIGCHLD].sa_flags=SA_NOCLDWAIT;
 CHECK(bs_prepare_parent(&o,&s,&e)==-1 && e.reason==BS_CHILD_POLICY && !s.mask_attempted);return 0;
}
static int parent_roundtrip(void) {
 struct fake f;struct bs_operations o;struct bs_state s;struct bs_error e;setup(&f,&o);
 sigaddset(&f.mask,SIGUSR2);f.a[SIGPIPE].sa_flags=SA_RESTART;
 CHECK(bs_prepare_parent(&o,&s,&e)==0 && s.prepared && f.a[SIGPIPE].sa_handler==SIG_IGN);
 for(int n=1;n<=31;n++) CHECK(sigismember(&f.mask,n)==(n!=SIGKILL && n!=SIGSTOP));
 CHECK(bs_restore_parent(&s,&e)==0 && s.pipe_restored && s.mask_restored);
 CHECK(f.a[SIGPIPE].sa_handler==SIG_DFL && f.a[SIGPIPE].sa_flags==SA_RESTART);
 CHECK(sigismember(&f.mask,SIGUSR2)==1 && sigismember(&f.mask,SIGUSR1)==0);
 int old=f.calls;CHECK(bs_restore_parent(&s,&e)==-1 && e.reason==BS_BAD_STATE && f.calls==old+1);return 0;
}
static int prepare_failures(void) {
 struct fake f;struct bs_operations o;struct bs_state s;struct bs_error e;
 setup(&f,&o);f.mask_failure=1;CHECK(bs_prepare_parent(&o,&s,&e)==-1 && e.stage==BS_BLOCK && e.system_errno==ENOSYS);
 CHECK(s.mask_attempted && !s.pipe_attempted);f.mask_failure=0;CHECK(bs_restore_parent(&s,&e)==0 && empty(&f.mask,31));
 setup(&f,&o);sigaddset(&f.pending,SIGPIPE);CHECK(bs_prepare_parent(&o,&s,&e)==-1 && e.reason==BS_PENDING_SIGNAL);
 CHECK(!s.pipe_attempted && f.a[SIGPIPE].sa_handler==SIG_DFL);CHECK(bs_restore_parent(&s,&e)==0);
 setup(&f,&o);f.action_signal=SIGPIPE;f.action_setting=1;
 CHECK(bs_prepare_parent(&o,&s,&e)==-1 && e.stage==BS_PIPE && e.system_errno==EIO && s.pipe_attempted);
 f.action_signal=0;CHECK(bs_restore_parent(&s,&e)==0 && empty(&f.mask,31));return 0;
}
static int child_success(void) {
 struct fake f;struct bs_operations o;struct bs_state s;struct bs_error e;setup(&f,&o);
 f.a[SIGUSR1].sa_handler=SIG_IGN;CHECK(bs_prepare_parent(&o,&s,&e)==0);
 f.pid=501;f.ppid=500;CHECK(bs_reset_in_owned_child(&s,&e)==0 && s.child_reset);
 CHECK(f.a[SIGPIPE].sa_handler==SIG_DFL && f.a[SIGUSR1].sa_handler==SIG_DFL);
 CHECK(bs_check_in_owned_child(&s,&e)==0 && bs_release_in_owned_child(&s,&e)==0 && empty(&f.mask,31));
 CHECK(bs_release_in_owned_child(&s,&e)==-1 && e.reason==BS_BAD_STATE);return 0;
}
static int ownership(void) {
 struct fake f;struct bs_operations o;struct bs_state s;struct bs_error e;setup(&f,&o);
 CHECK(bs_prepare_parent(&o,&s,&e)==0);int old=f.calls;
 CHECK(bs_reset_in_owned_child(&s,&e)==-1 && e.reason==BS_NOT_OWNED && f.calls==old+2);
 f.pid=501;f.ppid=499;CHECK(bs_reset_in_owned_child(&s,&e)==-1 && e.reason==BS_NOT_OWNED);
 f.ppid=500;CHECK(bs_restore_parent(&s,&e)==-1 && e.reason==BS_NOT_OWNED);return 0;
}
static int child_failures(void) {
 struct fake f;struct bs_operations o;struct bs_state s;struct bs_error e;setup(&f,&o);
 CHECK(bs_prepare_parent(&o,&s,&e)==0);f.pid=501;f.ppid=500;f.action_signal=SIGPIPE;f.action_setting=1;
 CHECK(bs_reset_in_owned_child(&s,&e)==-1 && e.stage==BS_CHILD_RESET && e.system_errno==EIO && s.reset_attempted && !s.child_reset);
 CHECK(bs_release_in_owned_child(&s,&e)==-1 && e.reason==BS_BAD_STATE);
 setup(&f,&o);CHECK(bs_prepare_parent(&o,&s,&e)==0);f.pid=501;f.ppid=500;f.stack_failure=1;
 CHECK(bs_reset_in_owned_child(&s,&e)==-1 && e.stage==BS_ALTSTACK && e.system_errno==ENOMEM);return 0;
}
static int release_failures(void) {
 struct fake f;struct bs_operations o;struct bs_state s;struct bs_error e;setup(&f,&o);
 CHECK(bs_prepare_parent(&o,&s,&e)==0);f.pid=501;f.ppid=500;CHECK(bs_reset_in_owned_child(&s,&e)==0);
 sigaddset(&f.pending,SIGUSR1);CHECK(bs_release_in_owned_child(&s,&e)==-1 && e.reason==BS_PENDING_SIGNAL);
 CHECK(sigismember(&f.mask,SIGUSR1)==1 && s.release_attempted);
 setup(&f,&o);CHECK(bs_prepare_parent(&o,&s,&e)==0);f.pid=501;f.ppid=500;CHECK(bs_reset_in_owned_child(&s,&e)==0);
 f.a[SIGUSR1].sa_handler=SIG_IGN;CHECK(bs_check_in_owned_child(&s,&e)==-1 && e.stage==BS_CHILD_VERIFY);
 CHECK(bs_release_in_owned_child(&s,&e)==-1 && e.stage==BS_CHILD_VERIFY && sigismember(&f.mask,SIGUSR1)==1);return 0;
}
static int restore_failures(void) {
 struct fake f;struct bs_operations o;struct bs_state s;struct bs_error e;setup(&f,&o);
 CHECK(bs_prepare_parent(&o,&s,&e)==0);int old=f.mask_sets;
 f.action_signal=SIGPIPE;f.action_setting=1;f.mask_failure=1;
 CHECK(bs_restore_parent(&s,&e)==-1 && e.stage==BS_RESTORE_PIPE && e.system_errno==EIO);
 CHECK(!s.pipe_restored && !s.mask_restored && f.mask_sets==old+1);return 0;
}
static int policy(void) {
 struct fake f;struct bs_operations o;struct bs_state s;struct bs_error e;setup(&f,&o);
 CHECK(bs_prepare_parent(&o,&s,&e)==0);
 struct { unsigned char before,out[BS_POLICY_CAPACITY],after; } b;memset(&b,0xa5,sizeof(b));size_t used=99;
 CHECK(bs_policy_bytes(&s,b.out,&used,&e)==0 && used==136 && memcmp(b.out,"GLUESP01",8)==0);
 CHECK(b.out[8]==0 && b.out[9]==1 && b.out[10]==0 && b.out[11]==29 && b.out[15]==136 && b.out[19]==15);
 unsigned k=0;for(int n=1;n<=31;n++) if(n!=SIGKILL && n!=SIGSTOP) { CHECK(b.out[20+4*k]==0 && b.out[23+4*k]==n);k++; }
 CHECK(b.before==0xa5 && b.after==0xa5);s.tag=0;
 CHECK(bs_policy_bytes(&s,b.out,&used,&e)==-1 && used==0);
 for(size_t i=0;i<sizeof(b.out);i++) { CHECK(b.out[i]==0); }
 return 0;
}
#ifdef __APPLE__
static double now(void) { struct timespec t;if(clock_gettime(CLOCK_MONOTONIC,&t))return -1;return (double)t.tv_sec+(double)t.tv_nsec/1e9; }
static int await_child(pid_t p) {
 double end=now()+2;int status=0;
 for(;;) {
  pid_t r=waitpid(p,&status,WNOHANG);if(r==p)return WIFEXITED(status)&&WEXITSTATUS(status)==0?0:-1;
  if(r==-1 && errno!=EINTR)return -1;
  double t=now();if(t<0 || t>=end)break;
  struct timespec pause={0,2000000};nanosleep(&pause,NULL);
 }
 if(kill(p,SIGKILL)==-1 && errno!=ESRCH)return -1;
 end=now()+2;
 for(;;) {
  pid_t r=waitpid(p,&status,WNOHANG);if(r==p)return -1;
  if(r==-1 && errno!=EINTR)return -1;
  double t=now();if(t<0 || t>=end)return -1;
  struct timespec pause={0,2000000};nanosleep(&pause,NULL);
 }
}
static int native_case(int pending_case,int ignored) {
 struct sigaction old,ignore;memset(&ignore,0,sizeof(ignore));ignore.sa_handler=SIG_IGN;sigemptyset(&ignore.sa_mask);
 if(ignored)CHECK(sigaction(SIGUSR1,&ignore,&old)==0);
 struct bs_state s;struct bs_error e;CHECK(bs_prepare_parent(bs_native_operations(),&s,&e)==0);
 pid_t p=fork();
 if(p==0) {
  if(bs_reset_in_owned_child(&s,&e) || bs_check_in_owned_child(&s,&e)) {
   dprintf(STDERR_FILENO,"child setup: stage=%d reason=%d errno=%d signal=%d\n",e.stage,e.reason,e.system_errno,e.signal_number);
   _exit(10);
  }
  if(pending_case) {
   if(raise(SIGUSR1) || bs_release_in_owned_child(&s,&e)!=-1 || e.reason!=BS_PENDING_SIGNAL)_exit(11);
   _exit(0);
  }
  if(bs_release_in_owned_child(&s,&e)) {
   dprintf(STDERR_FILENO,"child release: stage=%d reason=%d errno=%d signal=%d\n",e.stage,e.reason,e.system_errno,e.signal_number);
   _exit(12);
  }
  _exit(0);
 }
 int rc=p>0?await_child(p):-1;
 int restored=bs_restore_parent(&s,&e);CHECK(restored==0 && s.pipe_restored && s.mask_restored);
 if(ignored) { struct sigaction got;CHECK(sigaction(SIGUSR1,NULL,&got)==0 && got.sa_handler==SIG_IGN);CHECK(sigaction(SIGUSR1,&old,NULL)==0); }
 CHECK(rc==0);return 0;
}
static int native_unsafe(void) {
 struct sigaction old,ignore;memset(&ignore,0,sizeof(ignore));ignore.sa_handler=SIG_IGN;sigemptyset(&ignore.sa_mask);
 CHECK(sigaction(SIGCHLD,&ignore,&old)==0);struct bs_state s;struct bs_error e;
 int rc=bs_prepare_parent(bs_native_operations(),&s,&e);CHECK(sigaction(SIGCHLD,&old,NULL)==0);
 CHECK(rc==-1 && e.reason==BS_CHILD_POLICY && !s.mask_attempted);return 0;
}
#endif
int main(int argc,char **argv) {
 if(argc!=2)return 2;
 int rc=1;const char *n=argv[1];
 if(!strcmp(n,"arguments"))rc=arguments();else if(!strcmp(n,"unsafe-actions"))rc=unsafe_actions();
 else if(!strcmp(n,"parent-roundtrip"))rc=parent_roundtrip();else if(!strcmp(n,"prepare-failures"))rc=prepare_failures();
 else if(!strcmp(n,"child-success"))rc=child_success();else if(!strcmp(n,"ownership"))rc=ownership();
 else if(!strcmp(n,"child-failures"))rc=child_failures();else if(!strcmp(n,"release-failures"))rc=release_failures();
 else if(!strcmp(n,"restore-failures"))rc=restore_failures();else if(!strcmp(n,"policy"))rc=policy();
 else if(!strcmp(n,"native-unsupported")) { struct bs_state s;struct bs_error e;rc=bs_prepare_parent(bs_native_operations(),&s,&e)==-1 && e.reason==BS_UNSUPPORTED?0:1; }
#ifdef __APPLE__
 else if(!strcmp(n,"native-roundtrip"))rc=native_case(0,0);else if(!strcmp(n,"native-pending"))rc=native_case(1,0);
 else if(!strcmp(n,"native-inherited-ignore"))rc=native_case(0,1);else if(!strcmp(n,"native-unsafe-chld"))rc=native_unsafe();
#endif
 if(rc==0)printf("PASS %s\n",n);
 return rc;
}
