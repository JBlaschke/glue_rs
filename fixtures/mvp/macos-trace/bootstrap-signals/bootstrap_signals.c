#define _POSIX_C_SOURCE 200809L
#define _DEFAULT_SOURCE 1
#define _DARWIN_C_SOURCE 1
#include "bootstrap_signals.h"
#include <errno.h>
#include <string.h>
#include <unistd.h>
#define BS_TAG UINT32_C(0x42535031)
static int fail(struct bs_error *e, enum bs_stage st, enum bs_reason why, int n, int sig) {
 if(e) { e->stage=st; e->reason=why; e->system_errno=n; e->signal_number=sig; } return -1;
}
static void clear(struct bs_error *e) { if(e) memset(e,0,sizeof(*e)); }
static int catchable(int n) { return n!=SIGKILL && n!=SIGSTOP; }
static int valid(const struct bs_operations *o) {
 return o && o->supported==1 && o->last_signal>=SIGPIPE && o->last_signal>=SIGCHLD &&
 o->last_signal>=SIGKILL && o->last_signal>=SIGSTOP && o->last_signal<BS_SIGNAL_LIMIT &&
 o->getpid_fn && o->getppid_fn && o->action_fn && o->mask_fn && o->pending_fn && o->altstack_fn;
}
static int outcome(int rc,int saved,struct bs_error *e,enum bs_stage st,int sig) {
 if(rc==0) return 0;
 return fail(e,st,(rc==-1 && saved>0)?BS_SYSCALL:BS_ADAPTER,(rc==-1 && saved>0)?saved:0,sig);
}
static int action(struct bs_state *s,int n,const struct sigaction *in,struct sigaction *out,
 struct bs_error *e,enum bs_stage st) {
 int saved=0,rc=s->operations.action_fn(s->operations.context,n,in,out,&saved);
 return outcome(rc,saved,e,st,n);
}
static int mask(struct bs_state *s,const sigset_t *in,sigset_t *out,struct bs_error *e,enum bs_stage st) {
 int saved=0,rc=s->operations.mask_fn(s->operations.context,SIG_SETMASK,in,out,&saved);
 return outcome(rc,saved,e,st,0);
}
static int members(const struct bs_state *s,const sigset_t *m,int blocked,struct bs_error *e,enum bs_stage st) {
 for(int n=1;n<=s->operations.last_signal;n++) {
  int got=sigismember(m,n),want=blocked && catchable(n);
  if(got<0 || got!=want) return fail(e,st,BS_MISMATCH,0,n);
 } return 0;
}
static int pending(struct bs_state *s,struct bs_error *e) {
 sigset_t p; if(sigemptyset(&p)) return fail(e,BS_PENDING,BS_ADAPTER,0,0);
 int saved=0,rc=s->operations.pending_fn(s->operations.context,&p,&saved);
 if(outcome(rc,saved,e,BS_PENDING,0)) return -1;
 for(int n=1;n<=s->operations.last_signal;n++) {
  int got=sigismember(&p,n);
  if(got<0) return fail(e,BS_PENDING,BS_ADAPTER,0,n);
  if(got) return fail(e,BS_PENDING,BS_PENDING_SIGNAL,0,n);
 } return 0;
}
static int blocked(struct bs_state *s,struct bs_error *e,enum bs_stage st) {
 sigset_t m; if(sigemptyset(&m)) return fail(e,st,BS_ADAPTER,0,0);
 if(mask(s,NULL,&m,e,st)) return -1;
 return members(s,&m,1,e,st);
}
static int child(struct bs_state *s,struct bs_error *e) {
 if(!s || s->tag!=BS_TAG || !valid(&s->operations) || !s->prepared || s->restore_attempted)
  return fail(e,BS_OWNER,BS_BAD_STATE,0,0);
 pid_t pid=s->operations.getpid_fn(s->operations.context),ppid=s->operations.getppid_fn(s->operations.context);
 if(pid<=0 || pid==s->owner || ppid!=s->owner) return fail(e,BS_OWNER,BS_NOT_OWNED,0,0);
 return 0;
}
static int default_actions(struct bs_state *s,struct bs_error *e) {
 for(int n=1;n<=s->operations.last_signal;n++) if(catchable(n)) {
  struct sigaction a; memset(&a,0,sizeof(a));
  if(action(s,n,NULL,&a,e,BS_CHILD_VERIFY)) return -1;
  if(a.sa_handler!=SIG_DFL || ((unsigned)a.sa_flags&s->operations.public_action_flags))
   return fail(e,BS_CHILD_VERIFY,BS_MISMATCH,0,n);
  if(members(s,&a.sa_mask,0,e,BS_CHILD_VERIFY)) return -1;
 }
 stack_t a; memset(&a,0,sizeof(a)); int saved=0;
 int rc=s->operations.altstack_fn(s->operations.context,NULL,&a,&saved);
 if(outcome(rc,saved,e,BS_ALTSTACK,0)) return -1;
 if(!(a.ss_flags&SS_DISABLE) || (a.ss_flags&SS_ONSTACK)) return fail(e,BS_ALTSTACK,BS_MISMATCH,0,0);
 return blocked(s,e,BS_CHILD_VERIFY);
}
int bs_prepare_parent(const struct bs_operations *o,struct bs_state *s,struct bs_error *e) {
 clear(e); if(s) memset(s,0,sizeof(*s));
 if(!e || !s || !o) return fail(e,BS_ARGUMENT,BS_INVALID,0,0);
 if(o->supported==0) return fail(e,BS_OPERATIONS,BS_UNSUPPORTED,0,0);
 if(!valid(o)) return fail(e,BS_OPERATIONS,BS_INVALID,0,0);
 s->tag=BS_TAG; s->operations=*o; s->owner=o->getpid_fn(o->context);
 if(s->owner<=0) return fail(e,BS_OWNER,BS_NOT_OWNED,0,0);
 if(mask(s,NULL,&s->original_mask,e,BS_ACTIONS)) return -1;
 for(int n=1;n<=o->last_signal;n++) if(catchable(n)) {
  struct sigaction a; memset(&a,0,sizeof(a));
  if(action(s,n,NULL,&a,e,BS_ACTIONS)) return -1;
  if(a.sa_handler!=SIG_DFL && a.sa_handler!=SIG_IGN) return fail(e,BS_ACTIONS,BS_CUSTOM_HANDLER,0,n);
  if(n==SIGCHLD && (a.sa_handler!=SIG_DFL || (a.sa_flags&SA_NOCLDWAIT)))
   return fail(e,BS_ACTIONS,BS_CHILD_POLICY,0,n);
  if(n==SIGPIPE) s->original_pipe=a;
 }
 sigset_t all; if(sigemptyset(&all)) return fail(e,BS_BLOCK,BS_ADAPTER,0,0);
 for(int n=1;n<=o->last_signal;n++) if(catchable(n) && sigaddset(&all,n)) return fail(e,BS_BLOCK,BS_ADAPTER,0,n);
 s->mask_attempted=1;
 if(mask(s,&all,NULL,e,BS_BLOCK) || blocked(s,e,BS_BLOCK) || pending(s,e)) return -1;
 struct sigaction ignore; memset(&ignore,0,sizeof(ignore)); ignore.sa_handler=SIG_IGN;
 if(sigemptyset(&ignore.sa_mask)) return fail(e,BS_PIPE,BS_ADAPTER,0,0);
 s->pipe_attempted=1;
 if(action(s,SIGPIPE,&ignore,NULL,e,BS_PIPE)) return -1;
 struct sigaction got; memset(&got,0,sizeof(got));
 if(action(s,SIGPIPE,NULL,&got,e,BS_PIPE)) return -1;
 if(got.sa_handler!=SIG_IGN || ((unsigned)got.sa_flags&o->public_action_flags) ||
 members(s,&got.sa_mask,0,e,BS_PIPE)) return fail(e,BS_PIPE,BS_MISMATCH,0,SIGPIPE);
 s->prepared=1; return 0;
}
int bs_reset_in_owned_child(struct bs_state *s,struct bs_error *e) {
 clear(e); if(!e || child(s,e)) return -1;
 if(s->reset_attempted || s->release_attempted) return fail(e,BS_CHILD_RESET,BS_BAD_STATE,0,0);
 s->reset_attempted=1; if(blocked(s,e,BS_CHILD_RESET)) return -1;
 struct sigaction d; memset(&d,0,sizeof(d)); d.sa_handler=SIG_DFL;
 if(sigemptyset(&d.sa_mask)) return fail(e,BS_CHILD_RESET,BS_ADAPTER,0,0);
 for(int n=1;n<=s->operations.last_signal;n++) if(catchable(n) && action(s,n,&d,NULL,e,BS_CHILD_RESET)) return -1;
 stack_t a; memset(&a,0,sizeof(a)); int saved=0;
 int rc=s->operations.altstack_fn(s->operations.context,NULL,&a,&saved);
 if(outcome(rc,saved,e,BS_ALTSTACK,0)) return -1;
 if(a.ss_flags&SS_ONSTACK) return fail(e,BS_ALTSTACK,BS_MISMATCH,0,0);
 memset(&a,0,sizeof(a)); a.ss_flags=SS_DISABLE;
 /* Darwin's UNIX2003 libc wrapper checks size even when disabling. No stack
  * storage is installed; SS_DISABLE makes the kernel ignore this size. */
 a.ss_size=SIGSTKSZ; saved=0;
 rc=s->operations.altstack_fn(s->operations.context,&a,NULL,&saved);
 if(outcome(rc,saved,e,BS_ALTSTACK,0) || default_actions(s,e)) return -1;
 s->child_reset=1; return 0;
}
int bs_check_in_owned_child(struct bs_state *s,struct bs_error *e) {
 clear(e); if(!e || child(s,e)) return -1;
 if(!s->child_reset || s->release_attempted) return fail(e,BS_CHILD_VERIFY,BS_BAD_STATE,0,0);
 return default_actions(s,e);
}
int bs_release_in_owned_child(struct bs_state *s,struct bs_error *e) {
 clear(e); if(!e || child(s,e)) return -1;
 if(!s->child_reset || s->release_attempted) return fail(e,BS_RELEASE,BS_BAD_STATE,0,0);
 s->release_attempted=1;
 if(default_actions(s,e) || pending(s,e)) return -1;
 sigset_t empty,got;
 if(sigemptyset(&empty) || sigemptyset(&got)) return fail(e,BS_RELEASE,BS_ADAPTER,0,0);
 if(mask(s,&empty,NULL,e,BS_RELEASE) || mask(s,NULL,&got,e,BS_RELEASE)) return -1;
 return members(s,&got,0,e,BS_RELEASE);
}
static int same_mask(const struct bs_state *s,const sigset_t *a,const sigset_t *b) {
 for(int n=1;n<=s->operations.last_signal;n++) {
  int x=sigismember(a,n),y=sigismember(b,n); if(x<0 || y<0 || x!=y) return 0;
 } return 1;
}
int bs_restore_parent(struct bs_state *s,struct bs_error *e) {
 clear(e);
 if(!e || !s || s->tag!=BS_TAG || !valid(&s->operations)) return fail(e,BS_RESTORE_MASK,BS_BAD_STATE,0,0);
 if(s->operations.getpid_fn(s->operations.context)!=s->owner) return fail(e,BS_OWNER,BS_NOT_OWNED,0,0);
 if(s->restore_attempted) return fail(e,BS_RESTORE_MASK,BS_BAD_STATE,0,0);
 s->restore_attempted=1;
 struct bs_error first; memset(&first,0,sizeof(first));
 s->pipe_restored=!s->pipe_attempted; s->mask_restored=!s->mask_attempted;
 if(s->pipe_attempted) {
  struct sigaction got; memset(&got,0,sizeof(got));
  if(action(s,SIGPIPE,&s->original_pipe,NULL,e,BS_RESTORE_PIPE) ||
     action(s,SIGPIPE,NULL,&got,e,BS_RESTORE_PIPE)) first=*e;
  else if(got.sa_handler!=s->original_pipe.sa_handler ||
    (((unsigned)got.sa_flags^(unsigned)s->original_pipe.sa_flags)&s->operations.public_action_flags) ||
    !same_mask(s,&got.sa_mask,&s->original_pipe.sa_mask)) {
   fail(e,BS_RESTORE_PIPE,BS_MISMATCH,0,SIGPIPE); first=*e;
  } else s->pipe_restored=1;
 }
 if(s->mask_attempted) {
  struct bs_error later; memset(&later,0,sizeof(later)); sigset_t got;
  if(sigemptyset(&got)) fail(&later,BS_RESTORE_MASK,BS_ADAPTER,0,0);
  else if(mask(s,&s->original_mask,NULL,&later,BS_RESTORE_MASK) || mask(s,NULL,&got,&later,BS_RESTORE_MASK)) { }
  else if(!same_mask(s,&got,&s->original_mask)) fail(&later,BS_RESTORE_MASK,BS_MISMATCH,0,0);
  else s->mask_restored=1;
  if(first.reason==BS_OK && later.reason!=BS_OK) first=later;
 }
 *e=first; return first.reason==BS_OK?0:-1;
}
static void put16(unsigned char *p,unsigned v) { p[0]=(unsigned char)(v>>8);p[1]=(unsigned char)v; }
static void put32(unsigned char *p,unsigned v) { p[0]=(unsigned char)(v>>24);p[1]=(unsigned char)(v>>16);p[2]=(unsigned char)(v>>8);p[3]=(unsigned char)v; }
int bs_policy_bytes(const struct bs_state *s,unsigned char out[BS_POLICY_CAPACITY],size_t *used,struct bs_error *e) {
 clear(e); if(out) memset(out,0,BS_POLICY_CAPACITY); if(used) *used=0;
 if(!e || !s || !out || !used || s->tag!=BS_TAG || !valid(&s->operations) || !s->prepared)
  return fail(e,BS_POLICY,BS_INVALID,0,0);
 unsigned count=0;for(int n=1;n<=s->operations.last_signal;n++) if(catchable(n)) put32(out+20+4*count++,(unsigned)n);
 memcpy(out,"GLUESP01",8);put16(out+8,1);put16(out+10,count);put32(out+12,20+4*count);put32(out+16,15);
 *used=20+4*count;return 0;
}
static pid_t npid(void *p) { (void)p;return getpid(); }
static pid_t nppid(void *p) { (void)p;return getppid(); }
static int naction(void *p,int n,const struct sigaction *a,struct sigaction *b,int *e) { (void)p;int r=sigaction(n,a,b);if(r==-1)*e=errno;return r; }
static int nmask(void *p,int how,const sigset_t *a,sigset_t *b,int *e) { (void)p;int r=sigprocmask(how,a,b);if(r==-1)*e=errno;return r; }
static int npending(void *p,sigset_t *a,int *e) { (void)p;int r=sigpending(a);if(r==-1)*e=errno;return r; }
static int nstack(void *p,const stack_t *a,stack_t *b,int *e) { (void)p;int r=sigaltstack(a,b);if(r==-1)*e=errno;return r; }
const struct bs_operations *bs_native_operations(void) {
 static const struct bs_operations o={
#ifdef __APPLE__
  1,NSIG-1,
#else
  0,NSIG-1,
#endif
  SA_NOCLDSTOP|SA_NOCLDWAIT|SA_NODEFER|SA_ONSTACK|SA_RESETHAND|SA_RESTART|SA_SIGINFO,
  NULL,npid,nppid,naction,nmask,npending,nstack};return &o;
}
