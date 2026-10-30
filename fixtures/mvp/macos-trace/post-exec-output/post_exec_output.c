#ifndef _DARWIN_C_SOURCE
#define _DARWIN_C_SOURCE 1
#endif
#ifndef _POSIX_C_SOURCE
#define _POSIX_C_SOURCE 200809L
#endif
#include "post_exec_output.h"
#ifdef PX_TESTING
#include "post_exec_output_test.h"
#endif
#include <errno.h>
#include <limits.h>
#include <signal.h>
#include <stddef.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>
#ifdef __APPLE__
#include <CommonCrypto/CommonDigest.h>
#include <libproc.h>
#include <sys/proc_info.h>
_Static_assert(sizeof(void *)==8 && sizeof(long)==8 && sizeof(int)==4 && sizeof(pid_t)==4,"Darwin LP64");
#if __BYTE_ORDER__ != __ORDER_LITTLE_ENDIAN__
#error fixed native observer requires little-endian Darwin LP64
#endif
#define FIELD(member,offset,width) \
 _Static_assert(offsetof(struct vnode_fdinfo,member)==(offset),"vnode offset " #member); \
 _Static_assert(sizeof(((struct vnode_fdinfo *)0)->member)==(width),"vnode width " #member)
_Static_assert(sizeof(struct vnode_fdinfo)==176,"vnode_fdinfo bytes");
FIELD(pfi.fi_openflags,0,4); FIELD(pfi.fi_status,4,4); FIELD(pfi.fi_offset,8,8);
FIELD(pfi.fi_type,16,4); FIELD(pfi.fi_guardflags,20,4);
FIELD(pvi.vi_stat.vst_dev,24,4); FIELD(pvi.vi_stat.vst_mode,28,2);
FIELD(pvi.vi_stat.vst_nlink,30,2); FIELD(pvi.vi_stat.vst_ino,32,8);
FIELD(pvi.vi_stat.vst_uid,40,4); FIELD(pvi.vi_stat.vst_gid,44,4);
FIELD(pvi.vi_stat.vst_atime,48,8); FIELD(pvi.vi_stat.vst_atimensec,56,8);
FIELD(pvi.vi_stat.vst_mtime,64,8); FIELD(pvi.vi_stat.vst_mtimensec,72,8);
FIELD(pvi.vi_stat.vst_ctime,80,8); FIELD(pvi.vi_stat.vst_ctimensec,88,8);
FIELD(pvi.vi_stat.vst_birthtime,96,8); FIELD(pvi.vi_stat.vst_birthtimensec,104,8);
FIELD(pvi.vi_stat.vst_size,112,8); FIELD(pvi.vi_stat.vst_blocks,120,8);
FIELD(pvi.vi_stat.vst_blksize,128,4); FIELD(pvi.vi_stat.vst_flags,132,4);
FIELD(pvi.vi_stat.vst_gen,136,4); FIELD(pvi.vi_stat.vst_rdev,140,4);
FIELD(pvi.vi_stat.vst_qspare,144,16); FIELD(pvi.vi_type,160,4);
FIELD(pvi.vi_pad,164,4); FIELD(pvi.vi_fsid,168,8);
_Static_assert(sizeof(((struct vnode_fdinfo *)0)->pvi.vi_stat.vst_qspare[0])==8,"qspare element");
_Static_assert(sizeof(((struct vnode_fdinfo *)0)->pvi.vi_fsid.val[0])==4,"fsid element");
_Static_assert(PROC_PIDFDVNODEINFO==1 && PROC_FP_SHARED==1 && PROC_FP_CLEXEC==2 &&
 PROC_FP_GUARDED==4 && PROC_FP_CLFORK==8,"native proc constants");
_Static_assert(SIGSTOP==17,"fixed Darwin SIGSTOP");
#undef FIELD
#endif
/* Pinned f621 bsd/sys/fcntl.h: FMASK and FWASWRITTEN. */
#define PX_FMASK UINT32_C(0x404000cf)
#define PX_WRITTEN UINT32_C(0x00010000)
struct px_ops {
 void *context; pid_t (*getpid_fn)(void *); int (*policy_fn)(void *,int *);
 int (*clock_fn)(void *,uint64_t *,int *);
 pid_t (*wait_fn)(void *,pid_t,int *,int,int *);
 int (*query_fn)(void *,pid_t,int,uint8_t [176],int *);
};
struct px_query {
 uint32_t pid; int fd; uint64_t before,after,address; int result,saved;
 uint16_t flags; uint8_t role,round; uint8_t fields[176];
};
struct px_wait { uint64_t before,after; int pid,status,saved; uint32_t flags; };
struct px_observer {
 struct px_plan plan; struct px_ops ops; uint32_t owner,flags;
 enum px_state state; enum px_reason reason; int saved;
 unsigned queries,waits,accepted,errors; uint64_t last;
 struct px_query query[8]; struct px_wait wait[64]; uint8_t native[8][176];
};
static void put(uint8_t *p,uint64_t v,unsigned n){for(unsigned i=0;i<n;i++)p[i]=(uint8_t)(v>>(8*(n-1-i)));}
static uint64_t get(const uint8_t *p,unsigned n){uint64_t v=0;for(unsigned i=0;i<n;i++)v=(v<<8)|p[i];return v;}
static int error(struct px_error *e,enum px_reason r,int n){if(e)*e=(struct px_error){r,n>0?n:0};return -1;}
static int refuse(struct px_observer *s,enum px_reason r,int n,struct px_error *e){
 if(s->reason==PX_OK){s->reason=r;s->saved=n>0?n:0;s->errors=1;}
 if(s->state==PX_ACTIVE)s->state=PX_REFUSED;
 return error(e,s->reason,s->saved);
}
int px_codec_native_lp64le(const uint8_t native[176],uint8_t be[176]){
 if(!be)return -1;
 uint8_t copy[176];if(!native){memset(be,0,176);return -1;}memcpy(copy,native,176);
 static const uint8_t widths[]={4,4,8,4,4,4,2,2,8,4,4,8,8,8,8,8,8,8,8,8,8,4,4,4,4,8,8,4,4,4,4};
 unsigned off=0;for(unsigned i=0;i<sizeof(widths);i++){
  unsigned n=widths[i];for(unsigned j=0;j<n;j++)be[off+j]=copy[off+n-1-j];off+=n;
 }
 return off==176?0:-1;
}
#if defined(__APPLE__) || defined(PX_TESTING)
static int zero(const uint8_t *p,size_t n){for(size_t i=0;i<n;i++)if(p[i])return 0;return 1;}
static int original_valid(const struct px_plan *p,uint32_t owner){
 const uint8_t *b=p->original;
 if(memcmp(b,"GLUERW01",8)||get(b+8,4)!=1||get(b+12,4)!=320||get(b+16,4)!=owner||
  get(b+20,4)!=p->child||get(b+24,4)!=4||!zero(b+28,4)||memcmp(b+32,p->digests[0],32)||
  memcmp(b+64,p->digests[1],32)||memcmp(b+96,p->digests[2],32)||!zero(b+128,12)||
  get(b+140,4)!=UINT32_MAX||get(b+144,4)!=UINT32_MAX||!zero(b+148,12)||memcmp(b+160,b+240,80))return 0;
 for(unsigned i=0;i<2;i++){
  const uint8_t *v=b+160+40*i;uint64_t mode=get(v+12,4);
  if(get(v,4)!=(uint32_t)p->held[i]||get(v+4,4)>INT_MAX||!(get(v+4,4)&1)||
   get(v+8,4)>INT_MAX||(get(v+8,4)&3)!=1||mode>UINT16_MAX||(mode&0170000)!=0100000||get(v+32,8)!=1)return 0;
 }
 return memcmp(b+176,b+216,16)!=0;
}
static int plan_valid(const struct px_plan *p,uint32_t owner){
 if(!p||!owner||owner>INT_MAX||!p->child||p->child>INT_MAX||p->child==owner||
  p->held[0]<3||p->held[1]<3||p->held[0]==p->held[1]||!p->sequence||!p->deadline||!p->exec_ordinal||!p->new_tid)return 0;
 for(unsigned i=0;i<5;i++)if(zero(p->digests[i],32))return 0;
 return original_valid(p,owner);
}
static int ops_valid(const struct px_ops *o){return o&&o->getpid_fn&&o->policy_fn&&o->clock_fn&&o->wait_fn&&o->query_fn;}
static struct px_observer *create(const struct px_plan *p,const struct px_ops *o,struct px_error *e){
 if(e)*e=(struct px_error){PX_OK,0};
 if(!e||!p||!ops_valid(o)){error(e,PX_ARGUMENT,0);return NULL;}
 pid_t owner=o->getpid_fn(o->context);
 if(owner<=0||!plan_valid(p,(uint32_t)owner)){error(e,PX_ARGUMENT,0);return NULL;}
 int saved=0;if(o->policy_fn(o->context,&saved)!=0){error(e,PX_POLICY,saved);return NULL;}
 struct px_observer *s=calloc(1,sizeof(*s));if(!s){error(e,PX_ARGUMENT,ENOMEM);return NULL;}
 s->plan=*p;s->ops=*o;s->owner=(uint32_t)owner;s->flags=PX_OWNED;s->state=PX_ACTIVE;return s;
}
#endif
#ifdef PX_TESTING
struct px_observer *px_observer_model_new(const struct px_plan *p,const struct px_test_operations *o,struct px_error *e){
 if(!o){error(e,PX_ARGUMENT,0);return NULL;}
 const struct px_ops copy={o->context,o->getpid_fn,o->policy_fn,o->clock_fn,o->wait_fn,o->query_fn};return create(p,&copy,e);
}
#endif
static int guard(struct px_observer *s,struct px_error *e){
 if(s->ops.getpid_fn(s->ops.context)!=(pid_t)s->owner)return refuse(s,PX_OWNER,0,e);
 int saved=0;if(s->ops.policy_fn(s->ops.context,&saved)!=0)return refuse(s,PX_POLICY,saved,e);
 return 0;
}
static int clock_read(struct px_observer *s,uint64_t *out,int *have,struct px_error *e){
 int saved=0;uint64_t now=0;*have=0;
 if(s->ops.clock_fn(s->ops.context,&now,&saved)!=0)return refuse(s,PX_CLOCK,saved,e);
 *out=now;*have=1;uint64_t previous=s->last;s->last=now;
 if(now<previous)return refuse(s,PX_CLOCK,0,e);
 if(now>=s->plan.deadline)return refuse(s,PX_DEADLINE,0,e);
 return 0;
}
static int query_shape(const uint8_t *b,int parent){
 uint32_t f=(uint32_t)get(b,4),status=(uint32_t)get(b+4,4);
 return !(f&~(PX_FMASK|PX_WRITTEN))&&(f&UINT32_C(0x40000003))==2&&
  !(status&~3u)&&!!(status&2)==parent&&get(b+16,4)==1&&get(b+20,4)==0&&
  (get(b+28,2)&0170000)==0100000&&get(b+30,2)==1&&get(b+160,4)==1;
}
static uint64_t device(const uint8_t *b){uint64_t d=get(b+24,4);return d&UINT64_C(0x80000000)?d|UINT64_C(0xffffffff00000000):d;}
static int same_backing(const uint8_t *a,const uint8_t *b){return memcmp(a+24,b+24,16)==0;}
static int match(const struct px_observer *s){
 for(unsigned i=0;i<8;i++){
  unsigned role=i&1u;const uint8_t *b=s->query[i].fields,*first=s->query[role].fields,*old=s->plan.original+160+40*role;
  int parent=i<2||i>=6;
  if(!query_shape(b,parent)||!same_backing(b,first)||(get(b,4)&PX_FMASK)!=(get(first,4)&PX_FMASK)||
   device(b)!=get(old+16,8)||get(b+32,8)!=get(old+24,8)||get(b+28,2)!=get(old+12,4)||get(b+30,2)!=get(old+32,8))return 0;
 }
 return !(get(s->query[0].fields+24,4)==get(s->query[1].fields+24,4)&&get(s->query[0].fields+32,8)==get(s->query[1].fields+32,8));
}
static int sample(struct px_observer *s,struct px_error *e){
 if(guard(s,e))return -1;
 for(unsigned i=0;i<8;i++){
  uint64_t before=0;int have=0;if(clock_read(s,&before,&have,e))return -1;
  struct px_query *q=&s->query[i];q->pid=(i<2||i>=6)?s->owner:s->plan.child;
  q->fd=(i<2||i>=6)?s->plan.held[i&1u]:(int)(1+(i&1u));
  q->before=before;q->address=(uint64_t)(uintptr_t)s->native[i];q->role=(uint8_t)(1+(i&1u));q->round=(uint8_t)(i<4?1:2);
  q->flags=PX_Q_ATTEMPTED;s->queries=i+1;
  int saved=0;q->result=s->ops.query_fn(s->ops.context,(pid_t)q->pid,q->fd,s->native[i],&saved);
  q->saved=q->result==176?0:(saved>0?saved:0);
  if(q->result==176){q->flags|=PX_Q_FULL;(void)px_codec_native_lp64le(s->native[i],q->fields);}
  else{q->flags|=PX_Q_OPAQUE;memcpy(q->fields,s->native[i],176);}
  uint64_t after=0;int timed=0,cr=clock_read(s,&after,&timed,e);q->after=after;if(timed)q->flags|=PX_Q_AFTER;
  if(cr)return -1;
  if(q->result!=176)return refuse(s,PX_QUERY,q->saved,e);
 }
 if(guard(s,e))return -1;
 uint64_t final_time=0;int final_have=0;
 if(clock_read(s,&final_time,&final_have,e))return -1;
 if(!match(s))return refuse(s,PX_MISMATCH,0,e);
 s->flags|=PX_MATCHED;s->state=PX_COMPLETE;return 1;
}
int px_observer_poll(struct px_observer *s,struct px_error *e){
 if(e)*e=(struct px_error){PX_OK,0};
 if(!s||!e)return error(e,PX_ARGUMENT,0);
 if(s->state!=PX_ACTIVE||(s->flags&PX_ATTEMPTED))return error(e,PX_ARGUMENT,0);
 if(guard(s,e))return -1;
 if(s->waits>=64)return refuse(s,PX_WAIT_LIMIT,0,e);
 uint64_t before=0;int have=0;if(clock_read(s,&before,&have,e))return -1;
 struct px_wait *w=&s->wait[s->waits++];w->before=before;w->flags=PX_W_ATTEMPTED;
 int saved=0;pid_t n=s->ops.wait_fn(s->ops.context,(pid_t)s->plan.child,&w->status,WNOHANG|WUNTRACED,&saved);
 w->pid=(int)n;w->saved=n==-1&&saved>0?saved:0;
 if(n==(pid_t)s->plan.child){
  unsigned status=(unsigned)w->status;w->flags|=PX_W_STATUS;
  if((status&0x7fu)!=0x7fu){
   s->flags=(s->flags&~PX_OWNED)|PX_REAPED;s->state=PX_REAPED_STATE;w->flags|=PX_W_TERMINAL;
  }else if(status==UINT32_C(0x117f)){
   s->flags|=PX_STOPPED|PX_ATTEMPTED;s->accepted=s->waits;w->flags|=PX_W_STOP;
  }
 }else if(n==-1&&saved==ECHILD){
  s->flags=(s->flags&~PX_OWNED)|PX_LOST;s->state=PX_LOST_STATE;w->flags|=PX_W_ECHILD;
 }
 uint64_t after=0;int timed=0,cr=clock_read(s,&after,&timed,e);w->after=after;if(timed)w->flags|=PX_W_AFTER;
 if(cr)return -1;
 if(s->state==PX_REAPED_STATE)return refuse(s,PX_TERMINAL,0,e);
 if(s->state==PX_LOST_STATE)return refuse(s,PX_OWNERSHIP_LOST,ECHILD,e);
 if(w->flags&PX_W_STOP)return sample(s,e);
 if(n==0||(n==-1&&saved==EINTR))return s->waits==64?refuse(s,PX_WAIT_LIMIT,0,e):0;
 if(n==(pid_t)s->plan.child)return refuse(s,PX_STOP_SIGNAL,0,e);
 return refuse(s,PX_WAIT,w->saved,e);
}
int px_observer_encode(const struct px_observer *s,uint8_t out[4096],struct px_error *e){
 if(out)memset(out,0,4096);
 if(e)*e=(struct px_error){PX_OK,0};
 if(!out||!s||!e)return error(e,PX_ARGUMENT,0);
 memcpy(out,"GLUEPX01",8);put(out+8,1,2);put(out+10,256,2);put(out+12,4096,4);put(out+16,s->owner,4);put(out+20,s->plan.child,4);
 put(out+24,s->plan.sequence,8);put(out+32,s->plan.deadline,8);put(out+40,s->plan.exec_ordinal,8);put(out+48,s->plan.new_tid,8);
 put(out+56,s->queries,2);put(out+58,s->waits,2);put(out+60,s->state,2);put(out+62,s->reason,2);put(out+64,(uint32_t)s->saved,4);put(out+68,s->flags,4);
 put(out+72,s->last,8);put(out+80,s->accepted,2);put(out+82,s->errors,2);memcpy(out+96,s->plan.digests,160);
 for(unsigned i=0;i<s->queries;i++){
  const struct px_query *q=&s->query[i];uint8_t *p=out+256+224*i;
  put(p,q->pid,4);put(p+4,(uint32_t)q->fd,4);put(p+8,q->before,8);put(p+16,q->after,8);put(p+24,q->address,8);
  put(p+32,(uint32_t)q->result,4);put(p+36,(uint32_t)q->saved,4);put(p+40,q->flags,2);p[42]=q->role;p[43]=q->round;memcpy(p+48,q->fields,176);
 }
 for(unsigned i=0;i<s->waits;i++){
  const struct px_wait *w=&s->wait[i];uint8_t *p=out+2048+32*i;
  put(p,w->before,8);put(p+8,w->after,8);put(p+16,(uint32_t)w->pid,4);put(p+20,(uint32_t)w->status,4);put(p+24,(uint32_t)w->saved,4);put(p+28,w->flags,4);
 }
 return 0;
}
int px_observer_owns_child(const struct px_observer *s){return s&&(s->flags&PX_OWNED)!=0;}
void px_observer_free(struct px_observer *s){if(s){memset(s,0,sizeof(*s));free(s);}}
#ifdef __APPLE__
static pid_t native_pid(void *c){(void)c;return getpid();}
static int native_policy(void *c,int *e){
 (void)c;struct sigaction a;memset(&a,0,sizeof(a));
 if(sigaction(SIGCHLD,NULL,&a)==-1){*e=errno;return -1;}
 if(a.sa_handler!=SIG_DFL||(a.sa_flags&SA_NOCLDWAIT)){*e=EINVAL;return -1;}return 0;
}
static int native_clock(void *c,uint64_t *v,int *e){
 (void)c;struct timespec t;if(clock_gettime(CLOCK_MONOTONIC,&t)){*e=errno;return -1;}
 if(t.tv_sec<0||t.tv_nsec<0||t.tv_nsec>=1000000000L||(uint64_t)t.tv_sec>(UINT64_MAX-(uint64_t)t.tv_nsec)/UINT64_C(1000000000)){*e=EOVERFLOW;return -1;}
 *v=(uint64_t)t.tv_sec*UINT64_C(1000000000)+(uint64_t)t.tv_nsec;return 0;
}
static pid_t native_wait(void *c,pid_t p,int *status,int options,int *e){(void)c;pid_t r=waitpid(p,status,options);if(r==-1)*e=errno;return r;}
static int native_query(void *c,pid_t p,int fd,uint8_t bytes[176],int *e){
 (void)c;errno=0;int r=proc_pidfdinfo(p,fd,PROC_PIDFDVNODEINFO,bytes,176);int saved=errno;if(r!=176)*e=saved;return r;
}
#endif
struct px_observer *px_observer_new(const struct px_plan *p,struct px_error *e){
#ifdef __APPLE__
 if(e)*e=(struct px_error){PX_OK,0};
 if(!p||!e){error(e,PX_ARGUMENT,0);return NULL;}
 uint8_t digest[32];
 if(CC_SHA256(p->original,PX_ORIGINAL_BYTES,digest)!=digest||memcmp(digest,p->digests[4],32)){error(e,PX_ARGUMENT,0);return NULL;}
 const struct px_ops o={NULL,native_pid,native_policy,native_clock,native_wait,native_query};return create(p,&o,e);
#else
 (void)p;error(e,PX_UNSUPPORTED,ENOTSUP);return NULL;
#endif
}
