#ifndef _GNU_SOURCE
#define _GNU_SOURCE 1
#endif
#include "target_cwd.h"
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <signal.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>
_Static_assert(sizeof(dev_t)<=sizeof(uint64_t),"device width");
_Static_assert(sizeof(ino_t)<=sizeof(uint64_t),"inode width");
_Static_assert(sizeof(nlink_t)<=sizeof(uint64_t),"links width");
_Static_assert(sizeof(mode_t)<=sizeof(uint32_t),"mode width");
_Static_assert(sizeof(uid_t)<=sizeof(uint32_t),"uid width");
_Static_assert(sizeof(gid_t)<=sizeof(uint32_t),"gid width");
_Static_assert(TCWD_STAGE_FINAL<256,"stage fits existing detail byte");
static int fail(struct tcwd_error *e,enum tcwd_stage s,enum tcwd_reason r,int saved)
{ e->stage=s; e->reason=r; e->system_errno=saved; return -1; }
static int bad(int result,int saved,enum tcwd_stage stage,struct tcwd_error *e)
{
    return fail(e,stage,result==-1&&saved>0?TCWD_REASON_SYSCALL:TCWD_REASON_ADAPTER,
                result==-1&&saved>0?saved:0);
}
static void reset(struct tcwd_result *out)
{ memset(out,0,sizeof(*out)); out->before.fd=out->after.fd=-1; }
static int owner_guard(uint64_t owner,pid_t expected,const struct tcwd_operations *o,
                       enum tcwd_stage stage,pid_t *child,struct tcwd_error *e)
{
    pid_t self=o->getpid_fn(o->context),parent=o->getppid_fn(o->context);
    if(self<=0||parent<=0||(uint64_t)self==owner||(uint64_t)parent!=owner||(expected>0&&self!=expected))
        return fail(e,stage,TCWD_REASON_NOT_OWNED_CHILD,0);
    *child=self; return 0;
}
static int mask_guard(const struct tcwd_operations *o,enum tcwd_stage stage,struct tcwd_error *e)
{
    int saved=0,r=o->signals_blocked_fn(o->context,&saved);
    if(r==1)return 0;
    if(r==0)return fail(e,stage,TCWD_REASON_SIGNALS_UNBLOCKED,0);
    return bad(r,saved,stage,e);
}
static int deadline(const struct tcwd_guard *g,enum tcwd_stage stage,struct tcwd_error *e)
{
    int saved=0,r=g->before_fn(g->context,&saved);
    if(r==0)return 0;
    if(r==-1&&saved==0)return fail(e,stage,TCWD_REASON_DEADLINE,0);
    return bad(r,saved,stage,e);
}
static int directory(const struct tcwd_backing *s)
{ return (uint32_t)(mode_t)s->mode==s->mode&&S_ISDIR((mode_t)s->mode); }
static int same_backing(const struct tcwd_backing *a,const struct tcwd_backing *b)
{
    return a->device==b->device&&a->inode==b->inode&&a->links==b->links&&
           a->mode==b->mode&&a->uid==b->uid&&a->gid==b->gid;
}
static int same_entry(const struct tcwd_entry *a,const struct tcwd_entry *b)
{
    return a->fd==b->fd&&a->descriptor_flags==b->descriptor_flags&&a->status_flags==b->status_flags&&
           same_backing(&a->backing,&b->backing);
}
static int sample(int fd,const struct tcwd_operations *o,enum tcwd_stage stage,
                  struct tcwd_entry *out,struct tcwd_error *e)
{
    struct tcwd_entry v; memset(&v,0,sizeof(v)); v.fd=fd;
    int saved=0,r=o->stat_fn(o->context,fd,&v.backing,&saved);
    if(r!=0)return bad(r,saved,stage,e);
    if(!directory(&v.backing))return fail(e,stage,TCWD_REASON_NOT_DIRECTORY,0);
    saved=0; r=o->getfd_fn(o->context,fd,&saved);
    if(r<0)return bad(r,saved,stage,e);
    v.descriptor_flags=r;
    saved=0; r=o->getfl_fn(o->context,fd,&saved);
    if(r<0)return bad(r,saved,stage,e);
    v.status_flags=r;
    if(!(v.descriptor_flags&FD_CLOEXEC)||(v.status_flags&O_ACCMODE)!=O_RDONLY)
        return fail(e,stage,TCWD_REASON_FLAGS,0);
    *out=v; return 0;
}
int tcwd_select_in_owned_child(const struct tcwd_request *input,uint64_t owner,
    const struct tcwd_operations *operations,const struct tcwd_guard *guard,
    struct tcwd_result *out,struct tcwd_error *e)
{
    if(out)reset(out);
    if(!e)return -1;
    memset(e,0,sizeof(*e));
    if(!input||!out||!guard||!guard->before_fn)return fail(e,TCWD_STAGE_REQUEST,TCWD_REASON_ARGUMENT,0);
    const struct tcwd_request request=*input;
    if(request.directory_fd<3||!owner||owner>INT_MAX)return fail(e,TCWD_STAGE_REQUEST,TCWD_REASON_RANGE,0);
    if(!operations||!operations->getpid_fn||!operations->getppid_fn||!operations->signals_blocked_fn||
       !operations->stat_fn||!operations->getfd_fn||!operations->getfl_fn||!operations->change_fn||!operations->cwd_fn)
        return fail(e,TCWD_STAGE_OPERATIONS,TCWD_REASON_ARGUMENT,0);
    if(!operations->supported)return fail(e,TCWD_STAGE_OPERATIONS,TCWD_REASON_UNSUPPORTED,ENOTSUP);
    if(operations->supported!=1)return fail(e,TCWD_STAGE_OPERATIONS,TCWD_REASON_ARGUMENT,0);
    const struct tcwd_operations o=*operations;
    const struct tcwd_guard g=*guard;
    pid_t child=0;
    if(owner_guard(owner,0,&o,TCWD_STAGE_CHILD,&child,e)||mask_guard(&o,TCWD_STAGE_SIGNALS,e)||
       deadline(&g,TCWD_STAGE_FIRST,e))return -1;
    struct tcwd_result pending; reset(&pending);
    struct tcwd_entry again;
    if(sample(request.directory_fd,&o,TCWD_STAGE_FIRST,&pending.before,e))return -1;
    if(pending.before.backing.device!=request.device||pending.before.backing.inode!=request.inode)
        return fail(e,TCWD_STAGE_FIRST,TCWD_REASON_MISMATCH,0);
    if(deadline(&g,TCWD_STAGE_SECOND,e)||sample(request.directory_fd,&o,TCWD_STAGE_SECOND,&again,e))return -1;
    if(!same_entry(&pending.before,&again))return fail(e,TCWD_STAGE_SECOND,TCWD_REASON_CHANGED,0);
    if(owner_guard(owner,child,&o,TCWD_STAGE_BEFORE_CHANGE,&child,e)||mask_guard(&o,TCWD_STAGE_BEFORE_CHANGE,e)||
       deadline(&g,TCWD_STAGE_BEFORE_CHANGE,e))return -1;
    e->mutation_attempted=1;
    int saved=0,r=o.change_fn(o.context,request.directory_fd,&saved);
    if(r!=0)return bad(r,saved,TCWD_STAGE_CHANGE,e);
    if(deadline(&g,TCWD_STAGE_AFTER_CHANGE,e)||sample(request.directory_fd,&o,TCWD_STAGE_POST,&pending.after,e))return -1;
    if(!same_entry(&pending.before,&pending.after))return fail(e,TCWD_STAGE_POST,TCWD_REASON_CHANGED,0);
    if(deadline(&g,TCWD_STAGE_READBACK,e))return -1;
    saved=0; r=o.cwd_fn(o.context,&pending.cwd,&saved);
    if(r!=0)return bad(r,saved,TCWD_STAGE_READBACK,e);
    if(!directory(&pending.cwd)||!same_backing(&pending.before.backing,&pending.cwd))
        return fail(e,TCWD_STAGE_READBACK,TCWD_REASON_MISMATCH,0);
    if(owner_guard(owner,child,&o,TCWD_STAGE_FINAL,&child,e)||mask_guard(&o,TCWD_STAGE_FINAL,e)||
       deadline(&g,TCWD_STAGE_FINAL,e))return -1;
    pending.controller_pid=owner; pending.child_pid=(uint64_t)child; pending.ready=1;
    *out=pending; return 0;
}
static pid_t native_pid(void *c){(void)c;return getpid();}
static pid_t native_ppid(void *c){(void)c;return getppid();}
static int native_mask(void *c,int *e)
{
    (void)c;sigset_t mask;
    if(sigprocmask(SIG_SETMASK,NULL,&mask)==-1){*e=errno;return -1;}
    for(int signal_number=1;signal_number<NSIG;signal_number++){
        if(signal_number==SIGKILL||signal_number==SIGSTOP)continue;
        struct sigaction action;
        if(sigaction(signal_number,NULL,&action)==-1){
#if defined(__linux__)
            if(errno==EINVAL)continue;
#endif
            *e=errno;return -1;
        }
        int member=sigismember(&mask,signal_number);
        if(member==-1){*e=errno;return -1;}
        if(member!=1)return 0;
    }
    return 1;
}
static void backing(const struct stat *s,struct tcwd_backing *out)
{
#if defined(__APPLE__)
    out->device=(uint64_t)(uint32_t)s->st_dev;
#else
    out->device=(uint64_t)s->st_dev;
#endif
    out->inode=(uint64_t)s->st_ino;out->links=(uint64_t)s->st_nlink;
    out->mode=(uint32_t)s->st_mode;out->uid=(uint32_t)s->st_uid;out->gid=(uint32_t)s->st_gid;
}
static int native_stat(void *c,int fd,struct tcwd_backing *out,int *e)
{(void)c;struct stat s;int r=fstat(fd,&s);if(r==-1){*e=errno;return -1;}backing(&s,out);return r;}
static int native_fd(void *c,int fd,int *e){(void)c;int r=fcntl(fd,F_GETFD);if(r==-1)*e=errno;return r;}
static int native_fl(void *c,int fd,int *e){(void)c;int r=fcntl(fd,F_GETFL);if(r==-1)*e=errno;return r;}
static int native_change(void *c,int fd,int *e){(void)c;int r=fchdir(fd);if(r==-1)*e=errno;return r;}
static int native_cwd(void *c,struct tcwd_backing *out,int *e)
{(void)c;struct stat s;int r=stat(".",&s);if(r==-1){*e=errno;return -1;}backing(&s,out);return r;}
const struct tcwd_operations *tcwd_native_operations(void)
{
    static const struct tcwd_operations o={
#if defined(__APPLE__) || defined(__linux__)
        1,
#else
        0,
#endif
        NULL,native_pid,native_ppid,native_mask,native_stat,native_fd,native_fl,native_change,native_cwd};
    return &o;
}
int tcwd_error_detail(const struct tcwd_error *e)
{
    if(!e||(unsigned)e->stage>TCWD_STAGE_FINAL||(e->mutation_attempted!=0&&e->mutation_attempted!=1))return -1;
    return (int)e->stage|(e->mutation_attempted?TCWD_MUTATION_DETAIL:0);
}
const char *tcwd_stage_name(enum tcwd_stage stage)
{
    static const char *const names[]={"none","request","operations","child","signals","first","second","before-change","change","after-change","post","readback","final"};
    return (unsigned)stage<sizeof(names)/sizeof(names[0])?names[stage]:"unknown";
}
const char *tcwd_reason_name(enum tcwd_reason reason)
{
    static const char *const names[]={"none","argument","range","unsupported","not-owned-child","signals-unblocked","syscall","adapter","not-directory","flags","mismatch","changed","deadline"};
    return (unsigned)reason<sizeof(names)/sizeof(names[0])?names[reason]:"unknown";
}
