#ifndef _GNU_SOURCE
#define _GNU_SOURCE 1
#endif
#include "target_fd_objects.h"
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <signal.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

_Static_assert(sizeof(dev_t) <= sizeof(uint64_t), "device field width");
_Static_assert(sizeof(ino_t) <= sizeof(uint64_t), "inode field width");
_Static_assert(sizeof(nlink_t) <= sizeof(uint64_t), "link field width");
_Static_assert(sizeof(mode_t) <= sizeof(uint32_t), "mode field width");
static int fail(struct tfo_error *e, enum tfo_stage stage, enum tfo_reason reason, int saved, int role, int fd)
{ *e = (struct tfo_error){stage, reason, saved, role, fd}; return -1; }
static void reset_error(struct tfo_error *e)
{ *e = (struct tfo_error){TFO_STAGE_NONE, TFO_REASON_NONE, 0, -1, -1}; }
static void reset_snapshot(struct tfo_snapshot *s)
{ memset(s, 0, sizeof(*s)); for (unsigned i=0;i<TFO_KEEP_COUNT;i++) s->entries[i].fd=-1; }
static void reset_matches(struct tfo_matches *m)
{ memset(m, 0, sizeof(*m)); for (unsigned i=0;i<TFO_OUTPUT_COUNT;i++) m->outputs[i].child_fd=m->outputs[i].controller_fd=-1; }
static int valid_plan(const struct tfo_plan *p, enum tfo_stage stage, struct tfo_error *e)
{
    if (p->keep[0]!=0 || p->keep[1]!=1 || p->keep[2]!=2 || p->keep[3]<3 || p->keep[4]<3 || p->keep[3]==p->keep[4])
        return fail(e,stage,TFO_REASON_ARGUMENT,0,-1,-1);
    return 0;
}
static int valid_ops(const struct tfo_operations *o, struct tfo_error *e)
{
    if (!o || !o->getpid_fn || !o->getppid_fn || !o->signals_blocked_fn || !o->stat_fn || !o->getfd_fn || !o->getfl_fn)
        return fail(e,TFO_STAGE_OPERATIONS,TFO_REASON_ARGUMENT,0,-1,-1);
    if (o->supported==0) return fail(e,TFO_STAGE_OPERATIONS,TFO_REASON_UNSUPPORTED,ENOTSUP,-1,-1);
    if (o->supported!=1) return fail(e,TFO_STAGE_OPERATIONS,TFO_REASON_ARGUMENT,0,-1,-1);
    return 0;
}
static int bad_result(int result, int saved, enum tfo_stage stage, int role, int fd, struct tfo_error *e)
{
    return fail(e,stage,result==-1 && saved>0?TFO_REASON_SYSCALL:TFO_REASON_ADAPTER,
                result==-1 && saved>0?saved:0,role,fd);
}
static int stat_shape(const struct tfo_backing *b)
{
    mode_t mode=(mode_t)b->mode;
    if ((uint32_t)mode != b->mode) return 0;
    return S_ISREG(mode)||S_ISFIFO(mode)||S_ISCHR(mode)||S_ISDIR(mode)||S_ISSOCK(mode)||S_ISBLK(mode)||S_ISLNK(mode);
}
static int read_entry(int fd, int role, enum tfo_stage stage, const struct tfo_operations *o,
                      struct tfo_entry *out, struct tfo_error *e)
{
    struct tfo_entry v; memset(&v,0,sizeof(v)); v.fd=fd;
    int saved=0, result=o->stat_fn(o->context,fd,&v.backing,&saved);
    if (result!=0) return bad_result(result,saved,stage,role,fd,e);
    if (!stat_shape(&v.backing)) return fail(e,stage,TFO_REASON_STAT_SHAPE,0,role,fd);
    saved=0; result=o->getfd_fn(o->context,fd,&saved);
    if (result<0) return bad_result(result,saved,stage,role,fd,e);
    v.descriptor_flags=result;
    saved=0; result=o->getfl_fn(o->context,fd,&saved);
    if (result<0) return bad_result(result,saved,stage,role,fd,e);
    v.status_flags=result; *out=v; return 0;
}
static int same_backing(const struct tfo_backing *a,const struct tfo_backing *b)
{ return a->device==b->device && a->inode==b->inode && a->links==b->links && a->mode==b->mode; }
static int same_entry(const struct tfo_entry *a,const struct tfo_entry *b)
{ return a->fd==b->fd && same_backing(&a->backing,&b->backing) && a->descriptor_flags==b->descriptor_flags && a->status_flags==b->status_flags; }
static int child_guard(uint64_t owner, const struct tfo_operations *o, pid_t expected, pid_t *child, struct tfo_error *e)
{
    if (!owner || owner>INT_MAX) return fail(e,TFO_STAGE_CHILD,TFO_REASON_RANGE,0,-1,-1);
    pid_t self=o->getpid_fn(o->context), parent=o->getppid_fn(o->context);
    if (self<=0 || parent<=0 || (uint64_t)self==owner || (uint64_t)parent!=owner || (expected>0 && expected!=self))
        return fail(e,TFO_STAGE_CHILD,TFO_REASON_NOT_OWNED_CHILD,0,-1,-1);
    *child=self; return 0;
}
static int mask_guard(const struct tfo_operations *o,struct tfo_error *e)
{
    int saved=0,result=o->signals_blocked_fn(o->context,&saved);
    if (result==1) return 0;
    if (result==0) return fail(e,TFO_STAGE_SIGNALS,TFO_REASON_SIGNALS_UNBLOCKED,0,-1,-1);
    return bad_result(result,saved,TFO_STAGE_SIGNALS,-1,-1,e);
}
int tfo_snapshot_in_owned_child(const struct tfo_plan *input, uint64_t owner,
    const struct tfo_operations *operations, struct tfo_snapshot *out, struct tfo_error *e)
{
    if(out) reset_snapshot(out);
    if (!e) return -1;
    reset_error(e);
    if (!input || !out) return fail(e,TFO_STAGE_PLAN,TFO_REASON_ARGUMENT,0,-1,-1);
    const struct tfo_plan plan=*input;
    if (valid_plan(&plan,TFO_STAGE_PLAN,e)||valid_ops(operations,e)) return -1;
    const struct tfo_operations o=*operations;
    pid_t child=0;
    if (child_guard(owner,&o,0,&child,e)||mask_guard(&o,e)) return -1;
    struct tfo_snapshot pending; reset_snapshot(&pending);
    pending.controller_pid=owner;pending.child_pid=(uint64_t)child;
    for (unsigned i=0;i<TFO_KEEP_COUNT;i++)
        if(read_entry(plan.keep[i],(int)i,TFO_STAGE_FIRST,&o,&pending.entries[i],e)) return -1;
    for (unsigned i=0;i<TFO_KEEP_COUNT;i++) {
        struct tfo_entry again;
        if(read_entry(plan.keep[i],(int)i,TFO_STAGE_SECOND,&o,&again,e)) return -1;
        if(!same_entry(&pending.entries[i],&again)) return fail(e,TFO_STAGE_STABILITY,TFO_REASON_CHANGED,0,(int)i,plan.keep[i]);
    }
    if (child_guard(owner,&o,child,&child,e)||mask_guard(&o,e)) return -1;
    pending.ready=1; *out=pending;return 0;
}
static int validate_snapshot(const struct tfo_snapshot *s, struct tfo_error *e)
{
    if (s->ready!=1) return fail(e,TFO_STAGE_SNAPSHOT,TFO_REASON_NOT_READY,0,-1,-1);
    if (!s->controller_pid || s->controller_pid>INT_MAX || !s->child_pid || s->child_pid>INT_MAX || s->controller_pid==s->child_pid)
        return fail(e,TFO_STAGE_SNAPSHOT,TFO_REASON_RANGE,0,-1,-1);
    struct tfo_plan p;for(unsigned i=0;i<TFO_KEEP_COUNT;i++)p.keep[i]=s->entries[i].fd;
    if(valid_plan(&p,TFO_STAGE_SNAPSHOT,e))return -1;
    for(unsigned i=0;i<TFO_KEEP_COUNT;i++)
        if(!stat_shape(&s->entries[i].backing)||s->entries[i].descriptor_flags<0||s->entries[i].status_flags<0)
            return fail(e,TFO_STAGE_SNAPSHOT,TFO_REASON_ARGUMENT,0,(int)i,s->entries[i].fd);
    return 0;
}
static int output_shape(const struct tfo_entry *v,int role,int child,struct tfo_error *e)
{
    if(!S_ISREG((mode_t)v->backing.mode))return fail(e,TFO_STAGE_MATCH,TFO_REASON_NOT_REGULAR,0,role,v->fd);
    if(v->backing.links!=1)return fail(e,TFO_STAGE_MATCH,TFO_REASON_LINKS,0,role,v->fd);
    if((v->status_flags&O_ACCMODE)!=O_WRONLY)return fail(e,TFO_STAGE_MATCH,TFO_REASON_ACCESS,0,role,v->fd);
    if(child && (v->descriptor_flags&FD_CLOEXEC))return fail(e,TFO_STAGE_MATCH,TFO_REASON_CLOEXEC,0,role,v->fd);
    return 0;
}
int tfo_match_regular_outputs(const struct tfo_snapshot *input,const int held[2],
    const struct tfo_operations *operations,struct tfo_matches *out,struct tfo_error *e)
{
    if(out)reset_matches(out);
    if(!e)return -1;
    reset_error(e);
    if(!input||!held||!out)return fail(e,TFO_STAGE_PLAN,TFO_REASON_ARGUMENT,0,-1,-1);
    const struct tfo_snapshot snapshot=*input;int references[2]={held[0],held[1]};
    if(validate_snapshot(&snapshot,e))return -1;
    if(references[0]<3||references[1]<3||references[0]==references[1])return fail(e,TFO_STAGE_PLAN,TFO_REASON_ARGUMENT,0,-1,-1);
    if(valid_ops(operations,e))return -1;
    const struct tfo_operations o=*operations;
    if((uint64_t)o.getpid_fn(o.context)!=snapshot.controller_pid)return fail(e,TFO_STAGE_CONTROLLER,TFO_REASON_NOT_CONTROLLER,0,-1,-1);
    struct tfo_entry first[2];
    for(unsigned i=0;i<2;i++)if(read_entry(references[i],(int)i+1,TFO_STAGE_REFERENCE_FIRST,&o,&first[i],e))return -1;
    for(unsigned i=0;i<2;i++){
        struct tfo_entry again;
        if(read_entry(references[i],(int)i+1,TFO_STAGE_REFERENCE_SECOND,&o,&again,e))return -1;
        if(!same_entry(&first[i],&again))return fail(e,TFO_STAGE_STABILITY,TFO_REASON_CHANGED,0,(int)i+1,references[i]);
    }
    for(unsigned i=0;i<2;i++){
        const struct tfo_entry *child=&snapshot.entries[i+1];
        if(output_shape(child,(int)i+1,1,e)||output_shape(&first[i],(int)i+1,0,e))return -1;
        if(!same_backing(&child->backing,&first[i].backing)||child->status_flags!=first[i].status_flags)
            return fail(e,TFO_STAGE_MATCH,TFO_REASON_MISMATCH,0,(int)i+1,references[i]);
    }
    if(first[0].backing.device==first[1].backing.device&&first[0].backing.inode==first[1].backing.inode)
        return fail(e,TFO_STAGE_MATCH,TFO_REASON_ALIASED_SINKS,0,-1,-1);
    if((uint64_t)o.getpid_fn(o.context)!=snapshot.controller_pid)return fail(e,TFO_STAGE_CONTROLLER,TFO_REASON_NOT_CONTROLLER,0,-1,-1);
    struct tfo_matches pending;reset_matches(&pending);
    for(unsigned i=0;i<2;i++){
        struct tfo_output_match *v=&pending.outputs[i];
        v->child_fd=snapshot.entries[i+1].fd;v->controller_fd=references[i];
        v->child_descriptor_flags=snapshot.entries[i+1].descriptor_flags;
        v->controller_descriptor_flags=first[i].descriptor_flags;
        v->status_flags=first[i].status_flags;v->backing=first[i].backing;
    }
    pending.ready=1;*out=pending;return 0;
}
static pid_t native_pid(void *c){(void)c;return getpid();}
static pid_t native_ppid(void *c){(void)c;return getppid();}
static int native_mask(void *c,int *e)
{
    (void)c;sigset_t current;
    if(sigprocmask(SIG_SETMASK,NULL,&current)==-1){*e=errno;return -1;}
    for(int s=1;s<NSIG;s++){
        if(s==SIGKILL||s==SIGSTOP)continue;
        struct sigaction action;
        if(sigaction(s,NULL,&action)==-1){
#if defined(__linux__)
            if(errno==EINVAL)continue;
#endif
            *e=errno;return -1;
        }
        int member=sigismember(&current,s);
        if(member==-1){*e=errno;return -1;}
        if(member!=1)return 0;
    }
    return 1;
}
static int native_stat(void *c,int fd,struct tfo_backing *out,int *e)
{
    (void)c;struct stat s;memset(&s,0,sizeof(s));
    int r=fstat(fd,&s);if(r==-1){*e=errno;return -1;}
    out->device=(uint64_t)s.st_dev;out->inode=(uint64_t)s.st_ino;
    out->links=(uint64_t)s.st_nlink;out->mode=(uint32_t)s.st_mode;return r;
}
static int native_fd(void *c,int fd,int *e){(void)c;int r=fcntl(fd,F_GETFD);if(r==-1)*e=errno;return r;}
static int native_fl(void *c,int fd,int *e){(void)c;int r=fcntl(fd,F_GETFL);if(r==-1)*e=errno;return r;}
const struct tfo_operations *tfo_native_operations(void)
{
    static const struct tfo_operations o={
#if defined(__APPLE__) || defined(__linux__)
        1,
#else
        0,
#endif
        NULL,native_pid,native_ppid,native_mask,native_stat,native_fd,native_fl};return &o;
}
const char *tfo_stage_name(enum tfo_stage s)
{
    static const char *const names[]={"none","plan","operations","child","signals","first","second","stability","snapshot","controller","reference-first","reference-second","match"};
    return (unsigned)s<sizeof(names)/sizeof(names[0])?names[s]:"unknown";
}
const char *tfo_reason_name(enum tfo_reason r)
{
    static const char *const names[]={"none","argument","range","unsupported","not-owned-child","signals-unblocked","syscall","adapter","stat-shape","changed","not-ready","not-controller","not-regular","links","access","cloexec","aliased-sinks","mismatch"};
    return (unsigned)r<sizeof(names)/sizeof(names[0])?names[r]:"unknown";
}
