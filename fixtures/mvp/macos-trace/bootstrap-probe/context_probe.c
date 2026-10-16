#define _POSIX_C_SOURCE 200809L
#ifndef _DARWIN_C_SOURCE
#define _DARWIN_C_SOURCE 1
#endif
#include "probe_report.h"
#include <errno.h>
#include <string.h>
#include <unistd.h>
#if defined(__APPLE__)
#include <fcntl.h>
#include <grp.h>
#include <libproc.h>
#include <limits.h>
#include <signal.h>
#include <sys/proc_info.h>
#include <sys/stat.h>
extern char **environ;
_Static_assert(sizeof(dev_t)==4,"Darwin device width");
_Static_assert(sizeof(ino_t)==8,"Darwin inode width");
_Static_assert((ino_t)-1>0,"Darwin inode unsigned");
_Static_assert(sizeof(struct proc_fdinfo)==8,"Darwin FD record width");
_Static_assert(offsetof(struct proc_fdinfo,proc_fd)==0,"Darwin FD offset");
_Static_assert(offsetof(struct proc_fdinfo,proc_fdtype)==4,"Darwin FD type offset");
_Static_assert(O_ACCMODE==NP_DARWIN_ACCMODE&&O_RDONLY==0&&O_WRONLY==1,"Darwin access flags");
_Static_assert(O_NONBLOCK==NP_DARWIN_NONBLOCK&&O_ASYNC==NP_DARWIN_ASYNC&&O_EVTONLY==NP_DARWIN_EVTONLY,"Darwin status flags");
_Static_assert(FD_CLOEXEC==NP_DARWIN_CLOEXEC&&EPERM==NP_DARWIN_EPERM,"Darwin errno/FD flags");
#endif
static void diagnostic(const char *stage, int error) {
    /* Fixed vocabulary and decimal errno only; no argv/path/environment dump. */
    char message[96];size_t used=0;
    const char *prefix="GLUENP01 error stage=";
    for(size_t i=0;prefix[i]&&used<sizeof(message);i++)message[used++]=prefix[i];
    for(size_t i=0;stage[i]&&used<sizeof(message);i++)message[used++]=stage[i];
    const char *label=" errno=";for(size_t i=0;label[i]&&used<sizeof(message);i++)message[used++]=label[i];
    unsigned value=error>0?(unsigned)error:0;char digits[16];size_t count=0;
    do {digits[count++]=(char)('0'+value%10);value/=10;}while(value&&count<sizeof(digits));
    while(count&&used<sizeof(message))message[used++]=digits[--count];
    if(used<sizeof(message))message[used++]='\n';
    (void)write(2,message,used); /* Best effort, never retry or change signals. */
}
static void die(const char *stage, int error) { diagnostic(stage,error);_exit(1); }
#if defined(__APPLE__)
static void ids(uint64_t out[4]) {
    out[0]=(uint64_t)getuid();out[1]=(uint64_t)geteuid();out[2]=(uint64_t)getgid();out[3]=(uint64_t)getegid();
}
static void inspect_fds(void) {
    struct proc_fdinfo records[4];
    for(size_t i=0;i<4;i++){records[i].proc_fd=-1;records[i].proc_fdtype=0;}
    errno=0;int n=proc_pidinfo(getpid(),PROC_PIDLISTFDS,0,records,(int)sizeof(records));int e=errno;
    if(n<=0)die("descriptors",e>0?e:0);
    if((size_t)n>=sizeof(records)||(size_t)n%sizeof(records[0])||n!=3*(int)sizeof(records[0]))die("descriptors",0);
    unsigned found=0;
    for(size_t i=0;i<3;i++) {
        int fd=records[i].proc_fd;
        if(fd<0||fd>2||(found&(1u<<(unsigned)fd)))die("descriptors",0);
        found|=1u<<(unsigned)fd;
    }
    if(found!=7)die("descriptors",0);
}
static void inspect_signals(void) {
    sigset_t mask;if(sigprocmask(SIG_SETMASK,NULL,&mask)==-1)die("signals",errno);
    for(int s=1;s<NSIG;s++) {
        if(s==SIGKILL||s==SIGSTOP)continue;
        int member=sigismember(&mask,s);if(member==-1)die("signals",errno);if(member)die("signals",0);
        struct sigaction action;
        if(sigaction(s,NULL,&action)==-1)die("signals",errno);
        if(action.sa_handler!=SIG_DFL)die("signals",0);
    }
    stack_t stack;if(sigaltstack(NULL,&stack)==-1)die("signals",errno);
    if(!(stack.ss_flags&SS_DISABLE)||(stack.ss_flags&SS_ONSTACK))die("signals",0);
}
static void observe(struct np_report *r) {
    memset(r,0,sizeof(*r));ids(r->ids);
    for(size_t i=0;i<4;i++)if(!r->ids[i]||r->ids[i]>NP_ID_MAX)die("identity",0);
    if(r->ids[0]!=r->ids[1]||r->ids[2]!=r->ids[3])die("identity",0);
    if(environ&&environ[0])die("environment",0);
    pid_t pid=getpid(),parent=getppid(),group=getpgrp();
    if(pid<=0||parent<=0||group!=pid||parent==pid)die("process",0);
    r->pids[0]=(uint64_t)pid;r->pids[1]=(uint64_t)parent;r->pids[2]=(uint64_t)group;
    if(r->pids[0]>NP_ID_MAX||r->pids[1]>NP_ID_MAX||r->pids[2]>NP_ID_MAX)die("process",0);
    int count=getgroups(0,NULL);if(count==-1)die("groups",errno);
    if(count<=0||count>(int)NP_MAX_GROUPS)die("groups",0);
    gid_t groups[NP_MAX_GROUPS];for(size_t i=0;i<NP_MAX_GROUPS;i++)groups[i]=(gid_t)-1;
    int actual=getgroups((int)NP_MAX_GROUPS,groups);if(actual==-1)die("groups",errno);
    if(actual!=count)die("groups",0);r->group_count=(uint64_t)count;
    for(int i=0;i<count;i++) {
        r->groups[i]=(uint64_t)groups[i];if(r->groups[i]>NP_ID_MAX)die("groups",0);
        for(int j=0;j<i;j++)if(groups[i]==groups[j])die("groups",0);
    }
    if(r->groups[0]!=r->ids[2])die("groups",0);
    struct stat cwd;if(stat(".",&cwd)==-1)die("cwd",errno);
    if(!S_ISDIR(cwd.st_mode))die("cwd",0);
    r->cwd_device=(uint64_t)(uint32_t)cwd.st_dev;r->cwd_inode=(uint64_t)cwd.st_ino;
    for(int fd=0;fd<3;fd++) {
        int status=fcntl(fd,F_GETFL);if(status==-1)die("stdio",errno);
        int descriptor=fcntl(fd,F_GETFD);if(descriptor==-1)die("stdio",errno);
        if(status<0||descriptor<0||(status&O_ACCMODE)!=(fd?O_WRONLY:O_RDONLY)||
           (status&(O_NONBLOCK|O_ASYNC|O_EVTONLY))||(descriptor&FD_CLOEXEC))die("stdio",0);
        r->status_flags[fd]=(uint64_t)status;r->descriptor_flags[fd]=(uint64_t)descriptor;r->fds[fd]=(uint64_t)fd;
    }
    inspect_signals();inspect_fds();r->fd_count=3;r->signal_policy=1;
}
static int same_context(const struct np_report *a,const struct np_report *b) {
    return !memcmp(a->ids,b->ids,sizeof(a->ids))&&!memcmp(a->pids,b->pids,sizeof(a->pids))&&
        a->group_count==b->group_count&&!memcmp(a->groups,b->groups,sizeof(a->groups))&&
        a->cwd_device==b->cwd_device&&a->cwd_inode==b->cwd_inode&&a->fd_count==b->fd_count&&
        !memcmp(a->fds,b->fds,sizeof(a->fds))&&!memcmp(a->status_flags,b->status_flags,sizeof(a->status_flags))&&
        !memcmp(a->descriptor_flags,b->descriptor_flags,sizeof(a->descriptor_flags))&&
        a->signal_policy==b->signal_policy&&a->environment_count==b->environment_count;
}
#endif
int main(int argc,char **argv) {
    uint8_t digest[32];
    if(argc!=3||!argv||!argv[0]||!argv[1]||!argv[2]||strcmp(argv[1],"--request-sha256"))die("argument",0);
    size_t length=strnlen(argv[2],65);
    if(np_parse_sha256(argv[2],length,digest)!=NP_OK)die("argument",0);
#if !defined(__APPLE__)
    die("platform",ENOTSUP);
#else
    struct np_report before,after;observe(&before);
    errno=0;int rc=setuid(0);int saved_errno=errno;
    if(rc!=-1||saved_errno!=EPERM)die("root-regain",rc==-1?saved_errno:0);
    uint64_t post[4];ids(post);
    if(memcmp(post,before.ids,sizeof(post)))die("post-identity",0);
    observe(&after);if(!same_context(&before,&after))die("context",0);
    memcpy(after.request_sha256,digest,32);memcpy(after.post_ids,post,sizeof(post));
    after.root_regain_result=rc;after.root_regain_errno=(uint64_t)saved_errno;
    uint8_t report[NP_REPORT_SIZE];if(np_report_encode(&after,report)!=NP_OK)die("codec",0);
    ssize_t written=write(1,report,sizeof(report));int output_errno=errno;
    if(written!=(ssize_t)sizeof(report))die("output",written==-1?output_errno:0);
    _exit(0);
#endif
}
