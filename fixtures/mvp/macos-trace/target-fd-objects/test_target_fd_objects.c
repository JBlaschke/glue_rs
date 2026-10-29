#ifndef _GNU_SOURCE
#define _GNU_SOURCE 1
#endif
#include "target_fd_objects.h"
#include "../target-descriptors/target_descriptors.h"
#include "../target-endpoints/target_endpoints.h"
#include <assert.h>
#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <poll.h>
#include <signal.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/resource.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

struct model {
    pid_t self,parent; int mask,mask_errno,mask_calls,pid_calls,reads,fail_at,bad_result,saved;
    int change,change_from,self_final,parent_final,parent_calls,mask_final;struct tfo_entry values[32];
};
static struct model model(void)
{
    struct model m;memset(&m,0,sizeof(m));m.self=222;m.parent=111;m.mask=1;m.mask_final=INT_MAX;
    for(int i=0;i<32;i++){
        m.values[i].fd=i;m.values[i].backing.device=9;m.values[i].backing.inode=(uint64_t)(100+i);
        m.values[i].backing.links=1;m.values[i].backing.mode=S_IFREG|0600;
        m.values[i].descriptor_flags=i>=3?FD_CLOEXEC:0;m.values[i].status_flags=i==0?O_RDONLY:O_WRONLY;
    }
    for(int i=7;i<=8;i++){m.values[i].backing.mode=S_IFIFO|0600;m.values[i].status_flags=(i==7?O_RDONLY:O_WRONLY)|O_NONBLOCK;}
    m.values[20].backing=m.values[1].backing;m.values[21].backing=m.values[2].backing;
    m.bad_result=-1;m.saved=EIO;return m;
}
static pid_t mpid(void *c){struct model*m=c;m->pid_calls++;return m->self_final&&m->pid_calls>1?m->self_final:m->self;}
static pid_t mppid(void *c){struct model*m=c;m->parent_calls++;return m->parent_final&&m->parent_calls>1?m->parent_final:m->parent;}
static int mmask(void*c,int*e){struct model*m=c;m->mask_calls++;*e=m->mask_errno;return m->mask_calls>1&&m->mask_final!=INT_MAX?m->mask_final:m->mask;}
static int tick(struct model*m,int*e){m->reads++;*e=m->saved;return m->reads==m->fail_at;}
static int mstat(void*c,int fd,struct tfo_backing*out,int*e)
{
    struct model*m=c;assert(fd>=0&&fd<32);if(tick(m,e))return m->bad_result;*out=m->values[fd].backing;
    if(m->change_from&&m->reads>=m->change_from){
        if(m->change==1)out->device++;if(m->change==2)out->inode++;if(m->change==3)out->links++;
        if(m->change==4)out->mode^=0040;
    }return 0;
}
static int mfd(void*c,int fd,int*e){struct model*m=c;if(tick(m,e))return m->bad_result;return m->values[fd].descriptor_flags^((m->change==5&&m->reads>=m->change_from)?FD_CLOEXEC:0);}
static int mfl(void*c,int fd,int*e){struct model*m=c;if(tick(m,e))return m->bad_result;return m->values[fd].status_flags^((m->change==6&&m->reads>=m->change_from)?O_NONBLOCK:0);}
static struct tfo_operations ops(struct model*m){return (struct tfo_operations){1,m,mpid,mppid,mmask,mstat,mfd,mfl};}
static struct tfo_plan plan(void){return (struct tfo_plan){{0,1,2,7,8}};}
static void empty_snapshot(const struct tfo_snapshot*s)
{assert(!s->ready&&!s->controller_pid&&!s->child_pid);for(int i=0;i<5;i++)assert(s->entries[i].fd==-1&&!s->entries[i].backing.inode);}
static void empty_matches(const struct tfo_matches*m)
{assert(!m->ready);for(int i=0;i<2;i++)assert(m->outputs[i].child_fd==-1&&m->outputs[i].controller_fd==-1);}
static struct tfo_snapshot snapshot(struct model*m)
{struct tfo_snapshot s;struct tfo_error e;struct tfo_plan p=plan();struct tfo_operations o=ops(m);assert(!tfo_snapshot_in_owned_child(&p,111,&o,&s,&e));return s;}
static void success(void)
{
    struct model m=model();struct tfo_snapshot s=snapshot(&m);
    assert(s.ready&&s.controller_pid==111&&s.child_pid==222&&m.reads==30&&m.mask_calls==2);
    assert(s.entries[7-4].fd==7&&s.entries[1].backing.inode==101&&s.entries[3].status_flags==(O_RDONLY|O_NONBLOCK));
    m.self=111;m.reads=0;struct tfo_operations o=ops(&m);struct tfo_matches v;struct tfo_error e;int refs[]={20,21};
    assert(!tfo_match_regular_outputs(&s,refs,&o,&v,&e)&&v.ready&&m.reads==12);
    assert(v.outputs[0].child_descriptor_flags==0&&v.outputs[0].controller_descriptor_flags==FD_CLOEXEC);
    assert(v.outputs[0].backing.inode==101&&v.outputs[1].backing.inode==102);
    assert(e.reason==TFO_REASON_NONE&&e.role==-1&&e.fd==-1&&!e.system_errno);
}
static void plans(void)
{
    struct model m=model();struct tfo_operations o=ops(&m);struct tfo_snapshot s;struct tfo_error e;
    struct tfo_plan p=plan();assert(tfo_snapshot_in_owned_child(NULL,111,&o,&s,&e)==-1);empty_snapshot(&s);
    for(int i=0;i<5;i++){p=plan();p.keep[i]=-1;assert(tfo_snapshot_in_owned_child(&p,111,&o,&s,&e)==-1);empty_snapshot(&s);}
    p=plan();p.keep[4]=7;assert(tfo_snapshot_in_owned_child(&p,111,&o,&s,&e)==-1);
    p=plan();s.ready=1;assert(tfo_snapshot_in_owned_child(&p,111,&o,&s,NULL)==-1);empty_snapshot(&s);
    assert(tfo_snapshot_in_owned_child(&p,111,&o,NULL,&e)==-1);
    struct tfo_matches v;v.ready=1;assert(tfo_match_regular_outputs(&s,NULL,&o,&v,NULL)==-1);empty_matches(&v);
    assert(!m.reads&&!m.pid_calls);
}
static void callbacks(void)
{
    struct model m=model();struct tfo_snapshot s;struct tfo_plan p=plan();struct tfo_error e;
    for(int i=0;i<7;i++){
        struct tfo_operations o=ops(&m);if(i==0)o.getpid_fn=NULL;if(i==1)o.getppid_fn=NULL;if(i==2)o.signals_blocked_fn=NULL;
        if(i==3)o.stat_fn=NULL;if(i==4)o.getfd_fn=NULL;if(i==5)o.getfl_fn=NULL;if(i==6)o.supported=2;
        assert(tfo_snapshot_in_owned_child(&p,111,&o,&s,&e)==-1&&e.stage==TFO_STAGE_OPERATIONS);empty_snapshot(&s);
    }
    struct tfo_operations o=ops(&m);o.supported=0;
    assert(tfo_snapshot_in_owned_child(&p,111,&o,&s,&e)==-1&&e.reason==TFO_REASON_UNSUPPORTED&&e.system_errno==ENOTSUP);
    assert(!m.reads&&!m.pid_calls);
}
static void owner_masks(void)
{
    struct tfo_plan p=plan();struct tfo_snapshot s;struct tfo_error e;
    for(int i=0;i<6;i++){
        struct model m=model();uint64_t owner=111;if(i==0)owner=0;if(i==1)owner=(uint64_t)INT_MAX+1;if(i==2)m.self=111;
        if(i==3)m.parent=333;if(i==4)m.self=0;if(i==5)m.parent=0;struct tfo_operations o=ops(&m);
        assert(tfo_snapshot_in_owned_child(&p,owner,&o,&s,&e)==-1&&e.stage==TFO_STAGE_CHILD&&!m.reads);empty_snapshot(&s);
    }
    for(int result=-2;result<=0;result++){
        struct model m=model();m.mask=result;m.mask_errno=EINTR;struct tfo_operations o=ops(&m);
        assert(tfo_snapshot_in_owned_child(&p,111,&o,&s,&e)==-1&&e.stage==TFO_STAGE_SIGNALS&&!m.reads);empty_snapshot(&s);
    }
}
static void errors(void)
{
    struct tfo_plan p=plan();struct tfo_snapshot s;struct tfo_error e;
    for(int call=1;call<=30;call++){
        struct model m=model();m.fail_at=call;struct tfo_operations o=ops(&m);
        assert(tfo_snapshot_in_owned_child(&p,111,&o,&s,&e)==-1&&m.reads==call&&e.reason==TFO_REASON_SYSCALL&&e.system_errno==EIO);
        empty_snapshot(&s);
    }
    for(int i=0;i<3;i++){
        struct model m=model();m.fail_at=1;m.bad_result=i==0?1:-1;m.saved=i==2?-7:0;struct tfo_operations o=ops(&m);
        assert(tfo_snapshot_in_owned_child(&p,111,&o,&s,&e)==-1&&e.reason==TFO_REASON_ADAPTER&&!e.system_errno);
    }
    struct model m=model();m.fail_at=2;m.bad_result=-2;m.saved=EIO;struct tfo_operations o=ops(&m);
    assert(tfo_snapshot_in_owned_child(&p,111,&o,&s,&e)==-1&&e.reason==TFO_REASON_ADAPTER);
}
static void changes(void)
{
    struct tfo_plan p=plan();struct tfo_snapshot s;struct tfo_error e;
    for(int field=1;field<=6;field++){
        struct model m=model();m.change=field;m.change_from=16;struct tfo_operations o=ops(&m);
        assert(tfo_snapshot_in_owned_child(&p,111,&o,&s,&e)==-1&&e.reason==TFO_REASON_CHANGED);empty_snapshot(&s);
    }
    struct model m=model();m.values[0].backing.mode=0;struct tfo_operations o=ops(&m);
    assert(tfo_snapshot_in_owned_child(&p,111,&o,&s,&e)==-1&&e.reason==TFO_REASON_STAT_SHAPE);
    if(sizeof(mode_t)<sizeof(uint32_t)){
        m=model();m.values[0].backing.mode=(uint32_t)S_IFREG|UINT32_C(0x10000);o=ops(&m);
        assert(tfo_snapshot_in_owned_child(&p,111,&o,&s,&e)==-1&&e.reason==TFO_REASON_STAT_SHAPE);
    }
}
static void final_guards(void)
{
    for(int test=0;test<3;test++){
        struct model m=model();if(test==0)m.mask_final=0;if(test==1)m.self_final=333;if(test==2)m.parent_final=333;
        struct tfo_operations o=ops(&m);struct tfo_plan p=plan();struct tfo_snapshot s;struct tfo_error e;
        assert(tfo_snapshot_in_owned_child(&p,111,&o,&s,&e)==-1&&m.reads==30);empty_snapshot(&s);
    }
    struct model m=model();struct tfo_snapshot s=snapshot(&m);m.self=111;m.pid_calls=0;m.self_final=333;m.reads=0;
    struct tfo_operations o=ops(&m);struct tfo_matches v;struct tfo_error e;int refs[]={20,21};
    assert(tfo_match_regular_outputs(&s,refs,&o,&v,&e)==-1&&e.reason==TFO_REASON_NOT_CONTROLLER&&m.reads==12);empty_matches(&v);
}
static void match_errors(void)
{
    for(int call=1;call<=12;call++){
        struct model m=model();struct tfo_snapshot s=snapshot(&m);m.self=111;m.reads=0;m.fail_at=call;
        struct tfo_operations o=ops(&m);struct tfo_matches v;struct tfo_error e;int refs[]={20,21};
        assert(tfo_match_regular_outputs(&s,refs,&o,&v,&e)==-1&&m.reads==call&&e.reason==TFO_REASON_SYSCALL);empty_matches(&v);
    }
    for(int field=1;field<=6;field++){
        struct model m=model();struct tfo_snapshot s=snapshot(&m);m.self=111;m.reads=0;m.change=field;m.change_from=7;
        struct tfo_operations o=ops(&m);struct tfo_matches v;struct tfo_error e;int refs[]={20,21};
        assert(tfo_match_regular_outputs(&s,refs,&o,&v,&e)==-1&&e.reason==TFO_REASON_CHANGED);empty_matches(&v);
    }
}
static void match_shapes(void)
{
    for(int test=0;test<8;test++){
        struct model m=model();struct tfo_snapshot s=snapshot(&m);m.self=111;m.reads=0;
        if(test==0)s.entries[1].backing.mode=S_IFIFO|0600;
        if(test==1)s.entries[1].backing.links=2;
        if(test==2)s.entries[1].status_flags=O_RDWR;
        if(test==3)s.entries[1].descriptor_flags=FD_CLOEXEC;
        if(test==4)m.values[20].backing.inode++;
        if(test==5)m.values[21].status_flags|=O_APPEND;
        if(test==6)m.values[21].backing.mode=S_IFDIR|0600;
        if(test==7){s.entries[2].backing=s.entries[1].backing;m.values[21].backing=m.values[20].backing;}
        struct tfo_operations o=ops(&m);struct tfo_matches v;struct tfo_error e;int refs[]={20,21};
        assert(tfo_match_regular_outputs(&s,refs,&o,&v,&e)==-1);empty_matches(&v);
        if(test==7)assert(e.reason==TFO_REASON_ALIASED_SINKS);
    }
}
static void match_preflight(void)
{
    struct model m=model();struct tfo_snapshot s=snapshot(&m);m.reads=0;m.self=444;
    struct tfo_operations o=ops(&m);struct tfo_matches v;struct tfo_error e;int refs[]={20,21};
    assert(tfo_match_regular_outputs(&s,refs,&o,&v,&e)==-1&&e.reason==TFO_REASON_NOT_CONTROLLER&&!m.reads);
    m.self=111;refs[1]=20;assert(tfo_match_regular_outputs(&s,refs,&o,&v,&e)==-1&&!m.reads);refs[1]=21;
    for(int i=0;i<4;i++){
        struct tfo_snapshot bad=s;if(i==0)bad.ready=2;if(i==1)bad.controller_pid=bad.child_pid;if(i==2)bad.entries[1].fd=9;if(i==3)bad.entries[1].descriptor_flags=-1;
        assert(tfo_match_regular_outputs(&bad,refs,&o,&v,&e)==-1&&!m.reads);empty_matches(&v);
    }
    assert(tfo_match_regular_outputs(NULL,refs,&o,&v,&e)==-1);empty_matches(&v);
}
static void stale_errno_flags(void)
{
    struct model m=model();m.saved=EACCES;m.values[1].status_flags|=O_APPEND;m.values[20].status_flags|=O_APPEND;
    struct tfo_snapshot s=snapshot(&m);m.self=111;m.reads=0;struct tfo_operations o=ops(&m);struct tfo_matches v;struct tfo_error e;int refs[]={20,21};
    assert(!tfo_match_regular_outputs(&s,refs,&o,&v,&e)&&!e.system_errno);
    assert(v.outputs[0].status_flags==(O_WRONLY|O_APPEND));
    assert(!strcmp(tfo_stage_name(TFO_STAGE_MATCH),"match")&&!strcmp(tfo_reason_name(TFO_REASON_CHANGED),"changed"));
    assert(!strcmp(tfo_stage_name((enum tfo_stage)-1),"unknown")&&!strcmp(tfo_reason_name((enum tfo_reason)-1),"unknown"));
}

static int64_t milliseconds(void)
{
    struct timespec t;if(clock_gettime(CLOCK_MONOTONIC,&t))return -1;
    return (int64_t)t.tv_sec*1000+t.tv_nsec/1000000;
}
static int transfer(int fd,void *buffer,size_t size,int writing)
{
    size_t moved=0;int64_t start=milliseconds();if(start<0)return -1;int64_t deadline=start+4000;
    while(moved<size){
        ssize_t n=writing?write(fd,(char*)buffer+moved,size-moved):read(fd,(char*)buffer+moved,size-moved);
        if(n>0){moved+=(size_t)n;continue;}
        if(n==0)return -1;
        if(errno!=EAGAIN&&errno!=EWOULDBLOCK&&errno!=EINTR)return -1;
        int64_t now=milliseconds();if(now<0||now>=deadline)return -1;
        struct pollfd p={fd,writing?POLLOUT:POLLIN,0};int r=poll(&p,1,(int)(deadline-now));if(r<0&&errno!=EINTR)return -1;
    }return 0;
}
/* owned is cleared only after reap or an unexpected ECHILD. Never signal a PID
 * after ownership is lost. Every signal follows waitpid(child,WNOHANG)==0. */
static int wait_owned(pid_t child,int *status,int terminate,int *owned,int *actually_reaped)
{
    int64_t start=milliseconds(),deadline=start<0?0:start+5000;int failed=0;
    for(;;){
        pid_t r=waitpid(child,status,WNOHANG);
        if(r==child){*owned=0;*actually_reaped=1;return failed?-1:0;}
        if(r<0){if(errno==EINTR)continue;*owned=0;return -1;}
        if(r!=0){*owned=0;return -1;}
        int64_t now=milliseconds();
        if(terminate||now<0||now>=deadline){
            if(!terminate)failed=1;
            if(kill(child,SIGKILL)&&errno!=ESRCH)return -1;
            do{r=waitpid(child,status,0);}while(r<0&&errno==EINTR);
            if(r==child){*owned=0;*actually_reaped=1;}else if(r<0&&errno==ECHILD)*owned=0;
            return r==child&&!failed?0:-1;
        }
        const struct timespec pause={0,10000000};nanosleep(&pause,NULL);
    }
}
#if defined(__linux__)
/* Test-only real procfs inventory, not td_native_operations() support. */
static int linux_inventory(void*c,pid_t pid,struct td_record *out,size_t bytes,int*saved)
{
    (void)c;if(pid!=getpid()||bytes%sizeof(*out)){*saved=EINVAL;return -1;}
    DIR*d=opendir("/proc/self/fd");if(!d){*saved=errno;return -1;}int own=dirfd(d),error=0;size_t n=0,cap=bytes/sizeof(*out);
    if(own<0){error=errno?errno:EIO;goto done;}
    for(;;){errno=0;struct dirent *v=readdir(d);if(!v){error=errno;break;}
        if(!strcmp(v->d_name,".")||!strcmp(v->d_name,".."))continue;
        const char *s=v->d_name;if(!*s){error=EINVAL;break;}for(;*s;s++)if(*s<'0'||*s>'9'){error=EINVAL;break;}if(error)break;
        errno=0;char*end=NULL;long fd=strtol(v->d_name,&end,10);if(errno||!end||*end||fd<0||fd>INT_MAX){error=EOVERFLOW;break;}
        if((int)fd==own)continue;if(n>=cap){error=EOVERFLOW;break;}out[n++]=(struct td_record){(int32_t)fd,0};
    }
 done:
    if(closedir(d)&&!error)error=errno?errno:EIO;
    if(error){*saved=error;return -1;}if(n>INT_MAX/sizeof(*out)){*saved=EOVERFLOW;return -1;}return (int)(n*sizeof(*out));
}
static int real_close(void*c,int fd,int*e){(void)c;int r=close(fd);if(r==-1)*e=errno;return r;}
#endif
struct native_report{int snapshot_result,closure_result;struct td_error closure_error;struct tfo_error error;struct tfo_snapshot snapshot;};
_Static_assert(sizeof(struct native_report)<=512,"bounded atomic test report");
static int native_case(const char *name)
{
    if(getuid()==0||geteuid()==0)return 77;struct rlimit limit;assert(!getrlimit(RLIMIT_NOFILE,&limit));if(limit.rlim_cur<32)return 77;
    /* Ordinary diagnostic writes can set Darwin FWASWRITTEN on a shared
     * fileglob. Establish that test I/O before the full-word flag baselines. */
    static const char banner[]="owned descriptor control starting\n";
    assert(write(1,banner,sizeof(banner)-1)==(ssize_t)(sizeof(banner)-1));
    assert(write(2,banner,sizeof(banner)-1)==(ssize_t)(sizeof(banner)-1));
    struct stat stdio_before[3];int fd_before[3],fl_before[3];for(int i=0;i<3;i++){assert(!fstat(i,&stdio_before[i]));fd_before[i]=fcntl(i,F_GETFD);fl_before[i]=fcntl(i,F_GETFL);assert(fd_before[i]>=0&&fl_before[i]>=0);}
    char directory[]="/tmp/glue-fd-objects-XXXXXX";assert(mkdtemp(directory));char input[256],outpath[256],errpath[256],wrongpath[256];
    assert(snprintf(input,sizeof(input),"%s/input",directory)>0);assert(snprintf(outpath,sizeof(outpath),"%s/stdout",directory)>0);
    assert(snprintf(errpath,sizeof(errpath),"%s/stderr",directory)>0);assert(snprintf(wrongpath,sizeof(wrongpath),"%s/wrong",directory)>0);
    int source[3];source[0]=open(input,O_RDONLY|O_CREAT|O_EXCL|O_CLOEXEC,0600);source[1]=open(outpath,O_WRONLY|O_CREAT|O_EXCL|O_CLOEXEC,0600);source[2]=open(errpath,O_WRONLY|O_CREAT|O_EXCL|O_CLOEXEC,0600);
    for(int i=0;i<3;i++)assert(source[i]>=3);
    int wrong=open(wrongpath,O_WRONLY|O_CREAT|O_EXCL|O_CLOEXEC,0600);assert(wrong>=3);int sentinel=open(input,O_RDONLY|O_CLOEXEC);assert(sentinel>=3);
    int gate[2],channel[2];assert(!pipe(gate)&&!pipe(channel));for(int i=0;i<2;i++){int g=fcntl(gate[i],F_GETFL),s=fcntl(channel[i],F_GETFL);assert(g>=0&&s>=0);assert(!fcntl(gate[i],F_SETFL,g|O_NONBLOCK)&&!fcntl(channel[i],F_SETFL,s|O_NONBLOCK));}
    struct te_request request={{source[0],source[1],source[2],gate[0],channel[1]}};struct te_prepared prepared;struct te_error te;
    assert(!te_prepare_owned_sources(&request,te_native_operations(),&prepared,&te));
    struct td_record scratch[TD_MAX_CAPACITY];struct td_plan selected={{0,1,2,prepared.copies[3],prepared.copies[4]},scratch,TD_MAX_CAPACITY};
    struct tfo_plan selection={{0,1,2,prepared.copies[3],prepared.copies[4]}};
    struct sigaction saved_pipe;memset(&saved_pipe,0,sizeof(saved_pipe));
    sigset_t blocked,oldmask;assert(!sigfillset(&blocked)&&!sigprocmask(SIG_SETMASK,&blocked,&oldmask));pid_t owner=getpid(),child=fork();assert(child>=0);
    if(child==0){
        struct native_report r;memset(&r,0,sizeof(r));assert(!te_map_in_owned_child(&prepared,(uint64_t)owner,te_native_operations(),&te));
        const struct td_operations *td=td_native_operations();
#if defined(__linux__)
        assert(!td->supported);const struct tfo_operations *native=tfo_native_operations();
        struct td_operations linux_ops={1,NULL,native->getpid_fn,native->getppid_fn,native->signals_blocked_fn,linux_inventory,real_close};td=&linux_ops;
#endif
        r.closure_result=td_close_in_owned_child(&selected,(uint64_t)owner,td,&r.closure_error);assert(!r.closure_result);
        errno=0;assert(fcntl(sentinel,F_GETFD)==-1&&errno==EBADF);
        if(!strcmp(name,"native-missing"))assert(!close(1));
        r.snapshot_result=tfo_snapshot_in_owned_child(&selection,(uint64_t)owner,tfo_native_operations(),&r.snapshot,&r.error);
        if(transfer(selection.keep[4],&r,sizeof(r),1))_exit(5);
        if(!strcmp(name,"native-child-exits-before-go"))_exit(0);
        if(r.snapshot_result)_exit(!strcmp(name,"native-missing")?0:3);
        char go=0;if(transfer(selection.keep[3],&go,1,0)||go!='G')_exit(4);
        assert(write(1,"objects-out\n",12)==12&&write(2,"objects-err\n",12)==12);_exit(0);
    }
    int failed_parent=0,cleanup_failed=0,owned=1,actually_reaped=0,status=0,independent=-1,read_fd=-1,matched=-1,go_attempted=0;
    int expected_ebadf=0,go_errno=0,pipe_policy_set=0,pipe_policy_restored=0;
    int forced_read_case=!strcmp(name,"native-parent-read-failure")||!strcmp(name,"native-parent-unrelated-failure")||!strcmp(name,"native-parent-cleanup-failure")||!strcmp(name,"native-parent-ownership-loss");
    struct native_report r;memset(&r,0,sizeof(r));
    struct tfo_matches matches;struct tfo_error error;memset(&matches,0,sizeof(matches));memset(&error,0,sizeof(error));
#define PARENT_REQUIRE(condition) do {if(!(condition)){fprintf(stderr,"parent check failed at line %d\n",__LINE__);failed_parent=1;goto parent_cleanup;}}while(0)
#define PARENT_CLOSE(descriptor) do {int closing=(descriptor);(descriptor)=-1;PARENT_REQUIRE(close(closing)==0);}while(0)
    /* Parent-only policy, installed while blocked and restored after cleanup.
     * An exited child must produce EPIPE, never terminate this controller. */
    struct sigaction ignored;memset(&ignored,0,sizeof(ignored));ignored.sa_handler=SIG_IGN;
    PARENT_REQUIRE(!sigemptyset(&ignored.sa_mask));
    PARENT_REQUIRE(!sigaction(SIGPIPE,&ignored,&saved_pipe));pipe_policy_set=1;
    PARENT_REQUIRE(!sigprocmask(SIG_SETMASK,&oldmask,NULL));
    PARENT_CLOSE(gate[0]);PARENT_CLOSE(channel[1]);
    for(unsigned i=0;i<5;i++)PARENT_CLOSE(prepared.copies[i]);
    if(forced_read_case){
        PARENT_CLOSE(channel[0]);errno=0;int read_result=transfer(channel[0],&r,sizeof(r),0),read_errno=errno;
        expected_ebadf=read_result==-1&&read_errno==EBADF;PARENT_REQUIRE(expected_ebadf);
        if(!strcmp(name,"native-parent-unrelated-failure"))PARENT_REQUIRE(0);
        goto parent_cleanup;
    }
    PARENT_REQUIRE(!transfer(channel[0],&r,sizeof(r),0));
    int held[2]={source[1],source[2]};
    if(!strcmp(name,"native-reopened")){independent=open(outpath,O_WRONLY|O_CLOEXEC);PARENT_REQUIRE(independent>=3);held[0]=independent;}
    if(!strcmp(name,"native-mismatch"))held[0]=wrong;
    if(!r.snapshot_result)matched=tfo_match_regular_outputs(&r.snapshot,held,tfo_native_operations(),&matches,&error);
    if(!strcmp(name,"native-mismatch")){
        PARENT_REQUIRE(!r.snapshot_result&&r.snapshot.ready);
        PARENT_REQUIRE(matched==-1&&error.reason==TFO_REASON_MISMATCH&&!matches.ready);
        PARENT_REQUIRE(!wait_owned(child,&status,1,&owned,&actually_reaped));
        PARENT_REQUIRE(WIFSIGNALED(status)&&WTERMSIG(status)==SIGKILL);
    }else if(!strcmp(name,"native-missing")){
        PARENT_REQUIRE(r.snapshot_result==-1&&r.error.reason==TFO_REASON_SYSCALL&&r.error.system_errno==EBADF&&!r.snapshot.ready);
        PARENT_REQUIRE(!wait_owned(child,&status,0,&owned,&actually_reaped));PARENT_REQUIRE(WIFEXITED(status)&&WEXITSTATUS(status)==0);
    }else{
        PARENT_REQUIRE(!r.snapshot_result&&!matched&&matches.ready);
        PARENT_REQUIRE(matches.outputs[0].child_descriptor_flags==0&&(matches.outputs[0].controller_descriptor_flags&FD_CLOEXEC));
        if(!strcmp(name,"native-child-exits-before-go"))PARENT_REQUIRE(!wait_owned(child,&status,0,&owned,&actually_reaped));
        char go='G';go_attempted=1;errno=0;int written=transfer(gate[1],&go,1,1);go_errno=written?errno:0;PARENT_REQUIRE(!written);
        PARENT_REQUIRE(!wait_owned(child,&status,0,&owned,&actually_reaped)&&WIFEXITED(status)&&WEXITSTATUS(status)==0);
        read_fd=open(outpath,O_RDONLY);char bytes[16]={0};PARENT_REQUIRE(read_fd>=3);
        PARENT_REQUIRE(read(read_fd,bytes,sizeof(bytes))==12&&!memcmp(bytes,"objects-out\n",12));PARENT_CLOSE(read_fd);
        read_fd=open(errpath,O_RDONLY);memset(bytes,0,sizeof(bytes));PARENT_REQUIRE(read_fd>=3);
        PARENT_REQUIRE(read(read_fd,bytes,sizeof(bytes))==12&&!memcmp(bytes,"objects-err\n",12));PARENT_CLOSE(read_fd);
    }
    for(int i=0;i<3;i++){
        struct stat after;PARENT_REQUIRE(!fstat(i,&after)&&after.st_dev==stdio_before[i].st_dev&&after.st_ino==stdio_before[i].st_ino);
        PARENT_REQUIRE(fcntl(i,F_GETFD)==fd_before[i]&&fcntl(i,F_GETFL)==fl_before[i]);
    }
    struct rlimit after;PARENT_REQUIRE(!getrlimit(RLIMIT_NOFILE,&after)&&after.rlim_cur==limit.rlim_cur&&after.rlim_max==limit.rlim_max);
    PARENT_REQUIRE(fcntl(sentinel,F_GETFD)>=0);
#if defined(__APPLE__)
    puts("closure_adapter=Darwin_libproc_native");
#elif defined(__linux__)
    puts("closure_adapter=Linux_test_only_procfs production_TD_native_supported=0");
#endif
    printf("%s: actual_child_snapshot=%d conditional_backing_match=%d production_adoption=0 parent_stdio_limits_unchanged=1\n",name,r.snapshot_result,matched);
    if(!r.snapshot_result)for(unsigned i=0;i<5;i++)printf("fd=%d device=%llu inode=%llu mode=%u links=%llu fdflags=%d statusflags=%d\n",r.snapshot.entries[i].fd,(unsigned long long)r.snapshot.entries[i].backing.device,(unsigned long long)r.snapshot.entries[i].backing.inode,r.snapshot.entries[i].backing.mode,(unsigned long long)r.snapshot.entries[i].backing.links,r.snapshot.entries[i].descriptor_flags,r.snapshot.entries[i].status_flags);
 parent_cleanup:
    if(!strcmp(name,"native-parent-ownership-loss")){
        /* Test a stale ownership claim after another successful wait consumed
         * the child. The next actual wait must report ECHILD, never a reap. */
        int other_reap=0;
        if(wait_owned(child,&status,1,&owned,&other_reap)||!other_reap)cleanup_failed=1;
        else owned=1;
    }
    if(owned&&wait_owned(child,&status,1,&owned,&actually_reaped))cleanup_failed=1;
    if(independent>=0&&close(independent))cleanup_failed=1;if(read_fd>=0&&close(read_fd))cleanup_failed=1;
    for(unsigned i=0;i<5;i++)if(prepared.copies[i]>=0&&close(prepared.copies[i]))cleanup_failed=1;
    for(int i=0;i<3;i++)if(close(source[i]))cleanup_failed=1;
    if(close(wrong))cleanup_failed=1;if(close(sentinel))cleanup_failed=1;
    for(int i=0;i<2;i++){if(gate[i]>=0&&close(gate[i]))cleanup_failed=1;if(channel[i]>=0&&close(channel[i]))cleanup_failed=1;}
    if(unlink(input))cleanup_failed=1;if(unlink(outpath))cleanup_failed=1;
    if(unlink(errpath))cleanup_failed=1;if(unlink(wrongpath))cleanup_failed=1;if(rmdir(directory))cleanup_failed=1;
    /* Exercise a genuine cleanup syscall failure after all owned paths are gone. */
    if(!strcmp(name,"native-parent-cleanup-failure")&&rmdir(directory))cleanup_failed=1;
    if(pipe_policy_set){if(sigaction(SIGPIPE,&saved_pipe,NULL))cleanup_failed=1;else pipe_policy_restored=1;}
#undef PARENT_CLOSE
#undef PARENT_REQUIRE
    if(forced_read_case){
        int invariant_failed=0;struct rlimit unchanged;
        if(getrlimit(RLIMIT_NOFILE,&unchanged)||unchanged.rlim_cur!=limit.rlim_cur||unchanged.rlim_max!=limit.rlim_max)invariant_failed=1;
        for(int i=0;i<3;i++){struct stat st;int a=fstat(i,&st),b=fcntl(i,F_GETFD),c=fcntl(i,F_GETFL);if(a||st.st_dev!=stdio_before[i].st_dev||st.st_ino!=stdio_before[i].st_ino||b!=fd_before[i]||c!=fl_before[i])invariant_failed=1;}
        printf("forced_read_failure: exact_EBADF=%d other_parent_failure=%d actual_child_reap=%d cleanup_failure=%d invariants_failure=%d GO_attempted=%d SIGPIPE_restored=%d\n",expected_ebadf,failed_parent,actually_reaped,cleanup_failed,invariant_failed,go_attempted,pipe_policy_restored);
        if(expected_ebadf&&!failed_parent&&!owned&&actually_reaped&&!cleanup_failed&&!invariant_failed&&!go_attempted&&pipe_policy_restored){
            puts("expected_parent_read_failure=1 child_reaped=1 GO_attempted=0 parent_stdio_limits_unchanged=1");return 0;
        }
        return 1;
    }
    if(!strcmp(name,"native-child-exits-before-go"))
        printf("exited_before_GO: EPIPE=%d actual_child_reap=%d cleanup_failure=%d SIGPIPE_restored=%d\n",go_errno==EPIPE,actually_reaped,cleanup_failed,pipe_policy_restored);
    return failed_parent||cleanup_failed||owned||!actually_reaped||!pipe_policy_restored?1:0;
}

int main(int argc,char**argv)
{
    assert(argc==2);if(!strncmp(argv[1],"native-",7)){
        if(strcmp(argv[1],"native-basic")&&strcmp(argv[1],"native-reopened")&&strcmp(argv[1],"native-mismatch")&&strcmp(argv[1],"native-missing")&&strcmp(argv[1],"native-parent-read-failure")&&strcmp(argv[1],"native-parent-unrelated-failure")&&strcmp(argv[1],"native-parent-cleanup-failure")&&strcmp(argv[1],"native-parent-ownership-loss")&&strcmp(argv[1],"native-child-exits-before-go"))return 2;
        return native_case(argv[1]);
    }
    const struct{const char*name;void(*run)(void);} cases[]={
        {"success",success},{"plans",plans},{"callbacks",callbacks},{"owner-masks",owner_masks},
        {"errors",errors},{"changes",changes},{"final-guards",final_guards},{"match-errors",match_errors},{"match-shapes",match_shapes},
        {"match-preflight",match_preflight},{"stale-errno-flags",stale_errno_flags}};
    for(unsigned i=0;i<sizeof(cases)/sizeof(cases[0]);i++)if(!strcmp(argv[1],cases[i].name)){cases[i].run();puts(cases[i].name);return 0;}return 2;
}
