#ifndef _GNU_SOURCE
#define _GNU_SOURCE 1
#endif
#include "target_cwd.h"
#include "../target-descriptors/target_descriptors.h"
#include <assert.h>
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/resource.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

struct model {
    pid_t self,parent;
    int reads,fail_at,bad,saved,changed,change_at,field,shadow;
    int pid_calls,parent_calls,mask_calls,pid_fail,parent_fail,mask_fail;
    int mask,guard_calls,guard_at,guard_result,guard_errno;
    struct tcwd_backing backing;
};
static struct model model(void)
{
    struct model m;memset(&m,0,sizeof(m));
    m.self=222;m.parent=111;m.mask=1;m.bad=-1;m.saved=EIO;
    m.guard_result=-1;m.backing=(struct tcwd_backing){9,88,2,S_IFDIR|0700,501,20};return m;
}
static int tick(struct model *m,int *e){m->reads++;*e=m->saved;return m->reads==m->fail_at;}
static pid_t mpid(void *c){struct model *m=c;m->pid_calls++;return m->pid_fail==m->pid_calls?333:m->self;}
static pid_t mppid(void *c){struct model *m=c;m->parent_calls++;return m->parent_fail==m->parent_calls?333:m->parent;}
static int mmask(void *c,int *e){struct model *m=c;m->mask_calls++;*e=m->saved;return m->mask_fail==m->mask_calls?0:m->mask;}
static int mstat(void *c,int fd,struct tcwd_backing *out,int *e)
{
    struct model *m=c;assert(fd==7);
    if(tick(m,e))return m->bad;
    *out=m->backing;
    if(m->change_at&&m->reads>=m->change_at){
        switch(m->field){case 1:out->device++;break;case 2:out->inode++;break;case 3:out->links++;break;
            case 4:out->mode^=0040;break;case 5:out->uid++;break;case 6:out->gid++;break;}
    }
    return 0;
}
static int mfd(void *c,int fd,int *e)
{
    struct model *m=c;assert(fd==7);
    if(tick(m,e))return m->bad;
    return FD_CLOEXEC|(m->field==7&&m->reads>=m->change_at?0x100:0);
}
static int mfl(void *c,int fd,int *e)
{
    struct model *m=c;assert(fd==7);
    if(tick(m,e))return m->bad;
    return O_RDONLY|O_NONBLOCK|(m->field==8&&m->reads>=m->change_at?O_APPEND:0);
}
static int mchange(void *c,int fd,int *e)
{
    struct model *m=c;assert(fd==7);
    if(tick(m,e))return m->bad;
    m->changed=1;return 0;
}
static int mcwd(void *c,struct tcwd_backing *out,int *e)
{
    struct model *m=c;
    if(tick(m,e))return m->bad;
    *out=m->backing;
    if(m->shadow)out->inode++;
    return 0;
}
static int before(void *c,int *e)
{
    struct model *m=c;m->guard_calls++;*e=m->guard_errno;
    return m->guard_calls==m->guard_at?m->guard_result:0;
}
static struct tcwd_operations operations(struct model *m)
{return (struct tcwd_operations){1,m,mpid,mppid,mmask,mstat,mfd,mfl,mchange,mcwd};}
static int select_model(struct model *m,struct tcwd_result *out,struct tcwd_error *e)
{
    struct tcwd_operations o=operations(m);struct tcwd_guard g={m,before};
    struct tcwd_request r={7,9,88};return tcwd_select_in_owned_child(&r,111,&o,&g,out,e);
}
static void empty(const struct tcwd_result *r)
{assert(!r->ready&&!r->controller_pid&&!r->child_pid&&r->before.fd==-1&&r->after.fd==-1&&!r->cwd.inode);}
static void success(void)
{
    struct model m=model();struct tcwd_result r;struct tcwd_error e;
    assert(!select_model(&m,&r,&e)&&r.ready&&m.changed&&m.reads==11&&m.guard_calls==6);
    assert(m.pid_calls==3&&m.parent_calls==3&&m.mask_calls==3);
    assert(r.controller_pid==111&&r.child_pid==222&&r.before.fd==7&&r.after.fd==7);
    assert(r.before.descriptor_flags==FD_CLOEXEC&&r.before.status_flags==(O_RDONLY|O_NONBLOCK));
    assert(!memcmp(&r.before,&r.after,sizeof(r.before))&&r.cwd.inode==88);
    assert(e.mutation_attempted==1&&e.reason==TCWD_REASON_NONE&&!e.system_errno);
}
static void requests(void)
{
    struct model m=model();struct tcwd_operations o=operations(&m);struct tcwd_guard g={&m,before};
    struct tcwd_request request={7,9,88};struct tcwd_result out;struct tcwd_error e;
    memset(&out,1,sizeof(out));assert(tcwd_select_in_owned_child(NULL,111,&o,&g,&out,&e)==-1);empty(&out);
    assert(tcwd_select_in_owned_child(&request,111,&o,&g,&out,NULL)==-1);empty(&out);
    assert(tcwd_select_in_owned_child(&request,111,&o,&g,NULL,&e)==-1);
    for(int fd=-1;fd<3;fd++){request.directory_fd=fd;assert(tcwd_select_in_owned_child(&request,111,&o,&g,&out,&e)==-1&&!e.mutation_attempted);empty(&out);}
    request.directory_fd=7;
    assert(tcwd_select_in_owned_child(&request,0,&o,&g,&out,&e)==-1);
    assert(tcwd_select_in_owned_child(&request,(uint64_t)INT_MAX+1,&o,&g,&out,&e)==-1);
    assert(!m.reads&&!m.changed&&!m.guard_calls);
    request.inode++;
    assert(tcwd_select_in_owned_child(&request,111,&o,&g,&out,&e)==-1&&e.reason==TCWD_REASON_MISMATCH&&!e.mutation_attempted);empty(&out);
}
static void operation_contract(void)
{
    for(int field=0;field<10;field++){
        struct model m=model();struct tcwd_operations o=operations(&m);struct tcwd_guard g={&m,before};
        struct tcwd_request q={7,9,88};struct tcwd_result r;struct tcwd_error e;
        switch(field){case 0:o.getpid_fn=NULL;break;case 1:o.getppid_fn=NULL;break;case 2:o.signals_blocked_fn=NULL;break;
            case 3:o.stat_fn=NULL;break;case 4:o.getfd_fn=NULL;break;case 5:o.getfl_fn=NULL;break;case 6:o.change_fn=NULL;break;
            case 7:o.cwd_fn=NULL;break;case 8:o.supported=2;break;case 9:g.before_fn=NULL;break;}
        assert(tcwd_select_in_owned_child(&q,111,&o,&g,&r,&e)==-1&&!m.reads&&!m.changed);empty(&r);
    }
    struct model m=model();struct tcwd_operations o=operations(&m);o.supported=0;
    struct tcwd_guard g={&m,before};struct tcwd_request q={7,9,88};struct tcwd_result r;struct tcwd_error e;
    assert(tcwd_select_in_owned_child(&q,111,&o,&g,&r,&e)==-1&&e.system_errno==ENOTSUP&&!m.changed);
}
static void owners(void)
{
    for(int which=0;which<4;which++){
        struct model m=model();struct tcwd_result r;struct tcwd_error e;
        if(which==0)m.self=111;
        if(which==1)m.parent=333;
        if(which==2)m.self=0;
        if(which==3)m.parent=0;
        assert(select_model(&m,&r,&e)==-1&&e.reason==TCWD_REASON_NOT_OWNED_CHILD&&!m.reads&&!m.changed);empty(&r);
    }
}
static void masks(void)
{
    for(int mask=-2;mask<=2;mask++){
        if(mask==1)continue;
        struct model m=model();struct tcwd_result r;struct tcwd_error e;m.mask=mask;
        assert(select_model(&m,&r,&e)==-1&&!e.mutation_attempted&&!m.changed);empty(&r);
        assert(e.reason==(mask==0?TCWD_REASON_SIGNALS_UNBLOCKED:mask==-1?TCWD_REASON_SYSCALL:TCWD_REASON_ADAPTER));
    }
}
static void failures(void)
{
    for(int call=1;call<=11;call++){
        struct model m=model();struct tcwd_result r;struct tcwd_error e;m.fail_at=call;
        assert(select_model(&m,&r,&e)==-1&&m.reads==call&&e.reason==TCWD_REASON_SYSCALL&&e.system_errno==EIO);
        assert(e.mutation_attempted==(call>=7));assert(m.changed==(call>7));empty(&r);
    }
}
static void adapters(void)
{
    const int calls[]={1,7,11};
    for(unsigned i=0;i<3;i++)for(int bad_return=-2;bad_return<=1;bad_return++){
        if(bad_return==0||bad_return==-1)continue;
        struct model m=model();struct tcwd_result r;struct tcwd_error e;m.fail_at=calls[i];m.bad=bad_return;
        assert(select_model(&m,&r,&e)==-1&&e.reason==TCWD_REASON_ADAPTER&&!e.system_errno);empty(&r);
    }
    for(int call=1;call<=11;call++){
        struct model m=model();struct tcwd_result r;struct tcwd_error e;m.fail_at=call;m.saved=0;
        assert(select_model(&m,&r,&e)==-1&&e.reason==TCWD_REASON_ADAPTER&&!e.system_errno);empty(&r);
    }
}
static void changes(void)
{
    for(int field=1;field<=8;field++)for(int phase=0;phase<2;phase++){
        struct model m=model();struct tcwd_result r;struct tcwd_error e;m.field=field;m.change_at=phase?8:4;
        assert(select_model(&m,&r,&e)==-1&&e.reason==TCWD_REASON_CHANGED&&e.mutation_attempted==phase);
        assert(m.changed==phase);empty(&r);
    }
    struct model m=model();struct tcwd_result r;struct tcwd_error e;m.backing.mode=S_IFREG|0600;
    assert(select_model(&m,&r,&e)==-1&&e.reason==TCWD_REASON_NOT_DIRECTORY&&!e.mutation_attempted);
}
static void shadows(void)
{
    struct model m=model();struct tcwd_result r;struct tcwd_error e;m.shadow=1;
    assert(select_model(&m,&r,&e)==-1&&e.stage==TCWD_STAGE_READBACK&&e.reason==TCWD_REASON_MISMATCH&&e.mutation_attempted&&m.changed);empty(&r);
}
static void deadlines(void)
{
    for(int call=1;call<=6;call++){
        struct model m=model();struct tcwd_result r;struct tcwd_error e;m.guard_at=call;
        assert(select_model(&m,&r,&e)==-1&&m.guard_calls==call&&e.reason==TCWD_REASON_DEADLINE);
        assert(e.mutation_attempted==(call>=4)&&m.changed==(call>=4));empty(&r);
    }
    const int results[]={1,-2,-1};
    for(unsigned i=0;i<3;i++){
        struct model m=model();struct tcwd_result r;struct tcwd_error e;m.guard_at=1;m.guard_result=results[i];m.guard_errno=i==2?-1:0;
        assert(select_model(&m,&r,&e)==-1&&e.reason==TCWD_REASON_ADAPTER&&!m.changed);empty(&r);
    }
    struct model m=model();struct tcwd_result r;struct tcwd_error e;m.guard_at=4;m.guard_errno=EIO;
    assert(select_model(&m,&r,&e)==-1&&e.reason==TCWD_REASON_SYSCALL&&e.system_errno==EIO&&e.mutation_attempted&&m.changed);
}
static void final_guards(void)
{
    for(int phase=2;phase<=3;phase++)for(int field=0;field<3;field++){
        struct model m=model();struct tcwd_result r;struct tcwd_error e;
        if(field==0)m.pid_fail=phase;
        if(field==1)m.parent_fail=phase;
        if(field==2)m.mask_fail=phase;
        assert(select_model(&m,&r,&e)==-1&&e.mutation_attempted==(phase==3)&&m.changed==(phase==3));empty(&r);
    }
}
static void details(void)
{
    struct tcwd_error e={TCWD_STAGE_READBACK,TCWD_REASON_SYSCALL,EIO,1};
    assert(tcwd_error_detail(&e)==(TCWD_STAGE_READBACK|TCWD_MUTATION_DETAIL));
    e.mutation_attempted=0;assert(tcwd_error_detail(&e)==TCWD_STAGE_READBACK);
    e.mutation_attempted=2;assert(tcwd_error_detail(&e)==-1);
    assert(tcwd_error_detail(NULL)==-1);
    assert(!strcmp(tcwd_stage_name(TCWD_STAGE_CHANGE),"change")&&!strcmp(tcwd_reason_name(TCWD_REASON_DEADLINE),"deadline"));
    assert(!strcmp(tcwd_stage_name((enum tcwd_stage)-1),"unknown")&&!strcmp(tcwd_reason_name((enum tcwd_reason)-1),"unknown"));
}

static uint64_t now(void)
{struct timespec t;assert(!clock_gettime(CLOCK_MONOTONIC,&t));return (uint64_t)t.tv_sec*1000000000+(uint64_t)t.tv_nsec;}
struct real_context {const struct tcwd_operations *native;uint64_t deadline,last;int mode,changed;};
static int real_before(void *c,int *e)
{
    struct real_context *m=c;uint64_t n=now();
    if(n<m->last){*e=-1;return -1;}
    m->last=n;
    if(n>=m->deadline||(m->mode==7&&m->changed)){*e=0;return -1;}
    return 0;
}
static int real_change(void *c,int fd,int *e)
{struct real_context *m=c;int r=m->native->change_fn(NULL,fd,e);if(!r)m->changed=1;return r;}
static int real_cwd(void *c,struct tcwd_backing *out,int *e)
{struct real_context *m=c;if(m->mode==6){*e=EIO;return -1;}return m->native->cwd_fn(NULL,out,e);}
static uint64_t device(const struct stat *s)
{
#if defined(__APPLE__)
    return (uint64_t)(uint32_t)s->st_dev;
#else
    return (uint64_t)s->st_dev;
#endif
}
static int reap(pid_t child,int *status)
{
    uint64_t deadline=now()+UINT64_C(5000000000);
    for(;;){
        pid_t r=waitpid(child,status,WNOHANG);
        if(r==child)return 0;
        if(r<0){if(errno==EINTR)continue;return -1;}
        assert(r==0);
        if(now()>=deadline){assert(!kill(child,SIGKILL)||errno==ESRCH);do{r=waitpid(child,status,0);}while(r<0&&errno==EINTR);return -1;}
        struct timespec pause={0,10000000};nanosleep(&pause,NULL);
    }
}
struct report {int rc,ready,attempt,reason,stage,saved,cwd_original,fd_usable,fd_closed,changed,skip;};
static int native_case(int mode)
{
    if(getuid()==0||geteuid()==0)return 77;
    struct rlimit limit;assert(!getrlimit(RLIMIT_NOFILE,&limit));
    if(limit.rlim_cur<32)return 77;
    if(mode==8&&!td_native_operations()->supported)return 77;
    struct stat parent_before,held,replacement;assert(!stat(".",&parent_before));
    char root[]="/tmp/glue-held-cwd-XXXXXX";assert(mkdtemp(root));
    char path[256],renamed[256],wrong[256],file[256];
    assert(snprintf(path,sizeof(path),"%s/held",root)>0&&snprintf(renamed,sizeof(renamed),"%s/original",root)>0);
    assert(snprintf(wrong,sizeof(wrong),"%s/wrong",root)>0&&snprintf(file,sizeof(file),"%s/file",root)>0);
    assert(!mkdir(path,0700)&&!mkdir(wrong,0700));
    int fd=open(path,O_RDONLY|O_DIRECTORY|O_NOFOLLOW|O_CLOEXEC),other=open(wrong,O_RDONLY|O_DIRECTORY|O_NOFOLLOW|O_CLOEXEC);
    int regular=open(file,O_WRONLY|O_CREAT|O_EXCL|O_CLOEXEC,0600);assert(fd>=3&&other>=3&&regular>=3);
    assert(!fstat(fd,&held));int fdflags=fcntl(fd,F_GETFD),statusflags=fcntl(fd,F_GETFL);assert(fdflags>=0&&statusflags>=0);
    if(mode==1){assert(!rename(path,renamed)&&!mkdir(path,0700)&&!stat(path,&replacement));assert(replacement.st_ino!=held.st_ino||replacement.st_dev!=held.st_dev);}
    if(mode==5)assert(!chmod(path,0000));
    int gate[2],channel[2];assert(!pipe(gate)&&!pipe(channel));
    sigset_t blocked,old;assert(!sigfillset(&blocked)&&!sigprocmask(SIG_SETMASK,&blocked,&old));pid_t owner=getpid(),child=fork();assert(child>=0);
    if(child==0){
        struct report report;memset(&report,0,sizeof(report));int selected=mode==2?other:mode==4?regular:fd;
        if(mode==3)assert(!close(fd));
        struct real_context context={tcwd_native_operations(),now()+UINT64_C(2000000000),0,mode,0};
        struct tcwd_operations operations=*context.native;operations.context=&context;operations.change_fn=real_change;operations.cwd_fn=real_cwd;
        struct tcwd_guard guard={&context,real_before};struct tcwd_request request={selected,device(&held),(uint64_t)held.st_ino};
        struct tcwd_result result;struct tcwd_error error;
        report.rc=tcwd_select_in_owned_child(&request,(uint64_t)owner,&operations,&guard,&result,&error);
        report.ready=result.ready;report.attempt=error.mutation_attempted;report.reason=error.reason;report.stage=error.stage;report.saved=error.system_errno;report.changed=context.changed;
        struct stat cwd;assert(!stat(".",&cwd));report.cwd_original=cwd.st_dev==held.st_dev&&cwd.st_ino==held.st_ino;
        if(mode!=3)report.fd_usable=fcntl(fd,F_GETFD)==fdflags&&fcntl(fd,F_GETFL)==statusflags;
        if(mode==8){
            assert(!report.rc&&report.ready&&report.fd_usable);
            struct td_record scratch[TD_MAX_CAPACITY];struct td_plan plan={{0,1,2,gate[0],channel[1]},scratch,TD_MAX_CAPACITY};struct td_error te;
            assert(!td_close_in_owned_child(&plan,(uint64_t)owner,td_native_operations(),&te));
            errno=0;report.fd_closed=fcntl(fd,F_GETFD)==-1&&errno==EBADF;assert(!stat(".",&cwd));
            assert(cwd.st_dev==held.st_dev&&cwd.st_ino==held.st_ino);
        }
        if(mode==5&&report.rc==0)report.skip=1;
        assert(write(channel[1],&report,sizeof(report))==(ssize_t)sizeof(report));_exit(0);
    }
    assert(!sigprocmask(SIG_SETMASK,&old,NULL));assert(!close(channel[1]));
    int status=0;assert(!reap(child,&status)&&WIFEXITED(status)&&WEXITSTATUS(status)==0);
    struct report report;assert(read(channel[0],&report,sizeof(report))==(ssize_t)sizeof(report));
    struct stat parent_after;assert(!stat(".",&parent_after));assert(parent_before.st_dev==parent_after.st_dev&&parent_before.st_ino==parent_after.st_ino);
    assert(fcntl(fd,F_GETFD)==fdflags&&fcntl(fd,F_GETFL)==statusflags);
    if(!report.skip){
        if(mode==1||mode==8)assert(report.rc==0&&report.ready&&report.attempt&&report.changed&&report.cwd_original&&report.fd_usable);
        else if(mode==2)assert(report.rc==-1&&!report.ready&&!report.attempt&&!report.changed&&report.reason==TCWD_REASON_MISMATCH&&!report.cwd_original);
        else if(mode==3)assert(report.rc==-1&&!report.ready&&!report.attempt&&report.saved==EBADF&&!report.changed);
        else if(mode==4)assert(report.rc==-1&&!report.ready&&!report.attempt&&report.reason==TCWD_REASON_NOT_DIRECTORY&&!report.changed);
        else if(mode==5)assert(report.rc==-1&&!report.ready&&report.attempt&&report.saved==EACCES&&!report.changed&&!report.cwd_original);
        else if(mode==6)assert(report.rc==-1&&!report.ready&&report.attempt&&report.saved==EIO&&report.changed&&report.cwd_original&&report.fd_usable);
        else if(mode==7)assert(report.rc==-1&&!report.ready&&report.attempt&&report.reason==TCWD_REASON_DEADLINE&&report.changed&&report.cwd_original&&report.fd_usable);
        if(mode==8)assert(report.fd_closed);
    }
    assert(!close(fd)&&!close(other)&&!close(regular)&&!close(gate[0])&&!close(gate[1])&&!close(channel[0]));
    if(mode==5)assert(!chmod(path,0700));
    assert(!rmdir(path)&&!rmdir(wrong)&&!unlink(file));
    if(mode==1)assert(!rmdir(renamed));
    assert(!rmdir(root));
    printf("native mode=%d actual_fchdir=%d child_cwd_original=%d parent_cwd_unchanged=1 borrowed_flags_unchanged=%d TD_closed_fd=%d injected_readback=%d injected_late=%d\n",mode,report.changed,report.cwd_original,report.fd_usable,report.fd_closed,mode==6,mode==7);
    return report.skip?77:0;
}
int main(int argc,char **argv)
{
    assert(argc==2);
    if(!strncmp(argv[1],"native-",7))return native_case(atoi(argv[1]+7));
    const struct {const char *name;void(*run)(void);} cases[]={
        {"success",success},{"requests",requests},{"operations",operation_contract},{"owners",owners},
        {"masks",masks},{"failures",failures},{"adapters",adapters},{"changes",changes},{"shadows",shadows},
        {"deadlines",deadlines},{"final-guards",final_guards},{"details",details}};
    for(unsigned i=0;i<sizeof(cases)/sizeof(cases[0]);i++){
        if(!strcmp(argv[1],cases[i].name)){cases[i].run();puts("model-only held-CWD guard/fault control");return 0;}
    }
    return 2;
}
