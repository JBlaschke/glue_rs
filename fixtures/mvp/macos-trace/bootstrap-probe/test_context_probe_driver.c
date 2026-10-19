#define _POSIX_C_SOURCE 200809L
#define _DARWIN_C_SOURCE 1
#include <errno.h>
#include <fcntl.h>
#include <signal.h>
#include <stdlib.h>
#include <string.h>
#include <sys/resource.h>
#include <unistd.h>
/* Source-isolated ordinary-user test setup. No fork, credentials, callback
 * injection or native probe bypass. This private process execs only the probe
 * supplied by the Python test's just-built binary path, with closed modes. */
int main(int argc,char **argv) {
#if !defined(__APPLE__)
    (void)argc;(void)argv;return 77;
#else
    if(argc!=4||!getuid()||!geteuid()||!getgid()||!getegid())return 77;
    const char *modes[]={"positive","extra-fd","high-fd","nonblock","wrong-direction","closed-stdin","ignored-pipe","blocked-mask"};
    int known=0;for(size_t i=0;i<sizeof(modes)/sizeof(modes[0]);i++)if(!strcmp(argv[2],modes[i]))known=1;
    if(!known)return 2;
    if(getpgrp()!=getpid())return 2;
    sigset_t empty;if(sigemptyset(&empty)||sigprocmask(SIG_SETMASK,&empty,NULL))return 2;
    struct sigaction action;memset(&action,0,sizeof(action));action.sa_handler=SIG_DFL;
    if(sigemptyset(&action.sa_mask))return 2;
    for(int s=1;s<NSIG;s++)if(s!=SIGKILL&&s!=SIGSTOP&&sigaction(s,&action,NULL))return 2;
    /* Darwin UNIX2003 validates size even for SS_DISABLE; NULL storage is
     * never activated. Match the reviewed native-signal workaround. */
    stack_t stack;memset(&stack,0,sizeof(stack));stack.ss_flags=SS_DISABLE;stack.ss_size=SIGSTKSZ;
    if(sigaltstack(&stack,NULL))return 2;
    if(!strcmp(argv[2],"extra-fd")) {if(open("/dev/null",O_RDONLY)<3)return 2;}
    if(!strcmp(argv[2],"high-fd")) {
        struct rlimit limit;if(getrlimit(RLIMIT_NOFILE,&limit))return 2;
        if(limit.rlim_cur<=4096)return 77; /* Never raise any limit. */
        if(fcntl(0,F_DUPFD,4096)<4096)return 2;
    }
    if(!strcmp(argv[2],"nonblock")) {
        /* stdout is this subprocess's private pipe write end. Its parent owns
         * only the distinct read end, never an OFD alias to these flags. */
        int flags=fcntl(1,F_GETFL);if(flags<0||fcntl(1,F_SETFL,flags|O_NONBLOCK))return 2;
    }
    if(!strcmp(argv[2],"wrong-direction")) {
        int fd=open("/dev/null",O_WRONLY);if(fd<0)return 2;
        if(dup2(fd,0)!=0)return 2;if(fd>2&&close(fd))return 2;
    }
    if(!strcmp(argv[2],"closed-stdin")&&fcntl(0,F_SETFD,FD_CLOEXEC))return 2;
    if(!strcmp(argv[2],"ignored-pipe")) {
        action.sa_handler=SIG_IGN;if(sigaction(SIGPIPE,&action,NULL))return 2;
    }
    if(!strcmp(argv[2],"blocked-mask")) {
        if(sigaddset(&empty,SIGUSR1)||sigprocmask(SIG_SETMASK,&empty,NULL))return 2;
    }
    char *const args[]={argv[1],"--request-sha256",argv[3],NULL};
    char *const environment[]={NULL};
    execve(argv[1],args,environment);_exit(2);
#endif
}
