/* Owned native capability fixtures; never packaged application code. */
#ifndef _DARWIN_C_SOURCE
#define _DARWIN_C_SOURCE
#endif
#include <errno.h>
#include <fcntl.h>
#include <pthread.h>
#include <signal.h>
#include <spawn.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/syscall.h>
#include <sys/wait.h>
#include <unistd.h>

extern char **environ;
static int owned_read(const char *path, const char *role) {
    alarm(5);
    char buffer[64];
    int fd=(int)syscall(SYS_open,path,O_RDONLY|O_CLOEXEC,0);
    if (fd<0) { perror("owned direct open"); return 65; }
    ssize_t count=read(fd,buffer,sizeof(buffer));
    if (close(fd) || count!=20) return 66;
    fd=(int)syscall(SYS_open,"/glue-owned-no-such-parent/absent",O_RDONLY,0);
    int failure=errno;
    if (fd!=-1 || failure!=ENOENT) { if (fd>=0) close(fd); return 67; }
    uint64_t thread=0;
    if (pthread_threadid_np(NULL,&thread)) return 68;
    printf("OWNED_READ pid=%d ppid=%d tid=%llu role=%s failed_open_errno=%d\n",getpid(),getppid(),(unsigned long long)thread,role,failure);
    return fflush(stdout) ? 69 : 0;
}
static void *thread_read(void *path) { return (void *)(intptr_t)owned_read(path,"thread"); }
static int parent_exit(pid_t child) {
    if (child<0) { perror("owned child creation"); return 70; }
    printf("OWNED_PARENT_EXIT pid=%d child=%d\n",getpid(),child);
    return fflush(stdout) ? 71 : 0;
}
int main(int argc, char **argv) {
    if (argc!=3) { fputs("usage: lifecycle-probe read|delayed-read|thread|fork|double-fork|vfork|spawn|spawn-fail-open INPUT\n",stderr); return 64; }
    alarm(5);
    if (!strcmp(argv[1],"read")) return owned_read(argv[2],"root");
    if (!strcmp(argv[1],"delayed-read")) { usleep(400000); return owned_read(argv[2],"exec-child"); }
    if (!strcmp(argv[1],"thread")) {
        pthread_t thread; void *result;
        if (pthread_create(&thread,NULL,thread_read,argv[2]) || pthread_join(thread,&result)) return 72;
        return (int)(intptr_t)result;
    }
    if (!strcmp(argv[1],"fork") || !strcmp(argv[1],"double-fork")) {
        pid_t child=fork();
        if (child==0) {
            alarm(5);
            if (!strcmp(argv[1],"double-fork")) {
                if (setsid()<0) _exit(73);
                pid_t grandchild=fork();
                if (grandchild<0) _exit(74);
                if (grandchild>0) _exit(parent_exit(grandchild));
                alarm(5);
            }
            usleep(400000);
            _exit(owned_read(argv[2],"surviving-child"));
        }
        return parent_exit(child);
    }
    char *child_argv[]={argv[0],"delayed-read",argv[2],NULL};
    if (!strcmp(argv[1],"vfork")) {
        pid_t child=vfork();
        if (child==0) { execv(argv[0],child_argv); _exit(75); }
        return parent_exit(child);
    }
    if (!strcmp(argv[1],"spawn")) {
        pid_t child; int error=posix_spawn(&child,argv[0],NULL,NULL,child_argv,environ);
        if (error) { fprintf(stderr,"owned posix_spawn: %s\n",strerror(error)); return 76; }
        return parent_exit(child);
    }
    if (!strcmp(argv[1],"spawn-fail-open")) {
        posix_spawn_file_actions_t actions; pid_t child;
        int error=posix_spawn_file_actions_init(&actions);
        if (error) return 77;
        error=posix_spawn_file_actions_addopen(&actions,9,"/glue-owned-no-such-parent/attempted-output",O_WRONLY|O_CREAT,0600);
        if (!error) error=posix_spawn(&child,argv[0],&actions,NULL,child_argv,environ);
        posix_spawn_file_actions_destroy(&actions);
        if (error!=ENOENT) return 78;
        printf("OWNED_SPAWN_OPEN_FAILURE pid=%d errno=%d\n",getpid(),error);
        /* Ensure this control also provides the common open entry/return pair. */
        return owned_read(argv[2],"spawn-open-failure");
    }
    return 64;
}
