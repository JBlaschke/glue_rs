/* Independent owned request/result controls. Self-report is not kernel evidence. */
#ifndef _DARWIN_C_SOURCE
#define _DARWIN_C_SOURCE
#endif
#include <errno.h>
#include <fcntl.h>
#include <inttypes.h>
#include <limits.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <unistd.h>

#if !defined(__APPLE__) || !defined(__arm64__)
#error This owned control is native Darwin arm64 only
#endif

static const char input[]="owned trace fixture\n";
static const char marker[]="owned-open-intent-control-v1\n";
static const char *modes[]={"read-open","event-only","readwrite-open","append-open","denied-write-open","readonly-create","truncate-open","create-unlink","openat-dirfd","openat-fdcwd"};

static int usage(void) {
    fputs("usage: open-control --describe | --prepare NEW_ABSOLUTE_DIR | --run MODE OWNED_ABSOLUTE_DIR\n",stderr);
    return 2;
}
static int describe(void) {
    const struct { const char *name; int64_t value; } constants[]={
#define VALUE(name) {#name,(int64_t)(name)}
        VALUE(AT_FDCWD),VALUE(O_RDONLY),VALUE(O_WRONLY),VALUE(O_RDWR),VALUE(O_ACCMODE),
        VALUE(O_NONBLOCK),VALUE(O_APPEND),VALUE(O_SHLOCK),VALUE(O_EXLOCK),VALUE(O_ASYNC),
        VALUE(O_SYNC),VALUE(O_NOFOLLOW),VALUE(O_CREAT),VALUE(O_TRUNC),VALUE(O_EXCL),
        VALUE(O_RESOLVE_BENEATH),VALUE(O_UNIQUE),VALUE(O_EVTONLY),VALUE(O_NOCTTY),
        VALUE(O_DIRECTORY),VALUE(O_SYMLINK),VALUE(O_DSYNC),VALUE(O_CLOEXEC),
        VALUE(O_NOFOLLOW_ANY),VALUE(O_EXEC),VALUE(O_SEARCH),VALUE(SYS_open),VALUE(SYS_openat),
        VALUE(SYS_write),VALUE(SYS_unlink),VALUE(PATH_MAX)
#undef VALUE
    };
    printf("{\"revision\":1,\"protocol\":\"darwin-open-unit-abi-v1\",\"system\":\"Darwin\",\"architecture\":\"arm64\",\"sizeof_int\":%zu,\"sizeof_long\":%zu,\"sizeof_mode_t\":%zu,\"constants\":{",sizeof(int),sizeof(long),sizeof(mode_t));
    for (size_t i=0;i<sizeof(constants)/sizeof(constants[0]);++i)
        printf("%s\"%s\":%"PRId64,i ? "," : "",constants[i].name,constants[i].value);
    puts("}}");
    return ferror(stdout) ? 1 : 0;
}
static bool absolute(const char *path) {
    if (!path || path[0]!='/' || strlen(path)>PATH_MAX-64) return false;
    const char *component=path;
    while (*component) {
        while (*component=='/') ++component;
        const char *end=strchr(component,'/'); size_t size=end ? (size_t)(end-component) : strlen(component);
        if ((size==1 && component[0]=='.') || (size==2 && component[0]=='.' && component[1]=='.')) return false;
        component+=size;
    }
    return true;
}
static bool write_new(int root,const char *name,const char *bytes,size_t size) {
    int fd=openat(root,name,O_WRONLY|O_CREAT|O_EXCL|O_CLOEXEC|O_NOFOLLOW,0600);
    if (fd<0) return false;
    ssize_t result=write(fd,bytes,size); int close_result=close(fd);
    return result==(ssize_t)size && close_result==0;
}
static int prepare(const char *path) {
    if (!absolute(path)) return usage();
    if (mkdir(path,0700)) { perror("new owned control directory"); return 1; }
    int root=open(path,O_RDONLY|O_DIRECTORY|O_CLOEXEC|O_NOFOLLOW);
    if (root<0) { perror("owned directory"); return 1; }
    bool okay=write_new(root,"control-root.txt",marker,sizeof(marker)-1) &&
        write_new(root,"input.txt",input,sizeof(input)-1) && write_new(root,"mutable.txt",input,sizeof(input)-1);
    close(root);
    if (!okay) { perror("owned preparation"); return 1; }
    return 0;
}
static bool expected_file(int root,const char *name,const char *expected,size_t size) {
    int fd=openat(root,name,O_RDONLY|O_CLOEXEC|O_NOFOLLOW);
    if (fd<0) return false;
    struct stat facts; char bytes[128];
    bool okay=fstat(fd,&facts)==0 && S_ISREG(facts.st_mode) && facts.st_nlink==1 && facts.st_size==(off_t)size;
    ssize_t count=okay ? read(fd,bytes,sizeof(bytes)) : -1;
    close(fd);
    return count==(ssize_t)size && !memcmp(bytes,expected,size);
}
static bool path_join(char *output,const char *root,const char *name) {
    int size=snprintf(output,PATH_MAX,"%s/%s",root,name);
    return size>0 && size<PATH_MAX;
}
static void record(const char *operation,const char *path,int flags,mode_t mode,int dirfd,long result,int error) {
    printf("{\"revision\":1,\"protocol\":\"darwin-normalized-open-unit-v1\",\"origin\":\"owned-control-self-report\",\"operation\":\"%s\",\"flags\":%"PRIu32",\"mode\":%"PRIu32",\"path_hex\":\"",operation,(uint32_t)flags,(uint32_t)mode);
    for (const unsigned char *p=(const unsigned char *)path;*p;++p) printf("%02x",*p);
    fputs("\",\"dirfd\":",stdout);
    if (!strcmp(operation,"open")) fputs("null",stdout); else printf("%d",dirfd);
    printf(",\"result\":%ld,\"error\":%d}\n",result,error);
}
static long request(const char *operation,const char *path,int flags,mode_t mode,int dirfd) {
    errno=0;
    long result=!strcmp(operation,"open") ? syscall(SYS_open,path,flags,mode) : syscall(SYS_openat,dirfd,path,flags,mode);
    int error=result<0 ? errno : 0;
    record(operation,path,flags,mode,dirfd,result,error);
    errno=error;
    return result;
}
static int run(const char *mode,const char *root_path) {
    if (!absolute(root_path)) return usage();
    bool known=false;
    for (size_t i=0;i<sizeof(modes)/sizeof(modes[0]);++i) if (!strcmp(mode,modes[i])) known=true;
    if (!known) return usage();
    int root=open(root_path,O_RDONLY|O_DIRECTORY|O_CLOEXEC|O_NOFOLLOW);
    if (root<0) { perror("owned control root"); return 1; }
    if (!expected_file(root,"control-root.txt",marker,sizeof(marker)-1) || !expected_file(root,"input.txt",input,sizeof(input)-1) || !expected_file(root,"mutable.txt",input,sizeof(input)-1)) {
        close(root); fputs("owned directory marker/input mismatch\n",stderr); return 1;
    }
    char path[PATH_MAX]; const int modifiers=O_CLOEXEC|O_NOFOLLOW;
    long descriptor=-1,write_result=-1,unlink_result=-1,read_result=-1;
    bool okay=true;
    if (!strcmp(mode,"openat-dirfd")) {
        descriptor=request("open",root_path,O_RDONLY|O_DIRECTORY|modifiers,0,-1);
        if (descriptor<0) okay=false;
        else {
            long fd=request("openat","created-at",O_WRONLY|O_CREAT|O_EXCL|modifiers,0600,(int)descriptor);
            okay=fd>=0; if (fd>=0) close((int)fd);
        }
    } else {
        const char *name="input.txt"; int flags=O_RDONLY|modifiers; const char *operation="open";
        if (!strcmp(mode,"event-only")) flags=O_EVTONLY|modifiers;
        else if (!strcmp(mode,"readwrite-open")) { name="mutable.txt"; flags=O_RDWR|modifiers; }
        else if (!strcmp(mode,"append-open")) { name="mutable.txt"; flags=O_WRONLY|O_APPEND|modifiers; }
        else if (!strcmp(mode,"denied-write-open")) { name="missing-parent/denied-output"; flags=O_WRONLY|O_CREAT|O_EXCL|modifiers; }
        else if (!strcmp(mode,"readonly-create")) { name="readonly-created"; flags=O_RDONLY|O_CREAT|O_EXCL|modifiers; }
        else if (!strcmp(mode,"truncate-open")) { name="mutable.txt"; flags=O_WRONLY|O_TRUNC|modifiers; }
        else if (!strcmp(mode,"create-unlink")) { name="created-then-unlinked"; flags=O_WRONLY|O_CREAT|O_EXCL|modifiers; }
        else if (!strcmp(mode,"openat-fdcwd")) { name="created-fdcwd"; flags=O_WRONLY|O_CREAT|O_EXCL|modifiers; operation="openat"; }
        if (!path_join(path,root_path,name)) { close(root); return 2; }
        descriptor=request(operation,path,flags,0600,AT_FDCWD);
        int error=errno;
        if (!strcmp(mode,"denied-write-open")) okay=descriptor==-1 && error==ENOENT;
        else if (descriptor<0) okay=false;
        else if (!strcmp(mode,"read-open")) {
            char bytes[sizeof(input)]; read_result=syscall(SYS_read,(int)descriptor,bytes,sizeof(bytes));
            okay=read_result==(long)sizeof(input)-1 && !memcmp(bytes,input,sizeof(input)-1);
        } else if (!strcmp(mode,"create-unlink")) {
            write_result=syscall(SYS_write,(int)descriptor,input,sizeof(input)-1);
            unlink_result=syscall(SYS_unlink,path);
            okay=write_result==(long)sizeof(input)-1 && unlink_result==0;
        }
    }
    if (descriptor>=0 && close((int)descriptor)) okay=false;
    close(root);
    fprintf(stderr,"{\"scope\":\"owned self-report, not kernel capture\",\"control\":\"%s\",\"expected_result_observed\":%s,\"read_result\":%ld,\"write_result\":%ld,\"unlink_result\":%ld,\"full_trace_acceptance\":false}\n",mode,okay ? "true" : "false",read_result,write_result,unlink_result);
    return !okay || ferror(stdout) || ferror(stderr) ? 1 : 0;
}
int main(int argc,char **argv) {
    alarm(5);
    if (argc==2 && !strcmp(argv[1],"--describe")) return describe();
    if (argc==3 && !strcmp(argv[1],"--prepare")) return prepare(argv[2]);
    if (argc==4 && !strcmp(argv[1],"--run")) return run(argv[2],argv[3]);
    return usage();
}
