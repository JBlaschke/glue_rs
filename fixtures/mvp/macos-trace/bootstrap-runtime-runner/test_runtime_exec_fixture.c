#define _POSIX_C_SOURCE 200809L
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>
extern char **environ;
int main(int argc,char **argv){
 if(argc!=5||strcmp(argv[1],"run")||strcmp(argv[3],"--")||strcmp(argv[4],"argument with spaces")||environ[0]||getuid()==0||geteuid()==0)return 71;
 struct stat archive,cwd;if(stat(argv[2],&archive)||stat(".",&cwd)||!S_ISDIR(cwd.st_mode)||!S_ISREG(archive.st_mode))return 72;
 char path[4096];if(!getcwd(path,sizeof(path)))return 73;size_t n=strlen(path);if(n<10||strcmp(path+n-10,"/unrelated"))return 74;
 path[n-10]=0;char expected[4096];int amount=snprintf(expected,sizeof(expected),"%s/app.glue",path);char canonical[4096];if(amount<0||(size_t)amount>=sizeof(expected)||!realpath(argv[2],canonical)||strcmp(canonical,expected))return 77;
 size_t executable_length=strlen(argv[0]);if(executable_length<13||strcmp(argv[0]+executable_length-13,"/exec-fixture"))return 78;
 for(int fd=3;fd<64;fd++){errno=0;if(fcntl(fd,F_GETFD)!=-1||errno!=EBADF)return 75;}
 static const unsigned char output[]={0,'f','i','x','e','d','-','r','u','n','t','i','m','e','\n'};
 return write(1,output,sizeof(output))==(ssize_t)sizeof(output)?0:76;
}
