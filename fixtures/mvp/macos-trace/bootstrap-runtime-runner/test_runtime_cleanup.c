#define _POSIX_C_SOURCE 200809L
#define _DARWIN_C_SOURCE 1
#include "runtime_profile.h"
#include "../bootstrap-runner/runner_internal.h"
#include <assert.h>
#include <errno.h>
#include <fcntl.h>
#include <string.h>
#include <unistd.h>
/* Root IDs are modeled only for NULL-catalog early refusal. No root action. */
static uid_t modeled_root_uid(void){return 0;}
static int forbidden_clock(struct nr_attempt*a,uint64_t*n){(void)a;(void)n;assert(0);return -1;}
#define getuid modeled_root_uid
#define geteuid modeled_root_uid
#define nr_clock forbidden_clock
#include "../bootstrap-runner/runner_parent.c"
#undef nr_clock
#undef geteuid
#undef getuid
static void init(struct nr_attempt*a){memset(a,0,sizeof(*a));a->output_fd=-1;a->child=-1;a->runtime_cwd_fd=-1;a->held_outputs[0]=a->held_outputs[1]=-1;for(unsigned i=0;i<5;i++)a->sources[i]=-1;for(unsigned i=0;i<2;i++)a->gate[i]=a->status[i]=-1;}
int main(void){struct stat before,after;assert(!stat(".",&before));struct nr_attempt a;init(&a);int fd=open(".",O_RDONLY|O_DIRECTORY|O_CLOEXEC);assert(fd>=3);a.runtime_cwd_fd=fd;nr_cleanup(&a);assert(a.runtime_cwd_fd==-1&&!a.close_failed);errno=0;assert(fcntl(fd,F_GETFD)==-1&&errno==EBADF);assert(!stat(".",&after)&&before.st_dev==after.st_dev&&before.st_ino==after.st_ino);init(&a);a.runtime_cwd_fd=fd;nr_cleanup(&a);assert(a.runtime_cwd_fd==-1&&a.close_failed&&a.cleanup_error.saved_errno==EBADF);assert(nr_native_run_once("/must-not-open-runtime-request","/must-not-create-runtime-output")==2);return 0;}
