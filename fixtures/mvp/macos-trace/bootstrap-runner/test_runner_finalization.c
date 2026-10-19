/* Source-isolated finalization control: every file/IO/promotion operation is a
 * model callback. Never reads, creates, closes or renames native files. */
#define _POSIX_C_SOURCE 200809L
#define _DARWIN_C_SOURCE 1
#include "runner_internal.h"
#include <assert.h>
#include <errno.h>
#include <fcntl.h>
#include <stdarg.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#ifdef __APPLE__
#include <sys/stdio.h>
#endif
static int fail_fd,opens_after_capture,promotions,close_counts[64],events,dir_closed_at,pending_written_at,pending_closed_at,promoted_at;
static char pending_json[8192];
int nr_fail(struct nr_attempt*a,enum nr_stage st,enum nr_reason r,int e,int d){if(a->error.stage==NR_NONE)a->error=(struct nr_error){st,r,e,d};return -1;}
int nr_close_owned(struct nr_attempt*a,int*fd,enum nr_stage st){if(*fd<0)return 0;int n=*fd;*fd=-1;assert(n<64);assert(++close_counts[n]==1);events++;if(n==40)dir_closed_at=events;if(n==44)pending_closed_at=events;if(n==fail_fd){a->close_failed=1;return nr_fail(a,st,NR_SYSCALL,EINTR,n);}return 0;}
int nr_sha_bytes(const uint8_t*p,size_t n,uint8_t out[32]){(void)p;(void)n;memset(out,0,32);return 0;}
int nr_before(struct nr_attempt*a,struct bio_time d,enum nr_stage s){(void)a;(void)d;(void)s;return 0;}
int nr_probe_compare(const struct br_request*r,const struct bw_binding*b,const uint64_t f[3],const struct np_report*p){(void)r;(void)b;(void)f;(void)p;return -1;}
const struct ba_operations *ba_native_operations(void){return NULL;}
const struct te_operations *te_native_operations(void){return NULL;}
int te_prepare_owned_sources(const struct te_request*r,const struct te_operations*o,struct te_prepared*p,struct te_error*e){(void)r;(void)o;(void)p;(void)e;return -1;}
static int model_openat(int fd,const char*name,int flags,...){(void)flags;assert(fd==40);if(!strcmp(name,"probe.stdout"))return 41;if(!strcmp(name,"probe.stderr"))return 42;opens_after_capture++;return !strcmp(name,"status.bin")?43:44;}
static int model_open(const char*p,int f,...){(void)p;(void)f;return -1;}
static int model_stat(int fd,struct stat*s){assert(fd==41||fd==42);memset(s,0,sizeof(*s));s->st_mode=S_IFREG|0600;s->st_nlink=1;s->st_ino=fd==41?100:101;return 0;}
static ssize_t model_read(int fd,void*p,size_t n){(void)p;(void)n;assert(fd==41||fd==42);return 0;}
static ssize_t model_write(int fd,const void*p,size_t n){assert(fd==43||fd==44);if(fd==44){assert(dir_closed_at);pending_written_at=++events;assert(n<sizeof(pending_json));memcpy(pending_json,p,n);pending_json[n]=0;}return (ssize_t)n;}
static int model_pipe(int*p){(void)p;return -1;}
static int model_fcntl(int fd,int f,...){(void)fd;(void)f;return -1;}
#ifdef __APPLE__
static int model_statat(int fd,const char*p,struct stat*s,int flags){(void)fd;(void)p;(void)s;(void)flags;return -1;}
static int model_mkdirat(int fd,const char*p,mode_t m){(void)fd;(void)p;(void)m;return -1;}
static int model_rename(const char*from,const char*to,unsigned flags){assert(strstr(from,"/result.pending")&&strstr(to,"/result.json")&&flags==RENAME_EXCL);promotions++;promoted_at=++events;assert(pending_closed_at>pending_written_at&&pending_written_at>dir_closed_at);return 0;}
#define fstatat model_statat
#define mkdirat model_mkdirat
#define renamex_np model_rename
#endif
#define openat model_openat
#define open model_open
#define fstat model_stat
#define read model_read
#define write model_write
#define pipe model_pipe
#define fcntl model_fcntl
#include "runner_files.c"
static void init(struct nr_attempt*a,int fail){static const struct nr_catalog c={0};memset(a,0,sizeof(*a));a->catalog=&c;a->output_fd=40;strcpy(a->output_path,NR_OUTPUT_PREFIX "model");a->stdout_identity.st_ino=100;a->stderr_identity.st_ino=101;for(unsigned i=0;i<5;i++)a->sources[i]=-1;fail_fd=fail;opens_after_capture=promotions=0;memset(close_counts,0,sizeof(close_counts));events=dir_closed_at=pending_written_at=pending_closed_at=promoted_at=0;memset(pending_json,0,sizeof(pending_json));}
int main(void){struct nr_attempt a;
 for(int fd=41;fd<=42;fd++){init(&a,fd);assert(nr_finish_outputs(&a)==-1);assert(a.close_failed&&a.error.saved_errno==EINTR&&close_counts[fd]==1);assert(!opens_after_capture&&!promotions&&a.output_fd==40);}
 init(&a,40);assert(nr_finish_outputs(&a)==-1);assert(a.close_failed&&a.output_fd==-1&&!promotions&&close_counts[44]==1);
 init(&a,44);assert(nr_finish_outputs(&a)==-1);assert(a.close_failed&&!promotions&&close_counts[44]==1);

#ifdef __APPLE__
 init(&a,-1);assert(nr_finish_outputs(&a)==0);assert(promotions==1&&promoted_at==events&&close_counts[40]==1&&close_counts[44]==1);assert(strstr(pending_json,"\"stdout_capture_valid\":true")&&strstr(pending_json,"\"stderr_capture_valid\":true")&&strstr(pending_json,"\"full_acceptance\":false"));
#endif
 return 0;}
