#define _POSIX_C_SOURCE 200809L
#define _DARWIN_C_SOURCE 1
#include "runner_internal.h"
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <string.h>
#include <time.h>
#include <unistd.h>
#ifdef __APPLE__
#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Wdeprecated-declarations"
#include <CommonCrypto/CommonDigest.h>
#endif
int nr_fail(struct nr_attempt *a,enum nr_stage stage,enum nr_reason reason,int e,int detail) {
 if(a->error.stage==NR_NONE)a->error=(struct nr_error){stage,reason,e,detail};
 return -1;
}
int nr_close_owned(struct nr_attempt *a,int *fd,enum nr_stage stage) {
 if(*fd<0)return 0;
 int n=*fd;*fd=-1;
 if(close(n)){a->close_failed=1;return nr_fail(a,stage,NR_SYSCALL,errno,n);}
 return 0;
}
int nr_clock(struct nr_attempt *a,uint64_t *out) {
 struct timespec t;
 if(clock_gettime(CLOCK_MONOTONIC,&t))return nr_fail(a,NR_PREFLIGHT,NR_SYSCALL,errno,-1);
 if(t.tv_sec<0 || t.tv_nsec<0 || t.tv_nsec>=1000000000L ||
    (uint64_t)t.tv_sec>(UINT64_MAX-(uint64_t)t.tv_nsec)/UINT64_C(1000000000))
  return nr_fail(a,NR_PREFLIGHT,NR_CLOCK,0,-1);
 uint64_t n=(uint64_t)t.tv_sec*UINT64_C(1000000000)+(uint64_t)t.tv_nsec;
 if(n<a->last_clock)return nr_fail(a,NR_PREFLIGHT,NR_CLOCK,0,-1);
 a->last_clock=n;*out=n;return 0;
}
int nr_deadline(struct nr_attempt *a,unsigned ms,struct bio_time *out) {
 uint64_t now;if(nr_clock(a,&now))return -1;
 uint64_t delta=(uint64_t)ms*UINT64_C(1000000);
 if(now>UINT64_MAX-delta)return nr_fail(a,NR_PREFLIGHT,NR_CLOCK,0,-1);
 now+=delta;out->seconds=now/UINT64_C(1000000000);out->nanoseconds=now%UINT64_C(1000000000);return 0;
}
int nr_before(struct nr_attempt *a,struct bio_time d,enum nr_stage st) {
 uint64_t now;if(nr_clock(a,&now))return -1;
 if(d.nanoseconds>=UINT64_C(1000000000) || d.seconds>(UINT64_MAX-d.nanoseconds)/UINT64_C(1000000000))
  return nr_fail(a,st,NR_CLOCK,0,-1);
 if(now>=d.seconds*UINT64_C(1000000000)+d.nanoseconds)return nr_fail(a,st,NR_TIMEOUT,0,-1);
 return 0;
}
int nr_sha_bytes(const uint8_t *p,size_t n,uint8_t out[32]) {
#ifdef __APPLE__
 if(!p || !out || n>UINT32_MAX)return -1;
 return CC_SHA256(p,(CC_LONG)n,out)==out?0:-1;
#else
 (void)p;(void)n;if(out)memset(out,0,32);return -1;
#endif
}
int nr_read_request(struct nr_attempt *a,const char *path) {
 if(!path || path[0]!='/' || strnlen(path,4096)>=4096)return nr_fail(a,NR_REQUEST,NR_INVALID,0,-1);
 int fd=open(path,O_RDONLY|O_NOFOLLOW|O_NONBLOCK|O_CLOEXEC);
 if(fd<0)return nr_fail(a,NR_REQUEST,NR_SYSCALL,errno,-1);
 struct stat s;int rc=0;
 if(fstat(fd,&s))rc=nr_fail(a,NR_REQUEST,NR_SYSCALL,errno,-1);
 else if(!S_ISREG(s.st_mode) || s.st_size<BR_HEADER_SIZE || s.st_size>BR_MAX_WIRE)
  rc=nr_fail(a,NR_REQUEST,NR_INVALID,0,-1);
 if(!rc) {
  size_t expected=(size_t)s.st_size,used=0;
  while(used<expected) {
   if(nr_before(a,a->deadline,NR_REQUEST)){rc=-1;break;}
   ssize_t n=read(fd,a->request_wire+used,expected-used);
   if(n<=0) {rc=nr_fail(a,NR_REQUEST,n<0?NR_SYSCALL:NR_INCOMPLETE,n<0?errno:0,-1);break;}
   used+=(size_t)n;
  }
  uint8_t extra;
  if(!rc) {ssize_t n=read(fd,&extra,1);if(n!=0)rc=nr_fail(a,NR_REQUEST,n<0?NR_SYSCALL:NR_INVALID,n<0?errno:0,-1);}
  if(!rc) {
   struct br_error error;
   #ifdef GLUE_RUNTIME_PROFILE
   if(rr_request_decode(a->request_wire,expected,&a->request,&error)!=BR_OK)
#else
   if(br_request_decode(a->request_wire,expected,&a->request,&error)!=BR_OK)
#endif
    rc=nr_fail(a,NR_REQUEST,NR_INVALID,0,(int)error.field);
   else a->request_size=expected;
  }
 }
 if(nr_close_owned(a,&fd,NR_REQUEST))rc=-1;
 if(rc)return -1;
 if(nr_sha_bytes(a->request_wire,a->request_size,a->request_sha))return nr_fail(a,NR_REQUEST,NR_HELPER,0,-1);
 static const char hex[]="0123456789abcdef";
 for(unsigned i=0;i<32;i++){a->request_hex[2*i]=hex[a->request_sha[i]>>4];a->request_hex[2*i+1]=hex[a->request_sha[i]&15];}
 a->request_hex[64]=0;return 0;
}
int nr_admit(struct nr_attempt *a) {
#ifdef GLUE_RUNTIME_PROFILE
 return nrr_admit(a);
#else
 uint8_t bytes[NR_CATALOG_CAPACITY];size_t n;
 if(nr_catalog_bytes(a->catalog,bytes,&n) || nr_catalog_paths(a->catalog,a->executable,a->cwd) ||
    nr_sha_bytes(bytes,n,a->catalog_sha))return nr_fail(a,NR_CATALOG,NR_INVALID,0,-1);
 if(memcmp(a->catalog_sha,a->request.catalog_sha256,32) ||
    strlen(a->executable)!=a->request.executable.length || strlen(a->cwd)!=a->request.cwd.length ||
    memcmp(a->executable,a->request.executable.bytes,a->request.executable.length) ||
    memcmp(a->cwd,a->request.cwd.bytes,a->request.cwd.length))return nr_fail(a,NR_CATALOG,NR_MISMATCH,0,-1);
 struct ba_request r={(const unsigned char*)a->executable,strlen(a->executable),a->catalog->deployment};struct ba_error e;
 if(ba_admit_protected_executable(&r,ba_native_operations(),&a->admission,&e)) {
  a->admission_error=e;
  a->ownership_uncertain=e.ownership_uncertain;
  return nr_fail(a,NR_ADMISSION,e.ownership_uncertain?NR_OWNERSHIP:NR_HELPER,e.system_errno,(int)e.component);
 }
 const struct ba_metadata *cwd=&a->admission.components[6].metadata;
 if(cwd->device!=a->request.cwd_device || cwd->inode!=a->request.cwd_inode)
  return nr_fail(a,NR_ADMISSION,NR_MISMATCH,0,6);
#ifdef __APPLE__
 int fd=a->admission.components[7].fd;struct stat st;
 if(fstat(fd,&st))return nr_fail(a,NR_ADMISSION,NR_SYSCALL,errno,7);
 if(st.st_size<1 || (uint64_t)st.st_size!=a->catalog->probe_bytes ||
    (uint64_t)(uint32_t)st.st_dev!=a->admission.components[7].metadata.device ||
    (uint64_t)st.st_ino!=a->admission.components[7].metadata.inode)
  return nr_fail(a,NR_ADMISSION,NR_MISMATCH,0,7);
 CC_SHA256_CTX hash;if(CC_SHA256_Init(&hash)!=1)return nr_fail(a,NR_ADMISSION,NR_HELPER,0,7);
 uint8_t block[16384],digest[32];uint64_t remaining=a->catalog->probe_bytes;
 while(remaining) {
  if(nr_before(a,a->deadline,NR_ADMISSION))return -1;
  size_t want=remaining>sizeof(block)?sizeof(block):(size_t)remaining;
  ssize_t amount=read(fd,block,want);
  if(amount<=0)return nr_fail(a,NR_ADMISSION,amount<0?NR_SYSCALL:NR_INCOMPLETE,amount<0?errno:0,7);
  if(CC_SHA256_Update(&hash,block,(CC_LONG)amount)!=1)return nr_fail(a,NR_ADMISSION,NR_HELPER,0,7);
  remaining-=(uint64_t)amount;
 }
 ssize_t amount=read(fd,block,1);
 if(amount!=0)return nr_fail(a,NR_ADMISSION,amount<0?NR_SYSCALL:NR_MISMATCH,amount<0?errno:0,7);
 if(CC_SHA256_Final(digest,&hash)!=1 || memcmp(digest,a->catalog->probe_sha256,32))
  return nr_fail(a,NR_ADMISSION,NR_MISMATCH,0,7);
#else
 return nr_fail(a,NR_ADMISSION,NR_UNSUPPORTED,0,-1);
#endif
 return nr_before(a,a->deadline,NR_ADMISSION);
#endif
}
#ifdef __APPLE__
#pragma clang diagnostic pop
#endif
