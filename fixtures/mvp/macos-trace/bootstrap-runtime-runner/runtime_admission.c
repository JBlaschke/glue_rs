#define _POSIX_C_SOURCE 200809L
#define _DARWIN_C_SOURCE 1
#include "runtime_profile.h"
#include "../bootstrap-runner/runner_internal.h"
#include "../bootstrap-kit/request_catalog.h"
#include <errno.h>
#include <fcntl.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>
#ifdef __APPLE__
#ifdef __clang__
#pragma clang diagnostic ignored "-Wdeprecated-declarations"
#elif defined(__GNUC__)
#pragma GCC diagnostic ignored "-Wdeprecated-declarations"
#endif
#include <CommonCrypto/CommonDigest.h>
#endif
int nrr_prepare(struct nr_attempt *a){
 uint8_t bytes[NRR_CATALOG_CAPACITY];size_t used;struct tl_error e;
 if(nrr_catalog_paths(a->runtime_catalog,a->executable,a->cwd)||nrr_catalog_bytes(a->runtime_catalog,bytes,&used)||
    tl_prepare(&a->runtime_catalog->launch,(struct tl_span){(const uint8_t*)a->executable,strlen(a->executable)},&a->runtime_plan,&e)||
    nr_sha_bytes(bytes,used,a->catalog_sha))return nr_fail(a,NR_CATALOG,NR_INVALID,0,-1);
 return 0;
}
int nrr_admit(struct nr_attempt *a){
#ifndef __APPLE__
 return nr_fail(a,NR_ADMISSION,NR_UNSUPPORTED,0,-1);
#else
 if(a->runtime_cwd_fd!=-1)return nr_fail(a,NR_ADMISSION,NR_INVALID,0,6);
 if(!a->runtime_plan.ready||a->request.fixture!=2||a->request.argv_template!=2||a->request.environment_count||
    memcmp(a->catalog_sha,a->request.catalog_sha256,32)||strlen(a->executable)!=a->request.executable.length||
    memcmp(a->executable,a->request.executable.bytes,a->request.executable.length)||strlen(a->cwd)!=a->request.cwd.length||
    memcmp(a->cwd,a->request.cwd.bytes,a->request.cwd.length))return nr_fail(a,NR_CATALOG,NR_MISMATCH,0,-1);
 struct ba_request request={(const unsigned char*)a->executable,strlen(a->executable),a->runtime_catalog->deployment};
 if(ba_admit_protected_executable(&request,ba_native_operations(),&a->admission,&a->admission_error)){
  a->ownership_uncertain=a->admission_error.ownership_uncertain;
  return nr_fail(a,NR_ADMISSION,a->ownership_uncertain?NR_OWNERSHIP:NR_HELPER,a->admission_error.system_errno,(int)a->admission_error.component);
 }
 int fd=a->admission.components[7].fd;struct stat st;
 if(fstat(fd,&st))return nr_fail(a,NR_ADMISSION,NR_SYSCALL,errno,7);
 if(st.st_size<1||(uint64_t)st.st_size!=a->runtime_catalog->launcher_bytes||(uint64_t)st.st_size>NRR_MAX_LAUNCHER_BYTES||
    (uint64_t)(uint32_t)st.st_dev!=a->admission.components[7].metadata.device||(uint64_t)st.st_ino!=a->admission.components[7].metadata.inode)
  return nr_fail(a,NR_ADMISSION,NR_MISMATCH,0,7);
 CC_SHA256_CTX hash;if(CC_SHA256_Init(&hash)!=1)return nr_fail(a,NR_ADMISSION,NR_HELPER,0,7);
 uint64_t remaining=(uint64_t)st.st_size;uint8_t block[16384],digest[32];
 while(remaining){
  if(nr_before(a,a->deadline,NR_ADMISSION))return -1;
  size_t want=remaining>sizeof(block)?sizeof(block):(size_t)remaining;ssize_t n=read(fd,block,want);
  if(n<=0)return nr_fail(a,NR_ADMISSION,n<0?NR_SYSCALL:NR_INCOMPLETE,n<0?errno:0,7);
  if(CC_SHA256_Update(&hash,block,(CC_LONG)n)!=1)return nr_fail(a,NR_ADMISSION,NR_HELPER,0,7);
  remaining-=(uint64_t)n;
 }
 uint8_t extra;ssize_t n=read(fd,&extra,1);
 if(n!=0)return nr_fail(a,NR_ADMISSION,n<0?NR_SYSCALL:NR_MISMATCH,n<0?errno:0,7);
 if(CC_SHA256_Final(digest,&hash)!=1||memcmp(digest,a->runtime_catalog->launcher_sha256,32))return nr_fail(a,NR_ADMISSION,NR_MISMATCH,0,7);
 if(nr_before(a,a->deadline,NR_ADMISSION))return -1;
 a->runtime_cwd_fd=openat(a->admission.components[5].fd,a->runtime_catalog->cwd_name,O_RDONLY|O_DIRECTORY|O_NOFOLLOW|O_CLOEXEC);
 if(a->runtime_cwd_fd<0)return nr_fail(a,NR_ADMISSION,NR_SYSCALL,errno,6);
 if(a->runtime_cwd_fd<3)return nr_fail(a,NR_ADMISSION,NR_INVALID,0,6);
 struct ba_probe_error pe={BA_META_NONE,0};const struct ba_operations *ops=ba_native_operations();
 if(ops->inspect_fn(ops->context,a->runtime_cwd_fd,&a->runtime_cwd_metadata,&pe))return nr_fail(a,NR_ADMISSION,NR_HELPER,pe.system_errno,(int)pe.step);
 if(!bk_directory_metadata_valid(&a->runtime_cwd_metadata,&a->runtime_catalog->deployment,6)||
    a->runtime_cwd_metadata.device!=a->request.cwd_device||a->runtime_cwd_metadata.inode!=a->request.cwd_inode||
    (a->runtime_cwd_metadata.device==a->admission.components[6].metadata.device&&a->runtime_cwd_metadata.inode==a->admission.components[6].metadata.inode))
  return nr_fail(a,NR_ADMISSION,NR_MISMATCH,0,6);
 struct stat named;
 if(fstatat(a->admission.components[5].fd,a->runtime_catalog->cwd_name,&named,AT_SYMLINK_NOFOLLOW))return nr_fail(a,NR_ADMISSION,NR_SYSCALL,errno,6);
 if((uint64_t)(uint32_t)named.st_dev!=a->runtime_cwd_metadata.device||(uint64_t)named.st_ino!=a->runtime_cwd_metadata.inode)
  return nr_fail(a,NR_ADMISSION,NR_MISMATCH,0,6);
 return nr_before(a,a->deadline,NR_ADMISSION);
#endif
}
