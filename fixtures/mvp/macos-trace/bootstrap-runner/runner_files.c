#define _POSIX_C_SOURCE 200809L
#define _DARWIN_C_SOURCE 1
#include "runner_internal.h"
#include <errno.h>
#include <fcntl.h>
#include <inttypes.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#ifdef __APPLE__
#include <sys/stdio.h>
#endif
#ifdef GLUE_OWNED_TRACING
#define NR_RECEIPT_SCHEMA "glue-owned-traced-bootstrap-diagnostic-v1"
#define NR_RECEIPT_TRACING "true"
#else
#define NR_RECEIPT_SCHEMA "glue-owned-bootstrap-diagnostic-v1"
#define NR_RECEIPT_TRACING "false"
#endif
static int write_all(struct nr_attempt *a,int fd,const uint8_t *p,size_t n,enum nr_stage stage) {
 while(n) {ssize_t r=write(fd,p,n);if(r<=0)return nr_fail(a,stage,NR_SYSCALL,r<0?errno:EIO,-1);p+=(size_t)r;n-=(size_t)r;}
 return 0;
}
int nr_write_new(struct nr_attempt *a,const char *name,const uint8_t *p,size_t n) {
 int fd=openat(a->output_fd,name,O_WRONLY|O_CREAT|O_EXCL|O_NOFOLLOW|O_CLOEXEC,0600);
 if(fd<0)return nr_fail(a,NR_OUTPUT,NR_SYSCALL,errno,-1);
 int rc=write_all(a,fd,p,n,NR_OUTPUT);
 if(nr_close_owned(a,&fd,NR_OUTPUT))rc=-1;
 return rc;
}
#ifdef __APPLE__
static int directory(struct nr_attempt *a,int fd,unsigned index,int mode) {
 struct ba_metadata m;memset(&m,0,sizeof(m));m.acl_present=-1;
 struct ba_probe_error e={BA_META_NONE,0};const struct ba_operations *ops=ba_native_operations();
 if(ops->inspect_fn(ops->context,fd,&m,&e))return nr_fail(a,NR_OUTPUT,NR_HELPER,e.system_errno,(int)e.step);
 const struct ba_mount_id *wanted=index<3?&a->catalog->deployment.root:&a->catalog->deployment.data;
 if(m.uid || (m.mode&S_IFMT)!=S_IFDIR || (m.mode&~(uint32_t)(S_IFMT|07777)) ||
    (mode>=0?(m.mode&07777)!=(uint32_t)mode:(m.mode&(S_IWGRP|S_IWOTH|S_ISUID|S_ISGID))) ||
    m.populated!=(BA_OWNER_PRESENT|BA_GROUP_PRESENT|BA_MODE_PRESENT) ||
    m.filesec_uid!=m.uid || m.filesec_gid!=m.gid || m.filesec_mode!=m.mode || m.acl_present ||
    !(m.descriptor_flags&FD_CLOEXEC) || (m.status_flags&O_ACCMODE)!=O_RDONLY ||
    (m.status_flags&(O_ASYNC|O_EVTONLY)) || m.mount_policy!=(uint32_t)(BA_MOUNT_LOCAL|(index<3?BA_MOUNT_ROOTFS:0)) ||
    m.mount_owner || memchr(m.filesystem,0,sizeof(m.filesystem))==NULL || strcmp(m.filesystem,"apfs") ||
    memchr(m.mountpoint,0,sizeof(m.mountpoint))==NULL || strcmp(m.mountpoint,index<3?"/":"/System/Volumes/Data") ||
    m.device!=wanted->device || m.fsid[0]!=wanted->fsid[0] || m.fsid[1]!=wanted->fsid[1])
  return nr_fail(a,NR_OUTPUT,NR_MISMATCH,0,(int)index);
 return 0;
}
#endif
int nr_output(struct nr_attempt *a,const char *path) {
#ifdef __APPLE__
 const size_t prefix=sizeof(NR_OUTPUT_PREFIX)-1;
 if(!path || strnlen(path,BA_PATH_MAX)>=BA_PATH_MAX || strncmp(path,NR_OUTPUT_PREFIX,prefix))
  return nr_fail(a,NR_OUTPUT,NR_INVALID,0,-1);
 const unsigned char *name=(const unsigned char *)path+prefix;size_t n=strlen((const char*)name);
 if(!n || n>64)return nr_fail(a,NR_OUTPUT,NR_INVALID,0,-1);
 for(size_t i=0;i<n;i++)if(!((name[i]>='a'&&name[i]<='z')||(name[i]>='A'&&name[i]<='Z')||
    (name[i]>='0'&&name[i]<='9')||(i&&(name[i]=='_'||name[i]=='-'||name[i]=='.'))))
  return nr_fail(a,NR_OUTPUT,NR_INVALID,0,(int)i);
 static const char *const chain[]={"/","System","Volumes","Data","private","tmp"};
 int held[6]={-1,-1,-1,-1,-1,-1};int rc=0;
 for(unsigned i=0;i<6;i++) {
  if(nr_before(a,a->deadline,NR_OUTPUT)){rc=-1;break;}
  held[i]=i?openat(held[i-1],chain[i],O_RDONLY|O_DIRECTORY|O_NOFOLLOW|O_CLOEXEC):open("/",O_RDONLY|O_DIRECTORY|O_NOFOLLOW|O_CLOEXEC);
  if(held[i]<0){rc=nr_fail(a,NR_OUTPUT,NR_SYSCALL,errno,(int)i);break;}
  if(directory(a,held[i],i,i==5?01777:-1)){rc=-1;break;}
 }
 if(!rc && mkdirat(held[5],(const char*)name,0700))rc=nr_fail(a,NR_OUTPUT,NR_SYSCALL,errno,-1);
 if(!rc) {
  a->output_fd=openat(held[5],(const char*)name,O_RDONLY|O_DIRECTORY|O_NOFOLLOW|O_CLOEXEC);
  if(a->output_fd<0)rc=nr_fail(a,NR_OUTPUT,NR_SYSCALL,errno,-1);
  else {
   struct stat named,opened;
   if(fstatat(held[5],(const char*)name,&named,AT_SYMLINK_NOFOLLOW) || fstat(a->output_fd,&opened))
    rc=nr_fail(a,NR_OUTPUT,NR_SYSCALL,errno,-1);
   else if(named.st_dev!=opened.st_dev || named.st_ino!=opened.st_ino)rc=nr_fail(a,NR_OUTPUT,NR_MISMATCH,0,-1);
   else rc=directory(a,a->output_fd,6,0700);
   if(!rc)strcpy(a->output_path,path);
  }
 }
 for(unsigned i=0;i<6;i++)if(nr_close_owned(a,&held[i],NR_OUTPUT))rc=-1;
 if(rc)return -1;
 return nr_write_new(a,"request.bin",a->request_wire,a->request_size);
#else
 (void)path;return nr_fail(a,NR_OUTPUT,NR_UNSUPPORTED,0,-1);
#endif
}
static int pipe_owned(struct nr_attempt *a,int fds[2]) {
 if(pipe(fds))return nr_fail(a,NR_ENDPOINTS,NR_SYSCALL,errno,-1);
 for(unsigned i=0;i<2;i++) {
  int f=fcntl(fds[i],F_GETFL),d=fcntl(fds[i],F_GETFD);
  if(f<0 || d<0 || fcntl(fds[i],F_SETFL,f|O_NONBLOCK) || fcntl(fds[i],F_SETFD,d|FD_CLOEXEC))
   return nr_fail(a,NR_ENDPOINTS,NR_SYSCALL,errno,(int)i);
 }
 return 0;
}
int nr_endpoints(struct nr_attempt *a) {
 a->sources[0]=open("/dev/null",O_RDONLY|O_NOFOLLOW|O_CLOEXEC);
 if(a->sources[0]<0)return nr_fail(a,NR_ENDPOINTS,NR_SYSCALL,errno,0);
 struct stat st;
 if(fstat(a->sources[0],&st))return nr_fail(a,NR_ENDPOINTS,NR_SYSCALL,errno,0);
 if(!S_ISCHR(st.st_mode))return nr_fail(a,NR_ENDPOINTS,NR_MISMATCH,0,0);
 const char *const names[]={"probe.stdout","probe.stderr"};
 for(unsigned i=1;i<3;i++) {
  a->sources[i]=openat(a->output_fd,names[i-1],O_WRONLY|O_CREAT|O_EXCL|O_NOFOLLOW|O_CLOEXEC,0600);
  if(a->sources[i]<0)return nr_fail(a,NR_ENDPOINTS,NR_SYSCALL,errno,(int)i);
  if(fstat(a->sources[i],i==1?&a->stdout_identity:&a->stderr_identity))return nr_fail(a,NR_ENDPOINTS,NR_SYSCALL,errno,(int)i);
 }
 for(unsigned i=0;i<3;i++){int f=fcntl(a->sources[i],F_GETFL);if(f<0)return nr_fail(a,NR_ENDPOINTS,NR_SYSCALL,errno,(int)i);a->stdio_flags[i]=(uint64_t)f;}
 if(pipe_owned(a,a->gate) || pipe_owned(a,a->status))return -1;
 /* These two source slots are aliases, not additional owned FDs. */
 a->sources[3]=a->gate[0];a->sources[4]=a->status[1];
 struct te_request r;memcpy(r.source,a->sources,sizeof(r.source));
 if(te_prepare_owned_sources(&r,te_native_operations(),&a->endpoints,&a->endpoint_error)) {
  a->ownership_uncertain=a->endpoint_error.ownership_uncertain;
  return nr_fail(a,NR_ENDPOINTS,a->ownership_uncertain?NR_OWNERSHIP:NR_HELPER,a->endpoint_error.system_errno,a->endpoint_error.fd);
 }
 return nr_before(a,a->deadline,NR_ENDPOINTS);
}
static int capture(struct nr_attempt *a,const char *name,const struct stat *expected,uint8_t *out,size_t capacity,size_t *used,uint8_t digest[32]) {
 *used=0;int fd=openat(a->output_fd,name,O_RDONLY|O_NOFOLLOW|O_NONBLOCK|O_CLOEXEC);
 if(fd<0)return nr_fail(a,NR_PROBE,NR_SYSCALL,errno,-1);
 struct stat st;int rc=0;
 if(fstat(fd,&st))rc=nr_fail(a,NR_PROBE,NR_SYSCALL,errno,-1);
 else if(!S_ISREG(st.st_mode) || st.st_uid!=0 || (st.st_mode&07777)!=0600 || st.st_nlink!=1 ||
         st.st_dev!=expected->st_dev || st.st_ino!=expected->st_ino || st.st_size<0 || (uint64_t)st.st_size>capacity)
  rc=nr_fail(a,NR_PROBE,NR_MISMATCH,0,-1);
 while(!rc && *used<(size_t)st.st_size) {
  ssize_t n=read(fd,out+*used,(size_t)st.st_size-*used);
  if(n<=0){rc=nr_fail(a,NR_PROBE,NR_INCOMPLETE,n<0?errno:0,-1);break;}*used+=(size_t)n;
 }
 if(!rc){uint8_t extra;ssize_t n=read(fd,&extra,1);if(n!=0)rc=nr_fail(a,NR_PROBE,n<0?NR_SYSCALL:NR_MISMATCH,n<0?errno:0,-1);}
 if(nr_close_owned(a,&fd,NR_PROBE))rc=-1;
 if(!rc && nr_sha_bytes(out,*used,digest))rc=nr_fail(a,NR_PROBE,NR_HELPER,0,-1);
 return rc;
}
static void hex(const uint8_t *p,size_t n,char *out) {static const char h[]="0123456789abcdef";for(size_t i=0;i<n;i++){out[2*i]=h[p[i]>>4];out[2*i+1]=h[p[i]&15];}out[2*n]=0;}
int nr_finish_outputs(struct nr_attempt *a) {
 if(a->output_fd<0 || !a->output_path[0] || a->ownership_uncertain || a->close_failed || (a->forked&&!a->reaped) ||
    (a->signals_initialized&&!a->signals_restored)) {
  (void)nr_fail(a,NR_FINALIZE,NR_INCOMPLETE,0,-1);
#ifdef GLUE_OWNED_TRACING
  (void)nr_trace_parent_closed(a,1);
#endif
  return -1;
 }
 uint8_t stdout_bytes[NP_REPORT_SIZE],stderr_byte[4096],stdout_sha[32]={0},stderr_sha[32]={0},status_sha[32]={0};
 size_t out_n=0,err_n=0;
 int stdout_valid=0,stderr_valid=0;
 if(a->sources[1]<0 && a->sources[2]<0 && a->stdout_identity.st_ino && a->stderr_identity.st_ino) {
  int x=capture(a,"probe.stdout",&a->stdout_identity,stdout_bytes,sizeof(stdout_bytes),&out_n,stdout_sha);
  int y=capture(a,"probe.stderr",&a->stderr_identity,stderr_byte,sizeof(stderr_byte),&err_n,stderr_sha);
  stdout_valid=!x;stderr_valid=!y;
 }
 /* A capture-reader close can fail AFTER the entry guard. Do not create or
  * promote any further result metadata with ambiguous resource resolution. */
 if(a->close_failed){
#ifdef GLUE_OWNED_TRACING
  (void)nr_trace_parent_closed(a,1);
#endif
  return -1;
 }
 if(stdout_valid && stderr_valid && a->error.stage==NR_NONE) {
  struct np_report report;
  a->probe_fault=np_report_decode(stdout_bytes,out_n,a->request_sha,&report);
  struct bw_binding binding={(uint32_t)a->owner,(uint32_t)a->child,{0}};memcpy(binding.request_sha256,a->request_sha,32);
  if(err_n || a->probe_fault!=NP_OK || nr_probe_compare(&a->request,&binding,a->stdio_flags,&report))
   nr_fail(a,NR_PROBE,NR_MISMATCH,0,(int)a->probe_fault);
  else a->probe_matched=1;
 }
 int status_failed=nr_write_new(a,"status.bin",a->stream.raw,a->stream.used);
 if(!status_failed && nr_sha_bytes(a->stream.raw,a->stream.used,status_sha))status_failed=nr_fail(a,NR_FINALIZE,NR_HELPER,0,-1);
 if(status_failed){
#ifdef GLUE_OWNED_TRACING
  (void)nr_trace_parent_closed(a,1);
#endif
  return -1;
 }
#ifdef GLUE_OWNED_TRACING
 int unresolved=a->ownership_uncertain || a->close_failed || (a->forked&&!a->reaped);
 for(unsigned i=0;i<5;i++)if(a->sources[i]>=0)unresolved=1;
 for(unsigned i=0;i<2;i++)if(a->gate[i]>=0 || a->status[i]>=0)unresolved=1;
 for(size_t i=0;i<a->endpoints.owned_count;i++)if(a->endpoints.copies[i]>=0)unresolved=1;
 for(size_t i=0;i<a->admission.owned_count;i++)if(a->admission.components[i].fd>=0)unresolved=1;
 if(a->signals_initialized && (!a->signals_restored || !a->signals.pipe_restored || !a->signals.mask_restored))unresolved=1;
 if(nr_trace_parent_closed(a,unresolved))return -1;
 if(!nr_trace_success(a))(void)nr_fail(a,NR_FINALIZE,NR_INCOMPLETE,0,-1);
 if(nr_trace_write_sidecar(a))return -1;
#endif
 char request_h[65],catalog_h[65],policy_h[65],status_h[65],stdout_h[65],stderr_h[65],source_h[65],recipe_h[65],probe_h[65];
 hex(a->request_sha,32,request_h);hex(a->catalog_sha,32,catalog_h);hex(a->policy_sha,32,policy_h);hex(status_sha,32,status_h);
 hex(stdout_sha,32,stdout_h);hex(stderr_sha,32,stderr_h);hex(a->catalog->runner_static_sources_sha256,32,source_h);
 hex(a->catalog->build_recipe_sha256,32,recipe_h);hex(a->catalog->probe_sha256,32,probe_h);
 int pending=openat(a->output_fd,"result.pending",O_WRONLY|O_CREAT|O_EXCL|O_NOFOLLOW|O_CLOEXEC,0600);
 if(pending<0)return nr_fail(a,NR_FINALIZE,NR_SYSCALL,errno,-1);
 if(nr_close_owned(a,&a->output_fd,NR_FINALIZE)){nr_close_owned(a,&pending,NR_FINALIZE);return -1;}
 /* No resource owns a writer now except this pending file. Namespace stability
  * follows the explicit root-private output invariant, not a generic resolver. */
 char json[8192];
 const struct bw_status *ce=&a->stream.wire.reported_error;
 int n=snprintf(json,sizeof(json),
  "{\"schema\":\"" NR_RECEIPT_SCHEMA "\",\"tracing\":" NR_RECEIPT_TRACING ",\"exec_proved\":false,\"full_acceptance\":false,\"identity_policy\":\"request-declarations-compared-to-observations\","
  "\"consistent_owned_probe\":%s,\"controller_pid\":%ld,\"child_pid\":%ld,"
  "\"parent_error\":{\"stage\":%d,\"reason\":%d,\"errno\":%d,\"detail\":%d},"
  "\"cleanup_error\":{\"stage\":%d,\"reason\":%d,\"errno\":%d,\"detail\":%d},"
  "\"helpers\":{\"admission\":{\"stage\":%d,\"reason\":%d,\"errno\":%d,\"component\":%zu,\"metadata_step\":%d},\"endpoints\":{\"stage\":%d,\"reason\":%d,\"errno\":%d,\"role\":%d,\"fd\":%d},\"signal_prepare\":{\"stage\":%d,\"reason\":%d,\"errno\":%d}},"
  "\"child_error\":{\"present\":%s,\"stage\":%u,\"reason\":%u,\"errno\":%u,\"flags\":%u,\"detail\":%" PRId64 "},"
  "\"protocol\":{\"records\":%u,\"bytes\":%zu,\"wire_fault\":%d,\"io_stage\":%d,\"io_reason\":%d,\"io_errno\":%d,\"eof_class\":%d},"
  "\"go\":{\"action\":%" PRIu64 ",\"attempted\":%s,\"possibly_released\":%s,\"bytes\":%zu,\"stage\":%d,\"reason\":%d,\"errno\":%d,\"closed\":%s},"
  "\"ready_matched\":%s,\"probe_matched\":%s,\"wait\":{\"forked\":%s,\"reaped\":%s,\"lost\":%s,\"kill_attempted\":%s,\"raw_status\":%d},"
  "\"signals\":{\"prepared\":%s,\"restore_called\":%s,\"pipe_restored\":%s,\"mask_restored\":%s,\"restore_stage\":%d,\"restore_reason\":%d,\"restore_errno\":%d},"
  "\"identities\":{\"request_sha256\":\"%s\",\"catalog_sha256\":\"%s\",\"signal_policy_sha256\":\"%s\",\"status_sha256\":\"%s\",\"stdout_sha256\":\"%s\",\"stderr_sha256\":\"%s\",\"probe_sha256\":\"%s\",\"runner_static_sources_sha256\":\"%s\",\"build_recipe_sha256\":\"%s\"},"
  "\"stdout_capture_valid\":%s,\"stderr_capture_valid\":%s,\"stdout_bytes\":%zu,\"stderr_bytes\":%zu}\n",
  a->error.stage==NR_NONE&&a->probe_matched?"true":"false",(long)a->owner,(long)a->child,
  a->error.stage,a->error.reason,a->error.saved_errno,a->error.detail,
  a->cleanup_error.stage,a->cleanup_error.reason,a->cleanup_error.saved_errno,a->cleanup_error.detail,
  a->admission_error.stage,a->admission_error.reason,a->admission_error.system_errno,a->admission_error.component,a->admission_error.metadata_step,
  a->endpoint_error.stage,a->endpoint_error.reason,a->endpoint_error.system_errno,a->endpoint_error.role,a->endpoint_error.fd,
  a->signal_prepare_error.stage,a->signal_prepare_error.reason,a->signal_prepare_error.system_errno,
  a->stream.wire.has_reported_error?"true":"false",ce->stage,ce->reason,ce->system_errno,ce->mutation_flags,ce->detail,
  a->stream.wire.accepted_records,a->stream.used,a->stream.first_wire_error,a->stream.first_io_error.stage,a->stream.first_io_error.reason,a->stream.first_io_error.system_errno,a->stream.end,
  a->request.release_action,a->go_attempted?"true":"false",a->go_attempted?"true":"false",a->go_result.bytes_moved,a->go_error.stage,a->go_error.reason,a->go_error.system_errno,a->go_closed?"true":"false",
  a->ready_matched?"true":"false",a->probe_matched?"true":"false",a->forked?"true":"false",a->reaped?"true":"false",a->lost_child?"true":"false",a->kill_attempted?"true":"false",a->wait_status,
  a->signals.prepared?"true":"false",a->signals_restored?"true":"false",a->signals.pipe_restored?"true":"false",a->signals.mask_restored?"true":"false",a->signal_restore_error.stage,a->signal_restore_error.reason,a->signal_restore_error.system_errno,
  request_h,catalog_h,policy_h,status_h,stdout_h,stderr_h,probe_h,source_h,recipe_h,stdout_valid?"true":"false",stderr_valid?"true":"false",out_n,err_n);
 int rc=0;if(n<0 || (size_t)n>=sizeof(json))rc=nr_fail(a,NR_FINALIZE,NR_INVALID,0,-1);
#ifdef GLUE_OWNED_TRACING
 if(!rc) {
  int extra=snprintf(json+(size_t)n-2,sizeof(json)-(size_t)n+2,",\"trace_sidecar\":\"trace.json\",\"trace_finalization_safe\":true,\"trace_success_eligible\":%s}\n",nr_trace_success(a)?"true":"false");
  if(extra<0 || (size_t)extra>=sizeof(json)-(size_t)n+2)rc=nr_fail(a,NR_FINALIZE,NR_INVALID,0,-1);
  else n=n-2+extra;
 }
#endif
 if(!rc)rc=write_all(a,pending,(const uint8_t*)json,(size_t)n,NR_FINALIZE);
 if(nr_close_owned(a,&pending,NR_FINALIZE))rc=-1;
 if(rc)return -1;
#ifdef __APPLE__
 char from[BA_PATH_MAX+32],to[BA_PATH_MAX+32];
 int x=snprintf(from,sizeof(from),"%s/result.pending",a->output_path),y=snprintf(to,sizeof(to),"%s/result.json",a->output_path);
 if(x<0 || y<0 || (size_t)x>=sizeof(from) || (size_t)y>=sizeof(to))return nr_fail(a,NR_FINALIZE,NR_INVALID,0,-1);
 if(renamex_np(from,to,RENAME_EXCL))return nr_fail(a,NR_FINALIZE,NR_SYSCALL,errno,-1);
 /* No close or fallible finalization after promotion. */
 return 0;
#else
 return nr_fail(a,NR_FINALIZE,NR_UNSUPPORTED,0,-1);
#endif
}
