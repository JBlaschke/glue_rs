#define _POSIX_C_SOURCE 200809L
#define _DARWIN_C_SOURCE 1
#include "runner_internal.h"
#include <errno.h>
#include <limits.h>
#include <string.h>
#include <unistd.h>
#ifdef GLUE_FD_OBJECTS
#include "../target-cwd/target_cwd.h"
static int object_cwd_before(void *context,int *saved) {
 struct nr_attempt *a=context;
 if(!nr_before(a,a->deadline,NR_READY))return 0;
 *saved=a->error.reason==NR_TIMEOUT?0:(a->error.saved_errno>0?a->error.saved_errno:-1);
 return -1;
}
#endif
static int status_write(struct nr_attempt *a,const struct bw_status *s) {
 struct bio_error e;
#ifdef GLUE_FD_OBJECTS
 uint8_t bytes[BOW_STATUS_SIZE];struct bio_object_result r;
 if(bow_status_encode(s,s->kind==BW_READY?&a->child_objects:NULL,bytes)!=BW_OK)return -1;
 return bio_write_object_status(a->endpoints.copies[TE_STATUS_WRITER],bytes,a->deadline,bio_native_operations(),&r,&e);
#else
 uint8_t bytes[BW_STATUS_SIZE];struct bio_result r;
 if(bw_status_encode(s,bytes)!=BW_OK)return -1;
 return bio_write_record(a->endpoints.copies[TE_STATUS_WRITER],bytes,sizeof(bytes),a->deadline,bio_native_operations(),&r,&e);
#endif
}
static _Noreturn void child_error(struct nr_attempt *a,const struct bw_binding *b,unsigned seq,unsigned stage,unsigned flags,unsigned reason,int saved,int detail) {
 struct bw_status s;memset(&s,0,sizeof(s));s.binding=*b;s.kind=BW_ERROR;s.sequence=seq;s.stage=stage;s.mutation_flags=flags;
 s.reason=reason;s.system_errno=reason==BW_SYSCALL && saved>0 && saved<=INT32_MAX?(uint32_t)saved:0;
 if(reason==BW_SYSCALL && !s.system_errno)s.reason=BW_ADAPTER;
 s.detail=detail>=0?detail:-1;(void)status_write(a,&s);_exit(120);
}
#define ERROR(stage,reason,saved,detail) child_error(a,&binding,sequence,stage,flags,reason,saved,detail)
_Noreturn void nr_child(struct nr_attempt *a) {
 struct bw_binding binding={(uint32_t)a->owner,(uint32_t)getpid(),{0}};memcpy(binding.request_sha256,a->request_sha,32);
 unsigned sequence=0,flags=0;
 if(getpid()<=0 || getpid()>INT32_MAX || getpid()==a->owner || getppid()!=a->owner)
  ERROR(BW_REQUEST,BW_OWNERSHIP,0,-1);
 if(nr_before(a,a->deadline,NR_PROCESS_GROUP))ERROR(BW_PROCESS_GROUP,BW_TIMEOUT,0,-1);
 if(setpgid(0,0))ERROR(BW_PROCESS_GROUP,BW_SYSCALL,errno,-1);
 if(getpgrp()!=getpid())ERROR(BW_PROCESS_GROUP,BW_MISMATCH,0,-1);
 struct bs_error se;
 if(bs_reset_in_owned_child(&a->signals,&se))ERROR(BW_SIGNALS,se.system_errno?BW_SYSCALL:BW_SIGNAL_POLICY,se.system_errno,se.signal_number);
 struct te_error te;
 if(te_map_in_owned_child(&a->endpoints,(uint64_t)a->owner,te_native_operations(),&te))
  ERROR(BW_STDIO,te.system_errno?BW_SYSCALL:BW_MISMATCH,te.system_errno,te.fd);
 if(nr_before(a,a->deadline,NR_READY))ERROR(BW_CREDENTIALS,BW_TIMEOUT,0,-1);
 struct tc_error tc;
 if(tc_drop_in_owned_child(&a->request.credentials,(uint64_t)a->owner,tc_native_operations(),&tc)) {
  if(tc.mutation_attempted)flags|=BW_CREDENTIAL_ATTEMPT;
  ERROR(BW_CREDENTIALS,tc.system_errno?BW_SYSCALL:BW_MISMATCH,tc.system_errno,(int)tc.stage);
 }
 flags|=BW_CREDENTIAL_ATTEMPT;
 int cwd_detail=-1;
#ifdef GLUE_FD_OBJECTS
 if(a->admission.ready!=1 || a->admission.checked_count!=BA_COMPONENT_COUNT || a->admission.owned_count!=BA_COMPONENT_COUNT)
  ERROR(BW_CWD,BW_MISMATCH,0,TCWD_STAGE_REQUEST);
 if(nr_before(a,a->deadline,NR_READY))ERROR(BW_CWD,BW_TIMEOUT,0,TCWD_STAGE_BEFORE_CHANGE);
 #ifdef GLUE_RUNTIME_PROFILE
 if(a->runtime_cwd_fd<3)ERROR(BW_CWD,BW_MISMATCH,0,TCWD_STAGE_REQUEST);
 int cwd_fd=a->runtime_cwd_fd;
 #else
 int cwd_fd=a->admission.components[6].fd;
 #endif
 struct tcwd_request cwd_request={cwd_fd,a->request.cwd_device,a->request.cwd_inode};
 struct tcwd_guard cwd_guard={a,object_cwd_before};struct tcwd_result selected;struct tcwd_error ce;
 if(tcwd_select_in_owned_child(&cwd_request,(uint64_t)a->owner,tcwd_native_operations(),&cwd_guard,&selected,&ce))
  ERROR(BW_CWD,ce.system_errno?BW_SYSCALL:(ce.reason==TCWD_REASON_DEADLINE?BW_TIMEOUT:BW_MISMATCH),ce.system_errno,tcwd_error_detail(&ce));
 cwd_detail=TCWD_STAGE_FINAL|TCWD_MUTATION_DETAIL;
 if(!selected.ready)ERROR(BW_CWD,BW_MISMATCH,0,cwd_detail);
 if(nr_before(a,a->deadline,NR_READY))ERROR(BW_CWD,BW_TIMEOUT,0,cwd_detail);
 cwd_detail=TCWD_STAGE_READBACK|TCWD_MUTATION_DETAIL;
#else
 if(chdir(a->cwd))ERROR(BW_CWD,BW_SYSCALL,errno,-1);
#endif
 struct stat cwd;
 if(stat(".",&cwd))ERROR(BW_CWD,BW_SYSCALL,errno,cwd_detail);
 if((uint64_t)(uint32_t)cwd.st_dev!=a->request.cwd_device || (uint64_t)cwd.st_ino!=a->request.cwd_inode || !S_ISDIR(cwd.st_mode))
  ERROR(BW_CWD,BW_MISMATCH,0,cwd_detail);
#ifdef GLUE_FD_OBJECTS
 if(nr_before(a,a->deadline,NR_READY))ERROR(BW_CWD,BW_TIMEOUT,0,TCWD_STAGE_FINAL|TCWD_MUTATION_DETAIL);
#endif
 struct td_record scratch[TD_MAX_CAPACITY];struct td_plan plan={{0,1,2,a->endpoints.copies[TE_GATE_READER],a->endpoints.copies[TE_STATUS_WRITER]},scratch,TD_MAX_CAPACITY};
 struct td_error td;
 if(td_close_in_owned_child(&plan,(uint64_t)a->owner,td_native_operations(),&td)) {
  if(td.closure_attempted)flags|=BW_DESCRIPTOR_ATTEMPT;
  ERROR(BW_DESCRIPTORS,td.system_errno?BW_SYSCALL:BW_MISMATCH,td.system_errno,td.fd);
 }
 /* td_closure_attempted describes actual nonkeep-close attempts. This topology
  * always has admission/output/source/spare FDs in addition to the five keeps. */
 if(td.closure_attempted)flags|=BW_DESCRIPTOR_ATTEMPT;
 if(flags!=BR_READY_FLAGS)ERROR(BW_READY_IO,BW_MISMATCH,0,-1);
 if(bs_check_in_owned_child(&a->signals,&se))ERROR(BW_READY_IO,se.system_errno?BW_SYSCALL:BW_SIGNAL_POLICY,se.system_errno,se.signal_number);
#ifdef GLUE_FD_OBJECTS
 if(nr_before(a,a->deadline,NR_READY))ERROR(BW_READY_IO,BW_TIMEOUT,0,-1);
 struct tfo_plan object_plan;for(unsigned i=0;i<5;i++)object_plan.keep[i]=plan.keep[i];
 struct tfo_error oe;
 if(tfo_snapshot_in_owned_child(&object_plan,(uint64_t)a->owner,tfo_native_operations(),&a->child_objects,&oe))
  ERROR(BW_READY_IO,oe.system_errno?BW_SYSCALL:BW_MISMATCH,oe.system_errno,oe.fd);
 if(nr_before(a,a->deadline,NR_READY))ERROR(BW_READY_IO,BW_TIMEOUT,0,-1);
#endif
 struct bw_status ready;memset(&ready,0,sizeof(ready));ready.binding=binding;ready.kind=BW_READY;ready.detail=-1;ready.mutation_flags=flags;
 uint64_t ids[]={getuid(),geteuid(),getgid(),getegid()};
 for(unsigned i=0;i<4;i++)if(!ids[i] || ids[i]>INT32_MAX)ERROR(BW_READY_IO,BW_RANGE,0,(int)i);
 ready.real_uid=(uint32_t)ids[0];ready.effective_uid=(uint32_t)ids[1];ready.real_gid=(uint32_t)ids[2];ready.effective_gid=(uint32_t)ids[3];
 gid_t groups[16];int count=getgroups(16,groups);
 if(count<0)ERROR(BW_READY_IO,BW_SYSCALL,errno,-1);
 if(count<1 || count>16)ERROR(BW_READY_IO,BW_RANGE,0,count);
 ready.group_count=(uint32_t)count;
 for(int i=0;i<count;i++){if((uint64_t)groups[i]>INT32_MAX)ERROR(BW_READY_IO,BW_RANGE,0,i);ready.groups[i]=(uint32_t)groups[i];}
 ready.cwd_device=(uint64_t)(uint32_t)cwd.st_dev;ready.cwd_inode=(uint64_t)cwd.st_ino;
 for(unsigned i=0;i<5;i++)ready.kept_fds[i]=(uint32_t)plan.keep[i];
 memcpy(ready.signal_policy_sha256,a->policy_sha,32);
 if(nr_before(a,a->deadline,NR_READY))ERROR(BW_READY_IO,BW_TIMEOUT,0,-1);
 /* Failed/late writes can have delivered a full record or prefix; never append
  * another record after failure, which could fabricate a new framing boundary. */
 if(status_write(a,&ready))_exit(121);
 sequence=1;
 struct bio_result go;struct bio_error ioe;
 if(bio_read_record(plan.keep[3],BW_GO_SIZE,a->deadline,bio_native_operations(),&go,&ioe))
  ERROR(BW_GO_IO,ioe.system_errno?BW_SYSCALL:(ioe.reason==BIO_REASON_TRUNCATED?BW_EOF:BW_TIMEOUT),ioe.system_errno,-1);
 struct bw_binding decoded;
#ifdef GLUE_FD_OBJECTS
 if(bow_go_decode(go.prefix,go.bytes_moved,&binding,&decoded)!=BW_OK)ERROR(BW_GO_VALIDATE,BW_MISMATCH,0,-1);
#else
 if(bw_go_decode(go.prefix,go.bytes_moved,&binding,&decoded)!=BW_OK)ERROR(BW_GO_VALIDATE,BW_MISMATCH,0,-1);
#endif
 if(bio_require_eof(plan.keep[3],a->deadline,bio_native_operations(),&go,&ioe))
  ERROR(BW_GO_VALIDATE,ioe.system_errno?BW_SYSCALL:(ioe.reason==BIO_REASON_TRAILING?BW_EXTRA:BW_TIMEOUT),ioe.system_errno,-1);
 int gate=plan.keep[3];
 /* close is attempted exactly once; do not retry EINTR or guess ownership. */
 if(close(gate))ERROR(BW_GATE_CLOSE,BW_SYSCALL,errno,gate);
 if(bs_release_in_owned_child(&a->signals,&se))ERROR(BW_MASK_RESTORE,se.system_errno?BW_SYSCALL:BW_SIGNAL_POLICY,se.system_errno,se.signal_number);
 struct bw_status attempt;memset(&attempt,0,sizeof(attempt));attempt.binding=binding;attempt.kind=BW_EXEC_ATTEMPT;
 attempt.sequence=1;attempt.stage=BW_EXEC;attempt.mutation_flags=flags;attempt.detail=-1;
 if(status_write(a,&attempt))_exit(122);
 sequence=2;
#ifdef GLUE_RUNTIME_PROFILE
 if(!a->runtime_plan.ready)ERROR(BW_EXEC,BW_MISMATCH,0,-1);
 execve(a->executable,a->runtime_plan.argv,a->runtime_plan.environment);
#else
 char *const argv[]={a->executable,"--request-sha256",a->request_hex,NULL};char *const environment[]={NULL};
 execve(a->executable,argv,environment);
#endif
 int saved=errno;ERROR(BW_EXEC,BW_SYSCALL,saved,-1);
}
#undef ERROR
