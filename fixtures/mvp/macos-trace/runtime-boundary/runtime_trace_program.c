#include "runtime_trace_program.h"
#include "runtime_stopped_trace.h"
#include <limits.h>
#include <stdarg.h>
#include <stdio.h>
#include <string.h>
struct program_buffer { char bytes[RT_PROGRAM_CAPACITY];size_t used;int failed; };
static void append(struct program_buffer *b,const char *format,...) {
 if(b->failed)return;
 va_list args;va_start(args,format);
 int n=vsnprintf(b->bytes+b->used,sizeof(b->bytes)-b->used,format,args);
 va_end(args);
 if(n<0 || (size_t)n>=sizeof(b->bytes)-b->used)b->failed=1;
 else b->used+=(size_t)n;
}
static void header(struct program_buffer *b,unsigned kind,const char *detail) {
 append(b,"trace((uint64_t)%u);trace((uint64_t)timestamp);trace((uint64_t)pid);trace((uint64_t)tid);trace((uint64_t)(%s));",kind,detail);
}
static int fixed_program(uint32_t target_pid,char out[RT_PROGRAM_CAPACITY],size_t *used,const char *profile) {
 if(used)*used=0;
 if(out)out[0]=0;
 if(!out || !used || !target_pid || target_pid>INT32_MAX)return -1;
 struct program_buffer b={0};
 append(&b,"#pragma D option quiet\n/* %s */\nBEGIN { watched[%u]=1;",profile,target_pid);
 header(&b,1,"0");append(&b,"}\nEND {");header(&b,17,"0");append(&b,"}\n");
 const char *providers[]={"syscall","mach_trap"};
 for(unsigned family=0;family<2;family++)for(unsigned returning=0;returning<2;returning++) {
  append(&b,"%s:::%s /watched[pid]/ {",providers[family],returning?"return":"entry");
  header(&b,family?(returning?16u:15u):(returning?3u:2u),"ppid");
  unsigned count=returning?(family?1u:4u):8u;
  for(unsigned i=0;i<count;i++)append(&b,"trace((uint64_t)arg%u);",i);
  if(returning&&!family)append(&b,"trace((uint64_t)errno);");
  append(&b,"}\n");
 }
 static const struct {const char *name,*detail;unsigned kind;int leading;} clauses[]={
  {"create","args[0]->pr_pid",4,1},{"start","ppid",5,1},{"exec-success","ppid",7,1},
  {"exit","arg0",6,0},{"exec-failure","arg0",8,0},{"lwp-create","args[0]->pr_lwpid",9,0},
  {"lwp-start","0",10,0},{"lwp-exit","0",11,0},{"spawn-success","0",12,0},{"spawn-failure","arg0",13,0}
 };
 for(size_t i=0;i<sizeof(clauses)/sizeof(clauses[0]);i++) {
  append(&b,"proc:::%s /watched[pid]/ {",clauses[i].name);
  if(clauses[i].leading)append(&b,"watched[pid]=1;");
  header(&b,clauses[i].kind,clauses[i].detail);append(&b,"}\n");
 }
 append(&b,"proc:::exited /watched[args[0]->pr_pid]/ {");header(&b,18,"args[0]->pr_pid");
 append(&b,"trace((uint64_t)arg1);trace((uint64_t)args[0]->pr_addr);trace((uint64_t)((struct proc *)args[0]->pr_addr)->p_refcount);}\n");
 if(b.failed)return -1;
 memcpy(out,b.bytes,b.used+1);*used=b.used;return 0;
}
int rt_program(uint32_t target_pid,char out[RT_PROGRAM_CAPACITY],size_t *used) {
 return fixed_program(target_pid,out,used,RT_PROGRAM_PROFILE);
}
int rt_images_program(uint32_t target_pid,char out[RT_PROGRAM_CAPACITY],size_t *used) {
 return fixed_program(target_pid,out,used,RT_IMAGES_PROGRAM_PROFILE);
}

int rt_stopped_program(const struct ts_binding *binding,char out[RT_PROGRAM_CAPACITY],size_t *used) {
 if(used) {
  *used=0;
 }
 if(out) {
  out[0]=0;
 }
 if(!out||!used||!binding||binding->fixture!=TS_OWNED_RUNTIME_RECIPE||
    !binding->owner_pid||binding->owner_pid>INT32_MAX||!binding->target_pid||
    binding->target_pid>INT32_MAX||binding->owner_pid==binding->target_pid)return -1;
 unsigned request_present=0,catalog_present=0;
 char request[65],catalog[65];static const char hex[]="0123456789abcdef";
 for(unsigned i=0;i<32;i++) {
  unsigned a=binding->request_sha256[i],b=binding->catalog_sha256[i];
  request_present|=a;catalog_present|=b;
  request[2*i]=hex[a>>4];request[2*i+1]=hex[a&15];
  catalog[2*i]=hex[b>>4];catalog[2*i+1]=hex[b&15];
 }
 if(!request_present||!catalog_present) {
  return -1;
 }
 request[64]=catalog[64]=0;
 struct program_buffer b={0};
 append(&b,
  "#pragma D option quiet\n");
 append(&b,
  "/* glue-stopped-runtime-v1; first-selected-exec; owner-control-snapshots; no-process-creation */\n");
 append(&b,
  "/* owner=%u target=%u request=%s catalog=%s */\n",
  binding->owner_pid,
  binding->target_pid,
  request,
  catalog);
 append(&b,
  "BEGIN {watched[%u]=1;trace((uint64_t)1);trace((uint64_t)timestamp);trace((uint64_t)pid);trace((uint64_t)tid);trace((uint64_t)(0));}\n",
  binding->target_pid);
 append(&b,
  "END {trace((uint64_t)17);trace((uint64_t)timestamp);trace((uint64_t)pid);trace((uint64_t)tid);trace((uint64_t)(0));}\n");
 append(&b,
  "syscall:::entry /watched[pid] || (pid==%u && (probefunc==\"proc_info\" || probefunc==\"wait4\" || probefunc==\"wait4_nocancel\" || probefunc==\"kill\"))/ {self->call_id=self->call_id+1;self->s0=(uint64_t)arg0;self->s1=(uint64_t)arg1;self->s2=(uint64_t)arg2;self->s3=(uint64_t)arg3;self->s4=(uint64_t)arg4;self->s5=(uint64_t)arg5;selected_exec[pid]=probefunc==\"execve\"?tid:selected_exec[pid];trace((uint64_t)2);trace((uint64_t)timestamp);trace((uint64_t)pid);trace((uint64_t)tid);trace((uint64_t)(pid==%u?self->call_id:ppid));trace((uint64_t)arg0);trace((uint64_t)arg1);trace((uint64_t)arg2);trace((uint64_t)arg3);trace((uint64_t)arg4);trace((uint64_t)arg5);trace((uint64_t)arg6);trace((uint64_t)arg7);}\n",
  binding->owner_pid,
  binding->owner_pid);
 append(&b,
  "syscall:::return /watched[pid]/ {trace((uint64_t)3);trace((uint64_t)timestamp);trace((uint64_t)pid);trace((uint64_t)tid);trace((uint64_t)(ppid));trace((uint64_t)arg0);trace((uint64_t)arg1);trace((uint64_t)arg2);trace((uint64_t)arg3);trace((uint64_t)errno);}\n");
 append(&b,
  "mach_trap:::entry /watched[pid]/ {trace((uint64_t)15);trace((uint64_t)timestamp);trace((uint64_t)pid);trace((uint64_t)tid);trace((uint64_t)(ppid));trace((uint64_t)arg0);trace((uint64_t)arg1);trace((uint64_t)arg2);trace((uint64_t)arg3);trace((uint64_t)arg4);trace((uint64_t)arg5);trace((uint64_t)arg6);trace((uint64_t)arg7);}\n");
 append(&b,
  "mach_trap:::return /watched[pid]/ {trace((uint64_t)16);trace((uint64_t)timestamp);trace((uint64_t)pid);trace((uint64_t)tid);trace((uint64_t)(ppid));trace((uint64_t)arg0);}\n");
 append(&b,
  "proc:::create /watched[pid]/ {watched[pid]=1;trace((uint64_t)4);trace((uint64_t)timestamp);trace((uint64_t)pid);trace((uint64_t)tid);trace((uint64_t)(args[0]->pr_pid));}\n");
 append(&b,
  "proc:::start /watched[pid]/ {watched[pid]=1;trace((uint64_t)5);trace((uint64_t)timestamp);trace((uint64_t)pid);trace((uint64_t)tid);trace((uint64_t)(ppid));}\n");
 append(&b,
  "proc:::exec-success /watched[pid]/ {watched[pid]=1;image_seq[pid]=image_seq[pid]+1;pending_tid[pid]=(selected_exec[pid]!=0 && image_seq[pid]==1)?tid:0;selected_exec[pid]=0;trace((uint64_t)7);trace((uint64_t)timestamp);trace((uint64_t)pid);trace((uint64_t)tid);trace((uint64_t)(ppid));}\n");
 append(&b,
  "proc:::exit /watched[pid]/ {trace((uint64_t)6);trace((uint64_t)timestamp);trace((uint64_t)pid);trace((uint64_t)tid);trace((uint64_t)(arg0));}\n");
 append(&b,
  "proc:::exec-failure /watched[pid]/ {selected_exec[pid]=0;trace((uint64_t)8);trace((uint64_t)timestamp);trace((uint64_t)pid);trace((uint64_t)tid);trace((uint64_t)(arg0));}\n");
 append(&b,
  "proc:::lwp-create /watched[pid]/ {trace((uint64_t)9);trace((uint64_t)timestamp);trace((uint64_t)pid);trace((uint64_t)tid);trace((uint64_t)(args[0]->pr_lwpid));}\n");
 append(&b,
  "proc:::lwp-start /watched[pid]/ {trace((uint64_t)10);trace((uint64_t)timestamp);trace((uint64_t)pid);trace((uint64_t)tid);trace((uint64_t)(0));}\n");
 append(&b,
  "proc:::lwp-exit /watched[pid]/ {trace((uint64_t)11);trace((uint64_t)timestamp);trace((uint64_t)pid);trace((uint64_t)tid);trace((uint64_t)(0));}\n");
 append(&b,
  "proc:::spawn-success /watched[pid]/ {trace((uint64_t)12);trace((uint64_t)timestamp);trace((uint64_t)pid);trace((uint64_t)tid);trace((uint64_t)(0));}\n");
 append(&b,
  "proc:::spawn-failure /watched[pid]/ {trace((uint64_t)13);trace((uint64_t)timestamp);trace((uint64_t)pid);trace((uint64_t)tid);trace((uint64_t)(arg0));}\n");
 append(&b,
  "proc:::exited /watched[args[0]->pr_pid]/ {trace((uint64_t)18);trace((uint64_t)timestamp);trace((uint64_t)pid);trace((uint64_t)tid);trace((uint64_t)(args[0]->pr_pid));trace((uint64_t)arg1);trace((uint64_t)args[0]->pr_addr);trace((uint64_t)((struct proc *)args[0]->pr_addr)->p_refcount);}\n");
 append(&b,
  "proc:::lwp-start /watched[pid] && image_seq[pid]==1 && pending_tid[pid]!=0 && pending_tid[pid]==tid/ {trace((uint64_t)19);trace((uint64_t)timestamp);trace((uint64_t)pid);trace((uint64_t)tid);trace((uint64_t)(image_seq[pid]));trace((uint64_t)pending_tid[pid]);trace((uint64_t)17);raise(17);pending_tid[pid]=0;}\n");
 append(&b,
  "syscall::proc_info:return /pid==%u && (self->s0==3 && (self->s1==%u || self->s1==%u) && self->s2==1 && self->s4!=0 && self->s5==176 && ((self->s1==%u && (self->s3==1 || self->s3==2)) || (self->s1==%u && self->s3>=3 && self->s3<=2147483647)))/ {trace((uint64_t)20);trace((uint64_t)timestamp);trace((uint64_t)pid);trace((uint64_t)tid);trace((uint64_t)(self->call_id));trace((uint64_t)arg0);trace((uint64_t)arg1);trace((uint64_t)arg2);trace((uint64_t)arg3);trace((uint64_t)errno);tracemem(copyin(self->s4,176),176);}\n",
  binding->owner_pid,
  binding->owner_pid,
  binding->target_pid,
  binding->target_pid,
  binding->owner_pid);
 append(&b,
  "syscall::wait4:return /pid==%u && (self->s0==%u && self->s1!=0 && (self->s2==3 || self->s2==1) && self->s3==0)/ {trace((uint64_t)21);trace((uint64_t)timestamp);trace((uint64_t)pid);trace((uint64_t)tid);trace((uint64_t)(self->call_id));trace((uint64_t)arg0);trace((uint64_t)arg1);trace((uint64_t)arg2);trace((uint64_t)arg3);trace((uint64_t)errno);tracemem(copyin(self->s1,4),4);}\n",
  binding->owner_pid,
  binding->target_pid);
 append(&b,
  "syscall::wait4_nocancel:return /pid==%u && (self->s0==%u && self->s1!=0 && (self->s2==3 || self->s2==1) && self->s3==0)/ {trace((uint64_t)21);trace((uint64_t)timestamp);trace((uint64_t)pid);trace((uint64_t)tid);trace((uint64_t)(self->call_id));trace((uint64_t)arg0);trace((uint64_t)arg1);trace((uint64_t)arg2);trace((uint64_t)arg3);trace((uint64_t)errno);tracemem(copyin(self->s1,4),4);}\n",
  binding->owner_pid,
  binding->target_pid);
 append(&b,
  "syscall::kill:return /pid==%u/ {trace((uint64_t)22);trace((uint64_t)timestamp);trace((uint64_t)pid);trace((uint64_t)tid);trace((uint64_t)(self->call_id));trace((uint64_t)arg0);trace((uint64_t)arg1);trace((uint64_t)arg2);trace((uint64_t)arg3);trace((uint64_t)errno);}\n",
  binding->owner_pid);
 append(&b,
  "syscall:::return /pid==%u && ((probefunc==\"proc_info\" && !(self->s0==3 && (self->s1==%u || self->s1==%u) && self->s2==1 && self->s4!=0 && self->s5==176 && ((self->s1==%u && (self->s3==1 || self->s3==2)) || (self->s1==%u && self->s3>=3 && self->s3<=2147483647)))) || ((probefunc==\"wait4\" || probefunc==\"wait4_nocancel\") && !(self->s0==%u && self->s1!=0 && (self->s2==3 || self->s2==1) && self->s3==0)))/ {trace((uint64_t)23);trace((uint64_t)timestamp);trace((uint64_t)pid);trace((uint64_t)tid);trace((uint64_t)(self->call_id));trace((uint64_t)arg0);trace((uint64_t)arg1);trace((uint64_t)arg2);trace((uint64_t)arg3);trace((uint64_t)errno);}\n",
  binding->owner_pid,
  binding->owner_pid,
  binding->target_pid,
  binding->target_pid,
  binding->owner_pid,
  binding->target_pid);
 if(b.failed) {
  return -1;
 }
 memcpy(out,b.bytes,b.used+1);
 *used=b.used;
 return 0;
}
