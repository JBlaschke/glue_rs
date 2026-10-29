#include "runtime_trace_program.h"
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
int rt_program(uint32_t target_pid,char out[RT_PROGRAM_CAPACITY],size_t *used) {
 if(used)*used=0;
 if(out)out[0]=0;
 if(!out || !used || !target_pid || target_pid>INT32_MAX)return -1;
 struct program_buffer b={0};
 append(&b,"#pragma D option quiet\n/* " RT_PROGRAM_PROFILE " */\nBEGIN { watched[%u]=1;",target_pid);
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
