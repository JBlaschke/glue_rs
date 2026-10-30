/* Pure formatter controls: no libdtrace link or native process operations. */
#include "runtime_stopped_trace.h"
#include <assert.h>
#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
static void cleared(const char *p,size_t used){assert(!used&&!p[0]);}
int main(int argc,char **argv){
 char out[RT_PROGRAM_CAPACITY];size_t used=9;struct ts_binding b={TS_OWNED_RUNTIME_RECIPE,1,2,{1},{2}};
 if(argc==2&&!strcmp(argv[1],"bounds")){
  memset(out,0xa5,sizeof(out));assert(rt_stopped_program(NULL,out,&used));cleared(out,used);
  used=9;assert(rt_stopped_program(&b,NULL,&used)&&!used);out[0]='x';assert(rt_stopped_program(&b,out,NULL)&&!out[0]);
  b.fixture=1;assert(rt_stopped_program(&b,out,&used));cleared(out,used);b.fixture=2;
  b.owner_pid=0;assert(rt_stopped_program(&b,out,&used));cleared(out,used);b.owner_pid=1;
  b.target_pid=1;assert(rt_stopped_program(&b,out,&used));cleared(out,used);b.target_pid=2;
  b.target_pid=UINT32_MAX;assert(rt_stopped_program(&b,out,&used));cleared(out,used);b.target_pid=2;
  memset(b.request_sha256,0,32);assert(rt_stopped_program(&b,out,&used));cleared(out,used);b.request_sha256[0]=1;
  memset(b.catalog_sha256,0,32);assert(rt_stopped_program(&b,out,&used));cleared(out,used);b.catalog_sha256[0]=2;
  b.owner_pid=INT32_MAX;b.target_pid=INT32_MAX-1;assert(!rt_stopped_program(&b,out,&used)&&used==strlen(out)&&used<sizeof(out));puts("PASS formatter bounds");return 0;
 }
 assert(argc==3);char *e;unsigned long owner=strtoul(argv[1],&e,10);assert(!*e&&owner<=UINT32_MAX);unsigned long target=strtoul(argv[2],&e,10);assert(!*e&&target<=UINT32_MAX);b.owner_pid=(uint32_t)owner;b.target_pid=(uint32_t)target;assert(!rt_stopped_program(&b,out,&used));assert(fwrite(out,1,used,stdout)==used);return 0;
}
