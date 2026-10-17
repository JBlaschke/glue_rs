#define _POSIX_C_SOURCE 200809L
#define _DARWIN_C_SOURCE 1
#include "owned_trace_backend.h"
#include <errno.h>
#include <fcntl.h>
#include <inttypes.h>
#include <limits.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <time.h>
#include <unistd.h>
#ifdef __APPLE__
#include <dtrace.h>

#define NS_SECOND UINT64_C(1000000000)
#define MAX_PROGRAM 16384u
#define MAX_LINE 8192u
#define MAX_DIAGNOSTICS 16u
#define MAX_DRAIN_WORK 4096u
#define SHADOW_BIT UINT32_C(0x20)
enum raw_kind { RK_BEGIN=1,RK_SYSCALL_ENTRY,RK_SYSCALL_RETURN,RK_CREATE,RK_START,
 RK_EXIT,RK_EXEC_SUCCESS,RK_EXEC_FAILURE,RK_LWP_CREATE,RK_LWP_START,RK_LWP_EXIT,
 RK_SPAWN_SUCCESS,RK_SPAWN_FAILURE,RK_UNUSED_OPEN,RK_MACH_ENTRY,RK_MACH_RETURN,
 RK_END,RK_EXITED };
struct enabling { uint32_t epid,probe; unsigned kind; };
struct otb_backend {
 struct otb_snapshot view; int directory,files[4],failed,fault_delivered; unsigned diagnostics;
 uint64_t last_clock,callback_deadline; int clock_seen,draining;
 dtrace_hdl_t *handle; dtrace_probedesc_t inventory[OTB_MAX_PROBES];
 struct enabling enabling[OTB_MAX_ENABLINGS];
 ts_consume_fn consume; void *consume_context;
 char program[MAX_PROGRAM];
};
enum { PROGRAM_FILE,INVENTORY_FILE,EVENT_FILE,ERROR_FILE };
static const char *const file_names[]={"program.d","probes.tsv","events.jsonl","errors.jsonl"};
static int time_before(struct otb_backend *,enum otb_stage,uint64_t,int);
static int failure(struct otb_backend *,enum otb_stage,enum otb_reason,int,int,int,const char *);
struct line { char bytes[MAX_LINE]; size_t used; int failed; };
static void add(struct line *l,const char *format,...) {
 if(l->failed)return;
 va_list args;va_start(args,format);int n=vsnprintf(l->bytes+l->used,sizeof(l->bytes)-l->used,format,args);va_end(args);
 if(n<0 || (size_t)n>=sizeof(l->bytes)-l->used)l->failed=1;else l->used+=(size_t)n;
}
static void quoted(struct line *l,const char *s) {
 add(l,"\"");
 for(const unsigned char *p=(const unsigned char *)s;*p;p++) {
  if(*p=='"' || *p=='\\')add(l,"\\%c",*p);
  else if(*p<32 || *p>=127)add(l,"\\u%04x",*p);
  else add(l,"%c",*p);
 }
 add(l,"\"");
}
static int write_bytes(struct otb_backend *b,enum otb_stage stage,uint64_t d,int fd,const void *bytes,size_t n,uint64_t *confirmed,uint64_t limit) {
 if(*confirmed>limit || n>limit-*confirmed)
  return d?failure(b,stage,OTB_LIMIT,0,0,EFBIG,"output byte bound exceeded"):-1;
 const unsigned char *p=bytes;unsigned tries=0;
 while(n) {
  if(d && time_before(b,stage,d,1))return -1;
  if(++tries>4096)return d?failure(b,stage,OTB_LIMIT,0,0,EIO,"output retry bound exceeded"):-1;
  ssize_t k=write(fd,p,n);
  if(k<0 && errno==EINTR)continue;
  if(k<0)return d?failure(b,stage,OTB_OUTPUT,errno,0,EIO,"output write failed"):-1;
  if(!k)return d?failure(b,stage,OTB_OUTPUT,0,0,EIO,"output made no progress"):-1;
  *confirmed+=(uint64_t)k;p+=(size_t)k;n-=(size_t)k;
 }
 return 0;
}
static void diagnostic(struct otb_backend *b,const struct otb_error *e) {
 if(b->files[ERROR_FILE]<0 || b->diagnostics++>=MAX_DIAGNOSTICS)return;
 struct line l={0};add(&l,"{\"stage\":%d,\"reason\":%d,\"system_errno\":%d,\"libdtrace_code\":%d,\"callback_error\":%d,\"message\":",e->stage,e->reason,e->system_errno,e->libdtrace_code,e->callback_error);
 quoted(&l,e->message);add(&l,"}\n");
 if(!l.failed)(void)write_bytes(b,OTB_CLOSE,0,b->files[ERROR_FILE],l.bytes,l.used,&b->view.diagnostic_bytes,OTB_MAX_DIAGNOSTIC_BYTES);
}
static void callback_diagnostic(struct otb_backend *b,struct line *l) {
 if(b->files[ERROR_FILE]<0 || b->diagnostics++>=MAX_DIAGNOSTICS || l->failed)return;
 (void)write_bytes(b,OTB_PUMP,0,b->files[ERROR_FILE],l->bytes,l->used,&b->view.diagnostic_bytes,OTB_MAX_DIAGNOSTIC_BYTES);
}
static int failure(struct otb_backend *b,enum otb_stage stage,enum otb_reason reason,int posix,int native,int bridge,const char *message) {
 struct otb_error e={stage,reason,posix,native,bridge,{0}};
 snprintf(e.message,sizeof(e.message),"%s",message?message:"");
 if(b->view.first_error.reason==OTB_OK)b->view.first_error=e;
 if(stage==OTB_CLOSE && b->view.close_error.reason==OTB_OK)b->view.close_error=e;
 b->failed=1;diagnostic(b,&e);return -1;
}
static int native_failure(struct otb_backend *b,enum otb_stage stage,const char *operation,int code) {
 const char *message=dtrace_errmsg(b->handle,code);char bounded[513];
 snprintf(bounded,sizeof(bounded),"%s: %.460s",operation,message?message:"");
 return failure(b,stage,OTB_LIBDTRACE,0,code,EIO,bounded);
}
static int status_error(struct otb_backend *b,int *error) {
 *error=b->view.first_error.callback_error?b->view.first_error.callback_error:EIO;return -1;
}
static int actual_clock(uint64_t *out,int *error) {
 struct timespec t;
 if(clock_gettime(CLOCK_MONOTONIC,&t)){*error=errno;return -1;}
 if(t.tv_sec<0 || t.tv_nsec<0 || t.tv_nsec>=1000000000L ||
    (uint64_t)t.tv_sec>(UINT64_MAX-(uint64_t)t.tv_nsec)/NS_SECOND){*error=EOVERFLOW;return -1;}
 *out=(uint64_t)t.tv_sec*NS_SECOND+(uint64_t)t.tv_nsec;*error=0;return 0;
}
static int owner(struct otb_backend *b,enum otb_stage stage) {
 pid_t p=getpid();
 return p>0 && (uint64_t)p==b->view.binding.owner_pid?0:
  failure(b,stage,OTB_OWNER,0,0,EPERM,"controller ownership changed");
}
static int time_before(struct otb_backend *b,enum otb_stage stage,uint64_t d,int require_before) {
 uint64_t n=0;int e=0;
 if(actual_clock(&n,&e))return failure(b,stage,OTB_CLOCK,e==EOVERFLOW?0:e,0,e,"monotonic clock failed");
 if(b->clock_seen && n<b->last_clock)return failure(b,stage,OTB_CLOCK,0,0,EPROTO,"monotonic clock rolled back");
 b->clock_seen=1;b->last_clock=n;
 if(require_before && n>=d)return failure(b,stage,OTB_DEADLINE,0,0,ETIMEDOUT,"absolute deadline expired");
 return 0;
}
static int deadline(struct otb_backend *b,enum otb_stage stage,uint64_t d,int cleanup,int require_before) {
 if(owner(b,stage))return -1;
 if(time_before(b,stage,d,require_before))return -1;
 if(b->view.cleanup_deadline_ns) {
  if(d!=b->view.cleanup_deadline_ns)return failure(b,stage,OTB_BINDING,0,0,EPROTO,"cleanup deadline changed");
 } else if(cleanup || d!=b->view.original_attempt_deadline_ns) {
  if(d<=b->last_clock || d-b->last_clock>UINT64_C(2000000000))
   return failure(b,stage,OTB_BINDING,0,0,EPROTO,"invalid cleanup deadline");
  b->view.cleanup_deadline_ns=d;
 }
 return 0;
}
static uint32_t operation_owner(void *context,int *error) {
 (void)context;pid_t p=getpid();
 if(p<=0 || (uint64_t)p>INT32_MAX){*error=EOVERFLOW;return 0;}
 *error=0;return (uint32_t)p;
}
static int operation_clock(void *context,uint64_t *now,int *error) {
 (void)context;return actual_clock(now,error);
}
static int emit(struct otb_backend *b,enum ts_event_kind kind) {
 if(!b->consume)return failure(b,b->draining?OTB_DRAIN:OTB_PUMP,OTB_CONSUMER,0,0,EPROTO,"event outside pump/drain");
 struct ts_event event={kind,b->view.binding};
 if(b->consume(b->consume_context,&event))return failure(b,b->draining?OTB_DRAIN:OTB_PUMP,OTB_CONSUMER,0,0,EPROTO,"coordinator rejected event");
 return 0;
}
static void fault(struct otb_backend *b,enum ts_event_kind kind) {
 if(b->consume && !b->fault_delivered){b->fault_delivered=1;(void)emit(b,kind);}
}
static int valid_name(const char *s,size_t capacity) {
 size_t n=strnlen(s,capacity);if(n==capacity)return 0;
 for(size_t i=0;i<n;i++) {
  unsigned char c=(unsigned char)s[i];
  if(!((c>='a'&&c<='z')||(c>='A'&&c<='Z')||(c>='0'&&c<='9')||c=='_'||c=='.'||c=='-'))return 0;
 }
 return 1;
}
static unsigned kind_for(const dtrace_probedesc_t *p) {
 if(!valid_name(p->dtpd_provider,sizeof(p->dtpd_provider)) || !valid_name(p->dtpd_mod,sizeof(p->dtpd_mod)) ||
    !valid_name(p->dtpd_func,sizeof(p->dtpd_func)) || !valid_name(p->dtpd_name,sizeof(p->dtpd_name)))return 0;
 if(!strcmp(p->dtpd_provider,"dtrace") && !p->dtpd_mod[0] && !p->dtpd_func[0]) {
  if(!strcmp(p->dtpd_name,"BEGIN"))return RK_BEGIN;
  if(!strcmp(p->dtpd_name,"END"))return RK_END;
 }
 if((!strcmp(p->dtpd_provider,"syscall") || !strcmp(p->dtpd_provider,"mach_trap")) && p->dtpd_func[0]) {
  int mach=!strcmp(p->dtpd_provider,"mach_trap");
  if(!strcmp(p->dtpd_name,"entry"))return mach?RK_MACH_ENTRY:RK_SYSCALL_ENTRY;
  if(!strcmp(p->dtpd_name,"return"))return mach?RK_MACH_RETURN:RK_SYSCALL_RETURN;
 }
 if(!strcmp(p->dtpd_provider,"proc")) {
  static const struct {const char *name;unsigned kind;} kinds[]={
   {"create",RK_CREATE},{"start",RK_START},{"exit",RK_EXIT},{"exec-success",RK_EXEC_SUCCESS},
   {"exec-failure",RK_EXEC_FAILURE},{"lwp-create",RK_LWP_CREATE},{"lwp-start",RK_LWP_START},
   {"lwp-exit",RK_LWP_EXIT},{"spawn-success",RK_SPAWN_SUCCESS},{"spawn-failure",RK_SPAWN_FAILURE},{"exited",RK_EXITED}};
  for(size_t i=0;i<sizeof(kinds)/sizeof(kinds[0]);i++)if(!strcmp(p->dtpd_name,kinds[i].name))return kinds[i].kind;
 }
 return 0;
}
static int probe_equal(const dtrace_probedesc_t *a,const dtrace_probedesc_t *b) {
 return a->dtpd_id==b->dtpd_id && !strcmp(a->dtpd_provider,b->dtpd_provider) && !strcmp(a->dtpd_mod,b->dtpd_mod) &&
  !strcmp(a->dtpd_func,b->dtpd_func) && !strcmp(a->dtpd_name,b->dtpd_name);
}
static int inventory(dtrace_hdl_t *handle,const dtrace_probedesc_t *p,void *context) {
 (void)handle;struct otb_backend *b=context;
 if(!p || !kind_for(p))return 0;
 if(!p->dtpd_id || b->view.inventory_probes>=OTB_MAX_PROBES)
  return failure(b,OTB_START,OTB_INVENTORY,0,0,EPROTO,"probe inventory bound/identity");
 for(unsigned i=0;i<b->view.inventory_probes;i++)if(b->inventory[i].dtpd_id==p->dtpd_id)
  return failure(b,OTB_START,OTB_INVENTORY,0,0,EPROTO,"duplicate inventory probe ID");
 struct line l={0};add(&l,"%u\t%s\t%s\t%s\t%s\n",p->dtpd_id,p->dtpd_provider,p->dtpd_mod,p->dtpd_func,p->dtpd_name);
 if(l.failed || write_bytes(b,OTB_START,b->view.original_attempt_deadline_ns,b->files[INVENTORY_FILE],l.bytes,l.used,&b->view.inventory_bytes,OTB_MAX_DIAGNOSTIC_BYTES*16))
  return b->failed?-1:failure(b,OTB_START,OTB_OUTPUT,l.failed?0:errno,0,EIO,"inventory output failed");
 b->inventory[b->view.inventory_probes++]=*p;return 0;
}
static int required_inventory(struct otb_backend *b) {
 uint32_t seen=0;
 for(unsigned i=0;i<b->view.inventory_probes;i++)seen|=UINT32_C(1)<<kind_for(&b->inventory[i]);
 const uint32_t wanted=((UINT32_C(1)<<19)-2)&~(UINT32_C(1)<<RK_UNUSED_OPEN);
 return (seen&wanted)==wanted?0:failure(b,OTB_START,OTB_INVENTORY,0,0,EPROTO,"required BSD/Mach/proc/BEGIN/END probes missing");
}
static int bind_enabling(struct otb_backend *b,const dtrace_probedata_t *data,unsigned kind) {
 const dtrace_eprobedesc_t *d=data->dtpda_edesc;const dtrace_probedesc_t *p=data->dtpda_pdesc;int found=0;
 for(unsigned i=0;i<b->view.inventory_probes;i++)if(b->inventory[i].dtpd_id==p->dtpd_id){found=probe_equal(&b->inventory[i],p);break;}
 if(!found)return failure(b,b->draining?OTB_DRAIN:OTB_PUMP,OTB_INVENTORY,0,0,EPROTO,"event differs from retained inventory");
 for(unsigned i=0;i<b->view.enablings;i++) {
  const struct enabling *v=&b->enabling[i];
  if(v->epid==d->dtepd_epid)return v->probe==p->dtpd_id && v->kind==kind?0:
   failure(b,b->draining?OTB_DRAIN:OTB_PUMP,OTB_BINDING,0,0,EPROTO,"EPID changed clause identity");
  if(v->probe==p->dtpd_id && v->kind==kind)
   return failure(b,b->draining?OTB_DRAIN:OTB_PUMP,OTB_BINDING,0,0,EPROTO,"clause has multiple EPIDs");
 }
 if(b->view.enablings>=OTB_MAX_ENABLINGS)return failure(b,b->draining?OTB_DRAIN:OTB_PUMP,OTB_LIMIT,0,0,EFBIG,"enabling bound exceeded");
 b->enabling[b->view.enablings++]=(struct enabling){d->dtepd_epid,p->dtpd_id,kind};return 0;
}
static void layout_diagnostic(struct otb_backend *b,const dtrace_probedata_t *data) {
 if(!data || !data->dtpda_edesc || b->files[ERROR_FILE]<0 || b->diagnostics++>=MAX_DIAGNOSTICS)return;
 const dtrace_eprobedesc_t *d=data->dtpda_edesc;struct line l={0};
 add(&l,"{\"kind\":\"rejected-layout\",\"epid\":%u,\"probe_id\":%u,\"record_bytes\":%u,\"nrecs\":%d,\"records\":[",d->dtepd_epid,d->dtepd_probeid,d->dtepd_size,d->dtepd_nrecs);
 int count=d->dtepd_nrecs>=0 && d->dtepd_nrecs<=20?d->dtepd_nrecs:0;
 for(int i=0;i<count;i++) {
  const dtrace_recdesc_t *r=&d->dtepd_rec[i];
  add(&l,"%s{\"action\":%u,\"size\":%u,\"offset\":%u,\"u64\":",i?",":"",r->dtrd_action,r->dtrd_size,r->dtrd_offset);
  if(data->dtpda_data && d->dtepd_size<=8192 && r->dtrd_size==8 && r->dtrd_offset<=d->dtepd_size && 8<=d->dtepd_size-r->dtrd_offset) {
   uint64_t v;memcpy(&v,data->dtpda_data+r->dtrd_offset,8);add(&l,"%"PRIu64,v);
  }else add(&l,"null");
  add(&l,"}");
 }
 add(&l,"]}\n");if(!l.failed)(void)write_bytes(b,OTB_PUMP,0,b->files[ERROR_FILE],l.bytes,l.used,&b->view.diagnostic_bytes,OTB_MAX_DIAGNOSTIC_BYTES);
}
static int consume_probe(const dtrace_probedata_t *data,void *context) {
 struct otb_backend *b=context;enum otb_stage stage=b->draining?OTB_DRAIN:OTB_PUMP;
 const char *rejection="missing native event";
 if(!data || !data->dtpda_edesc || !data->dtpda_pdesc || !data->dtpda_data)goto invalid;
 const dtrace_eprobedesc_t *d=data->dtpda_edesc;const dtrace_probedesc_t *p=data->dtpda_pdesc;
 unsigned kind=kind_for(p);int leading=kind==RK_BEGIN || kind==RK_CREATE || kind==RK_START || kind==RK_EXEC_SUCCESS;
 unsigned payloads=kind==RK_SYSCALL_ENTRY || kind==RK_MACH_ENTRY?13:kind==RK_SYSCALL_RETURN?10:kind==RK_EXITED?8:kind==RK_MACH_RETURN?6:5;
 rejection="native descriptor shape";
 if(!kind || data->dtpda_cpu<0 || !d->dtepd_epid || !p->dtpd_id || d->dtepd_probeid!=p->dtpd_id ||
    d->dtepd_nrecs!=(int)(payloads+(unsigned)leading) || d->dtepd_size!=16+payloads*8)goto invalid;
 for(int i=0;i<d->dtepd_nrecs;i++) {
  const dtrace_recdesc_t *r=&d->dtepd_rec[i];unsigned scalar=(unsigned)i-(leading && i>0);
  if(r->dtrd_action!=DTRACEACT_DIFEXPR || r->dtrd_size!=(leading && i==0?0u:8u) ||
     r->dtrd_offset!=(leading && i==0?12u:16u+scalar*8))goto invalid;
 }
 uint64_t values[13]={0};
 for(unsigned i=0;i<payloads;i++)memcpy(&values[i],data->dtpda_data+d->dtepd_rec[i+(unsigned)leading].dtrd_offset,8);
 rejection="native scalar/header identity";
 if(values[0]!=kind || !values[1] || !values[2] || values[2]>INT32_MAX || !values[3])goto invalid;
 if(kind==RK_BEGIN || kind==RK_END) {
  if(values[2]!=b->view.binding.owner_pid || values[4])goto invalid;
 }else if(kind==RK_EXITED) {
  if(values[4]!=b->view.binding.target_pid || !values[6] || values[7]>UINT32_MAX)goto invalid;
 }else {
  if(values[2]!=b->view.binding.target_pid)goto invalid;
  if((kind==RK_SYSCALL_ENTRY || kind==RK_SYSCALL_RETURN || kind==RK_MACH_ENTRY || kind==RK_MACH_RETURN || kind==RK_START || kind==RK_EXEC_SUCCESS) && values[4]!=b->view.binding.owner_pid)goto invalid;
  if((kind==RK_LWP_START || kind==RK_LWP_EXIT || kind==RK_SPAWN_SUCCESS) && values[4])goto invalid;
  if(kind==RK_CREATE && (!values[4] || values[4]>INT32_MAX))goto invalid;
 }
 if(bind_enabling(b,data,kind))goto rejected;
 if(time_before(b,stage,b->callback_deadline,1))goto rejected;
 rejection="native lifecycle order";
 if(b->view.end_count)goto invalid;
 if(kind==RK_BEGIN) {if(b->view.begin_count || b->draining)goto invalid;}
 else if(!b->view.begin_count)goto invalid;
 if(kind==RK_END && (!b->draining || !b->view.stopped || !b->view.terminal_count))goto invalid;
 if(kind==RK_EXITED && !(values[7]&SHADOW_BIT) && b->view.terminal_count)goto invalid;
 if(b->view.terminal_count && kind!=RK_EXITED && kind!=RK_LWP_EXIT && kind!=RK_END)goto invalid;
 if(b->view.events>=TS_MAX_EVENTS){failure(b,stage,OTB_LIMIT,0,0,EFBIG,"raw event bound exceeded");goto rejected;}
 struct line l={0};
 add(&l,"{\"event\":%"PRIu64",\"cpu\":%d,\"epid\":%u,\"probe_id\":%u,\"record_bytes\":%u,\"header_record_indexes\":[%d,%d,%d,%d,%d],\"kind\":%u,\"timestamp\":%"PRIu64",\"pid\":%"PRIu64",\"tid\":%"PRIu64",\"detail\":%"PRIu64",\"provider\":",b->view.events+1,data->dtpda_cpu,d->dtepd_epid,p->dtpd_id,d->dtepd_size,leading,leading+1,leading+2,leading+3,leading+4,kind,values[1],values[2],values[3],values[4]);
 quoted(&l,p->dtpd_provider);add(&l,",\"module\":");quoted(&l,p->dtpd_mod);add(&l,",\"function\":");quoted(&l,p->dtpd_func);add(&l,",\"name\":");quoted(&l,p->dtpd_name);add(&l,",\"records\":[");
 for(int i=0;i<d->dtepd_nrecs;i++) {
  const dtrace_recdesc_t *r=&d->dtepd_rec[i];const unsigned char *raw=(const unsigned char *)data->dtpda_data+r->dtrd_offset;
  add(&l,"%s{\"action\":%u,\"size\":%u,\"offset\":%u,\"hex\":\"",i?",":"",r->dtrd_action,r->dtrd_size,r->dtrd_offset);
  for(uint32_t j=0;j<r->dtrd_size;j++)add(&l,"%02x",raw[j]);add(&l,"\"}");
 }
 add(&l,"]}\n");
 if(l.failed || write_bytes(b,stage,b->callback_deadline,b->files[EVENT_FILE],l.bytes,l.used,&b->view.raw_bytes,OTB_MAX_RAW_BYTES)) {
  if(!b->failed)failure(b,stage,OTB_LIMIT,0,0,EFBIG,"raw event serialization bound exceeded");
  fault(b,b->view.first_error.reason==OTB_OUTPUT?TS_OUTPUT_FAULT:TS_BACKEND_FAULT);goto rejected;
 }
 b->view.events++;
 if(time_before(b,stage,b->callback_deadline,1))goto rejected;
 if(kind==RK_BEGIN) {
  b->view.begin_count=1;
  /* Readiness derives from the exact enabled program/inventory plus this
   * actually consumed and serialized BEGIN, never start()/match counts alone. */
  if(emit(b,TS_PROVIDER_READY) || emit(b,TS_BEGIN))goto rejected;
 } else if(kind==RK_END) {b->view.end_count=1;if(emit(b,TS_END))goto rejected;}
 else if(kind==RK_EXITED) {
  if(!(values[7]&SHADOW_BIT)){b->view.terminal_count=1;if(emit(b,TS_TERMINAL))goto rejected;}
 } else if(kind==RK_CREATE || kind==RK_SPAWN_SUCCESS || kind==RK_SPAWN_FAILURE) {
  failure(b,stage,OTB_ORDER,0,0,EPROTO,"unexpected descendant/spawn in fixed owned context probe");goto rejected;
 } else if(!b->view.terminal_count && emit(b,TS_ACTIVITY))goto rejected;
 return DTRACE_CONSUME_NEXT;
invalid:
 failure(b,stage,OTB_LAYOUT,0,0,EPROTO,rejection);layout_diagnostic(b,data);
rejected:
 fault(b,TS_BACKEND_FAULT);return DTRACE_CONSUME_ABORT;
}
static int error_event(const dtrace_errdata_t *data,void *context) {
 struct otb_backend *b=context;b->view.faults++;
 failure(b,b->draining?OTB_DRAIN:OTB_PUMP,OTB_LIBDTRACE,0,0,EIO,data&&data->dteda_msg?data->dteda_msg:"DTrace error callback");
 if(data) {
  struct line l={0};add(&l,"{\"kind\":\"dtrace-fault\",\"cpu\":%d,\"fault\":%d,\"action\":%d,\"offset\":%d,\"address\":%"PRIu64",\"message\":",data->dteda_cpu,data->dteda_fault,data->dteda_action,data->dteda_offset,data->dteda_addr);
  char message[513];snprintf(message,sizeof(message),"%s",data->dteda_msg?data->dteda_msg:"");quoted(&l,message);add(&l,"}\n");callback_diagnostic(b,&l);
 }
 fault(b,TS_BACKEND_FAULT);return DTRACE_HANDLE_ABORT;
}
static int drop_event(const dtrace_dropdata_t *data,void *context) {
 struct otb_backend *b=context;
 if(data && UINT64_MAX-b->view.drops>=data->dtdda_drops)b->view.drops+=data->dtdda_drops;else b->view.drops=UINT64_MAX;
 failure(b,b->draining?OTB_DRAIN:OTB_PUMP,OTB_DROP,0,0,EIO,data&&data->dtdda_msg?data->dtdda_msg:"DTrace drop callback");
 if(data) {
  struct line l={0};add(&l,"{\"kind\":\"dtrace-drop\",\"cpu\":%d,\"drop_kind\":%d,\"drops\":%"PRIu64",\"total\":%"PRIu64",\"message\":",data->dtdda_cpu,data->dtdda_kind,data->dtdda_drops,data->dtdda_total);
  char message[513];snprintf(message,sizeof(message),"%s",data->dtdda_msg?data->dtdda_msg:"");quoted(&l,message);add(&l,"}\n");callback_diagnostic(b,&l);
 }
 fault(b,TS_DROP);return DTRACE_HANDLE_ABORT;
}
static int header(struct line *l,unsigned kind,const char *detail) {
 add(l,"trace((uint64_t)%u);trace((uint64_t)timestamp);trace((uint64_t)pid);trace((uint64_t)tid);trace((uint64_t)(%s));",kind,detail);return l->failed?-1:0;
}
static int program(struct otb_backend *b) {
 struct line l={0};add(&l,"#pragma D option quiet\nBEGIN { watched[%u]=1;",b->view.binding.target_pid);header(&l,RK_BEGIN,"0");add(&l,"}\nEND {");header(&l,RK_END,"0");add(&l,"}\n");
 const char *providers[]={"syscall","mach_trap"};
 for(unsigned family=0;family<2;family++)for(unsigned returning=0;returning<2;returning++) {
  add(&l,"%s:::%s /watched[pid]/ {",providers[family],returning?"return":"entry");
  header(&l,family?(returning?RK_MACH_RETURN:RK_MACH_ENTRY):(returning?RK_SYSCALL_RETURN:RK_SYSCALL_ENTRY),"ppid");
  unsigned count=returning?(family?1u:4u):8u;
  for(unsigned i=0;i<count;i++)add(&l,"trace((uint64_t)arg%u);",i);
  if(returning&&!family)add(&l,"trace((uint64_t)errno);");add(&l,"}\n");
 }
 static const struct {const char *name,*detail;unsigned kind;int leading;} clauses[]={
  {"create","args[0]->pr_pid",RK_CREATE,1},{"start","ppid",RK_START,1},{"exec-success","ppid",RK_EXEC_SUCCESS,1},
  {"exit","arg0",RK_EXIT,0},{"exec-failure","arg0",RK_EXEC_FAILURE,0},{"lwp-create","args[0]->pr_lwpid",RK_LWP_CREATE,0},
  {"lwp-start","0",RK_LWP_START,0},{"lwp-exit","0",RK_LWP_EXIT,0},{"spawn-success","0",RK_SPAWN_SUCCESS,0},{"spawn-failure","arg0",RK_SPAWN_FAILURE,0}};
 for(size_t i=0;i<sizeof(clauses)/sizeof(clauses[0]);i++) {
  add(&l,"proc:::%s /watched[pid]/ {",clauses[i].name);if(clauses[i].leading)add(&l,"watched[pid]=1;");header(&l,clauses[i].kind,clauses[i].detail);add(&l,"}\n");
 }
 add(&l,"proc:::exited /watched[args[0]->pr_pid]/ {");header(&l,RK_EXITED,"args[0]->pr_pid");
 add(&l,"trace((uint64_t)arg1);trace((uint64_t)args[0]->pr_addr);trace((uint64_t)((struct proc *)args[0]->pr_addr)->p_refcount);}\n");
 if(l.failed || l.used>=sizeof(b->program))return failure(b,OTB_START,OTB_LIMIT,0,0,EFBIG,"generated program bound exceeded");
 memcpy(b->program,l.bytes,l.used+1);uint64_t written=0;
 if(write_bytes(b,OTB_START,b->view.original_attempt_deadline_ns,b->files[PROGRAM_FILE],b->program,l.used,&written,MAX_PROGRAM))
  return b->failed?-1:failure(b,OTB_START,OTB_OUTPUT,errno,0,EIO,"program output failed");
 return 0;
}
static int start(void *context,const struct ts_binding *binding,uint64_t d,int *error) {
 struct otb_backend *b=context;*error=0;
 if(b->view.start_attempted || b->view.close_attempted){failure(b,OTB_START,OTB_ORDER,0,0,EPROTO,"start is once-only");return status_error(b,error);}
 b->view.start_attempted=1;
 if(!binding || memcmp(binding,&b->view.binding,sizeof(*binding)) || d!=b->view.original_attempt_deadline_ns) {
  failure(b,OTB_START,OTB_BINDING,0,0,EPROTO,"start binding/deadline differs");return status_error(b,error);
 }
 if(deadline(b,OTB_START,d,0,1))return status_error(b,error);
 for(unsigned i=0;i<4;i++) {
  if(time_before(b,OTB_START,d,1))return status_error(b,error);
  b->files[i]=openat(b->directory,file_names[i],O_WRONLY|O_CREAT|O_EXCL|O_NOFOLLOW|O_CLOEXEC,0600);
  if(b->files[i]<0){failure(b,OTB_START,OTB_POSIX,errno,0,errno,"exclusive output open failed");return status_error(b,error);}
  struct stat s;
  if(fstat(b->files[i],&s)){failure(b,OTB_START,OTB_POSIX,errno,0,errno,"output stat failed");return status_error(b,error);}
  if(!S_ISREG(s.st_mode) || (s.st_mode&07777)!=0600 || s.st_nlink!=1 || s.st_uid!=geteuid()) {
   failure(b,OTB_START,OTB_OUTPUT,0,0,EPROTO,"output identity/mode differs");return status_error(b,error);
  }
 }
 if(program(b))return status_error(b,error);
 if(time_before(b,OTB_START,d,1))return status_error(b,error);
 int setup=0;b->handle=dtrace_open(DTRACE_VERSION,DTRACE_O_LP64,&setup);
 if(!b->handle){native_failure(b,OTB_START,"open",setup);return status_error(b,error);}
 if(dtrace_handle_drop(b->handle,drop_event,b) || dtrace_handle_err(b->handle,error_event,b) ||
    dtrace_setopt(b->handle,"bufsize","16m") || dtrace_setopt(b->handle,"bufpolicy","switch") ||
    dtrace_setopt(b->handle,"switchrate","20ms") || dtrace_setopt(b->handle,"statusrate","20ms") ||
    dtrace_setopt(b->handle,"dynvarsize","8m") || dtrace_setopt(b->handle,"temporal","yes")) {
  native_failure(b,OTB_START,"options/callbacks",dtrace_errno(b->handle));return status_error(b,error);
 }
 if(time_before(b,OTB_START,d,1))return status_error(b,error);
 if(dtrace_probe_iter(b->handle,NULL,inventory,b) || b->failed || required_inventory(b)) {
  if(!b->failed)native_failure(b,OTB_START,"inventory",dtrace_errno(b->handle));return status_error(b,error);
 }
 b->view.expected_matches=b->view.inventory_probes;
 if(time_before(b,OTB_START,d,1))return status_error(b,error);
 dtrace_prog_t *compiled=dtrace_program_strcompile(b->handle,b->program,DTRACE_PROBESPEC_NAME,0,0,NULL);
 dtrace_proginfo_t info={0};
 if(!compiled){native_failure(b,OTB_START,"compile",dtrace_errno(b->handle));return status_error(b,error);}
 if(time_before(b,OTB_START,d,1))return status_error(b,error);
 if(dtrace_program_exec(b->handle,compiled,&info)){native_failure(b,OTB_START,"enable",dtrace_errno(b->handle));return status_error(b,error);}
 b->view.enabled_matches=info.dpi_matches;
 /* The fixed program has exactly one clause for every selected inventory
  * (kind, probe ID), including BEGIN/END. No wildcard partial enable is ready. */
 if(b->view.enabled_matches!=b->view.expected_matches){failure(b,OTB_START,OTB_INVENTORY,0,0,EPROTO,"enabled match count differs from exact selected inventory");return status_error(b,error);}
 if(time_before(b,OTB_START,d,1))return status_error(b,error);
 if(dtrace_go(b->handle)){native_failure(b,OTB_START,"go",dtrace_errno(b->handle));return status_error(b,error);}
 b->view.started=1;
 if(b->failed)return status_error(b,error);
 if(time_before(b,OTB_START,d,1))return status_error(b,error);
 return 0;
}
static int work(struct otb_backend *b,enum otb_stage stage,uint64_t d,ts_consume_fn consume,void *argument,int *done) {
 if(!consume)return failure(b,stage,OTB_ARGUMENT,0,0,EINVAL,"missing event consumer");
 if(time_before(b,stage,d,1))return -1;
 b->consume=consume;b->consume_context=argument;b->callback_deadline=d;
 dtrace_workstatus_t rc=dtrace_work(b->handle,NULL,consume_probe,NULL,b);
 if(rc==DTRACE_WORKSTATUS_ERROR && !b->failed)native_failure(b,stage,"work",dtrace_errno(b->handle));
 if(rc!=DTRACE_WORKSTATUS_ERROR && rc!=DTRACE_WORKSTATUS_OKAY && rc!=DTRACE_WORKSTATUS_DONE) {
  failure(b,stage,OTB_ORDER,0,0,EPROTO,"invalid work status");
  struct line l={0};add(&l,"{\"kind\":\"work-status\",\"status\":%d}\n",(int)rc);callback_diagnostic(b,&l);
 }
 if(b->failed)fault(b,TS_BACKEND_FAULT);
 b->consume=NULL;b->consume_context=NULL;
 *done=rc==DTRACE_WORKSTATUS_DONE;
 if(time_before(b,stage,d,1))return -1;
 return b->failed?-1:0;
}
static int pump(void *context,enum ts_phase phase,uint64_t d,ts_consume_fn consume,void *argument,int *error) {
 struct otb_backend *b=context;*error=0;
 if(phase!=TS_CLEANUP && (b->view.cleanup_deadline_ns || d!=b->view.original_attempt_deadline_ns)) {
  failure(b,OTB_PUMP,OTB_BINDING,0,0,EPROTO,"attempt pump deadline changed");return status_error(b,error);
 }
 if(phase<TS_BOOTSTRAP || phase>TS_CLEANUP || !b->view.started || b->view.stop_attempted || b->view.close_attempted ||
    deadline(b,OTB_PUMP,d,phase==TS_CLEANUP,1)) {
  if(!b->failed)failure(b,OTB_PUMP,OTB_ORDER,0,0,EPROTO,"invalid pump phase/lifecycle");return status_error(b,error);
 }
 if(b->failed)return status_error(b,error);
 int done=0;if(work(b,OTB_PUMP,d,consume,argument,&done))return status_error(b,error);
 if(done){failure(b,OTB_PUMP,OTB_INCOMPLETE,0,0,EPROTO,"backend DONE before stop");return status_error(b,error);}
 return 0;
}
static int stop(void *context,uint64_t d,int *error) {
 struct otb_backend *b=context;*error=0;
 if(b->view.stop_attempted || !b->view.started || b->view.close_attempted){failure(b,OTB_STOP,OTB_ORDER,0,0,EPROTO,"invalid/duplicate stop");return status_error(b,error);}
 b->view.stop_attempted=1;
 if(owner(b,OTB_STOP))return status_error(b,error);
 int bad=deadline(b,OTB_STOP,d,0,1);
 if(dtrace_stop(b->handle)){native_failure(b,OTB_STOP,"stop",dtrace_errno(b->handle));bad=-1;}else b->view.stopped=1;
 if(time_before(b,OTB_STOP,d,1))bad=-1;
 return bad?status_error(b,error):0;
}
static int drain(void *context,uint64_t d,ts_consume_fn consume,void *argument,int *error) {
 struct otb_backend *b=context;*error=0;
 if(b->view.drain_attempted || !b->view.stopped || b->view.close_attempted){failure(b,OTB_DRAIN,OTB_ORDER,0,0,EPROTO,"invalid/duplicate drain");return status_error(b,error);}
 b->view.drain_attempted=1;
 if(deadline(b,OTB_DRAIN,d,0,1))return status_error(b,error);
 b->draining=1;int done=0,bad=0;
 for(unsigned i=0;i<MAX_DRAIN_WORK;i++) {
  if(work(b,OTB_DRAIN,d,consume,argument,&done)){bad=-1;break;}
  if(done)break;
 }
 b->draining=0;
 if(!done || b->view.begin_count!=1 || b->view.terminal_count!=1 || b->view.end_count!=1) {
  failure(b,OTB_DRAIN,OTB_INCOMPLETE,0,0,EPROTO,"drain lacks actual DONE/BEGIN/terminal/END");bad=-1;
 }
 b->view.drained=!bad;
 return bad?status_error(b,error):0;
}
static int close_backend(void *context,uint64_t d,int *error) {
 struct otb_backend *b=context;*error=0;
 if(b->view.close_attempted){failure(b,OTB_CLOSE,OTB_ORDER,0,0,EPROTO,"close is once-only");return status_error(b,error);}
 b->view.close_attempted=1;if(owner(b,OTB_CLOSE))return status_error(b,error);
 int bad=deadline(b,OTB_CLOSE,d,0,1),closed=1;
 /* libdtrace's void close owns library cleanup; no successful syscall or
  * kernel resource readback is invented from this invocation. */
 if(b->handle){dtrace_hdl_t *handle=b->handle;b->handle=NULL;dtrace_close(handle);}
 for(unsigned i=0;i<4;i++)if(b->files[i]>=0) {
  int fd=b->files[i];b->files[i]=-1;
  if(close(fd)){failure(b,OTB_CLOSE,OTB_POSIX,errno,0,errno,"writer close failed; ownership unresolved");closed=0;bad=-1;}
 }
 b->view.resources_closed=closed;
 if(time_before(b,OTB_CLOSE,d,1))bad=-1;
 return bad?status_error(b,error):0;
}
int otb_create(struct otb_backend **out,int fd,const struct ts_binding *binding,uint64_t attempt,int ready,struct ts_operations *ops,struct otb_error *error) {
 if(out)*out=NULL;if(ops)memset(ops,0,sizeof(*ops));if(error)memset(error,0,sizeof(*error));
 if(!out || !ops || !error)return -1;
 struct otb_error invalid={OTB_CREATE,OTB_ARGUMENT,0,0,EINVAL,"invalid confirmed READY/binding/directory/deadline"};
 if(!binding || ready!=1 || fd<0 || binding->fixture!=TS_OWNED_CONTEXT_PROBE || !binding->owner_pid ||
    !binding->target_pid || binding->owner_pid>INT32_MAX || binding->target_pid>INT32_MAX || binding->owner_pid==binding->target_pid) {*error=invalid;return -1;}
 if((uint64_t)getpid()!=binding->owner_pid){invalid.reason=OTB_OWNER;invalid.callback_error=EPERM;*error=invalid;return -1;}
 struct stat s;int flags=fcntl(fd,F_GETFD),status=0;
 if(flags<0){invalid.reason=OTB_POSIX;invalid.system_errno=errno;invalid.callback_error=errno;*error=invalid;return -1;}
 status=fcntl(fd,F_GETFL);
 if(status<0 || fstat(fd,&s)){invalid.reason=OTB_POSIX;invalid.system_errno=errno;invalid.callback_error=errno;*error=invalid;return -1;}
 if(!S_ISDIR(s.st_mode) || !(flags&FD_CLOEXEC) || (status&O_ACCMODE)!=O_RDONLY){*error=invalid;return -1;}
 uint64_t now=0;int e=0;
 if(actual_clock(&now,&e)){invalid.reason=OTB_CLOCK;invalid.system_errno=e==EOVERFLOW?0:e;invalid.callback_error=e;*error=invalid;return -1;}
 if(attempt<=now || attempt-now>UINT64_C(10000000000)){invalid.reason=OTB_DEADLINE;invalid.callback_error=ETIMEDOUT;*error=invalid;return -1;}
 struct otb_backend *b=calloc(1,sizeof(*b));
 if(!b){invalid.reason=OTB_POSIX;invalid.system_errno=errno;invalid.callback_error=errno;*error=invalid;return -1;}
 b->directory=fd;b->view.binding=*binding;b->view.original_attempt_deadline_ns=attempt;b->last_clock=now;b->clock_seen=1;
 for(unsigned i=0;i<4;i++)b->files[i]=-1;
 *ops=(struct ts_operations){b,operation_owner,operation_clock,start,pump,stop,drain,close_backend};*out=b;return 0;
}
int otb_snapshot(const struct otb_backend *b,struct otb_snapshot *out) {if(!b||!out)return -1;*out=b->view;return 0;}
int otb_destroy(struct otb_backend **out) {
 if(!out || !*out)return -1;struct otb_backend *b=*out;
 if(b->view.start_attempted && (!b->view.close_attempted || !b->view.resources_closed))return -1;
 free(b);*out=NULL;return 0;
}
#else
struct otb_backend { int unused; };
int otb_create(struct otb_backend **out,int fd,const struct ts_binding *b,uint64_t d,int r,struct ts_operations *o,struct otb_error *e) {
 (void)fd;(void)b;(void)d;(void)r;if(out)*out=NULL;if(o)memset(o,0,sizeof(*o));
 if(e){memset(e,0,sizeof(*e));e->stage=OTB_CREATE;e->reason=OTB_ARGUMENT;e->callback_error=ENOTSUP;snprintf(e->message,sizeof(e->message),"native Darwin backend unavailable");}return -1;
}
int otb_snapshot(const struct otb_backend *b,struct otb_snapshot *s) {(void)b;(void)s;return -1;}
int otb_destroy(struct otb_backend **b) {(void)b;return -1;}
#endif
