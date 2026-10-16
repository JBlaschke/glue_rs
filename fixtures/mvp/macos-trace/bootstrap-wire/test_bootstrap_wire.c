#include "bootstrap_wire.h"
#include <assert.h>
#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
static int allzero(const void *p,size_t n) { const unsigned char *b=p;for(size_t i=0;i<n;i++)if(b[i])return 0;return 1; }
static struct bw_binding binding(void) { struct bw_binding b={123,456,{0}};for(unsigned i=0;i<32;i++)b.request_sha256[i]=(uint8_t)i;return b; }
static struct bw_status ready(void) {
    struct bw_status s={0};s.binding=binding();s.kind=BW_READY;s.mutation_flags=3;s.detail=-1;
    s.real_uid=s.effective_uid=501;s.real_gid=s.effective_gid=20;s.group_count=3;
    s.groups[0]=20;s.groups[1]=0;s.groups[2]=80;s.cwd_device=UINT64_C(0x0102030405060708);s.cwd_inode=UINT64_C(0xf0e0d0c0b0a09080);
    s.kept_fds[1]=1;s.kept_fds[2]=2;s.kept_fds[3]=10;s.kept_fds[4]=11;
    for(unsigned i=0;i<32;i++)s.signal_policy_sha256[i]=(uint8_t)(0xa0+i);
    return s;
}
static struct bw_status attempt(void) { struct bw_status s={0};s.binding=binding();s.kind=BW_EXEC_ATTEMPT;s.sequence=1;s.stage=BW_EXEC;s.mutation_flags=3;s.detail=-1;return s; }
static struct bw_status failure(unsigned sequence,unsigned stage,unsigned reason,unsigned flags) {
    struct bw_status s={0};s.binding=binding();s.kind=BW_ERROR;s.sequence=sequence;s.stage=stage;s.reason=reason;s.mutation_flags=flags;s.detail=-1;
    if(reason==BW_SYSCALL)s.system_errno=2;
    return s;
}
static void put32(uint8_t *p,uint32_t n) { p[0]=(uint8_t)(n>>24);p[1]=(uint8_t)(n>>16);p[2]=(uint8_t)(n>>8);p[3]=(uint8_t)n; }
static void encode(struct bw_status s,uint8_t out[256]) { assert(bw_status_encode(&s,out)==BW_OK); }
static void bad_encode(struct bw_status s) { uint8_t out[256];memset(out,0xa5,sizeof out);assert(bw_status_encode(&s,out)!=BW_OK);assert(allzero(out,sizeof out)); }
static void bad_decode(const uint8_t *data,size_t n,struct bw_binding expected) {
    struct bw_status s;memset(&s,0xa5,sizeof s);assert(bw_status_decode(data,n,&expected,&s)!=BW_OK);assert(allzero(&s,sizeof s));
}
static void roundtrip(struct bw_status s) {
    uint8_t a[256],b[256];encode(s,a);struct bw_status decoded;assert(bw_status_decode(a,sizeof a,&s.binding,&decoded)==BW_OK);encode(decoded,b);assert(!memcmp(a,b,256));
}
static void golden(void) { roundtrip(ready());roundtrip(attempt());roundtrip(failure(0,BW_REQUEST,BW_ARGUMENT,0));roundtrip(failure(1,BW_GO_VALIDATE,BW_MISMATCH,3));roundtrip(failure(2,BW_EXEC,BW_SYSCALL,3)); }
static void lengths(void) {
    uint8_t data[300];encode(ready(),data);struct bw_binding b=binding();
    for(size_t n=0;n<=sizeof data;n++)if(n!=256)bad_decode(data,n,b);
    bad_decode(data,SIZE_MAX,b);bad_decode(NULL,256,b);
    struct bw_status out;memset(&out,0xa5,sizeof out);assert(bw_status_decode(data,256,NULL,&out)!=BW_OK&&allzero(&out,sizeof out));
    assert(bw_status_decode(data,256,&b,NULL)==BW_FAULT_ARGUMENT);
    assert(bw_status_encode(NULL,data)==BW_FAULT_ARGUMENT&&allzero(data,256));
    struct bw_status r=ready();assert(bw_status_encode(&r,NULL)==BW_FAULT_ARGUMENT);
}
static void headers(void) {
    uint8_t data[256];struct bw_binding b=binding();
    for(unsigned i=0;i<8;i++){encode(ready(),data);data[i]^=1;bad_decode(data,256,b);}
    const unsigned offsets[]={8,9,10,11,12,13,14,15};
    for(unsigned i=0;i<sizeof offsets/sizeof offsets[0];i++){encode(ready(),data);data[offsets[i]]^=0x80;bad_decode(data,256,b);}
    for(unsigned i=232;i<256;i++){encode(ready(),data);data[i]=1;bad_decode(data,256,b);}
    struct bw_status s=ready();s.kind=0;bad_encode(s);s.kind=4;bad_encode(s);s.kind=UINT32_MAX;bad_encode(s);
}
static void bindings(void) {
    uint8_t data[256];encode(ready(),data);struct bw_binding b=binding();
    b.controller_pid=0;bad_decode(data,256,b);b=binding();b.child_pid=INT32_MAX+1u;bad_decode(data,256,b);
    b=binding();b.child_pid=b.controller_pid;bad_decode(data,256,b);
    b=binding();b.request_sha256[31]^=1;bad_decode(data,256,b);b=binding();b.controller_pid++;bad_decode(data,256,b);b=binding();b.child_pid++;bad_decode(data,256,b);
    for(unsigned i=16;i<56;i++){encode(ready(),data);data[i]^=0x80;bad_decode(data,256,binding());}
    struct bw_status s=ready();s.binding.controller_pid=0;bad_encode(s);s=ready();s.binding.child_pid=UINT32_MAX;bad_encode(s);
    s=ready();s.binding.child_pid=s.binding.controller_pid;bad_encode(s);
    s=ready();s.binding.controller_pid=1;s.binding.child_pid=INT32_MAX;memset(s.binding.request_sha256,0,32);roundtrip(s);
}
static void ready_bounds(void) {
    for(unsigned mode=0;mode<25;mode++) {
        struct bw_status s=ready();
        switch(mode){case 0:s.sequence=1;break;case 1:s.stage=BW_REQUEST;break;case 2:s.reason=BW_ARGUMENT;break;case 3:s.system_errno=1;break;
        case 4:s.detail=-2;break;case 5:s.detail=INT64_MAX;break;case 6:s.detail=0;break;case 7:s.mutation_flags=0;break;case 8:s.mutation_flags=4;break;
        case 9:s.real_uid=0;break;case 10:s.real_uid=s.effective_uid=INT32_MAX+1u;break;case 11:s.effective_uid++;break;case 12:s.real_gid=0;break;
        case 13:s.real_gid=s.effective_gid=INT32_MAX+1u;break;case 14:s.effective_gid++;break;case 15:s.group_count=0;break;case 16:s.group_count=17;break;
        case 17:s.groups[1]=s.groups[0];break;case 18:s.groups[0]=21;break;case 19:s.groups[2]=UINT32_MAX;break;case 20:s.groups[3]=1;break;
        case 21:s.kept_fds[0]=1;break;case 22:s.kept_fds[3]=2;break;case 23:s.kept_fds[4]=UINT32_MAX;break;case 24:s.kept_fds[4]=10;break;}
        bad_encode(s);
    }
    struct bw_status s=ready();s.mutation_flags=1;s.real_uid=s.effective_uid=INT32_MAX;s.real_gid=s.effective_gid=INT32_MAX;
    s.group_count=16;for(unsigned i=0;i<16;i++)s.groups[i]=i;s.groups[0]=INT32_MAX;s.kept_fds[3]=3;s.kept_fds[4]=INT32_MAX;s.cwd_device=s.cwd_inode=UINT64_MAX;memset(s.signal_policy_sha256,0,32);roundtrip(s);
    s=ready();s.cwd_device=s.cwd_inode=0;memset(s.binding.request_sha256,0,32);memset(s.signal_policy_sha256,0,32);roundtrip(s);
}
static void observations(void) {
    uint8_t data[256];struct bw_status a=attempt(),e=failure(2,BW_EXEC,BW_SYSCALL,3);
    for(unsigned i=72;i<224;i++){encode(a,data);data[i]=1;bad_decode(data,256,binding());encode(e,data);data[i]=1;bad_decode(data,256,binding());}
    a.groups[15]=1;bad_encode(a);a=attempt();a.cwd_inode=1;bad_encode(a);a=attempt();a.kept_fds[0]=1;bad_encode(a);a=attempt();a.signal_policy_sha256[31]=1;bad_encode(a);
    a=attempt();a.detail=0;bad_encode(a);a=attempt();a.sequence=2;bad_encode(a);a=attempt();a.stage=BW_CWD;bad_encode(a);a=attempt();a.mutation_flags=2;bad_encode(a);
}
static void error_contract(void) {
    for(unsigned seq=0;seq<=3;seq++)for(unsigned stage=0;stage<=14;stage++)for(unsigned flags=0;flags<5;flags++) {
        struct bw_status s=failure(seq,stage,BW_ARGUMENT,flags);uint8_t out[256];
        int phase=(seq==0&&stage>=1&&stage<=8)||(seq==1&&stage>=9&&stage<=12)||(seq==2&&stage==13);
        int bits=flags<4 && !(stage<5&&(flags&1)) && !(stage>=6&&!(flags&1)) && !(stage<7&&(flags&2));
        enum bw_fault f=bw_status_encode(&s,out);assert((f==BW_OK)==(phase&&bits));if(f!=BW_OK)assert(allzero(out,256));else roundtrip(s);
    }
    for(unsigned reason=0;reason<=18;reason++) {struct bw_status s=failure(0,BW_CREDENTIALS,reason,1);if(reason==0||reason==18)bad_encode(s);else roundtrip(s);}
    struct bw_status s=failure(2,BW_EXEC,BW_SYSCALL,1);s.system_errno=0;bad_encode(s);s.system_errno=UINT32_MAX;bad_encode(s);s.system_errno=INT32_MAX;s.detail=INT32_MAX;roundtrip(s);
    s=failure(0,BW_REQUEST,BW_ARGUMENT,0);s.system_errno=1;bad_encode(s);s.system_errno=0;s.detail=-2;bad_encode(s);s.detail=(int64_t)INT32_MAX+1;bad_encode(s);s.detail=0;roundtrip(s);
    s=failure(0,BW_REQUEST,UINT32_MAX,0);bad_encode(s);s=failure(UINT32_MAX,BW_REQUEST,BW_ARGUMENT,0);bad_encode(s);
    uint8_t data[256];encode(failure(0,BW_REQUEST,BW_ARGUMENT,0),data);put32(data+228,UINT32_MAX-1);bad_decode(data,256,binding());
}
static void go_contract(void) {
    uint8_t data[80],copy[80];struct bw_binding b=binding(),out;assert(bw_go_encode(&b,data)==BW_OK);
    for(size_t n=0;n<80;n++)if(n!=64){memset(&out,0xa5,sizeof out);assert(bw_go_decode(data,n,&b,&out)!=BW_OK&&allzero(&out,sizeof out));}
    assert(bw_go_decode(data,SIZE_MAX,&b,&out)==BW_FAULT_LENGTH);
    for(unsigned i=0;i<64;i++){memcpy(copy,data,64);copy[i]^=0x80;memset(&out,0xa5,sizeof out);assert(bw_go_decode(copy,64,&b,&out)!=BW_OK&&allzero(&out,sizeof out));}
    assert(bw_go_decode(data,64,&b,&out)==BW_OK);assert(bw_go_decode(NULL,64,&b,&out)==BW_FAULT_ARGUMENT&&allzero(&out,sizeof out));
    assert(bw_go_decode(data,64,NULL,&out)!=BW_OK&&allzero(&out,sizeof out));assert(bw_go_decode(data,64,&b,NULL)==BW_FAULT_ARGUMENT);
    b.child_pid=0;memset(data,0xa5,64);assert(bw_go_encode(&b,data)!=BW_OK&&allzero(data,64));assert(bw_go_encode(NULL,data)!=BW_OK&&allzero(data,64));
    assert(bw_go_encode(&b,NULL)==BW_FAULT_ARGUMENT);
}
static enum bw_fault push(struct bw_state *state,struct bw_status s) {uint8_t data[256];encode(s,data);return bw_state_push(state,data,256);}
static struct bw_state state(void) {struct bw_state s;struct bw_binding b=binding();assert(bw_state_init(&s,&b)==BW_OK);return s;}
static void state_paths(void) {
    struct bw_state s=state();assert(push(&s,ready())==BW_OK);assert(push(&s,attempt())==BW_OK);assert(push(&s,failure(2,BW_EXEC,BW_SYSCALL,3))==BW_OK);
    assert(s.accepted_records==3&&s.has_reported_error&&s.reported_error.system_errno==2&&bw_state_finish(&s)==BW_END_REPORTED_ERROR);
    s=state();assert(push(&s,failure(0,BW_REQUEST,BW_ARGUMENT,0))==BW_OK);assert(bw_state_finish(&s)==BW_END_REPORTED_ERROR);
    s=state();assert(push(&s,ready())==BW_OK);assert(push(&s,failure(1,BW_GO_IO,BW_EOF,3))==BW_OK);assert(bw_state_finish(&s)==BW_END_REPORTED_ERROR);
    s=state();assert(bw_state_finish(&s)==BW_END_INCOMPLETE);assert(bw_state_finish(&s)==BW_END_INCOMPLETE);
    s=state();assert(push(&s,ready())==BW_OK);assert(bw_state_finish(&s)==BW_END_INCOMPLETE);
    s=state();assert(push(&s,ready())==BW_OK&&push(&s,attempt())==BW_OK);assert(bw_state_finish(&s)==BW_END_ATTEMPT_WITHOUT_REPORTED_EXEC_ERROR);assert(bw_state_finish(&s)==BW_END_ATTEMPT_WITHOUT_REPORTED_EXEC_ERROR);
    /* Opaque observations are NOT compared to an unstated requested identity. */
    s=state();struct bw_status other=ready();other.real_uid=other.effective_uid=777;assert(push(&s,other)==BW_OK&&s.last.real_uid==777);
}
static void poison_paths(void) {
    struct bw_state s=state();uint8_t data[256];encode(ready(),data);assert(bw_state_push(&s,data,255)==BW_FAULT_LENGTH);assert(push(&s,ready())==BW_FAULT_LENGTH);assert(s.first_fault==BW_FAULT_LENGTH&&bw_state_finish(&s)==BW_END_INVALID);
    s=state();assert(push(&s,attempt())==BW_FAULT_ORDER);assert(push(&s,ready())==BW_FAULT_ORDER);
    s=state();assert(push(&s,ready())==BW_OK);assert(push(&s,ready())==BW_FAULT_ORDER);
    s=state();assert(push(&s,ready())==BW_OK);struct bw_status a=attempt();a.mutation_flags=1;assert(push(&s,a)==BW_FAULT_ORDER);
    s=state();struct bw_status r=ready();r.mutation_flags=1;assert(push(&s,r)==BW_OK);assert(push(&s,attempt())==BW_FAULT_ORDER);
    s=state();assert(push(&s,ready())==BW_OK&&push(&s,attempt())==BW_OK);assert(push(&s,failure(1,BW_GO_IO,BW_TIMEOUT,3))==BW_FAULT_ORDER);
    s=state();assert(push(&s,failure(1,BW_GO_IO,BW_TIMEOUT,3))==BW_FAULT_ORDER);
    s=state();struct bw_status e=failure(0,BW_REQUEST,BW_ARGUMENT,0);e.detail=42;assert(push(&s,e)==BW_OK);assert(push(&s,ready())==BW_FAULT_EXTRA);assert(s.has_reported_error&&s.reported_error.detail==42&&bw_state_finish(&s)==BW_END_INVALID);
    s=state();assert(push(&s,ready())==BW_OK);a=attempt();a.binding.request_sha256[0]++;assert(push(&s,a)==BW_FAULT_BINDING);assert(s.accepted_records==1);
    s=state();bw_state_finish(&s);assert(push(&s,ready())==BW_FAULT_EXTRA);
    s=state();assert(push(&s,ready())==BW_OK);bw_state_finish(&s);assert(push(&s,attempt())==BW_FAULT_EXTRA);
    s=state();assert(push(&s,ready())==BW_OK&&push(&s,attempt())==BW_OK);bw_state_finish(&s);assert(push(&s,failure(2,BW_EXEC,BW_SYSCALL,3))==BW_FAULT_EXTRA);
    s=state();assert(push(&s,ready())==BW_OK&&push(&s,attempt())==BW_OK&&push(&s,failure(2,BW_EXEC,BW_SYSCALL,3))==BW_OK);
    assert(push(&s,ready())==BW_FAULT_EXTRA&&s.accepted_records==3&&s.reported_error.system_errno==2);
    s=state();assert(push(&s,ready())==BW_OK);assert(push(&s,failure(1,BW_GO_IO,BW_EOF,1))==BW_FAULT_ORDER);
    struct bw_binding b=binding();b.child_pid=0;assert(bw_state_init(&s,&b)==BW_FAULT_BINDING&&bw_state_finish(&s)==BW_END_INVALID);
    memset(&s,0,sizeof s);assert(bw_state_push(&s,NULL,0)==BW_FAULT_STATE&&bw_state_finish(&s)==BW_END_INVALID);
    assert(bw_state_init(NULL,&b)==BW_FAULT_ARGUMENT&&bw_state_push(NULL,NULL,0)==BW_FAULT_ARGUMENT&&bw_state_finish(NULL)==BW_END_INVALID);
}
static void hex(const char *name,const uint8_t *data,size_t n){printf("%s:",name);for(size_t i=0;i<n;i++)printf("%02x",data[i]);putchar('\n');}
static void vectors(void) {
    uint8_t out[256];struct bw_status s=ready();encode(s,out);hex("ready",out,256);
    encode(attempt(),out);hex("attempt",out,256);encode(failure(0,BW_REQUEST,BW_ARGUMENT,0),out);hex("setup-error",out,256);
    encode(failure(1,BW_GO_VALIDATE,BW_MISMATCH,3),out);hex("gate-error",out,256);encode(failure(2,BW_EXEC,BW_SYSCALL,3),out);hex("exec-error",out,256);
    struct bw_binding b=binding();assert(bw_go_encode(&b,out)==BW_OK);hex("go",out,64);
}
static void decode_vector(const char *kind,const char *text) {
    size_t n=strlen(text)/2;assert(strlen(text)==n*2&&n<=256);uint8_t in[256],out[256];
    for(size_t i=0;i<n;i++){char word[3]={text[2*i],text[2*i+1],0};char *end;unsigned long v=strtoul(word,&end,16);assert(*end==0&&v<=255);in[i]=(uint8_t)v;}
    struct bw_binding b=binding();if(!strcmp(kind,"decode-go")){struct bw_binding decoded;assert(bw_go_decode(in,n,&b,&decoded)==BW_OK);assert(bw_go_encode(&decoded,out)==BW_OK);}
    else{struct bw_status decoded;assert(bw_status_decode(in,n,&b,&decoded)==BW_OK);assert(bw_status_encode(&decoded,out)==BW_OK);}
    assert(!memcmp(in,out,n));puts("decoded");
}
int main(int argc,char **argv) {
    assert(argc>=2);if(argc==3){decode_vector(argv[1],argv[2]);return 0;}
    const struct {const char *name;void(*run)(void);} cases[]={{"golden",golden},{"lengths",lengths},{"headers",headers},{"bindings",bindings},{"ready-bounds",ready_bounds},{"observations",observations},{"errors",error_contract},{"go",go_contract},{"state",state_paths},{"poison",poison_paths},{"vectors",vectors}};
    for(size_t i=0;i<sizeof cases/sizeof cases[0];i++) {
        if(!strcmp(argv[1],cases[i].name)){cases[i].run();return 0;}
    }
    return 2;
}
