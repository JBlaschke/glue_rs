#include "bootstrap_request.h"
#include <assert.h>
#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static struct br_request sample(void) {
    struct br_request r={0};
    static const uint8_t exe[]="/System/Volumes/Data/Library/GlueMVPFixtures/build/context-probe";
    static const uint8_t cwd[]="/System/Volumes/Data/Library/GlueMVPFixtures/build/cwd";
    r.fixture=1; r.credentials.uid=501; r.credentials.gid=20;
    r.credentials.group_count=3; r.credentials.groups[0]=20;
    r.credentials.groups[1]=0; r.credentials.groups[2]=80;
    r.signal_policy=r.stdio_policy=r.argv_template=1;
    r.release_action=BR_SEND_GO; r.max_live_fds=4096;
    r.attempt_ms=10000; r.cleanup_ms=2000;
    for (unsigned i=0;i<32;i++) r.catalog_sha256[i]=(uint8_t)i;
    r.cwd_device=UINT64_C(0x0102030405060708);
    r.cwd_inode=UINT64_C(0xf0e0d0c0b0a09080);
    r.executable=(struct br_span){exe,sizeof(exe)-1};
    r.cwd=(struct br_span){cwd,sizeof(cwd)-1};
    return r;
}
static struct br_request maximum(void) {
    struct br_request r=sample();
    static const uint8_t exe[]={'/','a','/',0xc3,0xa9};
    static const uint8_t cwd[]={'/'};
    r.credentials.uid=r.credentials.gid=INT32_MAX;
    r.credentials.group_count=16; r.credentials.groups[0]=INT32_MAX;
    for (unsigned i=1;i<16;i++) r.credentials.groups[i]=i-1;
    memset(r.catalog_sha256,0,32);
    r.cwd_device=r.cwd_inode=UINT64_MAX;
    r.release_action=BR_SIMULATED_PROVIDER_FAILURE;
    r.executable=(struct br_span){exe,sizeof(exe)};
    r.cwd=(struct br_span){cwd,sizeof(cwd)};
    return r;
}
static int zeros(const void *p,size_t n) {
    const uint8_t *b=p;
    for(size_t i=0;i<n;i++) if(b[i]) return 0;
    return 1;
}
static void be32(uint8_t *p,uint32_t n) {
    p[0]=(uint8_t)(n>>24);p[1]=(uint8_t)(n>>16);p[2]=(uint8_t)(n>>8);p[3]=(uint8_t)n;
}
static size_t encode(struct br_request r,uint8_t *bytes) {
    size_t n=0;struct br_error e;
    assert(br_request_encode(&r,bytes,&n,&e)==BR_OK);
    assert(e.fault==BR_OK && e.field==BR_FIELD_NONE && e.index==BR_NO_INDEX);
    assert(n>=208 && n<=BR_MAX_WIRE && zeros(bytes+n,BR_MAX_WIRE-n));return n;
}
static void bad_model(struct br_request r) {
    struct {uint8_t before[16],data[BR_MAX_WIRE],after[16];} b;
    memset(&b,0xa5,sizeof(b));size_t n=SIZE_MAX;struct br_error e;
    assert(br_request_encode(&r,b.data,&n,&e)!=BR_OK);
    assert(n==0 && zeros(b.data,BR_MAX_WIRE) && e.fault!=BR_OK);
    for(unsigned i=0;i<16;i++)assert(b.before[i]==0xa5 && b.after[i]==0xa5);
}
static void bad_wire(const uint8_t *p,size_t n) {
    struct {uint8_t before[16];struct br_request out;uint8_t after[16];} b;
    memset(&b,0xa5,sizeof(b));struct br_error e;
    assert(br_request_decode(p,n,&b.out,&e)!=BR_OK && zeros(&b.out,sizeof(b.out)));
    for(unsigned i=0;i<16;i++)assert(b.before[i]==0xa5 && b.after[i]==0xa5);
}
static void roundtrip(void) {
    uint8_t a[BR_MAX_WIRE],b[BR_MAX_WIRE];struct br_error e;struct br_request d;
    for(unsigned k=0;k<2;k++) {
        struct br_request r=k?maximum():sample();size_t n=encode(r,a),m=0;
        assert(br_request_decode(a,n,&d,&e)==BR_OK);
        assert(d.executable.bytes==a+208 && d.cwd.bytes==a+208+r.executable.length);
        assert(d.executable.length==r.executable.length && d.cwd.length==r.cwd.length);
        assert(br_request_encode(&d,b,&m,&e)==BR_OK && n==m && !memcmp(a,b,BR_MAX_WIRE));
        a[208]='X';bad_model(d);a[208]='/';
    }
}
static void lengths(void) {
    uint8_t a[BR_MAX_WIRE];size_t n=encode(sample(),a);
    for(size_t i=0;i<n;i++)bad_wire(a,i);
    bad_wire(NULL,0);bad_wire(NULL,207);bad_wire(NULL,208);
    bad_wire(NULL,BR_MAX_WIRE+1);bad_wire(NULL,SIZE_MAX);
    bad_wire(a,n+1);be32(a+12,(uint32_t)n+1);bad_wire(a,n+1);
    n=encode(sample(),a);be32(a+176,UINT32_MAX);bad_wire(a,n);
    n=encode(sample(),a);be32(a+180,0);bad_wire(a,n);
    n=encode(sample(),a);be32(a+176,0);bad_wire(a,n);
}
static void mutation_canonicality(void) {
    uint8_t original[BR_MAX_WIRE],changed[BR_MAX_WIRE],encoded[BR_MAX_WIRE];
    size_t n=encode(sample(),original);const uint8_t flips[]={1,0x80,0xff};
    for(size_t i=0;i<n;i++) {
        for(unsigned j=0;j<sizeof(flips);j++) {
            memcpy(changed,original,n);changed[i]^=flips[j];
            struct br_request decoded;memset(&decoded,0xa5,sizeof(decoded));struct br_error e;
            enum br_fault f=br_request_decode(changed,n,&decoded,&e);
            if(f==BR_OK) {
                size_t m=0;assert(br_request_encode(&decoded,encoded,&m,&e)==BR_OK);
                assert(m==n && !memcmp(encoded,changed,n) && zeros(encoded+n,BR_MAX_WIRE-n));
            } else assert(zeros(&decoded,sizeof(decoded)) && e.fault==f);
        }
    }
}
static void selectors(void) {
    uint8_t a[BR_MAX_WIRE];size_t n;
    const unsigned offsets[]={16,96,100,104,108,112,116,120,124};
    const uint32_t bads[]={0,2,UINT32_MAX};
    for(size_t i=0;i<sizeof(offsets)/sizeof(offsets[0]);i++) {
        for(unsigned j=0;j<3;j++) {
            if((offsets[i]==104 && bads[j]==2) ||
               ((offsets[i]==112 || offsets[i]==116) && bads[j]==2) ||
               (offsets[i]==124 && bads[j]==0))continue;
            n=encode(sample(),a);be32(a+offsets[i],bads[j]);bad_wire(a,n);
        }
    }
    n=encode(sample(),a);a[0]^=1;bad_wire(a,n);
    n=encode(sample(),a);a[9]=2;bad_wire(a,n);
    n=encode(sample(),a);a[10]=1;bad_wire(a,n);
    for(unsigned i=184;i<208;i++){n=encode(sample(),a);a[i]=1;bad_wire(a,n);}
    struct br_request r=sample();uint64_t *fields[]={&r.fixture,&r.signal_policy,&r.stdio_policy,
        &r.release_action,&r.max_live_fds,&r.attempt_ms,&r.cleanup_ms,&r.argv_template,&r.environment_count};
    for(size_t i=0;i<sizeof(fields)/sizeof(fields[0]);i++) {
        uint64_t old=*fields[i];*fields[i]=UINT64_MAX;bad_model(r);*fields[i]=old;
    }
    r=sample();r.attempt_ms=10001;bad_model(r);r=sample();r.cleanup_ms=2001;bad_model(r);
    r=sample();r.attempt_ms=r.cleanup_ms=1;encode(r,a);
}
static void groups(void) {
    struct br_request r=sample();uint8_t a[BR_MAX_WIRE];size_t n;
    r.credentials.uid=0;bad_model(r);r=sample();r.credentials.gid=0;bad_model(r);
    r=sample();r.credentials.uid=UINT64_MAX;bad_model(r);r=sample();r.credentials.gid=UINT64_MAX;bad_model(r);
    r=sample();r.credentials.group_count=0;bad_model(r);r=sample();r.credentials.group_count=SIZE_MAX;bad_model(r);
    r=sample();r.credentials.groups[0]=21;bad_model(r);r=sample();r.credentials.groups[1]=20;bad_model(r);
    r=sample();r.credentials.groups[2]=UINT64_MAX;bad_model(r);
    for(unsigned i=3;i<16;i++){r=sample();r.credentials.groups[i]=1;bad_model(r);}
    const unsigned offsets[]={20,24,28,32,36};
    for(unsigned i=0;i<5;i++){n=encode(sample(),a);be32(a+offsets[i],UINT32_MAX);bad_wire(a,n);}
    for(unsigned i=3;i<16;i++){n=encode(sample(),a);a[32+4*i+3]=1;bad_wire(a,n);}
    r=sample();r.credentials.group_count=1;r.credentials.groups[1]=r.credentials.groups[2]=0;encode(r,a);
}
static void paths(void) {
    const char *bad[]={"", "relative", "/", "//a", "/a//b", "/a/", "/.", "/..", "/a/./b", "/a/../b"};
    for(size_t i=0;i<sizeof(bad)/sizeof(bad[0]);i++) {
        struct br_request r=sample();r.executable=(struct br_span){(const uint8_t*)bad[i],strlen(bad[i])};bad_model(r);
        if(strcmp(bad[i],"/")){r=sample();r.cwd=(struct br_span){(const uint8_t*)bad[i],strlen(bad[i])};bad_model(r);}
    }
    static const uint8_t embedded[]={'/','a',0,'b'};
    struct br_request r=sample();r.cwd=(struct br_span){embedded,sizeof(embedded)};bad_model(r);
    r=sample();r.executable.bytes=NULL;bad_model(r);
    r=sample();r.cwd.length=SIZE_MAX;bad_model(r);
    uint8_t path[4096];memset(path,'a',sizeof(path));path[0]='/';
    r=sample();r.executable=(struct br_span){path,256};uint8_t bytes[BR_MAX_WIRE];encode(r,bytes);
    r.executable.length=257;bad_model(r);
    for(unsigned i=0;i<sizeof(path);i+=256)path[i]='/';
    r.executable.length=4095;encode(r,bytes);r.executable.length=4096;bad_model(r);
    size_t n=encode(sample(),bytes);bytes[208]=0;bad_wire(bytes,n);
    n=encode(sample(),bytes);bytes[n-1]='/';bad_wire(bytes,n);
}
static struct br_ready_context context(void) {
    struct br_ready_context c={0};c.binding.controller_pid=123;c.binding.child_pid=456;
    for(unsigned i=0;i<32;i++){c.binding.request_sha256[i]=(uint8_t)i;c.signal_policy_sha256[i]=(uint8_t)(0xa0+i);}
    c.kept_fds[0]=0;c.kept_fds[1]=1;c.kept_fds[2]=2;c.kept_fds[3]=10;c.kept_fds[4]=11;return c;
}
static struct bw_status ready(struct br_request r,struct br_ready_context c) {
    struct bw_status s={0};s.binding=c.binding;s.kind=BW_READY;s.detail=-1;s.mutation_flags=3;
    s.real_uid=s.effective_uid=(uint32_t)r.credentials.uid;s.real_gid=s.effective_gid=(uint32_t)r.credentials.gid;
    s.group_count=(uint32_t)r.credentials.group_count;
    for(unsigned i=0;i<16;i++)s.groups[i]=(uint32_t)r.credentials.groups[i];
    s.cwd_device=r.cwd_device;s.cwd_inode=r.cwd_inode;
    for(unsigned i=0;i<5;i++)s.kept_fds[i]=(uint32_t)c.kept_fds[i];
    memcpy(s.signal_policy_sha256,c.signal_policy_sha256,32);return s;
}
static void bad_ready(struct br_request r,struct br_ready_context c,struct bw_status s) {
    struct br_error e;assert(br_ready_compare(&r,&c,&s,&e)!=BR_OK && e.fault!=BR_OK);
}
static void ready_observations(void) {
    struct br_request r=sample();struct br_ready_context c=context();struct bw_status s=ready(r,c);struct br_error e;
    assert(br_ready_compare(&r,&c,&s,&e)==BR_OK);
    s.real_uid=s.effective_uid=502;assert(br_ready_compare(&r,&c,&s,&e)==BR_MISMATCH);
    s=ready(r,c);s.real_gid=s.effective_gid=21;s.groups[0]=21;bad_ready(r,c,s);
    s=ready(r,c);s.group_count=2;s.groups[2]=0;bad_ready(r,c,s);
    s=ready(r,c);s.groups[1]=80;s.groups[2]=0;assert(br_ready_compare(&r,&c,&s,&e)==BR_MISMATCH);
    for(unsigned i=0;i<16;i++){s=ready(r,c);s.groups[i]^=1;bad_ready(r,c,s);}
    s=ready(r,c);s.cwd_device^=1;bad_ready(r,c,s);s=ready(r,c);s.cwd_inode^=1;bad_ready(r,c,s);
    for(unsigned i=0;i<5;i++){s=ready(r,c);s.kept_fds[i]+=20;bad_ready(r,c,s);}
    for(unsigned i=0;i<32;i++){s=ready(r,c);s.signal_policy_sha256[i]^=1;bad_ready(r,c,s);}
    s=ready(r,c);s.mutation_flags=1;assert(br_ready_compare(&r,&c,&s,&e)==BR_MISMATCH);
    r=maximum();s=ready(r,c);assert(br_ready_compare(&r,&c,&s,&e)==BR_OK);
}
static void ready_canonical(void) {
    struct br_request r=sample();struct br_ready_context c=context();struct bw_status s;struct br_error e;
    uint32_t *p;
    const unsigned fields[]={0,1,2,3,4,5};
    for(unsigned i=0;i<sizeof(fields)/sizeof(fields[0]);i++) {
        s=ready(r,c);
        switch(fields[i]){case 0:p=&s.sequence;break;case 1:p=&s.stage;break;case 2:p=&s.reason;break;case 3:p=&s.system_errno;break;case 4:p=&s.effective_uid;break;default:p=&s.mutation_flags;break;}
        *p=UINT32_MAX;bad_ready(r,c,s);
    }
    s=ready(r,c);s.detail=0;bad_ready(r,c,s);
    memset(&s,0,sizeof(s));s.binding=c.binding;s.kind=BW_EXEC_ATTEMPT;s.sequence=1;s.stage=BW_EXEC;s.detail=-1;s.mutation_flags=3;
    assert(br_ready_compare(&r,&c,&s,&e)==BR_STATUS);
    memset(&s,0,sizeof(s));s.binding=c.binding;s.kind=BW_ERROR;s.stage=BW_REQUEST;s.reason=BW_ARGUMENT;s.detail=-1;
    assert(br_ready_compare(&r,&c,&s,&e)==BR_STATUS);
}
static void ready_bindings(void) {
    struct br_request r=sample();struct br_ready_context c=context();struct bw_status s=ready(r,c);
    s.binding.controller_pid++;bad_ready(r,c,s);s=ready(r,c);s.binding.child_pid++;bad_ready(r,c,s);
    for(unsigned i=0;i<32;i++){s=ready(r,c);s.binding.request_sha256[i]^=1;bad_ready(r,c,s);}
    s=ready(r,c);c.binding.controller_pid=0;bad_ready(r,c,s);c=context();c.binding.child_pid=123;bad_ready(r,c,s);
    c=context();c.binding.child_pid=UINT32_MAX;bad_ready(r,c,s);
    for(unsigned i=0;i<5;i++){c=context();c.kept_fds[i]=UINT64_MAX;bad_ready(r,c,s);}
    c=context();c.kept_fds[4]=c.kept_fds[3];bad_ready(r,c,s);
    c=context();c.kept_fds[3]=3;c.kept_fds[4]=INT32_MAX;s=ready(r,c);struct br_error e;
    assert(br_ready_compare(&r,&c,&s,&e)==BR_OK);
    r=sample();r.fixture=0;bad_ready(r,c,s);
}
static void clearing(void) {
    struct br_request r=sample(),out;struct br_error e;uint8_t bytes[BR_MAX_WIRE];size_t n=1;
    memset(bytes,0xa5,sizeof(bytes));assert(br_request_encode(NULL,bytes,&n,&e)==BR_ARGUMENT && !n && zeros(bytes,sizeof(bytes)));
    memset(bytes,0xa5,sizeof(bytes));assert(br_request_encode(&r,bytes,NULL,&e)==BR_ARGUMENT && zeros(bytes,sizeof(bytes)));
    memset(bytes,0xa5,sizeof(bytes));assert(br_request_encode(&r,bytes,&n,NULL)==BR_ARGUMENT && !n && zeros(bytes,sizeof(bytes)));
    assert(br_request_encode(&r,NULL,&n,&e)==BR_ARGUMENT && !n);
    n=encode(r,bytes);memset(&out,0xa5,sizeof(out));assert(br_request_decode(bytes,n,&out,NULL)==BR_ARGUMENT && zeros(&out,sizeof(out)));
    assert(br_request_decode(bytes,n,NULL,&e)==BR_ARGUMENT);
    struct br_ready_context c=context();struct bw_status s=ready(r,c);
    assert(br_ready_compare(NULL,&c,&s,&e)==BR_ARGUMENT);
    assert(br_ready_compare(&r,NULL,&s,&e)==BR_ARGUMENT);
    assert(br_ready_compare(&r,&c,NULL,&e)==BR_ARGUMENT);
    assert(br_ready_compare(&r,&c,&s,NULL)==BR_ARGUMENT);
}
int main(int argc,char **argv) {
    assert(argc==2);
    if(!strcmp(argv[1],"golden-normal") || !strcmp(argv[1],"golden-maximum")) {
        uint8_t bytes[BR_MAX_WIRE];size_t n=encode(!strcmp(argv[1],"golden-normal")?sample():maximum(),bytes);
        assert(fwrite(bytes,1,n,stdout)==n);return 0;
    }
    if(!strcmp(argv[1],"roundtrip"))roundtrip();
    else if(!strcmp(argv[1],"lengths"))lengths();
    else if(!strcmp(argv[1],"selectors"))selectors();
    else if(!strcmp(argv[1],"mutation-canonicality"))mutation_canonicality();
    else if(!strcmp(argv[1],"groups"))groups();
    else if(!strcmp(argv[1],"paths"))paths();
    else if(!strcmp(argv[1],"ready-observations"))ready_observations();
    else if(!strcmp(argv[1],"ready-canonical"))ready_canonical();
    else if(!strcmp(argv[1],"ready-bindings"))ready_bindings();
    else if(!strcmp(argv[1],"clearing"))clearing();
    else return 2;
    return 0;
}
