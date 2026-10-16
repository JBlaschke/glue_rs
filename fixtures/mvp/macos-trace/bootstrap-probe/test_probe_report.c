#include "probe_report.h"
#include <assert.h>
#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
static struct np_report valid(unsigned index) {
    struct np_report r;memset(&r,0,sizeof(r));
    /* Digests are supplied by independent Python/hashlib, not fabricated here. */
    r.pids[0]=456;r.pids[1]=123;r.pids[2]=456;
    r.ids[0]=r.ids[1]=501;r.ids[2]=r.ids[3]=20;
    r.group_count=3;r.groups[0]=20;r.groups[1]=0;r.groups[2]=80;
    r.cwd_device=UINT64_C(0x0102030405060708);r.cwd_inode=UINT64_C(0xf0e0d0c0b0a09080);
    r.fd_count=3;r.fds[1]=1;r.fds[2]=2;r.status_flags[1]=r.status_flags[2]=1;
    r.root_regain_result=-1;r.root_regain_errno=1;r.signal_policy=1;
    if(index) {
        r.pids[0]=r.pids[2]=NP_ID_MAX;r.pids[1]=1;
        for(size_t i=0;i<4;i++)r.ids[i]=NP_ID_MAX;
        r.group_count=16;r.groups[0]=NP_ID_MAX;
        for(size_t i=1;i<16;i++)r.groups[i]=i-1;
        r.cwd_device=UINT64_MAX;r.cwd_inode=0;
        r.status_flags[0]=65536;r.status_flags[1]=65537;r.status_flags[2]=33554433;
        r.descriptor_flags[0]=2; /* Unknown bits retained, never effects proof. */
    }
    memcpy(r.post_ids,r.ids,sizeof(r.ids));return r;
}
static void zeros(const void *p,size_t n) {
    const unsigned char *b=p;for(size_t i=0;i<n;i++)assert(!b[i]);
}
static void invalid(struct np_report r) {
    uint8_t out[256];memset(out,0xa5,sizeof(out));
    assert(np_report_encode(&r,out)==NP_CANONICAL);zeros(out,sizeof(out));
}
static void argument(void) {
    uint8_t out[256],digest[32];struct np_report r=valid(0),decoded;
    memset(out,0xa5,sizeof(out));assert(np_report_encode(NULL,out)==NP_ARGUMENT);zeros(out,sizeof(out));
    assert(np_report_encode(&r,NULL)==NP_ARGUMENT);
    memset(&decoded,0xa5,sizeof(decoded));assert(np_report_decode(NULL,256,digest,&decoded)==NP_ARGUMENT);zeros(&decoded,sizeof(decoded));
    assert(np_report_decode(out,256,NULL,&decoded)==NP_ARGUMENT);
    assert(np_report_decode(out,256,digest,NULL)==NP_ARGUMENT);
    assert(np_report_validate(NULL)==NP_ARGUMENT);
    memset(digest,0xa5,32);assert(np_parse_sha256(NULL,64,digest)==NP_ARGUMENT);zeros(digest,32);
    assert(np_parse_sha256("",0,NULL)==NP_ARGUMENT);
}
static void lengths(void) {
    struct np_report r=valid(0),decoded;uint8_t data[257];assert(np_report_encode(&r,data)==NP_OK);
    size_t bad[]={0,1,63,64,255,257,SIZE_MAX};
    for(size_t i=0;i<sizeof(bad)/sizeof(bad[0]);i++) {
        memset(&decoded,0xa5,sizeof(decoded));
        assert(np_report_decode(data,bad[i],r.request_sha256,&decoded)==NP_LENGTH);zeros(&decoded,sizeof(decoded));
    }
}
static void header(void) {
    struct np_report r=valid(0),decoded;uint8_t data[256],bad[256];assert(np_report_encode(&r,data)==NP_OK);
    size_t offsets[]={0,7,8,9,10,11,12,15};
    for(size_t i=0;i<sizeof(offsets)/sizeof(offsets[0]);i++) {
        memcpy(bad,data,256);bad[offsets[i]]^=1;
        assert(np_report_decode(bad,256,r.request_sha256,&decoded)==NP_HEADER);zeros(&decoded,sizeof(decoded));
    }
    for(size_t i=232;i<256;i++) {
        memcpy(bad,data,256);bad[i]=1;
        assert(np_report_decode(bad,256,r.request_sha256,&decoded)==NP_RESERVED);zeros(&decoded,sizeof(decoded));
    }
    uint8_t wrong[32]={1};assert(np_report_decode(data,256,wrong,&decoded)==NP_BINDING);zeros(&decoded,sizeof(decoded));
}
static void identity(void) {
    for(size_t i=0;i<4;i++) {
        struct np_report r=valid(0);r.ids[i]=r.post_ids[i]=0;invalid(r);
        r=valid(0);r.ids[i]=r.post_ids[i]=NP_ID_MAX+1;invalid(r);
        r=valid(0);r.ids[i]=r.post_ids[i]=UINT64_MAX;invalid(r);
        r=valid(0);r.post_ids[i]++;invalid(r);
    }
    struct np_report r=valid(0);r.ids[1]++;r.post_ids[1]++;invalid(r);
    r=valid(0);r.ids[3]++;r.post_ids[3]++;invalid(r);
}
static void groups(void) {
    uint64_t count[]={0,17,UINT64_MAX};
    for(size_t i=0;i<3;i++){struct np_report r=valid(0);r.group_count=count[i];invalid(r);}
    struct np_report r=valid(0);r.groups[0]=80;invalid(r);
    r=valid(0);r.groups[2]=r.groups[1];invalid(r);
    r=valid(0);r.groups[1]=NP_ID_MAX+1;invalid(r);
    r=valid(0);r.groups[15]=1;invalid(r);
}
static void process(void) {
    for(size_t i=0;i<3;i++) {
        struct np_report r=valid(0);r.pids[i]=0;invalid(r);
        r=valid(0);r.pids[i]=NP_ID_MAX+1;invalid(r);
    }
    struct np_report r=valid(0);r.pids[1]=r.pids[0];invalid(r);
    r=valid(0);r.pids[2]++;invalid(r);
}
static void stdio_flags(void) {
    for(size_t i=0;i<3;i++) {
        struct np_report r=valid(0);r.fds[i]=3;invalid(r);
        r=valid(0);r.status_flags[i]=2;invalid(r);
        r=valid(0);r.status_flags[i]|=NP_DARWIN_NONBLOCK;invalid(r);
        r=valid(0);r.status_flags[i]|=NP_DARWIN_ASYNC;invalid(r);
        r=valid(0);r.status_flags[i]|=NP_DARWIN_EVTONLY;invalid(r);
        r=valid(0);r.status_flags[i]=UINT64_MAX;invalid(r);
        r=valid(0);r.descriptor_flags[i]=1;invalid(r);
        r=valid(0);r.descriptor_flags[i]=UINT64_MAX;invalid(r);
    }
    struct np_report r=valid(0);r.fd_count=4;invalid(r);
}
static void root_and_policy(void) {
    struct np_report r=valid(0);r.root_regain_result=0;invalid(r);
    r=valid(0);r.root_regain_result=-2;invalid(r);
    r=valid(0);r.root_regain_result=INT64_MAX;invalid(r);
    r=valid(0);r.root_regain_errno=0;invalid(r);
    r=valid(0);r.root_regain_errno=UINT64_MAX;invalid(r);
    r=valid(0);r.signal_policy=0;invalid(r);
    r=valid(0);r.environment_count=1;invalid(r);
}
static void hex(void) {
    char text[64];memset(text,'a',64);uint8_t out[32];
    assert(np_parse_sha256(text,64,out)==NP_OK);for(size_t i=0;i<32;i++)assert(out[i]==0xaa);
    size_t sizes[]={0,1,63,65,SIZE_MAX};
    for(size_t i=0;i<5;i++){memset(out,0xa5,32);assert(np_parse_sha256(text,sizes[i],out)==NP_LENGTH);zeros(out,32);}
    unsigned char bad[]={0,'A','F','g','/',255};
    for(size_t i=0;i<sizeof(bad);i++) {
        text[63]=(char)bad[i];memset(out,0xa5,32);
        assert(np_parse_sha256(text,64,out)==NP_CANONICAL);zeros(out,32);
    }
}
static void roundtrip(void) {
    for(unsigned i=0;i<2;i++) {
        struct np_report r=valid(i),decoded;uint8_t data[256],again[256];
        assert(np_report_encode(&r,data)==NP_OK);
        memset(&decoded,0xa5,sizeof(decoded));assert(np_report_decode(data,256,r.request_sha256,&decoded)==NP_OK);
        assert(np_report_encode(&decoded,again)==NP_OK);assert(!memcmp(data,again,256));
    }
}
int main(int argc,char **argv) {
    if(argc==4&&!strcmp(argv[1],"golden")) {
        unsigned i=(unsigned)strtoul(argv[2],NULL,10);if(i>1)return 2;
        struct np_report r=valid(i);uint8_t out[256];
        if(np_parse_sha256(argv[3],strlen(argv[3]),r.request_sha256)!=NP_OK)return 2;
        if(np_report_encode(&r,out)!=NP_OK)return 2;
        return fwrite(out,1,256,stdout)==256?0:1;
    }
    if(argc==3&&!strcmp(argv[1],"decode")) {
        uint8_t data[257],expected[32],out[256];struct np_report r;
        if(np_parse_sha256(argv[2],strlen(argv[2]),expected)!=NP_OK)return 2;
        size_t n=fread(data,1,sizeof(data),stdin);
        if(np_report_decode(data,n,expected,&r)!=NP_OK)return 1;
        if(np_report_encode(&r,out)!=NP_OK)return 2;
        return fwrite(out,1,256,stdout)==256?0:1;
    }
    if(argc!=2)return 2;
    struct {const char *name;void(*test)(void);} tests[]={
        {"argument",argument},{"lengths",lengths},{"header",header},{"identity",identity},
        {"groups",groups},{"process",process},{"stdio",stdio_flags},{"root-policy",root_and_policy},
        {"hex",hex},{"roundtrip",roundtrip}};
    for(size_t i=0;i<sizeof(tests)/sizeof(tests[0]);i++)if(!strcmp(argv[1],tests[i].name)) {
        tests[i].test();puts(tests[i].name);return 0;
    }
    return 2;
}
