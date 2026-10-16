#include "probe_report.h"
#include <string.h>
static void put16(uint8_t *p, uint16_t n) { p[0]=(uint8_t)(n>>8);p[1]=(uint8_t)n; }
static void put32(uint8_t *p, uint32_t n) { for(unsigned i=0;i<4;i++)p[i]=(uint8_t)(n>>(24-8*i)); }
static void put64(uint8_t *p, uint64_t n) { for(unsigned i=0;i<8;i++)p[i]=(uint8_t)(n>>(56-8*i)); }
static uint16_t get16(const uint8_t *p) { return (uint16_t)((uint16_t)p[0]<<8|p[1]); }
static uint32_t get32(const uint8_t *p) { uint32_t n=0;for(unsigned i=0;i<4;i++)n=n<<8|p[i];return n; }
static uint64_t get64(const uint8_t *p) { uint64_t n=0;for(unsigned i=0;i<8;i++)n=n<<8|p[i];return n; }
enum np_fault np_parse_sha256(const char *text, size_t length, uint8_t out[32]) {
    if(out)memset(out,0,32);
    if(!text||!out)return NP_ARGUMENT;
    if(length!=64)return NP_LENGTH;
    uint8_t parsed[32]={0};
    for(size_t i=0;i<64;i++) {
        unsigned char c=(unsigned char)text[i];unsigned n;
        if(c>='0'&&c<='9')n=c-'0';else if(c>='a'&&c<='f')n=c-'a'+10;else return NP_CANONICAL;
        parsed[i/2]|=(uint8_t)(n<<(i%2?0:4));
    }
    memcpy(out,parsed,32);return NP_OK;
}
enum np_fault np_report_validate(const struct np_report *r) {
    if(!r)return NP_ARGUMENT;
    for(size_t i=0;i<3;i++)if(r->pids[i]==0||r->pids[i]>NP_ID_MAX)return NP_CANONICAL;
    if(r->pids[0]==r->pids[1]||r->pids[2]!=r->pids[0])return NP_CANONICAL;
    for(size_t i=0;i<4;i++)if(!r->ids[i]||r->ids[i]>NP_ID_MAX||r->post_ids[i]!=r->ids[i])return NP_CANONICAL;
    if(r->ids[0]!=r->ids[1]||r->ids[2]!=r->ids[3])return NP_CANONICAL;
    if(!r->group_count||r->group_count>NP_MAX_GROUPS||r->groups[0]!=r->ids[2])return NP_CANONICAL;
    for(size_t i=0;i<NP_MAX_GROUPS;i++) {
        if(i>=r->group_count) { if(r->groups[i])return NP_CANONICAL;continue; }
        if(r->groups[i]>NP_ID_MAX)return NP_CANONICAL;
        for(size_t j=0;j<i;j++)if(r->groups[i]==r->groups[j])return NP_CANONICAL;
    }
    if(r->fd_count!=3)return NP_CANONICAL;
    for(size_t i=0;i<3;i++) {
        if(r->fds[i]!=i||r->status_flags[i]>NP_ID_MAX||r->descriptor_flags[i]>NP_ID_MAX)return NP_CANONICAL;
        if((r->status_flags[i]&NP_DARWIN_ACCMODE)!=(i?1u:0u))return NP_CANONICAL;
        if(r->status_flags[i]&(NP_DARWIN_NONBLOCK|NP_DARWIN_ASYNC|NP_DARWIN_EVTONLY))return NP_CANONICAL;
        if(r->descriptor_flags[i]&NP_DARWIN_CLOEXEC)return NP_CANONICAL;
    }
    if(r->root_regain_result!=-1||r->root_regain_errno!=NP_DARWIN_EPERM||r->signal_policy!=1||r->environment_count)return NP_CANONICAL;
    return NP_OK;
}
enum np_fault np_report_encode(const struct np_report *r, uint8_t out[NP_REPORT_SIZE]) {
    if(out)memset(out,0,NP_REPORT_SIZE);
    if(!r||!out)return NP_ARGUMENT;
    enum np_fault f=np_report_validate(r);if(f)return f;
    memcpy(out,"GLUENP01",8);put16(out+8,1);put16(out+10,NP_REPORT_SIZE);put32(out+12,1);
    memcpy(out+16,r->request_sha256,32);
    for(size_t i=0;i<3;i++)put32(out+48+4*i,(uint32_t)r->pids[i]);
    for(size_t i=0;i<4;i++)put32(out+60+4*i,(uint32_t)r->ids[i]);
    put32(out+76,(uint32_t)r->group_count);
    for(size_t i=0;i<16;i++)put32(out+80+4*i,(uint32_t)r->groups[i]);
    put64(out+144,r->cwd_device);put64(out+152,r->cwd_inode);put32(out+160,3);
    for(size_t i=0;i<3;i++) {
        put32(out+164+4*i,(uint32_t)r->fds[i]);
        put32(out+176+4*i,(uint32_t)r->status_flags[i]);
        put32(out+188+4*i,(uint32_t)r->descriptor_flags[i]);
    }
    put32(out+200,UINT32_MAX);put32(out+204,(uint32_t)r->root_regain_errno);
    for(size_t i=0;i<4;i++)put32(out+208+4*i,(uint32_t)r->post_ids[i]);
    put32(out+224,1);return NP_OK;
}
enum np_fault np_report_decode(const uint8_t *data, size_t length, const uint8_t expected[32], struct np_report *out) {
    if(out)memset(out,0,sizeof(*out));
    if(!data||!expected||!out)return NP_ARGUMENT;
    if(length!=NP_REPORT_SIZE)return NP_LENGTH;
    if(memcmp(data,"GLUENP01",8)||get16(data+8)!=1||get16(data+10)!=NP_REPORT_SIZE||get32(data+12)!=1)return NP_HEADER;
    for(size_t i=232;i<256;i++)if(data[i])return NP_RESERVED;
    if(memcmp(data+16,expected,32))return NP_BINDING;
    struct np_report r;memset(&r,0,sizeof(r));memcpy(r.request_sha256,data+16,32);
    for(size_t i=0;i<3;i++)r.pids[i]=get32(data+48+4*i);
    for(size_t i=0;i<4;i++)r.ids[i]=get32(data+60+4*i);
    r.group_count=get32(data+76);
    for(size_t i=0;i<16;i++)r.groups[i]=get32(data+80+4*i);
    r.cwd_device=get64(data+144);r.cwd_inode=get64(data+152);r.fd_count=get32(data+160);
    for(size_t i=0;i<3;i++) {
        r.fds[i]=get32(data+164+4*i);r.status_flags[i]=get32(data+176+4*i);r.descriptor_flags[i]=get32(data+188+4*i);
    }
    r.root_regain_result=get32(data+200)==UINT32_MAX?-1:(int64_t)get32(data+200);
    r.root_regain_errno=get32(data+204);
    for(size_t i=0;i<4;i++)r.post_ids[i]=get32(data+208+4*i);
    r.signal_policy=get32(data+224);r.environment_count=get32(data+228);
    enum np_fault f=np_report_validate(&r);if(f)return f;
    *out=r;return NP_OK;
}
