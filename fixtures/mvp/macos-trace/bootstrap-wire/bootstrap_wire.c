#include "bootstrap_wire.h"
#include <limits.h>
#include <string.h>
#define BW_TAG UINT32_C(0x42535731)
_Static_assert(CHAR_BIT == 8, "wire octets");
_Static_assert(sizeof(uint32_t) == 4 && sizeof(uint64_t) == 8, "wire widths");
static const uint8_t status_magic[8] = {'G','L','U','E','B','S','0','1'};
static const uint8_t go_magic[8] = {'G','L','U','E','G','O','0','1'};
static void put16(uint8_t *p, uint32_t v) { p[0]=(uint8_t)(v>>8); p[1]=(uint8_t)v; }
static void put32(uint8_t *p, uint32_t v) { for (unsigned i=0;i<4;i++) p[i]=(uint8_t)(v>>(24-8*i)); }
static void put64(uint8_t *p, uint64_t v) { for (unsigned i=0;i<8;i++) p[i]=(uint8_t)(v>>(56-8*i)); }
static uint32_t get16(const uint8_t *p) { return ((uint32_t)p[0]<<8)|p[1]; }
static uint32_t get32(const uint8_t *p) { uint32_t v=0; for(unsigned i=0;i<4;i++)v=(v<<8)|p[i]; return v; }
static uint64_t get64(const uint8_t *p) { uint64_t v=0; for(unsigned i=0;i<8;i++)v=(v<<8)|p[i]; return v; }
static int zero(const uint8_t *p,size_t n) { for(size_t i=0;i<n;i++)if(p[i])return 0; return 1; }
static int binding_valid(const struct bw_binding *b) {
    return b && b->controller_pid>0 && b->controller_pid<=INT32_MAX &&
        b->child_pid>0 && b->child_pid<=INT32_MAX && b->controller_pid!=b->child_pid;
}
static int binding_equal(const struct bw_binding *a,const struct bw_binding *b) {
    return a->controller_pid==b->controller_pid && a->child_pid==b->child_pid &&
        memcmp(a->request_sha256,b->request_sha256,32)==0;
}
static void put_binding(uint8_t *p,const struct bw_binding *b) {
    put32(p,b->controller_pid);put32(p+4,b->child_pid);memcpy(p+8,b->request_sha256,32);
}
static void get_binding(const uint8_t *p,struct bw_binding *b) {
    b->controller_pid=get32(p);b->child_pid=get32(p+4);memcpy(b->request_sha256,p+8,32);
}
static int observations_zero(const struct bw_status *s) {
    if(s->real_uid||s->effective_uid||s->real_gid||s->effective_gid||s->group_count||s->cwd_device||s->cwd_inode)return 0;
    for(unsigned i=0;i<BW_GROUPS;i++)if(s->groups[i])return 0;
    for(unsigned i=0;i<5;i++)if(s->kept_fds[i])return 0;
    return zero(s->signal_policy_sha256,32);
}
static enum bw_fault status_valid(const struct bw_status *s) {
    if(!binding_valid(&s->binding))return BW_FAULT_BINDING;
    if(s->kind<BW_READY||s->kind>BW_ERROR)return BW_FAULT_KIND;
    if(s->mutation_flags & ~(BW_CREDENTIAL_ATTEMPT|BW_DESCRIPTOR_ATTEMPT))return BW_FAULT_CANONICAL;
    if(s->detail < -1 || s->detail>INT32_MAX)return BW_FAULT_CANONICAL;
    if(s->kind==BW_READY) {
        if(s->sequence||s->stage||s->reason||s->system_errno||s->detail!=-1||!(s->mutation_flags&BW_CREDENTIAL_ATTEMPT))return BW_FAULT_CANONICAL;
        if(!s->real_uid||s->real_uid>INT32_MAX||s->effective_uid!=s->real_uid||
           !s->real_gid||s->real_gid>INT32_MAX||s->effective_gid!=s->real_gid||
           s->group_count<1||s->group_count>BW_GROUPS||s->groups[0]!=s->real_gid)return BW_FAULT_CANONICAL;
        for(unsigned i=0;i<BW_GROUPS;i++) {
            if(i>=s->group_count) { if(s->groups[i])return BW_FAULT_CANONICAL; }
            else {
                if(s->groups[i]>INT32_MAX)return BW_FAULT_CANONICAL;
                for(unsigned j=0;j<i;j++)if(s->groups[j]==s->groups[i])return BW_FAULT_CANONICAL;
            }
        }
        if(s->kept_fds[0]!=0||s->kept_fds[1]!=1||s->kept_fds[2]!=2||
           s->kept_fds[3]<3||s->kept_fds[3]>INT32_MAX||s->kept_fds[4]<3||
           s->kept_fds[4]>INT32_MAX||s->kept_fds[3]==s->kept_fds[4])return BW_FAULT_CANONICAL;
        return BW_OK;
    }
    if(!observations_zero(s))return BW_FAULT_CANONICAL;
    if(s->kind==BW_EXEC_ATTEMPT) {
        if(s->sequence!=1||s->stage!=BW_EXEC||s->reason||s->system_errno||s->detail!=-1||
           !(s->mutation_flags&BW_CREDENTIAL_ATTEMPT))return BW_FAULT_CANONICAL;
        return BW_OK;
    }
    if(s->stage<BW_REQUEST||s->stage>BW_EXEC||s->reason<BW_ARGUMENT||s->reason>BW_SET_ID)return BW_FAULT_CANONICAL;
    if(s->reason==BW_SYSCALL) { if(!s->system_errno||s->system_errno>INT32_MAX)return BW_FAULT_CANONICAL; }
    else if(s->system_errno)return BW_FAULT_CANONICAL;
    if((s->sequence==0 && s->stage>BW_READY_IO)||
       (s->sequence==1 && (s->stage<BW_GO_IO||s->stage>BW_MASK_RESTORE))||
       (s->sequence==2 && s->stage!=BW_EXEC)||s->sequence>2)return BW_FAULT_CANONICAL;
    if(s->stage<BW_CREDENTIALS && (s->mutation_flags&BW_CREDENTIAL_ATTEMPT))return BW_FAULT_CANONICAL;
    if(s->stage>=BW_CWD && !(s->mutation_flags&BW_CREDENTIAL_ATTEMPT))return BW_FAULT_CANONICAL;
    if(s->stage<BW_DESCRIPTORS && (s->mutation_flags&BW_DESCRIPTOR_ATTEMPT))return BW_FAULT_CANONICAL;
    return BW_OK;
}
enum bw_fault bw_status_encode(const struct bw_status *s,uint8_t out[BW_STATUS_SIZE]) {
    if(!out)return BW_FAULT_ARGUMENT;
    memset(out,0,BW_STATUS_SIZE);
    if(!s)return BW_FAULT_ARGUMENT;
    enum bw_fault f=status_valid(s);if(f!=BW_OK)return f;
    memcpy(out,status_magic,8);put16(out+8,1);put16(out+10,s->kind);put32(out+12,BW_STATUS_SIZE);
    put_binding(out+16,&s->binding);put32(out+56,s->sequence);put32(out+60,s->stage);
    put32(out+64,s->system_errno);put32(out+68,s->mutation_flags);
    put32(out+72,s->real_uid);put32(out+76,s->effective_uid);put32(out+80,s->real_gid);put32(out+84,s->effective_gid);
    put32(out+88,s->group_count);for(unsigned i=0;i<BW_GROUPS;i++)put32(out+92+4*i,s->groups[i]);
    put64(out+156,s->cwd_device);put64(out+164,s->cwd_inode);
    for(unsigned i=0;i<5;i++)put32(out+172+4*i,s->kept_fds[i]);
    memcpy(out+192,s->signal_policy_sha256,32);put32(out+224,s->reason);
    put32(out+228,s->detail==-1?UINT32_MAX:(uint32_t)s->detail);return BW_OK;
}
enum bw_fault bw_status_decode(const uint8_t *in,size_t length,const struct bw_binding *expected,struct bw_status *out) {
    if(!out)return BW_FAULT_ARGUMENT;
    memset(out,0,sizeof(*out));
    if(length!=BW_STATUS_SIZE)return BW_FAULT_LENGTH;
    if(!in||!expected)return BW_FAULT_ARGUMENT;
    if(!binding_valid(expected))return BW_FAULT_BINDING;
    if(memcmp(in,status_magic,8))return BW_FAULT_MAGIC;
    if(get16(in+8)!=1)return BW_FAULT_VERSION;
    if(get32(in+12)!=BW_STATUS_SIZE)return BW_FAULT_LENGTH;
    if(!zero(in+232,24))return BW_FAULT_RESERVED;
    struct bw_status s={0};get_binding(in+16,&s.binding);
    if(!binding_equal(&s.binding,expected))return BW_FAULT_BINDING;
    s.kind=get16(in+10);s.sequence=get32(in+56);s.stage=get32(in+60);
    s.system_errno=get32(in+64);s.mutation_flags=get32(in+68);
    s.real_uid=get32(in+72);s.effective_uid=get32(in+76);s.real_gid=get32(in+80);s.effective_gid=get32(in+84);s.group_count=get32(in+88);
    for(unsigned i=0;i<BW_GROUPS;i++)s.groups[i]=get32(in+92+4*i);
    s.cwd_device=get64(in+156);s.cwd_inode=get64(in+164);
    for(unsigned i=0;i<5;i++)s.kept_fds[i]=get32(in+172+4*i);
    memcpy(s.signal_policy_sha256,in+192,32);s.reason=get32(in+224);
    uint32_t detail=get32(in+228);if(detail!=UINT32_MAX&&detail>INT32_MAX)return BW_FAULT_CANONICAL;
    s.detail=detail==UINT32_MAX?-1:(int64_t)detail;
    enum bw_fault f=status_valid(&s);if(f!=BW_OK)return f;
    *out=s;return BW_OK;
}
enum bw_fault bw_go_encode(const struct bw_binding *b,uint8_t out[BW_GO_SIZE]) {
    if(!out)return BW_FAULT_ARGUMENT;
    memset(out,0,BW_GO_SIZE);if(!binding_valid(b))return BW_FAULT_BINDING;
    memcpy(out,go_magic,8);put16(out+8,1);put16(out+10,BW_GO_SIZE);put_binding(out+12,b);return BW_OK;
}
enum bw_fault bw_go_decode(const uint8_t *in,size_t length,const struct bw_binding *expected,struct bw_binding *out) {
    if(!out)return BW_FAULT_ARGUMENT;
    memset(out,0,sizeof(*out));if(length!=BW_GO_SIZE)return BW_FAULT_LENGTH;
    if(!in||!expected)return BW_FAULT_ARGUMENT;
    if(!binding_valid(expected))return BW_FAULT_BINDING;
    if(memcmp(in,go_magic,8))return BW_FAULT_MAGIC;
    if(get16(in+8)!=1)return BW_FAULT_VERSION;
    if(get16(in+10)!=BW_GO_SIZE)return BW_FAULT_LENGTH;
    if(!zero(in+52,12))return BW_FAULT_RESERVED;
    struct bw_binding b={0};get_binding(in+12,&b);
    if(!binding_valid(&b)||!binding_equal(&b,expected))return BW_FAULT_BINDING;
    *out=b;return BW_OK;
}
static enum bw_fault poison(struct bw_state *s,enum bw_fault f) {
    if(s->first_fault==BW_OK)s->first_fault=f;
    s->phase=BW_POISONED;return s->first_fault;
}
enum bw_fault bw_state_init(struct bw_state *s,const struct bw_binding *b) {
    if(!s)return BW_FAULT_ARGUMENT;
    memset(s,0,sizeof(*s));s->tag=BW_TAG;
    if(!binding_valid(b))return poison(s,BW_FAULT_BINDING);
    s->expected=*b;return BW_OK;
}
enum bw_fault bw_state_push(struct bw_state *s,const uint8_t *in,size_t length) {
    if(!s)return BW_FAULT_ARGUMENT;
    if(s->tag!=BW_TAG) { memset(s,0,sizeof(*s));s->tag=BW_TAG;return poison(s,BW_FAULT_STATE); }
    if(s->phase==BW_POISONED)return s->first_fault;
    if(s->phase>BW_REPORTED_ERROR)return poison(s,BW_FAULT_STATE);
    if(s->sealed||s->phase==BW_REPORTED_ERROR||s->accepted_records>=3)return poison(s,BW_FAULT_EXTRA);
    struct bw_status record;
    enum bw_fault f=bw_status_decode(in,length,&s->expected,&record);
    if(f!=BW_OK)return poison(s,f);
    if(record.sequence!=s->accepted_records)return poison(s,BW_FAULT_ORDER);
    if((s->phase==BW_START && record.kind!=BW_READY && record.kind!=BW_ERROR)||
       (s->phase==BW_HAVE_READY && record.kind!=BW_EXEC_ATTEMPT && record.kind!=BW_ERROR)||
       (s->phase==BW_HAVE_ATTEMPT && record.kind!=BW_ERROR))return poison(s,BW_FAULT_ORDER);
    if(s->phase!=BW_START && record.mutation_flags!=s->ready_flags)return poison(s,BW_FAULT_ORDER);
    if(record.kind==BW_READY) {s->phase=BW_HAVE_READY;s->ready_flags=record.mutation_flags;}
    else if(record.kind==BW_EXEC_ATTEMPT)s->phase=BW_HAVE_ATTEMPT;
    else {s->phase=BW_REPORTED_ERROR;s->reported_error=record;s->has_reported_error=1;}
    s->last=record;s->accepted_records++;return BW_OK;
}
enum bw_eof_result bw_state_finish(struct bw_state *s) {
    if(!s)return BW_END_INVALID;
    if(s->tag!=BW_TAG) {memset(s,0,sizeof(*s));s->tag=BW_TAG;poison(s,BW_FAULT_STATE);return BW_END_INVALID;}
    s->sealed=1;
    if(s->phase==BW_START||s->phase==BW_HAVE_READY)return BW_END_INCOMPLETE;
    if(s->phase==BW_REPORTED_ERROR)return BW_END_REPORTED_ERROR;
    if(s->phase==BW_HAVE_ATTEMPT)return BW_END_ATTEMPT_WITHOUT_REPORTED_EXEC_ERROR;
    if(s->phase!=BW_POISONED)poison(s,BW_FAULT_STATE);
    return BW_END_INVALID;
}
