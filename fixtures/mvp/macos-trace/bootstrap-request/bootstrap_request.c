#include "bootstrap_request.h"
#include <limits.h>
#include <string.h>

_Static_assert(CHAR_BIT == 8, "wire octets");
_Static_assert(TC_MAX_GROUPS == 16 && BW_GROUPS == 16, "group profile");
static const uint8_t magic[8] = {'G','L','U','E','N','R','0','1'};
static void put16(uint8_t *p, uint32_t n) {
    p[0]=(uint8_t)(n>>8); p[1]=(uint8_t)n;
}
static void put32(uint8_t *p, uint64_t n) {
    for (unsigned i=0; i<4; i++) p[i]=(uint8_t)(n>>(24-8*i));
}
static void put64(uint8_t *p, uint64_t n) {
    for (unsigned i=0; i<8; i++) p[i]=(uint8_t)(n>>(56-8*i));
}
static uint32_t get16(const uint8_t *p) { return ((uint32_t)p[0]<<8)|p[1]; }
static uint32_t get32(const uint8_t *p) {
    uint32_t n=0; for (unsigned i=0; i<4; i++) n=(n<<8)|p[i]; return n;
}
static uint64_t get64(const uint8_t *p) {
    uint64_t n=0; for (unsigned i=0; i<8; i++) n=(n<<8)|p[i]; return n;
}
static enum br_fault fail(struct br_error *e, enum br_fault f, enum br_field field, size_t i) {
    if (e) { e->fault=f; e->field=field; e->index=i; }
    return f;
}
static void clear_error(struct br_error *e) {
    if (e) *e=(struct br_error){BR_OK,BR_FIELD_NONE,BR_NO_INDEX,BW_OK};
}
static enum br_fault path_valid(struct br_span p, int cwd, struct br_error *e) {
    enum br_field field=cwd ? BR_FIELD_CWD : BR_FIELD_EXECUTABLE;
    if (!p.bytes) return fail(e,BR_ARGUMENT,field,BR_NO_INDEX);
    if (p.length==0 || p.length>BR_MAX_PATH) return fail(e,BR_LENGTH,field,BR_NO_INDEX);
    if (p.bytes[0]!='/') return fail(e,BR_PATH,field,0);
    if (p.length==1) return cwd ? BR_OK : fail(e,BR_PATH,field,0);
    size_t start=1;
    for (size_t i=1; i<=p.length; i++) {
        if (i<p.length && p.bytes[i]==0) return fail(e,BR_PATH,field,i);
        if (i==p.length || p.bytes[i]=='/') {
            size_t n=i-start;
            if (n==0 || n>BR_MAX_COMPONENT ||
                (n==1 && p.bytes[start]=='.') ||
                (n==2 && p.bytes[start]=='.' && p.bytes[start+1]=='.'))
                return fail(e,BR_PATH,field,start);
            start=i+1;
        }
    }
    return BR_OK;
}
static enum br_fault validate(const struct br_request *r, struct br_error *e) {
    if (!r) return fail(e,BR_ARGUMENT,BR_FIELD_NONE,BR_NO_INDEX);
    if (r->fixture!=1) return fail(e,BR_SELECTOR,BR_FIELD_FIXTURE,BR_NO_INDEX);
    struct tc_error t;
    if (tc_validate_request(&r->credentials,&t))
        return fail(e,BR_GROUPS,BR_FIELD_CREDENTIALS,t.group_index);
    for (size_t i=r->credentials.group_count; i<TC_MAX_GROUPS; i++)
        if (r->credentials.groups[i]) return fail(e,BR_CANONICAL,BR_FIELD_GROUPS,i);
    if (r->signal_policy!=1) return fail(e,BR_SELECTOR,BR_FIELD_SIGNAL_POLICY,BR_NO_INDEX);
    if (r->stdio_policy!=1) return fail(e,BR_SELECTOR,BR_FIELD_STDIO_POLICY,BR_NO_INDEX);
    if (r->release_action!=BR_SEND_GO && r->release_action!=BR_SIMULATED_PROVIDER_FAILURE)
        return fail(e,BR_SELECTOR,BR_FIELD_RELEASE,BR_NO_INDEX);
    if (r->max_live_fds!=4096) return fail(e,BR_RANGE,BR_FIELD_FD_LIMIT,BR_NO_INDEX);
    if (r->attempt_ms<1 || r->attempt_ms>10000) return fail(e,BR_RANGE,BR_FIELD_ATTEMPT_MS,BR_NO_INDEX);
    if (r->cleanup_ms<1 || r->cleanup_ms>2000) return fail(e,BR_RANGE,BR_FIELD_CLEANUP_MS,BR_NO_INDEX);
    if (r->argv_template!=1) return fail(e,BR_SELECTOR,BR_FIELD_ARGV_TEMPLATE,BR_NO_INDEX);
    if (r->environment_count) return fail(e,BR_SELECTOR,BR_FIELD_ENVIRONMENT,BR_NO_INDEX);
    enum br_fault f=path_valid(r->executable,0,e);
    if (f!=BR_OK) return f;
    return path_valid(r->cwd,1,e);
}
enum br_fault br_request_encode(const struct br_request *r, uint8_t out[BR_MAX_WIRE],
                                size_t *written, struct br_error *e) {
    if (out) memset(out,0,BR_MAX_WIRE);
    if (written) *written=0;
    clear_error(e);
    if (!out || !written || !e) return fail(e,BR_ARGUMENT,BR_FIELD_NONE,BR_NO_INDEX);
    enum br_fault f=validate(r,e);
    if (f!=BR_OK) return f;
    size_t total=BR_HEADER_SIZE+r->executable.length+r->cwd.length;
    if (total>BR_MAX_WIRE) return fail(e,BR_LENGTH,BR_FIELD_HEADER,BR_NO_INDEX);
    memcpy(out,magic,8); put16(out+8,1); put16(out+10,BR_HEADER_SIZE);
    put32(out+12,total); put32(out+16,r->fixture);
    put32(out+20,r->credentials.uid); put32(out+24,r->credentials.gid);
    put32(out+28,r->credentials.group_count);
    for (unsigned i=0; i<TC_MAX_GROUPS; i++) put32(out+32+4*i,r->credentials.groups[i]);
    put32(out+96,r->signal_policy); put32(out+100,r->stdio_policy);
    put32(out+104,r->release_action); put32(out+108,r->max_live_fds);
    put32(out+112,r->attempt_ms); put32(out+116,r->cleanup_ms);
    put32(out+120,r->argv_template); put32(out+124,r->environment_count);
    memcpy(out+128,r->catalog_sha256,32);
    put64(out+160,r->cwd_device); put64(out+168,r->cwd_inode);
    put32(out+176,r->executable.length); put32(out+180,r->cwd.length);
    memcpy(out+BR_HEADER_SIZE,r->executable.bytes,r->executable.length);
    memcpy(out+BR_HEADER_SIZE+r->executable.length,r->cwd.bytes,r->cwd.length);
    *written=total;
    return BR_OK;
}
enum br_fault br_request_decode(const uint8_t *in, size_t n, struct br_request *out,
                                struct br_error *e) {
    if (out) memset(out,0,sizeof(*out));
    clear_error(e);
    if (!out || !e) return fail(e,BR_ARGUMENT,BR_FIELD_NONE,BR_NO_INDEX);
    if (n<BR_HEADER_SIZE || n>BR_MAX_WIRE) return fail(e,BR_LENGTH,BR_FIELD_HEADER,BR_NO_INDEX);
    if (!in) return fail(e,BR_ARGUMENT,BR_FIELD_NONE,BR_NO_INDEX);
    if (memcmp(in,magic,8)) return fail(e,BR_MAGIC,BR_FIELD_HEADER,BR_NO_INDEX);
    if (get16(in+8)!=1) return fail(e,BR_VERSION,BR_FIELD_HEADER,BR_NO_INDEX);
    if (get16(in+10)!=BR_HEADER_SIZE || get32(in+12)!=n)
        return fail(e,BR_LENGTH,BR_FIELD_HEADER,BR_NO_INDEX);
    for (unsigned i=184; i<208; i++)
        if (in[i]) return fail(e,BR_RESERVED,BR_FIELD_HEADER,i);
    uint32_t a=get32(in+176), b=get32(in+180);
    if (a==0 || a>BR_MAX_PATH || b==0 || b>BR_MAX_PATH ||
        (size_t)a+(size_t)b!=n-BR_HEADER_SIZE)
        return fail(e,BR_LENGTH,BR_FIELD_HEADER,BR_NO_INDEX);
    struct br_request r={0};
    r.fixture=get32(in+16); r.credentials.uid=get32(in+20);
    r.credentials.gid=get32(in+24); r.credentials.group_count=get32(in+28);
    for (unsigned i=0; i<TC_MAX_GROUPS; i++) r.credentials.groups[i]=get32(in+32+4*i);
    r.signal_policy=get32(in+96); r.stdio_policy=get32(in+100);
    r.release_action=get32(in+104); r.max_live_fds=get32(in+108);
    r.attempt_ms=get32(in+112); r.cleanup_ms=get32(in+116);
    r.argv_template=get32(in+120); r.environment_count=get32(in+124);
    memcpy(r.catalog_sha256,in+128,32);
    r.cwd_device=get64(in+160); r.cwd_inode=get64(in+168);
    r.executable=(struct br_span){in+BR_HEADER_SIZE,a};
    r.cwd=(struct br_span){in+BR_HEADER_SIZE+a,b};
    enum br_fault f=validate(&r,e);
    if (f!=BR_OK) return f;
    *out=r;
    return BR_OK;
}
enum br_fault br_ready_compare(const struct br_request *r, const struct br_ready_context *c,
                               const struct bw_status *s, struct br_error *e) {
    clear_error(e);
    if (!e) return BR_ARGUMENT;
    enum br_fault f=validate(r,e);
    if (f!=BR_OK) return f;
    if (!c || !s) return fail(e,BR_ARGUMENT,BR_FIELD_NONE,BR_NO_INDEX);
    uint8_t go[BW_GO_SIZE];
    enum bw_fault bf=bw_go_encode(&c->binding,go);
    if (bf!=BW_OK) {
        e->wire_fault=bf;
        return fail(e,BR_CONTEXT,BR_FIELD_BINDING,BR_NO_INDEX);
    }
    for (unsigned i=0; i<5; i++) {
        if ((i<3 && c->kept_fds[i]!=i) ||
            (i>=3 && (c->kept_fds[i]<3 || c->kept_fds[i]>INT32_MAX)))
            return fail(e,BR_CONTEXT,BR_FIELD_KEPT_FDS,i);
    }
    if (c->kept_fds[3]==c->kept_fds[4]) return fail(e,BR_CONTEXT,BR_FIELD_KEPT_FDS,4);
    uint8_t bytes[BW_STATUS_SIZE];
    bf=bw_status_encode(s,bytes);
    if (bf!=BW_OK) {
        e->wire_fault=bf;
        return fail(e,BR_STATUS,BR_FIELD_READY_KIND,BR_NO_INDEX);
    }
    struct bw_status checked;
    bf=bw_status_decode(bytes,sizeof(bytes),&c->binding,&checked);
    if (bf!=BW_OK) {
        e->wire_fault=bf;
        return fail(e,BR_STATUS,BR_FIELD_BINDING,BR_NO_INDEX);
    }
    if (checked.kind!=BW_READY) return fail(e,BR_STATUS,BR_FIELD_READY_KIND,BR_NO_INDEX);
    if (checked.mutation_flags!=BR_READY_FLAGS)
        return fail(e,BR_MISMATCH,BR_FIELD_READY_FLAGS,BR_NO_INDEX);
    if (checked.real_uid!=r->credentials.uid || checked.effective_uid!=r->credentials.uid ||
        checked.real_gid!=r->credentials.gid || checked.effective_gid!=r->credentials.gid)
        return fail(e,BR_MISMATCH,BR_FIELD_IDS,BR_NO_INDEX);
    if (checked.group_count!=r->credentials.group_count)
        return fail(e,BR_MISMATCH,BR_FIELD_GROUPS,BR_NO_INDEX);
    for (unsigned i=0; i<TC_MAX_GROUPS; i++)
        if (checked.groups[i]!=r->credentials.groups[i]) return fail(e,BR_MISMATCH,BR_FIELD_GROUPS,i);
    if (checked.cwd_device!=r->cwd_device || checked.cwd_inode!=r->cwd_inode)
        return fail(e,BR_MISMATCH,BR_FIELD_CWD_IDENTITY,BR_NO_INDEX);
    for (unsigned i=0; i<5; i++)
        if (checked.kept_fds[i]!=c->kept_fds[i]) return fail(e,BR_MISMATCH,BR_FIELD_KEPT_FDS,i);
    if (memcmp(checked.signal_policy_sha256,c->signal_policy_sha256,32))
        return fail(e,BR_MISMATCH,BR_FIELD_SIGNAL_POLICY,BR_NO_INDEX);
    return BR_OK;
}
