#include "runner_protocol.h"
#include <string.h>
static int append(struct nr_status_stream *s,const struct bio_result *r) {
    if(r->bytes_moved>sizeof(r->prefix) || r->bytes_moved>NR_STATUS_CAPACITY-s->used)return -1;
    memcpy(s->raw+s->used,r->prefix,r->bytes_moved);s->used+=r->bytes_moved;return 0;
}
static int io_fail(struct nr_status_stream *s,const struct bio_error *e) {
    if(!s->failed)s->first_io_error=*e;
    s->failed=1;s->end=BW_END_INVALID;return -1;
}
static int wire_fail(struct nr_status_stream *s,enum bw_fault f) {
    if(s->first_wire_error==BW_OK)s->first_wire_error=f;
    s->failed=1;s->end=BW_END_INVALID;return -1;
}
int nr_status_init(struct nr_status_stream *s,const struct bw_binding *b) {
    if(!s)return -1;
    memset(s,0,sizeof(*s));s->end=BW_END_INVALID;
    enum bw_fault f=bw_state_init(&s->wire,b);
    if(f!=BW_OK)return wire_fail(s,f);
    return 0;
}
static int finish(struct nr_status_stream *s,int fd,struct bio_time d,const struct bio_operations *o) {
    struct bio_result r;struct bio_error e;
    int rc=bio_require_eof(fd,d,o,&r,&e);
    if(append(s,&r))return wire_fail(s,BW_FAULT_EXTRA);
    if(rc)return io_fail(s,&e);
    s->end=bw_state_finish(&s->wire);s->ended=1;
    if(s->end==BW_END_INVALID)return wire_fail(s,BW_FAULT_STATE);
    return 1;
}
int nr_status_next(struct nr_status_stream *s,int fd,struct bio_time d,const struct bio_operations *o) {
    if(!s)return -1;
    if(s->failed || s->ended)return wire_fail(s,BW_FAULT_STATE);
    if(s->wire.phase==BW_REPORTED_ERROR || s->wire.accepted_records>=3)return finish(s,fd,d,o);
    struct bio_result r;struct bio_error e;
    int rc=bio_read_record(fd,BW_STATUS_SIZE,d,o,&r,&e);
    if(append(s,&r))return wire_fail(s,BW_FAULT_EXTRA);
    if(rc) {
        if(e.stage==BIO_STAGE_READ && e.reason==BIO_REASON_TRUNCATED && e.system_errno==0 && r.bytes_moved==0)
            /* Record-mode zero read lacks a post-read clock check. Require a
             * second bounded EOF operation at the SAME deadline before sealing. */
            return finish(s,fd,d,o);
        return io_fail(s,&e);
    }
    enum bw_fault f=bw_state_push(&s->wire,r.prefix,BW_STATUS_SIZE);
    if(f!=BW_OK)return wire_fail(s,f);
    return 0;
}
int nr_probe_compare(const struct br_request *r,const struct bw_binding *b,
                     const uint64_t flags[3],const struct np_report *p) {
    if(!r || !b || !flags || !p)return -1;
    uint8_t request[BR_MAX_WIRE],go[BW_GO_SIZE],report[NP_REPORT_SIZE];
    size_t used;struct br_error error;
    if(br_request_encode(r,request,&used,&error)!=BR_OK || bw_go_encode(b,go)!=BW_OK ||
       np_report_encode(p,report)!=NP_OK)return -1;
    struct np_report q;
    if(np_report_decode(report,sizeof(report),b->request_sha256,&q)!=NP_OK)return -1;
    if(q.pids[0]!=b->child_pid || q.pids[1]!=b->controller_pid || q.pids[2]!=b->child_pid ||
       q.ids[0]!=r->credentials.uid || q.ids[1]!=r->credentials.uid ||
       q.ids[2]!=r->credentials.gid || q.ids[3]!=r->credentials.gid ||
       q.group_count!=r->credentials.group_count || q.cwd_device!=r->cwd_device || q.cwd_inode!=r->cwd_inode)return -1;
    for(unsigned i=0;i<16;i++)if(q.groups[i]!=r->credentials.groups[i])return -1;
    for(unsigned i=0;i<3;i++)if(q.fds[i]!=i || q.status_flags[i]!=flags[i] || q.descriptor_flags[i])return -1;
    if(q.post_ids[0]!=r->credentials.uid || q.post_ids[1]!=r->credentials.uid ||
       q.post_ids[2]!=r->credentials.gid || q.post_ids[3]!=r->credentials.gid ||
       q.fd_count!=3 || q.signal_policy!=1 || q.environment_count!=0 ||
       q.root_regain_result!=-1 || q.root_regain_errno!=NP_DARWIN_EPERM)return -1;
    return 0;
}
