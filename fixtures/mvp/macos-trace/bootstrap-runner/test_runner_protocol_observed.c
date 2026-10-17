#define _POSIX_C_SOURCE 200809L
#define _DEFAULT_SOURCE 1
#include "runner_protocol.h"
#include <errno.h>
#include <fcntl.h>
#include <poll.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>

#define CHECK(x) do { if (!(x)) { fprintf(stderr,"line %d: %s\n",__LINE__,#x); exit(1); } } while(0)
#define SECOND UINT64_C(1000000000)
struct model {
    uint8_t data[NR_STATUS_CAPACITY];
    size_t length,offset,chunk,fail_offset;
    uint64_t now,deadline;
    unsigned clocks,polls,reads,pumps,zero_reads,eof_reads,max_timeout;
    unsigned fail_pump,fail_zero,late_zero,retry_polls,read_error_on;
    int observer_result,fail_after_offset,storm,advance_poll,late_progress;
    int poll_error,read_error,fail_clock,fail_after_read,inject_after_zero;
};
static struct bio_time time_at(uint64_t n) {
    return (struct bio_time){n/SECOND,n%SECOND};
}
static int clock_cb(void *c,struct bio_time *t,int *e) {
    struct model *m=c;m->clocks++;
    if(m->fail_clock){*e=EIO;return -1;}
    *t=time_at(m->now);return 0;
}
static int stat_cb(void *c,int fd,mode_t *mode,int *e) {
    (void)c;(void)e;CHECK(fd==7);*mode=S_IFIFO|0600;return 0;
}
static int flags_cb(void *c,int fd,int *e) {
    (void)c;(void)e;CHECK(fd==7);return O_RDONLY|O_NONBLOCK;
}
static int poll_cb(void *c,int fd,short wanted,int timeout,short *events,int *e) {
    struct model *m=c;CHECK(fd==7&&wanted==POLLIN&&timeout>0);m->polls++;
    if((unsigned)timeout>m->max_timeout)m->max_timeout=(unsigned)timeout;
    if(m->advance_poll)m->now+=(uint64_t)timeout*1000000;
    if(m->poll_error){*e=EACCES;m->fail_clock=1;return -1;}
    if(m->retry_polls){m->retry_polls--;*events=0;return 0;}
    if(m->storm){*events=0;return 0;}
    *events=POLLIN;return 1;
}
static ssize_t read_cb(void *c,int fd,void *p,size_t n,int *e) {
    struct model *m=c;CHECK(fd==7&&n>0&&n<=BW_STATUS_SIZE);m->reads++;
    if(n==1)m->eof_reads++;
    if(m->read_error||m->read_error_on==m->reads){*e=EACCES;m->fail_clock=1;return -1;}
    size_t amount=m->length-m->offset;
    if(amount>n)amount=n;
    if(m->chunk&&amount>m->chunk)amount=m->chunk;
    memcpy(p,m->data+m->offset,amount);m->offset+=amount;
    if(!amount){
        m->zero_reads++;
        if(m->late_zero==m->zero_reads)m->now=m->deadline;
        if(m->inject_after_zero){CHECK(m->length<sizeof(m->data));m->data[m->length++]=0x5a;m->inject_after_zero=0;}
    }
    if(amount&&m->late_progress)m->now=m->deadline;
    return (ssize_t)amount;
}
static ssize_t write_cb(void *c,int fd,const void *p,size_t n,int *e) {
    (void)c;(void)fd;(void)p;(void)n;(void)e;CHECK(0);return -1;
}
static int progress_cb(void *c,struct bio_time d) {
    struct model *m=c;m->pumps++;
    CHECK(d.seconds==m->deadline/SECOND&&d.nanoseconds==m->deadline%SECOND);
    if((m->fail_pump&&m->pumps==m->fail_pump)||
       (m->fail_after_offset&&m->offset>=m->fail_offset)||
       (m->fail_zero&&m->zero_reads>=m->fail_zero)||
       (m->fail_after_read&&m->reads>=(unsigned)m->fail_after_read)) {
        m->fail_clock=1;return m->observer_result;
    }
    return 0;
}
static struct bio_operations operations(struct model *m) {
    return (struct bio_operations){m,clock_cb,stat_cb,flags_cb,poll_cb,read_cb,write_cb};
}
static struct bw_binding binding(void) {
    struct bw_binding b={100,200,{0}};
    for(unsigned i=0;i<32;i++)b.request_sha256[i]=(uint8_t)i;
    return b;
}
static struct bw_status record(unsigned index) {
    struct bw_status s={0};s.binding=binding();s.detail=-1;s.mutation_flags=3;
    if(index==0){
        s.kind=BW_READY;s.real_uid=s.effective_uid=501;s.real_gid=s.effective_gid=20;
        s.group_count=2;s.groups[0]=20;s.groups[1]=0;s.cwd_device=77;s.cwd_inode=88;
        for(unsigned i=0;i<5;i++)s.kept_fds[i]=i;
        s.kept_fds[3]=8;s.kept_fds[4]=9;
    } else {
        s.kind=index==1?BW_EXEC_ATTEMPT:BW_ERROR;s.sequence=index;s.stage=BW_EXEC;
        if(index==2){s.reason=BW_SYSCALL;s.system_errno=EIO;}
    }
    return s;
}
static void add(struct model *m,struct bw_status s) {
    CHECK(m->length+BW_STATUS_SIZE<=sizeof(m->data));
    CHECK(bw_status_encode(&s,m->data+m->length)==BW_OK);m->length+=BW_STATUS_SIZE;
}
static void start(struct model *m,struct nr_status_stream *s,unsigned records) {
    memset(m,0,sizeof(*m));m->now=SECOND;m->deadline=2*SECOND+200000123;
    m->observer_result=-1;struct bw_binding b=binding();CHECK(nr_status_init(s,&b)==0);
    for(unsigned i=0;i<records;i++)add(m,record(i));
}
static int next(struct model *m,struct nr_status_stream *s) {
    struct bio_operations o=operations(m);struct bio_observer v={m,progress_cb};
    return nr_status_next_observed(s,7,time_at(m->deadline),&o,&v);
}
static void accepted(struct model *m,struct nr_status_stream *s,unsigned count) {
    for(unsigned i=0;i<count;i++)CHECK(next(m,s)==0);
    CHECK(s->wire.accepted_records==count);
}
static void opaque(struct model *m,struct nr_status_stream *s,const struct bw_state *before,
                   size_t used,enum bio_stage stage,enum bio_reason reason,size_t moved) {
    CHECK(s->failed&&!s->ended&&s->end==BW_END_INVALID&&s->used==used);
    CHECK(!memcmp(&s->wire,before,sizeof(*before))&&s->first_wire_error==BW_OK);
    CHECK(!memcmp(s->raw,m->data,used));
    for(size_t i=used;i<sizeof(s->raw);i++)CHECK(s->raw[i]==0);
    CHECK(s->first_io_error.stage==stage&&s->first_io_error.reason==reason&&s->first_io_error.bytes_moved==moved);
    struct bio_error first=s->first_io_error;unsigned clocks=m->clocks,polls=m->polls,reads=m->reads,pumps=m->pumps;
    CHECK(next(m,s)==-1&&s->used==used&&!memcmp(&s->first_io_error,&first,sizeof(first)));
    CHECK(m->clocks==clocks&&m->polls==polls&&m->reads==reads&&m->pumps==pumps);
    CHECK(!memcmp(&s->wire,before,sizeof(*before)));
}
static void arguments(void) {
    for(unsigned terminal=0;terminal<2;terminal++)for(unsigned missing=0;missing<2;missing++){
        struct model m;struct nr_status_stream s;start(&m,&s,terminal?3:1);
        if(terminal)accepted(&m,&s,3);
        struct bw_state before=s.wire;unsigned clocks=m.clocks,pumps=m.pumps;
        struct bio_operations o=operations(&m);struct bio_observer v={&m,NULL};
        CHECK(nr_status_next_observed(&s,7,time_at(m.deadline),&o,missing?NULL:&v)==-1);
        CHECK(m.clocks==clocks&&m.pumps==pumps);
        opaque(&m,&s,&before,terminal?768:0,BIO_STAGE_OPERATIONS,BIO_REASON_ARGUMENT,0);
    }
    struct model m;struct nr_status_stream s;start(&m,&s,1);
    struct bio_operations o=operations(&m);struct bio_observer v={&m,progress_cb};
    CHECK(nr_status_next_observed(NULL,7,time_at(m.deadline),&o,&v)==-1&&m.clocks==0);
}
static void sequences(void) {
    for(unsigned count=0;count<=3;count++){
        struct model m;struct nr_status_stream s;start(&m,&s,count);accepted(&m,&s,count);
        unsigned pumps=m.pumps,reads=m.reads;
        CHECK(next(&m,&s)==1&&s.ended&&!s.failed&&s.used==count*BW_STATUS_SIZE);
        CHECK(s.end==(count==3?BW_END_REPORTED_ERROR:count==2?BW_END_ATTEMPT_WITHOUT_REPORTED_EXEC_ERROR:BW_END_INCOMPLETE));
        CHECK(m.pumps-pumps==(count==3?3u:5u)&&m.reads-reads==(count==3?1u:2u)&&m.eof_reads==1);
        CHECK(m.max_timeout==BIO_OBSERVER_POLL_MS);
    }
    struct model m;struct nr_status_stream s;start(&m,&s,0);
    struct bw_status error=record(2);error.sequence=0;error.stage=BW_REQUEST;error.mutation_flags=0;add(&m,error);
    CHECK(next(&m,&s)==0&&s.wire.has_reported_error);
    CHECK(next(&m,&s)==1&&s.end==BW_END_REPORTED_ERROR&&m.eof_reads==1);
}
static void progress(void) {
    struct model m;struct nr_status_stream s;start(&m,&s,3);m.chunk=17;m.retry_polls=3;
    accepted(&m,&s,3);CHECK(next(&m,&s)==1);
    CHECK(s.used==768&&!memcmp(s.raw,m.data,768)&&m.pumps>3*3+3&&m.max_timeout==20);
    CHECK(s.wire.has_reported_error&&s.wire.accepted_records==3&&s.end==BW_END_REPORTED_ERROR);
}
static void before_record(void) {
    for(unsigned phase=0;phase<3;phase++)for(unsigned bad=0;bad<2;bad++){
        struct model m;struct nr_status_stream s;start(&m,&s,3);accepted(&m,&s,phase);
        struct bw_state before=s.wire;m.fail_pump=m.pumps+1;m.observer_result=bad?7:-1;
        unsigned reads=m.reads,polls=m.polls;CHECK(next(&m,&s)==-1);
        CHECK(m.reads==reads&&m.polls==polls&&s.first_io_error.system_errno==0);
        opaque(&m,&s,&before,phase*256,BIO_STAGE_OBSERVER,bad?BIO_REASON_ADAPTER:BIO_REASON_OBSERVER,0);
    }
}
static void failed_prefixes(void) {
    for(unsigned phase=0;phase<3;phase++)for(unsigned complete=0;complete<2;complete++){
        struct model m;struct nr_status_stream s;start(&m,&s,3);accepted(&m,&s,phase);
        struct bw_state before=s.wire;size_t amount=complete?256:13;
        m.chunk=amount;m.fail_after_offset=1;m.fail_offset=phase*256+amount;
        /* Even a malformed complete record must remain undecoded after the pump fails. */
        if(complete)m.data[phase*256+16]^=1;
        CHECK(next(&m,&s)==-1&&s.first_io_error.system_errno==0);
        opaque(&m,&s,&before,(phase*256)+amount,BIO_STAGE_OBSERVER,BIO_REASON_OBSERVER,amount);
    }
}
static void eof_failures(void) {
    /* Direct strict EOF after ERROR: fail before poll or after confirmed EOF. */
    for(unsigned after=0;after<2;after++){
        struct model m;struct nr_status_stream s;start(&m,&s,3);accepted(&m,&s,3);
        struct bw_state before=s.wire;if(after)m.fail_zero=1;else m.fail_pump=m.pumps+1;
        unsigned reads=m.reads;CHECK(next(&m,&s)==-1&&m.reads==reads+after);
        CHECK(s.wire.has_reported_error&&!s.wire.sealed);
        opaque(&m,&s,&before,768,BIO_STAGE_OBSERVER,BIO_REASON_OBSERVER,0);
    }
    /* Zero-record fallback must also pump, before poll and after EOF, with no sealing on failure. */
    for(unsigned after=0;after<2;after++){
        struct model m;struct nr_status_stream s;start(&m,&s,0);struct bw_state before=s.wire;
        m.fail_zero=after?2:1;CHECK(next(&m,&s)==-1&&m.zero_reads==(after?2u:1u));
        CHECK(m.eof_reads==after&&!s.wire.sealed);
        opaque(&m,&s,&before,0,BIO_STAGE_OBSERVER,BIO_REASON_OBSERVER,0);
    }
}
static void trailing_precedence(void) {
    struct model m;struct nr_status_stream s;start(&m,&s,3);accepted(&m,&s,3);
    struct bw_state before=s.wire;m.data[m.length++]=0x5a;
    /* A pump failure scheduled after the byte must not replace confirmed trailing. */
    m.fail_after_offset=1;m.fail_offset=769;
    CHECK(next(&m,&s)==-1&&s.first_io_error.system_errno==0&&s.wire.has_reported_error);
    opaque(&m,&s,&before,769,BIO_STAGE_EOF,BIO_REASON_TRAILING,1);
    /* A new byte appearing only during the strict fallback is also retained. */
    start(&m,&s,0);before=s.wire;m.inject_after_zero=1;
    m.fail_after_offset=1;m.fail_offset=1;
    CHECK(next(&m,&s)==-1&&m.reads==2&&m.eof_reads==1);
    opaque(&m,&s,&before,1,BIO_STAGE_EOF,BIO_REASON_TRAILING,1);
    /* Existing BIO post-read deadline precedence also remains unchanged. */
    start(&m,&s,3);accepted(&m,&s,3);before=s.wire;
    m.data[m.length++]=0x5a;m.late_progress=1;
    CHECK(next(&m,&s)==-1);
    opaque(&m,&s,&before,769,BIO_STAGE_CLOCK,BIO_REASON_DEADLINE,1);
}
static void io_precedence(void) {
    struct model m;struct nr_status_stream s;start(&m,&s,1);struct bw_state before=s.wire;
    m.poll_error=1;m.fail_pump=2;CHECK(next(&m,&s)==-1&&m.pumps==1&&s.first_io_error.system_errno==EACCES);
    opaque(&m,&s,&before,0,BIO_STAGE_POLL,BIO_REASON_SYSCALL,0);
    start(&m,&s,1);before=s.wire;m.read_error=1;m.fail_after_read=1;
    CHECK(next(&m,&s)==-1&&m.pumps==2&&s.first_io_error.system_errno==EACCES);
    opaque(&m,&s,&before,0,BIO_STAGE_READ,BIO_REASON_SYSCALL,0);
    start(&m,&s,1);m.length=23;before=s.wire;m.fail_zero=1;
    CHECK(next(&m,&s)==-1&&m.reads==2&&m.eof_reads==0&&m.zero_reads==1);
    opaque(&m,&s,&before,23,BIO_STAGE_READ,BIO_REASON_TRUNCATED,23);
    start(&m,&s,3);accepted(&m,&s,3);before=s.wire;
    m.read_error=1;m.fail_after_read=(int)m.reads+1;
    CHECK(next(&m,&s)==-1&&s.first_io_error.system_errno==EACCES);
    opaque(&m,&s,&before,768,BIO_STAGE_EOF,BIO_REASON_SYSCALL,0);
    start(&m,&s,0);before=s.wire;m.read_error_on=2;m.fail_after_read=2;
    CHECK(next(&m,&s)==-1&&m.reads==2&&m.eof_reads==1&&s.first_io_error.system_errno==EACCES);
    opaque(&m,&s,&before,0,BIO_STAGE_EOF,BIO_REASON_SYSCALL,0);
}
static void deadlines(void) {
    for(unsigned zero=1;zero<=2;zero++){
        struct model m;struct nr_status_stream s;start(&m,&s,0);struct bw_state before=s.wire;
        m.late_zero=zero;CHECK(next(&m,&s)==-1&&m.zero_reads==zero&&!s.ended);
        opaque(&m,&s,&before,0,BIO_STAGE_CLOCK,BIO_REASON_DEADLINE,0);
    }
    struct model m;struct nr_status_stream s;start(&m,&s,3);accepted(&m,&s,3);
    struct bw_state before=s.wire;m.late_zero=1;CHECK(next(&m,&s)==-1);
    opaque(&m,&s,&before,768,BIO_STAGE_CLOCK,BIO_REASON_DEADLINE,0);
    start(&m,&s,1);before=s.wire;m.late_progress=1;CHECK(next(&m,&s)==-1);
    opaque(&m,&s,&before,256,BIO_STAGE_CLOCK,BIO_REASON_DEADLINE,256);
    start(&m,&s,1);before=s.wire;m.storm=m.advance_poll=1;CHECK(next(&m,&s)==-1);
    CHECK(m.now>=m.deadline&&m.now-m.deadline<1000000&&m.max_timeout==20&&m.reads==0);
    opaque(&m,&s,&before,0,BIO_STAGE_CLOCK,BIO_REASON_DEADLINE,0);
}
static void wire_errors(void) {
    struct model m;struct nr_status_stream s;start(&m,&s,1);m.data[16]^=1;
    CHECK(next(&m,&s)==-1&&s.first_wire_error==BW_FAULT_BINDING&&s.used==256&&s.first_io_error.reason==BIO_REASON_NONE);
    start(&m,&s,0);add(&m,record(1));
    CHECK(next(&m,&s)==-1&&s.first_wire_error==BW_FAULT_ORDER&&s.used==256);
}
static void legacy(void) {
    struct model a,b;struct nr_status_stream sa,sb;start(&a,&sa,3);start(&b,&sb,3);
    struct bio_operations o=operations(&a);
    for(unsigned i=0;i<3;i++)CHECK(nr_status_next(&sa,7,time_at(a.deadline),&o)==next(&b,&sb));
    CHECK(nr_status_next(&sa,7,time_at(a.deadline),&o)==next(&b,&sb));
    CHECK(!memcmp(&sa,&sb,sizeof(sa))&&a.pumps==0&&a.max_timeout>20&&b.pumps>0&&b.max_timeout==20);
}
int main(int argc,char **argv) {
    CHECK(argc==2);
    const struct {const char *name;void (*run)(void);} cases[]={
        {"arguments",arguments},{"sequences",sequences},{"progress",progress},
        {"before-record",before_record},{"failed-prefixes",failed_prefixes},
        {"eof-failures",eof_failures},{"trailing-precedence",trailing_precedence},
        {"io-precedence",io_precedence},{"deadlines",deadlines},
        {"wire-errors",wire_errors},{"legacy",legacy}};
    for(size_t i=0;i<sizeof(cases)/sizeof(cases[0]);i++)if(!strcmp(argv[1],cases[i].name)){
        cases[i].run();puts(cases[i].name);return 0;
    }
    return 2;
}
