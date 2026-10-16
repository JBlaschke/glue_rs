#define _POSIX_C_SOURCE 200809L
#define _DEFAULT_SOURCE 1
#include "bootstrap_io.h"
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <poll.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

#define CHECK(c) do { if (!(c)) { fprintf(stderr,"line %d: %s\n", __LINE__, #c); return 1; } } while (0)
#define BASE UINT64_C(1000000000)
struct action { ssize_t value; int error; };
struct fake {
    mode_t mode;
    int flags, stat_rc, stat_error, flags_error, clock_rc, clock_error, clock_malformed;
    uint64_t time, tick, times[32];
    size_t times_len;
    int calls[6], poll_rc, poll_error, events;
    struct action reads[16], writes[16];
    size_t reads_len, writes_len, read_offset, write_offset;
    unsigned char data[256], emitted[256];
    int first_timeout, last_timeout;
};
static void init(struct fake *f, int writing) {
    memset(f, 0, sizeof(*f));
    f->mode = S_IFIFO | 0600;
    f->flags = (writing ? O_WRONLY : O_RDONLY) | O_NONBLOCK;
    f->time = BASE; f->poll_rc = 1; f->events = -1;
    for (size_t i=0;i<sizeof(f->data);i++) f->data[i]=(unsigned char)(i ^ 0x9b);
}
static int fclock(void *p, struct bio_time *t, int *e) {
    struct fake *f=p; size_t i=(size_t)f->calls[0]++;
    if (f->clock_rc) { *e=f->clock_error; return f->clock_rc; }
    if (f->clock_malformed) {
        t->seconds=f->clock_malformed==2 ? UINT64_MAX : 0;
        t->nanoseconds=f->clock_malformed==1 ? BASE : 0; return 0;
    }
    uint64_t v = i < f->times_len ? f->times[i] : f->time;
    t->seconds=v/BASE; t->nanoseconds=v%BASE;
    f->time += f->tick;
    return 0;
}
static int fstat_(void *p, int fd, mode_t *m, int *e) {
    struct fake *f=p; (void)fd; f->calls[1]++; *m=f->mode; *e=f->stat_error; return f->stat_rc;
}
static int fflags(void *p, int fd, int *e) {
    struct fake *f=p; (void)fd; f->calls[2]++; *e=f->flags_error; return f->flags;
}
static int fpoll(void *p, int fd, short wanted, int timeout, short *events, int *e) {
    struct fake *f=p; (void)fd; f->calls[3]++;
    if (!f->first_timeout) f->first_timeout=timeout;
    f->last_timeout=timeout;
    *events=(short)(f->events == -1 ? wanted : f->events); *e=f->poll_error;
    return f->poll_rc;
}
static ssize_t fread_(void *p, int fd, void *out, size_t n, int *e) {
    struct fake *f=p; (void)fd; size_t i=(size_t)f->calls[4]++;
    struct action a = i < f->reads_len ? f->reads[i] : (struct action){(ssize_t)n,0};
    *e=a.error;
    if (a.value>0 && (size_t)a.value<=n) {
        memcpy(out,f->data+f->read_offset,(size_t)a.value); f->read_offset+=(size_t)a.value;
    }
    return a.value;
}
static ssize_t fwrite_(void *p, int fd, const void *in, size_t n, int *e) {
    struct fake *f=p; (void)fd; size_t i=(size_t)f->calls[5]++;
    struct action a = i < f->writes_len ? f->writes[i] : (struct action){(ssize_t)n,0};
    *e=a.error;
    if (a.value>0 && (size_t)a.value<=n) {
        memcpy(f->emitted+f->write_offset,in,(size_t)a.value); f->write_offset+=(size_t)a.value;
    }
    return a.value;
}
static struct bio_operations ops(struct fake *f) {
    struct bio_operations o={f,fclock,fstat_,fflags,fpoll,fread_,fwrite_}; return o;
}
static struct bio_time deadline(void) { return (struct bio_time){2,0}; }
static int tail_zero(const struct bio_result *r) {
    for (size_t i=r->bytes_moved;i<256;i++) if (r->prefix[i]) return 0;
    return 1;
}
static int read_fake(struct fake *f, struct bio_result *r, struct bio_error *e) {
    struct bio_operations o=ops(f); return bio_read_record(10,64,deadline(),&o,r,e);
}
static int write_fake(struct fake *f, struct bio_result *r, struct bio_error *e) {
    struct bio_operations o=ops(f); return bio_write_record(11,f->data,64,deadline(),&o,r,e);
}
static int arguments(void) {
    struct fake f; struct bio_result r; struct bio_error e;
    init(&f,0); struct bio_operations o=ops(&f);
    size_t bad[]={0,1,63,65,255,257,SIZE_MAX};
    for(size_t i=0;i<sizeof(bad)/sizeof(bad[0]);i++) {
        memset(&r,0xa5,sizeof(r)); memset(&e,0xa5,sizeof(e));
        CHECK(bio_read_record(10,bad[i],deadline(),&o,&r,&e)==-1);
        CHECK(e.reason==BIO_REASON_LENGTH && r.bytes_moved==0 && tail_zero(&r));
    }
    CHECK(bio_read_record(-1,64,deadline(),&o,&r,&e)==-1 && e.reason==BIO_REASON_ARGUMENT);
    CHECK(bio_write_record(11,NULL,64,deadline(),&o,&r,&e)==-1 && e.reason==BIO_REASON_ARGUMENT);
    CHECK(bio_read_record(10,64,deadline(),&o,NULL,&e)==-1);
    CHECK(bio_read_record(10,64,deadline(),&o,&r,NULL)==-1);
    CHECK(!f.calls[0] && !f.calls[1] && !f.calls[3]);
    for (int i=0;i<6;i++) {
        o=ops(&f);
        switch(i) { case 0:o.clock_fn=NULL;break; case 1:o.stat_fn=NULL;break;
            case 2:o.flags_fn=NULL;break; case 3:o.poll_fn=NULL;break;
            case 4:o.read_fn=NULL;break; case 5:o.write_fn=NULL;break; }
        CHECK(bio_read_record(10,64,deadline(),&o,&r,&e)==-1 && e.stage==BIO_STAGE_OPERATIONS);
    }
    CHECK(bio_read_record(10,64,deadline(),NULL,&r,&e)==-1);
    CHECK(!f.calls[0] && !f.calls[1] && !f.calls[3]); return 0;
}
static int endpoint(void) {
    struct fake f; struct bio_result r; struct bio_error e;
    mode_t kinds[]={S_IFREG,S_IFDIR,S_IFSOCK,S_IFCHR};
    for(size_t i=0;i<sizeof(kinds)/sizeof(kinds[0]);i++) {
        init(&f,0);f.mode=kinds[i];CHECK(read_fake(&f,&r,&e)==-1 && e.reason==BIO_REASON_NOT_PIPE);
        CHECK(!f.calls[3] && !f.calls[4]);
    }
    int flags[]={O_RDONLY,O_WRONLY|O_NONBLOCK,O_RDWR|O_NONBLOCK};
    for(size_t i=0;i<sizeof(flags)/sizeof(flags[0]);i++) {
        init(&f,0);f.flags=flags[i];CHECK(read_fake(&f,&r,&e)==-1);
        CHECK(e.reason==(i?BIO_REASON_ACCESS:BIO_REASON_NONBLOCK));CHECK(!f.calls[3]);
    }
    init(&f,1);f.flags=O_RDONLY|O_NONBLOCK;CHECK(write_fake(&f,&r,&e)==-1 && e.reason==BIO_REASON_ACCESS);
    init(&f,0);f.stat_rc=-1;f.stat_error=EIO;CHECK(read_fake(&f,&r,&e)==-1 && e.system_errno==EIO);
    init(&f,0);f.stat_rc=1;CHECK(read_fake(&f,&r,&e)==-1 && e.reason==BIO_REASON_ADAPTER);
    init(&f,0);f.stat_rc=-1;CHECK(read_fake(&f,&r,&e)==-1 && e.reason==BIO_REASON_ADAPTER);
    init(&f,0);f.flags=-1;f.flags_error=EBADF;CHECK(read_fake(&f,&r,&e)==-1 && e.system_errno==EBADF);
    init(&f,0);f.flags=-2;CHECK(read_fake(&f,&r,&e)==-1 && e.reason==BIO_REASON_ADAPTER);
    return 0;
}
static int time_bounds(void) {
    struct fake f; struct bio_result r; struct bio_error e;
    struct bio_time bad[]={{1,BASE},{UINT64_MAX,0},{UINT64_MAX/BASE,BASE-1},{1,0},{31,1}};
    enum bio_reason reason[]={BIO_REASON_TIME_FORMAT,BIO_REASON_TIME_OVERFLOW,BIO_REASON_TIME_OVERFLOW,
                              BIO_REASON_DEADLINE,BIO_REASON_MAX_FUTURE};
    for(size_t i=0;i<sizeof(bad)/sizeof(bad[0]);i++) {
        init(&f,0);struct bio_operations o=ops(&f);
        CHECK(bio_read_record(10,64,bad[i],&o,&r,&e)==-1 && e.reason==reason[i]);CHECK(!f.calls[3]);
    }
    init(&f,0);f.clock_rc=-1;f.clock_error=EINTR;
    CHECK(read_fake(&f,&r,&e)==-1 && e.stage==BIO_STAGE_CLOCK && e.system_errno==EINTR);
    init(&f,0);f.clock_rc=1;CHECK(read_fake(&f,&r,&e)==-1 && e.reason==BIO_REASON_ADAPTER);
    init(&f,0);f.clock_rc=-1;CHECK(read_fake(&f,&r,&e)==-1 && e.reason==BIO_REASON_ADAPTER);
    init(&f,0);f.clock_malformed=1;
    CHECK(read_fake(&f,&r,&e)==-1 && e.reason==BIO_REASON_TIME_FORMAT);
    init(&f,0);f.clock_malformed=2;
    CHECK(read_fake(&f,&r,&e)==-1 && e.reason==BIO_REASON_TIME_OVERFLOW);
    init(&f,0);f.time=UINT64_MAX;
    CHECK(read_fake(&f,&r,&e)==-1 && e.reason==BIO_REASON_DEADLINE); /* valid largest flattened time */
    init(&f,0);struct bio_operations o=ops(&f);
    CHECK(bio_read_record(10,64,(struct bio_time){31,0},&o,&r,&e)==0);CHECK(f.first_timeout==30000);
    init(&f,0);o=ops(&f);
    CHECK(bio_read_record(10,64,(struct bio_time){1,1},&o,&r,&e)==0);CHECK(f.first_timeout==1);
    return 0;
}
static int time_progress(void) {
    struct fake f; struct bio_result r; struct bio_error e;
    init(&f,0);f.times_len=4;f.times[0]=BASE;f.times[1]=BASE;f.times[2]=BASE;f.times[3]=BASE-1;
    f.reads_len=1;f.reads[0]=(struct action){13,0};
    CHECK(read_fake(&f,&r,&e)==-1 && e.reason==BIO_REASON_CLOCK_ROLLBACK);
    CHECK(r.bytes_moved==13 && e.bytes_moved==13 && tail_zero(&r));
    init(&f,1);f.times_len=4;f.times[0]=BASE;f.times[1]=BASE;f.times[2]=BASE;f.times[3]=2*BASE;
    CHECK(write_fake(&f,&r,&e)==-1 && e.reason==BIO_REASON_DEADLINE);
    CHECK(r.bytes_moved==64 && f.write_offset==64 && !memcmp(r.prefix,f.data,64) && tail_zero(&r));
    init(&f,0);f.times_len=3;f.times[0]=BASE;f.times[1]=BASE;f.times[2]=2*BASE;
    CHECK(read_fake(&f,&r,&e)==-1 && e.reason==BIO_REASON_DEADLINE && !f.calls[4]);
    return 0;
}
static int partial(void) {
    struct fake f; struct bio_result r; struct bio_error e;
    init(&f,0); f.reads_len=4;
    f.reads[0]=(struct action){13,0};f.reads[1]=(struct action){-1,EAGAIN};
    f.reads[2]=(struct action){-1,EINTR};f.reads[3]=(struct action){51,0};
    CHECK(read_fake(&f,&r,&e)==0 && r.bytes_moved==64 && e.reason==BIO_REASON_NONE);
    CHECK(!memcmp(r.prefix,f.data,64) && tail_zero(&r) && f.calls[3]==4);
    init(&f,1);f.writes_len=4;
    f.writes[0]=(struct action){13,0};f.writes[1]=(struct action){-1,EAGAIN};
    f.writes[2]=(struct action){-1,EINTR};f.writes[3]=(struct action){51,0};
    CHECK(write_fake(&f,&r,&e)==0 && f.write_offset==64 && !memcmp(f.emitted,f.data,64));
    CHECK(!memcmp(r.prefix,f.data,64) && tail_zero(&r));
    init(&f,0);f.reads_len=2;f.reads[0]=(struct action){30,0};f.reads[1]=(struct action){-1,EIO};
    CHECK(read_fake(&f,&r,&e)==-1 && e.stage==BIO_STAGE_READ && e.system_errno==EIO);
    CHECK(r.bytes_moved==30 && e.bytes_moved==30 && tail_zero(&r));
    init(&f,1);f.writes_len=2;f.writes[0]=(struct action){30,0};f.writes[1]=(struct action){-1,EPIPE};
    CHECK(write_fake(&f,&r,&e)==-1 && e.stage==BIO_STAGE_WRITE && e.system_errno==EPIPE);
    CHECK(r.bytes_moved==30 && f.write_offset==30 && tail_zero(&r));
    return 0;
}
static int poll_anomalies(void) {
    struct fake f;struct bio_result r;struct bio_error e;
    int rc[]={-2,2,-1,0,1,1,1,1,1};
    int ev[]={0,0,0,POLLIN,0,POLLPRI,POLLNVAL,POLLERR,POLLIN|POLLERR};
    enum bio_reason why[]={BIO_REASON_ADAPTER,BIO_REASON_ADAPTER,BIO_REASON_ADAPTER,BIO_REASON_POLL_EVENT,
        BIO_REASON_POLL_EVENT,BIO_REASON_POLL_EVENT,BIO_REASON_POLL_INVALID,BIO_REASON_POLL_ERROR,BIO_REASON_POLL_ERROR};
    for(size_t i=0;i<sizeof(rc)/sizeof(rc[0]);i++) {
        init(&f,0);f.poll_rc=rc[i];f.events=ev[i];CHECK(read_fake(&f,&r,&e)==-1 && e.reason==why[i]);
        CHECK(!f.calls[4] && r.bytes_moved==0 && tail_zero(&r));
    }
    init(&f,0);f.poll_rc=-1;f.poll_error=ENOSYS;f.events=0;
    CHECK(read_fake(&f,&r,&e)==-1 && e.stage==BIO_STAGE_POLL && e.system_errno==ENOSYS);
    init(&f,0);f.events=POLLIN|POLLHUP;CHECK(read_fake(&f,&r,&e)==0 && r.bytes_moved==64);
    init(&f,0);f.events=POLLHUP;CHECK(read_fake(&f,&r,&e)==0);
    init(&f,1);f.events=POLLOUT|POLLHUP;CHECK(write_fake(&f,&r,&e)==-1 && !f.calls[5]);
    return 0;
}
static int storms(void) {
    struct fake f;struct bio_result r;struct bio_error e;
    init(&f,0);f.poll_rc=-1;f.poll_error=EINTR;f.events=0;f.tick=100000000;
    CHECK(read_fake(&f,&r,&e)==-1 && e.reason==BIO_REASON_DEADLINE && f.calls[3]<10);
    CHECK(f.last_timeout<=f.first_timeout);
    init(&f,0);f.poll_rc=-1;f.poll_error=EINTR;f.events=0;
    CHECK(read_fake(&f,&r,&e)==-1 && e.reason==BIO_REASON_RETRY_LIMIT && f.calls[3]==BIO_MAX_STEPS);
    init(&f,0);f.poll_rc=0;f.events=0;
    CHECK(read_fake(&f,&r,&e)==-1 && e.reason==BIO_REASON_RETRY_LIMIT && f.calls[3]==BIO_MAX_STEPS);
    init(&f,0);f.tick=100000000;f.reads_len=16;
    for(size_t i=0;i<16;i++)f.reads[i]=(struct action){-1,EAGAIN};
    CHECK(read_fake(&f,&r,&e)==-1 && e.reason==BIO_REASON_DEADLINE && f.calls[4]<10);
    return 0;
}
static int io_anomalies(void) {
    struct fake f;struct bio_result r;struct bio_error e;
    ssize_t values[]={-2,-1,65,0};
    enum bio_reason why[]={BIO_REASON_ADAPTER,BIO_REASON_ADAPTER,BIO_REASON_ADAPTER,BIO_REASON_TRUNCATED};
    for(size_t i=0;i<4;i++) {
        init(&f,0);f.reads_len=1;f.reads[0]=(struct action){values[i],0};
        CHECK(read_fake(&f,&r,&e)==-1 && e.reason==why[i] && r.bytes_moved==0 && tail_zero(&r));
        init(&f,1);f.writes_len=1;f.writes[0]=(struct action){values[i],0};
        CHECK(write_fake(&f,&r,&e)==-1 && e.reason==(i==3?BIO_REASON_ZERO_PROGRESS:why[i]));
    }
    init(&f,0);f.reads_len=2;f.reads[0]=(struct action){17,0};f.reads[1]=(struct action){0,0};
    CHECK(read_fake(&f,&r,&e)==-1 && e.reason==BIO_REASON_TRUNCATED && r.bytes_moved==17 && tail_zero(&r));
    init(&f,0);f.reads_len=1;f.reads[0]=(struct action){64,EIO};
    CHECK(read_fake(&f,&r,&e)==0 && e.system_errno==0); /* stale errno on success is ignored */
    return 0;
}
static int eof_fake(void) {
    struct fake f;struct bio_result r;struct bio_error e;
    init(&f,0);struct bio_operations o=ops(&f);f.events=POLLIN|POLLHUP;
    f.reads_len=1;f.reads[0]=(struct action){0,0};
    CHECK(bio_require_eof(10,deadline(),&o,&r,&e)==0 && r.bytes_moved==0 && tail_zero(&r));
    init(&f,0);o=ops(&f);f.reads_len=1;f.reads[0]=(struct action){1,0};
    CHECK(bio_require_eof(10,deadline(),&o,&r,&e)==-1 && e.reason==BIO_REASON_TRAILING);
    CHECK(r.bytes_moved==1 && r.prefix[0]==f.data[0] && tail_zero(&r));
    init(&f,0);o=ops(&f);f.reads_len=1;f.reads[0]=(struct action){2,0};
    CHECK(bio_require_eof(10,deadline(),&o,&r,&e)==-1 && e.reason==BIO_REASON_ADAPTER && !r.bytes_moved);
    init(&f,0);o=ops(&f);f.poll_rc=0;f.events=0;f.tick=100000000;
    CHECK(bio_require_eof(10,deadline(),&o,&r,&e)==-1 && e.reason==BIO_REASON_DEADLINE);
    return 0;
}
static int native_pipe(int p[2]) {
    if (pipe(p)) return -1;
    for(int i=0;i<2;i++) {
        int f=fcntl(p[i],F_GETFL);
        if(f<0 || fcntl(p[i],F_SETFL,f|O_NONBLOCK)) { close(p[0]);close(p[1]);return -1; }
    }
    return 0;
}
static uint64_t monotonic(void) {
    struct timespec t;if(clock_gettime(CLOCK_MONOTONIC,&t))abort();
    return (uint64_t)t.tv_sec*BASE+(uint64_t)t.tv_nsec;
}
static struct bio_time after(unsigned ms) {
    uint64_t n=monotonic()+(uint64_t)ms*1000000;
    return (struct bio_time){n/BASE,n%BASE};
}
static int reap_owned(pid_t child) {
    uint64_t end=monotonic()+2*BASE;int status=0;
    for(;;) {
        pid_t p=waitpid(child,&status,WNOHANG);
        if(p==child)return WIFEXITED(status)&&WEXITSTATUS(status)==0 ? 0 : -1;
        if(p<0 && errno!=EINTR)return -1;
        if(monotonic()>=end) {
            /* Child has not been reaped; never signal a recycled/reaped PID. */
            if(kill(child,SIGKILL) && errno!=ESRCH)return -1;
            do { p=waitpid(child,&status,0); } while(p<0 && errno==EINTR);
            return -1;
        }
        struct timespec pause={0,1000000};nanosleep(&pause,NULL);
    }
}
static int native_roundtrip(void) {
    int p[2];struct bio_result r;struct bio_error e;unsigned char data[256];
    for(size_t i=0;i<256;i++)data[i]=(unsigned char)i;
    CHECK(native_pipe(p)==0);
    int flags[2]={fcntl(p[0],F_GETFL),fcntl(p[1],F_GETFL)};
    for(size_t n=64;n<=256;n*=4) {
        CHECK(bio_write_record(p[1],data,n,after(500),bio_native_operations(),&r,&e)==0);
        CHECK(r.bytes_moved==n && !memcmp(r.prefix,data,n) && tail_zero(&r));
        CHECK(bio_read_record(p[0],n,after(500),bio_native_operations(),&r,&e)==0);
        CHECK(r.bytes_moved==n && !memcmp(r.prefix,data,n) && tail_zero(&r));
    }
    /* Darwin may expose an internal written-since-open bit after write.
     * Assert stable public access/nonblocking/append flags. */
    int stable=O_ACCMODE|O_NONBLOCK|O_APPEND;
    CHECK(!((flags[0]^fcntl(p[0],F_GETFL))&stable));
    CHECK(!((flags[1]^fcntl(p[1],F_GETFL))&stable));
    CHECK(close(p[1])==0);
    CHECK(bio_require_eof(p[0],after(500),bio_native_operations(),&r,&e)==0);
    CHECK(close(p[0])==0);return 0;
}
static int native_fragmented(void) {
    int p[2];CHECK(native_pipe(p)==0);pid_t child=fork();CHECK(child>=0);
    if(!child) {
        close(p[0]);unsigned char data[256];for(size_t i=0;i<256;i++)data[i]=(unsigned char)i;
        for(size_t off=0;off<256;) {
            size_t n=256-off<17?256-off:17;ssize_t w=write(p[1],data+off,n);
            if(w!=(ssize_t)n)_exit(1);
            off+=n;
            struct timespec pause={0,1000000};nanosleep(&pause,NULL);
        }
        close(p[1]);_exit(0);
    }
    close(p[1]);struct bio_result r;struct bio_error e;
    int rc=bio_read_record(p[0],256,after(1000),bio_native_operations(),&r,&e);
    int child_rc=reap_owned(child);close(p[0]);CHECK(rc==0 && child_rc==0 && r.bytes_moved==256);
    for(size_t i=0;i<256;i++)CHECK(r.prefix[i]==(unsigned char)i);
    return 0;
}
static int native_hup(void) {
    int p[2];CHECK(native_pipe(p)==0);unsigned char data[256];memset(data,0xd7,sizeof(data));
    CHECK(write(p[1],data,256)==256 && close(p[1])==0);
    struct bio_result r;struct bio_error e;
    CHECK(bio_read_record(p[0],256,after(500),bio_native_operations(),&r,&e)==0);
    CHECK(!memcmp(r.prefix,data,256));
    CHECK(bio_require_eof(p[0],after(500),bio_native_operations(),&r,&e)==0);
    CHECK(close(p[0])==0);return 0;
}
static int native_truncated(void) {
    int p[2];CHECK(native_pipe(p)==0);unsigned char data[17];memset(data,0xab,sizeof(data));
    CHECK(write(p[1],data,17)==17 && close(p[1])==0);
    struct bio_result r;struct bio_error e;
    CHECK(bio_read_record(p[0],64,after(500),bio_native_operations(),&r,&e)==-1);
    CHECK(e.reason==BIO_REASON_TRUNCATED && e.bytes_moved==17 && r.bytes_moved==17);
    CHECK(!memcmp(r.prefix,data,17) && tail_zero(&r));CHECK(close(p[0])==0);return 0;
}
static int native_eof_extra(void) {
    int p[2];CHECK(native_pipe(p)==0);CHECK(write(p[1],"X",1)==1 && close(p[1])==0);
    struct bio_result r;struct bio_error e;
    CHECK(bio_require_eof(p[0],after(500),bio_native_operations(),&r,&e)==-1);
    CHECK(e.reason==BIO_REASON_TRAILING && r.bytes_moved==1 && r.prefix[0]=='X' && tail_zero(&r));
    CHECK(close(p[0])==0);return 0;
}
static int native_deadline(void) {
    int p[2];CHECK(native_pipe(p)==0);struct bio_result r;struct bio_error e;
    uint64_t start=monotonic();
    CHECK(bio_require_eof(p[0],after(30),bio_native_operations(),&r,&e)==-1);
    CHECK(e.reason==BIO_REASON_DEADLINE && r.bytes_moved==0 && tail_zero(&r));
    uint64_t elapsed=monotonic()-start;CHECK(elapsed>=30000000 && elapsed<BASE);
    CHECK(close(p[0])==0 && close(p[1])==0);return 0;
}
static int native_broken_peer(void) {
    /* Policy is installed only inside this private test process, never by bio. */
    struct sigaction old,ignore;memset(&ignore,0,sizeof(ignore));ignore.sa_handler=SIG_IGN;
    sigemptyset(&ignore.sa_mask);CHECK(sigaction(SIGPIPE,&ignore,&old)==0);
    int p[2];CHECK(native_pipe(p)==0);CHECK(close(p[0])==0);
    unsigned char data[64]={0};struct bio_result r;struct bio_error e;
    CHECK(bio_write_record(p[1],data,64,after(500),bio_native_operations(),&r,&e)==-1);
    CHECK((e.reason==BIO_REASON_POLL_ERROR) || (e.reason==BIO_REASON_SYSCALL && e.system_errno==EPIPE));
    CHECK(!r.bytes_moved && tail_zero(&r));struct sigaction observed;
    CHECK(sigaction(SIGPIPE,NULL,&observed)==0 && observed.sa_handler==SIG_IGN);
    CHECK(close(p[1])==0 && sigaction(SIGPIPE,&old,NULL)==0);return 0;
}
static int native_endpoint(void) {
    int p[2];CHECK(native_pipe(p)==0);struct bio_result r;struct bio_error e;unsigned char data[64]={0};
    CHECK(bio_write_record(p[0],data,64,after(500),bio_native_operations(),&r,&e)==-1 && e.reason==BIO_REASON_ACCESS);
    CHECK(bio_read_record(p[1],64,after(500),bio_native_operations(),&r,&e)==-1 && e.reason==BIO_REASON_ACCESS);
    int flags=fcntl(p[0],F_GETFL);CHECK(fcntl(p[0],F_SETFL,flags&~O_NONBLOCK)==0);
    CHECK(bio_read_record(p[0],64,after(500),bio_native_operations(),&r,&e)==-1 && e.reason==BIO_REASON_NONBLOCK);
    CHECK(fcntl(p[0],F_GETFL)==(flags&~O_NONBLOCK));
    int file=open("/dev/null",O_RDONLY|O_NONBLOCK);CHECK(file>=0);
    CHECK(bio_require_eof(file,after(500),bio_native_operations(),&r,&e)==-1 && e.reason==BIO_REASON_NOT_PIPE);
    CHECK(close(file)==0 && close(p[0])==0 && close(p[1])==0);return 0;
}
int main(int argc,char **argv) {
    if(argc!=2)return 2;
    struct { const char *name; int(*test)(void); } cases[]={
        {"arguments",arguments},{"endpoint",endpoint},{"time-bounds",time_bounds},
        {"time-progress",time_progress},{"partial",partial},{"poll-anomalies",poll_anomalies},
        {"storms",storms},{"io-anomalies",io_anomalies},{"eof",eof_fake},
        {"native-roundtrip",native_roundtrip},{"native-fragmented",native_fragmented},
        {"native-hup",native_hup},{"native-truncated",native_truncated},
        {"native-eof-extra",native_eof_extra},{"native-deadline",native_deadline},
        {"native-broken-peer",native_broken_peer},{"native-endpoint",native_endpoint}};
    for(size_t i=0;i<sizeof(cases)/sizeof(cases[0]);i++)if(!strcmp(argv[1],cases[i].name)) {
        int rc=cases[i].test();if(!rc)printf("PASS %s\n",argv[1]);return rc;
    }
    return 2;
}
