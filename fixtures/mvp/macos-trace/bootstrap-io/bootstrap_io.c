#define _POSIX_C_SOURCE 200809L
#define _DEFAULT_SOURCE 1
#include "bootstrap_io.h"
#include <errno.h>
#include <fcntl.h>
#include <poll.h>
#include <string.h>
#include <sys/stat.h>
#include <time.h>
#include <unistd.h>

#define NS_PER_SECOND UINT64_C(1000000000)
#define NS_PER_MS UINT64_C(1000000)
struct run {
    struct bio_operations ops;
    struct bio_observer observer;
    int observed;
    struct bio_result *result;
    struct bio_error *error;
    uint64_t deadline, last;
};
static int fail(struct run *r, enum bio_stage stage, enum bio_reason reason,
                int saved_errno) {
    r->error->stage = stage;
    r->error->reason = reason;
    r->error->system_errno = saved_errno;
    r->error->bytes_moved = r->result->bytes_moved;
    return -1;
}
static int flatten(struct bio_time t, uint64_t *n) {
    if (t.nanoseconds >= NS_PER_SECOND) return BIO_REASON_TIME_FORMAT;
    if (t.seconds > (UINT64_MAX - t.nanoseconds) / NS_PER_SECOND)
        return BIO_REASON_TIME_OVERFLOW;
    *n = t.seconds * NS_PER_SECOND + t.nanoseconds;
    return BIO_REASON_NONE;
}
static int get_time(struct run *r, uint64_t *now) {
    struct bio_time t = {0, 0};
    int e = 0, rc = r->ops.clock_fn(r->ops.context, &t, &e);
    if (rc == -1 && e > 0) return fail(r, BIO_STAGE_CLOCK, BIO_REASON_SYSCALL, e);
    if (rc != 0) return fail(r, BIO_STAGE_CLOCK, BIO_REASON_ADAPTER, 0);
    int reason = flatten(t, now);
    if (reason) return fail(r, BIO_STAGE_CLOCK, (enum bio_reason)reason, 0);
    return 0;
}
static int check_time(struct run *r, uint64_t *now) {
    if (get_time(r, now)) return -1;
    if (*now < r->last) return fail(r, BIO_STAGE_CLOCK, BIO_REASON_CLOCK_ROLLBACK, 0);
    r->last = *now;
    if (*now >= r->deadline) return fail(r, BIO_STAGE_CLOCK, BIO_REASON_DEADLINE, 0);
    return 0;
}
static int observe(struct run *r, uint64_t *now) {
    if (!r->observed) return 0;
    struct bio_time d = {r->deadline / NS_PER_SECOND, r->deadline % NS_PER_SECOND};
    int rc = r->observer.progress_fn(r->observer.context, d);
    if (rc != 0)
        return fail(r, BIO_STAGE_OBSERVER,
                    rc == -1 ? BIO_REASON_OBSERVER : BIO_REASON_ADAPTER, 0);
    return check_time(r, now);
}
static int transfer(int fd, const unsigned char *input, size_t length,
                    int writing, int eof, struct bio_time deadline,
                    const struct bio_operations *operations,
                    int observed, const struct bio_observer *observer,
                    struct bio_result *result, struct bio_error *error) {
    struct run r;
    memset(&r, 0, sizeof(r));
    r.result = result;
    r.error = error;
    if (result) memset(result, 0, sizeof(*result));
    if (error) memset(error, 0, sizeof(*error));
    if (!result || !error) return -1;
    if (fd < 0 || (writing && !input))
        return fail(&r, BIO_STAGE_ARGUMENT, BIO_REASON_ARGUMENT, 0);
    if (!eof && length != BIO_GO_RECORD_BYTES && length != BIO_STATUS_RECORD_BYTES)
        return fail(&r, BIO_STAGE_ARGUMENT, BIO_REASON_LENGTH, 0);
    if (!operations || !operations->clock_fn || !operations->stat_fn ||
        !operations->flags_fn || !operations->poll_fn || !operations->read_fn ||
        !operations->write_fn)
        return fail(&r, BIO_STAGE_OPERATIONS, BIO_REASON_ARGUMENT, 0);
    r.ops = *operations;
    if (observed && (!observer || !observer->progress_fn))
        return fail(&r, BIO_STAGE_OPERATIONS, BIO_REASON_ARGUMENT, 0);
    r.observed = observed;
    if (observed) r.observer = *observer;
    unsigned char source[BIO_MAX_RECORD_BYTES] = {0};
    if (writing) memcpy(source, input, length);
    int reason = flatten(deadline, &r.deadline);
    if (reason) return fail(&r, BIO_STAGE_CLOCK, (enum bio_reason)reason, 0);
    uint64_t now = 0;
    if (get_time(&r, &now)) return -1;
    r.last = now;
    if (r.deadline <= now) return fail(&r, BIO_STAGE_CLOCK, BIO_REASON_DEADLINE, 0);
    if (r.deadline - now > BIO_MAX_FUTURE_SECONDS * NS_PER_SECOND)
        return fail(&r, BIO_STAGE_CLOCK, BIO_REASON_MAX_FUTURE, 0);
    mode_t mode = 0;
    int e = 0, rc = r.ops.stat_fn(r.ops.context, fd, &mode, &e);
    if (rc == -1 && e > 0) return fail(&r, BIO_STAGE_ENDPOINT, BIO_REASON_SYSCALL, e);
    if (rc != 0) return fail(&r, BIO_STAGE_ENDPOINT, BIO_REASON_ADAPTER, 0);
    if (!S_ISFIFO(mode)) return fail(&r, BIO_STAGE_ENDPOINT, BIO_REASON_NOT_PIPE, 0);
    e = 0;
    int flags = r.ops.flags_fn(r.ops.context, fd, &e);
    if (flags == -1 && e > 0) return fail(&r, BIO_STAGE_ENDPOINT, BIO_REASON_SYSCALL, e);
    if (flags < 0) return fail(&r, BIO_STAGE_ENDPOINT, BIO_REASON_ADAPTER, 0);
    if ((flags & O_ACCMODE) != (writing ? O_WRONLY : O_RDONLY))
        return fail(&r, BIO_STAGE_ENDPOINT, BIO_REASON_ACCESS, 0);
    if (!(flags & O_NONBLOCK))
        return fail(&r, BIO_STAGE_ENDPOINT, BIO_REASON_NONBLOCK, 0);
    enum bio_stage io_stage = writing ? BIO_STAGE_WRITE : (eof ? BIO_STAGE_EOF : BIO_STAGE_READ);
    short wanted = writing ? POLLOUT : POLLIN;
    for (unsigned step = 0; step < BIO_MAX_STEPS; step++) {
        if (check_time(&r, &now)) return -1;
        if (observe(&r, &now)) return -1;
        uint64_t remaining = r.deadline - now;
        int timeout = (int)((remaining + NS_PER_MS - 1) / NS_PER_MS);
        if (r.observed && timeout > BIO_OBSERVER_POLL_MS) timeout = BIO_OBSERVER_POLL_MS;
        short events = 0;
        e = 0;
        rc = r.ops.poll_fn(r.ops.context, fd, wanted, timeout, &events, &e);
        /* Preserve a fatal/anomalous poll result before any later clock
         * observation can replace its stage or saved errno. Nonfatal returns
         * still recheck time before retrying or touching bytes. */
        if (rc == -1 && e > 0 && e != EINTR)
            return fail(&r, BIO_STAGE_POLL, BIO_REASON_SYSCALL, e);
        if (rc < 0 && !(rc == -1 && e == EINTR))
            return fail(&r, BIO_STAGE_POLL, BIO_REASON_ADAPTER, 0);
        if (rc > 1) return fail(&r, BIO_STAGE_POLL, BIO_REASON_ADAPTER, 0);
        if (rc == 0 && events)
            return fail(&r, BIO_STAGE_POLL, BIO_REASON_POLL_EVENT, 0);
        if (rc == 1) {
            unsigned allowed = (unsigned)(wanted | POLLERR | POLLHUP | POLLNVAL);
            if (!events || ((unsigned short)events & ~allowed))
                return fail(&r, BIO_STAGE_POLL, BIO_REASON_POLL_EVENT, 0);
            if (events & POLLNVAL) return fail(&r, BIO_STAGE_POLL, BIO_REASON_POLL_INVALID, 0);
            if ((events & POLLERR) || (writing && (events & POLLHUP)))
                return fail(&r, BIO_STAGE_POLL, BIO_REASON_POLL_ERROR, 0);
            if (!(events & wanted) && !(events & POLLHUP))
                return fail(&r, BIO_STAGE_POLL, BIO_REASON_POLL_EVENT, 0);
        }
        if (check_time(&r, &now)) return -1;
        if (observe(&r, &now)) return -1;
        if (rc != 1) continue;
        unsigned char chunk[BIO_MAX_RECORD_BYTES] = {0};
        size_t moved = result->bytes_moved;
        size_t want = eof ? 1 : length - moved;
        e = 0;
        ssize_t amount = writing ?
            r.ops.write_fn(r.ops.context, fd, source + moved, want, &e) :
            r.ops.read_fn(r.ops.context, fd, chunk, want, &e);
        if (amount == -1 && e > 0) {
            if (e == EINTR || e == EAGAIN || e == EWOULDBLOCK) continue;
            return fail(&r, io_stage, BIO_REASON_SYSCALL, e);
        }
        if (amount < 0 || (size_t)amount > want)
            return fail(&r, io_stage, BIO_REASON_ADAPTER, 0);
        if (amount == 0) {
            if (writing) return fail(&r, io_stage, BIO_REASON_ZERO_PROGRESS, 0);
            if (!eof) return fail(&r, io_stage, BIO_REASON_TRUNCATED, 0);
            if (check_time(&r, &now)) return -1;
            return observe(&r, &now);
        }
        memcpy(result->prefix + moved, writing ? source + moved : chunk, (size_t)amount);
        result->bytes_moved += (size_t)amount;
        if (check_time(&r, &now)) return -1;
        if (eof) return fail(&r, BIO_STAGE_EOF, BIO_REASON_TRAILING, 0);
        if (observe(&r, &now)) return -1;
        if (result->bytes_moved == length) return 0;
    }
    return fail(&r, BIO_STAGE_POLL, BIO_REASON_RETRY_LIMIT, 0);
}
int bio_read_record(int fd, size_t n, struct bio_time d, const struct bio_operations *o,
                    struct bio_result *r, struct bio_error *e) {
    return transfer(fd, NULL, n, 0, 0, d, o, 0, NULL, r, e);
}
int bio_write_record(int fd, const unsigned char *p, size_t n, struct bio_time d,
                     const struct bio_operations *o, struct bio_result *r, struct bio_error *e) {
    return transfer(fd, p, n, 1, 0, d, o, 0, NULL, r, e);
}
int bio_require_eof(int fd, struct bio_time d, const struct bio_operations *o,
                    struct bio_result *r, struct bio_error *e) {
    return transfer(fd, NULL, 0, 0, 1, d, o, 0, NULL, r, e);
}
int bio_read_record_observed(int fd, size_t n, struct bio_time d, const struct bio_operations *o,
                             const struct bio_observer *v, struct bio_result *r, struct bio_error *e) {
    return transfer(fd, NULL, n, 0, 0, d, o, 1, v, r, e);
}
int bio_write_record_observed(int fd, const unsigned char *p, size_t n, struct bio_time d,
                              const struct bio_operations *o, const struct bio_observer *v,
                              struct bio_result *r, struct bio_error *e) {
    return transfer(fd, p, n, 1, 0, d, o, 1, v, r, e);
}
int bio_require_eof_observed(int fd, struct bio_time d, const struct bio_operations *o,
                             const struct bio_observer *v, struct bio_result *r, struct bio_error *e) {
    return transfer(fd, NULL, 0, 0, 1, d, o, 1, v, r, e);
}
static int native_clock(void *c, struct bio_time *t, int *e) {
    (void)c;
    struct timespec ts;
    int rc = clock_gettime(CLOCK_MONOTONIC, &ts);
    if (rc == -1) *e = errno;
    else { t->seconds = (uint64_t)ts.tv_sec; t->nanoseconds = (uint64_t)ts.tv_nsec; }
    return rc;
}
static int native_stat(void *c, int fd, mode_t *m, int *e) {
    (void)c;
    struct stat st;
    int rc = fstat(fd, &st);
    if (rc == -1) *e = errno;
    else *m = st.st_mode;
    return rc;
}
static int native_flags(void *c, int fd, int *e) {
    (void)c;
    int rc = fcntl(fd, F_GETFL);
    if (rc == -1) *e = errno;
    return rc;
}
static int native_poll(void *c, int fd, short events, int timeout, short *out, int *e) {
    (void)c;
    struct pollfd p = {fd, events, 0};
    int rc = poll(&p, 1, timeout);
    if (rc == -1) *e = errno;
    *out = p.revents;
    return rc;
}
static ssize_t native_read(void *c, int fd, void *p, size_t n, int *e) {
    (void)c;
    ssize_t rc = read(fd, p, n);
    if (rc == -1) *e = errno;
    return rc;
}
static ssize_t native_write(void *c, int fd, const void *p, size_t n, int *e) {
    (void)c;
    ssize_t rc = write(fd, p, n);
    if (rc == -1) *e = errno;
    return rc;
}
const struct bio_operations *bio_native_operations(void) {
    static const struct bio_operations o = {
        NULL, native_clock, native_stat, native_flags, native_poll, native_read, native_write
    };
    return &o;
}
const char *bio_stage_name(enum bio_stage s) {
    static const char *const names[] = {"none", "argument", "operations", "endpoint", "clock",
                                      "poll", "read", "write", "eof", "observer"};
    return (unsigned)s < sizeof(names) / sizeof(names[0]) ? names[s] : "unknown";
}
const char *bio_reason_name(enum bio_reason s) {
    static const char *const names[] = {"none", "argument", "length", "not-pipe", "access",
        "nonblock", "time-format", "time-overflow", "max-future", "clock-rollback", "deadline",
        "syscall", "adapter", "poll-invalid", "poll-event", "poll-error", "truncated",
        "zero-progress", "trailing", "retry-limit", "observer"};
    return (unsigned)s < sizeof(names) / sizeof(names[0]) ? names[s] : "unknown";
}
