#ifndef GLUE_BOOTSTRAP_IO_H
#define GLUE_BOOTSTRAP_IO_H

#include <stddef.h>
#include <stdint.h>
#include <sys/types.h>

#define BIO_GO_RECORD_BYTES 64u
#define BIO_STATUS_RECORD_BYTES 256u
#define BIO_MAX_RECORD_BYTES 256u
#define BIO_OBJECT_STATUS_RECORD_BYTES 512u
#define BIO_MAX_STEPS 4096u
#define BIO_MAX_FUTURE_SECONDS 30u
#define BIO_OBSERVER_POLL_MS 20

struct bio_time { uint64_t seconds; uint64_t nanoseconds; };
struct bio_result {
    size_t bytes_moved;
    unsigned char prefix[BIO_MAX_RECORD_BYTES];
};
/* Additive object-profile storage; legacy result layout and accepted sizes stay fixed. */
struct bio_object_result {
    size_t bytes_moved;
    unsigned char prefix[BIO_OBJECT_STATUS_RECORD_BYTES];
};
enum bio_stage {
    BIO_STAGE_NONE, BIO_STAGE_ARGUMENT, BIO_STAGE_OPERATIONS,
    BIO_STAGE_ENDPOINT, BIO_STAGE_CLOCK, BIO_STAGE_POLL,
    BIO_STAGE_READ, BIO_STAGE_WRITE, BIO_STAGE_EOF, BIO_STAGE_OBSERVER
};
enum bio_reason {
    BIO_REASON_NONE, BIO_REASON_ARGUMENT, BIO_REASON_LENGTH,
    BIO_REASON_NOT_PIPE, BIO_REASON_ACCESS, BIO_REASON_NONBLOCK,
    BIO_REASON_TIME_FORMAT, BIO_REASON_TIME_OVERFLOW, BIO_REASON_MAX_FUTURE,
    BIO_REASON_CLOCK_ROLLBACK, BIO_REASON_DEADLINE, BIO_REASON_SYSCALL,
    BIO_REASON_ADAPTER, BIO_REASON_POLL_INVALID, BIO_REASON_POLL_EVENT,
    BIO_REASON_POLL_ERROR, BIO_REASON_TRUNCATED, BIO_REASON_ZERO_PROGRESS,
    BIO_REASON_TRAILING, BIO_REASON_RETRY_LIMIT, BIO_REASON_OBSERVER
};
struct bio_error {
    enum bio_stage stage;
    enum bio_reason reason;
    int system_errno;
    size_t bytes_moved;
};

/* Trusted, libc-conforming callbacks; only -1 is failure and it must save a
 * positive errno. poll operates on exactly one FD, returning 0 or 1. */
struct bio_operations {
    void *context;
    int (*clock_fn)(void *, struct bio_time *, int *);
    int (*stat_fn)(void *, int, mode_t *, int *);
    int (*flags_fn)(void *, int, int *);
    int (*poll_fn)(void *, int, short, int, short *, int *);
    ssize_t (*read_fn)(void *, int, void *, size_t, int *);
    ssize_t (*write_fn)(void *, int, const void *, size_t, int *);
};

/* Separate trusted internal progress observer, copied once. Return0 on success,
 * -1 on explicit failure (including semantic failure with no errno). Any other
 * return is an adapter fault. Do not mutate API storage, pipe identities/flags,
 * aliases or signal policy, perform I/O on the supplied pipe, or reenter BIO.
 * Honor the supplied ORIGINAL absolute deadline; callbacks are cooperative. */
struct bio_observer {
    void *context;
    int (*progress_fn)(void *, struct bio_time);
};

/* All objects/spans must be valid, mutually nonoverlapping and stable. The caller
 * owns sole-writer provenance, fixed FD mapping/status flags (including shared
 * aliases) and SIGPIPE policy. No callback
 * may mutate these objects. Both outputs are mandatory; no endpoint is closed.
 * A failed write may already have delivered its entire record: NEVER replay it.
 * Returned bytes are confirmed prefixes only; failed records must not be decoded. */
int bio_read_record(int, size_t, struct bio_time, const struct bio_operations *,
                    struct bio_result *, struct bio_error *);
int bio_write_record(int, const unsigned char *, size_t, struct bio_time,
                     const struct bio_operations *, struct bio_result *,
                     struct bio_error *);
int bio_require_eof(int, struct bio_time, const struct bio_operations *,
                    struct bio_result *, struct bio_error *);
/* Observed variants require a nonnull observer/callback. Poll waits are capped
 * at20ms; all deadline/confirmed-prefix/no-replay rules still apply. An observer
 * failure after full delivery is failure, with the full confirmed prefix kept.
 * These functions neither validate trace events nor authorize finalization. */
int bio_read_record_observed(int, size_t, struct bio_time, const struct bio_operations *,
                             const struct bio_observer *, struct bio_result *, struct bio_error *);
int bio_write_record_observed(int, const unsigned char *, size_t, struct bio_time,
                              const struct bio_operations *, const struct bio_observer *,
                              struct bio_result *, struct bio_error *);
int bio_require_eof_observed(int, struct bio_time, const struct bio_operations *,
                             const struct bio_observer *, struct bio_result *, struct bio_error *);
/* Fixed 512-byte object-profile status only. Same deadline, confirmed-prefix,
 * no-replay, endpoint, callback and signal-policy requirements as above.
 * Legacy record APIs continue to refuse 512-byte requests. No framing or
 * atomic-delivery claim is supplied by these byte-transfer operations. */
int bio_read_object_status(int, struct bio_time, const struct bio_operations *,
                           struct bio_object_result *, struct bio_error *);
int bio_write_object_status(int, const unsigned char[BIO_OBJECT_STATUS_RECORD_BYTES],
                            struct bio_time, const struct bio_operations *,
                            struct bio_object_result *, struct bio_error *);
int bio_read_object_status_observed(int, struct bio_time, const struct bio_operations *,
                                    const struct bio_observer *, struct bio_object_result *, struct bio_error *);
int bio_write_object_status_observed(int, const unsigned char[BIO_OBJECT_STATUS_RECORD_BYTES],
                                     struct bio_time, const struct bio_operations *,
                                     const struct bio_observer *, struct bio_object_result *, struct bio_error *);
const struct bio_operations *bio_native_operations(void);
const char *bio_stage_name(enum bio_stage);
const char *bio_reason_name(enum bio_reason);
#endif
