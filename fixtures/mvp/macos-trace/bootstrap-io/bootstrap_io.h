#ifndef GLUE_BOOTSTRAP_IO_H
#define GLUE_BOOTSTRAP_IO_H

#include <stddef.h>
#include <stdint.h>
#include <sys/types.h>

#define BIO_GO_RECORD_BYTES 64u
#define BIO_STATUS_RECORD_BYTES 256u
#define BIO_MAX_RECORD_BYTES 256u
#define BIO_MAX_STEPS 4096u
#define BIO_MAX_FUTURE_SECONDS 30u

struct bio_time { uint64_t seconds; uint64_t nanoseconds; };
struct bio_result {
    size_t bytes_moved;
    unsigned char prefix[BIO_MAX_RECORD_BYTES];
};
enum bio_stage {
    BIO_STAGE_NONE, BIO_STAGE_ARGUMENT, BIO_STAGE_OPERATIONS,
    BIO_STAGE_ENDPOINT, BIO_STAGE_CLOCK, BIO_STAGE_POLL,
    BIO_STAGE_READ, BIO_STAGE_WRITE, BIO_STAGE_EOF
};
enum bio_reason {
    BIO_REASON_NONE, BIO_REASON_ARGUMENT, BIO_REASON_LENGTH,
    BIO_REASON_NOT_PIPE, BIO_REASON_ACCESS, BIO_REASON_NONBLOCK,
    BIO_REASON_TIME_FORMAT, BIO_REASON_TIME_OVERFLOW, BIO_REASON_MAX_FUTURE,
    BIO_REASON_CLOCK_ROLLBACK, BIO_REASON_DEADLINE, BIO_REASON_SYSCALL,
    BIO_REASON_ADAPTER, BIO_REASON_POLL_INVALID, BIO_REASON_POLL_EVENT,
    BIO_REASON_POLL_ERROR, BIO_REASON_TRUNCATED, BIO_REASON_ZERO_PROGRESS,
    BIO_REASON_TRAILING, BIO_REASON_RETRY_LIMIT
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
const struct bio_operations *bio_native_operations(void);
const char *bio_stage_name(enum bio_stage);
const char *bio_reason_name(enum bio_reason);
#endif
