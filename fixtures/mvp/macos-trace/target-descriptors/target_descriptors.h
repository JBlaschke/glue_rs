#ifndef GLUE_TARGET_DESCRIPTORS_H
#define GLUE_TARGET_DESCRIPTORS_H

#include <stddef.h>
#include <stdint.h>
#include <sys/types.h>

#define TD_KEEP_COUNT 5
#define TD_MAX_LIVE_FDS 4096
#define TD_MAX_CAPACITY (TD_MAX_LIVE_FDS + 1)

/* The type is opaque metadata; it never authorizes a kept endpoint object. */
struct td_record { int32_t fd; uint32_t type; };
struct td_plan {
    int keep[TD_KEEP_COUNT]; /* Exactly [0,1,2,gate_reader,status_writer]. */
    struct td_record *scratch;
    size_t capacity; /* 6..4097 records: one spare, not a numeric FD bound. */
};
enum td_stage {
    TD_STAGE_NONE, TD_STAGE_PLAN, TD_STAGE_OPERATIONS, TD_STAGE_CHILD,
    TD_STAGE_SIGNALS, TD_STAGE_INVENTORY, TD_STAGE_CLOSE, TD_STAGE_RESCAN
};
enum td_reason {
    TD_REASON_NONE, TD_REASON_ARGUMENT, TD_REASON_RANGE, TD_REASON_ALIGNMENT,
    TD_REASON_UNSUPPORTED, TD_REASON_NOT_OWNED_CHILD, TD_REASON_SIGNALS_UNBLOCKED,
    TD_REASON_SYSCALL, TD_REASON_ADAPTER, TD_REASON_EMPTY, TD_REASON_CAPACITY,
    TD_REASON_DUPLICATE, TD_REASON_MISSING_KEEP, TD_REASON_EXTRA_FD
};
struct td_error {
    enum td_stage stage;
    enum td_reason reason;
    int system_errno; /* Saved syscall errno, or ENOTSUP for unsupported native. */
    int fd; /* -1 unless a failed/invalid/missing descriptor is identified. */
    int closure_attempted;
};
struct td_operations {
    int supported; /* Exactly 0 or 1; native Linux is explicitly unsupported. */
    void *context;
    pid_t (*getpid_fn)(void *);
    pid_t (*getppid_fn)(void *);
    /* 1=all blockable signals masked, 0=not masked, -1=saved errno failure. */
    int (*signals_blocked_fn)(void *, int *);
    /* Return BYTES, not records. A syscall error may be 0 (Darwin libproc) or
     * -1, with saved positive errno. Must never write beyond supplied bytes. */
    int (*inventory_fn)(void *, pid_t, struct td_record *, size_t, int *);
    int (*close_fn)(void *, int, int *);
};

/* All objects/spans must be valid, nonoverlapping and stable for this call.
 * Allocate scratch before fork. Call ONLY in a single-threaded owned child,
 * with signals already blocked before earlier child setup and no concurrent
 * FD mutation. Reviewed callbacks/handlers must not close/rebind kept endpoints.
 * owner_pid is the original controller PID captured BEFORE fork; never infer it
 * from getppid at this call site. This guard cannot prove hostile ownership.
 * If a failure follows closure_attempted, exit the child without retry/rollback
 * or target exec. Even other failures do not authorize launch. Caller must own
 * a bounded whole-child deadline and reap that actual child on failure.
 * Success proves only a numeric keep set at return, not endpoint objects,
 * closure of cwd/Mach/fileport capabilities, a gate or trace acceptance. */
int td_close_in_owned_child(const struct td_plan *, uint64_t owner_pid,
                            const struct td_operations *, struct td_error *);
const struct td_operations *td_native_operations(void);
const char *td_stage_name(enum td_stage);
const char *td_reason_name(enum td_reason);

#endif
