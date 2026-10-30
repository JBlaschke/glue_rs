#ifndef GLUE_TARGET_CWD_H
#define GLUE_TARGET_CWD_H
#include <stdint.h>
#include <sys/types.h>

#define TCWD_MUTATION_DETAIL 256
struct tcwd_backing { uint64_t device, inode, links; uint32_t mode, uid, gid; };
struct tcwd_entry { int fd, descriptor_flags, status_flags; struct tcwd_backing backing; };
struct tcwd_request { int directory_fd; uint64_t device, inode; };
struct tcwd_result {
    int ready;
    uint64_t controller_pid, child_pid;
    struct tcwd_entry before, after;
    struct tcwd_backing cwd;
};
enum tcwd_stage {
    TCWD_STAGE_NONE, TCWD_STAGE_REQUEST, TCWD_STAGE_OPERATIONS, TCWD_STAGE_CHILD,
    TCWD_STAGE_SIGNALS, TCWD_STAGE_FIRST, TCWD_STAGE_SECOND, TCWD_STAGE_BEFORE_CHANGE,
    TCWD_STAGE_CHANGE, TCWD_STAGE_AFTER_CHANGE, TCWD_STAGE_POST, TCWD_STAGE_READBACK,
    TCWD_STAGE_FINAL
};
enum tcwd_reason {
    TCWD_REASON_NONE, TCWD_REASON_ARGUMENT, TCWD_REASON_RANGE, TCWD_REASON_UNSUPPORTED,
    TCWD_REASON_NOT_OWNED_CHILD, TCWD_REASON_SIGNALS_UNBLOCKED, TCWD_REASON_SYSCALL,
    TCWD_REASON_ADAPTER, TCWD_REASON_NOT_DIRECTORY, TCWD_REASON_FLAGS,
    TCWD_REASON_MISMATCH, TCWD_REASON_CHANGED, TCWD_REASON_DEADLINE
};
struct tcwd_error {
    enum tcwd_stage stage;
    enum tcwd_reason reason;
    int system_errno, mutation_attempted;
};
struct tcwd_operations {
    int supported; /* Exactly 0 or 1. */
    void *context;
    pid_t (*getpid_fn)(void *);
    pid_t (*getppid_fn)(void *);
    int (*signals_blocked_fn)(void *, int *); /* 1/0/-1. */
    int (*stat_fn)(void *, int, struct tcwd_backing *, int *); /* 0/-1. */
    int (*getfd_fn)(void *, int, int *); /* Nonnegative flags or -1. */
    int (*getfl_fn)(void *, int, int *);
    int (*change_fn)(void *, int, int *); /* Exactly one fchdir, 0/-1. */
    int (*cwd_fn)(void *, struct tcwd_backing *, int *); /* stat("."), 0/-1. */
};
struct tcwd_guard {
    void *context;
    /* Cooperative ORIGINAL absolute deadline; never reset or extend it.
     * 0: before deadline. -1/errno>0: syscall failure. -1/errno==0: late.
     * Other returns or negative errno are adapter failures. No hard preemption. */
    int (*before_fn)(void *, int *);
};
/* Stable trusted nonoverlapping spans/tables are required. Only in a quiescent
 * single-threaded owned child after credentials and before descriptor closure,
 * with original owner captured before fork and all blockable signals blocked.
 * No child thread-CWD override, concurrent namespace/mount/FD/status mutation or
 * callbacks that change API storage. Guards/samples do not prove that history.
 * Borrowed FD >=3 stays open with unchanged flags; no dup/remap/open/close occurs.
 * Native Darwin device uses the same uint32 bit-pattern widening as BA/BR;
 * Linux diagnostics retain native dev_t width. Expected identity is same-host.
 * On failure out.ready=0. mutation_attempted is set before the single change
 * callback, even if that callback fails; later failure may follow actual CWD
 * mutation. Exit/reap child; never retry, roll back, READY, GO or exec on failure.
 * Complete sampled metadata/readback does not prove atomicity, OFD/generation,
 * exact vnode/mount/namespace lineage, no thread override or future-call state. */
int tcwd_select_in_owned_child(const struct tcwd_request *, uint64_t owner_pid,
    const struct tcwd_operations *, const struct tcwd_guard *,
    struct tcwd_result *, struct tcwd_error *);
const struct tcwd_operations *tcwd_native_operations(void);
int tcwd_error_detail(const struct tcwd_error *);
const char *tcwd_stage_name(enum tcwd_stage);
const char *tcwd_reason_name(enum tcwd_reason);
#endif
