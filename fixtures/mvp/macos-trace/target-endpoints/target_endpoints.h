#ifndef GLUE_TARGET_ENDPOINTS_H
#define GLUE_TARGET_ENDPOINTS_H

#include <stddef.h>
#include <stdint.h>
#include <sys/types.h>

#define TE_ROLE_COUNT 5
enum te_role { TE_STDIN, TE_STDOUT, TE_STDERR, TE_GATE_READER, TE_STATUS_WRITER, TE_NO_ROLE };
enum te_kind { TE_REGULAR, TE_FIFO, TE_CHARACTER, TE_OTHER };
struct te_request { int source[TE_ROLE_COUNT]; };
struct te_prepared {
    int copies[TE_ROLE_COUNT]; /* Exact newly owned prefix; unused entries are -1. */
    size_t owned_count;
    int ready; /* Exactly 1 only after complete successful preparation. */
};
enum te_stage {
    TE_STAGE_NONE, TE_STAGE_REQUEST, TE_STAGE_OPERATIONS, TE_STAGE_SOURCE,
    TE_STAGE_DUPLICATE, TE_STAGE_COPY, TE_STAGE_CHILD, TE_STAGE_SIGNALS,
    TE_STAGE_MAP, TE_STAGE_STDIO_FLAGS, TE_STAGE_CONTROL_FLAGS, TE_STAGE_VERIFY
};
enum te_reason {
    TE_REASON_NONE, TE_REASON_ARGUMENT, TE_REASON_DUPLICATE, TE_REASON_DIRECTION,
    TE_REASON_SHAPE, TE_REASON_POLICY, TE_REASON_SYSCALL, TE_REASON_ADAPTER,
    TE_REASON_FLAGS, TE_REASON_PARTIAL_PLAN, TE_REASON_NOT_OWNED_CHILD,
    TE_REASON_SIGNALS_UNBLOCKED, TE_REASON_OWNERSHIP
};
struct te_error {
    enum te_stage stage;
    enum te_reason reason;
    int system_errno;
    enum te_role role;
    int fd;
    int mutation_attempted;
    int ownership_uncertain; /* Controller must exit; do not close a guessed FD. */
};
struct te_operations {
    void *context;
    pid_t (*getpid_fn)(void *);
    pid_t (*getppid_fn)(void *);
    int (*signals_blocked_fn)(void *, int *); /* 1,0,-1; save errno on -1. */
    int (*getfl_fn)(void *, int, int *);
    int (*getfd_fn)(void *, int, int *);
    int (*setfd_fn)(void *, int, int, int *);
    int (*kind_fn)(void *, int, enum te_kind *, int *); /* fstat shape only. */
    int (*duplicate_fn)(void *, int, int, int *); /* F_DUPFD_CLOEXEC, min FD. */
    int (*dup2_fn)(void *, int, int, int *);
};

/* All objects are valid, stable and nonoverlapping; no concurrent descriptor or
 * shared-status mutation/rebind. Output must not already own copies. Validate
 * caller object provenance: FIFO/regular stdio, or deliberately opened read-only
 * /dev/null for character stdin; FIFO controls. Stdio must be blocking, controls
 * nonblocking. Caller prepares all four private control ends before fork.
 * Different numbers do not prove
 * different objects. No close, F_SETFL, source F_SETFD or stdio remap occurs.
 * On failure ready=0: close the exact owned prefix once or exit; never map it.
 * If ownership_uncertain, exit controller instead of closing any guessed FD. */
int te_prepare_owned_sources(const struct te_request *, const struct te_operations *,
                              struct te_prepared *, struct te_error *);

/* Only in owned single-threaded child with setup signals already blocked and
 * no prior inherited callback/handler endpoint rebind. owner_pid comes from the
 * original controller BEFORE fork. No handler reset/credential/cwd/gate IO/exec.
 * Any mapping-attempt failure requires child exit after fixed error reporting;
 * never roll back or launch. Other failures also cannot authorize a target.
 * Leaves originals/spare copies open for a later numeric closure helper. */
int te_map_in_owned_child(const struct te_prepared *, uint64_t owner_pid,
                          const struct te_operations *, struct te_error *);
const struct te_operations *te_native_operations(void);
const char *te_stage_name(enum te_stage);
const char *te_reason_name(enum te_reason);

#endif
