#ifndef GLUE_TARGET_CREDENTIALS_H
#define GLUE_TARGET_CREDENTIALS_H

#include <stddef.h>
#include <stdint.h>
#include <sys/types.h>

#define TC_MAX_GROUPS 16
#define TC_ID_MAX UINT64_C(2147483647)
#define TC_NO_GROUP_INDEX SIZE_MAX

struct tc_request {
    uint64_t uid;
    uint64_t gid;
    size_t group_count;
    uint64_t groups[TC_MAX_GROUPS];
};

/* Tokens are readable byte spans, not NUL-terminated strings or JSON values. */
struct tc_decimal { const char *bytes; size_t length; };

enum tc_stage {
    TC_STAGE_NONE, TC_STAGE_REQUEST, TC_STAGE_OPERATIONS, TC_STAGE_CHILD,
    TC_STAGE_SETGROUPS, TC_STAGE_SETGID, TC_STAGE_SETUID,
    TC_STAGE_REAL_UID, TC_STAGE_EFFECTIVE_UID, TC_STAGE_REAL_GID,
    TC_STAGE_EFFECTIVE_GID, TC_STAGE_GROUPS
};
enum tc_reason {
    TC_REASON_NONE, TC_REASON_ARGUMENT, TC_REASON_SYNTAX, TC_REASON_RANGE,
    TC_REASON_DUPLICATE, TC_REASON_PRIMARY_GROUP, TC_REASON_NOT_OWNED_CHILD,
    TC_REASON_SYSCALL, TC_REASON_ADAPTER, TC_REASON_MISMATCH
};
struct tc_error {
    enum tc_stage stage;
    enum tc_reason reason;
    int system_errno; /* Preserved syscall errno; zero for non-syscall failures. */
    size_t group_index; /* TC_NO_GROUP_INDEX except a group validation/mismatch. */
    int mutation_attempted; /* Failure after this becomes true requires child exit. */
};

/* Injected operations must obey libc return conventions and save errno on -1.
 * All callbacks are required. They must not mutate request/table storage.
 * The real adapter is tc_native_operations(). No callback allocates for it. */
struct tc_operations {
    void *context;
    pid_t (*getpid_fn)(void *);
    pid_t (*getppid_fn)(void *);
    int (*setgroups_fn)(void *, size_t, const gid_t *, int *);
    int (*setgid_fn)(void *, gid_t, int *);
    int (*setuid_fn)(void *, uid_t, int *);
    uid_t (*getuid_fn)(void *);
    uid_t (*geteuid_fn)(void *);
    gid_t (*getgid_fn)(void *);
    gid_t (*getegid_fn)(void *);
    int (*getgroups_fn)(void *, int, gid_t *, int *);
};

int tc_parse_request(struct tc_decimal uid, struct tc_decimal gid,
                     const struct tc_decimal *groups, size_t group_count,
                     struct tc_request *output, struct tc_error *error);
int tc_validate_request(const struct tc_request *, struct tc_error *);

/* Only in a single-threaded owned child, with no assumed thread credentials.
 * owner_pid is the original controller PID selected BEFORE fork, never inferred
 * by this child. On ANY failure after mutation_attempted, exit the child; do not
 * retry, roll back or launch a target. Never call this from the controller.
 * error is mandatory. Success verifies real/effective IDs and exact group order,
 * not saved IDs, login/Mach/audit context, FD policy or tracing acceptance. */
int tc_drop_in_owned_child(const struct tc_request *, uint64_t owner_pid,
                           const struct tc_operations *, struct tc_error *);
const struct tc_operations *tc_native_operations(void);

const char *tc_stage_name(enum tc_stage);
const char *tc_reason_name(enum tc_reason);

#endif
