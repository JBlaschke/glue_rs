#ifndef GLUE_TARGET_FD_OBJECTS_H
#define GLUE_TARGET_FD_OBJECTS_H
#include <stdint.h>
#include <sys/types.h>

#define TFO_KEEP_COUNT 5
#define TFO_OUTPUT_COUNT 2
struct tfo_plan { int keep[TFO_KEEP_COUNT]; }; /* [0,1,2,gate_reader,status_writer] */
/* Same-host uint64 conversions of native stat fields, not paths/OFD IDs. */
struct tfo_backing { uint64_t device, inode, links; uint32_t mode; };
struct tfo_entry { int fd, descriptor_flags, status_flags; struct tfo_backing backing; };
struct tfo_snapshot {
    int ready;
    uint64_t controller_pid, child_pid;
    struct tfo_entry entries[TFO_KEEP_COUNT];
};
struct tfo_output_match {
    int child_fd, controller_fd, child_descriptor_flags, controller_descriptor_flags;
    int status_flags;
    struct tfo_backing backing;
};
struct tfo_matches { int ready; struct tfo_output_match outputs[TFO_OUTPUT_COUNT]; };
/* Completed reference reads only: first stdout/stderr, then second stdout/stderr.
 * Unused rows stay entirely zero; completed_samples distinguishes an unread fd0
 * sentinel from a completed value. Samples are observations, never matches. */
struct tfo_reference_observation {
    unsigned completed_samples;
    struct tfo_entry samples[4];
};
enum tfo_stage {
    TFO_STAGE_NONE, TFO_STAGE_PLAN, TFO_STAGE_OPERATIONS, TFO_STAGE_CHILD,
    TFO_STAGE_SIGNALS, TFO_STAGE_FIRST, TFO_STAGE_SECOND, TFO_STAGE_STABILITY,
    TFO_STAGE_SNAPSHOT, TFO_STAGE_CONTROLLER, TFO_STAGE_REFERENCE_FIRST,
    TFO_STAGE_REFERENCE_SECOND, TFO_STAGE_MATCH
};
enum tfo_reason {
    TFO_REASON_NONE, TFO_REASON_ARGUMENT, TFO_REASON_RANGE, TFO_REASON_UNSUPPORTED,
    TFO_REASON_NOT_OWNED_CHILD, TFO_REASON_SIGNALS_UNBLOCKED, TFO_REASON_SYSCALL,
    TFO_REASON_ADAPTER, TFO_REASON_STAT_SHAPE, TFO_REASON_CHANGED,
    TFO_REASON_NOT_READY, TFO_REASON_NOT_CONTROLLER, TFO_REASON_NOT_REGULAR,
    TFO_REASON_LINKS, TFO_REASON_ACCESS, TFO_REASON_CLOEXEC,
    TFO_REASON_ALIASED_SINKS, TFO_REASON_MISMATCH
};
struct tfo_error { enum tfo_stage stage; enum tfo_reason reason; int system_errno, role, fd; };
struct tfo_operations {
    int supported; /* Exactly 0 or 1. */
    void *context;
    pid_t (*getpid_fn)(void *);
    pid_t (*getppid_fn)(void *);
    int (*signals_blocked_fn)(void *, int *); /* 1/0/-1; saved errno only on failure. */
    int (*stat_fn)(void *, int, struct tfo_backing *, int *); /* 0/-1 */
    int (*getfd_fn)(void *, int, int *); /* nonnegative flags or -1 */
    int (*getfl_fn)(void *, int, int *);
};
/* Valid, stable, nonoverlapping input/output/error/callback spans are required.
 * ONLY in a quiescent, single-threaded owned child after numeric closure and
 * before GO. owner_pid was captured BEFORE fork. Signals were already blocked
 * before setup; no callback/handler/thread or shared-status alias mutates FDs.
 * PID/mask guards and equal samples cannot establish that history/atomicity.
 * Two full samples publish one complete observation; failure leaves ready=0.
 * No opens/closes/remaps/flag updates, retries, rollback, GO or launch occur.
 * Caller must impose a whole-child deadline and reap its actual owned child;
 * helper cannot interrupt a blocked syscall. Failure forbids target launch. */
int tfo_snapshot_in_owned_child(const struct tfo_plan *, uint64_t owner_pid,
    const struct tfo_operations *, struct tfo_snapshot *, struct tfo_error *);
/* Controller keeps actual child gated/unreaped and source refs held throughout.
 * Reads the two refs twice and conditionally matches distinct single-link regular
 * write-only backing observations to child slots1/2. Child CLOEXEC must be clear;
 * parent/child F_GETFD need not match. All status flags must match.
 * This is a trusted-memory integration boundary, not capture authentication.
 * Device/inode equality does NOT prove OFD/generation/path/lineage/current state.
 * Independent opens can match. Output is no launch or trace authorization.
 * No input descriptor is closed, and no partial match is published. */
int tfo_match_regular_outputs(const struct tfo_snapshot *, const int held[2],
    const struct tfo_operations *, struct tfo_matches *, struct tfo_error *);
/* Same preconditions and matching policy as the original API. observation is
 * required, valid, stable and nonoverlapping with every other span. It clears
 * on entry, then retains only fully completed read_entry originals, even on
 * failure. A changed second sample is retained before comparison/refusal.
 * No unread/partial row is invented; matches still publish all-or-none. */
int tfo_match_regular_outputs_observed(const struct tfo_snapshot *, const int held[2],
    const struct tfo_operations *, struct tfo_matches *,
    struct tfo_reference_observation *, struct tfo_error *);
const struct tfo_operations *tfo_native_operations(void);
const char *tfo_stage_name(enum tfo_stage);
const char *tfo_reason_name(enum tfo_reason);
#endif
