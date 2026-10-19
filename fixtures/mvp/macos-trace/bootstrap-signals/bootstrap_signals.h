#ifndef GLUE_BOOTSTRAP_SIGNALS_H
#define GLUE_BOOTSTRAP_SIGNALS_H
#include <signal.h>
#include <stddef.h>
#include <stdint.h>
#include <sys/types.h>
#define BS_SIGNAL_LIMIT 128
#define BS_POLICY_CAPACITY (20u + 4u * BS_SIGNAL_LIMIT)
enum bs_stage { BS_NONE, BS_ARGUMENT, BS_OPERATIONS, BS_OWNER, BS_ACTIONS,
 BS_BLOCK, BS_PENDING, BS_PIPE, BS_ALTSTACK, BS_CHILD_RESET, BS_CHILD_VERIFY,
 BS_RELEASE, BS_RESTORE_PIPE, BS_RESTORE_MASK, BS_POLICY };
enum bs_reason { BS_OK, BS_INVALID, BS_UNSUPPORTED, BS_SYSCALL, BS_ADAPTER,
 BS_CUSTOM_HANDLER, BS_CHILD_POLICY, BS_NOT_OWNED, BS_MISMATCH, BS_PENDING_SIGNAL,
 BS_BAD_STATE };
struct bs_error { enum bs_stage stage; enum bs_reason reason; int system_errno; int signal_number; };
struct bs_operations {
 int supported, last_signal; unsigned public_action_flags; void *context;
 pid_t (*getpid_fn)(void *); pid_t (*getppid_fn)(void *);
 int (*action_fn)(void *, int, const struct sigaction *, struct sigaction *, int *);
 int (*mask_fn)(void *, int, const sigset_t *, sigset_t *, int *);
 int (*pending_fn)(void *, sigset_t *, int *);
 int (*altstack_fn)(void *, const stack_t *, stack_t *, int *);
};
/* Initialize only with bs_prepare_parent. Valid, stable, nonalias storage and
 * trusted callbacks; callers never edit state. Single-threaded/quiescent owned
 * process only. Native Darwin covers every catchable signal; injected operations
 * are models, not host ABI evidence. No callback allocates or mutates API state. */
struct bs_state {
 uint32_t tag; struct bs_operations operations; pid_t owner;
 sigset_t original_mask; struct sigaction original_pipe;
 int mask_attempted, pipe_attempted, prepared, reset_attempted, child_reset;
 int release_attempted, restore_attempted, pipe_restored, mask_restored;
};
/* Output state must not already own an active/unrestored attempt: preparation
 * clears it, so never reuse it to discard a previous mask/disposition snapshot.
 * On preparation failure, if a mutation was attempted, restore once before exit.
 * Do not fork after any failure. Native unsupported rejects before callbacks. */
int bs_prepare_parent(const struct bs_operations *, struct bs_state *, struct bs_error *);
/* Owner PID captured by preparation BEFORE fork; never infer it in child.
 * Any child failure requires exit; no rollback, retry or target launch. */
int bs_reset_in_owned_child(struct bs_state *, struct bs_error *);
int bs_check_in_owned_child(struct bs_state *, struct bs_error *);
/* Call only after complete GO+EOF and checked gate close. Pending checks are
 * observations, not atomic exclusion of a subsequently arriving signal. */
int bs_release_in_owned_child(struct bs_state *, struct bs_error *);
/* Parent only, once, AFTER owned child/endpoint cleanup. Both steps attempted;
 * first failure retained and verified outcomes separately recorded in state. */
int bs_restore_parent(struct bs_state *, struct bs_error *);
/* Canonical description, not attestation. Clears whole output on failure. */
int bs_policy_bytes(const struct bs_state *, unsigned char [BS_POLICY_CAPACITY], size_t *, struct bs_error *);
const struct bs_operations *bs_native_operations(void);
#endif
