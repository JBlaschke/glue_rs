#ifndef _DEFAULT_SOURCE
#define _DEFAULT_SOURCE 1
#endif
#include "target_descriptors.h"

#include <errno.h>
#include <limits.h>
#include <signal.h>
#include <unistd.h>
#if defined(__APPLE__)
#include <libproc.h>
#include <sys/proc_info.h>
#endif

_Static_assert(sizeof(struct td_record) == 8, "record width");
_Static_assert(offsetof(struct td_record, fd) == 0, "FD offset");
_Static_assert(offsetof(struct td_record, type) == 4, "type offset");
_Static_assert(TD_MAX_CAPACITY <= INT_MAX / sizeof(struct td_record), "byte count overflow");
#if defined(__APPLE__)
_Static_assert(sizeof(struct td_record) == sizeof(struct proc_fdinfo), "native width");
_Static_assert(_Alignof(struct td_record) == _Alignof(struct proc_fdinfo), "native alignment");
_Static_assert(offsetof(struct td_record, fd) == offsetof(struct proc_fdinfo, proc_fd), "native FD offset");
_Static_assert(offsetof(struct td_record, type) == offsetof(struct proc_fdinfo, proc_fdtype), "native type offset");
#endif

static int fail(struct td_error *error, enum td_stage stage, enum td_reason reason,
                int system_errno, int fd)
{
    error->stage = stage;
    error->reason = reason;
    error->system_errno = system_errno;
    error->fd = fd;
    return -1;
}
static int kept(const struct td_plan *plan, int fd)
{
    for (size_t i = 0; i < TD_KEEP_COUNT; i++) if (plan->keep[i] == fd) return 1;
    return 0;
}
static int inspect(const struct td_plan *plan, const struct td_operations *ops,
                   pid_t pid, enum td_stage stage, struct td_error *error)
{
    const size_t bytes = plan->capacity * sizeof(*plan->scratch);
    /* An incomplete adapter fill must not reuse a prior valid record or read
     * uninitialized caller scratch. Opaque types are not interpreted. */
    for (size_t i = 0; i < plan->capacity; i++)
        plan->scratch[i] = (struct td_record){-1, 0};
    int saved_errno = 0;
    int result = ops->inventory_fn(ops->context, pid, plan->scratch, bytes, &saved_errno);
    if (result <= 0) {
        if ((result == 0 || result == -1) && saved_errno > 0)
            return fail(error, stage, TD_REASON_SYSCALL, saved_errno, -1);
        return fail(error, stage, result == 0 ? TD_REASON_EMPTY : TD_REASON_ADAPTER, 0, -1);
    }
    if ((size_t)result > bytes)
        return fail(error, stage, TD_REASON_RANGE, 0, -1);
    if ((size_t)result % sizeof(*plan->scratch) != 0)
        return fail(error, stage, TD_REASON_ALIGNMENT, 0, -1);
    if ((size_t)result == bytes)
        return fail(error, stage, TD_REASON_CAPACITY, 0, -1);
    const size_t count = (size_t)result / sizeof(*plan->scratch);
    for (size_t i = 0; i < count; i++) {
        int fd = plan->scratch[i].fd;
        if (fd < 0) return fail(error, stage, TD_REASON_RANGE, 0, fd);
        for (size_t j = 0; j < i; j++)
            if (plan->scratch[j].fd == fd)
                return fail(error, stage, TD_REASON_DUPLICATE, 0, fd);
    }
    for (size_t i = 0; i < TD_KEEP_COUNT; i++) {
        int found = 0;
        for (size_t j = 0; j < count; j++)
            if (plan->scratch[j].fd == plan->keep[i]) found = 1;
        if (!found) return fail(error, stage, TD_REASON_MISSING_KEEP, 0, plan->keep[i]);
    }
    if (stage == TD_STAGE_RESCAN && count != TD_KEEP_COUNT) {
        for (size_t i = 0; i < count; i++)
            if (!kept(plan, plan->scratch[i].fd))
                return fail(error, stage, TD_REASON_EXTRA_FD, 0, plan->scratch[i].fd);
    }
    return (int)count;
}

int td_close_in_owned_child(const struct td_plan *input, uint64_t owner_pid,
                            const struct td_operations *operations, struct td_error *error)
{
    if (error == NULL) return -1;
    *error = (struct td_error){TD_STAGE_NONE, TD_REASON_NONE, 0, -1, 0};
    if (input == NULL || input->scratch == NULL)
        return fail(error, TD_STAGE_PLAN, TD_REASON_ARGUMENT, 0, -1);
    const struct td_plan plan = *input;
    if (plan.capacity <= TD_KEEP_COUNT || plan.capacity > TD_MAX_CAPACITY)
        return fail(error, TD_STAGE_PLAN, TD_REASON_RANGE, 0, -1);
    if ((uintptr_t)plan.scratch % _Alignof(struct td_record) != 0)
        return fail(error, TD_STAGE_PLAN, TD_REASON_ALIGNMENT, 0, -1);
    if (plan.keep[0] != 0 || plan.keep[1] != 1 || plan.keep[2] != 2 ||
        plan.keep[3] < 3 || plan.keep[4] < 3)
        return fail(error, TD_STAGE_PLAN, TD_REASON_ARGUMENT, 0, -1);
    if (plan.keep[3] == plan.keep[4])
        return fail(error, TD_STAGE_PLAN, TD_REASON_DUPLICATE, 0, plan.keep[3]);
    if (operations == NULL || !operations->getpid_fn || !operations->getppid_fn ||
        !operations->signals_blocked_fn || !operations->inventory_fn || !operations->close_fn)
        return fail(error, TD_STAGE_OPERATIONS, TD_REASON_ARGUMENT, 0, -1);
    const struct td_operations ops = *operations;
    if (ops.supported == 0)
        return fail(error, TD_STAGE_OPERATIONS, TD_REASON_UNSUPPORTED, ENOTSUP, -1);
    if (ops.supported != 1)
        return fail(error, TD_STAGE_OPERATIONS, TD_REASON_ARGUMENT, 0, -1);
    if (owner_pid == 0 || owner_pid > INT_MAX)
        return fail(error, TD_STAGE_CHILD, TD_REASON_RANGE, 0, -1);
    pid_t self = ops.getpid_fn(ops.context), parent = ops.getppid_fn(ops.context);
    if (self <= 0 || parent <= 0 || (uint64_t)self == owner_pid || (uint64_t)parent != owner_pid)
        return fail(error, TD_STAGE_CHILD, TD_REASON_NOT_OWNED_CHILD, 0, -1);
    int saved_errno = 0;
    int blocked = ops.signals_blocked_fn(ops.context, &saved_errno);
    if (blocked != 1) {
        if (blocked == -1 && saved_errno > 0)
            return fail(error, TD_STAGE_SIGNALS, TD_REASON_SYSCALL, saved_errno, -1);
        return fail(error, TD_STAGE_SIGNALS, blocked == 0 ? TD_REASON_SIGNALS_UNBLOCKED : TD_REASON_ADAPTER, 0, -1);
    }
    int count = inspect(&plan, &ops, self, TD_STAGE_INVENTORY, error);
    if (count < 0) return -1;
    for (int i = 0; i < count; i++) {
        int fd = plan.scratch[i].fd;
        if (kept(&plan, fd)) continue;
        saved_errno = 0;
        error->closure_attempted = 1;
        int result = ops.close_fn(ops.context, fd, &saved_errno);
        if (result != 0) {
            if (result == -1 && saved_errno > 0)
                return fail(error, TD_STAGE_CLOSE, TD_REASON_SYSCALL, saved_errno, fd);
            return fail(error, TD_STAGE_CLOSE, TD_REASON_ADAPTER, 0, fd);
        }
    }
    if (inspect(&plan, &ops, self, TD_STAGE_RESCAN, error) < 0) return -1;
    return 0;
}

static pid_t native_pid(void *p) { (void)p; return getpid(); }
static pid_t native_ppid(void *p) { (void)p; return getppid(); }
static int native_signals(void *p, int *saved_errno)
{
    (void)p;
#if defined(__APPLE__)
    sigset_t current;
    if (sigprocmask(SIG_SETMASK, NULL, &current) == -1) { *saved_errno = errno; return -1; }
    /* Darwin SDK: 1..NSIG-1 are valid signal numbers; KILL/STOP cannot be masked.
     * This is not a Linux libc-reserved signal-number policy. */
    for (int signal_number = 1; signal_number < NSIG; signal_number++) {
        if (signal_number == SIGKILL || signal_number == SIGSTOP) continue;
        int member = sigismember(&current, signal_number);
        if (member == -1) { *saved_errno = errno; return -1; }
        if (member != 1) return 0;
    }
    return 1;
#else
    *saved_errno = ENOTSUP; return -1;
#endif
}
static int native_inventory(void *p, pid_t pid, struct td_record *records, size_t bytes, int *saved_errno)
{
    (void)p;
#if defined(__APPLE__)
    errno = 0;
    int result = proc_pidinfo(pid, PROC_PIDLISTFDS, 0, records, (int)bytes);
    if (result <= 0) *saved_errno = errno;
    return result;
#else
    (void)pid; (void)records; (void)bytes; *saved_errno = ENOTSUP; return -1;
#endif
}
static int native_close(void *p, int fd, int *saved_errno)
{ (void)p; int result = close(fd); if (result == -1) *saved_errno = errno; return result; }
const struct td_operations *td_native_operations(void)
{
    static const struct td_operations operations = {
#if defined(__APPLE__)
        1,
#else
        0,
#endif
        NULL, native_pid, native_ppid, native_signals, native_inventory, native_close
    };
    return &operations;
}
const char *td_stage_name(enum td_stage stage)
{
    static const char *const names[] = {"none", "plan", "operations", "child", "signals", "inventory", "close", "rescan"};
    return (unsigned)stage < sizeof(names) / sizeof(names[0]) ? names[stage] : "unknown";
}
const char *td_reason_name(enum td_reason reason)
{
    static const char *const names[] = {"none", "argument", "range", "alignment", "unsupported", "not-owned-child",
        "signals-unblocked", "syscall", "adapter", "empty", "capacity", "duplicate", "missing-keep", "extra-fd"};
    return (unsigned)reason < sizeof(names) / sizeof(names[0]) ? names[reason] : "unknown";
}
