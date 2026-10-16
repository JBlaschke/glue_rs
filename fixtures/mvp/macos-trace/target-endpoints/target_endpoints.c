#ifndef _GNU_SOURCE
#define _GNU_SOURCE 1
#endif
#include "target_endpoints.h"
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <signal.h>
#include <sys/stat.h>
#include <unistd.h>

static void clear_error(struct te_error *error)
{ *error = (struct te_error){TE_STAGE_NONE, TE_REASON_NONE, 0, TE_NO_ROLE, -1, 0, 0}; }
static int fail(struct te_error *error, enum te_stage stage, enum te_reason reason,
                int number, enum te_role role, int fd)
{
    error->stage = stage; error->reason = reason; error->system_errno = number;
    error->role = role; error->fd = fd;
    return -1;
}
static int operations_valid(const struct te_operations *ops, struct te_error *error)
{
    if (ops == NULL || !ops->getpid_fn || !ops->getppid_fn || !ops->signals_blocked_fn ||
        !ops->getfl_fn || !ops->getfd_fn || !ops->setfd_fn || !ops->kind_fn ||
        !ops->duplicate_fn || !ops->dup2_fn)
        return fail(error, TE_STAGE_OPERATIONS, TE_REASON_ARGUMENT, 0, TE_NO_ROLE, -1);
    return 0;
}
static int bad_result(int result, int saved_errno, enum te_stage stage,
                      enum te_role role, int fd, struct te_error *error)
{
    return fail(error, stage, result == -1 && saved_errno > 0 ? TE_REASON_SYSCALL : TE_REASON_ADAPTER,
                result == -1 && saved_errno > 0 ? saved_errno : 0, role, fd);
}
static int role_valid(const struct te_operations *ops, int fd, enum te_role role,
                      enum te_stage stage, struct te_error *error)
{
    int saved_errno = 0;
    int flags = ops->getfl_fn(ops->context, fd, &saved_errno);
    if (flags < 0) return bad_result(flags, saved_errno, stage, role, fd, error);
    int expected = role == TE_STDIN || role == TE_GATE_READER ? O_RDONLY : O_WRONLY;
    if ((flags & O_ACCMODE) != expected)
        return fail(error, stage, TE_REASON_DIRECTION, 0, role, fd);
    if ((role < TE_GATE_READER && (flags & O_NONBLOCK)) ||
        (role >= TE_GATE_READER && !(flags & O_NONBLOCK)))
        return fail(error, stage, TE_REASON_POLICY, 0, role, fd);
    int forbidden = 0;
#ifdef O_ASYNC
    forbidden |= O_ASYNC;
#endif
#ifdef O_EVTONLY
    forbidden |= O_EVTONLY;
#endif
#ifdef O_PATH
    forbidden |= O_PATH;
#endif
    if (flags & forbidden) return fail(error, stage, TE_REASON_POLICY, 0, role, fd);
    enum te_kind kind = TE_OTHER;
    saved_errno = 0;
    int result = ops->kind_fn(ops->context, fd, &kind, &saved_errno);
    if (result != 0) return bad_result(result, saved_errno, stage, role, fd, error);
    if (kind != TE_REGULAR && kind != TE_FIFO && kind != TE_CHARACTER && kind != TE_OTHER)
        return fail(error, stage, TE_REASON_ADAPTER, 0, role, fd);
    int shape_ok = role >= TE_GATE_READER ? kind == TE_FIFO :
        kind == TE_REGULAR || kind == TE_FIFO || (role == TE_STDIN && kind == TE_CHARACTER);
    if (!shape_ok) return fail(error, stage, TE_REASON_SHAPE, 0, role, fd);
    return 0;
}
static int descriptor_flags(const struct te_operations *ops, int fd, enum te_role role,
                            enum te_stage stage, struct te_error *error)
{
    int saved_errno = 0, result = ops->getfd_fn(ops->context, fd, &saved_errno);
    if (result < 0) return bad_result(result, saved_errno, stage, role, fd, error);
    return result;
}

int te_prepare_owned_sources(const struct te_request *input, const struct te_operations *operations,
                              struct te_prepared *output, struct te_error *error)
{
    if (error == NULL) return -1;
    clear_error(error);
    if (output == NULL) return fail(error, TE_STAGE_REQUEST, TE_REASON_ARGUMENT, 0, TE_NO_ROLE, -1);
    *output = (struct te_prepared){{-1, -1, -1, -1, -1}, 0, 0};
    if (input == NULL) return fail(error, TE_STAGE_REQUEST, TE_REASON_ARGUMENT, 0, TE_NO_ROLE, -1);
    const struct te_request request = *input;
    for (size_t i = 0; i < TE_ROLE_COUNT; i++) {
        if (request.source[i] < 0)
            return fail(error, TE_STAGE_REQUEST, TE_REASON_ARGUMENT, 0, (enum te_role)i, request.source[i]);
        for (size_t j = 0; j < i; j++) if (request.source[i] == request.source[j])
            return fail(error, TE_STAGE_REQUEST, TE_REASON_DUPLICATE, 0, (enum te_role)i, request.source[i]);
    }
    if (operations_valid(operations, error) != 0) return -1;
    const struct te_operations ops = *operations;
    for (size_t i = 0; i < TE_ROLE_COUNT; i++)
        if (role_valid(&ops, request.source[i], (enum te_role)i, TE_STAGE_SOURCE, error) != 0) return -1;
    for (size_t i = 0; i < TE_ROLE_COUNT; i++) {
        int saved_errno = 0;
        error->mutation_attempted = 1;
        int copy = ops.duplicate_fn(ops.context, request.source[i], 3, &saved_errno);
        if (copy < 0) {
            if (copy != -1 || saved_errno <= 0) error->ownership_uncertain = 1;
            return bad_result(copy, saved_errno, TE_STAGE_DUPLICATE, (enum te_role)i, request.source[i], error);
        }
        int uncertain = copy < 3;
        for (size_t j = 0; j < TE_ROLE_COUNT; j++) if (copy == request.source[j]) uncertain = 1;
        for (size_t j = 0; j < output->owned_count; j++) if (copy == output->copies[j]) uncertain = 1;
        if (uncertain) {
            error->ownership_uncertain = 1;
            return fail(error, TE_STAGE_DUPLICATE, TE_REASON_OWNERSHIP, 0, (enum te_role)i, copy);
        }
        output->copies[output->owned_count++] = copy;
        if (role_valid(&ops, copy, (enum te_role)i, TE_STAGE_COPY, error) != 0) return -1;
        int flags = descriptor_flags(&ops, copy, (enum te_role)i, TE_STAGE_COPY, error);
        if (flags < 0) return -1;
        if (!(flags & FD_CLOEXEC)) return fail(error, TE_STAGE_COPY, TE_REASON_FLAGS, 0, (enum te_role)i, copy);
    }
    output->ready = 1;
    return 0;
}

int te_map_in_owned_child(const struct te_prepared *input, uint64_t owner_pid,
                          const struct te_operations *operations, struct te_error *error)
{
    if (error == NULL) return -1;
    clear_error(error);
    if (input == NULL) return fail(error, TE_STAGE_REQUEST, TE_REASON_ARGUMENT, 0, TE_NO_ROLE, -1);
    const struct te_prepared plan = *input;
    if (plan.ready != 1 || plan.owned_count != TE_ROLE_COUNT)
        return fail(error, TE_STAGE_REQUEST, TE_REASON_PARTIAL_PLAN, 0, TE_NO_ROLE, -1);
    for (size_t i = 0; i < TE_ROLE_COUNT; i++) {
        if (plan.copies[i] < 3)
            return fail(error, TE_STAGE_REQUEST, TE_REASON_ARGUMENT, 0, (enum te_role)i, plan.copies[i]);
        for (size_t j = 0; j < i; j++) if (plan.copies[i] == plan.copies[j])
            return fail(error, TE_STAGE_REQUEST, TE_REASON_DUPLICATE, 0, (enum te_role)i, plan.copies[i]);
    }
    if (operations_valid(operations, error) != 0) return -1;
    const struct te_operations ops = *operations;
    if (owner_pid == 0 || owner_pid > INT_MAX)
        return fail(error, TE_STAGE_CHILD, TE_REASON_ARGUMENT, 0, TE_NO_ROLE, -1);
    pid_t self = ops.getpid_fn(ops.context), parent = ops.getppid_fn(ops.context);
    if (self <= 0 || parent <= 0 || (uint64_t)self == owner_pid || (uint64_t)parent != owner_pid)
        return fail(error, TE_STAGE_CHILD, TE_REASON_NOT_OWNED_CHILD, 0, TE_NO_ROLE, -1);
    int saved_errno = 0, blocked = ops.signals_blocked_fn(ops.context, &saved_errno);
    if (blocked != 1) {
        if (blocked == -1 && saved_errno > 0)
            return fail(error, TE_STAGE_SIGNALS, TE_REASON_SYSCALL, saved_errno, TE_NO_ROLE, -1);
        return fail(error, TE_STAGE_SIGNALS, blocked == 0 ? TE_REASON_SIGNALS_UNBLOCKED : TE_REASON_ADAPTER, 0, TE_NO_ROLE, -1);
    }
    int copy_flags[TE_ROLE_COUNT];
    for (size_t i = 0; i < TE_ROLE_COUNT; i++) {
        if (role_valid(&ops, plan.copies[i], (enum te_role)i, TE_STAGE_COPY, error) != 0) return -1;
        copy_flags[i] = descriptor_flags(&ops, plan.copies[i], (enum te_role)i, TE_STAGE_COPY, error);
        if (copy_flags[i] < 0) return -1;
        if (!(copy_flags[i] & FD_CLOEXEC))
            return fail(error, TE_STAGE_COPY, TE_REASON_FLAGS, 0, (enum te_role)i, plan.copies[i]);
    }
    for (size_t i = 0; i < 3; i++) {
        saved_errno = 0; error->mutation_attempted = 1;
        int result = ops.dup2_fn(ops.context, plan.copies[i], (int)i, &saved_errno);
        if (result != (int)i)
            return bad_result(result, saved_errno, TE_STAGE_MAP, (enum te_role)i, (int)i, error);
        int flags = descriptor_flags(&ops, (int)i, (enum te_role)i, TE_STAGE_STDIO_FLAGS, error);
        if (flags < 0) return -1;
        if (flags & FD_CLOEXEC)
            return fail(error, TE_STAGE_STDIO_FLAGS, TE_REASON_FLAGS, 0, (enum te_role)i, (int)i);
    }
    for (size_t i = TE_GATE_READER; i < TE_ROLE_COUNT; i++) {
        saved_errno = 0;
        int result = ops.setfd_fn(ops.context, plan.copies[i], copy_flags[i] | FD_CLOEXEC, &saved_errno);
        if (result != 0) return bad_result(result, saved_errno, TE_STAGE_CONTROL_FLAGS, (enum te_role)i, plan.copies[i], error);
        int flags = descriptor_flags(&ops, plan.copies[i], (enum te_role)i, TE_STAGE_CONTROL_FLAGS, error);
        if (flags < 0) return -1;
        if (!(flags & FD_CLOEXEC))
            return fail(error, TE_STAGE_CONTROL_FLAGS, TE_REASON_FLAGS, 0, (enum te_role)i, plan.copies[i]);
    }
    for (size_t i = 0; i < TE_ROLE_COUNT; i++)
        if (role_valid(&ops, i < 3 ? (int)i : plan.copies[i], (enum te_role)i, TE_STAGE_VERIFY, error) != 0) return -1;
    return 0;
}

static pid_t native_pid(void *p) { (void)p; return getpid(); }
static pid_t native_ppid(void *p) { (void)p; return getppid(); }
static int native_signals(void *p, int *saved_errno)
{
    (void)p; sigset_t current;
    if (sigprocmask(SIG_SETMASK, NULL, &current) == -1) { *saved_errno = errno; return -1; }
    for (int s = 1; s < NSIG; s++) {
        if (s == SIGKILL || s == SIGSTOP) continue;
        struct sigaction action;
        if (sigaction(s, NULL, &action) == -1) {
#if defined(__linux__)
            if (errno == EINVAL) continue; /* Invalid or libc-reserved; never change it. */
#endif
            *saved_errno = errno; return -1;
        }
        int member = sigismember(&current, s);
        if (member == -1) { *saved_errno = errno; return -1; }
        if (member != 1) return 0;
    }
    return 1;
}
static int native_getfl(void *p, int fd, int *e)
{ (void)p; int r = fcntl(fd, F_GETFL); if (r == -1) *e = errno; return r; }
static int native_getfd(void *p, int fd, int *e)
{ (void)p; int r = fcntl(fd, F_GETFD); if (r == -1) *e = errno; return r; }
static int native_setfd(void *p, int fd, int flags, int *e)
{ (void)p; int r = fcntl(fd, F_SETFD, flags); if (r == -1) *e = errno; return r; }
static int native_kind(void *p, int fd, enum te_kind *kind, int *e)
{
    (void)p; struct stat st;
    int r = fstat(fd, &st); if (r == -1) { *e = errno; return -1; }
    *kind = S_ISREG(st.st_mode) ? TE_REGULAR : S_ISFIFO(st.st_mode) ? TE_FIFO : S_ISCHR(st.st_mode) ? TE_CHARACTER : TE_OTHER;
    return 0;
}
static int native_duplicate(void *p, int fd, int minimum, int *e)
{ (void)p; int r = fcntl(fd, F_DUPFD_CLOEXEC, minimum); if (r == -1) *e = errno; return r; }
static int native_dup2(void *p, int fd, int destination, int *e)
{ (void)p; int r = dup2(fd, destination); if (r == -1) *e = errno; return r; }
const struct te_operations *te_native_operations(void)
{
    static const struct te_operations ops = {NULL, native_pid, native_ppid, native_signals,
        native_getfl, native_getfd, native_setfd, native_kind, native_duplicate, native_dup2};
    return &ops;
}
const char *te_stage_name(enum te_stage stage)
{
    static const char *const names[] = {"none", "request", "operations", "source", "duplicate", "copy",
        "child", "signals", "map", "stdio-flags", "control-flags", "verify"};
    return (unsigned)stage < sizeof(names) / sizeof(names[0]) ? names[stage] : "unknown";
}
const char *te_reason_name(enum te_reason reason)
{
    static const char *const names[] = {"none", "argument", "duplicate", "direction", "shape", "policy", "syscall",
        "adapter", "flags", "partial-plan", "not-owned-child", "signals-unblocked", "ownership"};
    return (unsigned)reason < sizeof(names) / sizeof(names[0]) ? names[reason] : "unknown";
}
