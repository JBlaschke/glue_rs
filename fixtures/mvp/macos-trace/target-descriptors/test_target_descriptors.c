#ifndef _DEFAULT_SOURCE
#define _DEFAULT_SOURCE 1
#endif
#include "target_descriptors.h"

#include <assert.h>
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <signal.h>
#include <stdio.h>
#include <string.h>
#include <sys/resource.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

struct mock {
    char calls[64]; size_t used;
    struct td_record first[16], second[16];
    int first_count, second_count, scans;
    int first_result, second_result, inventory_errno;
    int closed[16], closed_count, close_failure, close_result, close_errno;
    int signals_result, signals_errno;
    pid_t self, parent;
};
static void note(struct mock *m, char c)
{ assert(m->used + 1 < sizeof(m->calls)); m->calls[m->used++] = c; m->calls[m->used] = 0; }
static struct mock mock(void)
{
    struct mock m = {0};
    m.first_count = 7; m.second_count = 5;
    const int first[] = {0, 1, 2, 10, 11, 1000000, INT_MAX};
    for (int i = 0; i < 7; i++) m.first[i] = (struct td_record){first[i], UINT32_MAX};
    for (int i = 0; i < 5; i++) m.second[i] = m.first[i];
    m.first_result = m.second_result = INT_MIN;
    m.close_failure = -1; m.close_result = -1; m.close_errno = EINTR;
    m.signals_result = 1; m.self = 222; m.parent = 111;
    return m;
}
static struct td_plan plan(struct td_record *scratch)
{ return (struct td_plan){{0, 1, 2, 10, 11}, scratch, 16}; }
static pid_t self(void *p) { struct mock *m = p; note(m, 'p'); return m->self; }
static pid_t parent(void *p) { struct mock *m = p; note(m, 'P'); return m->parent; }
static int signals(void *p, int *e)
{ struct mock *m = p; note(m, 's'); *e = m->signals_errno; return m->signals_result; }
static int inventory(void *p, pid_t pid, struct td_record *out, size_t bytes, int *e)
{
    struct mock *m = p; assert(pid == 222); note(m, 'i');
    assert(m->scans < 2 && bytes >= 6 * sizeof(*out) && bytes <= TD_MAX_CAPACITY * sizeof(*out));
    int second = m->scans++;
    int count = second ? m->second_count : m->first_count;
    const struct td_record *records = second ? m->second : m->first;
    for (int i = 0; i < count && (size_t)i < bytes / sizeof(*out); i++) out[i] = records[i];
    *e = m->inventory_errno;
    int selected = second ? m->second_result : m->first_result;
    return selected == INT_MIN ? count * (int)sizeof(*out) : selected;
}
static int close_fd(void *p, int fd, int *e)
{
    struct mock *m = p; note(m, 'c');
    assert(m->closed_count < 16);
    m->closed[m->closed_count++] = fd;
    if (fd == m->close_failure) { *e = m->close_errno; return m->close_result; }
    return 0;
}
static struct td_operations operations(struct mock *m)
{ return (struct td_operations){1, m, self, parent, signals, inventory, close_fd}; }
static void error_is(struct td_error e, enum td_stage stage, enum td_reason reason, int number, int attempted)
{
    assert(e.stage == stage && e.reason == reason && e.system_errno == number);
    assert(e.closure_attempted == attempted);
}
static void success(void)
{
    struct td_record scratch[16]; struct td_plan p = plan(scratch);
    struct mock m = mock(); struct td_operations o = operations(&m); struct td_error e;
    assert(td_close_in_owned_child(&p, 111, &o, &e) == 0);
    assert(strcmp(m.calls, "pPsicci") == 0 && m.closed_count == 2);
    assert(m.closed[0] == 1000000 && m.closed[1] == INT_MAX);
    error_is(e, TD_STAGE_NONE, TD_REASON_NONE, 0, 1); assert(e.fd == -1);
    m = mock(); m.first_count = 5; o = operations(&m);
    assert(td_close_in_owned_child(&p, 111, &o, &e) == 0);
    assert(strcmp(m.calls, "pPsii") == 0 && !m.closed_count);
    error_is(e, TD_STAGE_NONE, TD_REASON_NONE, 0, 0);
}
static void plan_bounds(void)
{
    struct td_record scratch[TD_MAX_CAPACITY]; struct td_plan p;
    struct mock m = mock(); struct td_operations o = operations(&m); struct td_error e;
    const size_t bad[] = {0, 5, TD_MAX_CAPACITY + 1, SIZE_MAX};
    for (size_t i = 0; i < sizeof(bad) / sizeof(bad[0]); i++) {
        p = plan(scratch); p.capacity = bad[i];
        assert(td_close_in_owned_child(&p, 111, &o, &e) == -1 && !m.used);
        error_is(e, TD_STAGE_PLAN, TD_REASON_RANGE, 0, 0);
    }
    p = plan(NULL); assert(td_close_in_owned_child(&p, 111, &o, &e) == -1 && !m.used);
    p = plan(scratch); p.scratch = (struct td_record *)((char *)scratch + 1);
    assert(td_close_in_owned_child(&p, 111, &o, &e) == -1 && !m.used);
    error_is(e, TD_STAGE_PLAN, TD_REASON_ALIGNMENT, 0, 0);
    assert(td_close_in_owned_child(NULL, 111, &o, &e) == -1 && !m.used);
    assert(td_close_in_owned_child(&p, 111, &o, NULL) == -1 && !m.used);
    for (int slot = 0; slot < 5; slot++) {
        p = plan(scratch); p.keep[slot] = slot < 3 ? slot + 1 : -1;
        assert(td_close_in_owned_child(&p, 111, &o, &e) == -1 && !m.used);
    }
    p = plan(scratch); p.keep[4] = 10;
    assert(td_close_in_owned_child(&p, 111, &o, &e) == -1 && !m.used);
    error_is(e, TD_STAGE_PLAN, TD_REASON_DUPLICATE, 0, 0);
    /* Maximum allocated capacity is usable without becoming a numeric-FD cap. */
    p = plan(scratch); p.capacity = TD_MAX_CAPACITY;
    assert(td_close_in_owned_child(&p, 111, &o, &e) == 0);
}
static void preflight(void)
{
    struct td_record scratch[16]; struct td_plan p = plan(scratch); struct td_error e;
    struct mock m = mock(); struct td_operations o;
    for (int missing = 0; missing < 5; missing++) {
        o = operations(&m);
        switch (missing) {
        case 0: o.getpid_fn = NULL; break; case 1: o.getppid_fn = NULL; break;
        case 2: o.signals_blocked_fn = NULL; break; case 3: o.inventory_fn = NULL; break;
        case 4: o.close_fn = NULL; break;
        }
        assert(td_close_in_owned_child(&p, 111, &o, &e) == -1 && !m.used);
        error_is(e, TD_STAGE_OPERATIONS, TD_REASON_ARGUMENT, 0, 0);
    }
    assert(td_close_in_owned_child(&p, 111, NULL, &e) == -1 && !m.used);
    o = operations(&m); o.supported = 0;
    assert(td_close_in_owned_child(&p, 111, &o, &e) == -1 && !m.used);
    error_is(e, TD_STAGE_OPERATIONS, TD_REASON_UNSUPPORTED, ENOTSUP, 0);
    o.supported = 2;
    assert(td_close_in_owned_child(&p, 111, &o, &e) == -1 && !m.used);
}
static void child_and_signals(void)
{
    struct td_record scratch[16]; struct td_plan p = plan(scratch); struct td_error e;
    for (int mode = 0; mode < 8; mode++) {
        struct mock m = mock(); struct td_operations o = operations(&m);
        uint64_t owner = 111;
        if (mode == 0) owner = 0;
        if (mode == 1) owner = UINT64_MAX;
        if (mode == 2) m.self = 111;
        if (mode == 3) m.parent = 333;
        if (mode == 4) m.self = -1;
        if (mode == 5) m.parent = 0;
        if (mode == 6) m.signals_result = 0;
        if (mode == 7) { m.signals_result = -1; m.signals_errno = EIO; }
        assert(td_close_in_owned_child(&p, owner, &o, &e) == -1);
        assert(!m.scans && !m.closed_count && !e.closure_attempted);
        if (mode == 6) error_is(e, TD_STAGE_SIGNALS, TD_REASON_SIGNALS_UNBLOCKED, 0, 0);
        if (mode == 7) error_is(e, TD_STAGE_SIGNALS, TD_REASON_SYSCALL, EIO, 0);
    }
    const int bad[] = {-2, -1, 2};
    for (size_t i = 0; i < sizeof(bad) / sizeof(bad[0]); i++) {
        struct mock m = mock(); struct td_operations o = operations(&m); m.signals_result = bad[i];
        assert(td_close_in_owned_child(&p, 111, &o, &e) == -1);
        error_is(e, TD_STAGE_SIGNALS, TD_REASON_ADAPTER, 0, 0);
    }
}
static void response_bounds(void)
{
    struct td_record scratch[16]; struct td_plan p = plan(scratch); struct td_error e;
    const int bad[] = {0, -1, -2, 1, 127, 128, 136, INT_MAX};
    const enum td_reason reasons[] = {TD_REASON_EMPTY, TD_REASON_ADAPTER, TD_REASON_ADAPTER,
        TD_REASON_ALIGNMENT, TD_REASON_ALIGNMENT, TD_REASON_CAPACITY, TD_REASON_RANGE, TD_REASON_RANGE};
    for (size_t i = 0; i < sizeof(bad) / sizeof(bad[0]); i++) {
        struct mock m = mock(); struct td_operations o = operations(&m); m.first_result = bad[i];
        assert(td_close_in_owned_child(&p, 111, &o, &e) == -1 && !m.closed_count);
        error_is(e, TD_STAGE_INVENTORY, reasons[i], 0, 0);
    }
    for (int result = -1; result <= 0; result++) {
        struct mock m = mock(); struct td_operations o = operations(&m);
        m.first_result = result; m.inventory_errno = EPERM;
        assert(td_close_in_owned_child(&p, 111, &o, &e) == -1);
        error_is(e, TD_STAGE_INVENTORY, TD_REASON_SYSCALL, EPERM, 0);
    }
}
static void initial_records(void)
{
    struct td_record scratch[16]; struct td_plan p = plan(scratch); struct td_error e;
    for (int mode = 0; mode < 3; mode++) {
        struct mock m = mock(); struct td_operations o = operations(&m);
        if (mode == 0) m.first[6].fd = -1;
        if (mode == 1) m.first[6].fd = m.first[5].fd;
        if (mode == 2) m.first[4].fd = 12;
        assert(td_close_in_owned_child(&p, 111, &o, &e) == -1 && !m.closed_count);
        error_is(e, TD_STAGE_INVENTORY, mode == 0 ? TD_REASON_RANGE : mode == 1 ? TD_REASON_DUPLICATE : TD_REASON_MISSING_KEEP, 0, 0);
    }
    struct mock m = mock(); struct td_operations o = operations(&m);
    m.first_count = 4; m.first_result = 5 * (int)sizeof(struct td_record);
    assert(td_close_in_owned_child(&p, 111, &o, &e) == -1 && !m.closed_count);
    error_is(e, TD_STAGE_INVENTORY, TD_REASON_RANGE, 0, 0);
}
static void close_failures(void)
{
    struct td_record scratch[16]; struct td_plan p = plan(scratch); struct td_error e;
    for (int slot = 0; slot < 3; slot++) {
        struct mock m = mock(); struct td_operations o = operations(&m);
        m.close_failure = m.first[5 + slot % 2].fd;
        m.close_errno = slot == 0 ? EINTR : slot == 1 ? EBADF : EPERM;
        assert(td_close_in_owned_child(&p, 111, &o, &e) == -1);
        error_is(e, TD_STAGE_CLOSE, TD_REASON_SYSCALL, m.close_errno, 1);
        assert(e.fd == m.close_failure && m.closed_count == slot % 2 + 1 && m.scans == 1);
    }
    for (int mode = 0; mode < 3; mode++) {
        struct mock m = mock(); struct td_operations o = operations(&m);
        m.close_failure = m.first[5].fd;
        m.close_result = mode == 0 ? -2 : mode == 1 ? 1 : -1;
        m.close_errno = mode == 2 ? 0 : EIO;
        assert(td_close_in_owned_child(&p, 111, &o, &e) == -1);
        error_is(e, TD_STAGE_CLOSE, TD_REASON_ADAPTER, 0, 1);
        assert(m.closed_count == 1 && m.scans == 1);
    }
}
static void rescan(void)
{
    struct td_record scratch[16]; struct td_plan p = plan(scratch); struct td_error e;
    for (int mode = 0; mode < 6; mode++) {
        struct mock m = mock(); struct td_operations o = operations(&m);
        if (mode == 0) { m.second_count = 6; m.second[5] = (struct td_record){9000, 0}; }
        if (mode == 1) m.second[4].fd = 12;
        if (mode == 2) m.second[4].fd = 10;
        if (mode == 3) m.second_result = 128;
        if (mode == 4) { m.second_result = 0; m.inventory_errno = EIO; }
        if (mode == 5) m.second[4].fd = -1;
        assert(td_close_in_owned_child(&p, 111, &o, &e) == -1 && m.closed_count == 2);
        assert(e.stage == TD_STAGE_RESCAN && e.closure_attempted);
        if (mode == 0) assert(e.reason == TD_REASON_EXTRA_FD && e.fd == 9000);
        if (mode == 1) assert(e.reason == TD_REASON_MISSING_KEEP && e.fd == 11);
        if (mode == 2) assert(e.reason == TD_REASON_DUPLICATE);
        if (mode == 3) assert(e.reason == TD_REASON_CAPACITY);
        if (mode == 4) assert(e.reason == TD_REASON_SYSCALL && e.system_errno == EIO);
        if (mode == 5) assert(e.reason == TD_REASON_RANGE);
    }
}
static void error_reset(void)
{
    struct td_record scratch[16]; struct td_plan p = plan(scratch); struct td_error e;
    memset(&e, 0xa5, sizeof(e));
    struct mock m = mock(); m.close_failure = 1000000; struct td_operations o = operations(&m);
    assert(td_close_in_owned_child(&p, 111, &o, &e) == -1 && e.closure_attempted);
    m = mock(); m.first_count = 5; o = operations(&m);
    assert(td_close_in_owned_child(&p, 111, &o, &e) == 0);
    error_is(e, TD_STAGE_NONE, TD_REASON_NONE, 0, 0); assert(e.fd == -1);
    assert(strcmp(td_stage_name(TD_STAGE_CLOSE), "close") == 0);
    assert(strcmp(td_reason_name(TD_REASON_CAPACITY), "capacity") == 0);
    assert(strcmp(td_stage_name((enum td_stage)-1), "unknown") == 0);
}

#if defined(__APPLE__)
struct native_report { int result; struct td_error error; int high_fd; };
static int wait_owned(pid_t child, int *status)
{
    struct timespec start, now; assert(clock_gettime(CLOCK_MONOTONIC, &start) == 0);
    for (;;) {
        pid_t result = waitpid(child, status, WNOHANG);
        if (result == child) return 0;
        if (result == -1 && errno == EINTR) continue;
        assert(result == 0); /* Still our actual unreaped child, not a remembered PID. */
        assert(clock_gettime(CLOCK_MONOTONIC, &now) == 0);
        if (now.tv_sec - start.tv_sec >= 5) {
            assert(kill(child, SIGKILL) == 0);
            while (waitpid(child, status, 0) == -1) assert(errno == EINTR);
            return -1;
        }
        const struct timespec pause = {0, 10000000}; nanosleep(&pause, NULL);
    }
}
static int native_case(const char *mode)
{
    if (getuid() == 0 || geteuid() == 0) return 77;
    struct rlimit parent_limit; assert(getrlimit(RLIMIT_NOFILE, &parent_limit) == 0);
    /* No raising limits: this control requires enough existing capacity. */
    if (parent_limit.rlim_cur <= 128) return 77;
    int extra = open("/dev/null", O_RDONLY | O_CLOEXEC); assert(extra >= 3);
    int minimum = parent_limit.rlim_cur > 4096 ? 4096 : 128;
    int high = fcntl(extra, F_DUPFD_CLOEXEC, minimum); assert(high >= minimum);
    int high_flags = fcntl(high, F_GETFD), extra_flags = fcntl(extra, F_GETFD);
    int gate[2], status_pipe[2]; assert(pipe(gate) == 0 && pipe(status_pipe) == 0);
    assert(gate[0] >= 3 && status_pipe[1] >= 3);
    struct td_record scratch[TD_MAX_CAPACITY]; /* Allocated before fork. */
    struct td_plan selected = {{0, 1, 2, gate[0], status_pipe[1]}, scratch, TD_MAX_CAPACITY};
    if (strcmp(mode, "native-capacity") == 0) selected.capacity = 6;
    pid_t controller = getpid(), child = fork(); assert(child >= 0);
    if (child == 0) {
        /* This owned test has no inherited FD-mutating handlers/atfork callbacks;
         * masking is the first child setup step, before helper/limit activity. */
        sigset_t mask; assert(sigfillset(&mask) == 0 && sigprocmask(SIG_SETMASK, &mask, NULL) == 0);
        if (strcmp(mode, "native-unmasked") == 0) {
            assert(sigemptyset(&mask) == 0 && sigprocmask(SIG_SETMASK, &mask, NULL) == 0);
        }
        if (strcmp(mode, "native-lowered-limits") == 0) {
            struct rlimit lowered = {64, 64}; assert(setrlimit(RLIMIT_NOFILE, &lowered) == 0);
            struct rlimit actual; assert(getrlimit(RLIMIT_NOFILE, &actual) == 0);
            assert(actual.rlim_cur == 64 && actual.rlim_max == 64 && high > 64);
            assert(fcntl(high, F_GETFD) == high_flags);
        }
        if (strcmp(mode, "native-missing-stdio") == 0) assert(close(0) == 0);
        struct native_report report;
        report.result = td_close_in_owned_child(&selected, (uint64_t)controller, td_native_operations(), &report.error);
        report.high_fd = high;
        int good = 0;
        if (strcmp(mode, "native-capacity") == 0)
            good = report.result == -1 && report.error.stage == TD_STAGE_INVENTORY &&
                   report.error.reason == TD_REASON_CAPACITY && !report.error.closure_attempted;
        else if (strcmp(mode, "native-missing-stdio") == 0)
            good = report.result == -1 && report.error.stage == TD_STAGE_INVENTORY &&
                   report.error.reason == TD_REASON_MISSING_KEEP && report.error.fd == 0 && !report.error.closure_attempted;
        else if (strcmp(mode, "native-unmasked") == 0)
            good = report.result == -1 && report.error.stage == TD_STAGE_SIGNALS &&
                   report.error.reason == TD_REASON_SIGNALS_UNBLOCKED && !report.error.closure_attempted;
        else {
            good = report.result == 0 && report.error.closure_attempted;
            errno = 0; good = good && fcntl(high, F_GETFD) == -1 && errno == EBADF;
            errno = 0; good = good && fcntl(extra, F_GETFD) == -1 && errno == EBADF;
            for (size_t i = 0; i < TD_KEEP_COUNT; i++) good = good && fcntl(selected.keep[i], F_GETFD) >= 0;
        }
        ssize_t written = write(status_pipe[1], &report, sizeof(report));
        _exit(good && written == sizeof(report) ? 0 : 1);
    }
    assert(close(gate[0]) == 0 && close(status_pipe[1]) == 0);
    int status = 0, wait_result = wait_owned(child, &status);
    struct native_report report; ssize_t bytes = read(status_pipe[0], &report, sizeof(report));
    assert(wait_result == 0 && WIFEXITED(status) && WEXITSTATUS(status) == 0 && bytes == sizeof(report));
    assert(fcntl(high, F_GETFD) == high_flags && fcntl(extra, F_GETFD) == extra_flags);
    struct rlimit after; assert(getrlimit(RLIMIT_NOFILE, &after) == 0);
    assert(after.rlim_cur == parent_limit.rlim_cur && after.rlim_max == parent_limit.rlim_max);
    assert(close(high) == 0 && close(extra) == 0 && close(gate[1]) == 0 && close(status_pipe[0]) == 0);
    printf("%s: high_fd=%d parent_fds_and_limits_unchanged\n", mode, high);
    return 0;
}
#endif
static void native_unsupported(void)
{
#if !defined(__APPLE__)
    struct td_record scratch[16]; struct td_plan p = plan(scratch); struct td_error e;
    assert(td_native_operations()->supported == 0);
    assert(td_close_in_owned_child(&p, (uint64_t)getpid(), td_native_operations(), &e) == -1);
    error_is(e, TD_STAGE_OPERATIONS, TD_REASON_UNSUPPORTED, ENOTSUP, 0);
#endif
}
int main(int argc, char **argv)
{
    assert(argc == 2);
    const struct { const char *name; void (*run)(void); } cases[] = {
        {"success", success}, {"plan-bounds", plan_bounds}, {"preflight", preflight},
        {"child-signals", child_and_signals}, {"response-bounds", response_bounds},
        {"initial-records", initial_records}, {"close-failures", close_failures},
        {"rescan", rescan}, {"error-reset", error_reset}, {"native-unsupported", native_unsupported}
    };
#if defined(__APPLE__)
    if (strncmp(argv[1], "native-", 7) == 0 && strcmp(argv[1], "native-unsupported") != 0)
        return native_case(argv[1]);
#endif
    for (size_t i = 0; i < sizeof(cases) / sizeof(cases[0]); i++)
        if (strcmp(argv[1], cases[i].name) == 0) { cases[i].run(); puts(cases[i].name); return 0; }
    return 2;
}
