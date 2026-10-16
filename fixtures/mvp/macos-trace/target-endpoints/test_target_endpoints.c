#ifndef _GNU_SOURCE
#define _GNU_SOURCE 1
#endif
#include "target_endpoints.h"
#include <assert.h>
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/resource.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

struct mock {
    int status[64], flags[64]; enum te_kind kind[64];
    int sequence, duplicates, mappings, settings;
    unsigned source_modes, source_kinds;
    char failed_operation; int failed_fd, failure_result, failure_errno;
    int duplicate_result, retained_stdio_cloexec, ignored_control_set;
    int signals_result, signals_errno; pid_t self, parent;
};
static struct te_request request(void) { return (struct te_request){{5, 4, 9, 7, 8}}; }
static struct mock mock(void)
{
    struct mock m = {0};
    for (int i = 0; i < 64; i++) { m.status[i] = -1; m.flags[i] = FD_CLOEXEC; m.kind[i] = TE_FIFO; }
    struct te_request r = request();
    for (size_t i = 0; i < 5; i++) m.status[r.source[i]] = i == 0 || i == 3 ? O_RDONLY : O_WRONLY;
    m.status[r.source[3]] |= O_NONBLOCK; m.status[r.source[4]] |= O_NONBLOCK;
    m.status[0] = O_RDONLY; m.status[1] = m.status[2] = O_WRONLY;
    m.flags[0] = m.flags[1] = m.flags[2] = 0;
    m.failed_fd = -1; m.failure_result = -1; m.failure_errno = EIO;
    m.duplicate_result = INT_MIN; m.signals_result = 1; m.self = 222; m.parent = 111;
    return m;
}
static int injected(struct mock *m, char operation, int fd, int *number)
{
    m->sequence++;
    if (m->failed_operation == operation && m->failed_fd == fd) {
        *number = m->failure_errno; return 1;
    }
    return 0;
}
static pid_t self(void *p) { struct mock *m = p; return m->self; }
static pid_t parent(void *p) { struct mock *m = p; return m->parent; }
static int signals(void *p, int *number) { struct mock *m = p; *number = m->signals_errno; return m->signals_result; }
static int getfl(void *p, int fd, int *number)
{
    struct mock *m = p; assert(fd >= 0 && fd < 64);
    if (injected(m, 'f', fd, number)) return m->failure_result;
    struct te_request r = request();
    for (int i = 0; i < 5; i++) if (fd == r.source[i]) m->source_modes |= 1U << i;
    return m->status[fd];
}
static int getfd(void *p, int fd, int *number)
{
    struct mock *m = p; assert(fd >= 0 && fd < 64);
    if (injected(m, 'd', fd, number)) return m->failure_result;
    if (fd < 3 && m->retained_stdio_cloexec) return FD_CLOEXEC;
    if (m->settings && fd >= 23 && m->ignored_control_set) return 0;
    return m->flags[fd];
}
static int setfd(void *p, int fd, int flags, int *number)
{
    struct mock *m = p; assert(fd >= 23 && fd <= 24); m->settings++;
    if (injected(m, 's', fd, number)) return m->failure_result;
    m->flags[fd] = flags; return 0;
}
static int kind(void *p, int fd, enum te_kind *output, int *number)
{
    struct mock *m = p; assert(fd >= 0 && fd < 64);
    if (injected(m, 'k', fd, number)) return m->failure_result;
    struct te_request r = request();
    for (int i = 0; i < 5; i++) if (fd == r.source[i]) m->source_kinds |= 1U << i;
    *output = m->kind[fd]; return 0;
}
static int duplicate(void *p, int fd, int minimum, int *number)
{
    struct mock *m = p; assert(minimum == 3);
    if (!m->duplicates) assert(m->source_modes == 31 && m->source_kinds == 31);
    m->duplicates++;
    if (injected(m, 'a', fd, number)) return m->failure_result;
    if (m->duplicate_result != INT_MIN) return m->duplicate_result;
    int result = 19 + m->duplicates;
    m->status[result] = m->status[fd]; m->kind[result] = m->kind[fd]; m->flags[result] = FD_CLOEXEC;
    return result;
}
static int map(void *p, int fd, int destination, int *number)
{
    struct mock *m = p; assert(fd >= 20 && fd <= 22 && destination == fd - 20);
    m->mappings++;
    if (injected(m, 'm', destination, number)) return m->failure_result;
    m->status[destination] = m->status[fd]; m->kind[destination] = m->kind[fd]; m->flags[destination] = 0;
    return destination;
}
static struct te_operations operations(struct mock *m)
{ return (struct te_operations){m, self, parent, signals, getfl, getfd, setfd, kind, duplicate, map}; }
static void error_is(struct te_error e, enum te_stage stage, enum te_reason reason, int number, int attempted)
{
    assert(e.stage == stage && e.reason == reason && e.system_errno == number && e.mutation_attempted == attempted);
}
static struct te_prepared prepared(struct mock *m)
{
    struct te_request r = request(); struct te_operations o = operations(m); struct te_prepared p; struct te_error e;
    assert(te_prepare_owned_sources(&r, &o, &p, &e) == 0);
    return p;
}
static void success(void)
{
    struct mock m = mock(); struct mock original = m;
    struct te_request r = request(); struct te_operations o = operations(&m); struct te_prepared p; struct te_error e;
    assert(te_prepare_owned_sources(&r, &o, &p, &e) == 0 && p.ready && p.owned_count == 5);
    assert(m.duplicates == 5 && !m.mappings && !m.settings);
    for (size_t i = 0; i < 5; i++) {
        assert(p.copies[i] == 20 + (int)i);
        assert(m.status[r.source[i]] == original.status[r.source[i]]);
        assert(m.flags[r.source[i]] == original.flags[r.source[i]]);
    }
    assert(te_map_in_owned_child(&p, 111, &o, &e) == 0);
    assert(m.mappings == 3 && m.settings == 2 && !e.ownership_uncertain);
    error_is(e, TE_STAGE_NONE, TE_REASON_NONE, 0, 1);
}
static void requests(void)
{
    struct mock m = mock(); struct te_operations o = operations(&m); struct te_prepared p; struct te_error e;
    assert(te_prepare_owned_sources(NULL, &o, &p, &e) == -1 && !m.sequence);
    assert(te_prepare_owned_sources(NULL, &o, NULL, &e) == -1 && !m.sequence);
    assert(te_prepare_owned_sources(NULL, &o, &p, NULL) == -1 && !m.sequence);
    for (int i = 0; i < 5; i++) {
        struct te_request r = request(); r.source[i] = -1;
        assert(te_prepare_owned_sources(&r, &o, &p, &e) == -1 && !m.sequence && !p.owned_count);
        assert(e.stage == TE_STAGE_REQUEST && !e.mutation_attempted);
    }
    struct te_request r = request(); r.source[2] = r.source[1];
    assert(te_prepare_owned_sources(&r, &o, &p, &e) == -1 && !m.sequence);
    error_is(e, TE_STAGE_REQUEST, TE_REASON_DUPLICATE, 0, 0);
    r = request();
    for (int missing = 0; missing < 9; missing++) {
        o = operations(&m);
        switch (missing) {
        case 0: o.getpid_fn = NULL; break; case 1: o.getppid_fn = NULL; break;
        case 2: o.signals_blocked_fn = NULL; break; case 3: o.getfl_fn = NULL; break;
        case 4: o.getfd_fn = NULL; break; case 5: o.setfd_fn = NULL; break;
        case 6: o.kind_fn = NULL; break; case 7: o.duplicate_fn = NULL; break; case 8: o.dup2_fn = NULL; break;
        }
        assert(te_prepare_owned_sources(&r, &o, &p, &e) == -1 && !m.sequence);
        error_is(e, TE_STAGE_OPERATIONS, TE_REASON_ARGUMENT, 0, 0);
    }
}
static void roles(void)
{
    struct te_request r = request(); struct te_prepared p; struct te_error e;
    for (int role = 0; role < 5; role++) {
        struct mock m = mock(); struct te_operations o = operations(&m); m.status[r.source[role]] = O_RDWR;
        assert(te_prepare_owned_sources(&r, &o, &p, &e) == -1 && !m.duplicates && !p.owned_count);
        error_is(e, TE_STAGE_SOURCE, TE_REASON_DIRECTION, 0, 0);
        m = mock(); m.kind[r.source[role]] = TE_OTHER;
        assert(te_prepare_owned_sources(&r, &o, &p, &e) == -1 && !m.duplicates);
        error_is(e, TE_STAGE_SOURCE, TE_REASON_SHAPE, 0, 0);
        m = mock(); m.kind[r.source[role]] = TE_CHARACTER;
        if (role == 0) assert(te_prepare_owned_sources(&r, &o, &p, &e) == 0);
        else assert(te_prepare_owned_sources(&r, &o, &p, &e) == -1 && !m.duplicates);
        m = mock(); m.kind[r.source[role]] = TE_REGULAR;
        if (role < 3) assert(te_prepare_owned_sources(&r, &o, &p, &e) == 0);
        else assert(te_prepare_owned_sources(&r, &o, &p, &e) == -1 && !m.duplicates);
        m = mock();
        if (role < 3) m.status[r.source[role]] |= O_NONBLOCK;
        else m.status[r.source[role]] &= ~O_NONBLOCK;
        assert(te_prepare_owned_sources(&r, &o, &p, &e) == -1 && !m.duplicates);
        error_is(e, TE_STAGE_SOURCE, TE_REASON_POLICY, 0, 0);
    }
}
static void preparation_failures(void)
{
    struct te_request r = request(); struct te_prepared p; struct te_error e;
    for (int role = 0; role < 5; role++) {
        for (int operation = 0; operation < 2; operation++) {
            struct mock m = mock(); struct te_operations o = operations(&m);
            m.failed_operation = operation == 0 ? 'f' : 'k'; m.failed_fd = r.source[role]; m.failure_errno = EBADF;
            assert(te_prepare_owned_sources(&r, &o, &p, &e) == -1 && !m.duplicates && !p.owned_count && !p.ready);
            error_is(e, TE_STAGE_SOURCE, TE_REASON_SYSCALL, EBADF, 0);
        }
        struct mock m = mock(); struct te_operations o = operations(&m);
        m.failed_operation = 'a'; m.failed_fd = r.source[role]; m.failure_errno = EMFILE;
        assert(te_prepare_owned_sources(&r, &o, &p, &e) == -1 && p.owned_count == (size_t)role && !p.ready);
        error_is(e, TE_STAGE_DUPLICATE, TE_REASON_SYSCALL, EMFILE, 1);
        assert(!e.ownership_uncertain);
        for (int i = 0; i < role; i++) assert(p.copies[i] == 20 + i);
        for (int i = role; i < 5; i++) assert(p.copies[i] == -1);
        assert(te_map_in_owned_child(&p, 111, &o, &e) == -1 && !m.mappings);
        error_is(e, TE_STAGE_REQUEST, TE_REASON_PARTIAL_PLAN, 0, 0);
    }
    for (int operation = 0; operation < 3; operation++) {
        struct mock m = mock(); struct te_operations o = operations(&m);
        m.failed_operation = operation == 0 ? 'f' : operation == 1 ? 'k' : 'd'; m.failed_fd = 22;
        assert(te_prepare_owned_sources(&r, &o, &p, &e) == -1 && p.owned_count == 3 && !p.ready);
        error_is(e, TE_STAGE_COPY, TE_REASON_SYSCALL, EIO, 1);
        assert(p.copies[2] == 22 && !e.ownership_uncertain);
    }
}
static void uncertain_ownership(void)
{
    struct te_request r = request(); struct te_prepared p; struct te_error e;
    const int returns[] = {0, 1, 2, 5, 4, 9, 7, 8, -2, -1};
    for (size_t i = 0; i < sizeof(returns) / sizeof(returns[0]); i++) {
        struct mock m = mock(); struct te_operations o = operations(&m);
        m.duplicate_result = returns[i];
        assert(te_prepare_owned_sources(&r, &o, &p, &e) == -1 && !p.ready && !p.owned_count);
        assert(e.ownership_uncertain && e.stage == TE_STAGE_DUPLICATE && e.mutation_attempted);
        for (int j = 0; j < 5; j++) assert(p.copies[j] == -1);
    }
    struct mock m = mock(); struct te_operations o = operations(&m);
    m.failed_operation = 'a'; m.failed_fd = r.source[1]; m.failure_result = 20;
    assert(te_prepare_owned_sources(&r, &o, &p, &e) == -1 && p.owned_count == 1 && p.copies[0] == 20);
    assert(e.ownership_uncertain && p.copies[1] == -1);
}
static void child_guards(void)
{
    struct mock m = mock(); struct te_prepared p = prepared(&m); struct te_operations o = operations(&m); struct te_error e;
    struct te_prepared bad = p; bad.copies[0] = 0;
    assert(te_map_in_owned_child(&bad, 111, &o, &e) == -1 && !m.mappings);
    bad = p; bad.copies[4] = bad.copies[3];
    assert(te_map_in_owned_child(&bad, 111, &o, &e) == -1 && !m.mappings);
    bad = p; bad.owned_count = SIZE_MAX;
    assert(te_map_in_owned_child(&bad, 111, &o, &e) == -1 && !m.mappings);
    bad = p; bad.ready = 2;
    assert(te_map_in_owned_child(&bad, 111, &o, &e) == -1 && !m.mappings);
    for (int mode = 0; mode < 6; mode++) {
        m.self = 222; m.parent = 111; m.signals_result = 1;
        uint64_t owner = 111;
        if (mode == 0) owner = 0;
        if (mode == 1) owner = UINT64_MAX;
        if (mode == 2) m.self = 111;
        if (mode == 3) m.parent = 333;
        if (mode == 4) m.signals_result = 0;
        if (mode == 5) { m.signals_result = -1; m.signals_errno = EIO; }
        assert(te_map_in_owned_child(&p, owner, &o, &e) == -1 && !m.mappings && !m.settings && !e.mutation_attempted);
    }
    m = mock(); p = prepared(&m); o = operations(&m); m.flags[24] = 0;
    assert(te_map_in_owned_child(&p, 111, &o, &e) == -1 && !m.mappings);
    error_is(e, TE_STAGE_COPY, TE_REASON_FLAGS, 0, 0);
}
static void mapping_failures(void)
{
    struct te_error e;
    for (int role = 0; role < 3; role++) {
        struct mock m = mock(); struct te_prepared p = prepared(&m); struct te_operations o = operations(&m);
        m.failed_operation = 'm'; m.failed_fd = role; m.failure_errno = EINTR;
        assert(te_map_in_owned_child(&p, 111, &o, &e) == -1 && m.mappings == role + 1 && !m.settings);
        error_is(e, TE_STAGE_MAP, TE_REASON_SYSCALL, EINTR, 1);
    }
    struct mock m = mock(); struct te_prepared p = prepared(&m); struct te_operations o = operations(&m);
    m.retained_stdio_cloexec = 1;
    assert(te_map_in_owned_child(&p, 111, &o, &e) == -1 && m.mappings == 1);
    error_is(e, TE_STAGE_STDIO_FLAGS, TE_REASON_FLAGS, 0, 1);
    for (int role = 3; role < 5; role++) {
        m = mock(); p = prepared(&m); o = operations(&m); m.failed_operation = 's'; m.failed_fd = 20 + role;
        assert(te_map_in_owned_child(&p, 111, &o, &e) == -1 && m.mappings == 3 && m.settings == role - 2);
        error_is(e, TE_STAGE_CONTROL_FLAGS, TE_REASON_SYSCALL, EIO, 1);
    }
    m = mock(); p = prepared(&m); o = operations(&m); m.ignored_control_set = 1;
    assert(te_map_in_owned_child(&p, 111, &o, &e) == -1 && m.mappings == 3 && m.settings == 1);
    error_is(e, TE_STAGE_CONTROL_FLAGS, TE_REASON_FLAGS, 0, 1);
    m = mock(); p = prepared(&m); o = operations(&m); m.failed_operation = 'k'; m.failed_fd = 0;
    assert(te_map_in_owned_child(&p, 111, &o, &e) == -1 && m.settings == 2);
    error_is(e, TE_STAGE_VERIFY, TE_REASON_SYSCALL, EIO, 1);
}
static void error_reset(void)
{
    struct mock m = mock(); struct te_operations o = operations(&m); struct te_request r = request(); struct te_prepared p; struct te_error e;
    memset(&e, 0xa5, sizeof(e)); m.duplicate_result = 0;
    assert(te_prepare_owned_sources(&r, &o, &p, &e) == -1 && e.ownership_uncertain);
    m = mock();
    assert(te_prepare_owned_sources(&r, &o, &p, &e) == 0);
    error_is(e, TE_STAGE_NONE, TE_REASON_NONE, 0, 1);
    assert(!e.ownership_uncertain && e.role == TE_NO_ROLE && e.fd == -1);
    assert(strcmp(te_stage_name(TE_STAGE_MAP), "map") == 0);
    assert(strcmp(te_reason_name(TE_REASON_OWNERSHIP), "ownership") == 0);
}

/* Native controls continue below; no production target is launched. */
static int wait_owned(pid_t child, int *status, int seconds)
{
    struct timespec start, now; assert(clock_gettime(CLOCK_MONOTONIC, &start) == 0);
    for (;;) {
        pid_t result = waitpid(child, status, WNOHANG);
        if (result == child) return 0;
        if (result == -1 && errno == EINTR) continue;
        assert(result == 0);
        assert(clock_gettime(CLOCK_MONOTONIC, &now) == 0);
        if (now.tv_sec - start.tv_sec >= seconds) {
            assert(kill(child, SIGKILL) == 0);
            while (waitpid(child, status, 0) == -1) assert(errno == EINTR);
            return -1;
        }
        const struct timespec pause = {0, 10000000}; nanosleep(&pause, NULL);
    }
}
struct fixture {
    int input[2], output[2], error[2], gate[2], status[2], null_fd;
    int owned[11]; size_t count;
    struct te_request request;
    int original_flags[5], original_status[5];
};
static void add_pipe(struct fixture *f, int pair[2])
{
    assert(pipe(pair) == 0 && f->count + 2 <= 11);
    f->owned[f->count++] = pair[0]; f->owned[f->count++] = pair[1];
}
static struct fixture fixture(int null_input)
{
    struct fixture f = {0}; f.null_fd = -1;
    /* Deliberately create controls first: closing stdio beforehand then places
     * status writer at1 and stdin source at2, exercising numeric source swaps. */
    add_pipe(&f, f.status); add_pipe(&f, f.input); add_pipe(&f, f.output);
    add_pipe(&f, f.error); add_pipe(&f, f.gate);
    /* Both controller and child control ends are prepared before fork. This
     * fixture owns them; the endpoint helper must never change OFD flags. */
    for (int i = 0; i < 2; i++) {
        assert(fcntl(f.status[i], F_SETFL, fcntl(f.status[i], F_GETFL) | O_NONBLOCK) == 0);
        assert(fcntl(f.gate[i], F_SETFL, fcntl(f.gate[i], F_GETFL) | O_NONBLOCK) == 0);
    }
    if (null_input) { f.null_fd = open("/dev/null", O_RDONLY | O_CLOEXEC); assert(f.null_fd >= 0); f.owned[f.count++] = f.null_fd; }
    f.request = (struct te_request){{null_input ? f.null_fd : f.input[0], f.output[1], f.error[1], f.gate[0], f.status[1]}};
    for (size_t i = 0; i < 5; i++) {
        f.original_flags[i] = fcntl(f.request.source[i], F_GETFD);
        f.original_status[i] = fcntl(f.request.source[i], F_GETFL);
        assert(f.original_flags[i] >= 0 && f.original_status[i] >= 0);
    }
    return f;
}
static void close_fixture_fd(struct fixture *f, int fd)
{
    int found = 0;
    for (size_t i = 0; i < f->count; i++) if (f->owned[i] == fd) { f->owned[i] = -1; found = 1; }
    assert(found && close(fd) == 0);
}
static void close_fixture(struct fixture *f)
{
    for (size_t i = 0; i < f->count; i++) if (f->owned[i] >= 0) {
        assert(close(f->owned[i]) == 0); f->owned[i] = -1;
    }
}
static void originals_unchanged(const struct fixture *f)
{
    for (size_t i = 0; i < 5; i++) {
        assert(fcntl(f->request.source[i], F_GETFD) == f->original_flags[i]);
        assert(fcntl(f->request.source[i], F_GETFL) == f->original_status[i]);
    }
}
static void release_known(struct te_prepared *p, const struct te_error *e, const struct te_request *r)
{
    assert(!e->ownership_uncertain && p->owned_count <= 5);
    for (size_t i = 0; i < p->owned_count; i++) {
        assert(p->copies[i] >= 3);
        for (size_t j = 0; j < 5; j++) assert(p->copies[i] != r->source[j]);
        assert(close(p->copies[i]) == 0);
    }
}
struct native_report { int result, good; struct te_error error; };
static void controller(const char *mode)
{
    if (strcmp(mode, "native-closed-stdio") == 0)
        for (int i = 0; i < 3; i++) assert(close(i) == 0);
    const int null_input = strcmp(mode, "native-null-input") == 0;
    struct fixture f = fixture(null_input);
    struct te_prepared prepared; struct te_error error;
    const struct te_operations *ops = te_native_operations();
    if (strcmp(mode, "native-alias-reject") == 0 || strcmp(mode, "native-direction-reject") == 0 || strcmp(mode, "native-invalid-source") == 0) {
        struct te_request bad = f.request;
        if (strcmp(mode, "native-alias-reject") == 0) bad.source[2] = bad.source[1];
        if (strcmp(mode, "native-direction-reject") == 0) bad.source[0] = f.input[1];
        if (strcmp(mode, "native-invalid-source") == 0) bad.source[0] = -1;
        assert(te_prepare_owned_sources(&bad, ops, &prepared, &error) == -1);
        assert(!prepared.ready && !prepared.owned_count && !error.mutation_attempted);
        originals_unchanged(&f); close_fixture(&f); return;
    }
    if (strcmp(mode, "native-partial-emfile") == 0) {
        struct rlimit old; assert(getrlimit(RLIMIT_NOFILE, &old) == 0 && old.rlim_cur >= 64);
        struct rlimit selected = {32, old.rlim_max}; assert(setrlimit(RLIMIT_NOFILE, &selected) == 0);
        int filler[64], count = 0;
        for (;;) {
            int fd = open("/dev/null", O_RDONLY | O_CLOEXEC);
            if (fd == -1) { assert(errno == EMFILE); break; }
            assert(count < 64); filler[count++] = fd;
        }
        assert(count >= 2 && close(filler[--count]) == 0 && close(filler[--count]) == 0);
        assert(te_prepare_owned_sources(&f.request, ops, &prepared, &error) == -1);
        assert(prepared.owned_count == 2 && !prepared.ready && error.role == TE_STDERR);
        error_is(error, TE_STAGE_DUPLICATE, TE_REASON_SYSCALL, EMFILE, 1);
        originals_unchanged(&f); release_known(&prepared, &error, &f.request);
        for (int i = 0; i < count; i++) assert(close(filler[i]) == 0);
        close_fixture(&f); return; /* Limit is not raised/restored; this owned controller exits. */
    }
    assert(te_prepare_owned_sources(&f.request, ops, &prepared, &error) == 0);
    assert(prepared.ready && prepared.owned_count == 5);
    originals_unchanged(&f);
    for (size_t i = 0; i < 5; i++) assert(prepared.copies[i] >= 3 && (fcntl(prepared.copies[i], F_GETFD) & FD_CLOEXEC));
    if (strcmp(mode, "native-copy-flags") == 0)
        assert(fcntl(prepared.copies[3], F_SETFD, 0) == 0);
    assert(write(f.input[1], "I", 1) == 1 && write(f.gate[1], "G", 1) == 1);
    pid_t owner = getpid(), child = fork(); assert(child >= 0);
    if (child == 0) {
        sigset_t mask; assert(sigfillset(&mask) == 0 && sigprocmask(SIG_SETMASK, &mask, NULL) == 0);
        if (strcmp(mode, "native-map-limit") == 0) {
            struct rlimit limit = {1, 1}; assert(setrlimit(RLIMIT_NOFILE, &limit) == 0);
        }
        struct native_report report;
        report.result = te_map_in_owned_child(&prepared, (uint64_t)owner, ops, &report.error);
        report.good = 0;
        if (strcmp(mode, "native-map-limit") == 0) {
            report.good = report.result == -1 && report.error.stage == TE_STAGE_MAP &&
                report.error.reason == TE_REASON_SYSCALL && report.error.role == TE_STDOUT &&
                report.error.system_errno == EBADF && report.error.mutation_attempted;
        } else if (strcmp(mode, "native-copy-flags") == 0) {
            report.good = report.result == -1 && report.error.stage == TE_STAGE_COPY &&
                report.error.reason == TE_REASON_FLAGS && !report.error.mutation_attempted;
        } else if (report.result == 0) {
            char byte = 0;
            ssize_t input = read(0, &byte, 1);
            report.good = null_input ? input == 0 : input == 1 && byte == 'I';
            report.good = report.good && write(1, "O", 1) == 1 && write(2, "E", 1) == 1;
            report.good = report.good && read(prepared.copies[3], &byte, 1) == 1 && byte == 'G';
            for (int i = 0; i < 3; i++) report.good = report.good && !(fcntl(i, F_GETFD) & FD_CLOEXEC);
            for (int i = 3; i < 5; i++) report.good = report.good && (fcntl(prepared.copies[i], F_GETFD) & FD_CLOEXEC);
        }
        /* Fixed test report only; no target, gate protocol or exec is implemented. */
        ssize_t written = write(prepared.copies[4], &report, sizeof(report));
        _exit(report.good && written == sizeof(report) ? 0 : 1);
    }
    /* Close every controller-side writer alias before waiting/reading, so a
     * failed child yields EOF instead of a read hung by our own writer. */
    release_known(&prepared, &error, &f.request);
    for (size_t i = 0; i < 5; i++) close_fixture_fd(&f, f.request.source[i]);
    close_fixture_fd(&f, f.input[1]); close_fixture_fd(&f, f.gate[1]);
    int status = 0, waited = wait_owned(child, &status, 5);
    struct native_report report;
    ssize_t bytes = read(f.status[0], &report, sizeof(report));
    assert(waited == 0 && WIFEXITED(status) && WEXITSTATUS(status) == 0 && bytes == sizeof(report) && report.good);
    if (strcmp(mode, "native-map-limit") != 0 && strcmp(mode, "native-copy-flags") != 0) {
        char byte = 0;
        assert(read(f.output[0], &byte, 1) == 1 && byte == 'O');
        assert(read(f.error[0], &byte, 1) == 1 && byte == 'E');
    }
    close_fixture(&f);
}
static int native_case(const char *mode)
{
    if (getuid() == 0 || geteuid() == 0) return 77;
    struct rlimit before, after; assert(getrlimit(RLIMIT_NOFILE, &before) == 0);
    if (before.rlim_cur < 64) return 77;
    int flags[3]; for (int i = 0; i < 3; i++) { flags[i] = fcntl(i, F_GETFD); assert(flags[i] >= 0); }
    int sentinel = open("/dev/null", O_RDONLY | O_CLOEXEC); assert(sentinel >= 3);
    int sentinel_flags = fcntl(sentinel, F_GETFD);
    int completion[2]; assert(pipe(completion) == 0);
    pid_t owned_controller = fork(); assert(owned_controller >= 0);
    if (owned_controller == 0) {
        assert(close(completion[0]) == 0);
        controller(mode);
        assert(write(completion[1], "P", 1) == 1);
        _exit(0);
    }
    assert(close(completion[1]) == 0);
    int status = 0, waited = wait_owned(owned_controller, &status, 10);
    char done = 0; ssize_t bytes = read(completion[0], &done, 1);
    assert(waited == 0 && WIFEXITED(status) && WEXITSTATUS(status) == 0 && bytes == 1 && done == 'P');
    assert(close(completion[0]) == 0 && fcntl(sentinel, F_GETFD) == sentinel_flags && close(sentinel) == 0);
    assert(getrlimit(RLIMIT_NOFILE, &after) == 0 && before.rlim_cur == after.rlim_cur && before.rlim_max == after.rlim_max);
    for (int i = 0; i < 3; i++) assert(fcntl(i, F_GETFD) == flags[i]);
    printf("%s: owned_controller_and_child_only enclosing_parent_stdio_limits_sentinel_unchanged\n", mode);
    return 0;
}
int main(int argc, char **argv)
{
    assert(argc == 2);
    const struct { const char *name; void (*run)(void); } cases[] = {
        {"success", success}, {"requests", requests}, {"roles", roles},
        {"preparation-failures", preparation_failures}, {"uncertain-ownership", uncertain_ownership},
        {"child-guards", child_guards}, {"mapping-failures", mapping_failures}, {"error-reset", error_reset}
    };
    for (size_t i = 0; i < sizeof(cases) / sizeof(cases[0]); i++)
        if (strcmp(argv[1], cases[i].name) == 0) { cases[i].run(); puts(cases[i].name); return 0; }
    const char *native[] = {"native-basic", "native-closed-stdio", "native-null-input", "native-alias-reject",
        "native-direction-reject", "native-invalid-source", "native-partial-emfile", "native-map-limit", "native-copy-flags"};
    for (size_t i = 0; i < sizeof(native) / sizeof(native[0]); i++)
        if (strcmp(argv[1], native[i]) == 0) return native_case(argv[1]);
    return 2;
}
