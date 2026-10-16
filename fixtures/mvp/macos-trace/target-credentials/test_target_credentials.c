#include "target_credentials.h"

#include <assert.h>
#include <errno.h>
#include <limits.h>
#include <stdio.h>
#include <string.h>
#include <sys/wait.h>
#include <unistd.h>

struct mock {
    char calls[64];
    size_t used;
    char fail_call;
    char mismatch_call;
    int fail_result;
    int fail_errno;
    int count;
    pid_t pid, ppid;
    gid_t observed[TC_MAX_GROUPS];
};
static struct tc_request request(void)
{ return (struct tc_request){501, 20, 3, {20, 0, 80}}; }
static struct mock mock(void)
{
    struct mock m = {0};
    m.fail_result = -1; m.fail_errno = EACCES; m.count = 3;
    m.pid = 222; m.ppid = 111;
    m.observed[0] = 20; m.observed[1] = 0; m.observed[2] = 80;
    return m;
}
static void record(struct mock *m, char call)
{
    assert(m->used + 1 < sizeof(m->calls));
    m->calls[m->used++] = call;
    m->calls[m->used] = 0;
}
static int result(struct mock *m, char call, int *error)
{
    record(m, call);
    if (m->fail_call == call) { *error = m->fail_errno; return m->fail_result; }
    return 0;
}
static pid_t pid(void *p) { struct mock *m = p; record(m, 'p'); return m->pid; }
static pid_t ppid(void *p) { struct mock *m = p; record(m, 'P'); return m->ppid; }
static int groups(void *p, size_t n, const gid_t *g, int *e)
{
    assert(n == 3 && g[0] == 20 && g[1] == 0 && g[2] == 80);
    return result(p, 's', e);
}
static int gid(void *p, gid_t g, int *e) { assert(g == 20); return result(p, 'g', e); }
static int uid(void *p, uid_t u, int *e) { assert(u == 501); return result(p, 'u', e); }
static uid_t ruid(void *p)
{ struct mock *m = p; record(m, 'r'); return m->mismatch_call == 'r' ? 0 : 501; }
static uid_t euid(void *p)
{ struct mock *m = p; record(m, 'e'); return m->mismatch_call == 'e' ? 0 : 501; }
static gid_t rgid(void *p)
{ struct mock *m = p; record(m, 'R'); return m->mismatch_call == 'R' ? 0 : 20; }
static gid_t egid(void *p)
{ struct mock *m = p; record(m, 'E'); return m->mismatch_call == 'E' ? 0 : 20; }
static int read_groups(void *p, int capacity, gid_t *out, int *e)
{
    struct mock *m = p;
    assert(capacity == TC_MAX_GROUPS);
    int r = result(m, 'v', e);
    if (r != 0) return r;
    for (int i = 0; i < m->count && i < capacity; i++) out[i] = m->observed[i];
    return m->count;
}
static struct tc_operations operations(struct mock *m)
{
    return (struct tc_operations){m, pid, ppid, groups, gid, uid,
        ruid, euid, rgid, egid, read_groups};
}
static void error_is(struct tc_error e, enum tc_stage s, enum tc_reason r,
                     int number, int attempted)
{
    assert(e.stage == s && e.reason == r && e.system_errno == number);
    assert(e.mutation_attempted == attempted);
}
static struct tc_decimal token(const char *s)
{ return (struct tc_decimal){s, strlen(s)}; }
static void success(void)
{
    struct tc_request r = request(); struct mock m = mock();
    struct tc_operations o = operations(&m); struct tc_error e;
    assert(tc_drop_in_owned_child(&r, 111, &o, &e) == 0);
    assert(strcmp(m.calls, "pPsgureREv") == 0);
    error_is(e, TC_STAGE_NONE, TC_REASON_NONE, 0, 1);
    /* Explicit supplementary GID 0 is neither synthesized nor removed. */
    assert(r.groups[1] == 0);
}
static void numeric_boundaries(void)
{
    struct tc_request r = request(); struct tc_error e;
    r.uid = r.gid = TC_ID_MAX; r.group_count = TC_MAX_GROUPS; r.groups[0] = TC_ID_MAX;
    for (size_t i = 1; i < TC_MAX_GROUPS; i++) r.groups[i] = i - 1;
    assert(tc_validate_request(&r, &e) == 0);
    const uint64_t bad[] = {0, TC_ID_MAX + 1, UINT32_MAX, UINT64_MAX};
    for (size_t i = 0; i < sizeof(bad) / sizeof(bad[0]); i++) {
        r = request(); r.uid = bad[i]; assert(tc_validate_request(&r, &e) == -1);
        error_is(e, TC_STAGE_REQUEST, TC_REASON_RANGE, 0, 0);
        r = request(); r.gid = bad[i]; assert(tc_validate_request(&r, &e) == -1);
    }
    r = request(); r.groups[2] = TC_ID_MAX + 1;
    assert(tc_validate_request(&r, &e) == -1 && e.group_index == 2);
    r.groups[2] = UINT64_MAX;
    assert(tc_validate_request(&r, &e) == -1);
}
static void vector_boundaries(void)
{
    struct tc_request r; struct tc_error e;
    const size_t bad[] = {0, TC_MAX_GROUPS + 1, SIZE_MAX};
    for (size_t i = 0; i < sizeof(bad) / sizeof(bad[0]); i++) {
        r = request(); r.group_count = bad[i];
        assert(tc_validate_request(&r, &e) == -1);
        error_is(e, TC_STAGE_REQUEST, TC_REASON_RANGE, 0, 0);
    }
    r = request(); r.groups[1] = 20;
    assert(tc_validate_request(&r, &e) == -1 && e.group_index == 1);
    error_is(e, TC_STAGE_REQUEST, TC_REASON_DUPLICATE, 0, 0);
    r = request(); r.groups[0] = 19;
    assert(tc_validate_request(&r, &e) == -1 && e.group_index == 0);
    error_is(e, TC_STAGE_REQUEST, TC_REASON_PRIMARY_GROUP, 0, 0);
}
static void parse(void)
{
    struct tc_request r; struct tc_error e;
    struct tc_decimal g[] = {token("20"), token("0"), token("80")};
    assert(tc_parse_request(token("501"), token("20"), g, 3, &r, &e) == 0);
    assert(r.uid == 501 && r.gid == 20 && r.group_count == 3 && r.groups[1] == 0);
    const char *bad[] = {"", "-1", "+1", " 1", "1 ", "01", "1.0", "1e3", "true",
        "null", "4294967295", "2147483648", "99999999999999999999", "1\n", "é"};
    for (size_t i = 0; i < sizeof(bad) / sizeof(bad[0]); i++) {
        r = request();
        assert(tc_parse_request(token(bad[i]), token("20"), g, 3, &r, &e) == -1);
        assert(r.uid == 0 && r.group_count == 0 && !e.mutation_attempted);
        assert(tc_parse_request(token("501"), token(bad[i]), g, 3, &r, &e) == -1);
        struct tc_decimal original = g[2]; g[2] = token(bad[i]);
        assert(tc_parse_request(token("501"), token("20"), g, 3, &r, &e) == -1);
        assert(e.group_index == 2); g[2] = original;
    }
    const char embedded[] = {'1', 0, '2'};
    assert(tc_parse_request((struct tc_decimal){embedded, 3}, token("20"), g, 3, &r, &e) == -1);
    assert(tc_parse_request((struct tc_decimal){NULL, 1}, token("20"), g, 3, &r, &e) == -1);
    assert(tc_parse_request((struct tc_decimal){"1", SIZE_MAX}, token("20"), g, 3, &r, &e) == -1);
}
static void no_mutation(void)
{
    struct mock m = mock(); struct tc_operations o = operations(&m);
    struct tc_request r = request(); struct tc_error e;
    assert(tc_drop_in_owned_child(NULL, 111, &o, &e) == -1);
    assert(tc_drop_in_owned_child(&r, 111, &o, NULL) == -1);
    r.uid = 0; assert(tc_drop_in_owned_child(&r, 111, &o, &e) == -1);
    assert(!m.used); r = request();
    assert(tc_drop_in_owned_child(&r, 111, NULL, &e) == -1);
    error_is(e, TC_STAGE_OPERATIONS, TC_REASON_ARGUMENT, 0, 0);
    for (int missing = 0; missing < 10; missing++) {
        o = operations(&m);
        switch (missing) {
        case 0: o.getpid_fn = NULL; break;
        case 1: o.getppid_fn = NULL; break;
        case 2: o.setgroups_fn = NULL; break;
        case 3: o.setgid_fn = NULL; break;
        case 4: o.setuid_fn = NULL; break;
        case 5: o.getuid_fn = NULL; break;
        case 6: o.geteuid_fn = NULL; break;
        case 7: o.getgid_fn = NULL; break;
        case 8: o.getegid_fn = NULL; break;
        case 9: o.getgroups_fn = NULL; break;
        }
        assert(tc_drop_in_owned_child(&r, 111, &o, &e) == -1 && !m.used);
        error_is(e, TC_STAGE_OPERATIONS, TC_REASON_ARGUMENT, 0, 0);
    }
}
static void child_guard(void)
{
    struct tc_request r = request(); struct tc_error e;
    const uint64_t bad[] = {0, (uint64_t)INT_MAX + 1, UINT64_MAX};
    for (size_t i = 0; i < sizeof(bad) / sizeof(bad[0]); i++) {
        struct mock m = mock(); struct tc_operations o = operations(&m);
        assert(tc_drop_in_owned_child(&r, bad[i], &o, &e) == -1 && !m.used);
        error_is(e, TC_STAGE_CHILD, TC_REASON_RANGE, 0, 0);
    }
    for (int mode = 0; mode < 4; mode++) {
        struct mock m = mock(); struct tc_operations o = operations(&m);
        if (mode == 0) m.pid = 111;
        if (mode == 1) m.ppid = 333;
        if (mode == 2) m.pid = -1;
        if (mode == 3) m.ppid = 0;
        assert(tc_drop_in_owned_child(&r, 111, &o, &e) == -1);
        assert(strcmp(m.calls, "pP") == 0);
        error_is(e, TC_STAGE_CHILD, TC_REASON_NOT_OWNED_CHILD, 0, 0);
    }
}
static void syscall_failures(void)
{
    const char calls[] = "sguv";
    const enum tc_stage stages[] = {TC_STAGE_SETGROUPS, TC_STAGE_SETGID, TC_STAGE_SETUID, TC_STAGE_GROUPS};
    const char *prefixes[] = {"pPs", "pPsg", "pPsgu", "pPsgureREv"};
    for (size_t i = 0; i < 4; i++) {
        struct mock m = mock(); struct tc_operations o = operations(&m);
        struct tc_request r = request(); struct tc_error e;
        m.fail_call = calls[i]; m.fail_errno = i % 2 == 0 ? EPERM : EINTR;
        assert(tc_drop_in_owned_child(&r, 111, &o, &e) == -1);
        assert(strcmp(m.calls, prefixes[i]) == 0);
        error_is(e, stages[i], TC_REASON_SYSCALL, m.fail_errno, 1);
    }
}
static void adapter_failures(void)
{
    const char calls[] = "sguv";
    for (size_t i = 0; i < 4; i++) for (int mode = 0; mode < 3; mode++) {
        struct mock m = mock(); struct tc_operations o = operations(&m);
        struct tc_request r = request(); struct tc_error e;
        m.fail_call = calls[i]; m.fail_result = mode == 0 ? -2 : mode == 1 ? 1 : -1;
        m.fail_errno = mode == 2 ? 0 : EIO;
        if (calls[i] == 'v' && mode == 1) continue; /* Positive getgroups is a count. */
        assert(tc_drop_in_owned_child(&r, 111, &o, &e) == -1);
        assert(e.reason == TC_REASON_ADAPTER && e.system_errno == 0 && e.mutation_attempted);
    }
    struct mock m = mock(); m.count = TC_MAX_GROUPS + 1;
    struct tc_operations o = operations(&m); struct tc_request r = request(); struct tc_error e;
    assert(tc_drop_in_owned_child(&r, 111, &o, &e) == -1);
    error_is(e, TC_STAGE_GROUPS, TC_REASON_ADAPTER, 0, 1);
}
static void id_verification(void)
{
    const char calls[] = "reRE";
    const enum tc_stage stages[] = {TC_STAGE_REAL_UID, TC_STAGE_EFFECTIVE_UID,
        TC_STAGE_REAL_GID, TC_STAGE_EFFECTIVE_GID};
    const char *prefixes[] = {"pPsgur", "pPsgure", "pPsgureR", "pPsgureRE"};
    for (size_t i = 0; i < 4; i++) {
        struct mock m = mock(); struct tc_operations o = operations(&m);
        struct tc_request r = request(); struct tc_error e; m.mismatch_call = calls[i];
        assert(tc_drop_in_owned_child(&r, 111, &o, &e) == -1);
        assert(strcmp(m.calls, prefixes[i]) == 0);
        error_is(e, stages[i], TC_REASON_MISMATCH, 0, 1);
    }
}
static void exact_groups(void)
{
    for (int mode = 0; mode < 5; mode++) {
        struct mock m = mock(); struct tc_operations o = operations(&m);
        struct tc_request r = request(); struct tc_error e;
        if (mode == 0) m.count = 0;
        if (mode == 1) m.count = 2;
        if (mode == 2) { m.count = 4; m.observed[3] = 99; }
        if (mode == 3) { m.observed[1] = 80; m.observed[2] = 0; }
        if (mode == 4) m.observed[1] = 1;
        assert(tc_drop_in_owned_child(&r, 111, &o, &e) == -1);
        error_is(e, TC_STAGE_GROUPS, TC_REASON_MISMATCH, 0, 1);
        assert(e.group_index == (mode >= 3 ? 1 : TC_NO_GROUP_INDEX));
    }
}
static void parse_pointer_bounds(void)
{
    struct tc_request r; struct tc_error e;
    struct tc_decimal g[] = {token("20")};
    assert(tc_parse_request(token("501"), token("20"), NULL, 1, &r, &e) == -1);
    assert(tc_parse_request(token("501"), token("20"), g, SIZE_MAX, &r, &e) == -1);
    assert(tc_parse_request(token("501"), token("20"), g, 1, NULL, &e) == -1);
    assert(tc_parse_request(token("501"), token("20"), g, 1, &r, NULL) == -1);
    assert(tc_validate_request(NULL, &e) == -1 && !e.mutation_attempted);
    assert(tc_validate_request(&r, NULL) == -1);
    assert(strcmp(tc_stage_name(TC_STAGE_SETUID), "setuid") == 0);
    assert(strcmp(tc_reason_name(TC_REASON_SYSCALL), "syscall") == 0);
    assert(strcmp(tc_stage_name((enum tc_stage)-1), "unknown") == 0);
}
static void error_reset(void)
{
    struct tc_request r = request(); struct tc_error e;
    memset(&e, 0xa5, sizeof(e));
    assert(tc_validate_request(&r, &e) == 0);
    error_is(e, TC_STAGE_NONE, TC_REASON_NONE, 0, 0);
    assert(e.group_index == TC_NO_GROUP_INDEX);
    struct mock m = mock(); m.fail_call = 'u';
    struct tc_operations o = operations(&m);
    assert(tc_drop_in_owned_child(&r, 111, &o, &e) == -1 && e.mutation_attempted);
    assert(tc_validate_request(&r, &e) == 0);
    error_is(e, TC_STAGE_NONE, TC_REASON_NONE, 0, 0);
    assert(e.group_index == TC_NO_GROUP_INDEX);
    struct tc_decimal g[] = {token("20")};
    assert(tc_parse_request(token("501"), token("20"), g, 1, &r, &e) == 0);
    error_is(e, TC_STAGE_NONE, TC_REASON_NONE, 0, 0);
}
static int native_denied(void)
{
    /* No privileged host mutation is permitted by this test. */
    if (geteuid() == 0 || getuid() == 0) return 77;
    const uid_t before_uid = getuid(), before_euid = geteuid();
    const gid_t before_gid = getgid(), before_egid = getegid();
    const pid_t controller = getpid();
    pid_t child = fork(); assert(child >= 0);
    if (child == 0) {
        struct tc_request r = request(); struct tc_error e;
        int rc = tc_drop_in_owned_child(&r, (uint64_t)controller, tc_native_operations(), &e);
        _exit(rc == -1 && e.stage == TC_STAGE_SETGROUPS && e.reason == TC_REASON_SYSCALL &&
              e.system_errno == EPERM && e.mutation_attempted && getuid() == before_uid &&
              geteuid() == before_euid && getgid() == before_gid && getegid() == before_egid ? 0 : 1);
    }
    int status = 0; assert(waitpid(child, &status, 0) == child);
    assert(WIFEXITED(status) && WEXITSTATUS(status) == 0);
    assert(getuid() == before_uid && geteuid() == before_euid);
    assert(getgid() == before_gid && getegid() == before_egid);
    return 0;
}
static void native_parent_guard(void)
{
    struct tc_request r = request(); struct tc_error e;
    assert(tc_drop_in_owned_child(&r, (uint64_t)getpid(), tc_native_operations(), &e) == -1);
    error_is(e, TC_STAGE_CHILD, TC_REASON_NOT_OWNED_CHILD, 0, 0);
}
int main(int argc, char **argv)
{
    alarm(5);
    assert(argc == 2);
    const struct { const char *name; void (*run)(void); } cases[] = {
        {"success", success}, {"numeric-boundaries", numeric_boundaries},
        {"vector-boundaries", vector_boundaries}, {"parse", parse},
        {"no-mutation", no_mutation}, {"child-guard", child_guard},
        {"syscall-failures", syscall_failures}, {"adapter-failures", adapter_failures},
        {"id-verification", id_verification}, {"exact-groups", exact_groups},
        {"parse-pointer-bounds", parse_pointer_bounds}, {"error-reset", error_reset},
        {"native-parent-guard", native_parent_guard}
    };
    if (strcmp(argv[1], "native-denied") == 0) return native_denied();
    for (size_t i = 0; i < sizeof(cases) / sizeof(cases[0]); i++)
        if (strcmp(argv[1], cases[i].name) == 0) { cases[i].run(); puts(cases[i].name); return 0; }
    return 2;
}
