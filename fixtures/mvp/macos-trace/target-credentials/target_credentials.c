#ifndef _DEFAULT_SOURCE
#define _DEFAULT_SOURCE 1
#endif
#include "target_credentials.h"

#include <errno.h>
#include <grp.h>
#include <limits.h>
#include <unistd.h>

_Static_assert(NGROUPS_MAX >= TC_MAX_GROUPS, "native group limit below API bound");
_Static_assert(sizeof(uid_t) <= sizeof(uint64_t), "uid_t too wide");
_Static_assert(sizeof(gid_t) <= sizeof(uint64_t), "gid_t too wide");

static int fail(struct tc_error *error, enum tc_stage stage, enum tc_reason reason,
                int system_errno, size_t index)
{
    if (error != NULL) {
        error->stage = stage;
        error->reason = reason;
        error->system_errno = system_errno;
        error->group_index = index;
    }
    return -1;
}

static void clear_error(struct tc_error *error)
{
    *error = (struct tc_error){TC_STAGE_NONE, TC_REASON_NONE, 0, TC_NO_GROUP_INDEX, 0};
}

int tc_validate_request(const struct tc_request *request, struct tc_error *error)
{
    if (error == NULL) return -1;
    clear_error(error);
    if (request == NULL)
        return fail(error, TC_STAGE_REQUEST, TC_REASON_ARGUMENT, 0, TC_NO_GROUP_INDEX);
    if (request->uid == 0 || request->uid > TC_ID_MAX ||
        (uint64_t)(uid_t)request->uid != request->uid ||
        request->gid == 0 || request->gid > TC_ID_MAX ||
        (uint64_t)(gid_t)request->gid != request->gid)
        return fail(error, TC_STAGE_REQUEST, TC_REASON_RANGE, 0, TC_NO_GROUP_INDEX);
    if (request->group_count == 0 || request->group_count > TC_MAX_GROUPS)
        return fail(error, TC_STAGE_REQUEST, TC_REASON_RANGE, 0, TC_NO_GROUP_INDEX);
    for (size_t i = 0; i < request->group_count; i++) {
        if (request->groups[i] > TC_ID_MAX ||
            (uint64_t)(gid_t)request->groups[i] != request->groups[i])
            return fail(error, TC_STAGE_REQUEST, TC_REASON_RANGE, 0, i);
        for (size_t j = 0; j < i; j++)
            if (request->groups[j] == request->groups[i])
                return fail(error, TC_STAGE_REQUEST, TC_REASON_DUPLICATE, 0, i);
    }
    if (request->groups[0] != request->gid)
        return fail(error, TC_STAGE_REQUEST, TC_REASON_PRIMARY_GROUP, 0, 0);
    return 0;
}

static int decimal(struct tc_decimal token, uint64_t *output, struct tc_error *error,
                   size_t index)
{
    if (token.bytes == NULL || token.length == 0 || token.length > 10)
        return fail(error, TC_STAGE_REQUEST, TC_REASON_SYNTAX, 0, index);
    if (token.length > 1 && token.bytes[0] == '0')
        return fail(error, TC_STAGE_REQUEST, TC_REASON_SYNTAX, 0, index);
    uint64_t value = 0;
    for (size_t i = 0; i < token.length; i++) {
        unsigned char c = (unsigned char)token.bytes[i];
        if (c < '0' || c > '9')
            return fail(error, TC_STAGE_REQUEST, TC_REASON_SYNTAX, 0, index);
        value = value * 10 + (uint64_t)(c - '0');
    }
    if (value > TC_ID_MAX)
        return fail(error, TC_STAGE_REQUEST, TC_REASON_RANGE, 0, index);
    *output = value;
    return 0;
}

int tc_parse_request(struct tc_decimal uid, struct tc_decimal gid,
                     const struct tc_decimal *groups, size_t group_count,
                     struct tc_request *output, struct tc_error *error)
{
    if (error == NULL) return -1;
    clear_error(error);
    if (output == NULL)
        return fail(error, TC_STAGE_REQUEST, TC_REASON_ARGUMENT, 0, TC_NO_GROUP_INDEX);
    *output = (struct tc_request){0};
    if (groups == NULL || group_count == 0 || group_count > TC_MAX_GROUPS)
        return fail(error, TC_STAGE_REQUEST, TC_REASON_RANGE, 0, TC_NO_GROUP_INDEX);
    struct tc_request parsed = {0};
    if (decimal(uid, &parsed.uid, error, TC_NO_GROUP_INDEX) != 0 ||
        decimal(gid, &parsed.gid, error, TC_NO_GROUP_INDEX) != 0) return -1;
    parsed.group_count = group_count;
    for (size_t i = 0; i < group_count; i++)
        if (decimal(groups[i], &parsed.groups[i], error, i) != 0) return -1;
    if (tc_validate_request(&parsed, error) != 0) return -1;
    *output = parsed;
    return 0;
}

static int syscall_result(int result, int saved_errno, enum tc_stage stage,
                          struct tc_error *error)
{
    if (result == 0) return 0;
    if (result == -1 && saved_errno > 0)
        return fail(error, stage, TC_REASON_SYSCALL, saved_errno, TC_NO_GROUP_INDEX);
    return fail(error, stage, TC_REASON_ADAPTER, 0, TC_NO_GROUP_INDEX);
}

int tc_drop_in_owned_child(const struct tc_request *request, uint64_t owner_pid,
                           const struct tc_operations *operations, struct tc_error *error)
{
    if (error == NULL) return -1;
    if (tc_validate_request(request, error) != 0) return -1;
    /* Snapshot bounded caller inputs before invoking any injected operation. */
    const struct tc_request selected = *request;
    if (operations == NULL || !operations->getpid_fn || !operations->getppid_fn ||
        !operations->setgroups_fn || !operations->setgid_fn || !operations->setuid_fn ||
        !operations->getuid_fn || !operations->geteuid_fn || !operations->getgid_fn ||
        !operations->getegid_fn || !operations->getgroups_fn)
        return fail(error, TC_STAGE_OPERATIONS, TC_REASON_ARGUMENT, 0, TC_NO_GROUP_INDEX);
    const struct tc_operations ops = *operations;
    if (owner_pid == 0 || owner_pid > INT_MAX)
        return fail(error, TC_STAGE_CHILD, TC_REASON_RANGE, 0, TC_NO_GROUP_INDEX);
    pid_t own_pid = ops.getpid_fn(ops.context);
    pid_t parent_pid = ops.getppid_fn(ops.context);
    if (own_pid <= 0 || parent_pid <= 0 || (uint64_t)own_pid == owner_pid ||
        (uint64_t)parent_pid != owner_pid)
        return fail(error, TC_STAGE_CHILD, TC_REASON_NOT_OWNED_CHILD, 0, TC_NO_GROUP_INDEX);

    gid_t native_groups[TC_MAX_GROUPS];
    for (size_t i = 0; i < selected.group_count; i++)
        native_groups[i] = (gid_t)selected.groups[i];
    int saved_errno = 0;
    error->mutation_attempted = 1;
    int result = ops.setgroups_fn(ops.context, selected.group_count, native_groups, &saved_errno);
    if (syscall_result(result, saved_errno, TC_STAGE_SETGROUPS, error) != 0) return -1;
    saved_errno = 0;
    result = ops.setgid_fn(ops.context, (gid_t)selected.gid, &saved_errno);
    if (syscall_result(result, saved_errno, TC_STAGE_SETGID, error) != 0) return -1;
    saved_errno = 0;
    result = ops.setuid_fn(ops.context, (uid_t)selected.uid, &saved_errno);
    if (syscall_result(result, saved_errno, TC_STAGE_SETUID, error) != 0) return -1;

    if ((uint64_t)ops.getuid_fn(ops.context) != selected.uid)
        return fail(error, TC_STAGE_REAL_UID, TC_REASON_MISMATCH, 0, TC_NO_GROUP_INDEX);
    if ((uint64_t)ops.geteuid_fn(ops.context) != selected.uid)
        return fail(error, TC_STAGE_EFFECTIVE_UID, TC_REASON_MISMATCH, 0, TC_NO_GROUP_INDEX);
    if ((uint64_t)ops.getgid_fn(ops.context) != selected.gid)
        return fail(error, TC_STAGE_REAL_GID, TC_REASON_MISMATCH, 0, TC_NO_GROUP_INDEX);
    if ((uint64_t)ops.getegid_fn(ops.context) != selected.gid)
        return fail(error, TC_STAGE_EFFECTIVE_GID, TC_REASON_MISMATCH, 0, TC_NO_GROUP_INDEX);
    gid_t observed[TC_MAX_GROUPS];
    saved_errno = 0;
    int count = ops.getgroups_fn(ops.context, TC_MAX_GROUPS, observed, &saved_errno);
    if (count < 0) {
        if (count == -1 && saved_errno > 0)
            return fail(error, TC_STAGE_GROUPS, TC_REASON_SYSCALL, saved_errno, TC_NO_GROUP_INDEX);
        return fail(error, TC_STAGE_GROUPS, TC_REASON_ADAPTER, 0, TC_NO_GROUP_INDEX);
    }
    if (count > TC_MAX_GROUPS)
        return fail(error, TC_STAGE_GROUPS, TC_REASON_ADAPTER, 0, TC_NO_GROUP_INDEX);
    if ((size_t)count != selected.group_count)
        return fail(error, TC_STAGE_GROUPS, TC_REASON_MISMATCH, 0, TC_NO_GROUP_INDEX);
    for (size_t i = 0; i < selected.group_count; i++)
        if ((uint64_t)observed[i] != selected.groups[i])
            return fail(error, TC_STAGE_GROUPS, TC_REASON_MISMATCH, 0, i);
    return 0;
}

static pid_t native_pid(void *p) { (void)p; return getpid(); }
static pid_t native_ppid(void *p) { (void)p; return getppid(); }
static uid_t native_uid(void *p) { (void)p; return getuid(); }
static uid_t native_euid(void *p) { (void)p; return geteuid(); }
static gid_t native_gid(void *p) { (void)p; return getgid(); }
static gid_t native_egid(void *p) { (void)p; return getegid(); }
static int native_groups(void *p, size_t n, const gid_t *g, int *e)
{ (void)p; int r = setgroups((int)n, g); if (r == -1) *e = errno; return r; }
static int native_setgid(void *p, gid_t g, int *e)
{ (void)p; int r = setgid(g); if (r == -1) *e = errno; return r; }
static int native_setuid(void *p, uid_t u, int *e)
{ (void)p; int r = setuid(u); if (r == -1) *e = errno; return r; }
static int native_getgroups(void *p, int n, gid_t *g, int *e)
{ (void)p; int r = getgroups(n, g); if (r == -1) *e = errno; return r; }
const struct tc_operations *tc_native_operations(void)
{
    static const struct tc_operations operations = {
        NULL, native_pid, native_ppid, native_groups, native_setgid, native_setuid,
        native_uid, native_euid, native_gid, native_egid, native_getgroups
    };
    return &operations;
}

const char *tc_stage_name(enum tc_stage stage)
{
    static const char *const names[] = {"none", "request", "operations", "child",
        "setgroups", "setgid", "setuid", "real-uid", "effective-uid", "real-gid",
        "effective-gid", "groups"};
    return (unsigned)stage < sizeof(names) / sizeof(names[0]) ? names[stage] : "unknown";
}
const char *tc_reason_name(enum tc_reason reason)
{
    static const char *const names[] = {"none", "argument", "syntax", "range",
        "duplicate", "primary-group", "not-owned-child", "syscall", "adapter", "mismatch"};
    return (unsigned)reason < sizeof(names) / sizeof(names[0]) ? names[reason] : "unknown";
}
