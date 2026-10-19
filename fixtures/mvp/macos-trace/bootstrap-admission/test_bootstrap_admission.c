#ifndef _DEFAULT_SOURCE
#define _DEFAULT_SOURCE 1
#endif
#ifndef _DARWIN_C_SOURCE
#define _DARWIN_C_SOURCE 1
#endif
#include "bootstrap_admission.h"

#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

#define REQUIRE(c) do { if (!(c)) { fprintf(stderr, "%s:%d: %s\n", __func__, __LINE__, #c); return 1; } } while (0)
static const unsigned char good_path[] = BA_PREFIX "build-1/context-probe";
struct model {
    int calls, ids_calls, opened, inspected, bad_call;
    int open_failure, open_errno, open_result;
    int inspect_failure, inspect_errno, inspect_result;
    enum ba_metadata_step inspect_step;
    int mutation_component, mutation;
    uint32_t population_override; int use_population_override;
    const char *expected_build, *expected_leaf;
    uint64_t real, effective;
    int ids_result, ids_errno;
};
static struct ba_deployment deployment(void)
{
    return (struct ba_deployment){{1, {11, 12}}, {2, {21, 22}}};
}
static struct ba_request request(void)
{
    return (struct ba_request){good_path, sizeof(good_path) - 1, deployment()};
}
static struct model model(void)
{
    return (struct model){.open_failure = -1, .open_result = -1, .open_errno = EMFILE,
        .inspect_failure = -1, .inspect_errno = EIO, .inspect_result = -1,
        .inspect_step = BA_META_FSTATFS, .mutation_component = -1};
}
static int ids(void *p, uint64_t *real, uint64_t *effective, int *saved)
{
    struct model *m = p; m->calls++; m->ids_calls++;
    *real = m->real; *effective = m->effective; *saved = m->ids_errno;
    return m->ids_result;
}
static int open_next(struct model *m)
{
    int i = m->opened++; m->calls++;
    if (i == m->open_failure) { errno = EACCES; return m->open_result; }
    return 100 + i;
}
static int root_open(void *p, int *saved)
{
    struct model *m = p; *saved = m->open_errno;
    if (m->opened != 0) m->bad_call = 1;
    return open_next(m);
}
static int at_open(void *p, int parent, const char *name, int leaf, int *saved)
{
    static const char *const names[] = {"/", "System", "Volumes", "Data", "Library", "GlueMVPFixtures", "build-1", "context-probe"};
    struct model *m = p; int i = m->opened;
    const char *wanted = i == 6 && m->expected_build ? m->expected_build :
                         i == 7 && m->expected_leaf ? m->expected_leaf :
                         i >= 0 && i < BA_COMPONENT_COUNT ? names[i] : "invalid";
    if (i <= 0 || i >= BA_COMPONENT_COUNT || parent != 100 + i - 1 ||
        strcmp(name, wanted) != 0 || leaf != (i == 7)) m->bad_call = 1;
    *saved = m->open_errno;
    return open_next(m);
}
static struct ba_metadata metadata(int i)
{
    struct ba_metadata s = {0};
    s.device = i < 3 ? 1 : 2; s.inode = (uint64_t)(10 + i); s.links = 1;
    s.mode = (uint32_t)(i == 7 ? S_IFREG | 0555 : S_IFDIR | 0755);
    s.populated = 7; s.filesec_mode = s.mode;
    s.descriptor_flags = FD_CLOEXEC; s.status_flags = O_RDONLY | (i == 7 ? O_NONBLOCK : 0);
    s.fsid[0] = i < 3 ? 11 : 21; s.fsid[1] = i < 3 ? 12 : 22;
    s.mount_policy = BA_MOUNT_LOCAL | (i < 3 ? BA_MOUNT_ROOTFS : 0);
    strcpy(s.filesystem, "apfs"); strcpy(s.mountpoint, i < 3 ? "/" : "/System/Volumes/Data");
    return s;
}
enum mutations {
    BAD_UID = 1, BAD_TYPE, BAD_MODE_WRITE, BAD_MODE_SETID, BAD_MODE_STICKY, BAD_LINKS,
    BAD_POPULATION, BAD_FSUID, BAD_FSGID, BAD_FSMODE, BAD_ACL,
    BAD_CLOEXEC, BAD_ACCESS, BAD_NONBLOCK, BAD_ASYNC, BAD_FDFLAGS, BAD_FLFLAGS,
    BAD_DEV, BAD_FSID, BAD_LOCAL, BAD_ROOTFS, BAD_IGNORE, BAD_UNION, BAD_MOUNTOWNER,
    BAD_FSTYPE, BAD_MOUNTPOINT, BAD_UNTERMINATED_TYPE, BAD_UNTERMINATED_POINT,
    BAD_UNKNOWN_POLICY, BAD_MODE_RANGE
};
static void mutate(struct ba_metadata *s, int which)
{
    switch (which) {
    case BAD_UID: s->uid = s->filesec_uid = 501; break;
    case BAD_TYPE: s->mode = s->filesec_mode = S_IFIFO | 0555; break;
    case BAD_MODE_WRITE: s->mode |= S_IWGRP; s->filesec_mode = s->mode; break;
    case BAD_MODE_SETID: s->mode |= S_ISUID; s->filesec_mode = s->mode; break;
    case BAD_MODE_STICKY: s->mode |= S_ISVTX; s->filesec_mode = s->mode; break;
    case BAD_LINKS: s->links = 2; break;
    case BAD_POPULATION: s->populated = 0; break;
    case BAD_FSUID: s->filesec_uid = 1; break;
    case BAD_FSGID: s->filesec_gid = 1; break;
    case BAD_FSMODE: s->filesec_mode ^= S_IXUSR; break;
    case BAD_ACL: s->acl_present = 4; break;
    case BAD_CLOEXEC: s->descriptor_flags = 0; break;
    case BAD_ACCESS: s->status_flags = O_RDWR | O_NONBLOCK; break;
    case BAD_NONBLOCK: s->status_flags &= ~O_NONBLOCK; break;
    case BAD_ASYNC: s->status_flags |= O_ASYNC; break;
    case BAD_FDFLAGS: s->descriptor_flags = -1; break;
    case BAD_FLFLAGS: s->status_flags = -1; break;
    case BAD_DEV: s->device = 3; break;
    case BAD_FSID: s->fsid[1] ^= 1; break;
    case BAD_LOCAL: s->mount_policy &= ~BA_MOUNT_LOCAL; break;
    case BAD_ROOTFS: s->mount_policy ^= BA_MOUNT_ROOTFS; break;
    case BAD_IGNORE: s->mount_policy |= BA_MOUNT_IGNORE_OWNERSHIP; break;
    case BAD_UNION: s->mount_policy |= BA_MOUNT_UNION; break;
    case BAD_MOUNTOWNER: s->mount_owner = 501; break;
    case BAD_FSTYPE: strcpy(s->filesystem, "nfs"); break;
    case BAD_MOUNTPOINT: strcpy(s->mountpoint, "/private/tmp"); break;
    case BAD_UNTERMINATED_TYPE: memset(s->filesystem, 'a', sizeof(s->filesystem)); break;
    case BAD_UNTERMINATED_POINT: memset(s->mountpoint, 'a', sizeof(s->mountpoint)); break;
    case BAD_UNKNOWN_POLICY: s->mount_policy |= 16; break;
    case BAD_MODE_RANGE: s->mode |= UINT32_C(0x80000000); s->filesec_mode = s->mode; break;
    default: break;
    }
}
static int inspect(void *p, int fd, struct ba_metadata *out, struct ba_probe_error *error)
{
    struct model *m = p; int i = fd - 100;
    if (i < 0 || i > 7 || i != m->inspected) m->bad_call = 1;
    m->calls++; m->inspected++;
    if (i == m->inspect_failure) {
        /* A failed callback may write only a prefix; it still poisons admission. */
        out->uid = 0; *error = (struct ba_probe_error){m->inspect_step, m->inspect_errno};
        return m->inspect_result;
    }
    *out = metadata(i);
    if (i == m->mutation_component) mutate(out, m->mutation);
    if (m->use_population_override && i == 4) out->populated = m->population_override;
    return 0;
}
static struct ba_operations operations(struct model *m)
{
    return (struct ba_operations){1, m, ids, root_open, at_open, inspect};
}
static int run(struct model *m, struct ba_result *out, struct ba_error *error)
{
    struct ba_operations ops = operations(m); struct ba_request r = request();
    return ba_admit_protected_executable(&r, &ops, out, error);
}
static int positive(void)
{
    struct model m = model(); struct ba_result out; struct ba_error error;
    REQUIRE(run(&m, &out, &error) == 0);
    REQUIRE(out.ready == 1 && out.owned_count == 8 && out.checked_count == 8);
    REQUIRE(error.stage == BA_STAGE_NONE && error.reason == BA_REASON_NONE && error.system_errno == 0);
    REQUIRE(!error.ownership_uncertain && m.calls == 17 && !m.bad_call);
    for (int i = 0; i < 8; i++) REQUIRE(out.components[i].fd == 100 + i);
    REQUIRE(strcmp(out.components[0].name, "/") == 0 && strcmp(out.components[7].name, "context-probe") == 0);
    REQUIRE(out.components[2].metadata.mount_policy == (BA_MOUNT_LOCAL | BA_MOUNT_ROOTFS));
    REQUIRE(out.components[3].metadata.mount_policy == BA_MOUNT_LOCAL);
    return 0;
}
static int paths(void)
{
    const char *const bad[] = {"", "/tmp/build-1/context-probe", "/Library/GlueMVPFixtures/build-1/context-probe",
        BA_PREFIX, BA_PREFIX "build-1", BA_PREFIX "build-1/", BA_PREFIX "/context-probe",
        BA_PREFIX "./context-probe", BA_PREFIX "../context-probe", BA_PREFIX "build-1/.",
        BA_PREFIX "build-1/..", BA_PREFIX "build-1/sub/context-probe", BA_PREFIX "build 1/context-probe",
        BA_PREFIX "build-1/context-probe/", BA_PREFIX "build-1/context\xffprobe"};
    for (size_t i = 0; i < sizeof(bad) / sizeof(bad[0]); i++) {
        struct model m = model(); struct ba_operations ops = operations(&m);
        struct ba_request r = request(); struct ba_result out; struct ba_error error;
        r.path = (const unsigned char *)bad[i]; r.path_length = strlen(bad[i]);
        REQUIRE(ba_admit_protected_executable(&r, &ops, &out, &error) == -1);
        REQUIRE(error.reason == BA_REASON_PATH && out.ready == 0 && out.owned_count == 0 && m.calls == 0);
    }
    unsigned char b[BA_PATH_MAX + 1]; memset(b, 'a', sizeof(b));
    memcpy(b, BA_PREFIX, sizeof(BA_PREFIX) - 1);
    size_t prefix = sizeof(BA_PREFIX) - 1;
    memset(b + prefix, 'b', 65); b[prefix + 65] = '/'; b[prefix + 66] = 'c';
    struct model m = model(); struct ba_operations ops = operations(&m);
    struct ba_request r = request(); struct ba_result out; struct ba_error error;
    r.path = b; r.path_length = prefix + 67;
    REQUIRE(ba_admit_protected_executable(&r, &ops, &out, &error) == -1 && error.reason == BA_REASON_PATH);
    r.path_length = BA_PATH_MAX;
    REQUIRE(ba_admit_protected_executable(&r, &ops, &out, &error) == -1 && error.reason == BA_REASON_PATH);
    r = request(); b[0] = 0; r.path = b; r.path_length = sizeof(good_path) - 1;
    REQUIRE(ba_admit_protected_executable(&r, &ops, &out, &error) == -1 && error.reason == BA_REASON_PATH);
    const unsigned char nul[] = BA_PREFIX "build-1/context\0probe";
    r.path = nul; r.path_length = sizeof(nul) - 1;
    REQUIRE(ba_admit_protected_executable(&r, &ops, &out, &error) == -1 && error.reason == BA_REASON_PATH);
    char build[65], leaf[65]; memset(build, 'b', 64); memset(leaf, 'c', 64); build[64] = leaf[64] = 0;
    int length = snprintf((char *)b, sizeof(b), "%s%s/%s", BA_PREFIX, build, leaf);
    r.path = b; r.path_length = (size_t)length;
    m = model(); m.expected_build = build; m.expected_leaf = leaf; ops = operations(&m);
    REQUIRE(ba_admit_protected_executable(&r, &ops, &out, &error) == 0 && !m.bad_call);
    REQUIRE(strlen(out.components[6].name) == 64 && strlen(out.components[7].name) == 64);
    return 0;
}
static int preflight(void)
{
    struct model m = model(); struct ba_operations ops = operations(&m);
    struct ba_request r = request(); struct ba_result out; struct ba_error error;
    for (int which = 0; which < 4; which++) {
        ops = operations(&m);
        if (which == 0) ops.ids_fn = NULL;
        if (which == 1) ops.open_root_fn = NULL;
        if (which == 2) ops.openat_fn = NULL;
        if (which == 3) ops.inspect_fn = NULL;
        REQUIRE(ba_admit_protected_executable(&r, &ops, &out, &error) == -1);
        REQUIRE(error.stage == BA_STAGE_OPERATIONS && m.calls == 0 && out.owned_count == 0);
    }
    ops = operations(&m); ops.supported = 0;
    REQUIRE(ba_admit_protected_executable(&r, &ops, &out, &error) == -1);
    REQUIRE(error.reason == BA_REASON_UNSUPPORTED && error.system_errno == ENOTSUP && m.calls == 0);
    ops.supported = -1;
    REQUIRE(ba_admit_protected_executable(&r, &ops, &out, &error) == -1 && error.reason == BA_REASON_ARGUMENT && m.calls == 0);
    REQUIRE(ba_admit_protected_executable(NULL, &ops, &out, &error) == -1 && error.reason == BA_REASON_ARGUMENT);
    REQUIRE(ba_admit_protected_executable(&r, &ops, NULL, &error) == -1 && error.reason == BA_REASON_ARGUMENT);
    REQUIRE(ba_admit_protected_executable(&r, &ops, &out, NULL) == -1 && m.calls == 0);
    return 0;
}
static int profile(void)
{
    struct model m = model(); struct ba_operations ops = operations(&m);
    struct ba_request r = request(); struct ba_result out; struct ba_error error;
    r.deployment.data = r.deployment.root;
    REQUIRE(ba_admit_protected_executable(&r, &ops, &out, &error) == -1);
    REQUIRE(error.reason == BA_REASON_PROFILE && m.calls == 0 && out.owned_count == 0);
    return 0;
}
static int identities(void)
{
    for (int i = 0; i < 3; i++) {
        struct model m = model(); struct ba_result out; struct ba_error error;
        m.real = i != 1 ? 501 : 0; m.effective = i != 0 ? 501 : 0;
        REQUIRE(run(&m, &out, &error) == -1 && error.reason == BA_REASON_NOT_ROOT);
        REQUIRE(m.calls == 1 && m.opened == 0 && out.owned_count == 0);
    }
    struct model m = model(); struct ba_result out; struct ba_error error;
    m.ids_result = -1; m.ids_errno = EPERM;
    REQUIRE(run(&m, &out, &error) == -1 && error.system_errno == EPERM && error.reason == BA_REASON_SYSCALL);
    m.ids_errno = 0;
    REQUIRE(run(&m, &out, &error) == -1 && error.reason == BA_REASON_ADAPTER);
    return 0;
}
static int errors(void)
{
    for (int i = 0; i < 8; i++) {
        struct model m = model(); struct ba_result out; struct ba_error error;
        m.open_failure = i; m.open_errno = EINTR;
        REQUIRE(run(&m, &out, &error) == -1);
        REQUIRE(error.stage == BA_STAGE_OPEN && error.system_errno == EINTR && error.component == (size_t)i);
        REQUIRE(out.ready == 0 && out.owned_count == (size_t)i && out.checked_count == (size_t)i);
        REQUIRE(m.opened == i + 1 && !error.ownership_uncertain);
        m = model(); m.inspect_failure = i; m.inspect_errno = EIO;
        REQUIRE(run(&m, &out, &error) == -1);
        REQUIRE(error.stage == BA_STAGE_METADATA && error.system_errno == EIO && error.metadata_step == BA_META_FSTATFS);
        REQUIRE(out.owned_count == (size_t)i + 1 && out.checked_count == (size_t)i && out.ready == 0);
        for (int j = 0; j <= i; j++) REQUIRE(out.components[j].fd == 100 + j);
    }
    return 0;
}
static int uncertainty(void)
{
    struct model m = model(); struct ba_result out; struct ba_error error;
    m.open_failure = 2; m.open_result = 100;
    REQUIRE(run(&m, &out, &error) == -1 && error.reason == BA_REASON_OWNERSHIP);
    REQUIRE(error.ownership_uncertain == 1 && out.owned_count == 2 && out.components[2].fd == -1);
    m = model(); m.open_failure = 0; m.open_result = -2;
    REQUIRE(run(&m, &out, &error) == -1 && error.reason == BA_REASON_ADAPTER && error.ownership_uncertain == 1 && out.owned_count == 0);
    m = model(); m.open_failure = 4; m.open_errno = 0;
    REQUIRE(run(&m, &out, &error) == -1 && error.reason == BA_REASON_ADAPTER && error.ownership_uncertain == 1 && out.owned_count == 4);
    m = model(); m.inspect_failure = 4; m.inspect_errno = 0;
    REQUIRE(run(&m, &out, &error) == -1 && error.reason == BA_REASON_ADAPTER && !error.ownership_uncertain && out.owned_count == 5);
    m = model(); m.inspect_failure = 4; m.inspect_step = BA_META_NONE;
    REQUIRE(run(&m, &out, &error) == -1 && error.reason == BA_REASON_ADAPTER && error.metadata_step == BA_META_NONE);
    return 0;
}
static int fault_policy(int first, int last, int component)
{
    for (int which = first; which <= last; which++) {
        struct model m = model(); struct ba_result out; struct ba_error error;
        m.mutation_component = component; m.mutation = which;
        REQUIRE(run(&m, &out, &error) == -1);
        REQUIRE(error.stage == BA_STAGE_POLICY && error.component == (size_t)component && out.ready == 0);
        REQUIRE(out.owned_count == (size_t)component + 1 && out.checked_count == (size_t)component);
    }
    return 0;
}
static int owners_and_modes(void)
{
    REQUIRE(fault_policy(BAD_UID, BAD_MODE_SETID, 1) == 0);
    REQUIRE(fault_policy(BAD_UID, BAD_LINKS, 7) == 0);
    REQUIRE(fault_policy(BAD_MODE_RANGE, BAD_MODE_RANGE, 0) == 0);
    return 0;
}
static int filesec(void)
{
    /* Candidate statx1 false-success: apparently safe scalar zeros and absent ACL,
     * but no property validity. Zeroed storage must never imply absence. */
    for (int i = 0; i < 8; i++) REQUIRE(fault_policy(BAD_POPULATION, BAD_ACL, i) == 0);
    return 0;
}
static int scalar_boundaries(void)
{
    for (uint32_t bits = 0; bits < 16; bits++) {
        if (bits == 7) continue;
        /* Feed all noncanonical masks, not just zero, through the public API. */
        struct model m = model(); struct ba_result out; struct ba_error error;
        m.use_population_override = 1; m.population_override = bits;
        REQUIRE(run(&m, &out, &error) == -1 && error.reason == BA_REASON_FILESEC);
    }
    for (int step = BA_META_FILESEC_INIT; step <= BA_META_QUERY_ACL; step++) {
        struct model m = model(); struct ba_result out; struct ba_error error;
        m.inspect_failure = 3; m.inspect_step = (enum ba_metadata_step)step; m.inspect_errno = ENOMEM;
        REQUIRE(run(&m, &out, &error) == -1 && error.stage == BA_STAGE_METADATA);
        REQUIRE(error.system_errno == ENOMEM && error.metadata_step == (enum ba_metadata_step)step);
        REQUIRE(out.ready == 0 && out.owned_count == 4 && out.checked_count == 3);
    }
    return 0;
}
static int flags(void)
{
    REQUIRE(fault_policy(BAD_CLOEXEC, BAD_FLFLAGS, 7) == 0);
    REQUIRE(fault_policy(BAD_CLOEXEC, BAD_ACCESS, 0) == 0);
    REQUIRE(fault_policy(BAD_ASYNC, BAD_FLFLAGS, 0) == 0);
    return 0;
}
static int mounts(void)
{
    for (int i = 0; i < 8; i++) REQUIRE(fault_policy(BAD_DEV, BAD_UNKNOWN_POLICY, i) == 0);
    return 0;
}
static int reset_and_canaries(void)
{
    struct wrapped { uint64_t before; struct ba_result out; uint64_t after; } w;
    memset(&w, 0xa5, sizeof(w)); w.before = w.after = UINT64_C(0x1f2e3d4c5b6a7988);
    struct model m = model(); struct ba_error error;
    REQUIRE(run(&m, &w.out, &error) == 0);
    m = model(); m.open_failure = 0;
    REQUIRE(run(&m, &w.out, &error) == -1);
    REQUIRE(w.out.ready == 0 && w.out.owned_count == 0 && w.out.checked_count == 0);
    for (int i = 0; i < 8; i++) REQUIRE(w.out.components[i].fd == -1);
    REQUIRE(w.before == UINT64_C(0x1f2e3d4c5b6a7988) && w.after == w.before);
    REQUIRE(strcmp(ba_stage_name((enum ba_stage)999), "unknown") == 0);
    REQUIRE(strcmp(ba_reason_name((enum ba_reason)-1), "unknown") == 0);
    return 0;
}
static int native_preflight(void)
{
    struct ba_request r = request(); struct ba_result out; struct ba_error error;
#if defined(__APPLE__)
    if (getuid() == 0 || geteuid() == 0) return 77;
#endif
    REQUIRE(ba_admit_protected_executable(&r, ba_native_operations(), &out, &error) == -1);
    REQUIRE(out.ready == 0 && out.owned_count == 0);
#if defined(__APPLE__)
    REQUIRE(error.stage == BA_STAGE_IDENTITY && error.reason == BA_REASON_NOT_ROOT);
#else
    REQUIRE(error.stage == BA_STAGE_OPERATIONS && error.reason == BA_REASON_UNSUPPORTED && error.system_errno == ENOTSUP);
#endif
    return 0;
}
static int native_readonly(void)
{
#if defined(__APPLE__)
    const struct ba_operations *ops = ba_native_operations();
    const char *const names[] = {"System", "Volumes", "Data", "Library"};
    int saved = 0, fds[5] = {-1,-1,-1,-1,-1}, result = 1;
    fds[0] = ops->open_root_fn(NULL, &saved);
    if (fds[0] == -1) goto done;
    for (int i = 0; i < 5; i++) {
        if (i != 0) {
            fds[i] = ops->openat_fn(NULL, fds[i-1], names[i-1], 0, &saved);
            if (fds[i] == -1) goto done;
        }
        struct stat before = {0}, after = {0};
        if (fstat(fds[i], &before) != 0) goto done;
        int flags_before = fcntl(fds[i], F_GETFD), fl_before = fcntl(fds[i], F_GETFL);
        struct ba_metadata m; struct ba_probe_error e;
        if (ops->inspect_fn(NULL, fds[i], &m, &e) != 0) goto done;
        if (m.populated != 7 || m.filesec_uid != m.uid || m.filesec_gid != m.gid ||
            m.filesec_mode != m.mode || m.uid != (uint32_t)before.st_uid ||
            m.mode != (uint32_t)before.st_mode || m.gid != (uint32_t)before.st_gid ||
            m.acl_present < 0 || m.inode != (uint64_t)before.st_ino ||
            (m.descriptor_flags & FD_CLOEXEC) == 0 || (m.status_flags & O_ACCMODE) != O_RDONLY)
            goto done;
        if (fstat(fds[i], &after) != 0 || before.st_dev != after.st_dev || before.st_ino != after.st_ino ||
            before.st_uid != after.st_uid || before.st_gid != after.st_gid || before.st_mode != after.st_mode ||
            fcntl(fds[i], F_GETFD) != flags_before || fcntl(fds[i], F_GETFL) != fl_before) goto done;
        printf("readonly component=%d uid=%u gid=%u mode=%o populated=%u acl_presence=%d mount=%s\n",
               i, m.uid, m.gid, m.mode, m.populated, m.acl_present, m.mountpoint);
    }
    struct ba_metadata m; struct ba_probe_error e;
    if (ops->inspect_fn(NULL, -1, &m, &e) != -1 || e.step != BA_META_FD_FLAGS || e.system_errno != EBADF) goto done;
    result = 0;
done:
    for (int i = 4; i >= 0; i--) if (fds[i] >= 0 && close(fds[i]) != 0) result = 1;
    return result;
#else
    return 77;
#endif
}
int main(int argc, char **argv)
{
    if (argc != 2) return 2;
#define CASE(n) if (strcmp(argv[1], #n) == 0) return n()
    CASE(positive); CASE(paths); CASE(preflight); CASE(profile); CASE(identities); CASE(errors);
    CASE(uncertainty); CASE(owners_and_modes); CASE(filesec); CASE(scalar_boundaries); CASE(flags); CASE(mounts);
    CASE(reset_and_canaries); CASE(native_preflight); CASE(native_readonly);
#undef CASE
    return 2;
}
