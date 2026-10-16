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
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>
#if defined(__APPLE__)
#include <sys/mount.h>
#endif

static int fail(struct ba_error *e, enum ba_stage stage, enum ba_reason reason,
                int number, size_t component, enum ba_metadata_step step)
{
    e->stage = stage; e->reason = reason; e->system_errno = number;
    e->component = component; e->metadata_step = step;
    return -1;
}
static int same_mount(const struct ba_mount_id *a, const struct ba_mount_id *b)
{
    return a->device == b->device && a->fsid[0] == b->fsid[0] && a->fsid[1] == b->fsid[1];
}
static int ascii_first(unsigned char c)
{
    return (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9');
}
static int name_valid(const unsigned char *p, size_t n)
{
    if (n == 0 || n > BA_NAME_MAX || !ascii_first(p[0])) return 0;
    for (size_t i = 1; i < n; i++)
        if (!ascii_first(p[i]) && p[i] != '_' && p[i] != '-' && p[i] != '.') return 0;
    return 1;
}
static int path_names(const struct ba_request *r, char names[BA_COMPONENT_COUNT][BA_NAME_MAX + 1])
{
    static const char *const fixed[] = {"/", "System", "Volumes", "Data", "Library", "GlueMVPFixtures"};
    const size_t prefix = sizeof(BA_PREFIX) - 1;
    if (r->path == NULL || r->path_length <= prefix || r->path_length >= BA_PATH_MAX ||
        memcmp(r->path, BA_PREFIX, prefix) != 0) return -1;
    size_t split = prefix;
    while (split < r->path_length && r->path[split] != '/') split++;
    if (split == r->path_length || !name_valid(r->path + prefix, split - prefix) ||
        !name_valid(r->path + split + 1, r->path_length - split - 1)) return -1;
    for (size_t i = 0; i < 6; i++) strcpy(names[i], fixed[i]);
    memcpy(names[6], r->path + prefix, split - prefix);
    names[6][split - prefix] = 0;
    memcpy(names[7], r->path + split + 1, r->path_length - split - 1);
    names[7][r->path_length - split - 1] = 0;
    return 0;
}
static int policy(const struct ba_metadata *m, const struct ba_deployment *d,
                  size_t i, struct ba_error *e)
{
    if (m->descriptor_flags < 0 || m->status_flags < 0 ||
        !(m->descriptor_flags & FD_CLOEXEC) || (m->status_flags & O_ACCMODE) != O_RDONLY)
        return fail(e, BA_STAGE_POLICY, BA_REASON_FLAGS, 0, i, BA_META_NONE);
    int forbidden = O_ASYNC;
#ifdef O_EVTONLY
    forbidden |= O_EVTONLY;
#endif
#ifdef O_PATH
    forbidden |= O_PATH;
#endif
    if ((m->status_flags & forbidden) || (i == 7 && !(m->status_flags & O_NONBLOCK)))
        return fail(e, BA_STAGE_POLICY, BA_REASON_FLAGS, 0, i, BA_META_NONE);
    if (m->mode & ~(uint32_t)(S_IFMT | 07777))
        return fail(e, BA_STAGE_POLICY, BA_REASON_MODE, 0, i, BA_META_NONE);
    const uint32_t type = m->mode & S_IFMT;
    if (type != (uint32_t)(i == 7 ? S_IFREG : S_IFDIR))
        return fail(e, BA_STAGE_POLICY, BA_REASON_TYPE, 0, i, BA_META_NONE);
    if (m->uid != 0) return fail(e, BA_STAGE_POLICY, BA_REASON_OWNER, 0, i, BA_META_NONE);
    if ((i == 7 && (m->mode & 07777) != 0555) ||
        (i != 7 && (m->mode & (S_IWGRP | S_IWOTH | S_ISUID | S_ISGID))))
        return fail(e, BA_STAGE_POLICY, BA_REASON_MODE, 0, i, BA_META_NONE);
    if (i == 7 && m->links != 1)
        return fail(e, BA_STAGE_POLICY, BA_REASON_LINKS, 0, i, BA_META_NONE);
    if (m->populated != (BA_OWNER_PRESENT | BA_GROUP_PRESENT | BA_MODE_PRESENT)) {
        enum ba_metadata_step step = BA_META_NONE;
        if (!(m->populated & BA_OWNER_PRESENT)) step = BA_META_QUERY_OWNER;
        else if (!(m->populated & BA_GROUP_PRESENT)) step = BA_META_QUERY_GROUP;
        else if (!(m->populated & BA_MODE_PRESENT)) step = BA_META_QUERY_MODE;
        return fail(e, BA_STAGE_POLICY, BA_REASON_FILESEC, 0, i, step);
    }
    if (m->filesec_uid != m->uid)
        return fail(e, BA_STAGE_POLICY, BA_REASON_FILESEC, 0, i, BA_META_GET_OWNER);
    if (m->filesec_gid != m->gid)
        return fail(e, BA_STAGE_POLICY, BA_REASON_FILESEC, 0, i, BA_META_GET_GROUP);
    if (m->filesec_mode != m->mode)
        return fail(e, BA_STAGE_POLICY, BA_REASON_FILESEC, 0, i, BA_META_GET_MODE);
    if (m->acl_present != 0)
        return fail(e, BA_STAGE_POLICY, BA_REASON_ACL, 0, i, BA_META_QUERY_ACL);
    const struct ba_mount_id *wanted = i < 3 ? &d->root : &d->data;
    const uint32_t bits = BA_MOUNT_LOCAL | (i < 3 ? BA_MOUNT_ROOTFS : 0);
    const char *where = i < 3 ? "/" : "/System/Volumes/Data";
    if (m->mount_policy != bits || m->mount_owner != 0 ||
        memchr(m->filesystem, 0, sizeof(m->filesystem)) == NULL ||
        memchr(m->mountpoint, 0, sizeof(m->mountpoint)) == NULL ||
        strcmp(m->filesystem, "apfs") != 0 || strcmp(m->mountpoint, where) != 0 ||
        m->device != wanted->device || m->fsid[0] != wanted->fsid[0] || m->fsid[1] != wanted->fsid[1])
        return fail(e, BA_STAGE_POLICY, BA_REASON_MOUNT, 0, i, BA_META_FSTATFS);
    return 0;
}
int ba_admit_protected_executable(const struct ba_request *request, const struct ba_operations *operations,
                                 struct ba_result *result, struct ba_error *error)
{
    if (error == NULL) return -1;
    *error = (struct ba_error){BA_STAGE_NONE, BA_REASON_NONE, 0, BA_COMPONENT_COUNT, BA_META_NONE, 0};
    if (result == NULL) return fail(error, BA_STAGE_REQUEST, BA_REASON_ARGUMENT, 0, BA_COMPONENT_COUNT, BA_META_NONE);
    memset(result, 0, sizeof(*result));
    for (size_t i = 0; i < BA_COMPONENT_COUNT; i++) result->components[i].fd = -1;
    if (request == NULL) return fail(error, BA_STAGE_REQUEST, BA_REASON_ARGUMENT, 0, BA_COMPONENT_COUNT, BA_META_NONE);
    const struct ba_request r = *request;
    char names[BA_COMPONENT_COUNT][BA_NAME_MAX + 1] = {{0}};
    if (path_names(&r, names) != 0)
        return fail(error, BA_STAGE_REQUEST, BA_REASON_PATH, 0, BA_COMPONENT_COUNT, BA_META_NONE);
    if (same_mount(&r.deployment.root, &r.deployment.data))
        return fail(error, BA_STAGE_REQUEST, BA_REASON_PROFILE, 0, BA_COMPONENT_COUNT, BA_META_NONE);
    if (operations == NULL)
        return fail(error, BA_STAGE_OPERATIONS, BA_REASON_ARGUMENT, 0, BA_COMPONENT_COUNT, BA_META_NONE);
    const struct ba_operations ops = *operations;
    if (ops.supported == 0)
        return fail(error, BA_STAGE_OPERATIONS, BA_REASON_UNSUPPORTED, ENOTSUP, BA_COMPONENT_COUNT, BA_META_NONE);
    if (ops.supported != 1 || !ops.ids_fn || !ops.open_root_fn || !ops.openat_fn || !ops.inspect_fn)
        return fail(error, BA_STAGE_OPERATIONS, BA_REASON_ARGUMENT, 0, BA_COMPONENT_COUNT, BA_META_NONE);
    uint64_t real = UINT64_MAX, effective = UINT64_MAX;
    int saved = 0, rc = ops.ids_fn(ops.context, &real, &effective, &saved);
    if (rc != 0)
        return fail(error, BA_STAGE_IDENTITY, rc == -1 && saved > 0 ? BA_REASON_SYSCALL : BA_REASON_ADAPTER,
                    rc == -1 && saved > 0 ? saved : 0, BA_COMPONENT_COUNT, BA_META_NONE);
    if (real != 0 || effective != 0)
        return fail(error, BA_STAGE_IDENTITY, BA_REASON_NOT_ROOT, 0, BA_COMPONENT_COUNT, BA_META_NONE);
    for (size_t i = 0; i < BA_COMPONENT_COUNT; i++) {
        saved = 0;
        int fd = i == 0 ? ops.open_root_fn(ops.context, &saved) :
            ops.openat_fn(ops.context, result->components[i - 1].fd, names[i], i == 7, &saved);
        if (fd < 0) {
            if (fd != -1 || saved <= 0) error->ownership_uncertain = 1;
            return fail(error, BA_STAGE_OPEN, fd == -1 && saved > 0 ? BA_REASON_SYSCALL : BA_REASON_ADAPTER,
                        fd == -1 && saved > 0 ? saved : 0, i, BA_META_NONE);
        }
        for (size_t j = 0; j < result->owned_count; j++) {
            if (result->components[j].fd == fd) {
                error->ownership_uncertain = 1;
                return fail(error, BA_STAGE_OPEN, BA_REASON_OWNERSHIP, 0, i, BA_META_NONE);
            }
        }
        struct ba_component *c = &result->components[i];
        c->fd = fd; strcpy(c->name, names[i]); result->owned_count++;
        c->metadata.acl_present = -1;
        struct ba_probe_error pe = {BA_META_NONE, 0};
        rc = ops.inspect_fn(ops.context, fd, &c->metadata, &pe);
        if (rc != 0) {
            int valid = rc == -1 && pe.system_errno > 0 && pe.step >= BA_META_FD_FLAGS && pe.step <= BA_META_FSTATFS;
            return fail(error, BA_STAGE_METADATA, valid ? BA_REASON_SYSCALL : BA_REASON_ADAPTER,
                        valid ? pe.system_errno : 0, i, valid ? pe.step : BA_META_NONE);
        }
        if (policy(&c->metadata, &r.deployment, i, error) != 0) return -1;
        result->checked_count++;
    }
    result->ready = 1;
    return 0;
}

static int native_ids(void *unused, uint64_t *real, uint64_t *effective, int *saved)
{
    (void)unused; (void)saved; *real = (uint64_t)getuid(); *effective = (uint64_t)geteuid(); return 0;
}
static int native_root(void *unused, int *saved)
{
    (void)unused;
    int fd = open("/", O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC);
    if (fd == -1) *saved = errno;
    return fd;
}
static int native_at(void *unused, int parent, const char *name, int leaf, int *saved)
{
    (void)unused;
    int fd = openat(parent, name, O_RDONLY | O_NOFOLLOW | O_CLOEXEC | (leaf ? O_NONBLOCK : O_DIRECTORY));
    if (fd == -1) *saved = errno;
    return fd;
}
#if defined(__APPLE__)
_Static_assert(sizeof(dev_t) == sizeof(uint32_t), "device encoding");
_Static_assert(sizeof(uid_t) <= sizeof(uint32_t) && sizeof(gid_t) <= sizeof(uint32_t), "ID widths");
_Static_assert(sizeof(mode_t) <= sizeof(uint32_t), "mode width");
_Static_assert(sizeof(((struct stat *)0)->st_ino) <= sizeof(uint64_t), "inode width");
_Static_assert(sizeof(((struct stat *)0)->st_nlink) <= sizeof(uint64_t), "link width");
_Static_assert(sizeof(((struct statfs *)0)->f_flags) <= sizeof(uint64_t), "mount flags width");
_Static_assert(sizeof(((struct statfs *)0)->f_fsid) == 2 * sizeof(int32_t), "fsid pair width");
_Static_assert(sizeof(((struct statfs *)0)->f_fsid.val[0]) == sizeof(int32_t), "fsid width");
_Static_assert(sizeof(((struct statfs *)0)->f_fstypename) <= BA_FS_TYPE_MAX, "filesystem buffer");
_Static_assert(sizeof(((struct statfs *)0)->f_mntonname) <= BA_MOUNTPOINT_MAX, "mountpoint buffer");
static int native_inspect(void *unused, int fd, struct ba_metadata *m, struct ba_probe_error *e)
{
    (void)unused;
    memset(m, 0, sizeof(*m)); m->acl_present = -1;
    *e = (struct ba_probe_error){BA_META_FD_FLAGS, 0};
    m->descriptor_flags = fcntl(fd, F_GETFD);
    if (m->descriptor_flags == -1) { e->system_errno = errno; return -1; }
    e->step = BA_META_STATUS_FLAGS;
    m->status_flags = fcntl(fd, F_GETFL);
    if (m->status_flags == -1) { e->system_errno = errno; return -1; }
    e->step = BA_META_FILESEC_INIT; errno = 0;
    filesec_t fs = filesec_init();
    if (fs == NULL) { e->system_errno = errno; return -1; }
    struct stat st = {0};
    int rc = -1;
    e->step = BA_META_FSTATX; errno = 0;
    if (fstatx_np(fd, &st, fs) != 0) { e->system_errno = errno; goto done; }
    m->device = (uint32_t)st.st_dev; m->inode = (uint64_t)st.st_ino; m->links = (uint64_t)st.st_nlink;
    m->uid = (uint32_t)st.st_uid; m->gid = (uint32_t)st.st_gid; m->mode = (uint32_t)st.st_mode;
    /* Query/get typed scalar validity before interpreting any missing ACL.
     * A fresh filesec alone does not defeat statx1's realloc false success. */
    int present = 0;
    uid_t owner = 0; gid_t group = 0; mode_t mode = 0;
#define SCALAR(property, query_step, get_step, value, field, bit) do { \
    present = 0; e->step = query_step; errno = 0; \
    if (filesec_query_property(fs, property, &present) != 0) { e->system_errno = errno; goto done; } \
    if (!present) { rc = 0; goto done; } \
    e->step = get_step; errno = 0; \
    if (filesec_get_property(fs, property, &value) != 0) { e->system_errno = errno; goto done; } \
    m->field = (uint32_t)value; m->populated |= bit; \
} while (0)
    SCALAR(FILESEC_OWNER, BA_META_QUERY_OWNER, BA_META_GET_OWNER, owner, filesec_uid, BA_OWNER_PRESENT);
    SCALAR(FILESEC_GROUP, BA_META_QUERY_GROUP, BA_META_GET_GROUP, group, filesec_gid, BA_GROUP_PRESENT);
    SCALAR(FILESEC_MODE, BA_META_QUERY_MODE, BA_META_GET_MODE, mode, filesec_mode, BA_MODE_PRESENT);
#undef SCALAR
    if (m->filesec_uid != m->uid || m->filesec_gid != m->gid || m->filesec_mode != m->mode) { rc = 0; goto done; }
    e->step = BA_META_QUERY_ACL; errno = 0;
    if (filesec_query_property(fs, FILESEC_ACL, &present) != 0) { e->system_errno = errno; goto done; }
    m->acl_present = present;
    e->step = BA_META_FSTATFS;
    struct statfs mount = {0};
    if (fstatfs(fd, &mount) != 0) { e->system_errno = errno; goto done; }
    m->fsid[0] = mount.f_fsid.val[0]; m->fsid[1] = mount.f_fsid.val[1];
    m->mount_flags = mount.f_flags; m->mount_owner = mount.f_owner;
    if (mount.f_flags & MNT_LOCAL) m->mount_policy |= BA_MOUNT_LOCAL;
    if (mount.f_flags & MNT_ROOTFS) m->mount_policy |= BA_MOUNT_ROOTFS;
    if (mount.f_flags & MNT_IGNORE_OWNERSHIP) m->mount_policy |= BA_MOUNT_IGNORE_OWNERSHIP;
    if (mount.f_flags & MNT_UNION) m->mount_policy |= BA_MOUNT_UNION;
    memcpy(m->filesystem, mount.f_fstypename, sizeof(mount.f_fstypename));
    memcpy(m->mountpoint, mount.f_mntonname, sizeof(mount.f_mntonname));
    rc = 0;
done:
    filesec_free(fs);
    return rc;
}
#else
static int native_inspect(void *unused, int fd, struct ba_metadata *m, struct ba_probe_error *e)
{
    (void)unused; (void)fd; (void)m;
    *e = (struct ba_probe_error){BA_META_FSTATX, ENOTSUP}; return -1;
}
#endif
const struct ba_operations *ba_native_operations(void)
{
    static const struct ba_operations ops = {
#if defined(__APPLE__)
        1,
#else
        0,
#endif
        NULL, native_ids, native_root, native_at, native_inspect
    };
    return &ops;
}
const char *ba_stage_name(enum ba_stage value)
{
    static const char *const names[] = {"none", "request", "operations", "identity", "open", "metadata", "policy"};
    return (unsigned)value < sizeof(names) / sizeof(names[0]) ? names[value] : "unknown";
}
const char *ba_reason_name(enum ba_reason value)
{
    static const char *const names[] = {"none", "argument", "path", "profile", "unsupported", "not-root", "syscall", "adapter", "ownership", "flags", "type", "owner", "mode", "links", "filesec", "acl", "mount"};
    return (unsigned)value < sizeof(names) / sizeof(names[0]) ? names[value] : "unknown";
}
