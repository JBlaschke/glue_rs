#ifndef GLUE_BOOTSTRAP_ADMISSION_H
#define GLUE_BOOTSTRAP_ADMISSION_H

#include <stddef.h>
#include <stdint.h>

#define BA_COMPONENT_COUNT 8
#define BA_NAME_MAX 64
#define BA_PATH_MAX 256
#define BA_MOUNTPOINT_MAX 1024
#define BA_FS_TYPE_MAX 16
#define BA_PREFIX "/System/Volumes/Data/Library/GlueMVPFixtures/"

enum ba_mount_policy {
    BA_MOUNT_LOCAL = 1, BA_MOUNT_ROOTFS = 2,
    BA_MOUNT_IGNORE_OWNERSHIP = 4, BA_MOUNT_UNION = 8
};
enum ba_population { BA_OWNER_PRESENT = 1, BA_GROUP_PRESENT = 2, BA_MODE_PRESENT = 4 };
struct ba_mount_id { uint64_t device; int32_t fsid[2]; };
struct ba_deployment { struct ba_mount_id root, data; };
struct ba_request {
    const unsigned char *path; size_t path_length;
    struct ba_deployment deployment;
};
struct ba_metadata {
    uint64_t device, inode, links;
    uint32_t uid, gid, mode;
    uint32_t populated, filesec_uid, filesec_gid, filesec_mode;
    int acl_present; /* Raw property presence; exactly zero required. */
    int descriptor_flags, status_flags;
    int32_t fsid[2];
    uint64_t mount_flags; /* Native raw flags, retained without cross-OS interpretation. */
    uint32_t mount_policy, mount_owner;
    char filesystem[BA_FS_TYPE_MAX], mountpoint[BA_MOUNTPOINT_MAX];
};
enum ba_metadata_step {
    BA_META_NONE, BA_META_FD_FLAGS, BA_META_STATUS_FLAGS, BA_META_FILESEC_INIT,
    BA_META_FSTATX, BA_META_QUERY_OWNER, BA_META_GET_OWNER,
    BA_META_QUERY_GROUP, BA_META_GET_GROUP, BA_META_QUERY_MODE, BA_META_GET_MODE,
    BA_META_QUERY_ACL, BA_META_FSTATFS
};
struct ba_probe_error { enum ba_metadata_step step; int system_errno; };
struct ba_component {
    int fd; char name[BA_NAME_MAX + 1]; struct ba_metadata metadata;
};
struct ba_result {
    struct ba_component components[BA_COMPONENT_COUNT];
    size_t owned_count, checked_count;
    int ready;
};
enum ba_stage { BA_STAGE_NONE, BA_STAGE_REQUEST, BA_STAGE_OPERATIONS,
    BA_STAGE_IDENTITY, BA_STAGE_OPEN, BA_STAGE_METADATA, BA_STAGE_POLICY };
enum ba_reason { BA_REASON_NONE, BA_REASON_ARGUMENT, BA_REASON_PATH,
    BA_REASON_PROFILE, BA_REASON_UNSUPPORTED, BA_REASON_NOT_ROOT,
    BA_REASON_SYSCALL, BA_REASON_ADAPTER, BA_REASON_OWNERSHIP,
    BA_REASON_FLAGS, BA_REASON_TYPE, BA_REASON_OWNER, BA_REASON_MODE,
    BA_REASON_LINKS, BA_REASON_FILESEC, BA_REASON_ACL, BA_REASON_MOUNT };
struct ba_error {
    enum ba_stage stage; enum ba_reason reason; int system_errno;
    size_t component; /* BA_COMPONENT_COUNT means no component. */
    enum ba_metadata_step metadata_step;
    int ownership_uncertain; /* Exit controller; never close an unreturned/guessed FD. */
};
struct ba_operations {
    int supported;
    void *context;
    int (*ids_fn)(void *, uint64_t *, uint64_t *, int *);
    int (*open_root_fn)(void *, int *);
    int (*openat_fn)(void *, int, const char *, int, int *); /* last int: leaf 0/1 */
    int (*inspect_fn)(void *, int, struct ba_metadata *, struct ba_probe_error *);
};

/* Parent-only: stable, trusted, nonoverlapping storage/operations and no concurrent
 * namespace/FD/OFD/metadata/mount mutation. Output must not already own FDs.
 * Deployment profile comes from independently reviewed native provisioning;
 * caller-selected metadata, hashes or injected tables do not authorize a target.
 * No close or mutation is performed. On any failure ready=0: caller closes only
 * the exact newly owned prefix once or exits. On ownership_uncertain, exit instead
 * of closing guessed FDs. No target launch, catalog/hash matching or cwd support.
 * Success leaves all eight controller-owned CLOEXEC FDs open. The outer controller
 * must exclude them from the child keep set and enforce the protected-path
 * invariant through any later pathname execve. This API does not attest it. */
int ba_admit_protected_executable(const struct ba_request *, const struct ba_operations *,
                                 struct ba_result *, struct ba_error *);
/* Its inspect callback also supports parent-only unprivileged read-only API
 * diagnostics. Such a query is not native admission or an authorization API. */
const struct ba_operations *ba_native_operations(void);
const char *ba_stage_name(enum ba_stage);
const char *ba_reason_name(enum ba_reason);

#endif
