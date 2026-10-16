# Bound parent-only admission to a protected Darwin fixture path

Status: approved bounded implementation plan; no privileged native positive,
controller integration, target execution or full trace acceptance.

The helper admits filesystem metadata for one deliberately narrow physical path:
`/System/Volumes/Data/Library/GlueMVPFixtures/<build-id>/<leaf>`. The final two
components are bounded ASCII names, selected by the outer trusted controller.
They are not arbitrary executable authorization. The controller must still
select an exact reviewed fixture/catalog/build, hash the held executable FD,
and enforce its argument/load-command policy. No caller hash, `verified` bit or
synthetic operation table authorizes a native target.

Proposed API, confined to the new `bootstrap-admission` directory:

```
ba_admit_protected_executable(request, operations, result, error)
ba_native_operations()
```

The request carries the exact bounded path bytes and a deployment profile with
root and Data device/fsid identities. That profile comes from independently
reviewed protected provisioning, not discovery of whichever mounts happen to be
present. Both mounts must be local APFS, owned by UID0 and ownership-enforcing;
union/ownership-ignored mounts reject. Held-FD `fstatfs` must report the exact
root mountpoint `/` through `/System/Volumes`, then the exact Data mountpoint
`/System/Volumes/Data` from Data onward. Root must have MNT_ROOTFS; Data must not.
Root and Data profiles must differ. There is exactly this one admitted mount
transition and no further transition, including one with an unexpected mounted
path. This avoids inferring `/Library` firmlink behavior. These records do not
attest APFS volume-group membership or an exact guest kernel source revision.
An unavailable or uncalibrated deployment profile remains unsupported.

Native support is Darwin only. The admission function requires real and
effective UID0 before opening anything. Native Linux rejects as unsupported
before calling operation callbacks. A separately labelled injected model can
exercise scalar/policy/error boundaries; it cannot manufacture native root
admission evidence. No CLI, privilege acquisition or metadata mutation exists.

Walk one literal component at a time from an opened `/`, retaining each opened
FD: root, System, Volumes, Data, Library, GlueMVPFixtures, build-id and leaf.
Use O_NOFOLLOW/O_CLOEXEC for every open, O_DIRECTORY for ancestors and O_NONBLOCK
for the read-only leaf. Recheck descriptor flags, exact access mode and native
file type. Reject symlinks, special files and unknown/malformed components;
never use realpath, access or a full-path no-follow open as a substitute.
All ancestors must be UID0-owned directories, without group/world write or
set-ID bits. The leaf must be a UID0-owned single-link ordinary file with exact
0555 permission/special bits. Group ownership is retained, not resolved by name.
No output is created; no descriptor is passed to a child by this helper.

Every held object uses fresh parent-only `filesec_init` storage and successful
`fstatx_np`. Require OWNER, GROUP and MODE property queries to succeed with
nonzero presence, their typed getters to succeed, and native uid_t/gid_t/mode_t
values to equal the same returned stat fields. Only then interpret a successful
FILESEC_ACL query with presence zero as absence. Any present ACL, missing scalar,
query/get error or mismatch rejects. Presence is not equivalent to scalar value
nonzero: UID/GID0 are expected. A presence result need not equal1.

This guard is required by the pinned Apple Libc candidate
[statx_np.c](https://github.com/apple-oss-distributions/Libc/blob/71bbe350ab79eef58113991d817ccc6165061a64/sys/statx_np.c#L130-L220):
a failed ACL-buffer realloc can return unchanged error0 before populating a
fresh filesec. [filesec.c](https://github.com/apple-oss-distributions/Libc/blob/71bbe350ab79eef58113991d817ccc6165061a64/gen/filesec.c#L190-L341)
sets scalar validity bits directly and returns bit masks for presence. Ordinary
successful no-ACL processing can leave errno=EINVAL from an ignored NULL
ACL_ALLOCSIZE setter; do not require errno zero after a successful call. These
pinned bytes are source grounding, not a claim the current host/guest Libc is
identical. The independent source review is retained at
`/private/tmp/glue-bootstrap-admission-source-review-20261016`.

All storage is bounded and fixed-size. The result retains the exact opened FD
prefix and component stat/filesec/mount records, with `ready=1` only after the
complete walk. On failure it is never usable as admission; the caller must close
only that newly owned prefix once or exit. An impossible callback open result
that aliases a held FD or has uncertain ownership requires controller exit;
never close a guessed or original descriptor. No close/retry/rollback is hidden
inside admission. Errors retain first stage/reason/original errno/component.
All arguments/storage/tables must be valid, stable and nonoverlapping, and an
output must not already own FDs. The operation table is trusted implementation
code, not an untrusted plugin boundary.

Protected provisioning must create new root-controlled files, close preparation
writers and retain its source/build history. No privileged actor may change the
namespace, mounts, metadata or contents during admission and later pathname
execve; no preexisting writable alias may survive insecure provisioning. The
held FD and hash do not pin a later pathname execve against a privileged mutator.
Single-link/root/no-ACL metadata cannot prove historical capability absence.
`/tmp`, `/private/tmp`, user homes and worktrees remain rejected even when a leaf
is root-owned0555. No unsafe fallback or root-opened cwd shortcut exists.

Controls will cover canonical paths, mount boundary/profile/ACL/scalar false
success, failed and impossible opens, exact ownership prefixes and descriptor
flags using isolated injected operations. Unprivileged Darwin controls may query
fresh fstatx/filesec on already root-owned directories and demonstrate native
nonroot rejection; they cannot claim a protected native positive. Linux tests
exercise the injected model and explicit unsupported native adapter only. No
root execution, target launch, VM/security change, output creation, hash/catalog
implementation, cwd/gate/credential setup or tracing acceptance is in scope.
