This parent-only helper checks a narrow protected filesystem path and retains
its opened FDs and metadata. It is not connected to a controller or collector.
The [decision](../../../../docs/decisions/mvp-r02-bootstrap-admission.md) precedes
the API and records its trusted deployment assumptions.

`ba_admit_protected_executable` accepts exactly
`/System/Volumes/Data/Library/GlueMVPFixtures/<build-id>/<leaf>` as an explicit
byte span. Both variable components are 1..64 ASCII bytes, start with an ASCII
letter/digit and then contain only letters/digits/underscore/hyphen/dot. Empty,
relative, dot/dot-dot, NUL, non-ASCII, nested or trailing components reject.
The outer controller must choose both names through its reviewed closed fixture
catalog; this metadata helper does not authorize arbitrary code in that tree.

The request's root/Data deployment profile contains exact device/fsid tuples
from independently reviewed native provisioning. It is not a discovery option,
caller hash or privileged trust boolean. The root mount must be local APFS,
owner0, ownership-enforcing and marked MNT_ROOTFS, with mountpoint `/`. This
profile applies to `/`, System and Volumes. Exactly at Data it changes to the
reviewed Data identity, whose mountpoint is `/System/Volumes/Data`, without
MNT_ROOTFS; all remaining objects stay there. Union, ignored-ownership, foreign,
nonlocal, user-owned or unprofiled mounts reject. Raw native flags are retained;
other flags are not interpreted as authorization. No APFS volume-group or
firmlink attestation is claimed. The physical path avoids `/Library` firmlink
inference. If that path/profile is unavailable, admission stays unsupported.

All eight descriptors stay open: `/`, System, Volumes, Data, Library,
GlueMVPFixtures, build-id, leaf. Single-component read-only openat uses NOFOLLOW,
CLOEXEC and DIRECTORY for ancestors; the leaf uses NONBLOCK and must be an
ordinary single-link UID0-owned exact0555 file. All directories are UID0-owned,
without group/world-write or set-ID bits. Every FD is queried with fresh native
filesec storage; OWNER/GROUP/MODE must be present, successfully obtained with
native typed getters and equal to the same returned stat fields before absent
ACL is interpreted. Any ACL, even empty/deny/inheritable, rejects. This avoids
pinned Libc's possible success-with-unpopulated-filesec realloc failure. Valid
presence is nonzero, not necessarily1; successful calls may leave errno set.
The fresh read-only native query controls are API observations, not a native
protected-tree positive.

`ready=1` only describes successful metadata checks under those assumptions.
The outer controller separately hashes the held leaf, matches the exact
reviewed catalog/build/load-command provenance and keeps the protected-path
invariant through any later pathname execve. No privileged actor may mutate
namespace/mounts/metadata/content, and provisioning must not leave historical
writable aliases. Root/no-write/single-link/no-ACL metadata cannot prove that
history. `/tmp`, `/private/tmp`, homes and worktrees remain rejected, even with a
root-owned0555 leaf. No cwd shortcut, target launch, privilege acquisition,
output creation or execution/tracing success claim exists.

Inputs, operation table, result and error storage must be valid, stable and
nonoverlapping. The output must not already own FDs. The native table is trusted
code; injected operations exercise a model only. Native admission requires both
real and effective UID0 before any opens. Native Linux reports unsupported before
callbacks, even when run as root. The inspect callback may be called directly
for unprivileged read-only diagnostics; that is not admission. Do not use an
injected success or direct inspection to bypass native admission preflight.

On failure `ready=0`; `owned_count` is the exact newly opened prefix and
`checked_count` counts completed checks. Caller closes only those FDs once or
exits; no hidden close, retry or cleanup mutation occurs. Ordinary syscall
failures preserve stage/errno/component and metadata substep. An impossible
open result with uncertain ownership requires controller exit; never close a
guessed FD. A partial result cannot authorize a target. The caller excludes
admission handles from any child keep set. Storage and call counts are bounded;
this synchronous helper does not interrupt a stalled kernel/filesystem call or
provide a process deadline. The trusted outer controller owns that liveness
policy and must not admit unreviewed mounts or asynchronous mutation.

Run the focused controls on an ordinary account:

```
python3 fixtures/mvp/macos-trace/bootstrap-admission/test_bootstrap_admission.py -v
BA_SANITIZE=1 python3 fixtures/mvp/macos-trace/bootstrap-admission/test_bootstrap_admission.py -v
```

The labelled model cases cover complete/partial walks, precise failure
ownership, the scalar false-success route and all ancestor mount checks.
Darwin native cases only verify nonroot admission rejects before opens and make
fresh read-only filesec queries on existing root-owned system directories,
checking unchanged descriptor/metadata identity. They neither stage a protected
fixture nor run admission as root. Native Linux tests only its explicit
unsupported path; its injected model is portable, without pretending fstatx or
APFS calibration. No host sudo, target execution, VM or security change occurs.
