# Owned-child credential primitive

Status: bounded implementation; native Darwin privileged transition calibration
is unavailable. This does not change the capture controller or trace acceptance.

The existing collector runs its target with inherited root credentials. Add a
separate reusable C primitive before integrating any target launch mode. The
caller must select explicit numeric IDs and groups before forking an owned,
single-threaded child; neither environment variables nor account lookup select
an identity. The original controller PID is an explicit input, checked against
the calling PID and parent PID to catch accidental controller invocation. This
check cannot establish ownership against a dishonest caller.

Validate the entire request and syscall table before any mutation. Use a bounded
policy of UID/GID 1..2147483647 and 1..16 ordered groups, with the selected primary
GID first. Group entries are 0..2147483647; group 0 is allowed only as an explicit
supplementary entry. Reject duplicates, sentinels, overflow and unsupported
counts. The optional text parser accepts only length-delimited canonical ASCII
decimal tokens, without signs, whitespace, embedded NUL, leading zeroes or
coercion of other types. The typed C request uses uint64_t fields and is checked
again when consumed, before conversion to native uid_t/gid_t.

Call setgroups, setgid, then setuid, stopping on the first failure. Read back real
and effective UID/GID and the full kernel group vector into a fixed-size buffer;
require exact count, values and order. No sorting or group synthesis is allowed.
Every failure reports a stage, reason and original positive syscall errno when
applicable. Once a mutation was attempted the child must exit on failure;
rollback or continuing to a target is forbidden. The primitive does not exit or
launch anything itself. An injected syscall table supports ordering and failure
controls without changing host credentials; the production adapter calls libc.

Apple XNU reference f6217f891ac0bb64f3d375211650a4c1ff8ca1ea provides the
grounding, not an exact identity claim about the guest kernel:

- [kern_prot.c](https://github.com/apple-oss-distributions/xnu/blob/f6217f891ac0bb64f3d375211650a4c1ff8ca1ea/bsd/kern/kern_prot.c#L680-L765)
  describes privileged setuid changing real/effective/saved UID; lines 928–993
  describe the corresponding setgid behavior. This API verifies only the real
  and effective IDs it can query portably, not saved IDs or root-regain behavior.
- The same file, lines 396–449 and 1301–1457, stores the effective GID at group
  slot zero, exposes the ordered vector through getgroups, and replaces an empty
  setgroups vector with GID 0. Hence the nonempty, primary-first requirement.
- [kern_credential.c](https://github.com/apple-oss-distributions/xnu/blob/f6217f891ac0bb64f3d375211650a4c1ff8ca1ea/bsd/kern/kern_credential.c#L4096-L4163)
  preserves ordinal group order and distinguishes explicit groups from memberd
  participation. This primitive intentionally selects explicit groups; it does
  not reconstruct a login context.
- The inspected macOS SDK sys/syslimits.h defines NGROUPS_MAX=16 and
  UID_MAX=GID_MAX=2147483647. These are declared conservative API bounds, not a
  claim that wider IDs or more groups work on every native host.

The retained source assessment records kern_prot.c SHA256
988c19ea6b73574292a70ea2ce3174374a7ec70de76ffe6a8d4f07675c846014 and
kern_credential.c SHA256
ad41648405d7e19714a2a2f214934a889a04635d9fb8434730b8c2a9df00de12.

The caller must have no assumed per-thread credentials and must use this only
in its owned child. Success proves the requested observations at return, not a
complete login/Mach/audit/session identity, target exec behavior or irrevocable
privilege confinement. FD closure, cwd, signals, process groups, launch gates,
set-ID target policy, tracing and full R02 acceptance remain separate work. No
collector, reader, captured stream or guest security policy changes here.
