# Owned-child numeric descriptor closure

Status: bounded helper implementation; collector integration and privileged
guest bootstrap calibration remain unavailable. This is not trace acceptance.

Add a separate C primitive under `macos-trace/target-descriptors`. The caller
must prepare its owned, single-threaded child and declare exactly five kept
descriptor numbers: stdin 0, stdout 1, stderr 2, launch-gate reader and status
writer. The controls must be distinct and at least 3. No stdio remapping, channel
creation, credential drop, cwd operation or gate protocol belongs to this helper.

Before invoking it, the caller must block all blockable signals, rule out every
concurrent FD mutation, and ensure reviewed atfork callbacks/handlers did not
close or rebind any prepared endpoint. The helper verifies the current signal
mask, controller/caller/parent PID relation, numeric keep list and callback table;
these checks cannot prove ownership, absence of other threads or endpoint object
identity. They catch accidental misuse within the stated caller contract.

The caller preallocates a `td_record` scratch array of 6..4097 entries. This
allows 5..4096 live descriptors plus one spare. The cap bounds live count and
storage, not the largest numeric FD. Read the actual child's own descriptor table
using Darwin `proc_pidinfo(PROC_PIDLISTFDS)`. Reject zero/negative, oversized,
misaligned or capacity-equal returns, duplicate/negative FD numbers and absent
keep entries. Close every nonkeep number exactly once; any error or uncertainty
stops without retry. Rescan with the same checks and require exactly the five
declared numbers. Never infer completeness from soft/hard RLIMIT or a parent
snapshot, sort away duplicates, or normalize an invalid response.

Errors carry the stage, reason, saved positive syscall errno when supplied,
failed FD if applicable and a `closure_attempted` flag. Any failure after that
flag becomes true requires immediate child exit without target exec or rollback.
Even pre-closure failures cannot authorize a launch. The primitive returns for a
future fixed status writer; it does not implement that writer or select an exit
status. The caller must enforce an external whole-child deadline for blocked or
guarded closes and retain responsibility for its actual unreaped child.

Primary source grounding uses Apple XNU commit
f6217f891ac0bb64f3d375211650a4c1ff8ca1ea as a candidate, not an identity claim
about the guest's installed kernel:

- [proc_info.c:490–553](https://github.com/apple-oss-distributions/xnu/blob/f6217f891ac0bb64f3d375211650a4c1ff8ca1ea/bsd/kern/proc_info.c#L490-L553)
  reads allocated table capacity before locked iteration and clips to the
  supplied buffer. A NULL-buffer query returns table capacity plus padding,
  not live count or maximum FD. Spare capacity requires no concurrent mutation.
- [kern_descrip.c:678–702](https://github.com/apple-oss-distributions/xnu/blob/f6217f891ac0bb64f3d375211650a4c1ff8ca1ea/bsd/kern/kern_descrip.c#L678-L702)
  iterates settled entries through `fd_afterlast`; sparse high FDs are visible.
  Its fork-copy code at 955–1004 creates a separate child table and omits
  confined/reserved/CLOFORK entries. Its close code at 5420–5440 does not use a
  soft-RLIMIT enumeration horizon and can encounter guarded descriptors.
- [libproc.c:100–110](https://github.com/apple-oss-distributions/xnu/blob/f6217f891ac0bb64f3d375211650a4c1ff8ca1ea/libsyscall/wrappers/libproc/libproc.c#L100-L110)
  maps syscall error to zero. Save errno immediately; zero with no errno is
  still invalid for this nonempty keep-set contract. The thin source wrapper
  is not a portable async-signal-safety guarantee or guest binary attestation.

The inspected SDK declares 8-byte `proc_fdinfo` with int32 FD and uint32 opaque
type. The Darwin adapter checks that layout at compile time. Linux explicitly
returns ENOTSUP before attempting closure, while injected controls remain usable.
Native unprivileged Mac controls run only in forked children and test sparse
sentinels above subsequently lowered soft and hard limits, exact keep numbers,
and unchanged parent descriptors. They calibrate this host's ordinary libproc
numeric closure, not a privileged guest launch, endpoint provenance, cwd/Mach/
fileport closure, login context or full R02 acceptance.
