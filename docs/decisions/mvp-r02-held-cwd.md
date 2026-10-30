# Select the held admitted working directory in the object child

29 October 2026. Implementation decision; full native tracing/M2 acceptance remains open.

The object-profile child must select the already admitted directory descriptor,
`admission.components[6].fd`, after a successful credential drop and before
numeric descriptor closure. It must not resolve `a->cwd` again for this step.
The legacy profile keeps its existing pathname behavior. The directory FD is
borrowed: no open, close, duplicate, remap or flag update is performed, and it
is not added to the five kept descriptors. The later descriptor closure closes
that FD while the kernel's current-directory reference persists.

Add a bounded owned-child primitive with a copied request, operation table and
cooperative original-deadline callback. It checks the original pre-fork owner,
actual child/parent PIDs and blocked-signal state; takes two complete held-FD
stat/descriptor/status-flag samples; requires a directory, read-only access,
CLOEXEC and matching request device/inode; calls `fchdir` exactly once; then
checks the original deadline, held-FD metadata/flags and effective `stat(".")`
readback. Final PID/mask/deadline checks precede publishing a complete result.
No retry, rollback, permission inference or target release is attempted.

Every failure clears ready output and preserves its stage, valid saved errno
and an explicit mutation-attempt bit. The bit is set immediately before the
fchdir callback, including syscall refusal, and stays set for later readback,
identity, flag, guard or deadline failures. A successful syscall followed by
failure may already have changed the child's CWD; the only allowed caller
action is child exit/owned cleanup. Deadline callbacks return 0 on success,
-1 with positive errno on syscall failure, -1 with zero errno on deadline
failure; any other return or negative errno is an adapter fault. Checks surround
finite synchronous calls; they do not provide hard cancellation or preemption.

The object runner delegates checks to `nr_before` with its existing absolute
attempt deadline and retains its outer before/after checks. Request and READY
continue comparing the actual `stat(".")` device/inode/type. BW_CWD error detail
packs the helper stage in the low byte and mutation-attempt in bit8, fitting the
existing nonnegative int32 detail field. Existing BW mutation flags, record
formats and wire revision stay unchanged. Failed/partial credential drop must
never reach the CWD helper, closure, READY, GO or exec.

The exact installed SDK declares `fchdir` in unistd.h line564; its chdir(2) page
requires directory search access and documents EACCES/EBADF/ENOTDIR/EINTR/EIO.
The installed kernel stub exports fchdir and __pthread_fchdir separately.
At pinned XNU f6217f891ac0bb64f3d375211650a4c1ff8ca1ea,
[vfs_syscalls.c](https://github.com/apple-oss-distributions/xnu/blob/f6217f891ac0bb64f3d375211650a4c1ff8ca1ea/bsd/vfs/vfs_syscalls.c#L4347)
checks a live VDIR, MAC policy and KAUTH_VNODE_SEARCH (4376–4400), may cross a
mounted-here vnode (4402–4414), and separates thread uu_cdir from process
fd_cdir (4424–4442). sys_fchdir uses process mode (4459–4461), which does not
clear a preexisting thread-CWD override. Normal fork passes the calling thread's
CWD through kern_fork.c1031–1037 and fdt_fork in kern_descrip.c897–905 promotes
that reference to the child's process CWD. The fixed caller history must forbid
creating a child thread override or concurrent CWD/FD/namespace/mount mutation;
stat(".") verifies the effective view rather than asserting override absence.

Device/inode/type/owner/link/mode and flag samples are conditional metadata,
not atomic snapshots, OFD identities, vnode generation, namespace provenance,
permission guarantees or future-call bindings. Readback rejects observed mount
or effective-CWD differences, but sampled equality cannot prove those histories.
The legacy protected-path/held-executable invariant for later pathname exec
still applies. No credential-transition proof is inferred from ordinary native
tests; source-isolated runner controls establish the credential/helper ordering.

Meaningful native unprivileged controls rename the original held directory and
replace its old path, then require child `.` to identify the original held
object and parent CWD to remain unchanged. They cover wrong/closed/non-directory
FDs, opened-then-no-search denial where actual permissions support it, preserved
borrowed FD flags and descriptor closure with CWD persistence. Injected controls
cover every read/mutation callback failure, unstable observations, anomalous
returns, ownership/mask guards and failures after successful mutation. Pure,
source-isolated and actual native results are recorded separately.

Public source and exact SDK bytes/hashes are retained only in the ignored
.evidence-local/sources/held-cwd-20261029 directory. No VM, sudo, SIP change,
privileged native admission or raw-proof publication is performed. Configured
source registries remain guarded at their existing reviewed C; after independent
implementation review, root creates the separate new C→R registration.
