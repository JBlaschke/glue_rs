# Fixed owned post-exec context probe v1

Status: decision-only contract before implementation. This is one ordinary-user
Darwin diagnostic, outside the collector, native runner, readers and shared CI.
It never obtains privilege, executes another program, selects an arbitrary
action/plugin, proves kernel exec or grants full Darwin/M2 acceptance. Its only
argv is `[exe, "--request-sha256", lowercase64hex]`. The future caller first
hashes the canonical request bytes, then derives that argv; the request never
contains its own hash. Supplied hash bytes bind a self-report, not proof that
the probe consumed or authenticated the original request.

The native program rejects UID/EUID/GID/EGID zero, unequal real/effective IDs,
IDs or PID values outside1..2147483647, and PGID different from PID. It reads
actual ordered kernel groups without account lookup:1..16 unique values through
2147483647, primary GID first, supplementary zero preserved when actually present.
No group sorting/truncation/fabrication makes an unsupported context pass.
Native ordinary-user positive controls are unavailable if the actual vector
violates these bounds/order; that is an explicit skip, not a fake positive.

Require empty environment; all catchable dispositions DFL; empty catchable mask;
disabled alternate signal stack; and blocking exact O_RDONLY stdin/O_WRONLY
stdout/stderr with CLOEXEC clear. Capture raw nonnegative Darwin F_GETFL/F_GETFD
values through INT_MAX. Reject known nonblocking, asynchronous and event-only
status modes; retain other bits as opaque data, never effects authorization.
Observe cwd stat(".") device/inode and actual PID/PPID/PGID. No cwd change,
pathname resolution claim or inherited parent context is invented.

Use self proc_pidinfo(PROC_PIDLISTFDS) with a fixed four-record buffer, strict
positive/aligned byte count below full capacity, poisoned unused entries and
exact unique numeric set0/1/2. A full buffer rejects rather than assuming the
kernel enumerated everything. Verify the set before and after the remaining
queries/root-regain check. Do not close an extra FD or open/query a process other
than self. This is numeric live-set observation under an owned single-threaded
fixture assumption, not endpoint/fileglob identity or historical FD effects.

Only after every initial check, call setuid(0) once. The sole acceptable result
is -1 with actual saved EPERM, followed by four IDs equal to their original
nonzero values. Unexpected success/error/changed IDs fails and exits without
rollback, further target actions or another privilege call. No claim about
saved IDs or a hostile kernel follows from this one negative probe. Recheck
ordinary observations after the attempt before encoding; any failure produces
no report. Native Linux is explicitly unsupported before these native operations;
pure codec/parser tests remain portable. No controller, source/admission
bypass, credential-drop adapter or test-only root CLI mode is added.

## Canonical report

Exactly256 bytes, unsigned big-endian except the signed root-regain result.
Host C models are never wire structs. All reserved/unused bytes are zero.

| Offset | Field |
| --- | --- |
| 0 | eight literal bytes GLUENP01 |
| 8,10 | u16 version1, u16 length256 |
| 12 | u32 profile1 |
| 16 | supplied request SHA256,32 bytes |
| 48,52,56 | u32 actual PID, PPID, PGID (PID!=PPID; PGID==PID) |
| 60,64,68,72 | u32 real UID, effective UID, real GID, effective GID |
| 76 | u32 group count1..16 |
| 80 | sixteen ordered u32 groups, ending143; unused slots zero |
| 144,152 | u64 opaque cwd device, inode |
| 160 | u32 FD count3 |
| 164,168,172 | u32 exact numeric FDs0,1,2 |
| 176 | three actual Darwin F_GETFL u32 values, ending187 |
| 188 | three actual Darwin F_GETFD u32 values, ending199 |
| 200,204 | i32 setuid(0) result-1; u32 saved Darwin EPERM1 |
| 208,212,216,220 | four post-attempt IDs, equal original four |
| 224 | u32 signal policy1: verified DFL/empty mask/no alternate stack |
| 228 | u32 environment count0 |
| 232 |24 reserved zero bytes |

Device/inode/digest values are opaque including zero. Native-width conversions
must be checked, not truncated. Darwin device bits are converted through the
unsigned native-width device type; inode is its unsigned native integer value.
The pure codec requires exact lengths, closed header/profile/policy constants,
canonical fields and expected request digest. It clears encode/decode outputs
on failure. Wide host fields let validation reject values before narrowing.
Golden vectors are independently built using Python struct/hashlib, with exact
report bytes and report SHA256 retained as synthetic codec controls.

No stdout write occurs until all checks and encoding succeed. Then attempt one
blocking256-byte write; do not retry a short/failed report or change signal
policy to hide a broken peer. Context/codec failures produce only a bounded
stage/positive saved errno diagnostic attempt on stderr and nonzero exit.
A stdout failure can leave a partial prefix, and default unblocked SIGPIPE can
terminate before stderr; retain those bytes/exit status rather than promising
rollback. Consumers require exactly256 bytes AND normal exit0, then strict decode
and independent comparison with READY/request/known child. Even that result is
only a diagnostic self-report, never exec or full acceptance. Do not add a
post-success close/finalization action that could silently invalidate a report.

## Controls and safety

Implement pure canonical parser/codec boundaries and independent golden controls
first, with no native observation/privilege call. Compile/review the native source
before any ordinary-user execution. Later native tests use only a deliberately
owned child with its own process group, empty environment, blocking private
stdio and a parent-owned monotonic deadline/reap path; parent context is unchanged.
No hostroot, elevation, VM, SIP or executable installation/provisioning occurs.
Native negative controls cover malformed argv/environment, initial context,
extra/high FD, flags, ignored/masked signals and noncanonical group preconditions.
A genuine ordinary-user positive must perform the failed setuid(0) check; no
injected report or callback is relabeled native evidence.

Source grounding: the local Darwin SDK sys/fcntl.h supplies access/nonblock/
async/event-only/CLOEXEC values; sys/signal.h and signal APIs supply catchable
mask/disposition/alternate-stack checks; libproc/sys/proc_info.h supply the
proc_fdinfo layout. Existing reviewed target-descriptors and target-credentials
helpers at base4e59295 ground bounded live-FD and actual ordered-group handling.
These are current host ABI controls, not installed guest-kernel attestation.
