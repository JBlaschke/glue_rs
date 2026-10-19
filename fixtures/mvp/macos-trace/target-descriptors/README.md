# Owned-child numeric descriptor closure

This standalone C helper closes every inventoried descriptor except the five
declared numbers `[0,1,2,gate_reader,status_writer]`, then verifies an exact numeric
rescan. It is not integrated with the collector or a target launcher. It does
not authorize objects behind those numbers or provide full trace acceptance.

Before fork, allocate a `struct td_record` scratch array and prepare a valid
`td_plan`. Capacity is 6..4097 records and includes a mandatory spare entry, so
it permits at most 5..4096 live descriptors. This is a count/storage bound, not a
maximum FD value. The gate reader and status writer must be distinct integers
at least 3, with stdio already mapped to 0/1/2. This helper never opens, duplicates,
remaps or changes CLOEXEC flags. Stdio sources, channels, direction, flags and
endpoint object provenance must already be correct under the caller's policy.

Only in the caller's **owned, single-threaded forked child**, call:

```c
struct td_error error;
int result = td_close_in_owned_child(&plan, original_controller_pid,
                                    td_native_operations(), &error);
```

The original controller PID must be captured before fork. The helper verifies
that its caller differs from the controller and that its parent equals that
controller. This catches accidental misuse; it cannot prove hostile ownership
or the absence of other threads.

Signals must already be blocked before earlier child setup; the caller must
prevent inherited handlers or atfork callbacks from mutating descriptors or
closing/rebinding prepared endpoints. Block before fork when that is needed to
prevent an earlier handler window. The helper reads the current mask and checks
Darwin signals 1..NSIG-1 except unmaskable SIGKILL/SIGSTOP. That readback does not
attest what handlers did before the check. No concurrent FD mutation is allowed.
The helper does not reset handlers or alter the mask. Later unblocking requires
an independent reviewed signal policy. Linux's reserved signal policy is not
inferred from Darwin; its native adapter is explicitly unsupported.

The plan, error output, callback table/context and scratch must be valid,
nonoverlapping objects with stable lifetime for the entire call. Only the
inventory callback may fill scratch, within the supplied byte bound; other
callbacks must not modify scratch or caller inputs. The helper snapshots the
plan and callback table before use and allocates nothing. The injected syscall
table is for controlled tests, not an untrusted plugin boundary.

The Darwin adapter invokes `proc_pidinfo(getpid(), PROC_PIDLISTFDS, 0, ...)` with
the preallocated array. Compile-time assertions check `proc_fdinfo` size, both
field offsets, alignment and bounded int byte count. Returned type metadata is
opaque. The helper requires a positive, aligned byte count strictly below the
supplied capacity; rejects duplicates, negative FDs and missing kept numbers;
then closes each nonkeep number exactly once. It does not enumerate up to an
RLIMIT, query the NULL-buffer capacity, sort away duplicates or accept a clipped
capacity-equal response. A second inventory must contain exactly the five kept
numbers. Every rescan passes the same validation rules.

Libproc can return zero on syscall failure, so the native adapter clears and
saves errno around that call. Zero without errno still fails this nonempty-set
contract. Errors expose stage, reason, saved positive syscall errno, affected FD
when known, and `closure_attempted`. Unsupported native platforms report
`operations/unsupported` with ENOTSUP before callbacks/closure. An unchanged
successful syscall's stale errno is never interpreted as a failure.

`closure_attempted` becomes true **before the first close**, even if it errors.
After any subsequent failure, immediately exit the child without target exec,
retry or rollback. In particular, do not retry EINTR or close an uncertain reused
number. Even a failure before closure does not authorize launch. The primitive
returns only so a future fixed child status writer can report the result; that
protocol and exit status are outside this module. Success with no nonkeep FDs
leaves `closure_attempted` false. All error fields reset on each invocation.

The caller must impose an external whole-child deadline: a guarded/blocked close
can fail or stall. A child with signals blocked cannot rely on SIGALRM. Cleanup
must track and reap the caller's actual unreaped child, not signal a remembered
PID that might have been reused. A matching rescan does not establish absence of
concurrent mutation or keep-object rebinding; these remain caller preconditions.

This numeric property does not remove inherited cwd, Mach/fileport rights or
audit/session context. Absolute cwd traversal under dropped credentials, signal
policy, credential drop, gate/READY/GO, exec-success proof, parent/watchdog writer
closure and endpoint validation remain independent work. Native privileged guest
libproc/bootstrap calibration remains unavailable. See the
[decision](../../../../docs/decisions/mvp-r02-target-descriptors.md).

Run native compile and controls without elevation:

```sh
python3 fixtures/mvp/macos-trace/target-descriptors/test_target_descriptors.py -v
```

Injected controls cover bounds, all callback preflights, owner/signal checks,
clipped/zero/error/misaligned/duplicate/negative/missing inventories, opaque type
values, very high numeric FD values, exact close ordering/no retry, rescan
failures and initialized error outputs. Linux runs those controls and an explicit
unsupported-native check; no libproc behavior is claimed there.

Native Mac controls only close descriptors inside an unprivileged owned child.
They preallocate scratch before fork, create sparse high sentinels within the
existing limit, lower **only the child's** soft and hard limits below a sentinel,
verify exact keep numbers, check missing stdio/unmasked-signal/capacity failures,
and confirm parent-owned sentinels and limits remain unchanged. A parent-side
monotonic deadline kills only its still-unreaped child on timeout, reaps and
fails. No limit is raised. The explicit native precondition is current soft FD
capacity above 128; a lower-capacity/root host reports a skip instead of claiming
execution. No host sudo, VM, security, target exec or collector action occurs.
