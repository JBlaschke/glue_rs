# Owned endpoint copies and child stdio mapping

This standalone C helper prepares five already-owned diagnostic endpoint sources
and maps only the child stdio slots. No collector, target launcher or bootstrap
protocol is integrated. It neither opens source paths nor closes descriptors.

`te_request.source` is ordered `[stdin,stdout,stderr,gate_reader,status_writer]`.
All five numbers must be nonnegative and distinct. Numeric aliases, including
merged stdout/stderr, reject; different numbers still do not prove different
objects. The caller must establish object provenance, endpoint roles, no
unintended aliasing and no concurrent FD/shared-status mutation or callback/
handler close/rebind. All request/output/error/operation/context objects must be
valid, stable and nonoverlapping for the call. Injected operations are trusted
test adapters, not a plugin security boundary.

Every source is checked before any duplication:

- stdin: exact O_RDONLY, blocking, regular file or FIFO. A character device is
  supported **only under caller policy that it deliberately opened `/dev/null`**;
  fstat shape alone cannot identify which device. There is no major/minor
  hardcoding or child pathname/name-service lookup.
- stdout/stderr: exact O_WRONLY, blocking, regular file or FIFO capture sinks.
- gate reader/status writer: exact O_RDONLY/O_WRONLY respectively, **nonblocking
  FIFOs**. Before normalization/fork, the caller sets and checks O_NONBLOCK on
  **all four** private control-pipe ends, including the controller GO writer and
  status reader outside this five-source helper. This matches the separate
  bounded bootstrap-IO contract. The helper never calls F_SETFL.

O_RDWR, directories, sockets, character output, asynchronous and path/event-only
modes are unsupported. Other F_GETFL bits remain caller opening-policy data;
they are not interpreted as object provenance or an effects authorization.

In the owned controller, call `te_prepare_owned_sources(request,ops,output,error)`.
Supply output storage that owns no previous copies. The helper checks all nine
callbacks, validates all source roles, then uses F_DUPFD_CLOEXEC with minimum3
for each. There is no fallback, limit increase, original-source closure or flag
change, or controller stdio remapping. Every new copy must be distinct, at least3
and different from all original source numbers. Its role/shape/CLOEXEC is checked
before proceeding. Only complete success sets `ready=1` with `owned_count=5`.

On ordinary allocation/verification failure, `ready=0` and the exact newly owned
prefix remains in `copies[0..owned_count)`, with all other entries -1. The caller
must close that prefix once or exit; it must never map a partial output. A failed
copy-verification still includes that freshly allocated copy in the owned list.
No automatic rollback closes anything. If an impossible duplication return
creates ownership uncertainty (below3, an original, a prior copy or an invalid
adapter failure), `ownership_uncertain=1` requires **controller exit**, never
closing a guessed FD. An uncertain returned number is not appended to the list.
Returning an error is not permission to keep using a partial bootstrap plan.

In the single-threaded owned child, call
`te_map_in_owned_child(prepared,original_controller_pid,ops,error)`. Capture the
controller PID before fork; never infer it from getppid at this call site. Its
PID/parent guard catches misuse, not hostile ownership assertions. Signals must
already be blocked before earlier setup, and inherited callbacks/handlers must
not have rebound endpoints. Current-mask readback cannot prove that history or
the absence of other threads. Darwin checks all declared signal slots; Linux
queries libc-supported signal numbers and skips EINVAL reserved/unsupported
numbers, without claiming every kernel/internal signal is masked.

The mapper rejects incomplete/duplicate/below3 copies and revalidates every role,
shape and CLOEXEC before any duplication. Checked `dup2` maps only three copies
onto0/1/2. As the sources are all at least3, same-slot no-op and mapping-cycle
hazards cannot occur. Verify stdio CLOEXEC is clear; unexpected flags fail rather
than being silently repaired. Explicitly set/verify CLOEXEC on the normalized
gate/status copies, then recheck all mapped access modes and shapes. Control
O_NONBLOCK is preserved/revalidated. Originals and unused copies remain open
until the later numeric closure helper. Controller/watchdog channel aliases must
also be closed by their owners in the future integrated protocol.

Both APIs report stage, reason, saved syscall errno, role, relevant FD and
`mutation_attempted`. Prepare sets the latter before the first allocation attempt;
map sets it before the first dup2, even on failure. Child failure after an attempt
requires child exit after fixed error reporting, without rollback/retry or target
exec. Other child failures also cannot authorize launch. No EINTR retry exists.
Any caller must enforce an external deadline and reap its actual owned child.

The native adapter uses ordinary fcntl/fstat/dup2 and read-only PID/signal queries
on Mac and Linux. These are endpoint-shape/POSIX behavior controls, not Darwin
libproc, kernel-object identity or privileged guest calibration. The helper does
not perform credentials, cwd, gate/status IO, target exec, signal reset, FD
closure, audit/Mach context setup or trace acceptance. A root-opened cwd handle
is never an integration shortcut. See the
[decision](../../../../docs/decisions/mvp-r02-target-endpoints.md).

Run without elevation:

```sh
python3 fixtures/mvp/macos-trace/target-endpoints/test_target_endpoints.py -v
```

Injected controls validate ordering and all callbacks, exact partial allocation
ownership, impossible returns, directions/shapes/nonblocking policy, complete
plan and owner/mask guards, mapping/flag errors and stop-without-retry behavior.
Native controls fork an **owned controller subprocess**, which alone may close
stdio or lower its limit. That controller forks an owned mapping child with a
five-second parent waitpid/monotonic deadline; its enclosing parent has a
ten-second controller deadline and verifies unchanged stdio, limit and sentinel.
Each timeout kills only a still-unreaped child, reaps and fails. No SIGALRM is
relied on while signals are blocked.

Native cases exercise actual mapped stream bytes, all control roles/flags,
initially closed stdio and swapped source numbers, caller-opened `/dev/null`,
alias/direction/invalid-source rejection, exact two-copy EMFILE cleanup and a
child hard/soft limit of1 producing a partial mapping failure. No limit is
raised/restored in those disposable processes. The explicit native preconditions
are nonroot UID/EUID and existing soft capacity at least64; unmet conditions
report a skip. There is no target runner, host sudo, VM/security change or full
R02 claim.
