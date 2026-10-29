# Owned-child descriptor backing observations

`target_fd_objects.c` captures real `fstat`, `F_GETFD` and `F_GETFL` observations
for exactly five retained descriptors before GO. A second API conditionally
matches regular child output backing observations against the controller's
still-held capture handles. This supplies a bounded native observation step;
it does not authorize launch, identify an open file description or admit a
Darwin extraction trace.

```c
struct tfo_snapshot snapshot;
struct tfo_error error;
int result = tfo_snapshot_in_owned_child(&plan, original_controller_pid,
    tfo_native_operations(), &snapshot, &error);
/* In the controller, with the actual owned child still gated/unreaped: */
int held_outputs[2] = {held_stdout, held_stderr};
struct tfo_matches matches;
int matched = tfo_match_regular_outputs(&snapshot, held_outputs,
    tfo_native_operations(), &matches, &error);
```

## Capture contract

`plan.keep` is exactly `[0,1,2,gate_reader,status_writer]`. The final two numbers
are distinct and at least3. Allocate all data before entering the owned,
single-threaded child. Numeric closure must already have completed, with the
same five keeps. Signals were blocked before earlier setup, with no inherited
callbacks, handlers, other threads or shared-status aliases mutating the selected
descriptors. Capture the controller PID before fork. PID/parent and current-mask
guards catch misuse but do not prove this history or authenticate ownership.

The helper validates the entire callback table before use, then reads all five
entries twice. Each entry records same-host uint64 conversions of native
`st_dev`, `st_ino`, `st_nlink`, the native-width mode and nonnegative descriptor/
status flag words. It validates the native mode width and known stat shape;
flags remain observed metadata rather than a broad flag authorization.

Complete equality of the two backing/flag samples and final PID/mask checks
permits publication of one snapshot. Any error leaves `ready=0` and no entries
published. A reused output is cleared even when the caller omits the error
pointer. Metadata comparisons use fields, never struct-padding equality.
Repeated samples detect some changes; they are **not atomic snapshots** or proof
that no mutation occurred between equal observations.

The API never opens, closes, remaps or changes flags, never emits GO and allocates
no heap storage itself. It neither inventories all descriptors nor replaces the
numeric closure helper. Objects and callback spans must be valid, stable and
nonoverlapping; the adapter table is trusted, not a plugin security boundary.
Native Darwin and Linux adapters use ordinary unprivileged POSIX observation.
Linux's signal check excludes libc-invalid/reserved signal slots through
read-only sigaction queries; it does not claim a Darwin/internal signal policy.

## Conditional regular output matching

The controller must retain its actual unreaped child behind the barrier and keep
both capture references open throughout capture and matching. The matcher checks
controller identity, reads both held handles twice and compares child slots1/2.
The supported sinks are distinct single-link regular files with matching
write-only access and complete F_GETFL status observations. Child stdout/stderr
must have close-on-exec clear. Parent and child F_GETFD values are recorded but
need not agree: held CLOEXEC references and dup2 stdio intentionally differ.

Matches publish only after both references pass. No partial match survives
failure. Device/inode/mode/link observations are backing metadata; they do not
prove a pathname, shared file description, offset, generation, complete alias
set or current slot state. Independent opens of the same file can match. The
controlled dup/fork lineage and quiescent descriptor/status ownership are
integration assumptions, not an extra caller boolean granting authority.
No pipe, CWD, arbitrary process or after-exec binding is inferred.

Saved syscall errno is used only after actual failure; stale errno after success
is ignored. No retry, guessed descriptor closure or rollback occurs in these
APIs. Child failure forbids launch. The caller owns a bounded whole-child deadline
and must reap its actual child; the primitive cannot interrupt a blocked call.
A `ready` or matched result is not capture authentication, a state-feed assertion
or extraction/launch acceptance.

## Native integration controls

The controls create only private test files/pipes in an owned controller process.
They use the existing `te_prepare_owned_sources`/`te_map_in_owned_child` to map
stdio, and the unchanged `td_close_in_owned_child` algorithm to retain exactly
five descriptors. Capture happens after closure and before a test GO. The child
stays gated while the controller matches still-held references; only a successful
intended match releases GO and verifies bytes in the selected output files.

Darwin uses the actual libproc TD native adapter. Linux controls supply a
**test-only** `/proc/self/fd` inventory callback to that same TD algorithm. It
excludes its own directory descriptor, closes it before returning, validates
all numeric names and byte/capacity bounds, and rejects errors rather than
clipping/filtering them. Production `td_native_operations()` remains unsupported
on Linux. Linux execution is established only by its own native CI receipt;
local Darwin execution cannot substitute for it.

Native controls cover a successful capture/match, independent reopening of the
same backing file (demonstrating the OFD limitation), a wrong held sink, a missing
kept descriptor and an unexpected parent read failure. Those refusal cases never
attempt GO. An exact forced `EBADF` is accepted only with an actual successful
owned-child wait, intact parent observations and successful cleanup; unrelated
parent errors, real cleanup failures and an actual `ECHILD` caused by another
wait consuming ownership remain failures. A separate control lets
the child exit before GO and checks that the failed write produces `EPIPE` and
reaches cleanup. The controller installs a saved, parent-only SIGPIPE ignore
action while signals remain blocked, and restores it after cleanup.
Parent failure paths terminate/reap only the actual owned child;
normal waits use monotonic deadlines. Parent stdio descriptors/flags, resource
limits and a sentinel remain unchanged. No limit is raised. The native
preconditions are nonroot execution and existing FD capacity at least32.
Fixed controller stdout/stderr banners precede the full status-word baselines:
ordinary writes can set Darwin's kernel-observed `FWASWRITTEN` bit. The controls
retain exact flag comparisons; repeated status sampling requires quiescence of
ordinary I/O as well as explicit flag changes.

Injected portable controls cover complete publication, both sampling passes,
every leaf failure position, no retry/partial results, all callback preflights,
fixed plans, null-error stale outputs, ownership/mask guards before and after
samples, impossible mode widths, each identity/flag change, controller guards,
regular/link/access/CLOEXEC requirements, aliased sinks and stale errno.

Run from the repository root:

```sh
python3 fixtures/mvp/macos-trace/target-fd-objects/test_target_fd_objects.py -v
```

The test harness normally removes its build directory. For a durable local
receipt, set `GLUE_TFO_TEST_RETAIN` to a **new** owned directory; it retains exact
compile argv/logs/source and binary hashes plus each control's output/status.
This variable affects test storage only, not the production primitive or launch
policy. Existing target helper and production runner/kit sources are unchanged.

Production controller/wire/kit adoption, authoritative later-call object binding,
filesystem paths, OFD lifetimes, effect ordering and the full Darwin oracle
remain separate work. No root, VM, SIP, privileged tracing or raw publication
operation is performed. See the [decision](../../../../docs/decisions/mvp-r02-target-fd-objects.md).
