# Explicit credentials in an owned child

`target_credentials.h` / `.c` supply a bounded primitive with a real libc syscall
adapter. They do not integrate with the collector or launch a target. Native
privileged Darwin target-transition calibration is still unavailable.

Before forking, select an explicit UID, primary GID, nonempty ordered group vector
and the original controller PID. UID/GID must be nonzero and no greater than
2147483647. There are at most 16 groups, each in 0..2147483647, with no duplicates;
the first must equal the primary GID. A supplementary GID 0 is allowed only when
explicitly selected. No account lookup, `SUDO_*` inference, implicit groups or
empty-list fallback exists. These are API policy bounds matching the inspected
Darwin SDK, not universal native credential limits.

`tc_parse_request` optionally converts length-delimited ASCII decimal tokens to
the typed request. It rejects signs, whitespace, decimal/exponent syntax,
non-ASCII bytes, embedded NUL, leading zeroes, overflow and textual booleans/null.
It does not accept JSON values or coerce other types. Any future binding must
reject inappropriate source types before constructing these spans. Failed parse
leaves its output zeroed. `tc_validate_request` is also called by the drop API,
so a directly constructed or subsequently changed request is checked again.
Callers must supply valid, nonoverlapping readable/writable C objects and spans.

Only in the **owned, single-threaded forked child**, with no assumed per-thread
credentials, call:

```c
struct tc_error error;
int result = tc_drop_in_owned_child(&selected_request, original_controller_pid,
                                   tc_native_operations(), &error);
```

Never call it in the controller. The PID guard checks that the caller differs
from the declared controller and that its parent equals that controller. The
controller PID must be selected before fork, not inferred from `getppid()` at
the call site; the guard catches mistakes, not dishonest ownership assertions.
The request, error, operations and context storage must not alias or change
concurrently. All callbacks are checked before mutation, and the request and
callback table are copied locally before callbacks begin.

The order is exactly `setgroups` → `setgid` → `setuid`. Each syscall failure stops
immediately without retry or rollback. On success of those calls, verify
`getuid`, `geteuid`, `getgid`, `getegid`, then one bounded `getgroups` read. Success
requires exact IDs and exact group count, values **and order**. The primitive
never sorts, deduplicates or normalizes kernel output to make it pass. A host
that changes group order can therefore reject this contract. Linux commonly
sorts groups; any future isolated-root Linux control must deliberately choose a
compatible ordered vector and cannot calibrate Darwin group ordering.

The mandatory error output gives `stage`, `reason`, original `system_errno` for
a syscall failure (zero for validation/verification failures), optional group
index, and `mutation_attempted`. The latter becomes true immediately before the
first mutation attempt, even if that call fails. **After any such failure the
child must exit without running a target.** A failure can leave credentials
partially changed, and retrying, rolling back or returning to controller code is
unsafe. The primitive returns to permit a future owned-child fixed status writer;
it does not choose an exit code or perform that protocol. Validation/ownership
failures do not attempt mutations. Even these failures must not be treated as a
successful credential selection by a launcher.

Success observes real/effective IDs and explicit groups at this point. It does
not verify saved IDs or negative root-regain behavior, reconstruct memberd/login
groups, or establish Mach/audit/session context. It does not close inherited
descriptors, change cwd/signals/limits, implement a gate, validate set-ID target
behavior, trace a process or grant any R02/full-filesystem acceptance. The future
caller must establish those independent launch conditions before using this in
a controller. See the [decision](../../../../docs/decisions/mvp-r02-target-credentials.md).

Run native compile and controls without elevation:

```sh
python3 fixtures/mvp/macos-trace/target-credentials/test_target_credentials.py -v
```

The injected syscall table checks boundaries, ordering, precise errno and stop
behavior, every observed-ID mismatch, group order/count/value mismatches, and
controller rejection. The real adapter negative control forks an owned child
only when the host is unprivileged; its first `setgroups` must fail with EPERM,
then the child exits and the parent verifies its own IDs did not change. A root
host explicitly skips that negative control rather than dropping host privilege.
No successful privileged Darwin transition is claimed by these controls. There
is no host sudo, guest action, target execution or collector modification.
