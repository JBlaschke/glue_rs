# Owned-probe trace-session coordinator models

This internal C interface coordinates an injected backend for exactly the owned
context-probe fixture. It does not provide a native backend, launch a process,
call libdtrace, change signals/credentials, perform FD/filesystem operations or
decode raw trace/BW records. No existing runner, builder, kit, packet or capture
reader uses it. A model event is not native provider or kernel-exec evidence.

`ts_init` snapshots the trusted controller/actual still-owned child binding,
request/catalog digests, original absolute monotonic attempt deadline and exact
request cleanup budget. Caller storage is zero-initialized once, nonalias and
stable; only the owner calls this single-threaded API. Callbacks and context are
trusted internal inputs for models and a future separately reviewed adapter;
there is no command-line, runtime backend, arbitrary executable or argv selector.
The coordinator neither proves ownership from a supplied PID nor authenticates
the supplied digests. The parent must derive them from its real fork/request.

The backend has one `start`, repeated `pump`, one `stop`, one `drain` and one
`close`. Every callback receives the active absolute deadline; it must cooperate
with that deadline. The coordinator checks monotonic time before/after calls,
but cannot interrupt a stalled kernel call or malicious callback. It bounds
consumed events and pump calls separately, without counter wraparound. There is
no sleep, watchdog or hidden retry.

The future adapter must validate raw descriptor/layout/provider/enabling and
output bounds before delivering a consumed event to the supplied sink. The sink
additionally checks the fixed session binding and legal event sequence. These
context tags do not transform an injected event into kernel attestation. Exactly
one provider-ready event then one BEGIN must be consumed before GO permission;
starting a provider or counting matching probes is insufficient. Duplicate,
out-of-order or mismatched events, drops, backend/output errors and late callbacks
poison success. An observed terminal prevents GO even before wait observes reap.

`ts_claim_go` grants permission once and immediately marks possible release.
`ts_go_result` retains the confirmed byte count; zero, partial, failed, late or
even fully delivered failed writes never permit replay. `ts_go_failed` explicitly
reports a failed BIO result even when all64 bytes were confirmed and its saved
errno is0; no errno is fabricated to represent a semantic or clock fault.
The parent supplies
`ts_bootstrap_sealed` only after its independent strict BW validation and EOF
check (the fixed successful stream contains READY+ATTEMPT,512 bytes). On failure,
`ts_bootstrap_failed` retains the opaque confirmed prefix count up to769; no
prefix is decoded, repaired or promoted by this component. Calling that failure
entry point latches failure even with errno0 (for example strict EOF/framing).

Pump calls distinguish bootstrap, owned-child wait and cleanup. Cleanup binds
its separate absolute deadline exactly once, within the original request's
1..2000ms budget; it never changes the attempt deadline or renews on progress,
EINTR or repeated calls. Entering cleanup while the child is live without an
existing failure poisons success, preventing cleanup time from extending a
successful attempt. Cleanup pumping remains possible after an earlier fault.

Reap permanently records the consumed child ownership before any later fallible
owner/time observation. Actual ECHILD permanently records lost ownership.
Neither state can
grant a later kill claim; one live-child kill claim is only a state permission,
not a signal operation or descendant-containment mechanism. A valid fixed child
binding retains owner-checked cleanup eligibility when initialization fails on
clock, deadline or owner observation; full initialization success is needed for
starting capture. Stop occurs after
the child ceases to be live. Drain is attempted once only after known reap and a
successful stop; queued terminal events may first arrive during that drain.
Terminal and END must both precede a successful drain return. No event after END
is accepted. A failed stop is not retried through drain or cleanup.

`close` is attempted once even after partial/failed start. The backend must report
success only after resolving all of its resources and writers. A late successful
close can record resource closure while retaining a deadline failure. The parent
separately confirms its GO close and all remaining channels, writers, FDs and
signal restoration; these are trusted caller declarations, not observations the
coordinator obtains. A failed/ambiguous close never becomes safe finalization.

`ts_finalization_safe` requires known reap, backend close and parent resource
closure and can be true for a failed attempt. `ts_success_eligible` additionally
requires clean primary/cleanup errors, normal child status, no kill claim,
readiness/BEGIN, complete GO, strict-parent bootstrap completion and terminal,
END, stop and drain. It is only an additional parent prerequisite. Probe
comparison, real event provenance, native target identity and the parent's
existing result-promotion policy remain independent requirements. Primary error
precedence survives cleanup; the first cleanup error is retained separately.

## Handoff seams and remaining work

1. In `bootstrap-runner/runner_parent.c`, enter only after the complete READY
   comparison sets `ready_matched`, before the original GO deadline check/write.
   Provider setup and consumed BEGIN must finish within that same deadline.
2. `bootstrap-io` currently polls one FD for the remaining deadline. A separate
   integration must provide cooperative pumping during BW reads, GO writes and
   EOF checks, preserving confirmed prefixes and the original absolute deadline.
   Pump during `wait_until` and the existing cleanup wait as well.
3. After actual reap, stop and drain queued events, retaining terminal/END and
   every backend/output/close fault. Close all trace resources before the parent
   can promote its final result. Keep its no-fallible-work-after-promotion rule.
4. Do not embed `capture-native`'s CLI wrapper: it forks another target, releases
   before consuming BEGIN, installs signal handlers and requires named open
   calibration absent from context-probe. Its watchdog does not clear an
   inherited blocked mask and may hold unwanted channel/writer aliases.
5. A native adapter, independently validated receipt/profile, actual provider
   calibration, source-map/build-ID/kit changes and separately reviewed guest
   execution are still required. The existing raw capability reader and old
   captures retain their original contracts. Full Darwin object/effect coverage,
   extraction verdicts, budgets and R02/M2 acceptance remain open.

## Controls

Run `python3 -B test_trace_session.py -v`. It compiles and executes only a pure
injected C model executable with strict warnings. Set
`GLUE_TRACE_SESSION_SANITIZE=1` for AddressSanitizer/UndefinedBehaviorSanitizer.
The ten model groups exercise successful completion and queued post-reap events;
missing/late/duplicate/mismatched BEGIN; unchanged deadlines/cleanup budgets;
partial or failed GO and BW; error precedence and cleanup pumping; reap/ECHILD;
backend/drop/output/stop/drain/close failures; once-only operations; ordering,
owner checks and resource bounds. No model forks, waits, signals, executes a
target, operates on protected paths or accesses a tracing provider.

See [the decision](../../../../docs/decisions/mvp-r02-trace-session-coordinator.md).
