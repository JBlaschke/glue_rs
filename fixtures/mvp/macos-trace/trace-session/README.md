# Owned-probe trace-session coordinator

This internal C interface coordinates an injected backend for exactly the owned
context-probe fixture. It does not provide a native backend, launch a process,
call libdtrace, change signals/credentials, perform FD/filesystem operations or
decode raw trace/BW records. The separately compiled tracing parent now adopts
it through the fixed native adapter; the ordinary build stays nontracing. A model
event is not native provider or kernel-exec evidence.

`ts_init` snapshots the trusted controller/actual still-owned child binding,
request/catalog digests, original absolute monotonic attempt deadline and exact
request cleanup budget. Caller storage is zero-initialized once, nonalias and
stable; only the owner calls this single-threaded API. Callbacks and context are
trusted internal inputs for models and the separately reviewed native adapter;
there is no command-line, runtime backend, arbitrary executable or argv selector.
The coordinator neither proves ownership from a supplied PID nor authenticates
the supplied digests. The parent must derive them from its real fork/request.

The backend has one `start`, repeated `pump`, one `stop`, one `drain` and one
`close`. Every callback receives the active absolute deadline; it must cooperate
with that deadline. The coordinator checks monotonic time before/after calls,
but cannot interrupt a stalled kernel call or malicious callback. It bounds
consumed events and pump calls separately, without counter wraparound. There is
no sleep, watchdog or hidden retry.

The adapter must validate raw descriptor/layout/provider/enabling and
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
separately confirms its GO close, the attempt's bootstrap/target/trace channels
and writers, admission FDs and signal restoration. These are trusted caller
declarations, not observations the coordinator obtains. Keep the backend context
alive through the report's owner/clock callbacks. A failed/ambiguous close never
becomes safe lifecycle finalization.
Each close-result report is consumed once before interpreting its errno or
observing the current owner. A negative malformed errno or a positive close
error remains unresolved even if a later report attempts to replace it with0.
`ts_gate_close_failed` and `ts_parent_close_failed` explicitly retain a failed
closure/resource-restoration observation whose saved errno is0; this does not
require inventing an errno for a semantic restoration failure.

`ts_finalization_safe` requires known reap, backend close and parent resource
closure and can be true for a failed attempt. `ts_success_eligible` additionally
requires clean primary/cleanup errors, normal child status, no kill claim,
readiness/BEGIN, complete GO, strict-parent bootstrap completion and terminal,
END, stop and drain. It is only an additional parent prerequisite. Probe
comparison, real event provenance, native target identity and the parent's
existing result-promotion policy remain independent requirements. Primary error
precedence survives cleanup; the first cleanup error is retained separately.
Final metadata authoring has separate caller-owned sidecar/pending writers and
a held output directory. Every such resource must close before result promotion,
even after parent completion succeeds. A metadata close failure forbids promotion;
`ts_finalization_safe` alone never grants publication permission. See the
[resource-boundary decision](../../../../docs/decisions/mvp-r02-trace-parent-completion.md).

## Integration and remaining work

The source-selected tracing parent enters after complete READY comparison and
consumes provider readiness/BEGIN before once-only GO. Cooperative BIO and status
variants pump during bounded reads, writes and EOF checks without renewing the
original deadline or replaying failed prefixes. Wait and valid shared cleanup
also pump. Reap/ECHILD retires kill ownership before later fallible observations.
After stop/drain, backend and parent resource closure precede separate final
metadata closure and the last fallible result rename. A failed cleanup-clock or
binding cannot authorize tracing work against the longer attempt deadline.

The fixed adapter's source/model/SDK-link reviews do not establish native
availability. A fresh policy-reboot proof, admitted tracing source/kit, independent
receipt checking and separately reviewed guest execution still precede native
calibration. Do not embed `capture-native`'s distinct launch/watchdog wrapper.
Historical readers/captures keep their contracts. Full Darwin object/effect
coverage, extraction verdicts, budgets and R02/M2 acceptance remain open.

## Controls

Run `python3 -B test_trace_session.py -v`. It compiles and executes only a pure
injected C model executable with strict warnings. Set
`GLUE_TRACE_SESSION_SANITIZE=1` for AddressSanitizer/UndefinedBehaviorSanitizer.
The eleven model groups exercise successful completion and queued post-reap events;
missing/late/duplicate/mismatched BEGIN; unchanged deadlines/cleanup budgets;
partial or failed GO and BW; error precedence and cleanup pumping; reap/ECHILD;
backend/drop/output/stop/drain/close failures; once-only operations; ordering,
owner checks and resource bounds. No model forks, waits, signals, executes a
target, operates on protected paths or accesses a tracing provider.

See [the decision](../../../../docs/decisions/mvp-r02-trace-session-coordinator.md).

## Fixed runtime recipe entry

`TS_OWNED_RUNTIME_RECIPE` is fixture 2. The separate `ts_runtime_init` entry fixes
that identifier through the same private initializer; `ts_init` still accepts
fixture 1 exclusively. Neither entry accepts a public profile selector. Every
consumed event must match the original complete binding, including the fixture,
owner/child PIDs and request/catalog digests. All owner, readiness, GO, child,
deadline, error-precedence and once-only cleanup rules above are shared.

The runtime entry's object-status success retains 1024 bytes (READY+ATTEMPT), and
its opaque failure prefix is bounded at 1537 bytes. The original entry preserves
its 512-byte success and 769-byte failure cap. This is fixed source selection,
not caller permission to decode a failed prefix or choose an arbitrary bound.

This source addition does not adopt a traced-runtime runner, configure a catalog
or grant native proof. The old adapter remains independently registered. Its
source registration must advance separately before the changed coordinator
bytes can pass the configured source loader.

The session controls run every lifecycle group through both fixed entries,
including crossed factory/event bindings and both status-prefix bounds. Set
`GLUE_TRACE_SESSION_RETAIN` to a fresh directory to keep compiler/model commands,
streams, binary and source identities. These are injected models only.
