# Fixed owned context tracing backend

This internal native libdtrace adapter implements `ts_operations` for the one
owned context probe. It has no CLI, launch, privilege transition, GO, kill or
signal operations. The separately compiled tracing parent adopts it after READY;
the ordinary nontracing build and historical reader keep their existing paths.
The separate tracing kit profile remains unconfigured, with no admitted native
kit or guest run. Native calibration and full R02/M2 remain open.

After independently comparing complete READY and retaining the actual unreaped
child, a trusted parent calls `otb_create` with its binding, original absolute
attempt deadline and borrowed held private output directory. Creation allocates
private state; `start_fn` exclusively creates `program.d`, `probes.tsv`,
`events.jsonl` and `errors.jsonl`, then opens/configures/enables libdtrace.
The parent admits and preserves that directory's namespace and FD until close.
Binding tags and request/catalog hashes are caller context, not kernel attestation.

The single fixed profile requires BSD syscall entry/return, Mach trap entry/return
and process lifecycle clauses. It has no named-open calibration requirement or
smaller fallback profile. Mach values remain raw scalars; no object, port,
filesystem effect, complete coverage or authorization decision is made. The
generated program selects exactly one clause per selected inventory probe.
Enabled match count must equal that inventory count, including BEGIN/END;
the snapshot retains both expected and actual counts.

Actual events must match the retained inventory, exact historical v8 native
descriptor shapes and one-to-one session EPID/clause bindings. Raw JSONL retains
every descriptor and its native bytes. Before any event reaches the coordinator,
the adapter checks bounds, binding, lifecycle and deadline and completes its
bounded raw write. A fully validated, serialized actual BEGIN causes delivery of
`TS_PROVIDER_READY` immediately followed by `TS_BEGIN`. Start success or probe
counts alone never emits readiness. This is an explicit projection of one native
BEGIN into two coordinator observations, not a new raw kernel event.

Only the bound child's nonshadow `proc:::exited` target record is terminal.
The target address/refcount shape and `P_REF_SHADOW=0x20` follow the existing v8
contract; a later actual guest run must calibrate this adapter's generated
program. Shadow exits and permitted `lwp-exit` cleanup stay raw after terminal
without becoming application activity. Unexpected child creation/spawn fails
this fixed probe scope. BEGIN/END retain controller context; current-context
`proc:::exit` never substitutes for target terminal evidence.

Pump uses one `dtrace_work` call; final drain has a fixed call bound and requires
actual `DTRACE_WORKSTATUS_DONE`, one BEGIN, terminal and END. Every operation
retains the original attempt deadline; cleanup binds one separate deadline at
most two seconds ahead. An attempt-phase pump cannot replace it. Stop/drain/close
and all owned writer closes are once-only. Close still reclaims owned resources
after expiry, clock failure or rollback under confirmed controller ownership,
while recording failure. A close error leaves closure unresolved and is never
retried. `dtrace_close` returns void: the adapter relies on library cleanup and
does not invent a successful syscall or kernel resource readback.

`otb_snapshot` retains immutable binding/deadlines, first and close errors,
a separate writer-close error and per-file close outcomes,
lifecycle observations and output counts. `system_errno` records actual POSIX
failures; `libdtrace_code` records actual libdtrace status, with its bounded
message. `callback_error` is explicitly an adapter status mapping for the
coordinator's callback convention and never POSIX provenance. Fault/drop raw
diagnostics retain their own native fields. Counts do not replace the coordinator
and the parent's strict bootstrap/reap/closure/promotion gates. Destroy only
frees storage after resolved close or before any start; it performs no cleanup.

Run `python3 -B test_owned_trace_backend.py -v` and optionally
`GLUE_OWNED_TRACE_SANITIZE=1 python3 -B test_owned_trace_backend.py -v`.
Darwin controls compile a source-isolated TU defining all used DTrace functions,
without linking libdtrace. They exercise actual adapter code with fake probe
buffers and ordinary temporary files: strict session completion, BSD/Mach raw
shapes, shadow exit attribution, partial enabling, inventory/layout/EPID faults,
output limits/errors, drop/fault callbacks, immutable deadlines, once-only drain
and close, failed-start cleanup, expiry, clock failure and rollback. A separate
actual SDK compile/link includes `-ldtrace` but never runs that resulting binary.
Other hosts test unsupported refusal and explicitly skip Darwin SDK controls.

No provider, sudo, SIP setting, guest operation, capture/export or publication is
performed. Existing SIP-enabled proof and fixed catalog tuples do not authorize
a later tracing run. A tracing-policy reboot requires fresh literal deployment
observations and separately reviewed catalog/kit/receipt integration. Callbacks
are cooperative and cannot interrupt a blocked syscall or libdtrace operation.
