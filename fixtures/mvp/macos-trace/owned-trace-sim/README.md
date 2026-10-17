# Pure SIM diagnostic metadata predicate

`sim_metadata_collectable(native_status, result_bytes, trace_bytes, *,
expected_request_sha256, expected_catalog_sha256)` returns a deeply frozen
`DiagnosticFacts` or raises `DiagnosticRefusal`. Inputs must be immutable bytes,
within the producer's result8192/sidecar16384-byte bounds, containing ASCII,
duplicate-free JSON with exact keys/types/array shapes and bounded integers.
There is no CLI, file reader, renderer, collector or raw decoder.

The predicate checks **collection eligibility of pinned producer declarations**.
It cannot prove that anonymous bytes came from a promoted file or an actual
process. A future caller must separately establish exact invocation/native
status, promoted-file physical identity and permissions, pending-result absence,
stable private namespace, actual outer completion and checked metadata copying.
This helper neither performs nor authorizes those operations, and does not
enumerate or claim absence of any raw output file.

Collection requires actual native CLI1, the two distinct traced schemas, READY,
action2 with no GO attempt/release/bytes, fixed staged request/catalog digests,
distinct reported controller/child PIDs, fork/reap without lost ownership,
closed gate, prepared/restored signals and valid capture/finalization
declarations. Successful parent helper metadata retains endpoint role5/fd-1.
Configured sessions must report reaped child and gate/backend/parent closure,
with actual parent wait/kill values matching the session. Allocated backends
must have snapshot/destroy resolved; failed create must have no session or
backend snapshot. Writer names and all four errno slots are always present,
including the native zero-snapshot case.

Resource shapes stay distinct:

- Failed create has create_attempted1, session/snapshot/destroy0, zero session
  and backend observations except the fixed writer-name array, and a bounded
  create-error namespace. No created resource or BEGIN is inferred.
- Allocated but never started has configured session closure and
  snapshot/destroy1. Backend binding/original deadline exist, while all backend
  lifecycle/writer/counter/error observations remain0. Backend close/resources
  are0 because none were started; this is not a successful close observation.
  A session can be configured but uninitialized after an init-time clock error,
  or start_attempted1 with backend_touched0 after a pre-start clock error.
  The fixed caller permits only initialized/start_attempted pairs0/0 or1/1.
- Started/failed-start requires backend close/resources1, failed writer mask0,
  all four close errno0 and a clean writer-close error. Attempted writer masks
  are only fixed creation prefixes0/1/3/7/15. Fully started requires15.
  The backend close-error namespace must also be zero: its callback failure
  otherwise prevents the pinned TS producer from declaring a closed session.
  Backend started1 with session started0 is permitted: the backend can succeed
  at `dtrace_go` and then fail its final clock observation before returning.

The original result/sidecar bytes and every parsed observation are retained
unchanged. Nested objects are `FrozenObject` tuples and arrays become tuples;
ordinary mutation is rejected. Native raw wait, kill, child/protocol prefixes,
EOF, counters, messages and each parent/TS/OTB error remain literal. Native
POSIX errno, libdtrace code, callback status and writer-close errors have
separate exact namespaces. Unknown bounded tracing errors or failed
terminal/END/stop/drain observations are retained for review, without being
classified as expected SIM behavior. Partial records are never decoded or
inferred from byte counts. Neither wait120 nor cleanup kill is normalized or
required as a calibrated outcome.

Every returned fact has a distinct diagnostic schema and status
`metadata-collectable-for-review`, with `sim_case_pass=false`,
`sim_calibration_accepted=false`, `exec_proved=false` and
`full_acceptance=false`. Frozen objects are Python data, not authentication
tokens. The original packet's SIM_POLICY/refusal and complete-case checker
remain unchanged. Collection eligibility never admits a SIM case, provider,
proof, kit or execution.

Source enum selectors have their fixed namespace ranges; an out-of-range
selector refuses. Uncalibrated combinations of valid TS/end/drain errors remain
literal observations. Native libdtrace codes retain their signed C-int values,
and callback/POSIX codes remain separate bounded nonnegative fields. This is
metadata schema consistency, not an accepted SIM failure matrix. The future
collector's `metadata-recorded-for-review` receipt would follow checked copying
and writer closure; this predicate performs no such operation.

The source contracts are the fixed `runner_parent.c`, `runner_files.c`,
`runner_trace.c`, `trace_session.c/.h`, `owned_trace_backend.c/.h` and endpoint
success sentinels at the feature base. Their exact hashes and before/after
identities accompany the closed host controls. There is no DTrace/monotonic
clock comparison, original attempt/cleanup clock-budget derivation, raw trace
validation, independent kernel liveness/provenance or hostile-mutator guarantee.

Run only the pure host controls:

```
python3 -B fixtures/mvp/macos-trace/owned-trace-sim/test_sim_metadata.py -v
```

The tests start from complete independently literal source-based baselines for
every resource shape before focused corruption. No generated/native/privileged
phase, inspector, provider, kit/build, proof/source registration, VM, staging,
export/raw operation, network or publication belongs to this step. Root owns
integration/CI/docs; actual diagnostic collection, SIM calibration and R02/M2
acceptance remain open.
