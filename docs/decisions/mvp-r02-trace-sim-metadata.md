# R02: retain safely finalized SIM metadata without admitting SIM

Add only `fixtures/mvp/macos-trace/owned-trace-sim/` with a pure bounded
`sim_metadata_collectable(native_status, result_bytes, trace_bytes, *,
expected_request_sha256, expected_catalog_sha256)` predicate. It returns frozen
diagnostic facts or refuses. No filesystem, CLI, renderer, collector, raw trace,
VM, kit/build, source/proof registry or publication operation belongs here.
Root owns integration, CI and the progress ledger.

Accept exact immutable ASCII duplicate-free result/sidecar bytes within their
8192/16384-byte producer bounds. Check every key, type, array, fixed namespace
and integer bound before collection-safety predicates. Retain the original
bytes and deeply frozen literal metadata, including actual wait/kill/error,
prefix/EOF, counters, messages and unknown TS/stop/drain observations. Native
POSIX errno, library codes, callback status, TS errors, parent errors and writer
close errors stay separate. Do not decode or infer BW/NP/events/raw files.

Native status must be literal CLI1. Require traced promoted-result declarations,
READY, action2, no GO attempt/release/bytes, staged request/catalog identities,
distinct actual reported PIDs, known fork/reap without lost ownership, closed
gate, restored signals/capture declarations and parent finalization safety.
For configured sessions require reaped child, gate/backend/parent close reports,
snapshot and destroy. Model exactly failed create, allocated-never-started and
started/failed-start shapes. Writer creation/close masks are only actual fixed
prefixes0/1/3/7/15; fully started requires15. Failed closes, ambiguous resource
ownership or unknown resource shapes refuse. Absence of started resources is a
source declaration, not an observed successful close.

Do not require clean END/terminal/drain, zero TS/first errors or normal wait120.
Those fields are observations retained for later review, not calibrated failure
outcomes. Facts always carry sim_case_pass=false, sim_calibration_accepted=false,
exec_proved=false and full_acceptance=false. No broad outcome acceptance,
SIM_POLICY change or normal-case weakening follows from collection eligibility.
The existing packet and complete-case SIM refusals remain byte-identical.

Physical promoted-file identity, actual result.pending absence, outer completion,
namespace stability, exact argv and checked metadata copying remain duties of a
future separately reviewed caller. A bytes-only predicate cannot establish
those facts or authenticate pinned producer declarations/kernel liveness. No
DTrace/monotonic equivalence or original-clock budget derivation is claimed.

Read fixed runner/TS/OTB source contracts independently; use complete separately
literal synthetic baselines for every resource shape before focused corruption.
Preserve exact source pins and raw host test receipts in an exclusive control
record. No generated/native/privileged phase is executed, and no actual tracing
proof, kit, export or guest is opened. Actual diagnostic collection/calibration,
source/proof admission and R02/M2 acceptance remain separate prerequisites.
