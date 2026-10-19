# Pure complete owned-trace case consistency checks

## Decision

Add `fixtures/mvp/macos-trace/owned-trace-cases/` on
`codex/mvp-r02-owned-trace-cases` from
`ac7e27a5f2d70805dde4a813af2ab2a95ca89ba8`. This is a later pure consistency
layer after the packet team's distinct terminal-metadata/export gate. It neither
calls that gate nor proves the safety or origin of its inputs.

`validate_case(case, *, catalog, request, status, probe_stdout, probe_stderr,
result, sidecar, raw, actual, roster, cli_status)` consumes bounded immutable byte
payloads, accepted RawFacts or None, frozen actual context and a declared frozen
file-name roster. It returns immutable case facts or refuses. Unknown/SIM case
selectors refuse before touching payloads; SIM has no calibrated failure bucket.
No file, CLI, VM, provider, shell renderer, registry or publication interface is
added. Caller-declared actual binding/roster and RawFacts provenance are trusted;
bytes cannot establish authentication, physical absence or export safety.

Reuse only the exact self-contained pure codec subset from legacy
`bootstrap-vm/checker.py`, SHA256
`0d42737849bd96ab9fdf6e92a4d4418b799b70caeac43f98d38c4335d03b2e0e`,
at the base above. Vendor selected constants/exception/helpers and catalog,
request, BW status/stream and NP probe decoders unchanged, retaining explicit
symbol inventory and AST equivalence controls. Never copy/import/call its full
case checker, producer, packet loader, filesystem helpers or main. The accepted
raw facts contract is pinned separately. All legacy sources remain unchanged.

Independently validate exact traced result/sidecar schemas, every serialized
parent/child/helper/signal/session/backend field and native-vs-callback error
namespace. Bind catalog/request/status/probe/digests/PIDs/context and fixed
10000/2000ms request budgets. Positive requires a complete clean result, one
once-only successful64-byte GO, exact READY/ATTEMPT plus EOF, normal exit0,
matching probe, restored parent resources, one BEGIN/target-terminal/END and
fully resolved stop/drain/close/destroy. Expected/enabled inventory counts,
observed EPIDs, byte counts and raw-to-session event projection must agree;
writer-close mask15 and all native/bridge errors must be zero.

Denied requires a single exact pre-READY stage6/reason3/EACCES13 child ERROR,
strict EOF, empty probe streams, no GO/READY/session/backend/raw capture and
resolved parent resources. The declared six-file roster excludes backend files;
this is not a physical-absence proof. Accept only the source-consistent cleanup
race pairs (raw wait30720,killfalse), (30720,killtrue), (9,killtrue). Child ERROR
and EOF may be observed just before _exit120; cleanup can attempt SIGKILL during
that interval and either win or race with the normal exit. Refuse (9,killfalse)
and all other pairs. This bounded denial policy does not calibrate SIM.

Compare declared attempt/cleanup deadline identities and necessary order/bounds
within their recorded clock observations only. Original attempt-start and
cleanup-entry clocks are not retained; no independent budget derivation or
DTrace timestamp/CLOCK_MONOTONIC equivalence is invented. Keep exec_proved and
full_acceptance false. Complete independent synthetic passing fixtures precede
single-field corruptions with intended refusal reasons; no provider/native
program/guest/export/build/SDK/network execution or evidence admission occurs.
Root retains integration/CI/progress and source/packet admission ownership.
