# Pure complete owned-trace case consistency

`validate_case(case, *, catalog, request, status, probe_stdout, probe_stderr,
result, sidecar, raw, actual, roster, cli_status)` returns immutable `CaseFacts`
or raises `CaseRefusal` without partial facts. Only `positive` and `denied` are
accepted case selectors; unknown and SIM selectors refuse before payloads are
inspected. SIM remains uncalibrated, with no permissive failure bucket.

This layer follows the packet team's separate small terminal metadata and
export gate. It neither imports nor invokes that gate. It performs no file,
CLI, subprocess, shell rendering, VM, provider, authentication, registry or
publication operation. The caller supplies immutable bounded payload bytes,
frozen `CaseBinding` (controller/child PIDs, ordinary UID/GID/groups and exact
executable/cwd/device/inode context), declared `frozenset` roster and observed
CLI status. Positive also supplies `RawFacts` from the separately pinned raw
validator; denied supplies None. Those actual identities, roster and RawFacts
provenance are trusted caller declarations. Bytes do not prove physical file
absence, protected namespace/FD ownership, process identity, outer completion,
export safety or origin of the inputs.

The source-defined roster is six native case files: `request.bin`, `status.bin`,
`probe.stdout`, `probe.stderr`, `result.json`, `trace.json`. Positive additionally
requires the four backend names `program.d`, `probes.tsv`, `events.jsonl`,
`errors.jsonl`; denied declares their absence. Pending/unknown names refuse.
Raw files are streamed and validated separately; this module does not read or
retain them again. The declared absence of a name is not a filesystem finding.

The checker decodes and links exact catalog, request, BW status/stream and NP
probe bytes. It checks the fixed build path, request/catalog digest,10000/2000ms
budgets and GO selector, actual credentials/groups/cwd, BW PIDs/request digest,
READY context, ATTEMPT and declared EOF, probe process/session/stdio/root-regain/
signal/environment context, and every result identity/capture hash and size.
Only the distinct traced result and sidecar schemas are accepted. JSON must be
ASCII, duplicate-free and exactly producer-encoded; booleans and integers cannot
substitute for one another. Result is bounded to8192 bytes, sidecar16384, probe
stdout256, stderr4096; the pinned codecs bound catalog/request/BW/NP payloads.

Every serialized parent/child/helper/protocol/GO/wait/signal field is checked.
Positive requires CLI0, normal reaped exit0 without kill, exact READY+ATTEMPT,
empty stderr, matching probe, zero parent/helper/cleanup/signal failures and
once-only successful64-byte GO plus gate closure. Every serialized tracing
field must describe clean initialized/session/backend start, parent report,
actual BEGIN/target terminal/END, stop/drain/close, snapshot and destroy. It
requires full writer mask15, no failed mask/errno, drops/faults/diagnostics0,
zero create/first/close/writer errors and zero TS callback errors. The expected
and enabled match counts equal the full raw inventory count; observed enabling
count agrees with RawFacts but need not cover unused inventory probes.

The backend raw count/bytes/inventory count/bytes agree with RawFacts. The TS
projection is exactly `raw.events + 1 - raw.shadow_exits -
raw.post_terminal_lwp_exits`: raw BEGIN projects to provider-ready plus BEGIN;
shadow exits and post-terminal lwp cleanup remain raw without TS activity.
Session pumps sum to the bounded total, with bootstrap/wait pumps present and
no cleanup pump on the clean positive path. These are source-consistency checks
on reported state, not independent observation of callback invocation counts.

Denied requires CLI1, exact single sequence0 stage6/reason3/EACCES13 child
ERROR with flags1/detail-1 and declared strict EOF, empty probe streams, no
READY/GO/session/backend/raw, a fully zero serialized session/backend, and
resolved parent/signal completion. The only allowed wait/kill pairs are
`(30720,false)`, `(30720,true)`, `(9,true)`. ERROR and EOF may arrive just before
`_exit(120)`; the source cleanup kill can lose or win that race. `(9,false)`
and all other pairs refuse. All cleanup/helper/signal errors remain zero.
Nothing about these denial pairs admits SIM or a failed tracing start.

Error namespaces stay distinct: native parent/child/helper errno, TS
`callback_error`, OTB `system_errno`, `libdtrace_code`, `callback_error`, and
per-writer close errno/masks have separate exact schemas. Positive allows only
zero errors; denied retains the actual child EACCES while its parent reported-
error status has errno0. No native error is inferred from a callback mapping.
Unexpected nonzero/errors/partial state refuse rather than being normalized.

Positive declared attempt deadlines agree across session/backend; cleanup
agrees across parent/session/backend. Recorded `last_ns` is positive and before
cleanup deadline, with at most the fixed2s remaining. Denied has only a positive
parent cleanup deadline and zero session/backend clocks. Original attempt-start
and cleanup-entry clocks are absent, so no independent budget derivation or
ordering of attempt versus cleanup deadlines is possible. DTrace timestamps
are never compared to CLOCK_MONOTONIC. Coherent alternate declared clocks may
pass; this supplies no native clock/deadline provenance or timing proof.

`legacy_codecs.py` vendors exactly20 selected symbols/constants from
`bootstrap-vm/checker.py` at `ac7e27a5f2d70805dde4a813af2ab2a95ca89ba8`, SHA256
`0d42737849bd96ab9fdf6e92a4d4418b799b70caeac43f98d38c4335d03b2e0e`.
`SELECTED_SYMBOLS` inventories that closure. Definitions are AST-identical;
only standard hashlib/json/re/struct imports and explicit pin metadata are
added. No full case checker, producer, packet loader, filesystem helper or CLI
is copied/imported/called, and no module globals are overridden. The RawFacts
source pin is `0e741d951934ec153ed3c89d7e7fab048515aab2c4f2bed40c0e6e27b0d7d66a`.
The trusted loader/caller must make both this directory and the accepted
`owned-trace-check` module available on Python's import path. Source pins are
reviewed build/integration requirements, not runtime authentication checks.
Legacy sources and registries stay unchanged.

Run `python3 -B test_owned_trace_cases.py -v` here. Independent complete synthetic
catalog/request/BW/NP/result/sidecar fixtures pass before single-field, key,
type, grammar, link, counter, deadline or state corruption is tested. The three
denied race pairs have explicit passing baselines. The RawFacts boundary uses
synthetic immutable observations, not an actual capture or ABI calibration.
Static source controls verify exact codec AST equivalence, dependency closure
and pins without importing or executing the legacy checker. No native program,
provider, guest/export, SDK/build tool, network or admitted packet runs.

Returned facts keep tracing true and exec_proved/full_acceptance false. Complete
fixture consistency establishes no kernel exec, extraction/effect decoding,
complete process tree, authenticated evidence admission, R02 or M2 proof.
