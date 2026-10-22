# R02: classify strictly observed tree-open request flags

Status: accepted for diagnostic classification; full Darwin acceptance pending.

The strict historical raw-v4 tree-open observer already validates the complete
capture, pairs calls and retains copied pathname bytes, canonical flag words,
observed actors and source indexes. The independent normalized open-intent unit
already classifies Darwin flags, including failed write requests and read-only
creation. Connect these existing components without inventing normalized origins,
resolved filesystem identities or an extraction verdict.

Extract a pure `classify_flags(flags_u32)` function in `open_intent.py`. It accepts
only a canonical unsigned32 integer and returns exactly `intent`,
`no_output_policy`, `write_reasons`, `unmodeled_bits`, `unknown_bits` and
`unmodeled_sdk_flags`. It uses the existing ABI constants and classification
rules. It accepts no origin, path, result, descriptor, object or trust claim.
The existing normalized decoder must retain its exact schema, validation and
result fields, delegating only the flag classification to this helper.

Add a separate `tree-open-intent` observer whose public entry accepts only the
capture and toolkit paths. It invokes the strict tree-open observer itself;
there is no API accepting caller-provided observations or validation claims.
Retain the complete tree-open report and source-pair/raw-frame bundle. Each
classification links to its one-based source observation, pair/consumer indexes
and observed actor identity. Preserve copied path bytes, all flag bits and
failed returns in that source. A non-open pairing/integrity failure rejects the
entire operation before a report, and the upstream4096-open/input bounds remain.

Use the pure flag classifier directly; do not forge `synthetic-unit` or
`owned-control-self-report` records. Unknown/unmodeled flag combinations remain
explicit unsupported classifications with their bits and write reasons retained.
Retain the ABI and classifier/observer source hashes. There are no application
output exemptions, pathname resolution, descriptor/object guesses or successful
effect claims. Read intent never authorizes a device/file or proves complete
coverage. This step changes no interpretation of the no-extraction constraint.

Every report has `full_trace_acceptance: false`. Full-acceptance API/CLI requests
unconditionally refuse, including before nonexistent input access. CLI success
means all open flag requests were classified; observed write requests remain in
the report. Unsupported/malformed input returns failure. No API is registered
as a full acceptance backend.

Controls use complete rehashed synthetic raw capture/toolkit fixtures, with
read/event/write/create/truncate/append combinations, failed writes, unknown and
high-bit flags, process/thread/exec provenance, non-open corruption, bounds and
unconditional acceptance refusal. Existing normalized decoder output must remain
compatible. These controls establish source semantics, not fresh native capture.
CI adds the new focused suite; existing tree/open-unit suites stay enabled.

This step reads no actual guest capture, changes no source/kit/proof registry,
builds/runs no tracing kit and changes no VM or SIP policy. The latest owned
backend still lacks copied paths and authoritative filesystem identities. Native
calibration, complete process-tree collection, object/FD/cwd causality, other
mutation routes, corpus/budgets and R02/M2 remain separate work.
