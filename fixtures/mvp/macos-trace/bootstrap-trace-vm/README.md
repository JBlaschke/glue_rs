# Disabled owned-tracing VM packet preparer

`prepare.py --kit ABS --output NEW` is a separate, closed host interface. In
this revision `APPROVED = None`, `EXECUTION_ENABLED = False`, and
`SIM_POLICY = None` refuse before source-helper loading, supplied kit/proof
reads, output creation or nonce generation. There is no environment or CLI
approval, hash, target, provider, credential, profile or execution override.
The existing NONTRACING preparer/checker, approved kit03 binding, templates,
registry, proof policies and limits are unchanged.

The developer-only pure plan/renderer helpers accept synthetic identities and
emit **hard-disabled** shell text. They do not prepare an admitted packet.
Changing the three constants alone cannot enable this prototype: the renderer
also requires their original disabled values and emits literal guard `0` and
an `UNAPPROVED` kit marker. A later reviewed activation/render change must bind
an independently reviewed fresh exact SIP-disabled proof and current literal
mount/device/FSID observations, frozen tracing sources, zero reproducible
builder/strict-signature controls, full kit manifest, recipe, catalog, build ID
and three artifact identities. Existing protected installation prefixes require
separate reviewed retention. No packet is staged or executed by this module.

The fixed tracing roster is `context-probe`, `owned-trace-runner`, and
`make-request`. Narrow shared kit helpers are checked against exact source SHA
before import; the tracing wrapper retains its own disabled-SIP and libdtrace
policy. The plan has a distinct tracing schema and 16-hex nonce, fresh ordinary
work/root stage/output/export/run-receipt paths, actual caller IDs/groups,
current-inspector observations, attempt10000ms/cleanup2000ms budgets and exact
per-case evidence names. Current exact disabled-SIP/model/OS/kernel/inspector
preflight precedes authentication in the outer template. Full BSD type/mode,
special-bit, owner, single-link, size/hash, physical path and strict-signature
checks guard trusted destinations; no old prefix or arbitrary command is
repaired or reused. Environments and NUL argv are explicit.

`gates.py` is a pure small metadata gate, **not an offline checker or raw trace
validator**. It generates the same typed predicates and identity/deadline
relations used by synthetic tests. The root template first reads only bounded,
physical, root-owned promoted `result.json` and `trace.json`, requires no pending
result and resolved child/FD/signal/session/backend/writer/snapshot/destroy
closure, then permits raw roster inspection. Positive additionally requires
clean TS/OTB BEGIN/terminal/END, one complete64-byte GO, strict READY/ATTEMPT/EOF,
normal reap0 and successful owned probe. These are source/metadata consistency
observations; raw decoding and independent complete case validation are a later
separately reviewed layer.

Denied requires exact pre-READY permission failure, resolved reap and no created
session/backend. Its closed cleanup-race wait/kill matrix accepts only
`(30720,false)`, `(30720,true)` or `(9,true)`, retaining the actual observations;
raw9 without a kill claim and every other pair fail. Its exact six-file native roster excludes all four backend
files. Mode restoration follows closure, expected-case and physical roster
checks, with no failure trap. Trailing requires the accepted positive request
plus exactly one NUL, native CLI2 and complete output absence. Other CLI2 stops
before raw read/export/restoration. Export repeats metadata gates and physical
bounds before each selected raw file read or hash. Private wrapper/native
stdout/stderr captures can exist on failure; they are never promoted into a
completed exported batch. Final fixed-roster export requires all wrapper gates
and `complete0`; the separate launcher requires outer0 before receipt export.

SIM always refuses as uncalibrated. Neither normal exit120 nor cleanup kill is
normalized, accepted as a general failure bucket, or promised a clean END/drain.
Actual wait/kill/error facts remain private for a separately authorized future
diagnostic calibration. Consequently even a future individually successful
positive case cannot produce a completed four-case batch in this revision.

The new export roster streams at most128MiB event bytes for each positive/SIM
case,270MiB total,8192 bytes per future JSONL line,1000000 events,1MiB/8192 probes,
16384 program bytes and65536 diagnostics bytes. These are distinct new bounds;
legacy8MiB-member/64MiB-tree limits are unchanged. This preparer does not parse
JSONL, validate raw field layouts, or infer native provenance from synthetic
text. Metadata deadline identity is source consistency only: receipts lack
original attempt-start and cleanup-entry clocks, and no DTrace timestamp versus
monotonic clock-domain comparison is made.

Controls are host Python and synthetic gate models, plus `/bin/sh -n` on
generated text. No generated privileged phase is executed. Run:

```
python3 -B fixtures/mvp/macos-trace/bootstrap-trace-vm/test_prepare.py -v
python3 -B fixtures/mvp/macos-trace/bootstrap-trace-vm/test_gates.py -v
```

No offline checker, actual proof admission/source registration, native build,
provider execution, VM, sudo/SIP operation, export mutation, networking or
publication belongs to this step. The stable private namespace/no privileged
mutator condition remains explicit; shell guards are not atomic hostile-mutator
containment or independent kernel liveness proof. Tracing consistency never
means kernel exec, extraction behavior, generic tree coverage or full R02/M2
acceptance.
