# Owned raw request assessment

`assessment.py` integrates the complete owned raw transport reader, the pinned
BSD source contracts and common open flag classification. It exposes a pure
diagnostic API; every result has `status: incomplete`,
`full_trace_acceptance: false` and `state_feed_eligible: false`. It does not
execute a collector, accept native evidence, feed a state engine or change SIP.

```python
from assessment import assess_owned_raw

result = assess_owned_raw(program_bytes, probe_inventory_bytes, error_bytes,
                          raw_event_lines, owner_pid=owner_pid,
                          target_pid=target_pid,
                          contract_bytes=exact_contract_bytes)
report = result.to_dict()  # fresh JSON-compatible containers
```

The API takes original immutable static bytes and a bounded byte-line iterable.
`observe_raw_bsd` performs complete transport validation and exhaustion before
any assessment is returned. Its exact contract asset identity, 128 MiB transport
bound, 8,191-byte event bound and 4,096 BSD-phase projection bound apply without
caller overrides. A late malformed event or iterator failure yields no prefix.
The caller supplies the contract bytes; the API never opens `contracts.json`.
Physical file handling and operator output are a subsequent feature.

The frozen result retains one complete `OwnedBsdObservations` object as `source`.
Each entry-side request row contains its original `ordinal` and `phase_index`:
`source.observations[row.phase_index]` is the exact original phase. That phase
retains provider/module/function/probe/EPID, every unsigned raw scalar, source
name/family, selected raw fields and **all unresolved source requirements**.
Rows add route gaps and optional common open flag diagnostics without copying
raw frames or manufacturing a normalized origin. All nested collections are
immutable. `to_dict()` creates fresh dictionaries and lists.

All 161 declarations dispatch through a closed roster of twelve source families:

| Source family | Request category | Interpretation still needed |
| --- | --- | --- |
| asynchronous | asynchronous-request | Indirect buffers and submission/completion effects |
| cwd-state | cwd-state-request | Cwd, root and thread scope |
| fd-mutation | fd-operation-request | Payload, metadata, flush, transfer and descriptor objects |
| fd-state | descriptor-state-request | Commands, descriptor lineage and initial state |
| indirect-open | indirect-open-request | Filehandle or object-ID binding |
| mapping | mapping-request | Backing objects, aliases, protections and writes |
| opaque-control | opaque-control-request | Pointed structures and command-specific effects |
| open-request | open-request | Path, dirfd, mode and every variant-specific requirement |
| path-mutation | path-mutation-request | Source/destination/literal-target and object binding |
| path-observation | path-observation-request | Path binding and operation semantics |
| rights-or-namespace | rights-or-namespace-request | Ports, sockets, rights and namespace objects |
| spawn-or-exec | spawn-or-exec-request | Images, inherited state and transitions |

Unknown BSD entry names use `unsupported-bsd-request` and retain their complete
raw phases. A family is an unresolved routing obligation, never an effects
allowlist: `fsync`, `sendfile` and `write` share `fd-operation-request` without
implying an observed payload write. `path-observation-request` grants no harmless
read permission. Numeric descriptors 0, 1 and 2 receive no special authorization.
Symlink literal targets remain distinct from destination path fields.

For all nine open variants, the source-declared `flags` field alone selects the
common flag word. Only words already in the canonical unsigned32 range reach
the unchanged classifier. Higher bits stay unsupported and fully retained;
there is no masking, truncation or signed reinterpretation. Unsupported common
flags retain their reasons and unmodeled/unknown bits. Guarded, protected and
extended variants retain every additional source requirement. A classified
read/event request establishes no path or object authorization. The classifier's
separate no-output policy is not applied as a product verdict.

Failed attempts, unpaired entries and orphan return phases remain visible.
This API does not invoke the stricter closed-call pairer, which deliberately
refuses several valid owned transport shapes. Return facts retain unsupported
shapes and control-flow gaps; no successful result, libc errno, descriptor
creation or causal transition is inferred. Coverage exposes BSD entry/return
counts, unknown names, unsupported returns, all twelve family/category counts,
Mach entry/return counts and every lifecycle kind count including zero. The
upstream projection retains Mach/lifecycle aggregate counts, not their bodies.

Declared application outputs can legitimately receive writes. Object/path
binding is needed before applying that exemption or declaring an extraction
violation. Neither an observed write-capability request nor zero observed writes
provides a complete extraction verdict. Fixed missing-capability reasons remain
present even for zero BSD activity.

Fixed helper code and the classifier ABI are identity-checked before normal
imports, once per module import, assuming a stable trusted source tree. No
`sys.path`/global module-cache changes, upstream monkey patches or state-engine
imports occur. After import, assessment and serialization open no code/assets
and start no subprocess/network activity beyond consuming the caller's stream.

Run the portable controls from the repository root:

```sh
python3 fixtures/mvp/macos-trace/owned-trace-assessment/test_assessment.py
```

## Standalone diagnostic CLI

For independently supplied diagnostic data, run:

```sh
python3 fixtures/mvp/macos-trace/owned-trace-assessment/inspect_trace.py \
  --input DIRECTORY --owner-pid PID --target-pid PID
```

The directory must contain exactly four files: `program.d`, `probes.tsv`,
`errors.jsonl` and `events.jsonl`. Its numeric mode must be 0700. Each leaf must
be an ordinary, single-link file with numeric mode 0600, owned by the current
user. Root or mismatched real/effective UID/GID operation refuses. Numeric
ownership and modes **do not attest ACL privacy**. The input origin and both PIDs
are caller declarations; ownership, a valid transport and the exact four-file
roster do not authenticate a capture or establish native export safety.

The inspector stops a roster scan at a fifth entry. It holds no-follow,
close-on-exec, nonblocking directory/file descriptors, checks held identities
against the root path and anchored leaf entries before and after consumption,
and checks the exact roster again. Every opened input descriptor receives one
close attempt; a read, identity, roster or close error suppresses the report.
Stable trusted source and owned input namespaces without a concurrent privileged
mutator remain workflow preconditions.
Root symlinks and directory paths ending in `.` or `..` refuse; select the
directory by its explicit path.

The fixed bounds are 16,384 program bytes, 1,048,576 inventory bytes, 65,536 error
bytes, 134,217,728 event transport bytes and 8,191 bytes per event line. Complete
upstream validation still requires the exact program, empty errors and valid
inventory/transport. Static invalidity refuses before event consumption. Fixed
assessment, helper and asset identities have no caller overrides. Events stream
through the assessor once; no prefix report is published after a late failure.

Exit 0 means a complete diagnostic JSON report was produced. The report records
all four exact byte counts and SHA-256 hashes, declared PIDs, fixed assessor/core
identities and the full assessment. Its `origin` is
`caller-supplied/unverified`, its `status` is `incomplete`, and
`native_admission`, `export_admission`, `full_trace_acceptance` and
`state_feed_eligible` are always false. Canonical compact JSON, including its
final LF, must fit 16 MiB before any stdout write. Oversize output refuses
without truncation. A broken stdout pipe can still fail during publication.

Invalid input exits 1 with a bounded generic diagnostic and empty stdout;
argument errors exit 2. `--acceptance` alone exits 1 before required argument
checks, helper imports or input access. This command cannot act as a native
harness backend. It creates no export and does not call or replace packet,
metadata, closure or export admission. Existing capture/export gates and SIP
requirements remain in force. It grants no permission to read or copy protected
failed captures.

Run the synthetic directory/file controls from the repository root:

```sh
python3 fixtures/mvp/macos-trace/owned-trace-assessment/test_inspect_trace.py -v
```

The controls use serialized fixtures, literal expected selector vectors for all
161 declarations and independent positions for all nine open variants. They
exercise failed/unpaired attempts, high flag bits, unknown/unsupported phases,
Mach/lifecycle counts, exact/over projection bounds, late failure, immutable
serialization, runtime no-I/O and dependency preflight. They establish this
diagnostic integration only. Full R02 native calibration, object/state binding
and extraction acceptance remain open as recorded in
[the decision](../../../../docs/decisions/mvp-r02-owned-request-assessment.md).
