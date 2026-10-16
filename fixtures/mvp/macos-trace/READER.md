# Capability integrity reader

`read_capability.py` validates revision 4, `darwin-capability-raw-v4`, and exports its raw
timeline. It is a bounded diagnostic consumer, not a Darwin syscall decoder.
Every summary retains `full_trace_acceptance: false`. Its acceptance API and
`--acceptance` CLI option reject this format unconditionally.
Raw-v1/v2/v3 receipts require their retained source-matched older reader; this reader
does not reinterpret or upgrade old captures.

Run on the host after copying an actual guest capture and its matching toolkit:

```sh
python3 fixtures/mvp/macos-trace/read_capability.py \
  --capture /absolute/retained/capture-open \
  --toolkit /absolute/retained/toolkit \
  --output /new/absolute/raw-export
```

The reader requires Python 3.9 or newer and uses only the standard library. It
does not execute the toolkit or recorded argv, invoke DTrace, elevate privileges,
or change OS settings. The collector can still run in a guest without Python;
copy its evidence back to run this consumer. Paths must name real directories
throughout, including ancestors (`/private/tmp`, rather than the `/tmp` alias).
Directory symlinks, internal symlinks, hard links and nonregular files fail.

Use the reader from the reviewed checkout matching the retained toolkit's C
sources. It verifies all twelve `SHA256SUMS` entries, the retained source bytes
against `capture-native.c`, `lifecycle-probe.c` and `owned-probe.c` beside the
reader, and the receipt's collector/fixture identities against that toolkit.
It requires the revised producer's mandatory boolean `identity_checks_passed`
footer (introduced by `9414fed`). Missing, nonboolean or false identity status
rejects every capture status, including failed/unavailable captures. Such
evidence cannot establish transport integrity even when useful raw diagnostics
remain on disk. Older receipts without this footer are unsupported.
The source-matched toolkit is an explicit anchor selected by the operator.
Hashes establish byte identity; they do not authenticate a producer or prove
that retained source compiled into a binary. Retained build argv is bounded and
must be NUL terminated, but the reader does not attest compiler behavior or
signatures. Actual guest host/kernel labels are retained without mapping them to
assumed kernel semantics.

The export contains:

- `summary.json`: transport consistency, producer status and reason, host, argv,
  counts, observed process ledger, toolkit/receipt/reader identities and the
  unconditional full-trace rejection. `producer_diagnostics` retains validated
  rejected-layout/libdtrace metadata separately from callback fault/drop counts.
- `timeline.jsonl`: consumer index, producer kind label, original event object
  with exact typed byte hex, and subsequent numeric records represented as raw
  native little-endian uint64 values.

The numeric conversion is supported only for the reviewed native Darwin arm64
producer. There is no return-code/errno success classification, pathname
decoding, syscall pairing, FD/cwd tracking, process generation inference,
filesystem mutation verdict, or kernel-coverage claim. The copyinstr bytes stay
hex; a NUL or truncation interpretation requires actual ABI evidence. A consumer
index is not a kernel sequence or independent loss detector. Timeline records
stay in received order; the reader does not invent a cross-CPU ordering.

Validation requires exact JSON key sets/types, supported header/profile, bounded
identities, the exact generated D program including root PID, inventory-matched
probe descriptors, exact clause record counts/actions/sizes/offsets/byte totals,
explicit header record indexes, and
agreement between exposed headers and their raw uint64 bytes. It recomputes
event/open/callback totals. For `captured`, it additionally requires clean final
completion fields, exactly one BEGIN and END, required open events, no retained
errors, an empty watchdog file and a consistent replay of the producer's
observed ledger. The open-only profile records root terminal state from the
producer's root wait; this does not invent a proc exit event. The tree ledger is
only the producer's observed PID ledger, not proof that every child was visible.

Within one inspection, each EPID must retain its probe ID, complete descriptor
tuple, kind, record-byte total, header indexes and action/size/offset layout.
Each `(kind, probe ID)` in this fixed generated program must also retain one
EPID. Changed bindings or duplicate enablings reject even when individual
records, inventory and rebuilt hashes otherwise validate. Call-specific values
are not identity. The two session-local maps each admit at most 8192 enablings;
larger sessions fail the explicit diagnostic bound. No identities are evicted,
and maps are never carried between captures. See the
[binding decision](../../../docs/decisions/mvp-r02-darwin-enabling-bindings.md).

Raw-v4 retains every descriptor, including the exact zero-width assignment
descriptor at index 0, offset 12 for BEGIN/create/start/exec-success.
Its action must be `DTRACEACT_DIFEXPR` (1), size must be
zero and raw hex must be empty. The five uint64 header records start at offset
16 and their explicit indexes must match the clause. Other zero-width records,
arbitrary gaps, moved headers or skipped descriptors reject. The copyinstr
record retains all 1024 configured bytes at offset 56. The actual guest v4
diagnostic established the BEGIN layout; the other source-derived clause
layouts remain strict candidates for subsequent actual calibration, with no
kernel semantics or full-trace acceptance inferred from synthetic controls.

Kind 6 (`proc:::exit`) retains five scalar records for the current callback
context only. Its raw detail is not an application exit status or a target PID;
it neither clears a watch nor retires any observed process. Kind 18
(`proc:::exited`) retains the explicitly translated target PID as header detail,
then the opaque raw `arg1`, target `pr_addr` and raw target `p_refcount` as uint64
records at offsets 56, 64 and 72. Its eight scalar descriptors occupy 80 total
bytes, with no zero-width assignment or D watch clearing. The target address
must be nonzero and its refcount must fit uint32. Create
and exited target details must be in `1..INT_MAX` before any PID conversion.
The raw exit value is not decoded into application status. The pinned XNU
`P_REF_SHADOW` bit (`0x20`) prevents a shadow exited record from marking the PID
terminal. Such a record remains raw even after an observed terminal PID, and
does not create an unknown PID ledger entry. Only nonshadow target exits update
the observed terminal ledger. Duplicate nonshadow terminal events, create
reuse of a created/terminal PID and current activity after termination reject.
`lwp-exit` remains context-only cleanup and does not update the ledger.

This is a bounded replay of the reviewed collector's state, not process
generation attestation. A nonshadow exit for an unknown target remains
`created: false` and cannot complete the observed ledger. The raw address is
not a generally reusable generation identity. Actual v6 captures showed that
target PID alone could retire the live post-exec process during old-object
cleanup; new guest evidence must separately calibrate the private CTF field
reads and shadow discrimination. Source-matched synthetic controls cannot
establish that native result. See the
[shadow exit decision](../../../docs/decisions/mvp-r02-darwin-shadow-exit.md).

The revised producer's `layout-error` and `libdtrace-error` envelopes require
exact key sets, native integer bounds, bounded byte strings and at most sixteen
combined diagnostics. Layout metadata keeps signed descriptor counts, a
five-value header and at most twenty descriptors. A nonnull uint64 must belong
to an in-range eight-byte record within an 8 KiB probe; the header must agree
with those descriptor values. Descriptor actions retain their native uint16
bound. Null values do not prove data availability.
These envelopes are allowed only for started, failed captures. They neither
increment DTrace callback counters nor become events. A diagnostic explaining
an event index gap, count mismatch or rejected layout cannot excuse it. A
failed, internally inconsistent capture still rejects without publishing an
export, while its original files remain untouched.

Limits include 1 MiB receipt, 128 entries per flat directory, 256 processes,
1,000,000 events, 128 MiB event JSONL, 64 KiB lines, 8 KiB typed probe offsets,
1 KiB copyinstr records, 64 MiB other retained files and 256 MiB exported timeline.
Files are opened relative to held directory FDs with no-follow/nonblocking
flags; each read checks regular-file identity and metadata for changes. The
capture directory must contain exactly the protocol's eight files. Toolkit
extras may be regular unlinked build logs, with at most 128 total entries.
Unknown/missing/null identities fail closed, including the original collector's
64–128 MiB identity-limit inconsistency; the reviewed collector follow-up fixes
that producer bound. A nonempty watchdog always invalidates the final receipt.

No output directory is created until validation succeeds. The export path must
be new and is never overwritten. Exit 0 means only internally consistent
`captured` capability transport. Exit 1 means a failed/unavailable producer,
invalid/missing evidence, export failure or the unconditional acceptance
rejection. Internally consistent failure evidence can still be exported so its
raw diagnostics remain inspectable. No failed evidence is rewritten.

Run the controls with:

```sh
python3 fixtures/mvp/macos-trace/test_read_capability.py -v
```

Tests generate conspicuously synthetic records and dummy executable identities
inside temporary directories. They prove reader behavior, not native provider or
kernel capture. A Darwin-only control compares every generated D program with
the actual reviewed C generator without starting DTrace. Another control
compares every clause's synthetic C event output against the reader's strict
layout, retaining zero-width descriptors rather than discarding them.
