# Original stopped-runtime diagnostic reader

`runtime_stopped.pair_runtime_stopped_raw` consumes one complete original
physical stream for the fixed `glue-stopped-runtime-v1` producer. Its inputs
are `program.d`, `probes.tsv`, `errors.jsonl`, an iterable of complete original
`events.jsonl` lines, the pinned contract bytes, the eight original runtime
recipe assets, and the original 4096-byte GLUEPX output-observation packet.
Owner/target PIDs are explicit and must agree with all original bindings.
It accepts no continuation sidecar, normalized capture, caller operations,
profile switch, match boolean, native-origin assertion or policy callback.

The eight recipe assets remain `request`, `catalog`, `launch_plan`,
`status_stream`, `launcher_artifact`, `output_witness`, `gate_delivery` and
`go_prefix`, packaged by the existing immutable `RuntimeRecipeEvidence`.
The entire original 1024-byte status stream and all existing RR/RC/TL,
16 MiB launcher, empty environment, held unrelated CWD, original output,
actual GO-delivery and close checks run through the shared private recipe
validator. The new reader verifies exact expected program bytes and the
original GLUEPX request/catalog/first READY/program/output-witness digests.
A digest binds bytes; these inputs do not authenticate native execution.

The private `runtime_physical` codec delegates unchanged legacy decoding to
the identity-checked owned reader. Its new closed grammar checks all scalar,
zero-size assignment, raise and tracemem action descriptors, offsets, widths,
record sizes, headers and enabling identities. Query buffers remain 176
original little-endian bytes and wait buffers remain four original bytes.
The original owned reader and its source facts are unchanged. The physical
transport consumes the iterable once and retains every owner/child phase
with its original outer ordinal. Child attachment position is counted
separately, so an owner prelude cannot turn an arbitrary child return into
an accepted attachment orphan.

Each owner entry/return is paired by the original thread, call ID and probe
identity. The fixed shape predicates select query, wait, kill or scalar-only
fallback records; query shape never establishes pointer validity. Missing,
repeated, unsafe or contradictory owner controls remain in the result and
make it incomplete. Terminal waits and ECHILD retire conditional owner
bookkeeping even if the GLUEPX observer failed after that wait. Cleanup
context remains visible. No later signal can restore a retired lease.

A correlated episode requires one selected exec/new TID, one exact stop
request marker after that exec-success in the original outer ordinal order,
the original wait journal, a contiguous matching prefix of
all eight successful queries, and the immediately following actual
`kill(child, SIGCONT, 1)` entry/return. Original query PID, fd, buffer address,
flavor, byte count, outcome and all 176 bytes must agree. GLUEPX field-encoded
buffers are reversed at the fixed SDK field widths; opaque failure buffers
are compared without reinterpretation. Wait status bytes are compared with
the actual four retained bytes, including opaque failed/zero-return buffers.
GLUEPX has no wait-status-buffer address, so this is a conditional journal
join and does not authenticate that pointer.

Independent ECBs need not share timestamps. A query's raw entry/return gives
its lookup window; copying completes no later than the next selected owner
entry on that same thread, ultimately the SIGCONT entry. The reader does
not treat a header timestamp as the copy instant or compare C monotonic
clocks with DTrace timestamps. Closed child call intervals touching these
windows, pre-CONT child progress/exit/additional threads, later execs and
unsupported Mach/image paths make the entire diagnostic incomplete. They
grant no retrospective write permission. Every physical phase is accounted
for even if image interpretation fails, in which case no image/query prefix
is published as a successful interpretation. Invalid physical transport or
original evidence raises the existing validation exception.

The immutable result is either `source-conditional-correlated` or
`incomplete`. All native/raw origin, quiescence, OFD/generation, full flags,
state feed, sink exemption and full acceptance flags stay false. Actual raw
kill calls express intended control only: retention before continuation and
successful signal delivery are unproved. Foreign controllers and unobserved
mutations are not excluded. No current TS session, runner, controller,
registered kit or protected-target admission adopts this profile. Native
preflight/proof remains a separate pending gate; SIP stays enabled.

Run the original-byte synthetic reader controls with:

```sh
PYTHONDONTWRITEBYTECODE=1 python3 test_runtime_stopped.py -v
```

Run the adoptable producer/reader controls with:

```sh
PYTHONDONTWRITEBYTECODE=1 python3 test_runtime_stopped_backend.py -v
```

The latter uses strict `-pedantic -Werror` pure C formatting and a forced
non-Apple unavailable-factory/getter test on portable hosts. Its Darwin SDK
controls compile actual backend code with all libdtrace functions defined
by the test TU; they never link libdtrace, enable a provider or send a signal.
They cover 26 injected modes and compare both original C marker orders with
the private physical decoder. These small injected streams are deliberately
not full recipe/GLUEPX or native traces. SDK-only controls are explicitly
skipped on other hosts. `GLUE_RUNTIME_STOPPED_RETAIN` retains commands,
stdout/stderr, artifact streams and source guards in a new local directory;
`GLUE_RUNTIME_STOPPED_SANITIZE=1` enables ASan/UBSan. Retain and assess actual
compiler/sanitizer failures instead of treating unavailable instrumentation
as a successful native measurement.
