# Independent owned-trace raw transport validator

`owned_trace_check.validate_raw(program, probes, errors, event_lines,
owner_pid=actual_controller_pid, target_pid=actual_owned_child_pid)` returns
immutable `RawFacts`, or raises `RawValidationError` without returning partial
facts. It has no CLI, filesystem, provider, subprocess, trust, profile, deadline
or target-selection interface. Actual positive PIDs are trusted caller inputs;
this module does not observe process existence, ownership or kernel identity.
No existing reader, runner, registry, kit or packet adopts it in this step.

Program/probes/errors must be immutable bounded bytes. Each streaming iterable
item must be one immutable complete LF-terminated event line. The caller must
bound each source read itself, for example `readline(8192)` followed by this
validator's8191-byte check. The validator neither opens a path nor makes an
unbounded file read. The iterable must terminate, with no concurrent mutation
or reentry. An underlying source exception propagates and never returns facts.
Only inventory/enabling maps, fixed counters and one bounded line are retained;
raw events and captures are never accumulated. Hashes cover the exact supplied
bytes, including formatting and LF; JSON whitespace is accepted within the
physical line bound. Unknown, duplicate or missing JSON keys refuse.

The fixed independently reconstructed `program.d` must match byte for byte,
including the actual child literal, clause order, BSD and Mach transport, and
shadow discriminator read. No producer code is imported, executed or parsed.
`probes.tsv` requires canonical positive decimal uint32 IDs, unique IDs and
name tuples, exact native ASCII name capacities, and all17 selected categories:
BEGIN/END; BSD/Mach entry/return; and create/start/exit/exec-success/exec-failure/
lwp-create/lwp-start/lwp-exit/spawn-success/spawn-failure/exited. Unknown and
named-open kinds refuse. Permitted native module/function names are preserved;
there is no source-defined list of actual kernel probe IDs. Additional syscall
or Mach functions may exist. Inventory completeness against the real kernel and
enabled match counts require separate evidence; observed EPIDs need not cover
an unused inventory probe.

Events require contiguous consumer ordinals, nonnegative int32 CPU, positive
uint32 IDs, exact inventory names/kind and an observed EPID↔(probe,kind)
bijection. Every scalar is independently reconstructed from16 lowercase hex
characters as little-endian uint64. All five displayed header values must match
those bytes. Exact descriptor action/width/offset/count, total probe bytes and
header-index vector are checked, including the optional size-zero assignment
at offset12 for BEGIN/create/start/exec-success and empty hex for that record.
No bool/float/string substitutes for integers are accepted. Scalar payloads
start at offset16 and cannot overlap or escape the exact probe boundary.

A complete transport has one owner-context BEGIN before target observations,
one bound-target nonshadow exited terminal, and one owner-context END last.
The exited actor may be another positive int32 PID: target identity is its
`detail`, with nonzero address and uint32 refcount. Raw bit0x20 distinguishes
shadow exits; they never substitute for terminal. After terminal, only shadow
exited records, target lwp-exit cleanup and END are allowed. Current-context
exit, raw return/error values and thread cleanup do not prove target termination
or POSIX wait status. Descendant/create/spawn observations always refuse.

Bounds match the owned backend: program16384 bytes, inventory1048576 bytes and
8192 probes/enablings, errors65536 bytes, raw134217728 bytes,1000000 events.
Backend `char[8192]` reserves a NUL, so a serialized line is at most8191 bytes
including LF. Nonempty errors refuse before the event iterable is touched;
malformed or partial diagnostics remain opaque. No successful result can hide
a fault, drop, rejected-layout or partial raw tail. `RawFacts` retains exact
counts/hashes, observed enabling count, kind histograms and terminal raw scalars;
there is no whole-session acceptance boolean.

The contract sources are the reviewed
[`owned_trace_backend.c`](../owned-trace-backend/owned_trace_backend.c),
[`owned_trace_backend.h`](../owned-trace-backend/owned_trace_backend.h),
[`trace_session.h`](../trace-session/trace_session.h) and
[`CAPTURE_FORMAT.md`](../CAPTURE_FORMAT.md). Local primary Apple SDK header
`/Library/Developer/CommandLineTools/SDKs/MacOSX.sdk/usr/include/sys/dtrace.h`
defines `DTRACEACT_DIFEXPR=1`, invalid ID0, uint32 probe/EPID types, int CPU type
and name capacities64/64/128/64 (including terminating NUL). Its observed SHA256
is `2f491e086b408e62a7fc67846ae394daa7bf3db88145cf6b394f99a72e65b32c`.
The historical v8 contract grounds native little-endian arm64 shapes and raw
`P_REF_SHADOW=0x20`; these sources do not calibrate a new actual guest capture.
No SDK tools, compiler or native program are needed to run these controls.

Run `python3 -B test_owned_trace_check.py -v` in this directory. The suite uses
a literal program fixture and independently serialized scalar/descriptor data,
single mutations, hostile JSON/name/integer/boundary cases, source exceptions,
8192-probe capacity and a streaming128MiB fixture with bounded traced memory.
It exercises the separate event-count guard directly because the raw-byte cap
prevents reaching one million valid records in the current verbose JSON shape.
Every descriptor/header/JSON/integer mutation replaces a record in a complete
accepted lifecycle, with an explicit passing baseline and intended rejection
reason. A regression control records why a lone non-BEGIN record was an invalid
baseline for the earlier mutation harness. Fixtures and their PASS results
supply no native ABI/provider calibration.

Raw order proves neither GO permission/write, successful kernel exec, enabled
probe counts, actual stop/drain/DONE, child reap, writer/resource closure nor
bootstrap/result/sidecar consistency. Timestamp values stay raw; no DTrace to
CLOCK_MONOTONIC domain equivalence, timestamp ordering or deadline derivation
is asserted. This module is not an extraction/effect decoder, full process-tree
oracle, evidence admission, R02 or M2 proof. Native calibration and later
independent session/sidecar/packet checks remain separate.
