# Independent fixed owned-trace raw transport validator

## Decision

Add a pure Python validator in `fixtures/mvp/macos-trace/owned-trace-check/`.
Its only input contract is bounded program, probe-inventory and error bytes,
a streaming iterable of bounded event-line bytes, and the actual controller
and owned bootstrap-child PIDs supplied by a trusted caller. It has no runtime
profile, trust, target, library or acceptance-policy selector and no filesystem,
tool, provider or native execution interface.

Independently regenerate the exact fixed owned-backend D program; do not import,
execute or adapt the producer. Validate the complete selected inventory and
observed EPID/probe/kind identities, strict duplicate-free JSON objects, native
scalar/descriptor layouts and little-endian header relationships. Require one
controller BEGIN, one bound-target nonshadow exited terminal and one controller
END in order. Shadow exited and lwp cleanup retain their limited raw meaning;
descendant/spawn observations refuse. All required BSD/Mach/proc categories must
exist; named-open and smaller profiles are not accepted. Errors must be empty.

Return bounded immutable facts and streaming byte hashes/counts only after full
transport validation. Preserve the backend bounds: program16384 bytes,
inventory1048576 bytes/8192 probes, diagnostics65536 bytes, raw134217728 bytes,
one million events and8192-byte C line storage (at most8191 serialized bytes,
including LF, because the writer reserves a NUL). No partial tail is decoded.

Primary local SDK headers ground DIFEXPR1, uint32 IDs, int CPU IDs and native
name capacities. The reviewed owned backend and CAPTURE_FORMAT supply the fixed
v8 scalar/zero-assignment/target-exit contract. This is independently implemented
source-contract checking, not native ABI calibration. Synthetic fixtures are
serialized independently and include individual corruptions and early bounds.

The validator does not accept a bootstrap session, sidecar, result or evidence
packet. Raw event order cannot establish GO, stop/drain/DONE, enabled probe
counts, wait status, resource closure, identities beyond the supplied values,
or loss-free coverage. DTrace timestamps are raw uint64 observations; no
CLOCK_MONOTONIC domain equivalence, deadline derivation or native timing proof
is inferred. Fixture PASS establishes no kernel exec, extraction, complete
process tree, R02 or M2 proof. Existing readers, sources, registries, CI and
progress records remain unchanged; root owns later integration and admission.
