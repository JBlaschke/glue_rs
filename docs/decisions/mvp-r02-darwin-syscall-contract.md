# Source contracts before a Darwin raw adapter

16 October 2026. R02 remains open. Actual owned v3/v4 captures exposed zero-byte
DIF assignment descriptors; v5 exposed process-target loss when `proc:::exit`
fired in the parent's context. Neither raw framing nor normalized state controls
establish a complete Darwin extraction oracle.

Add a bounded executable registry of BSD syscall declarations and argument-word
selectors, pinned to public Apple XNU sources and explicitly identified local
SDK headers. A separately validated raw-reader timeline can be inspected against
this registry. Unknown calls/providers and unresolved control-flow returns remain
unsupported. Every entry reports unresolved path, FD, lifecycle, memory or nested
structure requirements. No entry is an allowed operation or a proof verdict.

The registry preserves raw uint64 argument/result bits. It does not pretend a
pointer is a path, an FD number is an object, current probe PID is a lifecycle
target, or a failed return removes an attempted mutation. No raw event is
converted into a synthetic normalized unit to obtain acceptance. Full acceptance
requests always fail. The direct-open adapter and C producer remain separately
owned work with their own actual calibration requirements.

The local default SDK is 27.0; the owned guest is 26.6.2. SDK-only routes are
recorded as unsupported rather than inferred available on the guest. The registry
is a reusable source/coverage boundary for the real raw adapter, not a claim that
all Darwin syscalls have been enumerated or decoded. Pointer snapshots, spawned
file actions, inherited rights, FD/object generations, async work and Mach RPC
semantics still require implementation and adversarial native acceptance.
