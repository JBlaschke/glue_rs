# Derive the fixed tracing inventory from the compiled selectors

Status: accepted for the owned diagnostic adapter; native calibration pending.

The first two-case guest attempt (`269bf09070bc81f8`) reports native status1
before GO. Bounded read-only UI inspection of its saved metadata reports 1,051
inventory probes and expected matches, but 1,257 enabled matches. The parent
reports the child reaped and resources closed. This is a failed private attempt,
not a retained native acceptance result or independent cleanup attestation.

The adapter inventories all probes before compiling the fixed program and then
assumes that count equals the compiled program's match count. The public SDK
defines `dpi_matches` for the program; Apple's source sums matches for compiled
ECB descriptions. Compilation and probe information lookup can provision probes.
Neither that mechanism nor overlapping descriptors is established as the cause
of this guest's particular count difference. A precompile inventory does not
prove the required equivalence.

Compile the unchanged program first. Use public `dtrace_stmt_iter` to visit at
most 512 statements and retain at most 17 distinct `dtsd_ecbdesc` pointers. Shared
ECB pointers across multiple action statements are counted once. Validate every
ECB probe selector against the unchanged fixed 17-clause contract: BEGIN/END,
BSD and Mach entry/return, and eleven named process lifecycle probes. Reject
missing, additional, duplicate or unexpectedly normalized selectors.

Enumerate matches of each validated compiled selector once with public
`dtrace_probe_iter`. Require a nonempty bounded set for every selector and exact
expected probe kind, valid names, nonzero unique IDs and unique full name tuples.
Reject overlaps across selectors. Retain at most 8,192 physical probes in total,
with the existing output-byte bound. Check the original deadline at iteration
callbacks and libdtrace boundaries. The sum of validated selector matches is the
expected enabling count; proved exactly-once coverage also makes it equal to
the retained unique inventory count. Require exact `dpi_matches` equality before
`dtrace_go`. Do not retry, recount after enabling, weaken equality or pin the
observed guest counts.

The fixed program, provider scope, callback identity/EPID checks, readiness from
an actual serialized BEGIN, lifecycle and cleanup contracts, public adapter API
and metadata schemas remain unchanged. This changes no extraction interpretation.
Boundary controls must cover compile-time probe creation, shared ECB statements,
missing/extra/overlapping selectors, malformed identities, iteration failures,
bounds/deadlines, and enabled counts one below or above the validated expectation.
Native SDK compile/link and source-isolated models do not establish native
provider calibration.

Existing registered source pins, kits and packets remain immutable. The repaired
adapter requires a separately reviewed source registration, fresh kit and fresh
packet before another guest diagnostic. The failed attempt is not rerun or
promoted. Full Darwin acceptance remains open.
