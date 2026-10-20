# Synthetic mapping state units

This bounded engine checks declared mapping intervals and requested shared-file
write capability. It does not read raw Darwin captures, discover native mappings
or objects, or grant extraction acceptance. Every report and rejection diagnostic
has full_trace_acceptance false. Full-acceptance requests always refuse before
input reads and contain no invented input digest.

    python3 -B fixtures/mvp/macos-trace/mapping-units/test_mapping_state.py -v
    python3 -B fixtures/mvp/macos-trace/mapping-units/mapping_state.py --input /absolute/units.jsonl

CLI zero means only that the supplied synthetic model closed, including any
retained shared-file write requests. Rejected input returns one, emits no stdout,
and normally emits a bounded JSON rejection on stderr. Output-bound failures
can emit a smaller explicitly incomplete diagnostic; an impossibly small output
limit can suppress even that diagnostic. No prefix is a closed model or resumable
observation. Normal process exit does not prove native resource cleanup.

## Record contract

Each JSONL record has exactly revision, protocol, origin, index, event and data.
Revision is integer 1, protocol is darwin-normalized-mapping-unit-v1, origin is
synthetic-unit, and indexes are consecutive from one. Each event data object has
exactly these fields:

| Event | Data |
| --- | --- |
| start | page_size: 4096 or 16384 |
| process | process token, positive pid, exec: 0 |
| backing | backing token, kind: regular |
| enter | process, exec, unique call, operation, args |
| returned | process, exec, call, operation, result, error |
| exec | process, exec, new_exec |
| retire | process, exec, mappings: exact distinct live mapping tokens |
| finish | records: footer-inclusive count, totals: exact counters |

The declared page size is a synthetic grid, not a host or guest observation.
The start record seeds no mappings. Backing and process declarations are
individual records, not bulk initial-state lists. Objects are supplied regular
file generations, not paths, descriptor slots, kernel addresses or authentication.
The process generation, call generation, backing generation and mapping
generation namespaces are separate. Tokens never revive; a live PID cannot be
reused. Mapping tokens are consumed at entry even when map later fails.

The process/epoch must remain exact. Only one request may be pending per process,
including for disjoint ranges; different processes may use the same addresses.
An exec event advances exactly one epoch only with empty mappings and no pending
call. Retirement lists each remaining mapping generation once even if it has
several fragments. It removes those ranges without deleting history/attempts.
Every process must retire before the exact footer. Fork/spawn/vfork inheritance
and native initial-state discovery are unsupported.

Operations and exact argument fields:

| Operation | Args |
| --- | --- |
| map | mapping, address: 0, length, prot, flags, offset, backing |
| protect | address, length, prot |
| unmap | address, length |

File map flags are exactly 1 (shared) or 2 (private), with a declared backing token.
The only anonymous flags are 4098 (private plus anonymous), with null backing and
offset zero. Protection is exactly a combination of bits 1, 2 and 4, including
zero. Other flags/protection bits reject; requested bits imply no extra hardware
permissions or hardened-runtime admission. In particular FIXED, JIT, resilient,
translated and TPRO mappings, anonymous Mach tags, shared anonymous/System V
memory, device mappings, msync and Mach aliases are unsupported.

Map success returns an aligned positive address and error zero; failure returns
null and a positive error. Protect/unmap success returns integer zero/error zero;
failure returns -1/positive error. These are declared normalized results, not
rules for decoding raw pointer/errno/provider words.

Ranges are page-aligned, nonempty half-open intervals, with end at most 2^64-1.
No wrapping or rounding occurs. File offsets and offset-plus-length fit positive
signed 64-bit range (offset may be zero). Protect/unmap require complete coverage,
including when spanning fragments; holes reject. Protection splits preserve
mapping/backing generation, sharing and file offsets. Partial unmap removes only
covered bytes; address reuse requires a new mapping generation. No coalescing is
performed. Anonymous fragments have null file offset.

Backing tokens are copied into mappings. There is no descriptor lookup or close
event; later FD reuse cannot rebind those copied tokens. A future native adapter
must independently establish and retain the actual backing identity.

## Attempts and rejected effects

Shared file map with requested write, and protect requesting write on a shared
file range, append entry-time attempts even when already writable or later
unsuccessful. Each attempt retains call/index, process/epoch, operation, requested
range/protection/flags, clipped shared-file fragments and eventual outcome.
Before map success, its address/result and fragment start/end are null. Private
and anonymous mappings remain distinct state, without authorizing execution.
Capability requests are not observed stores, dirty-page writeback or file effects.

A failed map installs nothing and keeps its consumed mapping generation.
Failed protect/unmap retains entry intent, records the failed outcome and
permanently poisons replay: no atomic no-effect guarantee is inferred.
Its diagnostic contains the last modeled state marked nonauthoritative, plus
attempt/history prefixes. Malformed and unsupported records poison too.

The pure API is MappingMachine.feed(record), finish(), and rejection(error).
MappingError carries a stable code and optional report from replay(path).
Report materialization is once-only. Input records and their nested scalar
arguments are copied where retained; emitted fragment/attempt copies do not
alias the machine's state. finish requires a valid footer; rejection is
explicitly incomplete and cannot become acceptance.
Optional input metadata is a closed sha256/bytes/scope object with a lowercase
64-digit digest and canonical bounded byte count. It remains caller-supplied
metadata in the pure API, without authenticating an input or native capture.

## Bounds and provenance

The input cap is 8 MiB, 50,000 records, and 64 KiB per LF-terminated line.
Objects/calls/processes are bounded at 4096/10000/64 generations; live fragments
are globally capped at 4096. There are at most 10000 attempt records, 50000
aggregate attempt-fragment slots and separately 50000 snapshot/output fragment
slots. History has at most 50000 reserved records. Each stored attempt and
entry/result/history snapshot reserves a second fragment slot for its single
eventual output copy; live-state output copies are additionally reserved.
These conservative counters are cumulative, including retired history and failed
requests. They can refuse before the live interval limit would be reached.
Prospective split/snapshot/attempt/history costs are checked before mutation.

No initial or declaration batch lists are accepted. Retirement lists are capped
by the global live-fragment bound. Integers are built-in ints, excluding bool
and subclasses. Tokens are 1–64 ASCII identifier characters. Duplicate keys,
floats/nonfinite JSON, truncated lines, type/schema/epoch gaps and unsupported
records reject. Input must be a singly linked regular file opened no-follow and
nonblocking; size and device/inode/link/mtime/ctime identity are checked after
reading. JSON encoding is bounded incrementally to 32 MiB.

A successful replay hashes the complete input. Rejection labels its hash
consumed-prefix unless the complete stream was actually read and hashed. The
prefix can include the rejected line or its bounded read prefix; it is not the
hash of only accepted records. Acceptance refusal reads no input and reports no
input digest. Header/source declarations do not authenticate any capture.

abi.json pins the inspected macOS 27.0 SDK settings, sys/mman.h and three man
pages, with exact byte sizes and SHA-256 values. Constants and primitive candidate
semantics are from those sources. Their agreement with the macOS 26.6.2 guest,
actual page size, raw arguments/results, failure atomicity and authoritative
mapping/FD generations is unproved. No local SDK file is needed to run these
portable source-only controls.

The independent tests compare per-page tuples using their own small page grid,
rather than calling the interval splitting helpers. They establish synthetic
consistency only. Native calibration, effect ordering/races, inheritance/Mach
alias coverage, complete collection and the adversarial extraction corpus remain
open under docs/decisions/mvp-r02-darwin-mapping-state.md.
