# R02: bounded synthetic mapping state and shared-write requests

Status: accepted for the bounded source implementation below. Full Darwin
R02/M2 remains open; this record grants no native acceptance.

The existing normalized state engine models descriptors and cwd, but not mapped
memory. The syscall contract names mapping obligations without implementing
them. A shared file mapping can carry write capability after its original FD is
closed, and a protection change can request write capability later. Add this
missing state calculation without claiming that the present raw traces supply
its object identities, initial state or causal ordering.

Implement a separate pure engine and bounded JSONL driver under
`fixtures/mvp/macos-trace/mapping-units/`, with `mapping_state.py`,
`test_mapping_state.py`, `abi.json` and README. Preserve the existing
`darwin-normalized-state-unit-v1`, FD/cwd engine, normalized open decoder, strict
readers and native capture formats byte-for-byte. Do not register this protocol
as an extraction backend or convert raw observations into synthetic records.
The no-extraction policy and application-output distinction remain unchanged.

## Explicit unit facts

Use the new `darwin-normalized-mapping-unit-v1` protocol, revision integer 1 and
the sole origin `synthetic-unit`. Each record has exactly `revision`, `protocol`,
`origin`, consecutive one-based `index`, `event` and `data`. Each event's data
schema is closed: extra/missing fields or unsupported types reject. No record
can assert native validation, trusted observation, allowed output or acceptance.

The start record fixes a declared model page size of either 4,096 or 16,384
bytes. These are supported synthetic grids, not a host/guest page-size probe.
It seeds no mappings. Processes are independently declared with unique process
generation tokens, positive numeric PIDs and initial exec epoch zero. Numeric
PIDs cannot be reused while live; a retired token never becomes live again.
Declare backing-object generations separately, with the sole file kind
`regular`. These are explicit unit facts, not inferred paths, vnode addresses,
FD numbers, stat results, signatures or kernel attestation.

All requests and returns name the exact live process generation and exec epoch,
and a globally unique call token. At most one request is pending per process:
this first engine rejects concurrent requests even when their ranges differ.
The declared unit order is an assumption, not proof of kernel effect order.
An explicit exec-boundary event may advance the epoch by exactly one only when
the process has no live mappings or pending request. No fork, vfork, spawn or
mapping inheritance is modeled. A process-retirement event must name exactly
its remaining live mapping generations and have no pending request; it retires
those ranges without deleting their history or attempted-write records. The
footer checks exact record/totals accounting and every process terminal.

## Mapping and range transitions

Use half-open byte intervals `[start, end)`. Nonzero lengths, addresses used for
installed ranges, file offsets and range boundaries must be aligned to the
declared page size. Reject noncanonical integers, negative values, arithmetic
overflow, zero lengths, unsupported rounding and any range outside the declared
unsigned 64-bit address domain. Require `start < end <= 2^64 - 1`; this is a
conservative unit bound, not a statement about usable Darwin address space.
File offsets are nonnegative signed-64 values; offset plus length must not
exceed `2^63 - 1`. Do not truncate, wrap or silently round inputs.

Admit only three request operations, with operation-specific exact argument and
return schemas:

- `map`: length, requested protection, mapping flags, file offset and backing
  generation or null. The only address hint is zero. File-backed flags are
  exactly `MAP_SHARED` or `MAP_PRIVATE`; the sole anonymous combination is
  `MAP_PRIVATE | MAP_ANON`, with null backing and offset zero. A successful
  normalized result supplies its actual aligned, nonzero address and error
  zero. Failure supplies no address and a positive canonical error. The new
  range must not overlap an existing range. Its mapping generation is unique
  even after unmap, failure, process retirement or address reuse.
  Supply that generation as an explicit `mapping` token in the map arguments;
  consume it at entry, including for failed maps. Mapping and call tokens have
  separate globally unique namespaces.
- `protect`: aligned address/length and requested protection over a completely
  covered live range. The exact fragments are snapshotted at entry. A canonical
  zero success splits intervals as necessary and changes only the covered
  protections, retaining mapping/backing generations and correct file offsets.
- `unmap`: aligned address/length over a completely covered live range. A
  canonical zero success removes exactly that range, splitting survivors and
  retaining their mapping/backing generations and adjusted offsets.

Return records must match the one pending call, operation, actor and epoch.
Protect/unmap ranges may span adjacent fragments only if every byte is modeled;
holes, unknown mappings, stale generations or unexplained replacement reject.
Keep separate generations at a reused address. Do not merge away provenance;
coalescing is optional only when mapping generation, backing generation, sharing,
protection and contiguous backing offsets all agree.

A mapping copies the supplied backing generation into its own immutable state;
it does not retain a reference to a descriptor slot or consult a later FD table.
This engine has no FD lookup, close or reuse input. Closing/reusing an external
FD therefore cannot rebind an existing mapping to another object. A future raw
adapter must establish the copied identity and retain the source evidence.

## Attempted writes and incomplete effects

Retain an entry-time shared-file write-capability request whenever `map` requests
`MAP_SHARED` with `PROT_WRITE`, or `protect` requests `PROT_WRITE` on any covered
shared file fragment. This includes requests that retain already-writable
protections, requests spanning several backing generations and failed calls.
Record the call/index, process/epoch, operation, affected mapping/backing
generations, requested range/protection/flags and eventual normalized outcome.
An attempted map has no installed address before a successful return. Do not
fabricate one to populate its attempt record.

Private and anonymous writes are distinct modeled categories; they do not erase
shared-file attempts or authorize an execution. A protection request is not an
observed memory store, dirty-page writeback, file effect or extraction verdict.
No application-output, stdio or pathname exemption is introduced.

A failed nonfixed `map` installs no range and retains its attempted intent.
For failed `protect` or `unmap`, these inspected sources do not establish an
atomic unchanged-state guarantee for this model. Poison replay rather than
assume old or new state. Preserve the entry attempt ledger in an explicitly
incomplete rejection diagnostic; it must never be a closed-state report or an
acceptance result. Any malformed/unsupported record also poisons the instance;
later records cannot repair it. No normal report is emitted before valid footer
closure. A retained diagnostic prefix is labeled incomplete and cannot be fed
back as observations or used to resume replay.

Reject unknown protection bits and every unmodeled flag, including `MAP_FIXED`,
`MAP_JIT`, resilient/translated/TPRO flags and anonymous Mach tags. Both/neither
sharing bits reject. `PROT_NONE/READ/WRITE/EXEC` describe requested bits only;
the engine does not infer additional hardware permissions or hardened-runtime
admission. Mach VM aliases/remapping, shared anonymous/System V objects, msync,
fork/exec inheritance, device mappings and initial native mapping discovery
remain unsupported. No failed return turns one of these routes into support.

## Bounds, outputs and verification

Use built-in integers only, excluding booleans/subclasses. Tokens are bounded
1–64 character ASCII identifiers. Bound the complete input to 8 MiB, 50,000
records, 64 KiB per LF-terminated line, 64 process generations, 4,096 backing
generations, 10,000 call generations and 4,096 live fragments across the whole
model. Initial/declaration lists are each bounded to 128. Retain at most 10,000
attempt records and 50,000 aggregate attempt-fragment entries across the entire
replay, including failed/incomplete attempts. Separately bound aggregate retained
entry snapshots, transition-history fragments and pending snapshots together to
50,000 fragment entries; call/transition history has at most 50,000 records.
Copies and diagnostic materializations count against these limits, not merely
distinct live intervals. Keep at most one pending request per live process.
Check prospective split, snapshot, history and attempt costs before mutation;
refuse rather than allocate an unbounded product of calls and fragments. Bound
serialized normal/rejection output to 32 MiB and preserve exact input hash/counts.

Strict JSON parsing rejects duplicate keys, nonfinite values and oversized or
truncated records. Read only a singly linked regular file through a no-follow,
nonblocking descriptor, check size and non-atime identity before/after, and
never execute input data. Parser, transition and diagnostic output bounds must
be enforced in the implementation, including worst-case split/attempt growth.

Every report or rejection diagnostic has `full_trace_acceptance: false` and
explicit synthetic scope. CLI zero means only that the declared model closed;
attempted shared writes remain present. Unsupported/incomplete input returns
nonzero. The full-acceptance API and CLI option unconditionally refuse before
opening the input, including nonexistent input. No new acceptance backend,
trace registry, proof, kit or VM operation is added.
Label a rejection digest as a consumed-prefix digest unless the complete input
was actually hashed. Acceptance refusal must not manufacture any input digest.

Controls must exercise shared versus private/anonymous requests, failed maps,
shared read-to-write upgrades and already-writable requests, split protection
ranges, partial unmap and address reuse, backing-generation stability, distinct
processes/epochs, unsupported inheritance/flags/aliases, failed range-change
poisoning, pending-call mismatch, exact footer closure, arithmetic/alignment/
gap limits, fragment/attempt bounds and unconditional acceptance refusal.
Use literal expected transitions and a small independent page-grid reference
model for bounded split/unmap sequences. Existing FD/cwd and open-intent suites
remain unchanged; add one focused source-only CI invocation after review.

## Exact local source boundary

Inspected 20 October 2026 through
`/Library/Developer/CommandLineTools/SDKs/MacOSX.sdk`, resolving to
`/Library/Developer/CommandLineTools/SDKs/MacOSX27.0.sdk`.
`SDKSettings.json` identifies `CanonicalName: macosx27.0`, `Version: 27.0`.
Pin the following exact bytes in the later `abi.json`:

| SDK-relative file | Bytes | SHA-256 |
| --- | ---: | --- |
| `SDKSettings.json` | 7948 | `7b93ad7e534cc4b31c6a4e39d19b5e0288acf2168c2649479a796d1cb51939fb` |
| `usr/include/sys/mman.h` | 11090 | `07adbf7f11a601e6461ca508a2deca037103008600608f8dbe93a4b0887d46e9` |
| `usr/share/man/man2/mmap.2` | 11710 | `ccc6064c76ad2b01d7e82b0079d3e8ed3d84878c086aa300f12fb3eeb5645659` |
| `usr/share/man/man2/mprotect.2` | 5078 | `818ececb641630643b612ae2cc1700e91d982ab88c5592c4f7cf3b68f1c174a9` |
| `usr/share/man/man2/munmap.2` | 5377 | `610a0cefd19decf5f00cba83a86a81138372bd647ea4d5917b91c8849b808f65` |

The header defines `PROT_NONE=0`, `PROT_READ=1`, `PROT_WRITE=2`, `PROT_EXEC=4`,
`MAP_FILE=0`, `MAP_SHARED=1`, `MAP_PRIVATE=2`, `MAP_FIXED=0x10`, `MAP_JIT=0x800`
and `MAP_ANON=0x1000`; `MAP_COPY` aliases `MAP_PRIVATE` and `MAP_ANONYMOUS`
aliases `MAP_ANON`. These are source constants, not guessed runtime values.
`MAP_FAILED` is the header's pointer-minus-one macro, not a uint64 raw return
normalization rule for this protocol.

The mmap page describes shared/private modifications, successful returned
addresses, replacement by MAP_FIXED and the fact that close does not unmap.
The protect/unmap pages describe range transitions and canonical libc results;
munmap also describes deferred dirty shared-file writeback. They ground these
primitive candidate semantics, not kernel source equivalence, atomic failure
effects, native page size, object identity, complete initial mappings or DTrace
argument/result/control-flow encodings. The inspected SDK is 27.0; the existing
guest observations identify macOS 26.6.2. Neither is evidence that this engine
models an actual guest execution.

Native admission still requires calibrated raw mmap/protect/unmap slots and
returns, authoritative backing/mapping generations and seeded state, proved
effect ordering and races, inheritance and Mach alias coverage, complete
collection and adversarial extraction/corpus evidence. This decision supplies
none of those facts and does not advance R02/M2 acceptance.
