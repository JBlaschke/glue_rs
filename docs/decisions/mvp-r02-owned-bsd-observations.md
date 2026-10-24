# R02: retain BSD scalar observations from the owned transport

Status: accepted for a bounded observation adapter; native calibration and full
Darwin/R02 acceptance remain open.

The owned collector already records BSD entry and return scalars, and its
independent `owned_trace_check.validate_raw` validates their exact transport.
That function currently returns only aggregate `RawFacts`. The historical
`pair_calls` adapter accepts a different source-matched toolkit and the
`lifecycle-probe` fixture; it cannot be applied to this owned collector by
relabeling records. Connect the owned transport to the existing BSD source
contracts without inventing the missing call, object or filesystem semantics.

## Preserve the existing transport API

Keep the public `validate_raw(program, probes, errors, event_lines, *, owner_pid,
target_pid)` signature, returned `RawFacts`, rejection conditions and streaming
memory bounds unchanged. It still performs no filesystem I/O, provider work,
subprocess work or contract-asset reads. Importing the module must not read the
contract asset. The existing 128 MiB streaming control and its memory assertion
remain enabled. No selected record list is allocated on this old API's path.

Factor the existing checks through one private strict walk. The walk may pass
an already validated event's inventory identity, scalar tuple and exact ordinal
to a private projection accumulator. This is not a public callback or a stream
of trusted prefixes. It must not expose an observation, partial report or mutable
internal accumulator to the caller before exhausting the input and checking the
complete BEGIN/target-terminal/END transport. Source-iterator exceptions and
later corruption return neither `RawFacts` nor projected observations.

## A pure, separately bounded observation API

Add `observe_raw_bsd` with the same transport inputs and trusted actual PID
arguments, plus mandatory immutable `contract_bytes`. It returns a frozen result
containing the unchanged `RawFacts` and a tuple of frozen BSD-phase observations.
Every nested retained collection is immutable and detached from caller or parser
objects. No API accepts a caller-provided `RawFacts`, validated-event assertion,
normalized unit, pathname identity or object declaration in place of validation.

The API uses the checked-in `syscall-contract/contracts.json` asset:

- size: 96,972 bytes;
- SHA-256: `31f96f93c2ca1bd58ae322a6d3c223dd764e5a763088cfed2dbf78a8a21104e2`.

The caller supplies those bytes through its separately bounded input handling.
The new API checks the bytes type, exact size and exact pinned digest before
parsing or consuming events. It does not open the asset or search an SDK. Add a
pure bounded-byte table parser in `syscall_contract.py`; the existing `load_table`
keeps its file contract and delegates only its table parsing to that helper.
Neither the parser nor existing entry/return fact helpers perform an implicit
file read when the parsed table is explicitly supplied. This step changes no
contract entries, selectors, source claims or native-adapter statuses.

Retain each observed BSD entry and return, including unknown names and phases
that cannot be paired. An observation contains the exact consumer ordinal, CPU,
probe ID, EPID, provider/module/function/name, all five raw header scalars, and
all eight entry or five return words. These are unsigned raw bits. The aggregate
raw SHA-256 and ordinal link it to the complete retained transport; the adapter
does not accumulate original JSON lines or manufacture a new raw-capture hash.

For a source-contract entry, invoke the existing `entry_facts` helper using the
once-parsed pinned table. Freeze its selected raw fields, source declaration
number/family, argument count, unresolved requirements and contract identity.
Unknown names have no source declaration and remain explicitly unresolved;
inventory membership or a successful transport is never an effects allowlist.

For a return, retain the existing `return_facts` raw projection when its
duplication/errno shape is supported. Otherwise retain all raw words and an
explicit unsupported-shape reason. Such a shape was not forbidden by the old
transport validator and must not silently become a new transport rejection.
Control-flow-unmodeled results remain explicit. There is no successful libc
result, canonical errno result, return-to-entry link, completed call or
successful effect. A return without an observed entry remains an unpaired raw
return; an entry without an observed return remains an entry observation.

Use a fixed maximum of 4,096 retained BSD phases, checked prospectively before
append; there is no caller override. The existing native name capacities, fixed
raw word counts and pinned table bound each observation. Refusal at this new
projection bound returns no prefix. It does not change the old validator's
million-event/128 MiB limits. `RawFacts` retains all Mach and lifecycle kind
counts, including events outside the selected BSD projection; an empty BSD list
does not imply no filesystem effects or complete coverage. Known entries keep
all unresolved source requirements and unknown names remain visible in the
observations and coverage counts.

Every result has `full_trace_acceptance: false`. Full-acceptance requests always
refuse before input consumption. There is no new CLI, full acceptance backend,
native capture replay, source/proof registration or calibration-packet adoption
in this step. Copied paths, authoritative FD/backing objects, process/thread
generations, exec boundaries, effect ordering, spawn actions, Mach effects and
complete extraction policy remain unresolved. No observed scalar is converted
into `synthetic-unit` or another invented normalized origin.

## Controls and later native evidence

Extend the existing `test_owned_trace_check.py` suite already invoked by CI;
do not add another CI test-script invocation. Use independently serialized
complete transport fixtures to cover known selectors with distinct boundary
words, unknown BSD names, failed-write entry facts, unsupported raw returns,
unpaired and nonreturning phases, all metadata/raw-word provenance, immutability
and detachment. A failed return must not erase its separate entry observation
or imply that entry and return belong to one call.

Compare the old API's complete `RawFacts` against the new result's facts across
valid minimal, BSD, Mach, lifecycle, shadow/cleanup and hostile-shape baselines.
For transport mutations, both APIs must refuse with the same transport reason
when within the projection limit. Preserve independent expected facts/hashes;
the differential comparison alone is not an independent correctness oracle.
Check that corruption in a nonselected event, a late malformed line, missing
terminal/END, a trailing event or source exception exposes no report or prefix.
Exercise exact/over projection bounds with valid complete transports, contract
byte type/size/digest refusal before stream consumption, no implicit asset reads
on import or either API, and unchanged streaming memory on `validate_raw`.

These portable source controls do not prove native provider behavior. Later,
apply this same adapter to a freshly admitted repaired collector capture and
retain its raw hashes and independently reviewed scalar observations. That work
requires its own kit/proof/session checks; it does not reuse or open the retained
failed native attempt. This change does not alter the C producer, tracing
selectors, native protocols, registries, VM/SIP settings or R02 acceptance rules.
