# R02: pair closed owned provider-call intervals

Status: accepted for bounded source implementation; native calibration, state
integration and full Darwin/R02 acceptance remain open.

Add `pair_raw_owned(program, probes, errors, event_lines, *, owner_pid,
target_pid, contract_bytes)` in `owned_trace_check.py`. It invokes the same
private strict transport walk through exhaustion and uses the same exact pinned
contract bytes as `observe_raw_bsd`. It accepts no caller-asserted validation,
`RawFacts`, observation bundle, normalized units or public callback. Existing
`validate_raw` and `observe_raw_bsd` signatures, output, refusal and memory paths
remain unchanged. Code imports remain separate from asset access; the new API
performs no file I/O or helper-code loading after normal module import.

## Closed intervals only

Use one pending slot per capture-observed numeric TID across BSD and Mach
families. An entry reserves it. Its return must match the exact actor PID/TID,
provider, module and function, with BSD entry/return or Mach entry/return kinds
matching. EPIDs describe clauses, not calls. A second entry on that TID, any
orphan return including an initial midcall return, or a family/actor mismatch
refuses the entire pairing operation. Calls on distinct established TIDs may
interleave. No pending entry may survive thread exit, nonshadow target terminal
or END; there are no special nonreturning-call exceptions.

Retain each phase's exact ordinal, CPU, probe ID, EPID, descriptor names, all five
header scalars and all eight entry, five BSD-return or one Mach-return words.
Known BSD entries retain existing frozen source-contract facts and unresolved
requirements. Unknown names can form opaque matching intervals but remain
unsupported. Preserve unsupported BSD return shapes with their raw words and
reason, as the observation API does; do not introduce libc normalization or
success/effect claims. Mach return words remain opaque. A failed return cannot
erase its paired entry request or its source-declared write requirements.

## Capture-local thread and lifecycle subset

The fixed target PID is the only process scope. Descendant/create/spawn routes
remain rejected by the existing raw validator. Apply these additional rules:

- BEGIN establishes no target thread. The first target observation must be a BSD
  or Mach call entry; its positive numeric TID seeds one active capture-observed
  thread. This is neither a birth observation nor a kernel generation, and no
  initial `close` or launch-gate call is presumed.
- `proc:start` refuses as an unsupported launch boundary. Other target lifecycle
  activity before that first entry also refuses. There is no implicit initial
  `lwp-start` exception.
- `lwp-create` requires an already active creator TID. Its raw detail must be a
  positive uint64 TID not previously observed, declared or retired, and distinct
  from the creator. Reserve that TID; no calls may use it yet. The creator may
  have a pending call; no causal connection to that call is inferred.
- `lwp-start` requires the exact reserved numeric TID, then makes it active.
  Unknown, repeated, active or retired starts refuse. Calls from any additional
  TID before this declaration/start sequence refuse.
- `lwp-exit` requires an active known numeric TID with no pending call, then
  permanently retires it. Unknown, reserved-only or duplicate exits refuse.
  Numeric reuse is forbidden, including after retirement.
- `proc:exit` requires an active known TID and no pending call on any thread.
  Mark this projection closing without retiring any association. Only known
  `lwp-exit` cleanup, nonshadow target terminal and END may follow; further calls,
  create/start/context-exit records or any other continuation refuse. Its detail
  remains raw context, never application status, process wait, target termination
  or a successful effect.
- Every exec-success, exec-failure and shadow-exited event refuses, irrespective
  of pending state. No Python epoch increment or shadow cleanup association
  substitutes for the missing native lifetime contract.
- A nonshadow target terminal requires no pending calls. Its target is the raw
  detail, not the current actor PID/TID. It does not retire thread associations.
  Already known active threads may subsequently have the `lwp-exit` cleanup
  permitted by the transport. END requires every observed thread retired and
  every declaration started; no unaccounted association is discarded.

These are conservative source-level associations requiring native calibration.
They do not attest thread births, IDs, kernel generations, call semantics or
complete provider coverage. This new API deliberately refuses current bootstrap
captures containing initial orphan returns, exec transitions, shadow cleanup or
unreturned `exit`/thread-termination entries. The existing validator and scalar
observer remain available for those raw transports; pairing is not weakened to
make them pass.

## Exact timestamp rule

Check globally nondecreasing raw timestamps across every validated record,
including BEGIN, END and otherwise unselected lifecycle context. No conversion
to a wall or deadline clock is performed. A repeated timestamp is permitted only
when every record at that timestamp is a BSD/Mach call phase. Any equal-timestamp
bucket containing lifecycle context, BEGIN or END refuses, even across different
TIDs. This conservatively rejects ambiguous start/exit/boundary ordering while
allowing capture-ordered call phases. Such pairing order is not a kernel effect
order or a successful-operation causal proof.

## Bounded immutable result

Use prospective fixed limits of 4,096 BSD/Mach phases, 2,048 completed pairs,
256 distinct observed or reserved TIDs, and 1,024 retained noncall records.
The noncall limit includes BEGIN, END and target terminal. There is no caller
override. Count unsupported routes too. A refusal exposes no prefix or completed
transport claim. Every returned result requires the complete strict raw walk,
input exhaustion, all pairing/lifecycle closure checks and at least one pair.

Return unchanged `RawFacts`, pinned contract identity, frozen pairs ordered by
entry ordinal and frozen noncall context in consumer order. Retain phase objects
once within their pair; do not accumulate or rewrite original JSON lines. A
pair's ordinal-based correlation ID is capture-local, never a kernel call ID.
All nested values are immutable and detached. Include explicit phase/pair/thread/
lifecycle counts and `unpaired_phase_count: 0`. Every result has
`full_trace_acceptance: false` and `state_feed_eligible: false`; full acceptance
always refuses before input consumption. There is no new CLI or normalized
state feed, and no invented FD/object/backing identities or normalized origin.

## Controls and scope

Extend the existing `test_owned_trace_check.py` invocation. Independently
serialize complete transports with distinct source words and timestamps; check
BSD/Mach interleaving, one shared pending slot, exact provenance, unsupported
returns, failed write entries, mismatches/orphans/overlaps, every lifecycle and
timestamp-tie rule, exact/over bounds, immutable detachment and late/source
failure without a prefix. Preserve existing API outputs/refusals and the old
128 MiB streaming-memory control. The differential checks also retain independent
expected raw hashes/counts rather than comparing only shared code paths.

Edit only this decision and the existing checker, tests and README. Do not change
syscall contracts, C producers, wire formats, historical pairing, normalized
state engines, registries, kits, packets or the CI script count. No native run,
VM/SIP action, raw-capture access, proof admission or publication occurs. Later
actual calibration must establish the missing associations; if the producer
cannot provide them, propose a versioned correlation/lifecycle extension instead
of relaxing these checks. Path/object/FD state, descendants, Mach effects and
the full extraction corpus remain separate acceptance work.
