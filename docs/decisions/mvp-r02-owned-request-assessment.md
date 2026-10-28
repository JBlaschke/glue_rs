# R02: assess requests from complete owned raw transport

Status: accepted for diagnostic integration. Full Darwin acceptance remains open.

The owned reader now exposes bounded BSD observations and a separate strict
closed-call subset. Existing open-intent classification and source contracts
remain separate. Add one assessment API that combines the complete owned
transport, all source-contract families and request flags without manufacturing
filesystem identities or synthetic normalized origins.

## Original inputs and complete validation

Add `owned-trace-assessment/assessment.py` with
`assess_owned_raw(program, probes, errors, event_lines, *, owner_pid, target_pid,
contract_bytes)`. It calls `observe_raw_bsd` itself. It accepts no caller-supplied
RawFacts, prevalidated observations, normalized state or approval assertions.
Use the exact upstream contract-byte identity and existing bounds. No report is
available before complete transport exhaustion; later corruption, unsupported
transport or iterator failure returns no prefix. Keep all upstream files and
native kit/registry/packet identities unchanged.

Do not require the stricter closed pairer: it intentionally rejects initial
orphan returns, exec/shadow transitions and nonreturning calls. Those conditions
must not erase an observed entry request. Return phases remain independent raw
observations, including unsupported return shapes; no successful call, canonical
errno, returned descriptor or causal state transition is inferred.

## Frozen requests and explicit coverage

Return an immutable result retaining the complete OwnedBsdObservations once.
Each entry assessment links the original phase/ordinal and preserves source
name, family, selected unsigned raw fields and all unresolved source requirements.
Dispatch through an explicit closed roster of the 12 source families covering
all 161 pinned declarations. Unknown names or unhandled routes remain visibly
unsupported. A source family is not an effects allowlist: in particular,
fd-mutation includes flushing and sendfile requests, and opaque control, async,
rights, mappings, spawn and descriptor/cwd state need further interpretation.

For open-request declarations, select flags only through the existing source
contract. Classify only raw flag words already in the unsigned32 range using the
unchanged flag classifier. Preserve larger words as unsupported width; never
silently mask, sign-extend, truncate or reinterpret them. Guarded and protected
variants retain their extra requirements even when common flag bits are shown.
Unsupported flags retain the classifier's reasons and bits. Flag classification
does not authorize a target, read, execution or variant.

Expose all BSD entry/return and raw Mach/lifecycle kind counts, unknown names,
unsupported returns and fixed missing-capability reasons. Zero BSD entries,
zero observed writes or absent selected activity cannot yield a clean result.
Mach bodies, port/object identities and lifecycle generations stay unresolved.
No observed numeric fd is treated as stdout/stderr authorization.

The product policy allows explicitly declared application outputs. Without
resolved object/path bindings, an observed mutation or write-capability request
is not a definite extraction violation, and absence of such rows is not proof of
no extraction. Every assessment has `status: incomplete`,
`full_trace_acceptance: false` and `state_feed_eligible: false`.

## Dependencies and verification

Load fixed helper code and the pinned classifier/ABI once during normal module
import, with reviewed source identities. No code/asset filesystem I/O, subprocess,
network or state-engine call occurs during assessment beyond consumption of the
caller-supplied stream. Keep retained nested collections frozen and bounded by
the upstream 4,096-phase limit; returned mutable serializations must not alias
internal state. Trusted source loading assumes a stable source tree.

Controls use complete serialized raw fixtures and independently expected field
vectors for all 161 contracts and all nine open flag positions. Cover failed and
unpaired entries, high-bit flag words, unknown/unsupported calls and returns,
zero-BSD/Mach/lifecycle coverage, immutability, runtime no-I/O and late failures.
Add the focused suite to portable CI. A subsequent feature provides bounded
physical input handling and operator output; this pure API does not register a
native acceptance backend or change guest SIP.
