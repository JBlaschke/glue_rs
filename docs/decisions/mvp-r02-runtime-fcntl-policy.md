# Fixed raw runtime fcntl interval profile v2

Preserve the original v1 factory, 15-name behavior and result
shape. Add one fixed v2 original-byte factory using four pinned scalar fcntl
commands, one recipe pass and already-associated private semantic decoders.

GETFD is an interval-local bit observation; it does not rewrite the table. SETFD
updates only the selected descriptor bit after an isolated closed window. DUPFD
commands share the allocator conflict domain and never infer backing from numbers.
Canonical failures retain explicit uncertainty gaps; failed SETFD loses only bit
certainty under otherwise complete conditional mutation coverage. Unknown/control
commands keep the sticky entry-onward horizon. Every exec still retires all output
certainty; no native/state/output/exemption/full acceptance is introduced.

Source rules and limits are documented in the existing scalar fcntl helper
under fixtures/mvp/macos-trace/bsd-fcntl-semantics/.
Targeted physical-byte controls must cover successes/failures/domain errors,
concurrency, conservation, no stream replay and unchanged v1 behavior.

Successful lookups contradicting known absence and allocator returns into known
occupied slots retain explicit gaps, retire incompatible certainty and skip
replacement propagation. This guard belongs to the separate v2 profile.
