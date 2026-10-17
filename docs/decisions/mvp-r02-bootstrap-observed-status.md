# R02: preserve status decoding across observed pipe waits

Add an explicit `nr_status_next_observed` status-stream entry point with a separate
trusted `bio_observer`. The legacy API, status-stream layout, wire decoder and
operation table remain unchanged. Both entry points share one decoder core; the
observed path selects the observed BIO record and strict EOF operations, including
the zero-record EOF fallback. Every call keeps the caller's original absolute
deadline, with no renewal on observer progress, partial reads or fallback.

A missing observer or callback must fail closed through observed BIO validation.
Append every confirmed I/O prefix before handling failure, including a full record
followed by observer failure. Such bytes remain opaque: never push a failed record
into the wire decoder, attempt EOF after an observer fault, or retry a poisoned
stream. Existing confirmed trailing, truncated, syscall and deadline errors retain
their BIO classification and precedence. EOF success still requires the strict
on-time operation before the wire stream is sealed.

Injected controls cover pumps and faults around READY, ATTEMPT, reported ERROR,
strict EOF and zero-record fallback, retained partial/full failed records, trailing
precedence and original deadlines. This adds only a cooperative status-codec seam;
it does not adopt tracing in the native runner, supply a tracing backend, change
parent/files behavior, register a source/kit, access a guest or prove execution.
