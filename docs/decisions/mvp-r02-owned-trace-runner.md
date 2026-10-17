# R02: adopt tracing in a separately compiled owned diagnostic

Connect the reviewed trace-session coordinator, observed bootstrap status codec
and fixed native backend to the existing owned bootstrap child. Preserve the
ordinary nontracing build and its CLI/receipt. A separately named diagnostic is
selected only by the source-defined `GLUE_OWNED_TRACING` build recipe; there is
no runtime tracing, target, argv, backend or profile override. A tracing build
must fail if a required provider is unavailable, without fallback.

Create/start the backend only in the parent, after fork and complete independent
READY comparison and before any GO permission/write. Bind actual controller and
owned child PIDs, request/catalog digests and the original attempt deadline.
Consume validated provider readiness and actual BEGIN before once-only GO.
Observed status/EOF and GO operations pump during bounded waits; child wait and
cleanup also pump. Setup, progress, EINTR and partial I/O never renew deadlines.
Retain full failed GO prefixes and never replay a failed record.

Report actual reap/ECHILD to the coordinator before any later clock/pump check;
neither observation permits a later kill. Bind one request-limited cleanup
deadline at cleanup entry and share it across child cleanup and backend
stop/drain/close. Preserve first parent/cleanup/native errors separately.
Attempt owned resource closure once even after a deadline fault, recording
failure and ambiguity without promoting success. Restore parent channels,
writers, admission FDs and signals before parent-completion reporting.

Before any result promotion, finish the single queued terminal/END drain, checked
backend/writer closure, raw diagnostic snapshot, parent resource restoration and
all fallible receipt work. Positive success additionally requires coordinator
eligibility and the existing strict bootstrap/probe comparisons. Failure may
retain a diagnostic only when resource finalization is resolved. Tracing gets a
distinct receipt schema and fixed sidecar; never relabel kit03 or feed it to the
historical nontracing checker. Native messages retain separate library codes,
actual POSIX errno and adapter callback-status mappings.

This step changes no deployment proof, source registry, kit, signing policy or
VM state. A tracing kit needs an explicitly reviewed libdtrace dependency/recipe,
new tracing-profile admission, fresh post-SIP-reboot mount observations and a
separate offline checker before guest calibration. Source-isolated controls and
SDK builds do not establish provider availability, kernel exec, extraction
behavior, full process-tree coverage or R02/M2 acceptance. No new guest operation
is authorized by this decision.
