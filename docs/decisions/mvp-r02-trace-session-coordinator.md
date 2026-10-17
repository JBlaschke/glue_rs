# R02: model the owned-probe tracing session before native adoption

Add an internal, injected-backend C coordinator under the Darwin diagnostic
fixtures. It has no native backend, command-line interface, process launch,
signal, FD, filesystem or libdtrace operation. No existing runner, builder,
source registry, packet or capture reader adopts it in this step. Its outputs
are state-machine observations, never native provider, exec or extraction proof.

The intended entry seam is `runner_parent.c` after the complete READY comparison
and before the first GO write. The trusted caller supplies the actual still-owned
child/controller IDs, owned-context-probe selector, request/catalog digests,
original absolute monotonic attempt deadline and exact reviewed request cleanup
budget (1..2000ms). The coordinator snapshots these once. There is no runtime
target, argv, profile or backend selector. Trusted callbacks report the current
controller and monotonic time and implement one start, repeated bounded pump,
one stop, one drain and one close. A failed start may still own resources; its
close is attempted once. No cleanup operation retries an earlier operation.

A future adapter must validate raw descriptors, event layout, provider/enabling
identity and bounded output before delivering a consumed event. The coordinator
additionally checks its immutable session binding and legal event order. Exactly
one provider-ready and one BEGIN must be consumed before once-only GO permission.
Any malformed, late, duplicate or missing readiness, drop, backend/output error
or deadline fault poisons success. Permission marks possible release before the
caller attempts a write; partial, failed or late GO can never be replayed.

The existing BIO helpers poll one FD and may wait for the whole remaining
deadline. Later integration must pump during those waits and child cleanup,
without replacing deadlines on progress or EINTR. Here explicit pump calls model
bootstrap, owned-child wait and cleanup seams. A cleanup deadline is separately
bound once, within the supplied request budget; the original attempt deadline
never changes. Callbacks are cooperative, not a hard kernel-stall watchdog.

Wait/reap or ECHILD immediately ends kill eligibility even if a later clock
check fails. Stopping and draining occur only after the child is no longer
live; queued terminal events may arrive during the single drain after reap.
Clean success requires terminal+END, completed drain, backend close, gate close,
strict-parent bootstrap completion, normal child exit and caller-confirmed
channel/resource/signal restoration. Resource finalization safety is reported
separately: a failed attempt may have safely closed resources and retain its
original error. The first primary error survives later cleanup errors, which
also have their own first-error field. Ambiguous closure or lost child ownership
never becomes safe finalization evidence.

Do not reuse `capture-native`'s wrapper: it launches a different root target,
releases before consuming BEGIN, requires named open calibration absent from
the fixed context probe, installs signal handlers, and its watchdog inherits a
blocked mask without clearing it. Native backend design, actual raw-event
validation, cooperative BIO/runner integration, independent result/receipt
validation, source/kit registration and SIP-approved native calibration remain
separate reviewed steps. No full R02/M2 acceptance follows from these models.
