# R02: distinguish lifecycle completion from final metadata publication

The first native caller makes the coordinator's parent-completion boundary
concrete. It covers the owned attempt's bootstrap/target/trace channels and
writers, admission descriptors and parent signal restoration. These resources
must be resolved before `ts_parent_close_result`; an unresolved resource reports
failure. Keep the native backend context alive through that report because it
performs owner/clock observations, then snapshot and destroy it once.

The caller's final metadata authoring is a separate finalization phase: its held
output directory, trace sidecar and pending result writer are not resources
released to the target or owned by the tracing backend. Their successful closure
remains mandatory before exclusive result promotion. A sidecar, pending writer
or held-directory close failure forbids promotion, even after the coordinator's
parent-completion report succeeded. No fallible operation follows promotion.

Clarify the internal header/README accordingly. `ts_finalization_safe` is one
lifecycle prerequisite and never grants permission to publish a receipt. No C
state-machine predicate, operation/layout, once-only closure or error-precedence
rule changes. The native parent must enforce both this prerequisite and its
metadata closure/promotion gates; neither models nor source review replace a
native tracing result or full R02/M2 acceptance.
