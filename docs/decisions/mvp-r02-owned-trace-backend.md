# R02: fixed native backend for the owned context probe

Implement one internal libdtrace adapter for the reviewed trace-session
coordinator. This step adopts neither runner nor kit, registry, VM packet or
historical capability reader. It supplies no CLI, runtime profile/target
selector, fork, exec, gate, signal policy, kill or privilege transition.

The caller must first independently compare complete READY and still own its
actual unreaped unprivileged bootstrap child. Creation snapshots that explicit
binding, the original absolute attempt deadline and a borrowed held private
output directory. Allocate backend resources only after that confirmation;
open/enable DTrace only through the coordinator's once-only start callback.
The only profile is the exact owned context probe: BSD syscall and Mach trap entry/return,
exec success/failure, context exit/thread cleanup, unexpected create/spawn and
the calibrated exited-target address/refcount shadow discriminator. It has no
named-open calibration requirement or general descendant-coverage claim.
Mach fields retain the historical tree-mach scalar layouts as raw observations;
they do not decode port identities/effects or authorize filesystem behavior.
Every required BSD/Mach/proc provider clause must match; no smaller fallback
profile is selected when a provider is unavailable.

Keep fixed exclusive program.d, probes.tsv, events.jsonl and errors.jsonl outputs.
Before delivering a coordinator event, validate the actual probe inventory,
provider and exact descriptor layout, bounded raw output and session-local
EPID-to-clause plus inverse clause binding. Retain original native raw bytes.
Provider readiness is a backend observation delivered only immediately before
a fully validated, serialized actual BEGIN is consumed; start or nonzero probe
counts alone never releases GO. Only the bound child's nonshadow exited-target
record is terminal. Retain permitted shadow/thread cleanup after terminal as raw
context rather than inventing application activity.

Pump cooperatively with unchanged absolute deadlines. Stop, final drain to actual
DTRACE_WORKSTATUS_DONE, DTrace close and each writer close are once-only, including
failed-start cleanup. Keep actual libdtrace error codes/messages distinct from
POSIX errno, and preserve the first fault plus close failures. No raw event count
substitutes for BEGIN, terminal, END, complete drain or checked writer closure.
The coordinator and future parent remain responsible for owned-child reap,
strict bootstrap sealing, resource/signal restoration and final promotion gates.
Callbacks cannot interrupt a blocked kernel/libdtrace call.

Validate adapter boundaries through a separately linked fake libdtrace SDK and
source-isolated controls, plus actual host SDK compile/link without executing
the adapter/provider. No sudo, SIP change, guest operation, capture/evidence
access or native calibration is authorized here. SIP-enabled builds do not prove
provider availability; a later tracing-policy reboot needs fresh literal mount
observations and separately reviewed catalog/kit/receipt adoption. Preserve all
historical capture-native, raw-v4 readers and kit03 bytes.
