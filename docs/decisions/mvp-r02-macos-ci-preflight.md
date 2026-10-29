# R02: inventory a standard macOS 26 CI host

The physical Mac and current test VM retain SIP. Native compact acceptance still
needs a measured macOS tracing environment. Add an independent read-only
preflight on the standard `macos-26` arm64 GitHub runner, using the existing
source/CI publication authorization. This is not a paid runner or a new VM.

The fixed command list collects OS/build/architecture/kernel, SDK/compiler
metadata, `csrutil status`, and a syscall entry-provider **listing** with
`sudo -n dtrace -l`. It enables no probes, runs no traced target, sets no
destructive option, sends no process-control signal and changes no security
setting. It reads no environment dump, user files or process inventory.
Each command has a time and output bound; original stdout/stderr and completion
status are retained in a new private runner-temp folder. CI retains that folder
as a normal 14-day artifact, not a release asset.

Successful metadata collection is distinct from eligibility. SIP/custom-policy
and provider-list results remain observations: even a successful listing cannot
prove probe enablement, exec-stop timing, process-tree completeness or extraction
correctness. All native/calibration/full-acceptance flags remain false. A failed
or restricted command is retained rather than converted into a native pass.

The feature uses a branch push trigger plus manual dispatch, so the preflight can
run before merging and without duplicating it on pull-request events. The
portable baseline continues separately. Follow-up work must review the actual
host receipt before selecting a native collector profile.
