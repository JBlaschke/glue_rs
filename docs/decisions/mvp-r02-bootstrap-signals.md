# Owned-bootstrap signal policy

The standalone Darwin bootstrap needs signal setup before it forks or changes
identity. This dependency implements that process-local policy without launching
a target, changing credentials, tracing or changing system security settings.
It is for a reviewed single-threaded controller with no atfork mutation, custom
reaper, concurrent signal-policy changes or external signal injection. Its native
adapter supports Darwin; other platforms fail before callbacks or mutation.

The controller requires SIGCHLD default disposition and no SA_NOCLDWAIT, and
rejects any caught handler. Inherited default/ignored dispositions for other
catchable signals are permitted. Preparation snapshots the original mask and
SIGPIPE action, blocks all catchable signals and verifies the mask, rejects any
pending signal, then temporarily ignores SIGPIPE with checked readback. Ignoring
SIGPIPE prevents a generated pending signal from later killing the controller
when its original mask is restored after an EPIPE. Pending checks are observations,
not atomic protection against a concurrent external sender; signal quiescence is
an explicit controlled-diagnostic assumption.

Only an actual owned child, selected by the controller PID captured before fork,
may reset dispositions or release its setup mask. It resets every catchable
disposition to default with an empty handler mask and zero public flags,
disables the alternate stack, and verifies all dispositions/stack/setup mask.
After the caller validates complete GO plus EOF and closes the gate, release
checks that policy again, rejects pending signals, installs and verifies an
empty mask. Signals arriving after the check may terminate the child; this
helper supplies no atomic signal-to-exec guarantee.

The controller restores its saved SIGPIPE disposition and original mask only
after its owned endpoints/child are cleaned up. It attempts both restoration
steps once, preserves the first failure and separately reports their verified
outcomes. Every preparation failure requires this cleanup, even after a failed
mutation syscall. A restoration failure invalidates the attempt. Child failures
require child exit without rollback or launch. Neither child reset nor release
can be called as controller rollback. A repeated restore/release is rejected.

A trusted, complete operation table permits injected failure controls. Its
callbacks obey libc conventions and save errno immediately, do not mutate API
objects and must return. All state/output/table objects are valid, stable and
nonoverlapping. The state snapshots the table. The native signal list is exactly
1 through NSIG-1 except SIGKILL/SIGSTOP; no Darwin EINVAL is silently skipped.
Injected models do not prove an operating system's complete signal ABI.

Policy bytes are a canonical data description, not raw sigset_t or sigaction
storage: magic GLUESP01, big-endian version1 u16, count u16, total length u32,
policy bits15 u32 (default actions, disabled altstack, blocked setup, empty final
mask), then ordered u32 signal numbers. The caller may hash these bytes for
READY only after actual child checks pass; the digest never asserts that the
final empty mask was already installed at READY. No cryptographic implementation
or authentication claim is added here.

Controls cover preflight, ownership, signal-policy rejection, mutation failures,
pending signals, exact restoration and separate native unprivileged Darwin
processes. Native child checks use a known direct child, an absolute parent wait
deadline and once-only unreaped-child kill/reap cleanup. External test timeouts
remain necessary for a stalled kernel or nonconforming callback. Linux runs
injected/data controls and explicit unsupported-native checks. Full controller,
privileged Darwin identity transitions, collector integration and R02/M2 remain
separate work. Guest SIP remains enabled.
