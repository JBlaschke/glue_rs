# Owned-bootstrap signal lifecycle

This dependency changes signal state only in a reviewed single-threaded
controller and its direct owned child. It does not fork, launch, trace, change
credentials or change machine security policy. See the
[decision](../../../../docs/decisions/mvp-r02-bootstrap-signals.md).

`bs_prepare_parent` snapshots the mask and SIGPIPE action, rejects caught handlers
and unsafe SIGCHLD disposition/autoreaping, blocks every catchable signal, checks
pending signals and temporarily ignores SIGPIPE. It snapshots its trusted complete
operation table. If preparation attempted either mutation, the controller must
call `bs_restore_parent` once after endpoint/child cleanup even when preparation
failed. Do not fork after a preparation failure. The state is initialized only
by preparation; callers never edit or alias it with other API arguments.

Only a child with a different PID and the selected original controller as parent
may reset/check/release policy. Reset installs default actions and empty handler
masks, disables the alternate stack and verifies the blocked setup policy.
Release rechecks that state, rejects pending signals, then installs and verifies
an empty mask. Call release only after matching GO, EOF and checked gate close.
Every child failure requires exit, without retry, rollback or target launch.
The parent PID check is a mistake guard under trusted process ownership.

Restore is parent-only and once-only. It attempts SIGPIPE restoration and then
mask restoration even if the first fails, retaining the first stage/errno.
`pipe_restored` and `mask_restored` indicate separately verified outcomes; a
failure cannot be reported as a restored attempt. Native syscall failures save
positive errno immediately; anomalous callbacks have errno zero. C objects and
callbacks must be valid, stable and nonoverlapping; callbacks follow libc
conventions and cannot mutate API objects. They must return. No allocation is
performed by the helper.

The native Darwin adapter covers exactly signals 1 through NSIG-1 except KILL
and STOP, with no ignored query/reset error. Other native platforms return
unsupported before callbacks. Public action flags, mask membership and stack
state are compared semantically; raw padding is never hashed or compared.
`bs_policy_bytes` clears its output on failure and returns the canonical policy
description on success. It supplies no hash or attestation: a READY digest may
describe the final empty-mask policy while the actual setup mask is still blocked.

The caller owns a quiescent process, no custom reaper/atfork or endpoint mutation,
no externally injected setup signals, cleanup/reaping deadlines and external
timeouts. Pending-signal checks cannot exclude a later arrival. Unmasking may
terminate the child before exec; a closed status pipe never proves exec success.

Run focused controls:

```sh
python3 fixtures/mvp/macos-trace/bootstrap-signals/test_bootstrap_signals.py -v
BS_TEST_CFLAGS='-fsanitize=address,undefined -fno-omit-frame-pointer' \
  python3 fixtures/mvp/macos-trace/bootstrap-signals/test_bootstrap_signals.py -v
```

Fifteen groups collect 14 native Mac passes and one Linux-only unsupported skip.
Offline unprivileged Linux passes ten injected/data groups plus the explicit
unsupported-native check, with four Darwin controls skipped. Mac ASan/UBSan
passes the ten injected/data groups, with five skips: sanitizers install caught
handlers and therefore cannot satisfy native controller admission. No production
policy bypass exists. Native controls exercise actual owned fork/reset/release,
inherited ignored signals, pending-signal rejection and unsafe SIGCHLD preflight;
the parent uses an absolute bounded wait and kills only its still-unreaped child.
The enclosing Python process retains its original signal state. Earlier failed
logs, including the zero-size alternate-stack ENOMEM and strict-compiler test
warnings, remain outside Git. Full controller/privileged Darwin/R02/M2 checks
remain open.
