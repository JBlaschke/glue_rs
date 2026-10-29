# Select the admitted working-directory handle

`tcwd_select_in_owned_child` selects an already opened and admitted directory
through one `fchdir`, after credential drop and before numeric FD closure. It
borrows the descriptor without duplicating, remapping or closing it. Two initial
metadata/flag samples, owned-child and blocked-signal guards, effective `stat(".")`
readback and the caller's original cooperative deadline checks surround selection.
The object bootstrap profile uses admission component 6; the default legacy
profile keeps its existing behavior. The fixed object status/GO wire is unchanged.

A failure never returns a ready result. Its error retains whether selection was
attempted, including syscall refusal and late/readback failure after actual CWD
mutation. The child exits without retry, rollback, READY, GO or target execution.
The caller must preserve the controlled single-thread/no-thread-CWD-override and
stable namespace/mount/FD assumptions. Samples establish neither atomicity nor
OFD/vnode generations. Deadline checks do not preempt a blocked kernel call.

Run `python3 fixtures/mvp/macos-trace/target-cwd/test_target_cwd.py -v`. Its twenty
controls distinguish twelve injected models, six actual unprivileged native
controls and two actual `fchdir` controls with explicitly injected later faults.
Native checks include renamed/replaced paths selecting the original held object,
live search-permission denial, borrowed-FD preservation, actual descriptor closure
with persistent CWD, and unchanged parent CWD after child reap. They do not prove
the privileged production credential transition. Real-child source controls bind
selection after successful credential drop and reject partial or late failures.
No provider, VM, sudo or SIP change is involved. Full Mac oracle/M2 remains open.
