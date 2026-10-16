# Target-aware Darwin capability termination

Status: accepted for a new bounded capability capture; actual v6 calibration is
pending. Full Darwin/R02 acceptance remains unavailable.

Actual v5 `spawn-open` capture `glue-mvp-guest-native-v5-DaKZWirY` observed child
1564 creation, then `proc:::exit` in current parent context 1562. The parent
continued, printed its expected failed-spawn/read markers and exited zero. The
v2 producer incorrectly treated current PID 1562 as terminal and cleared its
watch entry, losing the parent's remaining syscalls. The observed child stayed
nonterminal and the capture correctly failed its deadline gate. Preserve this
failed evidence unchanged.

Pinned Apple [spawn cleanup](https://github.com/apple-oss-distributions/xnu/blob/f6217f891ac0bb64f3d375211650a4c1ff8ca1ea/bsd/kern/kern_exec.c#L4707-L4721)
calls `exit1` on the failed child from its current constructing thread.
The [exit probe](https://github.com/apple-oss-distributions/xnu/blob/f6217f891ac0bb64f3d375211650a4c1ff8ca1ea/bsd/kern/kern_exit.c#L1411-L1418)
supplies only a lifecycle code, whereas [exited](https://github.com/apple-oss-distributions/xnu/blob/f6217f891ac0bb64f3d375211650a4c1ff8ca1ea/bsd/kern/kern_exit.c#L2417-L2439)
supplies the target process and raw exit value. The [SDT declaration](https://github.com/apple-oss-distributions/xnu/blob/f6217f891ac0bb64f3d375211650a4c1ff8ca1ea/bsd/dev/dtrace/sdt_subr.c#L152-L158)
translates exited `args[0]` to `psinfo_t *`. These sources explain the observed
current-context mismatch; actual new guest records must validate target framing.

Use receipt revision 3 and `darwin-capability-raw-v3`. Keep kind 6 as a raw
current-context `proc:::exit` observation, with five scalar descriptors and no
watch or terminal mutation. Require a new `proc:::exited` clause selected by
`watched[args[0]->pr_pid]`. Kind 18 retains five scalar header fields with the
translated target PID in `detail`, then raw `arg1`, then exactly one trailing
zero-width assignment clearing that target's watch entry. Its seven records
have total byte size 64: scalars at 16–56, assignment at index 6/offset 64.
The raw exit value is not labeled as application status.

Only kind 18 marks its target terminal. Validate target `detail` in 1..INT_MAX
before any `pid_t` conversion; apply the same bound to kind-4 child creation.
Parent errno, missing events, thread exit and current probe context cannot
replace target-specific termination evidence. Missing required exited probe,
malformed target/layout, loss, missing observed terminal or deadline still
fails. The independent reader must reproduce this target ledger and the exact
new generated program. No zero-descriptor fallback or old-evidence upgrade is
permitted. PID generations and complete-tree/mutation coverage remain open.

Controls must prove that kind-6 parent context leaves parent and child live,
kind-18 child target terminates only the child even when current PID is the
parent, and the parent can emit subsequent open/syscall records. Root closure
requires its own target event. Reject zero/overflow targets and malformed new
assignment/layout. Run all nine new owned guest cases, retaining the original
streams, identity hashes and failure gates. Full-acceptance APIs stay rejected.
