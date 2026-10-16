# Darwin capability transport: retain exec shadow identity

Status: implemented diagnostic candidate; new guest compilation and calibration
required. Full Darwin/R02 acceptance remains false.

The immutable v6 guest batch `glue-mvp-guest-native-v6-rYilzb7D` rejected all
seven tree cases. Each initial exec produced an `exited` callback on its old
thread, with current PID zero and target PID equal to the still-live post-exec
root. The PID-only terminal rule cleared the live root's watch. Four retained
stdout identities subsequently changed because unobserved descendants kept
writing. Those captures remain failed; no footer or hash is repaired.

Pinned Apple XNU `f6217f891ac0bb64f3d375211650a4c1ff8ca1ea` supplies a candidate
explanation, not verified exact source for the running guest's
`xnu-12377.161.14~5/RELEASE_ARM64_VMAPPLE` kernel:

- [forkproc](https://github.com/apple-oss-distributions/xnu/blob/f6217f891ac0bb64f3d375211650a4c1ff8ca1ea/bsd/kern/kern_fork.c#L937-L946)
  copies PID, unique ID and PID version into an exec clone and marks it shadow.
- [proc_exec_switch_task](https://github.com/apple-oss-distributions/xnu/blob/f6217f891ac0bb64f3d375211650a4c1ff8ca1ea/bsd/kern/kern_exec.c#L4898-L4906)
  replaces the PID-hash entry and transfers the shadow flag to the old object.
- [P_REF_SHADOW](https://github.com/apple-oss-distributions/xnu/blob/f6217f891ac0bb64f3d375211650a4c1ff8ca1ea/bsd/sys/proc_internal.h#L198-L208)
  is bit `0x20` of the 32-bit `proc.p_refcount`, rather than a local/list flag.
- [exit1](https://github.com/apple-oss-distributions/xnu/blob/f6217f891ac0bb64f3d375211650a4c1ff8ca1ea/bsd/kern/kern_exit.c#L2395-L2460)
  emits `proc:::exited` for shadow objects too. The installed Apple `darwin.d`
  translator defines `psinfo.pr_addr` as the actual `struct proc *` address.

Use receipt revision 4 and `darwin-capability-raw-v4`. Kind 18 keeps five header
words, then raw `arg1`, translated target `pr_addr`, and the target's raw
`p_refcount` read through the kernel CTF type. Its eight DIFEXPR records have
size eight, offsets 16 through 72, total probe bytes 80, and no assignment.
Require target PID in 1..INT_MAX, nonzero object address and refcount in
0..UINT32_MAX. Preserve all original records. Only a target whose captured
refcount has `0x20` clear may retire its PID; shadow records remain raw context.
Do not infer shadow state from current PID, thread ID, elapsed time or absence.

Remove D-side watch clearing entirely. The bounded diagnostic PID table retains
terminal entries; later ordinary activity, duplicate nonshadow termination or
observed PID reuse rejects rather than silently reauthorizing a PID. The sole
context-only postterminal lifecycle exemption is `lwp-exit`, which does not
change watches or the process ledger; final thread cleanup may follow process
exit. This is
not a proven process-generation ledger. It deliberately fails unsupported reuse,
and object address alone does not establish a lifetime or prevent pointer reuse.
The independent reader must reproduce these checks and exact generated source.

Native compilation of the CTF field expression and new guest records must show
old-shadow exits retained without ending live roots, actual root/child terminal
records, failed-spawn parent continuation and unchanged final stream identities.
Synthetic controls cover the same-PID shadow sequence, duplicate/reuse/late
activity and invalid identity/layout boundaries, but cannot calibrate the guest
kernel. Keep all nine owned cases, deadlines, loss gates and failure evidence.
