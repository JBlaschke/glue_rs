# Pair actual Darwin raw calls without inventing results

Status: bounded diagnostic adapter; full Darwin/R02 acceptance remains false.

The strict source-matched reader validated all nine immutable v8 captures. The
seven tree captures contain no orphan return, overlapping call on one thread,
or provider/module/function mismatch. They contain 1,083 returned BSD calls and
110 returned Mach traps. Twelve `exit` entries and one `bsdthread_terminate`
entry have no return; each is followed by an observed exit of that same thread.
Initial `execve` returns on the old thread before its exit; exec-success starts
on a newly declared thread. Failed-spawn context `proc:::exit` occurs while the
parent's `posix_spawn` is pending and does not abandon that call.

Add `call-pairing/pair_calls.py`. Its capture/toolkit API invokes the strict
raw-v4 reader itself and requires a clean completed tree/tree-mach capture on
the calibrated host. It never accepts caller-asserted validation or normalized
units as native evidence. Preserve the reader's source/binary/receipt identity,
every raw frame, all eight entry words, all five BSD or one Mach return words,
and exact descriptor family. Copied named-open path records stay opaque.

Use a closed roster of names observed in the v8 calibration; unknown names
reject. This roster limits opaque pairing, not permitted effects or supported
argument decoders. Require BEGIN/END framing and nondecreasing temporal delivery,
one pending call per observed thread across both provider families, and matching
process, thread, exec epoch and descriptor family on return. Unknown threads,
reuse, recursive entry, mismatched return, missing path clause, pending calls
across exec, or unexplained termination reject. Track observed PID/TID lifetimes
and exec epochs conservatively; these are not attested kernel generations.

Only these source-grounded nonreturn routes can retire a pending entry:

- Apple XNU `f6217f891ac0bb64f3d375211650a4c1ff8ca1ea`
  [exit](https://github.com/apple-oss-distributions/xnu/blob/f6217f891ac0bb64f3d375211650a4c1ff8ca1ea/bsd/kern/kern_exit.c#L1335-L1351)
  is explicitly noreturn. Require its same-thread context exit, subsequent
  `lwp-exit`, and final nonshadow target-process exit.
- Apple libpthread `c032e0b076700a0a47db75528a282b8d3a06531a`
  [_bsdthread_terminate](https://github.com/apple-oss-distributions/libpthread/blob/c032e0b076700a0a47db75528a282b8d3a06531a/kern/kern_support.c#L463-L527)
  terminates the current thread and reaches `thread_exception_return` followed
  by `__builtin_unreachable`. Require same-thread `lwp-exit` and separately
  completed target-process lifecycle. Keep the entry and lifecycle frames as
  `terminated-without-return`, with no fabricated return or successful result.

These public sources guide narrow candidate semantics; they are not claimed to
be exact sources for the guest kernel. Tests must exercise rebuilt-hash negative
captures through the public strict-reader API, plus actual seven-capture replay.
No FD/object, pathname, mutation, shared-map, spawn-action, Mach-message or
effect-order acceptance follows from pairing. Full acceptance APIs always fail.

The context detail 1 required for a pending `exit` is only the observed raw
`CLD_EXITED` tag, not application status or proof of normal completion. BSD
primary duplication and kernel-error/builtin-errno agreement likewise constrain
the observed raw shape; control-flow encodings and unobserved shapes reject
instead of being normalized into general XNU results. The name roster cannot
be reused as an effects allowlist.
