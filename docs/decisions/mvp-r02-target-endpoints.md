# Normalize owned endpoint sources before child stdio mapping

Status: bounded helper implementation; no collector/launcher integration,
privileged guest calibration or full trace acceptance.

The caller supplies five already-owned source descriptor numbers, in order:
read-only stdin, write-only stdout capture, write-only stderr capture, read-only
launch-gate reader and write-only status writer. Reject negative or duplicate
numbers; merged stdout/stderr is deliberately unsupported. Different descriptor
numbers can still alias one object, so object provenance and absence of aliasing,
concurrent mutation or inherited callback/handler rebinding remain caller
responsibilities, not facts proved by metadata.

Before any duplication, validate every source's exact access mode and shape.
Stdio supports regular files and FIFOs; stdin additionally permits a character
device only under the caller's policy that it is the deliberately opened
read-only `/dev/null`. No major/minor constant or child pathname lookup can
authenticate that assertion. Gate/status support FIFOs only. Directories,
sockets, other character outputs and read-write sources are unsupported. Stdio
must be blocking; both control sources must be nonblocking, matching the separate
bounded bootstrap-IO contract. The caller sets and checks O_NONBLOCK on all four
private control-pipe ends before normalization/fork, including controller ends
outside this helper. The helper never changes OFD status flags. Asynchronous or
path/event-only modes are unsupported. Other status bits remain caller
opening-policy data, not an effects authorization.

In the owned controller, normalize each source using checked F_DUPFD_CLOEXEC
with minimum 3. Never close or change originals, remap controller stdio, raise a
limit or silently use an alternate duplication API. Each returned copy must be
new, distinct, at least 3 and not any original source number. Verify its role,
shape and CLOEXEC. The output contains the exact newly owned prefix even after
ordinary allocation/verification failure, with ready=false; the caller must close
that prefix once or exit. An impossible successful return with uncertain
ownership requires controller exit, and never instructs closing an original.
A partial plan cannot be used for child mapping.

In a single-threaded owned forked child with setup signals already blocked,
validate the complete plan and original-controller PID relationship, recheck all
copy roles/shapes/CLOEXEC before any mapping, then dup2 only the three stdio
copies onto 0/1/2. Because all sources are at least 3, no same-slot no-op or mapping
cycle can preserve CLOEXEC or destroy another source. Verify stdio CLOEXEC is
clear, explicitly set and verify CLOEXEC on the distinct normalized gate/status
copies, then verify the mapped endpoint roles again. Any uncertain child result
prevents launch; after a mapping attempt the child must exit on failure without
rollback. The future descriptor-closure helper removes originals and spare
copies; this helper never closes them.

Primary grounding: Apple's pinned XNU commit
f6217f891ac0bb64f3d375211650a4c1ff8ca1ea,
[kern_descrip.c:2475–2485](https://github.com/apple-oss-distributions/xnu/blob/f6217f891ac0bb64f3d375211650a4c1ff8ca1ea/bsd/kern/kern_descrip.c#L2475-L2485)
checks the destination limit and preserves flags on dup2(old==new);
[2825–2848](https://github.com/apple-oss-distributions/xnu/blob/f6217f891ac0bb64f3d375211650a4c1ff8ca1ea/bsd/kern/kern_descrip.c#L2825-L2848)
selects fresh F_DUPFD_CLOEXEC copies and exposes descriptor flags. Apple's
[dup2 manual](https://developer.apple.com/library/archive/documentation/System/Conceptual/ManPages_iPhoneOS/man2/dup2.2.html)
and [fcntl manual](https://developer.apple.com/library/archive/documentation/System/Conceptual/ManPages_iPhoneOS/man2/fcntl.2.html)
provide historical API context; the current SDK/native controls verify this
helper's compiled behavior, not the exact guest kernel or a general endpoint
security boundary. The archived dup2 return-value prose is not used as a current
return-value contract; the pinned implementation and native controls require the
requested destination descriptor. Apple [sigaction](https://developer.apple.com/library/archive/documentation/System/Conceptual/ManPages_iPhoneOS/man2/sigaction.2.html)
permits querying dispositions without changing them. The native mask check
queries valid signals and excludes unmaskable KILL/STOP. Darwin rejects any query
error for its SDK-declared 1..NSIG-1 slots; Linux alone skips EINVAL numbers to
accommodate libc-reserved/unsupported signals. It checks libc-supported signals,
not every kernel/internal signal. Readback cannot attest prior handler behavior
or thread quiescence.

All storage is fixed-size; injected operation tables test failure/ownership
boundaries without manipulating host stdio. Real Mac and Linux tests mutate only
owned controller/child subprocesses with external parent deadlines and exact
reaping. No target is executed, and no credentials, cwd, gate protocol, FD closure,
Mach/audit context or trace acceptance is implemented. `/dev/null` must be opened
and authorized before child setup; a root-opened cwd FD is never a shortcut.
