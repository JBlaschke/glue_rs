# Interpret bounded descriptor operations from complete owned BSD pairs

Status: accepted for source-grounded operation interpretation; native/object admission remains open.

28 October 2026. Build on the paired BSD outcome and entry ABI helpers to add
executable per-operation rules for exactly eleven existing declarations:
close/close_nocancel, dup, dup2, write/write_nocancel, pwrite/pwrite_nocancel,
fsync/fsync_nocancel and ftruncate. Read/pread are absent from the existing
contract; command-specific fcntl, vector and guarded operations remain explicit
unhandled rows rather than acquiring a broad family permission.

The pure decode_owned_fd_semantics API accepts original immutable static bytes,
a bounded event-line iterable and the exact contract asset. It calls
pair_raw_owned exactly once. Only after complete strict transport and pairing
exhaustion does it reuse fixed identity-checked private pure helpers from the
entry ABI and outcome modules. It does not rerun the stream through their public
raw-input APIs. Original BSD/Mach pairs and lifecycle records remain retained.
Every BSD pair gets a row, including unknown and known-unhandled names; invalid
transport or unresolved pairing returns no prefix. Failed paired entry attempts
are never removed. The separate entry ABI API retains unpaired attempts; this
closed-pair API refuses such input rather than pretending a clean result.

Rows retain typed canonical arguments, original pair indices and typed kernel
outcomes. Recognized requests add descriptor/buffer/count/offset/length values
and an attempt category. Successful source consistency yields a conditional
postcondition rule, not an applied state transition or object identity. Failures
keep explicit effect uncertainty and no postcondition. Unknown/noncanonical
arguments, unsupported control flow and inconsistent success results remain
unsupported with reasons.

Executable success rules:
- close/fsync/ftruncate require primary result zero. LP64 dispatcher initialization
  plus unused return storage proves this domain, including ftruncate's POSIX
  shared-memory branch. For these closed int handlers, also require secondary zero:
  they modify only retval[0] or leave storage unused, and both LP64 dispatchers
  initialize both slots. Retain the original typed secondary without rewriting it.
- dup requires a nonnegative returned descriptor distinct from its source and a
  source within the supported nonnegative signed descriptor domain. Its rule
  requires lowest-free allocation at the allocation point and shared fileglob
  binding; neither can be asserted from numbers or return order alone.
- dup2 requires the requested target result. Self-dup preserves descriptor flags;
  a distinct target conditionally replaces its slot with an alias whose close-on-
  exec bit is clear. Original unsigned arguments above INT_MAX remain unsupported
  instead of inventing the implementation-defined conversion to signed int.
- write/pwrite require 0 <= reported bytes <= requested bytes <= INT_MAX.
  Preserve implicit versus explicit-offset requests, and reject a claimed
  pwrite success at offset -1. Other negative offsets are not discarded by a
  blanket nonnegative assumption: this wrapper rejects only -1. Buffers stay
  opaque; zero-byte requests still retain their entry attempt.
- ftruncate success additionally requires nonnegative requested length; its
  object can be a vnode or POSIX shared-memory object, not an assumed regular file.
  Its conditional rule is object-specific: POSIX shared memory can round to page
  size and permits only one allocation per lifetime. Requested length is not an
  observed resulting size; branch, page-size, prior-allocation and lifetime
  witnesses remain required.

The error model must not assert no effects. close releases its slot before
fg_drop can report an error. dup2 can close/reserve the target before finishdup
fails. fp_writev computes progress even with an error, and only selected restart/
interrupt/would-block errors clear after progress; other failures can hide
partial bytes behind the provider's all-ones failure tuple. Flush/truncate
failures also retain uncertainty. No failure makes an attempted mutation safe.

All conditional rules still require object/descriptor generations, source ABI
calibration and successful-effect ordering. No object token, initial table,
current slot state at return, application-output exemption, filesystem verdict
or synthetic normalized state event is produced. Results remain incomplete with
native calibration, effect ordering, state eligibility and full acceptance false.
Guest SIP, native kits, existing raw readers and state engines stay unchanged.

Seven exact source files are retained under the ignored preparation record:
- kern_descrip.c: finishdup516–578, zeroed allocation1107–1113, fdalloc1177–1214,
  dup2394–2428, dup22448–2539, close5404–5439, slot removal1773–1791 and
  fg_drop244–294.
- sys_generic.c: fp_writev578–617, write_internal675–695, wrappers699–750.
- vfs_syscalls.c: length validation8635–8649, truncate8653–8700/ftruncate8740–8810,
  fsync8819–8836/common8878–8912.
- posix_shm.c: pshm_truncate537–542 declares the result pointer unused.
- arm/systemcalls.c130/136 and i386/systemcalls.c365–366 initialize LP64 result slots.
- syscalls.master exactly matches the existing contract source identity.
All are pinned to Apple XNU f6217f891ac0bb64f3d375211650a4c1ff8ca1ea, with
SHA256/size/HTTPS command receipts in sources-final.json. No native execution is
established by public source agreement or portable synthetic controls.
