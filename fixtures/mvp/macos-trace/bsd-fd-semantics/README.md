# Bounded BSD descriptor semantics

`bsd_fd_semantics.py` supplies executable source rules for eleven descriptor
operations: `close`/`close_nocancel`, `dup`, `dup2`, `write`/`write_nocancel`,
`pwrite`/`pwrite_nocancel`, `fsync`/`fsync_nocancel` and `ftruncate`.
It turns typed requests and provider outcomes into operation-specific consistency
checks and **conditional postconditions**. It does not apply state transitions,
identify objects or grant extraction acceptance.

```python
from bsd_fd_semantics import decode_owned_fd_semantics

result = decode_owned_fd_semantics(
    program_bytes, probe_inventory_bytes, error_bytes, raw_event_lines,
    owner_pid=owner_pid, target_pid=target_pid,
    contract_bytes=exact_contract_bytes)
report = result.to_dict()
```

The API invokes `pair_raw_owned` exactly once over the original immutable static
bytes and bounded event iterable. Only after complete transport validation and
closed, unambiguous pairing does it invoke identity-checked private pure entry
ABI and outcome helpers. It does not run the stream again through their public
input APIs. Invalid, orphan, unpaired or ambiguous input returns no prefix.
The separate entry ABI API remains available for inspecting unpaired requests;
this API does not make them disappear into a clean closed-call report.

Each BSD pair has one row linking its original `source_pair_index` and correlation
ordinals. The full frozen source retains original phases, words, requirements,
Mach pairs and lifecycle records. Known-unhandled operations and unknown names
receive explicit unsupported rows with unmodeled intent, rather than being
ignored or classified harmless. `read`/`pread` are absent from the pinned current
contract; vector, guarded and command-specific `fcntl` rules are deferred.

Rows retain all typed arguments and the typed kernel outcome unchanged. A
recognized request adds the numeric descriptor(s), opaque buffer address, byte
count, signed offset or length and its entry-attempt category. Noncanonical or
unsupported arguments never erase write, flush or truncate attempts.

## Executable operation rules

A `source-consistent` row means only that the handled request/result relations
below hold. It is not proof of native origin, every object/resource precondition,
a completed filesystem effect or supported execution on an installed kernel.

| Operation | Required successful result and conditional postcondition |
| --- | --- |
| close | Zero primary, zero secondary and nonnegative fd; release that kernel-bound descriptor slot. |
| dup | Distinct nonnegative returned fd, zero secondary; alias the kernel-chosen shared open file description, clear close-on-exec, and require lowest-free allocation at the allocation point. |
| dup2 | Return the requested target, zero secondary. Same-fd case preserves flags and allocates nothing; distinct target conditionally replaces the slot with a shared alias and clears close-on-exec. |
| write/pwrite | `0 <= reported bytes <= requested bytes <= INT_MAX`, nonnegative fd. Retain implicit versus explicit-offset requests and the reported count. A claimed pwrite success at offset `-1` contradicts its wrapper. |
| fsync | Zero primary/secondary and nonnegative fd; a conditional file-integrity flush against a vnode. |
| ftruncate | Zero primary/secondary, nonnegative fd and requested length; retain an object-specific truncate rule. The requested length is not an observed resulting size. |

Both pinned LP64 dispatchers initialize the two result slots. The closed int
handlers write only the first slot or leave storage unused, including
`pshm_truncate`; the explicit zero-secondary check is limited to those handlers.
The original typed secondary is retained even when the row is unsupported.
Unsigned dup arguments above `INT_MAX` remain unsupported rather than guessing
the kernel implementation's unsigned-to-signed conversion.

The pwrite wrapper rejects only `-1` at that layer. Other negative offsets remain
signed request scalars; there is no blanket nonnegative filter, accepted byte
range or current-file-position inference. Buffers remain opaque. Implicit writes
can depend on open-file-description flags such as append; no offset or backing
identity is invented. Zero-byte writes retain their payload-write attempt.

Conditional aliases refer to the **kernel lookup/chosen fileglob**, not an
assumed entry-time descriptor binding. Calls can drop locks, and other threads
can mutate descriptor tables. No rule asserts slot state at return, orders effects
by return time or supplies an object/generation token.

Truncate rules additionally require the vnode-versus-POSIX-shared-memory branch,
page size, prior allocation and object lifetime. The shared-memory implementation
permits only one allocation per lifetime and stores a page-rounded size.
`requested_length` is the original request, not an observed or calculated
resulting object size. No uniform size transition is inferred across those
object kinds.

## Failures and missing evidence

A kernel error never provides a no-effect claim:

- Close can release its descriptor slot before a later fileglob drop reports an error.
- Dup2 can close/reserve its destination before duplication fails.
- Writes compute progress even with some errors; the provider's failure tuple
  can hide partial written bytes. No error row invents a zero byte count.
- Flush and truncate errors retain durability/metadata/size/backing uncertainty.

Failed oversize requests, failed signed-negative offsets and failed mutation
attempts remain visible. Unsupported provider control flow and malformed tuples
also retain requests, raw phases and reasons, with no postcondition.

All reports have `status: incomplete`, `native_abi_calibrated: false`,
`successful_effect_ordering: false`, `state_feed_eligible: false` and
`full_trace_acceptance: false`, including a report containing only Mach pairs.
Each conditional rule retains explicit native/object/lifetime/ordering witness
requirements. Numeric fds 0/1/2 have no application-output exemption. No
synthetic normalized-state event, state-engine update, collector, native/export
admission, filesystem verdict or SIP change is produced.

Nested collections are immutable and `to_dict()` returns detached containers.
Fixed helper hashes are checked before imports, assuming a stable trusted
checkout. After import only caller bytes and their event iterable are accessed;
there is no asset load, subprocess or network operation in the API.

## Source evidence

Seven operation sources are fixed to Apple XNU commit
`f6217f891ac0bb64f3d375211650a4c1ff8ca1ea`; exact SHA256 identities are in
`SOURCE_IDENTITIES` and each report. Physical source lines:

- [Descriptor duplication](https://github.com/apple-oss-distributions/xnu/blob/f6217f891ac0bb64f3d375211650a4c1ff8ca1ea/bsd/kern/kern_descrip.c#L516): `finishdup`516–578, zeroed allocation1107–1113, `fdalloc`1177–1214, `sys_dup`2394–2428 and `dup2`2448–2539.
- [Close and error effects](https://github.com/apple-oss-distributions/xnu/blob/f6217f891ac0bb64f3d375211650a4c1ff8ca1ea/bsd/kern/kern_descrip.c#L1773): slot removal1773–1791, `fg_drop`244–294 and close5404–5439.
- [Write progress and wrappers](https://github.com/apple-oss-distributions/xnu/blob/f6217f891ac0bb64f3d375211650a4c1ff8ca1ea/bsd/kern/sys_generic.c#L578): `fp_writev`578–617, `write_internal`675–695 and wrappers699–750.
- [Truncate and flush](https://github.com/apple-oss-distributions/xnu/blob/f6217f891ac0bb64f3d375211650a4c1ff8ca1ea/bsd/vfs/vfs_syscalls.c#L8635): length validation8635–8649, truncate8653–8700/8740–8810 and fsync8819–8836/8878–8912.
- [POSIX shared-memory truncate](https://github.com/apple-oss-distributions/xnu/blob/f6217f891ac0bb64f3d375211650a4c1ff8ca1ea/bsd/kern/posix_shm.c#L537): unused return-storage parameter537–542; one-allocation lifetime check582–585, page rounding607 and stored rounded size643.
- [arm64 result initialization](https://github.com/apple-oss-distributions/xnu/blob/f6217f891ac0bb64f3d375211650a4c1ff8ca1ea/bsd/dev/arm/systemcalls.c#L130), lines130/136, and [x86_64 result initialization](https://github.com/apple-oss-distributions/xnu/blob/f6217f891ac0bb64f3d375211650a4c1ff8ca1ea/bsd/dev/i386/systemcalls.c#L365), lines365–366.
- The retained `syscalls.master` exactly matches the existing contract source
  identity. Entry ABI and provider outcomes retain their separate fixed helper
  identities and interpretation profiles.

Public source agreement and synthetic controls are separate from required native
calibration. Existing raw readers/contracts, helpers, collectors, native kits and
state engines are unchanged by this feature.

Run portable controls from the repository root:

```sh
python3 fixtures/mvp/macos-trace/bsd-fd-semantics/test_bsd_fd_semantics.py -v
```
