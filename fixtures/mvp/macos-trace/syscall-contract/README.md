# Darwin BSD source contracts

This executable inventory gives 161 selected BSD syscall declarations, zero-based
DTrace entry argument positions, semantic selectors and unresolved decoder/state
requirements. It advances the raw adapter's dispatch boundary. It grants no
syscall permission and cannot accept an extraction trace. The
[decision](../../../../docs/decisions/mvp-r02-darwin-syscall-contract.md) records
the boundary; the C producer, strict transport reader and direct-open adapter
remain separately reviewed components.

`contracts.json` pins Apple XNU commit
`f6217f891ac0bb64f3d375211650a4c1ff8ca1ea` and SHA-256/size identities for
`syscalls.master`, `systrace.c`, `makesyscalls.sh`, spawn declarations and the
installed `/usr/lib/dtrace/io.d`. Declaration argument lists are in entry
`arg0`, `arg1`, ... order. The generator removes an internal `sys_` prefix for
probe names; unknown names are never silently normalized. The pinned
[declarations](https://github.com/apple-oss-distributions/xnu/blob/f6217f891ac0bb64f3d375211650a4c1ff8ca1ea/bsd/kern/syscalls.master),
[argument generator](https://github.com/apple-oss-distributions/xnu/blob/f6217f891ac0bb64f3d375211650a4c1ff8ca1ea/bsd/kern/makesyscalls.sh)
and [provider](https://github.com/apple-oss-distributions/xnu/blob/f6217f891ac0bb64f3d375211650a4c1ff8ca1ea/bsd/dev/dtrace/systrace.c)
provide the source boundary. Signed source fields
are widened through int64; pointers and unsigned fields through uint64. This
module preserves those bits and does not guess widths or dereference pointers.

`parse_table(raw_bytes)` performs the same bounded table parsing without file
I/O. It requires immutable bytes up to256KiB and returns the same table/call-map/
digest tuple as `load_table`. It does not pin arbitrary supplied bytes to this
asset; callers needing that identity check it separately. Passing the parsed
tuple explicitly to `entry_facts` avoids its default file-loader path.

The default local SDK identifies as `macosx27.0`; the guest is 26.6.2. The exact
SDK header hashes are recorded. Its vector-AIO declarations at syscall numbers
246/247 are absent from the pinned kernel declarations and actual v4 guest probe
inventory. `aio_readv` and `aio_writev` remain unsupported, not evidence of guest
coverage. A pinned public source declaration is not installed-kernel attestation.

## Required coverage

| Family | Entry fields and obligations |
| --- | --- |
| Open variants | `open` path0/flags1/mode2; `openat` dirfd0/path1/flags2/mode3; protected/extended/guarded variants retain their distinct fields. Guarded flags are at3, not1. Indirect `fhopen`/`openbyid_np` require an object-ID decoder. |
| Path mutations | Both source/destination paths and independent dirfds for rename/link/clone. Symlink target text is literal; only the new link name is a created destination. Include unlink/delete/undelete, mkdir/mknod/FIFO, truncation, ownership/mode/flags/time/xattr/attribute changes. Detect attempts at entry even when the return fails. |
| Cwd and roots | Process cwd, thread cwd via `__pthread_chdir`/`__pthread_fchdir`, fchdir object identity, and explicit rejection of unmodeled chroot/mount namespace transitions. Absolute-path and AT_FDCWD resolution are not supplied by pointer words. |
| FD state and writes | Close/reuse generations, dup/dup2/fcntl and close-on-exec semantics; write/writev/pwrite/pwritev/guarded variants, FD metadata/truncation and sendfile. Darwin `sendfile` source FD is arg0 and output socket is arg1. Unknown fcntl commands require rejection, not a generic read-only classification. |
| Spawn and execution | `posix_spawn` path1 and descriptor pointer2; bounded descriptor/action snapshots and source-sized arrays. [File actions](https://github.com/apple-oss-distributions/xnu/blob/f6217f891ac0bb64f3d375211650a4c1ff8ca1ea/bsd/sys/spawn_internal.h) OPEN/CLOSE/DUP2/INHERIT/FILEPORT_DUP2/CHDIR/FCHDIR occur in kernel spawning work and cannot be inferred from the eventual child's ordinary syscalls. |
| Mappings and protections | mmap address0/length1/prot2/flags3/fd4/offset5; mprotect and msync need mapping/object generations and shared-write capability. Private/anonymous mappings are distinct from shared file writes. Mach VM aliases remain unmodeled. |
| Async work | aiocb/list pointers, opcodes, FD generations, submission/completion accounting for aio and lio; bounded nested structures for kevent variants. Until decoded, these routes reject complete acceptance. |
| Rights and namespaces | SCM_RIGHTS message control, Unix socket addresses, fileport makeport/makefd and named shared-memory/semaphore objects require explicit decoding and provenance. A message pointer is not a filesystem path or a known descriptor transfer. |
| Opaque controls | ioctl/fsctl/ffsctl command payloads, mount data, filesystem snapshots and graft operations require request-specific decoders. Unknown commands remain unsupported even after a failed attempt. |
| Read-side path lookup | Path snapshots, dirfd/cwd object identity and symlink traversal are required for stat/access/readlink/attribute queries; the registry does not classify them as universally safe. |

`io.d` exposes fileglob and vnode information through `fds[]`, but its pathname
is explicitly assembled as `??/parent/name`. It is not an authoritative absolute
path. Numeric FD, partial pathname and a reused kernel address cannot substitute
for open-file-description/vnode generations. Entry-time FD lookup may race a
concurrent table mutation; overlapping mutations need rejection until a proven
ordering/object model exists. Per-descriptor close-on-exec differs from shared
fileglob flags.

Actual v5 `proc:::exit` ran in parent context while a child exited. The current
probe PID must not be treated as the target process. This module does not
translate lifecycle events or suppress the retained failed spawn case. Likewise,
minimal owned Mach startup already uses `mach_msg2_trap`; rejecting all Mach
messages is an honest support gap, not a usable accepted-host policy. Packed
headers, destination ports, rights and kernel RPC semantics require a future
bounded model. No broad Mach-message allowlist is proposed.

## Return framing and use

Apple's provider supplies return arg0=primary result, arg1=the same primary
result, arg2=secondary result and arg3=kernel return/error code; builtin `errno`
comes from that code. The producer records those five words. The registry checks
the duplication and errno equality, retaining bits rather than inventing libc
results. ERESTART/EJUSTRETURN and successful type-specific returns require
explicit control-flow/return-type normalization before state updates. Entry and
return pairing, effect ordering and incomplete-call rejection are not performed
here.

```sh
python3 fixtures/mvp/macos-trace/syscall-contract/test_syscall_contract.py -v
python3 fixtures/mvp/macos-trace/syscall-contract/syscall_contract.py \
  --source /absolute/path/to/the/pinned/syscalls.master
python3 fixtures/mvp/macos-trace/syscall-contract/syscall_contract.py \
  --timeline /absolute/path/to/a/separately-validated/timeline.jsonl
```

The source command checks the exact source hash and all 161 declarations. The
timeline command inspects bounded ordinary reader exports without executing
captured commands or modifying captures. Unknown calls, unmodeled control-flow
returns, separately retained open-path payloads and lifecycle/Mach providers
produce an incomplete observation and
nonzero exit. Even an `inspected` observation has `full_trace_acceptance=false`
and no native coverage attestation. `--acceptance` always fails. This is not a
complete syscall inventory, raw pathname decoder, FD oracle or R02 acceptance.

A read-only observation over all nine independently exported v5 timelines found
all nine incomplete. Direct-open cases retain path-byte events as uninterpreted
auxiliary evidence; process cases include unsupported BSD routes and lifecycle
records; the Mach case includes 220 Mach-provider records. This registry does not
turn the eight drained captures or the failed spawn capture into acceptance.
The out-of-tree observation report is
`/private/tmp/glue-darwin-source-contract-v5-review-final-20261016/review.json`,
SHA-256 `60cc23285fc5c81a4c47cbf8c220b50470f3561a7b858fb13a3ab044683d6f3a`.
