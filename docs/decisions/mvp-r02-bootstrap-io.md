# Bounded nonblocking bootstrap pipe I/O

The future bootstrap uses 64-byte GO and 256-byte status records. This change
adds a byte transport dependency, without integrating the collector or interpreting
those records. Its API accepts exactly either size, or a separate require-EOF
operation. Every invocation validates FIFO type, exact read-only or write-only
access and `O_NONBLOCK`; it never changes flags, signal disposition or ownership.
The caller must already establish sole-writer provenance, stable descriptor
mapping/status flags across shared aliases without concurrent close/rebind or
flag mutation, and an explicit SIGPIPE policy.

Deadlines are absolute `CLOCK_MONOTONIC` values. Normalized uint64 seconds and
nanoseconds must flatten without overflow, be strictly in the future and at most
30 seconds away at entry. Every loop, completed poll and positive transfer checks
time again. Backwards time rejects. EINTR/EAGAIN preserve the same deadline and
current offset. At most 4096 poll/transfer steps are admitted: this is a bounded
bootstrap diagnostic, not a general streaming API. Native calls are nonblocking,
but a caller still needs an independent process deadline for a stalled kernel or
nonconforming injected adapter.

A result always contains a zero-initialized 256-byte buffer and the exact confirmed
prefix/count, including on failure. A complete transfer that is late still fails
and retains all bytes. Sent bytes may already have been consumed: a failed GO
send may already have released its peer. The caller must terminate/reap its owned
child after a failed launch, must never replay a failed record, and cannot infer
that an error prevented every exec. A child failing to send READY must exit; an
incomplete accepted sequence never becomes launch success. CLOEXEC EOF proves
only that the pipe has no writers, not exec success. Partial reads are evidence,
not decoded records.

One trusted operation table supports native POSIX adapters and injected controls.
All callbacks are checked before any callback runs. They must obey libc buffer
bounds, not mutate the API objects or descriptor mapping, and report the errno
saved immediately after failure. All argument objects and byte spans must be valid,
nonoverlapping and stable through the call. The helper snapshots the operation
table and write bytes, allocates no memory, closes nothing and never retries close.
A read with POLLIN plus HUP drains buffered bytes; EOF checks reject a trailing
byte and time out on a leaked writer. Fatal/anomalous poll results are diagnosed before a later clock read can hide
the first stage/errno; successful, timeout and EINTR polls recheck time before
I/O or retry. Poll errors and anomalous callback returns fail with a stage, reason, original positive syscall errno and confirmed count.

Focused injected and owned private-pipe controls can run without tracing or
privilege. They do not establish protocol ordering, endpoint object identities,
parent liveness, target credentials, exec, raw Darwin ABI, filesystem effects or
full R02 acceptance.
