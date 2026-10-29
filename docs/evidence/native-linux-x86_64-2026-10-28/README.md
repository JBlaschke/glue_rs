# Native GNU Linux x86_64 acceptance — 28 October 2026

[Run 40758958354](https://github.com/JBlaschke/glue_rs/actions/runs/40758958354)
at [30e8d08](https://github.com/JBlaschke/glue_rs/commit/30e8d080500de2bd6646c1c68d814eb80208f5f8)
passes all 24 application cases and five unchanged reviewed budgets. Complete
independent offline replay verifies 39 receipts, 156 oracle controls, 990 rank
measurements/streams, eighteen Python environment checks and fifteen payload
inventory reconstructions. All source/capture identities remain unchanged.

This refresh includes the Python exact-version-token probe fix absent from the
historical `e3962701` run. It matches the source of the fresh
[arm64 acceptance](../native-linux-arm64-2026-10-28/README.md). The x86 profile
retains ordinary seeded Python environments for both cases and benchmarks.
No corpus, rank count, budget or runtime input pin was relaxed.

Every process tree uses `traceable-native-syscalls-v1`; asynchronous kernel I/O
is disabled so ordinary syscall fallback can be traced. Structural/I/O/FD/scaling
limits stay fixed. Time/RSS limits remain host-fingerprint scoped, without a
universal timing, cold-cache or unrestricted-host acceptance claim.

The original 160,076,851-byte CI ZIP and all 4,803 extracted files are verified.
A separate local transfer archive prepares/restores with every hash/size/mode
checked: 4,846 source files/882,116,761 bytes, 318,718,289-byte archive. Exact
identities are in [acceptance.json](acceptance.json), [budget-replay.json](budget-replay.json)
and [retention.json](retention.json). Raw captures/archives remain outside Git.

A minimal eight-file, 161,129,470-byte publication set is prepared and passes all
five documented checksum/extraction/full-replay commands in a fresh directory.
It has not been uploaded or published: the previous arm-only authorization does
not cover this x86 set. External x86 retention remains pending explicit approval.
Complete Darwin oracle/corpus, Mac budgets and final compatibility/sign-off
remain open; these two Linux cells alone do not close M2.
