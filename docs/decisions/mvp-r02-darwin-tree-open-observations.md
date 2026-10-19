# Observe named opens inside actual Darwin process trees

Status: observation bridge only; full Darwin/R02 acceptance remains false.

All seven clean v8 tree captures pass the source-matched raw-call pairing API.
They contain 68 named `open` pairs: 52 match the calibrated nonnegative-result
tuple and 16 match the calibrated ENOENT tuple. Every pair also matches the
historical open observer's zero-mode, canonical signed-32 flag argument, unused
argument-word, bounded NUL/padding and exact return-tuple invariants. Retained
flag values are 0, 2, 0x01000000 and 0x20100000. The value 2 includes write-capable
requests; its presence is data, never permission to write. Several captures
contain opens from distinct observed processes or threads and exec epochs.

Add `tree-open/observe_tree_open.py` with a capture/toolkit API that invokes
`pair_capture` itself. Do not accept caller-asserted validation, prepaired data
or normalized synthetic units. Preserve the entire returned pair bundle,
including all non-open calls, every raw frame and reader/toolkit/receipt
provenance. Each open observation references its source pair and three consumer
indexes, carries the observed PID/TID/exec epoch and retains copied path bytes
and every flag bit. Numeric results are calibrated observations, not FD objects.

Reuse the reviewed `_normalize_call` invariant helper in `observe_open.py`;
leave its historical root/open-only API and unsupported cases unchanged. Record
both helper-file and bridge-file hashes. Only its already calibrated mode zero,
unused-word shape, unambiguous bounded terminator/zero padding, nonnegative
result tuple or exact ENOENT tuple are supported. Unknown flags remain raw bits;
they are not silently masked or treated as harmless. Missing/duplicate paths,
uncalibrated modes/results and noncanonical encodings reject. Any strict-reader
or pairing failure poisons the whole bridge result.

This is not a resolved pathname, vnode, file description, FD generation, attempt
authorization, successful effect or full mutation observation. The copied user
buffer may differ from the kernel lookup or race with another thread. Other
syscalls and Mach operations remain opaque in the preserved source bundle.
The public acceptance API and CLI reject unconditionally. Controls must include
rehashed malformed paths/results, write-capable/high-bit flag retention,
multiple processes/threads, interleaving and poisoning by non-open pairing or
source-integrity errors. Retain actual seven-capture replay separately from
synthetic controls; never rewrite the original captures.
