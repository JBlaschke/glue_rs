# Native Darwin capability transport

`capture-native` is an owned diagnostic collector, **not a complete Darwin
process-tree decoder or extraction oracle**. A `captured` capability result
never satisfies R02 application acceptance. Raw records from the actual VM must
establish ABI and lifecycle behavior before a complete backend is implemented.

Build on the macOS arm64 host, selecting its installed 26.5 SDK and an 11.0
deployment floor:

```sh
fixtures/mvp/macos-trace/prepare-native.sh /new/absolute/toolkit
```

Copy the resulting directory to the approved guest. It contains three independent
ad-hoc signed native executables, a controlled 20-byte input, source/build/signing
metadata and SHA256SUMS. The executables link only system libraries. The guest
needs its own compatible libdtrace/providers and root invocation, but no Python,
compiler, SDK installation or package manager. The collector never elevates
itself or changes OS settings. Build compatibility and strict signatures must
also be verified at the copied guest paths; a deployment floor is not guest
execution evidence.

Initial guest commands (substitute the actual absolute toolkit location):

```sh
sudo /toolkit/capture-native --output /new/capture-open --timeout 15 --profile open -- /toolkit/owned-probe /toolkit/input.txt
sudo /toolkit/capture-native --output /new/capture-returns --timeout 15 --profile open -- /toolkit/lifecycle-probe read /toolkit/input.txt
sudo /toolkit/capture-native --output /new/capture-fork --timeout 15 --profile tree -- /toolkit/lifecycle-probe fork /toolkit/input.txt
sudo /toolkit/capture-native --output /new/capture-double-fork --timeout 15 --profile tree -- /toolkit/lifecycle-probe double-fork /toolkit/input.txt
sudo /toolkit/capture-native --output /new/capture-thread --timeout 15 --profile tree -- /toolkit/lifecycle-probe thread /toolkit/input.txt
sudo /toolkit/capture-native --output /new/capture-spawn --timeout 15 --profile tree -- /toolkit/lifecycle-probe spawn /toolkit/input.txt
sudo /toolkit/capture-native --output /new/capture-vfork --timeout 15 --profile tree -- /toolkit/lifecycle-probe vfork /toolkit/input.txt
sudo /toolkit/capture-native --output /new/capture-spawn-open --timeout 15 --profile tree -- /toolkit/lifecycle-probe spawn-fail-open /toolkit/input.txt
sudo /toolkit/capture-native --output /new/capture-mach --timeout 15 --profile tree-mach -- /toolkit/lifecycle-probe read /toolkit/input.txt
```

The provided fixtures have five-second alarms, including detached descendants.
Use this first-stage tool only with these reviewed owned fixtures. It does not
provide general containment for arbitrary programs. The root gate cannot exec
the fixture until libdtrace compilation, enabling and `dtrace_go` succeed. No
`DTRACE_C_ZDEFS`/`-Z` permits missing required probe clauses. Setup errors retain an
`unavailable` receipt with no fixture execution. Unavailability does not prove
the reason is SIP: inspect the actual retained error.

Unlike `dtrace -c app`, the collector remains alive after root wait completion,
consuming tagged lifecycle records until every observed process terminates,
then stops and drains. The `fork` fixture deliberately returns from its parent
before its child reads; `double-fork` additionally creates a reparented child in
a separate session. `spawn`/`vfork` exec the owned fixture; `thread` reads in a
pthread. `spawn-fail-open` requests a kernel spawn write-open under a missing
parent directory and requires ENOENT, so it creates no file. Its raw spawn data
does not decode the opaque action list or itself establish mutation coverage.

The profile `open` requires named open entry/return and records the entry path.
`tree` adds wildcard BSD entry/return and required proc create/start/exit,
exec-success/failure, spawn-success/failure and lwp-create/start/exit probes.
`tree-mach` additionally requires Mach trap entry/return probes. Probe clause
availability and kernel type translation are checked by libdtrace at runtime;
no provider availability is inferred from the host build.

The CLI accepts a new absolute output path, an absolute executable and direct
argv (no command shell), a 1–60 second deadline, and one profile. The event loop
and final drain respect that deadline. A separate watchdog kills a stuck
collector at deadline+2 seconds and leaves watchdog.json; such a capture has no
valid final receipt. The watchdog only signals its still-live parent and never
remembered/reaped PIDs. Owned descendant alarms prevent unbounded fixture work.
Normal collector failure kills/reaps its still-owned root group; it does not
signal remembered descendant PIDs that could have been reused.

Limits are 256 observed PIDs, 1,000,000 events, 128 MiB raw JSONL and 8 KiB per
typed probe. Principal/dynamic/speculative/other drop notifications and DTrace
fault callbacks abort capture. Options use switch buffering, 16 MiB buffers,
8 MiB dynamic state, 20 ms consume/status intervals and temporal ordering. A
final drain failure, missing observed terminal, nonzero owned root exit, missing
open events, timeout, signal, record bound or output error is a failure.
Required fixture, collector and evidence identities are computed before selecting
the final status, using a 16 KiB streaming buffer and a 128 MiB per-file bound
matching the permitted raw capture size. Missing, nonregular, unreadable,
oversized files or byte counts differing from the initial stat fail verification; a failed identity
cannot produce `captured`. The receipt records `identity_checks_passed`; null
identities can appear only in a failed/unavailable diagnostic. A one-byte
sentinel bounds detection of growth after the initial file-size check.

## Files and raw schema

- `program.d`: exact generated program with the gated root PID.
- `probes.tsv`: actual syscall/proc/mach_trap inventory, including IDs.
- `events.jsonl`: bounded typed records; no Linux strace grammar is used.
- `errors.jsonl`: drop/fault callback records, bounded rejected-layout/libdtrace
  diagnostics and literal setup diagnostics (the file can contain plain text
  during setup failure). The first failure cause is preserved in the receipt;
  a later drain or cleanup failure cannot replace it.
- `target.stdout` / `target.stderr`: actual owned fixture streams.
- `watchdog.json`: empty normally; explicit hard-timeout diagnostic if fired.
- `capability.json`: native kernel/architecture, profile, exact argv, root wait
  status, observed process ledger, event/drop/error counts, fixture/collector and
  evidence SHA256 identities. `full_trace_acceptance` is always false.

Each event records consumer event index, CPU, enabled probe ID, provider/module/
function/name and all trace records with action/size/offset and exact native byte
hex. It exposes the first five uint64 fields as `kind`, `timestamp`, `pid`, `tid`,
`detail`. Their raw bytes remain authoritative. `event` is a consumer sequence,
not a kernel sequence or an independent detector of lost events. The protocol is
`darwin-capability-raw-v1`; the prepared binaries are native little-endian arm64.

A rejected callback emits a `layout-error` diagnostic with its reason, consumer
event count, descriptor count, total probe byte size, first five record values
(`header`) and up to twenty descriptor metadata entries. Each entry retains
`action`, `size`, `offset` and `u64`; a value is null unless its record is exactly
eight bytes and lies within a probe bounded to 8 KiB. Zero-width or invalid
descriptors remain rejected. These metadata do not become accepted events and
do not establish the actual kernel ABI. Work/stop/drain failures additionally
retain `libdtrace-error` with the operation, actual libdtrace error number and a
message bounded to 512 bytes. At most sixteen combined layout/libdtrace
diagnostics are emitted; callback drop/fault counters keep their existing
meaning. An event count that exceeds serialized events is incomplete evidence,
even when a rejected-record diagnostic explains the gap.

| Kind | Meaning | Detail / subsequent records |
| --- | --- | --- |
| 1 / 17 | BEGIN / END | collector context; no application lifecycle inference |
| 2 | BSD syscall entry | ppid; arg0 through arg7 |
| 3 | BSD syscall return | ppid; arg0, arg1, arg2, arg3, DTrace errno |
| 4 | proc create | translated child PID |
| 5 | proc start | observed ppid |
| 6 | proc exit | raw arg0 lifecycle code (`CLD_*`), not application exit status |
| 7 / 8 | exec success / failure | ppid / raw arg0 error |
| 9 | lwp create | translated thread ID; retain raw width for ABI inspection |
| 10 / 11 | lwp start / exit | zero |
| 12 / 13 | spawn success / failure | zero / raw arg0 error |
| 14 | named open path | zero; bounded copyinstr record |
| 15 / 16 | Mach trap entry / return | ppid; raw arg0..arg7 / raw arg0 |

For kind 6, the collector records `proc:::exit`'s `arg0` unchanged. The inspected
Apple [exit implementation](https://github.com/apple-oss-distributions/xnu/blob/main/bsd/kern/kern_exit.c)
emits `CLD_EXITED` there; it separately emits `proc:::exited` with a target
process and exit value. This collector does not subscribe to `proc:::exited`.
The receipt's `root_wait_status` comes from the collector's `waitpid` call and
is separate from the lifecycle code; the raw protocol does not establish
application exit statuses for descendants. Published source guides this
distinction but does not substitute for calibration against the actual guest
kernel.

## Remaining hard acceptance blockers

The ledger uses observed PIDs, not proven PID generations, and spawn discovery
uses proc start/exec-success fallback as well as create. Actual controls must
establish ordering and coverage before any complete-tree claim; events from an
entirely unobservable child cannot be inferred from this ledger. Paths are copied
only for named open; path NUL/truncation semantics remain to be proved. There is
no syscall pairing checker, full-path/dirfd/per-thread-cwd decoder, FD inheritance
and SCM_RIGHTS/fileport resolution, spawn-action decoder, mmap/mprotect backing
ledger, asynchronous-I/O decoder, Mach message/VM rights decoder, protected-exec
visibility proof, complete syscall coverage table or filesystem mutation oracle.
Raw capture success proves none of those. Missing or cut evidence, nonempty
watchdog output or a failed/unavailable receipt must never be promoted to R02.

Source grounding: local Apple dtrace.h/sys/dtrace.h define consume and drop/error
interfaces; the installed dtrace(1) documents -c lifetime. Apple's
[systrace source](https://github.com/apple-oss-distributions/xnu/blob/main/bsd/dev/dtrace/systrace.c)
and [proc SDT definitions](https://github.com/apple-oss-distributions/xnu/blob/main/bsd/dev/dtrace/sdt_subr.c)
explain the raw argument choices, but do not substitute for VM captures matching
the actual running kernel.
