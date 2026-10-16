# Native open observations

`observe_open.py` is the first adapter that pairs actual source-matched native
capability records. It accepts a clean completed `open` profile on the calibrated
Darwin 25.6.0 arm64/macOS 26.6.2 build 25G83 guest, with one owned root/thread.
It observes direct `open`; variants such as `openat` remain unsupported.

```sh
python3 fixtures/mvp/macos-trace/observe_open.py \
  --capture /absolute/capture-open --toolkit /absolute/matching-toolkit
```

The adapter first runs the strict transport reader, including exact producer
sources, raw hashes, generated program, record layouts and completion checks.
It pairs entry/path/return by PID/TID and consumer order. Separate entry/path
callbacks have different timestamps and EPIDs; timestamps need only be ordered.
Results retain every raw frame, the copied user pathname bytes and terminator
position, raw flag bits, zero mode, descriptor number or observed ENOENT error.
Write-capable requests remain visible, including the actual runtime startup
open of `/dev/dtracehelper`. No request is authorized by this adapter.

Boundary controls cover malformed pairing, ambiguous/truncated paths, padding,
non-UTF-8 bytes, unsupported return tuples, signed argument encoding, modes,
additional threads, source corruption, host/completion checks and bounds:

```sh
python3 fixtures/mvp/macos-trace/test_observe_open.py -v
```

The actual v5 guest `open` and `returns` captures replayed successfully, yielding
7 and 8 complete calls respectively. The independent fifteen controlled-pair
calibration across eight completed guest cases is identified in the
[decision](../../../docs/decisions/mvp-r02-darwin-owned-open-observations.md).
Raw evidence and replay output remain outside Git in the Darwin checkpoint.
Synthetic tests and successful replay do not attest the kernel or establish an
extraction oracle. There is no resolved pathname, FD object, process generation,
complete syscall coverage or application acceptance; `--acceptance` always fails.
