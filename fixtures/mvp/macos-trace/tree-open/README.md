# Tree-aware named-open observations

The `observe_tree_capture(capture, toolkit)` API calls the actual raw-call
pairing adapter, which runs the strict raw-v4 reader itself. Callers cannot pass
their own validation claim, paired objects or normalized state units.

```sh
python3 fixtures/mvp/macos-trace/tree-open/observe_tree_open.py \
  --capture /absolute/owned/tree-case --toolkit /absolute/matching/native-capture-v8
python3 fixtures/mvp/macos-trace/tree-open/test_observe_tree_open.py -v
```

Each observation retains the copied user pathname as hex bytes, all 32 flag
bits, mode zero and the calibrated numeric result/errno. Write-capable flags
remain request data even on failed opens. Unknown bits are not masked. The
observed PID/TID/exec epoch identifies only a bounded session lifetime; it is
not an attested kernel generation. Source pair number and consumer indexes
link each observation to the preserved raw entry/path/return frames.

The complete `source_pairs` object remains in the result, including non-open
BSD/Mach calls, lifecycle frames, unreturned entries and all source/toolkit/
receipt provenance. Only calibrated zero mode, canonical signed-32 flags,
unused argument words, bounded NUL/zero padding and exact success/ENOENT tuples
are supported. Other shapes reject. The historical `observe_open.py` API is
unchanged; its reviewed invariant helper is reused and its file hash retained.

Copied bytes can race or differ from the pathname used by the kernel. A numeric
result is not an FD object; a successful tuple does not authorize an effect.
There is no cwd/dirfd resolution, vnode/file-description identity, allowed write,
spawn-action or shared-map decision. Full Darwin/R02 acceptance always rejects.
The bridge permits at most 4,096 observations and inherits all stricter reader
and pairing bounds. See the [decision](../../../../docs/decisions/mvp-r02-darwin-tree-open-observations.md).
