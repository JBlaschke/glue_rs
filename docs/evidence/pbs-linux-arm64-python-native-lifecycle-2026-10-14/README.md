# GNU Linux arm64 Python native lifecycle evidence

Captured on 14 October 2026 from clean feature commit `9b1c386` on
`codex/a7-python-native-lifecycle`, based on merged `3f6bf8f`.
[Decision 0028](../../decisions/0028-python-native-module-lifecycle.md) defines
this separate registered-initializer experiment. The unchanged stock runtime is
CPython 3.13.16 / PBS `20261009`, conventional GIL, original unstripped GNU arm64
image, with independently verified stock headers.

The independent ordinary stock registration driver passes custom creation,
reference-cycle collection and initialization-error retry. After its real
`Py_FinalizeEx`, the pure-C ledger reports five allocated states, five frees,
five releases and zero owned references. Seven isolated ledger protocol controls
pass. The four runtime/native-provider combinations pass both normal execution
and intentional application error; the latter preserve the original error after
successful cleanup checks. Archived dependency corruption, a missing host
native dependency and a changed host root reject before loading.

All eleven new complete syscall traces pass strict replay against their actual
archive frames and independently pinned native metadata. The 33 bounded hostile
trace edits reject. The separate historical native regression reruns all eleven
old cases with the same launcher bytes and unchanged old images/archives; all
pass the unchanged historical policy. Its compiled source identities match the
clean implementation. All runtime cells are offline, UID/GID 65534, read-only,
with producer interpreters, compiler headers, repository and build staging absent.

GNU source workspaces pass 501/502 checks for Lua 5.4/5.5, with all-target
Clippy clean. The Mac Lua 5.5 source workspace passes 502 checks; the Mac Lua 5.4
Python packaging workspace passes 546 checks. Both Mac configurations pass Clippy. Optimized GNU
Python/probe tests pass 165 checks and Clippy; the new trace policy passes 22 units
on Mac Python 3.15 and stock Python 3.13, alongside 264 historical Python trace
units. Rust 1.88.0 and the pinned Podman image are recorded in the capture.
Workspace logs were captured before the implementation commit without a
contemporaneous source inventory. The clean native run rebuilds and checks the
committed runtime code; its complete input map is independently compared with
Git blob bytes.

`capture/` holds clean-run commands, source inputs/revision/status, environment,
provenance, output/status receipts, compressed complete traces, native inspections
and strict replay/mutation results. `historical-regression/` holds the old corpus
rerun and input/launcher bindings. `checks/` and `linux-source/` retain workspace
and policy logs. `native-images/` contains the four exact inspected ELF files;
`manifests/` contains all seven exact manifest frames. `archives/` retains the two
small host-runtime archives. Larger bundled frames and the launcher have complete
recorded identities and reproducible preparation commands; duplicate stock runtime
payloads are omitted from Git.

`validation-bindings.json` binds the clean source and identical regression
launcher, and labels its source list as a selected runtime subset. The complete
input map, including embedded fixture assets, is `capture/source-inputs.json`. `decoded-identities.json` records each compressed file's original byte
identity. `artifacts.sha256` covers every retained file except itself. Replay the
compressed traces from the repository root, for example:

```sh
python3 scripts/check-linux-python-native-lifecycle-trace.py \
  docs/evidence/pbs-linux-arm64-python-native-lifecycle-2026-10-14/capture/host-host.trace.txt.gz \
  --mode host-host \
  --stdout-file docs/evidence/pbs-linux-arm64-python-native-lifecycle-2026-10-14/capture/host-host.stdout.txt \
  --stderr-file docs/evidence/pbs-linux-arm64-python-native-lifecycle-2026-10-14/capture/host-host.stderr.txt \
  --native-metadata-file docs/evidence/pbs-linux-arm64-python-native-lifecycle-2026-10-14/capture/native-metadata.json \
  --archive-file docs/evidence/pbs-linux-arm64-python-native-lifecycle-2026-10-14/archives/host-host.glue
```

Trace replay establishes descriptor/mapping operations, pinned visible ELF bytes
and output order. Reviewed C/Rust control flow, the pinned integer ledger and
independent stock driver establish callback semantics and post-finalization
meaning. Complete cleanup is measured for this bounded fixture; no universal
callback ordering or exact traversal count is claimed. These observations leave
G0/G1/G2, arbitrary native packages, extension-file loading, other runtimes/ABIs,
subinterpreters, image unloading and other platforms open.
