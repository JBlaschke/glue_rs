# GNU Linux arm64 Python native package evidence

Captured on 15 October 2026 from clean feature commit `dd8cdd3` on
`codex/a7-python-native-package-imports`, based on merged `478ebcd`.
[Decision 0029](../../decisions/0029-python-native-package-imports.md) defines
this separate descriptor-backed package-member experiment. The unchanged stock
runtime is CPython 3.13.16 / PBS `20261009`, conventional GIL, original unstripped
GNU arm64 image, with independently verified stock headers.

Three dotted native children of an archive source package use stock
`ExtensionFileLoader` creation/execution. Their real origins name retained
`/proc/self/fd/N` descriptors; source-package modules and resources keep virtual
`glue://` identities. The four native images, twelve public Python imports and
API4 29-export C boundary retain their historical identity. This route supplies
zero built-in registrations. A scoped callback checks aliases, image bases,
exports, relocations and global absence around each stock loader operation.

The independent ordinary stock descriptor-loader driver passes dotted metadata,
relative imports, resources, caching/reload/removal, custom creation, create/exec
error retry and GC. Its integer ledger reports five states allocated, freed and
released, with zero owned references after real `Py_FinalizeEx`. It also rejects
eight forged spec/path/flags/unknown-child controls before initialization. This
baseline does not separately run an intentional application-error entry.

The four runtime/native-provider combinations pass both normal execution and
intentional application error. Every run reports the same five-state cleanup
after interpreter finalization; error runs preserve the original application
error. Archived corruption, a missing host dependency and a changed host root
reject before native loading. All eleven complete traces pass strict replay
against actual archive frames and independently pinned native metadata. All
twenty distinct hostile trace edits reject, including finalization order and
the measured parser-buffer owner/growth/full-release checks.

The same launcher bytes rerun all eleven registered-initializer and eleven
lifecycle cases against unchanged original archives, images and historical
policies. All 22 outcomes and strict replays pass. All runtime cases execute
offline as UID/GID 65534, read-only, with producer interpreters, headers,
repository and staging absent. Both disposable historical volumes and the clean
capture volume are removed.

GNU source workspaces pass 505/506 checks for Lua 5.4/5.5, with all-target Clippy
clean. Mac Lua 5.4 Python packaging passes 550 checks; Mac Lua 5.5 source passes
506, both with all-target Clippy clean. The optimized GNU Python/probe suite
passes 170 checks and Clippy. All 300 Python trace-policy units pass; the fourteen
new units also pass on Mac Python and stock Python 3.13 in the clean harness.
Rust 1.88.0 and the pinned Podman image are recorded in the capture.

The contemporaneous Mac/GNU broad source inventories contain 370 files. All
compiled input bytes match the clean feature commit. Two policy scripts changed
after those broad checks to admit only the observed bundled parser-buffer size
pair (299008 to 593920); their before/final identities are recorded explicitly.
The final policy suite, clean native replay and hostile audit use the committed
scripts. Every clean capture input is independently compared with current files
and committed Git blob bytes.

`capture/` retains clean commands, source identity, environment, provenance,
output/status receipts, compressed complete traces, native inspections and
strict replay/audit results. `historical-regression/` retains both historical
corpora and their input/launcher bindings. `checks/` and `linux-source/` retain
workspace/policy logs and contemporaneous source inventories. `native-images/`
contains the four exact inspected ELF files; `manifests/` contains all seven
exact manifest frames. `archives/` contains the two small host-runtime archives.
The larger bundled archives and launcher have recorded complete identities and
reproducible preparation commands; duplicate stock payloads are omitted from Git.

`validation-bindings.json` binds the clean commit, identical regression launcher
and broad snapshots. Its compiled input list is a selected subset; the complete
map, including embedded assets, is `capture/source-inputs.json`.
`retention-inputs.json` and `decoded-identities.json` bind retained and decoded
bytes. `artifacts.sha256` covers every retained file except itself. For example,
replay a retained trace from the repository root:

```sh
python3 scripts/check-linux-python-native-packages-trace.py \
  docs/evidence/pbs-linux-arm64-python-native-packages-2026-10-15/capture/host-host.trace.txt.gz \
  --mode host-host \
  --stdout-file docs/evidence/pbs-linux-arm64-python-native-packages-2026-10-15/capture/host-host.stdout.txt \
  --stderr-file docs/evidence/pbs-linux-arm64-python-native-packages-2026-10-15/capture/host-host.stderr.txt \
  --native-metadata-file docs/evidence/pbs-linux-arm64-python-native-packages-2026-10-15/capture/native-metadata.json \
  --archive-file docs/evidence/pbs-linux-arm64-python-native-packages-2026-10-15/archives/host-host.glue
```

Trace replay establishes descriptor/mapping operations, visible pinned ELF bytes
and output order. Reviewed Rust/Python/C control flow, the pinned integer ledger
and independent stock driver establish public loader delegation and cleanup
meaning. Syscall tracing does not observe API calls or callback instruction
timing. This controlled observation leaves G0/G1/G2, arbitrary native wheels,
native `__init__` packages, path-relative native data, other runtimes/ABIs,
subinterpreters, image unloading and other platforms open.
