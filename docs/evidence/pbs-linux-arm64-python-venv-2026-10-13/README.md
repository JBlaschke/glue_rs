# Installed Python package ingestion — GNU Linux arm64, 2026-10-13

Clean implementation `35dae5247ab4ce964a72025ab68f6cea2af42b3a` on
`codex/a7-python-venv-ingestion`, from merged `6afed9a`, adds the opt-in
`glue build-python` command. It packages a complete source-only installed tree
or conventional Python 3.13 venv against an explicit admitted runtime template.
Runtime selection, installation and dependency resolution remain separate work.
See [decision 0022](../../decisions/0022-python-installed-package-ingestion.md).

All **15 complete runtime traces** pass live checks and compressed replays:
six installed-package cases and nine fresh regressions of the prior metadata
application. Three additional **process-only build traces** show exactly one
`glue` execution/one PID, no child/interpreter/installer execution, and status 0.
They are distinct from the complete runtime traces.

## Inputs and observed behavior

The checked-in pure wheel is 2,674 bytes, SHA-256
`ac1701dbdecd3883432a32a1a79204a9c89186fc11554596b3d326010bd5be3a`.
Its ZIP construction is deterministic. A genuine stock Python 3.13.16 venv
is created with `--without-pip`; the producer's pip 26.2.1 installs the exact
package offline by name with `--no-index`, `--find-links`, `--no-deps` and
`--no-cache-dir`. Pip produces thirteen RECORD rows: ten retained files, two
bytecode files and one generated console wrapper. No application/plugin code
is invoked during installation. The setup commands and actual installation,
wrapper, source and original RECORD identities are retained in
[installation-provenance.json](installation-provenance.json).

The product reads those inputs without executing Python. It verifies retained
original hashes/sizes, omits and reports the three supported generated inputs,
and rewrites RECORD in sorted LF CSV with fresh SHA-256/size fields and a blank
self-entry. Every other selected source/data/metadata byte stays unchanged.
The independent expected tree contains eleven application resources: the ten
distribution files and the unchanged `app/main.py`. Normalized RECORD is 872
bytes, SHA-256 `bbb0ed2aa74f8fc5ce48b67899e32267f15710dcb86a079237c952c9bbe7064e`.

The same product-built application succeeds with bundled, full-host and
install-only host providers, exercising version/requirements, plugin loading,
import-name mapping and virtual RECORD resource reads. Physical host metadata
lures remain invisible. Each provider has a one-byte METADATA CRC control that
rejects before provider acquisition. Success stdout is exactly:

```text
glue python distribution metadata ok: version=1.2.3 plugin=42 files=10
```

## Validation and provenance

| Validation | Result |
| --- | --- |
| Mac/Linux source workspace, Lua 5.4 / 5.5 | 452 / 453 Rust tests; all-target Clippy with warnings denied |
| Mac workspace with `python-pack` | 465 Rust tests; Clippy with warnings denied; formatting passes |
| Optimized GNU Python/probe | 129 Rust tests; Clippy with warnings denied |
| Optimized GNU installed-package packer | 33 Rust tests; Clippy with warnings denied |
| Optimized GNU runner | 16 CLI tests; Clippy with warnings denied |
| Metadata/importer/entry protocols, stock Linux Python | 32 / 16 / 7 tests |
| Deterministic wheel fixture, Mac / stock Linux Python | 8 / 8 tests |
| Python trace-policy suite, Mac / stock Linux Python | 235 / 235 tests, including eight new ingestion policy tests |
| Installed-input controls, each of Mac and GNU Linux | Two valid builds and all 30 hostile cases pass |
| New GNU product commands | All 27 exact controls agree, including three transformation JSON reports |
| Actual installed-package trace mutations | All 126 reject from six passing baselines |
| Complete compressed runtime trace replays | All 15 exit 0 |

Workspace validation ran before the implementation commit on identical code.
The Linux source-workspace bundle preserves its development status/diff, plus
a [binding to the committed code](linux-source-workspace/committed-code-binding.json).
The native execution, prior metadata regression and Mac product-control
captures ran from clean `35dae52`. The clean Mac receipt verifies 239 source/
input files against that commit and records an absent input-interpreter target:
the Linux-created venv interpreter symlink cannot execute on that Mac. Both input
modes still build successfully. The Mac and GNU install-only outputs agree at
15,068 bytes with SHA-256
`cda39021d7c56c6abbf356b453d796bcec67443816eef118fd84e96431325b92`.

[product-audit.json](product-audit.json) independently verifies 4,427 valid
decoded members across six archives and the three intentional CRC failures,
all seven artifact hashes, all 27 product commands, original/normalized RECORD
identities, retained input identities, omissions and the three build-process
traces. Its reproducible script imports neither product nor trace-policy code.
[build-controls/audit.json](build-controls/audit.json) and the
[Mac controls](macos/build-controls/audit.json) verify the two valid modes and
30 rejection cases independently of the Rust unit tests. Cases cover native/
cache-native files, hooks/editables, traversal, missing/damaged inputs, duplicate
paths before omission, shared/unrecorded ownership, symlinks, venv/WHEEL
declarations, app collisions, bounds and existing-output protection.

[hostile-audit.json](hostile-audit.json) names the 126 actual-trace mutations.
[capture-summary.json](capture-summary.json) binds every runtime output/status,
archive identity, decompressed trace identity/record count and replay result.
Tool logs/traces are losslessly gzip-compressed where needed. The strict new
policy privately reuses the old policy without widening syscall or allocator
pins. Its CRC phase additionally binds the exact ordered entry/INSTALLER/
METADATA reads, ZIP offsets, visible bytes, totals and final cursor.

## Observed cell and boundary

The immutable offline image is
`62812c4a0e15bc750ddd6ec68d2a19f8815a14b60d520e201a911e2e29f40abe`,
repository digest
`sha256:c3aa290549c5ba0e63aec9de61fc10b6e4bd59e89c0c3f72bb270dd426eedeba`.
GNU Linux arm64 uses kernel `7.1.4-200.fc44.aarch64`, glibc
`2.36-9+deb12u10`, Rust 1.88.0, GCC 12.2.0, strace 6.1 and 4,096-byte pages.
Runtime containers run as UID/GID 65534, offline and read-only, without
workspace/build inputs, accessible temporary paths or usable Python environment
overrides. Volume-removal receipts are retained.

Runtime/helper/provider identities remain stock CPython 3.13.16 / PBS `20261009`,
conventional GIL and non-debug ABI. The C boundary, native loaders, importer,
metadata helper, source readers, profile registry and old metadata trace policy
remain byte-identical; metadata parsing code changed only visibility for facade
reuse. [unchanged-runtime.json](unchanged-runtime.json) records those comparisons.
The two host metadata lures are documented additions to read-only provider trees.
This harness retains their provenance but does not claim an independent complete
post-runtime installation audit.

These observations establish this bounded source-only build workflow and exact
fixture on the pinned cell. They do not establish general package compatibility,
wheel installation, dependency solving, native packages, extra runtime versions,
other target cells or G3/G4/G5/G6 acceptance. Source/package input trees must
remain stable during build-time reads. Existing outputs are never overwritten;
an output write failure may leave a partial file, as for ordinary builds.

## Replay

From the repository root, replay a retained installed-package trace using its
archive length from `source-metadata.json`:

```sh
python3 scripts/check-linux-python-venv-trace.py \
  docs/evidence/pbs-linux-arm64-python-venv-2026-10-13/install-host.trace.txt.gz \
  --mode install-host --archive-bytes 15068 \
  --stdout-file docs/evidence/pbs-linux-arm64-python-venv-2026-10-13/install-host.stdout.txt \
  --stderr-file docs/evidence/pbs-linux-arm64-python-venv-2026-10-13/install-host.stderr.txt \
  --metadata-file docs/evidence/pbs-linux-arm64-python-venv-2026-10-13/source-metadata.json
python3 scripts/test_linux_python_venv_trace.py --audit-capture \
  docs/evidence/pbs-linux-arm64-python-venv-2026-10-13 \
  target/python-venv-retained-hostile-audit.json
```

`metadata-regression/` retains the old policy's nine fresh traces, metadata and
replay outputs. `implementation-files.json` records all committed input changes.
`SHA256SUMS` covers every retained file except itself; verify from this directory
with `shasum -a 256 -c SHA256SUMS`.
