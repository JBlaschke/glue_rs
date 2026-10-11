# Bundled Python source application evidence — GNU Linux arm64, 2026-10-12

These fresh optimized captures use clean implementation
`d3ddac33e41bd681668ce0565c3830e46105ebf5` on
`codex/a7-python-source-apps`, from merged `90c4a10`. Captures ran on
2026-10-11–12 and were retained on 2026-10-12. The product launcher uses
default linked Lua 5.4 plus `python-pbs`; the historical thin probe shares
`glue-runtime-python` through `pbs-bootstrap`. The source-app harness's
`development-opt-in.txt` is `false`.

Six ordinary `glue run APP.glue` invocations cover independent application IDs,
component names and entries, imports/resources, application and compiler errors,
and corrupt-source rejection. All **48 complete traces** pass live checks and
compressed-file replays: six new source-app traces and 42 fresh regressions.
The latter cover the existing product route (9), native initialization (11),
host archive imports (7), bundled archive imports (3), frozen startup (4) and
installed-host startup (8). Historical trace checkers remain unchanged.

## Observed cell and validation

The immutable image is
`62812c4a0e15bc750ddd6ec68d2a19f8815a14b60d520e201a911e2e29f40abe`
(repository digest
`sha256:c3aa290549c5ba0e63aec9de61fc10b6e4bd59e89c0c3f72bb270dd426eedeba`).
The observed GNU Linux arm64 cell uses kernel `7.1.4-200.fc44.aarch64`,
glibc `2.36-9+deb12u10`, 4,096-byte pages, Rust 1.88.0, GCC 12.2.0 and
strace 6.1. Runtime pins remain stock CPython 3.13.16 / PBS `20261009`,
conventional GIL and non-debug mode. Pins, input projections, verified headers,
frozen startup and source inventories are retained with their provenance.

| Validation | Result |
| --- | --- |
| Mac arm64 source workspace, Lua 5.4 / 5.5 | 366 / 367 Rust tests; all-target Clippy with warnings denied |
| Mac arm64 Python-enabled workspace | 366 Rust tests; all-target Clippy with warnings denied |
| GNU Linux arm64 source workspace, Lua 5.4 / 5.5 | 366 / 367 Rust tests; all-target Clippy with warnings denied |
| Every optimized GNU shared Python/probe build | 87 Rust tests; all-target Clippy with warnings denied |
| Optimized GNU product runner | 14 CLI tests; all-target Clippy with warnings denied |
| Trace-policy suite, Mac / pinned stock Linux Python | 238 / 238 tests |
| Existing importer protocol, Mac / pinned stock Linux Python | 16 / 16 tests |
| New byte-entry protocol, Mac / pinned stock Linux Python | 7 / 7 tests |
| Source-app product controls | All 34 exact build/inspect/verify/doctor/cat controls agree |
| Existing product controls | All 30 exact inspect/verify/doctor/cat controls agree |
| Independent actual-source-app hostile edits | All 198 reject, from six passing clean baselines |
| Compressed trace replays | All 48 exit 0 |

The 34 source-app controls include five successful builds, three rejected
build declarations, four read-only commands for each of six modes, and two
rejected doctor declarations. Admission rejects before a missing input-root
lookup or output creation. Actual archive inventories and contents independently
determine expected read-only results. Doctor reports declarations/build/target
readiness even for damaged content; verify and run reject that corruption.

## Artifacts and results

| Artifact | Bytes | SHA-256 |
| --- | ---: | --- |
| Product release `glue` | 3,316,256 | `d6dbfce6713db0cb2c2fc85987ade0b23a93d06a2f613aeedebb060c0ccc5578` |
| Shared thin regression probe | 3,191,336 | `5a7560bfd90a8f09a14aedeae7eb79b28be0108bc7449240b87e0ae1826e7fea` |
| minimal archive | 83,085,052 | `b5c40d817f6e618045a9d69ab6ba9385fe3ea31aa4947306ae25120340ddb084` |
| resources archive | 83,088,333 | `3a6cdb5dee05c0049af85a503f93c1718752b6bbe0c887b0b30f1cb36e3e36d4` |
| app-error archive | 83,084,125 | `62d8db804ae6dfa9e338850f58b661eb85c43505faa25bacc362c071a6acae87` |
| syntax archive | 83,084,119 | `1a9166427e9bccaeae32d72e80bcb79b7e570727db494258ad830f7881e93059` |
| nul archive | 83,084,094 | `00e5cea5acd655b154a428b5e90f085cbb0d202d7754ad5b437e8b5edd035cd7` |
| corrupt-source archive | 83,085,052 | `b9609b72f42883949915c291c6439f331770a3a8f256dcc063e34158d80562d6` |

| Mode | App resources / bytes | Exit | Stdout / stderr bytes | Trace records |
| --- | ---: | ---: | ---: | ---: |
| `minimal` | 2 / 685 | 0 | 50 / 0 | 33,310 |
| `resources` | 7 / 2,178 | 0 | 90 / 0 | 33,380 |
| `app-error` | 1 / 59 | 1 | 0 / 43 | 33,292 |
| `syntax` | 1 / 38 | 1 | 0 / 42 | 33,290 |
| `nul` | 1 / 22 | 1 | 0 / 69 | 33,294 |
| `corrupt-source` | 2 / 685 declared | 1 | 0 / 70 | 26,289 |

The resource entry is `app/tasks/report's [daily].py`. Its virtual origin
preserves that filename identity through percent-encoding:
`glue://daily.report/app/tasks/report%27s%20%5Bdaily%5D.py`. The workloads exercise
byte-source encoding, modules, packages, a one-portion namespace, binary/text
resource streams and finalization reads. The minimal entry is `app/launch.py`;
IDs and selected component names differ across workloads. The application error,
syntax error and embedded-NUL entry use stock execution/compilation and the
existing bounded diagnostic/status-1 contract. Protocol tests also cover empty
source, BOMs, encoding failures and `SystemExit` behavior.

Corruption changes exactly one stored byte in
`app/python/simple_value.py`, from `answer = 42\n` to `` `nswer = 42\n ``.
The manifest remains identical to the minimal archive. The exact changed offset
and original/corrupt hashes are retained in `corruption.json`; execution rejects
before creating a runtime memfd or initializing Python.

The original 2,174 stdlib sources total 39,158,056 bytes. Together with the
pinned library, importer and frozen bundle they form 2,177 fixed resources.
The library remains 73,563,968 bytes with SHA-256
`42be968275d5be2d9e632ec9ef6790dd2c10f1d4a710ad1028fc2b687242f219`.
The frozen bundle is 139,523 bytes with SHA-256
`6a41fc38141d45c5197adfc1b0ee740c6244ea681742c205b8aa7b8449d865d7`.

The product executable is byte-identical across new and original product
captures; the thin probe is byte-identical across its five regression captures.
Product `readelf -W` output shows only `libm`, `libgcc_s` and `libc` dependencies
and no undefined `Py_*`/`_Py_*` imports. The four source-app C provenance receipts
and matching `nm` logs retain API4, 29 selected exports and the 240-byte table.
The C source/header, build script and Linux loader mechanisms are byte-identical
to merged `90c4a10`. Ten exact native ELF files are retained in the two
regression native captures, five images totaling 341,400 bytes per capture.

## Runtime and trace contract

Runtime containers are offline, unprivileged and read-only, without a workspace
mount. Working directories are empty, temporary paths unavailable and Python
environment variables poisoned. Producer tools, headers, preparers and build
intermediates are removed before tracing. Existing explicit-host installations
and native files remain immutable read-only prerequisites.

The new source-app policy binds the exact command, inherited streams, expected
diagnostics/status, typed source inventory, pinned provider/target and actual
canonical archive layout. Readiness must occur once after complete metadata
admission and before payload reads. Every declared resource verifies into owned
memory and the archive closes before runtime loading. Application modules resolve
only below `app/python/`; additional `app/` files are resources. Reserved runtime
and stdlib names, ambiguous layouts, bytecode/cache/native paths and inventory
limits reject during portable admission.

Complete source-app traces check archive byte coverage and descriptor lifetimes,
runtime write coverage and all required seals before mapping, the visible ELF
prefix, alias-header reads/fstat, guarded address reservation and positive-span
trimming, writable/BSS mappings, alias closure, RELRO protection, finalization
and runtime-image lifetime through exit. Failed forbidden filesystem/source
fallback, payload mutation and process/thread creation attempts also reject.
The initialized source-app workloads each exercise Python's observed 2,496-byte
initialization entropy request and one TID query; the pre-initialization
corrupt-source case exercises neither. Launcher/startup entropy calls remain
present in the complete traces. These new observations use a separate strict
checker and do not widen old policies.

Tracing uses `-s 256`: requested/returned write counts establish complete byte
coverage, and visible bytes establish the pinned ELF prefix. Truncated trace
strings cannot independently hash every runtime write byte. Complete archive
and library hashes are separately verified and bound by retained metadata.
The evidence claims these combined checks, rather than an untruncated dump of
all written payload bytes.

## Retention and replay

Root files retain the six source-app modes. `regressions/` retains the 42 older
modes, with shared validation logs under `regressions/validation/`.
`capture-summary.json`, fixture/trace summaries, source metadata, exact manifests,
commands, stdout/stderr/statuses, controls, provenance and complete gzip traces
are retained. Large upstream inputs, runtime archives and executables are
identified by hashes rather than copied. `source.sha256` covers 241 non-evidence
source files at implementation `d3ddac3`; documentation added after capture is
not part of that implementation snapshot. Root `SHA256SUMS` covers every retained
file except itself; the nested checksum file independently covers its subtree.

New source-app, original product and native-regression branches were recorded
during capture. Four older harnesses lacked branch receipts; their
`source-branch-at-retention.txt` files explicitly identify retention-time records.
All seven original captures record the same clean implementation revision and
empty source status/diff receipts.

For example, replay the source/resource workload using retained layout metadata
without its large archive:

```sh
python3 scripts/check-linux-python-source-app-trace.py \
  docs/evidence/pbs-linux-arm64-python-source-apps-2026-10-12/resources.trace.txt.gz \
  --mode resources \
  --stdout-file docs/evidence/pbs-linux-arm64-python-source-apps-2026-10-12/resources.stdout.txt \
  --stderr-file docs/evidence/pbs-linux-arm64-python-source-apps-2026-10-12/resources.stderr.txt \
  --metadata-file docs/evidence/pbs-linux-arm64-python-source-apps-2026-10-12/source-metadata.json \
  --archive-bytes 83088333
```

Live checks additionally use `--archive-file` to bind metadata to the complete
actual archive. `validation/compressed-replay-commands.json` records the six
new replay commands; `regressions/validation/retain-evidence.py` records the
42 regression replays and retention checks.

`validation/product-trace-audit.py`, commands and result JSON retain the
198-edit audit, including all six baselines, checker/script identities, actual
archive/manifest/trace/stream hashes and clean capture/current-source receipts.
To repeat it, copy that exact script to `target/python-source-app-trace-audit.py`
in a clean `d3ddac3` checkout with the original ignored capture/build directories
cached, then use its recorded command. The script resolves checkers from its
original location and `--require-clean-capture` checks source identity/status.
The 34-control and 30-control audit scripts and commands are also retained;
copy them to their recorded `target/` locations when repeating those commands.

## Scope

This admits bounded application-owned source/assets for the exact bundled
GNU Linux arm64 runtime profile. Entry bytes compile as a script in `__main__`,
with virtual filename/argv and no application arguments or `-m` entry. Uncaught
exceptions, including `SystemExit(None)` and `SystemExit(0)`, retain the existing
bounded message and status 1; full traceback rendering remains open.

General host-stdlib admission, wheels, extension-file discovery, path-required
packages, runtime-version selection, worker/thread support, other Python
ABIs/platforms and minimum-version acceptance remain open. The old host profile
still verifies only its fixed 69-source closure; hashing/descriptors do not
freeze mutable files. Trusted application/native code retains ordinary language
capabilities. These representative workloads do not certify every Python
package. G0/G1/G2 remain open. See
[decision 0017](../../decisions/0017-bundled-python-source-apps.md).
