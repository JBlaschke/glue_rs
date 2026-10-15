# Python compatibility evidence (P05)

The public `glue build python` command was executed against the following covering
matrix on native hardware. Each successful V02 receipt compares exit/stdout/stderr
with the selected stock interpreter, relocates the distribution, removes the
original input prefix, disables payload writes, empties the language-tool PATH and
uses an unrelated cwd with unusable HOME/temp/cache. Linux rows also pass the R02
complete descendant syscall trace and injected extraction-oracle controls.

| Native target | Exact CPython | Origin / environment | Executed corpus and input route |
| --- | --- | --- | --- |
| macOS arm64 | 3.12.14 | Supplied installation / ordinary `venv --copies`, including pip | Source, namespace resources, metadata/plugins, stdlib math/ssl, file entry |
| macOS arm64 | 3.13.16 | PBS / ordinary copied venv, including pip | Installed package console-script entry |
| macOS arm64 | 3.14.5 | PBS / uv 0.12.23 venv | Source file/module and dependency-heavy native corpus |
| macOS arm64 | 3.15.0b1 | PBS / ordinary copied venv, including pip | Source file corpus, archived stdlib including frozen encodings |
| macOS arm64 | 3.14.8 | Homebrew framework / supplied environment | Source, explicit dependency normalization, real stock interpreter |
| Linux arm64 | 3.13.16 | PBS / ordinary copied venv, including pip | Source file, module and console-script entries |
| Linux arm64 | 3.13.16 | PBS / supplied native site trees | Scientific C/C++/Rust/FFI corpus; independent stock PEP 489 lifecycle inputs |
| Linux arm64 | 3.13.16 | PBS archive override | Full `.tar.zst`, install_only and install_only_stripped `.tar.gz` inputs |
| Linux arm64 | 3.13.16 | PBS / existing cp311-abi3 wheel | cryptography 50.0.2 SHA-256 and Ed25519 operations with CFFI 2.1.1 |
| Linux arm64 | 3.14.8 | Independent cached manylinux CPython | Source corpus; existing OpenSSL 1.1/secondary libraries supplied explicitly |
| Linux x86_64 | 3.12.15 | PBS / ordinary copied venv | Source file, module, console-script and scientific/native corpus |
| Linux x86_64 | 3.13.16 | PBS / ordinary copied venv | Source file, module, console-script and scientific/native corpus |
| Linux x86_64 | 3.14.8 | Independent conda-forge installation / ordinary copied venv | Source file, module, console-script and scientific/native corpus; matching pinned libstdc++/libgcc closure |

Native hosted [run 38800548172](https://github.com/JBlaschke/glue_rs/actions/runs/38800548172)
on [source e3962701](https://github.com/JBlaschke/glue_rs/commit/e3962701f558c287515508c97df4679e08d64ed2)
passed all 24 language acceptance cases, including the twelve Python x86_64
cases above, and all five reviewed R03 budgets in enforcement mode. Independent
replay checked every acceptance receipt, all fifteen benchmark-variant
receipts/traces, controls and all 990 rank results. Structure, size, I/O, FD and
scaling limits apply across hosts; time/RSS retain the recorded host scope.
These runs use the explicit
[`traceable-native-syscalls-v1` CI policy](decisions/mvp-v02-ci-trace-environment.md):
asynchronous kernel I/O returns ENOSYS throughout stock references, packaged
processes, controls and ranks so the strict syscall oracle can observe writes.
Unrestricted ring-enabled hosts are outside this evidence.

The native corpus uses NumPy BLAS/LAPACK, contourpy's translated C++ exception,
pydantic_core Rust validation errors, stock extension caching, ctypes and CFFI,
and an independent secondary C library with TLS/pthreads. Exact prebuilt package
versions differ between Linux 3.13 and macOS 3.14 without product allowlist changes.
P04 records those versions and original-byte comparisons in `python-native.md`.
No Python build or run command installs a package, fetches a runtime or compiles a
module. Explicit wheel test provisioning is separate and records upstream SHA-256.

A real uv environment contains executable `_virtualenv.pth`. Default ingestion
correctly diagnoses that hook. The uv cases explicitly request
`--prune app/site/0/_virtualenv.pth`, retaining the omission report and all original
input bytes. No executable `.pth` is silently admitted. The stock references also
use `-S`, matching the declared isolated application environment.

The 3.14.5 and 3.14.8 macOS source runs used the same included glue SHA-256
`e329ea18ac66cbcae1e9443795f7e3a89f6dab964c8bbe7143722dcfc7cfe269` with
different runtime executable digests. This demonstrates an additional patch
runtime without recompiling glue. These runs use the real framework executable at standalone `runtime/bin/Python`,
with every final Mach-O passing strict development-policy verification. A later
metadata-only lock correction records original runtime-native dependency hashes;
its focused regression rejects a changed runtime library before publication and
excludes application-only native dependencies from the runtime identity.

Wrong `--python 3.12` against a 3.13 environment returns JSON
`runtime_abi_mismatch`. Selecting the existing free-threaded 3.15 runtime with
`--python 3.15` returns `unsupported_capability`. Both leave output absent.
Extension suffix and WHEEL ABI mismatches reject before publication. Valid abi3
admission follows the supplied wheel's minimum CPython version, with no arbitrary
future-version ceiling; this does not prove every future ABI or wheel compatible.

## Reproduce through the public CLI

```sh
glue build python ./project --env ./environment --entry main.py --output ./dist
glue build python ./project --env ./environment --module main --output ./module-dist
glue build python ./project --env ./environment --console-script sample --output ./console-dist
# Existing native inputs / paths needing explicit normalization:
glue build python ./project --env ./environment --entry main.py \
  --normalize-native-paths --native-search /supplied/libraries --output ./native-dist
# Existing PBS archive override; never downloaded by this command:
glue build python ./project --env ./environment --entry main.py \
  --runtime /supplied/cpython-install_only.tar.gz \
  --normalize-native-paths --native-search /supplied/libraries --output ./archive-dist
./dist/glue run ./dist/app.glue -- 'argument café'
```

`fixtures/mvp/cases/python-*.json` drive the shared V02 harness. Supply
`GLUE_MVP_GLUE`, `GLUE_MVP_PYTHON_ROOT`, `GLUE_MVP_PYTHON_RELATIVE` (for example
`bin/python3.13`), `GLUE_MVP_PYTHON_TOOL` and `GLUE_MVP_PYTHON_ENV_KIND`
(`ordinary`, `uv` or `descriptor`). uv additionally uses the supplied `GLUE_MVP_UV`.
Native cases use `GLUE_MVP_PYTHON_SITE` and `GLUE_MVP_PYTHON_SECONDARY`.
Normalized cases use `GLUE_MVP_NATIVE_SEARCH`; Linux requires independently
provided patchelf through `GLUE_PATCHELF`. The archive case also requires
`GLUE_MVP_PYTHON_ARCHIVE`.

```sh
scripts/run-mvp.sh --case python-source-normalized \
  --target aarch64-unknown-linux-gnu --output /new/evidence/source
scripts/check-mvp-results.py /new/evidence/source/receipt.json
```

Run Linux in a native `--network none` container with `strace`, SYS_PTRACE and
an appropriate seccomp policy, and set `GLUE_MVP_TRACE=required`. macOS harness
execution needs permission to launch its own sandbox so network denial is real.
`stage-runtime.py` makes an explicit independent execution fixture when an input
installation contains development/metadata aliases that cannot survive copying;
it reports exclusions and contained link rewrites and never edits native bytes.
Framework test preparation reports its initial copied-interpreter core-edge edit;
product normalization is separately recorded in the build report.

## Evidence locations and remaining gates

Raw evidence remains outside Git under decision 0030. Successful shared receipts:

- `/private/tmp/glue-python-v02-mac{312-source,313-console,314-uv-native,315-source}-offline/receipt.json`.
- `/private/tmp/glue-python-v02-mac{314-source,314-module,3148-framework}-standalone-release/receipt.json`.
- `/private/tmp/glue-python-v02-linux-evidence/linux313-{source,module,console}-ordinary/receipt.json`.
- `/private/tmp/glue-python-v02-linux-evidence/linux313-native/receipt.json`.
- `/private/tmp/glue-python-v02-linux-evidence/linux313-archive-{install_only-bounded,install_only_stripped,pgo-lto-full-bounded}/receipt.json`.
- `/private/tmp/glue-python-v02-linux-evidence/linux313-abi3-complete/receipt.json`.
- `/private/tmp/glue-python-v02-linux-evidence/linux3148-nonpbs/receipt.json`.
- `/private/tmp/glue-native-x86-evidence-38800548172/cases/python-{3.12.15,3.13.16,3.14.8}-{source,module,console,native}/receipt.json`.

The final hosted evidence is retained in
[artifact 12005186009](https://github.com/JBlaschke/glue_rs/actions/runs/38800548172/artifacts/12005186009),
ZIP SHA256 `c1cc519d76e73888ed0339714deec1e97eea816c1f8861ab551da4579644e7a4`.
Its current expiry is 29 October 2026; durable evidence publication remains open.
The local independent replay summary is
`/private/tmp/glue-native-x86-evidence-38800548172/independent-replay.json`.
The supplied 3.14 runtime's complete prebuilt package lock and preparation
provenance are described in
[`conda-runtime.md`](../fixtures/mvp/python-matrix/conda-runtime.md).

Focused PEP 489 evidence is `/private/tmp/glue-python-lifecycle-linux313.json`;
CLI negative cases are `/private/tmp/glue-python-cli-negatives/*.json`.
Runtime-native rebuild-lock regression evidence is
`/private/tmp/glue-python-runtime-native-lock.json`. The derived 16-cell table is
`/private/tmp/glue-python-matrix-final/matrix.md` with its verified JSON index;
the twelve hosted x86_64 cases are indexed separately in the final run above.
The shared receipts retain raw streams, inventories, exact runtime/launcher
identities and Linux syscall evidence. Discarded copies of quarantined original
inputs are reproducible from their recorded inventories; source runtime and wheel
inputs remain available separately.

`python-matrix/matrix.py --cell NAME=/receipt.json --output NEWDIR` rechecks
receipts and derives a table. It reports only the listed cells. Global M2
acceptance belongs to R04 and requires the external version/provider/native/input
ledger, complete target coverage, R02 signing/tracing and release policy.
The complete Darwin process-tree decoder and extraction oracle remain
unimplemented and unvalidated. Mac R02 acceptance, its full corpus/controls/cost
budgets and M2 remain open. Durable evidence assets have not been published.
Public Developer ID/notarization remains a later release gate; strict development
verification does not establish that approval. Tcl/Tk script resources and general
multiprocessing spawn are outside this executed corpus and retain explicit
capability limitations.
