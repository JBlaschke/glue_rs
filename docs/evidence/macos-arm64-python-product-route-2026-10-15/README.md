# macOS arm64 host Python product-route evidence

Captured on 15 October 2026 from clean feature commit `4b12b99` on
`claude/distracted-wozniak-c2a76a`, based on merged `28b0cab`.
[Decision 0032](../../decisions/0032-macos-python-product-route.md)
defines the step; the [fixture](../../../fixtures/python-host-macos/README.md)
describes the archives. This is the first `glue doctor` and `glue run` of a
Python profile on macOS.

The observed cell is macOS 26.7 (Darwin 25.6.0, build 25G229) on Apple
silicon with 16 KiB pages and `kern.osproductversion` 26.7, Rust 1.88.0 and
Apple clang 21.0.0 (`environment.txt`). The inputs are the ones the
[explicit-host startup evidence](../macos-arm64-python-host-2026-10-15/README.md)
left behind: the pinned PBS `20261009` CPython 3.13.16 aarch64-apple-darwin
install-only artifact (`artifact.sha256`), its read-only installation whose
`libpython3.13.dylib` is unchanged (`library.sha256`), and the seven archives
that fixture run prepared (`archives.sha256`): `success.glue` for the valid
installation and one archive for each rejected control installation. One
GNU Linux arm64 declaration, the `python.stripped-host` metadata archive the
stripped-host fixture prepared on this Mac (`linux-declaration.archive.sha256`,
`linux-declaration.inspect.stdout.txt`), serves as the cross-cell control; its
declared installation does not exist here and is never opened.

## Build, tests and lints

The default-feature workspace checks ran first, so that the launcher built
afterwards with Python is the one every receipt uses: `cargo fmt --all --
--check` (`fmt.txt`, empty), `cargo test --workspace --locked`
(`workspace-tests.txt`, 514 passed) and `cargo clippy --workspace
--all-targets --locked -- -D warnings` (`workspace-clippy.txt`). Then, with
`GLUE_PYTHON_INCLUDE_DIR` naming the installation's `include/python3.13`,
`cargo clean -p glue-runtime-python -p glue-runner -p
glue-python-bootstrap-probe` preceded `cargo build --locked -p glue-runner -p
glue-python-bootstrap-probe --features
glue-runner/python-pbs,glue-python-bootstrap-probe/pbs-bootstrap`
(`build.txt`). `boundary-provenance.txt` records the macOS arm64 cell, the
compiled boundary and the 264 verified headers. The feature-enabled crate
suite passes 177 tests including the macOS cell readiness test and the C
boundary self-tests (`tests.txt`), the runner passes 23 CLI tests with
`python-pbs` (`runner-tests.txt`), and Clippy with warnings denied is clean
for the three feature-enabled crates (`clippy.txt`). The launcher was copied
to `target/product-route/glue` before any receipt; it links only libSystem and
libiconv (`launcher.dependencies.txt`), is ad-hoc signed
(`launcher.codesign.txt`) and has the identity in `launcher.sha256`.

A second feature-enabled build without `GLUE_PYTHON_INCLUDE_DIR`, in its own
target directory, records `boundary_compiled=false`
(`no-boundary.build.txt`, `no-boundary.provenance.txt`,
`no-boundary.launcher.sha256`).

## Receipts

`doctor` ran with the ordinary environment. Every `run` used the fixture's
environment: `env -i` with `PATH=/usr/bin:/bin`, unavailable `HOME` and
`TMPDIR`, poisoned `PYTHONPATH`, `PYTHONHOME`, `PYTHONPYCACHEPREFIX`,
`PYTHONIOENCODING`, `PYTHONUTF8`, `PYTHONSAFEPATH` and
`PYTHONDONTWRITEBYTECODE`, and no loader overrides except in the
`loader-override` case.

| Case | Status | Observation |
| --- | --- | --- |
| `doctor-summary` | 0 | `Python: controlled CPython 3.13.16 / PBS 20261009 profiles; explicit macOS arm64 host startup execution only` |
| `success.inspect`, `success.verify` | 0 | one application resource of 1,572 bytes verifies |
| `success.doctor` | 0 | `Ready: controlled explicit-host macOS arm64 Python startup build/target prerequisites, CPython 3.13.16 / PBS 20261009` |
| `success.run` | 0 | `PASS Python=3.13.16 encodings=installed math=built-in ssl=built-in answer=42 openssl=OpenSSL 3.5.9 29 Sep 2026` |
| `loader-override.run` | 1 | `DYLD_LIBRARY_PATH` rejected in preflight |
| `wrong-library.run` | 1 | library identity mismatch before loading |
| `wrong-stdlib.run` | 1 | `encodings/utf_8.py` identity mismatch before loading |
| `missing-encodings.run` | 1 | missing startup source rejected before loading |
| `symlink-stdlib.run` | 1 | symlinked stdlib directory rejected before loading |
| `missing-library.run` | 1 | missing library rejected before loading |
| `cached-bytecode.run` | 1 | startup bytecode cache rejected before loading |
| `<control>.doctor` (six) | 0 | `Ready`; readiness checks the declaration and the host, not the installation |
| `linux-declaration.doctor`, `linux-declaration.run` | 2 | `the pinned Python target requires macOS arm64` |
| `no-boundary.doctor-summary` | 0 | `declaration validation only; no execution boundary is compiled` |
| `no-boundary.doctor`, `no-boundary.run` | 2 | `the pinned Python boundary is not compiled; macOS arm64 builds require GLUE_PYTHON_INCLUDE_DIR to name the verified install-only header tree` |

Every rejection diagnostic is the probe's, under the `glue:` prefix, and
every rejected `run` leaves stdout empty. The six rejected installations are
reported ready by `doctor` because readiness never opens host files; `run`
verifies the installation before loading, as the fixture documents.

The installation snapshot (`installation.before.txt`,
`installation.after.txt`: mode, owner, size, mtime and ctime of all 1,807
entries) is identical after all runs, and the only cache present afterwards
is the deliberate `cached-bytecode` control (`caches-after.txt`).
`source-status.txt` names only this evidence directory, which was untracked
while the receipts were written. No syscall or filesystem tracer is available
to an unprivileged user on this cell; `tracing.txt` records that and the root
`fs_usage` command that would supply a trace.

`artifacts.sha256` covers every retained file except itself. Under
[decision 0030](../../decisions/0030-evidence-retention.md) the receipts
beyond this README and the inventories are to be published as a release asset
and restored with `scripts/fetch-evidence.sh`; `bundle.json` records that
publication once it has happened.
