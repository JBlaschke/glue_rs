# macOS arm64 host Python product harness evidence

Captured on 15 October 2026 from clean feature commit `f69284e` on
`claude/relaxed-torvalds-a9df39`, based on `108b4d0` of
`claude/distracted-wozniak-c2a76a`.
[Decision 0034](../../decisions/0034-macos-python-product-harness.md)
defines the step; the [fixture](../../../fixtures/python-host-macos/README.md)
describes the harness. This is the first capture of the product route of
[decision 0032](../../decisions/0032-macos-python-product-route.md) by the
checked-in harness rather than an out-of-tree script. It was run from the
repository root, with the pinned artifact in `target/pbs-macos/`, as

```sh
sh fixtures/python-host-macos/run-product-macos.sh target/python-host-macos-product-validation
```

`commands.sh` is the harness as run; `check-product-results.py` passed
before `artifacts.sha256` was written, and this directory is the harness's
`evidence` directory copied unchanged.

The observed cell is macOS 26.7 (Darwin 25.6.0, build 25G229) on Apple
silicon with 16 KiB pages and `kern.osproductversion` 26.7, Rust 1.88.0 and
Apple clang 21.0.0 (`environment.txt`). The input is the pinned PBS
`20261009` CPython 3.13.16 aarch64-apple-darwin install-only artifact
(`artifact.sha256`), extracted into a fresh read-only prefix containing a
space, whose `libpython3.13.dylib` is unchanged (`library.sha256`,
`library.dependencies.txt`, `library.codesign.txt`) and whose three shipped
encodings caches were removed (`shipped-caches.txt`). `source-status.txt` is
empty: the tree was clean when the capture began and the output directory
lies under the ignored `target/`; the only edit made while it ran was the
cleanup note in the fixture README, which lands with this inventory.

## Build, tests and lints

The default-feature workspace checks ran first, so that the launcher built
afterwards with Python is the one every receipt uses: `cargo fmt --all --
--check` (`fmt.txt`, empty), `cargo test --workspace --locked`
(`workspace-tests.txt`, 514 passed) and `cargo clippy --workspace
--all-targets --locked -- -D warnings` (`workspace-clippy.txt`). Then, with
`GLUE_PYTHON_INCLUDE_DIR` naming the installation's `include/python3.13`,
`cargo clean` of the three Python crates (`clean.txt`) preceded `cargo build
--locked -p glue-runner -p glue-python-bootstrap-probe --features
glue-runner/python-pbs,glue-python-bootstrap-probe/pbs-bootstrap`
(`build.txt`). `boundary-provenance.txt` records the macOS arm64 cell, the
compiled boundary and the 264 verified headers. The launcher and the probe
were copied aside at once (`launcher.sha256`); the launcher links only
libSystem and libiconv (`launcher.dependencies.txt`) and is ad-hoc signed
(`launcher.codesign.txt`). The feature-enabled crate suite passes 177 tests
including the macOS cell readiness test and the C boundary self-tests
(`tests.txt`), the runner passes 23 CLI tests with `python-pbs`
(`runner-tests.txt`), and Clippy with warnings denied is clean for the three
feature-enabled crates (`clippy.txt`). A second feature-enabled build without
`GLUE_PYTHON_INCLUDE_DIR`, in `target/no-boundary`, records
`boundary_compiled=false` (`no-boundary.build.txt`,
`no-boundary.provenance.txt`, `no-boundary.launcher.sha256`).

## Archives

`prepare-controls.py` derived the six rejected control installations
(`controls.stdout.txt`), and the copied probe prepared the valid archive and
one archive per control (`<mode>.prepare.*`, `archives.sha256`). The GNU
Linux arm64 control is the install-only host metadata application of the
[metadata fixture](../../../fixtures/python-metadata/README.md), staged from
its checked-in input against the absent prefix `/nonexistent/pinned Linux
Python` (`linux-declaration.stage.*`) and packaged by the copied launcher's
`glue build` (`linux-declaration.build.stdout.txt`: 10 resources, 13,485
archive bytes, 21,770 uncompressed bytes). Its identity
(`linux-declaration.archive.sha256`) is the one the checker pins, so the
archive is reproducible from the repository alone; its declared installation
does not exist here and is never opened.

## Receipts

Every receipt ran from the empty working directory through `env -i` with
`PATH=/usr/bin:/bin`, unavailable `HOME` and `TMPDIR`, poisoned
`PYTHONPATH`, `PYTHONHOME`, `PYTHONPYCACHEPREFIX`, `PYTHONIOENCODING`,
`PYTHONUTF8`, `PYTHONSAFEPATH` and `PYTHONDONTWRITEBYTECODE`, and no loader
override except in the two `loader-override` cases. `<case>.inspect-json`
holds `inspect --json`; the checker recomputes the manifest digest that
`<case>.inspect` prints from it and compares the decoded manifest with the
expected declaration.

| Case | Status | Observation |
| --- | --- | --- |
| `doctor-summary` | 0 | `Python: controlled CPython 3.13.16 / PBS 20261009 profiles; explicit macOS arm64 host startup execution only` |
| `success.inspect`, `success.verify` | 0 | one application resource of 1,572 bytes verifies |
| `success.doctor` | 0 | `Ready: controlled explicit-host macOS arm64 Python startup build/target prerequisites, CPython 3.13.16 / PBS 20261009` |
| `success.run` | 0 | `PASS Python=3.13.16 encodings=installed math=built-in ssl=built-in answer=42 openssl=OpenSSL 3.5.9 29 Sep 2026` |
| `<control>.inspect`, `<control>.verify` (six) | 0 | the control's declared paths; the same application resource verifies |
| `<control>.doctor` (six) | 0 | `Ready`; readiness checks the declaration and the host, not the installation |
| `wrong-library.run` | 1 | library identity mismatch before loading |
| `wrong-stdlib.run` | 1 | `encodings/utf_8.py` identity mismatch before loading |
| `missing-encodings.run` | 1 | missing startup source rejected before loading |
| `symlink-stdlib.run` | 1 | symlinked stdlib directory rejected before loading |
| `missing-library.run` | 1 | missing library rejected before loading |
| `cached-bytecode.run` | 1 | startup bytecode cache rejected before loading |
| `loader-override.doctor` | 0 | `Ready`; readiness does not inspect the loader environment |
| `loader-override.run` | 1 | `DYLD_LIBRARY_PATH` rejected in preflight |
| `linux-declaration.inspect`, `linux-declaration.verify` | 0 | the pinned GNU Linux arm64 declaration; ten resources verify |
| `linux-declaration.doctor`, `linux-declaration.run` | 2 | `the pinned Python target requires macOS arm64` |
| `no-boundary.doctor-summary` | 0 | `declaration validation only; no execution boundary is compiled` |
| `no-boundary.inspect`, `no-boundary.verify` | 0 | the same success archive and digest as the compiled launcher reports |
| `no-boundary.doctor`, `no-boundary.run` | 2 | `the pinned Python boundary is not compiled; macOS arm64 builds require GLUE_PYTHON_INCLUDE_DIR to name the verified install-only header tree` |

Every rejection diagnostic is the probe's, under the `glue:` prefix, and
every rejected or unsupported `run` leaves stdout empty.

The installation snapshot (`installation.before.txt`,
`installation.after.txt`: mode, owner, size, mtime and ctime of all 1,807
entries) is identical after all receipts, the empty working directory stayed
empty (`working-directory.txt`), and the only cache present afterwards is
the deliberate `cached-bytecode` control (`caches-after.txt`). No syscall or
filesystem tracer is available to an unprivileged user on this cell;
`tracing.txt` records that and the root `fs_usage` command that would supply
a trace.

`artifacts.sha256` covers every retained file except itself. Under
[decision 0030](../../decisions/0030-evidence-retention.md) the receipts
beyond this README and the inventories are to be published as a release asset
and restored with `scripts/fetch-evidence.sh`; `bundle.json` records that
publication once it has happened.
