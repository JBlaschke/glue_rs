# macOS host Python product harness (A7/A1)

Implementation contract, 15 October 2026. Continue from `108b4d0` on
`claude/distracted-wozniak-c2a76a`, the evidence inventory of
[decision 0032](0032-macos-python-product-route.md). That record served the
`stock-pbs-host-startup-macos` archive through `glue doctor` and `glue run`
on macOS arm64 but captured its receipts with an out-of-tree script and left
a checked-in product harness as the next macOS item. This is that harness,
in the spirit of `fixtures/python-runner/run-linux.sh` for the macOS cell.

## Scope

Add `fixtures/python-host-macos/run-product-macos.sh` and its exact checker
`check-product-results.py`. The harness reproduces the decision 0032 capture
from the repository root with the pinned install-only artifact and a new
output directory, and the checker compares every status, stdout and stderr
with the values that record documents. No runtime, profile, manifest or
launcher code changes: the product route remains one controlled startup
profile from one explicitly declared installation.

## Mechanism

Build time runs the default-feature workspace checks first, `cargo fmt`, the
workspace tests and Clippy with warnings denied, because they rebuild
`target/debug/glue` without Python. It then extracts the artifact into a
fresh read-only prefix without the three shipped encodings caches, builds
`glue-runner` with `python-pbs` and the probe with `pbs-bootstrap` against
that prefix's 264 verified headers, copies the launcher and the probe aside
before any further Cargo invocation, runs the feature-enabled runtime and
runner tests and Clippy, and builds a second feature-enabled launcher without
`GLUE_PYTHON_INCLUDE_DIR` in `target/no-boundary`. The six rejected control
installations come from the unchanged `prepare-controls.py`, and the probe's
`prepare-host-macos` writes the seven macOS archives.

The GNU Linux control is staged portably. The checked-in
[metadata fixture](../../fixtures/python-metadata/README.md) input is
prepared for the install-only host provider against the fixed absent prefix
`/nonexistent/pinned Linux Python`, and the copied launcher's `glue build`
packages it. Every input is checked in, so the archive is deterministic and
the checker pins its manifest and archive identities; nothing under
`target/` is required beyond the pinned artifact.

Every launcher receipt runs from an empty working directory through `env -i`
with `PATH=/usr/bin:/bin`, unavailable `HOME` and `TMPDIR`, the poisoned
`PYTHON*` variables of the startup fixture and no loader override except in
the `DYLD_LIBRARY_PATH` case. The harness records `doctor`, `inspect`,
`inspect --json`, `verify` and `run` for the valid archive, the six controls,
the GNU Linux declaration and the no-boundary launcher, plus `doctor` and
`run` under the loader override and both `doctor` summaries. The checker
recomputes each printed manifest digest from the `inspect --json` receipt and
requires the decoded manifest to equal the expected declaration. The
read-only installation is snapshotted before and after the receipts, and
`artifacts.sha256` inventories every retained file.

## Evidence and limits

On the observed macOS 26.7 cell the harness and checker pass: `doctor` Ready
and `run` PASS at status 0, the six installation rejections and the loader
override at status 1 with the probe's diagnostics under the `glue:` prefix,
the GNU Linux declaration and the no-boundary build at status 2, and the
1,807-entry installation snapshot unchanged. The harness observes one cell.
It does not supply a syscall trace, which still requires root `fs_usage`, and
it does not add installation discovery, native extensions, the complete
stdlib, bundled macOS Python or the distribution signing policy.
