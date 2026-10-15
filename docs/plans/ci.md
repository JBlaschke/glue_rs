# Portable checks

`.github/workflows/portable.yml` runs baseline workspace, selectable Lua55 and
Python packaging suites separately on native Linux x86_64, Linux arm64 and
macOS arm64. `scripts/ci-portable.sh` places Rust 1.88.0's own bin directory first,
checks Rust/Clippy versions and the actual native target, then uses locked Cargo
inputs. `--all-features` is intentionally absent: Lua families cannot coexist.

Runner labels follow the [GitHub-hosted runner reference](https://docs.github.com/en/actions/reference/runners/github-hosted-runners).
Checkout is pinned to a commit. Build prerequisites are Rustup, a C toolchain,
Git and ripgrep. Native collector tests use readelf on Linux and otool/codesign
on Mac; hosted runner images provide these. No evidence downloads, application
package installation, signing secrets or release publication occur here.

Portable green checks alone do not close M2. Product runtime/version tests,
whole-process syscall tracing, immutable/offline execution and final deployment
signing each require V02/R02 receipts. Platform-gated legacy tests remain visible
in test output; their unexecuted target cells are not inferred from another host.
Hosted jobs have not executed merely because this configuration is committed.
