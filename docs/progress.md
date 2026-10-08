# Implementation progress

The baseline is `8d474be` (`PLAN.md`). Feature work is stacked; `main` remains at
the baseline until reviewed.

| Step | Branch | State | Evidence |
| --- | --- | --- | --- |
| A0 experimental contracts and Rust workspace | `codex/a0-contracts` / `96e188b` | Implemented | 20 contract tests on macOS and Linux arm64 / Rust 1.88.0; format and Clippy clean on macOS |
| A4 archive/resource foundation | `codex/a4-archive-resources` / `c4b307f` (stacked on A0) | Implemented | 56 tests on macOS and Linux arm64; deterministic ZIP64, corrupt/unsupported input rejection and bounded resources |
| Packaging/inspection CLI scaffold | `codex/packaging-cli` / `4581386` (stacked on A4) | Implemented | 76 tests on macOS and Linux arm64; explicit-inventory builder and read-only CLI commands; format/Clippy clean |
| A3 Linux memfd fixture | `codex/a3-linux-memfd-probe` / `447a339` (stacked on CLI) | Controlled spike | 80 Rust tests on macOS/Linux arm64, 15 trace-policy tests; Clippy clean on both; native ordinary-loader comparison and full syscall checks pass |
| A6 linked Lua source slice | Feature branch, commit pending | Experimental implementation | macOS arm64 CLI fixture builds, reports readiness and prints the expected result; 111 Rust tests and workspace Clippy pass; current Linux execution/trace evidence pending |

## Gate status

G0, G1 and G2 are open. Linked official Lua 5.4.9 is now an explicit source-only
execution profile; it is partial A6/G2 work, not native-Lua or four-OS acceptance.
The Linux memfd spike remains separate from the product runner. General native
backends, archived/host runtime bootstraps, Python/Node execution, workers,
approved system-library profiles and signed deployment remain pending.
The archive and manifest are version 0. Lua is pinned to `mlua` 0.12.2 and
`lua-src` 551.0.2 with int64/float64 configuration; other runtime release pins
still depend on platform experiments. The logical Lua build ID is not a compiler
configuration or artifact hash. See [the profile decision](decisions/0005-linked-lua-source-profile.md).

Lua 5.5.1 support is planned next on a separate feature branch, using mutually
exclusive compiled `lua54` (default) and `lua55` profiles with exact manifest
identities. Supporting both versions through separate launchers does not provide
simultaneous multi-runtime acquisition or worker execution.

The maintained `mlua` API protects Lua calls and catches callback panics, but
upstream Lua longjmp may cross its Drop-free Rust protected-call thunk. This
does not satisfy PLAN.md's literal C-only/no-Rust-frame boundary. A shim or an
explicitly accepted boundary contract remains a release requirement.

## Local test environments

The initial host is macOS arm64. Rust 1.88.0 is installed through Rustup; its
toolchain directory was placed first in PATH to avoid the Homebrew Rust 1.99
executables. `scripts/test-linux.sh` vendors the locked dependencies and runs
tests offline in a read-only Podman container with build outputs in memory.
Its default Linux arm64 image is Rust 1.88.0 / Debian bookworm, pinned by digest
`sha256:93717e495a1029ba94b9b4a5768cf14d5376077d26cfad3354cbe70be27c2b1d`.
This cell does not supply Linux x86_64 execution evidence.

The native fixture ran from clean commit `447a339` on Linux
`7.1.4-200.fc44.aarch64`, glibc `2.36-9+deb12u10`, GCC 12.2.0, 4 KiB pages and
`vm.memfd_noexec=0`. It returned 42/7/1 for function/data/constructor observations
with ordinary loading and archive memfds, and passed the full trace checker.
The [evidence record](evidence/linux-arm64-memfd-2026-10-08/README.md) retains the
commands, image identity, source and artifact hashes, test logs and raw trace.
The [probe decision](decisions/0004-linux-memfd-probe.md) lists its limits.

The synthetic resource fixture produces 1,469 archive bytes for 57 uncompressed
resource bytes, with SHA-256
`e2fa199105c8cffde55ec2dd403f27d3e1dc334c399aa334afba133c64be7d85`.
It is a packaging/resource fixture and contains no actual Lua runtime.
Its selected `host` provider still returns status 2; the linked runtime is never
used as a fallback. Separate [linked fixtures](../fixtures/lua-linked/README.md)
declare the exact source/build/ABI and macOS arm64 or GNU Linux arm64 target.
The current macOS arm64 fixture was built through the CLI, reported ready through
`doctor`, and printed its expected nested-import/asset result. The complete
workspace passed 111 Rust tests and Clippy with warnings denied on this host.
Current Linux execution/trace validation is pending; its eventual evidence will
remain separate from the historical native probe observation above.

## Next critical-path assignments

Complete and record the linked-source CLI/relocation/trace checks, and resolve
its error-boundary contract before release. Continue A1 (signed macOS arm64
mapping), A2 (Windows PE) and A3 (Linux/FreeBSD ELF) with actual runtime startup.
Establish the FreeBSD bundled Python/Node producer and inspect pinned PBS
artifacts. G2 also requires a real native Lua module; the source-only slice and
the separate memfd fixture do not meet that acceptance criterion together.
