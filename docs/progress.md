# Implementation progress

The baseline is `8d474be` (`PLAN.md`). Feature work is stacked; `main` remains at
the baseline until reviewed.

| Step | Branch | State | Evidence |
| --- | --- | --- | --- |
| A0 experimental contracts and Rust workspace | `codex/a0-contracts` / `96e188b` | Implemented | 20 contract tests on macOS and Linux arm64 / Rust 1.88.0; format and Clippy clean on macOS |
| A4 archive/resource foundation | `codex/a4-archive-resources` / `c4b307f` (stacked on A0) | Implemented | 56 tests on macOS and Linux arm64; deterministic ZIP64, corrupt/unsupported input rejection and bounded resources |
| Packaging/inspection CLI scaffold | `codex/packaging-cli` / `4581386` (stacked on A4) | Implemented | 76 tests on macOS and Linux arm64; explicit-inventory builder and read-only CLI commands; format/Clippy clean |
| A3 Linux memfd fixture | `codex/a3-linux-memfd-probe` (stacked on CLI) | Controlled spike | Sealed anonymous shared-library loading; ordinary-loader comparison and full syscall evidence described in the probe decision |

## Gate status

G0 and G1 are open. The Linux memfd spike is separate from the product runner.
No general native backend, runtime bootstrap, approved system-library profile,
signed deployment probe or four-platform execution evidence exists yet.
The archive and manifest are version 0. Candidate runtime sources are recorded
in `docs/decisions/0001-foundation-contract.md`; exact release pins are pending
the platform experiments. Later gates remain pending.

## Local test environments

The initial host is macOS arm64. Rust 1.88.0 is installed through Rustup; its
toolchain directory was placed first in PATH to avoid the Homebrew Rust 1.99
executables. `scripts/test-linux.sh` vendors the locked dependencies and runs
tests offline in a read-only Podman container with build outputs in memory.
Its default Linux arm64 image is Rust 1.88.0 / Debian bookworm, pinned by digest
`sha256:93717e495a1029ba94b9b4a5768cf14d5376077d26cfad3354cbe70be27c2b1d`.
This cell does not supply Linux x86_64 execution evidence.

The synthetic resource fixture produces 1,469 archive bytes for 57 uncompressed
resource bytes, with SHA-256
`e2fa199105c8cffde55ec2dd403f27d3e1dc334c399aa334afba133c64be7d85`.
It is a packaging/resource fixture and contains no actual Lua runtime.

## Next critical-path assignments

Run A1 (signed macOS arm64 mapping), A2 (Windows PE), and A3 (Linux/FreeBSD ELF)
with actual runtime startup, extending the initial Linux memfd fixture. Establish
the FreeBSD bundled Python/Node producer and inspect pinned PBS artifacts. Publish capability
evidence before implementing broad native coordination or language adapters.
