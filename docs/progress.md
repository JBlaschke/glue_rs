# Implementation progress

The earlier feature work and evidence were merged into `main` at `a596305`.
Further implementation continues on separate feature branches.

| Step | Branch | State | Evidence |
| --- | --- | --- | --- |
| A0 experimental contracts and Rust workspace | `codex/a0-contracts` / `96e188b` | Implemented | 20 contract tests on macOS and Linux arm64 / Rust 1.88.0; format and Clippy clean on macOS |
| A4 archive/resource foundation | `codex/a4-archive-resources` / `c4b307f` (stacked on A0) | Implemented | 56 tests on macOS and Linux arm64; deterministic ZIP64, corrupt/unsupported input rejection and bounded resources |
| Packaging/inspection CLI scaffold | `codex/packaging-cli` / `4581386` (stacked on A4) | Implemented | 76 tests on macOS and Linux arm64; explicit-inventory builder and read-only CLI commands; format/Clippy clean |
| A3 Linux memfd fixture | `codex/a3-linux-memfd-probe` / `447a339` (stacked on CLI) | Controlled spike | 80 Rust tests on macOS/Linux arm64, 15 trace-policy tests; Clippy clean on both; native ordinary-loader comparison and full syscall checks pass |
| A6 linked Lua 5.4 source slice | `codex/a6-lua-linked-execution` / `03303d7` | Experimental implementation | macOS arm64 CLI fixture builds, reports readiness and prints the expected result; 111 Rust tests and workspace Clippy pass; Linux execution/trace evidence pending at this baseline |
| A6 Lua 5.5 compiled profile | `codex/a6-lua55-profile` / `cb88d7d` (stacked on `03303d7`) | Experimental implementation | Separate exact Lua 5.4.9/5.5.1 compiled profiles; macOS arm64 CLI execution and opposite-version rejection pass |
| A6 linked Lua Linux validation | `codex/a6-lua-linux-validation` / `8b6eb1f` (stacked on `cb88d7d`; evidence bundle follows) | Controlled observation | macOS/Linux arm64: 118/119 Rust tests for `lua54`/`lua55`, all-target Clippy clean for both; both relocated Linux profiles exit 0 with exact output and full trace checks; 27 Python policy tests pass |
| A6 C-owned Lua error boundary | `codex/a6-lua-c-boundary` / `ee7c9d3` (from merged `db2c271`) | Experimental implementation | macOS/Linux arm64: 142/143 Rust tests for `lua54`/`lua55`, Clippy clean for both; 50/51 optimized macOS boundary tests; both relocated Linux fixtures pass exact output and full no-extraction trace checks |
| A5/A6 Linux native Lua closure | `codex/a6-linux-native-lua` / `3a24833`, fixture cleanup `fb61e5e` (from merged `7853282`) | Experimental implementation; controlled observation | Mac/Linux source workspaces: 181/182 tests; GNU Linux native workspaces: 178/179; 37 portable native tests and 54 Python policy tests; Clippy clean for all profiles; both Lua versions match ordinary loading and pass complete two-memfd/no-payload-write traces; twelve ELF rejection traces pass before any memfd attempt |
| A1 signed macOS arm64 Mach-O probe | `codex/a1-macos-macho-probe` / `346b2f0` (from merged `a596305`) | Controlled signed observation; acceptance evidence incomplete | 31 portable/optimized parser tests; 212/213 source workspace tests for Lua 5.4/5.5 and Clippy on Mac/Linux; ad-hoc hardened-runtime/allow-jit debug and optimized launchers match ordinary loading; fourteen native rejections, four signing controls and two memory-policy controls pass; full trace and distribution signing remain open |

## Gate status

G0, G1 and G2 are open. Linked official Lua 5.4.9 and 5.5.1 have explicit,
version-specific source-only profiles and optional GNU Linux arm64 native
profiles. This is partial A5/A6/G2 work; four-OS acceptance remains open.
The original Linux memfd spike remains a separate historical observation.
The product now integrates a controlled native Lua closure. General native
backends, archived/host runtime bootstraps, Python/Node execution, workers,
approved system-library profiles and signed deployment remain pending.
The archive and manifest are version 0. Lua is pinned to `lua-src` 551.0.2
with int64/float64 configuration; other runtime release pins
still depend on platform experiments. The logical Lua build ID is not a compiler
configuration or artifact hash. See [the base profile decision](decisions/0005-linked-lua-source-profile.md)
and [version selection](decisions/0006-versioned-linked-lua-profiles.md).

The profile branch added mutually exclusive compiled `lua54` (default) and
`lua55` profiles with exact manifest identities. Supporting both versions through
separate launchers does not provide simultaneous multi-runtime acquisition or
worker execution.

The new C boundary replaces `mlua` in the source adapter. C owns the Lua state,
allocator, protected execution and result construction. Rust only serves archive
requests and catches callback panics; it never receives a Lua state. Replies are
released before C propagates an error, including allocation failures. Logical build
IDs now select source-v2/c-boundary-1, so v1 archives require rebuilding.
See [the boundary decision](decisions/0007-lua-c-error-boundary.md).

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
At the Lua 5.4 baseline, the macOS arm64 fixture was built through the CLI, reported ready through
`doctor`, and printed its expected nested-import/asset result. The complete
workspace passed 111 Rust tests and Clippy with warnings denied on this host.
The final validation branch passed 118 Rust tests with `lua54` and 119 with
`lua55` on macOS and GNU Linux arm64, and all-target Clippy with warnings denied
for both. Lua 5.5 built
through the CLI, reported ready for 5.5.1, and printed the expected `Lua 5.5`
result. Its fixture archive SHA-256 is
`4c0d21b1e8b2bec3bd146280958f0ddf958c03f7177451eb2049b9e3570a0094`.
Opposite-version archives return 1 without executing source; 27 Python
trace-policy tests pass.

The final Linux captures used clean commit `8b6eb1f` on
`codex/a6-lua-linux-validation`, stacked on source profiles `cb88d7d`. Both
relocated Lua fixtures exited 0 with exactly the expected stdout and empty
stderr, and passed full `strace` checks. The observed arm64 cell used Linux
`7.1.4-200.fc44.aarch64`, glibc `2.36-9+deb12u10`, Rust 1.88.0, GCC 12.2.0,
strace 6.1 and 4 KiB pages. Direct Podman commands were used because the
sandboxed wrapper could not access its socket. The
[retained evidence](evidence/linux-arm64-lua-2026-10-08/README.md) contains
commands, source/fixture/artifact identities, all build-provenance instances,
feature trees, test/Clippy logs and raw traces. These debug source-only
observations remain separate from the native probe and do not establish the
declared minimum kernel/glibc versions or other platforms/architectures.

The C-owned source adapter was captured from clean implementation `ee7c9d3` on
2026-10-09 using the same pinned Linux image and observed arm64 environment.
Both workspace profiles pass 142/143 Rust tests and all-target Clippy on macOS
and GNU Linux; the optimized macOS boundary suites pass 50/51 tests. Both new
relocated, read-only Linux fixtures produce exactly 55 stdout bytes, empty stderr,
exit 0 and pass the full trace checker. The
[boundary evidence](evidence/linux-arm64-lua-c-boundary-2026-10-09/README.md)
retains the fresh source/artifact identities, all provenance records, raw traces
and Mac/Linux test logs. The strict C-only error boundary is implemented for
this source profile; general native and platform/release acceptance remain pending.

The native Lua closure was captured from clean `fb61e5e` on 2026-10-09 using
the same immutable image and observed GNU Linux arm64 environment. Both source
workspace profiles pass 181/182 tests on Mac and Linux; native-feature profiles
pass 178/179 on GNU Linux and 177/178 on Mac, where the loader is unsupported.
All four profiles pass all-target Clippy with warnings denied on both systems.
Optimized Mac native C-boundary suites pass 53/54 tests. Both relocated native
fixtures match ordinary loading of the same compiled Lua core, exit 0 with
exact output and empty stderr, and pass full traces proving two completely
sealed memfds before loading and no payload filesystem mutation. All six
adversarial ELF cases per version reject with exact diagnostics and statuses
before any memfd attempt. The
[native evidence](evidence/linux-arm64-native-lua-2026-10-09/README.md)
retains all fourteen traces, source/artifact hashes, build provenance and
Mac/Linux validation logs. This completes the controlled Linux native Lua
slice, with the platform, release and general compatibility gates still open.

The signed macOS arm64 probe was captured from clean `346b2f0` on 2026-10-09.
Debug and optimized launchers use only the allow-jit entitlement under hardened
runtime and match ordinary dyld loading after PID normalization. All seven
native rejections per launcher and signing/memory-policy controls pass with
exact results. Source workspaces pass 212/213 tests and Clippy on Mac/Linux;
the parser has 31 tests, also passing in optimized Mac builds. The
[macOS evidence](evidence/macos-arm64-macho-2026-10-09/README.md)
retains source/artifact identities, signatures, inspections and tool denials.
This is a native-only fixture with an unacquired Lua scaffold. Full independent
filesystem/VM tracing is unavailable under current rights and no Developer ID
identity is available; A1 release acceptance and G0/G1 remain open.

## Next critical-path assignments

Extend native platform/release evidence beyond the controlled Linux Lua closure.
Complete A1 independent tracing and distribution-signing evidence, then extend
the supported Mach-O subset to actual runtime startup. Continue A2 (Windows PE)
and A3 (Linux/FreeBSD ELF) on their native OS runners.
Establish the FreeBSD bundled Python/Node producer and inspect pinned PBS
artifacts. The Linux native Lua vertical slice exercises the G2 fixture on its
observed cell; it does not establish the four-platform prerequisite or general
package compatibility.
