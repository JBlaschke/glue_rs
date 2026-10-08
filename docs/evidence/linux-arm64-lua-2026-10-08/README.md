# Linux arm64 linked Lua observation

Captured on 2026-10-08 from clean source commit
`8b6eb1f78a83d7325387938b806577321e51cad9` on
`codex/a6-lua-linux-validation`, stacked on the versioned profiles in `cb88d7d`.
Separate compiled launchers selected `lua54` (Lua 5.4.9) and `lua55` (Lua 5.5.1),
both with `mlua` 0.12.2 / `lua-src` 551.0.2 and int64/float64 defaults.
The [profile decision](../../decisions/0006-versioned-linked-lua-profiles.md)
records the exact source pins and logical build IDs.

The Mac host invoked Podman directly through the approved `podman` command
prefix because the sandboxed wrapper was denied access to the Podman socket.
The recorded commands disabled networking, mounted the repository read-only,
used tmpfs for Cargo/build outputs, and supplied the immutable local image ID.
The source commit, clean Git status, empty diff and checked source/fixture hashes
are retained for each run. The package was moved to
`/build-target/relocated Lua fixture/app.glue` and made read-only before execution.

| Record | Lua 5.4 | Lua 5.5 |
| --- | --- | --- |
| Outer Podman invocation | [command](lua54/podman-command.sh) | [command](lua55/podman-command.sh) |
| Inner build/test/run commands | [script](lua54/commands.sh) | [script](lua55/commands.sh) |
| Clean source identity | [commit](lua54/source-commit.txt), [status](lua54/source-status.txt), [identity check](lua54/identity-check.txt) | [commit](lua55/source-commit.txt), [status](lua55/source-status.txt), [identity check](lua55/identity-check.txt) |
| Source and fixture hashes | [source](lua54/source.sha256), [inputs](lua54/fixture-inputs.sha256) | [source](lua55/source.sha256), [inputs](lua55/fixture-inputs.sha256) |
| Selected manifest | [manifest](lua54/manifest.input.json) | [manifest](lua55/manifest.input.json) |

## Observed environment and build

Both runs used Linux `7.1.4-200.fc44.aarch64`, glibc `2.36-9+deb12u10`,
GCC `12.2.0-14+deb12u1`, Rust/Clippy 1.88.0 and strace `6.1-0.1`, with 4 KiB
pages. [Lua 5.4 environment](lua54/environment.txt),
[Lua 5.5 environment](lua55/environment.txt).

The local image ID was
`62812c4a0e15bc750ddd6ec68d2a19f8815a14b60d520e201a911e2e29f40abe`,
with image digest
`sha256:c3aa290549c5ba0e63aec9de61fc10b6e4bd59e89c0c3f72bb270dd426eedeba`.
It was built from the Rust 1.88.0 / Debian bookworm base pinned by
`docker.io/library/rust@sha256:93717e495a1029ba94b9b4a5768cf14d5376077d26cfad3354cbe70be27c2b1d`,
installing strace `6.1-0.1` and Rust Clippy.
[Dockerfile](image.Dockerfile), [selected image metadata](image-summary.json).
The apt repository is moving; this identifies the observed image rather than a
byte-reproducible image producer.

Each run built, tested and linted offline in debug/O0 mode with Lua API checks.
The complete workspace
passed 118 Rust tests with `lua54` and 119 with `lua55`; all-target Clippy passed
with warnings denied. The same final test counts and Clippy checks passed on
macOS arm64. [Lua 5.4 tests](lua54/workspace-tests.txt),
[Lua 5.5 tests](lua55/workspace-tests.txt),
[Lua 5.4 Clippy](lua54/workspace-clippy.txt),
[Lua 5.5 Clippy](lua55/workspace-clippy.txt).

Both build-script provenance instances per profile are retained, alongside
the Cargo feature graph. They record the selected source, default C compiler
arguments, target and debug configuration; they are local build evidence, not
a complete artifact fingerprint. The feature graphs do not enable `ucid`.
[Lua 5.4 feature graph](lua54/lua-src-feature-tree.txt),
[Lua 5.5 feature graph](lua55/lua-src-feature-tree.txt),
[Lua 5.4 provenance](lua54/build-provenance/),
[Lua 5.5 provenance](lua55/build-provenance/).
The launcher lists only `libgcc_s.so.1`, `libm.so.6` and `libc.so.6` as direct
dynamic dependencies. [Lua 5.4 dynamic metadata](lua54/launcher.dynamic.txt),
[Lua 5.5 dynamic metadata](lua55/launcher.dynamic.txt).

## Execution and artifacts

Both relocated runs exited 0 and printed exactly 55 stdout bytes, respectively:

```text
Lua 5.4 answer=42 asset=Hello from archived resources!
Lua 5.5 answer=42 asset=Hello from archived resources!
```

Each had empty stderr. The fixture exercises nested source imports, `require`
caching, virtual source origins and an archived asset.
[Lua 5.4 stdout](lua54/lua.stdout.txt), [status](lua54/lua.exit-status.txt),
[Lua 5.5 stdout](lua55/lua.stdout.txt), [status](lua55/lua.exit-status.txt).
Both outer Podman invocations also exited 0.
[Lua 5.4 harness status](lua54/harness.exit-status.txt),
[Lua 5.5 harness status](lua55/harness.exit-status.txt).

The complete `strace -f -yy -s 256 -e trace=all` records passed the fail-closed
fixture checker with status 0. It accepted the exact stdout stream, one launcher
execution, relocated archive reads and observed read-only OS startup operations.
It rejected unapproved reads, payload/file mutations (including failed attempts),
native payload mappings, memfds, shared mappings and unknown/incomplete calls.
Fixture inputs remained mounted read-only under `/workspace`; the runtime
traces never opened them or host Lua files. Only the original package directory
was removed after relocation.
[Lua 5.4 trace](lua54/lua.trace.txt), [check](lua54/trace-check.txt),
[Lua 5.5 trace](lua55/lua.trace.txt), [check](lua55/trace-check.txt).

| Artifact | SHA-256 |
| --- | --- |
| Linux `lua54` launcher | `469116956d522150cca18e54bd7bc461993b51a2074a7effee3e313a1c27cea5` |
| Linux Lua 5.4 archive | `f62519256b0abf4bf76be05c3f5eb8bd2f29904c09d0cac25650f98c23b97a39` |
| Linux `lua55` launcher | `6b95c00c40b78e655c19173b697c41aa9c12f751ecb3675267ce19b40ea74025` |
| Linux Lua 5.5 archive | `4656e1fa65fe87b8f8b29b70d0fab3ff9cbf8ea7319b327b2c53648391b3438f` |

[Lua 5.4 artifact hashes](lua54/artifacts.sha256),
[Lua 5.5 artifact hashes](lua55/artifacts.sha256).
The archive payloads remain under ignored
`target/evidence/linux-lua/run-final-lua54-ma3cx4l2` and
`target/evidence/linux-lua/run-final-lua55-vue1ez6d` on the development host;
the launchers were ephemeral tmpfs outputs. This bundle retains text records,
not binaries, archives, full image inspection or vendoring logs.

## Scope

This is positive evidence for two fixed source-only fixtures in one GNU Linux
arm64 cell. The declared kernel 6.1 minimum was not tested: the observed kernel
was 7.1.4. It does not prove compatibility at the minimum glibc version across
systems, on Linux x86_64, Windows or FreeBSD, with arbitrary Lua programs,
or for release/performance behavior, native modules, simultaneous runtimes,
mixed workers, host/archived runtime acquisition or signed deployment.
The syscall checker is an observation checker, not a sandbox.

The maintained `mlua` API protects calls and catches callback panics, but Lua
longjmp may cross a Drop-free Rust protected-call thunk. PLAN.md's literal
C-only/no-Rust-frame boundary is still unmet; a shim or explicitly accepted
boundary contract is required before release. G0/G1/G2 remain open.

For a fresh observation on a host with Podman socket access, run
`sh scripts/run-linux-lua.sh lua54` and `sh scripts/run-linux-lua.sh lua55` from
the repository root with the recorded test image available. The retained outer
commands show the direct invocation used for this capture; their absolute host
paths must be adjusted on another machine.
