# Linked Lua C boundary evidence — 2026-10-09

This bundle records the source-only C boundary for separate Lua 5.4.9 and
5.5.1 launchers at clean source commit
`ee7c9d329e7e3eeea529660308620ea5adf479c3`, on
`codex/a6-lua-c-boundary`. Both Linux captures and the Mac validation logs passed.
It supersedes the earlier adapter's error-boundary limitation for this source-only
profile; native-module and mixed-runtime boundaries remain outside this evidence.

The Rust bridge calls no Lua API. C owns the Lua state, protected calls, value
construction, errors and shutdown; Rust callbacks return owned bytes before C can
raise a Lua error. The structural review, panic/OOM/GC/cleanup tests and exceptional
one-panic-payload leak are documented in
[ADR 0007](../../decisions/0007-lua-c-error-boundary.md). This is evidence for the
implemented boundary, not a general proof of every future extension.

| Validation | Lua 5.4 | Lua 5.5 |
| --- | ---: | ---: |
| Linux arm64 debug workspace tests | 142 | 143 |
| Mac arm64 debug workspace tests | 142 | 143 |
| Mac optimized `glue-runtime-lua` tests | 50 | 51 |
| Workspace/all-targets Clippy, `-D warnings`, both systems | passed | passed |
| Linux relocated run and complete trace check | exit 0 | exit 0 |

Each Linux run produced the exact expected 55-byte stdout and empty stderr.
The raw traces are [Lua 5.4](lua54/lua.trace.txt) and
[Lua 5.5](lua55/lua.trace.txt); corresponding
[5.4](lua54/trace-check.txt) and [5.5](lua55/trace-check.txt) checker records
report archive reads, no payload/file mutations, memfds or shared mappings, and
a completed zero exit. The syscall checker verifies this fixture's trace; it is
not a syscall sandbox.

## Environment and build identity

Both captures used Linux arm64, kernel `7.1.4-200.fc44.aarch64`, Debian glibc
`2.36-9+deb12u10`, 4096-byte pages, GCC `12.2.0-14+deb12u1`, Rust/Clippy 1.88.0
and strace `6.1-0.1`. They are debug/O0 builds with Lua API checks. See the
[5.4](lua54/environment.txt) and [5.5](lua55/environment.txt) environment records.
The Mac logs used the same source code and pinned Rust 1.88.0 on
`aarch64-apple-darwin`; their attribution and separately collected compiler record
are in [validation-context.txt](macos/validation-context.txt) and
[rustc-verified.txt](macos/rustc-verified.txt).

The immutable image is
`62812c4a0e15bc750ddd6ec68d2a19f8815a14b60d520e201a911e2e29f40abe`, digest
`sha256:c3aa290549c5ba0e63aec9de61fc10b6e4bd59e89c0c3f72bb270dd426eedeba`.
[image-summary.json](image-summary.json) retains the selected inspection fields.
[image.Dockerfile](image.Dockerfile) pins the Rust base to
`sha256:93717e495a1029ba94b9b4a5768cf14d5376077d26cfad3354cbe70be27c2b1d`
and strace to `6.1-0.1`. The apt repository is moving; the image digest
identifies the observed image rather than a byte-reproducible image producer.

The source pin is `lua-src 551.0.2`, using Lua 5.4.9 or 5.5.1, int64/float64,
with explicit version-specific `c-boundary-1` build identities. The
[5.4](lua54/manifest.input.json) and [5.5](lua55/manifest.input.json) manifests,
[5.4](lua54/lua-src-feature-tree.txt) and [5.5](lua55/lua-src-feature-tree.txt)
feature graphs, and every record in each `build-provenance` directory are retained.
The feature graphs contain neither `mlua` nor the optional `ucid` feature. Provenance records show default
compiler arguments and declared source-builder additions; they are partial local
build evidence, not a complete compiler-command or artifact fingerprint.

## Artifacts and commands

| Linux profile | Debug launcher SHA-256 | Archive SHA-256 |
| --- | --- | --- |
| Lua 5.4 | `32584b8c38f3173db0a167bfa307eb708871ce18b7a58c170c7bbb7fe4d2431f` | `d3722cba5bb1cb8faf4340989b36415e2481e987781c4af416f5a5372317669d` |
| Lua 5.5 | `02fa40a6f89e0d02b7604850caadafc4abf71fa029d77ace75efc2c33d57222e` | `b44867dbb2a171f8b5c853fa9b41c6f2e34d9b7eed9ac34b864ce840f8ff4418` |

These values come from [5.4](lua54/artifacts.sha256) and
[5.5](lua55/artifacts.sha256). Launchers were ephemeral container artifacts;
archives remain in the local ignored `target/evidence` run directories. Neither
binaries nor archives are copied into this text bundle. Dynamic-section records
show `libm`, `libgcc_s` and `libc` dependencies, without a shared `liblua` dependency.

Exact Podman invocations are retained for [5.4](lua54/podman-command.sh) and
[5.5](lua55/podman-command.sh), with their [5.4](lua54/commands.sh) and
[5.5](lua55/commands.sh) build/run scripts. Direct Podman invocation was used
because the desktop sandbox wrapper could not reach its socket. The repository
was mounted read-only, networking disabled, and builds placed in an ephemeral
`/build-target`. The archive was relocated and its original package directory
removed. Fixture inputs remained mounted read-only, but neither runtime trace
opened them.

The six root Mac logs are retained in [macos](macos/validation-context.txt).
Each profile's clean Git status, empty source diff, 51 source hashes, five fixture
hashes, exit statuses and exact expected output are retained. All copied records
were checked byte-for-byte, and source/fixture hashes checked against the clean
Git object; see [verification.txt](verification.txt). [SHA256SUMS](SHA256SUMS)
covers every bundle file except itself. From this directory, verify with
`shasum -a 256 -c SHA256SUMS`.

## Limits

This observes one Linux arm64/glibc/page-size/kernel combination and Mac arm64
tests. Declared minimum OS/kernel/libc versions were not tested. Optimized Mac
runtime tests do not establish a signed release, release performance or release
Linux coverage. Separate launchers select one Lua version; simultaneous runtimes,
native modules, mixed components, host/bundled runtime acquisition and the
four-OS gates remain open. The exceptional panic-payload leak in ADR 0007 remains
an explicit failure-path policy.
