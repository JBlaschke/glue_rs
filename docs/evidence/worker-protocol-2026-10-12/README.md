# Synthetic worker-message evidence, 12 October 2026

Captured from clean implementation
`42197bbbe6116fae4683e4fa21f441757c675244` on
`codex/a9-worker-protocol`, based on merged `aae69ef`.
The [wire decision](../../decisions/0020-worker-message-protocol.md) describes
the version-0 codec and controller ledger. This is A9 foundation evidence;
the product launcher and language runtimes do not yet use workers. G4 remains
open.

## Observations

| Check | macOS arm64 | GNU Linux arm64 |
| --- | --- | --- |
| Default Lua 5.4 source workspace tests | 432 pass | 432 pass |
| Lua 5.5 source workspace tests | 433 pass | 433 pass |
| Optimized IPC/fixture tests | 37 pass | 37 pass |
| Workspace all-target Clippy, both Lua profiles | Clean | Clean |
| Workspace format | Clean | Same checked sources |

The 37 new tests comprise 15 codec/ledger unit tests, 17 independent codec
conformance tests and five real-pipe tests. They exercise numeric extrema and
negative zero, Unicode and binary values, canonical maps, malformed inputs,
allocation/depth/count budgets, fragmented/interrupted I/O, request identity,
out-of-order completion, cancellation, draining and EOF distinction.

The complete [Linux trace](linux-pipes.trace.txt.gz) comes from the built release
pipe-test executable, with compiler/build activity outside the trace. Its five
tests launch six synthetic Rust peers and create 18 anonymous pipes (stdin,
stdout and stderr per peer). The peer exit statuses are `0, 17, 17, 17, 1, 0`:
two successful shutdowns, three deliberate output/crash controls and one
rejected truncated controller request. The test process exits 0, all five
assertions pass, and its stderr is empty. Protocol frames travel over inherited
pipe descriptors. The trace is retained in full, compressed with deterministic
gzip metadata; this record does not claim runtime payload-extraction evidence.

These trusted synthetic peers reserve their stdin/stdout for the protocol and
use stderr for diagnostics. Product workers still need private inherited
protocol handles independent of application stdio. Actual runtime dispatch,
archive/provider transfer, worker-side cancellation races, queue-byte budgets,
enforced deadlines, crash supervision and mixed-language execution remain
pending. No Windows or FreeBSD execution was observed.

## Environment and reproduction

The [Mac environment](mac-environment.txt) is macOS 26.7 / Darwin 25.6.0 arm64.
The [Linux environment](linux-environment.txt) is
`7.1.4-200.fc44.aarch64`, GNU libc `2.36-9+deb12u10`, strace 6.1 and 4 KiB pages.
Both use Rust/Cargo/Clippy 1.88. The Linux harness uses the existing offline
probe image pinned by ID
`62812c4a0e15bc750ddd6ec68d2a19f8815a14b60d520e201a911e2e29f40abe`;
its [image inspection](linux-image-inspect.json) records the corresponding
repository digest. Network access is disabled, sources are read-only, and
build outputs use a fresh tmpfs.

From the repository root, with the implementation sources unchanged:

```sh
export PATH="$(rustup run 1.88.0 rustc --print sysroot)/bin:$PATH"
cargo fmt --all --check
cargo test --workspace --locked --offline
cargo clippy --workspace --all-targets --locked --offline -- -D warnings
cargo test --workspace --locked --offline --no-default-features \
  --features glue-runner/lua55,glue-runtime-lua/lua55
cargo clippy --workspace --all-targets --locked --offline --no-default-features \
  --features glue-runner/lua55,glue-runtime-lua/lua55 -- -D warnings
cargo test --release --locked --offline -p glue-ipc -p glue-worker-protocol-fixture
sh fixtures/worker-protocol/run-linux.sh
```

The explicit toolchain PATH prevents Homebrew child tools from shadowing Rustup.
The [Linux harness](../../../fixtures/worker-protocol/run-linux.sh) vendors the
locked dependencies, runs the same workspace profiles plus release IPC tests,
then traces the pipe-test executable directly. Its runtime command is:

```sh
strace -f -s 256 -yy -e trace=all -o /evidence/linux-pipes.trace.txt \
  /build-target/release/deps/pipes-b68a9bfe6d99f40d --test-threads=1
```

## Retained records

[The summary](validation-summary.json) records exact test totals and observed
pipe/process outcomes. [Source identities](source-identities.json) cover the
new crate, fixture, wire contract and workspace/toolchain locks from the clean
implementation commit. [Artifact hashes](linux-artifacts.sha256) identify the
traced pipe-test executable and peer. The directory retains all six test logs
as `*-tests.txt.gz`, four Clippy logs, Mac formatting output, environment/image
identities, clean source status, and exact traced stdout/stderr/status. Traced
stdout is `linux-pipes.stdout.txt.gz`; the summary uses the original logical
log names. Compression preserves every byte, including trailing blank lines.
[Checksums](checksums.sha256)
cover every retained record except the checksum file itself.
