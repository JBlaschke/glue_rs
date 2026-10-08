# glue_rs

A Rust packager and launcher under development for Python, Node.js and Lua apps
in a read-only archive. The runtime contract forbids payload extraction and
silent runtime-provider fallback. See [PLAN.md](PLAN.md) for the full design.

The current implementation packages explicit resources, validates manifest and
ZIP32/ZIP64 metadata, verifies stored/deflate contents, and exposes a read-only
resource tree with bounded memory caching. Experimental **linked Lua 5.4.9 and
5.5.1 source profiles** run archive scripts and resources on matching macOS or GNU
Linux targets. General native loading, host/archived runtime acquisition,
Python/Node execution, workers and standalone executables remain pending.
The archive and manifest are experimental version 0; G0/G1/G2 remain open.
A separate Linux fixture probes archived shared-library loading through sealed
memfds; that mechanism is not integrated into `glue run`.

## Try linked Lua

Use Rust 1.88.0 through Rustup. If Homebrew shadows Rustup, put `$HOME/.cargo/bin`
first in PATH. These commands select the macOS arm64 fixture; on GNU Linux arm64,
use `fixtures/lua-linked/manifest.linux-arm64.json` instead. The target's OS,
architecture, ABI, minimum versions and page size must match the running host.

```sh
cargo build --locked -p glue-runner
target/debug/glue build --manifest fixtures/lua-linked/manifest.macos-arm64.json \
  --root fixtures/lua-linked/input --output target/linked-lua-demo.glue
target/debug/glue doctor target/linked-lua-demo.glue
target/debug/glue run target/linked-lua-demo.glue
```

The fixture performs nested archive imports, checks `require` caching and virtual
origins, reads an asset, and prints
`Lua 5.4 answer=42 asset=Hello from archived resources!`. Existing build outputs
are preserved; choose a new output name when rebuilding.

Lua 5.4 is the default compiled profile. To select Lua 5.5 explicitly, use its
matching manifest and a separate build directory. On GNU Linux arm64, substitute
`manifest.lua55.linux-arm64.json` below:

```sh
cargo build --locked -p glue-runner --no-default-features --features lua55 \
  --target-dir target/lua55
target/lua55/debug/glue build --manifest fixtures/lua-linked/manifest.lua55.macos-arm64.json \
  --root fixtures/lua-linked/input --output target/linked-lua55-demo.glue
target/lua55/debug/glue doctor target/linked-lua55-demo.glue
target/lua55/debug/glue run target/linked-lua55-demo.glue
```

The 5.5 fixture prints the same result with a `Lua 5.5` prefix. `lua54` and `lua55`
are mutually exclusive build features. Each compiled launcher accepts only its
own exact source/build/ABI identity; another Lua version is rejected. Supporting
both versions through separate launchers does not provide simultaneous runtimes
in one launcher/archive; those providers and workers remain later work.

Provisioning must explicitly select `linked` / `lua_source`, the compiled Lua
release's exact source pin and build profile, and int64/float64 ABI. No installed Lua is required.
`require` searches `app/?.lua` and `app/?/init.lua`; `loadfile` and `dofile` read
canonical archive keys. Every consumed resource is fully verified before use.
`glue.read`, `glue.stat`, `glue.list` and `glue.origin` expose read-only assets.
Bytecode, `io`, `os`, `debug`, native loading, declared host imports and multiple
components/runtimes/targets are unsupported in this initial profile. These are
experimental compatibility restrictions, not a sandbox or the final host-I/O
policy. See the [fixture](fixtures/lua-linked/README.md) and
[base profile decision](docs/decisions/0005-linked-lua-source-profile.md) and
[version selection](docs/decisions/0006-versioned-linked-lua-profiles.md).

The adapter uses the maintained `mlua` safe API to catch callback panics and
protect Lua calls. Upstream Lua longjmp may still cross a Drop-free Rust
protected-call thunk. **PLAN.md's literal C-only, no-Rust-frame boundary is not
satisfied**; a shim or explicitly accepted boundary contract is needed before
release.

## Try the resource fixture

This older fixture declares a fictional `host` Lua library and tests packaging
and resources. It remains unsupported for execution; linked Lua is never
silently substituted for its selected provider.

```sh
cargo build --locked -p glue-runner
target/debug/glue build --manifest fixtures/resources/manifest.json \
  --root fixtures/resources/input --output target/resource-fixture.glue
target/debug/glue inspect target/resource-fixture.glue
target/debug/glue verify target/resource-fixture.glue
target/debug/glue cat target/resource-fixture.glue assets/message.txt
target/debug/glue explain-size target/resource-fixture.glue
target/debug/glue doctor
```

`build` consumes only the manifest's declared files. Each file's uncompressed
length and SHA-256 must match its declaration. Symlink resource components are
rejected; existing output files are preserved. Build-time filesystem use is
allowed. Default inputs are limited to 64 MiB per resource and 256 MiB in total.
The builder validates and verifies the generated archive before creating output.
An output write failure may leave a partial file and returns an error.

`inspect` validates metadata, with `--json` for the canonical manifest. Use
`verify` to check every resource's stream termination, length, CRC and SHA-256.
`cat` verifies a member before writing its bytes to stdout. Archive readers never
materialize a resource as a filesystem file. These hashes detect corruption;
they do not authenticate an archive's author.

`run` and `doctor APP.glue` return 0 for a matching linked profile, 2 for an
unsupported provider/capability, and 1 for malformed input or mismatched
source/build/ABI/host prerequisites. `doctor` checks metadata and acquisition
readiness without executing scripts or verifying every resource; use `verify`
for a complete content check. The original host resource fixture still returns
2. `build --standalone` remains unavailable with status 2. Successful core
operations return 0; input and argument errors return 1.

## Development and evidence

The current macOS arm64 workspace passes 118 Rust tests with `lua54` and 117 with
`lua55`, with workspace Clippy clean for both. Both CLI fixtures run, and the
opposite minor-version archive is rejected before execution. The 27 Python
trace-policy tests pass. Linux execution/trace validation is in progress;
earlier native observations below remain separate evidence.

```sh
cargo test --workspace --locked
cargo fmt --all -- --check
cargo clippy --workspace --all-targets --locked -- -D warnings
sh scripts/test-linux.sh
python3 -m unittest discover -s scripts -p 'test_linux_memfd_trace.py'
sh scripts/run-linux-memfd.sh
python3 -m unittest discover -s scripts -p 'test_linux_lua_trace.py'
sh scripts/run-linux-lua.sh lua54
sh scripts/run-linux-lua.sh lua55
```

The Linux script vendors dependencies already present in the build machine's
Cargo cache, then tests offline in a read-only Podman container. Pull its pinned
image once first:

```sh
podman pull docker.io/library/rust@sha256:93717e495a1029ba94b9b4a5768cf14d5376077d26cfad3354cbe70be27c2b1d
```

Its default test cell is Linux arm64, Rust 1.88.0, Debian bookworm. It does not
establish Linux x86_64 or native-loader compatibility.

The memfd script builds a test image with GCC, strace and Rust Clippy, then runs
offline. It compares the native fixture with ordinary OS loading, removes the
compiler's shared-library files, loads the archive payload via anonymous memfds,
and checks a full syscall trace. It requires Python 3.10+ for the trace checker.
Build tools and Podman are development dependencies only. See the
[probe decision](docs/decisions/0004-linux-memfd-probe.md) for its narrow scope
and the remaining platform/runtime experiments.

The Lua harness reuses that local test image and records separate profile runs,
including relocated CLI execution, binary/source identities and a complete
syscall trace. Its checker admits only the fixture's exact output diagnostic
and read-only runtime operations. This is fixture evidence, not a sandbox or
a proof about arbitrary Lua programs.

See [CONTRIBUTING.md](CONTRIBUTING.md), [progress](docs/progress.md),
[container contract](docs/decisions/0002-experimental-container.md) and
[fixture protocol](docs/fixtures.md). Implementation steps use stacked feature
branches. The linked source slice does not establish native Lua, mixed apps,
archived/host Python or Node startup, signed macOS deployment, or four-OS
compatibility. Their feasibility and release gates remain open.
