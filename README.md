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
An opt-in GNU Linux arm64 profile also runs a controlled native Lua closure
through sealed executable memfds in `glue run`.

## Try linked Lua

Use Rust 1.88.0 through Rustup. If Homebrew shadows Rustup, put `$HOME/.cargo/bin`
first in PATH. These commands select the macOS arm64 fixture; on GNU Linux arm64,
use `fixtures/lua-linked/manifest.linux-arm64.json` instead. The target's OS,
architecture, ABI, minimum versions and page size must match the running host.

```sh
cargo build --locked -p glue-runner
target/debug/glue build --manifest fixtures/lua-linked/manifest.macos-arm64.json \
  --root fixtures/lua-linked/input --output target/linked-lua-v2-demo.glue
target/debug/glue doctor target/linked-lua-v2-demo.glue
target/debug/glue run target/linked-lua-v2-demo.glue
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
  --root fixtures/lua-linked/input --output target/linked-lua55-v2-demo.glue
target/lua55/debug/glue doctor target/linked-lua55-v2-demo.glue
target/lua55/debug/glue run target/linked-lua55-v2-demo.glue
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

The adapter uses a private C boundary for Lua execution and errors. C owns the
Lua state and allocator; Rust archive callbacks return data before C calls Lua
APIs or raises errors. Protected result construction releases callback replies
even on allocation failure. See [the boundary decision](docs/decisions/0007-lua-c-error-boundary.md).
The changed adapter has a v2 build identity; rebuild archives created with v1.

## Native Lua on GNU Linux arm64

The optional `linux-native` feature supplies a separate native-v1 build identity
for either Lua version. It requires GNU Linux AArch64, 4 KiB pages, executable
memfd support/policy, one linked runtime and a collision-free namespace. It
accepts a bounded ELF subset and explicitly declared dependencies; its reviewed
OS import is `getpid` from `libc.so.6`. It validates every native image and hash
before running constructors, then loads dependencies locally before creating
the Lua state. Rust callbacks return cached C initializers; C owns Lua invocation
and error handling. Handles stay pinned until process exit.

`require` searches archive source first, then declared native roots. A root's
module ID determines its `luaopen_` name, and its resource basename must match
its SONAME. `package.loadlib` accepts that canonical archive key and exact
initializer. Native code must obey the C/Lua ABI and contain foreign exceptions;
it is trusted code. TLS, IFUNC, general unwind/constructor reentry, host native
modules, nested loading and other OS/architecture profiles remain pending.
Default source-only builds retain their v2 identities.

The reproducible fixture uses the pinned local Podman probe image, compares
ordinary disk loading against the same compiled Lua core, removes the compiled
inputs, relocates the read-only archive and checks the complete syscall trace:

```sh
sh scripts/run-linux-native-lua.sh lua54
sh scripts/run-linux-native-lua.sh lua55
```

See the [native fixture](fixtures/native/lua-linux/README.md) and
[profile decision](docs/decisions/0008-linux-native-lua-closure.md). Both Lua
versions have retained [execution and rejection evidence](docs/evidence/linux-arm64-native-lua-2026-10-09/README.md). This narrow
vertical slice does not establish general native compatibility or four-OS gates.

## Signed macOS mapping probe

The separate A1 spike tests a bounded arm64 Mach-O subset with two archived
images, a real OS import and a constructor. It uses an ad-hoc signed hardened
runtime and the `allow-jit` entitlement. It does not acquire a language runtime
or enable native macOS execution in `glue run`.

```sh
cargo build --locked -p glue-runner -p glue-macos-macho-probe
sh fixtures/native/macos-macho/run.sh \
  "$PWD/target/debug/glue" "$PWD/target/debug/glue-macos-macho-probe" \
  "$PWD/target/evidence/macos-macho/capture-1"
```

Use a fresh capture directory. See the [fixture](fixtures/native/macos-macho/README.md)
and [mapping decision](docs/decisions/0009-signed-macos-macho-probe.md).
Both debug and optimized signed runs have [retained evidence](docs/evidence/macos-arm64-macho-2026-10-09/README.md).
Full write tracing and Developer ID distribution evidence remain open.

## Inspect pinned Python inputs

`glue-pbs-inspect` reads pinned stock Python Build Standalone full and unstripped
install-only inputs without extracting them. It hashes the complete inventory,
checks shared-runtime/startup metadata and verifies the exact upstream
install-only projection. The initial fixture pins CPython 3.13.16 / PBS
`20261009` for GNU Linux arm64. The tool runs on Mac or Linux with no Python or
uv dependency; it emits deterministic JSON to stdout.

See [the input fixture and command](fixtures/python-pbs/README.md) and
[inspection decision](docs/decisions/0010-pinned-pbs-inspection.md).
This is build-time provider work. [Retained evidence](docs/evidence/pbs-linux-arm64-inspection-2026-10-09/README.md)
includes identical Mac/Linux reports and the complete Linux inspector trace.

The separate `glue-python-bootstrap-probe` prepares a bounded archive from that
exact library and startup bytecode compiled by the matching stock interpreter.
Its opt-in `pbs-bootstrap` feature uses public CPython APIs and a C-owned boundary
on GNU Linux arm64; other targets reject execution before opening the archive.
The [bootstrap fixture](fixtures/python-bootstrap/README.md) and
[decision](docs/decisions/0011-stock-pbs-frozen-bootstrap.md) describe its frozen
startup subset, exact runtime profile and trace protocol. Product Python and host
providers, general imports and native extensions remain pending.
The [clean bootstrap capture](docs/evidence/pbs-linux-arm64-bootstrap-2026-10-10/README.md)
matches ordinary loading and passes all four complete syscall checks after the
producer installation and headers are removed.

The separate [host startup fixture](fixtures/python-host/README.md) selects that
exact library with its installed stdlib through explicit host paths. It verifies
the library and six startup sources, rejects startup bytecode caches and uses
the installed encodings package without our frozen bundle. Product host
discovery and Python execution remain pending.
The [clean host capture](docs/evidence/pbs-linux-arm64-host-python-2026-10-10/README.md)
passes all eight host traces and four frozen-bootstrap regression traces from
the same implementation commit.

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

The source-profile workspace passes 308/309 Rust tests for `lua54`/`lua55` on
macOS and GNU Linux arm64, including 31 portable Mach-O parser tests, 64 PBS inspection tests
and 32 Python bootstrap/host bundle/profile tests. Both
profiles pass all-target Clippy with warnings denied on both systems. The
GNU opt-in bootstrap/host fixture passes 34 release tests and Clippy; all 112
Python trace-policy tests pass, including 23 host startup checks. The
earlier native Linux validation covers both optional native profiles and
53/54 optimized Mac C-boundary tests. Tests cover allocation
failures, callback panic containment, buffer cleanup, GC/finalizers, native
initializer/function errors, bounded ELF parsing and closure rejection.
Both native Linux fixtures match ordinary loading and pass complete sealed
memfd/no-extraction trace checks; all twelve rejection traces pass before any
memfd attempt. The [native evidence](docs/evidence/linux-arm64-native-lua-2026-10-09/README.md)
retains source/artifact hashes, commands, provenance and full traces from clean
`fb61e5e`. The earlier [C boundary](docs/evidence/linux-arm64-lua-c-boundary-2026-10-09/README.md),
[v1](docs/evidence/linux-arm64-lua-2026-10-08/README.md) and native probe records
remain separate historical evidence.

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
python3 -m unittest discover -s scripts -p 'test_linux_native_lua_trace.py'
python3 -m unittest discover -s scripts -p 'test_linux_native_lua_rejections.py'
python3 -m unittest discover -s scripts -p 'test_linux_pbs_trace.py'
python3 -m unittest discover -s scripts -p 'test_linux_python_bootstrap_trace.py'
python3 -m unittest discover -s scripts -p 'test_linux_python_host_trace.py'
sh scripts/run-linux-native-lua.sh lua54
sh scripts/run-linux-native-lua.sh lua55
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
and read-only runtime operations. The final capture used direct Podman commands
because the sandboxed wrapper could not access the Podman socket. This is
debug/O0 fixture evidence on Linux arm64 kernel 7.1.4, glibc 2.36 and 4 KiB
pages. It is not a sandbox or proof about arbitrary Lua programs, the declared
kernel 6.1 minimum, release/performance behavior or other architectures.

See [CONTRIBUTING.md](CONTRIBUTING.md), [progress](docs/progress.md),
[container contract](docs/decisions/0002-experimental-container.md) and
[fixture protocol](docs/fixtures.md). Implementation steps use stacked feature
branches. The controlled Linux native slice does not establish mixed apps,
archived/host Python or Node startup, signed macOS deployment, or four-OS
compatibility. Their feasibility and release gates remain open.
