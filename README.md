# glue_rs

A Rust packager and launcher under development for Python, Node.js and Lua apps
in a read-only archive. The runtime contract forbids payload extraction and
silent runtime-provider fallback. See [PLAN.md](PLAN.md) for the full design.

The current implementation packages explicit resources, validates manifest and
ZIP32/ZIP64 metadata, verifies stored/deflate contents, and exposes a read-only
resource tree with bounded memory caching. Experimental **linked Lua 5.4.9 and
5.5.1 source profiles** run archive scripts and resources on matching macOS or GNU
Linux targets. General native loading, host/archived runtime acquisition,
general Python/Node compatibility, workers and standalone executables remain pending.
The archive and manifest are experimental version 0; G0/G1/G2 remain open.
An experimental worker-message codec and controller ledger are tested through
synthetic Rust peers over anonymous pipes. Runtime worker execution and
cross-language calls remain pending; see
[the protocol fixture](fixtures/worker-protocol/README.md).
Separate pinned Python metadata profiles expose application `.dist-info`
through `importlib.metadata`, including plugin entry points and virtual RECORD
file reads. They reuse the bundled/full-host/install-only providers; see
[the metadata fixture](fixtures/python-metadata/README.md). The opt-in
`build-python` adapter packages a bounded source-only installed package tree or
Python 3.13 venv against an admitted runtime template, without running the input
interpreter. General wheel installation and native-package ingestion remain pending.
An opt-in GNU Linux arm64 profile also runs a controlled native Lua closure
through sealed executable memfds in `glue run`. The optional `python-pbs` build
also routes the exact controlled PBS source/resource and registered-native profiles
through `glue doctor` and `glue run`; it requires GNU Linux arm64 and verified
CPython 3.13.16 headers at build time.

## Build from installed Python packages

Build with `--features python-pack` for portable packaging, or `python-pbs` for
the existing GNU Linux arm64 execution support. Prepare a provider template with
`python-template`; it fixes the runtime, target and provider bytes independently
of the venv. Application input contains an `app/` subtree, including the selected
entry. For example:

```sh
cargo build --locked -p glue-runner --features python-pack
target/debug/glue python-template --provider bundled \
  --pbs-full PINNED_FULL.tar.zst --frozen-bootstrap PINNED_BOOTSTRAP.json \
  --output target/python-provider --json
target/debug/glue build-python \
  --provider-template target/python-provider/manifest.json \
  --provider-root target/python-provider/root \
  --app APPLICATION_DIR --venv VENV_DIR --app-id my.application \
  --entry app/main.py --output target/my-application.glue --json
```

The bundled template accepts the exact CPython 3.13.16 / PBS `20261009` GNU Linux
arm64 full archive and the [retained frozen startup bundle](docs/evidence/pbs-linux-arm64-python-venv-2026-10-13/freeze-bundle.json).
It verifies both inputs and preserves the pinned library and 2,174 source files.
Preparation works on Mac without executing the target interpreter. Use
`--provider host-full --host-prefix /absolute/target/prefix` or
`--provider host-install --host-prefix /absolute/target/prefix` instead to declare
the exact full or install-only host prerequisite. Host preparation does not
inspect or install that prefix; execution verifies the actual installation.
`provenance.json` and JSON stdout record these distinctions and all resource
identities. The output parent must exist and the output directory must be new.

Prepare the admitted host prerequisites with `python-host` when needed:

```sh
target/debug/glue python-host --provider host-install \
  --pbs-install-only PINNED_INSTALL_ONLY.tar.gz \
  --output "$PWD/target/python-host" --json
target/debug/glue python-template --provider host-install \
  --host-prefix /absolute/deployment/python-host \
  --output target/host-provider --json
```

Use `--provider host-full --pbs-full PINNED_FULL.tar.zst` for the full-source
profile. Unix builders, including Mac, can prepare both GNU-target trees without
executing Python. The output contains the pinned embedding library and exact
source/cache prerequisites, plus provenance; it omits the executable, headers
and other unselected stock contents. Files receive mode `0444`, directories
`0555`, and mtimes the fixed stock epoch. Keep the deployed tree on immutable
storage at the template's declared prefix. Preparation protects existing outputs
and requires an absolute admitted prefix with an existing parent. See the
[host-prerequisite fixture](fixtures/python-host-prerequisites/README.md).

An explicit installed runtime tree can supply the install-only prerequisites:

```sh
target/debug/glue python-host --provider host-install \
  --runtime-tree /absolute/pinned/python-installation \
  --output "$PWD/target/python-host" --json
```

This reads the same 1,041 pinned files without running the input interpreter.
It accepts the exact stock layout or the tested uv 0.12.23 layout from an
explicitly configured unstripped PBS installation. For that uv layout, it
records and restores the one relocated sysconfig source to the stock embedding
configuration. Other versions require separate support.
The report distinguishes selected tree inspection from archive inspection;
unselected files are neither read nor copied. Input and output trees must not
overlap. See the [installed-runtime-tree fixture](fixtures/python-runtime-trees/README.md).

For the separately pinned PBS `20261009` CPython 3.13.16 GNU Linux arm64
`install_only_stripped` image, use `--provider host-install-stripped` in both
commands. It accepts the exact stripped archive with `--pbs-install-only`, or
its stock selected tree with `--runtime-tree`. Its library is 22,177,832 bytes;
the source and three cache prerequisites match the unstripped provider. Both
profiles verify their own library identity and reject the opposite image.
Stripped tree input currently requires stock sysconfig; the uv normalization
above belongs to the tested unstripped input. This is an explicit PBS pin and
does not admit uv's default catalog or select another version. See the
[stripped-host fixture](fixtures/python-stripped-host/README.md).

Use `--site-packages PACKAGE_DIR` instead of `--venv` for an explicit installed
package directory. Venv convenience mode accepts the conventional
`lib/python3.13/site-packages` layout with system site-packages disabled. It reads
configuration and package files; it does not activate the environment, execute
its interpreter, install dependencies or resolve them. The complete package
inventory must be source-only and fit the existing 1,024-file / 8 MiB application
limits. Seeded pip/setuptools environments are not silently pruned.

Distribution `Requires-Python` fields are checked against the selected runtime
before provider files are read or an output is created, including metadata in
the explicit application tree. The admitted subset supports bounded numeric
release comparisons, comma-conjoined ranges, equality/inequality `.*` prefixes
and `~=` compatible releases. Missing fields impose no extra constraint;
duplicate, folded, empty, incompatible or unsupported specifiers reject.
This validates the pinned version and does not select or download another one.
The [real-package fixture](fixtures/python-real-packages/README.md) exercises
unmodified Markdown parser/plugin wheels through all three providers.

Source, data and metadata bytes are preserved. RECORD is verified and rewritten
for archive paths; bytecode and recognized generated console/gui wrappers are
omitted and reported. Native files, editables, `.pth` hooks, escaping paths and
unowned files reject before output creation. `--json` records input identities,
distribution identities, omissions and final archive hashes. The command still
uses the explicitly prepared provider template; automated runtime/version
selection, general runtime installation and package compatibility remain later
work. See the [runtime-template fixture](fixtures/python-runtime-templates/README.md),
[offline venv fixture](fixtures/python-venv-ingestion/README.md) and
[ingestion contract](docs/decisions/0022-python-installed-package-ingestion.md).

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
startup subset, exact runtime profile and trace protocol. This checkpoint
established the frozen-startup mechanism.
The [clean bootstrap capture](docs/evidence/pbs-linux-arm64-bootstrap-2026-10-10/README.md)
matches ordinary loading and passes all four complete syscall checks after the
producer installation and headers are removed.

The separate [host startup fixture](fixtures/python-host/README.md) selects that
exact library with its installed stdlib through explicit host paths. It verifies
the library and six startup sources, rejects startup bytecode caches and uses
the installed encodings package without our frozen bundle. General host
discovery remains pending.
The [clean host capture](docs/evidence/pbs-linux-arm64-host-python-2026-10-10/README.md)
passes all eight host traces and four frozen-bootstrap regression traces from
the same implementation commit.

The [archive source/resource fixture](fixtures/python-imports/README.md) extends
the bundled startup experiment with Rust-owned source resolution and actual
`importlib.resources` streams. It exercises modules, packages, one-portion
namespaces, virtual origins, import caching/reload, source encoding and binary/text
assets. Materializing resource helpers reject before temporary-file attempts.
This checkpoint established the controlled bundled source/resource adapter.
The [clean import capture](docs/evidence/pbs-linux-arm64-python-imports-2026-10-10/README.md)
passes all three import traces and twelve earlier startup regression traces from
the same implementation commit.

The [host archive-import fixture](fixtures/python-host-imports/README.md) uses
the same app/importer with explicit installed paths. Its 18-entry archive holds
only app/helper/assets; the host owns the stdlib. It verifies the library,
69 reviewed sources and absence of relevant caches before loading. Archive-owned
packages and namespaces block filesystem fallback, while installed
`importlib.resources` reads the archive's streams. Controlled product integration
is described below.
The [clean host-import capture](docs/evidence/pbs-linux-arm64-host-imports-2026-10-10/README.md)
passes seven host-import traces plus fifteen bundled-import/startup regressions
from the same implementation commit.

The [registered native fixture](fixtures/python-extensions/README.md) adds
single-phase and multi-phase initialization through stock `BuiltinImporter`.
The selected runtime stays private; native function and data relocation slots
must bind to that runtime or the declared private dependency before registration.
Runtime and native providers vary independently across bundled/explicit-host and
archived/explicit-host inputs. This controlled GNU Linux arm64 profile exercises
cache/reload/removal, initialization/execution errors and retry, and finalization
callbacks. General extension-file loading remains open. The controlled registry is now
shared with the launcher through `glue-runtime-python`; the earlier probe
remains a thin experimental fixture CLI.
The [clean native capture](docs/evidence/pbs-linux-arm64-python-extensions-2026-10-10/README.md)
passes eleven matrix/control traces and twenty-two earlier Python regressions
from implementation `b784c99`, with all 37 hostile trace edits rejected.

The separate [native lifecycle fixture](fixtures/python-native-lifecycle/README.md)
adds custom creation, owned reference cycles, GC callbacks and retry after
creation/execution failures. A private integer-only ledger verifies cleanup after
actual interpreter finalization, through the same four runtime/native provider
combinations. An independent stock registration driver checks the same lifecycle.

## Run the pinned Python profiles

The launcher feature is `python-pbs`; the shared executor's build feature is
`pbs-bootstrap`. The registry admits bounded bundled and explicit-host source applications,
the two exact bundled/explicit-host source/resource fixtures and the
registered-native declaration profiles with four independent runtime/native
provider combinations. The source profile accepts application-owned entries,
modules and assets while retaining the exact runtime, startup and stdlib pins.
See the [source application staging/build workflow](fixtures/python-source-apps/README.md).
The [explicit-host workflow](fixtures/python-host-source-apps/README.md) uses
the full pinned source projection from its selected installation. Source bytes
verify into an immutable snapshot before startup; later imports use the shared
buffer importer with filesystem fallback disabled. Installed startup paths must
remain immutable and read-only.
Broader host installations, wheels and native package admission remain open.
For the registered native profile, hashes identify declared images; admission
also requires the reviewed ELF/import/initializer contract.

The [install-only host workflow](fixtures/python-install-host-source-apps/README.md)
selects the independently pinned install-only distribution's 1,037 sources and
three encoding caches. All selected source/library/cache identities verify
before Python loads; the stock cache directory admits only its exact three
files. Later imports use the same owned source snapshot and virtual resource
streams. The full-source host profile continues to require its wider inventory
and reject every startup cache. See
[the install-only host decision](docs/decisions/0019-install-only-host-python-source-apps.md).

```sh
# GNU Linux arm64, using the independently verified pinned header tree:
GLUE_PYTHON_INCLUDE_DIR=/absolute/path/to/include/python3.13 \
  cargo build --locked -p glue-runner --features python-pbs
target/debug/glue doctor /absolute/path/to/controlled-profile.glue
target/debug/glue run /absolute/path/to/controlled-profile.glue
# On macOS, build and exercise the pinned Linux cell through Podman:
sh fixtures/python-runner/run-linux.sh
```

`doctor` validates the selected declarations and checks compiled target, kernel,
GNU libc and page size without starting Python or inspecting host providers.
`run` verifies archive payloads and host prerequisites before loading. The
opened archive transfers directly to the shared executor, with the selected
profile's size limits rechecked before reads. The C bridge owns one
synchronous interpreter lifecycle; loaded images remain pinned until exit.
Default builds report Python execution as disabled, while inspection and
verification accept the pinned runtime's 80 MiB member bound. See the
[runner fixture](fixtures/python-runner/README.md) and
[integration decision](docs/decisions/0016-controlled-python-runner.md).

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

`run` and `doctor APP.glue` return 0 for an admitted, ready profile, 2 for
unavailable providers or execution capabilities, and 1 for invalid declarations,
integrity errors or failed execution. `doctor` checks metadata and build/target
prerequisites without executing scripts or verifying every resource; use `verify`
for a complete content check. The original host resource fixture still returns
2. `build --standalone` remains unavailable with status 2. Successful core
operations return 0; input and argument errors return 1.

## Development and evidence

The install-only host source application checkpoint passes 395/396 Rust tests
for `lua54`/`lua55` on macOS and GNU Linux arm64, with all-target Clippy warnings
denied. The Mac Python-enabled workspace passes 395 tests and Clippy;
execution requires the reviewed GNU Linux arm64 target. Every optimized GNU
shared Python/probe build passes 116 tests and Clippy, and product runner
builds pass 14 CLI tests and Clippy. On Mac and pinned stock Linux, all 288
policy, 16 importer and seven byte-entry tests pass. The host source protocol
passes all 11 tests on stock Linux; Mac runs 11 with two stock-only skips.
All 16 new and 61 fresh regression traces pass from clean `7a8e32c` and all
77 compressed traces replay. The 60 new, 51 full-host, 34 bundled-app and
30 original product controls match; all 894 hostile trace edits reject.
The [install-only host evidence](docs/evidence/pbs-linux-arm64-python-install-host-source-apps-2026-10-12/README.md)
retains source/artifact identities, controls, the independent complete-provider
audit and full traces. The
[full-host checkpoint](docs/evidence/pbs-linux-arm64-python-host-source-apps-2026-10-12/README.md),
[bundled source-app checkpoint](docs/evidence/pbs-linux-arm64-python-source-apps-2026-10-12/README.md)
and [runner checkpoint](docs/evidence/pbs-linux-arm64-python-runner-2026-10-11/README.md)
retain the earlier provider/product evidence. Earlier native
Linux validation covers
both optional native profiles and
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
python3 -m unittest discover -s scripts -p 'test_linux_python_import_trace.py'
python3 -m unittest discover -s scripts -p 'test_linux_python_host_import_trace.py'
python3 -m unittest discover -s scripts -p 'test_linux_python_extension_trace.py'
sh fixtures/python-extensions/run-linux.sh
sh fixtures/python-runner/run-linux.sh
sh fixtures/python-source-apps/run-linux.sh
sh fixtures/python-host-source-apps/run-linux.sh
sh fixtures/python-install-host-source-apps/run-linux.sh
python3 -m unittest discover -s scripts -p 'test_linux_python_install_host_source_app_trace.py'
python3 fixtures/python-host-source-apps/test_protocol.py
python3 fixtures/python-source-apps/test_entry.py
python3 fixtures/python-imports/test_importer.py
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
general Python/Node compatibility, signed macOS deployment, or four-OS
compatibility. Their feasibility and release gates remain open.
