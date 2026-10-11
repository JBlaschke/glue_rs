# Public native registration with stock Python

This controlled GNU Linux arm64 fixture adds four reviewed native initializers
and a private dependency to the shared
[archive source/resource app](../python-imports/README.md). It uses unchanged
CPython 3.13.16 / PBS `20261009`, conventional GIL, non-debug ABI and verified
stock headers. The runtime and native-image locations vary independently:

| Cell | Runtime | Native images |
| --- | --- | --- |
| `bundled-archived` | Sealed bundled library | Sealed archived images |
| `bundled-host` | Sealed bundled library | Explicit read-only host files |
| `host-archived` | Explicit read-only installation | Sealed archived images |
| `host-host` | Explicit read-only installation | Explicit read-only host files |

The commands are:

```text
glue-python-bootstrap-probe prepare-extensions BASE.glue NATIVE_DIRECTORY archived|host OUTPUT.glue
glue-python-bootstrap-probe run-extensions OUTPUT.glue
glue-python-bootstrap-probe run-extensions-negative OUTPUT.glue app-error
glue-python-bootstrap-probe corrupt-extensions INPUT.glue CORRUPT.glue
```

The base must match the existing bundled-import or installed-host-import
profile. Preparation verifies every base resource and the five compiled ELF
images, then creates a new output. Host image paths and hashes are explicit;
there is no search-path discovery. The selected directory supplies
`libglue_python_dependency.so` and `glue_native_{single,multi,init_error,exec_error}.so`,
each bounded to 256 KiB. Native C is trusted; declared hashes identify the bytes
and do not make arbitrary extension code safe.

With the [cached PBS inputs](../python-pbs/README.md) and recorded Linux image
and Rust 1.88.0 available, run from the repository root with fresh directories:

```sh
sh fixtures/python-extensions/run-linux.sh target/python-extensions-validation \
  target/python-extensions-validation-build
```

The harness compiles the C fixtures and a separate dynamic stock-runtime
registration driver. That comparison executes the native conformance app
without the Rust adapter. The opt-in `pbs-bootstrap` build adds boundary API
revision 4: 29 acquired public exports, a 240-byte table, and no direct Python
link. C registers copied names through public `PyImport_AppendInittab` before
initialization; stock `BuiltinImporter` handles the native initialization.
Registered modules honestly report origin `built-in`, appear in
`sys.builtin_module_names`, and have no file/cache location. This is a registered
initializer experiment, not general `ExtensionFileLoader` integration.

The app checks single-phase `m_size=-1` caching, reload and original-dictionary
restoration after removal/reimport, including shared method objects. It checks
fresh independent multi-phase module state, no execution on reload, cleanup and
retry after initializer/execution-slot errors, and ordinary method errors.
Retained old/new modules call the private dependency during an `atexit` callback
inside actual finalization. The existing archive import/resource checks run
first, then the native app prints:

```text
GLUE_PYTHON_EXTENSIONS_PASS single=42 multi=44 retry=2 dependency=42
```

All archive resources are verified and the archive closes before native host
lookup. Host files and ancestors reject symlinks; bounded descriptor-based hashes,
EOF checks and rewinds precede loading. Installed host runtimes retain their
69-source/cache-absence prerequisites. Host trees must remain immutable and
read-only throughout execution; open descriptors do not freeze mutable files.

All native ELF images pass admission before loading. A separate data-import
opt-in permits only the reviewed global `PyExc_RuntimeError` variable import
with ordinary `GLOB_DAT`; the original Lua inspector still rejects object
imports. Native constructors, TLS, IFUNCs, additional dependencies, versions and
undeclared/weak imports reject. GNU loading is eager and local, dependency first.
Exact runtime/dependency SONAME reuse is followed by checking every function,
data and relative relocation slot against its expected provider. Runtime/native
exports remain absent from global lookup. Successfully loaded descriptors and
loader handles remain pinned through finalization and until process exit,
including later failure paths. C-copied names stay pinned from the first
registration attempt, including partial registration failure.

The runtime harness removes producer executables, headers and Cargo/native
build intermediates. A separate unprivileged, offline, read-only cell runs
without the workspace, with unavailable temporary paths and poisoned Python
environment variables. Its complete traces cover the four successful
cells, their four matching app-error runs, `corrupt-native` (the first stored
dependency byte), `missing-host-image` (the explicit dependency), and
`wrong-host-image` (a same-size altered single-phase image). Invalid images must
reject before Python initialization; archived corruption must reject before
runtime mapping or host lookup. The [clean capture](../../docs/evidence/pbs-linux-arm64-python-extensions-2026-10-10/README.md)
from implementation `b784c99` passes all eleven cases and twenty-two prior
Python regressions. It retains complete compressed traces, exact native ELF
files, manifests, metadata, provenance and replay results. Mac/Linux workspace
checks pass 338/339 tests for Lua 5.4/5.5 and Clippy; portable Python tests pass
59 checks and the GNU opt-in fixture passes 65 release tests and Clippy. All 191
trace-policy tests (30 native registration checks) and both 16-test importer
protocol runs pass. Independent replay rejects all 37 hostile trace edits.

Product Python execution/discovery, arbitrary wheels/extensions, mutable host
installations, subinterpreters, general extension-file metadata, unloading and
other versions/platforms remain open. G0/G1/G2 remain open. See
[the decision](../../docs/decisions/0015-python-registered-extensions.md).
