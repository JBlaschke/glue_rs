# MVP contracts

Specification, 15 October 2026; pending implementation. Read with
[PLAN.md](../../PLAN.md) and [decision 0035](../decisions/0035-mvp-delivery-and-runtime-scope.md).
These semantics prevent task owners inventing incompatible layouts or CLI flags.
Internal type names are sketches; C01 maps them into the existing schema.

## Distribution and shared data

```text
my-app/
  glue                    # target launcher
  app.glue                # manifest, app sources/resources/metadata
  glue.lock.json          # resolved inputs and transformations
  build-report.json       # outputs, requirements, sizes, omissions
  runtime/                # selected executable/helper, runtime native deps
    ...                   # Python stdlib ZIP if needed for stock startup
  native/<closure-id>/...  # package libraries with needed relative layout
  support/                # bounded glue bootstrap/bridge files
  licenses/               # notices; a combined indexed file is acceptable
```

Create only used directories. Stage completely before atomic publication; failure
leaves the requested output absent. Refuse existing outputs by default. Runtime
never creates missing payloads. Resolve siblings relative to the archive, not cwd
or the builder's prefix. Required runtime locations inside a preserved distribution
may differ from this sketch; the manifest records them.

`app.glue` declares `delivery=compact`, required relative payload paths, sizes and
hashes. Native bytes have one authoritative deployed copy, not a duplicate in ZIP.
A second stdlib archive is allowed for Python bootstrap. Avoid loose source trees.
The external report records the final archive hash; avoid circular self-hashes.
No original absolute build path may be needed after relocation.

Use one application entry/runtime per MVP artifact. Keep the old low-level
`glue build --manifest ...` interface and experimental archives. New semantics
need an explicit manifest revision; never reinterpret old `bundled` silently as
adjacent files. Keep archive bounds, canonical paths and integrity verification.
Legacy 1,024-file/8 MiB application fixture limits are not product requirements.
Choose documented configurable product limits that admit the MVP corpus and
10,000-entry scale test while retaining bounded parsing, decompression and memory.

Shared contracts to implement before adapters:

- `RuntimeDescriptor`: exact implementation/version, provider, target, ABI/GIL/
  debug/numeric/addon modes, inputs and payload identities.
- `NativeInventory`: root modules, dependency edges, selected providers, deployed
  paths, host requirements, required binary features and transformations.
- `RuntimeLaunchSpec`: executable/helper, argv, environment, archive access and
  stdio/signal policy. No shell command strings.
- `BuildReport`: selected runtime, complete payload inventory, source/output
  hashes, omissions, transformations, compatibility limits and size accounting.
- `BuildLock`: resolved input identities and runtime constraints, usable offline;
  content identity is not a trust catalog.

## Common selection and CLI

Default `--delivery compact --runtime-mode bundled`. Memory mode is accepted only
for proven profiles; fail before publication otherwise. Explicit host mode declares
its prerequisites and cannot satisfy bundled-mode acceptance. Copy a compatible
glue launcher into the output; users do not need glue installed on execution nodes.

Common options: `--output DIR`, `--entry PATH`, `--target TRIPLE`, `--json`,
`--config FILE`, repeatable `--native-search DIR`, and
`--normalize-native-paths`. Optional project `glue.toml` supplies defaults;
CLI wins. Search roots are build-time inputs, not runtime environment hacks.

Infer target from the selected runtime and confirm native inputs agree. Initial
builders run on the target OS/architecture. Cross-target inspection must not
execute foreign interpreters or imply tested cross-target builds. Report libc,
minimum OS/CPU and runtime ABI requirements, not merely OS/architecture.

Version constraints select from supplied/configured installed runtimes. Report
the exact selection; never silently fetch, substitute or rebuild. A future
explicit runtime-fetch command is convenience, not a prerequisite for BYO inputs.

## Python inputs and runtime

`glue build python --env DIR [--project DIR]`: project defaults to cwd, environment
defaults to its `.venv` if present. Ordinary and uv-created venvs use the same path.
`--runtime PATH` accepts a Python executable, installed runtime root or local PBS
archive, overriding discovered base runtime only if ABI-compatible. `--python
VERSION` constrains selection; it cannot retarget installed binary wheels.

Choose exactly one of `--entry FILE`, `--module NAME`, `--console-script NAME`.
Console entries come from distribution metadata, not absolute wrapper shebangs.
Without an entry, use only an unambiguous configured entry; otherwise explain the
candidates. Do not require an artificial `app/` input subtree or provider template.

Discover `pyvenv.cfg`, base-interpreter symlinks, exact version, SOABI, extension
suffixes, GIL/debug mode, stdlib, site-packages and distribution metadata. The
environment is an inventory; copying a venv verbatim is not general relocation.
[Python venv portability](https://docs.python.org/3/library/venv.html)

A selected local interpreter may run a bounded isolated metadata probe
(`-I -S -B`, timeout, captured output). Do not import app packages or run `.pth`,
sitecustomize, entry points or build hooks. Read `pyvenv.cfg` separately because
`-S` prefix behavior differs by Python version. Executing the user-selected
runtime is a documented build operation, not a sandbox for untrusted binaries.
Inspection-only/foreign-target paths use metadata and diagnose missing facts.

Accept PBS full/install-only/stripped inputs and installed/uv runtime trees.
Use distribution metadata where present, but do not require full-archive metadata
in an install-only tree. Record actual files, not moving uv selection symlinks.
Pair the selected runtime with its own stdlib. The subprocess route need not
require `libpython` if the executable works without it; its real dependencies
must still be collected. P00 proves relocatable startup with an archived stdlib.
[PBS formats](https://docs.astral.sh/python-build-standalone/distributions/)

Preserve installed packages, `.dist-info`, package assets and native wheel support
directories. Validate available RECORD entries; report unowned files rather than
silently discard them. Normal pip-containing environments are valid. Pruning
pip/tests/debug data is opt-in. Existing extensions require no source or headers.

Internal path-only `.pth` entries may be incorporated explicitly. Executable
`.pth`, editables and uncontrolled system-site access initially reject with a
remedy. Resolve safe internal symlinks; treat the known venv base-runtime link
separately from arbitrary escapes. Do not execute package installation hooks.

Run Python isolated with cache/bytecode writes and user-site leakage disabled.
Start from the selected runtime and stdlib archive, then install application
imports before app code. Preserve namespace packages, import caching, metadata,
and single-/multi-phase extension lifecycle by delegating native initialization
to stock Python loaders at declared deployed paths. Virtual source origins are
not OS paths. Support `importlib.resources` streams and reject archive `as_file`
materialization. Map declared native locations for `ctypes` and tested CFFI
routes; arbitrary native `fopen`/`dlopen` is not automatically virtualized.

## Lua inputs and runtime

`glue build lua DIR --lua 5.4|5.5`: default entry `main.lua` if present, otherwise
require `--entry`. Collect project sources/assets and existing native modules.
`--rocks-tree DIR` consumes an installed LuaRocks tree without installing/compiling
rocks. Preserve logical Lua module paths and selected-version native layouts.

One packaging CLI selects either family without user Cargo builds. Ship only
the selected linked helper, built with glue rather than the user's app. Do not
load 5.4 and 5.5 in one process. Record patch version, integer/number ABI and
required exports; never treat 5.4 and 5.5 native modules as interchangeable.
When binary metadata cannot establish a module ABI, require its declaration.

Reuse C-owned Lua state and protected error boundaries. Use normal OS loading
for compact native modules bound to the matching Lua API. Preserve `require`
caching and archive `loadfile`/`dofile` and resource methods. Application host I/O
is allowed; archived paths remain read-only. `package.loadlib` resolves declared
native entries; unsupported bytecode or path-required behavior gets a useful
error. No LuaJIT or older-Lua compatibility work.

## Node inputs and runtime

`glue build node DIR --node PATH`: consume package.json, existing dependencies,
assets and explicit/unambiguous entry. `--node` selects an executable/runtime
root; `--node-version RANGE` constrains installed selection. Record Node-API
support and module ABI. No install/postinstall/build scripts; TS/toolchain projects
provide already runnable output. Lockfiles supply provenance; installed bytes
are the payload, and lock/install differences are reported.

Stock Node subprocess plus bounded bootstrap and glue-owned Rust Node-API archive
reader is the first design. N00 proves it. The reader reuses format/resources;
do not write a separate JavaScript ZIP parser. Its glue-owned bridge is built with
glue; user addons are not recompiled and require no catalog membership.

Use version-checked public hooks for CJS/ESM. Preserve package exports/imports,
conditions, package type, JSON, relative/bare imports, cache identities and declared
dynamic imports. A generated index is allowed; flattening conflicting dependency
versions is not. Normalize npm/pnpm installed layouts into a logical graph while
checking symlinks. Yarn PnP may initially reject with an explicit explanation.

Provide resource reads and a bounded Node fs facade for virtual paths: readFile
(sync/callback/promises), stat, readdir, exists and streams. Real host paths retain
normal behavior. Unsupported fd/mmap/write operations on virtual paths fail.
Test this separately: module hooks do not virtualize all filesystem operations.

Stock Node loads declared deployed `.node` addons and their dependencies. Start
with Node-API, checking the required version; legacy V8/NAN support follows later.
Disable on-disk compile caches. Worker-thread/child bootstrap and native helper
executables require later explicit gates. Execution needs neither npm nor Deno.

Node SEA's documented native-addon path writes a temporary file, so it cannot
substitute for our memory loader. Deno is not assumed to remove this requirement.
[Node SEA limitations](https://nodejs.org/api/single-executable-applications.html#native-addon-limitations)

## Native collection, ownership and diagnostics

Resolve dependencies to the selected runtime, a bundled image or a declared
system/host prerequisite. Preserve `$ORIGIN`, `@loader_path` and `@rpath`
relationships where possible; do not flatten by basename. Reject wrong target,
missing edges, escapes and incompatible runtime identities before publication.
Computed native loads need declarations; static inspection cannot prove all
possible execution paths. System dependencies follow the target baseline, not
whatever happens to be installed on the builder. Musl is a separate later profile.

Compact loading uses the OS's TLS, constructors and unwind handling. Do not apply
memory-parser restrictions to ordinary OS-supported binaries. Preserve allocator
ownership and exception/panic boundaries; do not rebuild C++/Rust modules to make
them “C-only.” Pin glue-owned handles while callbacks/threads might use them;
arbitrary unload/reload is not part of the MVP.

Preserve input bytes if already relocatable. Otherwise fail with the precise
proposed edits and `--normalize-native-paths` remedy. That option permits load-path
metadata edits, not semantic code changes. Record input/output hashes, independently
validate metadata and re-sign Mach-O as required. Host runtimes never substitute
silently for missing bundled dependencies.

`doctor` checks mode, runtime/ABI, files and host prerequisites without running
application code. `run` forwards argv, stdin/out/err, exit status and signals;
child errors must not become launcher success. No cross-language RPC is needed.

Build verifies all payloads. Runtime verifies consumed archive members and
required binaries before use, without scanning loose source trees. Initial
compact mode assumes immutable deployment storage; document mutable-storage
check/exec races rather than claiming signature-grade security. No unchecked cache.

Errors name input, feature/edge, target/runtime and next action. JSON reports have
stable codes. Inspect/size reports list deployed files, dependencies and large
contributors. Explicit include/exclude/pruning options report every omission.
No aggressive pruning inferred from incomplete import traces.

Reserve stable error categories for missing input/entry/dependency, runtime ABI
mismatch, target mismatch, unsupported capability/mode, path escape, payload
integrity failure, transformation required, and runtime process failure. C01
defines exact spellings once; each adapter supplies structured context, not its
own incompatible error protocol.
