# Conformance fixture protocol

Fixtures must report the command, commit, native OS/architecture, toolchain,
runtime source/build IDs, supported features, unsupported features and observed
result. Preserve stdout/stderr, exit code and payload-write traces as evidence.
Record whether memory objects or direct mapping were used. Tests must not infer
no extraction from an empty directory after exit.
Since [decision 0030](decisions/0030-evidence-retention.md), a new evidence
directory keeps its README and inventories in Git and publishes the remaining
files as a verified release asset; `scripts/fetch-evidence.sh` restores them.

The first native fixture exports a function and data value, calls one archived
dependency and one actual OS dependency, and reports constructor count. Compare
it with normal OS loading. Wrong architecture, missing imports and unsupported
relocations must fail before a constructor. Later fixtures cover dependency cycles,
TLS on existing/new/library-created threads, callbacks, weak/versioned symbols,
unwind registration and runtime aliases. A trivial function call proves only that
fixture's declared ABI profile.

The integrated [Linux native Lua fixture](../fixtures/native/lua-linux/README.md)
uses the exact linked 5.4.9/5.5.1 core, one archived dependency and a versioned
libc `getpid` import. It checks constructor/data observations, selected-state
identity, real C-function caching and initializer/function errors, and routes
`package.loadlib` through the same retained initializer. All images are sealed
before the first constructor; ordinary loading and archive loading agree.
Portable adversarial tests validate closure metadata without running code;
actual GNU negative captures must reject before any memfd creation/loading.

The [macOS arm64 fixture](../fixtures/native/macos-macho/README.md) compares
ordinary dyld loading with a separate signed anonymous-mapping probe. Its
allow-jit/hardened-runtime launcher checks real function/data exports, one
archived dependency, libSystem `getpid` and a constructor. It never acquires
the schema's Lua scaffold. Complete tracing and Developer ID distribution
remain separate acceptance requirements; an unavailable tracer is recorded as
unavailable, not a no-extraction result.

Python startup must use actual stock PBS and compatible host libraries, import
`encodings`, `math` and `_ssl`, and prove library/stdlib identity. FreeBSD needs
its own bundled producer. Node and Lua fixtures must use the actual runtimes;
synthetic workers prove protocol behavior only.

The [product runtime-template fixture](../fixtures/python-runtime-templates/README.md)
prepares all three pinned providers through `glue python-template`, checks exact
resource/provenance identities and publication protection, then builds the same
genuine offline-installed application through `glue build-python`. Template
process/file/network traces distinguish host declarations from discovery.
The installed-package runtime policy, with its isolated inventory-specific host
adapter, checks all six valid/CRC-damage traces in the relocated, read-only GNU
Linux arm64 cell. Mac preparation of these
Linux-target templates establishes portable input processing, not Mac execution.

The [host-prerequisite fixture](../fixtures/python-host-prerequisites/README.md)
replaces historical host installer calls with `glue python-host`. Independent
oracles verify every published file, mode, mtime and inventory/provenance field.
Complete preparation traces distinguish writing the admitted library from reading
or mapping it for execution. A strict inventory-specific adapter of the six-mode
runtime policy tests the resulting full/install-only trees on immutable GNU Linux
storage; Mac preparation supplies cross-target byte/metadata evidence. The
[retained evidence](evidence/pbs-linux-arm64-python-host-prerequisites-2026-10-13/README.md)
includes two preparation traces, six runtime traces and compressed replays.

The [real-package fixture](../fixtures/python-real-packages/README.md) installs
three unmodified upstream Markdown parser/plugin wheels with stock offline pip
and independently audits the resulting source-only projection. It exercises all
three providers, real metadata/resources/console-callable behavior and early
Requires-Python rejection for both input forms. The
[clean evidence](evidence/pbs-linux-arm64-python-real-packages-2026-10-14/README.md)
retains six runtime traces, complete host preparation traces, process records,
32 requirement controls per builder and closed trace mutation/replay audits.

The [installed-runtime-tree fixture](../fixtures/python-runtime-trees/README.md)
uses a genuine, explicitly configured offline uv installation as selected input
to `glue python-host --runtime-tree`. Independent audits bind all 1,041 input and
output files, including one exactly admitted sysconfig normalization. Complete
preparation traces check selected-only descriptor reads and publication order;
the existing real-package runtime matrix and policies remain unchanged. Unselected
input contents are outside inspection, and default stripped uv builds are separate.
The [clean capture](evidence/pbs-linux-arm64-python-runtime-trees-2026-10-14/README.md)
retains complete preparation/runtime traces and independent compressed replays.

The [stripped-host fixture](../fixtures/python-stripped-host/README.md) compares
the separately authenticated stock stripped install-only artifact with the
unstripped input. Complete inventories, selected source/cache bytes and allocated
ELF contents support a distinct `host-install-stripped` metadata profile. Its
portable preparation audit verifies all 1,041 output files and original inventory
provenance; the native fixture covers explicit image selection, source/metadata/
resource execution and rejection before loading. Stock selected trees are admitted;
relocated uv stripped sysconfig and uv's default catalog remain separate work.

The [stock PBS bootstrap fixture](../fixtures/python-bootstrap/README.md) targets
the inspected GNU Linux arm64 library. It compiles pinned startup sources with
the matching stock producer at build time, removes that installation and its
headers, then executes a relocated read-only archive under full syscall tracing.
It compares the exact same library/bundle/app under ordinary loading and tests
missing encodings, corrupt marshal bytes and application errors. The comparison
is separate from the planned host provider using an installed standard library.

The separate [installed host fixture](../fixtures/python-host/README.md) uses
the shared app and exact same library with declared installed stdlib paths.
Its archive contains only the app. It verifies the library and six startup
sources, rejects startup caches, and initializes without our custom frozen
modules. Missing/mismatched libraries or sources, symlinked stdlib and cached
startup bytecode must reject before runtime mapping. A read-only installation
and complete trace establish this controlled startup subset; product host
discovery and general stdlib/package compatibility remain separate work.
The [macOS host startup fixture](../fixtures/python-host-macos/README.md)
repeats that startup subset on macOS arm64 with the pinned install-only
artifact, dyld path loading, `LC_UUID` binding, six installation rejections,
a loader-override rejection and unchanged read-only installation snapshots.
No unprivileged syscall tracer exists there; the evidence says so. The product
route of [decision 0032](decisions/0032-macos-python-product-route.md) serves
the same archives through `glue doctor` and `glue run` on that cell. Its
checked-in harness, `run-product-macos.sh` of
[decision 0033](decisions/0033-macos-python-product-harness.md), runs the
default-feature checks before the feature-enabled build, records doctor,
inspect, verify and run receipts for the valid archive, the six controls, a
loader override, a portably staged GNU Linux declaration and a feature-enabled
build without the header tree, all from the poisoned environment, and compares
every status and stream with exact expected values.

The [archive Python source/resource fixture](../fixtures/python-imports/README.md)
extends stock bundled startup with source modules, packages, single-archive
namespace portions and actual `importlib.resources`. Rust verifies all app,
stdlib sources and assets into bounded immutable memory before Python loading;
the C callback bridge transfers bytes without exposing Python objects to Rust.
Virtual origins, import caching/reload, encoding cookies, failure cleanup and
seekable binary/text streams are exercised. Materialization helpers must reject
before temporary-file attempts, and corrupt source must reject before any memfd.
The [installed-host archive-import fixture](../fixtures/python-host-imports/README.md)
uses the same app/importer, with stdlib imports owned by the host. Its archive
has only 18 app/helper/asset entries. All 69 reviewed installed sources and
12 cache locations are verified before loading; invalid supplemental sources
and nested caches reject before initialization. Host module/namespace lures must
remain unused. Native extension initialization and product integration remain
subsequent work.

Parser/resource fixtures may be synthetic and run on the development host. They
must cover deterministic output, stored/deflate and ZIP64 members, path/case
collisions, undeclared payloads, symlinks, encryption, unknown schema fields,
duplicate JSON keys, truncated/overlapping ranges, corrupt hashes/CRC, decoding
limits, positional reads, EOF, streams, cache bounds and a relocated archive.
Those tests are foundation evidence, not G1 or G2 acceptance.
