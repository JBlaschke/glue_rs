# Pinned PBS Python runtime

This crate owns execution mechanisms shared by the product runner and the
Python bootstrap probe. Its public registry supports bounded bundled and host source
applications and the existing exact source/resource and registered-native
declaration profiles for stock CPython
3.13.16 / PBS `20261009`, conventional GIL, non-debug ABI, on GNU Linux arm64.
General installation discovery and native package compatibility remain pending.
Separate metadata-aware source profiles add public `importlib.metadata`
discovery for bounded application `.dist-info` inventories. They validate
identities, canonical RECORD paths, ownership, hashes and sizes before provider
acquisition, then expose metadata and files through the immutable resource
callbacks. The legacy importer and source profiles retain their existing pins.
`Requires-Python` is admitted against the selected pinned version using the
bounded numeric release subset in
[decision 0025](../../docs/decisions/0025-python-real-package-compatibility.md).
Duplicate/folded, unsupported or unsatisfied fields reject. The same portable
check applies to installed packages and explicit application metadata before
builder provider reads or publication.
See [the metadata fixture](../../fixtures/python-metadata/README.md).
The portable `packaging` facade admits metadata provider templates and checks
owned application contents for the build-time installed-package adapter. It
shares the runtime's identity/RECORD policy without acquiring a provider or
initializing Python; see [decision 0022](../../docs/decisions/0022-python-installed-package-ingestion.md).
Its `packaging::template` constructors prepare the exact bundled metadata profile
from pinned PBS/frozen inputs or declare full/install-only host prerequisites
from an explicit prefix. The bundled constructor verifies the complete frozen
identity before reading PBS; host constructors perform no filesystem discovery.
`glue python-template` stages the resulting manifest, owned resources and
provenance for `build-python`. See [decision 0023](../../docs/decisions/0023-python-runtime-templates.md).
`packaging::host_prerequisites` prepares the exact full/install-only host library,
source and cache projections as owned bytes from pinned artifacts. `glue
python-host` publishes these embedding prerequisites on Unix builders with fixed
permissions and mtimes, without executing Python. Complete installations and uv
discovery remain separate work. See [decision 0024](../../docs/decisions/0024-python-host-prerequisites.md)
and the [Mac/GNU preparation and execution evidence](../../docs/evidence/pbs-linux-arm64-python-host-prerequisites-2026-10-13/README.md).

The runner enables execution with `--features python-pbs`; the crate feature
is `pbs-bootstrap`. Default runner builds need no Python headers. On the exact
supported target, building the C boundary requires
`GLUE_PYTHON_INCLUDE_DIR` to name the independently verified installed stock
header tree. Python is acquired dynamically from the selected provider and is
never a link-time dependency. Feature-enabled builds on other targets can
validate declarations but cannot execute Python. On macOS arm64 the same
boundary compiles when `GLUE_PYTHON_INCLUDE_DIR` names the pinned macOS
install-only artifact's header tree, checked against
`fixtures/python-host-macos/header-pins.json`; without it, Mac builds keep
validating only. That cell supports the experimental `run-host-macos` probe
route described in [decision 0031](../../docs/decisions/0031-macos-python-host-startup.md).

The registry contains:

| Application identity | Runtime | Native images |
| --- | --- | --- |
| Arbitrary admitted ID with the bundled-source-apps-v1 build identity | Bundled, sealed library | None |
| Arbitrary admitted ID with the host-source-apps-v1 build identity | Explicit immutable host library/startup paths; full pinned source snapshot | None |
| Arbitrary admitted ID with the host-install-source-apps-v1 build identity | Explicit immutable host paths; install-only source snapshot and three pinned startup caches | None |
| Arbitrary admitted ID with the bundled-metadata-apps-v1 build identity | Bundled source applications with bounded distribution metadata | None |
| Arbitrary admitted ID with the host-metadata-apps-v1 build identity | Full-source host applications with bounded distribution metadata | None |
| Arbitrary admitted ID with the host-install-metadata-apps-v1 build identity | Install-only host applications with bounded distribution metadata | None |
| `stock-pbs-archive-imports` | Bundled, sealed library | None |
| `stock-pbs-host-archive-imports` | Explicit immutable host installation | None |
| `stock-pbs-registered-extensions` | Either provider above | Archived sealed images or explicit immutable host files |
| `stock-pbs-native-lifecycle` | Either provider above | Separate four-image lifecycle closure, archived or explicit immutable host files |
| `stock-pbs-native-packages` | Either provider above | Same lifecycle images, imported as descriptor-backed dotted package children |
| `stock-pbs-host-startup-macos` (experimental probe only) | Explicit immutable macOS arm64 installation of the pinned install-only artifact, loaded by dyld | None |

Source applications declare their own entry, modules and assets below `app/`;
importable sources live below `app/python/`. Runtime, importer, frozen startup
and stdlib identities stay pinned. App inventory limits are 1,024 files, 8 MiB
combined, 4 MiB per file and 64 KiB for the entry. Reserved runtime names,
unsupported module layouts, bytecode/cache/native paths and provider drift
reject before acquisition. See [the source application contract](../../docs/decisions/0017-bundled-python-source-apps.md).

Historical fixture admission preserves the exact app/helper/source declarations,
provider layout, ABI, target and inventories. The registered-native profile admits a fixed
five-image dependency/API/ELF contract using declared image hashes. Those hashes
identify bytes; they are not fixed compiled fixture pins or a safety guarantee
for native C. It uses stock `BuiltinImporter` registration metadata and does
not provide extension-file discovery.

The separate native lifecycle profile admits three custom-create roots and an
integer-only ledger dependency, with its own finite public import set. After the
C boundary returns from interpreter finalization, the pinned ledger must report
complete cleanup for the controlled workload; passing checks preserve the
original application result. The historical native profile performs no ledger
calls. See [the lifecycle fixture](../../fixtures/python-native-lifecycle/README.md).

The native package profile delegates three declared dotted children to stock
`ExtensionFileLoader`. A scoped callback exposes their retained descriptor aliases
and checks native ownership around creation/execution. Parent source/resources
stay in the archive; native metadata truthfully names `/proc/self/fd/N`. This route
supplies zero built-in registrations and retains the unchanged C boundary. See
[the package-member fixture](../../fixtures/python-native-packages/README.md).

Open an archive once, validate its declarations, then pass that same owner into
execution:

```rust
let archive = glue_format::Archive::open_with_limits(
    std::fs::File::open(path)?,
    glue_runtime_python::profile::archive_limits(),
)?;
let selected = glue_runtime_python::profile::validate(archive.manifest())?;
glue_runtime_python::execute(archive, selected)?;
```

`ControlledProfile` is opaque and tied to its admitted manifest. `validate`
is portable and does not inspect host files. `readiness(&selected)` checks build
and platform prerequisites without loading Python; it is useful for doctor
reporting. `execute` revalidates the token and performs readiness once, so run
callers need no additional readiness call. `ExecutionError::is_unsupported()`
distinguishes unavailable capability status 2 from invalid/integrity/application
failure status 1.

Each profile rechecks its original archive bounds with
`Archive::check_limits` before reading any payload. That check uses actual
opened layout facts without I/O. Required resources verify into owned memory
and the archive closes before explicit host lookup. The synchronous C boundary
owns initialization, execution, finalization and Python objects; no Python
object or API pointer is public. Archive callbacks, frozen records, host files
and directory leases remain live through finalization. Successfully loaded
provider handles stay pinned for process life, and a process may attempt one
Python lifecycle.

Historical host validation covers the controlled app's 69-source dependency closure and
required absent bytecode-cache locations. The new host source-app profile
verifies all 2,174 pinned sources into an owned snapshot, checks derived cache
locations and startup shadows, and removes ordinary filesystem import fallback
before installing the same shared importer. Individual snapshot source
descriptors close promptly. Already initialized host startup modules retain
their stock metadata; later source modules use virtual origins. See
[decision 0018](../../docs/decisions/0018-host-python-source-apps.md).

The separate install-only host profile snapshots its 1,037 pinned sources and
requires the exact three shipped startup caches in a closed encoding-cache
directory. Every other derived cache location remains forbidden. Cache owners
join startup and directory leases through finalization. The 256-directory cap
is supplemented by a 763-total-owner cap before host access. Its bounded helper
stages app-only archives without a full runtime archive. See
[decision 0019](../../docs/decisions/0019-install-only-host-python-source-apps.md).

The host installation and native
files must stay immutable and read-only throughout execution. Open descriptors
do not freeze mutable backing bytes, and this profile does not validate an
arbitrary installed stdlib or site-packages tree. Shared source imports and
resources preserve virtual diagnostic origins, source-only compilation,
read-only seekable streams and `as_file`/legacy `path` rejection.

`experimental::dispatch` retains fixture preparation, disk baselines and
negative controls for the thin `glue-python-bootstrap-probe` executable.
Product `execute` exposes none of those overrides. The optional CLI route
does not add runtime discovery, unloading, workers or another platform/ABI.

See [decision 0016](../../docs/decisions/0016-controlled-python-runner.md) for
the ownership and scope contract.
The [source-app evidence](../../docs/evidence/pbs-linux-arm64-python-source-apps-2026-10-12/README.md)
retains six application traces and 42 fresh regression traces from clean
`d3ddac3`, all independently replayed. The shared optimized GNU builds pass
87 tests and Clippy; the unchanged C bridge and Linux loader retain API4,
29 selected exports and a 240-byte table.

The [host source-app evidence](../../docs/evidence/pbs-linux-arm64-python-host-source-apps-2026-10-12/README.md)
retains the paired explicit-host provider's 13 cases and 48 fresh regressions
from clean `dd6274f`. All 61 complete traces replay, all 51 new controls agree
and all 567 hostile trace edits reject; optimized GNU shared builds pass 102
tests and Clippy. The C boundary and selected GNU library mapping implementation
remain unchanged.

The [install-only host evidence](../../docs/evidence/pbs-linux-arm64-python-install-host-source-apps-2026-10-12/README.md)
retains 16 stock/cache cases and 61 fresh regressions from clean `7a8e32c`.
All 77 complete traces replay, all 60 new controls agree and all 894 hostile
edits reject; optimized GNU shared builds pass 116 tests and Clippy.
