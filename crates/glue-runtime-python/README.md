# Pinned PBS Python runtime

This crate owns execution mechanisms shared by the product runner and the
Python bootstrap probe. Its public registry supports bounded bundled source
applications and the existing exact source/resource and registered-native
declaration profiles for stock CPython
3.13.16 / PBS `20261009`, conventional GIL, non-debug ABI, on GNU Linux arm64.
General host-stdlib and native package compatibility remain pending.

The runner enables execution with `--features python-pbs`; the crate feature
is `pbs-bootstrap`. Default runner builds need no Python headers. On the exact
supported target, building the C boundary requires
`GLUE_PYTHON_INCLUDE_DIR` to name the independently verified installed stock
header tree. Python is acquired dynamically from the selected provider and is
never a link-time dependency. Feature-enabled builds on other targets can
validate declarations but cannot execute Python.

The registry contains:

| Application identity | Runtime | Native images |
| --- | --- | --- |
| Arbitrary admitted ID with the bundled-source-apps-v1 build identity | Bundled, sealed library | None |
| `stock-pbs-archive-imports` | Bundled, sealed library | None |
| `stock-pbs-host-archive-imports` | Explicit immutable host installation | None |
| `stock-pbs-registered-extensions` | Either provider above | Archived sealed images or explicit immutable host files |

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

Host validation covers the controlled app's 69-source dependency closure and
required absent bytecode-cache locations. The host installation and native
files must stay immutable and read-only throughout execution. Open descriptors
do not freeze mutable backing bytes, and this profile does not validate an
arbitrary installed stdlib or site-packages tree. Bundled archive imports and
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
