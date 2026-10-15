# Descriptor-backed native package members

This controlled GNU Linux arm64 fixture imports three native children under an
archive source package through stock CPython's public `ExtensionFileLoader`.
It uses unchanged CPython 3.13.16 / PBS `20261009`, the original unstripped
runtime and the [lifecycle fixture's](../python-native-lifecycle/README.md)
unchanged native images. Runtime and native-image providers vary independently:

| Cell | Runtime | Native images |
| --- | --- | --- |
| `bundled-archived` | Sealed bundled library | Sealed archived images |
| `bundled-host` | Sealed bundled library | Explicit read-only host files |
| `host-archived` | Explicit read-only installation | Sealed archived images |
| `host-host` | Explicit read-only installation | Explicit read-only host files |

```text
glue-python-bootstrap-probe prepare-native-packages BASE.glue NATIVE_DIRECTORY archived|host OUTPUT.glue
glue-python-bootstrap-probe run-native-packages OUTPUT.glue
glue-python-bootstrap-probe run-native-packages-negative OUTPUT.glue app-error
glue-python-bootstrap-probe corrupt-native-packages INPUT.glue CORRUPT.glue
```

The base is the pinned bundled-import or installed-host-import profile. The native
directory supplies `libglue_python_lifecycle.so`, `glue_native_lifecycle.so`,
`glue_native_create_error.so` and `glue_native_lifecycle_exec_error.so`, each
bounded to 256 KiB. Every image is verified and inspected before any native load.
The loader privately preloads the dependency-first closure, verifies relocation
and export ownership, and retains all image descriptors and mappings.

The parent `glue_native_pkg` is ordinary archive source with a relative-import
helper and text/binary resources. Each native child has a dotted import name
and truthful descriptor-backed `__file__`, spec origin and loader filename:
`/proc/self/fd/N`. Stock dynamic import uses the exact same retained alias used
for preloading. The source package and its resources keep virtual `glue://`
identities. There is no payload directory entry or extraction.

A narrow loader subclass delegates creation and execution to stock Python,
checking the declared name/spec/path, local eager loader flags and native
ownership around each operation. The scoped byte callback exposes only the
three declared aliases. These children use dynamic extension semantics and do
not appear in `sys.builtin_module_names`; no `AppendInittab` registrations are
supplied for this profile. The existing API4 29-export C boundary is unchanged.

The app exercises dotted metadata, relative imports, source-package resources,
cache/reload/removal, custom creation, create/exec failures and retry, GC and
finalization. The independent ordinary stock driver establishes the dynamic
loader's lifecycle observations before the archive adapter is tested. Both
successful and intentional application-error paths check the pinned integer-only
ledger after actual interpreter finalization.

With cached PBS inputs, Rust 1.88.0 and the pinned Podman image available, run
from a clean feature branch with fresh output directories:

```sh
sh fixtures/python-native-packages/run-linux.sh \
  target/python-native-packages-validation target/python-native-packages-validation-build
```

The harness runs offline, unprivileged and read-only, with producer interpreters,
headers, repository and staging unavailable during execution. It captures four
successes, four matching app errors and three pre-load native corruption/missing
image controls. Trace replay binds exact source/manifest/native identities and
measured descriptor/mapping operations.

Native `__init__` packages, native-child resource readers, path-relative native
data access, third-party wheel ingestion and wider ELF/runtime/platform support
remain later work. See the [decision](../../docs/decisions/0029-python-native-package-imports.md).
