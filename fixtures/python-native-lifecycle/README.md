# Registered native module lifecycle

This GNU Linux arm64 fixture extends the registered-initializer experiment with
custom module creation and garbage-collected module state. It uses unchanged
CPython 3.13.16 / PBS `20261009`, the original unstripped runtime and verified
stock headers. Runtime and native providers vary independently:

| Cell | Runtime | Native images |
| --- | --- | --- |
| `bundled-archived` | Sealed bundled library | Sealed archived images |
| `bundled-host` | Sealed bundled library | Explicit read-only host files |
| `host-archived` | Explicit read-only installation | Sealed archived images |
| `host-host` | Explicit read-only installation | Explicit read-only host files |

```text
glue-python-bootstrap-probe prepare-native-lifecycle BASE.glue NATIVE_DIRECTORY archived|host OUTPUT.glue
glue-python-bootstrap-probe run-native-lifecycle OUTPUT.glue
glue-python-bootstrap-probe run-native-lifecycle-negative OUTPUT.glue app-error
glue-python-bootstrap-probe corrupt-native-lifecycle INPUT.glue CORRUPT.glue
```

The base must match the bundled-import or installed-host-import profile. The
selected directory supplies three roots, `glue_native_lifecycle.so`,
`glue_native_create_error.so` and `glue_native_lifecycle_exec_error.so`, and their
private `libglue_python_lifecycle.so` dependency. Each file is bounded to 256 KiB.
Preparation verifies the entire base and native closure. Explicit host paths
and hashes are fixed in the manifest; host inputs must remain read-only and
immutable. Native code is trusted.

Each root uses `Py_mod_create` and positive `m_size`. Execution allocates state
that owns a list referring back to the module. The app checks built-in metadata,
cached imports, reload, independent state after removal/reimport, method errors,
and cleanup/retry after custom-create and execution failures. It explicitly
collects two state cycles, then keeps three successful instances usable through
`atexit`, including archive resource reads during finalization.

The private dependency stores bounded integer-only lifecycle records. It owns
no Python references and imports neither Python nor libc. After the C boundary
returns from `Py_FinalizeEx`, Rust queries its verified export and requires all
five states to have been freed and all five owned references released. Both
success and intentional application-error paths perform this check. A separate
stock registration driver establishes the same observations without the Rust
adapter. Callback order and exact traversal counts are not assumed; complete
cleanup is the measured acceptance condition for this particular fixture.

With cached PBS inputs, Rust 1.88.0 and the pinned Linux image available, run
from a clean feature branch with fresh output directories:

```sh
sh fixtures/python-native-lifecycle/run-linux.sh \
  target/python-native-lifecycle-validation target/python-native-lifecycle-validation-build
```

The harness compiles the native closure and ordinary stock driver, then runs
all four cells and their matching application-error cases. Three controls reject
an archived dependency corruption, a missing host dependency and a changed host
root. The execution container is offline, unprivileged and read-only, with the
repository, producer interpreter, compiler headers and staging absent. Complete
syscall traces and artifact identities support independent policy replay.

The [historical native profile](../python-extensions/README.md) retains its exact
five-image inventory and public imports. This separate profile keeps the API4
29-export boundary and public `PyImport_AppendInittab` protocol. Arbitrary wheels,
extension-file discovery, subinterpreters, other ABIs/platforms and unloading
remain later work. See the [decision](../../docs/decisions/0028-python-native-module-lifecycle.md).
