# Controlled Python profiles in the product runner

The Python provider, archive importer and native registration mechanisms move
from the bootstrap spike into `glue-runtime-python`. The probe and the optional
product CLI share one implementation. This slice advances the planned runtime
crate ownership and actual `glue run` dispatch while preserving the existing
controlled admission contracts.

The work starts from merged `f92ac34` on
`codex/a7-python-runner-profile`. It does not generalize the fixture manifests
into arbitrary application admission. The public registry accepts these
existing profile identities:

| Application profile | Runtime provider | Native-image provider |
| --- | --- | --- |
| `stock-pbs-archive-imports` | Bundled | None |
| `stock-pbs-host-archive-imports` | Explicit host | None |
| `stock-pbs-registered-extensions` | Bundled or explicit host | Archived or explicit host |

The four registered-native combinations retain the contract in
[decision 0015](0015-python-registered-extensions.md). The two source/resource
profiles retain [decision 0013](0013-python-archive-source-resources.md) and
[decision 0014](0014-host-python-archive-imports.md). All require stock CPython
3.13.16 / PBS `20261009`, conventional GIL, non-debug ABI and the declared GNU
Linux arm64 target. Source/helper/app identities, inventories, compression and
provider declarations remain checked by the original validators. Arbitrary
application identities are unsupported; drift within a recognized profile is
invalid input. No alternative runtime or provider is substituted.

The native profile fixes five image names, dependency edges, initializer
exports and the bounded ELF/API contract. Its native image hashes come from
the manifest and identify the admitted bytes; they are not a hardcoded list of
the previously captured compiled fixture hashes. Portable ELF admission and
runtime relocation/provider checks remain necessary. Native C remains trusted
code, and neither declared hashes nor loader admission establish a sandbox.

The public Rust facade has three operations:

```text
profile::validate(&Manifest) -> Result<ControlledProfile, ExecutionError>
profile::readiness(&ControlledProfile) -> Result<(), ExecutionError>
execute(Archive<File>, ControlledProfile) -> Result<(), ExecutionError>
```

Validation is portable and performs no provider acquisition or host-file
lookup. The opaque profile stores the admitted manifest; execution rejects a
token selected from another manifest and revalidates its declarations.
Readiness separately checks the compiled feature/boundary and actual platform
without loading Python. The supported GNU path observes kernel/libc versions
and page size against the declared prerequisites. These declarations describe
the controlled profile; they do not establish an upstream compatibility floor.

`execute` owns one synchronous initialization/execution/finalization lifecycle
on the calling thread. It calls readiness once before preparing payloads.
The CLI run path therefore selects a profile and calls `execute`; doctor calls
readiness separately and reports metadata/platform readiness, with content and
explicit-host verification deferred to run. Unsupported capabilities preserve
CLI status 2. Invalid declarations, integrity errors and failed executions use
status 1. Successful execution uses status 0.

The archive is opened once and passed into execution. The generic runner's
entry-size bound accommodates the 73,563,968-byte pinned runtime library.
Each Python profile rechecks its original narrower archive policy through
`Archive::check_limits`, using retained actual layout facts and indexed entry
sizes without additional I/O. Every required resource verifies into owned
memory before runtime loading. The archive closes before explicit host lookup;
validation does not reopen its pathname.

The C boundary owns Python objects and all public Python API calls. The API4
table and selected local runtime remain private. Frozen-record storage,
configuration strings, immutable archive callback data, and verified host
files/directory leases remain live through `Py_FinalizeEx`, including archive
and native calls from the existing finalization callbacks. Runtime/native
descriptors and loaded handles stay pinned for process life. The existing one
execution-attempt rule prevents interpreter retry or concurrent lifecycle use.
This facade does not expose raw pointers, Python objects, unloading or separate
start/stop methods.

The runner feature is `python-pbs`; it enables the runtime crate's
`pbs-bootstrap` feature. Default runner builds retain linked Lua and do not
require Python headers. Exact GNU Linux arm64 builds compile the private C
boundary from the independently verified stock header tree supplied through
`GLUE_PYTHON_INCLUDE_DIR`, with no link-time libpython dependency. Other targets
can validate declarations but execution is unsupported. Backend dispatch also
requires the build script's actual compiled-boundary marker.

The explicitly named `experimental::dispatch` namespace preserves historical
probe preparation, baseline and fault-injection commands. The probe executable
is a thin argument/diagnostic wrapper over that scaffold. Product execution
uses the facade and exposes no baseline-library override or injected-error
parameter. Cached upstream PBS inspection and fixture construction remain
experimental preparation operations.

Installed host verification still covers the fixed conformance workload's
69 reviewed sources and relevant cache-absence prerequisites. The immutable,
read-only host tree requirement remains in force: retained descriptors do not
freeze mutable files or bind Python's later pathname reads. This slice does
not certify the complete installation or arbitrary imports. Bundled resources
retain source-only loading, virtual origins, immutable seekable streams and
materialization rejection. The UTF-8 syntax-diagnostic sentinel workaround
keeps its previously measured scope; general traceback/linecache and compiler
warning behavior remain separate work.

G0/G1/G2 remain open. General application admission, broader host source
verification, wheels, extension discovery, custom creation/free conformance,
version selection, subinterpreters, free-threaded/debug ABIs, workers, mutable
host installations and other targets require further implementation and
evidence. This extraction and controlled CLI route do not close those gates.
