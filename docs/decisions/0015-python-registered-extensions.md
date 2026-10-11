# Registered native initializers with the selected Python runtime

This slice extends the controlled GNU Linux arm64 CPython 3.13.16 / PBS
`20261009` experiment with public native-module registration. The shared archive
source/resource app imports four reviewed native roots backed by one private
dependency. The runtime and native-image providers vary independently:

| Runtime | Native images |
| --- | --- |
| Bundled, sealed runtime | Archived, sealed images |
| Bundled, sealed runtime | Explicit immutable host images |
| Explicit immutable host runtime | Archived, sealed images |
| Explicit immutable host runtime | Explicit immutable host images |

The native roots are `glue_native_single`, `glue_native_multi`,
`glue_native_init_error` and `glue_native_exec_error`. Their image filenames are
the root names followed by `.so`; the dependency is
`libglue_python_dependency.so`. Each image is bounded to 256 KiB. The exact
manifest, resource inventory, target, runtime identity and declared dependencies
must match the fixture profile. Archived native resources use stored compression;
host images require one explicit canonical directory and declared SHA-256 hashes.
Preparation compiles trusted fixture C against the independently verified stock
headers and records the resulting binary identities. Hashes establish identity,
not safety of arbitrary native code.

All archive inputs are verified and decoded before the archive closes. Native
host lookup starts only after closure. Every host ancestor and regular file is
opened without following symlinks; image sizes come from opened descriptors,
then bounded reads, hashes, EOF checks and rewinds establish the selected bytes.
All five native images undergo portable ELF admission before runtime loading or
any Python initialization. Explicit host runtime verification retains the
existing library, 69-source and cache-absence prerequisites from
[the host-import decision](0014-host-python-archive-imports.md).

The reusable ELF inspector gains an explicit data-import opt-in. Its existing
entry point continues to reject undefined object imports, preserving the Lua
profile. The new entry point admits only declared global undefined OBJECT
symbols with ordinary `GLOB_DAT` relocations; the declaration must be a subset
of admitted imports. Object imports cannot enter the PLT. This Python fixture
uses that opt-in only for public `PyExc_RuntimeError` where required. Its
function-import list is finite and public, including `PyModule_Create2`,
`PyModuleDef_Init`, state/constant APIs and `Py_DecRef`. Private `_Py_*` imports
remain unsupported.

Native admission requires each root's one exact executable `PyInit_*` export,
the dependency's one exact function export, exact direct `DT_NEEDED` entries,
and the existing bounded AArch64 relocation profile. Native constructors,
TLS, IFUNCs, symbol versions, additional dependencies and undeclared/weak imports
reject. Native images are trusted C code; these checks are not a sandbox.

GNU `ld.so` loads the dependency first, then the roots, with
`RTLD_NOW | RTLD_LOCAL`. Each root declares the selected
`libpython3.13.so.1.0` and the private dependency by exact SONAME. The already
loaded runtime stays local. SONAME reuse alone is insufficient: Rust verifies
every admitted relocation slot against the selected runtime, declared dependency,
own image or checked relative address. Function and data addresses must have
their expected loader owner; the exception import binds the exported variable's
address, not its pre-initialization value. Loaded-image checks reject a second
runtime or undeclared provider. Reviewed Python/native exports must remain
absent from the global lookup scope.

Archived native images use executable memfds with all four required seals; the
whole native closure is prepared before its first image mapping. Explicit host
images use their verified read-only descriptors. Handles and successfully loaded
descriptors remain pinned until process exit, including later errors. Host trees
must remain immutable and read-only throughout execution: retained descriptors
and prior hashing do not freeze mutable backing bytes. There is no temporary-file
materialization, discovery or provider fallback.

C boundary revision 4 appends only public `PyImport_AppendInittab`, giving 29
selected public exports and a 240-byte API table. Its 16-byte extension record
contains a borrowed name and reviewed initializer address; no Python object
crosses Rust. C checks at most eight unique top-level ASCII names of at most
255 bytes, beginning with `glue_native_` and a nonempty suffix, and non-NULL
addresses before Python calls. It copies names, rejects frozen-name conflicts,
then registers them after configuration and before `Py_InitializeFromConfig`.
From the first append attempt, copied names remain pinned until process exit,
including partial registration failure. Registration is never rolled back or
retried. Existing entry points pass no native registrations and preserve their
startup and archive-callback behavior.

Stock `BuiltinImporter` invokes the initializers and owns both single-phase and
multi-phase protocols. Metadata is deliberately built-in: origin `built-in`,
no location, no `__file__` or `__cached__`, and names in
`sys.builtin_module_names`. This does not implement `ExtensionFileLoader` or
general extension-file discovery.

The single-phase fixture has `m_size = -1`. Ordinary imports cache its module;
reload does not rerun initialization. Removal from `sys.modules` followed by
reimport creates another module from CPython's original shallow dictionary copy,
without calling its initializer again. Initial method objects remain shared;
this is not isolated per-module state. The multi-phase fixture has per-module
state: reload preserves that state, while removal/reimport creates a fresh
module and executes it independently. Separate initializer and execution-slot
failures must remove incomplete modules and permit a successful retry. A native
method exception must leave its existing module usable. An `atexit` callback
calls retained old/new modules and their dependency during real finalization;
the archive resource callback context also stays live through `Py_FinalizeEx`.
The multi-phase fixture uses default creation. Custom creation slots and explicit
`m_free`/GC teardown instrumentation remain later conformance cases.

The fixture compares these semantics with an independent stock-runtime public
registration driver, then exercises all four provider cells, matching app-error
runs, archived native corruption, and wrong/missing explicit host images. The
[clean native evidence](../evidence/pbs-linux-arm64-python-extensions-2026-10-10/README.md)
from `b784c99` passes eleven native cases and twenty-two earlier Python
regressions. It retains exact native artifacts, manifests, complete compressed
traces and source/input/build identities. The GNU fixture passes 65 release
tests and Clippy; all 191 trace-policy tests pass on Mac and the matching stock
Linux interpreter, and independent replay rejects all 37 hostile trace edits.
Earlier source/import and startup evidence remains separately scoped.

G0/G1/G2 remain open. Product Python execution/acquisition, arbitrary wheels or
extensions, general dynamic-file-loader metadata, mutable installations,
subinterpreters, free-threaded/debug ABIs, unloading, other Python versions and
other target platforms require separate work and evidence.
