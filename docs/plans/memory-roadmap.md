# Memory loading and expansion roadmap

Planned follow-up to the [compact MVP](mvp-tasks.md), with optional independent
feasibility probes. None of these profiles is established merely by the existing
tiny native-loader fixtures. Keep the product [constraints](../../PLAN.md) intact:
BYO compiled libraries, no module rebuild, no runtime extraction and no fallback.

## Common acceptance

Memory mode reads native bytes from the archive. Anonymous memory decompression
is allowed. Linux executable memfds are allowed and reported; they have no
directory payload entry. Disk-backed O_TMPFILE, a mounted tmpfs/RAM disk, FUSE,
create-then-unlink and any temp/cache extraction are not replacements.

The output may initially be a launcher plus archive. “One executable” is a
separate build/signing/layout task, not proof of native memory loading. Only
declared OS libraries or explicitly selected host prerequisites may be loaded
from paths in memory mode. Compact library sidecars are not hidden exceptions.

Scope is compatible native modules with C-facing interfaces, allowing C++ and
Rust internals. Support function/data imports, constructors, thread-local state,
unwinding inside a binding, callbacks, dependency identity and required introspection.
Rust panic=abort versus panic=unwind is a property of the supplied binary; the
packager cannot switch it without rebuilding. No exception/longjmp may escape
through glue's forbidden FFI boundaries. C ABI is not a “C implementation only”
guarantee. [Rust FFI rules](https://doc.rust-lang.org/nomicon/ffi.html)

Compatibility is feature-based, with fixture pins for reproducibility, not a
catalog of allowed user libraries. New metadata/ABI features get explicit tests.
Do not expand the parser by removing checks wholesale. Retain live handles and
dependencies for the process lifetime initially; unload/reload remains unsupported.

## Linux memory tasks

### ML01 — Generalize executable memfd acquisition

**Needs:** compact native inventories and Linux MVP corpus. **Owns:**
`glue-native/src/linux.rs`, ELF admission and dedicated fixtures.

Use sealed executable memfds and ordinary ld.so with retained descriptor aliases.
Let the system loader perform its supported relocations, TLS and unwind handling.
Verify architecture, kernel policy and proc availability. Separate parser safety
from deliberate capability admission; decision 0033 is a static survey, not proof
of dynamic behavior or a universal system-library allowlist.

**Gate:** GNU Linux x86_64 and arm64, real modules plus runtime/dependency images,
TLS on existing/new/library-created threads, translated C++ exceptions and handled
Rust panic paths. Compare with compact OS loading; trace every load. Disabled
executable memfd/proc fails explicitly, without files or an implicit custom mapper.

### ML02 — Resolve complete archive dependency graphs

**Needs:** ML01. **Owns:** native closure/name/scope coordinator and tests.

Dependency-first preloading with SONAME matching is a starting mechanism, not a
general solution to cycles, duplicate names, missing SONAME, absolute edges,
symbol interposition, `$ORIGIN` or nested dlopen. Freeze the supported behavior
for each through a minimal test. Keep optional build-time metadata normalization
explicit and preserve original inputs. Determine runtime global/local visibility
from real extension requirements; do not instantiate a second runtime by accident.

**Gate:** secondary dependencies, versioned symbols, conflict/cycle diagnosis,
runtime/data symbol binding, loader introspection and declared nested loading.
No incidental host lookup satisfies an undeclared dependency. Keep descriptors
alive. Unsupported cases reject before exposing a partially initialized module.

### ML03 — Connect all three language archive paths

**Needs:** ML01/ML02 and compact adapters. **Owns:** memory-provider integration.

Reuse Python/Lua memory work where valid; route Python import/ctypes/CFFI, Lua
native search/loadlib and Node addons through the supported native manager.
Probe Linux execution of selected runtime executables from memfds where useful;
do not assume the compact subprocess provider can be used unchanged on every OS.

**Gate:** the same supported compact corpus runs with all non-system native
payloads archived; no sidecars, source installation or runtime extraction.
Return per-runtime/ABI evidence rather than extrapolating from tiny C modules.

## macOS memory tasks

This is a custom Mach-O loader inside glue alongside dyld, not an installable
dyld extension. dyld continues to own genuine system images. Its public memory
image APIs are not a shortcut: Apple's NSLinkModule implementation materializes
temporary images, violating our contract.
[Apple dyld implementation](https://github.com/apple-oss-distributions/dyld/blob/main/dyld/DyldAPIs.cpp)

### MM01 — Map real image structures and bind dependencies

**Needs:** compact macOS corpus and existing Mach-O spike. **Owns:** spike/parser
graduation into a narrowly defined production backend; no Python special cases.

Support required MH_BUNDLE/MH_DYLIB images, segment/zero-fill mapping, classic and
required chained fixups, imports/exports, ordinals, weak/re-export behavior,
initializers, final protections and instruction-cache synchronization. Separate
dyld-owned system handles from custom image handles. Reject unsupported arm64e/
pointer-authentication formats explicitly rather than assuming arm64 coverage.

**Gate:** unmodified BYO Lua module plus secondary dylib and OS dependency, normal
dyld reference comparison, malformed images, failures without callable partial
state, and a signed launcher under the intended executable-memory policy.

### MM02 — Establish thread-local storage and lifetime semantics

**Needs:** MM01. **Owns:** Mach-O TLS/TLV handling and concurrency fixtures.

Handle compiler-emitted TLV descriptors, per-thread initialization/destruction,
existing and future threads, and threads started by libraries. A hand-written
single-thread test or one-time TLS callback is insufficient. Identify any
dependence on private OS mechanisms and its release risk explicitly.

**Gate:** Lua module then actual selected libpython TLS, callbacks and thread
exit, concurrent use, initializer failure, and process-lifetime pinning. No
recompiling the supplied modules to remove TLS.

### MM03 — Establish unwind and loader-identity behavior

**Needs:** MM01, with MM02 before combined corpus. **Owns:** unwind integration,
symbol lookup/identity and native-loader call routing.

Make required unwind metadata discoverable so C++ exceptions/Rust panics caught
inside their binding traverse mapped code correctly. Test dladdr/dlsym and
required image enumeration. Route loader calls in mapped code where possible;
do not claim arbitrary calls from system libraries or direct syscalls are
intercepted. Exclude archived ObjC/Swift runtime registration initially.

**Gate:** prebuilt C++ and Rust extensions with translated errors, TLS interactions,
secondary libraries, and declared nested loading. If a required capability has
no supportable implementation, keep that profile blocked and retain compact mode
as an explicitly selected product mode, never an automatic fallback.

### MM04 — Prove language runtime acquisition and JIT/signing together

**Needs:** MM01–MM03. **Owns:** runtime-specific memory providers and deployment
integration; split Lua, Python and Node subcards after interfaces stabilize.

Lua can remain linked in the launcher. Python needs a compatible archived shared
runtime and matching bootstrap/stdlib; the compact executable-only path is not
automatically a memory provider. Revisit version-specific embedding boundaries
without hardcoding CPython 3.13 forever.

For Node, prove an explicit compatible embedding/combined-executable provider.
A stock executable is not a loadable dylib, and macOS cannot be assumed to execute
an anonymous runtime image like Linux. A build-time Node SEA route still needs
a non-extracting addon bridge; a source-built embedding provider must be separately
identified and cannot masquerade as unchanged BYO-runtime support. No user addons
are rebuilt. If arbitrary stock runtime inputs cannot meet memory mode, report
the required runtime shape; compact mode retains stock executable support.

Coordinate V8 executable-memory/JIT handling with the mapper, entitlements and
W^X policy. Test actual final signatures/distribution; do not require disabling
SIP or machine-wide protections. [Apple JIT guidance](https://developer.apple.com/documentation/apple-silicon/porting-just-in-time-compilers-to-apple-silicon)

**Gate:** actual archived Python and Node native workloads, zero payload writes,
supported signed deployment and version-specific evidence. Merely mapping a
library or running JavaScript does not close this gate.

## Later bounded work

| ID | Scope and prerequisites | Acceptance |
| --- | --- | --- |
| X01 | Combined executable after each memory profile passes | Verified archive locator survives final platform signing; corruption/relocation tested; no first-run extraction |
| X02 | HPC sharing after ML03 | Measure per-node inherited/transferred sealed descriptors vs per-rank memfds, startup I/O and PSS; no mandatory daemon; acknowledge per-process relocations remain |
| X03 | Wider native/runtime compatibility after M2 | Free-threaded/debug CPython, legacy Node ABI, additional OS/arch/API subsets as individually tested profiles; no arbitrary version catalog |
| X04 | Prebuilt Julia PackageCompiler libraries after M2, mode-specific native support | Complete bundle ingestion, C exports and init/shutdown, matching Julia runtime/system image/artifacts, GC/thread/JIT behavior, relocated/offline operations and no extraction; no Julia package build/install |
| X05 | Cross-language calls after the single-language product works | Reuse existing IPC with private inherited pipes and actual runtime bindings; lifecycle/cancellation/exit tests, then consider same-process calls separately |
| X06 | Windows/BSD after Linux/macOS feature completion | Their own runtime providers, dependency rules, signing/tracing and native loader evidence; Linux/macOS results do not count |

PackageCompiler libraries include Julia's runtime and system image; C-callable
exports do not remove those dependencies. Accept the complete prebuilt output,
not just its top-level `.so`/dylib. Keep one compatible Julia runtime per process
initially; multiple incompatible versions require explicit isolation. A compact
Julia bundle passing does not prove memory mode. [PackageCompiler libraries](https://julialang.github.io/PackageCompiler.jl/stable/libs.html)

Do not publish effort estimates for general macOS memory compatibility from the
small existing spike. Each gate needs an executable demonstration before larger
implementation work is assigned to simpler models.
