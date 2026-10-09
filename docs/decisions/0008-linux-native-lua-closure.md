# Explicit Linux native Lua closure

Status: experimental implementation on `codex/a6-linux-native-lua`, from merged
`main` `7853282`. Both Lua versions have controlled GNU Linux arm64 execution
and rejection evidence from clean `fb61e5e`; see the
[retained records](../evidence/linux-arm64-native-lua-2026-10-09/README.md).

Add an opt-in `linux-native` Cargo feature alongside either `lua54` or `lua55`.
The default source-only profiles and their v2 identities remain available.
The native profiles have distinct logical build IDs:
`glue-lua54-native-linux-v1/c-boundary-1/lua-src-551.0.2/int64-float64` and
`glue-lua55-native-linux-v1/c-boundary-1/lua-src-551.0.2/int64-float64`.
Source pins and numeric configuration remain unchanged. Initial execution is
restricted to GNU Linux AArch64, 4 KiB pages, explicitly executable sealed
memfds, one linked Lua runtime and one collision-free native namespace.

Introduce `glue-native` with portable bounded ELF inspection, dependency closure
validation and a private Linux loader. Verify every declared image and the
complete closure before any constructor. Accept only a documented ELF64
little-endian AArch64 RELA subset with SysV dynamic-symbol hash metadata and
immediate binding. Reject undeclared dependencies/imports, cycles, duplicate
SONAMEs, runtime substitutions, TLS/IFUNC, executable stacks, text relocations,
search paths and unsupported format features. Reject payload definitions of Lua
API symbols and Lua state-creation imports. OS imports initially admit only
explicit symbols from `libc.so.6`; the manifest's version floor is checked.

The existing schema needs no extension: each native resource basename is its
required SONAME; selected component native-module IDs are Lua import names and
determine `luaopen_` initializers by replacing dots with underscores. Other
modules are dependency libraries. All belong to namespace `linked-lua` and
declared target/runtime edges. These conventions are restrictions of this
experimental profile, not a general native-module naming contract.

Create, fill and seal all anonymous executable memfds before loading. Load
dependency-first with `RTLD_NOW | RTLD_LOCAL`. An observed glibc experiment
confirms reuse of an already loaded local dependency by SONAME. Keep handles
and descriptors pinned for process lifetime. Check pre-existing SONAME conflicts
and actual resolved import/initializer ownership. Publish no initializer on
partial failure. GNU local scope is not a separate linker namespace; preload,
interposition, multiple native closures and arbitrary nested loading remain
unsupported expansion gates.
Constructor code must leave relocation slots unchanged. Actual slot/owner
checks run after `dlopen` and therefore after constructors; they reject detected
binding changes before publishing initializers, not arbitrary constructor
behavior before it runs. Metadata/closure rejection is the pre-load guarantee.

Execution errors retain an unsupported-capability classification for the runner:
unsupported ELF/profile/kernel/policy returns status 2; inconsistent metadata,
loader failures and protected Lua errors return status 1. The runtime exposes
`ExecutionError::is_unsupported()` without exposing its private error storage.

Load and resolve the entire native closure before creating the Lua state.
Archive callbacks during Lua execution only return already-resolved initializer
leases. They never run constructors or invoke Lua APIs. This prevents loader
constructor work beneath active Rust archive callbacks. Initial constructors
must use ordinary C initialization and receive no Lua state; arbitrary native
code is not sandboxed. A general constructor reentry contract remains later work.
Native functions must obey the selected C/Lua ABI: no escaping C++ exceptions
and no Rust implementation frames around Lua calls that can throw. Returning a
C function cannot establish this property for arbitrary foreign module code.

Extend the private C reply protocol with a native-function tag. Only the manager
can construct an initializer lease; Lua receives a genuine C function after
Rust returns. C handles invocation through upstream `require` and its protected
execution frames. A native searcher follows archive source resolution.
`package.loadlib` accepts only a declared root's canonical resource key and its
exact derived initializer, through the same retained manager. Host paths and
global loading shortcuts fail. Selective linker exports are a reviewed Lua API
allowlist and retained explicitly; inspect the emitted launcher symbols.

Validation covers real modules for both Lua versions, an archived dependency,
libc, constructor/data observations, selected Lua-state identity, caching,
native initializer/function errors and source/resource behavior. Compare the
same fixture with ordinary disk loading using the exact compiled Lua core.
Remove compiler-produced shared-library inputs, relocate the archive, and retain
complete traces proving two sealed memfds and no payload filesystem mutation.
Adversarial tests must reject whole-closure defects before loading. This advances
native Lua feasibility; it does not close general native, signed deployment,
mixed-runtime or four-OS gates.
