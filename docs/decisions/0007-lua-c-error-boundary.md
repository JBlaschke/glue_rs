# C-owned Lua execution boundary

Status: implemented on `codex/a6-lua-c-boundary`, from merged `main`
`db2c271`. Clean implementation `ee7c9d3` passes 142/143 workspace tests for
`lua54`/`lua55` on macOS and GNU Linux arm64, with workspace Clippy clean for
both. Optimized macOS boundary tests pass 50/51 tests. Both relocated Linux
fixtures pass exact output and full syscall trace checks.
[Retained evidence](../evidence/linux-arm64-lua-c-boundary-2026-10-09/README.md).

The linked Lua source adapter must meet PLAN.md's literal requirement that
Lua errors never jump across Rust frames. The pinned `mlua` implementation
uses Rust protected-call thunks and callback machinery; adding a native-module
shim would leave those paths in the source adapter. Replace that dependency
with a small private C boundary and retain the exact official Lua sources.

Only C sees `lua_State` or calls Lua APIs. It owns state creation, the system
allocator, protected initialization, compilation, execution, traceback
generation and shutdown. Rust enters the boundary synchronously and receives
an ordinary status and copied error message. Every potentially throwing Lua
operation executes beneath a C protection frame. Rust archive callbacks use
no Lua APIs, catch panics, and return byte descriptors. C raises callback
errors only after Rust has returned. Result construction is itself protected;
the Rust-owned reply is released on both success and Lua allocation failure
before C propagates any error. Resources remain alive through Lua shutdown.

The private reply protocol carries nil, booleans, signed 64-bit integers,
binary strings and tables. Tables use integer or string keys. Encoding and
decoding are bounded and validated: at most 16 results, depth 32 and 128 MiB
per reply. Returned execution diagnostics are limited to 4 KiB. This is internal implementation machinery,
not an archive-format change or a stable external ABI. A Lua bootstrap retains
upstream `require` cache/preload semantics, archive search precedence, text-only
loading, raw environment arguments and virtual origins. The Rust resource
service still verifies bytes before supplying them; it creates no payload files.

The public `execute` error type becomes `ExecutionError` instead of an `mlua`
error. Both mutually exclusive Cargo features remain available: `lua54`
(5.4.9) and `lua55` (5.5.1), int64/float64, using `lua-src` 551.0.2. The pinned
source artifact and digest remain unchanged. The logical build IDs change to
`glue-lua54-source-v2/c-boundary-1/lua-src-551.0.2/int64-float64` and
`glue-lua55-source-v2/c-boundary-1/lua-src-551.0.2/int64-float64`. Archives
declaring the previous adapter identity are rejected, with no fallback.

Validation must cover both versions on macOS and Linux, existing source and
resource behavior, callback panics, allocation failures while constructing
callback results, cleanup, coroutines, Lua error values and shutdown callbacks.
Structural review must establish that Rust callbacks cannot call Lua APIs and
that error protection and reply cleanup live in C. Retain fresh Linux execution
traces for the changed launchers. Historical evidence remains unchanged.

This step addresses the source adapter's error boundary. Native Lua loading,
signed deployment, general runtime acquisition, mixed execution and the G0/G1/G2
and four-OS gates remain open.

A Rust callback panic makes the execution fail even if Lua catches the error,
and prevents further Rust requests. The bridge deliberately forgets that one
panic payload: an arbitrary payload destructor could panic again inside the C
callback. This exceptional payload leak occurs only on a failed execution;
normal replies are released, and no allocation is needed for the panic reply.
