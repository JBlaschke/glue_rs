# Explicit linked Lua source profile

Status: experimental Lua 5.4 baseline `03303d7`, 8 October 2026. macOS arm64 CLI
validation and 111 workspace Rust tests/Clippy passed; Linux execution/trace
evidence was pending at this baseline. G0/G1/G2 remain open.

## Acquisition contract

The first runnable language slice links official Lua into the launcher through
`mlua`. It accepts only an explicitly selected `linked` / `lua_source` runtime,
one component/runtime/target, Lua 5.4.9, 64-bit integers and float64 numbers.
Selected `host` and archived `bundled` providers remain unsupported with status
2; they never fall back to this linked build. Python, Node, declared native
modules/host imports/loader features and CPU feature requirements are pending.

The profile is pinned to:

| Identity | Value |
| --- | --- |
| Lua source release | `5.4.9` |
| Rust binding | `mlua` `0.12.2` |
| Source crate | `lua-src` `551.0.2` |
| Source artifact | `https://static.crates.io/crates/lua-src/lua-src-551.0.2.crate` |
| Original artifact SHA-256 | `d400ffef0e3d4d29287092bdc5a276d0bf468b2c69709d5bab0d469312d9f947` |
| Source variant | `lua54-static-int64-float64`; revision absent |
| Build profile | `glue-lua54-source-v1/mlua-0.12.2/lua-src-551.0.2/int64-float64` |

The build ID is a logical profile identity, not a compiler/configuration or
artifact hash. Evidence must retain the actual toolchain, build inputs and
binary hashes separately. Source-pin hashes also remain distinct from archive
resource hashes.

The [follow-up decision](0006-versioned-linked-lua-profiles.md) adds Lua 5.5.1
from the same pinned source crate through mutually exclusive compiled profiles.
No version substitution or simultaneous runtime acquisition is part of this
source-only slice; multi-runtime providers and workers remain later work.

Before execution, the CLI validates the exact source/build/ABI declaration and
the selected OS/architecture/ABI against the running host. The initial platforms
are macOS Darwin and GNU Linux; Windows, FreeBSD and musl execution are pending.
macOS product version, Linux kernel/glibc versions and host page size are queried
read-only and checked against the target's minimum versions and page-size set.
Mismatched acquisition/target prerequisites return 1; unsupported capabilities
return 2. `doctor` performs this readiness check without executing Lua or fully
verifying all resources.

## Archive execution surface

The adapter loads verified source buffers with virtual `glue://` origins.
`require` searches `app/?.lua` and `app/?/init.lua`, while preserving Lua's
preload and loaded-module cache semantics. `loadfile`/`dofile` accept canonical
archive keys; `load` accepts source strings. Bytecode is rejected. `glue.read`,
`glue.stat`, `glue.list` and `glue.origin` provide the read-only resource view.
Resource hashes are checked before consumed script or asset bytes are published.

`io`, `os`, `debug` and native loading are unavailable in this initial profile.
This is an experimental compatibility restriction, not a sandbox or the final
policy for ordinary application host I/O. No shared-library payload mapping,
LuaRocks ingestion, workers or standalone layout is implemented by this slice.
The separate Linux memfd spike remains separate evidence.

## Error-boundary and release limits

The adapter uses the maintained `mlua` safe API, which catches callback panics
and protects Lua calls. Upstream Lua longjmp may nevertheless cross a Drop-free
Rust protected-call thunk. **PLAN.md's literal C-only boundary with no Rust frame
crossed is not satisfied.** A dedicated shim or an explicitly accepted boundary
contract must resolve this before release; using the safe binding is not evidence
that the stricter design condition has been met.

The [arm64 fixtures](../../fixtures/lua-linked/README.md) cover nested imports,
cache semantics, virtual origins and an asset. The macOS arm64 fixture was built
through the CLI, passed `doctor` and printed the expected result. Linux trace
evidence remains separately recorded after validation. Neither these fixtures nor the older native
probe close G1's four-OS requirements or G2's native-Lua acceptance criterion.
Mixed execution, Python/Node providers, approved external dependencies and
signed deployment remain open.
