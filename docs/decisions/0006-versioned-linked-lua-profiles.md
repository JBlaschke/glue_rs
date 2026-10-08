# Version-specific linked Lua builds

Status: experimental implementation on `codex/a6-lua55-profile`, stacked on the
Lua 5.4 baseline `03303d7`. macOS arm64 passes 118/119 Rust tests for `lua54`/`lua55`,
workspace Clippy for both, both CLI profiles and opposite-version rejection.
The 27 Python policy tests pass. GNU Linux execution/trace validation is pending.

The launcher now has two mutually exclusive compiled profiles:

| Feature | Exact source release | Source variant | Logical build ID |
| --- | --- | --- | --- |
| `lua54` (default) | `5.4.9` | `lua54-static-int64-float64` | `glue-lua54-source-v1/mlua-0.12.2/lua-src-551.0.2/int64-float64` |
| `lua55` | `5.5.1` | `lua55-static-int64-float64` | `glue-lua55-source-v1/mlua-0.12.2/lua-src-551.0.2/int64-float64` |

Both use official Lua sources in the same `lua-src` 551.0.2 crate, `mlua` 0.12.2,
64-bit integers and float64 numbers. The source artifact remains
`https://static.crates.io/crates/lua-src/lua-src-551.0.2.crate`, SHA-256
`d400ffef0e3d4d29287092bdc5a276d0bf468b2c69709d5bab0d469312d9f947`.
Its shared digest identifies the original crate; release and variant select
the exact upstream source configuration within it. Build IDs remain logical
profile identities, not compiler/configuration or binary hashes.

`cargo build --locked -p glue-runner` selects 5.4. Select 5.5 with
`--no-default-features --features lua55`; use separate target directories to
retain both launchers. Selecting both profiles or neither is a build error.
The manifest must explicitly declare `linked` / `lua_source` and that launcher's
exact release, variant, build ID and ABI. The other minor version is rejected
even when its declaration is otherwise valid. Host and archived providers still
return unsupported; none is silently replaced by a linked runtime.

This is support for both versions through separate compiled launchers. Each
archive still selects one component/runtime/target. Simultaneous multi-runtime
acquisition, mixed workers and native modules remain later work. The archive
import/resource surface and OS/architecture/ABI/prerequisite checks are unchanged
from the [base decision](0005-linked-lua-source-profile.md). The [fixtures](../../fixtures/lua-linked/README.md)
provide explicit macOS arm64 and GNU Linux arm64 manifests for each version.

The maintained `mlua` API protects calls and catches callback panics, but Lua
longjmp may still cross a Drop-free Rust protected-call thunk. PLAN.md's literal
C-only/no-Rust-frame boundary remains unmet; a shim or explicitly accepted
boundary contract is required before release. Separate source profiles do not
close G0/G1/G2, native-Lua, mixed execution, signing or four-OS gates.
