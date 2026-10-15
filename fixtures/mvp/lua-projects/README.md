# Lua project adapter corpus (L02)

`first` has the default `main.lua`, a nested module, binary-safe resource reads,
require caching and argv/varargs assertions. `second` has an explicit
`src/start.lua`, a dynamically selected module and an init module layout.
Both run with either selected helper family and the argument `argument with spaces`.

The adapter's `LuaProjectOptions` accepts a shared exact runtime descriptor and
selected helper bytes, avoiding Cargo feature unification between Lua families.
The CLI owns `glue.toml` default resolution. Project-relative files are archived
as `app/<relative path>`. Installed rocks `share/lua/<family>` and
`lib/lua/<family>` map to the same logical module root. Native bytes enter the
native inventory and deployed payloads rather than ZIP source resources; L03
completes dependency inspection and execution.

`crates/glue-pack/tests/lua.rs` covers two layouts and both families, installed
rocks selection, duplicate logical names, exclusions, missing/ambiguous entries,
safe/escaping symlinks, byte bounds and helper identity changes. Compact helper
subprocess tests cover argv/varargs, ordinary application host I/O and process
exit status. Legacy direct-execution tests retain the original restricted profile.

Local checks run on macOS arm64 with Rust 1.88.0. Target relocation/offline and
native cell evidence is recorded separately by the shared MVP harness.
