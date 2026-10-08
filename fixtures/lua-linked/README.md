# Linked Lua source fixture

This fixture explicitly selects official Lua 5.4.9 linked into the launcher,
using `mlua` 0.12.2 / `lua-src` 551.0.2 with int64/float64 ABI. It imports two
nested Lua source modules, checks `require` caching and virtual source identity,
reads `assets/message.txt`, and prints:

```text
Lua 5.4 answer=42 asset=Hello from archived resources!
```

Choose the manifest matching the host:

| Manifest | Declared prerequisites |
| --- | --- |
| `manifest.macos-arm64.json` | macOS arm64, Darwin, macOS 11.0+, 16 KiB pages |
| `manifest.linux-arm64.json` | GNU Linux arm64, kernel 6.1+, glibc 2.36+, 4 KiB pages |

These declared minimums are checked at execution time; running on a newer host
does not establish compatibility at every minimum version. The fixtures do not
supply x86_64, Windows, FreeBSD, signed deployment or native-module evidence.
The macOS arm64 CLI fixture has been validated; current GNU Linux arm64
execution/trace evidence is pending.

From the repository root, use the macOS manifest below or substitute the Linux
manifest on GNU Linux arm64:

```sh
cargo build --locked -p glue-runner
target/debug/glue build --manifest fixtures/lua-linked/manifest.macos-arm64.json \
  --root fixtures/lua-linked/input --output target/linked-lua-demo.glue
target/debug/glue verify target/linked-lua-demo.glue
target/debug/glue doctor target/linked-lua-demo.glue
target/debug/glue run target/linked-lua-demo.glue
```

Existing outputs are preserved; choose a new output name to rebuild. The archive
can be moved before running: scripts and assets resolve inside it, without a
host Lua installation or the builder input directory. The exact source pin,
logical build ID, ABI and target prerequisites must match the compiled profile.
The build ID is not a compiler/configuration or binary hash.

These manifests select the current Lua 5.4 profile. Lua 5.5.1 manifests and an
explicit `lua55` compiled profile are planned on the next feature branch; a 5.4
manifest will not be silently run by a 5.5 launcher. Concurrent runtimes in one
archive remain later provider/worker work.

`io`, `os`, `debug`, bytecode and native loading are unsupported in this initial
experimental profile. Archive reads are available through `glue.read`, `stat`,
`list` and `origin`; `loadfile`/`dofile` use canonical archive keys. This is a
compatibility profile, not a sandbox. The older `fixtures/resources` manifest
selects `host` provisioning and still returns status 2: no linked fallback occurs.

The maintained `mlua` API protects calls and catches callback panics, but Lua
longjmp may cross a Drop-free Rust protected-call thunk. PLAN.md's literal
C-only/no-Rust-frame boundary remains unmet until a shim or accepted contract
resolves it. G0/G1/G2, native and mixed execution, and four-OS acceptance remain
open. See [the profile decision](../../docs/decisions/0005-linked-lua-source-profile.md).
