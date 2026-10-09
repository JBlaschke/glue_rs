# Linked Lua source fixture

This fixture explicitly selects official Lua 5.4.9 or 5.5.1 linked into the launcher,
using a private C error boundary / `lua-src` 551.0.2 with int64/float64 ABI. It imports two
nested Lua source modules, checks `require` caching and virtual source identity,
reads `assets/message.txt`, and prints:

```text
Lua 5.4 answer=42 asset=Hello from archived resources!
```

Lua 5.5 prints the same result with a `Lua 5.5` prefix. Choose the manifest
matching both the compiled runtime profile and host:

| Compiled feature | Manifest | Declared prerequisites |
| --- | --- | --- |
| `lua54` (default) | `manifest.macos-arm64.json` | macOS arm64, Darwin, macOS 11.0+, 16 KiB pages |
| `lua54` (default) | `manifest.linux-arm64.json` | GNU Linux arm64, kernel 6.1+, glibc 2.36+, 4 KiB pages |
| `lua55` | `manifest.lua55.macos-arm64.json` | macOS arm64, Darwin, macOS 11.0+, 16 KiB pages |
| `lua55` | `manifest.lua55.linux-arm64.json` | GNU Linux arm64, kernel 6.1+, glibc 2.36+, 4 KiB pages |

These declared minimums are checked at execution time; running on a newer host
does not establish compatibility at every minimum version. The fixtures do not
supply x86_64, Windows, FreeBSD, signed deployment or native-module evidence.
Both macOS arm64 CLI profiles pass with the new C boundary, including
opposite-version rejection. The workspaces pass 142/143 Rust tests for
`lua54`/`lua55`. Fresh Linux captures are pending. Historical debug v1
captures used kernel 7.1.4, glibc 2.36 and 4 KiB pages and did not validate
every declared minimum.
See the [v1 evidence](../../docs/evidence/linux-arm64-lua-2026-10-08/README.md).

From the repository root, use the macOS manifest below or substitute the Linux
manifest on GNU Linux arm64:

```sh
cargo build --locked -p glue-runner
target/debug/glue build --manifest fixtures/lua-linked/manifest.macos-arm64.json \
  --root fixtures/lua-linked/input --output target/linked-lua-v2-demo.glue
target/debug/glue verify target/linked-lua-v2-demo.glue
target/debug/glue doctor target/linked-lua-v2-demo.glue
target/debug/glue run target/linked-lua-v2-demo.glue
```

For a separate Lua 5.5 launcher on macOS arm64:

```sh
cargo build --locked -p glue-runner --no-default-features --features lua55 \
  --target-dir target/lua55
target/lua55/debug/glue build --manifest fixtures/lua-linked/manifest.lua55.macos-arm64.json \
  --root fixtures/lua-linked/input --output target/linked-lua55-v2-demo.glue
target/lua55/debug/glue verify target/linked-lua55-v2-demo.glue
target/lua55/debug/glue doctor target/linked-lua55-v2-demo.glue
target/lua55/debug/glue run target/linked-lua55-v2-demo.glue
```

On GNU Linux arm64, use `manifest.lua55.linux-arm64.json`. The two features are
mutually exclusive; selecting `lua55` requires disabling default features.

Existing outputs are preserved; choose a new output name to rebuild. The archive
can be moved before running: scripts and assets resolve inside it, without a
host Lua installation or the builder input directory. The exact source pin,
logical build ID, ABI and target prerequisites must match the compiled profile.
The build ID is not a compiler/configuration or binary hash.

Each compiled launcher rejects the other version's manifest; a 5.4
manifest is not silently run by a 5.5 launcher. Concurrent runtimes in one
archive remain later provider/worker work.

`io`, `os`, `debug`, bytecode and native loading are unsupported in this initial
experimental profile. Archive reads are available through `glue.read`, `stat`,
`list` and `origin`; `loadfile`/`dofile` use canonical archive keys. This is a
compatibility profile, not a sandbox. The older `fixtures/resources` manifest
selects `host` provisioning and still returns status 2: no linked fallback occurs.

The source-v2 adapter confines Lua calls and errors to C. Rust only supplies
archive data; callback replies are released before error propagation. Archives
built for the previous `mlua` adapter have a different build ID and must be
rebuilt. G0/G1/G2, native and mixed execution, and four-OS acceptance remain open.
See [the boundary decision](../../docs/decisions/0007-lua-c-error-boundary.md),
[the base profile decision](../../docs/decisions/0005-linked-lua-source-profile.md)
and [version selection](../../docs/decisions/0006-versioned-linked-lua-profiles.md).
