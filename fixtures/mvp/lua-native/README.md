# Compact Lua native corpus (L03)

`module.c` and `secondary.c` are independently compiled fixture inputs. The
packager never invokes their compiler. The module binds the selected helper's
public Lua API and uses a secondary shared library with real TLS and pthread
work. `main.lua` verifies require caching, constructor count, a callback, ordinary
function and initializer errors, missing exports, a version-check failure and
declared package.loadlib success/error results.

Run the integration tests with the pinned toolchain:

```sh
cargo test -p glue-runtime-lua --test compact_native --locked
cargo test -p glue-runtime-lua --test compact_native --no-default-features --features lua55 --locked
```

The test hashes native inputs before and after packaging, inspects the deployed
identity, renames the distribution to a path with spaces/non-ASCII, removes the
input tree and runs from `/` with cleared environment, no language tools on PATH
and unusable HOME/TMPDIR. The helper uses normal dlopen/dlsym, verifies declared
native payloads before constructors and retains handles for process lifetime.
All Lua initializer/function/error work remains beneath C-owned protection.
Unknown module ABI requires a matching explicit declaration, never a hash pin.

Observed locally: macOS arm64 and native Linux arm64 (cached Rust 1.88.0 Podman
VM, offline), both linked Lua 5.4.9 and 5.5.1. Linux x86_64 native execution,
full extraction traces and final Developer ID/notarization remain separate
evidence requirements. Successful ordinary/ad-hoc Mach-O loading does not prove
Developer ID distribution policy.
