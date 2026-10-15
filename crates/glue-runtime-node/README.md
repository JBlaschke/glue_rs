# Stock Node compact provider

`discover(executable_or_root, requested_target)` probes builtins with a five-second
and 64 KiB output bound. It records exact version, target, Node-API/addon ABI and
executable content identity; synchronous hooks and Node-API 8 are required.
`prepare(discovery, bridge.node, closure, native_inventory, host)` returns a typed
runtime descriptor, literal launch spec and payload sources for the distribution
builder. C03/C04 callers must supply the runtime's complete native closure.
Host mode is explicit and records its absolute executable prerequisite.

The Node-API bridge is built as this crate's cdylib (rename its `.dylib`/`.so` output
to `archive.node` before selecting it). It links no libnode. Its bounded interface
and ownership are documented in `spikes/node-archive/README.md`. Bootstrap source
is a bounded deployed support file, and application sources stay archived.

Validated on macOS arm64, Node 26.10.0: three Rust provider tests, bridge malformed
input/handle/ownership/path boundaries and the N00 CJS/ESM/addon corpus using this
crate's actual bridge. Local receipt: `/private/tmp/glue-node-n01-evidence/receipt.json`.
The selected Homebrew Node runtime still needs C04's closure/normalization before
it can satisfy bundled runtime-prefix removal. Linux and a second Node major are
unexecuted. This is not complete N01 target acceptance.
