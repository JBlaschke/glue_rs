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

N02 adds an indexed resolver with package type, ordered conditional and wildcard
exports/imports, dependency versions, self references, CJS extension/directory
resolution, ESM exact relative paths, JSON, dynamic imports and stock runtime
caches. Builtins retain Node behavior. Missing packages never search cwd or
unrelated node_modules. Absolute/file module imports outside the virtual tree
report `ERR_GLUE_RESOLUTION`. Application argv is rewritten before loading entry.

```sh
node crates/glue-runtime-node/tests/resolver.cjs
python3 crates/glue-runtime-node/tests/compare.py --node /path/to/node \
  --pack /path/to/N00-pack --bridge /path/to/archive.node
```

On macOS Node 26.10.0 these execute 21 resolver boundary checks and compare actual
stock/archive CJS and ESM graphs (cycles, cache identity, dual-mode/wildcard/blocked
exports, imports, duplicate dependency versions and JSON). The integration test
removes its source tree before archive execution. The required second-major run
remains missing. URL query/fragment module identities are currently unsupported;
no general npm-ecosystem compatibility is claimed from this corpus.
