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

N04 virtual resources use `/__glue_archive__/...` paths (including `__dirname`
joins and `file:` URL objects). `node:fs`, `fs`, `node:fs/promises` and ESM named
exports expose readFile sync/callback/promises, stat/lstat, readdir with Dirents,
exists, read-only access and bounded Readable streams. Streams honor ranges,
backpressure, destroy/close and errors; each resource is verified into a bounded
buffer before bytes are emitted. Explicit `glueResources` offers read/list/stat/
createReadStream and the virtual root. Stat identities and timestamps are
synthetic read-only values. Recursive readdir, fd-only opens, mmap-style access
and mutation APIs reject without creating files. Host paths retain their ordinary
methods. Native filesystem calls and worker/child bootstrap are not virtualized.

`node crates/glue-runtime-node/tests/resources.cjs` actually passed on macOS Node
26.10.0, including callback/promises, binary data, bigint stat, Dirents, ranges,
backpressure, close/errors, traversal and denied writes. The N03 actual archive
execution now also reads an installed package asset through `node:fs` after its
source was deleted, for both npm CJS and pnpm ESM cases.

Follow-up N05 evidence supersedes the early missing-major/Linux notes: official
Node 24.22.0 and 26.10.0 passed the same stock/archive graphs and fs resource corpus
on macOS arm64 and native Linux arm64. Node 24.10.0 passed the small N00 probe but
failed ESM-imported CJS dependency resolution. Discovery now executes that public
hook capability test and rejects failing patches, without a version/digest list.
Mac bundled Node-API relocation and Linux explicit-host native evidence are in
`fixtures/mvp/node-native/README.md`. Initial getter-inspection restrictions there
remain explicit. Source URL query/fragment identities remain unsupported.


The optional revision-one module-index `aliases` map records canonical targets,
file/directory kind and symlink text length. Both resolver and fs facade enforce
bounded traversal; escaped links reject during build and cycles never fall back
to host files. Actual npm/pnpm tests cover assets through directory links after
source removal. Source bytes and deployed images retain one authoritative copy.
The bridge uses glue-format's bounded seek-aware reader for archive header I/O.
