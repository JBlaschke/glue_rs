# Stock Node compact provider

`discover(executable_or_root, requested_target)` inspects the native executable
before executing it, then probes builtins with a five-second and 64 KiB output
bound. Foreign OS/architecture, wrapper scripts and delegated runtime shims reject.
The probe records exact version, target, Node-API/addon ABI and executable content
identity. Working synchronous ESM-imported-CJS hooks and Node-API 8 are required;
there is no version or executable-digest catalog. Node 24.10.0 fails the mixed
module capability probe; the tested 24.22.0 and 26.10.0 releases pass it.

`prepare(discovery, bridge.node, closure, native_inventory, host)` returns a typed
runtime descriptor, literal launch spec and payload sources. The project adapter
collects the complete runtime, bridge and addon native closure. Explicit host mode
records its absolute executable prerequisite and source identity. The launcher
checks that identity before using a host runtime.

The bridge is this crate's cdylib, renamed to `.node` for selection. It links no
libnode. Its bounded resource and ownership interface is documented in
`spikes/node-archive/README.md`. The bridge uses glue-format's seek-aware bounded
reader. Bootstrap and resolver support files are deployed; application sources
stay archived. Compile caches are disabled.

The indexed resolver supports package type, ordered conditional and wildcard
exports/imports, distinct dependency versions, self references, CJS extension and
directory resolution, strict ESM relative paths, JSON, dynamic import and stock
module caches. Builtins retain stock behavior. Missing packages never search cwd
or unrelated node_modules. The optional revision-one module-index `aliases` map
preserves canonical file/directory symlink targets without duplicate bytes. Both
resolver and resource facade bound alias traversal. Escaped links reject during
build; cycles never fall back to host files. URL query/fragment module identities
are unsupported. Worker and child-process bootstrap is not virtualized.

Virtual resources use `/__glue_archive__/...`, including `__dirname` joins and
`file:` URL objects. `node:fs`, `fs`, `node:fs/promises` and ESM named exports offer
readFile sync/callback/promises, stat/lstat, readdir with Dirents, exists,
read-only access and bounded Readable streams. Streams honor ranges,
backpressure, destroy/close and errors. Each resource is verified into a bounded
buffer before bytes are emitted. `glueResources` offers read/list/stat/
createReadStream and the virtual root. Stat identities and timestamps are
synthetic read-only values. Recursive readdir, fd-only opens, mmap-style access
and mutations reject without materializing resources. Host paths retain their
ordinary methods. Native filesystem calls do not see the archive.

```sh
node crates/glue-runtime-node/tests/resolver.cjs
node crates/glue-runtime-node/tests/resources.cjs
python3 crates/glue-runtime-node/tests/compare.py --node /path/to/node \
  --pack /path/to/N00-pack --bridge /path/to/archive.node
```

Final validation used stock Node 24.22.0 and 26.10.0 on native macOS arm64 and
Linux arm64. All sixteen V02 cases passed: CJS, ESM, resources and the same
pre-existing Node-API addon on each major/OS. Stock/reference outputs match after
source/runtime prefixes become inaccessible, with relocated read-only payloads,
no language tools, denied temp/home/cache and enforced offline execution. The
focused Linux suite passed sixteen pack tests and four provider tests, including
npm/pnpm source removal, lock discrepancy reports and native relocation.

All eight Linux V02 cases also passed complete descendant syscall tracing and
R02's extraction oracle controls. No complete macOS tracer was available; no
macOS no-extraction trace pass is claimed. The macOS development policy is
explicit ad-hoc signing: independently prepared copies of the stock runtime
were signed before ingestion, and every final deployed Mach-O image passed
`codesign --verify --strict`. Developer ID, notarization and x86_64 native
execution remain unproven. Exact artifact identities and local evidence paths
are in `fixtures/mvp/node-native/README.md`.
