# N03 installed project acceptance

The executable fixtures are constructed by `glue-pack::node` tests, keeping their
npm and pnpm graph inputs explicit and independent of package managers.

```sh
cargo build -p glue-runtime-node
# Copy the cdylib to /tmp/archive.node; macOS suffix .dylib, Linux suffix .so.
GLUE_NODE_TEST_BRIDGE=/tmp/archive.node GLUE_NODE_TEST_EXECUTABLE=/path/to/node \
  cargo test -p glue-pack node::
```

The execution check builds an npm CJS project and a pnpm ESM project in explicit
host-provider mode, preserves a package asset, deletes each project, and runs its
relocated archive from another cwd with no tools/temp/home access. It verifies
argv, dependency results, resources and absence of script effects. macOS arm64
Node 26.10.0 actually passed all five Node tests. Host mode is recorded as host;
it does not satisfy bundled acceptance or runtime-prefix removal.

The inventory supports package scopes, conditional-export order, lockfile bytes,
prebuilt JS entrypoints, internal pnpm links, multiple package roots and native
handoff. Native addon bytes are never included as source resources. Absent normal
dependencies, escaped links, ambiguous entries and Yarn PnP diagnose before build.
No install, postinstall, compiler, node-gyp or TypeScript command is invoked.

Follow-up bundled V02 cases passed macOS arm64 and Linux arm64 on stock Node
24.22.0 and 26.10.0. Linux uses explicit native path normalization. `glue.lock.json` records `options.node.lock-provenance`: source lock hashes and
version/presence differences for npm package-lock/shrinkwrap package maps and pnpm
importer/package maps. Supplied installed bytes remain authoritative. Unsupported
lock shapes explicitly report an unrecognized comparison status; Yarn lock bytes
are retained without pretending to compare them. This is metadata reconciliation,
not verification of npm tarball SRI against individually installed files.

Internal file/directory links use an optional logical index alias map. Modules
canonicalize to one cache identity; fs resource reads, stat/lstat, directory entries
and streams follow safe aliases without duplicating source/native bytes.
