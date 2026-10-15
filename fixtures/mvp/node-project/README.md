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

Remaining evidence: bundled runtime native closure after C04, target versions and
Linux. Lockfiles are retained as provenance but lock-vs-install reconciliation is
not yet implemented. Internal package-directory links use Node's ordinary canonical
realpath graph; resource aliases through directory links are not currently exposed.
