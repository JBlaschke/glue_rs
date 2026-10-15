# N05 existing Node-API addon corpus

Prepare a test input independently of packaging:

```sh
fixtures/mvp/node-native/prepare.sh /path/to/node/include/node /tmp/node-native
```

The script compiles the fixture as a separate developer action. `glue build node`
never calls it or any compiler/package-manager script. It produces one Node-API 8
addon and a secondary library with TLS and a constructor. The packaged test checks
unchanged native hashes, ordinary package resolution, repeated load, constructor
once, callback/error propagation and an async worker using that library.

```sh
GLUE_NODE_TEST_BRIDGE=/tmp/archive.node \
GLUE_NODE_TEST_NATIVE_DIR=/tmp/node-native \
GLUE_NODE_TEST_RUNTIMES=/node24/bin/node:/node26/bin/node \
  cargo test -p glue-pack native_execution_tests:: -- --nocapture
```

Actually passed on macOS arm64 with official Node 24.22.0 and 26.10.0, after both
project and copied runtime inputs were deleted. Bundled copies ran from relocated
paths with spaces/Unicode, no language tools and unusable temp/home. The same
preexisting Node-API binary ran on both majors. Linux arm64 passed the same addon
and project corpus in **explicit host mode** on both versions, plus N00, resolver,
stock/archive comparisons and resource stream tests. Set
`GLUE_NODE_TEST_NATIVE_HOST=1` for that recorded host-mode test. Linux bundled
compiler-runtime closure awaits the explicit ELF normalization implementation.
No Linux x86_64 or macOS x86_64 execution is claimed.

Static ELF/Mach-O inspection verifies standard Node-API registration and recognized
constant-return API-version getters, without loading or running supplied addons.
Wrong required API and architecture reject. V8/NAN imports, absent getter metadata
and unrecognized getter code report the exact unsupported capability. This is a
bounded initial admission path; arbitrary compiler-generated getter bodies and
older Node-API binaries without getters are not silently guessed. The OS loader
handles the declared deployed image; no `.node` file is created at runtime.

`fixtures/mvp/cases/node-{cjs,esm,resources,native}.json` use the V02 recipe protocol.
Set `GLUE_MVP_GLUE`, `GLUE_MVP_NODE_RUNTIME`, `GLUE_MVP_NODE_BRIDGE`, and for the
native case `GLUE_MVP_NODE_NATIVE`. The source recipe's asset checks use ordinary
Node fs calls; `prepare-project.cjs` only copies existing native fixture inputs.

Local evidence (not published release assets):
`/private/tmp/glue-node-two-majors-evidence/receipt.json` (Mac N00) and
`/private/tmp/glue-node-linux-out/n00-receipt/receipt.json` (Linux N00).
The broader stock/archive graph, fs and native execution are executable tests in
`crates/glue-runtime-node/tests` and `glue-pack::node`, with terminal results from
the 15 October 2026 run. Final no-extraction tracing/signing remains R02.

The V02 recipes also require `GLUE_MVP_NODE_CONFIG`: use
`fixtures/mvp/node-project/macos.toml` for an official Mac runtime, or the explicit
Linux architecture config for compiler-runtime search/normalization. Patchelf is
a separately provisioned build tool, selected with `GLUE_PATCHELF` if needed; glue
never installs it. Stock Node 24.10.0 has a failing mixed-module hook capability
and is rejected; maintained 24.22.0 passes. The Linux normalization follow-up was
then blocked by the shared parser's rejection of an OS-supported string table
spanning adjacent file-backed PT_LOAD mappings; the exact reproduction was handed
to C03. This is an upstream parser issue, not a reason to relax integrity checks.
