# Existing Node-API addon acceptance

Prepare an input independently of packaging:

```sh
fixtures/mvp/node-native/prepare.sh /path/to/node/include/node /tmp/node-native
```

This separate test preparation compiles one Node-API 8 addon and a secondary
library with TLS and a constructor. `glue build node` never invokes that script,
a compiler, npm or postinstall. The corpus checks normal package resolution,
unchanged native inputs, repeated load, constructor once, callback/error
propagation and an async worker using the dependency. The same compatible addon
binary runs on both selected majors.

```sh
GLUE_NODE_TEST_BRIDGE=/tmp/archive.node \
GLUE_NODE_TEST_NATIVE_DIR=/tmp/node-native \
GLUE_NODE_TEST_RUNTIMES=/node24/bin/node:/node26/bin/node \
  cargo test -p glue-pack native_execution_tests:: -- --nocapture
```

Actually passed on macOS arm64 and native Linux arm64 with official Node 24.22.0
and 26.10.0, after both copied project and runtime prefixes became inaccessible.
Bundled copies ran under relocated paths with spaces/Unicode, read-only payloads,
no language tools, unusable temp/home and enforced offline execution. Linux
bundles libstdc++/libgcc/libatomic as needed using explicit normalization:
`GLUE_NODE_TEST_NATIVE_SEARCH=/usr/lib/aarch64-linux-gnu`,
`GLUE_NODE_TEST_NORMALIZE=1`, and `GLUE_PATCHELF=/path/to/patchelf`. Transformations
record original/result identities; the input images remain unchanged. Patchelf
is a separately provisioned test/build prerequisite, never installed by glue.
No Linux x86_64 or macOS x86_64 execution is claimed.

Static ELF/Mach-O inspection verifies standard Node-API registration and recognized
constant-return API-version getters without loading supplied addons. Wrong API
and architecture reject. V8/NAN imports, absent getter metadata and unrecognized
getter code report specific unsupported capabilities. Older getter-less Node-API
binaries and arbitrary compiler-generated getter bodies are not guessed. The
OS loader loads declared deployed images; no `.node` file is created at runtime.

The V02 recipes `node-cjs`, `node-esm`, `node-resources`, `node-native` require
`GLUE_MVP_GLUE`, `GLUE_MVP_NODE_RUNTIME`, `GLUE_MVP_NODE_BRIDGE`, and
`GLUE_MVP_NODE_CONFIG`; native also needs `GLUE_MVP_NODE_NATIVE`. Select the checked
Mac or Linux architecture config from `fixtures/mvp/node-project`. Preparation
only copies independently prepared native inputs. Stock Node 24.10.0 exposed a
mixed-module hook bug; provider discovery rejects that failed capability while
24.22.0 passes. There is no runtime digest catalog.

All eight shared V02 receipts passed on each tested OS (four cases per major).
Local evidence, not published release assets:

- Mac: `/private/tmp/glue-v02-node{24,26}-{cjs,esm,resources,native}/receipt.json`
- Linux: `/private/tmp/glue-node-linux-out/v02-{24.22.0,26.10.0}-node-{cjs,esm,resources,native}/receipt.json`
- N00: `/private/tmp/glue-node-two-majors-evidence/receipt.json` and
  `/private/tmp/glue-node-linux-out/n00-receipt/receipt.json`

Final no-extraction process tracing and distribution signing remain R02 checks.
