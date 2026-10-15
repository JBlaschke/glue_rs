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
Later hosted Linux x86_64 coverage is recorded below; macOS x86_64 remains unexecuted.

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

Earlier release validation passed all sixteen shared V02 cases: four cases per
major on native macOS arm64 and Linux arm64. All eight Linux cases additionally
passed complete process-tree syscall traces, the no-extraction checker and its
read-only/create-unlink/denied-write/descendant-write controls. The complete
macOS tracer is unavailable, so that cell remains unexecuted. Failed or
interrupted disk-exhaustion attempts were retained separately and excluded.

The selected macOS development policy is ad-hoc signing. Independently prepared
copies of the stock Node executable were signed before ingestion; packaging
preserved those input bytes. Every final Mach-O image passed the separate
`codesign --verify --strict` policy gate. The unmodified official runtime's
signature could not be verified on this host; that original failed gate remains
separate evidence. Developer ID deployment and notarization are unproven.

Exact SHA-256 identities for the final Node acceptance artifacts:

| Artifact | SHA-256 |
| --- | --- |
| macOS included launcher | `19a4119d29794f429eae7084566b2db3585612992053958c565e69a9ad202e67` |
| macOS archive bridge | `1fd132eb9f4715e2d112f28b010e2cd615b429cdaaf3b906b0fe3827ba177194` |
| macOS ad-hoc Node 24.22.0 input | `badc742a262732fe2e8dd09211ebe8bceaab60c48e10c795506d898b7cb8d91d` |
| macOS ad-hoc Node 26.10.0 input | `24ca93e297e49c584f301e433cd1ede2ad8deccb7e394ebf339014dd09f833d8` |
| Linux included launcher | `9c47835813a1e9dd530d5ed9073ef2f7415323a46428f5d4d144d7e1d049014c` |
| Linux archive bridge | `445d95c45d6e43e821cfb9a8fb3c5036f643a1cd5e4b54b9e6b27a04474d7d51` |

A subsequent Python-only copied-venv builder fix produced Linux launcher
`8e5e1b4add7ca970a4f29c4cb33fe36cbcf9a97a83300f9bd85ba1ce38e423bd`;
it does not change the Node startup implementation. Node acceptance and R03
measurements remain scoped to the earlier immutable artifact above.

Local evidence, not raw receipts committed to Git or published release assets:

- Full final matrix and per-case paths: `/private/tmp/glue-node-final-summary.json`.
- Mac final V02: `/private/tmp/glue-adhoc-v02-{24.22.0,26.10.0}-{node-cjs,node-esm,node-resources,node-native}/receipt.json`.
- Mac final signature policy: `/private/tmp/glue-node-final-mac-adhoc-signatures.json`.
- Original official-runtime signature failure: `/private/tmp/glue-node-final-mac-signatures.json`.
- Linux 24 CJS/ESM/resources: `/private/tmp/glue-node-linux-out/final-v02-24.22.0-node-{cjs,esm,resources}/receipt.json`.
- Linux 24 native and all 26 cases: `/private/tmp/glue-node-linux-out/final2-v02-{24.22.0,26.10.0}-node-{cjs,esm,resources,native}/receipt.json` (only the cases listed in the full matrix exist).
- Original N00: `/private/tmp/glue-node-two-majors-evidence/receipt.json` and `/private/tmp/glue-node-linux-out/n00-receipt/receipt.json`.

The final sixteen receipts and retained raw Linux traces were independently
rechecked with the shared harness checker. R03's Linux Node CJS 10,000-resource
1/32-rank budget also passed using the included launcher identity above; its
separate measurement owner retains those receipts.


Native GNU Linux x86_64 hosted run
[38796669924](https://github.com/JBlaschke/glue_rs/actions/runs/38796669924)
subsequently passed all eight Node V02/R02 cases (24.22.0 and 26.10.0,
CJS/ESM/resources/native), independently replayed from retained receipts and raw
process-tree traces. Node CJS R03 also passed all empty/baseline/10,000-resource
variants and first/warm 1/32 ranks. This brings the Node V02 corpus to 24 passing
cases across macOS arm64, GNU Linux arm64 and native GNU Linux x86_64.

The hosted run explicitly inherits the recorded `traceable-native-syscalls-v1`
CI seccomp policy for stock references and packaged trees: asynchronous kernel
I/O returns ENOSYS so the strict syscall oracle can observe file operations.
This is evidence for that recorded execution environment; unrestricted ring-enabled
hosts remain unproven. The complete workflow failed on an unrelated Python 3.14
native input conflict; its Node cases and five R03 reports passed independently.

| Hosted x86_64 artifact | SHA-256 |
| --- | --- |
| Included launcher | `80114ea81faceefc540aafce40854d26e88d5d1f67398ebd9a3d0492f6669830` |
| Archive bridge | `c1643c7ed93a4cc71d6248ca10750d4a989a2deb585fe93e0b831ff3df32447c` |
| Official Node 24.22.0 input | `67ca5783febb8bf85736c79fcdd92c8d6d465a0eb2a082672bcdfa76a506751c` |
| Official Node 26.10.0 input | `ab9c8eecf9f82d6693cdc3accced17034065c8d96213b0aa76a7e803d20ae1da` |

[Artifact 12003666300](https://github.com/JBlaschke/glue_rs/actions/runs/38796669924/artifacts/12003666300)
contains the full receipts/traces; its ZIP SHA256 is
`9dea9422cefedf9d938164883cb088a82fb3757f6dbc9ed4bfe422ba104d68a8`.
Local extraction and independent replay summary are
`/private/tmp/glue-native-x86-evidence-38796669924/independent-replay.json`.
Raw receipts and traces are not committed to Git.


The subsequent full native run
[38800548172](https://github.com/JBlaschke/glue_rs/actions/runs/38800548172)
passed all 24 language acceptance cases and all five reviewed R03 budgets,
including the eight Node cases and Node CJS benchmark. The included launcher,
bridge and Node identities match the hosted table above. All retained receipts,
39 main/variant trace groups, controls and rank streams were independently
replayed successfully. Final [artifact 12005186009](https://github.com/JBlaschke/glue_rs/actions/runs/38800548172/artifacts/12005186009)
has ZIP SHA256 `c1cc519d76e73888ed0339714deec1e97eea816c1f8861ab551da4579644e7a4`;
local replay is
`/private/tmp/glue-native-x86-evidence-38800548172/independent-replay.json`.
The same explicitly recorded syscall-trace environment scope applies.
