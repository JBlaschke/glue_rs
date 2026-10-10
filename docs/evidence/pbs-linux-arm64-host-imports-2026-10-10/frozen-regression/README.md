# Frozen startup regression

Fresh captures from clean implementation
`9aababab78156f84628128060b64f51906bde5fe` preserve the separate
[frozen startup fixture](../../../../fixtures/python-bootstrap/README.md).
Both source status and diff records are empty. See the
[parent evidence](../README.md) for the exact pinned GNU Linux arm64 image and
compressed-trace replay instructions.

The release launcher is 3,266,864 bytes, SHA-256
`bc0d43be649fc4eb9b0c15720baad5e77556b37f2369ea9e68be10a82f3b27c5`.
All four runs use the same 73,707,094-byte archive, SHA-256
`9b155e92dea9f054679a9a0950a9adada1ddd4c3dd6268a13f50adf24279f062`.
Its unchanged 73,563,968-byte stock CPython 3.13.16 library loads from a sealed
memfd. The six-module frozen bundle is 139,523 bytes, SHA-256
`6a41fc38141d45c5197adfc1b0ee740c6244ea681742c205b8aa7b8449d865d7`.

| Mode | Records | Exit | Stdout / stderr bytes |
| --- | ---: | ---: | ---: |
| success | 2,490 | 0 | 108 / 0 |
| missing-encodings | 2,594 | 1 | 0 / 713 |
| bad-bytecode | 2,594 | 1 | 0 / 713 |
| app-error | 2,493 | 1 | 108 / 68 |

Success and the ordinary-loader comparison print exactly:

```text
PASS Python=3.13.16 encodings=frozen math=built-in ssl=built-in answer=42 openssl=OpenSSL 3.5.9 29 Sep 2026
```

Negative startup modes alter already verified in-memory frozen inputs; they
exercise controlled initialization errors rather than archive corruption.
App-error prints the success line before its exact diagnostic. All four raw
captures and independently replayed compressed traces pass the unchanged
frozen policy, with one PID per trace. Release tests report 56 passes and
Clippy succeeds.

This evidence confirms isolated startup, empty module search paths, sealed
private library mappings and rejection of mutation attempts after build-input
removal. It does not establish general imports, resources, arbitrary frozen
bundles, or another runtime platform.
