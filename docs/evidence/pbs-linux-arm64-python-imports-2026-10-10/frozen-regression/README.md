# Frozen-startup regression

This fresh optimized GNU Linux arm64 capture uses clean implementation
`94da8de499cf860f7d06fb9fec2b51eae46d0132`, with the same release launcher as
the [archive-import capture](../README.md). All four complete traces and the
ordinary-loader comparison pass after producer/stdlib/library/header removal.
Captured source status and diff are empty; C API revision is 3 with 28 exports.

| Mode | Exit | Trace records |
| --- | ---: | ---: |
| Success | 0 | 2,490 |
| Missing encodings | 1 | 2,594 |
| Corrupt startup bytecode | 1 | 2,594 |
| App error | 1 | 2,493 |

Success produces the unchanged exact 108-byte `encodings=frozen` output with
empty stderr. The 73,707,094-byte archive has SHA-256
`9b155e92dea9f054679a9a0950a9adada1ddd4c3dd6268a13f50adf24279f062`.
It retains the unchanged library, matching-producer startup bundle and shared
startup app. All 45 GNU opt-in release tests, Clippy and compilation pass.

`fixture-summary.json`, canonical manifest, artifact/provenance records, commands,
outputs and compressed traces are retained here. Every compressed trace passes
the unchanged frozen-startup policy; independent replay logs and statuses are
retained. The parent's `SHA256SUMS` covers these files.

This verifies preservation of the earlier startup subset after the shared C/API
changes. It does not add source/resource import acceptance to the frozen fixture.
See [the bootstrap decision](../../../decisions/0011-stock-pbs-frozen-bootstrap.md).
