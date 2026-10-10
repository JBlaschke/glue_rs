# Frozen-bootstrap regression

This fresh capture uses clean `a50ae864acf3cf2b59a338215ead55efea2e179e` and the
same optimized launcher as the installed-host capture. The ordinary-loader
baseline and four sealed-memfd traces pass with exact output/status checks:
success exits 0; missing encodings, corrupt bytecode and app error exit 1.
The valid result is 108 bytes with `encodings=frozen` and agrees with the
ordinary-loader baseline. All 34 opt-in release tests, Clippy and build pass.

Before tracing, the harness removes the stock producer, stdlib, library files,
headers and Cargo intermediates. This exercises archive/frozen startup with one
fully sealed private memfd. It is separate from the installed-host observation.
See the [parent record](../README.md) for the cell, validation and limits.

The archive is 73,707,094 bytes, SHA-256
`9b155e92dea9f054679a9a0950a9adada1ddd4c3dd6268a13f50adf24279f062`.
`fixture-summary.json` retains the launcher, archive, bundle and library
identities. `source-status.txt` and `source-diff.patch` are empty.
`trace-summary.json` retains raw and deterministic-gzip identities. Every
compressed trace was decompressed, hash-checked and independently replayed.
The parent's `SHA256SUMS` covers these files.

Replay from the repository root:

```sh
evidence=docs/evidence/pbs-linux-arm64-host-python-2026-10-10/frozen-regression
for mode in success missing-encodings bad-bytecode app-error; do
  python3 scripts/check-linux-python-bootstrap-trace.py "$evidence/$mode.trace.txt.gz" \
    --mode "$mode" --stdout-file "$evidence/$mode.stdout.txt" \
    --stderr-file "$evidence/$mode.stderr.txt" --archive-bytes 73707094
done
```
