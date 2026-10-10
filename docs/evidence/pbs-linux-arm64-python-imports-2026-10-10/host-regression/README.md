# Installed-host startup regression

This fresh optimized GNU Linux arm64 capture uses clean implementation
`94da8de499cf860f7d06fb9fec2b51eae46d0132`, with the same release launcher as
the [archive-import capture](../README.md). All eight complete traces pass using
the explicit read-only installed stock library/stdlib. Captured source status
and diff are empty; C API revision is 3 with 28 exports.

| Mode | Exit | Trace records |
| --- | ---: | ---: |
| Success | 0 | 1,718 |
| Wrong library | 1 | 1,298 |
| Wrong stdlib | 1 | 1,372 |
| Missing encodings | 1 | 1,366 |
| Symlinked stdlib | 1 | 112 |
| Missing library | 1 | 169 |
| Cached bytecode | 1 | 148 |
| App error | 1 | 1,721 |

Success produces the unchanged exact 111-byte `encodings=installed` output with
empty stderr. The 2,741-byte app-only successful archive has SHA-256
`950ce62eaeab9eb59dbe3777b087e0428b97fbbb0fc4fddd98747de11da11d18`.
All 45 GNU opt-in release tests, Clippy and compilation pass. The separate
build-time ordinary-loader comparison still uses the frozen startup app.

The seven prepared archives, installed prerequisites and controls have identities
in `fixture-summary.json`, `host-runtime-provenance.json` and `manifests/`.
Commands, outputs, build provenance and compressed traces are retained here.
Every compressed trace passes the unchanged host-startup policy; independent
replay logs and statuses are retained. The parent's `SHA256SUMS` covers these files.

These observations verify preservation of explicit installed-host startup after
the shared C/API changes. They do not establish host-provider archive source or
resource imports, product host discovery, arbitrary mutable installations or
complete stdlib compatibility. See
[the host decision](../../../decisions/0012-explicit-host-python-startup.md).
