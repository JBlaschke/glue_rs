# Pinned PBS inspection fixture

This fixture pins stock conventional-GIL CPython 3.13.16 / PBS `20261009`
GNU Linux arm64 full and unstripped install-only artifacts. The inputs are
build-time downloads; they are not checked into Git. The Rust inspector never
downloads or extracts them and emits its inventory only to stdout.

Download the exact `full.url` and `install_only.url` in [pins.json](pins.json)
to a build-time directory such as `target/pbs-inspection`, using their declared
filenames. The tool verifies both compressed sizes and SHA-256 digests. Use
Rust 1.88.0:

```sh
cargo run -p glue-pbs --release --locked --offline -- \
  fixtures/python-pbs/pins.json \
  target/pbs-inspection/cpython-3.13.16+20261009-aarch64-unknown-linux-gnu-pgo+lto-full.tar.zst \
  target/pbs-inspection/cpython-3.13.16+20261009-aarch64-unknown-linux-gnu-install_only.tar.gz \
  > target/pbs-inspection/report.json
```

Omit the final input to inspect only the full artifact. No Python, uv, zstd
command, compiler or network access is needed by the compiled inspector. All
parsing and decompression use Rust. Regular files are streamed and hashed;
only bounded metadata and binary prefixes stay in memory.

The JSON includes exact input pins, all member identities, reviewed install-only
omissions, runtime/startup candidates and unchanged upstream CRT claims.
`bootstrap_observed: false` and `loader_compatibility_validated: false` make its
scope explicit. Interpreter startup, uv-tree ingestion, stripped inputs,
other target profiles and conversion into runnable glue archives are pending.
See [the decision](../../docs/decisions/0010-pinned-pbs-inspection.md).
