# glue_rs

A Rust packager and launcher under development for Python, Node.js and Lua apps
in a read-only archive. The runtime contract forbids payload extraction and
silent runtime-provider fallback. See [PLAN.md](PLAN.md) for the full design.

The current implementation packages explicit resources, validates the manifest
and ZIP32/ZIP64 metadata, verifies stored/deflate contents, and exposes a read-only
resource tree with bounded memory caching. **Language execution, native loading,
workers and standalone executables are not implemented yet.** The archive and
manifest are experimental version 0; G0/G1 are still open.

## Try the resource fixture

Use Rust 1.88.0 through Rustup. If Homebrew shadows Rustup, put `$HOME/.cargo/bin`
first in PATH. The fixture declares a fictional host Lua library and tests only
packaging and resources.

```sh
cargo build --locked -p glue-runner
target/debug/glue build --manifest fixtures/resources/manifest.json \
  --root fixtures/resources/input --output target/resource-fixture.glue
target/debug/glue inspect target/resource-fixture.glue
target/debug/glue verify target/resource-fixture.glue
target/debug/glue cat target/resource-fixture.glue assets/message.txt
target/debug/glue explain-size target/resource-fixture.glue
target/debug/glue doctor
```

`build` consumes only the manifest's declared files. Each file's uncompressed
length and SHA-256 must match its declaration. Symlink resource components are
rejected; existing output files are preserved. Build-time filesystem use is
allowed. Default inputs are limited to 64 MiB per resource and 256 MiB in total.
The builder validates and verifies the generated archive before creating output.
An output write failure may leave a partial file and returns an error.

`inspect` validates metadata, with `--json` for the canonical manifest. Use
`verify` to check every resource's stream termination, length, CRC and SHA-256.
`cat` verifies a member before writing its bytes to stdout. Archive readers never
materialize a resource as a filesystem file. These hashes detect corruption;
they do not authenticate an archive's author.

`run`, `doctor APP.glue` and `build --standalone` return status 2 because execution
or standalone packaging is unavailable. `doctor APP.glue` validates metadata and
reports pending capabilities; it does not validate a declared host runtime.
Errors in input/arguments return status 1; successful core operations return 0.

## Development and evidence

```sh
cargo test --workspace --locked
cargo fmt --all -- --check
cargo clippy --workspace --all-targets --locked -- -D warnings
sh scripts/test-linux.sh
```

The Linux script vendors dependencies already present in the build machine's
Cargo cache, then tests offline in a read-only Podman container. Pull its pinned
image once first: `podman pull docker.io/library/rust:1.88.0-slim-bookworm`.
Its default test cell is Linux arm64, Rust 1.88.0, Debian bookworm. It does not
establish Linux x86_64 or native-loader compatibility.

See [CONTRIBUTING.md](CONTRIBUTING.md), [progress](docs/progress.md),
[container contract](docs/decisions/0002-experimental-container.md) and
[fixture protocol](docs/fixtures.md). Implementation steps use stacked feature
branches. Native loaders and real runtime bootstraps require the next platform
experiments before a runnable language profile can be advertised.
