#!/bin/sh
set -eu

# This image is the observed arm64 Rust 1.88.0 / Debian bookworm test cell.
# Supply another immutable image to test another architecture deliberately.
image=${GLUE_LINUX_IMAGE:-docker.io/library/rust@sha256:93717e495a1029ba94b9b4a5768cf14d5376077d26cfad3354cbe70be27c2b1d}
repo_dir=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
cd "$repo_dir"

mkdir -p target
cargo vendor --locked --offline target/vendor > target/vendor-config.toml

podman run --rm --network none --read-only \
    --tmpfs /tmp:rw,size=256m \
    --tmpfs /build-target:rw,size=2g \
    --mount "type=bind,source=$repo_dir,destination=/workspace,ro" \
    --workdir /workspace \
    --env RUSTUP_TOOLCHAIN=1.88.0 \
    --env CARGO_HOME=/tmp/cargo \
    --env CARGO_TARGET_DIR=/build-target \
    "$image" \
    cargo \
    --config 'source.crates-io.replace-with="vendored-sources"' \
    --config 'source.vendored-sources.directory="/workspace/target/vendor"' \
    test --workspace --locked --offline
