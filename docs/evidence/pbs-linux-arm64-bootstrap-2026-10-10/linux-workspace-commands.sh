#!/bin/sh
set -eu
export PATH=/usr/local/rustup/toolchains/1.88.0-aarch64-unknown-linux-gnu/bin:$PATH
export CARGO_HOME=/tmp/cargo CARGO_TARGET_DIR=/build-target
mkdir -p "$CARGO_HOME"
printf '%s\n' '[source.crates-io]' 'replace-with = "vendored-sources"' '[source.vendored-sources]' 'directory = "/workspace/target/vendor"' > "$CARGO_HOME/config.toml"
cargo test --workspace --locked --offline > /evidence/linux-lua54-tests.txt 2>&1
cargo clippy --workspace --all-targets --locked --offline -- -D warnings > /evidence/linux-lua54-clippy.txt 2>&1
cargo test --workspace --locked --offline --no-default-features --features glue-runner/lua55 > /evidence/linux-lua55-tests.txt 2>&1
cargo clippy --workspace --all-targets --locked --offline --no-default-features --features glue-runner/lua55 -- -D warnings > /evidence/linux-lua55-clippy.txt 2>&1
rustc --version > /evidence/linux-workspace-environment.txt
uname -srvmo >> /evidence/linux-workspace-environment.txt
