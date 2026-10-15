#!/bin/sh
set -eu
export PATH=/usr/local/rustup/toolchains/1.88.0-aarch64-unknown-linux-gnu/bin:$PATH
export CARGO_HOME=/tmp/cargo CARGO_TARGET_DIR=/build-target
mkdir -p "$CARGO_HOME"
printf '%s\n' '[source.crates-io]' 'replace-with = "vendored-sources"' \
    '[source.vendored-sources]' 'directory = "/workspace/target/python-bootstrap-vendor"' > "$CARGO_HOME/config.toml"
rustc --version > /evidence/rust.txt
uname -a > /evidence/kernel.txt
set +e
cargo test --locked --offline --workspace --all-targets > /evidence/lua54-tests.txt 2>&1
status=$?
printf '%s\n' "$status" > /evidence/lua54-tests.exit-status.txt
test "$status" -eq 0 || exit "$status"
cargo clippy --locked --offline --workspace --all-targets -- -D warnings > /evidence/lua54-clippy.txt 2>&1
status=$?
printf '%s\n' "$status" > /evidence/lua54-clippy.exit-status.txt
test "$status" -eq 0 || exit "$status"
cargo test --locked --offline --workspace --all-targets --no-default-features --features glue-runner/lua55 > /evidence/lua55-tests.txt 2>&1
status=$?
printf '%s\n' "$status" > /evidence/lua55-tests.exit-status.txt
test "$status" -eq 0 || exit "$status"
cargo clippy --locked --offline --workspace --all-targets --no-default-features --features glue-runner/lua55 -- -D warnings > /evidence/lua55-clippy.txt 2>&1
status=$?
printf '%s\n' "$status" > /evidence/lua55-clippy.exit-status.txt
exit "$status"
