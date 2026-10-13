#!/bin/sh
set -eu
export PATH=/usr/local/rustup/toolchains/1.88.0-aarch64-unknown-linux-gnu/bin:$PATH
export CARGO_HOME=/tmp/cargo CARGO_TARGET_DIR=/build-target
mkdir -p "$CARGO_HOME"
printf '%s\n' '[source.crates-io]' 'replace-with = "vendored-sources"' '[source.vendored-sources]' 'directory = "/workspace/target/python-bootstrap-vendor"' > "$CARGO_HOME/config.toml"
cp "$CARGO_HOME/config.toml" /evidence/linux-vendor-config.toml
case "$(rustc --version)" in "rustc 1.88.0 "*) ;; *) exit 1 ;; esac
case "$(cargo clippy --version)" in "clippy 0.1.88 "*) ;; *) exit 1 ;; esac
rustc --version > /evidence/linux-workspace-environment.txt
uname -srvmo >> /evidence/linux-workspace-environment.txt
cargo --version >> /evidence/linux-workspace-environment.txt
cargo clippy --version >> /evidence/linux-workspace-environment.txt
cargo test --workspace --locked --offline > /evidence/linux-lua54-tests.txt 2>&1
cargo clippy --workspace --all-targets --locked --offline -- -D warnings > /evidence/linux-lua54-clippy.txt 2>&1
cargo test --workspace --locked --offline --no-default-features --features glue-runner/lua55 > /evidence/linux-lua55-tests.txt 2>&1
cargo clippy --workspace --all-targets --locked --offline --no-default-features --features glue-runner/lua55 -- -D warnings > /evidence/linux-lua55-clippy.txt 2>&1
printf '%s\n' passed > /evidence/linux-workspace-result.txt
