#!/bin/sh
set -eu
export PATH=/usr/local/rustup/toolchains/1.88.0-aarch64-unknown-linux-gnu/bin:$PATH
export CARGO_HOME=/tmp/python-template-workspace-cargo CARGO_TARGET_DIR=/build-target
mkdir -p "$CARGO_HOME"
cat > "$CARGO_HOME/config.toml" <<'CFG'
[source.crates-io]
replace-with = "vendored-sources"
[source.vendored-sources]
directory = "/workspace/target/python-bootstrap-vendor"
CFG
uname -srvmo > /evidence/linux-environment.txt
rustc --version >> /evidence/linux-environment.txt
cargo --version >> /evidence/linux-environment.txt
getconf PAGESIZE >> /evidence/linux-environment.txt
dpkg-query -W libc6 strace >> /evidence/linux-environment.txt
check() {
    name=$1
    shift
    status=0
    "$@" > "/evidence/$name.txt" 2>&1 || status=$?
    printf '%s\n' "$status" > "/evidence/$name.exit-status.txt"
    test "$status" -eq 0
}
check linux-workspace-tests cargo test --workspace --locked --offline
check linux-workspace-clippy cargo clippy --workspace --all-targets --locked --offline -- -D warnings
check linux-lua55-tests cargo test --workspace --locked --offline --no-default-features --features glue-runner/lua55,glue-runtime-lua/lua55
check linux-lua55-clippy cargo clippy --workspace --all-targets --locked --offline --no-default-features --features glue-runner/lua55,glue-runtime-lua/lua55 -- -D warnings
