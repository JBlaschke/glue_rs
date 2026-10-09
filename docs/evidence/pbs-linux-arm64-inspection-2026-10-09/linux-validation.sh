#!/bin/sh
set -eu
mkdir -p /tmp/cargo /evidence/linux
cat > /tmp/cargo/config.toml <<'CONFIG'
[source.crates-io]
replace-with="vendored-sources"
[source.vendored-sources]
directory="/workspace/target/vendor"
CONFIG
uname -a > /evidence/linux/environment.txt
rustc --version >> /evidence/linux/environment.txt
cargo clippy --version >> /evidence/linux/environment.txt
getconf PAGESIZE >> /evidence/linux/environment.txt
ldd --version >> /evidence/linux/environment.txt
strace --version >> /evidence/linux/environment.txt
for profile in lua54 lua55; do
 cargo test --workspace --locked --offline --no-default-features --features "$profile" --quiet > "/evidence/linux/$profile-tests.txt" 2>&1
 cargo clippy --workspace --all-targets --locked --offline --no-default-features --features "$profile" -- -D warnings > "/evidence/linux/$profile-clippy.txt" 2>&1
done
cargo test -p glue-pbs --release --locked --offline > /evidence/linux/pbs-optimized-tests.txt 2>&1
cargo build -p glue-pbs --release --locked --offline > /evidence/linux/pbs-build.txt 2>&1
full=/workspace/target/pbs-inspection/cpython-3.13.16+20261009-aarch64-unknown-linux-gnu-pgo+lto-full.tar.zst
install=/workspace/target/pbs-inspection/cpython-3.13.16+20261009-aarch64-unknown-linux-gnu-install_only.tar.gz
sha256sum /build-target/release/glue-pbs-inspect > /evidence/linux/inspector-sha256.txt
strace -f -s 256 -yy -o /evidence/linux/inspection.trace.txt /build-target/release/glue-pbs-inspect /workspace/fixtures/python-pbs/pins.json "$full" "$install" > /evidence/linux/inspection.json 2> /evidence/linux/inspection.stderr.txt
