#!/bin/sh
set -eu
PATH=/Users/johannes.blaschke/.rustup/toolchains/1.88.0-aarch64-apple-darwin/bin:$PATH
export PATH
uname -a > target/pbs-inspection/final-886a415/macos/environment.txt
sw_vers >> target/pbs-inspection/final-886a415/macos/environment.txt
rustc --version >> target/pbs-inspection/final-886a415/macos/environment.txt
cargo clippy --version >> target/pbs-inspection/final-886a415/macos/environment.txt
cargo fmt --all -- --check > target/pbs-inspection/final-886a415/macos/format.txt 2>&1
for profile in lua54 lua55; do
 cargo test --workspace --locked --offline --no-default-features --features "$profile" --quiet > "target/pbs-inspection/final-886a415/macos/$profile-tests.txt" 2>&1
 cargo clippy --workspace --all-targets --locked --offline --no-default-features --features "$profile" -- -D warnings > "target/pbs-inspection/final-886a415/macos/$profile-clippy.txt" 2>&1
done
cargo test -p glue-pbs --release --locked --offline > target/pbs-inspection/final-886a415/macos/pbs-optimized-tests.txt 2>&1
cargo build -p glue-pbs --release --locked --offline > target/pbs-inspection/final-886a415/macos/pbs-build.txt 2>&1
shasum -a 256 target/release/glue-pbs-inspect > target/pbs-inspection/final-886a415/macos/inspector-sha256.txt
full=target/pbs-inspection/cpython-3.13.16+20261009-aarch64-unknown-linux-gnu-pgo+lto-full.tar.zst
install=target/pbs-inspection/cpython-3.13.16+20261009-aarch64-unknown-linux-gnu-install_only.tar.gz
target/release/glue-pbs-inspect fixtures/python-pbs/pins.json "$full" "$install" > target/pbs-inspection/final-886a415/macos/inspection.json 2> target/pbs-inspection/final-886a415/macos/inspection.stderr.txt
target/release/glue-pbs-inspect fixtures/python-pbs/pins.json "$full" > target/pbs-inspection/final-886a415/macos/full-only.json 2> target/pbs-inspection/final-886a415/macos/full-only.stderr.txt
set +e
target/release/glue-pbs-inspect target/pbs-inspection/final-886a415/bad-digest-pins.json "$full" "$install" > target/pbs-inspection/final-886a415/macos/bad-digest.stdout.txt 2> target/pbs-inspection/final-886a415/macos/bad-digest.stderr.txt
status=$?
set -e
printf '%s\n' "$status" > target/pbs-inspection/final-886a415/macos/bad-digest.exit-status.txt
test "$status" -eq 1
test ! -s target/pbs-inspection/final-886a415/macos/bad-digest.stdout.txt
