#!/bin/sh
set -eu
mkdir -p /evidence/linux /tmp/cargo
cat > /tmp/cargo/config.toml <<'CONFIG'
[source.crates-io]
replace-with = "vendored-sources"
[source.vendored-sources]
directory = "/workspace/target/vendor"
CONFIG
cargo_fixture() {
    cargo "$@"
}
uname -a > /evidence/linux/environment.txt
rustc --version >> /evidence/linux/environment.txt
cargo clippy --version >> /evidence/linux/environment.txt
for profile in lua54 lua55; do
    cargo_fixture test --workspace --locked --offline --no-default-features --features "$profile" --quiet > "/evidence/linux/$profile-workspace-tests.txt" 2>&1
    cargo_fixture clippy --workspace --all-targets --locked --offline --no-default-features --features "$profile" -- -D warnings > "/evidence/linux/$profile-workspace-clippy.txt" 2>&1
done
cargo_fixture build --locked --offline -p glue-macos-macho-probe > /evidence/linux/probe-build.txt 2>&1
set +e
/build-target/debug/glue-macos-macho-probe run /not-a-fixture.glue > /evidence/linux/unsupported.stdout.txt 2> /evidence/linux/unsupported.stderr.txt
status=$?
set -e
printf '%s\n' "$status" > /evidence/linux/unsupported.exit-status.txt
test "$status" -eq 2
test ! -s /evidence/linux/unsupported.stdout.txt
printf '%s\n' 'PASS Linux portable workspace tests, Clippy and unsupported execution classification'
