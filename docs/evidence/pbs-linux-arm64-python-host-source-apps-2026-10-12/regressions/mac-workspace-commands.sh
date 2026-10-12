#!/bin/sh
# Run only after the implementation checkpoint is committed and source-clean.
set -eu
hostsourceapp_repo=/Users/johannes.blaschke/Developer/glue_rs
hostsourceapp_toolchain=/Users/johannes.blaschke/.rustup/toolchains/1.88.0-aarch64-apple-darwin/bin
hostsourceapp_logs=${1:-"$hostsourceapp_repo/target/python-host-source-app-checks"}
test "$(uname -s)" = Darwin
test -x "$hostsourceapp_toolchain/cargo"
if test -e "$hostsourceapp_logs"; then
    test "${2:-}" = --resume
    test "$(cat "$hostsourceapp_logs/source-revision.txt")" = "$(git -C "$hostsourceapp_repo" rev-parse HEAD)"
else
    mkdir -p "$hostsourceapp_logs"
fi
cd "$hostsourceapp_repo"
if test -n "$(git status --porcelain)"; then
    echo 'Host-source-app validation requires a committed, clean source checkpoint.' >&2
    exit 1
fi
hostsourceapp_logs=$(CDPATH= cd -- "$hostsourceapp_logs" && pwd)
export PATH="$hostsourceapp_toolchain:$PATH"
export CARGO_TARGET_DIR="$hostsourceapp_logs/build"
export CARGO_HOME="$hostsourceapp_logs/cargo-home"
mkdir -p "$CARGO_HOME"
printf '%s\n' '[source.crates-io]' 'replace-with = "vendored-sources"' \
    '[source.vendored-sources]' 'directory = "/Users/johannes.blaschke/Developer/glue_rs/target/vendor"' \
    > "$CARGO_HOME/config.toml"
cp "$CARGO_HOME/config.toml" "$hostsourceapp_logs/mac-vendor-config.toml"
git rev-parse HEAD > "$hostsourceapp_logs/source-revision.txt"
git branch --show-current > "$hostsourceapp_logs/source-branch.txt"
git status --porcelain > "$hostsourceapp_logs/source-status.txt"
git diff --binary > "$hostsourceapp_logs/source-diff.patch"
cp "$0" "$hostsourceapp_logs/commands.sh"
uname -srvm > "$hostsourceapp_logs/environment.txt"
rustc --version >> "$hostsourceapp_logs/environment.txt"
cargo --version >> "$hostsourceapp_logs/environment.txt"
cargo clippy --version >> "$hostsourceapp_logs/environment.txt"
python3 --version >> "$hostsourceapp_logs/environment.txt"
rustc --version | rg '^rustc 1\.88\.0 '
cargo clippy --version | rg '^clippy 0\.1\.88 '

hostsourceapp_variant() {
    hostsourceapp_label=$1
    shift
    cargo --config 'source.crates-io.replace-with="vendored-sources"' \
        --config 'source.vendored-sources.directory="/Users/johannes.blaschke/Developer/glue_rs/target/vendor"' test --locked --offline --workspace "$@" \
        > "$hostsourceapp_logs/$hostsourceapp_label-tests.txt" 2>&1
    cargo --config 'source.crates-io.replace-with="vendored-sources"' \
        --config 'source.vendored-sources.directory="/Users/johannes.blaschke/Developer/glue_rs/target/vendor"' clippy --locked --offline --workspace --all-targets "$@" -- -D warnings \
        > "$hostsourceapp_logs/$hostsourceapp_label-clippy.txt" 2>&1
}
hostsourceapp_variant lua54
hostsourceapp_variant lua55 --no-default-features \
    --features glue-runner/lua55,glue-runtime-lua/lua55
hostsourceapp_variant python-pbs --features glue-runner/python-pbs
python3 -I -S -B -m unittest discover -s scripts -p 'test_*.py' \
    > "$hostsourceapp_logs/policy-tests.txt" 2>&1
python3 -I -S -B -m unittest discover -s fixtures/python-imports -p 'test_*.py' \
    > "$hostsourceapp_logs/importer-tests.txt" 2>&1
python3 -I -S -B fixtures/python-source-apps/test_entry.py \
    > "$hostsourceapp_logs/entry-tests.txt" 2>&1
python3 -I -S -B fixtures/python-host-source-apps/test_protocol.py \
    > "$hostsourceapp_logs/host-protocol-tests.txt" 2>&1
git status --porcelain > "$hostsourceapp_logs/final-source-status.txt"
test ! -s "$hostsourceapp_logs/final-source-status.txt"
test "$(git rev-parse HEAD)" = "$(cat "$hostsourceapp_logs/source-revision.txt")"
printf 'Clean Mac host-source-app validation passed: %s\n' "$hostsourceapp_logs"
