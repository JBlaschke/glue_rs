#!/bin/sh
# Run only after the implementation checkpoint is committed and source-clean.
set -eu
sourceapp_repo=/Users/johannes.blaschke/Developer/glue_rs
sourceapp_toolchain=/Users/johannes.blaschke/.rustup/toolchains/1.88.0-aarch64-apple-darwin/bin
sourceapp_logs=${1:-"$sourceapp_repo/target/python-source-app-checks"}
test "$(uname -s)" = Darwin
test -x "$sourceapp_toolchain/cargo"
if test -e "$sourceapp_logs"; then
    test "${2:-}" = --resume
    test "$(cat "$sourceapp_logs/source-revision.txt")" = "$(git -C "$sourceapp_repo" rev-parse HEAD)"
else
    mkdir -p "$sourceapp_logs"
fi
cd "$sourceapp_repo"
if test -n "$(git status --porcelain)"; then
    echo 'Source-app validation requires a committed, clean source checkpoint.' >&2
    exit 1
fi
sourceapp_logs=$(CDPATH= cd -- "$sourceapp_logs" && pwd)
export PATH="$sourceapp_toolchain:$PATH"
export CARGO_TARGET_DIR="$sourceapp_logs/build"
export CARGO_HOME="$sourceapp_logs/cargo-home"
mkdir -p "$CARGO_HOME"
printf '%s\n' '[source.crates-io]' 'replace-with = "vendored-sources"' \
    '[source.vendored-sources]' 'directory = "/Users/johannes.blaschke/Developer/glue_rs/target/vendor"' \
    > "$CARGO_HOME/config.toml"
cp "$CARGO_HOME/config.toml" "$sourceapp_logs/mac-vendor-config.toml"
git rev-parse HEAD > "$sourceapp_logs/source-revision.txt"
git branch --show-current > "$sourceapp_logs/source-branch.txt"
git status --porcelain > "$sourceapp_logs/source-status.txt"
git diff --binary > "$sourceapp_logs/source-diff.patch"
cp "$0" "$sourceapp_logs/commands.sh"
uname -srvm > "$sourceapp_logs/environment.txt"
rustc --version >> "$sourceapp_logs/environment.txt"
cargo --version >> "$sourceapp_logs/environment.txt"
cargo clippy --version >> "$sourceapp_logs/environment.txt"
python3 --version >> "$sourceapp_logs/environment.txt"
rustc --version | rg '^rustc 1\.88\.0 '
cargo clippy --version | rg '^clippy 0\.1\.88 '

sourceapp_variant() {
    sourceapp_label=$1
    shift
    cargo --config 'source.crates-io.replace-with="vendored-sources"' \
        --config 'source.vendored-sources.directory="/Users/johannes.blaschke/Developer/glue_rs/target/vendor"' test --locked --offline --workspace "$@" \
        > "$sourceapp_logs/$sourceapp_label-tests.txt" 2>&1
    cargo --config 'source.crates-io.replace-with="vendored-sources"' \
        --config 'source.vendored-sources.directory="/Users/johannes.blaschke/Developer/glue_rs/target/vendor"' clippy --locked --offline --workspace --all-targets "$@" -- -D warnings \
        > "$sourceapp_logs/$sourceapp_label-clippy.txt" 2>&1
}
sourceapp_variant lua54
sourceapp_variant lua55 --no-default-features \
    --features glue-runner/lua55,glue-runtime-lua/lua55
sourceapp_variant python-pbs --features glue-runner/python-pbs
python3 -I -S -B -m unittest discover -s scripts -p 'test_*.py' \
    > "$sourceapp_logs/policy-tests.txt" 2>&1
python3 -I -S -B -m unittest discover -s fixtures/python-imports -p 'test_*.py' \
    > "$sourceapp_logs/importer-tests.txt" 2>&1
python3 -I -S -B fixtures/python-source-apps/test_entry.py \
    > "$sourceapp_logs/entry-tests.txt" 2>&1
git status --porcelain > "$sourceapp_logs/final-source-status.txt"
test ! -s "$sourceapp_logs/final-source-status.txt"
test "$(git rev-parse HEAD)" = "$(cat "$sourceapp_logs/source-revision.txt")"
printf 'Clean Mac source-app validation passed: %s\n' "$sourceapp_logs"
