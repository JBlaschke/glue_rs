#!/bin/sh
# Run only after the implementation checkpoint is committed and source-clean.
set -eu
runner_repo=/Users/johannes.blaschke/Developer/glue_rs
runner_toolchain=/Users/johannes.blaschke/.rustup/toolchains/1.88.0-aarch64-apple-darwin/bin
runner_logs=${1:-"$runner_repo/target/python-runner-checks"}
test "$(uname -s)" = Darwin
test -x "$runner_toolchain/cargo"
if test -e "$runner_logs"; then
    test "${2:-}" = --resume
    test "$(cat "$runner_logs/source-revision.txt")" = "$(git -C "$runner_repo" rev-parse HEAD)"
else
    mkdir -p "$runner_logs"
fi
cd "$runner_repo"
if test -n "$(git status --porcelain)"; then
    echo 'Runner validation requires a committed, clean source checkpoint.' >&2
    exit 1
fi
runner_logs=$(CDPATH= cd -- "$runner_logs" && pwd)
export PATH="$runner_toolchain:$PATH"
export CARGO_TARGET_DIR="$runner_logs/build"
export CARGO_HOME="$runner_logs/cargo-home"
mkdir -p "$CARGO_HOME"
printf '%s\n' '[source.crates-io]' 'replace-with = "vendored-sources"' \
    '[source.vendored-sources]' 'directory = "/Users/johannes.blaschke/Developer/glue_rs/target/vendor"' \
    > "$CARGO_HOME/config.toml"
cp "$CARGO_HOME/config.toml" "$runner_logs/mac-vendor-config.toml"
git rev-parse HEAD > "$runner_logs/source-revision.txt"
git branch --show-current > "$runner_logs/source-branch.txt"
git status --porcelain > "$runner_logs/source-status.txt"
git diff --binary > "$runner_logs/source-diff.patch"
cp "$0" "$runner_logs/commands.sh"
uname -srvm > "$runner_logs/environment.txt"
rustc --version >> "$runner_logs/environment.txt"
cargo --version >> "$runner_logs/environment.txt"
cargo clippy --version >> "$runner_logs/environment.txt"
python3 --version >> "$runner_logs/environment.txt"
rustc --version | rg '^rustc 1\.88\.0 '
cargo clippy --version | rg '^clippy 0\.1\.88 '

runner_variant() {
    runner_label=$1
    shift
    cargo --config 'source.crates-io.replace-with="vendored-sources"' \
        --config 'source.vendored-sources.directory="/Users/johannes.blaschke/Developer/glue_rs/target/vendor"' test --locked --offline --workspace "$@" \
        > "$runner_logs/$runner_label-tests.txt" 2>&1
    cargo --config 'source.crates-io.replace-with="vendored-sources"' \
        --config 'source.vendored-sources.directory="/Users/johannes.blaschke/Developer/glue_rs/target/vendor"' clippy --locked --offline --workspace --all-targets "$@" -- -D warnings \
        > "$runner_logs/$runner_label-clippy.txt" 2>&1
}
runner_variant lua54
runner_variant lua55 --no-default-features \
    --features glue-runner/lua55,glue-runtime-lua/lua55
runner_variant python-pbs --features glue-runner/python-pbs
python3 -I -S -B -m unittest discover -s scripts -p 'test_*.py' \
    > "$runner_logs/policy-tests.txt" 2>&1
python3 -I -S -B -m unittest discover -s fixtures/python-imports -p 'test_*.py' \
    > "$runner_logs/importer-tests.txt" 2>&1
git status --porcelain > "$runner_logs/final-source-status.txt"
test ! -s "$runner_logs/final-source-status.txt"
printf 'Clean Mac runner validation passed: %s\n' "$runner_logs"
