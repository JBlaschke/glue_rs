#!/bin/sh
# Run only after the implementation checkpoint is committed and source-clean.
set -eu
installhostapp_repo=/Users/johannes.blaschke/Developer/glue_rs
installhostapp_toolchain=/Users/johannes.blaschke/.rustup/toolchains/1.88.0-aarch64-apple-darwin/bin
installhostapp_logs=${1:-"$installhostapp_repo/target/python-install-host-source-app-checks"}
test "$(uname -s)" = Darwin
test -x "$installhostapp_toolchain/cargo"
if test -e "$installhostapp_logs"; then
    test "${2:-}" = --resume
    test "$(cat "$installhostapp_logs/source-revision.txt")" = "$(git -C "$installhostapp_repo" rev-parse HEAD)"
else
    mkdir -p "$installhostapp_logs"
fi
cd "$installhostapp_repo"
if test -n "$(git status --porcelain)"; then
    echo 'Host-source-app validation requires a committed, clean source checkpoint.' >&2
    exit 1
fi
installhostapp_logs=$(CDPATH= cd -- "$installhostapp_logs" && pwd)
export PATH="$installhostapp_toolchain:$PATH"
export CARGO_TARGET_DIR="$installhostapp_logs/build"
export CARGO_HOME="$installhostapp_logs/cargo-home"
mkdir -p "$CARGO_HOME"
printf '%s\n' '[source.crates-io]' 'replace-with = "vendored-sources"' \
    '[source.vendored-sources]' 'directory = "/Users/johannes.blaschke/Developer/glue_rs/target/vendor"' \
    > "$CARGO_HOME/config.toml"
cp "$CARGO_HOME/config.toml" "$installhostapp_logs/mac-vendor-config.toml"
git rev-parse HEAD > "$installhostapp_logs/source-revision.txt"
git branch --show-current > "$installhostapp_logs/source-branch.txt"
git status --porcelain > "$installhostapp_logs/source-status.txt"
git diff --binary > "$installhostapp_logs/source-diff.patch"
cp "$0" "$installhostapp_logs/commands.sh"
uname -srvm > "$installhostapp_logs/environment.txt"
rustc --version >> "$installhostapp_logs/environment.txt"
cargo --version >> "$installhostapp_logs/environment.txt"
cargo clippy --version >> "$installhostapp_logs/environment.txt"
python3 --version >> "$installhostapp_logs/environment.txt"
rustc --version | rg '^rustc 1\.88\.0 '
cargo clippy --version | rg '^clippy 0\.1\.88 '

installhostapp_variant() {
    installhostapp_label=$1
    shift
    cargo --config 'source.crates-io.replace-with="vendored-sources"' \
        --config 'source.vendored-sources.directory="/Users/johannes.blaschke/Developer/glue_rs/target/vendor"' test --locked --offline --workspace "$@" \
        > "$installhostapp_logs/$installhostapp_label-tests.txt" 2>&1
    cargo --config 'source.crates-io.replace-with="vendored-sources"' \
        --config 'source.vendored-sources.directory="/Users/johannes.blaschke/Developer/glue_rs/target/vendor"' clippy --locked --offline --workspace --all-targets "$@" -- -D warnings \
        > "$installhostapp_logs/$installhostapp_label-clippy.txt" 2>&1
}
installhostapp_variant lua54
installhostapp_variant lua55 --no-default-features \
    --features glue-runner/lua55,glue-runtime-lua/lua55
installhostapp_variant python-pbs --features glue-runner/python-pbs
python3 -I -S -B -m unittest discover -s scripts -p 'test_*.py' \
    > "$installhostapp_logs/policy-tests.txt" 2>&1
python3 -I -S -B -m unittest discover -s fixtures/python-imports -p 'test_*.py' \
    > "$installhostapp_logs/importer-tests.txt" 2>&1
python3 -I -S -B fixtures/python-source-apps/test_entry.py \
    > "$installhostapp_logs/entry-tests.txt" 2>&1
python3 -I -S -B fixtures/python-host-source-apps/test_protocol.py \
    > "$installhostapp_logs/host-protocol-tests.txt" 2>&1
git status --porcelain > "$installhostapp_logs/final-source-status.txt"
test ! -s "$installhostapp_logs/final-source-status.txt"
test "$(git rev-parse HEAD)" = "$(cat "$installhostapp_logs/source-revision.txt")"
printf 'Clean Mac host-source-app validation passed: %s\n' "$installhostapp_logs"
