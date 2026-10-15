#!/bin/sh
# Native offline cell; /vendor and /workspace are read-only input mounts.
set -eu
: "${CARGO_HOME:?}"
: "${CARGO_TARGET_DIR:?}"
mkdir -p "$CARGO_HOME"
cat > "$CARGO_HOME/config.toml" <<'CONFIG'
[source.crates-io]
replace-with = "vendored-sources"
[source.vendored-sources]
directory = "/vendor"
CONFIG
test "$(rustc --version | cut -d ' ' -f 2)" = 1.88.0
cargo build -p glue-runner -p glue-runtime-lua --locked --offline
cargo build -p glue-runtime-lua --no-default-features --features lua55 --bin glue-lua55 --locked --offline
for family in 54 55; do
    case "$family" in
        54) release=5.4.9 ;;
        55) release=5.5.1 ;;
    esac
    source_dir="/vendor/lua-src/lua-$release"
    cc -O2 -DLUA_USE_LINUX -DLUA_COMPAT_5_3 -I"$source_dir" \
        "$source_dir"/*.c fixtures/mvp/lua-projects/reference-driver.c \
        -Wl,--export-dynamic -lm -ldl -o "$CARGO_TARGET_DIR/lua$family-reference"
    fixtures/mvp/lua-native/prepare.sh "$CARGO_TARGET_DIR/lua$family-native" "$source_dir"
done
export GLUE_MVP_GLUE="$CARGO_TARGET_DIR/debug/glue"
export GLUE_MVP_HELPERS="$CARGO_TARGET_DIR/debug"
export GLUE_MVP_LUA54="$CARGO_TARGET_DIR/lua54-reference"
export GLUE_MVP_LUA55="$CARGO_TARGET_DIR/lua55-reference"
export GLUE_MVP_LUA54_NATIVE="$CARGO_TARGET_DIR/lua54-native"
export GLUE_MVP_LUA55_NATIVE="$CARGO_TARGET_DIR/lua55-native"
for family in 54 55; do
    for corpus in project native; do
        scripts/run-mvp.sh --case "lua$family-$corpus" --target aarch64-unknown-linux-gnu --output "/evidence/lua$family-$corpus"
        scripts/check-mvp-results.py "/evidence/lua$family-$corpus/receipt.json"
    done
done
