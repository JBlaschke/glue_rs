#!/bin/sh
# One installation produces both version-specific helpers. No app code is built.
set -eu
if [ "$#" -ne 1 ]; then
    echo "usage: scripts/install-lua-helpers.sh PREFIX" >&2
    exit 2
fi
repository=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
prefix=$1
case "$prefix" in
    /*) ;;
    *) prefix="$(pwd)/$prefix" ;;
esac
toolchain_bin=$(dirname -- "$(cd "$repository" && rustup which cargo)")
PATH="$toolchain_bin:$PATH"
export PATH
cd "$repository"
target_dir=${CARGO_TARGET_DIR:-"$repository/target"}
case "$target_dir" in
    /*) ;;
    *) target_dir="$repository/$target_dir" ;;
esac
stage=$(mktemp -d "${TMPDIR:-/tmp}/glue-lua-helpers.XXXXXXXX")
trap 'rm -rf "$stage"' EXIT HUP INT TERM
for family in 54 55; do
    cargo build --locked --release -p glue-runtime-lua --no-default-features \
        --features "lua$family" --bin "glue-lua$family"
    cp "$target_dir/release/glue-lua$family" "$stage/glue-lua$family"
done
mkdir -p "$prefix/bin"
for family in 54 55; do
    install -m 755 "$stage/glue-lua$family" "$prefix/bin/glue-lua$family"
done
echo "Installed glue-lua54 and glue-lua55 in $prefix/bin"
