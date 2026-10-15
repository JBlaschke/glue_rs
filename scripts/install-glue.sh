#!/bin/sh
# Build and install only glue-owned tools. User applications/dependencies are inputs.
set -eu
if [ "$#" -ne 1 ]; then echo 'usage: scripts/install-glue.sh PREFIX' >&2; exit 2; fi
repository=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
prefix=$1
case "$prefix" in /*) ;; *) prefix="$(pwd)/$prefix";; esac
cd "$repository"
toolchain_bin=$(dirname -- "$(rustup which cargo)")
PATH="$toolchain_bin:$PATH"
export PATH
cargo build --release --locked -p glue-runner -p glue-runtime-node
target_dir=${CARGO_TARGET_DIR:-"$repository/target"}
case "$target_dir" in /*) ;; *) target_dir="$repository/$target_dir";; esac
case "$(uname -s)" in Darwin) bridge="$target_dir/release/libglue_runtime_node.dylib";; Linux) bridge="$target_dir/release/libglue_runtime_node.so";; *) echo 'Linux/macOS only' >&2; exit 1;; esac
mkdir -p "$prefix/bin"
install -m 755 "$target_dir/release/glue" "$prefix/bin/glue"
install -m 755 "$bridge" "$prefix/bin/glue-archive.node"
scripts/install-lua-helpers.sh "$prefix"
echo "Installed glue, both Lua helpers, and Node archive bridge in $prefix/bin"
