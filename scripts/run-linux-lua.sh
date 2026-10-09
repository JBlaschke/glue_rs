#!/bin/sh
set -eu

repo_dir=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
cd "$repo_dir"
if test "$#" -gt 1; then
    echo 'Usage: sh scripts/run-linux-lua.sh [lua54|lua55]' >&2
    exit 1
fi
lua_profile=${1:-lua54}
case "$lua_profile" in
    lua54) lua_version=5.4 ;;
    lua55) lua_version=5.5 ;;
    *) echo 'Expected lua54 or lua55 profile.' >&2; exit 1 ;;
esac
toolchain_dir=$(dirname -- "$(rustup which --toolchain 1.88.0 cargo)")
PATH="$toolchain_dir:$PATH"
export PATH
mkdir -p target/evidence/linux-lua
run_dir=$(mktemp -d "$repo_dir/target/evidence/linux-lua/run-XXXXXXXX")
printf '%s\n' "$lua_version" > "$run_dir/lua-version.txt"
printf '%s\n' "$lua_profile" > "$run_dir/lua-profile.txt"
if ! cargo vendor --locked --offline target/linux-lua-vendor \
    > "$run_dir/vendor-config.toml" 2> "$run_dir/vendor.log"; then
    cat "$run_dir/vendor.log" >&2
    exit 1
fi
# Reuse the local probe image built from the digest-pinned native Dockerfile.
# Resolve its immutable local ID before running; do not rebuild or pull here.
image=$(podman image inspect --format '{{.Id}}' localhost/glue-linux-probe:rust-1.88.0)
printf '%s\n' "$image" > "$run_dir/image-id.txt"
podman image inspect "$image" > "$run_dir/image-inspect.json"
git rev-parse HEAD > "$run_dir/source-commit.txt"
git status --short --branch > "$run_dir/source-status.txt"
git diff --binary > "$run_dir/source.diff"
set +e
podman run --rm --network none --read-only \
    --tmpfs /tmp:rw,size=256m \
    --tmpfs /build-target:rw,size=2g \
    --mount "type=bind,source=$repo_dir,destination=/workspace,ro" \
    --mount "type=bind,source=$run_dir,destination=/evidence" \
    --workdir /workspace \
    --env RUSTUP_TOOLCHAIN=1.88.0 \
    --env CARGO_HOME=/tmp/cargo \
    --env CARGO_TARGET_DIR=/build-target \
    --env "GLUE_LUA_PROFILE=$lua_profile" \
    "$image" sh fixtures/lua-linked/run-linux.sh \
    > "$run_dir/harness.stdout.txt" 2> "$run_dir/harness.stderr.txt"
harness_status=$?
set -e
printf '%s\n' "$harness_status" > "$run_dir/harness.exit-status.txt"
if test "$harness_status" -ne 0; then
    cat "$run_dir/harness.stderr.txt" >&2
    printf 'Linux Lua harness failed. Evidence: %s\n' "$run_dir" >&2
    exit "$harness_status"
fi
set +e
python3 scripts/check-linux-lua-trace.py --lua-version "$lua_version" "$run_dir/lua.trace.txt" \
    > "$run_dir/trace-check.txt" 2> "$run_dir/trace-check.stderr.txt"
check_status=$?
set -e
printf '%s\n' "$check_status" > "$run_dir/trace-check.exit-status.txt"
cat "$run_dir/trace-check.txt"
if test "$check_status" -ne 0; then
    cat "$run_dir/trace-check.stderr.txt" >&2
    printf 'Linux Lua trace rejected. Evidence: %s\n' "$run_dir" >&2
    exit "$check_status"
fi
printf 'Lua %s answer=42 asset=Hello from archived resources!\n' "$lua_version" \
    > "$run_dir/expected.stdout.txt"
cmp "$run_dir/expected.stdout.txt" "$run_dir/lua.stdout.txt"
test ! -s "$run_dir/lua.stderr.txt"
printf 'Trace checks passed. Evidence: %s\n' "$run_dir"
