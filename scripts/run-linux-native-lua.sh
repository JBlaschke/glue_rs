#!/bin/sh
set -eu
repository=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
cd "$repository"
if test "$#" -gt 1; then
    echo 'Usage: run-linux-native-lua.sh [lua54|lua55]' >&2
    exit 1
fi
profile=${1:-lua54}
case "$profile" in
    lua54) version=5.4 ;;
    lua55) version=5.5 ;;
    *) echo 'Expected lua54 or lua55 profile.' >&2; exit 1 ;;
esac
toolchain_dir=$(dirname -- "$(rustup which --toolchain 1.88.0 cargo)")
PATH="$toolchain_dir:$PATH"
export PATH
mkdir -p target/evidence/linux-native-lua
run_dir=$(mktemp -d "$repository/target/evidence/linux-native-lua/run-XXXXXXXX")
printf '%s\n' "$profile" > "$run_dir/lua-profile.txt"
printf '%s\n' "$version" > "$run_dir/lua-version.txt"
if ! cargo vendor --locked --offline target/linux-lua-vendor \
    > "$run_dir/vendor-config.toml" 2> "$run_dir/vendor.log"; then
    cat "$run_dir/vendor.log" >&2
    exit 1
fi
image=$(podman image inspect --format '{{.Id}}' localhost/glue-linux-probe:rust-1.88.0)
printf '%s\n' "$image" > "$run_dir/image-id.txt"
podman image inspect "$image" > "$run_dir/image-inspect.json"
git rev-parse HEAD > "$run_dir/source-commit.txt"
git status --short --branch > "$run_dir/source-status.txt"
git diff --binary > "$run_dir/source.diff"
set +e
podman run --rm --network none --read-only --tmpfs /tmp:rw,size=256m --tmpfs /build-target:rw,size=2g \
    --mount "type=bind,source=$repository,destination=/workspace,ro" \
    --mount "type=bind,source=$run_dir,destination=/evidence" --workdir /workspace \
    --env RUSTUP_TOOLCHAIN=1.88.0 --env CARGO_HOME=/tmp/cargo \
    --env CARGO_TARGET_DIR=/build-target --env "GLUE_LUA_PROFILE=$profile" \
    "$image" sh fixtures/native/lua-linux/run-linux.sh \
    > "$run_dir/harness.stdout.txt" 2> "$run_dir/harness.stderr.txt"
status=$?
set -e
printf '%s\n' "$status" > "$run_dir/harness.exit-status.txt"
if test "$status" -ne 0; then
    cat "$run_dir/harness.stderr.txt" >&2
    printf 'Native Lua harness failed. Evidence: %s\n' "$run_dir" >&2
    exit "$status"
fi
set +e
PYTHONDONTWRITEBYTECODE=1 python3 scripts/check-linux-native-lua-trace.py --lua-version "$version" "$run_dir/native-lua.trace.txt" \
    > "$run_dir/trace-check.txt" 2> "$run_dir/trace-check.stderr.txt"
status=$?
set -e
printf '%s\n' "$status" > "$run_dir/trace-check.exit-status.txt"
cat "$run_dir/trace-check.txt"
if test "$status" -ne 0; then
    cat "$run_dir/trace-check.stderr.txt" >&2
    printf 'Native Lua trace rejected. Evidence: %s\n' "$run_dir" >&2
    exit "$status"
fi
set +e
PYTHONDONTWRITEBYTECODE=1 python3 scripts/check-linux-native-lua-rejections.py "$run_dir/native-rejections" \
    > "$run_dir/rejection-trace-check.txt" 2> "$run_dir/rejection-trace-check.stderr.txt"
status=$?
set -e
printf '%s\n' "$status" > "$run_dir/rejection-trace-check.exit-status.txt"
cat "$run_dir/rejection-trace-check.txt"
if test "$status" -ne 0; then
    cat "$run_dir/rejection-trace-check.stderr.txt" >&2
    printf 'Native Lua rejection traces rejected. Evidence: %s\n' "$run_dir" >&2
    exit "$status"
fi
# Both processes exercised the same compiled core and fixture. Their OS PIDs
# differ; every other byte must agree, and the trace independently checks its PID.
sed 's/ pid=[0-9][0-9]*/ pid=PROCESS/' "$run_dir/baseline.stdout.txt" > "$run_dir/baseline.normalized.txt"
sed 's/ pid=[0-9][0-9]*/ pid=PROCESS/' "$run_dir/native-lua.stdout.txt" > "$run_dir/native-lua.normalized.txt"
cmp "$run_dir/baseline.normalized.txt" "$run_dir/native-lua.normalized.txt"
printf 'Native Lua %s trace/baseline checks passed. Evidence: %s\n' "$version" "$run_dir"
