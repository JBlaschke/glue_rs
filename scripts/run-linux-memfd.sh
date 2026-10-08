#!/bin/sh
set -eu

repo_dir=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
cd "$repo_dir"
mkdir -p target/evidence/linux-memfd
if ! cargo vendor --locked --offline target/vendor > target/vendor-config.toml \
    2> target/vendor.log; then
    cat target/vendor.log >&2
    exit 1
fi
podman build --tag localhost/glue-linux-probe:rust-1.88.0 \
    --file fixtures/native/linux-memfd/Dockerfile fixtures/native/linux-memfd
image=$(podman image inspect --format '{{.Id}}' localhost/glue-linux-probe:rust-1.88.0)
run_dir=$(mktemp -d "$repo_dir/target/evidence/linux-memfd/run-XXXXXXXX")
printf '%s\n' "$image" > "$run_dir/image-id.txt"
git rev-parse HEAD > "$run_dir/source-commit.txt"
git status --short --branch > "$run_dir/source-status.txt"
git diff --binary > "$run_dir/source.diff"
podman run --rm --network none --read-only \
    --tmpfs /tmp:rw,size=256m \
    --tmpfs /build-target:rw,size=2g \
    --mount "type=bind,source=$repo_dir,destination=/workspace,ro" \
    --mount "type=bind,source=$run_dir,destination=/evidence" \
    --workdir /workspace \
    --env RUSTUP_TOOLCHAIN=1.88.0 \
    --env CARGO_HOME=/tmp/cargo \
    --env CARGO_TARGET_DIR=/build-target \
    "$image" sh fixtures/native/linux-memfd/run.sh

python3 scripts/check-linux-memfd-trace.py "$run_dir/probe.trace.txt" \
    > "$run_dir/trace-check.txt"
cat "$run_dir/trace-check.txt"
rg -q 'baseline PASS.*answer=42.*data=7.*constructors=1' "$run_dir/baseline.stdout.txt"
rg -q 'PASS.*answer=42.*data=7.*constructors=1' "$run_dir/probe.stdout.txt"
printf 'Trace checks passed. Evidence: %s\n' "$run_dir"
