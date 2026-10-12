#!/bin/sh
# Source-workspace and synthetic anonymous-pipe validation; no runtime worker.
set -eu
image=62812c4a0e15bc750ddd6ec68d2a19f8815a14b60d520e201a911e2e29f40abe

if test "${1:-}" = --container; then
    export PATH=/usr/local/rustup/toolchains/1.88.0-aarch64-unknown-linux-gnu/bin:$PATH
    export CARGO_HOME=/tmp/cargo CARGO_TARGET_DIR=/build-target
    mkdir -p "$CARGO_HOME"
    printf '%s\n' '[source.crates-io]' 'replace-with = "vendored-sources"' \
        '[source.vendored-sources]' 'directory = "/workspace/target/worker-protocol-vendor"' > "$CARGO_HOME/config.toml"
    uname -srvmo > /evidence/linux-environment.txt
    rustc --version >> /evidence/linux-environment.txt
    cargo --version >> /evidence/linux-environment.txt
    getconf PAGESIZE >> /evidence/linux-environment.txt
    dpkg-query -W libc6 strace >> /evidence/linux-environment.txt
    cargo test --workspace --locked --offline > /evidence/linux-workspace-tests.txt 2>&1
    cargo clippy --workspace --all-targets --locked --offline -- -D warnings > /evidence/linux-workspace-clippy.txt 2>&1
    cargo test --workspace --locked --offline --no-default-features \
        --features glue-runner/lua55,glue-runtime-lua/lua55 > /evidence/linux-lua55-tests.txt 2>&1
    cargo clippy --workspace --all-targets --locked --offline --no-default-features \
        --features glue-runner/lua55,glue-runtime-lua/lua55 -- -D warnings > /evidence/linux-lua55-clippy.txt 2>&1
    cargo test --release --locked --offline -p glue-ipc -p glue-worker-protocol-fixture \
        > /evidence/linux-ipc-release-tests.txt 2>&1
    # Run the built pipe-test executable directly, keeping compiler/build I/O
    # outside this process/descriptor trace. Tests create only synthetic peers.
    for candidate in /build-target/release/deps/pipes-*; do
        if test -f "$candidate" && test -x "$candidate"; then pipe_test=$candidate; fi
    done
    test -n "${pipe_test:-}"
    sha256sum "$pipe_test" /build-target/release/glue-ipc-peer > /evidence/linux-artifacts.sha256
    strace -f -s 256 -yy -e trace=all -o /evidence/linux-pipes.trace.txt \
        "$pipe_test" --test-threads=1 > /evidence/linux-pipes.stdout.txt 2> /evidence/linux-pipes.stderr.txt
    printf '0\n' > /evidence/linux-pipes.exit-status.txt
    test ! -s /evidence/linux-pipes.stderr.txt
    exit 0
fi

repo_dir=$(CDPATH= cd -- "$(dirname -- "$0")/../.." && pwd)
cd "$repo_dir"
evidence_dir=${GLUE_IPC_EVIDENCE_DIR:-$repo_dir/target/evidence/worker-protocol}
mkdir -p "$evidence_dir"
evidence_dir=$(CDPATH= cd -- "$evidence_dir" && pwd)
rustup run 1.88.0 cargo vendor --locked --offline target/worker-protocol-vendor \
    > target/worker-protocol-vendor-config.toml
podman run --rm --network none --read-only \
    --tmpfs /tmp:rw,size=256m --tmpfs /build-target:rw,size=2g \
    --mount "type=bind,source=$repo_dir,destination=/workspace,ro" \
    --mount "type=bind,source=$evidence_dir,destination=/evidence,rw" \
    --workdir /workspace "$image" sh /workspace/fixtures/worker-protocol/run-linux.sh --container
