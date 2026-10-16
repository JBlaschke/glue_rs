#!/bin/sh
set -eu
repository=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
cd "$repository"
toolchain_bin=$(dirname -- "$(rustup which cargo)")
PATH="$toolchain_bin:$PATH"
export PATH
rustc --version | grep -E '^rustc 1\.88\.0 '
cargo clippy --version | grep -E '^clippy 0\.1\.88 '
host=$(rustc -vV | sed -n 's/^host: //p')
if [ -n "${GLUE_CI_EXPECT_HOST:-}" ] && [ "$host" != "$GLUE_CI_EXPECT_HOST" ]; then
    echo "native runner mismatch: $host != $GLUE_CI_EXPECT_HOST" >&2
    exit 1
fi
cargo fmt --all -- --check
case "${1:-baseline}" in
    baseline)
        python3 --version
        python3 scripts/test-evidence-bundle.py -v
        python3 fixtures/mvp/macos-trace/test_read_capability.py -v
        python3 fixtures/mvp/macos-trace/test_observe_open.py -v
        python3 fixtures/mvp/macos-trace/syscall-contract/test_syscall_contract.py -v
        python3 fixtures/mvp/macos-trace/call-pairing/test_pair_calls.py -v
        python3 fixtures/mvp/macos-trace/tree-open/test_observe_tree_open.py -v
        python3 fixtures/mvp/macos-trace/mach-msg2/test_observe_msg2.py -v
        # Native SDK/signature controls keep their separate target receipts.
        python3 fixtures/mvp/macos-trace/open-intent/test_open_intent.py OpenIntentUnits -v
        python3 fixtures/mvp/macos-trace/state-units/test_state_machine.py -v
        cargo test --workspace --locked
        cargo clippy --workspace --all-targets --locked -- -D warnings
        ;;
    lua55)
        cargo test -p glue-runtime-lua --no-default-features --features lua55 --locked
        cargo test -p glue-runner --no-default-features --features lua55 --locked
        cargo clippy -p glue-runner -p glue-runtime-lua --no-default-features --features lua55 --all-targets --locked -- -D warnings
        ;;
    packaging)
        cargo test -p glue-pack --features python --locked
        cargo test -p glue-runner --features python-pack --locked
        cargo clippy -p glue-pack -p glue-runner --features python-pack --all-targets --locked -- -D warnings
        ;;
    *) echo 'usage: scripts/ci-portable.sh [baseline|lua55|packaging]' >&2; exit 2 ;;
esac
# Target-gated historical fixture tests still need their own execution receipts.
echo "portable $host suite ${1:-baseline} passed; product trace/signing/version gates are separate"
