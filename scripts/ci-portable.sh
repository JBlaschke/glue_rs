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
        python3 fixtures/mvp/test_trace_environment.py -v
        python3 fixtures/mvp/test_linux_acceptance.py -v
        python3 fixtures/mvp/python-matrix/test_provision_conda.py -v
        python3 fixtures/mvp/python-matrix/test_prepare.py -v
        python3 fixtures/mvp/macos-trace/test_read_capability.py -v
        python3 fixtures/mvp/macos-trace/test_observe_open.py -v
        python3 fixtures/mvp/macos-trace/syscall-contract/test_syscall_contract.py -v
        python3 fixtures/mvp/macos-trace/call-pairing/test_pair_calls.py -v
        python3 fixtures/mvp/macos-trace/tree-open/test_observe_tree_open.py -v
        python3 fixtures/mvp/macos-trace/tree-open-intent/test_observe_tree_open_intent.py -v
        python3 fixtures/mvp/macos-trace/mach-msg2/test_observe_msg2.py -v
        python3 fixtures/mvp/macos-trace/target-credentials/test_target_credentials.py -v
        python3 fixtures/mvp/macos-trace/target-descriptors/test_target_descriptors.py -v
        python3 fixtures/mvp/macos-trace/target-endpoints/test_target_endpoints.py -v
        python3 fixtures/mvp/macos-trace/bootstrap-wire/test_bootstrap_wire.py -v
        python3 fixtures/mvp/macos-trace/bootstrap-io/test_bootstrap_io.py -v
        python3 fixtures/mvp/macos-trace/bootstrap-io/test_observed_io.py -v
        python3 fixtures/mvp/macos-trace/bootstrap-signals/test_bootstrap_signals.py -v
        python3 fixtures/mvp/macos-trace/bootstrap-request/test_bootstrap_request.py -v
        python3 fixtures/mvp/macos-trace/bootstrap-probe/test_probe_report.py -v
        python3 fixtures/mvp/macos-trace/bootstrap-probe/test_context_probe.py -v
        python3 fixtures/mvp/macos-trace/bootstrap-admission/test_bootstrap_admission.py -v
        python3 fixtures/mvp/macos-trace/bootstrap-inspector/test_inspect_deployment.py -v
        python3 fixtures/mvp/macos-trace/bootstrap-runner/test_bootstrap_runner.py -v
        python3 fixtures/mvp/macos-trace/bootstrap-runner/test_runner_protocol_observed.py -v
        python3 fixtures/mvp/macos-trace/bootstrap-runner/test_owned_trace_parent.py -v
        python3 fixtures/mvp/macos-trace/bootstrap-kit/test_build_kit.py -v
        python3 fixtures/mvp/macos-trace/bootstrap-trace-kit/test_build_kit.py -v
        python3 fixtures/mvp/macos-trace/bootstrap-trace-match-kit/test_build_kit.py -v
        python3 fixtures/mvp/macos-trace/bootstrap-vm/test_prepare.py -v
        python3 fixtures/mvp/macos-trace/bootstrap-vm/test_checker.py -v
        python3 fixtures/mvp/macos-trace/bootstrap-trace-vm/test_prepare.py -v
        python3 fixtures/mvp/macos-trace/bootstrap-trace-vm/test_gates.py -v
        python3 fixtures/mvp/macos-trace/trace-session/test_trace_session.py -v
        python3 fixtures/mvp/macos-trace/owned-trace-backend/test_owned_trace_backend.py -v
        python3 fixtures/mvp/macos-trace/owned-trace-check/test_owned_trace_check.py -v
        python3 fixtures/mvp/macos-trace/bsd-outcomes/test_bsd_outcomes.py -v
        python3 fixtures/mvp/macos-trace/owned-trace-assessment/test_assessment.py -v
        python3 fixtures/mvp/macos-trace/owned-trace-assessment/test_inspect_trace.py -v
        python3 fixtures/mvp/macos-trace/owned-trace-cases/test_owned_trace_cases.py -v
        python3 fixtures/mvp/macos-trace/owned-trace-sim/test_sim_metadata.py -v
        python3 fixtures/mvp/macos-trace/bootstrap-trace-calibration-vm/test_calibration.py -v
        python3 fixtures/mvp/macos-trace/bootstrap-trace-calibration-vm/test_packet_admission.py -v
        python3 fixtures/mvp/macos-trace/bootstrap-retain-kit03/test_prepare.py -v
        # Native SDK/signature controls keep their separate target receipts.
        python3 fixtures/mvp/macos-trace/open-intent/test_open_intent.py OpenIntentUnits -v
        python3 fixtures/mvp/macos-trace/state-units/test_state_machine.py -v
        python3 fixtures/mvp/macos-trace/mapping-units/test_mapping_state.py -v
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
