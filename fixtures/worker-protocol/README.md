# Synthetic worker protocol fixture

This Rust-only fixture tests the experimental A9 message layer over actual
parent/child anonymous pipes. It does not embed a language runtime or start a
product worker. The `glue` CLI still executes one selected component directly.

Run with the pinned Rust toolchain:

```sh
export PATH="$(rustup run 1.88.0 rustc --print sysroot)/bin:$PATH"
cargo test --locked -p glue-ipc -p glue-worker-protocol-fixture
# On macOS, validate the pinned GNU Linux arm64 cell through Podman:
sh fixtures/worker-protocol/run-linux.sh
```

The test-only `glue-ipc-peer` executable reserves stdin/stdout for protocol bytes
and sends ordinary fixture diagnostics to stderr. Product worker integration
will use private inherited pipes so application stdio remains independent.
The parent-side fixture tests have deadlines and clean up the child on failure.

See [decision 0020](../../docs/decisions/0020-worker-message-protocol.md) for the
wire representation, budgets, connection ordering and remaining A9 work.
