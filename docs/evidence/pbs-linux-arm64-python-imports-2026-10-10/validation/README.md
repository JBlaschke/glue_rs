# Supplemental validation

These logs were collected while assembling the implementation. The three
separate fixture captures retain fresh clean-commit GNU release tests and Clippy.
Source workspaces use Rust 1.88.0; Mac Python protocol tests use the interpreter
identified in `mac-environment.txt`. `linux-importer-tests.txt` uses the exact
stock producer independently provisioned from the pinned PBS input, not a system
Python. These fake-callback tests are separate from the actual import traces.

Mac workspace commands, with the recorded Rust toolchain first on PATH:

```sh
cargo test --workspace --locked
cargo clippy --workspace --all-targets --locked -- -D warnings
cargo test --workspace --locked --no-default-features --features glue-runner/lua55
cargo clippy --workspace --all-targets --locked --no-default-features --features glue-runner/lua55 -- -D warnings
cargo test --locked -p glue-python-bootstrap-probe
cargo build --locked -p glue-python-bootstrap-probe --features pbs-bootstrap
target/debug/glue-python-bootstrap-probe run-imports /missing-import-fixture.glue
python3 fixtures/python-imports/test_importer.py
python3 -m unittest discover -s scripts -p 'test_*.py' -v
```

The missing-archive execution returns status 2 before opening it. Its stdout,
stderr and status are retained. The other checks above pass.

The Linux workspace checks run offline in the immutable image with read-only
workspace input and temporary Cargo/build directories; see the parent's
`linux-workspace-commands.sh`. Supplemental Linux opt-in checks use the same image,
absolute vendored dependencies and pinned installed headers:

```sh
cargo test --locked --offline --release -p glue-python-bootstrap-probe --features pbs-bootstrap
cargo clippy --locked --offline --release --all-targets -p glue-python-bootstrap-probe --features pbs-bootstrap -- -D warnings
/producer/bin/python3.13 -I -S -B /fixture/test_importer.py
```

The last command runs with the independently provisioned producer and fixture
mounted read-only at `/producer` and `/fixture`, respectively. No network is used.
