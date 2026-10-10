#!/bin/sh
set -eu
export PATH=/Users/johannes.blaschke/.rustup/toolchains/1.88.0-aarch64-apple-darwin/bin:$PATH
cargo test --workspace --locked --offline > target/python-extensions-checks/mac-lua54-tests.txt 2>&1
cargo clippy --workspace --all-targets --locked --offline -- -D warnings > target/python-extensions-checks/mac-lua54-clippy.txt 2>&1
cargo test --workspace --locked --offline --no-default-features --features glue-runner/lua55 > target/python-extensions-checks/mac-lua55-tests.txt 2>&1
cargo clippy --workspace --all-targets --locked --offline --no-default-features --features glue-runner/lua55 -- -D warnings > target/python-extensions-checks/mac-lua55-clippy.txt 2>&1
rustc --version > target/python-extensions-checks/mac-environment.txt
python3 --version >> target/python-extensions-checks/mac-environment.txt
python3 -m unittest discover -s scripts -p 'test_*.py' > target/python-extensions-checks/mac-python-policy-tests.txt 2>&1
python3 fixtures/python-imports/test_importer.py > target/python-extensions-checks/mac-importer-protocol-tests.txt 2>&1
