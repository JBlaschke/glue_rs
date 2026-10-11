#!/bin/sh
set -eu
export PATH=/Users/johannes.blaschke/.rustup/toolchains/1.88.0-aarch64-apple-darwin/bin:$PATH
sh fixtures/python-runner/run-linux.sh target/python-runner-final-capture target/python-runner-final-build
sh fixtures/python-extensions/run-linux.sh target/python-runner-native-regression-capture target/python-runner-native-regression-build
sh fixtures/python-host-imports/run-linux.sh target/python-runner-host-import-regression-capture target/python-runner-host-import-regression-build
sh fixtures/python-imports/run-linux.sh target/python-runner-bundled-regression-capture target/python-runner-bundled-regression-build
sh fixtures/python-bootstrap/run-linux.sh target/python-runner-frozen-regression-capture target/python-runner-frozen-regression-build
sh fixtures/python-host/run-linux.sh target/python-runner-host-regression-capture target/python-runner-host-regression-build
