#!/bin/sh
set -eu
export PATH=/Users/johannes.blaschke/.rustup/toolchains/1.88.0-aarch64-apple-darwin/bin:$PATH
sh fixtures/python-host-imports/run-linux.sh target/python-extensions-host-import-regression-capture target/python-extensions-host-import-regression-build
sh fixtures/python-imports/run-linux.sh target/python-extensions-bundled-regression-capture target/python-extensions-bundled-regression-build
sh fixtures/python-bootstrap/run-linux.sh target/python-extensions-frozen-regression-capture target/python-extensions-frozen-regression-build
sh fixtures/python-host/run-linux.sh target/python-extensions-host-regression-capture target/python-extensions-host-regression-build
