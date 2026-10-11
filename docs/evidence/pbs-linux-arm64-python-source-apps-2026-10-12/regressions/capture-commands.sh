#!/bin/sh
set -eu
export PATH=/Users/johannes.blaschke/.rustup/toolchains/1.88.0-aarch64-apple-darwin/bin:$PATH
sourceapp_expected=${1:?supply clean source commit}
test "$(git rev-parse HEAD)" = "$sourceapp_expected"
test -z "$(git status --porcelain)"
sh fixtures/python-source-apps/run-linux.sh target/python-source-apps-final-capture target/python-source-apps-final-build
sh fixtures/python-runner/run-linux.sh target/python-source-apps-runner-regression-capture target/python-source-apps-runner-regression-build
sh fixtures/python-extensions/run-linux.sh target/python-source-apps-native-regression-capture target/python-source-apps-native-regression-build
sh fixtures/python-host-imports/run-linux.sh target/python-source-apps-host-import-regression-capture target/python-source-apps-host-import-regression-build
sh fixtures/python-imports/run-linux.sh target/python-source-apps-bundled-regression-capture target/python-source-apps-bundled-regression-build
sh fixtures/python-bootstrap/run-linux.sh target/python-source-apps-frozen-regression-capture target/python-source-apps-frozen-regression-build
sh fixtures/python-host/run-linux.sh target/python-source-apps-host-regression-capture target/python-source-apps-host-regression-build
test "$(git rev-parse HEAD)" = "$sourceapp_expected"
test -z "$(git status --porcelain)"
printf 'All clean source-app and historical capture cells passed\n'
