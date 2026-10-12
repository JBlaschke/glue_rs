#!/bin/sh
# Read-only pinned-stock protocol/policy checks; no deployment claim.
set -eu
installhostapp_python=/workspace/target/python-bootstrap-development/producer/bin/python3.13
export PYTHONDONTWRITEBYTECODE=1
export PYTHONPYCACHEPREFIX=/__glue_validation_no_cache__
# The explicit -X option also applies when -I ignores environment variables.
"$installhostapp_python" -I -S -B -X pycache_prefix=/__glue_validation_no_cache__ --version \
    > /evidence/linux-python-environment.txt
"$installhostapp_python" -I -S -B -X pycache_prefix=/__glue_validation_no_cache__ -m unittest discover \
    -s scripts -p 'test_*.py' > /evidence/linux-python-policy-tests.txt 2>&1
"$installhostapp_python" -I -S -B -X pycache_prefix=/__glue_validation_no_cache__ fixtures/python-imports/test_importer.py \
    > /evidence/linux-importer-protocol-tests.txt 2>&1
"$installhostapp_python" -I -S -B -X pycache_prefix=/__glue_validation_no_cache__ fixtures/python-source-apps/test_entry.py \
    > /evidence/linux-entry-protocol-tests.txt 2>&1
"$installhostapp_python" -I -S -B -X pycache_prefix=/__glue_validation_no_cache__ fixtures/python-host-source-apps/test_protocol.py \
    > /evidence/linux-host-protocol-tests.txt 2>&1
