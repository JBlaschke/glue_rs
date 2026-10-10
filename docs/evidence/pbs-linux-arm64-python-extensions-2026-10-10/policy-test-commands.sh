#!/bin/sh
set -eu
python3 -m unittest discover -s scripts -p 'test_*.py' > target/python-extensions-checks/mac-python-policy-tests.txt 2>&1
python3 -m unittest discover -s scripts -p 'test_linux_python_extension_trace.py' > target/python-extensions-checks/mac-extension-policy-tests.txt 2>&1
python3 fixtures/python-imports/test_importer.py > target/python-extensions-checks/mac-importer-protocol-tests.txt 2>&1
podman run --rm --network none --read-only --tmpfs /tmp:rw,size=256m \
    --mount type=bind,source=/Users/johannes.blaschke/Developer/glue_rs,destination=/workspace,ro \
    --mount type=bind,source=/Users/johannes.blaschke/Developer/glue_rs/target/python-extensions-checks,destination=/evidence \
    --workdir /workspace 62812c4a0e15bc750ddd6ec68d2a19f8815a14b60d520e201a911e2e29f40abe sh -c '
python=/workspace/target/python-bootstrap-development/producer/bin/python3.13
"$python" -I -S -B -m unittest discover -s scripts -p "test_*.py" > /evidence/linux-python-policy-tests.txt 2>&1
"$python" -I -S -B fixtures/python-imports/test_importer.py > /evidence/linux-importer-protocol-tests.txt 2>&1'
