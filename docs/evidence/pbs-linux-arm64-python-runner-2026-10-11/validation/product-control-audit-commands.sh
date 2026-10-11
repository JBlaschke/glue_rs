#!/bin/sh
set -eu
podman run --rm --network none --read-only --cap-drop ALL --security-opt no-new-privileges \
  --mount 'type=bind,source=/Users/johannes.blaschke/Developer/glue_rs/target/python-runner-final-build/relocated Python runner,destination=/inputs,readonly' \
  62812c4a0e15bc750ddd6ec68d2a19f8815a14b60d520e201a911e2e29f40abe \
  readelf -W -d --dyn-syms /inputs/glue \
  > target/python-runner-final-capture/launcher-wide.elf.txt
python3 target/python-runner-control-audit.py \
  --capture target/python-runner-final-capture --build target/python-runner-final-build \
  --source-revision 32a9562c6e0e60da458e874d29c0e1bd17af098b \
  --wide-elf target/python-runner-final-capture/launcher-wide.elf.txt \
  --output target/python-runner-final-capture/control-audit.json
