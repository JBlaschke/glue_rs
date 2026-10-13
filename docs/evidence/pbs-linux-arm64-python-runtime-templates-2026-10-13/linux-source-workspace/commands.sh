#!/bin/sh
# Dirty development source workspace check; no clean-capture claim.
podman run --rm --network none --read-only \
  --tmpfs /tmp:rw,size=256m --tmpfs /build-target:rw,size=2g \
  --mount type=bind,source="$PWD",destination=/workspace,ro \
  --mount type=bind,source="$PWD/target/python-template-linux-source-workspace-development",destination=/evidence,rw \
  --workdir /workspace \
  62812c4a0e15bc750ddd6ec68d2a19f8815a14b60d520e201a911e2e29f40abe \
  sh /evidence/container-checks.sh
