#!/bin/sh
set -eu
export PATH=/Users/johannes.blaschke/.rustup/toolchains/1.88.0-aarch64-apple-darwin/bin:$PATH
cargo vendor --locked --offline target/vendor > target/python-runner-checks/linux-vendor-config.toml 2> target/python-runner-checks/linux-vendor.stderr.txt
mkdir -p target/python-runner-workspace-build
podman run --rm --network none --read-only --tmpfs /tmp:rw,size=256m \
  --mount type=bind,source=/Users/johannes.blaschke/Developer/glue_rs,destination=/workspace,ro \
  --mount type=bind,source=/Users/johannes.blaschke/Developer/glue_rs/target/python-runner-workspace-build,destination=/build-target \
  --mount type=bind,source=/Users/johannes.blaschke/Developer/glue_rs/target/python-runner-checks,destination=/evidence \
  --mount type=bind,source=/private/tmp/glue-python-runner-linux-workspace.sh,destination=/commands.sh,ro \
  --workdir /workspace 62812c4a0e15bc750ddd6ec68d2a19f8815a14b60d520e201a911e2e29f40abe sh /commands.sh
