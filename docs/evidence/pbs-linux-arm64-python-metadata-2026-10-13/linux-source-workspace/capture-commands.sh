#!/bin/sh
set -eu
metadata_repo=/Users/johannes.blaschke/Developer/glue_rs
metadata_expected=80c4b33698d7f9c6caa54f8c8afcc69ff6faa2ee
metadata_logs="$metadata_repo/target/python-metadata-source-workspace-linux"
metadata_image=62812c4a0e15bc750ddd6ec68d2a19f8815a14b60d520e201a911e2e29f40abe
cd "$metadata_repo"
test "$(git rev-parse HEAD)" = "$metadata_expected"
test -z "$(git status --porcelain)"
git rev-parse HEAD > "$metadata_logs/source-revision.txt"
git branch --show-current > "$metadata_logs/source-branch.txt"
git status --porcelain > "$metadata_logs/source-status.txt"
podman image inspect "$metadata_image" > "$metadata_logs/linux-image-inspect.json"
podman run --rm --pull=never --network none --read-only --tmpfs /tmp:rw,size=256m \
    --mount "type=bind,source=$metadata_repo,destination=/workspace,ro" \
    --mount "type=bind,source=$metadata_logs,destination=/evidence" \
    --mount "type=bind,source=$metadata_logs/build-target,destination=/build-target" \
    --workdir /workspace "$metadata_image" sh /evidence/linux-workspace-commands.sh \
    > "$metadata_logs/linux-workspace-console.txt" 2>&1
metadata_status=$?
printf '%s\n' "$metadata_status" > "$metadata_logs/linux-workspace-exit-status.txt"
git rev-parse HEAD > "$metadata_logs/final-source-revision.txt"
git status --porcelain > "$metadata_logs/final-source-status.txt"
test ! -s "$metadata_logs/final-source-status.txt"
test "$(git rev-parse HEAD)" = "$metadata_expected"
