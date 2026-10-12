#!/bin/sh
# Wait for the source owner's clean checkpoint before running this script.
# Usage: sh /private/tmp/glue-python-source-app-validation.sh SOURCE_COMMIT [--resume]
set -eu
sourceapp_repo=/Users/johannes.blaschke/Developer/glue_rs
sourceapp_checks="$sourceapp_repo/target/python-source-app-checks"
sourceapp_linux_build="$sourceapp_repo/target/python-source-app-workspace-build"
sourceapp_image=62812c4a0e15bc750ddd6ec68d2a19f8815a14b60d520e201a911e2e29f40abe
sourceapp_expected=${1:?supply the committed clean implementation checkpoint}
cd "$sourceapp_repo"
test "$(git rev-parse HEAD)" = "$sourceapp_expected"
test -z "$(git status --porcelain)"
test -d target/vendor
test -f scripts/test_linux_python_source_app_trace.py
test -f target/python-bootstrap-development/producer/bin/python3.13
if test -e "$sourceapp_checks"; then test "${2:-}" = --resume; fi
sh /private/tmp/glue-python-source-app-mac-checks.sh "$sourceapp_checks" "${2:-}"
cp "$0" "$sourceapp_checks/validation-commands.sh"
cp /private/tmp/glue-python-source-app-linux-workspace.sh "$sourceapp_checks/linux-workspace-commands.sh"
cp /private/tmp/glue-python-source-app-policy-checks.sh "$sourceapp_checks/linux-policy-commands.sh"
python3 -I -S -B - <<'PY' > "$sourceapp_checks/stock-protocol-producer-identity.json"
import hashlib,json
from pathlib import Path
root=Path.cwd()
prefix=root/'target/python-bootstrap-development/producer'
expected={
    'bin/python3.13':(73325136,'1abe8738dd82558ba7884a0dd00bb8e9561ad0b85a3ddd3d755999c2dd878d45'),
    'lib/libpython3.13.so.1.0':(73563968,'42be968275d5be2d9e632ec9ef6790dd2c10f1d4a710ad1028fc2b687242f219'),
}
files={}
for name,(size,digest) in expected.items():
    path=prefix/name
    with path.open('rb') as stream: actual=hashlib.file_digest(stream,'sha256').hexdigest()
    assert path.stat().st_size==size and actual==digest,name
    files[name]={'size':size,'sha256':actual}
inventory=root/'fixtures/python-imports/stdlib-pins.json'
pins=json.loads(inventory.read_text())['files']
stdlib=prefix/'lib/python3.13'
sources={}
for path in sorted(stdlib.rglob('*.py')):
    name=path.relative_to(stdlib).as_posix()
    with path.open('rb') as stream: digest=hashlib.file_digest(stream,'sha256').hexdigest()
    assert name in pins and path.stat().st_size==pins[name]['size'] and digest==pins[name]['sha256'],name
    sources[name]={'size':path.stat().st_size,'sha256':digest}
assert sources
print(json.dumps({'schema_version':0,'files':files,'present_stock_sources':sources,
                  'source_inventory_sha256':hashlib.sha256(inventory.read_bytes()).hexdigest(),
                  'note':'Existing cached install-only producer, with every present .py independently checked against the full pinned inventory. Protocol commands direct bytecode cache lookup to an unavailable prefix and disable writes; the producer tree is never modified.'},indent=2,sort_keys=True))
PY
if test -e "$sourceapp_linux_build"; then
    test "${2:-}" = --resume
else
    mkdir -p "$sourceapp_linux_build"
fi
podman image inspect "$sourceapp_image" > "$sourceapp_checks/linux-image-inspect.json"
podman run --rm --network none --read-only --tmpfs /tmp:rw,size=256m \
    --mount "type=bind,source=$sourceapp_repo,destination=/workspace,ro" \
    --mount "type=bind,source=$sourceapp_checks,destination=/evidence" \
    --mount "type=bind,source=$sourceapp_linux_build,destination=/build-target" \
    --mount type=bind,source=/private/tmp/glue-python-source-app-linux-workspace.sh,destination=/commands.sh,ro \
    --workdir /workspace "$sourceapp_image" sh /commands.sh \
    > "$sourceapp_checks/linux-workspace-console.txt" 2>&1
podman run --rm --network none --read-only --tmpfs /tmp:rw,size=256m \
    --mount "type=bind,source=$sourceapp_repo,destination=/workspace,ro" \
    --mount "type=bind,source=$sourceapp_checks,destination=/evidence" \
    --mount type=bind,source=/private/tmp/glue-python-source-app-policy-checks.sh,destination=/commands.sh,ro \
    --workdir /workspace "$sourceapp_image" sh /commands.sh \
    > "$sourceapp_checks/linux-policy-console.txt" 2>&1
git status --porcelain > "$sourceapp_checks/final-source-status.txt"
test ! -s "$sourceapp_checks/final-source-status.txt"
test "$(git rev-parse HEAD)" = "$sourceapp_expected"
printf 'Clean Mac/GNU source-app validation passed: %s\n' "$sourceapp_checks"
