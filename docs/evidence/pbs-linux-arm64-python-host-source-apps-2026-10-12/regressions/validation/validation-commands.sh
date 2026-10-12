#!/bin/sh
# Wait for the source owner's clean checkpoint before running this script.
# Usage: sh /private/tmp/glue-python-host-source-app-validation.sh SOURCE_COMMIT [--resume]
set -eu
hostsourceapp_repo=/Users/johannes.blaschke/Developer/glue_rs
hostsourceapp_checks="$hostsourceapp_repo/target/python-host-source-app-checks"
hostsourceapp_linux_build="$hostsourceapp_repo/target/python-host-source-app-workspace-build"
hostsourceapp_image=62812c4a0e15bc750ddd6ec68d2a19f8815a14b60d520e201a911e2e29f40abe
hostsourceapp_expected=${1:?supply the committed clean implementation checkpoint}
cd "$hostsourceapp_repo"
test "$(git rev-parse HEAD)" = "$hostsourceapp_expected"
test -z "$(git status --porcelain)"
test -d target/vendor
test -f scripts/test_linux_python_host_source_app_trace.py
test -f fixtures/python-host-source-apps/test_protocol.py
test -f target/python-bootstrap-development/producer/bin/python3.13
if test -e "$hostsourceapp_checks"; then test "${2:-}" = --resume; fi
sh /private/tmp/glue-python-host-source-app-mac-checks.sh "$hostsourceapp_checks" "${2:-}"
cp "$0" "$hostsourceapp_checks/validation-commands.sh"
cp /private/tmp/glue-python-host-source-app-linux-workspace.sh "$hostsourceapp_checks/linux-workspace-commands.sh"
cp /private/tmp/glue-python-host-source-app-policy-checks.sh "$hostsourceapp_checks/linux-policy-commands.sh"
python3 -I -S -B - <<'PY' > "$hostsourceapp_checks/stock-protocol-producer-identity.json"
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
assert len(sources)==1037,('cached producer source count differs',len(sources))
print(json.dumps({'schema_version':0,'files':files,'present_stock_sources':sources,
                  'source_inventory_sha256':hashlib.sha256(inventory.read_bytes()).hexdigest(),
                  'note':'Existing cached install-only producer, with every present .py independently checked against the full pinned inventory. Protocol commands direct bytecode cache lookup to an unavailable prefix and disable writes; the producer tree is never modified.'},indent=2,sort_keys=True))
PY
if test -e "$hostsourceapp_linux_build"; then
    test "${2:-}" = --resume
else
    mkdir -p "$hostsourceapp_linux_build"
fi
podman image inspect "$hostsourceapp_image" > "$hostsourceapp_checks/linux-image-inspect.json"
podman run --rm --network none --read-only --tmpfs /tmp:rw,size=256m \
    --mount "type=bind,source=$hostsourceapp_repo,destination=/workspace,ro" \
    --mount "type=bind,source=$hostsourceapp_checks,destination=/evidence" \
    --mount "type=bind,source=$hostsourceapp_linux_build,destination=/build-target" \
    --mount type=bind,source=/private/tmp/glue-python-host-source-app-linux-workspace.sh,destination=/commands.sh,ro \
    --workdir /workspace "$hostsourceapp_image" sh /commands.sh \
    > "$hostsourceapp_checks/linux-workspace-console.txt" 2>&1
podman run --rm --network none --read-only --tmpfs /tmp:rw,size=256m \
    --mount "type=bind,source=$hostsourceapp_repo,destination=/workspace,ro" \
    --mount "type=bind,source=$hostsourceapp_checks,destination=/evidence" \
    --mount type=bind,source=/private/tmp/glue-python-host-source-app-policy-checks.sh,destination=/commands.sh,ro \
    --workdir /workspace "$hostsourceapp_image" sh /commands.sh \
    > "$hostsourceapp_checks/linux-policy-console.txt" 2>&1
git status --porcelain > "$hostsourceapp_checks/final-source-status.txt"
test ! -s "$hostsourceapp_checks/final-source-status.txt"
test "$(git rev-parse HEAD)" = "$hostsourceapp_expected"
python3 -I -S -B - "$hostsourceapp_checks" <<'PY_SUMMARY'
import json,re,sys
from pathlib import Path
logs=Path(sys.argv[1])
summary={}
for name in ('lua54','lua55','python-pbs','linux-lua54','linux-lua55'):
    output=(logs/(name+'-tests.txt')).read_text()
    results=re.findall(r'test result: ok\. (\d+) passed;',output)
    assert results,('missing Rust test results',name)
    summary[name]={'tests':sum(map(int,results)),'clippy':'pass'}
for name in ('policy-tests','importer-tests','entry-tests','host-protocol-tests',
             'linux-python-policy-tests','linux-importer-protocol-tests',
             'linux-entry-protocol-tests','linux-host-protocol-tests'):
    output=(logs/(name+'.txt')).read_text()
    result=re.search(r'Ran (\d+) tests?',output)
    assert result and re.search(r'^OK(?: \(skipped=\d+\))?$',output,re.M),('missing Python success',name)
    summary[name]=int(result.group(1))
    skipped=re.search(r'^OK \(skipped=(\d+)\)$',output,re.M)
    if skipped: summary[name+'-skipped']=int(skipped.group(1))
summary['source_commit']=(logs/'source-revision.txt').read_text().strip()
summary['source_branch']=(logs/'source-branch.txt').read_text().strip()
summary['source_clean_before_after']=not ((logs/'source-status.txt').read_text().strip() or (logs/'final-source-status.txt').read_text().strip())
assert summary['source_clean_before_after']
summary['linux_python']=(logs/'linux-python-environment.txt').read_text().strip()
(logs/'validation-summary.json').write_text(json.dumps(summary,sort_keys=True,indent=2)+'\n')
PY_SUMMARY
printf 'Clean Mac/GNU host-source-app validation passed: %s\n' "$hostsourceapp_checks"
