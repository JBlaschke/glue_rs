#!/usr/bin/env python3
"""Retain six clean source-app captures AFTER the independently owned legacy42.

Run from the repository root only after all48 captures/workspace checks finish:
  python3 -B target/python-source-apps-retain.py SOURCE_COMMIT
The only permitted preexisting output is the legacy helper's regressions tree.
This helper records identities for large artifacts; it does not copy them.
"""
import gzip
import hashlib
import importlib.util
import json
from pathlib import Path
import re
import shutil
import struct
import subprocess
import sys
import zipfile

REPO = Path.cwd().resolve()
OUT = REPO / 'docs/evidence/pbs-linux-arm64-python-source-apps-2026-10-12'
CAPTURE = REPO / 'target/python-source-apps-final-capture'
BUILD = REPO / 'target/python-source-apps-final-build'
CHECKS = REPO / 'target/python-source-app-checks'
EXPECTED_COMMIT = 'd3ddac33e41bd681668ce0565c3830e46105ebf5'


def require(condition, message):
    if not condition:
        raise ValueError(message)


def sha(data):
    return hashlib.sha256(data).hexdigest()


def identity(path):
    with path.open('rb') as stream:
        digest = hashlib.file_digest(stream, 'sha256').hexdigest()
    return {'file': path.name, 'size': path.stat().st_size, 'sha256': digest}


def save(path, data):
    path.write_text(json.dumps(data, indent=2, sort_keys=True) + '\n')


def clean_receipt(capture, modes):
    require((capture / 'source-revision.txt').read_text().strip() == EXPECTED_COMMIT, 'capture revision differs: ' + str(capture))
    require((capture / 'source-status.txt').read_bytes() == (capture / 'source-diff.patch').read_bytes() == b'', 'dirty capture: ' + str(capture))
    require({path.name.removesuffix('.trace.txt') for path in capture.glob('*.trace.txt')} == set(modes), 'trace inventory differs: ' + str(capture))
    for mode in modes:
        require((capture / (mode + '.trace-check.txt')).read_text().startswith('Trace checks passed:'), 'missing successful live replay: ' + mode)


def main():
    require(len(sys.argv) == 2 and sys.argv[1] == EXPECTED_COMMIT, 'supply the complete reviewed checkpoint')
    require((REPO / 'scripts/check-linux-python-source-app-trace.py').is_file(), 'run from repository root')
    commit = subprocess.check_output(['git', 'rev-parse', 'HEAD'], cwd=REPO, text=True).strip()
    branch = subprocess.check_output(['git', 'branch', '--show-current'], cwd=REPO, text=True).strip()
    require(commit == EXPECTED_COMMIT, 'current source differs from capture checkpoint')
    require(OUT.is_dir() and {path.name for path in OUT.iterdir()} == {'regressions'}, 'legacy child must create only the known regressions subtree first')
    require(not (OUT / 'regressions').is_symlink(), 'legacy subtree must not be a symlink')
    allowed = (OUT / 'regressions').relative_to(REPO).as_posix() + '/'
    status = subprocess.check_output(['git', 'status', '--porcelain', '--untracked-files=all'], cwd=REPO, text=True)
    require(all(line.startswith('?? ' + allowed) for line in status.splitlines()), 'source is dirty outside the known retained legacy subtree')
    spec = importlib.util.spec_from_file_location('source_retention_policy', REPO / 'scripts/check-linux-python-source-app-trace.py')
    policy = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(policy)
    legacy = [('runner', ('bundled-imports','host-imports','bundled-archived','bundled-host','host-archived','host-host','corrupt-native','missing-host-image','wrong-host-image')),
              ('native', ('bundled-archived','bundled-host','host-archived','host-host','bundled-archived-app-error','bundled-host-app-error','host-archived-app-error','host-host-app-error','corrupt-native','missing-host-image','wrong-host-image')),
              ('host-import', ('success','app-error','corrupt-source','wrong-library','wrong-import-source','missing-import-source','cached-import-bytecode')),
              ('bundled', ('success','app-error','corrupt-source')), ('frozen', ('success','missing-encodings','bad-bytecode','app-error')),
              ('host', ('success','wrong-library','wrong-stdlib','missing-encodings','symlink-stdlib','missing-library','cached-bytecode','app-error'))]
    for name, modes in legacy:
        clean_receipt(REPO / ('target/python-source-apps-' + name + '-regression-capture'), modes)
    clean_receipt(CAPTURE, policy.MODES)
    require((CAPTURE / 'development-opt-in.txt').read_bytes() == b'false\n', 'source capture used development opt-in')
    require((CAPTURE / 'commands.sh').read_bytes() == subprocess.check_output(['git', 'show', commit + ':fixtures/python-source-apps/run-linux.sh'], cwd=REPO), 'capture command differs from source')
    control = json.loads((CAPTURE / 'control-audit.json').read_text())
    require(control['source_clean'] and control['source_revision'] == commit and control['counts']['controls'] == 34 and not control['findings'], 'clean34-control audit is missing')
    actual_audit = json.loads((CHECKS / 'product-trace-audit.json').read_text())
    require(actual_audit['capture_revision'] == actual_audit['repository_revision'] == commit and actual_audit['passed'] and actual_audit['baseline_count'] == 6 and actual_audit['rejected_count'] == actual_audit['mutation_count'] == 198, 'clean hostile audit is missing')
    replay_statuses = list((OUT / 'regressions').rglob('*.compressed-trace-check.exit-status.txt'))
    require(len(list((OUT / 'regressions').rglob('*.trace.txt.gz'))) == len(replay_statuses) == 42 and all(path.read_bytes() == b'0\n' for path in replay_statuses), 'legacy42 replay retention is incomplete')
    source = BUILD / 'relocated Python source apps'
    for line in (CAPTURE / 'artifacts.sha256').read_text().splitlines():
        digest, recorded = line.split('  ', 1)
        require(recorded.startswith('/build-target/') and re.fullmatch('[0-9a-f]{64}', digest) is not None, 'artifact receipt shape differs')
        actual_path = BUILD / recorded.removeprefix('/build-target/')
        require(actual_path.is_file() and not actual_path.is_symlink() and identity(actual_path)['sha256'] == digest, 'captured artifact identity differs: ' + recorded)
    records, manifests, content = {}, {}, {}
    for mode in policy.MODES:
        archive = source / (mode + '.glue')
        records[mode] = policy.archive_record(archive, mode)
        require(records[mode] == policy.retained_metadata(CAPTURE / 'source-metadata.json', mode, archive.stat().st_size), 'archive metadata mismatch: ' + mode)
        with archive.open('rb') as stream:
            locator = stream.read(64)
            raw = stream.read(struct.unpack_from('<Q', locator, 16)[0])
        manifests[mode] = raw
        manifest = json.loads(raw)
        # The corrupt archive differs only at one stored byte, checked below.
        # Verify the complete CRC/content inventory of all five pristine apps.
        if mode != 'corrupt-source':
            with zipfile.ZipFile(archive) as members:
                for key, item in manifest['resources'].items():
                    payload = members.read(key)
                    require(len(payload) == item['size'] and sha(payload) == item['sha256'], 'resource identity mismatch: ' + mode + '/' + key)
        content[mode] = {'resources': len(manifest['resources']), 'uncompressed_bytes': sum(item['size'] for item in manifest['resources'].values())}
    require(manifests['minimal'] == manifests['corrupt-source'], 'CRC control changes manifest')
    selected_offset = records['corrupt-source']['corrupt_offset']
    changed = []
    with (source / 'minimal.glue').open('rb') as good, (source / 'corrupt-source.glue').open('rb') as bad:
        position = 0
        while block := good.read(1024 * 1024):
            other = bad.read(len(block))
            require(len(other) == len(block), 'corrupt archive length differs')
            if block != other:
                changed.extend(position + index for index, pair in enumerate(zip(block, other)) if pair[0] != pair[1])
                require(len(changed) <= 1, 'corrupt control modifies more than one byte')
            position += len(block)
        require(not bad.read(1) and changed == [selected_offset], 'corrupt control differs outside selected source')
    corruption = json.loads((CAPTURE / 'corruption.json').read_text())
    require(corruption['original_sha256'] == records['minimal']['sha256'] and corruption['corrupt_sha256'] == records['corrupt-source']['sha256'] and corruption['only_changed_archive_byte'] == selected_offset, 'corruption receipt differs')
    frozen = identity(CAPTURE / 'freeze-bundle.json')
    require(frozen['size'] == 139523 and frozen['sha256'] == '6a41fc38141d45c5197adfc1b0ee740c6244ea681742c205b8aa7b8449d865d7', 'compiled frozen bundle identity differs')
    elf = (CAPTURE / 'launcher.elf.txt').read_text()
    require('[...]' not in elf and re.findall(r'Shared library: \[([^]]+)\]', elf) == ['libm.so.6','libgcc_s.so.1','libc.so.6'] and not re.search(r'\bUND[ \t]+(?:Py|_Py)', elf), 'launcher ELF dependency/undefined-symbol mismatch')
    api_source = subprocess.check_output(['git','show',commit + ':crates/glue-runtime-python/src/linux.rs'], cwd=REPO, text=True)
    require('std::mem::size_of::<Api>() == 240' in api_source, 'selected API table size assertion differs')
    require(len(control['provenance']) == 8, 'C provenance inventory differs')
    # All preconditions and full resource checks finish before top-level output.
    for path in CAPTURE.rglob('*'):
        require(not path.is_symlink(), 'capture contains a symlink')
        if path.is_file() and not path.name.endswith('.trace.txt'):
            target = OUT / path.relative_to(CAPTURE)
            target.parent.mkdir(parents=True, exist_ok=True)
            shutil.copyfile(path, target)
    traces = {}
    replay_commands = []
    for mode in policy.MODES:
        raw = (CAPTURE / (mode + '.trace.txt')).read_bytes()
        packed = gzip.compress(raw, compresslevel=9, mtime=0)
        require(packed[4:8] == b'\0' * 4 and gzip.decompress(packed) == raw, 'gzip timestamp/content differs')
        path = OUT / (mode + '.trace.txt.gz')
        path.write_bytes(packed)
        traces[mode] = {'raw_bytes':len(raw), 'raw_sha256':sha(raw), 'gzip_bytes':len(packed), 'gzip_sha256':sha(packed), 'records':len(raw.splitlines()), 'pids':sorted(set(int(pid) for pid in re.findall(rb'^([0-9]+)\s',raw,re.M)))}
        command = [sys.executable, '-B', str(REPO / 'scripts/check-linux-python-source-app-trace.py'), str(path), '--mode', mode,
                   '--stdout-file', str(OUT / (mode + '.stdout.txt')), '--stderr-file', str(OUT / (mode + '.stderr.txt')),
                   '--metadata-file', str(OUT / 'source-metadata.json'), '--archive-bytes', str(records[mode]['bytes'])]
        result = subprocess.run(command, cwd=REPO, capture_output=True)
        (OUT / (mode + '.compressed-trace-check.txt')).write_bytes(result.stdout + result.stderr)
        (OUT / (mode + '.compressed-trace-check.exit-status.txt')).write_text(str(result.returncode) + '\n')
        require(result.returncode == 0, 'compressed replay failed: ' + result.stderr.decode())
        replay_commands.append(command)
        (OUT / (mode + '.manifest.json')).write_bytes(manifests[mode])
    validation = OUT / 'validation'
    validation.mkdir()
    for name, source_path in [('retain-source-apps.py',Path(__file__)), ('product-control-audit.py',REPO / 'target/python-source-apps-control-audit.py'), ('product-control-audit-commands.sh',REPO / 'target/python-source-apps-control-audit-commands.sh'),
                              ('product-trace-audit.py',CHECKS / 'product-trace-audit.py'), ('product-trace-audit.json',CHECKS / 'product-trace-audit.json'), ('product-trace-audit.commands.txt',CHECKS / 'product-trace-audit.commands.txt')]:
        shutil.copyfile(source_path, validation / name)
    save(validation / 'compressed-replay-commands.json', replay_commands)
    for source_path, name in [('fixtures/python-pbs/pins.json','pins.json'),('fixtures/python-bootstrap/header-pins.json','header-pins.json'),('fixtures/python-imports/stdlib-pins.json','stdlib-pins.json')]:
        shutil.copyfile(REPO / source_path, OUT / name)
    pins = json.loads((OUT / 'stdlib-pins.json').read_text())
    summary = {'source_commit':commit, 'source_clean':True, 'source_branch':{'value':branch,'receipt':'source-branch.txt','recorded_at':'capture'},
               'image_id':'62812c4a0e15bc750ddd6ec68d2a19f8815a14b60d520e201a911e2e29f40abe', 'target_triple':'aarch64-unknown-linux-gnu',
               'launcher':identity(source / 'glue'), 'archives':{mode:{'file':mode + '.glue','size':record['bytes'],'sha256':record['sha256']} for mode,record in records.items()},
               'applications':{mode:{'app_id':record['app_id'],'component':record['component'],'entry':record['entry'],'resources':record['application'],'resource_count':len(record['application']),'bytes':sum(item['size'] for item in record['application'].values())} for mode,record in records.items()},
               'content':content, 'source_projection':{'files':len(pins['files']),'uncompressed_bytes':sum(item['size'] for item in pins['files'].values()),'inventory':identity(OUT / 'stdlib-pins.json')},
               'frozen_bundle':identity(OUT / 'freeze-bundle.json'), 'api':{'revision':4,'public_exports':29,'table_bytes':240,'provenance_receipts':4},
               'corrupt_source':{'key':policy.CORRUPT_KEY,'data_offset':selected_offset,'size':len(policy.CORRUPT_BYTES),'only_changed_archive_byte':selected_offset,
                                'original_member_sha256':policy.expected_application('minimal')[policy.CORRUPT_KEY]['sha256'],'corrupt_member_sha256':sha(policy.CORRUPT_BYTES),
                                'original_archive_sha256':records['minimal']['sha256'],'corrupt_archive_sha256':records['corrupt-source']['sha256']},
               'statuses':{mode:0 if mode in ('minimal','resources') else 1 for mode in policy.MODES}, 'stdout_bytes':{mode:len(policy.expected_output(mode)[0]) for mode in policy.MODES},
               'trace_write_scope':'Complete requested/returned stock image byte counts and exact visible256-byte ELF prefixes plus seals; s256 does not retain all write payload bytes. Full input/library hashes are separately verified.',
               'controls':34,'hostile_actual_mutations':198}
    save(OUT / 'fixture-summary.json',summary)
    save(OUT / 'trace-summary.json',traces)
    legacy_summary = json.loads((OUT / 'regressions/capture-summary.json').read_text())
    save(OUT / 'capture-summary.json',{'sourceapps':summary,'regressions':legacy_summary})
    source_lines = []
    for entry in subprocess.check_output(['git','ls-tree','-r','-z',commit],cwd=REPO).split(b'\0'):
        if not entry:
            continue
        meta, name = entry.split(b'\t',1)
        fields = meta.split()
        path = name.decode()
        if fields[1] != b'blob' or path.startswith('docs/evidence/'):
            continue
        payload = subprocess.check_output(['git','cat-file','blob',fields[2].decode()],cwd=REPO)
        source_lines.append(sha(payload) + '  ' + path)
    (OUT / 'source.sha256').write_text('\n'.join(source_lines) + '\n')
    require((OUT / 'source.sha256').read_bytes() == (OUT / 'regressions/source.sha256').read_bytes(), 'top and legacy source inventories differ')
    checksums = [identity(path)['sha256'] + '  ' + path.relative_to(OUT).as_posix() for path in sorted(OUT.rglob('*')) if path.is_file() and path != OUT / 'SHA256SUMS']
    (OUT / 'SHA256SUMS').write_text('\n'.join(checksums) + '\n')
    print(json.dumps({'source_commit':commit,'source_traces':6,'legacy_traces':42,'all_compressed_replays':48,'controls':34,'hostile_mutations':198,'source_files':len(source_lines),'retained_files_before_root_README':len(checksums)+1,'output':str(OUT)},indent=2))


if __name__ == '__main__':
    main()
