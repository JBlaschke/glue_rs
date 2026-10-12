#!/usr/bin/env python3
"""Retain/replay seven clean historical Python groups (48 complete traces).

Usage: python3 -B /private/tmp/glue-retain-python-host-source-app-regressions.py SOURCE_COMMIT [--output RELATIVE_REGRESSIONS_PATH]
Run only after all seven clean regression captures and host-source-app checks complete.
Retain these regressions before the separately owned thirteen new top-level captures.
The output directory must not exist. README files are supplied separately.
"""
import argparse
import gzip
import hashlib
import json
from pathlib import Path
import re
import shutil
import struct
import subprocess
import sys
import zipfile

repo = Path.cwd().resolve()
assert (repo / 'scripts/check-linux-python-runner-trace.py').is_file(), 'run from the repository root'
parser = argparse.ArgumentParser(description=__doc__)
parser.add_argument('source_commit')
parser.add_argument('--output', default='docs/evidence/pbs-linux-arm64-python-host-source-apps-2026-10-12/regressions')
args = parser.parse_args()
relative = Path(args.output)
assert not relative.is_absolute() and '..' not in relative.parts and relative.parts[:2] == ('docs', 'evidence') and relative.name == 'regressions', 'output must be a repository evidence regressions subtree'
out = repo / relative
commit = subprocess.check_output(['git', 'rev-parse', 'HEAD'], cwd=repo).decode().strip()
branch = subprocess.check_output(['git', 'branch', '--show-current'], cwd=repo).decode().strip()
assert commit == args.source_commit
assert not subprocess.check_output(['git', 'status', '--porcelain'], cwd=repo)
assert not out.exists()
assert (repo / 'target/python-host-source-app-checks').is_dir(), 'workspace/policy/audit checks must be complete'

checks_preflight = repo / 'target/python-host-source-app-checks'
validation_report = json.loads((checks_preflight / 'validation-summary.json').read_text())
assert validation_report['source_commit'] == commit and validation_report['source_clean_before_after'] is True
assert (checks_preflight / 'source-status.txt').read_bytes() == b'' and (checks_preflight / 'final-source-status.txt').read_bytes() == b''
for stem, count in [('bundled-source-control-audit', 34), ('original-product-control-audit', 30)]:
    for suffix in ['.py', '.json', '-commands.sh']:
        assert (checks_preflight / (stem + suffix)).is_file(), 'completed control audit missing: ' + stem + suffix
    report = json.loads((checks_preflight / (stem + '.json')).read_text())
    assert report['source_revision'] == commit and report['source_clean'] is True and report['source_branch'] == branch
    assert report['counts']['controls'] == count and len(report['controls']) == count and report['findings'] == []


def sha(data):
    return hashlib.sha256(data).hexdigest()

def identity(path):
    with path.open('rb') as stream:
        h = hashlib.file_digest(stream, 'sha256').hexdigest()
    return {'file': path.name, 'size': path.stat().st_size, 'sha256': h}

def save_json(path, value):
    path.write_text(json.dumps(value, indent=2) + '\n')

def manifest(path, destination):
    with path.open('rb') as stream:
        locator = stream.read(64)
        assert locator[:8] == b'GLUERS00'
        size = struct.unpack_from('<Q', locator, 16)[0]
        assert 0 < size <= 2 * 1024 * 1024
        raw = stream.read(size)
        assert len(raw) == size and hashlib.sha256(raw).digest() == locator[32:64]
    destination.write_bytes(raw)
    return json.loads(raw)

def copy_capture(capture, destination):
    assert (capture / 'source-revision.txt').read_text().strip() == commit
    assert (capture / 'source-status.txt').read_bytes() == b''
    assert (capture / 'source-diff.patch').read_bytes() == b''
    destination.mkdir(parents=True, exist_ok=True)
    for path in capture.rglob('*'):
        assert not path.is_symlink(), 'capture companions must be regular files/directories'
        if path.is_dir() or path.name.endswith('.trace.txt'):
            continue
        dest = destination / path.relative_to(capture)
        dest.parent.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(path, dest)
    if (capture / 'source-branch.txt').is_file():
        assert (capture / 'source-branch.txt').read_text().strip() == branch
    if not (capture / 'source-branch.txt').is_file():
        (destination / 'source-branch-at-retention.txt').write_text(branch + '\n')
    summary = {}
    for path in sorted(capture.glob('*.trace.txt')):
        raw = path.read_bytes()
        compressed = gzip.compress(raw, compresslevel=9, mtime=0)
        dest = destination / (path.name + '.gz')
        dest.write_bytes(compressed)
        assert gzip.decompress(compressed) == raw
        mode = path.name.removesuffix('.trace.txt')
        summary[mode] = {'raw_bytes': len(raw), 'raw_sha256': sha(raw),
                         'gzip_bytes': len(compressed), 'gzip_sha256': sha(compressed),
                         'records': len(raw.splitlines()),
                         'pids': sorted(set(int(p) for p in re.findall(rb'^([0-9]+)\s', raw, re.M)))}
    save_json(destination / 'trace-summary.json', summary)
    return summary

def replay(destination, checker, archives, offset=None):
    for mode, archive in archives.items():
        args = [sys.executable, '-B', str(repo / 'scripts' / checker),
                str(destination / (mode + '.trace.txt.gz')), '--mode', mode,
                '--stdout-file', str(destination / (mode + '.stdout.txt')),
                '--stderr-file', str(destination / (mode + '.stderr.txt')),
                '--archive-bytes', str(archive['size'])]
        if mode == 'corrupt-source':
            args += ['--corrupt-source-offset', str(offset)]
        result = subprocess.run(args, capture_output=True, cwd=repo)
        (destination / (mode + '.compressed-trace-check.txt')).write_bytes(result.stdout + result.stderr)
        (destination / (mode + '.compressed-trace-check.exit-status.txt')).write_text(str(result.returncode) + '\n')
        assert result.returncode == 0, result.stderr.decode()

image = '62812c4a0e15bc750ddd6ec68d2a19f8815a14b60d520e201a911e2e29f40abe'
cells = ('bundled-archived', 'bundled-host', 'host-archived', 'host-host')
controls = ('corrupt-native', 'missing-host-image', 'wrong-host-image')
product_modes = ('bundled-imports', 'host-imports') + cells + controls
native_modes = cells + tuple(c + '-app-error' for c in cells) + controls
profiles = [
    ('hostimports', out / 'host-import-regression', 'python-host-source-apps-host-import-regression', 'relocated Python host imports',
     {m: ('success.glue' if m == 'app-error' else m + '.glue') for m in
      ('success', 'app-error', 'corrupt-source', 'wrong-library', 'wrong-import-source', 'missing-import-source', 'cached-import-bytecode')},
     'check-linux-python-host-import-trace.py'),
    ('imports', out / 'bundled-import-regression', 'python-host-source-apps-bundled-import-regression', 'relocated Python imports',
     {'success': 'app.glue', 'app-error': 'app.glue', 'corrupt-source': 'corrupt-source.glue'},
     'check-linux-python-import-trace.py'),
    ('frozen', out / 'frozen-regression', 'python-host-source-apps-frozen-regression', 'relocated Python bootstrap',
     {m: 'app.glue' for m in ('success', 'missing-encodings', 'bad-bytecode', 'app-error')},
     'check-linux-python-bootstrap-trace.py'),
    ('host', out / 'host-startup-regression', 'python-host-source-apps-host-startup-regression', 'relocated Python host',
     {m: ('success.glue' if m == 'app-error' else m + '.glue') for m in
      ('success', 'wrong-library', 'wrong-stdlib', 'missing-encodings', 'symlink-stdlib', 'missing-library', 'cached-bytecode', 'app-error')},
     'check-linux-python-host-trace.py'),
]
# Check all acquisition receipts before creating any retained output.
source_modes = ('minimal', 'resources', 'app-error', 'syntax', 'nul', 'corrupt-source')
expected_captures = [('python-host-source-apps-source-regression', source_modes), ('python-host-source-apps-runner-regression', product_modes), ('python-host-source-apps-native-regression', native_modes)] + [
    (prefix, tuple(modes)) for _, _, prefix, _, modes, _ in profiles
]
for prefix, modes in expected_captures:
    capture = repo / 'target' / (prefix + '-capture')
    assert (capture / 'source-revision.txt').read_text().strip() == commit
    assert (capture / 'source-status.txt').read_bytes() == b''
    assert (capture / 'source-diff.patch').read_bytes() == b''
    if (capture / 'source-branch.txt').is_file():
        assert (capture / 'source-branch.txt').read_text().strip() == branch
    assert {p.name.removesuffix('.trace.txt') for p in capture.glob('*.trace.txt')} == set(modes)
    build = repo / 'target' / (prefix + '-build')
    for line in (capture / 'artifacts.sha256').read_text().splitlines():
        recorded_hash, recorded_path = line.split('  ', 1)
        if recorded_path.startswith('/build-target/'):
            actual = build / recorded_path.removeprefix('/build-target/')
        else:
            assert recorded_path.startswith('/evidence/')
            actual = capture / recorded_path.removeprefix('/evidence/')
        assert identity(actual)['sha256'] == recorded_hash, recorded_path
    for mode in modes:
        expected = 0 if mode in {'success', 'minimal', 'resources', 'bundled-imports', 'host-imports', *cells} else 1
        assert int((capture / (mode + '.exit-status.txt')).read_text()) == expected
    images = json.loads((capture / 'image-inspect.json').read_text())
    assert len(images) == 1 and images[0]['Id'].removeprefix('sha256:') == image
out.mkdir(parents=True)
print(f'Retention preconditions passed; output created: {out}', flush=True)
all_summaries = {}


def branch_record(capture):
    if (capture / 'source-branch.txt').is_file():
        return {'value': branch, 'receipt': 'source-branch.txt', 'recorded_at': 'capture'}
    return {'value': branch, 'receipt': 'source-branch-at-retention.txt', 'recorded_at': 'retention',
            'note': 'This legacy capture has no per-harness capture-time branch receipt; branch was derived from the clean current checkout at retention with the same source commit. Separate orchestration records retain the branch around every capture.'}



def corruption(original_archive, corrupt_archive, key):
    with zipfile.ZipFile(original_archive) as archive:
        info = archive.getinfo(key)
        assert info.compress_type == zipfile.ZIP_STORED
        with original_archive.open('rb') as stream:
            stream.seek(info.header_offset)
            header = stream.read(30)
            assert header[:4] == b'PK\x03\x04'
            names, extra = struct.unpack_from('<HH', header, 26)
            offset = info.header_offset + 30 + names + extra
        original = archive.read(info)
    with corrupt_archive.open('rb') as stream:
        stream.seek(offset)
        corrupt = stream.read(len(original))
    assert original and corrupt == bytes([original[0] ^ 1]) + original[1:]
    with original_archive.open('rb') as first, corrupt_archive.open('rb') as second:
        position = 0
        while left := first.read(1024 * 1024):
            right = second.read(len(left))
            if position <= offset < position + len(left):
                index = offset - position
                assert left[:index] == right[:index] and left[index + 1:] == right[index + 1:]
            else:
                assert left == right
            position += len(left)
        assert not second.read(1)
    return {'key': key, 'data_offset': offset, 'size': len(original),
            'original_sha256': sha(original), 'corrupt_sha256': sha(corrupt),
            'only_changed_archive_byte': offset}


def retain_native(kind, destination, prefix, relocation, modes, program, checker):
    capture = repo / 'target' / (prefix + '-capture')
    build = repo / 'target' / (prefix + '-build')
    traces = copy_capture(capture, destination)
    assert set(traces) == set(modes)
    assert (capture / 'native-baseline.exit-status.txt').read_text().strip() == '0'
    assert (capture / 'native-baseline.stderr.txt').read_bytes() == b''
    archives = {mode: identity(build / relocation / (mode.removesuffix('-app-error') + '.glue')) for mode in modes}
    (destination / 'manifests').mkdir()
    manifests = {name: manifest(build / relocation / (name + '.glue'), destination / 'manifests' / (name + '.glue.json'))
                 for name in set(m.removesuffix('-app-error') for m in modes)}
    (destination / 'native-images').mkdir()
    images = {}
    for path in sorted((build / 'host Python extensions').glob('*.so')):
        shutil.copyfile(path, destination / 'native-images' / path.name)
        images[path.name] = identity(path)
    assert len(images) == 5 and sum(v['size'] for v in images.values()) == 341400
    for cell in cells:
        m = manifests[cell]
        for name, spec in images.items():
            if cell.endswith('-archived'):
                declared = m['resources']['native/' + name]
                assert declared['sha256'] == spec['sha256'] and declared['size'] == spec['size']
            else:
                assert m['host_imports'][name]['sha256'] == spec['sha256']
        if cell.endswith('-archived'):
            with zipfile.ZipFile(build / relocation / (cell + '.glue')) as archive:
                for name, spec in images.items():
                    member = archive.getinfo('native/' + name)
                    assert member.compress_type == zipfile.ZIP_STORED
                    payload = archive.read(member)
                    assert len(payload) == spec['size'] and sha(payload) == spec['sha256']
        assert bool(m['native_modules']) == cell.endswith('-archived')
        assert bool(m['host_imports']) == cell.endswith('-host')
        stdout = (capture / (cell + '.stdout.txt')).read_bytes()
        assert stdout == (capture / 'bundled-archived.stdout.txt').read_bytes()
        assert stdout.endswith((capture / 'native-baseline.stdout.txt').read_bytes())
    corrupt = corruption(build / relocation / 'bundled-archived.glue', build / relocation / 'corrupt-native.glue',
                         'native/libglue_python_dependency.so')
    summary = {'source_commit': commit, 'source_clean': True, 'source_branch': branch_record(capture), 'image_id': image,
               'target_triple': 'aarch64-unknown-linux-gnu', 'launcher': identity(build / relocation / program),
               'archives': archives, 'images': images,
               'frozen_bundle': identity(capture / 'freeze-bundle.json'),
               'stdout_bytes': {mode: len((capture / (mode + '.stdout.txt')).read_bytes()) for mode in modes},
               'baseline_stdout_bytes': len((capture / 'native-baseline.stdout.txt').read_bytes()),
               'statuses': {mode: int((capture / (mode + '.exit-status.txt')).read_text()) for mode in modes},
               'corrupt_native': corrupt}
    metadata = json.loads((destination / 'native-metadata.json').read_text())
    for name, spec in images.items():
        assert all(metadata['files'][name][field] == spec[field] for field in ('size', 'sha256'))
    for mode, spec in archives.items():
        record = (metadata['imports'] if mode in ('bundled-imports', 'host-imports') else metadata['archives'])[mode.removesuffix('-app-error')]
        assert record['bytes'] == spec['size'] and record['sha256'] == spec['sha256']
        for filename in ('manifest_bytes', 'manifest_sha256'):
            assert filename in record
        assert record['manifest_sha256'] == sha((destination / 'manifests' / (mode.removesuffix('-app-error') + '.glue.json')).read_bytes())
    for mode, archive in archives.items():
        args = [sys.executable, '-B', str(repo / 'scripts' / checker), str(destination / (mode + '.trace.txt.gz')),
                '--mode', mode, '--stdout-file', str(destination / (mode + '.stdout.txt')),
                '--stderr-file', str(destination / (mode + '.stderr.txt')), '--archive-bytes', str(archive['size']),
                '--native-metadata-file', str(destination / 'native-metadata.json')]
        if mode == 'corrupt-native':
            args += ['--corrupt-native-offset', str(corrupt['data_offset'])]
        result = subprocess.run(args, capture_output=True, cwd=repo)
        (destination / (mode + '.compressed-trace-check.txt')).write_bytes(result.stdout + result.stderr)
        (destination / (mode + '.compressed-trace-check.exit-status.txt')).write_text(str(result.returncode) + '\n')
        assert result.returncode == 0, result.stderr.decode()
    if kind == 'runner':
        assert (capture / 'bundled-imports.stdout.txt').read_bytes() == (capture / 'host-imports.stdout.txt').read_bytes()
        pins = json.loads((repo / 'fixtures/python-imports/stdlib-pins.json').read_text())
        selected = {key.removeprefix('stdlib/'): spec for key, spec in manifests['bundled-imports']['resources'].items() if key.startswith('stdlib/')}
        assert set(selected) == set(pins['files']) and len(selected) == 2174
        for key, spec in selected.items():
            assert all(spec[field] == pins['files'][key][field] for field in ('size', 'sha256'))
        assert sum(s['size'] for s in selected.values()) == 39158056
        assert len(manifests['host-imports']['resources']) == 18
        assert not any(key.startswith('stdlib/') for key in manifests['host-imports']['resources'])
        supplemental = json.loads((repo / 'fixtures/python-host-imports/stdlib-import-pins.json').read_text())
        provenance = json.loads((capture / 'host-runtime-provenance.json').read_text())
        tree = provenance['runtime_trees']['/build-target/host Python imports']
        for key, spec in supplemental['files'].items():
            assert tree['lib/python3.13/' + key] == {field: spec[field] for field in ('size', 'sha256')}
        stdlib_sources = {k: v for k, v in tree.items() if k.endswith('.py') and k not in
                         {'lib/python3.13/' + lure for lure in provenance['lures']}}
        assert len(stdlib_sources) == 69 and sum(s['size'] for s in stdlib_sources.values()) == 1434587
        summary['source_projection'] = {'files': len(selected), 'uncompressed_bytes': sum(s['size'] for s in selected.values()),
                                        'inventory': identity(repo / 'fixtures/python-imports/stdlib-pins.json')}
        summary['host_sources'] = {'startup_files': 6, 'supplemental_files': 63, 'total_files': 69, 'total_bytes': 1434587,
                                  'supplemental_bytes': 1372061, 'cache_locations': 12,
                                  'supplemental_pins': identity(repo / 'fixtures/python-host-imports/stdlib-import-pins.json'),
                                  'runtime_names': identity(repo / 'fixtures/python-host-imports/runtime-names.json')}
    save_json(destination / 'fixture-summary.json', summary)
    all_summaries[kind] = summary


def retain_source_app():
    prefix = 'python-host-source-apps-source-regression'
    capture, build = (repo / 'target' / (prefix + suffix) for suffix in ('-capture', '-build'))
    destination = out / 'source-regression'
    traces = copy_capture(capture, destination)
    assert set(traces) == set(source_modes)
    assert (capture / 'development-opt-in.txt').read_text().strip() == 'false'
    relocation = build / 'relocated Python source apps'
    archives = {mode: identity(relocation / (mode + '.glue')) for mode in source_modes}
    manifests_dir = destination / 'manifests'
    manifests_dir.mkdir()
    manifests = {mode: manifest(relocation / (mode + '.glue'), manifests_dir / (mode + '.glue.json')) for mode in source_modes}
    metadata = json.loads((destination / 'source-metadata.json').read_text())
    assert type(metadata['schema_version']) is int and metadata['schema_version'] == 0 and set(metadata['archives']) == set(source_modes)
    pins = json.loads((repo / 'fixtures/python-imports/stdlib-pins.json').read_text())
    for mode in source_modes:
        record = metadata['archives'][mode]
        assert record['bytes'] == archives[mode]['size'] and record['sha256'] == archives[mode]['sha256']
        assert record['manifest_sha256'] == sha((manifests_dir / (mode + '.glue.json')).read_bytes())
        selected = {key.removeprefix('stdlib/'): spec for key, spec in manifests[mode]['resources'].items() if key.startswith('stdlib/')}
        assert set(selected) == set(pins['files']) and len(selected) == 2174
        assert sum(spec['size'] for spec in selected.values()) == 39158056
        for key, spec in selected.items():
            assert spec['compression'] == 'deflate'
            assert all(spec[field] == pins['files'][key][field] for field in ('size', 'sha256'))
        library = manifests[mode]['resources']['python/libpython3.13.so.1.0']
        assert library == {'size':73563968,'sha256':'42be968275d5be2d9e632ec9ef6790dd2c10f1d4a710ad1028fc2b687242f219','compression':'stored'}
        frozen = manifests[mode]['resources']['python/frozen.json']
        assert frozen == {'size':139523,'sha256':'6a41fc38141d45c5197adfc1b0ee740c6244ea681742c205b8aa7b8449d865d7','compression':'stored'}
        replay_args = [sys.executable, '-B', str(repo / 'scripts/check-linux-python-source-app-trace.py'),
                       str(destination / (mode + '.trace.txt.gz')), '--mode', mode,
                       '--stdout-file', str(destination / (mode + '.stdout.txt')),
                       '--stderr-file', str(destination / (mode + '.stderr.txt')),
                       '--metadata-file', str(destination / 'source-metadata.json'), '--archive-bytes', str(archives[mode]['size'])]
        result = subprocess.run(replay_args, capture_output=True, cwd=repo)
        (destination / (mode + '.compressed-trace-check.txt')).write_bytes(result.stdout + result.stderr)
        (destination / (mode + '.compressed-trace-check.exit-status.txt')).write_text(str(result.returncode) + '\n')
        assert result.returncode == 0, result.stderr.decode()
    corrupt = corruption(relocation / 'minimal.glue', relocation / 'corrupt-source.glue', 'app/python/simple_value.py')
    assert metadata['archives']['corrupt-source']['corrupt_offset'] == corrupt['data_offset']
    assert manifests['minimal'] == manifests['corrupt-source']
    summary = {'source_commit':commit,'source_clean':True,'source_branch':branch_record(capture),'image_id':image,
               'target_triple':'aarch64-unknown-linux-gnu','launcher':identity(relocation / 'glue'),'archives':archives,
               'frozen_bundle':identity(capture / 'freeze-bundle.json'),
               'source_projection':{'files':2174,'uncompressed_bytes':39158056,'inventory':identity(repo / 'fixtures/python-imports/stdlib-pins.json')},
               'applications':{mode:{'id':m['app_id'],'entry':m['components'][m['entrypoint']]['entry_point'],
                                     'component':m['entrypoint'],'files':sum(key.startswith('app/') for key in m['resources']),
                                     'bytes':sum(spec['size'] for key,spec in m['resources'].items() if key.startswith('app/'))}
                               for mode,m in manifests.items()},
               'stdout_bytes':{mode:len((capture / (mode + '.stdout.txt')).read_bytes()) for mode in source_modes},
               'stderr_bytes':{mode:len((capture / (mode + '.stderr.txt')).read_bytes()) for mode in source_modes},
               'statuses':{mode:int((capture / (mode + '.exit-status.txt')).read_text()) for mode in source_modes},
               'corrupt_source':corrupt}
    save_json(destination / 'fixture-summary.json',summary)
    all_summaries['source'] = summary


retain_source_app()


retain_native('runner', out / 'runner-regression', 'python-host-source-apps-runner-regression', 'relocated Python runner', product_modes,
              'glue', 'check-linux-python-runner-trace.py')
retain_native('extensions', out / 'native-regression', 'python-host-source-apps-native-regression', 'relocated Python extensions', native_modes,
              'glue-python-bootstrap-probe', 'check-linux-python-extension-trace.py')
for kind, destination, prefix, relocation, modes, checker in profiles:
    capture = repo / 'target' / (prefix + '-capture')
    build = repo / 'target' / (prefix + '-build')
    traces = copy_capture(capture, destination)
    assert set(traces) == set(modes)
    assert (capture / 'baseline.exit-status.txt').read_text().strip() == '0'
    archives = {mode: identity(build / relocation / name) for mode, name in modes.items()}
    manifests_dir = destination / 'manifests'
    manifests_dir.mkdir()
    manifests = {name: manifest(build / relocation / name, manifests_dir / (name + '.json')) for name in set(modes.values())}
    summary = {'source_commit': commit, 'source_clean': True, 'source_branch': branch_record(capture), 'image_id': image,
               'target_triple': 'aarch64-unknown-linux-gnu',
               'launcher': identity(build / relocation / 'glue-python-bootstrap-probe'),
               'archives': archives, 'frozen_bundle': identity(capture / 'freeze-bundle.json'),
               'stdout_bytes': len((capture / 'success.stdout.txt').read_bytes()),
               'statuses': {mode: int((capture / (mode + '.exit-status.txt')).read_text()) for mode in modes}}
    offset = None
    if kind in {'imports', 'hostimports'}:
        pins = json.loads((repo / 'fixtures/python-imports/stdlib-pins.json').read_text())
        selected = {key.removeprefix('stdlib/'): spec for key, spec in manifests['success.glue' if kind == 'hostimports' else 'app.glue']['resources'].items() if key.startswith('stdlib/')}
        if kind == 'imports':
            assert set(selected) == set(pins['files'])
        else:
            assert not selected and len(manifests['success.glue']['resources']) == 18
        for key, spec in selected.items():
            assert all(spec[field] == pins['files'][key][field] for field in ('size', 'sha256'))
        if kind == 'imports':
            assert len(selected) == 2174 and sum(spec['size'] for spec in selected.values()) == 39158056
        key = 'app/python/glue_demo/__init__.py'
        a = build / relocation / ('success.glue' if kind == 'hostimports' else 'app.glue')
        b = build / relocation / 'corrupt-source.glue'
        with zipfile.ZipFile(a) as z:
            info = z.getinfo(key)
            assert info.compress_type == zipfile.ZIP_STORED and info.file_size == 104
            with a.open('rb') as stream:
                stream.seek(info.header_offset)
                header = stream.read(30)
                assert header[:4] == b'PK\x03\x04'
                names, extra = struct.unpack_from('<HH', header, 26)
                offset = info.header_offset + 30 + names + extra
            original = z.read(key)
        with b.open('rb') as stream:
            stream.seek(offset)
            corrupt = stream.read(104)
        assert original[0] == ord('f') and corrupt[0] == ord('g') and corrupt[1:] == original[1:]
        with a.open('rb') as first, b.open('rb') as second:
            position = 0
            while left := first.read(1024 * 1024):
                right = second.read(len(left))
                if position <= offset < position + len(left):
                    index = offset - position
                    assert left[:index] == right[:index] and left[index + 1:] == right[index + 1:]
                else:
                    assert left == right
                position += len(left)
            assert not second.read(1)
        summary['corrupt_source'] = {'key': key, 'data_offset': offset, 'size': 104,
                                      'original_sha256': sha(original), 'corrupt_sha256': sha(corrupt),
                                      'only_changed_archive_byte': offset}
        summary['source_projection'] = {'files': len(selected), 'uncompressed_bytes': sum(s['size'] for s in selected.values()),
                                        'inventory': identity(repo / 'fixtures/python-imports/stdlib-pins.json')}
        summary['resource_count'] = len(manifests['success.glue' if kind == 'hostimports' else 'app.glue']['resources'])
    if kind == 'hostimports':
        supplemental = json.loads((repo / 'fixtures/python-host-imports/stdlib-import-pins.json').read_text())
        provenance = json.loads((capture / 'host-runtime-provenance.json').read_text())
        tree = provenance['runtime_trees']['/build-target/host Python imports']
        for key, spec in supplemental['files'].items():
            assert tree['lib/python3.13/' + key] == {field: spec[field] for field in ('size', 'sha256')}
        stdlib_sources = {k:v for k,v in tree.items() if k.endswith('.py') and k not in
                         {'lib/python3.13/' + lure for lure in provenance['lures']}}
        assert len(stdlib_sources) == 69 and sum(s['size'] for s in stdlib_sources.values()) == 1434587
        assert len(supplemental['files']) == 63 and sum(s['size'] for s in supplemental['files'].values()) == 1372061
        summary['host_sources'] = {'startup_files': 6, 'supplemental_files': 63, 'total_files': 69,
                                  'total_bytes': 1434587, 'supplemental_bytes': 1372061,
                                  'supplemental_pins': identity(repo / 'fixtures/python-host-imports/stdlib-import-pins.json'),
                                  'runtime_names': identity(repo / 'fixtures/python-host-imports/runtime-names.json'),
                                  'cache_locations': 12}
    save_json(destination / 'fixture-summary.json', summary)
    replay(destination, checker, archives, offset)
    all_summaries[kind] = summary


# Every legacy route must use the exact same thin probe binary; the product
# launcher has a different entry point and independently recorded identity.
probe_hashes = {value['launcher']['sha256'] for key, value in all_summaries.items() if key not in {'runner', 'source'}}
assert len(probe_hashes) == 1
assert all_summaries['runner']['launcher']['sha256'] not in probe_hashes
assert all_summaries['source']['launcher'] == all_summaries['runner']['launcher']
assert len(list(out.rglob('*.trace.txt.gz'))) == 48
shutil.copyfile(repo / 'fixtures/python-pbs/pins.json', out / 'upstream-pins.json')
validation = out / 'validation'
checks = repo / 'target/python-host-source-app-checks'
shutil.copytree(checks, validation, ignore=lambda directory, names: ['build', 'cargo-home'] if Path(directory) == checks else [])
assert not (validation / 'build').exists()
assert not (validation / 'cargo-home').exists()
orchestration = repo / 'target/python-host-source-apps-regression-orchestration'
assert orchestration.is_dir()
shutil.copytree(orchestration, validation / 'regression-orchestration')
receipt = json.loads((orchestration / 'regression-capture-summary.json').read_text())
assert receipt['source_commit'] == commit and receipt['source_branch'] == branch and receipt['source_clean_before_after'] is True and receipt['trace_count'] == 48
shutil.copyfile(Path(__file__), validation / 'retain-evidence.py')
for source, name in [('/private/tmp/glue-python-host-source-app-mac-checks.sh', 'mac-workspace-commands.sh'),
                     ('/private/tmp/glue-python-host-source-app-linux-workspace.sh', 'linux-workspace-commands.sh'),
                     ('/private/tmp/glue-python-host-source-app-regressions.sh', 'capture-commands.sh'),
                     ('/private/tmp/glue-python-host-source-app-validation.sh', 'validation-commands.sh'),
                     ('/private/tmp/glue-python-host-source-app-policy-checks.sh', 'linux-policy-commands.sh')]:
    assert Path(source).is_file()
    shutil.copyfile(source, out / name)
source_lines = []
for entry in subprocess.check_output(['git', 'ls-tree', '-r', '-z', commit], cwd=repo).split(b'\0'):
    if not entry:
        continue
    metadata, name = entry.split(b'\t', 1)
    if name.startswith(b'docs/evidence/'):
        continue
    _, kind, blob = metadata.split()
    assert kind == b'blob'
    contents = subprocess.check_output(['git', 'cat-file', 'blob', blob.decode()], cwd=repo)
    source_lines.append(sha(contents) + '  ' + name.decode())
(out / 'source.sha256').write_text('\n'.join(source_lines) + '\n')
save_json(out / 'capture-summary.json', all_summaries)
checksum_lines = []
for path in sorted(out.rglob('*')):
    if not path.is_file() or path.name in {'SHA256SUMS', 'README.md'}:
        continue
    checksum_lines.append(identity(path)['sha256'] + '  ' + path.relative_to(out).as_posix())
(out / 'SHA256SUMS').write_text('\n'.join(checksum_lines) + '\n')
print(json.dumps({'source_commit': commit, 'profiles': {
    key: {'launcher': value['launcher'], 'archives': value['archives']} for key, value in all_summaries.items()},
    'traces': 48, 'source_files': len(source_lines), 'retained_files_before_READMEs': len(checksum_lines) + 1,
    'probe_sha256': next(iter(probe_hashes)), 'product_sha256': all_summaries['runner']['launcher']['sha256']}, indent=2))
