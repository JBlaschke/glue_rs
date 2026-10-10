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

repo = Path('/Users/johannes.blaschke/Developer/glue_rs')
out = repo / 'docs/evidence/pbs-linux-arm64-python-extensions-2026-10-10'
commit = subprocess.check_output(['git', 'rev-parse', 'HEAD'], cwd=repo).decode().strip()
branch = subprocess.check_output(['git', 'branch', '--show-current'], cwd=repo).decode().strip()
assert commit == sys.argv[1]
assert not subprocess.check_output(['git', 'status', '--porcelain'], cwd=repo)
assert not out.exists()

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
        if path.is_dir() or path.name.endswith('.trace.txt'):
            continue
        dest = destination / path.relative_to(capture)
        dest.parent.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(path, dest)
    (destination / 'source-branch.txt').write_text(branch + '\n')
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
        args = [sys.executable, str(repo / 'scripts' / checker),
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
profiles = [
    ('hostimports', out / 'host-import-regression', 'python-extensions-host-import-regression', 'relocated Python host imports',
     {m: ('success.glue' if m == 'app-error' else m + '.glue') for m in
      ('success', 'app-error', 'corrupt-source', 'wrong-library', 'wrong-import-source', 'missing-import-source', 'cached-import-bytecode')},
     'check-linux-python-host-import-trace.py'),
    ('imports', out / 'bundled-import-regression', 'python-extensions-bundled-regression', 'relocated Python imports',
     {'success': 'app.glue', 'app-error': 'app.glue', 'corrupt-source': 'corrupt-source.glue'},
     'check-linux-python-import-trace.py'),
    ('frozen', out / 'frozen-regression', 'python-extensions-frozen-regression', 'relocated Python bootstrap',
     {m: 'app.glue' for m in ('success', 'missing-encodings', 'bad-bytecode', 'app-error')},
     'check-linux-python-bootstrap-trace.py'),
    ('host', out / 'host-startup-regression', 'python-extensions-host-regression', 'relocated Python host',
     {m: ('success.glue' if m == 'app-error' else m + '.glue') for m in
      ('success', 'wrong-library', 'wrong-stdlib', 'missing-encodings', 'symlink-stdlib', 'missing-library', 'cached-bytecode', 'app-error')},
     'check-linux-python-host-trace.py'),
]
out.mkdir(parents=True)
all_summaries = {}
# Native matrix inputs are small enough to retain exactly; full runtime/archive
# payloads remain separately hashed, with byte-exact manifest and member facts.
native_capture = repo / 'target/python-extensions-final-capture'
native_build = repo / 'target/python-extensions-final-build'
native_traces = copy_capture(native_capture, out)
cells = ('bundled-archived', 'bundled-host', 'host-archived', 'host-host')
native_modes = cells + tuple(c + '-app-error' for c in cells) + ('corrupt-native', 'missing-host-image', 'wrong-host-image')
assert set(native_traces) == set(native_modes)
assert (native_capture / 'native-baseline.exit-status.txt').read_text().strip() == '0'
native_archives = {mode: identity(native_build / 'relocated Python extensions' / (mode.removesuffix('-app-error') + '.glue')) for mode in native_modes}
(out / 'manifests').mkdir()
native_manifests = {name: manifest(native_build / 'relocated Python extensions' / (name + '.glue'), out / 'manifests' / (name + '.glue.json')) for name in set(m.removesuffix('-app-error') for m in native_modes)}
(out / 'native-images').mkdir()
native_images = {}
for path in sorted((native_build / 'host Python extensions').glob('*.so')):
    shutil.copyfile(path, out / 'native-images' / path.name)
    native_images[path.name] = identity(path)
assert len(native_images) == 5 and sum(v['size'] for v in native_images.values()) == 341400
for cell in cells:
    m = native_manifests[cell]
    for name, spec in native_images.items():
        if cell.endswith('-archived'):
            declared = m['resources']['native/' + name]
            assert declared['sha256'] == spec['sha256'] and declared['size'] == spec['size']
        else:
            assert m['host_imports'][name]['sha256'] == spec['sha256']
    if cell.endswith('-archived'):
        with zipfile.ZipFile(native_build / 'relocated Python extensions' / (cell + '.glue')) as archive:
            for name, spec in native_images.items():
                member = archive.getinfo('native/' + name)
                assert member.compress_type == zipfile.ZIP_STORED
                payload = archive.read(member)
                assert len(payload) == spec['size'] and sha(payload) == spec['sha256']
    assert bool(m['native_modules']) == cell.endswith('-archived')
    assert bool(m['host_imports']) == cell.endswith('-host')
    assert (native_capture / (cell + '.stdout.txt')).read_bytes() == (native_capture / 'bundled-archived.stdout.txt').read_bytes()
    assert (native_capture / (cell + '.stdout.txt')).read_bytes().endswith((native_capture / 'native-baseline.stdout.txt').read_bytes())
original_archive = native_build / 'relocated Python extensions/bundled-archived.glue'
corrupt_archive = native_build / 'relocated Python extensions/corrupt-native.glue'
with zipfile.ZipFile(original_archive) as z:
    info = z.getinfo('native/libglue_python_dependency.so')
    with original_archive.open('rb') as stream:
        stream.seek(info.header_offset)
        header = stream.read(30)
        names, extra = struct.unpack_from('<HH', header, 26)
        native_offset = info.header_offset + 30 + names + extra
    original = z.read(info)
with corrupt_archive.open('rb') as stream:
    stream.seek(native_offset)
    corrupt = stream.read(len(original))
assert original[0] == 127 and corrupt[0] == 126 and original[1:] == corrupt[1:]
with original_archive.open('rb') as first, corrupt_archive.open('rb') as second:
    position = 0
    while left := first.read(1024 * 1024):
        right = second.read(len(left))
        if position <= native_offset < position + len(left):
            index = native_offset - position
            assert left[:index] == right[:index] and left[index + 1:] == right[index + 1:]
        else:
            assert left == right
        position += len(left)
    assert not second.read(1)
native_summary = {'source_commit': commit, 'source_clean': True, 'image_id': image,
    'target_triple': 'aarch64-unknown-linux-gnu',
    'launcher': identity(native_build / 'relocated Python extensions/glue-python-bootstrap-probe'),
    'archives': native_archives, 'images': native_images,
    'stdout_bytes': 169, 'baseline_stdout_bytes': 69,
    'statuses': {mode: int((native_capture / (mode + '.exit-status.txt')).read_text()) for mode in native_modes},
    'corrupt_native': {'key': 'native/libglue_python_dependency.so', 'data_offset': native_offset,
        'size': len(original), 'original_sha256': sha(original), 'corrupt_sha256': sha(corrupt),
        'only_changed_archive_byte': native_offset}}
save_json(out / 'fixture-summary.json', native_summary)
for mode, archive in native_archives.items():
    args = [sys.executable, str(repo / 'scripts/check-linux-python-extension-trace.py'),
        str(out / (mode + '.trace.txt.gz')), '--mode', mode,
        '--stdout-file', str(out / (mode + '.stdout.txt')),
        '--stderr-file', str(out / (mode + '.stderr.txt')),
        '--archive-bytes', str(archive['size']), '--native-metadata-file', str(out / 'native-metadata.json')]
    if mode == 'corrupt-native':
        args += ['--corrupt-native-offset', str(native_offset)]
    result = subprocess.run(args, capture_output=True, cwd=repo)
    (out / (mode + '.compressed-trace-check.txt')).write_bytes(result.stdout + result.stderr)
    (out / (mode + '.compressed-trace-check.exit-status.txt')).write_text(str(result.returncode) + '\n')
    assert result.returncode == 0, result.stderr.decode()
metadata = json.loads((out / 'native-metadata.json').read_text())
for name, spec in native_images.items():
    assert all(metadata['files'][name][field] == spec[field] for field in ('size', 'sha256'))
for mode, spec in native_archives.items():
    key = mode.removesuffix('-app-error')
    assert metadata['archives'][key]['bytes'] == spec['size'] and metadata['archives'][key]['sha256'] == spec['sha256']
all_summaries['extensions'] = native_summary
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
    summary = {'source_commit': commit, 'source_clean': True, 'image_id': image,
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

assert len({v['launcher']['sha256'] for v in all_summaries.values()}) == 1
shutil.copyfile(repo / 'fixtures/python-pbs/pins.json', out / 'upstream-pins.json')
shutil.copyfile('/private/tmp/glue-python-host-imports-workspace.sh', out / 'linux-workspace-commands.sh')
shutil.copyfile('/private/tmp/glue-python-extension-mac-checks.sh', out / 'mac-workspace-commands.sh')
shutil.copyfile('/private/tmp/glue-python-extension-policy-checks.sh', out / 'policy-test-commands.sh')
shutil.copyfile('/private/tmp/glue-python-extension-regressions.sh', out / 'regression-commands.sh')
validation = out / 'validation'
shutil.copytree(repo / 'target/python-extensions-checks', validation)
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
print(json.dumps({key: {'launcher': value['launcher'], 'archives': value['archives']} for key, value in all_summaries.items()}, indent=2))
