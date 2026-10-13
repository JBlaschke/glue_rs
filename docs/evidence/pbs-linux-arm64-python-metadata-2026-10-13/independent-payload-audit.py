"""Independent fixed artifact, payload and CLI audit; no trace policy imports."""
import csv
import hashlib
import io
import json
from pathlib import Path
import struct
import sys
import zipfile

capture, artifacts, root = map(Path, sys.argv[1:4])
records = json.loads((capture / 'source-metadata.json').read_text())['archives']
profiles = ('bundled', 'host', 'install-host')
metadata_key = 'app/python/glue_meta_demo-1.2.3.dist-info/METADATA'
record_key = 'app/python/glue_meta_demo-1.2.3.dist-info/RECORD'
app = (root / 'fixtures/python-metadata/input/app/main.py').read_bytes()
helper = (root / 'fixtures/python-metadata/bootstrap.py').read_bytes()
manifests, verified, controls = {}, {}, {}


def sha(path):
    with path.open('rb') as stream:
        return hashlib.file_digest(stream, 'sha256').hexdigest()


for mode, retained in records.items():
    path = artifacts / (mode + '.glue')
    size = path.stat().st_size
    assert size == retained['bytes'] and sha(path) == retained['sha256'], mode
    with path.open('rb') as stream:
        header = stream.read(64)
        assert header[:16] == b'GLUERS00' + b'\0' * 8
        length, payload_length = struct.unpack_from('<QQ', header, 16)
        raw = stream.read(length)
        assert length == retained['manifest_bytes'] and payload_length == size - 64 - length
        assert hashlib.sha256(raw).digest() == header[32:64]
        assert hashlib.sha256(raw).hexdigest() == retained['manifest_sha256']
    manifest = json.loads(raw)
    assert json.dumps(manifest, sort_keys=True, separators=(',', ':'), ensure_ascii=False).encode() == raw
    assert manifest['runtimes']['python'] == retained['provider']
    assert manifest['targets']['linux-arm64'] == retained['target']
    manifests[mode] = manifest
    total, count = 0, 0
    with zipfile.ZipFile(path) as archive:
        assert archive.start_dir == retained['zip_directory_offset']
        assert len(archive.infolist()) == len(manifest['resources'])
        assert set(archive.namelist()) == set(manifest['resources'])
        for key, spec in manifest['resources'].items():
            info = archive.getinfo(key)
            assert info.file_size == spec['size']
            assert info.compress_type == (zipfile.ZIP_STORED if spec['compression'] == 'stored' else zipfile.ZIP_DEFLATED)
            if mode.endswith('-corrupt-metadata') and key == metadata_key:
                try:
                    archive.read(key)
                except zipfile.BadZipFile as error:
                    assert 'CRC' in str(error)
                else:
                    raise AssertionError('CRC control did not reject')
                continue
            digest, member_bytes = hashlib.sha256(), 0
            with archive.open(key) as stream:
                while data := stream.read(1024 * 1024):
                    digest.update(data); member_bytes += len(data)
            assert member_bytes == spec['size'] and digest.hexdigest() == spec['sha256'], (mode, key)
            total += member_bytes; count += 1
        assert archive.read('app/main.py') == app
        assert archive.read('python/archive-metadata.py') == helper
    verified[mode] = {'archive_sha256': retained['sha256'], 'verified_members': count,
                      'verified_uncompressed_bytes': total, 'deliberately_corrupt_members': int(mode.endswith('-corrupt-metadata'))}
    for operation in ('inspect', 'verify', 'doctor', 'cat'):
        prefix = capture / 'cli-controls' / (mode + '.' + operation)
        status = int(Path(str(prefix) + '.exit-status.txt').read_text())
        expected = int(operation == 'verify' and mode.endswith('-corrupt-metadata'))
        assert status == expected, (mode, operation)
        stdout = Path(str(prefix) + '.stdout.txt').read_bytes()
        stderr = Path(str(prefix) + '.stderr.txt').read_bytes()
        if expected:
            assert stdout == b'' and stderr == ('glue: resource "' + metadata_key + '" failed CRC32 verification\n').encode()
        else:
            assert stderr == b''
        if operation == 'inspect': assert json.loads(stdout) == manifest
        if operation == 'cat': assert stdout == app
        if operation == 'doctor': assert b'Ready: pinned ' in stdout and b'Python distribution metadata application' in stdout
        controls[mode + '.' + operation] = {'exit_status': status, 'stdout_sha256': hashlib.sha256(stdout).hexdigest(), 'stderr_sha256': hashlib.sha256(stderr).hexdigest()}

differences = {}
for profile in profiles:
    normal, bad, corrupt = (artifacts / (profile + suffix + '.glue') for suffix in ('', '-bad-record', '-corrupt-metadata'))
    offsets, cursor = [], 0
    with normal.open('rb') as left, corrupt.open('rb') as right:
        while first := left.read(1024 * 1024):
            second = right.read(len(first)); assert len(second) == len(first)
            offsets.extend(cursor + index for index, (a, b) in enumerate(zip(first, second)) if a != b)
            cursor += len(first)
        assert not right.read(1)
    assert offsets == [records[profile + '-corrupt-metadata']['corrupt_offset']]
    assert manifests[profile] == manifests[profile + '-corrupt-metadata']
    with zipfile.ZipFile(normal) as left, zipfile.ZipFile(bad) as right:
        assert left.namelist() == right.namelist()
        original = list(csv.reader(io.StringIO(left.read(record_key).decode())))
        changed = list(csv.reader(io.StringIO(right.read(record_key).decode())))
        assert original[0][0] != '../escape.py'
        original[0][0] = '../escape.py'
        assert changed == original
        for key in left.namelist():
            if key != record_key:
                assert manifests[profile]['resources'][key] == manifests[profile + '-bad-record']['resources'][key]
        expected = json.loads(json.dumps(manifests[profile]))
        expected['resources'][record_key] = manifests[profile + '-bad-record']['resources'][record_key]
        assert manifests[profile + '-bad-record'] == expected
    differences[profile] = {'crc_changed_archive_bytes': 1, 'crc_changed_offset': offsets[0], 'bad_record_changed_csv_cells': 1}

assert (capture / 'source-revision.txt').read_text().strip() == '80c4b33698d7f9c6caa54f8c8afcc69ff6faa2ee'
assert (capture / 'source-status.txt').read_bytes() == b''
assert (capture / 'source-diff.patch').read_bytes() == b''
artifacts_lines = (capture / 'artifacts.sha256').read_text().splitlines()
assert len(artifacts_lines) == 10
for line in artifacts_lines:
    expected, path = line.split('  ', 1)
    assert sha(artifacts / Path(path).name) == expected
result = {'schema_version': 0, 'source_revision': '80c4b33698d7f9c6caa54f8c8afcc69ff6faa2ee',
          'source_clean': True, 'archive_count': len(verified), 'checked_artifact_hashes': len(artifacts_lines),
          'verified_members': sum(item['verified_members'] for item in verified.values()), 'archives': verified,
          'control_differences': differences, 'cli_control_count': len(controls), 'cli_controls': controls,
          'metadata_helper_sha256': hashlib.sha256(helper).hexdigest()}
(capture / 'independent-payload-audit.json').write_text(json.dumps(result, sort_keys=True, indent=2) + '\n')
print('Independent payload audit passed:', result['archive_count'], 'archives;', result['verified_members'], 'verified members;', result['cli_control_count'], 'CLI controls;', result['checked_artifact_hashes'], 'artifact hashes')
