"""Independent archive and hostile trace controls for installed-package evidence."""
from __future__ import annotations

import base64
import copy
import csv
import gzip
import hashlib
import importlib.util
import io
import json
from pathlib import Path
import struct
import subprocess
import sys
import tempfile
import unittest
import zipfile


def load(filename, name):
    spec = importlib.util.spec_from_file_location(name, Path(__file__).with_name(filename))
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


C = load('check-linux-python-venv-trace.py', 'venv_trace_policy_test')
T = load('test_linux_python_metadata_trace.py', 'venv_private_metadata_tests')
ROOT = Path(__file__).resolve().parents[1]
LEGACY_ARCHIVE_FIXTURE = T.archive_fixture
_metadata_fixture = T.metadata_fixture
_rejection_trace = T.rejection_trace


def archive_fixture(directory, mode='host', change=None):
    """Construct from checked-in normalized bytes, independently of C helpers."""
    app = ROOT / 'fixtures/python-venv-ingestion/expected-input'
    payloads = {path.relative_to(app).as_posix(): path.read_bytes()
                for path in sorted(app.rglob('*')) if path.is_file()}
    payloads['python/archive-importer.py'] = (ROOT / 'fixtures/python-imports/bootstrap.py').read_bytes()
    payloads['python/archive-metadata.py'] = (ROOT / 'fixtures/python-metadata/bootstrap.py').read_bytes()
    resources = {key: {'size': len(value), 'sha256': hashlib.sha256(value).hexdigest(),
                       'compression': 'deflate' if key.startswith('python/') else 'stored'}
                 for key, value in payloads.items()}
    manifest = {'schema_version': 0, 'app_id': 'distribution.metadata', 'entrypoint': 'launch',
                'components': {'launch': {'entry_point': 'app/main.py', 'runtime': 'python', 'native_modules': []}},
                'runtimes': {'python': C.provider_contract(mode)}, 'targets': {'linux-arm64': copy.deepcopy(C.TARGET)},
                'native_modules': {}, 'host_imports': {}, 'resources': resources}
    if change:
        change(manifest)
    raw = json.dumps(manifest, sort_keys=True, separators=(',', ':'), ensure_ascii=False).encode()
    payload = io.BytesIO()
    with zipfile.ZipFile(payload, 'w') as archive:
        for key, value in payloads.items():
            archive.writestr(key, value, compress_type=zipfile.ZIP_DEFLATED if key.startswith('python/') else zipfile.ZIP_STORED)
    locator = b'GLUERS00' + b'\0' * 8 + struct.pack('<QQ', len(raw), len(payload.getvalue())) + hashlib.sha256(raw).digest()
    path = directory / (mode + '.glue')
    path.write_bytes(locator + raw + payload.getvalue())
    if mode.endswith('-corrupt-metadata'):
        with zipfile.ZipFile(path) as archive:
            info = archive.getinfo(C.CORRUPT_KEY)
        data = bytearray(path.read_bytes())
        names, extra = struct.unpack_from('<HH', data, info.header_offset + 26)
        data[info.header_offset + 30 + names + extra] ^= 1
        path.write_bytes(data)
    return path


# Reuse the unchanged actual-trace hostile audit with this fresh policy/fixture.
T.C = C
T.archive_fixture = archive_fixture
audit_capture = T.audit_capture


def metadata_fixture(directory):
    data = _metadata_fixture(directory)
    # These are retained-schema unit identities, not invented runtime captures.
    record = data['archives']['bundled-corrupt-metadata']
    record['crc_read_offsets'] = dict(zip(C.CRC_PREFIX, (500000, 503000, 504000)))
    record['corrupt_offset'] = 504000
    return data


def rejection_trace(directory, mode='host-corrupt-metadata'):
    lines, record = _rejection_trace(directory, mode)
    token = '3<' + C.archive_for(mode) + '>'
    at = next(index for index, line in enumerate(lines)
              if line == f'lseek({token}, {record["corrupt_offset"]}, SEEK_SET) = {record["corrupt_offset"]}')
    key = C.CRC_PREFIX[1]
    offset = record['crc_read_offsets'][key]
    data = (ROOT / 'fixtures/python-venv-ingestion/expected-input' / key).read_bytes()
    lines[at:at] = [f'lseek({token}, {offset}, SEEK_SET) = {offset}',
                   f'read({token}, {T.quoted_bytes(data)}, {len(data)}) = {len(data)}']
    return lines, record


T.metadata_fixture = metadata_fixture
T.rejection_trace = rejection_trace


class InstalledPackageTraceTests(unittest.TestCase):
    def test_normalized_record_covers_ten_retained_package_files(self):
        app = ROOT / 'fixtures/python-venv-ingestion/expected-input'
        record = (app / C.RECORD_KEY).read_text()
        seen = set()
        for name, digest, size in csv.reader(io.StringIO(record)):
            key = 'app/python/' + name
            self.assertNotIn(key, seen)
            seen.add(key)
            data = (app / key).read_bytes()
            if key == C.RECORD_KEY:
                self.assertEqual((digest, size), ('', ''))
            else:
                self.assertEqual(digest, 'sha256=' + base64.urlsafe_b64encode(hashlib.sha256(data).digest()).decode().rstrip('='))
                self.assertEqual(size, str(len(data)))
        expected = {path.relative_to(app).as_posix() for path in (app / 'app/python').rglob('*') if path.is_file()}
        self.assertEqual(seen, expected)
        self.assertEqual(len(seen), 10)
        self.assertIn('"glue_meta_demo/data/message,one.txt"', record)
        self.assertNotIn('__pycache__', record)
        self.assertNotIn('../../../bin/', record)
        self.assertEqual(len(C.application_bytes('host')), 11)

    def test_actual_host_archives_admit_success_and_crc_for_both_providers(self):
        with tempfile.TemporaryDirectory() as temporary:
            directory = Path(temporary)
            for mode in C.MODES:
                if C.profile_for(mode) == 'bundled':
                    continue
                with self.subTest(mode=mode):
                    record = C.archive_record(archive_fixture(directory, mode), mode)
                    self.assertEqual(record['provider'], C.provider_contract(mode))
                    self.assertEqual(len(record['application']), 11)
                    self.assertEqual('corrupt_offset' in record, mode.endswith('-corrupt-metadata'))
                    if not C.rejected(mode):
                        self.assertIn('files=10', C.expected_output(mode)[0].decode())

    def test_template_helper_target_and_normalized_bytes_cannot_drift(self):
        with tempfile.TemporaryDirectory() as temporary:
            directory = Path(temporary)
            changes = [lambda m: m['resources']['python/archive-metadata.py'].update(sha256='0' * 64),
                       lambda m: m['runtimes']['python']['abi'].update(debug=0),
                       lambda m: m['runtimes']['python']['provisioning'].update(stdlib='/tmp/python'),
                       lambda m: m['resources'][C.RECORD_KEY].update(compression='deflate'),
                       lambda m: m['resources']['app/main.py'].update(sha256='1' * 64)]
            for change in changes:
                with self.assertRaises(C.TraceError):
                    C.archive_record(archive_fixture(directory, change=change), 'host')
            with self.assertRaises(C.TraceError):
                C.archive_record(LEGACY_ARCHIVE_FIXTURE(directory), 'host')
            path = archive_fixture(directory)
            with zipfile.ZipFile(path) as archive:
                info = archive.getinfo(C.RECORD_KEY)
            raw = bytearray(path.read_bytes())
            names, extra = struct.unpack_from('<HH', raw, info.header_offset + 26)
            raw[info.header_offset + 30 + names + extra] ^= 1
            path.write_bytes(raw)
            with self.assertRaises((C.TraceError, zipfile.BadZipFile)):
                C.archive_record(path, 'host')

    def test_retained_inventory_excludes_old_record_controls_and_requires_exact_types(self):
        with tempfile.TemporaryDirectory() as temporary:
            directory = Path(temporary)
            original = T.metadata_fixture(directory)
            path = directory / 'metadata.json'
            path.write_text(json.dumps(original))
            for mode in C.MODES:
                self.assertEqual(C.retained_metadata(path, mode, original['archives'][mode]['bytes']), original['archives'][mode])
            for old_mode in ('bundled-bad-record', 'host-bad-record', 'install-host-bad-record'):
                with self.assertRaises(C.TraceError):
                    C.profile_for(old_mode)
            for kind in ('extra-mode', 'byte-bool', 'provider', 'record', 'offset'):
                changed = copy.deepcopy(original)
                mode = 'host-corrupt-metadata' if kind == 'offset' else 'host'
                record = changed['archives'][mode]
                if kind == 'extra-mode':
                    changed['archives']['host-bad-record'] = record
                elif kind == 'byte-bool':
                    record['bytes'] = True
                elif kind == 'provider':
                    record['provider']['build_id'] = C.provider_contract('install-host')['build_id']
                elif kind == 'record':
                    record['application'][C.RECORD_KEY]['sha256'] = '1' * 64
                else:
                    record['corrupt_offset'] = True
                path.write_text(json.dumps(changed))
                with self.assertRaises(C.TraceError):
                    C.retained_metadata(path, mode, original['archives'][mode]['bytes'])

    def test_crc_controls_require_complete_reads_readiness_and_closed_archive(self):
        with tempfile.TemporaryDirectory() as temporary:
            for mode in ('host-corrupt-metadata', 'install-host-corrupt-metadata'):
                lines, record = T.rejection_trace(Path(temporary), mode)
                T.check(lines, mode, record)
                for at, line in enumerate(lines):
                    if line.startswith(('read(', 'uname(', 'close(')):
                        with self.subTest(mode=mode, line=at):
                            with self.assertRaises(C.TraceError):
                                T.check(lines[:at] + lines[at + 1:], mode, record)

    def test_crc_controls_reject_extra_source_provider_process_and_filesystem_operations(self):
        with tempfile.TemporaryDirectory() as temporary:
            mode = 'host-corrupt-metadata'
            lines, record = T.rejection_trace(Path(temporary), mode)
            calls = [f'openat({C.CWD}, "/tmp/package.py", O_RDONLY|O_CLOEXEC) = -1 ENOENT (No such file or directory)',
                     f'openat({C.CWD}, "/tmp", O_RDWR|O_TMPFILE, 0600) = -1 EACCES (Permission denied)',
                     'unlink("/tmp/package") = -1 ENOENT (No such file or directory)',
                     'clone3({}, 64) = -1 ENOSYS (Function not implemented)',
                     'execve("/bin/sh", ["sh"], NULL) = -1 EACCES (Permission denied)',
                     'socket(AF_INET, SOCK_STREAM, 0) = -1 EPERM (Operation not permitted)',
                     f'openat({C.CWD}, "/build-target/host Python metadata/lib/libpython3.13.so.1.0", O_RDONLY|O_CLOEXEC) = -1 ENOENT (No such file or directory)']
            for call in calls:
                with self.subTest(call=call):
                    with self.assertRaises(C.TraceError):
                        T.check(lines[:-3] + [call] + lines[-3:], mode, record)

    def test_installer_and_metadata_read_order_offsets_and_visible_bytes_are_exact(self):
        with tempfile.TemporaryDirectory() as temporary:
            mode = 'host-corrupt-metadata'
            lines, record = T.rejection_trace(Path(temporary), mode)
            token = '3<' + C.archive_for(mode) + '>'
            positions = [next(index for index, line in enumerate(lines)
                              if line == f'lseek({token}, {record["crc_read_offsets"][key]}, SEEK_SET) = {record["crc_read_offsets"][key]}')
                         for key in C.CRC_PREFIX[1:]]
            installer, metadata = positions
            reordered = lines.copy()
            reordered[installer:installer + 2], reordered[metadata:metadata + 2] = lines[metadata:metadata + 2], lines[installer:installer + 2]
            mutations = [reordered]
            for at, key in zip(positions, C.CRC_PREFIX[1:]):
                missing = lines[:at] + lines[at + 2:]
                mutations.append(missing)
                wrong_offset = lines.copy()
                offset = record['crc_read_offsets'][key]
                wrong_offset[at] = f'lseek({token}, {offset + 1}, SEEK_SET) = {offset + 1}'
                mutations.append(wrong_offset)
                wrong_bytes = lines.copy()
                data = C.corrupt_bytes() if key == C.CORRUPT_KEY else C.application_bytes(mode)[key]
                changed = bytes([data[0] ^ 1]) + data[1:]
                wrong_bytes[at + 1] = f'read({token}, {T.quoted_bytes(changed)}, {len(data)}) = {len(data)}'
                mutations.append(wrong_bytes)
            for mutated in mutations:
                with self.assertRaises(C.TraceError):
                    T.check(mutated, mode, record)

    def test_raw_gzip_cli_replays_and_truncated_gzip_rejects(self):
        with tempfile.TemporaryDirectory() as temporary:
            directory = Path(temporary)
            metadata = directory / 'metadata.json'
            metadata.write_text(json.dumps(T.metadata_fixture(directory)))
            mode = 'host-corrupt-metadata'
            lines, record = T.rejection_trace(directory, mode)
            stdout, stderr = directory / 'stdout.txt', directory / 'stderr.txt'
            stdout.write_bytes(b'')
            stderr.write_bytes(C.expected_output(mode)[1])
            raw = ''.join('1234  ' + line + '\n' for line in lines).encode()
            for compressed in (False, True):
                trace = directory / ('trace.txt.gz' if compressed else 'trace.txt')
                trace.write_bytes(gzip.compress(raw) if compressed else raw)
                args = [sys.executable, '-I', '-S', '-B', C.__file__, str(trace), '--mode', mode,
                        '--archive-bytes', str(record['bytes']), '--metadata-file', str(metadata),
                        '--stdout-file', str(stdout), '--stderr-file', str(stderr)]
                result = subprocess.run(args, capture_output=True, text=True)
                self.assertEqual(result.returncode, 0, result.stderr)
                if compressed:
                    trace.write_bytes(trace.read_bytes()[:-8])
                    result = subprocess.run(args, capture_output=True, text=True)
                    self.assertEqual(result.returncode, 1, result.stderr)
                    self.assertNotIn('Traceback', result.stderr)


if __name__ == '__main__':
    if len(sys.argv) == 4 and sys.argv[1] == '--audit-capture':
        audit_capture(Path(sys.argv[2]), Path(sys.argv[3]))
    else:
        unittest.main()
