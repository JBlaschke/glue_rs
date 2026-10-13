"""Independent archive identity and hostile trace controls for metadata evidence."""
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


spec = importlib.util.spec_from_file_location('metadata_trace_policy_test', Path(__file__).with_name('check-linux-python-metadata-trace.py'))
C = importlib.util.module_from_spec(spec)
spec.loader.exec_module(C)
ROOT = Path(__file__).resolve().parents[1]


def archive_fixture(directory, mode='host', change=None):
    """Use fixture files and wheel CSV directly, without policy payload helpers."""
    app = ROOT / 'fixtures/python-metadata/input'
    payloads = {path.relative_to(app).as_posix(): path.read_bytes() for path in sorted(app.rglob('*')) if path.is_file()}
    if mode.endswith('-bad-record'):
        rows = list(csv.reader(io.StringIO(payloads[C.RECORD_KEY].decode())))
        rows[0][0] = '../escape.py'
        output = io.StringIO(newline=''); csv.writer(output, lineterminator='\n').writerows(rows)
        payloads[C.RECORD_KEY] = output.getvalue().encode()
    payloads['python/archive-importer.py'] = (ROOT / 'fixtures/python-imports/bootstrap.py').read_bytes()
    payloads['python/archive-metadata.py'] = (ROOT / 'fixtures/python-metadata/bootstrap.py').read_bytes()
    resources = {key: {'size': len(value), 'sha256': hashlib.sha256(value).hexdigest(), 'compression': 'deflate' if key.startswith('python/') else 'stored'} for key, value in payloads.items()}
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
    path = directory / (mode + '.glue'); path.write_bytes(locator + raw + payload.getvalue())
    if mode.endswith('-corrupt-metadata'):
        with zipfile.ZipFile(path) as archive:
            info = archive.getinfo(C.CORRUPT_KEY)
        data = bytearray(path.read_bytes()); names, extra = struct.unpack_from('<HH', data, info.header_offset + 26)
        data[info.header_offset + 30 + names + extra] ^= 1
        path.write_bytes(data)
    return path


def metadata_fixture(directory):
    archives = {}
    for mode in C.MODES:
        if C.profile_for(mode) == 'bundled':
            # Retained schema tests can validate a bounded bundled identity
            # without inventing actual PBS bytes. Live archive tests below use
            # only genuinely constructed complete host archives.
            size, length, central = 80 * 1024 * 1024, 400000, 80 * 1024 * 1024 - 400000
            record = {'bytes': size, 'sha256': 'a' * 64, 'manifest_sha256': 'b' * 64,
                      'manifest_bytes': length, 'zip_directory_offset': central,
                      'app_id': 'distribution.metadata', 'entry': 'app/main.py', 'component': 'launch',
                      'provider': C.provider_contract(mode), 'target': copy.deepcopy(C.TARGET), 'application': C.expected_application(mode),
                      'readiness': {'archive_read_bytes': 800064, 'archive_cursor': central - 1, 'ranges_sha256': 'c' * 64}}
            if mode.endswith('-corrupt-metadata'):
                record['corrupt_offset'] = 500000
        else:
            record = C.archive_record(archive_fixture(directory, mode), mode)
        archives[mode] = record
    return {'schema_version': 0, 'archives': archives}


def quoted_bytes(data):
    return json.dumps(data[:256].decode('latin1')) + ('...' if len(data) > 256 else '')


def rejection_trace(directory, mode='host-corrupt-metadata'):
    path = archive_fixture(directory, mode); record = C.archive_record(path, mode); raw = path.read_bytes()
    token = '3<' + C.archive_for(mode) + '>'; cwd = C.CWD
    lines = [f'execve({json.dumps(C.PROGRAM)}, {json.dumps([C.PROGRAM, "run", C.archive_for(mode)])}, 0x1234 /* 18 vars */) = 0',
             f'openat({cwd}, {json.dumps(C.archive_for(mode))}, O_RDONLY|O_CLOEXEC) = {token}',
             f'lseek({token}, 0, SEEK_END) = {len(raw)}', f'lseek({token}, 0, SEEK_SET) = 0']
    def read(start, length):
        lines.extend([f'lseek({token}, {start}, SEEK_SET) = {start}',
                      f'read({token}, {quoted_bytes(raw[start:start + length])}, {length}) = {length}'])
    read(0, 64); read(64, record['manifest_bytes']); read(record['zip_directory_offset'], len(raw) - record['zip_directory_offset']); read(len(raw) - 42, 20)
    with zipfile.ZipFile(path) as archive:
        infos = archive.infolist()
        for info in infos:
            names, extra = struct.unpack_from('<HH', raw, info.header_offset + 26)
            read(info.header_offset, 30 + names + extra)
    lines.append('uname({sysname="Linux", nodename="metadata-unit-tests", ...}) = 0')
    if mode.endswith('-corrupt-metadata'):
        info = next(info for info in infos if info.filename == 'app/main.py')
        names, extra = struct.unpack_from('<HH', raw, info.header_offset + 26)
        read(info.header_offset + 30 + names + extra, info.compress_size)
        read(record['corrupt_offset'], len(C.corrupt_bytes()))
    else:
        for info in infos:
            names, extra = struct.unpack_from('<HH', raw, info.header_offset + 26)
            read(info.header_offset + 30 + names + extra, info.compress_size)
    lines.append(f'close({token}) = 0')
    message = C.expected_output(mode)[1]
    lines.extend([f'write(2</evidence/{mode}.stderr.txt>, {json.dumps(message.decode())}, {len(message)}) = {len(message)}',
                  'exit_group(1) = ?', '+++ exited with 1 +++'])
    return lines, record


def check(lines, mode, record):
    C.check_lines((f'1234  {line}\n' for line in lines), mode, record['bytes'], record)


class MetadataArchiveTests(unittest.TestCase):
    def test_checked_in_record_hashes_cover_every_python_package_resource(self):
        root = ROOT / 'fixtures/python-metadata/input'
        record = (root / C.RECORD_KEY).read_text()
        seen = set()
        for name, digest, size in csv.reader(io.StringIO(record)):
            key = 'app/python/' + name
            self.assertNotIn(key, seen); seen.add(key)
            data = (root / key).read_bytes()
            if key == C.RECORD_KEY:
                self.assertEqual((digest, size), ('', ''))
            else:
                self.assertEqual(digest, 'sha256=' + base64.urlsafe_b64encode(hashlib.sha256(data).digest()).decode().rstrip('='))
                self.assertEqual(size, str(len(data)))
        expected = {path.relative_to(root).as_posix() for path in (root / 'app/python').rglob('*') if path.is_file()}
        self.assertEqual(seen, expected); self.assertEqual(len(seen), 7)
        self.assertIn('"glue_meta_demo/data/message,one.txt"', record)

    def test_actual_host_archives_admit_all_six_provider_and_rejection_cases(self):
        with tempfile.TemporaryDirectory() as temporary:
            directory = Path(temporary)
            for mode in C.MODES:
                if C.profile_for(mode) == 'bundled': continue
                with self.subTest(mode=mode):
                    record = C.archive_record(archive_fixture(directory, mode), mode)
                    self.assertEqual(record['provider'], C.provider_contract(mode))
                    self.assertEqual(len(record['application']), 8)
                    self.assertEqual('corrupt_offset' in record, mode.endswith('-corrupt-metadata'))

    def test_declared_helper_identity_provider_and_application_cannot_drift(self):
        with tempfile.TemporaryDirectory() as temporary:
            directory = Path(temporary)
            changes = [lambda m: m['resources']['python/archive-metadata.py'].update(sha256='0' * 64),
                       lambda m: m['runtimes']['python']['abi'].update(debug=0),
                       lambda m: m['runtimes']['python']['provisioning'].update(stdlib='/tmp/python'),
                       lambda m: m['components']['launch'].update(entry_point='app/other.py'),
                       lambda m: m['resources']['app/main.py'].update(compression='deflate')]
            for change in changes:
                with self.assertRaises(C.TraceError): C.archive_record(archive_fixture(directory, change=change), 'host')

    def test_actual_archive_bytes_names_and_crc_control_are_independently_pinned(self):
        with tempfile.TemporaryDirectory() as temporary:
            directory = Path(temporary)
            for kind in ('helper', 'record', 'local-name', 'corruption'):
                mode = 'host-corrupt-metadata' if kind == 'corruption' else 'host'
                path = archive_fixture(directory, mode)
                key = 'python/archive-metadata.py' if kind == 'helper' else C.RECORD_KEY if kind == 'record' else C.CORRUPT_KEY
                with zipfile.ZipFile(path) as archive: info = archive.getinfo(key)
                raw = bytearray(path.read_bytes()); names, extra = struct.unpack_from('<HH', raw, info.header_offset + 26)
                at = info.header_offset + 30 if kind == 'local-name' else info.header_offset + 30 + names + extra
                if kind == 'helper': at += info.compress_size // 2
                raw[at] ^= 1; path.write_bytes(raw)
                with self.assertRaises((C.TraceError, zipfile.BadZipFile, RuntimeError, OSError)): C.archive_record(path, mode)

    def test_retained_schema_types_inventory_bounds_and_readiness_are_strict(self):
        with tempfile.TemporaryDirectory() as temporary:
            directory = Path(temporary); original = metadata_fixture(directory)
            path = directory / 'metadata.json'; path.write_text(json.dumps(original))
            for mode in C.MODES:
                self.assertEqual(C.retained_metadata(path, mode, original['archives'][mode]['bytes']), original['archives'][mode])
            for kind in ('schema', 'inventory', 'extra', 'bytes', 'digest', 'provider', 'helper', 'readiness', 'offset'):
                with self.subTest(kind=kind):
                    data = copy.deepcopy(original); mode = 'host-corrupt-metadata' if kind == 'offset' else 'host'; record = data['archives'][mode]
                    if kind == 'schema': data['schema_version'] = False
                    elif kind == 'inventory': del data['archives']['bundled']
                    elif kind == 'extra': record['unexpected'] = 1
                    elif kind == 'bytes': record['bytes'] = True
                    elif kind == 'digest': record['sha256'] = 'A' * 64
                    elif kind == 'provider': record['provider']['build_id'] = C.provider_contract('install-host')['build_id']
                    elif kind == 'helper': record['application']['app/main.py']['size'] = True
                    elif kind == 'readiness': record['readiness']['archive_cursor'] = 64
                    else: record['corrupt_offset'] = True
                    path.write_text(json.dumps(data))
                    with self.assertRaises(C.TraceError): C.retained_metadata(path, mode, original['archives'][mode]['bytes'])


class MetadataRejectionTraceTests(unittest.TestCase):
    def reject(self, lines, mode, record):
        with self.assertRaises(C.TraceError): check(lines, mode, record)

    def test_complete_actual_crc_and_record_rejections_admit_before_provider_reads(self):
        with tempfile.TemporaryDirectory() as temporary:
            for mode in ('host-corrupt-metadata', 'install-host-corrupt-metadata', 'host-bad-record', 'install-host-bad-record'):
                with self.subTest(mode=mode):
                    lines, record = rejection_trace(Path(temporary), mode); check(lines, mode, record)

    def test_readiness_complete_metadata_selected_payload_and_close_cannot_be_removed(self):
        with tempfile.TemporaryDirectory() as temporary:
            mode = 'host-corrupt-metadata'; lines, record = rejection_trace(Path(temporary), mode)
            for at, line in enumerate(lines):
                if line.startswith(('read(', 'uname(', 'close(')):
                    with self.subTest(line=at):
                        self.reject(lines[:at] + lines[at + 1:], mode, record)
                        if not line.startswith('close('): self.reject(lines[:at] + [line] + lines[at:], mode, record)

    def test_failed_fallback_mutation_process_network_and_provider_attempts_reject(self):
        with tempfile.TemporaryDirectory() as temporary:
            for mode in ('host-corrupt-metadata', 'host-bad-record'):
                lines, record = rejection_trace(Path(temporary), mode)
                calls = [f'openat({C.CWD}, "/tmp/metadata", O_RDONLY|O_CLOEXEC) = -1 ENOENT (No such file or directory)',
                         f'openat({C.CWD}, "/tmp", O_RDWR|O_TMPFILE, 0600) = -1 EPERM (Operation not permitted)',
                         'unlink("/tmp/python") = -1 ENOENT (No such file or directory)',
                         'mkdir("/tmp/__pycache__", 0700) = -1 EACCES (Permission denied)',
                         'clone3({}, 64) = -1 ENOSYS (Function not implemented)',
                         'execve("/bin/sh", ["sh"], NULL) = -1 EACCES (Permission denied)',
                         'socket(AF_INET, SOCK_STREAM, 0) = -1 EPERM (Operation not permitted)',
                         'memfd_create("fallback", MFD_CLOEXEC|MFD_ALLOW_SEALING) = -1 ENOSYS (Function not implemented)',
                         f'openat({C.CWD}, "/build-target/host Python metadata/lib/libpython3.13.so.1.0", O_RDONLY|O_CLOEXEC) = -1 ENOENT (No such file or directory)']
                for call in calls:
                    with self.subTest(mode=mode, call=call): self.reject(lines[:-3] + [call] + lines[-3:], mode, record)

    def test_output_descriptor_bytes_exit_and_post_exit_records_are_exact(self):
        with tempfile.TemporaryDirectory() as temporary:
            mode = 'host-corrupt-metadata'; lines, record = rejection_trace(Path(temporary), mode)
            at = next(i for i, line in enumerate(lines) if line.startswith('write('))
            for mutation in (lines[at].replace('/evidence/', '/tmp/'), lines[at].replace('CRC32', 'SHA256'), lines[at].rsplit(' = ', 1)[0] + ' = 0'):
                changed = lines.copy(); changed[at] = mutation; self.reject(changed, mode, record)
            self.reject(lines[:-2] + ['exit_group(0) = ?', '+++ exited with 0 +++'], mode, record)
            self.reject(lines + ['gettid() = 1234'], mode, record)

    def test_raw_and_gzip_cli_replay_and_truncated_gzip_rejection(self):
        with tempfile.TemporaryDirectory() as temporary:
            directory = Path(temporary); data = metadata_fixture(directory); mode = 'host-corrupt-metadata'
            lines, record = rejection_trace(directory, mode)
            metadata = directory / 'metadata.json'; metadata.write_text(json.dumps(data))
            stdout, stderr = directory / 'stdout.txt', directory / 'stderr.txt'
            stdout.write_bytes(b''); stderr.write_bytes(C.expected_output(mode)[1])
            for compressed in (False, True):
                trace = directory / ('trace.txt.gz' if compressed else 'trace.txt')
                raw = ''.join('1234  ' + line + '\n' for line in lines).encode(); trace.write_bytes(gzip.compress(raw) if compressed else raw)
                args = [sys.executable, '-I', '-S', '-B', C.__file__, str(trace), '--mode', mode, '--archive-bytes', str(record['bytes']),
                        '--metadata-file', str(metadata), '--stdout-file', str(stdout), '--stderr-file', str(stderr)]
                result = subprocess.run(args, capture_output=True, text=True); self.assertEqual(result.returncode, 0, result.stderr)
                if compressed:
                    trace.write_bytes(trace.read_bytes()[:-8]); result = subprocess.run(args, capture_output=True, text=True)
                    self.assertEqual(result.returncode, 1, result.stderr); self.assertNotIn('Traceback', result.stderr)


def audit_capture(directory, output):
    """Audit hostile edits of actual complete traces after their normal replay.

    This deliberately injects syscalls into real workloads rather than seeding
    checker state. Every normal trace and retained stream must pass first.
    """
    metadata = directory / 'source-metadata.json'
    records = json.loads(metadata.read_text())['archives']
    cases = {}
    for mode in C.MODES:
        record = C.retained_metadata(metadata, mode, records[mode]['bytes'])
        path = directory / (mode + '.trace.txt')
        if not path.exists(): path = path.with_suffix('.txt.gz')
        with (gzip.open if path.suffix == '.gz' else open)(path, 'rt', encoding='utf-8') as stream:
            lines = stream.readlines()
        for suffix, expected in zip(('stdout', 'stderr'), C.expected_output(mode)):
            if (directory / f'{mode}.{suffix}.txt').read_bytes() != expected:
                raise AssertionError(f'{mode}: retained {suffix} differs before audit')
        C.check_lines(lines, mode, record['bytes'], record)
        pid = lines[0].split()[0]
        publication = next(i for i, line in enumerate(lines) if re_search_stdio(line))
        readiness = next(i for i, line in enumerate(lines) if ' uname(' in line)
        archive_close = next(i for i, line in enumerate(lines) if ' close(' in line and '.glue>' in line)
        cwd = C.CWD
        calls = {
            'failed-source-fallback': f'openat({cwd}, "/tmp/metadata.py", O_RDONLY|O_CLOEXEC) = -1 ENOENT (No such file or directory)',
            'named-extraction': f'openat({cwd}, "/tmp/image.so", O_RDWR|O_CREAT|O_EXCL, 0600) = -1 EACCES (Permission denied)',
            'anonymous-extraction': f'openat({cwd}, "/tmp", O_RDWR|O_TMPFILE, 0600) = -1 EACCES (Permission denied)',
            'unlink': 'unlink("/tmp/image.so") = -1 ENOENT (No such file or directory)',
            'cache-directory': 'mkdir("/tmp/__pycache__", 0700) = -1 EACCES (Permission denied)',
            'extra-proc-alias': f'openat({cwd}, "/proc/self/fd/777", O_RDONLY|O_CLOEXEC) = -1 ENOENT (No such file or directory)',
            'physical-metadata': f'openat({cwd}, "/build-target/host Python metadata/lib/python3.13/site-packages/glue_metadata_physical_lure-99.dist-info/METADATA", O_RDONLY|O_CLOEXEC) = -1 ENOENT (No such file or directory)',
            'extra-process': 'clone3({}, 64) = -1 ENOSYS (Function not implemented)',
            'extra-exec': 'execve("/bin/sh", ["sh"], NULL) = -1 EACCES (Permission denied)',
            'network': 'socket(AF_INET, SOCK_STREAM, 0) = -1 EPERM (Operation not permitted)',
            'fallback-image': 'memfd_create("fallback", MFD_CLOEXEC|MFD_ALLOW_SEALING) = -1 ENOSYS (Function not implemented)',
        }
        mutants = {name: lines[:publication] + [pid + '  ' + call + '\n'] + lines[publication:] for name, call in calls.items()}
        mutants['missing-readiness'] = lines[:readiness] + lines[readiness + 1:]
        mutants['duplicate-readiness'] = lines[:readiness] + [lines[readiness]] + lines[readiness:]
        mutants['missing-archive-close'] = lines[:archive_close] + lines[archive_close + 1:]
        mutants['truncated-completion'] = lines[:-1]
        changed = lines.copy(); changed[publication] = changed[publication].replace('/evidence/', '/tmp/')
        mutants['wrong-output-owner'] = changed
        changed = lines.copy(); changed[publication] = changed[publication].replace('glue', 'Glue', 1)
        mutants['wrong-output-bytes'] = changed
        changed = lines.copy(); changed[readiness] = str(int(pid) + 1) + changed[readiness][len(pid):]
        mutants['extra-pid'] = changed
        read = next(i for i, line in enumerate(lines) if i > readiness and ' read(' in line and '.glue>' in line)
        mutants['missing-payload-read'] = lines[:read] + lines[read + 1:]
        changed = lines.copy(); query = changed.pop(readiness); changed.insert(publication - 1, query)
        mutants['late-readiness'] = changed
        guard = next((i for i, line in enumerate(lines) if ' mprotect(' in line and ', 40960, PROT_NONE)' in line), None)
        if guard is not None:
            changed = lines.copy(); changed[guard] = changed[guard].replace('PROT_NONE', 'PROT_READ')
            mutants['wrong-image-guard'] = changed
        if C.rejected(mode):
            last_write = max(i for i, line in enumerate(lines) if re_search_stdio(line))
            acquire = f'openat({cwd}, "/build-target/host Python metadata/lib/libpython3.13.so.1.0", O_RDONLY|O_CLOEXEC) = -1 ENOENT (No such file or directory)'
            mutants['provider-after-rejection'] = lines[:last_write + 1] + [pid + '  ' + acquire + '\n'] + lines[last_write + 1:]
        for name, mutant in mutants.items():
            try:
                C.check_lines(mutant, mode, record['bytes'], record)
            except C.TraceError:
                continue
            raise AssertionError(f'{mode}: hostile actual-trace mutation admitted: {name}')
        cases[mode] = {'archive_sha256': record['sha256'], 'trace_sha256': hashlib.sha256(''.join(lines).encode()).hexdigest(),
                       'normal_trace_passed': True, 'rejected_mutations': sorted(mutants)}
    result = {'schema_version': 0, 'cases': cases, 'normal_traces': len(cases),
              'rejected_mutations': sum(len(case['rejected_mutations']) for case in cases.values())}
    output.write_text(json.dumps(result, sort_keys=True, indent=2) + '\n')
    print(f"Actual metadata trace audit passed: {result['normal_traces']} normal traces; {result['rejected_mutations']} hostile mutations rejected")


def re_search_stdio(line):
    return ' write(1</evidence/' in line or ' write(2</evidence/' in line


if __name__ == '__main__':
    if len(sys.argv) == 4 and sys.argv[1] == '--audit-capture':
        audit_capture(Path(sys.argv[2]), Path(sys.argv[3]))
    else:
        unittest.main()
