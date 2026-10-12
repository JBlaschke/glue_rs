"""Independent hostile controls for the explicit-host source snapshot policy."""

import copy
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


ROOT = Path(__file__).resolve().parents[1]


def load(filename, name):
    spec = importlib.util.spec_from_file_location(name, Path(__file__).with_name(filename))
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


C = load('check-linux-python-host-source-app-trace.py', 'host_source_app_policy_test')

def app_root(mode):
    if mode == 'stdlib':
        return ROOT / 'fixtures/python-host-source-apps/input-stdlib'
    mode = 'minimal' if mode in C.CONTROLS or mode == 'corrupt-source' else mode
    mode = 'error' if mode == 'app-error' else mode
    return ROOT / 'fixtures/python-source-apps' / ('input-' + mode)


def archive_fixture(directory, mode='minimal', change=None):
    app_id, entry, component = C.identity_for(mode)
    manifest = {
        'schema_version': 0, 'app_id': app_id, 'entrypoint': component,
        'components': {component: {'entry_point': entry, 'runtime': 'python', 'native_modules': []}},
        'runtimes': {'python': C.provider_contract(mode)}, 'targets': {'linux-arm64': copy.deepcopy(C.TARGET)},
        'native_modules': {}, 'host_imports': {}, 'resources': C.fixed_specs() | C.expected_application(mode),
    }
    if change:
        change(manifest)
    raw = json.dumps(manifest, sort_keys=True, separators=(',', ':'), ensure_ascii=False).encode()
    payload = io.BytesIO()
    with zipfile.ZipFile(payload, 'w') as archive:
        archive.writestr('python/archive-importer.py', (ROOT / 'fixtures/python-imports/bootstrap.py').read_bytes(), compress_type=zipfile.ZIP_DEFLATED)
        for path in sorted(app_root(mode).rglob('*')):
            if path.is_file():
                archive.writestr(path.relative_to(app_root(mode)).as_posix(), path.read_bytes(), compress_type=zipfile.ZIP_STORED)
    header = b'GLUERS00' + b'\0' * 8 + struct.pack('<QQ', len(raw), len(payload.getvalue())) + hashlib.sha256(raw).digest()
    path = directory / (mode + '.glue')
    path.write_bytes(header + raw + payload.getvalue())
    if mode == 'corrupt-source':
        with zipfile.ZipFile(path) as archive:
            info = archive.getinfo(C.CORRUPT_KEY)
        data = bytearray(path.read_bytes())
        names, extra = struct.unpack_from('<HH', data, info.header_offset + 26)
        offset = info.header_offset + 30 + names + extra
        data[offset] ^= 1
        path.write_bytes(data)
    return path


def metadata_fixture(directory):
    return {'schema_version': 0, 'archives': {mode: C.archive_record(archive_fixture(directory, mode), mode) for mode in C.MODES}}


def cli_arguments(directory, metadata):
    trace = directory / 'trace.txt'; trace.write_bytes(b'')
    stdout, stderr = directory / 'stdout.txt', directory / 'stderr.txt'
    stdout.write_bytes(C.expected_output('minimal')[0]); stderr.write_bytes(C.expected_output('minimal')[1])
    path = directory / 'metadata.json'; path.write_text(json.dumps(metadata))
    return [sys.executable, '-I', '-S', '-B', str(Path(C.__file__)), str(trace), '--mode', 'minimal',
            '--archive-bytes', str(metadata['archives']['minimal']['bytes']), '--metadata-file', str(path),
            '--stdout-file', str(stdout), '--stderr-file', str(stderr)]


def trace_bytes(data):
    return json.dumps(data[:256].decode('latin1')) + ('...' if len(data) > 256 else '')


def corrupt_trace(directory):
    """Read actual locator/ZIP bytes; no runtime/checker state is mocked."""
    path = archive_fixture(directory, 'corrupt-source'); facts = C.archive_record(path, 'corrupt-source')
    raw = path.read_bytes(); token = '3<' + C.archive_for('corrupt-source') + '>'; cwd = C.COMMON.CWD
    lines = [f'execve({json.dumps(C.PROGRAM)}, {json.dumps([C.PROGRAM, "run", C.archive_for("corrupt-source")])}, 0x1234 /* 18 vars */) = 0',
             f'openat({cwd}, {json.dumps(C.archive_for("corrupt-source"))}, O_RDONLY|O_CLOEXEC) = {token}',
             f'lseek({token}, 0, SEEK_END) = {len(raw)}', f'lseek({token}, 0, SEEK_SET) = 0']
    def read(start, length):
        lines.extend([f'lseek({token}, {start}, SEEK_SET) = {start}',
                      f'read({token}, {trace_bytes(raw[start:start + length])}, {length}) = {length}'])
    read(0, 64); read(64, facts['manifest_bytes']); read(facts['zip_directory_offset'], len(raw) - facts['zip_directory_offset'])
    read(len(raw) - 42, 20)
    with zipfile.ZipFile(path) as archive:
        for info in archive.infolist():
            names, extra = struct.unpack_from('<HH', raw, info.header_offset + 26)
            read(info.header_offset, 30 + names + extra)
    lines.append('uname({sysname="Linux", nodename="host-unit-tests", ...}) = 0')
    read(facts['corrupt_offset'], 12)
    lines.append(f'close({token}) = 0')
    message = C.expected_output('corrupt-source')[1]
    lines.extend([f'write(2</evidence/corrupt-source.stderr.txt>, {json.dumps(message.decode())}, {len(message)}) = {len(message)}',
                  'exit_group(1) = ?', '+++ exited with 1 +++'])
    return lines, facts


def check_corrupt(lines, facts):
    C.check_lines((f'1234  {line}\n' for line in lines), 'corrupt-source', facts['bytes'], facts)


class HostSourceMetadataTests(unittest.TestCase):
    def reject_metadata(self, directory, data, mode='minimal'):
        path = directory / 'metadata.json'
        path.write_text(json.dumps(data))
        with self.assertRaises(C.TraceError):
            C.retained_metadata(path, mode, data['archives'][mode]['bytes'])

    def test_actual_small_archive_metadata_admits_all_thirteen_exact_workloads(self):
        with tempfile.TemporaryDirectory() as temporary:
            directory = Path(temporary)
            data = metadata_fixture(directory)
            path = directory / 'metadata.json'; path.write_text(json.dumps(data))
            for mode in C.MODES:
                with self.subTest(mode=mode):
                    record = C.retained_metadata(path, mode, data['archives'][mode]['bytes'])
                    self.assertEqual(record, C.archive_record(directory / (mode + '.glue'), mode))
                    self.assertEqual(record['provider']['provisioning']['stdlib'], C.prefix_for(mode) + '/lib/python3.13')
                    self.assertEqual(set(record['application']), set(C.expected_application(mode)))

    def test_retained_metadata_rejects_typed_shape_inventory_and_digest_lies(self):
        with tempfile.TemporaryDirectory() as temporary:
            directory = Path(temporary); original = metadata_fixture(directory)
            for kind in ('schema-bool', 'missing-case', 'extra-case', 'record-null', 'extra-field', 'missing-field', 'bytes-bool', 'digest-case', 'digest-null'):
                with self.subTest(kind=kind):
                    data = copy.deepcopy(original); record = data['archives']['minimal']
                    if kind == 'schema-bool': data['schema_version'] = False
                    elif kind == 'missing-case': del data['archives']['stdlib']
                    elif kind == 'extra-case': data['archives']['extra'] = record.copy()
                    elif kind == 'record-null': data['archives']['minimal'] = None
                    elif kind == 'extra-field': record['prelude'] = 'untrusted'
                    elif kind == 'missing-field': del record['application']
                    elif kind == 'bytes-bool': record['bytes'] = True
                    elif kind == 'digest-case': record['sha256'] = 'A' * 64
                    else: record['manifest_sha256'] = None
                    path = directory / 'metadata.json'; path.write_text(json.dumps(data))
                    with self.assertRaises(C.TraceError): C.retained_metadata(path, 'minimal', original['archives']['minimal']['bytes'])

    def test_provider_target_and_mode_specific_host_paths_cannot_drift(self):
        with tempfile.TemporaryDirectory() as temporary:
            directory = Path(temporary); original = metadata_fixture(directory)
            for kind in ('debug-int', 'version-bool', 'gil', 'discovery', 'prefix', 'library', 'bundled', 'feature', 'target-page', 'target-cpu', 'target-os', 'control-prefix'):
                with self.subTest(kind=kind):
                    data = copy.deepcopy(original); mode = 'wrong-source' if kind == 'control-prefix' else 'minimal'; record = data['archives'][mode]; provider = record['provider']
                    if kind == 'debug-int': provider['abi']['debug'] = 0
                    elif kind == 'version-bool': provider['abi']['version']['minor'] = True
                    elif kind == 'gil': provider['abi']['gil'] = 'free_threaded'
                    elif kind == 'discovery': provider['provisioning']['discovery'] = 'environment'
                    elif kind == 'prefix': provider['provisioning']['stdlib'] = '/tmp/python/lib/python3.13'
                    elif kind == 'library': provider['provisioning']['runtime_library'] += 'x'
                    elif kind == 'bundled': provider['provisioning']['mode'] = 'bundled'
                    elif kind == 'feature': provider['required_features'] = ['optional-feature']
                    elif kind == 'target-page': record['target']['page_sizes'] = [16384]
                    elif kind == 'target-cpu': record['target']['cpu_features'] = ['unreviewed']
                    elif kind == 'target-os': record['target']['minimum_os_version'] = '0'
                    else: provider['provisioning'] = C.provider_contract('minimal')['provisioning']
                    self.reject_metadata(directory, data, mode)

    def test_application_entry_assets_and_resource_spec_types_are_exact(self):
        with tempfile.TemporaryDirectory() as temporary:
            directory = Path(temporary); original = metadata_fixture(directory)
            for kind in ('entry', 'app-id', 'component', 'missing', 'extra-native', 'size-bool', 'size', 'hash', 'compression'):
                with self.subTest(kind=kind):
                    data = copy.deepcopy(original); record = data['archives']['minimal']; item = record['application']['app/launch.py']
                    if kind == 'entry': record['entry'] = 'app/other.py'
                    elif kind == 'app-id': record['app_id'] = 'other.source'
                    elif kind == 'component': record['component'] = 'other'
                    elif kind == 'missing': del record['application']['app/python/simple_value.py']
                    elif kind == 'extra-native': record['application']['app/hidden.so'] = item.copy()
                    elif kind == 'size-bool': item['size'] = True
                    elif kind == 'size': item['size'] += 1
                    elif kind == 'hash': item['sha256'] = '0' * 64
                    else: item['compression'] = 'deflate'
                    self.reject_metadata(directory, data)

    def test_readiness_and_admission_require_exact_types_and_payload_bounds(self):
        with tempfile.TemporaryDirectory() as temporary:
            directory = Path(temporary); original = metadata_fixture(directory)
            for kind in ('read-bool', 'cursor-bool', 'range-case', 'missing', 'early-cursor', 'extra-read', 'manifest-bool', 'manifest-zero', 'directory-bool', 'directory-overlap'):
                with self.subTest(kind=kind):
                    data = copy.deepcopy(original); record = data['archives']['minimal']; readiness = record['readiness']
                    if kind == 'read-bool': readiness['archive_read_bytes'] = True
                    elif kind == 'cursor-bool': readiness['archive_cursor'] = False
                    elif kind == 'range-case': readiness['ranges_sha256'] = 'A' * 64
                    elif kind == 'missing': readiness.pop('ranges_sha256')
                    elif kind == 'early-cursor': readiness['archive_cursor'] = 64
                    elif kind == 'extra-read': readiness['archive_read_bytes'] = record['bytes'] + 21
                    elif kind == 'manifest-bool': record['manifest_bytes'] = True
                    elif kind == 'manifest-zero': record['manifest_bytes'] = 0
                    elif kind == 'directory-bool': record['zip_directory_offset'] = True
                    else: record['zip_directory_offset'] = 64 + record['manifest_bytes']
                    self.reject_metadata(directory, data)

    def test_corrupt_source_offset_is_typed_and_within_declared_member_region(self):
        with tempfile.TemporaryDirectory() as temporary:
            directory = Path(temporary); original = metadata_fixture(directory)
            for value in (True, -1, 64, original['archives']['corrupt-source']['zip_directory_offset'] - 11):
                data = copy.deepcopy(original); data['archives']['corrupt-source']['corrupt_offset'] = value
                self.reject_metadata(directory, data, 'corrupt-source')
            path = archive_fixture(directory, 'corrupt-source'); raw = bytearray(path.read_bytes())
            raw[original['archives']['corrupt-source']['corrupt_offset']] ^= 1; path.write_bytes(raw)
            with self.assertRaises(C.TraceError): C.archive_record(path, 'corrupt-source')

    def test_real_archive_provider_typing_locator_digest_and_zip_inventory_reject(self):
        with tempfile.TemporaryDirectory() as temporary:
            directory = Path(temporary)
            for kind in ('debug-int', 'locator-version', 'manifest-hash', 'extra-zip'):
                with self.subTest(kind=kind):
                    path = archive_fixture(directory, change=(lambda m: m['runtimes']['python']['abi'].update(debug=0)) if kind == 'debug-int' else None)
                    raw = bytearray(path.read_bytes())
                    if kind == 'locator-version': raw[8] = 1; path.write_bytes(raw)
                    elif kind == 'manifest-hash': raw[32] ^= 1; path.write_bytes(raw)
                    elif kind == 'extra-zip':
                        with zipfile.ZipFile(path, 'a') as archive: archive.writestr('extra.py', b'pass\n')
                        raw = bytearray(path.read_bytes()); struct.pack_into('<Q', raw, 24, len(raw) - 64 - struct.unpack_from('<Q', raw, 16)[0]); path.write_bytes(raw)
                    with self.assertRaises(C.TraceError): C.archive_record(path, 'minimal')

    def test_live_archive_rejects_member_payload_and_local_name_substitution(self):
        with tempfile.TemporaryDirectory() as temporary:
            directory = Path(temporary)
            for kind in ('payload', 'local-name'):
                with self.subTest(kind=kind):
                    path = archive_fixture(directory)
                    with zipfile.ZipFile(path) as archive: info = archive.getinfo('app/python/simple_value.py')
                    raw = bytearray(path.read_bytes()); names, extra = struct.unpack_from('<HH', raw, info.header_offset + 26)
                    at = info.header_offset + 30 + names + extra if kind == 'payload' else info.header_offset + 30
                    raw[at] ^= 1; path.write_bytes(raw)
                    with self.assertRaises((C.TraceError, zipfile.BadZipFile)): C.archive_record(path, 'minimal')

    def test_cli_emits_the_same_complete_metadata_from_actual_archives(self):
        with tempfile.TemporaryDirectory() as temporary:
            directory = Path(temporary); expected = metadata_fixture(directory); output = directory / 'emitted.json'
            result = subprocess.run([sys.executable, '-I', '-S', '-B', str(Path(C.__file__)), '--emit-metadata', str(directory), str(output)], capture_output=True, text=True)
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertEqual(json.loads(output.read_text()), expected)

    def test_cli_requires_metadata_and_one_archive_identity_source(self):
        with tempfile.TemporaryDirectory() as temporary:
            directory = Path(temporary); data = metadata_fixture(directory); original = cli_arguments(directory, data)
            for flag in ('--metadata-file', '--archive-bytes'):
                args = original.copy(); at = args.index(flag); del args[at:at + 2]
                self.assertEqual(subprocess.run(args, capture_output=True).returncode, 2)
            args = original + ['--archive-file', str(directory / 'minimal.glue')]
            self.assertEqual(subprocess.run(args, capture_output=True).returncode, 2)

    def test_cli_malformed_metadata_rejects_before_runtime_without_tracebacks(self):
        with tempfile.TemporaryDirectory() as temporary:
            directory = Path(temporary); original = metadata_fixture(directory)
            for kind in ('schema-bool', 'provider-null', 'numeric-hash', 'missing-readiness', 'application-bool', 'invalid-json'):
                with self.subTest(kind=kind):
                    data = copy.deepcopy(original); record = data['archives']['minimal']
                    if kind == 'schema-bool': data['schema_version'] = False
                    elif kind == 'provider-null': record['provider'] = None
                    elif kind == 'numeric-hash': record['sha256'] = 42
                    elif kind == 'missing-readiness': record.pop('readiness')
                    elif kind == 'application-bool': record['application']['app/launch.py']['size'] = True
                    args = cli_arguments(directory, data)
                    if kind == 'invalid-json': (directory / 'metadata.json').write_bytes(b'{invalid')
                    result = subprocess.run(args, capture_output=True, text=True)
                    self.assertEqual(result.returncode, 1, result.stderr)
                    self.assertIn('trace rejected:', result.stderr)
                    self.assertNotIn('Traceback', result.stderr)
                    self.assertNotIn('awaiting complete development', result.stderr)


class HostSourcePreparationTests(unittest.TestCase):
    def fixture(self, directory):
        application = directory / 'application'; (application / 'app').mkdir(parents=True)
        (application / 'app/launch.py').write_bytes(b'pass\n')
        return application

    def reject(self, directory, application, expected, prefix='/missing host source prefix'):
        output = directory / 'output'
        result = subprocess.run([sys.executable, str(ROOT / 'fixtures/python-host-source-apps/prepare.py'), 'stage',
                                 str(directory / 'missing-base.glue'), str(application), str(output),
                                 '--prefix', prefix, '--app-id', 'helper.test', '--entry', 'app/launch.py'], capture_output=True, text=True)
        self.assertEqual(result.returncode, 1, result.stderr)
        self.assertIn(expected, result.stderr)
        self.assertNotIn('missing-base', result.stderr)
        self.assertNotIn('Traceback', result.stderr)
        self.assertFalse(output.exists())

    def test_symlink_file_directory_and_app_root_reject_before_base_read(self):
        for kind in ('file', 'directory', 'root'):
            with self.subTest(kind=kind), tempfile.TemporaryDirectory() as temporary:
                directory = Path(temporary); app = self.fixture(directory)
                if kind == 'file': (app / 'app/link.py').symlink_to('launch.py')
                elif kind == 'directory': (app / 'app/linked').symlink_to(app / 'app', target_is_directory=True)
                else:
                    alias = directory / 'alias'; alias.symlink_to(app, target_is_directory=True); app = alias
                self.reject(directory, app, 'symlink' if kind != 'root' else 'ordinary directory')

    def test_count_and_entry_file_total_bounds_reject_before_base_read(self):
        for kind in ('count', 'entry', 'file', 'total'):
            with self.subTest(kind=kind), tempfile.TemporaryDirectory() as temporary:
                directory = Path(temporary); app = self.fixture(directory)
                if kind == 'count':
                    for number in range(1024): (app / f'app/{number}.txt').write_bytes(b'')
                elif kind in ('entry', 'file'):
                    path = app / ('app/launch.py' if kind == 'entry' else 'app/asset.bin')
                    with path.open('wb') as stream: stream.truncate((64 * 1024 if kind == 'entry' else 4 * 1024 * 1024) + 1)
                else:
                    for number in range(2):
                        with (app / f'app/{number}.bin').open('wb') as stream: stream.truncate(4 * 1024 * 1024)
                self.reject(directory, app, 'inventory exceeds' if kind in ('count', 'total') else 'individual app payload')

    def test_native_bytecode_cache_and_nonportable_paths_reject_before_base_read(self):
        for key in ('app/source.PYC', 'app/source.pYo', 'app/native.SO', 'app/native.so.1', 'app/tool.EXE',
                    'app/__PyCache__/source.py', 'app/NUL.txt', 'app/com1.py', 'outside.txt'):
            with self.subTest(key=key), tempfile.TemporaryDirectory() as temporary:
                directory = Path(temporary); app = self.fixture(directory); path = app / key
                path.parent.mkdir(parents=True, exist_ok=True); path.write_bytes(b'payload')
                expected = 'nonportable' if key in ('app/NUL.txt', 'app/com1.py') else 'unsupported bytecode/native/cache'
                self.reject(directory, app, expected)

    def test_prefix_normalization_unicode_control_and_path_bounds_reject_before_base_read(self):
        for prefix in ('relative', '/', '/host/', '/host//python', '/host/../python', '/höst', '/host\npython', '/host\\python', '/' + 'a' * 4096):
            with self.subTest(prefix=prefix), tempfile.TemporaryDirectory() as temporary:
                directory = Path(temporary); self.reject(directory, self.fixture(directory), 'noncanonical', prefix)

    def test_prefix_directory_owner_budget_rejects_before_base_read(self):
        with tempfile.TemporaryDirectory() as temporary:
            directory = Path(temporary)
            self.reject(directory, self.fixture(directory), 'noncanonical', '/a' * 53)


class HostSourceEarlyRuntimeTests(unittest.TestCase):
    def reject(self, lines, facts):
        with self.assertRaises(C.TraceError): check_corrupt(lines, facts)

    def test_complete_real_crc_rejection_protocol_admits_without_host_acquisition(self):
        with tempfile.TemporaryDirectory() as temporary:
            lines, facts = corrupt_trace(Path(temporary)); check_corrupt(lines, facts)

    def test_readiness_once_in_exact_metadata_phase_and_single_process(self):
        with tempfile.TemporaryDirectory() as temporary:
            lines, facts = corrupt_trace(Path(temporary)); at = next(i for i, line in enumerate(lines) if line.startswith('uname('))
            self.reject(lines[:at] + lines[at + 1:], facts)
            self.reject(lines[:at] + [lines[at], lines[at]] + lines[at + 1:], facts)
            for destination in (1, at - 1, at + 3):
                changed = lines.copy(); query = changed.pop(at); changed.insert(destination, query); self.reject(changed, facts)
            with self.assertRaises(C.TraceError):
                C.check_lines((f'{1235 if i == at else 1234}  {line}\n' for i, line in enumerate(lines)), 'corrupt-source', facts['bytes'], facts)

    def test_complete_metadata_reads_cannot_be_omitted_or_duplicated(self):
        with tempfile.TemporaryDirectory() as temporary:
            lines, facts = corrupt_trace(Path(temporary))
            for at, line in enumerate(lines):
                if not line.startswith('read(') or '`nswer' in line: continue
                with self.subTest(read=at):
                    self.reject(lines[:at] + lines[at + 1:], facts)
                    self.reject(lines[:at] + [line] + lines[at:], facts)

    def test_selected_corrupt_bytes_read_width_and_closed_publication_are_exact(self):
        with tempfile.TemporaryDirectory() as temporary:
            lines, facts = corrupt_trace(Path(temporary)); at = next(i for i, line in enumerate(lines) if '`nswer' in line)
            for changed in (lines[at].replace('`nswer', 'answer'), lines[at].replace('12) = 12', '11) = 11')):
                mutant = lines.copy(); mutant[at] = changed; self.reject(mutant, facts)
            self.reject(lines[:at] + lines[at + 1:], facts)
            self.reject(lines[:at] + [lines[at]] + lines[at:], facts)
            close = next(i for i, line in enumerate(lines) if line.startswith('close('))
            self.reject(lines[:close] + lines[close + 1:], facts)
            mutant = lines.copy(); publication = mutant.pop(close + 1); mutant.insert(at, publication); self.reject(mutant, facts)

    def test_failed_host_source_native_cache_process_and_network_attempts_reject(self):
        with tempfile.TemporaryDirectory() as temporary:
            lines, facts = corrupt_trace(Path(temporary)); cwd = C.COMMON.CWD
            calls = [f'openat({cwd}, "/tmp/source.py", O_RDONLY|O_CLOEXEC) = -1 ENOENT (No such file or directory)',
                     f'openat({cwd}, "glue://minimal.source/app/launch.py", O_RDONLY|O_CLOEXEC) = -1 ENOENT (No such file or directory)',
                     f'openat({cwd}, "/tmp/image.so", O_RDWR|O_CREAT|O_EXCL, 0600) = -1 EACCES (Permission denied)',
                     f'openat({cwd}, "/tmp", O_RDWR|O_TMPFILE, 0600) = -1 EACCES (Permission denied)',
                     'mkdir("/tmp/__pycache__", 0700) = -1 EACCES (Permission denied)',
                     'memfd_create("fallback", MFD_CLOEXEC|MFD_ALLOW_SEALING) = -1 ENOSYS (Function not implemented)',
                     'clone3({}, 64) = -1 ENOSYS (Function not implemented)',
                     'execve("/bin/sh", ["sh"], NULL) = -1 EACCES (Permission denied)',
                     'socket(AF_INET, SOCK_STREAM, 0) = -1 EPERM (Operation not permitted)']
            for call in calls:
                with self.subTest(call=call): self.reject(lines[:-3] + [call] + lines[-3:], facts)

    def test_output_path_byte_counts_exit_status_and_post_exit_operations_reject(self):
        with tempfile.TemporaryDirectory() as temporary:
            lines, facts = corrupt_trace(Path(temporary)); at = next(i for i, line in enumerate(lines) if line.startswith('write('))
            mutant = lines.copy(); mutant[at] = mutant[at].replace('/evidence/', '/tmp/'); self.reject(mutant, facts)
            mutant = lines.copy(); mutant[at] = mutant[at].rsplit(' = ', 1)[0] + ' = 0'; self.reject(mutant, facts)
            mutant = lines.copy(); mutant[-2:] = ['exit_group(0) = ?', '+++ exited with 0 +++']; self.reject(mutant, facts)
            self.reject(lines + ['gettid() = 1234'], facts)

    def test_cli_accepts_raw_and_gzip_crc_protocol_and_rejects_truncated_gzip(self):
        with tempfile.TemporaryDirectory() as temporary:
            directory = Path(temporary); data = metadata_fixture(directory); lines, facts = corrupt_trace(directory)
            for compressed in (False, True):
                trace = directory / ('trace.txt.gz' if compressed else 'trace.txt')
                raw = ''.join('1234  ' + line + '\n' for line in lines).encode(); trace.write_bytes(gzip.compress(raw) if compressed else raw)
                metadata = directory / 'metadata.json'; metadata.write_text(json.dumps(data))
                stdout, stderr = directory / 'stdout.txt', directory / 'stderr.txt'
                stdout.write_bytes(b''); stderr.write_bytes(C.expected_output('corrupt-source')[1])
                args = [sys.executable, '-I', '-S', '-B', str(Path(C.__file__)), str(trace), '--mode', 'corrupt-source',
                        '--archive-bytes', str(facts['bytes']), '--metadata-file', str(metadata), '--stdout-file', str(stdout), '--stderr-file', str(stderr)]
                good = subprocess.run(args, capture_output=True, text=True); self.assertEqual(good.returncode, 0, good.stderr)
                if compressed:
                    trace.write_bytes(trace.read_bytes()[:-8]); bad = subprocess.run(args, capture_output=True, text=True)
                    self.assertEqual(bad.returncode, 1, bad.stderr); self.assertNotIn('Traceback', bad.stderr)


if __name__ == '__main__':
    unittest.main()
