"""Independent pinned archives and hostile complete stripped-host traces.

Unit archives use the real small application and existing pinned helpers. They
exercise archive/closed-rejection policy boundaries and never execute Python.
--audit-capture instead replays and mutates complete observed native traces.
"""
from __future__ import annotations

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


def load(filename, name):
    spec = importlib.util.spec_from_file_location(name, Path(__file__).with_name(filename))
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


C = load('check-linux-python-stripped-host-trace.py', 'stripped_host_test_policy')
ROOT = Path(__file__).resolve().parents[1]


def archive_fixture(directory, mode='stripped', change=None, payload_change=None):
    payloads = C.application_bytes(mode) | {
        name: (ROOT / spec[0]).read_bytes() for name, spec in C.HELPER_PINS.items()}
    manifest = {'schema_version': 0, 'app_id': C.IDENTITY[0], 'entrypoint': C.IDENTITY[2],
                'components': {C.IDENTITY[2]: {'entry_point': C.IDENTITY[1], 'runtime': 'python', 'native_modules': []}},
                'runtimes': {'python': C.provider_contract(mode)}, 'targets': {'linux-arm64': copy.deepcopy(C.TARGET)},
                'native_modules': {}, 'host_imports': {}, 'resources': C.fixed_specs() | C.expected_application(mode)}
    if change:
        change(manifest)
    if payload_change:
        payload_change(payloads)
    raw = json.dumps(manifest, sort_keys=True, separators=(',', ':'), ensure_ascii=False).encode()
    output = io.BytesIO()
    with zipfile.ZipFile(output, 'w') as archive:
        for name, data in sorted(payloads.items()):
            archive.writestr(name, data, compress_type=zipfile.ZIP_DEFLATED if name.startswith('python/') else zipfile.ZIP_STORED)
    locator = b'GLUERS00' + b'\0' * 8 + struct.pack('<QQ', len(raw), len(output.getvalue())) + hashlib.sha256(raw).digest()
    path = directory / (mode + '.glue')
    path.write_bytes(locator + raw + output.getvalue())
    if mode == 'corrupt-entry':
        with zipfile.ZipFile(path) as archive:
            info = archive.getinfo('app/main.py')
        data = bytearray(path.read_bytes())
        names, extra = struct.unpack_from('<HH', data, info.header_offset + 26)
        data[info.header_offset + 30 + names + extra] ^= 1
        path.write_bytes(data)
    return path


def metadata_fixture(directory):
    return {'schema_version': 0, 'archives': {
        mode: C.archive_record(archive_fixture(directory, mode), mode) for mode in C.MODES}}


def quoted_bytes(data):
    return json.dumps(data[:256].decode('latin1')) + ('...' if len(data) > 256 else '')


def rejection_trace(path):
    """Construct only the closed CRC-rejection path from inspected real bytes."""
    mode = 'corrupt-entry'
    record, raw = C.archive_record(path, mode), path.read_bytes()
    token = '3<' + C.archive_for(mode) + '>'
    lines = [f'execve({json.dumps(C.PROGRAM)}, {json.dumps([C.PROGRAM, "run", C.archive_for(mode)])}, 0x1234 /* 18 vars */) = 0',
             f'ppoll([{{fd=0</dev/null<char 1:3>>, events=0}}, {{fd=1</evidence/{mode}.stdout.txt>, events=0}}, {{fd=2</evidence/{mode}.stderr.txt>, events=0}}], 3, {{tv_sec=0, tv_nsec=0}}, NULL, 0) = 0 (Timeout)',
             f'openat({C.CWD}, {json.dumps(C.archive_for(mode))}, O_RDONLY|O_CLOEXEC) = {token}',
             f'lseek({token}, 0, SEEK_END) = {len(raw)}', f'lseek({token}, 0, SEEK_SET) = 0']
    def read(start, length):
        lines.extend([f'lseek({token}, {start}, SEEK_SET) = {start}',
                      f'read({token}, {quoted_bytes(raw[start:start + length])}, {length}) = {length}'])
    read(0, 64)
    read(64, record['manifest_bytes'])
    read(record['zip_directory_offset'], len(raw) - record['zip_directory_offset'])
    read(len(raw) - 42, 20)
    with zipfile.ZipFile(path) as archive:
        for info in archive.infolist():
            names, extra = struct.unpack_from('<HH', raw, info.header_offset + 26)
            read(info.header_offset, 30 + names + extra)
    lines.append('uname({sysname="Linux", nodename="stripped-unit-tests", ...}) = 0')
    read(record['corrupt_offset'], len(C.corrupt_bytes()))
    lines.append(f'close({token}) = 0')
    message = C.expected_output(mode)[1]
    lines.extend([f'write(2</evidence/{mode}.stderr.txt>, {json.dumps(message.decode())}, {len(message)}) = {len(message)}',
                  'exit_group(1) = ?', '+++ exited with 1 +++'])
    return [f'1234  {line}\n' for line in lines], record


def parsed(line):
    match = C.BASE.LINE.fullmatch(line.rstrip('\n'))
    if match is None:
        raise AssertionError('test mutation requires one complete parsed syscall')
    return match, C.BASE.split_arguments(match[3])


def changed_call(line, argument=None, value=None, result=None):
    match, args = parsed(line)
    if argument is not None:
        args[argument] = value
    return f'{match[1]}  {match[2]}({", ".join(args)}) = {match[4] if result is None else result}\n'


def private_policy(checker):
    method = checker.checker.call.__func__
    return dict(zip(method.__code__.co_freevars, (cell.cell_contents for cell in method.__closure__)))['private']


def trace_lines(directory, mode):
    path = directory / (mode + '.trace.txt')
    if not path.exists():
        path = path.with_suffix('.txt.gz')
    lines = []
    total = 0
    with (gzip.open if path.suffix == '.gz' else open)(path, 'rt', encoding='utf-8') as stream:
        while line := stream.readline(C.MAX_LINE_CHARACTERS + 2):
            total += len(line.encode('utf-8'))
            if len(lines) >= C.MAX_RECORDS or total > C.MAX_TRACE_BYTES:
                raise AssertionError('captured test input exceeds trace bounds')
            lines.append(line)
    return lines


def mutations(lines, mode, record):
    """Change observations in complete native traces, never checker state."""
    mutants = {}
    pid = lines[0].split()[0]
    publication = next(i for i, line in enumerate(lines) if ' write(' in line and '/evidence/' in line)
    poll = next(i for i, line in enumerate(lines) if ' ppoll(' in line)
    def replace(name, at, replacement):
        changed = lines.copy()
        changed[at] = replacement
        mutants[name] = changed
    def remove(name, at):
        mutants[name] = lines[:at] + lines[at + 1:]
    def repeat(name, at):
        mutants[name] = lines[:at] + [lines[at]] + lines[at:]
    def inject(name, at, call):
        mutants[name] = lines[:at] + [pid + '  ' + call + '\n'] + lines[at:]
    def move(name, at, destination):
        changed = lines.copy()
        call = changed.pop(at)
        changed.insert(destination - (destination > at), call)
        mutants[name] = changed

    remove('poll-missing', poll)
    repeat('poll-repeated', poll)
    replace('poll-wrong-owner', poll, lines[poll].replace('/evidence/', '/tmp/'))
    replace('poll-wrong-result', poll, changed_call(lines[poll], result='1'))
    replace('program-renamed', 0, lines[0].replace(C.PROGRAM, C.DIRECTORY + '/python'))
    replace('exit-wrong-status', len(lines) - 2, changed_call(lines[-2], 0, '1' if mode in C.SUCCESS else '0'))
    replace('publication-wrong-owner', publication, lines[publication].replace('/evidence/', '/tmp/'))
    remove('publication-missing', publication)
    inject('extra-process', publication, 'clone3({}, 64) = -1 ENOSYS (Function not implemented)')
    inject('extra-executable', publication, 'execve("/bin/sh", ["sh"], NULL) = -1 EACCES (Permission denied)')
    inject('network', publication, 'socket(AF_INET, SOCK_STREAM, 0) = -1 EPERM (Operation not permitted)')
    inject('memfd', publication, 'memfd_create("fallback", MFD_CLOEXEC|MFD_ALLOW_SEALING) = -1 ENOSYS (Function not implemented)')
    inject('writable-file', publication, f'openat({C.CWD}, "/tmp/extracted.py", O_WRONLY|O_CREAT|O_TRUNC, 0600) = -1 EACCES (Permission denied)')
    inject('external-source', publication, f'openat({C.CWD}, "/tmp/package.py", O_RDONLY|O_CLOEXEC) = -1 ENOENT (No such file or directory)')
    inject('external-config', publication, f'openat({C.CWD}, "/etc/ssl/openssl.cnf", O_RDONLY) = -1 ENOENT (No such file or directory)')
    inject('duplicated-descriptor', publication, 'dup(1</evidence/' + mode + '.stdout.txt>) = 200</evidence/' + mode + '.stdout.txt>')
    inject('filesystem-mutation', publication, 'unlink("/tmp/package.py") = -1 ENOENT (No such file or directory)')
    inject('unclassified-acquisition', publication, 'pidfd_getfd(3, 4, 0) = -1 EPERM (Operation not permitted)')

    library = C.prefix_for(mode) + '/lib/libpython3.13.so.1.0'
    library_reads = [i for i, line in enumerate(lines) if ' read(' in line and library + '>' in line]
    if mode == 'corrupt-entry':
        at = next(i for i, line in enumerate(lines) if ' read(' in line and
                  f', {len(C.corrupt_bytes())}) = {len(C.corrupt_bytes())}' in line and C.archive_for(mode) + '>' in line)
        remove('crc-first-entry-read-missing', at)
        repeat('crc-first-entry-read-repeated', at)
        for name, arg, value, result in (
                ('wrong-bytes', 1, quoted_bytes(C.application_bytes(mode)['app/main.py']), None),
                ('missing-ellipsis', 1, parsed(lines[at])[1][1].removesuffix('...'), None),
                ('short-request', 2, '256', None), ('short-result', None, None, '256')):
            replace('crc-' + name, at, changed_call(lines[at], arg, value, result))
        seek = max(i for i in range(at) if ' lseek(' in lines[i] and C.archive_for(mode) + '>' in lines[i])
        replace('crc-wrong-entry-offset', seek, changed_call(lines[seek], 1, str(record['corrupt_offset'] + 1), str(record['corrupt_offset'] + 1)))
        inject('crc-provider-before-entry-verification', at, f'openat({C.CWD}, "{library}", O_RDONLY|O_NONBLOCK|O_NOFOLLOW|O_CLOEXEC) = -1 ENOENT (No such file or directory)')
        return mutants

    lookup = ' statx(' if mode == 'missing-library' else ' openat('
    opened = next((i for i, line in enumerate(lines) if lookup in line and '"' + library + '"' in line), None)
    if opened is None:
        raise AssertionError('capture lacks selected library acquisition/absence')
    remove('library-path-check-missing', opened)
    replace('library-path-wrong-provider', opened, lines[opened].replace(C.prefix_for(mode), '/tmp/other-Python'))
    if mode == 'missing-library':
        replace('missing-library-wrong-error', opened, changed_call(lines[opened], result='-1 EACCES (Permission denied)'))
    else:
        token = parsed(lines[opened])[0][4]
        metadata = [i for i in range(opened + 1, len(lines)) if ' statx(' in lines[i] and token in lines[i]]
        for ordinal, at in enumerate(metadata[:2]):
            remove(f'library-metadata-{ordinal}-missing', at)
        if mode in ('wrong-library', 'wrong-profile'):
            at = metadata[1] + 1
            inject('size-rejection-reads-library', at, f'read({token}, "", 1) = 0')
            inject('size-rejection-seeks-library', at, f'lseek({token}, 0, SEEK_SET) = 0')
            inject('size-rejection-acquires-alias', at, f'openat({C.CWD}, "/proc/self/fd/{token.split("<")[0]}", O_RDONLY|O_CLOEXEC) = 200<{library}>')
            replace('size-rejection-admitted-size', metadata[0], lines[metadata[0]].replace(
                'stx_size=' + str(C.image_parameters(mode).observed_size), 'stx_size=' + str(C.image_parameters(mode).expected_size)))
        else:
            if not library_reads:
                raise AssertionError('capture lacks selected library hashing')
            first, eof = library_reads[0], library_reads[-1]
            remove('library-hash-first-read-missing', first)
            replace('library-hash-wrong-header', first, changed_call(lines[first], 1, '""'))
            remove('library-hash-eof-missing', eof)
            repeat('library-hash-eof-repeated', eof)
            replace('library-hash-eof-nonempty', eof, changed_call(lines[eof], 1, '"x"', '1'))
            if mode == 'corrupt-library':
                inject('hash-rejection-seeks-library', eof + 1, f'lseek({token}, 0, SEEK_SET) = 0')
                inject('hash-rejection-acquires-alias', eof + 1, f'openat({C.CWD}, "/proc/self/fd/{token.split("<")[0]}", O_RDONLY|O_CLOEXEC) = 200<{library}>')
    if mode not in C.SUCCESS:
        inject('rejection-extra-crypto-wake', publication, 'futex(0x10000000, FUTEX_WAKE_PRIVATE, 2147483647) = 0')
        inject('rejection-config-open', publication, f'openat({C.CWD}, "/dev/null", O_RDONLY) = 200</dev/null<char 1:3>>')
        inject('rejection-initialization-thread', publication, f'gettid() = {pid}')
        return mutants

    wakes = [i for i, line in enumerate(lines) if ' futex(' in line]
    if len(wakes) != 14:
        raise AssertionError('success capture lacks fourteen pinned crypto wakes')
    for ordinal, at in enumerate(wakes):
        remove(f'crypto-wake-{ordinal:02d}-missing', at)
        repeat(f'crypto-wake-{ordinal:02d}-repeated', at)
    at = wakes[0]
    address = parsed(lines[at])[1][0]
    for name, arg, value, result in (
            ('unowned-address', 0, '0x10000000', None),
            ('wrong-image-word', 0, hex(int(address, 16) + 4), None),
            ('bad-address', 0, '0xnothex', None),
            ('nonprivate', 1, 'FUTEX_WAKE', None), ('wait', 1, 'FUTEX_WAIT_PRIVATE', None),
            ('wrong-count', 2, '1', None), ('wrong-result', None, None, '1'),
            ('failed', None, None, '-1 EFAULT (Bad address)')):
        replace('crypto-' + name, at, changed_call(lines[at], arg, value, result))
    move('crypto-before-image-hash', at, library_reads[0])
    move('crypto-cleanup-before-publication', wakes[-1], publication)
    move('crypto-cleanup-before-finalization', wakes[-1], publication + 1)
    move('crypto-initialization-after-publication', wakes[12], publication + 1)
    mutants['crypto-after-exit'] = lines + [lines[wakes[-1]]]

    config = next(i for i, line in enumerate(lines) if ' openat(' in line and ', "/dev/null", O_RDONLY)' in line)
    config_token = parsed(lines[config])[0][4]
    if [parsed(lines[config + offset])[0][2] for offset in range(5)] != ['openat', 'newfstatat', 'ioctl', 'read', 'close']:
        raise AssertionError('capture lacks complete uninterrupted empty config sequence')
    for offset, name in enumerate(('open', 'metadata', 'query', 'eof', 'close')):
        remove('config-' + name + '-missing', config + offset)
        repeat('config-' + name + '-repeated', config + offset)
    for name, arg, value, result in (
            ('wrong-path', 1, '"/etc/ssl/openssl.cnf"', None),
            ('writable', 2, 'O_RDWR', None), ('extra-flags', 2, 'O_RDONLY|O_CLOEXEC', None),
            ('stdio-descriptor', None, None, '0</dev/null<char 1:3>>'),
            ('owned-descriptor', None, None, token.split('<')[0] + '</dev/null<char 1:3>>'),
            ('wrong-device', None, None, config_token.replace('char 1:3', 'char 1:5')),
            ('missing-annotation', None, None, config_token.split('<')[0]),
            ('failed', None, None, '-1 ENOENT (No such file or directory)')):
        replace('config-' + name, config, changed_call(lines[config], arg, value, result))
    for name, at, arg, value, result in (
            ('wrong-metadata', config + 1, 2, '{st_mode=S_IFREG|0444, st_size=0, ...}', None),
            ('wrong-mode', config + 1, 2, '{st_mode=S_IFCHR|0644, st_rdev=makedev(0x1, 0x3), ...}', None),
            ('metadata-without-empty-path', config + 1, 3, '0', None),
            ('successful-query', config + 2, None, None, '0'),
            ('bad-query-pointer', config + 2, 2, '0xnothex', None),
            ('wrong-query', config + 2, 1, 'TIOCSWINSZ', None),
            ('different-eof-size', config + 3, 2, '8192', None),
            ('nonempty-eof', config + 3, 1, '"x"', '1'),
            ('different-reader', config + 3, 0, token, None),
            ('wrong-close', config + 4, 0, token, None),
            ('failed-close', config + 4, None, None, '-1 EBADF (Bad file descriptor)')):
        replace('config-' + name, at, changed_call(lines[at], arg, value, result))
    inject('config-interrupted', config + 2, f'gettid() = {pid}')
    move('config-before-initialization', config, library_reads[0])
    move('config-after-publication', config, publication + 1)
    image_map = next(i for i, line in enumerate(lines) if ' mmap(' in line and library + '>' in line and ', 20423824,' in line)
    replace('image-map-writable-executable', image_map, changed_call(lines[image_map], 2, 'PROT_READ|PROT_WRITE|PROT_EXEC'))
    replace('image-map-wrong-geometry', image_map, changed_call(lines[image_map], 1, '20423825'))
    alias = next(i for i, line in enumerate(lines) if ' openat(' in line and '"/proc/self/fd/' in line)
    remove('image-alias-missing', alias)
    move('image-alias-before-verification', alias, library_reads[0])
    close = next(i for i in range(publication, len(lines)) if ' close(' in lines[i] and '/lib/python3.13/codecs.py>' in lines[i])
    remove('source-ownership-incomplete-finalization', close)
    return mutants


def audit_capture(directory, output, metadata_path=None):
    metadata_path = metadata_path or directory / 'archive-metadata.json'
    report = {'schema_version': 0, 'workload': 'python.stripped-host', 'normal_traces': 0,
              'rejected_mutations': 0, 'cases': {},
              'runtime_images': {mode: {'size': C.image_parameters(mode).expected_size,
                                       'sha256': C.image_parameters(mode).expected_sha}
                                 for mode in C.MODES}}
    for mode in C.MODES:
        record = C.retained_metadata(metadata_path, mode)
        lines = trace_lines(directory, mode)
        raw = ''.join(lines).encode('utf-8')
        C.check_lines(lines, mode, record['bytes'], record)
        for name, expected in zip(('stdout', 'stderr'), C.expected_output(mode)):
            with (directory / (mode + '.' + name + '.txt')).open('rb') as stream:
                observed = stream.read(len(expected) + 1)
            if observed != expected:
                raise AssertionError('capture output differs: ' + mode)
        with (directory / (mode + '.exit-status.txt')).open('rb') as stream:
            status = stream.read(3)
        if status != (b'0\n' if mode in C.SUCCESS else b'1\n'):
            raise AssertionError('capture process outcome differs: ' + mode)
        rejected = {}
        for name, changed in mutations(lines, mode, record).items():
            try:
                C.check_lines(changed, mode, record['bytes'], record)
            except C.TraceError as error:
                rejected[name] = str(error)
            else:
                raise AssertionError(f'{mode}: hostile mutation admitted: {name}')
        report['cases'][mode] = {'archive_sha256': record['sha256'], 'trace_bytes': len(raw),
                                 'trace_sha256': hashlib.sha256(raw).hexdigest(), 'trace_records': len(lines),
                                 'stdout_sha256': hashlib.sha256(C.expected_output(mode)[0]).hexdigest(),
                                 'stderr_sha256': hashlib.sha256(C.expected_output(mode)[1]).hexdigest(),
                                 'exit_status': 0 if mode in C.SUCCESS else 1, 'rejected_mutations': rejected}
        report['normal_traces'] += 1
        report['rejected_mutations'] += len(rejected)
    output.write_text(json.dumps(report, sort_keys=True, indent=2) + '\n')
    print(f"Actual stripped-host trace audit passed: {report['normal_traces']} normal traces; {report['rejected_mutations']} hostile mutations rejected")


class StrippedHostTraceTests(unittest.TestCase):
    def test_image_selection_is_closed_and_profile_separation_is_exact(self):
        expected = {'stripped': (C.STRIPPED_BYTES, C.STRIPPED_BYTES), 'unstripped': (C.UNSTRIPPED_BYTES, C.UNSTRIPPED_BYTES),
                    'wrong-library': (C.STRIPPED_BYTES, C.UNSTRIPPED_BYTES), 'wrong-profile': (C.UNSTRIPPED_BYTES, C.STRIPPED_BYTES)}
        for mode, sizes in expected.items():
            with self.subTest(mode=mode):
                parameters = C.image_parameters(mode)
                self.assertEqual((parameters.expected_size, parameters.observed_size), sizes)
                self.assertEqual(C.provider_contract(mode)['build_id'], C.OLD_BUILD_ID if C.original_profile(mode) else C.BUILD_ID)
                with self.assertRaises(AttributeError):
                    parameters.expected_size = 1
        self.assertEqual(C.image_parameters('corrupt-library').visible_header, bytes([C.STRIPPED_HEADER[0] ^ 1]) + C.STRIPPED_HEADER[1:])
        for mode in ('bundled', 'host', 'minimal', 'corrupt-source'):
            with self.subTest(mode=mode), self.assertRaises(C.TraceError):
                C.image_parameters(mode)

    def test_fixed_application_helpers_and_output_bind_the_real_fixture(self):
        application = C.expected_application('stripped')
        self.assertEqual(len(application), 5)
        self.assertEqual(sum(spec['size'] for spec in application.values()), 1725)
        self.assertEqual(len(C.fixed_specs()), 2)
        self.assertEqual(C.expected_output('stripped'), C.expected_output('unstripped'))
        self.assertEqual(len(C.expected_output('stripped')[0]), 70)
        with self.assertRaises(TypeError):
            C.APP_PINS['app/main.py'] = (1, '0' * 64)

    def test_archive_identity_tracks_profile_not_observed_opposite_image(self):
        with tempfile.TemporaryDirectory() as temporary:
            directory = Path(temporary)
            for mode in C.MODES:
                record = C.archive_record(archive_fixture(directory, mode), mode)
                C.validate_record(record, mode, record['bytes'])
                self.assertEqual(record['runtime_image']['size'], C.image_parameters(mode).expected_size)
                self.assertEqual('corrupt_offset' in record, mode == 'corrupt-entry')

    def test_archive_rejects_declaration_types_profiles_resources_and_payload_drift(self):
        changes = {
            'old-profile': lambda m: m['runtimes']['python'].update(build_id=C.OLD_BUILD_ID),
            'wrong-prefix': lambda m: m['runtimes']['python']['provisioning'].update(stdlib=C.UNSTRIPPED_PREFIX + '/lib/python3.13'),
            'boolean-version': lambda m: m['runtimes']['python']['abi']['version'].update(major=True),
            'debug-type': lambda m: m['runtimes']['python']['abi'].update(debug=0),
            'extra-native': lambda m: m['components']['launch'].update(native_modules=['extension']),
            'helper-digest': lambda m: m['resources']['python/archive-importer.py'].update(sha256='0' * 64),
            'entry-storage': lambda m: m['resources']['app/main.py'].update(compression='deflate'),
            'extra-field': lambda m: m.update(runtime_image={'size': C.STRIPPED_BYTES}),
        }
        with tempfile.TemporaryDirectory() as temporary:
            directory = Path(temporary)
            for name, change in changes.items():
                with self.subTest(name=name), self.assertRaises(C.TraceError):
                    C.archive_record(archive_fixture(directory, change=change), 'stripped')
            for key in ('app/main.py', 'python/archive-metadata.py'):
                with self.subTest(key=key), self.assertRaises(C.TraceError):
                    C.archive_record(archive_fixture(directory, payload_change=lambda values: values.update({key: values[key] + b'\n'})), 'stripped')

    def test_checker_graphs_are_private_and_do_not_rebind_historical_modules(self):
        original = (C.REFERENCE.COMMON.LIBRARY_BYTES, C.REFERENCE.SOURCE.LIBRARY_PREFIX, C.REFERENCE.PREFIX, C.REFERENCE.PROGRAM)
        modules = sys.modules.copy()
        with tempfile.TemporaryDirectory() as temporary:
            directory = Path(temporary)
            records = metadata_fixture(directory)['archives']
            stripped = C.Checker('stripped', records['stripped']['bytes'], records['stripped'])
            old = C.Checker('unstripped', records['unstripped']['bytes'], records['unstripped'])
            first, second = private_policy(stripped), private_policy(old)
            for name in ('COMMON', 'SOURCE', 'BASE', 'PBS', 'PRODUCT'):
                self.assertIsNot(getattr(first, name), getattr(second, name))
                self.assertIsNot(getattr(first, name), getattr(C.REFERENCE, name))
            self.assertEqual(first.COMMON.LIBRARY_BYTES, C.STRIPPED_BYTES)
            self.assertEqual(second.COMMON.LIBRARY_BYTES, C.UNSTRIPPED_BYTES)
            self.assertEqual(original, (C.REFERENCE.COMMON.LIBRARY_BYTES, C.REFERENCE.SOURCE.LIBRARY_PREFIX, C.REFERENCE.PREFIX, C.REFERENCE.PROGRAM))
            self.assertEqual(modules, sys.modules)

    def test_private_parameters_cannot_drift_between_syscalls(self):
        with tempfile.TemporaryDirectory() as temporary:
            directory = Path(temporary)
            record = C.archive_record(archive_fixture(directory), 'stripped')
            for field in ('size', 'header', 'program', 'prefix', 'tuple'):
                checker = C.Checker('stripped', record['bytes'], record)
                private = private_policy(checker)
                if field == 'size': private.COMMON.LIBRARY_BYTES = C.UNSTRIPPED_BYTES
                elif field == 'header': private.SOURCE.LIBRARY_PREFIX = C.UNSTRIPPED_HEADER
                elif field == 'program': private.PROGRAM += '-renamed'
                elif field == 'prefix': private.PREFIX = C.UNSTRIPPED_PREFIX
                else: checker.parameters = C.image_parameters('unstripped')
                with self.subTest(field=field), self.assertRaisesRegex(C.TraceError, 'private image parameters changed'):
                    checker.line('1234  gettid() = 1234')
                with self.subTest(field=field, phase='finish'), self.assertRaisesRegex(C.TraceError, 'private image parameters changed'):
                    checker.finish()

    def test_retained_records_reject_bool_sizes_observed_image_claims_and_extra_fields(self):
        with tempfile.TemporaryDirectory() as temporary:
            directory = Path(temporary)
            original = metadata_fixture(directory)
            path = directory / 'metadata.json'
            path.write_text(json.dumps(original))
            for mode in C.MODES:
                self.assertEqual(C.retained_metadata(path, mode), original['archives'][mode])
            for kind in ('schema-bool', 'unknown-mode', 'size-bool', 'image-size-bool', 'observed-image', 'image-sha',
                         'extra-field', 'provider', 'application', 'readiness', 'crc-offset-bool', 'digest-case'):
                changed = copy.deepcopy(original)
                record = changed['archives']['wrong-library']
                if kind == 'schema-bool': changed['schema_version'] = False
                elif kind == 'unknown-mode': changed['archives']['host'] = record
                elif kind == 'size-bool': record['bytes'] = True
                elif kind == 'image-size-bool': record['runtime_image']['size'] = True
                elif kind == 'observed-image': record['runtime_image'] = {'size': C.UNSTRIPPED_BYTES, 'sha256': C.UNSTRIPPED_SHA}
                elif kind == 'image-sha': record['runtime_image']['sha256'] = '0' * 64
                elif kind == 'extra-field': record['load_observed'] = True
                elif kind == 'provider': record['provider']['abi']['debug'] = 0
                elif kind == 'application': record['application']['app/main.py']['sha256'] = '0' * 64
                elif kind == 'readiness': record['readiness']['archive_cursor'] = 64
                elif kind == 'crc-offset-bool': changed['archives']['corrupt-entry']['corrupt_offset'] = True
                else: record['sha256'] = record['sha256'].upper()
                path.write_text(json.dumps(changed))
                mode = 'corrupt-entry' if kind == 'crc-offset-bool' else 'wrong-library'
                with self.subTest(kind=kind), self.assertRaises(C.TraceError):
                    C.retained_metadata(path, mode)

    def test_retained_json_requires_unique_fields_finite_values_and_bounded_bytes(self):
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / 'metadata.json'
            for payload in (b'{"schema_version":0,"schema_version":0,"archives":{}}',
                            b'{"schema_version":NaN,"archives":{}}', b' ' * (256 * 1024 + 1)):
                path.write_bytes(payload)
                with self.subTest(size=len(payload)), self.assertRaises(C.TraceError):
                    C.retained_metadata(path, 'stripped')

    def test_crc_rejection_observes_one_full_entry_and_no_provider_initialization(self):
        with tempfile.TemporaryDirectory() as temporary:
            lines, record = rejection_trace(archive_fixture(Path(temporary), 'corrupt-entry'))
            C.check_lines(lines, 'corrupt-entry', record['bytes'], record)
            for name, changed in mutations(lines, 'corrupt-entry', record).items():
                with self.subTest(name=name), self.assertRaises(C.TraceError):
                    C.check_lines(changed, 'corrupt-entry', record['bytes'], record)

    def test_rejection_decoder_rejects_partial_lines_crlf_malformed_pid_and_gzip_truncation(self):
        with tempfile.TemporaryDirectory() as temporary:
            lines, record = rejection_trace(archive_fixture(Path(temporary), 'corrupt-entry'))
            raw = ''.join(lines).encode()
            for payload in (raw, gzip.compress(raw)):
                stream = io.BytesIO(payload) if payload is raw else gzip.GzipFile(fileobj=io.BytesIO(payload))
                with stream:
                    C.check_lines((line.decode() for line in stream), 'corrupt-entry', record['bytes'], record)
            for changed in (lines[:-1], lines[:-1] + [lines[-1].rstrip('\n')],
                            [lines[0].replace('\n', '\r\n')] + lines[1:],
                            ['9999' + lines[0][4:]] + lines[1:]):
                with self.subTest(first=changed[0][:20]), self.assertRaises(C.TraceError):
                    C.check_lines(changed, 'corrupt-entry', record['bytes'], record)
            with self.assertRaises((EOFError, OSError)):
                with gzip.GzipFile(fileobj=io.BytesIO(gzip.compress(raw)[:-8])) as stream:
                    C.check_lines((line.decode() for line in stream), 'corrupt-entry', record['bytes'], record)

    def test_cli_checks_raw_and_gzip_with_independent_archive_and_exact_output(self):
        with tempfile.TemporaryDirectory() as temporary:
            directory = Path(temporary)
            metadata = metadata_fixture(directory)
            archive = directory / 'corrupt-entry.glue'
            lines, record = rejection_trace(archive)
            metadata['archives']['corrupt-entry'] = record
            path = directory / 'metadata.json'
            path.write_text(json.dumps(metadata))
            stdout, stderr = directory / 'stdout.txt', directory / 'stderr.txt'
            stdout.write_bytes(b'')
            stderr.write_bytes(C.expected_output('corrupt-entry')[1])
            raw = ''.join(lines).encode()
            for filename, payload in (('trace.txt', raw), ('trace.txt.gz', gzip.compress(raw))):
                trace = directory / filename
                trace.write_bytes(payload)
                command = [sys.executable, '-I', '-S', '-B', C.__file__, str(trace), '--mode', 'corrupt-entry',
                           '--metadata-file', str(path), '--stdout-file', str(stdout), '--stderr-file', str(stderr), '--archive-file', str(archive)]
                result = subprocess.run(command, capture_output=True)
                self.assertEqual(result.returncode, 0, result.stderr.decode())
                stderr.write_bytes(C.expected_output('corrupt-entry')[1] + b'X')
                result = subprocess.run(command, capture_output=True)
                self.assertEqual(result.returncode, 1)
                self.assertIn(b'captured stdout/stderr differs', result.stderr)
                stderr.write_bytes(C.expected_output('corrupt-entry')[1])


if __name__ == '__main__':
    if len(sys.argv) in (4, 6) and sys.argv[1] == '--audit-capture':
        if len(sys.argv) == 6 and sys.argv[4] != '--metadata-file':
            raise SystemExit('expected --metadata-file PATH')
        audit_capture(Path(sys.argv[2]), Path(sys.argv[3]), Path(sys.argv[5]) if len(sys.argv) == 6 else None)
    else:
        unittest.main()
