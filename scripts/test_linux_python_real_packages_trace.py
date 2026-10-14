"""Independent archive/CRC boundaries and hostile actual real-package traces."""
from __future__ import annotations

from contextlib import contextmanager
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


C = load('check-linux-python-real-packages-trace.py', 'real_package_test_policy')
LEGACY = load('test_linux_python_metadata_trace.py', 'real_package_private_metadata_tests')
LEGACY.C = C
ROOT = Path(__file__).resolve().parents[1]


@contextmanager
def synthetic_inventory(directory):
    """Tiny independent archive fixtures exercise policy boundaries only.

    These are parser/closed-rejection unit inputs, never native package evidence.
    Production policy identities remain pinned to the complete real corpus.
    """
    entry = b'raise AssertionError("unit entry must not execute")\n'
    files = {'app/main.py': entry,
             'app/python/corpus-1.dist-info/METADATA': b'Metadata-Version: 2.3\nName: Corpus\nVersion: 1\n',
             'app/python/corpus-1.dist-info/RECORD': b'corpus-1.dist-info/METADATA,,\ncorpus-1.dist-info/RECORD,,\n'}
    inventory = json.dumps({'schema_version': 0, 'files': {
        key: {'size': len(value), 'sha256': hashlib.sha256(value).hexdigest()}
        for key, value in files.items()}}, sort_keys=True).encode()
    output = b'glue python real packages unit fixture\n'
    (directory / 'application/app').mkdir(parents=True)
    (directory / 'application/app/main.py').write_bytes(entry)
    (directory / 'expected-inventory.json').write_bytes(inventory)
    (directory / 'expected.stdout.txt').write_bytes(output)
    names = ('FIXTURE', 'INVENTORY_SHA256', 'APP_SHA256', 'OUTPUT_SHA256', 'INVENTORY_FILES', 'INVENTORY_BYTES')
    previous = tuple(getattr(C, name) for name in names)
    for name, value in zip(names, (directory, hashlib.sha256(inventory).hexdigest(),
                                  hashlib.sha256(entry).hexdigest(), hashlib.sha256(output).hexdigest(),
                                  len(files), sum(map(len, files.values())))):
        setattr(C, name, value)
    try:
        yield files
    finally:
        for name, value in zip(names, previous):
            setattr(C, name, value)


def archive_fixture(directory, files, mode='host', change=None):
    payloads = files | {
        'python/archive-importer.py': (ROOT / 'fixtures/python-imports/bootstrap.py').read_bytes(),
        'python/archive-metadata.py': (ROOT / 'fixtures/python-metadata/bootstrap.py').read_bytes()}
    resources = {key: {'size': len(value), 'sha256': hashlib.sha256(value).hexdigest(),
                       'compression': 'deflate' if key.startswith('python/') else 'stored'}
                 for key, value in payloads.items()}
    manifest = {'schema_version': 0, 'app_id': 'python.real-packages', 'entrypoint': 'launch',
                'components': {'launch': {'entry_point': 'app/main.py', 'runtime': 'python', 'native_modules': []}},
                'runtimes': {'python': C.provider_contract(mode)}, 'targets': {'linux-arm64': copy.deepcopy(C.TARGET)},
                'native_modules': {}, 'host_imports': {}, 'resources': resources}
    if change:
        change(manifest)
    raw = json.dumps(manifest, sort_keys=True, separators=(',', ':'), ensure_ascii=False).encode()
    output = io.BytesIO()
    with zipfile.ZipFile(output, 'w') as archive:
        for name, data in payloads.items():
            archive.writestr(name, data, compress_type=zipfile.ZIP_DEFLATED if name.startswith('python/') else zipfile.ZIP_STORED)
    locator = b'GLUERS00' + b'\0' * 8 + struct.pack('<QQ', len(raw), len(output.getvalue())) + hashlib.sha256(raw).digest()
    path = directory / (mode + '.glue')
    path.write_bytes(locator + raw + output.getvalue())
    if C.rejected(mode):
        with zipfile.ZipFile(path) as archive:
            info = archive.getinfo('app/main.py')
        data = bytearray(path.read_bytes())
        names, extra = struct.unpack_from('<HH', data, info.header_offset + 26)
        data[info.header_offset + 30 + names + extra] ^= 1
        path.write_bytes(data)
    return path


def quoted_bytes(data):
    return json.dumps(data[:256].decode('latin1')) + ('...' if len(data) > 256 else '')


def rejection_trace(path, mode):
    record = C.archive_record(path, mode)
    raw = path.read_bytes()
    token = '3<' + C.archive_for(mode) + '>'
    lines = [f'execve({json.dumps(C.PROGRAM)}, {json.dumps([C.PROGRAM, "run", C.archive_for(mode)])}, 0x1234 /* 18 vars */) = 0',
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
    lines.append('uname({sysname="Linux", nodename="real-package-unit-tests", ...}) = 0')
    read(record['corrupt_offset'], len(C.corrupt_bytes()))
    lines.append(f'close({token}) = 0')
    message = C.expected_output(mode)[1]
    lines.extend([f'write(2</evidence/{mode}.stderr.txt>, {json.dumps(message.decode())}, {len(message)}) = {len(message)}',
                  'exit_group(1) = ?', '+++ exited with 1 +++'])
    return lines, record


def check(lines, mode, record):
    C.check_lines((f'1234  {line}\n' for line in lines), mode, record['bytes'], record)


def trace_lines(directory, mode):
    path = directory / (mode + '.trace.txt')
    if not path.exists():
        path = path.with_suffix('.txt.gz')
    with (gzip.open if path.suffix == '.gz' else open)(path, 'rt', encoding='utf-8') as stream:
        return stream.readlines()


def changed_call(line, argument=None, value=None, result=None):
    """Change one parsed actual syscall without manufacturing checker state."""
    match = C.BASE.LINE.fullmatch(line.rstrip('\n'))
    args = C.BASE.split_arguments(match[3])
    if argument is not None:
        args[argument] = value
    return f'{match[1]}  {match[2]}({", ".join(args)}) = {match[4] if result is None else result}\n'


def corpus_observation_mutations(lines, mode):
    """Closed argparse/parser boundary controls over complete native traces."""
    mutants = {}
    pid = lines[0].split()[0]
    publication = next(i for i, line in enumerate(lines) if LEGACY.re_search_stdio(line))
    poll = next(i for i, line in enumerate(lines) if ' ppoll(' in line)
    changed = lines.copy()
    changed[poll] = changed[poll].replace('/evidence/', '/tmp/')
    mutants['real-package-poll-wrong-owner'] = changed
    changed = lines.copy()
    changed[poll] = changed_call(changed[poll], result='1')
    mutants['real-package-poll-wrong-result'] = changed
    if C.rejected(mode):
        call = f'{pid}  ioctl(1</evidence/{mode}.stdout.txt>, TIOCGWINSZ, 0x1234) = -1 ENOTTY (Inappropriate ioctl for device)\n'
        mutants['real-package-rejection-terminal-query'] = lines[:publication] + [call] + lines[publication:]
        return mutants
    queries = [i for i, line in enumerate(lines) if ' ioctl(' in line and ', TIOCGWINSZ,' in line]
    if len(queries) != 5:
        raise AssertionError(f'{mode}: capture lacks five independent argparse queries')
    at = queries[0]
    mutants['real-package-terminal-missing'] = lines[:at] + lines[at + 1:]
    mutants['real-package-terminal-repeated'] = lines[:at] + [lines[at]] + lines[at:]
    for name, replacement in (
            ('stderr-owner', changed_call(lines[at], 0, f'2</evidence/{mode}.stderr.txt>')),
            ('wrong-owner', lines[at].replace('/evidence/', '/tmp/')),
            ('successful', changed_call(lines[at], result='0')),
            ('pointer', changed_call(lines[at], 2, '0xnothex')),
            ('request', changed_call(lines[at], 1, 'TIOCSWINSZ'))):
        changed = lines.copy()
        changed[at] = replacement
        mutants['real-package-terminal-' + name] = changed
    threads = [i for i, line in enumerate(lines) if ' gettid(' in line]
    if len(threads) != 2:
        raise AssertionError(f'{mode}: capture lacks the two stock thread boundaries')
    changed = lines.copy()
    call = changed.pop(at)
    changed.insert(threads[-1], call)
    mutants['real-package-terminal-before-initialization'] = changed
    changed = lines.copy()
    call = changed.pop(at)
    changed.insert(publication, call)
    mutants['real-package-terminal-after-publication'] = changed
    mutants['real-package-terminal-after-exit'] = lines + [lines[at]]
    if mode != 'install-host':
        return mutants
    at = next(i for i, line in enumerate(lines) if ' mremap(' in line and ', 282624, 565248,' in line)
    match = C.BASE.LINE.fullmatch(lines[at].rstrip('\n'))
    args = C.BASE.split_arguments(match[3])
    owner, destination = args[0], match[4]
    allocation = max(i for i in range(at) if ' mmap(NULL, 282624,' in lines[i])
    release = next(i for i in range(at + 1, len(lines)) if f' munmap({destination}, 565248)' in lines[i])
    image = next(C.BASE.split_arguments(C.BASE.LINE.fullmatch(line.rstrip('\n'))[3])[0]
                 for line in lines if ' mmap(' in line and ', 20423824,' in line)
    mutants['real-package-remap-missing'] = lines[:at] + lines[at + 1:]
    mutants['real-package-remap-repeated'] = lines[:at] + [lines[at]] + lines[at:]
    for name, argument, value, result in (
            ('unowned', 0, '0x10000000', None),
            ('source-unaligned', 0, hex(int(owner, 16) + 1), None),
            ('source-overflow', 0, '0xfffffffffffff000', None),
            ('old-size', 1, '278528', None),
            ('new-size', 2, '569344', None),
            ('flags', 3, 'MREMAP_MAYMOVE|MREMAP_FIXED', None),
            ('failed', None, None, '-1 ENOMEM (Cannot allocate memory)'),
            ('destination-unaligned', None, None, hex(int(destination, 16) + 1)),
            ('destination-overflow', None, None, '0xfffffffffffff000'),
            ('destination-image', None, None, image)):
        changed = lines.copy()
        changed[at] = changed_call(lines[at], argument, value, result)
        mutants['real-package-remap-' + name] = changed
    changed = lines.copy()
    changed[allocation] = changed_call(lines[allocation], 2, 'PROT_READ')
    mutants['real-package-remap-owner-not-writable'] = changed
    for name, call in (
            ('owner-released', f'munmap({owner}, 282624) = 0'),
            ('owner-protected', f'mprotect({owner}, 282624, PROT_READ) = 0')):
        mutants['real-package-remap-' + name] = lines[:at] + [pid + '  ' + call + '\n'] + lines[at:]
    other = next(C.BASE.LINE.fullmatch(lines[i].rstrip('\n'))[4] for i in range(at - 1, 0, -1)
                 if ' mmap(NULL, 565248, PROT_READ|PROT_WRITE, MAP_PRIVATE|MAP_ANONYMOUS,' in lines[i])
    changed = lines.copy()
    changed[at] = changed_call(lines[at], result=other)
    mutants['real-package-remap-destination-other-live-owner'] = changed
    changed = lines.copy()
    call = changed.pop(at)
    changed.insert(threads[-1], call)
    mutants['real-package-remap-before-initialization'] = changed
    changed = lines.copy()
    call = changed.pop(at)
    changed.insert(queries[0], call)
    mutants['real-package-remap-after-terminal-query'] = changed
    mutants['real-package-remap-release-missing'] = lines[:release] + lines[release + 1:]
    mutants['real-package-remap-release-repeated'] = lines[:release] + [lines[release]] + lines[release:]
    changed = lines.copy()
    changed[release] = changed_call(lines[release], 1, '282624')
    mutants['real-package-remap-release-partial'] = changed
    mutants['real-package-remap-result-protected'] = lines[:release] + [
        f'{pid}  mprotect({destination}, 565248, PROT_READ) = 0\n'] + lines[release:]
    return mutants


def audit_capture(directory, output):
    LEGACY.audit_capture(directory, output)
    report = json.loads(output.read_text())
    records = json.loads((directory / 'source-metadata.json').read_text())['archives']
    for mode in C.MODES:
        record = C.retained_metadata(directory / 'source-metadata.json', mode, records[mode]['bytes'])
        lines = trace_lines(directory, mode)
        pid = lines[0].split()[0]
        publication = next(i for i, line in enumerate(lines) if ' write(1</evidence/' in line or ' write(2</evidence/' in line)
        profile = C.profile_for(mode)
        prefix = '/build-target/' + ('install' if profile == 'install-host' else 'host') + ' Python metadata'
        calls = {
            'real-package-physical-metadata': f'openat({C.CWD}, "{prefix}/lib/python3.13/site-packages/markdown_it_py-999.dist-info/METADATA", O_RDONLY|O_CLOEXEC) = -1 ENOENT (No such file or directory)',
            'real-package-physical-source': f'openat({C.CWD}, "{prefix}/lib/python3.13/site-packages/markdown_it/main.py", O_RDONLY|O_CLOEXEC) = -1 ENOENT (No such file or directory)',
            'real-package-license-extraction': f'openat({C.CWD}, "/tmp/LICENSE", O_WRONLY|O_CREAT|O_TRUNC, 0600) = -1 EACCES (Permission denied)',
        }
        mutants = {name: lines[:publication] + [pid + '  ' + call + '\n'] + lines[publication:]
                   for name, call in calls.items()}
        mutants.update(corpus_observation_mutations(lines, mode))
        if C.rejected(mode):
            at = next(i for i, line in enumerate(lines) if ' read(' in line and
                      f', {len(C.corrupt_bytes())}) = {len(C.corrupt_bytes())}' in line and
                      C.archive_for(mode) + '>' in line)
            mutants['real-package-duplicate-entry-read'] = lines[:at] + [lines[at]] + lines[at:]
            changed = lines.copy()
            match = C.BASE.LINE.fullmatch(lines[at].rstrip('\n'))
            args = C.BASE.split_arguments(match[3])
            args[1] = quoted_bytes(C.application_bytes(mode)[C.CORRUPT_KEY])
            changed[at] = f'{pid}  read({", ".join(args)}) = {len(C.corrupt_bytes())}\n'
            mutants['real-package-wrong-corrupt-entry-bytes'] = changed
            seek = max(i for i in range(at) if ' lseek(' in lines[i] and C.archive_for(mode) + '>' in lines[i])
            changed = lines.copy()
            offset = record['corrupt_offset']
            changed[seek] = changed[seek].replace(f', {offset}, SEEK_SET) = {offset}', f', {offset + 1}, SEEK_SET) = {offset + 1}')
            mutants['real-package-wrong-first-entry-offset'] = changed
            actual_args = C.BASE.split_arguments(C.BASE.LINE.fullmatch(lines[at].rstrip('\n'))[3])
            for name, argument, value, result in (
                    ('missing-ellipsis', 1, actual_args[1].removesuffix('...'), None),
                    ('short-request', 2, '256', None),
                    ('short-result', None, None, '256')):
                changed = lines.copy()
                changed[at] = changed_call(lines[at], argument, value, result)
                mutants['real-package-entry-' + name] = changed
        for name, changed in mutants.items():
            try:
                C.check_lines(changed, mode, record['bytes'], record)
            except C.TraceError:
                continue
            raise AssertionError(f'{mode}: hostile real-package mutation admitted: {name}')
        report['cases'][mode]['rejected_mutations'].extend(sorted(mutants))
        report['cases'][mode]['rejected_mutations'].sort()
        report['rejected_mutations'] += len(mutants)
    report['workload'] = 'python.real-packages'
    report['fixture_identities'] = {'application_sha256': C.APP_SHA256,
                                    'normalized_inventory_sha256': C.INVENTORY_SHA256,
                                    'expected_stdout_sha256': C.OUTPUT_SHA256}
    output.write_text(json.dumps(report, sort_keys=True, indent=2) + '\n')
    print(f"Actual real-package trace audit passed: {report['normal_traces']} normal traces; {report['rejected_mutations']} hostile mutations rejected")


class RealPackageTraceTests(unittest.TestCase):
    def test_visible_entry_prefix_requires_exact_bytes_and_length_driven_ellipsis(self):
        for data in (b'entry', b'entry\n' * 100):
            C.fixed_visible_payload(quoted_bytes(data), data)
            for token in (quoted_bytes(b'X' + data[1:]), quoted_bytes(data) + '...',
                          '0x1234', quoted_bytes(data[:-1]) if len(data) <= 256 else quoted_bytes(data).removesuffix('...')):
                with self.subTest(size=len(data), token=token[:20]), self.assertRaises(C.TraceError):
                    C.fixed_visible_payload(token, data)

    def test_terminal_boundary_preserves_initialization_and_exact_failed_stdout_queries(self):
        # This isolated predicate test supplies readiness explicitly. Actual
        # native ordering/closure is independently replayed by --audit-capture.
        with tempfile.TemporaryDirectory() as temporary:
            directory = Path(temporary)
            with synthetic_inventory(directory) as files:
                record = C.archive_record(archive_fixture(directory, files), 'host')
                runtime = C.Checker('host', record['bytes'], record).checker
                token = '1</evidence/host.stdout.txt>'
                args = [token, 'TIOCGWINSZ', '0x1234']
                failure = '-1 ENOTTY (Inappropriate ioctl for device)'
                with self.assertRaises(C.TraceError):
                    runtime.call('ioctl', args, failure)
                runtime.runtime_ready = lambda: True
                for changed, result in (([token, 'TIOCGWINSZ', 'garbage'], failure),
                                        (['2</evidence/host.stderr.txt>', 'TIOCGWINSZ', '0x1234'], failure),
                                        (['1</tmp/host.stdout.txt>', 'TIOCGWINSZ', '0x1234'], failure),
                                        (args, '0')):
                    with self.subTest(args=changed, result=result), self.assertRaises(C.TraceError):
                        runtime.call('ioctl', changed, result)
                for _ in range(5):
                    runtime.call('ioctl', args, failure)
                self.assertEqual(runtime.terminal_queries, 5)
                with self.assertRaises(C.TraceError):
                    runtime.call('ioctl', args, failure)
                runtime.terminal_queries = 0
                runtime.output[0].extend(b'published')
                with self.assertRaises(C.TraceError):
                    runtime.call('ioctl', args, failure)

    def test_parser_allocation_requires_fresh_writable_owner_and_complete_release(self):
        # Readiness is a boundary input here, never a claimed native result.
        # Fresh mmap/owner/remap/release bookkeeping runs through real methods.
        with tempfile.TemporaryDirectory() as temporary:
            directory = Path(temporary)
            with synthetic_inventory(directory) as files:
                record = C.archive_record(archive_fixture(directory, files, 'install-host'), 'install-host')
                def initialized():
                    runtime = C.Checker('install-host', record['bytes'], record).checker
                    runtime.execs, runtime.remaps, runtime.image_base = 1, 4, 0x10000000
                    runtime.reservation = runtime.image_base
                    runtime.runtime_ready = lambda: True
                    runtime.memory('mmap', ['NULL', '282624', 'PROT_READ|PROT_WRITE', 'MAP_PRIVATE|MAP_ANONYMOUS', '-1', '0'], '0x50000000')
                    return runtime
                args = ['0x50000000', '282624', '565248', 'MREMAP_MAYMOVE']
                for kind in ('unowned', 'protected', 'released', 'uninitialized', 'unaligned', 'overflow', 'image', 'other-owner', 'flags', 'failed'):
                    runtime = initialized()
                    changed, result = args.copy(), '0x60000000'
                    if kind == 'unowned': changed[0] = '0x40000000'
                    elif kind == 'protected': runtime.memory('mprotect', ['0x50000000', '282624', 'PROT_READ'], '0')
                    elif kind == 'released': runtime.memory('munmap', ['0x50000000', '282624'], '0')
                    elif kind == 'uninitialized': runtime.runtime_ready = lambda: False
                    elif kind == 'unaligned': result = '0x60000001'
                    elif kind == 'overflow': result = '0xfffffffffffff000'
                    elif kind == 'image': result = '0x10000000'
                    elif kind == 'other-owner': runtime.anonymous[0x60000000] = 1048576
                    elif kind == 'flags': changed[3] = 'MREMAP_MAYMOVE|MREMAP_FIXED'
                    else: result = '-1 ENOMEM (Cannot allocate memory)'
                    with self.subTest(kind=kind), self.assertRaises(C.TraceError):
                        runtime.memory('mremap', changed, result)
                runtime = initialized()
                runtime.memory('mremap', args, '0x60000000')
                self.assertEqual((runtime.remaps, runtime.corpus_remaps), (4, 1))
                with self.assertRaises(C.TraceError):
                    runtime.call('ioctl', ['1</evidence/install-host.stdout.txt>', 'TIOCGWINSZ', '0x1234'], '-1 ENOTTY (Inappropriate ioctl for device)')
                with self.assertRaises(C.TraceError):
                    runtime.memory('munmap', ['0x60000000', '282624'], '0')
                runtime.memory('munmap', ['0x60000000', '565248'], '0')
                self.assertTrue(runtime.corpus_released)
                with self.assertRaises(C.TraceError):
                    runtime.memory('munmap', ['0x60000000', '565248'], '0')

    def test_production_corpus_pins_bind_complete_real_inventory_entry_and_output(self):
        specs = C.expected_application('host')
        self.assertEqual(len(specs), 152)
        self.assertEqual(sum(value['size'] for value in specs.values()), 451195)
        self.assertEqual(min(specs), 'app/main.py')
        self.assertEqual(specs['app/main.py']['size'], 10607)
        self.assertEqual(len(C.expected_output('host')[0]), 129)
        folders = {path.split('/')[2] for path in specs if path.startswith('app/python/')
                   and path.split('/')[2].endswith('.dist-info')}
        self.assertEqual(folders, {'markdown_it_py-4.2.0.dist-info', 'mdit_py_plugins-0.6.1.dist-info', 'mdurl-0.1.2.dist-info'})
        self.assertTrue(any(path.endswith('/licenses/LICENSE') for path in specs))
        self.assertTrue(any(path.endswith('/py.typed') for path in specs))
        self.assertFalse(any('__pycache__' in path or path.endswith('.pyc') for path in specs))

    def test_workload_inventory_and_internal_aliases_are_closed(self):
        self.assertEqual(len(C.MODES), 6)
        for mode in C.MODES:
            self.assertEqual(C.external_mode(C.internal_mode(mode)), mode)
        for old in ('host-corrupt-metadata', 'host-bad-record', 'minimal', 'resources'):
            with self.assertRaises(C.TraceError):
                C.profile_for(old)

    def test_fixed_inventory_identity_rejects_source_drift(self):
        with tempfile.TemporaryDirectory() as temporary:
            directory = Path(temporary)
            with synthetic_inventory(directory):
                self.assertEqual(len(C.expected_application('host')), 3)
                entry = directory / 'application/app/main.py'
                entry.write_bytes(entry.read_bytes() + b'\n')
                with self.assertRaises(C.TraceError):
                    C.expected_application('host')

    def test_normalized_inventory_semantics_require_exact_types_paths_and_budgets(self):
        with tempfile.TemporaryDirectory() as temporary:
            directory = Path(temporary)
            with synthetic_inventory(directory):
                path = directory / 'expected-inventory.json'
                original = json.loads(path.read_bytes())
                for kind in ('type', 'path', 'entry', 'first-read', 'budget'):
                    changed = copy.deepcopy(original)
                    if kind == 'type':
                        changed['files']['app/main.py']['size'] = True
                    elif kind == 'path':
                        changed['files']['app/../escape'] = changed['files'].pop('app/main.py')
                    elif kind == 'entry':
                        changed['files']['app/main.py']['sha256'] = '0' * 64
                    elif kind == 'first-read':
                        changed['files']['app/before-entry.txt'] = {'size': 0, 'sha256': hashlib.sha256(b'').hexdigest()}
                    else:
                        for index in range(3):
                            changed['files'][f'app/data-{index}.txt'] = {'size': 4 * 1024 * 1024, 'sha256': '0' * 64}
                    raw = json.dumps(changed).encode()
                    path.write_bytes(raw)
                    C.INVENTORY_SHA256 = hashlib.sha256(raw).hexdigest()
                    with self.subTest(kind=kind), self.assertRaises(C.TraceError):
                        C.expected_application('host')

    def test_host_archive_helpers_and_entry_bytes_are_independently_verified(self):
        with tempfile.TemporaryDirectory() as temporary:
            directory = Path(temporary)
            with synthetic_inventory(directory) as files:
                for mode in ('host', 'install-host', 'host-corrupt-entry', 'install-host-corrupt-entry'):
                    record = C.archive_record(archive_fixture(directory, files, mode), mode)
                    self.assertEqual(record['app_id'], 'python.real-packages')
                    self.assertEqual('corrupt_offset' in record, C.rejected(mode))
                for change in (lambda value: value.update(app_id='distribution.metadata'),
                               lambda value: value['resources']['python/archive-importer.py'].update(sha256='0' * 64),
                               lambda value: value['resources']['app/main.py'].update(compression='deflate')):
                    with self.assertRaises(C.TraceError):
                        C.archive_record(archive_fixture(directory, files, change=change), 'host')

    def test_crc_rejection_is_one_entry_read_before_any_provider(self):
        with tempfile.TemporaryDirectory() as temporary:
            directory = Path(temporary)
            with synthetic_inventory(directory) as files:
                for mode in ('host-corrupt-entry', 'install-host-corrupt-entry'):
                    lines, record = rejection_trace(archive_fixture(directory, files, mode), mode)
                    check(lines, mode, record)
                    for at, line in enumerate(lines):
                        if line.startswith(('read(', 'uname(', 'close(')):
                            with self.subTest(mode=mode, line=at), self.assertRaises(C.TraceError):
                                check(lines[:at] + lines[at + 1:], mode, record)
                    entry_read = next(i for i, line in enumerate(lines) if line.startswith('read(') and
                                      line.endswith(f', {len(C.corrupt_bytes())}) = {len(C.corrupt_bytes())}'))
                    with self.assertRaises(C.TraceError):
                        check(lines[:entry_read] + [lines[entry_read]] + lines[entry_read:], mode, record)

    def test_retained_metadata_requires_exact_inventory_types_and_offset(self):
        with tempfile.TemporaryDirectory() as temporary:
            directory = Path(temporary)
            with synthetic_inventory(directory) as files:
                records = {}
                for mode in C.MODES:
                    if C.profile_for(mode) == 'bundled':
                        size, length, central = 80 * 1024 * 1024, 400000, 80 * 1024 * 1024 - 400000
                        record = {'bytes': size, 'sha256': 'a' * 64, 'manifest_sha256': 'b' * 64,
                                  'manifest_bytes': length, 'zip_directory_offset': central,
                                  'app_id': 'python.real-packages', 'entry': 'app/main.py', 'component': 'launch',
                                  'provider': C.provider_contract(mode), 'target': copy.deepcopy(C.TARGET),
                                  'application': C.expected_application(mode),
                                  'readiness': {'archive_read_bytes': 800064, 'archive_cursor': central - 1, 'ranges_sha256': 'c' * 64}}
                        if C.rejected(mode):
                            record['corrupt_offset'] = 500000
                    else:
                        record = C.archive_record(archive_fixture(directory, files, mode), mode)
                    records[mode] = record
                original = {'schema_version': 0, 'archives': records}
                path = directory / 'metadata.json'
                path.write_text(json.dumps(original))
                for mode in C.MODES:
                    self.assertEqual(C.retained_metadata(path, mode, records[mode]['bytes']), records[mode])
                for kind in ('old-mode', 'bytes-type', 'abi-type', 'application', 'offset-type', 'readiness'):
                    changed = copy.deepcopy(original)
                    mode = 'host-corrupt-entry'
                    record = changed['archives'][mode]
                    if kind == 'old-mode':
                        changed['archives']['host-corrupt-metadata'] = record
                    elif kind == 'bytes-type':
                        record['bytes'] = True
                    elif kind == 'abi-type':
                        record['provider']['abi']['debug'] = 0
                    elif kind == 'application':
                        record['application']['app/main.py']['sha256'] = '0' * 64
                    elif kind == 'offset-type':
                        record['corrupt_offset'] = True
                    else:
                        record['readiness']['archive_cursor'] = 64
                    path.write_text(json.dumps(changed))
                    with self.subTest(kind=kind), self.assertRaises(C.TraceError):
                        C.retained_metadata(path, mode, records[mode]['bytes'])

    def test_crc_rejection_denies_image_source_process_network_and_payload_writes(self):
        with tempfile.TemporaryDirectory() as temporary:
            directory = Path(temporary)
            with synthetic_inventory(directory) as files:
                mode = 'host-corrupt-entry'
                lines, record = rejection_trace(archive_fixture(directory, files, mode), mode)
                calls = [f'openat({C.CWD}, "/tmp/package.py", O_RDONLY|O_CLOEXEC) = -1 ENOENT (No such file or directory)',
                         f'openat({C.CWD}, "/tmp", O_RDWR|O_TMPFILE, 0600) = -1 EACCES (Permission denied)',
                         'unlink("/tmp/package") = -1 ENOENT (No such file or directory)',
                         'memfd_create("fallback", MFD_CLOEXEC|MFD_ALLOW_SEALING) = -1 ENOSYS (Function not implemented)',
                         'clone3({}, 64) = -1 ENOSYS (Function not implemented)',
                         'execve("/bin/sh", ["sh"], NULL) = -1 EACCES (Permission denied)',
                         'socket(AF_INET, SOCK_STREAM, 0) = -1 EPERM (Operation not permitted)']
                for call in calls:
                    with self.subTest(call=call), self.assertRaises(C.TraceError):
                        check(lines[:-3] + [call] + lines[-3:], mode, record)

    def test_raw_gzip_cli_replays_exact_crc_and_rejects_truncated_gzip(self):
        # CLI uses production pin identities. Standalone synthetic tests exercise
        # the same stream decoder directly, without passing mutable pin options.
        with tempfile.TemporaryDirectory() as temporary:
            directory = Path(temporary)
            with synthetic_inventory(directory) as files:
                mode = 'host-corrupt-entry'
                lines, record = rejection_trace(archive_fixture(directory, files, mode), mode)
                raw = ''.join(f'1234  {line}\n' for line in lines).encode()
                for payload in (raw, gzip.compress(raw)):
                    stream = io.BytesIO(payload) if payload is raw else gzip.GzipFile(fileobj=io.BytesIO(payload))
                    with stream:
                        C.check_lines((line.decode() for line in stream), mode, record['bytes'], record)
                with self.assertRaises((EOFError, OSError)):
                    with gzip.GzipFile(fileobj=io.BytesIO(gzip.compress(raw)[:-8])) as stream:
                        C.check_lines((line.decode() for line in stream), mode, record['bytes'], record)


if __name__ == '__main__':
    if len(sys.argv) == 4 and sys.argv[1] == '--audit-capture':
        audit_capture(Path(sys.argv[2]), Path(sys.argv[3]))
    else:
        unittest.main()
