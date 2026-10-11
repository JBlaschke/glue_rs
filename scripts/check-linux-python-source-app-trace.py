#!/usr/bin/env python3
"""Strict complete traces for six arbitrary bundled source-app workloads.

These are concrete evidence workloads, not a policy for arbitrary Python code.
The unchanged parser, OS reads and sealed stock-image admission are reused in
private instances. Workload entropy/thread counts, entry outcomes, metadata
readiness and selected-image memory lifetime belong to this separate policy.
"""
from __future__ import annotations

import argparse
import gzip
import hashlib
import json
from pathlib import Path
import re
import struct
import sys
import zipfile
import importlib.util

SPEC = importlib.util.spec_from_file_location('source_product_policy', Path(__file__).with_name('check-linux-python-runner-trace.py'))
PRODUCT = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(PRODUCT)
BASE, PBS, TraceError = PRODUCT.BASE, PRODUCT.PBS, PRODUCT.TraceError
DIRECTORY = '/build-target/relocated Python source apps'
PROGRAM = DIRECTORY + '/glue'
MODES = ('minimal', 'resources', 'app-error', 'syntax', 'nul', 'corrupt-source')
OUTPUTS = {
    'minimal': (b'PASS source-app=minimal entry=launch.py answer=42\n', b''),
    'resources': (b'PASS source-app=resources packages=archive namespaces=archive resources=streams answer=42\n', b''),
    'app-error': (b'', b'glue: intentional source application error\n'),
    'syntax': (b'', b'glue: invalid syntax (invalid.py, line 1)\n'),
    'nul': (b'', b'glue: source code string cannot contain null bytes (embedded-nul.py)\n'),
    'corrupt-source': (b'', b'glue: resource "app/python/simple_value.py" failed CRC32 verification\n'),
}
IDENTITIES = {
    'minimal': ('minimal.source', 'app/launch.py', 'launch'),
    'resources': ('daily.report', "app/tasks/report's [daily].py", 'report'),
    'app-error': ('failing.source', 'app/jobs/fail.py', 'fail'),
    'syntax': ('syntax.source', 'app/jobs/invalid.py', 'syntax'),
    'nul': ('nul.source', 'app/embedded-nul.py', 'nul'),
    'corrupt-source': ('minimal.source', 'app/launch.py', 'launch'),
}
CORRUPT_KEY = 'app/python/simple_value.py'
CORRUPT_BYTES = b'`nswer = 42\n'
ROOT = Path(__file__).resolve().parents[1]
INPUTS = {'minimal': 'minimal', 'resources': 'resources', 'app-error': 'error', 'syntax': 'syntax', 'nul': 'nul', 'corrupt-source': 'minimal'}
LIBRARY_PREFIX = bytes.fromhex('7f454c460201010000000000000000000300b7000100000000000000000000004000000000000000407562040000000000000000400038000800400028002700010000000500000000000000000000000000000000000000000000000000000058fe14010000000058fe14010000000000000100000000000100000006000000c8a8150100000000c8a8150100000000c8a8150100000000d0c9190000000000c8fb2100000000000000010000000000020000000600000098ba24010000000098ba24010000000098ba240100000000500200000000000050020000000000000800000000000000040000000400000000020000000000000002000000000000')
MAX_TRACE_BYTES, MAX_LINE_CHARACTERS, MAX_RECORDS = PRODUCT.MAX_TRACE_BYTES, PRODUCT.MAX_LINE_CHARACTERS, PRODUCT.MAX_RECORDS


def expected_application(mode):
    directory = ROOT / 'fixtures/python-source-apps' / ('input-' + INPUTS[mode])
    return {path.relative_to(directory).as_posix(): {'size': path.stat().st_size, 'sha256': hashlib.sha256(path.read_bytes()).hexdigest(), 'compression': 'stored'}
            for path in sorted(directory.rglob('*')) if path.is_file()}


def typed_equal(actual, expected):
    try:
        return json.dumps(actual, sort_keys=True, separators=(',', ':'), allow_nan=False) == json.dumps(expected, sort_keys=True, separators=(',', ':'), allow_nan=False)
    except (TypeError, ValueError) as error:
        raise TraceError('metadata contains a noncanonical JSON value') from error


def provider_contract():
    pins = json.loads((ROOT / 'fixtures/python-pbs/pins.json').read_text())
    return {'abi': {'debug': False, 'gil': 'conventional', 'language': 'python', 'version': {'major': 3, 'minor': 13, 'patch': 16}},
            'build_id': 'pbs-20261009-cpython-3.13.16-pgo-lto-bundled-source-apps-v1',
            'provisioning': {'mode': 'bundled', 'provider': 'python_build_standalone', 'runtime_library': 'python/libpython3.13.so.1.0', 'stdlib': 'python/frozen.json',
                'source': {'artifact': pins['full']['filename'], 'release': pins['release'], 'revision': pins['revision'], 'sha256': pins['full']['sha256'], 'variant': 'pgo+lto-full/bundled-source-apps-v1'}},
            'required_features': [], 'target': 'linux-arm64'}


TARGET = {'abi': {'family': 'glibc', 'minimum_version': '2.36'}, 'arch': 'aarch64', 'cpu_features': [], 'minimum_os_version': '7.1.4', 'os': 'linux', 'page_sizes': [4096]}


def fixed_specs():
    pins = json.loads((ROOT / 'fixtures/python-imports/stdlib-pins.json').read_text())
    specs = {'stdlib/' + key: {'size': value['size'], 'sha256': value['sha256'], 'compression': 'deflate'} for key, value in pins['files'].items()}
    helper = (ROOT / 'fixtures/python-imports/bootstrap.py').read_bytes()
    specs.update({'python/libpython3.13.so.1.0': {'size': 73563968, 'sha256': '42be968275d5be2d9e632ec9ef6790dd2c10f1d4a710ad1028fc2b687242f219', 'compression': 'stored'},
                  'python/frozen.json': {'size': 139523, 'sha256': '6a41fc38141d45c5197adfc1b0ee740c6244ea681742c205b8aa7b8449d865d7', 'compression': 'stored'},
                  'python/archive-importer.py': {'size': len(helper), 'sha256': hashlib.sha256(helper).hexdigest(), 'compression': 'deflate'}})
    return specs


def archive_for(mode):
    if mode not in MODES:
        raise TraceError('unknown source-app workload')
    return DIRECTORY + '/' + mode + '.glue'


def expected_output(mode):
    archive_for(mode)
    return OUTPUTS[mode]


class Checker:
    def __init__(self, mode, size, record):
        self.mode, self.record = mode, record
        self.uname_queries = 0
        admission = record['manifest_bytes'], record['zip_directory_offset']
        PRODUCT.validate_readiness(record['readiness'], size, admission)
        private = PRODUCT.policy('check-linux-python-import-trace.py', 'private_source_app_runtime')
        PRODUCT.unify(private)
        private.PROGRAM = PROGRAM
        old_mode = 'success' if mode in ('minimal', 'resources') else 'corrupt-source' if mode == 'corrupt-source' else 'app-error'
        private.command_for = lambda _: [PROGRAM, 'run', archive_for(mode)]
        private.expected_output = lambda _: expected_output(mode)
        private.SUCCESS, private.APP_ERROR = expected_output(mode)
        private.CORRUPT_SOURCE, private.CORRUPT_ERROR = CORRUPT_BYTES, OUTPUTS['corrupt-source'][1]

        class Runtime(private.Checker):
            def __init__(self):
                super().__init__(old_mode, size, record.get('corrupt_offset', 4096))
                self.archive = archive_for(mode)
                self.image_base = None
                self.reservation = None
                self.trims = set()
                self.guard = self.bss = self.relro = False
                self.manifest_allocations = 0
                self.alias_header = self.alias_metadata = False

            def inherited(self, token):
                number, path, deleted = private.descriptor(token)
                expected = {0: '/dev/null', 1: f'/evidence/{mode}.stdout.txt', 2: f'/evidence/{mode}.stderr.txt'}
                if deleted or number not in expected or path != expected[number]:
                    raise TraceError('source workload inherited descriptor identity differs')
                return number

            def image_ready(self):
                return super().image_ready() and self.alias_header and self.alias_metadata and self.guard and self.bss and self.relro and self.trims == {'prefix', 'tail'}

            def runtime_ready(self):
                return (self.image_ready() and self.overcommit_reads == self.virtual_queries == self.timezone_queries == 1 and
                        self.import_entropy == self.tid_queries == 1)

            def overlaps(self, start, length):
                return self.image_base is not None and start < self.image_base + 20426752 and self.image_base < start + length

            def call(self, name, args, result):
                if self.exit_group:
                    raise TraceError('source syscall follows exit_group')
                value = private.result_number(result)
                if self.output[1] and name in {'openat', 'read', 'lseek', 'memfd_create', 'mmap', 'mremap', 'mprotect', 'fcntl'}:
                    raise TraceError('acquisition or memory mutation follows rejection publication')
                if name == 'write' and len(args) == 3 and private.descriptor(args[0])[0] in self.created:
                    match = re.fullmatch(r'"((?:[^"\\]|\\.)*)"\.\.\.', args[1])
                    if self.populated == 0:
                        if match is None:
                            raise TraceError('stock write lacks its complete observed ELF prefix')
                        try:
                            visible = bytes(match[1], 'ascii').decode('unicode_escape').encode('latin1')
                        except (ValueError, UnicodeError) as error:
                            raise TraceError('stock prefix is not a complete byte encoding') from error
                        if visible != LIBRARY_PREFIX:
                            raise TraceError('stock write visible bytes differ from the pinned ELF prefix')
                if name in {'read', 'newfstatat'}:
                    self.arity(name, args, (3,) if name == 'read' else (4,))
                    descriptor_number, path, _ = private.descriptor(args[0])
                    if path == private.MEMFD_PATH and descriptor_number not in self.created:
                        self.reader(args[0])
                        if descriptor_number not in self.memfds or self.alias_opens != 1 or self.reservation is not None:
                            raise TraceError('selected alias observation differs from its live admission owner')
                        if name == 'read':
                            match = re.fullmatch(r'"((?:[^"\\]|\\.)*)"\.\.\.', args[1])
                            if self.alias_header or match is None or args[2] != '832' or result != '832':
                                raise TraceError('selected alias requires one exact ELF header read')
                            try:
                                visible = bytes(match[1], 'ascii').decode('unicode_escape').encode('latin1')
                            except (ValueError, UnicodeError) as error:
                                raise TraceError('alias ELF prefix is not a complete byte encoding') from error
                            if visible != LIBRARY_PREFIX:
                                raise TraceError('selected alias visible bytes differ from pinned ELF header')
                            self.alias_header = True
                        else:
                            if self.alias_metadata or not self.alias_header:
                                raise TraceError('selected alias metadata must follow its one header read')
                            self.alias_metadata = True
                if name == 'gettid':
                    self.arity(name, args, (0,))
                    if not self.image_ready() or self.tid_queries >= 1:
                        raise TraceError('thread query differs from this initialized workload')
                    if self.tid_queries == 0 and (self.overcommit_reads != 1 or self.virtual_queries or self.timezone_queries or self.import_entropy):
                        raise TraceError('first thread query must precede virtual and import observations')
                    self.succeeds(value, int(self.pid))
                    self.tid_queries += 1
                    return
                if name == 'ppoll':
                    expected = '[{fd=0</dev/null<char 1:3>>, events=0}, ' + f'{{fd=1</evidence/{mode}.stdout.txt>, events=0}}, {{fd=2</evidence/{mode}.stderr.txt>, events=0}}]'
                    if args != [expected, '3', '{tv_sec=0, tv_nsec=0}', 'NULL', '0'] or result != '0 (Timeout)':
                        raise TraceError('source workload inherited-stream poll differs')
                    return
                # Pin both observed GNU file-map operations and the anonymous
                # BSS/guard/RELRO setup, retaining the image through finalization.
                if name in {'mmap', 'munmap', 'mprotect', 'mremap'}:
                    expected_arity = {'mmap': 6, 'munmap': 2, 'mprotect': 3, 'mremap': 4}[name]
                    self.arity(name, args, (expected_arity,))
                    private.pointer(args[0])
                    requested = 0 if args[0] == 'NULL' else int(args[0], 16)
                    length = private.unsigned(args[1])
                    if length == 0 or name == 'mremap' and private.unsigned(args[2]) == 0:
                        raise TraceError('zero-length memory operations are outside the observed source profile')
                    if value is not None and value >= 0 and requested % 4096:
                        raise TraceError('successful memory operation has an unaligned requested address')
                    if name == 'mmap' and args == ['NULL', '20489360', 'PROT_NONE', 'MAP_PRIVATE|MAP_ANONYMOUS', '-1', '0']:
                        if self.reservation is not None or not self.seal_verified or self.alias_opens != 1 or not self.alias_header or not self.alias_metadata or value is None or value <= 0:
                            raise TraceError('stock reservation must follow the single sealed alias')
                        self.reservation = value
                    elif name == 'mmap' and private.MEMFD_PATH in args[4]:
                        if not self.image_mappings:
                            if self.reservation is None or requested != (self.reservation + 65535) // 65536 * 65536:
                                raise TraceError('stock base must lie in its verified loader reservation')
                            self.image_base = requested
                            if requested == self.reservation:
                                self.trims.add('prefix')
                        elif requested != self.image_base + 0x115a000 or not self.guard or self.trims != {'prefix', 'tail'}:
                            raise TraceError('stock writable map differs from selected image base')
                        return super().call(name, args, result)
                    elif name == 'munmap' and self.reservation is not None and self.image_base is not None:
                        choices = {'prefix': (self.reservation, self.image_base - self.reservation),
                                   'tail': (self.image_base + 20426752, self.reservation + 20489360 - self.image_base - 20426752)}
                        selected = next((key for key, span in choices.items() if span == (requested, length)), None)
                        if selected is not None:
                            if selected in self.trims or self.relro or len(self.image_mappings) != 1 or result != '0':
                                raise TraceError('loader reservation trim differs or repeats')
                            self.trims.add(selected)
                            return
                    if self.image_base is not None:
                        if name == 'mprotect' and args[1:] == ['40960', 'PROT_NONE'] and requested == self.image_base + 0x1150000:
                            if self.guard or self.bss or self.trims != {'prefix', 'tail'} or len(self.image_mappings) != 1 or result != '0':
                                raise TraceError('stock guard setup differs or repeats')
                            self.guard = True
                            return
                        if name == 'mmap' and args[1:] == ['533648', 'PROT_READ|PROT_WRITE', 'MAP_PRIVATE|MAP_FIXED|MAP_ANONYMOUS', '-1', '0'] and requested == self.image_base + 0x12f8000:
                            if self.bss or not self.guard or len(self.image_mappings) != 2 or len(self.memfds) != 2 or value != requested:
                                raise TraceError('stock anonymous BSS differs or repeats')
                            self.bss = True
                            return
                        if name == 'mprotect' and args[1:] == ['1007616', 'PROT_READ'] and requested == self.image_base + 0x115a000:
                            if self.relro or not self.bss or any(self.readers) or set(self.memfds) != set(self.created) or result != '0':
                                raise TraceError('stock RELRO must follow BSS and alias/OS-reader closure')
                            self.relro = True
                            return
                        moved_size = private.unsigned(args[2]) if name == 'mremap' else length
                        if self.overlaps(requested, length) or name in {'mmap', 'mremap'} and value is not None and value > 0 and self.overlaps(value, moved_size):
                            raise TraceError('operation replaces, changes or unmaps the live selected stock image')
                if name == 'mremap':
                    if args[0] == 'NULL' or int(args[0], 16) != self.remap_candidate or args[1:] != ['266240', '528384', 'MREMAP_MAYMOVE'] or self.remaps or self.created or value is None or value <= 0:
                        raise TraceError('only this source profile manifest-buffer growth is admitted')
                    self.remaps = 1
                    self.remap_candidate = None
                    return
                result_value = super().call(name, args, result)
                if name == 'mmap' and args[1:5] == ['266240', 'PROT_READ|PROT_WRITE', 'MAP_PRIVATE|MAP_ANONYMOUS', '-1'] and not self.created and not self.remaps:
                    if self.manifest_allocations or value is None or value <= 0:
                        raise TraceError('source manifest buffer allocation differs or repeats')
                    self.manifest_allocations = 1
                    self.remap_candidate = value
                return result_value

        self.runtime = Runtime()

    def line(self, line):
        match = BASE.LINE.fullmatch(line)
        if match is not None and match[2] == 'uname':
            runtime = self.runtime
            runtime.process(match[1])
            args = BASE.split_arguments(match[3])
            fact = self.record['readiness']
            if (self.uname_queries or runtime.execs != 1 or runtime.exit_group or len(args) != 1 or
                    re.fullmatch(r'\{sysname="Linux", nodename="[A-Za-z0-9][A-Za-z0-9_.-]{0,63}", \.\.\.\}', args[0]) is None or match[4] != '0' or
                    runtime.archive_opened != 1 or not runtime.archive_sized or not runtime.locator_read or runtime.created or any(runtime.output) or
                    runtime.archive not in runtime.readers.values() or
                    runtime.archive_read != fact['archive_read_bytes'] or runtime.archive_cursor != fact['archive_cursor'] or
                    PRODUCT.range_digest(runtime.archive_ranges) != fact['ranges_sha256']):
                raise TraceError('readiness must follow exact metadata admission and precede all payloads')
            self.uname_queries = 1
            return
        self.runtime.line(line)

    def finish(self):
        if self.uname_queries != 1:
            raise TraceError('source-app product readiness query is missing')
        if self.mode == 'corrupt-source':
            record, runtime = self.record, self.runtime
            PRODUCT.NATIVE.validate_admission(runtime.archive_bytes, (record['manifest_bytes'], record['zip_directory_offset']))
            for lower, upper in ((0, 64 + record['manifest_bytes']), (record['zip_directory_offset'], runtime.archive_bytes)):
                covered = lower
                for start, end in sorted(runtime.archive_ranges):
                    if start <= covered:
                        covered = max(covered, end)
                if covered < upper:
                    raise TraceError('CRC rejection lacks complete manifest/ZIP metadata admission')
        self.runtime.finish()


def check_lines(lines, mode, size, record):
    checker = Checker(mode, size, record)
    total = 0
    for number, line in enumerate(lines, 1):
        total += len(line.encode('utf-8'))
        if number > MAX_RECORDS or total > MAX_TRACE_BYTES or len(line) > MAX_LINE_CHARACTERS + 1 or not line.endswith('\n') or '\r' in line:
            raise TraceError('source trace is oversized, noncanonical or incomplete')
        try:
            checker.line(line[:-1])
        except TraceError as error:
            raise TraceError(f'line {number}: {error}') from error
    checker.finish()


def archive_record(path, mode):
    size = path.stat().st_size
    if not 73563968 < size <= 128 * 1024 * 1024:
        raise TraceError('source archive exceeds pinned profile bounds')
    with path.open('rb') as stream:
        locator = stream.read(64)
        if len(locator) != 64 or locator[:8] != b'GLUERS00' or locator[8:16] != b'\0' * 8:
            raise TraceError('source archive lacks exact locator')
        length = struct.unpack_from('<Q', locator, 16)[0]
        if not 0 < length <= 2 * 1024 * 1024:
            raise TraceError('source manifest exceeds bounded profile')
        raw = stream.read(length)
        if len(raw) != length or hashlib.sha256(raw).digest() != locator[32:64] or struct.unpack_from('<Q', locator, 24)[0] != size - 64 - length:
            raise TraceError('source locator regions or manifest digest differs')
        manifest = json.loads(raw)
        if raw != json.dumps(manifest, sort_keys=True, separators=(',', ':'), ensure_ascii=False).encode('utf-8'):
            raise TraceError('source manifest is not canonical')
        stream.seek(0)
        digest = hashlib.file_digest(stream, 'sha256').hexdigest()
    with zipfile.ZipFile(path) as archive:
        directory = archive.start_dir
        if len(archive.infolist()) != len(manifest['resources']) or set(archive.namelist()) != set(manifest['resources']):
            raise TraceError('source ZIP inventory differs from complete declarations')
        for key, spec in manifest['resources'].items():
            info = archive.getinfo(key)
            if info.file_size != spec['size'] or info.compress_type != (zipfile.ZIP_STORED if spec['compression'] == 'stored' else zipfile.ZIP_DEFLATED):
                raise TraceError('source ZIP member size/storage differs from declaration')
        offset = None
        if mode == 'corrupt-source':
            info = archive.getinfo(CORRUPT_KEY)
            if info.compress_type != zipfile.ZIP_STORED or info.file_size != len(CORRUPT_BYTES):
                raise TraceError('corrupt control differs from tiny stored source')
            with path.open('rb') as stream:
                stream.seek(info.header_offset)
                header = stream.read(30)
                names, extra = struct.unpack_from('<HH', header, 26)
                offset = info.header_offset + 30 + names + extra
                stream.seek(offset)
                if stream.read(len(CORRUPT_BYTES)) != CORRUPT_BYTES:
                    raise TraceError('corrupt stored source bytes differ')
    app_id, entry, component = IDENTITIES[mode]
    if (manifest['app_id'], manifest['components'][manifest['entrypoint']]['entry_point'], manifest['entrypoint']) != (app_id, entry, component):
        raise TraceError('actual source workload identity differs')
    expected = {'schema_version': 0, 'app_id': app_id, 'entrypoint': component, 'components': {component: {'entry_point': entry, 'native_modules': [], 'runtime': 'python'}},
                'runtimes': {'python': provider_contract()}, 'targets': {'linux-arm64': TARGET}, 'native_modules': {}, 'host_imports': {},
                'resources': fixed_specs() | expected_application(mode)}
    if not typed_equal(manifest, expected):
        raise TraceError('actual source declarations differ from fixed provider and checked-in workload')
    record = {'bytes': size, 'sha256': digest, 'manifest_sha256': hashlib.sha256(raw).hexdigest(),
              'manifest_bytes': length, 'zip_directory_offset': directory, 'app_id': app_id, 'entry': entry, 'component': component,
              'application': {key: spec for key, spec in manifest['resources'].items() if key.startswith('app/')},
              'provider': provider_contract(), 'target': TARGET,
              'readiness': PRODUCT.readiness_record(path)}
    if offset is not None:
        record['corrupt_offset'] = offset
    return record


def retained_metadata(path, mode, size):
    if path.stat().st_size > 64 * 1024:
        raise TraceError('source metadata exceeds bounded profile')
    data = json.loads(path.read_text())
    if not isinstance(data, dict) or set(data) != {'schema_version', 'archives'} or type(data.get('schema_version')) is not int or data['schema_version'] != 0 or not isinstance(data.get('archives'), dict) or set(data['archives']) != set(MODES):
        raise TraceError('retained source metadata inventory differs')
    record = data['archives'][mode]
    keys = {'bytes', 'sha256', 'manifest_sha256', 'manifest_bytes', 'zip_directory_offset', 'app_id', 'entry', 'component', 'application', 'provider', 'target', 'readiness'} | ({'corrupt_offset'} if mode == 'corrupt-source' else set())
    if not isinstance(record, dict) or set(record) != keys or type(record.get('bytes')) is not int or record['bytes'] != size or (record.get('app_id'), record.get('entry'), record.get('component')) != IDENTITIES[mode]:
        raise TraceError('retained source metadata identity differs')
    if not typed_equal(record['application'], expected_application(mode)) or not typed_equal(record['provider'], provider_contract()) or not typed_equal(record['target'], TARGET):
        raise TraceError('retained source application inventory or pinned provider/target differs')
    if any(not isinstance(record.get(key), str) or re.fullmatch('[0-9a-f]{64}', record[key]) is None for key in ('sha256', 'manifest_sha256')):
        raise TraceError('retained source digest is noncanonical')
    PRODUCT.validate_readiness(record.get('readiness'), size, (record.get('manifest_bytes'), record.get('zip_directory_offset')))
    if mode == 'corrupt-source' and (type(record.get('corrupt_offset')) is not int or not 64 + record['manifest_bytes'] <= record['corrupt_offset'] <= record['zip_directory_offset'] - len(CORRUPT_BYTES)):
        raise TraceError('corrupt source offset is outside admitted payload bounds')
    return record


def main():
    if len(sys.argv) == 4 and sys.argv[1] == '--emit-metadata':
        directory, output = Path(sys.argv[2]), Path(sys.argv[3])
        output.write_text(json.dumps({'schema_version': 0, 'archives': {mode: archive_record(directory / (mode + '.glue'), mode) for mode in MODES}}, indent=2, sort_keys=True) + '\n')
        return 0
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('trace', type=Path)
    parser.add_argument('--mode', required=True, choices=MODES)
    parser.add_argument('--stdout-file', type=Path, required=True)
    parser.add_argument('--stderr-file', type=Path, required=True)
    parser.add_argument('--metadata-file', type=Path, required=True)
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument('--archive-file', type=Path)
    group.add_argument('--archive-bytes', type=int)
    args = parser.parse_args()
    size = args.archive_file.stat().st_size if args.archive_file else args.archive_bytes
    record = retained_metadata(args.metadata_file, args.mode, size)
    if args.archive_file and archive_record(args.archive_file, args.mode) != record:
        raise TraceError('retained source metadata differs from actual archive')
    for path, expected in zip((args.stdout_file, args.stderr_file), expected_output(args.mode)):
        with path.open('rb') as stream:
            if stream.read(len(expected) + 1) != expected:
                raise TraceError('retained source diagnostic differs')
    if args.trace.stat().st_size > MAX_TRACE_BYTES:
        raise TraceError('raw/compressed source trace exceeds bounded input')
    with (gzip.open if args.trace.suffix == '.gz' else open)(args.trace, 'rb') as stream:
        def lines():
            while line := stream.readline(MAX_LINE_CHARACTERS + 2):
                yield line.decode('utf-8', 'strict')
        check_lines(lines(), args.mode, size, record)
    print('Trace checks passed: source app metadata and readiness, complete verified archive, private sealed stock image retained through finalization, exact entry outcomes, no filesystem fallback/mutation or extra process')
    return 0


if __name__ == '__main__':
    try:
        raise SystemExit(main())
    except (OSError, EOFError, ValueError, KeyError, TypeError, UnicodeError, struct.error, zipfile.BadZipFile, TraceError) as error:
        print('Python source app trace rejected: ' + str(error), file=sys.stderr)
        raise SystemExit(1)
