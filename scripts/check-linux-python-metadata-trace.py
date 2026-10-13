#!/usr/bin/env python3
"""Strict complete traces for three pinned archive distribution metadata profiles.

These nine concrete workloads are evidence, not a filesystem sandbox or a
compatibility policy for arbitrary installed Python distributions. Existing
source and host policies are imported privately and retain their unchanged
archive, loader, startup and descriptor ownership checks.
"""
from __future__ import annotations

import argparse
import csv
import gzip
import hashlib
import importlib.util
import io
import json
from pathlib import Path
import re
import struct
import sys
import zipfile
import zlib


def policy(filename, name):
    spec = importlib.util.spec_from_file_location(name, Path(__file__).with_name(filename))
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def unify_private(module, seen=None):
    """Private import graphs must report one public rejection exception type."""
    seen = set() if seen is None else seen
    if id(module) in seen:
        return
    seen.add(id(module))
    module.TraceError = TraceError
    for name in ('COMMON', 'PBS', 'BASE', 'SOURCE', 'PRODUCT', 'NATIVE'):
        child = getattr(module, name, None)
        if child is not None and child is not module:
            unify_private(child, seen)


SOURCE = policy('check-linux-python-source-app-trace.py', 'metadata_source_policy')
PRODUCT, BASE, PBS, TraceError = SOURCE.PRODUCT, SOURCE.BASE, SOURCE.PBS, SOURCE.TraceError
ROOT = Path(__file__).resolve().parents[1]
DIRECTORY = '/build-target/relocated Python metadata'
PROGRAM = DIRECTORY + '/glue'
CWD = 'AT_FDCWD</build-target/runtime-empty>'
PROFILES = ('bundled', 'host', 'install-host')
MODES = tuple(profile + suffix for suffix in ('', '-bad-record', '-corrupt-metadata') for profile in PROFILES)
TARGET = SOURCE.TARGET
IDENTITY = ('distribution.metadata', 'app/main.py', 'launch')
DIST_INFO = 'app/python/glue_meta_demo-1.2.3.dist-info'
RECORD_KEY = DIST_INFO + '/RECORD'
CORRUPT_KEY = DIST_INFO + '/METADATA'
MAX_TRACE_BYTES, MAX_LINE_CHARACTERS, MAX_RECORDS = SOURCE.MAX_TRACE_BYTES, SOURCE.MAX_LINE_CHARACTERS, SOURCE.MAX_RECORDS


def profile_for(mode):
    if mode not in MODES:
        raise TraceError('unknown metadata workload')
    return next(profile for profile in reversed(PROFILES) if mode == profile or mode.startswith(profile + '-'))


def archive_for(mode):
    profile_for(mode)
    return DIRECTORY + '/' + mode + '.glue'


def rejected(mode):
    return mode.endswith(('-bad-record', '-corrupt-metadata'))


def application_bytes(mode):
    profile_for(mode)
    directory = ROOT / 'fixtures/python-metadata/input'
    data = {path.relative_to(directory).as_posix(): path.read_bytes() for path in sorted(directory.rglob('*')) if path.is_file()}
    if mode.endswith('-bad-record'):
        rows = list(csv.reader(io.StringIO(data[RECORD_KEY].decode('utf-8'))))
        rows[0][0] = '../escape.py'
        output = io.StringIO(newline='')
        csv.writer(output, lineterminator='\n').writerows(rows)
        data[RECORD_KEY] = output.getvalue().encode('utf-8')
    return data


def expected_application(mode):
    return {key: {'size': len(value), 'sha256': hashlib.sha256(value).hexdigest(), 'compression': 'stored'} for key, value in application_bytes(mode).items()}


def corrupt_bytes():
    raw = (ROOT / 'fixtures/python-metadata/input' / CORRUPT_KEY).read_bytes()
    return bytes([raw[0] ^ 1]) + raw[1:]


def expected_output(mode):
    profile_for(mode)
    if mode.endswith('-corrupt-metadata'):
        return b'', ('glue: resource "' + CORRUPT_KEY + '" failed CRC32 verification\n').encode()
    if mode.endswith('-bad-record'):
        return b'', b'glue: invalid RECORD path: invalid resource path "../escape.py": empty, absolute or traversal components are forbidden\n'
    files = len([key for key in application_bytes(mode) if key.startswith('app/python/')])
    return f'glue python distribution metadata ok: version=1.2.3 plugin=42 files={files}\n'.encode(), b''


def provider_contract(mode):
    profile = profile_for(mode)
    if profile == 'bundled':
        provider = SOURCE.provider_contract()
        provider['build_id'] = 'pbs-20261009-cpython-3.13.16-pgo-lto-bundled-metadata-apps-v1'
        provider['provisioning']['source']['variant'] = 'pgo+lto-full/bundled-metadata-apps-v1'
        return provider
    prefix = '/build-target/' + ('host' if profile == 'host' else 'install') + ' Python metadata'
    return {'abi': {'debug': False, 'gil': 'conventional', 'language': 'python', 'version': {'major': 3, 'minor': 13, 'patch': 16}},
            'build_id': 'pbs-20261009-cpython-3.13.16-pgo-lto-' + ('host' if profile == 'host' else 'host-install') + '-metadata-apps-v1',
            'provisioning': {'mode': 'host', 'discovery': 'explicit_paths', 'runtime_library': prefix + '/lib/libpython3.13.so.1.0', 'stdlib': prefix + '/lib/python3.13'},
            'required_features': [], 'target': 'linux-arm64'}


def fixed_specs(mode):
    specs = SOURCE.fixed_specs() if profile_for(mode) == 'bundled' else {'python/archive-importer.py': SOURCE.fixed_specs()['python/archive-importer.py']}
    helper = (ROOT / 'fixtures/python-metadata/bootstrap.py').read_bytes()
    return specs | {'python/archive-metadata.py': {'size': len(helper), 'sha256': hashlib.sha256(helper).hexdigest(), 'compression': 'deflate'}}


def archive_record(path, mode):
    profile = profile_for(mode)
    size = path.stat().st_size
    lower, upper = (73563968, 128 * 1024 * 1024) if profile == 'bundled' else (64, 16 * 1024 * 1024)
    if not lower < size <= upper:
        raise TraceError('metadata archive exceeds pinned profile bounds')
    with path.open('rb') as stream:
        locator = stream.read(64)
        if len(locator) != 64 or locator[:8] != b'GLUERS00' or locator[8:16] != b'\0' * 8:
            raise TraceError('metadata archive lacks exact locator')
        length = struct.unpack_from('<Q', locator, 16)[0]
        manifest_bound = (2 if profile == 'bundled' else 1) * 1024 * 1024
        if not 0 < length <= manifest_bound:
            raise TraceError('metadata manifest exceeds bounded profile')
        raw = stream.read(length)
        if len(raw) != length or hashlib.sha256(raw).digest() != locator[32:64] or struct.unpack_from('<Q', locator, 24)[0] != size - 64 - length:
            raise TraceError('metadata locator regions or manifest digest differ')
        manifest = json.loads(raw)
        if raw != json.dumps(manifest, sort_keys=True, separators=(',', ':'), ensure_ascii=False).encode():
            raise TraceError('metadata manifest is not canonical')
        stream.seek(0)
        digest = hashlib.file_digest(stream, 'sha256').hexdigest()
    app_id, entry, component = IDENTITY
    expected = {'schema_version': 0, 'app_id': app_id, 'entrypoint': component,
                'components': {component: {'entry_point': entry, 'native_modules': [], 'runtime': 'python'}},
                'runtimes': {'python': provider_contract(mode)}, 'targets': {'linux-arm64': TARGET},
                'native_modules': {}, 'host_imports': {}, 'resources': fixed_specs(mode) | expected_application(mode)}
    if not SOURCE.typed_equal(manifest, expected):
        raise TraceError('metadata declarations differ from pinned provider/helper/checked-in application')
    offset = None
    with zipfile.ZipFile(path) as archive:
        directory = archive.start_dir
        directory_bound = 2 * 1024 * 1024 if profile == 'bundled' else 256 * 1024
        if not 0 < size - directory <= directory_bound or len(archive.infolist()) != len(expected['resources']) or set(archive.namelist()) != set(expected['resources']):
            raise TraceError('metadata ZIP inventory differs from complete declarations')
        for key, spec in expected['resources'].items():
            info = archive.getinfo(key)
            if info.file_size != spec['size'] or info.compress_type != (zipfile.ZIP_STORED if spec['compression'] == 'stored' else zipfile.ZIP_DEFLATED):
                raise TraceError('metadata ZIP member size/storage differs')
            if mode.endswith('-corrupt-metadata') and key == CORRUPT_KEY:
                # Validate local member identity without triggering its expected
                # CRC failure; independently pin all deliberately altered bytes.
                with archive.open(key):
                    pass
                with path.open('rb') as stream:
                    stream.seek(info.header_offset)
                    header = stream.read(30)
                    names, extra = struct.unpack_from('<HH', header, 26)
                    offset = info.header_offset + 30 + names + extra
                    stream.seek(offset)
                    if stream.read(spec['size']) != corrupt_bytes():
                        raise TraceError('corrupt metadata bytes differ from fixed one-byte control')
            else:
                data = archive.read(key)
                if len(data) != spec['size'] or hashlib.sha256(data).hexdigest() != spec['sha256']:
                    raise TraceError('metadata ZIP bytes differ from independently pinned declarations')
    record = {'bytes': size, 'sha256': digest, 'manifest_sha256': hashlib.sha256(raw).hexdigest(), 'manifest_bytes': length,
              'zip_directory_offset': directory, 'app_id': app_id, 'entry': entry, 'component': component,
              'application': expected_application(mode), 'provider': provider_contract(mode), 'target': TARGET,
              'readiness': PRODUCT.readiness_record(path)}
    if offset is not None:
        record['corrupt_offset'] = offset
    return record


def retained_metadata(path, mode, size):
    profile = profile_for(mode)
    if path.stat().st_size > 256 * 1024:
        raise TraceError('retained metadata exceeds bounded profile')
    data = json.loads(path.read_text())
    if not isinstance(data, dict) or set(data) != {'schema_version', 'archives'} or type(data.get('schema_version')) is not int or data['schema_version'] != 0 or not isinstance(data.get('archives'), dict) or set(data['archives']) != set(MODES):
        raise TraceError('retained metadata schema/workload inventory differs')
    record = data['archives'][mode]
    keys = {'bytes', 'sha256', 'manifest_sha256', 'manifest_bytes', 'zip_directory_offset', 'app_id', 'entry', 'component', 'application', 'provider', 'target', 'readiness'} | ({'corrupt_offset'} if mode.endswith('-corrupt-metadata') else set())
    lower, upper = (73563968, 128 * 1024 * 1024) if profile == 'bundled' else (64, 16 * 1024 * 1024)
    if not isinstance(record, dict) or set(record) != keys or type(record.get('bytes')) is not int or record['bytes'] != size or not lower < size <= upper or (record.get('app_id'), record.get('entry'), record.get('component')) != IDENTITY:
        raise TraceError('retained metadata archive identity differs')
    if not SOURCE.typed_equal(record['application'], expected_application(mode)) or not SOURCE.typed_equal(record['provider'], provider_contract(mode)) or not SOURCE.typed_equal(record['target'], TARGET):
        raise TraceError('retained metadata application/provider/target differs')
    if any(not isinstance(record.get(key), str) or re.fullmatch('[0-9a-f]{64}', record[key]) is None for key in ('sha256', 'manifest_sha256')):
        raise TraceError('retained metadata digest is noncanonical')
    PRODUCT.validate_readiness(record['readiness'], size, (record['manifest_bytes'], record['zip_directory_offset']))
    manifest_bound = (2 if profile == 'bundled' else 1) * 1024 * 1024
    directory_bound = 2 * 1024 * 1024 if profile == 'bundled' else 256 * 1024
    if record['manifest_bytes'] > manifest_bound or size - record['zip_directory_offset'] > directory_bound:
        raise TraceError('retained metadata manifest/directory exceeds selected profile bounds')
    if mode.endswith('-corrupt-metadata') and (type(record['corrupt_offset']) is not int or not 64 + record['manifest_bytes'] <= record['corrupt_offset'] <= record['zip_directory_offset'] - len(corrupt_bytes())):
        raise TraceError('corrupt metadata offset lies outside admitted payload')
    return record


def closed_rejection(runtime, mode, record):
    if runtime.readers or runtime.created or runtime.memfds or runtime.image_mappings:
        return False
    if mode.endswith('-bad-record'):
        return runtime.archive_complete()
    last = getattr(runtime, 'last_read', getattr(runtime, 'last_archive_read', None))
    observed = getattr(runtime, 'corrupt_read', getattr(runtime, 'corrupt_source_read', False))
    return observed and last == (record['corrupt_offset'], len(corrupt_bytes()))


def bundled_checker(mode, size, record):
    private = policy('check-linux-python-source-app-trace.py', 'metadata_private_source')
    unify_private(private)
    private.PROGRAM = PROGRAM
    private.archive_for = lambda _: archive_for(mode)
    private.expected_output = lambda _: expected_output(mode)
    private.CORRUPT_BYTES = corrupt_bytes()
    private.OUTPUTS['corrupt-source'] = expected_output(mode)
    checker = private.Checker('corrupt-source' if rejected(mode) else 'resources', size, record)
    runtime = checker.runtime
    parent = type(runtime)

    class MetadataRuntime(parent):
        def inherited(self, token):
            number, path, deleted = PBS.descriptor(token) if token != '0</dev/null<char 1:3>>' else (0, '/dev/null', False)
            if deleted or path != {0: '/dev/null', 1: f'/evidence/{mode}.stdout.txt', 2: f'/evidence/{mode}.stderr.txt'}.get(number):
                raise TraceError('metadata inherited stream identity differs')
            return number

        def rejection_ready(self):
            return closed_rejection(self, mode, record)

        def runtime_ready(self):
            return (self.image_ready() and self.overcommit_reads == self.virtual_queries == self.timezone_queries == self.import_entropy == 1 and self.tid_queries == 2)

        def call(self, name, args, result):
            if self.exit_group or self.completed:
                raise TraceError('metadata operation follows process exit')
            if name == 'gettid' and self.tid_queries == 1:
                if args or result != self.pid or not self.image_ready() or self.overcommit_reads != 1 or self.virtual_queries != 1 or self.timezone_queries != 1 or self.import_entropy != 1 or any(self.output):
                    raise TraceError('metadata publication thread query differs from fully initialized workload')
                self.tid_queries = 2
                return
            if name == 'ppoll':
                expected = '[{fd=0</dev/null<char 1:3>>, events=0}, ' + f'{{fd=1</evidence/{mode}.stdout.txt>, events=0}}, {{fd=2</evidence/{mode}.stderr.txt>, events=0}}]'
                if args != [expected, '3', '{tv_sec=0, tv_nsec=0}', 'NULL', '0'] or result != '0 (Timeout)':
                    raise TraceError('metadata inherited stream poll differs')
                return
            if rejected(mode) and name == 'memfd_create':
                raise TraceError('metadata rejection may not acquire a runtime image')
            return super().call(name, args, result)

        def finish(self):
            if not rejected(mode):
                return super().finish()
            if self.execs != 1 or not self.exit_group or not self.completed or self.remaps != 1 or not self.rejection_ready() or tuple(bytes(value) for value in self.output) != expected_output(mode):
                raise TraceError('metadata rejection lacks complete closed admission and exact diagnostic')
            if self.virtual_queries or self.overcommit_reads or self.tid_queries or self.timezone_queries or self.import_entropy:
                raise TraceError('metadata rejection must precede all Python startup observations')

    runtime.__class__ = MetadataRuntime
    if mode.endswith('-bad-record'):
        runtime.corrupt_source_offset = -1
    return checker


def host_checker(mode, size, record):
    profile = profile_for(mode)
    filename = 'check-linux-python-' + ('install-' if profile == 'install-host' else '') + 'host-source-app-trace.py'
    private = policy(filename, 'metadata_private_' + profile)
    unify_private(private)
    private.PROGRAM = PROGRAM
    private.PREFIX = provider_contract(mode)['provisioning']['stdlib'].removesuffix('/lib/python3.13')
    private.archive_for = lambda _: archive_for(mode)
    private.expected_output = lambda _: expected_output(mode)
    private.CORRUPT_BYTES = corrupt_bytes()
    private.SUCCESS = {mode} if not rejected(mode) else set()
    private.INITIALIZED = {mode} if not rejected(mode) else set()
    parent = private.Checker

    class MetadataHost(parent):
        def initialized_observations(self, threads):
            caches = profile != 'install-host' or self.raw_cache_done == set(self.startup_caches)
            return (self.image_ready() and self.raw_done == self.raw_sources and caches and
                    self.virtual_queries == self.overcommit_reads == self.timezone_queries == self.entropy == 1 and self.tid_queries == threads and
                    self.remaps == (4 if profile == 'install-host' else 2) and
                    self.enums.get(('runtime', self.stdlib)) == (193 if profile == 'install-host' else 192) and
                    self.enums.get(('runtime', self.stdlib + '/encodings')) == (125 if profile == 'install-host' else 124) and self.import_probes_seen == self.probes)

        def runtime_ready(self):
            return self.finalized_boundary or self.initialized_observations(2)

        def control_ready(self):
            return closed_rejection(self, mode, record) and not self.cache_checks and not self.fd_states and not self.alias_opened

        def call(self, name, args, result):
            if self.exit_group or self.completed:
                raise TraceError('metadata host operation follows process exit')
            if name == 'gettid' and self.tid_queries == 1:
                if args or result != self.pid or not self.initialized_observations(1) or any(self.output):
                    raise TraceError('metadata publication thread query differs from fully initialized host workload')
                self.tid_queries = 2
                return
            if name == 'getdents64' and len(args) == 3:
                number, path = self.reader(args[0])
                state = self.fd_states.get(number)
                if state is not None and state['role'] == 'runtime-enum' and path == self.stdlib:
                    match = re.fullmatch(r'0x[0-9a-f]{1,16} /\* ([0-9]{1,3}) entries \*/', args[1])
                    value = private.COMMON.result_number(result)
                    if state['eof'] or not self.image_ready() or state['metadata'] != 1 or args[2] != '32768' or match is None or value is None or not 0 <= value <= 32768 or (value == 0) != (int(match[1]) == 0):
                        raise TraceError('metadata directory enumeration lacks exact live owner/count grammar')
                    state['bytes'] += int(match[1])
                    if value == 0:
                        expected = 193 if profile == 'install-host' else 192
                        if state['eof'] or state['bytes'] != expected:
                            raise TraceError('metadata installed directory entries differ from prepared runtime inventory')
                        state['eof'] = True
                        self.enums['runtime', path] = expected
                    return
            if rejected(mode) and name in {'statx', 'newfstatat', 'fstat', 'openat'}:
                if name == 'openat' and len(args) >= 2:
                    path = private.COMMON.quoted(args[1])
                elif name != 'fstat' and len(args) >= 2 and args[0] == private.COMMON.CWD:
                    path = private.COMMON.quoted(args[1])
                else:
                    path = None
                if path is not None and (path in self.host_paths | self.caches | self.shadow_paths | self.probes or path == private.PREFIX or path.startswith(self.stdlib + '/')):
                    raise TraceError('metadata rejection may not acquire any installed provider input')
            if mode.endswith('-corrupt-metadata') and name == 'read' and len(args) == 3 and self.archive_cursor == record['corrupt_offset']:
                number, path = self.reader(args[0])
                value = private.COMMON.result_number(result)
                if path == self.archive:
                    if self.corrupt_read or value != len(corrupt_bytes()) or args[2] != str(value) or private.payload(args[1], value) != corrupt_bytes()[:256]:
                        raise TraceError('metadata CRC rejection lacks exact selected corrupted bytes')
                    self.corrupt_read = True
            return super().call(name, args, result)

        def finish(self):
            if self.execs != 1 or not self.exit_group or not self.completed or self.uname_queries != 1:
                raise TraceError('metadata process/readiness/exit is incomplete')
            if rejected(mode):
                if not self.control_ready() or tuple(bytes(value) for value in self.output) != expected_output(mode):
                    raise TraceError('metadata rejection lacks exact closed provider-free outcome')
                if self.virtual_queries or self.overcommit_reads or self.tid_queries or self.timezone_queries or self.entropy:
                    raise TraceError('metadata rejection must precede all Python startup observations')
            else:
                return super().finish()

    return MetadataHost(mode, size, record)


class Checker:
    def __init__(self, mode, size, record):
        self.mode, self.record = mode, record
        self.crc_payload_reads = 0
        PRODUCT.validate_readiness(record['readiness'], size, (record['manifest_bytes'], record['zip_directory_offset']))
        self.checker = bundled_checker(mode, size, record) if profile_for(mode) == 'bundled' else host_checker(mode, size, record)

    def line(self, line):
        if self.mode.endswith('-corrupt-metadata'):
            match = BASE.LINE.fullmatch(line)
            if match is not None and match[2] == 'read':
                args = BASE.split_arguments(match[3])
                runtime = getattr(self.checker, 'runtime', self.checker)
                if len(args) == 3 and PBS.descriptor(args[0])[1] == archive_for(self.mode) and self.checker.uname_queries:
                    data = application_bytes(self.mode)['app/main.py'] if self.crc_payload_reads == 0 else corrupt_bytes()
                    visible = re.fullmatch(r'"((?:[^"\\]|\\.)*)"(\.\.\.)?', args[1])
                    if self.crc_payload_reads >= 2 or visible is None or args[2] != str(len(data)) or match[4] != str(len(data)):
                        raise TraceError('CRC control payload reads differ from exact ordered entry and metadata verification')
                    try:
                        prefix = bytes(visible[1], 'ascii').decode('unicode_escape').encode('latin1')
                    except (ValueError, UnicodeError) as error:
                        raise TraceError('CRC control visible bytes are not a complete byte encoding') from error
                    if prefix != data[:256] or bool(visible[2]) != (len(data) > 256) or self.crc_payload_reads == 1 and runtime.archive_cursor != self.record['corrupt_offset']:
                        raise TraceError('CRC control entry/metadata bytes, truncation or selected offset differ')
                    self.crc_payload_reads += 1
        return self.checker.line(line)

    def finish(self):
        self.checker.finish()
        if self.mode.endswith('-corrupt-metadata'):
            runtime = getattr(self.checker, 'runtime', self.checker)
            expected_read = self.record['readiness']['archive_read_bytes'] + len(application_bytes(self.mode)['app/main.py']) + len(corrupt_bytes())
            if self.crc_payload_reads != 2 or runtime.archive_read != expected_read or runtime.archive_cursor != self.record['corrupt_offset'] + len(corrupt_bytes()):
                raise TraceError('CRC rejection lacks exact complete entry/metadata read phase')
            for lower, upper in ((0, 64 + self.record['manifest_bytes']), (self.record['zip_directory_offset'], runtime.archive_bytes)):
                if not any(start <= lower and end >= upper for start, end in PRODUCT.merged_ranges(runtime.archive_ranges)):
                    raise TraceError('metadata CRC rejection lacks complete manifest/ZIP admission')


def check_lines(lines, mode, size, record):
    checker, total = Checker(mode, size, record), 0
    for number, line in enumerate(lines, 1):
        total += len(line.encode('utf-8'))
        if number > MAX_RECORDS or total > MAX_TRACE_BYTES or len(line) > MAX_LINE_CHARACTERS + 1 or not line.endswith('\n') or '\r' in line:
            raise TraceError('metadata trace is oversized, noncanonical or incomplete')
        try:
            checker.line(line[:-1])
        except TraceError as error:
            raise TraceError(f'line {number}: {error}') from error
    checker.finish()


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
    if args.archive_file and not SOURCE.typed_equal(archive_record(args.archive_file, args.mode), record):
        raise TraceError('retained metadata differs from actual archive')
    for path, expected in zip((args.stdout_file, args.stderr_file), expected_output(args.mode)):
        with path.open('rb') as stream:
            if stream.read(len(expected) + 1) != expected:
                raise TraceError('retained metadata diagnostic differs')
    if args.trace.stat().st_size > MAX_TRACE_BYTES:
        raise TraceError('raw/compressed metadata trace exceeds bounded input')
    with (gzip.open if args.trace.suffix == '.gz' else open)(args.trace, 'rb') as stream:
        def lines():
            while line := stream.readline(MAX_LINE_CHARACTERS + 2):
                yield line.decode('utf-8', 'strict')
        check_lines(lines(), args.mode, size, record)
    print('Trace checks passed: exact metadata admission, provider and entry outcomes; archive-only distribution discovery and resources; no filesystem fallback/mutation or extra process')
    return 0


if __name__ == '__main__':
    try:
        raise SystemExit(main())
    except (OSError, EOFError, ValueError, KeyError, TypeError, UnicodeError, struct.error, zipfile.BadZipFile, zlib.error, TraceError) as error:
        print('Python metadata trace rejected: ' + str(error), file=sys.stderr)
        raise SystemExit(1)
