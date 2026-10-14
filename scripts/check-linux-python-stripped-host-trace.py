#!/usr/bin/env python3
"""Closed traces for separately pinned stripped/unstripped host metadata images.

Every checker owns a fresh historical policy graph. Its explicit workload,
selected image size/visible header and projected-root enumeration are adapted;
measured crypto wakes and one empty config descriptor have closed predicates.
Historical modules and sys.modules entries are never modified. This is evidence
for the declared fixture, rather than a compatibility policy or sandbox.
"""
from __future__ import annotations

import argparse
import gzip
import hashlib
import importlib.util
import json
from pathlib import Path
import re
import struct
import sys
from types import MappingProxyType
from typing import NamedTuple
import zipfile
import zlib

ROOT = Path(__file__).resolve().parents[1]
FIXTURE = ROOT / 'fixtures/python-stripped-host'
DIRECTORY = '/build-target/relocated Python stripped host'
PROGRAM = DIRECTORY + '/glue'
PREFIX = '/build-target/Python stripped host'
UNSTRIPPED_PREFIX = '/build-target/Python unstripped host'
IDENTITY = ('python.stripped-host', 'app/main.py', 'launch')
MODES = ('stripped', 'unstripped', 'missing-library', 'wrong-library',
         'corrupt-library', 'corrupt-entry', 'wrong-profile')
SUCCESS = frozenset(('stripped', 'unstripped'))
BUILD_ID = 'pbs-20261009-cpython-3.13.16-pgo-lto-host-install-stripped-metadata-apps-v1'
OLD_BUILD_ID = 'pbs-20261009-cpython-3.13.16-pgo-lto-host-install-metadata-apps-v1'
STRIPPED_BYTES = 22177832
STRIPPED_SHA = '327af7e7114d339222b4fa8af954207c78a3b382f1edda667f16a48c89dfaf75'
UNSTRIPPED_BYTES = 73563968
UNSTRIPPED_SHA = '42be968275d5be2d9e632ec9ef6790dd2c10f1d4a710ad1028fc2b687242f219'
STRIPPED_HEADER = bytes.fromhex('7f454c460201010000000000000000000300b7000100000000000000000000004000000000000000a8605201000000000000000040003800080040001e001d00010000000500000000000000000000000000000000000000000000000000000058fe14010000000058fe14010000000000000100000000000100000006000000c8a8150100000000c8a8150100000000c8a8150100000000d0c9190000000000c8fb2100000000000000010000000000020000000600000098ba24010000000098ba24010000000098ba240100000000500200000000000050020000000000000800000000000000040000000400000000020000000000000002000000000000')
APP_PINS = MappingProxyType({
    'app/main.py': (1320, '8ef16eb02268541428eb40edf8f542ebc9483a4d872fd9562c6e6d200586b706'),
    'app/python/glue_stripped_demo-1.0.dist-info/METADATA': (90, '44ba00ff729273d1efacdf1e45a97789b718c33ec99910ef3f0d52349f099ed3'),
    'app/python/glue_stripped_demo-1.0.dist-info/RECORD': (300, '4a88208219d74e8d8ce9cdff0ce5439cea37e9dcc5423731c31a3075d0bd9798'),
    'app/python/stripped_demo/__init__.py': (12, '0a775022744f64c352863f165f2e125898419999bc57c83204772036d0ef6b2e'),
    'app/python/stripped_demo/data/value.txt': (3, '084c799cd551dd1d8d5c5f9a5d593b2e931f5e36122ee5c793c1d08a19839cc0'),
})
HELPER_PINS = MappingProxyType({
    'python/archive-importer.py': ('fixtures/python-imports/bootstrap.py', 13510, '7001318a2554b3800c1abbda6b114c6d0e5d6fed56788dc54727d2637ed2f43f'),
    'python/archive-metadata.py': ('fixtures/python-metadata/bootstrap.py', 4852, '3e39d544468ddb014fb19c14347e4ea5ab85c01188213e556aff5f1ed3c3d4bd'),
})
OUTPUT_SHA = '7d6fc6c4836b2c88f5b9a25a6e6193cf294340ba00964f84d12ec96a38dc488b'
# Observed OpenSSL one-time initialization in the pinned built-in _hashlib.
# These mutex words belong to the selected image, never an anonymous owner.
CRYPTO_WAKE_OFFSETS = (0x1377b70, 0x1377afc, 0x13776e8, 0x1377b04, 0x1377b0c,
                       0x1377bf8, 0x1377b1c, 0x1377b20, 0x1377680, 0x1377b78,
                       0x1377678, 0x1377b10, 0x1377b24, 0x13774c8)


def policy():
    spec = importlib.util.spec_from_file_location(
        'stripped_host_private_install_policy',
        Path(__file__).with_name('check-linux-python-install-host-source-app-trace.py'))
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


REFERENCE = policy()
BASE, PBS, PRODUCT, SOURCE, TraceError = (
    REFERENCE.BASE, REFERENCE.PBS, REFERENCE.PRODUCT, REFERENCE.SOURCE, REFERENCE.TraceError)
TARGET = SOURCE.TARGET
CWD = REFERENCE.COMMON.CWD
MAX_TRACE_BYTES, MAX_LINE_CHARACTERS, MAX_RECORDS = (
    SOURCE.MAX_TRACE_BYTES, SOURCE.MAX_LINE_CHARACTERS, SOURCE.MAX_RECORDS)
UNSTRIPPED_HEADER = SOURCE.LIBRARY_PREFIX


def require(condition, message):
    if not condition:
        raise TraceError(message)


def mode_check(mode):
    require(mode in MODES, 'unknown stripped-host workload')


def prefix_for(mode):
    mode_check(mode)
    return (UNSTRIPPED_PREFIX if mode == 'unstripped' else PREFIX if mode in
            ('stripped', 'corrupt-entry', 'wrong-profile') else PREFIX + ' ' + mode)


def archive_for(mode):
    mode_check(mode)
    return DIRECTORY + '/' + mode + '.glue'


def original_profile(mode):
    mode_check(mode)
    return mode in ('unstripped', 'wrong-profile')


def provider_contract(mode):
    prefix = prefix_for(mode)
    return {'abi': {'debug': False, 'gil': 'conventional', 'language': 'python',
                    'version': {'major': 3, 'minor': 13, 'patch': 16}},
            'build_id': OLD_BUILD_ID if original_profile(mode) else BUILD_ID,
            'provisioning': {'mode': 'host', 'discovery': 'explicit_paths',
                             'runtime_library': prefix + '/lib/libpython3.13.so.1.0',
                             'stdlib': prefix + '/lib/python3.13'},
            'required_features': [], 'target': 'linux-arm64'}


def strict_json(payload):
    def pairs(items):
        result = {}
        for key, value in items:
            require(key not in result, 'duplicate stripped-host JSON field')
            result[key] = value
        return result
    return json.loads(payload, object_pairs_hook=pairs,
                      parse_constant=lambda _: (_ for _ in ()).throw(TraceError('nonfinite stripped-host JSON')))


def pinned_bytes(path, size, sha):
    with path.open('rb') as stream:
        payload = stream.read(size + 1)
    require(len(payload) == size and hashlib.sha256(payload).hexdigest() == sha,
            'stripped-host fixture bytes differ: ' + path.name)
    return payload


def application_bytes(mode):
    mode_check(mode)
    return {name: pinned_bytes(FIXTURE / 'application' / name, *pin) for name, pin in APP_PINS.items()}


def expected_application(mode):
    return {name: {'size': len(payload), 'sha256': hashlib.sha256(payload).hexdigest(), 'compression': 'stored'}
            for name, payload in application_bytes(mode).items()}


def fixed_specs():
    return {name: {'size': size, 'sha256': sha, 'compression': 'deflate'}
            for name, (path, size, sha) in HELPER_PINS.items() if pinned_bytes(ROOT / path, size, sha) is not None}


def corrupt_bytes():
    raw = application_bytes('corrupt-entry')['app/main.py']
    return bytes([raw[0] ^ 1]) + raw[1:]


def expected_output(mode):
    mode_check(mode)
    if mode in SUCCESS:
        return pinned_bytes(FIXTURE / 'expected.stdout.txt', 70, OUTPUT_SHA), b''
    library = prefix_for(mode) + '/lib/libpython3.13.so.1.0'
    message = ('resource "app/main.py" failed CRC32 verification' if mode == 'corrupt-entry' else
               f'host path {library}: No such file or directory (os error 2)' if mode == 'missing-library' else
               f'host file identity mismatch: {library}' if mode == 'corrupt-library' else
               f'host file size mismatch: {library}')
    return b'', ('glue: ' + message + '\n').encode('ascii')


class ImageParameters(NamedTuple):
    expected_size: int
    expected_sha: str
    observed_size: int
    visible_header: bytes


def image_parameters(mode):
    mode_check(mode)
    expected_size, expected_sha = ((UNSTRIPPED_BYTES, UNSTRIPPED_SHA) if original_profile(mode)
                                   else (STRIPPED_BYTES, STRIPPED_SHA))
    actual_original = mode in ('unstripped', 'wrong-library')
    observed_size, header = ((UNSTRIPPED_BYTES, UNSTRIPPED_HEADER) if actual_original
                             else (STRIPPED_BYTES, STRIPPED_HEADER))
    if mode == 'corrupt-library':
        header = bytes([header[0] ^ 1]) + header[1:]
    return ImageParameters(expected_size, expected_sha, observed_size, header)


def archive_record(path, mode):
    mode_check(mode)
    size = path.stat().st_size
    require(64 < size <= 16 * 1024 * 1024, 'stripped-host archive exceeds fixed bound')
    with path.open('rb') as stream:
        locator = stream.read(64)
        require(len(locator) == 64 and locator[:16] == b'GLUERS00' + b'\0' * 8, 'stripped-host locator differs')
        length, zipped = struct.unpack_from('<QQ', locator, 16)
        require(0 < length <= 1024 * 1024 and 64 + length + zipped == size, 'stripped-host framing differs')
        raw = stream.read(length)
        require(hashlib.sha256(raw).digest() == locator[32:64], 'stripped-host manifest hash differs')
        manifest = strict_json(raw)
        require(raw == json.dumps(manifest, sort_keys=True, separators=(',', ':'), ensure_ascii=False).encode(),
                'stripped-host manifest is not canonical')
        stream.seek(0)
        digest = hashlib.file_digest(stream, 'sha256').hexdigest()
    app_id, entry, component = IDENTITY
    expected = {'schema_version': 0, 'app_id': app_id, 'entrypoint': component,
                'components': {component: {'entry_point': entry, 'native_modules': [], 'runtime': 'python'}},
                'runtimes': {'python': provider_contract(mode)}, 'targets': {'linux-arm64': TARGET},
                'native_modules': {}, 'host_imports': {}, 'resources': fixed_specs() | expected_application(mode)}
    require(SOURCE.typed_equal(manifest, expected), 'stripped-host declarations differ from the closed profile')
    offset = None
    with zipfile.ZipFile(path) as archive:
        directory = archive.start_dir
        require(0 < size - directory <= 256 * 1024 and len(archive.infolist()) == len(expected['resources']) and
                set(archive.namelist()) == set(expected['resources']), 'stripped-host ZIP inventory differs')
        for name, declaration in expected['resources'].items():
            info = archive.getinfo(name)
            require(info.file_size == declaration['size'] and info.compress_type ==
                    (zipfile.ZIP_STORED if declaration['compression'] == 'stored' else zipfile.ZIP_DEFLATED),
                    'stripped-host member size/storage differs')
            if mode == 'corrupt-entry' and name == 'app/main.py':
                try:
                    archive.read(name)
                except zipfile.BadZipFile as error:
                    require('CRC' in str(error), 'stripped-host entry failed for a different reason')
                else:
                    raise TraceError('stripped-host damaged entry unexpectedly verified')
                with path.open('rb') as stream:
                    stream.seek(info.header_offset)
                    header = stream.read(30)
                    names, extra = struct.unpack_from('<HH', header, 26)
                    offset = info.header_offset + 30 + names + extra
                    stream.seek(offset)
                    require(stream.read(info.file_size) == corrupt_bytes(), 'stripped-host CRC bytes differ')
            else:
                payload = archive.read(name)
                require(len(payload) == declaration['size'] and hashlib.sha256(payload).hexdigest() == declaration['sha256'],
                        'stripped-host member bytes differ')
    parameters = image_parameters(mode)
    record = {'bytes': size, 'sha256': digest, 'manifest_sha256': hashlib.sha256(raw).hexdigest(),
              'manifest_bytes': length, 'zip_directory_offset': directory, 'app_id': app_id, 'entry': entry,
              'component': component, 'application': expected_application(mode), 'provider': provider_contract(mode),
              'target': TARGET, 'readiness': PRODUCT.readiness_record(path),
              'runtime_image': {'size': parameters.expected_size, 'sha256': parameters.expected_sha}}
    if offset is not None:
        record['corrupt_offset'] = offset
    return record


def retained_metadata(path, mode, size=None):
    with path.open('rb') as stream:
        raw = stream.read(256 * 1024 + 1)
    require(len(raw) <= 256 * 1024, 'stripped-host retained metadata exceeds bound')
    value = strict_json(raw)
    require(isinstance(value, dict) and set(value) == {'schema_version', 'archives'} and
            type(value['schema_version']) is int and value['schema_version'] == 0 and
            isinstance(value['archives'], dict) and set(value['archives']) == set(MODES),
            'stripped-host retained metadata schema/workloads differ')
    record = value['archives'][mode]
    require(isinstance(record, dict) and 'bytes' in record, 'stripped-host retained archive is malformed')
    if size is None:
        size = record['bytes']
    validate_record(record, mode, size)
    return record


def validate_record(record, mode, size):
    keys = {'bytes', 'sha256', 'manifest_sha256', 'manifest_bytes', 'zip_directory_offset', 'app_id', 'entry',
            'component', 'application', 'provider', 'target', 'readiness', 'runtime_image'}
    if mode == 'corrupt-entry':
        keys.add('corrupt_offset')
    params = image_parameters(mode)
    require(isinstance(record, dict) and set(record) == keys and type(record['bytes']) is int and
            record['bytes'] == size and 64 < size <= 16 * 1024 * 1024 and
            (record['app_id'], record['entry'], record['component']) == IDENTITY,
            'stripped-host retained archive identity differs')
    require(SOURCE.typed_equal(record['application'], expected_application(mode)) and
            SOURCE.typed_equal(record['provider'], provider_contract(mode)) and SOURCE.typed_equal(record['target'], TARGET) and
            SOURCE.typed_equal(record['runtime_image'], {'size': params.expected_size, 'sha256': params.expected_sha}),
            'stripped-host retained application/provider/image facts differ')
    require(all(isinstance(record[key], str) and re.fullmatch('[0-9a-f]{64}', record[key])
                for key in ('sha256', 'manifest_sha256')), 'stripped-host retained digest is noncanonical')
    PRODUCT.validate_readiness(record['readiness'], size, (record['manifest_bytes'], record['zip_directory_offset']))
    require(record['manifest_bytes'] <= 1024 * 1024 and size - record['zip_directory_offset'] <= 256 * 1024,
            'stripped-host retained manifest/directory exceeds fixed bound')
    if mode == 'corrupt-entry':
        require(type(record['corrupt_offset']) is int and 64 + record['manifest_bytes'] <= record['corrupt_offset'] <=
                record['zip_directory_offset'] - len(corrupt_bytes()), 'stripped-host CRC offset differs')


def unify_errors(module, seen=None):
    seen = set() if seen is None else seen
    if id(module) in seen:
        return
    seen.add(id(module))
    module.TraceError = TraceError
    for name in ('COMMON', 'PBS', 'BASE', 'SOURCE', 'PRODUCT', 'NATIVE'):
        child = getattr(module, name, None)
        if child is not None and child is not module:
            unify_errors(child, seen)


class Checker:
    def __init__(self, mode, size, record):
        validate_record(record, mode, size)
        self.mode, self.record = mode, record
        self.parameters = image_parameters(mode)
        private = policy()
        unify_errors(private)
        private.PROGRAM = PROGRAM
        private.PREFIX = prefix_for(mode)
        private.prefix_for = lambda _: prefix_for(mode)
        private.archive_for = lambda _: archive_for(mode)
        private.expected_output = lambda _: expected_output(mode)
        private.COMMON.LIBRARY_BYTES = self.parameters.observed_size
        private.SOURCE.LIBRARY_PREFIX = self.parameters.visible_header
        private.CORRUPT_BYTES = corrupt_bytes()
        private.SUCCESS = {mode} if mode in SUCCESS else set()
        private.INITIALIZED = {mode} if mode in SUCCESS else set()
        parent = private.Checker
        parameters, outer = self.parameters, self
        internal = 'corrupt-source' if mode == 'corrupt-entry' else mode
        def unchanged_parameters():
            require(outer.parameters == parameters and private.COMMON.LIBRARY_BYTES == parameters.observed_size and
                    private.SOURCE.LIBRARY_PREFIX == parameters.visible_header and private.PROGRAM == PROGRAM and
                    private.PREFIX == prefix_for(mode), 'stripped-host private image parameters changed')
        self._unchanged_parameters = unchanged_parameters

        class SelectedHost(parent):
            def inherited(self, token):
                number, path, deleted = PBS.descriptor(token) if token != '0</dev/null<char 1:3>>' else (0, '/dev/null', False)
                require(not deleted and path == {0: '/dev/null', 1: f'/evidence/{mode}.stdout.txt',
                                                2: f'/evidence/{mode}.stderr.txt'}.get(number),
                        'stripped-host inherited stream identity differs')
                return number

            def initialized_observations(self, threads):
                return (self.image_ready() and self.raw_done == self.raw_sources and self.raw_cache_done == set(self.startup_caches) and
                        self.virtual_queries == self.overcommit_reads == self.timezone_queries == self.entropy == 1 and
                        self.tid_queries == threads and self.remaps == 4 and self.enums.get(('runtime', self.stdlib)) == 191 and
                        self.enums.get(('runtime', self.stdlib + '/encodings')) == 125 and self.import_probes_seen == self.probes)

            def runtime_ready(self):
                return self.finalized_boundary or self.initialized_observations(2)

            def metadata(self, name, args, result):
                outcome = super().metadata(name, args, result)
                state = self.fd_states.get(self.library_fd, {})
                if mode in ('wrong-library', 'wrong-profile') and state.get('metadata') == 2:
                    require(state['path_rechecked'] and state['bytes'] == 0 and not state['eof'] and self.prerequisites() and
                            not self.startup_done and not self.snapshot_done, 'opposite-profile image rejection phase differs')
                    self.failure = True
                return outcome

            def call(self, name, args, result):
                unchanged_parameters()
                require(not self.exit_group and not self.completed, 'stripped-host operation follows process exit')
                if self.config_fd is not None:
                    token = str(self.config_fd) + '</dev/null<char 1:3>>'
                    expected_name = ('newfstatat', 'ioctl', 'read', 'close')[self.config_stage - 1]
                    require(name == expected_name, 'stripped-host empty config descriptor sequence was interrupted')
                    if name == 'newfstatat':
                        require(args == [token, '""', '{st_mode=S_IFCHR|0666, st_rdev=makedev(0x1, 0x3), ...}', 'AT_EMPTY_PATH'] and
                                result == '0', 'stripped-host config char-device identity differs')
                    elif name == 'ioctl':
                        require(len(args) == 3 and args[:2] == [token, 'TCGETS'] and
                                result == '-1 ENOTTY (Inappropriate ioctl for device)', 'stripped-host config terminal query differs')
                        PBS.pointer(args[2])
                    elif name == 'read':
                        require(args == [token, '""', '4096'] and result == '0', 'stripped-host config must have exact empty EOF')
                    else:
                        require(args == [token] and result == '0', 'stripped-host config descriptor close differs')
                        self.config_fd = None
                    self.config_stage += 1
                    return
                if name == 'ppoll':
                    expected = '[{fd=0</dev/null<char 1:3>>, events=0}, ' + f'{{fd=1</evidence/{mode}.stdout.txt>, events=0}}, {{fd=2</evidence/{mode}.stderr.txt>, events=0}}]'
                    require(self.execs == 1 and not self.stream_polls and not self.archive_opened and
                            args == [expected, '3', '{tv_sec=0, tv_nsec=0}', 'NULL', '0'] and result == '0 (Timeout)',
                            'stripped-host inherited stream poll differs')
                    self.stream_polls = 1
                    return
                if name == 'futex':
                    require(mode in SUCCESS and self.crypto_wakes < len(CRYPTO_WAKE_OFFSETS) and
                            len(args) == 3 and args[1:] == ['FUTEX_WAKE_PRIVATE', '2147483647'] and result == '0' and
                            self.image_base is not None and re.fullmatch('0x[0-9a-f]{1,16}', args[0]) and
                            int(args[0], 16) == self.image_base + CRYPTO_WAKE_OFFSETS[self.crypto_wakes],
                            'stripped-host crypto wake address/operation/sequence differs')
                    if self.crypto_wakes < 13:
                        require(self.initialized_observations(1) and not self.finalized_boundary and not any(self.output) and
                                self.config_stage == (5 if self.crypto_wakes == 12 else 0),
                                'stripped-host crypto initialization wake phase differs')
                    else:
                        require(self.finalized_boundary and self.tid_queries == 2 and
                                tuple(bytes(value) for value in self.output) == expected_output(mode) and self.config_stage == 5 and
                                self.readers == {self.library_fd: self.library} and self.relro and
                                self.image_mappings == {(20423824, 0), (1695744, 0x115a000)},
                                'stripped-host crypto cleanup wake precedes complete finalization')
                    self.crypto_wakes += 1
                    return
                if name == 'openat' and len(args) >= 2 and args[1] == '"/dev/null"':
                    require(mode in SUCCESS and self.crypto_wakes == 12 and self.config_stage == 0 and
                            self.initialized_observations(1) and not self.finalized_boundary and not any(self.output) and
                            args == [CWD, '"/dev/null"', 'O_RDONLY'], 'stripped-host empty config open phase/flags differs')
                    match = re.fullmatch(r'([0-9]{1,10})</dev/null<char 1:3>>', result)
                    require(match is not None and 3 <= int(match[1]) <= 1048576 and int(match[1]) not in self.readers,
                            'stripped-host empty config requires one fresh annotated descriptor')
                    self.config_fd, self.config_stage = int(match[1]), 1
                    return
                if name == 'gettid' and self.tid_queries == 1 and mode in SUCCESS:
                    require(not self.exit_group and not self.completed and not args and result == self.pid and
                            self.initialized_observations(1) and not any(self.output), 'stripped-host publication thread query differs')
                    self.tid_queries = 2
                    return
                if name == 'getdents64' and len(args) == 3:
                    number, path = self.reader(args[0])
                    state = self.fd_states.get(number)
                    if state is not None and state['role'] == 'runtime-enum' and path == self.stdlib:
                        match = re.fullmatch(r'0x[0-9a-f]{1,16} /\* ([0-9]{1,3}) entries \*/', args[1])
                        value = PBS.result_number(result)
                        require(not self.exit_group and not self.completed and not state['eof'] and self.image_ready() and
                                state['metadata'] == 1 and args[2] == '32768' and match is not None and value is not None and
                                0 <= value <= 32768 and (value == 0) == (int(match[1]) == 0), 'stripped-host root enumeration grammar differs')
                        state['bytes'] += int(match[1])
                        if value == 0:
                            require(state['bytes'] == 191, 'stripped-host projected root inventory differs')
                            state['eof'] = True
                            self.enums['runtime', path] = 191
                        return
                if name == 'read' and len(args) == 3:
                    number, path = self.reader(args[0])
                    state = self.fd_states.get(number)
                    if mode in ('wrong-library', 'wrong-profile') and path == self.library:
                        raise TraceError('opposite-profile size rejection cannot read image payload')
                    if mode == 'corrupt-entry' and path == self.archive and self.uname_queries:
                        data = corrupt_bytes()
                        value = PBS.result_number(result)
                        require(not self.exit_group and not self.completed and self.execs == 1 and not self.failure and
                                not self.pending_checked and not self.corrupt_read and state is not None and state['role'] == 'archive' and
                                args[2] == str(len(data)) and value == len(data) and private.payload(args[1], value) == data[:256] and
                                self.archive_cursor == record['corrupt_offset'] and self.archive_read == record['readiness']['archive_read_bytes'],
                                'stripped-host CRC requires its one complete first-entry read')
                        self.corrupt_read = True
                        self.last_read = self.archive_cursor, value
                        self.archive_ranges.append((self.archive_cursor, self.archive_cursor + value))
                        self.archive_cursor += value
                        self.archive_read += value
                        return
                outcome = super().call(name, args, result)
                if mode == 'corrupt-library' and name == 'read' and len(args) == 3 and self.library_fd in self.fd_states:
                    state = self.fd_states[self.library_fd]
                    if state['eof']:
                        require(state['metadata'] == 2 and state['bytes'] == parameters.expected_size and self.prerequisites() and
                                not self.startup_done and not self.snapshot_done, 'corrupt image rejection lacks complete hashing/EOF')
                        self.failure = True
                return outcome

            def control_ready(self):
                if self.alias_opened or self.image_mappings or self.readers or self.fd_states:
                    return False
                if mode == 'corrupt-entry':
                    return (self.corrupt_read and not self.cache_checks and not self.startup_done and not self.snapshot_done and
                            self.last_read == (record['corrupt_offset'], len(corrupt_bytes())) and
                            self.archive_read == record['readiness']['archive_read_bytes'] + len(corrupt_bytes()) and
                            self.archive_cursor == record['corrupt_offset'] + len(corrupt_bytes()))
                return (self.archive_complete() and self.failure and self.prerequisites() and not self.startup_done and
                        not self.snapshot_done)

            def finish(self):
                super().finish()
                require(self.stream_polls == 1 and self.crypto_wakes == (14 if mode in SUCCESS else 0) and
                        self.config_stage == (5 if mode in SUCCESS else 0) and self.config_fd is None,
                        'stripped-host stream/crypto/config observations are incomplete')
                require(self.tid_queries == (2 if mode in SUCCESS else 0), 'stripped-host initialized thread count differs')
                if mode not in SUCCESS:
                    require(not (self.virtual_queries or self.overcommit_reads or self.timezone_queries or self.entropy),
                            'stripped-host rejection follows Python initialization')

        self.checker = SelectedHost(internal, size, record)
        self.checker.stream_polls = self.checker.crypto_wakes = self.checker.config_stage = 0
        self.checker.config_fd = None

    def line(self, line):
        self._unchanged_parameters()
        self.checker.line(line)

    def finish(self):
        self._unchanged_parameters()
        self.checker.finish()


def check_lines(lines, mode, size, record):
    checker = Checker(mode, size, record)
    total = 0
    for number, line in enumerate(lines, 1):
        total += len(line.encode('utf-8'))
        require(number <= MAX_RECORDS and total <= MAX_TRACE_BYTES and len(line) <= MAX_LINE_CHARACTERS + 1 and
                line.endswith('\n') and '\r' not in line, 'stripped-host trace exceeds complete-line bounds')
        checker.line(line.rstrip('\n'))
    checker.finish()
    return total


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--emit-metadata', nargs=2, type=Path, metavar=('ARCHIVES', 'OUTPUT'))
    parser.add_argument('trace', nargs='?', type=Path)
    parser.add_argument('--mode', choices=MODES)
    parser.add_argument('--stdout-file', type=Path)
    parser.add_argument('--stderr-file', type=Path)
    parser.add_argument('--metadata-file', type=Path)
    parser.add_argument('--archive-file', type=Path)
    args = parser.parse_args()
    if args.emit_metadata:
        directory, output = args.emit_metadata
        output.write_text(json.dumps({'schema_version': 0, 'archives': {
            mode: archive_record(directory / (mode + '.glue'), mode) for mode in MODES}}, sort_keys=True, indent=2) + '\n')
        return 0
    require(args.trace and args.mode and args.stdout_file and args.stderr_file and args.metadata_file,
            'trace checks require mode, output files and retained metadata')
    record = retained_metadata(args.metadata_file, args.mode)
    size = record['bytes']
    if args.archive_file:
        require(SOURCE.typed_equal(archive_record(args.archive_file, args.mode), record),
                'stripped-host retained metadata differs from independently inspected archive')
    for path, expected in zip((args.stdout_file, args.stderr_file), expected_output(args.mode)):
        with path.open('rb') as stream:
            observed = stream.read(len(expected) + 1)
        require(observed == expected, 'stripped-host captured stdout/stderr differs')
    with (gzip.open if args.trace.suffix == '.gz' else open)(args.trace, 'rt', encoding='utf-8') as stream:
        def lines():
            while line := stream.readline(MAX_LINE_CHARACTERS + 2):
                yield line
        check_lines(lines(), args.mode, size, record)
    print('PASS exact stripped-host trace: ' + args.mode)
    return 0


if __name__ == '__main__':
    try:
        raise SystemExit(main())
    except (OSError, EOFError, ValueError, KeyError, TypeError, UnicodeError, struct.error,
            zipfile.BadZipFile, zlib.error, TraceError) as error:
        print('Python stripped-host trace rejected: ' + str(error), file=sys.stderr)
        raise SystemExit(1)
