#!/usr/bin/env python3
"""Separate strict complete traces for pinned stock install-only host source-snapshot workloads.

Only these representative applications are evidence workloads. This is neither
a Python sandbox nor a compatibility policy for arbitrary Python packages.
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
import zipfile


def policy(filename, name):
    spec = importlib.util.spec_from_file_location(name, Path(__file__).with_name(filename))
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


SOURCE = policy('check-linux-python-source-app-trace.py', 'paired_source_policy')
PRODUCT, BASE, PBS, TraceError = SOURCE.PRODUCT, SOURCE.BASE, SOURCE.PBS, SOURCE.TraceError
COMMON = policy('check-linux-python-bootstrap-trace.py', 'install_host_source_common')
PRODUCT.unify(COMMON)
ROOT = Path(__file__).resolve().parents[1]
DIRECTORY = '/build-target/relocated Python install host source apps'
PROGRAM = DIRECTORY + '/glue'
PREFIX = '/build-target/host Python install source apps'
APPS = ('minimal', 'resources', 'stdlib', 'app-error', 'syntax', 'nul', 'corrupt-source')
CONTROLS = ('missing-source', 'wrong-source', 'deep-cache', 'startup-native', 'startup-bytecode', 'missing-library', 'missing-cache', 'wrong-cache', 'extra-cache')
MODES = APPS + CONTROLS
INITIALIZED = set(APPS) - {'corrupt-source'}
SUCCESS = {'minimal', 'resources', 'stdlib'}
CONTROL_SOURCE = 'asyncio/taskgroups.py'
CONTROL_CACHE = 'site-packages/pip/_vendor/idna/__pycache__'
CONTROL_STARTUP_CACHE = 'encodings/__pycache__/__init__.cpython-313.pyc'
EXTRA_STARTUP_CACHE = 'encodings/__pycache__/unreviewed.cpython-313.pyc'
CORRUPT_KEY, CORRUPT_BYTES = SOURCE.CORRUPT_KEY, SOURCE.CORRUPT_BYTES
MAX_TRACE_BYTES, MAX_LINE_CHARACTERS, MAX_RECORDS = SOURCE.MAX_TRACE_BYTES, SOURCE.MAX_LINE_CHARACTERS, SOURCE.MAX_RECORDS
TARGET = SOURCE.TARGET
SPECS = json.loads((ROOT / 'fixtures/python-install-host-source-apps/source-pins.json').read_text())['files']
CACHE_PINS = json.loads((ROOT / 'fixtures/python-install-host-source-apps/cache-pins.json').read_text())
CACHE_SPECS = CACHE_PINS['files']
CACHE_MAGIC = b'\xf3\r\r\n'
CACHE_MTIME = 1791559484
STARTUP = {'codecs.py', 'encodings/__init__.py', 'encodings/aliases.py', 'encodings/ascii.py', 'encodings/latin_1.py', 'encodings/utf_8.py'}
RAW_IMPORTS = {'encodings/__init__.py', 'encodings/aliases.py', 'encodings/utf_8.py'}
READ_FLAGS = {'O_RDONLY', 'O_NONBLOCK', 'O_NOFOLLOW', 'O_CLOEXEC'}
DIRECTORY_FLAGS = READ_FLAGS | {'O_DIRECTORY'}
ENUM_FLAGS = {'O_RDONLY', 'O_NONBLOCK', 'O_CLOEXEC', 'O_DIRECTORY'}


def prefix_for(mode):
    return PREFIX + (' ' + mode if mode in CONTROLS else '')


def archive_for(mode):
    if mode not in MODES:
        raise TraceError('unknown host source-app workload')
    return DIRECTORY + '/' + mode + '.glue'


def identity_for(mode):
    if mode == 'stdlib':
        return 'stdlib.source', 'app/tasks/stdlib.py', 'stdlib'
    return SOURCE.IDENTITIES['minimal' if mode in CONTROLS else mode]


def expected_application(mode):
    if mode == 'stdlib':
        root = ROOT / 'fixtures/python-host-source-apps/input-stdlib'
        return {path.relative_to(root).as_posix(): {'size': path.stat().st_size, 'sha256': hashlib.sha256(path.read_bytes()).hexdigest(), 'compression': 'stored'}
                for path in sorted(root.rglob('*')) if path.is_file()}
    return SOURCE.expected_application('minimal' if mode in CONTROLS else mode)


def provider_contract(mode):
    prefix = prefix_for(mode)
    return {'abi': {'debug': False, 'gil': 'conventional', 'language': 'python', 'version': {'major': 3, 'minor': 13, 'patch': 16}},
            'build_id': 'pbs-20261009-cpython-3.13.16-pgo-lto-host-install-source-apps-v1',
            'provisioning': {'mode': 'host', 'discovery': 'explicit_paths', 'runtime_library': prefix + '/lib/libpython3.13.so.1.0', 'stdlib': prefix + '/lib/python3.13'},
            'required_features': [], 'target': 'linux-arm64'}


def fixed_specs():
    helper = (ROOT / 'fixtures/python-imports/bootstrap.py').read_bytes()
    return {'python/archive-importer.py': {'size': len(helper), 'sha256': hashlib.sha256(helper).hexdigest(), 'compression': 'deflate'}}


def expected_output(mode):
    archive_for(mode)
    if mode == 'stdlib':
        return b'PASS source-app=stdlib fractions=1/2 statistics=42 xml=42 resources=streams\n', b''
    if mode in APPS:
        return SOURCE.expected_output(mode)
    stdlib = prefix_for(mode) + '/lib/python3.13/'
    messages = {
        'missing-source': f'host path {stdlib}{CONTROL_SOURCE}: No such file or directory (os error 2)',
        'wrong-source': f'host file identity mismatch: {stdlib}{CONTROL_SOURCE}',
        'deep-cache': f'host startup bytecode cache is unsupported: {stdlib}{CONTROL_CACHE}',
        'startup-native': f'host startup encodings entry is outside pinned sources: {stdlib}encodings/__init__.cpython-313-aarch64-linux-gnu.so',
        'startup-bytecode': f'host startup encodings entry is outside pinned sources: {stdlib}encodings/__init__.pyc',
        'missing-library': f'host path {prefix_for(mode)}/lib/libpython3.13.so.1.0: No such file or directory (os error 2)',
        'missing-cache': 'host startup cache inventory differs from pinned caches',
        'wrong-cache': f'host file identity mismatch: {stdlib}{CONTROL_STARTUP_CACHE}',
        'extra-cache': f'host startup cache entry is outside pinned caches: {stdlib}{EXTRA_STARTUP_CACHE}',
    }
    return b'', ('glue: ' + messages[mode] + '\n').encode('ascii')


def archive_record(path, mode):
    size = path.stat().st_size
    if not 64 < size <= 16 * 1024 * 1024:
        raise TraceError('host source archive exceeds pinned profile bounds')
    with path.open('rb') as stream:
        locator = stream.read(64)
        if len(locator) != 64 or locator[:8] != b'GLUERS00' or locator[8:16] != b'\0' * 8:
            raise TraceError('host source archive lacks exact locator')
        length = struct.unpack_from('<Q', locator, 16)[0]
        if not 0 < length <= 1024 * 1024:
            raise TraceError('host source manifest exceeds bounded profile')
        raw = stream.read(length)
        if len(raw) != length or hashlib.sha256(raw).digest() != locator[32:64] or struct.unpack_from('<Q', locator, 24)[0] != size - 64 - length:
            raise TraceError('host source locator regions or manifest digest differs')
        manifest = json.loads(raw)
        if raw != json.dumps(manifest, sort_keys=True, separators=(',', ':'), ensure_ascii=False).encode('utf-8'):
            raise TraceError('host source manifest is not canonical')
        stream.seek(0)
        digest = hashlib.file_digest(stream, 'sha256').hexdigest()
    app_id, entry, component = identity_for(mode)
    expected = {'schema_version': 0, 'app_id': app_id, 'entrypoint': component, 'components': {component: {'entry_point': entry, 'native_modules': [], 'runtime': 'python'}},
                'runtimes': {'python': provider_contract(mode)}, 'targets': {'linux-arm64': TARGET}, 'native_modules': {}, 'host_imports': {},
                'resources': fixed_specs() | expected_application(mode)}
    if not SOURCE.typed_equal(manifest, expected):
        raise TraceError('actual host source declarations differ from pinned provider/checked-in workload')
    offset = None
    with zipfile.ZipFile(path) as archive:
        directory = archive.start_dir
        if not 0 < size - directory <= 256 * 1024 or len(archive.infolist()) != len(manifest['resources']) or set(archive.namelist()) != set(manifest['resources']):
            raise TraceError('host source ZIP inventory differs from complete declarations')
        for key, spec in manifest['resources'].items():
            info = archive.getinfo(key)
            if info.file_size != spec['size'] or info.compress_type != (zipfile.ZIP_STORED if spec['compression'] == 'stored' else zipfile.ZIP_DEFLATED):
                raise TraceError('host source ZIP member size/storage differs')
            if mode != 'corrupt-source' or key != CORRUPT_KEY:
                data = archive.read(key)
                if len(data) != spec['size'] or hashlib.sha256(data).hexdigest() != spec['sha256']:
                    raise TraceError('actual host source application/helper bytes differ from fixture identities')
        if mode == 'corrupt-source':
            info = archive.getinfo(CORRUPT_KEY)
            # Opening verifies the local filename/flags without consuming the
            # deliberately CRC-damaged payload.
            with archive.open(CORRUPT_KEY):
                pass
            with path.open('rb') as stream:
                stream.seek(info.header_offset)
                header = stream.read(30)
                names, extra = struct.unpack_from('<HH', header, 26)
                offset = info.header_offset + 30 + names + extra
                stream.seek(offset)
                if info.compress_type != zipfile.ZIP_STORED or info.file_size != len(CORRUPT_BYTES) or stream.read(len(CORRUPT_BYTES)) != CORRUPT_BYTES:
                    raise TraceError('corrupt stored source differs from selected twelve bytes')
    record = {'bytes': size, 'sha256': digest, 'manifest_sha256': hashlib.sha256(raw).hexdigest(), 'manifest_bytes': length, 'zip_directory_offset': directory,
              'app_id': app_id, 'entry': entry, 'component': component, 'application': expected_application(mode), 'provider': provider_contract(mode), 'target': TARGET,
              'readiness': PRODUCT.readiness_record(path)}
    if offset is not None:
        record['corrupt_offset'] = offset
    return record


def retained_metadata(path, mode, size):
    if path.stat().st_size > 128 * 1024:
        raise TraceError('host source metadata exceeds bounded profile')
    data = json.loads(path.read_text())
    if not isinstance(data, dict) or set(data) != {'schema_version', 'archives'} or type(data.get('schema_version')) is not int or data['schema_version'] != 0 or not isinstance(data.get('archives'), dict) or set(data['archives']) != set(MODES):
        raise TraceError('retained host source metadata inventory differs')
    record = data['archives'][mode]
    keys = {'bytes', 'sha256', 'manifest_sha256', 'manifest_bytes', 'zip_directory_offset', 'app_id', 'entry', 'component', 'application', 'provider', 'target', 'readiness'} | ({'corrupt_offset'} if mode == 'corrupt-source' else set())
    if not isinstance(record, dict) or set(record) != keys or type(record.get('bytes')) is not int or record['bytes'] != size or not 64 < size <= 16 * 1024 * 1024 or (record.get('app_id'), record.get('entry'), record.get('component')) != identity_for(mode):
        raise TraceError('retained host source metadata identity differs')
    if not SOURCE.typed_equal(record['application'], expected_application(mode)) or not SOURCE.typed_equal(record['provider'], provider_contract(mode)) or not SOURCE.typed_equal(record['target'], TARGET):
        raise TraceError('retained host source application/provider/target differs')
    if any(not isinstance(record.get(key), str) or re.fullmatch('[0-9a-f]{64}', record[key]) is None for key in ('sha256', 'manifest_sha256')):
        raise TraceError('retained host source digest is noncanonical')
    PRODUCT.validate_readiness(record.get('readiness'), size, (record.get('manifest_bytes'), record.get('zip_directory_offset')))
    if mode == 'corrupt-source' and (type(record.get('corrupt_offset')) is not int or not 64 + record['manifest_bytes'] <= record['corrupt_offset'] <= record['zip_directory_offset'] - len(CORRUPT_BYTES)):
        raise TraceError('corrupt host source offset is outside admitted payload')
    return record


def payload(token, returned):
    match = re.fullmatch(r'"((?:[^"\\]|\\.)*)"(\.\.\.)?', token)
    if match is None:
        raise TraceError('read data is not a complete or bounded visible byte string')
    try:
        visible = bytes(match[1], 'ascii').decode('unicode_escape').encode('latin1')
    except (ValueError, UnicodeError) as error:
        raise TraceError('read byte encoding is invalid') from error
    if len(visible) != min(returned, 256) or bool(match[2]) != (returned > 256):
        raise TraceError('visible bytes/truncation disagree with the returned read count')
    return visible


class Checker(COMMON.Checker):
    def __init__(self, mode, size, record):
        super().__init__('success' if mode in SUCCESS else 'app-error')
        self.cell, self.record = mode, record
        self.expected = expected_output(mode)
        self.archive, self.archive_bytes = archive_for(mode), size
        self.archive_sized = self.locator_read = False
        self.uname_queries = 0
        self.stdlib = prefix_for(mode) + '/lib/python3.13'
        self.library = prefix_for(mode) + '/lib/libpython3.13.so.1.0'
        self.sources = {self.stdlib + '/' + key: spec['size'] for key, spec in SPECS.items()}
        self.cache_directory = self.stdlib + '/encodings/__pycache__'
        self.startup_caches = {self.stdlib + '/' + key: spec['size'] for key, spec in CACHE_SPECS.items()}
        source_directories = {str(parent) for path in self.sources for parent in Path(path).parents}
        self.directories = source_directories | {self.cache_directory}
        self.host_paths = self.directories | set(self.sources) | set(self.startup_caches) | {self.library}
        self.caches = {path + '/__pycache__' for path in source_directories if path == self.stdlib or path.startswith(self.stdlib + '/')} - {self.cache_directory}
        self.shadow_paths = {self.stdlib + '/' + name + suffix for name in ('codecs', 'encodings') for suffix in ('.pyc', '.pyo', '.cpython-313-aarch64-linux-gnu.so', '.abi3.so', '.so')}
        self.shadow_paths |= {self.stdlib + '/codecs', self.stdlib + '/encodings.py'}
        self.raw_sources = {self.stdlib + '/' + key for key in RAW_IMPORTS}
        self.startup_sources = {self.stdlib + '/' + key for key in STARTUP}
        self.probes = {self.stdlib + '/encodings/__init__' + suffix for suffix in ('.cpython-313-aarch64-linux-gnu.so', '.abi3.so', '.so')}
        self.fd_states = {}
        self.path_metadata = {}
        self.cache_checks, self.shadows, self.enc_members, self.cache_members = set(), set(), set(), set()
        self.cache_counts = {}
        self.startup_done, self.snapshot_done, self.raw_done, self.verified_caches, self.raw_cache_done = set(), set(), set(), set(), set()
        self.library_fd = self.alias_fd = None
        self.alias_opened = self.alias_header = self.alias_metadata = False
        self.prereq_enum = self.cache_enum = self.failure = False
        self.enums = {}
        self.corrupt_read = False
        self.last_read = None
        self.reservation = self.image_base = None
        self.trims = set()
        self.guard = self.bss = self.relro = False
        self.entropy = self.remaps = 0
        self.anonymous = {}
        self.import_probes_seen = set()
        self.finalized_boundary = False
        self.pending_checked = None
        self.last_pre_path = None

    def inherited(self, token):
        number, path, deleted = COMMON.descriptor(token)
        if deleted or path != {0: '/dev/null', 1: f'/evidence/{self.cell}.stdout.txt', 2: f'/evidence/{self.cell}.stderr.txt'}.get(number):
            raise TraceError('host source workload inherited stream identity differs')
        return number

    def archive_complete(self):
        return (self.archive_opened == 1 and self.archive_sized and self.locator_read and self.archive_read == self.archive_bytes + 20 and
                self.archive not in self.readers.values() and PRODUCT.merged_ranges(self.archive_ranges) == [[0, self.archive_bytes]])

    def live_ancestors(self, path):
        retained = {self.readers[fd] for fd, state in self.fd_states.items() if state['role'] == 'directory' and state['metadata'] >= 1 and self.path_metadata.get(self.readers[fd], 0) >= state['path_before'] + 1}
        return all(str(parent) in retained for parent in Path(path).parents)

    def prerequisites(self):
        return self.cache_checks == self.caches and self.shadows == self.shadow_paths and self.prereq_enum and self.cache_enum and self.verified_caches == set(self.startup_caches)

    def startup_ready(self):
        return self.prerequisites()

    def host_complete(self):
        state = self.fd_states.get(self.library_fd, {})
        return (self.startup_ready() and self.startup_done == self.startup_sources and self.snapshot_done == set(self.sources) and
                state.get('eof') and state.get('rewound') and state.get('metadata') == 3 and
                {self.readers[fd] for fd, s in self.fd_states.items() if s['role'] == 'startup' and s['eof'] and s['rewound'] and s['metadata'] == 3 and s['path_rechecked']} == self.startup_sources and
                {self.readers[fd] for fd, s in self.fd_states.items() if s['role'] == 'cache' and s['eof'] and s['rewound'] and s['metadata'] == 3 and s['path_rechecked']} == set(self.startup_caches) and
                not any(s['role'] == 'snapshot' for s in self.fd_states.values()) and
                self.directories <= {self.readers[fd] for fd, s in self.fd_states.items() if s['role'] == 'directory' and s['metadata'] >= 1 and self.path_metadata.get(self.readers[fd], 0) >= s['path_before'] + 1})

    def image_ready(self):
        return (self.host_complete() and self.alias_opened and self.alias_header and self.alias_metadata and self.alias_fd is None and
                self.image_mappings == {(20423824, 0), (1695744, 0x115a000)} and self.guard and self.bss and self.relro and self.trims == {'prefix', 'tail'})

    def runtime_ready(self):
        return self.finalized_boundary or (self.image_ready() and self.raw_done == self.raw_sources and self.raw_cache_done == set(self.startup_caches) and self.virtual_queries == self.overcommit_reads == self.timezone_queries == self.tid_queries == self.entropy == 1 and
                self.remaps == 4 and self.enums.get(('runtime', self.stdlib)) == 199 and self.enums.get(('runtime', self.stdlib + '/encodings')) == 125 and self.import_probes_seen == self.probes)

    def control_ready(self):
        if self.alias_opened or self.image_mappings or self.readers:
            return False
        if self.cell == 'corrupt-source':
            return self.corrupt_read and self.last_read == (self.record['corrupt_offset'], len(CORRUPT_BYTES)) and not self.cache_checks and not self.fd_states
        if not self.archive_complete() or not self.failure:
            return False
        if self.cell == 'deep-cache':
            target = self.stdlib + '/' + CONTROL_CACHE
            return self.cache_checks == {path for path in self.caches if path <= target} and not self.shadows and not self.startup_done and not self.snapshot_done
        if self.cell in {'startup-native', 'startup-bytecode'}:
            return self.cache_checks == self.caches and self.shadows == self.shadow_paths and not self.startup_done and not self.snapshot_done and not self.cache_members and not self.verified_caches
        if self.cell in {'missing-cache', 'extra-cache', 'wrong-cache'}:
            selected = set(self.startup_caches) - {self.stdlib + '/' + CONTROL_STARTUP_CACHE}
            return (self.cache_checks == self.caches and self.shadows == self.shadow_paths and self.prereq_enum and
                    not self.startup_done and not self.snapshot_done and not self.verified_caches and
                    (self.cell != 'missing-cache' or self.cache_members == selected) and
                    (self.cell != 'wrong-cache' or self.cache_enum and self.cache_members == set(self.startup_caches)))
        if self.cell == 'missing-library':
            return self.prerequisites() and not self.startup_done and not self.snapshot_done
        target = self.stdlib + '/' + CONTROL_SOURCE
        return self.prerequisites() and self.startup_done == self.startup_sources and self.snapshot_done == {path for path in self.sources if path < target}

    def metadata(self, name, args, result):
        self.last_pre_path = None
        value = COMMON.result_number(result)
        if name == 'statx':
            self.arity(name, args, (5,))
            if args[2:4] != ['AT_STATX_SYNC_AS_STAT|' + ('AT_SYMLINK_NOFOLLOW' if args[0] == COMMON.CWD else 'AT_EMPTY_PATH'), 'STATX_ALL']:
                raise TraceError('host snapshot statx flags differ')
            body = args[4]
            if value == 0:
                match = re.fullmatch(r'\{stx_mask=STATX_ALL\|STATX_MNT_ID, stx_attributes=(?:0|STATX_ATTR_MOUNT_ROOT), stx_mode=(S_IFREG|S_IFDIR)\|([0-7]{4}), stx_size=([0-9]{1,20}), \.\.\.\}', body)
                if match is None:
                    raise TraceError('host snapshot statx kind/size is unparsed')
                body = '{st_mode=' + match[1] + '|' + match[2] + ', st_size=' + match[3] + ', ...}'
            flags = 'AT_SYMLINK_NOFOLLOW' if args[0] == COMMON.CWD else 'AT_EMPTY_PATH'
            return self.metadata('newfstatat', [args[0], args[1], body, flags], result)
        self.arity(name, args, (2,) if name == 'fstat' else (4,))
        if name == 'fstat':
            number, _, _ = COMMON.descriptor(args[0])
            if number < 3:
                return super().call(name, args, result)
            number, path = self.reader(args[0]); body = args[1]
        elif args[0] == COMMON.CWD:
            number, path, body = None, COMMON.quoted(args[1]), args[2]
            if args[3] not in {'0', 'AT_SYMLINK_NOFOLLOW'}:
                raise TraceError('unapproved host path metadata flags')
        else:
            number, path = self.reader(args[0]); body = args[2]
            if args[1] != '""' or args[3] != 'AT_EMPTY_PATH':
                raise TraceError('metadata must identify the live exact descriptor')
        known = self.host_paths | self.caches | self.shadow_paths
        if path in known and not self.archive_complete():
            raise TraceError('host metadata precedes complete archive verification/closure')
        if path in self.caches and not self.alias_opened:
            if number is not None or args[3] != 'AT_SYMLINK_NOFOLLOW' or not self.live_ancestors(path):
                raise TraceError('cache checks require retained no-follow directory owners')
            if self.cell == 'deep-cache' and path == self.stdlib + '/' + CONTROL_CACHE:
                if value != 0 or re.fullmatch(r'\{st_mode=S_IFDIR\|[0-7]{4}, st_size=[0-9]{1,20}, \.\.\.\}', body) is None:
                    raise TraceError('deep cache rejection lacks its present directory')
                self.failure = True
            else:
                if result != '-1 ENOENT (No such file or directory)':
                    raise TraceError('every selected source cache must be absent')
                COMMON.pointer(body)
            self.cache_counts[path] = self.cache_counts.get(path, 0) + 1
            if self.cache_counts[path] > 1:
                raise TraceError('cache prerequisite repeats beyond selected phases')
            self.cache_checks.add(path); return
        if path in self.shadow_paths and not self.alias_opened:
            if number is not None or args[3] != 'AT_SYMLINK_NOFOLLOW' or result != '-1 ENOENT (No such file or directory)' or self.cache_checks != self.caches or not self.live_ancestors(path) or path in self.shadows:
                raise TraceError('startup exclusion must follow all caches and fail once')
            COMMON.pointer(body); self.shadows.add(path); return
        if path in self.probes and self.alias_opened:
            if not self.image_ready() or result != '-1 ENOENT (No such file or directory)' or number is not None or path in self.import_probes_seen:
                raise TraceError('startup import fallback probe is outside its selected phase')
            COMMON.pointer(body); self.import_probes_seen.add(path); return
        if path not in self.host_paths:
            return super().call(name, args, result)
        if self.cell in {'missing-source', 'missing-library'} and path == (self.stdlib + '/' + CONTROL_SOURCE if self.cell == 'missing-source' else self.library):
            if number is not None or args[3] != 'AT_SYMLINK_NOFOLLOW' or result != '-1 ENOENT (No such file or directory)' or not self.live_ancestors(path):
                raise TraceError('missing prerequisite must fail its guarded no-follow lookup')
            if not self.startup_ready() or self.cell == 'missing-source' and (self.startup_done != self.startup_sources or self.snapshot_done != {source for source in self.sources if source < path}):
                raise TraceError('missing prerequisite lookup occurs before its exact complete validation phase')
            COMMON.pointer(body); self.failure = True; return
        expected_kind = 'S_IFDIR' if path in self.directories else 'S_IFREG'
        match = re.fullmatch(r'\{st_mode=' + expected_kind + r'\|[0-7]{4}, st_size=([0-9]{1,20}), \.\.\.\}', body)
        if value != 0 or match is None or (expected_kind == 'S_IFREG' and int(match[1]) != (COMMON.LIBRARY_BYTES if path == self.library else self.startup_caches[path] if path in self.startup_caches else self.sources[path])):
            raise TraceError('host prerequisite metadata kind/pinned size differs')
        COMMON.unsigned(match[1])
        if self.pending_checked is not None:
            pending = self.fd_states[self.pending_checked]
            if number == self.pending_checked and pending['metadata'] == 0:
                pass
            elif number is None and path == self.readers[self.pending_checked] and pending['metadata'] == 1:
                pending['path_rechecked'] = True
                self.pending_checked = None
            else:
                raise TraceError('checked open requires its exact descriptor metadata then no-follow path recheck')
        if number is None:
            if not self.alias_opened:
                if args[3] != 'AT_SYMLINK_NOFOLLOW':
                    raise TraceError('pre-load path metadata must reject symlinks')
                self.path_metadata[path] = self.path_metadata.get(path, 0) + 1
                self.last_pre_path = None if any(self.readers[fd] == path and s['role'] in {'directory', 'library', 'startup', 'snapshot', 'cache'} and s['path_rechecked'] and self.path_metadata[path] == s['path_before'] + 1 for fd, s in self.fd_states.items()) else path
                if path in self.startup_caches and self.shadows == self.shadow_paths and self.library_fd is None:
                    self.cache_members.add(path)
                elif path.startswith(self.stdlib + '/encodings/') and self.shadows == self.shadow_paths and self.library_fd is None:
                    self.enc_members.add(path)
            elif not self.image_ready() or self.raw_done == self.raw_sources or path not in {self.stdlib, self.stdlib + '/encodings'} | self.raw_sources | set(self.startup_caches):
                raise TraceError('runtime metadata exceeds startup-only host lookup closure')
        elif number == self.alias_fd:
            if self.alias_metadata or not self.alias_header:
                raise TraceError('one alias metadata query must follow its exact header')
            self.alias_metadata = True
        elif number in self.fd_states:
            state = self.fd_states[number]
            if state['role'] in {'library', 'startup', 'snapshot', 'cache'} and state['metadata'] >= 2 and not state['eof']:
                raise TraceError('post-read metadata must follow complete file bytes and EOF')
            state['metadata'] += 1

    def call(self, name, args, result):
        value = COMMON.result_number(result)
        if self.exit_group or self.completed or (value is None and name != 'exit_group'):
            raise TraceError('operation follows exit or has an incomplete result')
        if name != 'execve' and self.execs != 1:
            raise TraceError('trace must begin with its sole selected exec')
        if name not in {'statx', 'newfstatat', 'fstat', 'openat', 'brk'}:
            self.last_pre_path = None
        if self.pending_checked is not None and name not in {'statx', 'newfstatat', 'fstat'}:
            raise TraceError('operation interrupts a selected path/open/descriptor/path identity check')
        if self.failure and name in {'openat', 'read', 'lseek', 'statx', 'newfstatat', 'fstat', 'getdents64', 'mmap', 'mremap', 'mprotect', 'fcntl', 'ioctl', 'uname'}:
            raise TraceError('validation resumes after its observed prerequisite failure')
        if self.output[1] and name not in {'write', 'exit_group'}:
            if name == 'sigaltstack' and args == ['{ss_sp=NULL, ss_flags=SS_DISABLE, ss_size=16384}', 'NULL'] and result == '0':
                return super().call(name, args, result)
            if name != 'munmap' or len(args) != 2 or args[0] == 'NULL' or not re.fullmatch(r'0x[0-9a-f]{1,16}', args[0]) or self.anonymous.get(int(args[0], 16)) != COMMON.unsigned(args[1]):
                raise TraceError('runtime work resumes after rejection publication')
        if name == 'execve':
            self.arity(name, args, (3,))
            if self.execs or args[:2] != [json.dumps(PROGRAM), json.dumps([PROGRAM, 'run', self.archive])] or re.fullmatch(r'0x[0-9a-f]{1,16} /\* [0-9]{1,6} vars \*/', args[2]) is None or value != 0:
                raise TraceError('execve differs from the exact product workload')
            self.execs = 1; return
        if name == 'uname':
            fact = self.record['readiness']
            if self.uname_queries or len(args) != 1 or re.fullmatch(r'\{sysname="Linux", nodename="[A-Za-z0-9][A-Za-z0-9_.-]{0,63}", \.\.\.\}', args[0]) is None or result != '0' or not self.archive_sized or not self.locator_read or self.archive not in self.readers.values() or self.archive_read != fact['archive_read_bytes'] or self.archive_cursor != fact['archive_cursor'] or PRODUCT.range_digest(self.archive_ranges) != fact['ranges_sha256']:
                raise TraceError('readiness must follow exact metadata admission before all payload/host reads')
            self.uname_queries = 1; return
        if name in {'statx', 'newfstatat', 'fstat'}:
            return self.metadata(name, args, result)
        if name == 'memfd_create':
            raise TraceError('host provider must not create a memfd or use bundled fallback')
        if name == 'openat':
            self.arity(name, args, (3,))
            pre_path, self.last_pre_path = self.last_pre_path, None
            if args[0] != COMMON.CWD:
                raise TraceError('unexpected filesystem directory descriptor')
            path = COMMON.quoted(args[1]); flags = BASE.flags(args[2], DIRECTORY_FLAGS)
            alias = re.fullmatch(r'/proc/self/fd/([0-9]{1,10})', path)
            role, target = None, path
            if path == self.archive:
                if self.archive_opened or flags != {'O_RDONLY', 'O_CLOEXEC'}:
                    raise TraceError('archive must open once read-only')
                self.archive_opened = 1; role = 'archive'
            elif alias:
                if self.cell not in INITIALIZED or not self.host_complete() or self.alias_opened or int(alias[1]) != self.library_fd or flags != {'O_RDONLY', 'O_CLOEXEC'}:
                    raise TraceError('selected library alias precedes complete source snapshots')
                role, target, self.alias_opened = 'alias', self.library, True
            elif path in self.host_paths:
                if not self.archive_complete():
                    raise TraceError('host opens precede verified archive closure')
                if flags == DIRECTORY_FLAGS and path in self.directories and not self.alias_opened:
                    role = 'directory'
                elif flags == READ_FLAGS and path in set(self.sources) | set(self.startup_caches) | {self.library} and not self.alias_opened:
                    if not self.live_ancestors(path):
                        raise TraceError('host hashing lacks retained ancestors')
                    if path in self.startup_caches:
                        if not self.cache_enum or path in self.verified_caches or self.library_fd is not None:
                            raise TraceError('cache hashing must follow the closed cache inventory before the host library')
                        role = 'cache'
                    elif not self.startup_ready():
                        raise TraceError('host hashing precedes complete cache/startup guards')
                    else:
                        role = 'library' if path == self.library else 'startup' if path in self.startup_sources and path not in self.startup_done else 'snapshot'
                    if role not in {'library', 'cache'} and not all(self.fd_states.get(self.library_fd, {}).get(field) for field in ('eof', 'rewound')):
                        raise TraceError('source hashing precedes complete pinned library verification')
                    if role == 'snapshot' and (self.startup_done != self.startup_sources or path in self.snapshot_done or any(s['role'] == 'snapshot' for s in self.fd_states.values())):
                        raise TraceError('snapshots must be sequential after six startup verifications')
                elif flags == ENUM_FLAGS and path in {self.stdlib, self.stdlib + '/encodings', self.cache_directory}:
                    if self.alias_opened:
                        if not self.image_ready() or self.raw_done == self.raw_sources:
                            raise TraceError('runtime enumeration exceeds image/startup phase')
                        if path == self.cache_directory:
                            raise TraceError('runtime cache enumeration exceeds stock startup closure')
                        role = 'runtime-enum'
                    elif path == self.cache_directory and self.prereq_enum and not self.cache_enum:
                        role = 'cache-enum'
                    elif path == self.stdlib + '/encodings' and self.cache_checks == self.caches and self.shadows == self.shadow_paths and not self.prereq_enum:
                        role = 'prereq-enum'
                    else:
                        raise TraceError('unapproved installed directory enumeration')
                elif flags == {'O_RDONLY', 'O_CLOEXEC'} and self.alias_opened and path in self.raw_sources | set(self.startup_caches) and self.image_ready():
                    role = 'raw-cache' if path in self.startup_caches else 'raw'
                    if role == 'raw':
                        cache = str(Path(path).parent / '__pycache__' / (Path(path).stem + '.cpython-313.pyc'))
                        if cache not in self.raw_cache_done:
                            raise TraceError('startup source open must follow its complete stale stock cache read')
                    if path in (self.raw_cache_done if role == 'raw-cache' else self.raw_done):
                        raise TraceError('stock startup source/cache reopened after its exact completed read')
                else:
                    raise TraceError('host source open is outside its exact role/phase')
                if role in {'directory', 'library', 'startup', 'snapshot', 'cache'} and self.path_metadata.get(path, 0) == 0:
                    raise TraceError('no-follow open lacks its path metadata prerequisite')
                if role in {'directory', 'library', 'startup', 'snapshot', 'cache'} and pre_path != path:
                    raise TraceError('checked open lacks its own fresh pre-open no-follow path query')
                if role != 'directory' and not self.live_ancestors(path):
                    raise TraceError('host open lacks live verified ancestor owners')
            elif path in self.probes:
                if not self.image_ready() or flags != {'O_RDONLY', 'O_CLOEXEC'} or result != '-1 ENOENT (No such file or directory)' or path in self.import_probes_seen:
                    raise TraceError('only selected once-only absent bytecode probes are admitted')
                self.import_probes_seen.add(path); return
            else:
                if path in {COMMON.OVERCOMMIT, '/usr/share/zoneinfo/UTC0'} and not self.image_ready():
                    raise TraceError('Python query precedes image mappings/alias closure')
                return super().call(name, args, result)
            number, annotation, deleted = COMMON.descriptor(result)
            if value is None or value < 3 or number in self.readers or deleted or annotation != target:
                raise TraceError('open lacks a distinct exact live descriptor identity')
            self.readers[number] = target
            self.last_pre_path = None
            self.fd_states[number] = {'role': role, 'bytes': 0, 'eof': False, 'rewound': False, 'metadata': 0, 'path_before': self.path_metadata.get(target, 0), 'path_rechecked': False}
            if role in {'directory', 'library', 'startup', 'snapshot', 'cache'}:
                self.pending_checked = number
            if role == 'library':
                if self.library_fd is not None:
                    raise TraceError('selected host library reopened during validation')
                self.library_fd = number
            elif role == 'alias':
                self.alias_fd = number
            return
        if name == 'read':
            self.arity(name, args, (3,)); number, path = self.reader(args[0]); count = COMMON.unsigned(args[2])
            if value is None or not 0 <= value <= count or count == 0 or count > 80 * 1024 * 1024:
                raise TraceError('read count exceeds its bounded successful role')
            visible = payload(args[1], value)
            state = self.fd_states.get(number)
            if state is None:
                return super().call(name, args, result)
            role = state['role']
            if role == 'archive':
                if self.archive_cursor == 0 and count == value == 64 and visible.startswith(b'GLUERS00'):
                    self.locator_read = True
                if value:
                    self.last_read = self.archive_cursor, value
                    self.archive_ranges.append((self.archive_cursor, self.archive_cursor + value))
                if self.cell == 'corrupt-source' and self.archive_cursor == self.record['corrupt_offset']:
                    if self.corrupt_read or count != len(CORRUPT_BYTES) or visible != CORRUPT_BYTES:
                        raise TraceError('CRC rejection lacks exact selected corrupt source read')
                    self.corrupt_read = True
                self.archive_cursor += value; self.archive_read += value
                if self.archive_cursor > self.archive_bytes or self.archive_read > 3 * self.archive_bytes:
                    raise TraceError('archive read exceeds declared size/pass bound')
            elif role in {'library', 'startup', 'snapshot', 'raw', 'cache', 'raw-cache'}:
                size = COMMON.LIBRARY_BYTES if role == 'library' else self.startup_caches[path] if role in {'cache', 'raw-cache'} else self.sources[path]
                if state['eof'] or state['rewound'] or state['metadata'] < 2 or role in {'library', 'startup', 'cache'} and count > 65536 or role == 'snapshot' and count > size + 1 or role in {'raw', 'raw-cache'} and not self.image_ready() or role not in {'raw', 'raw-cache'} and self.path_metadata.get(path, 0) < state['path_before'] + 1:
                    raise TraceError('source read lacks live metadata/phase or continues after EOF')
                if role == 'library' and state['bytes'] == 0 and visible != SOURCE.LIBRARY_PREFIX:
                    raise TraceError('host library visible bytes differ from pinned ELF prefix')
                if role in {'cache', 'raw-cache'} and state['bytes'] == 0 and value:
                    source = path.replace('/__pycache__/', '/').removesuffix('.cpython-313.pyc') + '.py'
                    header = CACHE_MAGIC + struct.pack('<III', 0, CACHE_MTIME, self.sources[source])
                    if self.cell == 'wrong-cache' and path == self.stdlib + '/' + CONTROL_STARTUP_CACHE:
                        header = bytes([header[0] ^ 1]) + header[1:]
                    if visible[:16] != header:
                        raise TraceError('startup cache visible header differs from its exact timestamp/source identity')
                state['bytes'] += value
                if state['bytes'] > size:
                    raise TraceError('source bytes exceed their pinned identity')
                if value == 0:
                    if state['bytes'] != size or count != 1:
                        raise TraceError('source EOF must follow all selected bytes with positive probe')
                    state['eof'] = True
                    if self.cell == 'wrong-source' and path == self.stdlib + '/' + CONTROL_SOURCE or self.cell == 'wrong-cache' and role == 'cache' and path == self.stdlib + '/' + CONTROL_STARTUP_CACHE:
                        self.failure = True
            elif role == 'alias':
                if not self.host_complete() or self.alias_header or self.reservation is not None or count != 832 or value != 832 or visible != SOURCE.LIBRARY_PREFIX:
                    raise TraceError('one exact selected alias ELF header must precede reservation/maps')
                self.alias_header = True
            else:
                raise TraceError('directory may not be read as a regular file')
            return
        if name == 'lseek':
            self.arity(name, args, (3,)); number, _, _ = COMMON.descriptor(args[0])
            if number < 3:
                return super().call(name, args, result)
            number, path = self.reader(args[0]); state = self.fd_states.get(number)
            if path == self.archive:
                offset = COMMON.unsigned(args[1]); expected = self.archive_bytes if args[1:] == ['0', 'SEEK_END'] else offset if args[2] == 'SEEK_SET' and offset <= self.archive_bytes else None
                if value != expected:
                    raise TraceError('archive seek differs from bounded offset')
                if args[2] == 'SEEK_END': self.archive_sized = True
                self.archive_cursor = expected; return
            if state and state['role'] in {'library', 'startup', 'cache'} and args[1:] == ['0', 'SEEK_SET'] and value == 0 and state['eof'] and state['metadata'] == 3 and not state['rewound']:
                state['rewound'] = True
                if state['role'] == 'startup': self.startup_done.add(path)
                elif state['role'] == 'cache': self.verified_caches.add(path)
                return
            if state and state['role'] in {'raw', 'raw-cache'} and args[1:] == ['0', 'SEEK_CUR'] and value == state['bytes']:
                return
            raise TraceError('unapproved seek on selected host descriptor')
        if name == 'getdents64':
            self.arity(name, args, (3,)); number, path = self.reader(args[0]); state = self.fd_states.get(number)
            match = re.fullmatch(r'0x[0-9a-f]{1,16} /\* ([0-9]{1,3}) entries \*/', args[1])
            if state is None or state['role'] not in {'prereq-enum', 'cache-enum', 'runtime-enum'} or state['metadata'] != 1 or args[2] != '32768' or match is None or value is None or not 0 <= value <= 32768 or (value == 0) != (int(match[1]) == 0):
                raise TraceError('directory enumeration lacks its exact live owner/count grammar')
            state['bytes'] += int(match[1])
            if value == 0:
                expected = 199 if state['role'] == 'runtime-enum' and path == self.stdlib else (4 if self.cell == 'missing-cache' else 5) if state['role'] == 'cache-enum' else 125
                if state['eof'] or state['bytes'] != expected:
                    raise TraceError('installed directory entries differ from prepared source inventory')
                state['eof'] = True
                if state['role'] == 'prereq-enum':
                    if self.enc_members != {path for path in self.sources if path.startswith(self.stdlib + '/encodings/')} | {self.cache_directory}:
                        raise TraceError('startup enumeration lacks every pinned encodings file metadata')
                    self.prereq_enum = True
                elif state['role'] == 'cache-enum':
                    expected_members = set(self.startup_caches) - ({self.stdlib + '/' + CONTROL_STARTUP_CACHE} if self.cell == 'missing-cache' else set())
                    if self.cache_members != expected_members:
                        raise TraceError('closed startup cache directory lacks exact selected member metadata')
                    if self.cell == 'missing-cache': self.failure = True
                    else: self.cache_enum = True
                else:
                    self.enums['runtime', path] = expected
            return
        if name == 'close':
            self.arity(name, args, (1,)); number, path = self.reader(args[0]); state = self.fd_states.get(number)
            if state is None:
                return super().call(name, args, result)
            self.succeeds(value)
            role = state['role']
            if role == 'directory' and (state['metadata'] != 1 or not state['path_rechecked']):
                raise TraceError('directory owner closes without its descriptor/path identity checks')
            if role in {'directory', 'startup', 'cache'} and self.alias_opened and not self.finalized_boundary:
                if not self.runtime_ready():
                    raise TraceError('retained host owners close before complete initialized observations')
                if self.cell in SUCCESS and bytes(self.output[0]) != self.expected[0]:
                    raise TraceError('successful application output must precede retained owner release')
                self.finalized_boundary = True
            if role in {'directory', 'startup', 'cache'} and self.cell in INITIALIZED and not self.alias_opened:
                raise TraceError('retained host source/directory lease closes before runtime loading')
            if role == 'library' and self.cell in INITIALIZED:
                raise TraceError('loaded library descriptor must remain pinned')
            if role == 'snapshot':
                if not state['eof'] or state['metadata'] != (2 if self.cell == 'wrong-source' and path == self.stdlib + '/' + CONTROL_SOURCE else 3) or self.path_metadata.get(path, 0) < state['path_before'] + 1:
                    raise TraceError('snapshot descriptor closes before complete identity/EOF/metadata')
                if not self.failure: self.snapshot_done.add(path)
            elif role in {'raw', 'raw-cache'}:
                if not state['eof'] or state['metadata'] != 2:
                    raise TraceError('startup source closes before complete raw import')
                (self.raw_cache_done if role == 'raw-cache' else self.raw_done).add(path)
            elif role == 'alias':
                if self.image_mappings != {(20423824, 0), (1695744, 0x115a000)} or not self.bss:
                    raise TraceError('loader alias closes before complete stock setup')
                self.alias_fd = None
            elif role in {'prereq-enum', 'cache-enum', 'runtime-enum'} and not state['eof'] and self.cell not in {'startup-native', 'startup-bytecode', 'extra-cache'}:
                raise TraceError('enumeration descriptor closes without complete directory EOF')
            elif role in {'prereq-enum', 'cache-enum'} and not state['eof']:
                if state['metadata'] != 1 or not 0 < state['bytes'] <= (6 if role == 'cache-enum' else 126) or role == 'prereq-enum' and not self.enc_members or role == 'cache-enum' and self.cell != 'extra-cache':
                    raise TraceError('startup rejection lacks a checked nonempty directory enumeration')
                self.failure = True
            del self.fd_states[number]; del self.readers[number]; return
        if name in {'fcntl', 'ioctl'}:
            self.arity(name, args, (2,) if name == 'fcntl' else (3,))
            if COMMON.descriptor(args[0])[0] < 3:
                return super().call(name, args, result)
            number, path = self.reader(args[0]); state = self.fd_states.get(number)
            if state is None or state['role'] not in {'raw', 'raw-cache'} or not self.image_ready():
                raise TraceError('descriptor query exceeds startup source closure')
            if name == 'fcntl' and (args[1] != 'F_GETFD' or result != '0x1 (flags FD_CLOEXEC)'):
                raise TraceError('startup source FD query differs')
            if name == 'ioctl':
                COMMON.pointer(args[2])
                if args[1] != 'TCGETS' or result != '-1 ENOTTY (Inappropriate ioctl for device)': raise TraceError('startup source terminal query differs')
            return
        if name == 'ppoll':
            expected = '[{fd=0</dev/null<char 1:3>>, events=0}, ' + f'{{fd=1</evidence/{self.cell}.stdout.txt>, events=0}}, {{fd=2</evidence/{self.cell}.stderr.txt>, events=0}}]'
            if args != [expected, '3', '{tv_sec=0, tv_nsec=0}', 'NULL', '0'] or result != '0 (Timeout)': raise TraceError('inherited stream poll differs')
            return
        if name == 'getrandom' and len(args) == 3 and args[1] == '2496':
            if not self.image_ready() or self.entropy or not self.virtual_queries or not self.timezone_queries or args[2] != 'GRND_NONBLOCK' or value != 2496:
                raise TraceError('Python entropy differs from initialized snapshot phase')
            payload(args[0], value); self.entropy = 1; return
        if name in {'gettid', 'readlinkat'} and not self.image_ready():
            raise TraceError('Python startup observation precedes image readiness')
        if name == 'write':
            self.arity(name, args, (3,))
            if not (self.runtime_ready() if self.cell in INITIALIZED else self.control_ready()):
                raise TraceError('publication precedes complete initialized or rejection boundary')
        if name in {'mmap', 'mprotect', 'munmap', 'mremap'}:
            return self.memory(name, args, result)
        return super().call(name, args, result)

    def memory(self, name, args, result):
        self.arity(name, args, ({'mmap': 6, 'mprotect': 3, 'munmap': 2, 'mremap': 4}[name],))
        COMMON.pointer(args[0]); start = 0 if args[0] == 'NULL' else int(args[0], 16); length = COMMON.unsigned(args[1]); value = COMMON.result_number(result)
        if not length or name == 'mremap' and not COMMON.unsigned(args[2]): raise TraceError('zero-length memory operation')
        moved = COMMON.unsigned(args[2]) if name == 'mremap' else length
        if length > 256 * 1024 * 1024 or moved > 256 * 1024 * 1024 or start + length > 1 << 64 or start and start % 4096 or name in {'mmap', 'mremap'} and value is not None and value > 0 and (value % 4096 or value + moved > 1 << 64):
            raise TraceError('memory operation has an unaligned or overflowing bounded address span')
        if name == 'mmap' and args == ['NULL', '20489360', 'PROT_NONE', 'MAP_PRIVATE|MAP_ANONYMOUS', '-1', '0']:
            if self.reservation is not None or not self.host_complete() or not self.alias_header or not self.alias_metadata or value is None or value <= 0: raise TraceError('stock reservation lacks verified alias')
            self.reservation = value; return
        if name == 'mmap' and self.library in args[4]:
            fd, _ = self.reader(args[4]); offset = int(args[5], 16) if re.fullmatch(r'0x[0-9a-f]{1,16}', args[5]) else COMMON.unsigned(args[5])
            segment = length, offset; expected = {(20423824, 0): 'PROT_READ|PROT_EXEC', (1695744, 0x115a000): 'PROT_READ|PROT_WRITE'}
            if fd != self.alias_fd or not self.host_complete() or not self.alias_header or not self.alias_metadata or segment in self.image_mappings or args[2] != expected.get(segment) or BASE.flags(args[3], {'MAP_PRIVATE', 'MAP_FIXED', 'MAP_DENYWRITE'}) != {'MAP_PRIVATE', 'MAP_FIXED', 'MAP_DENYWRITE'} or start == 0 or value != start:
                raise TraceError('selected host file mapping contradicts pinned GNU image facts')
            if not self.image_mappings:
                if segment != (20423824, 0):
                    raise TraceError('first selected stock mapping must be the pinned RX operation')
                if self.reservation is None or start != (self.reservation + 65535) // 65536 * 65536: raise TraceError('stock mapping lacks coherent reservation base')
                self.image_base = start
                if start == self.reservation: self.trims.add('prefix')
            elif segment != (1695744, 0x115a000) or start != self.image_base + 0x115a000 or not self.guard: raise TraceError('second selected stock mapping must be coherent pinned RW setup')
            self.image_mappings.add(segment); return
        if self.image_base is not None:
            spans = {'prefix': (self.reservation, self.image_base - self.reservation), 'tail': (self.image_base + 20426752, self.reservation + 20489360 - self.image_base - 20426752)}
            selected = next((key for key, span in spans.items() if span == (start, length)), None)
            if name == 'munmap' and selected:
                if selected in self.trims or self.relro or len(self.image_mappings) != 1 or result != '0': raise TraceError('reservation trim repeats or precedes/follows wrong phase')
                self.trims.add(selected); return
            if name == 'mprotect' and start == self.image_base + 0x1150000 and args[1:] == ['40960', 'PROT_NONE']:
                if self.guard or self.trims != {'prefix', 'tail'} or len(self.image_mappings) != 1 or result != '0': raise TraceError('stock guard setup differs')
                self.guard = True; return
            if name == 'mmap' and start == self.image_base + 0x12f8000 and args[1:] == ['533648', 'PROT_READ|PROT_WRITE', 'MAP_PRIVATE|MAP_FIXED|MAP_ANONYMOUS', '-1', '0']:
                if self.bss or not self.guard or len(self.image_mappings) != 2 or value != start: raise TraceError('stock BSS mapping differs')
                self.bss = True; return
            if name == 'mprotect' and start == self.image_base + 0x115a000 and args[1:] == ['1007616', 'PROT_READ']:
                if self.relro or not self.bss or self.alias_fd is not None or result != '0': raise TraceError('stock RELRO must follow alias closure')
                self.relro = True; return
        lower, upper = (self.image_base, self.image_base + 20426752) if self.image_base is not None else (self.reservation, self.reservation + 20489360) if self.reservation is not None else (0, 0)
        moved = COMMON.unsigned(args[2]) if name == 'mremap' else length
        if lower < start + length and start < upper or name in {'mmap', 'mremap'} and value is not None and value > 0 and lower < value + moved and value < upper:
            raise TraceError('operation replaces/unmaps/protects the live selected image')
        if name == 'mremap':
            pairs = ((139264, 155648), (176128, 196608), (196608, 221184), (249856, 278528))
            if not self.image_ready() or self.remaps >= len(pairs) or self.raw_done != self.raw_sources or self.raw_cache_done != set(self.startup_caches) or (length, moved) != pairs[self.remaps] or self.anonymous.get(start) != length or args[3] != 'MREMAP_MAYMOVE' or self.entropy != (0, 0, 0, 1)[self.remaps] or value is None or value <= 0:
                raise TraceError('source parser remap differs from observed live anonymous backing')
            del self.anonymous[start]; self.anonymous[value] = moved; self.remaps += 1; return
        result_value = super().call(name, args, result)
        if name == 'mmap' and args[2] == 'PROT_READ|PROT_WRITE' and args[3] in {'MAP_PRIVATE|MAP_ANONYMOUS', 'MAP_PRIVATE|MAP_ANONYMOUS|MAP_STACK'} and args[4:] == ['-1', '0']:
            self.anonymous[value] = length
        elif name == 'munmap':
            for address, span in list(self.anonymous.items()):
                if start < address + span and address < start + length: del self.anonymous[address]
        return result_value

    def finish(self):
        if self.execs != 1 or not self.exit_group or not self.completed or self.uname_queries != 1:
            raise TraceError('complete selected process/readiness/exit required')
        if self.cell in INITIALIZED:
            # Runtime owners close after finalization, so image readiness was
            # required at every initialization/publication boundary above.
            if not self.finalized_boundary or self.readers != {self.library_fd: self.library} or self.fd_states.get(self.library_fd, {}).get('role') != 'library' or not self.relro or self.raw_done != self.raw_sources:
                raise TraceError('finalization lacks closed source/directory owners and pinned library')
        elif not self.control_ready():
            raise TraceError('pre-initialization control lacks its exact closed rejection boundary')
        if self.cell == 'corrupt-source':
            for lower, upper in ((0, 64 + self.record['manifest_bytes']), (self.record['zip_directory_offset'], self.archive_bytes)):
                if not any(start <= lower and end >= upper for start, end in PRODUCT.merged_ranges(self.archive_ranges)):
                    raise TraceError('CRC control lacks complete manifest/ZIP metadata admission')
        if tuple(bytes(data) for data in self.output) != self.expected:
            raise TraceError('trace stdout/stderr differs from complete workload outcomes')


def check_lines(lines, mode, size, record):
    checker = Checker(mode, size, record)
    total = 0
    for number, line in enumerate(lines, 1):
        total += len(line.encode('utf-8'))
        if number > MAX_RECORDS or total > MAX_TRACE_BYTES or len(line) > MAX_LINE_CHARACTERS + 1 or not line.endswith('\n') or '\r' in line:
            raise TraceError('host source trace is oversized, noncanonical or incomplete')
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
        raise TraceError('retained host source metadata differs from actual archive')
    for path, expected in zip((args.stdout_file, args.stderr_file), expected_output(args.mode)):
        with path.open('rb') as stream:
            if stream.read(len(expected) + 1) != expected:
                raise TraceError('retained host source diagnostic differs')
    if args.trace.stat().st_size > MAX_TRACE_BYTES:
        raise TraceError('raw/compressed host source trace exceeds bounded input')
    with (gzip.open if args.trace.suffix == '.gz' else open)(args.trace, 'rb') as stream:
        def lines():
            while line := stream.readline(MAX_LINE_CHARACTERS + 2):
                yield line.decode('utf-8', 'strict')
        check_lines(lines(), args.mode, size, record)
    phase = ('all pinned sources and three closed startup caches verified before load, observed stale-cache reads and source startup, private stock image retained through finalization'
             if args.mode in INITIALIZED else 'closed pre-initialization rejection without mapping a provider')
    print(f'Trace checks passed: {args.mode}; exact readiness/archive/input phases and entry outcomes; {phase}; no source fallback/mutation or extra process')
    return 0


if __name__ == '__main__':
    try:
        raise SystemExit(main())
    except (OSError, EOFError, ValueError, KeyError, TypeError, UnicodeError, struct.error, zipfile.BadZipFile, TraceError) as error:
        print('Python install host source app trace rejected: ' + str(error), file=sys.stderr)
        raise SystemExit(1)
