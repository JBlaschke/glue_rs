#!/usr/bin/env python3
"""Strict complete-trace policy for the pinned registered-extension matrix.

Native descriptor admission is checked here. Every remaining record is replayed
through a fresh, unchanged archive-import runtime policy. The only translations
are the previously checked fixture command and standard-output file identities.
This is bounded experiment evidence, not a runtime sandbox or a wheel loader.
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
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


BUNDLED = policy('check-linux-python-import-trace.py', 'extension_bundled_policy')
HOST = policy('check-linux-python-host-import-trace.py', 'extension_host_policy')
PBS, BASE, TraceError = BUNDLED.PBS, BUNDLED.BASE, BUNDLED.TraceError
# Unify error types in these private module instances for bounded CLI rejection.
for module in (HOST, HOST.COMMON, HOST.PBS, HOST.BASE, PBS, BASE):
    module.TraceError = TraceError
quoted, unsigned, pointer, result_number, descriptor = (
    PBS.quoted, PBS.unsigned, PBS.pointer, PBS.result_number, BUNDLED.descriptor
)
DIRECTORY = '/build-target/relocated Python extensions'
PROGRAM = DIRECTORY + '/glue-python-bootstrap-probe'
NATIVE_PREFIX = '/build-target/host Python extensions'
CELLS = ('bundled-archived', 'bundled-host', 'host-archived', 'host-host')
NEGATIVE = ('corrupt-native', 'missing-host-image', 'wrong-host-image')
MODES = CELLS + tuple(cell + '-app-error' for cell in CELLS) + NEGATIVE
NAMES = ('libglue_python_dependency.so', 'glue_native_single.so', 'glue_native_multi.so',
         'glue_native_init_error.so', 'glue_native_exec_error.so')
SIZES = dict(zip(NAMES, (67152, 68536, 68640, 68400, 68672)))
HASHES = dict(zip(NAMES, (
    'dd71198aa5f249666a9be2fdd58738598c56adfd7c69060c6f8d5d57c6d45168',
    '32c79302f631ae823f095a7a35153a57e16a8f3904ae2b3a8dcc2ff43c36cf9d',
    '1d7abceaf3c2e7e3db228e91b3c28bf9b6ec58aac7a7b9fefbdaba1e9a0bbd20',
    '139fd5c5f9fac35a94d1396779ff4a81b7d9b6e4f2344de4851e9aa869289f2e',
    '25a42b2b856145fe4e84b18160cb17826f54fcc1857eceff2069a9b89e7e3db6')))
EXPECTED_LOADS = {
    name: [{'flags': 5, 'offset': 0, 'vaddr': 0, 'filesz': rx, 'memsz': rx, 'align': 65536},
           {'flags': 6, 'offset': offset, 'vaddr': offset + 65536,
            'filesz': file_size, 'memsz': memory_size, 'align': 65536}]
    for name, (rx, offset, file_size, memory_size) in zip(NAMES, (
        (712, 0xff00, 256, 256), (2036, 0xfe38, 688, 696),
        (2064, 0xfe48, 752, 760), (1688, 0xfe48, 640, 648),
        (2068, 0xfe40, 728, 744)))
}
# The two observed GNU file-map operations, including the temporary RX gap.
SEGMENTS = {
    'libglue_python_dependency.so': {(131072, 0): 'PROT_READ|PROT_EXEC', (4096, 0xf000): 'PROT_READ|PROT_WRITE'},
    'glue_native_single.so': {(131312, 0): 'PROT_READ|PROT_EXEC', (8192, 0xf000): 'PROT_READ|PROT_WRITE'},
    'glue_native_multi.so': {(131392, 0): 'PROT_READ|PROT_EXEC', (8192, 0xf000): 'PROT_READ|PROT_WRITE'},
    'glue_native_init_error.so': {(131280, 0): 'PROT_READ|PROT_EXEC', (8192, 0xf000): 'PROT_READ|PROT_WRITE'},
    'glue_native_exec_error.so': {(131368, 0): 'PROT_READ|PROT_EXEC', (8192, 0xf000): 'PROT_READ|PROT_WRITE'},
}
NATIVE_PASS = b'GLUE_PYTHON_EXTENSIONS_PASS single=42 multi=44 retry=2 dependency=42\n'
SUCCESS = BUNDLED.SUCCESS + NATIVE_PASS
APP_ERROR = BUNDLED.APP_ERROR
CORRUPT_KEY = 'native/libglue_python_dependency.so'
CORRUPT_ERROR = b'glue-python-bootstrap-probe: resource "native/libglue_python_dependency.so" failed CRC32 verification\n'
READ_FLAGS = {'O_RDONLY', 'O_NOFOLLOW', 'O_NONBLOCK', 'O_CLOEXEC'}
DIRECTORY_FLAGS = READ_FLAGS | {'O_DIRECTORY'}
MAX_TRACE_BYTES = PBS.MAX_TRACE_BYTES
MAX_LINE_CHARACTERS = PBS.MAX_LINE_CHARACTERS
MAX_RECORDS = PBS.MAX_RECORDS


def cell_for(mode):
    if mode not in MODES:
        raise TraceError('unknown registered-extension fixture mode')
    return mode.removesuffix('-app-error') if mode not in NEGATIVE else 'bundled-archived' if mode == 'corrupt-native' else 'bundled-host'


def archive_for(mode):
    return DIRECTORY + '/' + (mode if mode in NEGATIVE else cell_for(mode)) + '.glue'


def prefix_for(mode):
    return NATIVE_PREFIX + (' ' + mode if mode in {'missing-host-image', 'wrong-host-image'} else '')


def command_for(mode):
    return ([PROGRAM, 'run-extensions-negative', archive_for(mode), 'app-error']
            if mode.endswith('-app-error') else [PROGRAM, 'run-extensions', archive_for(mode)])


def expected_output(mode):
    cell_for(mode)
    if mode not in NEGATIVE:
        return SUCCESS, APP_ERROR if mode.endswith('-app-error') else b''
    if mode == 'corrupt-native':
        return b'', CORRUPT_ERROR
    path = prefix_for(mode) + '/' + (NAMES[0] if mode == 'missing-host-image' else NAMES[1])
    message = (f'host path {path}: No such file or directory (os error 2)' if mode == 'missing-host-image'
               else f'host file identity mismatch: {path}')
    return b'', ('glue-python-bootstrap-probe: ' + message + '\n').encode('ascii')


class Checker:
    def __init__(self, mode, archive_bytes, corrupt_offset=None, admission=None):
        self.mode, self.cell = mode, cell_for(mode)
        self.initialized = mode not in NEGATIVE
        self.expected = expected_output(mode)
        if type(archive_bytes) is not int or not 0 < archive_bytes <= 128 * 1024 * 1024:
            raise TraceError('archive size is outside the bounded extension profile')
        self.runtime_mode = 'app-error' if mode.endswith('-app-error') or not self.initialized else 'success'
        self.runtime_policy = HOST if self.cell.startswith('host-') else BUNDLED
        # The host parent deliberately bounds its historical tiny archive. This
        # independent profile includes five native images but preserves its rules.
        self.runtime = (HOST.Checker(self.runtime_mode, 4096) if self.runtime_policy is HOST
                        else BUNDLED.Checker(self.runtime_mode, archive_bytes))
        self.runtime.archive_bytes = archive_bytes
        self.runtime.archive = archive_for(mode)
        self.runtime.expected = self.expected
        # The parents use this constant to gate app-error stderr publication.
        self.runtime_policy.SUCCESS = SUCCESS
        self.prefix = prefix_for(mode)
        self.paths = {self.prefix + '/' + name: name for name in NAMES}
        self.dirs = {'/', '/build-target', self.prefix}
        self.directory_fds = {}
        self.directory_metadata = set()
        self.path_metadata = {}
        self.native_fds = {}
        self.states = {name: {'source': None, 'alias': None, 'created': False,
                              'bytes': 0, 'cursor': 0, 'passes': 0, 'eof': False,
                              'rewinds': 0, 'fdstat': False, 'seals': 0, 'headers': 0,
                              'maps': set(), 'relro': False, 'reservation': None,
                              'guard': False, 'trims': [], 'trimmed': 0} for name in NAMES}
        self.load_order = []
        self.failure = False
        self.corrupt_offset = corrupt_offset
        if mode == 'corrupt-native' and (type(corrupt_offset) is not int or not 64 <= corrupt_offset <= archive_bytes - SIZES[NAMES[0]]):
            raise TraceError('corrupt native replay requires retained member offset within archive bounds')
        self.admission = admission
        if mode == 'corrupt-native':
            validate_admission(archive_bytes, admission, corrupt_offset)
        self.corrupt_read = False
        self.corrupt_bytes = 0
        self.last_archive_read = None
        self.manifest_backing = None
        self.manifest_remaps = 0
        self.runtime_spans = []
        self.output = [bytearray(), bytearray()]

    def source_ready(self):
        if self.cell.endswith('-archived'):
            return self.runtime.archive_complete()
        return self.runtime.archive_complete() and all(
            state['passes'] == 2 and state['rewinds'] == 2 and state['cursor'] == 0 and state['fdstat'] and
            state['source'] in self.native_fds and self.path_metadata.get(self.prefix + '/' + name, 0) == 2 and
            (bytes(self.output[0]) == SUCCESS or all(fd in self.directory_fds for fd in state.get('ancestors', ())))
            for name, state in self.states.items())

    def closure_prepared(self):
        return self.source_ready() and (not self.cell.endswith('-archived') or all(
            state['created'] and state['bytes'] == SIZES[name] and state['seals'] == 2
            for name, state in self.states.items()))

    def native_ready(self):
        return (self.closure_prepared() and self.load_order == list(NAMES) and
                all(state['alias'] is None and state['headers'] == 1 and state['maps'] == set(SEGMENTS[name])
                    and state['relro'] and (state['seals'] == 2 if self.cell.endswith('-archived') else not state['created'])
                    for name, state in self.states.items()))

    def preinit(self):
        return self.runtime.virtual_queries == self.runtime.tid_queries == 0 and self.runtime.overcommit_reads in {0, 1} and not any(self.output)

    def result_fd(self, result, expected_path, deleted=False):
        number, path, actual_deleted = descriptor(result)
        if number < 3 or path != expected_path or actual_deleted != deleted or number in self.native_fds or number in self.directory_fds or number in self.runtime.readers or number in self.runtime.memfds:
            raise TraceError('native descriptor is not a distinct exact annotated input')
        return number

    def native_fd(self, argument):
        number, path, deleted = descriptor(argument)
        name, role = self.native_fds[number]
        expected = '/memfd:glue-python-native-' + name if self.states[name]['created'] else self.prefix + '/' + name
        if path != expected or deleted != self.states[name]['created']:
            raise TraceError('native descriptor annotation differs from its verified image')
        return number, name, role

    def normalized(self, args):
        actual = {f'/evidence/{self.mode}.{stream}.txt': f'/evidence/{self.runtime_mode}.{stream}.txt'
                  for stream in ('stdout', 'stderr')}
        normalized = []
        for argument in args:
            for found in re.findall(r'/evidence/[^<>\], }]+', argument):
                if found not in actual:
                    raise TraceError('inherited evidence stream identity differs from this matrix cell')
            for source, target in actual.items():
                argument = argument.replace(source, target)
            normalized.append(argument)
        return normalized

    def control_ready(self):
        if any(state['created'] or state['maps'] or state['alias'] is not None for state in self.states.values()) or self.runtime.created or self.runtime.image_mappings or self.native_fds or self.directory_fds or self.runtime.readers:
            return False
        if self.mode == 'corrupt-native':
            manifest_bytes, directory_offset = self.admission
            return (self.runtime.archive_opened == 1 and self.runtime.archive_sized and self.runtime.locator_read and
                    self.covered(0, 64 + manifest_bytes) and self.covered(directory_offset, self.runtime.archive_bytes) and
                    self.corrupt_read and self.corrupt_bytes == SIZES[NAMES[0]] and
                    self.last_archive_read == (self.corrupt_offset + 65536, 1616))
        if not self.runtime.archive_complete():
            return False
        if self.mode == 'missing-host-image':
            return self.failure and not any(state['bytes'] for state in self.states.values())
        return (self.states[NAMES[0]]['passes'] == 2 and self.states[NAMES[1]]['passes'] == 1 and
                all(self.states[name]['passes'] == 0 for name in NAMES[2:]))

    def covered(self, start, end):
        cursor = start
        for left, right in sorted(self.runtime.archive_ranges):
            if right <= cursor:
                continue
            if left > cursor:
                return False
            cursor = max(cursor, right)
            if cursor >= end:
                return True
        return False

    def call(self, name, args, result):
        runtime = self.runtime
        value = result_number(result)
        if runtime.exit_group or (value is None and name != 'exit_group'):
            raise TraceError('incomplete operation or syscall after exit_group')
        if name != 'execve' and runtime.execs != 1:
            raise TraceError('trace must begin with its sole execve')
        arities = {'execve': 3, 'openat': 3, 'read': 3, 'write': 3, 'lseek': 3,
                   'close': 1, 'fstat': 2, 'newfstatat': 4, 'statx': 5,
                   'memfd_create': 2, 'mmap': 6, 'mprotect': 3, 'munmap': 2,
                   'mremap': 4, 'exit_group': 1}
        if name in arities and len(args) != arities[name]:
            raise TraceError('unexpected syscall arity')
        if name == 'fcntl' and len(args) not in {2, 3}:
            raise TraceError('unexpected fcntl arity')
        if not self.initialized and self.output[1] and name in {'openat', 'read', 'lseek', 'statx', 'newfstatat', 'fstat', 'mmap', 'mprotect', 'mremap', 'fcntl', 'memfd_create'}:
            raise TraceError('input acquisition or mapping after validation rejection diagnostic')
        if name == 'execve':
            if args[:2] != [json.dumps(PROGRAM), json.dumps(command_for(self.mode))]:
                raise TraceError('execve differs from the exact registered extension command')
            old_program = self.runtime_policy.PROGRAM
            old_command = [old_program, 'run-host-imports' if self.runtime_policy is HOST else 'run-imports', runtime.archive]
            if self.runtime_mode == 'app-error':
                old_command = [old_program, 'run-host-imports-negative' if self.runtime_policy is HOST else 'run-imports-negative', runtime.archive, 'app-error']
            if self.runtime_policy is BUNDLED:
                old_command = BUNDLED.command_for(self.runtime_mode)
            return runtime.call(name, [json.dumps(old_program), json.dumps(old_command), args[2]], result)
        if name == 'openat':
            path = quoted(args[1])
            if path in self.paths or path in self.dirs and 'O_DIRECTORY' in args[2] and not self.source_ready():
                if self.cell.endswith('-archived') or not runtime.archive_complete() or not self.preinit() or runtime.image_mappings:
                    raise TraceError('explicit native lookup precedes closed verified archive or occurs after image loading')
                flags = BASE.flags(args[2], DIRECTORY_FLAGS)
                expected = DIRECTORY_FLAGS if path in self.dirs else READ_FLAGS
                if len(args) != 3 or args[0] != BUNDLED.CWD or flags != expected:
                    raise TraceError('native host inputs require exact read-only no-follow flags')
                if path in self.dirs:
                    number = self.result_fd(result, path)
                    self.directory_fds[number] = path
                    return
                if result == '-1 ENOENT (No such file or directory)' and self.mode == 'missing-host-image' and path.endswith('/' + NAMES[0]):
                    self.require_ancestors(path)
                    self.failure = True
                    return
                image = self.paths[path]
                state = self.states[image]
                ancestors = self.require_ancestors(path)
                if state['source'] is not None or self.path_metadata.get(path, 0) != 1:
                    raise TraceError('native input lacks retained no-follow directory ancestors or is reopened')
                number = self.result_fd(result, path)
                state['source'] = number
                state['ancestors'] = tuple(ancestors)
                self.native_fds[number] = (image, 'source')
                return
            match = re.fullmatch(r'/proc/self/fd/([0-9]+)', path)
            if match and int(match[1]) in self.native_fds:
                original = int(match[1])
                image, role = self.native_fds[original]
                state = self.states[image]
                if not self.closure_prepared() or not runtime.image_ready() or not self.preinit() or role != 'source' or state['alias'] is not None or state['headers'] or (state['seals'] != 2 if state['created'] else state['rewinds'] != 2) or BASE.flags(args[2], {'O_RDONLY', 'O_CLOEXEC'}) != {'O_RDONLY', 'O_CLOEXEC'} or args[0] != BUNDLED.CWD or len(args) != 3:
                    raise TraceError('native loader alias precedes full verification, sealing or selected runtime')
                expected = '/memfd:glue-python-native-' + image if state['created'] else self.prefix + '/' + image
                number = self.result_fd(result, expected, state['created'])
                if len(self.load_order) >= len(NAMES) or image != NAMES[len(self.load_order)]:
                    raise TraceError('native closure must load dependency first in the exact admitted order')
                self.load_order.append(image)
                state['alias'] = number
                self.native_fds[number] = (image, 'alias')
                return
        if name == 'memfd_create' and args and quoted(args[0]).startswith('glue-python-native-'):
            image = quoted(args[0]).removeprefix('glue-python-native-')
            if image not in self.states or not self.cell.endswith('-archived') or not self.source_ready() or not runtime.image_ready() or not self.preinit() or len(args) != 2 or BASE.flags(args[1], {'MFD_CLOEXEC', 'MFD_ALLOW_SEALING', '0x10'}) != {'MFD_CLOEXEC', 'MFD_ALLOW_SEALING', '0x10'}:
                raise TraceError('native memfd requires archived provider and selected runtime before initialization')
            state = self.states[image]
            if state['created']:
                raise TraceError('native memfd created twice')
            number = self.result_fd(result, '/memfd:glue-python-native-' + image, True)
            state['created'], state['source'] = True, number
            self.native_fds[number] = (image, 'source')
            return
        if name in {'statx', 'newfstatat'} and len(args) >= 2 and args[1].startswith('"') and (quoted(args[1]) in self.paths or quoted(args[1]) in self.dirs and not self.source_ready()):
            path = quoted(args[1])
            if self.cell.endswith('-archived') or not runtime.archive_complete() or not self.preinit() or runtime.image_mappings or args[0] != BUNDLED.CWD:
                raise TraceError('native host metadata query occurs outside verification phase')
            flags = args[2] if name == 'statx' else args[3]
            body = args[4] if name == 'statx' else args[2]
            if len(args) != (5 if name == 'statx' else 4) or flags != ('AT_STATX_SYNC_AS_STAT|AT_SYMLINK_NOFOLLOW' if name == 'statx' else 'AT_SYMLINK_NOFOLLOW') or name == 'statx' and args[3] != 'STATX_ALL':
                raise TraceError('native host metadata must reject symbolic links')
            if result == '-1 ENOENT (No such file or directory)' and self.mode == 'missing-host-image' and path.endswith('/' + NAMES[0]):
                self.require_ancestors(path)
                pointer(body)
                self.failure = True
                return
            self.metadata_body(name, body, value, 'S_IFDIR' if path in self.dirs else 'S_IFREG', None if path in self.dirs else SIZES[self.paths[path]])
            self.path_metadata[path] = self.path_metadata.get(path, 0) + 1
            return
        number = None
        if name in {'read', 'write', 'fcntl', 'lseek', 'close', 'fstat', 'newfstatat', 'statx'} and args:
            try:
                number = descriptor(args[0])[0]
            except TraceError:
                pass
        if number in self.directory_fds:
            path = self.directory_fds[number]
            if descriptor(args[0])[1:] != (path, False):
                raise TraceError('native directory descriptor annotation changed')
            if name == 'close' and value == 0 and len(args) == 1:
                if self.initialized and bytes(self.output[0]) != SUCCESS:
                    raise TraceError('native ancestor descriptor closed before finalization diagnostics')
                del self.directory_fds[number]
                self.directory_metadata.discard(number)
                return
            if name in {'fstat', 'newfstatat', 'statx'} and value == 0:
                body = args[-1] if name != 'newfstatat' else args[2]
                self.metadata_arguments(name, args)
                self.metadata_body(name, body, value, 'S_IFDIR')
                self.directory_metadata.add(number)
                return
            raise TraceError('unapproved native directory operation')
        if number in self.native_fds:
            number, image, role = self.native_fd(args[0])
            state = self.states[image]
            if name == 'write':
                count = unsigned(args[2])
                if len(args) != 3 or not state['created'] or role != 'source' or state['seals'] or PBS.BUFFER.fullmatch(args[1]) is None or value != count or not 0 < count <= SIZES[image] - state['bytes']:
                    raise TraceError('native memfd population differs from exact immutable image size')
                state['bytes'] += count
                return
            if name == 'fcntl':
                if args[1] == 'F_ADD_SEALS' and len(args) == 3 and state['created'] and role == 'source' and state['bytes'] == SIZES[image] and state['seals'] == 0 and BASE.flags(args[2], BASE.SEALS) == BASE.SEALS and value == 0:
                    state['seals'] = 1
                    return
                if args[1:] == ['F_GET_SEALS'] and state['seals'] == 1 and value == 15:
                    state['seals'] = 2
                    return
                raise TraceError('native seal operation is missing, duplicated or out of order')
            if name == 'read':
                count = unsigned(args[2])
                if len(args) != 3 or PBS.BUFFER.fullmatch(args[1]) is None or value is None or not 0 <= value <= count or not 0 < count <= 65536 or value == 0 and args[1] != '""':
                    raise TraceError('unparsed native input read')
                if role == 'alias':
                    if state['headers'] or count != 832 or value != 832 or not args[1].startswith('"\\177ELF'):
                        raise TraceError('native alias requires one exact GNU ELF header read')
                    state['headers'] = 1
                    return
                if state['created'] or not self.preinit() or state['rewinds'] >= 2 or state['cursor'] + value > SIZES[image] or state['eof'] or not state['fdstat'] or self.path_metadata.get(self.prefix + '/' + image, 0) != 2 or any(fd not in self.directory_fds for fd in state['ancestors']):
                    raise TraceError('native host image read differs from two complete bounded verification passes')
                if state['cursor'] == 0 and value > 0:
                    prefix = '"~ELF' if self.mode == 'wrong-host-image' and image == 'glue_native_single.so' else '"\\177ELF'
                    if not args[1].startswith(prefix):
                        raise TraceError('native host verification did not read the selected ELF/control prefix')
                state['cursor'] += value
                state['bytes'] += value
                if value == 0:
                    if state['cursor'] != SIZES[image]:
                        raise TraceError('native image EOF precedes full image read')
                    state['eof'] = True
                    state['passes'] += 1
                return
            if name == 'lseek':
                if role != 'source' or args[1:] != ['0', 'SEEK_SET'] or value != 0 or not state['eof'] or state['rewinds'] >= 2:
                    raise TraceError('native host image rewind must follow complete EOF verification')
                state['cursor'], state['eof'] = 0, False
                state['rewinds'] += 1
                return
            if name in {'fstat', 'newfstatat', 'statx'}:
                body = args[-1] if name != 'newfstatat' else args[2]
                self.metadata_arguments(name, args)
                self.metadata_body(name, body, value, 'S_IFREG', SIZES[image])
                state['fdstat'] = True
                return
            if name == 'close':
                if len(args) != 1 or value != 0 or role == 'source' and self.initialized:
                    raise TraceError('native image lifetime ended before process termination')
                if role == 'alias':
                    if state['maps'] != set(SEGMENTS[image]) or not state['guard'] or state['trimmed'] != len(state['trims']):
                        raise TraceError('native loader alias closed before all segments and guard setup')
                    state['alias'] = None
                del self.native_fds[number]
                return
            raise TraceError('unapproved native descriptor operation')
        if name == 'mmap' and len(args) == 6:
            active = next(((image, state) for image, state in self.states.items() if state['alias'] is not None), None)
            if active and args[:1] == ['NULL'] and args[2:] == ['PROT_NONE', 'MAP_PRIVATE|MAP_ANONYMOUS', '-1', '0']:
                image, state = active
                size = next(size for (size, offset) in SEGMENTS[image] if offset == 0)
                if state['reservation'] is not None or state['headers'] != 1 or not state['fdstat'] or unsigned(args[1]) != size + 65536 or value is None or value <= 0 or value + size + 65536 > 1 << 64:
                    raise TraceError('native reservation differs from exact once-only loader span')
                self.require_unowned(value, size + 65536)
                base = (value + 65535) & ~65535
                end = base + ((size + 4095) & ~4095)
                state['reservation'] = (value, size + 65536, base, end)
                if base > value:
                    state['trims'].append((value, base - value))
                state['trims'].append((end, value + size + 65536 - end))
                return
            number = descriptor(args[4])[0]
            if number in self.native_fds:
                number, image, role = self.native_fd(args[4])
                state = self.states[image]
                count = unsigned(args[1])
                offset = int(args[5], 16) if args[5].startswith('0x') else unsigned(args[5])
                if role != 'alias' or state['headers'] != 1 or not self.preinit() or not self.source_ready() or not runtime.image_ready() or state['alias'] != number or BASE.flags(args[3], {'MAP_PRIVATE', 'MAP_FIXED', 'MAP_DENYWRITE'}) != {'MAP_PRIVATE', 'MAP_FIXED', 'MAP_DENYWRITE'} or args[2] != SEGMENTS[image].get((count, offset)) or (count, offset) in state['maps'] or args[0] == 'NULL' or value is None or value <= 0 or int(args[0], 16) != value or value + count > 1 << 64 or state['reservation'] is None:
                    raise TraceError('native mapping requires exact immutable private segment and fixed-address result')
                base = state['reservation'][2]
                if value != base + (0 if offset == 0 else 0x1f000) or offset and (not state['guard'] or state['trimmed'] != len(state['trims'])):
                    raise TraceError('native segment address/order differs from its owned reservation')
                state['maps'].add((count, offset))
                state.setdefault('addresses', {})[(count, offset)] = value
                return
        if name == 'mprotect' and len(args) == 3 and args[0] != 'NULL':
            address = int(args[0], 16)
            for image, state in self.states.items():
                if state['reservation'] is not None and address == state['reservation'][2] + 4096:
                    if args[1:] != ['122880', 'PROT_NONE'] or value != 0 or state['guard'] or len(state['maps']) != 1 or state['trimmed'] != len(state['trims']):
                        raise TraceError('native loader gap guard differs from exact reserved pages/order')
                    state['guard'] = True
                    return
                rw = next((key for key, protection in SEGMENTS[image].items() if protection == 'PROT_READ|PROT_WRITE'), None)
                if rw in state.get('addresses', {}) and address == state['addresses'][rw]:
                    if args[1:] != ['4096', 'PROT_READ'] or value != 0 or state['relro'] or state['maps'] != set(SEGMENTS[image]) or state['alias'] is not None:
                        raise TraceError('native RELRO must seal the exact once-only mapped data page')
                    state['relro'] = True
                    return
        if name == 'munmap' and len(args) == 2 and args[0] != 'NULL':
            pair = (int(args[0], 16), unsigned(args[1]))
            for state in self.states.values():
                if state['trimmed'] < len(state['trims']) and pair == state['trims'][state['trimmed']]:
                    if value != 0 or len(state['maps']) != 1 or state['guard']:
                        raise TraceError('native reservation trim precedes initial mapping or follows guard')
                    state['trimmed'] += 1
                    return
                if pair in state['trims']:
                    raise TraceError('native reservation trim is duplicated or reordered')
        if name in {'mprotect', 'munmap', 'mremap', 'mmap'} and args[0] != 'NULL':
            start = int(args[0], 16)
            length = unsigned(args[1])
            self.require_unowned(start, length, runtime_too=bool(self.load_order))
        if name in {'mmap', 'mremap'} and value is not None and value > 0:
            self.require_unowned(value, unsigned(args[1 if name == 'mmap' else 2]), runtime_too=bool(self.load_order))
        if name == 'write':
            if descriptor(args[0])[0] in runtime.created:
                if not self.initialized or not self.source_ready():
                    raise TraceError('runtime memfd population precedes native host admission')
                return runtime.call(name, self.normalized(args), result)
            stream = descriptor(args[0])[0] - 1
            if len(args) != 3 or stream not in {0, 1} or not (self.native_ready() if self.initialized else self.control_ready()):
                raise TraceError('extension diagnostic precedes complete native/runtime admission')
            self.runtime.inherited(self.normalized([args[0]])[0])
            match = re.fullmatch(r'"((?:[^"\\]|\\.)*)"', args[1])
            if match is None:
                raise TraceError('diagnostic must retain complete bytes')
            payload = bytes(match[1], 'ascii').decode('unicode_escape').encode('latin1')
            if not payload or value != len(payload) or unsigned(args[2]) != len(payload):
                raise TraceError('diagnostic write count differs from complete bytes')
            self.output[stream].extend(payload)
            if not self.expected[stream].startswith(self.output[stream]):
                raise TraceError('diagnostic bytes differ from exact matrix output')
            if not self.initialized:
                return
        if name == 'read' and descriptor(args[0])[1] == runtime.archive:
            start = runtime.archive_cursor
            self.last_archive_read = (start, value)
            if self.mode == 'corrupt-native' and start == self.corrupt_offset + self.corrupt_bytes and value in {32768, 1616}:
                if self.corrupt_bytes == 0:
                    self.corrupt_read = args[1].startswith('"~ELF')
                if self.corrupt_read:
                    self.corrupt_bytes += value
        if self.runtime_policy is BUNDLED and name == 'mremap':
            if len(args) != 4 or self.manifest_backing is None or args[0] == 'NULL' or int(args[0], 16) != self.manifest_backing or args[1:] != ['176128', '348160', 'MREMAP_MAYMOVE'] or self.manifest_remaps or runtime.archive_complete() or runtime.created or value is None or value <= 0:
                raise TraceError('native manifest growth differs from observed private anonymous backing')
            self.manifest_remaps = 1
            self.manifest_backing = None
            return
        if name == 'munmap' and self.manifest_backing is not None and args[0] != 'NULL':
            start, length = int(args[0], 16), unsigned(args[1])
            if start < self.manifest_backing + 176128 and self.manifest_backing < start + length:
                self.manifest_backing = None
        if self.initialized and name in {'gettid', 'readlinkat'} or name == 'openat' and quoted(args[1]) == '/usr/share/zoneinfo/UTC0':
            if not self.native_ready():
                raise TraceError('Python initialization precedes closed, fully admitted native closure')
        if name == 'memfd_create' or name == 'openat' and quoted(args[1]) in HOST.Checker('success').host_sizes:
            if not self.source_ready():
                raise TraceError('runtime acquisition precedes complete native host verification')
        if name in {'openat', 'memfd_create'} and value is not None and value >= 3 and value in self.native_fds.keys() | self.directory_fds.keys():
            raise TraceError('runtime descriptor allocation collides with a retained native owner')
        runtime.call(name, self.normalized(args), result)
        if name == 'mmap' and len(args) == 6 and args[4] != '-1' and descriptor(args[4])[1] == (runtime.library if self.runtime_policy is HOST else BUNDLED.MEMFD_PATH):
            self.runtime_spans.append((value, value + unsigned(args[1])))
        if self.runtime_policy is BUNDLED and name == 'mmap' and args[:5] == ['NULL', '176128', 'PROT_READ|PROT_WRITE', 'MAP_PRIVATE|MAP_ANONYMOUS', '-1'] and runtime.archive_opened == 1 and not runtime.archive_complete():
            self.manifest_backing = value

    def require_unowned(self, start, length, runtime_too=True):
        if not 0 < length or start + length > 1 << 64:
            raise TraceError('memory interval is empty or overflows u64')
        spans = list(self.runtime_spans) if runtime_too else []
        for state in self.states.values():
            if state['reservation'] is not None:
                raw, count, base, end = state['reservation']
                spans.append((raw, raw + count) if state['trimmed'] != len(state['trims']) else (base, end))
        if any(start < end and base < start + length for base, end in spans):
            raise TraceError('memory result overlaps a retained native or selected runtime image')

    def require_ancestors(self, path):
        ancestors = []
        for parent in Path(path).parents:
            candidates = [fd for fd, retained in self.directory_fds.items() if retained == str(parent)]
            if not candidates or candidates[-1] not in self.directory_metadata or self.path_metadata.get(str(parent), 0) < 2:
                raise TraceError('native input lacks retained no-follow directory ancestors')
            ancestors.append(candidates[-1])
        return ancestors

    def metadata_arguments(self, name, args):
        if name == 'fstat' and len(args) == 2:
            return
        if name == 'newfstatat' and len(args) == 4 and args[1] == '""' and args[3] == 'AT_EMPTY_PATH':
            return
        if name == 'statx' and len(args) == 5 and args[1:4] == ['""', 'AT_STATX_SYNC_AS_STAT|AT_EMPTY_PATH', 'STATX_ALL']:
            return
        raise TraceError('native descriptor metadata must inspect its exact opened object')

    def metadata_body(self, name, body, value, kind, size=None):
        pattern = (r'\{stx_mask=STATX_ALL\|STATX_MNT_ID, stx_attributes=(?:0|STATX_ATTR_MOUNT_ROOT), stx_mode=' + kind + r'\|[0-7]{4}, stx_size=([0-9]{1,20}), \.\.\.\}' if name == 'statx'
                   else r'\{st_mode=' + kind + r'\|[0-7]{4}, st_size=([0-9]{1,20}), \.\.\.\}')
        match = re.fullmatch(pattern, body)
        if value != 0 or match is None or size is not None and unsigned(match[1]) != size:
            raise TraceError('native metadata differs from exact regular-image/directory structure and size')

    def line(self, line):
        runtime = self.runtime
        if runtime.completed:
            raise TraceError('record after process completion')
        completed = re.fullmatch(r'([1-9][0-9]{0,9})\s+\+\+\+ exited with ([01]) \+\+\+', line)
        if completed:
            runtime.process(completed[1])
            expected = 0 if self.mode in CELLS else 1
            if not runtime.exit_group or int(completed[2]) != expected:
                raise TraceError('completion differs from exact fixture exit')
            runtime.completed = True
            return
        match = BASE.LINE.fullmatch(line)
        if match is None:
            raise TraceError('unparsed, abbreviated or incomplete trace record')
        runtime.process(match[1])
        self.call(match[2], BASE.split_arguments(match[3]), match[4])

    def finish(self):
        if self.runtime_policy is BUNDLED:
            expected_remaps = 1 if self.cell == 'bundled-archived' else 0
            if self.manifest_remaps != expected_remaps:
                raise TraceError('native manifest allocation sequence is incomplete')
            self.runtime.remaps = 1  # Its independently checked replacement profile above.
        if self.initialized:
            if not self.native_ready():
                raise TraceError('native closure is incomplete')
            self.runtime.finish()
        elif not self.control_ready() or self.runtime.execs != 1 or not self.runtime.exit_group or not self.runtime.completed or self.runtime.virtual_queries or self.runtime.overcommit_reads or self.runtime.tid_queries:
            raise TraceError('pre-initialization rejection lacks exact failed admission and closed inputs')
        if tuple(bytes(stream) for stream in self.output) != self.expected:
            raise TraceError('retained diagnostics differ from exact extension fixture output')


def check_lines(lines, mode, archive_bytes, corrupt_offset=None, admission=None):
    checker = Checker(mode, archive_bytes, corrupt_offset, admission)
    total = 0
    for number, line in enumerate(lines, 1):
        total += len(line.encode('utf-8'))
        if number > MAX_RECORDS or total > MAX_TRACE_BYTES or len(line) > MAX_LINE_CHARACTERS + 1 or not line.endswith('\n') or '\r' in line:
            raise TraceError('trace is oversized, noncanonical or incomplete')
        try:
            checker.line(line[:-1])
        except TraceError as error:
            raise TraceError(f'line {number}: {error}') from error
    checker.finish()


def check_file(path, mode, archive_bytes, corrupt_offset=None, admission=None):
    if path.stat().st_size > MAX_TRACE_BYTES:
        raise TraceError('trace input exceeds bounded raw/compressed size')
    with (gzip.open if path.suffix == '.gz' else open)(path, 'rb') as stream:
        def lines():
            while raw := stream.readline(MAX_LINE_CHARACTERS + 2):
                yield raw.decode('utf-8', errors='strict')
        check_lines(lines(), mode, archive_bytes, corrupt_offset, admission)


def validate_admission(size, admission, offset=None):
    if not isinstance(admission, (tuple, list)) or len(admission) != 2:
        raise TraceError('corrupt native replay requires retained manifest and ZIP-directory bounds')
    length, directory = admission
    if (type(length) is not int or type(directory) is not int or not 0 < length <= 1024 * 1024 or
            not 64 + length < directory <= size - 22 or
            offset is not None and not 64 + length <= offset <= directory - SIZES[NAMES[0]]):
        raise TraceError('retained manifest/ZIP-directory bounds are inconsistent with archive/member size')


def corrupt_offset(path):
    with zipfile.ZipFile(path) as archive:
        info = archive.getinfo(CORRUPT_KEY)
        if info.compress_type != zipfile.ZIP_STORED or info.file_size != SIZES[NAMES[0]] or info.compress_size != SIZES[NAMES[0]]:
            raise TraceError('corrupt dependency differs from the pinned stored native image')
        with path.open('rb') as stream:
            stream.seek(info.header_offset)
            header = stream.read(30)
            if len(header) != 30 or header[:4] != b'PK\x03\x04':
                raise TraceError('corrupt dependency lacks complete local ZIP header')
            names, extra = struct.unpack_from('<HH', header, 26)
            return info.header_offset + 30 + names + extra


def native_facts(directory):
    facts = {}
    for name in NAMES:
        path = directory / name
        if path.is_symlink() or path.stat().st_size != SIZES[name]:
            raise TraceError('native retained image size/type differs from pinned fixture')
        payload = path.read_bytes()
        if hashlib.sha256(payload).hexdigest() != HASHES[name] or payload[:6] != b'\x7fELF\x02\x01' or struct.unpack_from('<H', payload, 18)[0] != 183:
            raise TraceError('native retained image identity/architecture differs from pinned fixture')
        offset = struct.unpack_from('<Q', payload, 32)[0]
        stride, count = struct.unpack_from('<HH', payload, 54)
        if stride != 56 or not 0 < count <= 32 or offset + count * stride > len(payload):
            raise TraceError('native program headers are outside bounded image')
        loads = []
        for index in range(count):
            kind, flags, start, virtual, physical, file_size, memory_size, align = struct.unpack_from('<IIQQQQQQ', payload, offset + index * stride)
            if kind == 1:
                loads.append({'flags': flags, 'offset': start, 'vaddr': virtual,
                              'filesz': file_size, 'memsz': memory_size, 'align': align})
        if loads != EXPECTED_LOADS[name]:
            raise TraceError('native retained PT_LOAD inventory differs')
        facts[name] = {'size': len(payload), 'sha256': HASHES[name], 'loads': loads}
    return facts


def archive_record(path):
    size = path.stat().st_size
    if not 0 < size <= 128 * 1024 * 1024:
        raise TraceError('retained archive is outside bounded extension profile')
    digest = hashlib.sha256()
    with path.open('rb') as stream:
        header = stream.read(64)
        if len(header) != 64 or header[:8] != b'GLUERS00':
            raise TraceError('archive lacks exact locator')
        length = struct.unpack_from('<Q', header, 16)[0]
        if not 0 < length <= 1024 * 1024 or 64 + length > size:
            raise TraceError('archive manifest is outside bounded locator')
        manifest_bytes = stream.read(length)
        manifest = json.loads(manifest_bytes)
        stream.seek(0)
        while block := stream.read(1024 * 1024):
            digest.update(block)
    with zipfile.ZipFile(path) as archive:
        directory_offset = archive.start_dir
    validate_admission(size, (length, directory_offset))
    provisioning = manifest['runtimes']['python']['provisioning']
    if provisioning['mode'] not in {'host', 'bundled'}:
        raise TraceError('archive runtime provider is outside extension matrix')
    runtime = provisioning['mode']
    native = 'host' if manifest['host_imports'] else 'archived'
    declarations = {}
    for name in NAMES:
        spec = (manifest['host_imports'][name] if native == 'host' else manifest['resources']['native/' + name])
        declarations[name] = {'sha256': spec['sha256']}
        if native == 'host':
            declarations[name]['path'] = spec['path']
        else:
            declarations[name]['size'] = spec['size']
            declarations[name]['compression'] = spec['compression']
    record = {'bytes': size, 'sha256': digest.hexdigest(), 'manifest_sha256': hashlib.sha256(manifest_bytes).hexdigest(),
              'manifest_bytes': length, 'zip_directory_offset': directory_offset,
              'runtime': runtime, 'native': native, 'declarations': declarations}
    if path.stem == 'corrupt-native':
        record['corrupt_native_offset'] = corrupt_offset(path)
    return record


def emit_metadata(directory, archives, output):
    names = CELLS + NEGATIVE
    metadata = {'schema_version': 0, 'files': native_facts(directory),
                'archives': {name: archive_record(archives / (name + '.glue')) for name in names}}
    output.write_text(json.dumps(metadata, indent=2, sort_keys=True) + '\n')


def retained_metadata(path, mode, size, offset):
    if path.stat().st_size > 64 * 1024:
        raise TraceError('native metadata exceeds bounded profile')
    metadata = json.loads(path.read_text())
    if (not isinstance(metadata, dict) or type(metadata.get('schema_version')) is not int or metadata['schema_version'] != 0 or
            not isinstance(metadata.get('files'), dict) or set(metadata['files']) != set(NAMES) or
            not isinstance(metadata.get('archives'), dict) or set(metadata['archives']) != set(CELLS + NEGATIVE)):
        raise TraceError('retained native metadata inventory differs')
    for name, facts in metadata['files'].items():
        if not isinstance(facts, dict) or facts.get('size') != SIZES[name] or facts.get('sha256') != HASHES[name] or facts.get('loads') != EXPECTED_LOADS[name]:
            raise TraceError('retained native image identity differs')
        first, second = facts['loads']
        count = next(count for count, file_offset in SEGMENTS[name] if file_offset == 0)
        rw = next(count for count, file_offset in SEGMENTS[name] if file_offset != 0)
        if first['flags'] != 5 or first['offset'] != 0 or first['vaddr'] != 0 or first['align'] != 65536 or second['flags'] != 6 or second['align'] != 65536 or second['vaddr'] - second['offset'] != 65536 or second['vaddr'] + second['memsz'] != count or ((second['vaddr'] + second['memsz'] + 4095) & ~4095) - (second['vaddr'] & ~4095) != rw:
            raise TraceError('retained native PT_LOAD facts differ from observed GNU image layout')
    key = mode if mode in NEGATIVE else cell_for(mode)
    record = metadata['archives'][key]
    runtime, native = cell_for(mode).split('-')
    if (not isinstance(record, dict) or record.get('bytes') != size or record.get('runtime') != runtime or record.get('native') != native or
            not isinstance(record.get('declarations'), dict) or set(record['declarations']) != set(NAMES)):
        raise TraceError('retained archive size/provider/declaration inventory differs from cell')
    if any(not isinstance(record.get(key), str) or re.fullmatch(r'[0-9a-f]{64}', record[key]) is None for key in ('sha256', 'manifest_sha256')):
        raise TraceError('retained archive/manifest identity is not a canonical SHA256')
    validate_admission(size, (record.get('manifest_bytes'), record.get('zip_directory_offset')), offset if mode == 'corrupt-native' else None)
    for name, spec in record['declarations'].items():
        if not isinstance(spec, dict) or spec.get('sha256') != HASHES[name] or (spec.get('path') != prefix_for(mode) + '/' + name if native == 'host' else spec.get('size') != SIZES[name] or spec.get('compression') != 'stored'):
            raise TraceError('native manifest declaration differs from pinned image/path')
    if mode == 'corrupt-native' and record.get('corrupt_native_offset') != offset:
        raise TraceError('retained corruption offset differs from archive metadata')
    return record


def main():
    if len(sys.argv) == 5 and sys.argv[1] == '--emit-native-metadata':
        try:
            emit_metadata(Path(sys.argv[2]), Path(sys.argv[3]), Path(sys.argv[4]))
        except (OSError, ValueError, KeyError, struct.error, zipfile.BadZipFile, TraceError) as error:
            print(f'native metadata rejected: {error}', file=sys.stderr)
            return 1
        return 0
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('trace', type=Path)
    parser.add_argument('--mode', choices=MODES, required=True)
    parser.add_argument('--stdout-file', type=Path, required=True)
    parser.add_argument('--stderr-file', type=Path, required=True)
    archive = parser.add_mutually_exclusive_group(required=True)
    archive.add_argument('--archive-file', type=Path)
    archive.add_argument('--archive-bytes', type=int)
    parser.add_argument('--corrupt-native-offset', type=int)
    parser.add_argument('--native-metadata-file', type=Path, required=True)
    args = parser.parse_args()
    try:
        for path, expected in zip((args.stdout_file, args.stderr_file), expected_output(args.mode)):
            with path.open('rb') as stream:
                if stream.read(len(expected) + 1) != expected:
                    raise TraceError('retained stdout/stderr differs from exact fixture output')
        size = args.archive_file.stat().st_size if args.archive_file else args.archive_bytes
        offset = corrupt_offset(args.archive_file) if args.mode == 'corrupt-native' and args.archive_file else args.corrupt_native_offset
        record = retained_metadata(args.native_metadata_file, args.mode, size, offset)
        if args.archive_file and archive_record(args.archive_file) != record:
            raise TraceError('retained archive identity/manifest differs from native metadata')
        check_file(args.trace, args.mode, size, offset, (record['manifest_bytes'], record['zip_directory_offset']))
    except (OSError, UnicodeError, EOFError, ValueError, KeyError, zipfile.BadZipFile, struct.error, TraceError) as error:
        print(f'registered Python extension trace rejected: {error}', file=sys.stderr)
        return 1
    print('Trace checks passed: complete immutable archive and five-image native admission, exact provider mappings before Python initialization, isolated imports and finalization, exact diagnostics and exit, no mutation, fallback or extra process')
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
