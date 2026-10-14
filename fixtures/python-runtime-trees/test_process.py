#!/usr/bin/env python3
"""Closed GNU arm64 process audit for selected installed-runtime preparation.

No product module is imported. Full file identities come from the independent
selected-input/output audit. A -s512 trace additionally binds live descriptor
owners, visible byte prefixes, exact transfer totals, EOF, and publication order;
it cannot recover SHA-256 for bytes which strace deliberately abbreviates.
"""
from __future__ import annotations

import argparse
from dataclasses import dataclass
import gzip
import importlib.util
import json
from pathlib import Path
import posixpath
import re
import sys

# The native harness runs a stock producer with -I -S. Admit only this fixture
# directory for its independent sibling oracle, never an input Python path.
sys.path.insert(0, str(Path(__file__).resolve().parent))
import prepare


HERE = Path(__file__).resolve().parent
MTIME = 1704067200
TRACE_BYTES = 512
DIRECTORY_FLAGS = {'O_RDONLY', 'O_NOFOLLOW', 'O_DIRECTORY', 'O_CLOEXEC'}
LEAF_FLAGS = {'O_RDONLY', 'O_NOFOLLOW', 'O_NONBLOCK', 'O_CLOEXEC'}
WRITE_FLAGS = {'O_WRONLY', 'O_CREAT', 'O_EXCL', 'O_CLOEXEC'}
SYSTEM_LIBRARIES = {'/usr/lib/aarch64-linux-gnu/' + name
                    for name in ('libm.so.6', 'libgcc_s.so.1', 'libc.so.6')}
QUOTED = re.compile(r'"((?:[^"\\]|\\.)*)"')
DESCRIPTOR = re.compile(r'(AT_FDCWD|\d+)<([^<>]*)>')


def require(condition, message):
    if not condition:
        raise ValueError(message)


def load_host_oracle():
    path = HERE.parent / 'python-host-prerequisites/test_prepare.py'
    spec = importlib.util.spec_from_file_location('_original_host_file_oracle', path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def path_string(text):
    require(type(text) is str and text.startswith('/') and text != '/' and text.isascii() and
            not any(ord(c) < 32 or ord(c) == 127 or c in '\\<>' for c in text) and
            not text.endswith('/') and '//' not in text and
            all(part not in ('.', '..') for part in text.split('/')), 'noncanonical process audit path')
    return text


def ancestors(path):
    result = {'/'}
    while path != '/':
        result.add(path)
        path = posixpath.dirname(path)
    return result


def directories(files):
    result = {''}
    for path in files:
        parent = posixpath.dirname(path)
        while parent:
            result.add(parent)
            parent = posixpath.dirname(parent)
    return result


def compact(value):
    return json.dumps(value, ensure_ascii=False, separators=(',', ':'), allow_nan=False).encode() + b'\n'


@dataclass
class Contract:
    program: str
    root: str
    prefix: str
    inputs: dict
    input_prefixes: dict
    outputs: dict
    output_prefixes: dict
    report: bytes
    provenance: bytes
    layout: str
    require_system_reads: bool = True

    @property
    def command(self):
        return [self.program, 'python-host', '--provider', 'host-install', '--runtime-tree',
                self.root, '--output', self.prefix, '--json']


def contract(program, root, prefix, report_bytes, input_audit):
    for path in (program, root, prefix):
        path_string(path)
    require(not (root == prefix or root.startswith(prefix + '/') or prefix.startswith(root + '/')),
            'audit input/output roots overlap')
    if 'selected_input_audit' in input_audit:
        input_audit = input_audit['selected_input_audit']
    stock = {path: {'size': item['size'], 'sha256': item['sha256']}
             for path, item in prepare.selected_contract().items()}
    layout = input_audit['input_layout']
    require(layout in ('stock', 'uv-0.12.23') and input_audit['root'] == root, 'input audit root/layout differs')
    uv = prepare.uv_sysconfig(Path(root))
    inputs = dict(stock)
    if layout != 'stock':
        inputs[prepare.SYSCONFIG] = prepare.identity(uv)
    expected_facts = {'schema_version': 0, 'root': root, 'input_layout': layout,
                      'selected_files': inputs, 'selected_file_count': 1041,
                      'selected_input_bytes': sum(item['size'] for item in inputs.values()),
                      'selected_output_bytes': 89479393,
                      'sysconfig_input': inputs[prepare.SYSCONFIG], 'sysconfig_output': prepare.STOCK_IDENTITY,
                      'sysconfig_normalized': layout != 'stock', 'input_python_execution_observed': False,
                      'complete_input_inventory_observed': False}
    require(prepare.same_json({key: input_audit[key] for key in expected_facts}, expected_facts),
            'input audit differs from independent selected contract')
    prefixes = input_audit['selected_file_prefixes']
    require(set(prefixes) == set(inputs), 'input audit prefix inventory differs')
    decoded = {}
    for path, value in prefixes.items():
        require(type(value) is str and re.fullmatch('[0-9a-f]*', value) is not None and
                len(value) == 2 * min(TRACE_BYTES, inputs[path]['size']), 'input audit prefix length/spelling differs')
        decoded[path] = bytes.fromhex(value)
        if inputs[path]['size'] <= TRACE_BYTES:
            require(prepare.same_json(prepare.identity(decoded[path]), inputs[path]), 'complete short input bytes differ')
    require(decoded[prepare.SYSCONFIG] == (uv if layout != 'stock' else (HERE / 'stock-sysconfig.py').read_bytes())[:TRACE_BYTES],
            'independent sysconfig prefix differs')

    host = load_host_oracle()
    host_files, base = host.expected_contract('host-install')
    require(prepare.same_json(stock, host_files), 'independent output contracts disagree')
    base['files'] = stock
    template = (HERE / 'uv-0.12.23-sysconfig.py.in').read_bytes()
    require(prepare.identity(template) == {'size': 51552, 'sha256': 'ac2bdd1c0d98d36a508b19006c7485e0100585ff3703f090dab6b075017f11fb'},
            'fixed sysconfig template reference differs')
    tree = {'input_root': root, 'input_layout': 'uv-0.12.23-sysconfig' if layout != 'stock' else 'stock-install-only',
            'inspection_scope': 'selected-prerequisites-only', 'expected_artifact': base['artifact'],
            'sysconfig_input': inputs[prepare.SYSCONFIG], 'sysconfig_output': stock[prepare.SYSCONFIG],
            'sysconfig_normalized': layout != 'stock',
            'sysconfig_template': ({'path': 'fixtures/python-runtime-trees/uv-0.12.23-sysconfig.py.in'} |
                                   prepare.identity(template)) if layout != 'stock' else None}
    provenance = {}
    for key, value in base.items():
        provenance[key] = None if key in ('artifact', 'artifact_entries', 'artifact_payload_bytes',
                                        'omitted_files', 'omitted_bytes') else value
        if key == 'omitted_bytes':
            provenance['installed_tree'] = tree
    provenance_bytes = compact(provenance)
    expected_report = {'provider': 'host-install', 'prefix': prefix, 'provenance': provenance,
                       'provenance_file': {'path': 'provenance.json'} | prepare.identity(provenance_bytes),
                       'files': stock, 'file_count': 1041, 'payload_bytes': 89479393,
                       'directory_count': len(directories(stock)), 'file_mode': 292, 'directory_mode': 365,
                       'mtime_seconds': MTIME}
    require(report_bytes == compact(expected_report), 'stdout bytes differ from complete independent report')
    outputs = dict(stock)
    outputs['provenance.json'] = prepare.identity(provenance_bytes)
    out_prefixes = dict(decoded)
    out_prefixes[prepare.SYSCONFIG] = (HERE / 'stock-sysconfig.py').read_bytes()[:TRACE_BYTES]
    out_prefixes['provenance.json'] = provenance_bytes[:TRACE_BYTES]
    return Contract(program, root, prefix, inputs, decoded, outputs, out_prefixes,
                    report_bytes, provenance_bytes, layout)


def decode_bytes(text):
    result, index = bytearray(), 0
    escapes = {'a': 7, 'b': 8, 'f': 12, 'n': 10, 'r': 13, 't': 9, 'v': 11,
               '\\': 92, '"': 34, "'": 39}
    while index < len(text):
        char = text[index]
        index += 1
        if char != '\\':
            result.extend(char.encode('utf-8'))
            continue
        require(index < len(text), 'unterminated trace escape')
        char = text[index]
        index += 1
        if char in escapes:
            result.append(escapes[char])
        elif char in '01234567':
            digits = char
            while index < len(text) and len(digits) < 3 and text[index] in '01234567':
                digits += text[index]
                index += 1
            require(int(digits, 8) <= 255, 'trace octal escape exceeds a byte')
            result.append(int(digits, 8))
        elif char == 'x':
            digits = text[index:index + 2]
            require(re.fullmatch('[0-9a-fA-F]{2}', digits) is not None, 'invalid trace hexadecimal escape')
            result.append(int(digits, 16))
            index += 2
        else:
            raise ValueError('unknown trace escape')
    return bytes(result)


def string(token):
    match = QUOTED.fullmatch(token.strip())
    require(match is not None, 'incomplete trace pathname')
    return decode_bytes(match.group(1)).decode('utf-8')


def split_arguments(text):
    result, start, stack, quoted, escaped, angle = [], 0, [], False, False, 0
    for index, char in enumerate(text):
        if quoted:
            if escaped:
                escaped = False
            elif char == '\\':
                escaped = True
            elif char == '"':
                quoted = False
        elif char == '"':
            quoted = True
        elif char == '<':
            angle += 1
        elif char == '>' and angle:
            angle -= 1
        elif not angle and char in '([{':
            stack.append(char)
        elif not angle and char in ')]}':
            require(stack and '([{'.index(stack.pop()) == ')]}'.index(char), 'unbalanced syscall arguments')
        elif char == ',' and not stack and not angle:
            result.append(text[start:index].strip())
            start = index + 1
    require(not stack and not quoted and not angle, 'incomplete syscall arguments')
    result.append(text[start:].strip())
    return result


def descriptor(token):
    match = re.fullmatch(r'(AT_FDCWD|-?\d+)(?:<([^<>]*)>)?', token)
    require(match is not None, 'descriptor argument lacks complete owner annotation')
    number = match.group(1) if match.group(1) == 'AT_FDCWD' else int(match.group(1))
    path = decode_bytes(match.group(2)).decode() if match.group(2) is not None else None
    return number, path


def flags(token):
    require(re.fullmatch(r'O_[A-Z0-9_]+(?:\|O_[A-Z0-9_]+)*', token) is not None, 'open flags are unclassified')
    values = token.split('|')
    require(len(values) == len(set(values)), 'duplicate open flag')
    return set(values)


@dataclass
class Owner:
    path: str
    kind: str
    transferred: int = 0
    stats: int = 0
    eof: bool = False
    mode: bool = False
    mtime: bool = False


class Audit:
    def __init__(self, expected):
        self.expected = expected
        self.pid = None
        self.live = {}
        self.execs = self.exits = self.exit_groups = self.stdout_bytes = 0
        self.selected_opened = self.selected_closed = 0
        self.output_absence_probes = 0
        self.input_bytes = self.output_bytes = 0
        self.max_input_owners = 0
        self.created_dirs, self.finished_files, self.finished_dirs = set(), set(), set()
        self.created_files = []
        self.stdout_path = None
        self.system_opened, self.system_closed = set(), set()
        self.root_ancestors = ancestors(expected.root)
        self.parent_ancestors = ancestors(posixpath.dirname(expected.prefix))
        self.input_dirs = {expected.root + ('/' + name if name else '') for name in directories(expected.inputs)}
        self.output_dirs = {expected.prefix + ('/' + name if name else '') for name in directories(expected.outputs)}
        self.input_open_order = []
        for absolute in sorted(self.root_ancestors, key=lambda path: (path.count('/'), path)):
            self.input_open_order.append(absolute)
        for relative in sorted(expected.inputs):
            parts = relative.split('/')
            self.input_open_order.extend(expected.root + '/' + '/'.join(parts[:index]) for index in range(1, len(parts) + 1))
        self.input_open_index = 0
        self.creation_order = sorted(expected.inputs) + ['provenance.json']

    def relative(self, path, root):
        require(path.startswith(root + '/'), 'descriptor is outside its expected tree')
        return path[len(root) + 1:]

    def owner(self, token, kinds=None):
        number, annotation = descriptor(token)
        require(type(number) is int and number in self.live, 'descriptor was not opened or was already closed')
        owner = self.live[number]
        require(annotation == owner.path, 'descriptor annotation aliases its remembered owner')
        require(kinds is None or owner.kind in kinds, 'descriptor operation does not fit its owner')
        return number, owner

    def resolved(self, base, pathname):
        number, annotation = descriptor(base)
        if number == 'AT_FDCWD':
            require(annotation is not None and annotation.startswith('/'), 'AT_FDCWD lacks a complete absolute owner')
            parent = annotation
        else:
            _, owner = self.owner(base, {'input-directory', 'output-directory'})
            parent = owner.path
        require('\0' not in pathname and pathname != '.', 'pathname has NUL/dot')
        if pathname.startswith('/'):
            require('//' not in pathname and '/./' not in pathname and '/..' not in pathname and
                    (pathname == '/' or not pathname.endswith('/')), 'noncanonical absolute trace pathname')
            return pathname
        require(pathname and '/' not in pathname and pathname not in ('.', '..'), 'relative open is not one path component')
        return parent.rstrip('/') + '/' + pathname

    def check_buffer(self, token, requested, returned, expected_prefix, offset, whole=None):
        match = re.fullmatch(r'"((?:[^"\\]|\\.)*)"(\.\.\.)?', token)
        require(match is not None and 0 <= returned <= requested, 'transfer buffer/result is malformed')
        visible = decode_bytes(match.group(1))
        expected_visible = min(returned, TRACE_BYTES)
        require(len(visible) == expected_visible and bool(match.group(2)) == (returned > TRACE_BYTES),
                'transfer buffer visibility differs from -s512')
        payload = whole if whole is not None else expected_prefix
        overlap = min(len(visible), max(0, len(payload) - offset))
        require(visible[:overlap] == payload[offset:offset + overlap], 'visible transfer bytes differ from independent audit')

    def complete_inputs(self):
        require(self.selected_closed == len(self.expected.inputs) and self.input_open_index == len(self.input_open_order) and
                not any(owner.kind.startswith('input-') for owner in self.live.values()),
                'publication precedes complete selected reads/EOF/restats/closes')

    def complete_publication(self):
        require(self.finished_files == set(self.expected.outputs) and self.finished_dirs == self.output_dirs and
                self.created_dirs == self.output_dirs and not self.live,
                'stdout/exit precedes complete frozen publication and descriptor closure')

    def open(self, args, result):
        require(len(args) in (3, 4), 'openat argument count differs')
        opened_flags = flags(args[2])
        pathname = string(args[1])
        if pathname == self.expected.prefix + '/':
            # The publisher opens output.join("") last to freeze its root.
            require(opened_flags == {'O_RDONLY', 'O_CLOEXEC'} and descriptor(args[0])[0] == 'AT_FDCWD',
                    'trailing slash is not the final published root-directory open')
            value = self.expected.prefix
        else:
            value = self.resolved(args[0], pathname)
        require(not result.startswith('-'), 'unexpected failed open')
        number, returned = descriptor(result)
        require(type(number) is int and number > 2 and number not in self.live, 'open reassigns a live/standard descriptor')
        if value in self.root_ancestors or value in self.input_dirs or value.startswith(self.expected.root + '/'):
            require(self.input_open_index < len(self.input_open_order) and value == self.input_open_order[self.input_open_index],
                    'input path/order is not the complete pinned selected traversal')
            self.input_open_index += 1
            require(returned == value and len(args) == 3, 'input open aliases its declared path')
            relative = value[len(self.expected.root) + 1:] if value.startswith(self.expected.root + '/') else None
            leaf = relative in self.expected.inputs
            require(opened_flags == (LEAF_FLAGS if leaf else DIRECTORY_FLAGS), 'input open lacks exact no-follow directory/leaf flags')
            if value != '/':
                base_number, _ = descriptor(args[0])
                require(type(base_number) is int and string(args[1]) == posixpath.basename(value),
                        'input open bypasses descriptor-relative component traversal')
                _, parent = self.owner(args[0], {'input-directory'})
                require(parent.path == posixpath.dirname(value), 'input component owner is not its actual parent')
            self.live[number] = Owner(value, 'input-file' if leaf else 'input-directory')
            if leaf:
                self.selected_opened += 1
            self.max_input_owners = max(self.max_input_owners, sum(owner.kind.startswith('input-') for owner in self.live.values()))
            require(self.max_input_owners <= 4, 'selected traversal exceeds four live input owners')
        elif value == self.expected.prefix or value.startswith(self.expected.prefix + '/'):
            self.complete_inputs()
            require(returned == value, 'publication open aliases its declared output')
            if opened_flags == WRITE_FLAGS:
                require(len(args) == 4 and args[3] == '0666' and self.created_dirs == self.output_dirs,
                        'file publication lacks exclusive creation or complete directory creation')
                relative = self.relative(value, self.expected.prefix)
                require(len(self.created_files) < len(self.creation_order) and
                        relative == self.creation_order[len(self.created_files)] and
                        all(name in self.finished_files for name in self.created_files),
                        'file publication order/closure differs; provenance must be last')
                self.created_files.append(relative)
                self.live[number] = Owner(value, 'output-file')
            else:
                require(opened_flags == {'O_RDONLY', 'O_CLOEXEC'} and len(args) == 3 and
                        self.finished_files == set(self.expected.outputs), 'output directory opened before complete files')
                expected_order = sorted(self.output_dirs, reverse=True)
                require(len(self.finished_dirs) < len(expected_order) and value == expected_order[len(self.finished_dirs)] and
                        not any(owner.kind.startswith('output-') for owner in self.live.values()), 'directory freeze order/closure differs')
                self.live[number] = Owner(value, 'output-directory')
        else:
            require(self.input_open_index == 0 and not self.created_dirs and opened_flags == {'O_RDONLY', 'O_CLOEXEC'} and len(args) == 3,
                    'foreign read/write-capable open outside loader startup')
            aliases = {'/lib/aarch64-linux-gnu/' + posixpath.basename(name): name for name in SYSTEM_LIBRARIES}
            aliases['/etc/ld.so.cache'] = '/etc/ld.so.cache'
            aliases['/proc/self/maps'] = '/proc/' + str(self.pid) + '/maps'
            require(value in aliases and returned == aliases[value], 'open is outside exact ordinary OS read family')
            require(returned not in self.system_opened, 'system input is opened repeatedly outside fixed startup')
            self.system_opened.add(returned)
            self.live[number] = Owner(returned, 'system')

    def stat(self, name, args, result):
        require(name in ('statx', 'newfstatat'), 'unclassified metadata operation')
        require(len(args) == (5 if name == 'statx' else 4), 'metadata argument count differs')
        if result.startswith('-1'):
            require(name == 'statx' and self.output_absence_probes == 0 and self.input_open_index == 0 and
                    self.resolved(args[0], string(args[1])) == self.expected.prefix and
                    args[2] == 'AT_STATX_SYNC_AS_STAT|AT_SYMLINK_NOFOLLOW' and args[3] == 'STATX_ALL' and
                    result.startswith('-1 ENOENT '), 'failed stat is not the initial no-follow absent-output probe')
            self.output_absence_probes += 1
            return
        require(result == '0', 'unexpected stat result')
        if string(args[1]) == '':
            _, owner = self.owner(args[0], {'input-file', 'system'})
            metadata = args[4] if name == 'statx' else args[2]
            require('S_IFREG|' in metadata, 'selected/system open is not a regular file')
            size = re.search(r'\b(?:stx_size|st_size)=(\d+)', metadata)
            require(size is not None, 'metadata omits regular-file size')
            if owner.kind == 'input-file':
                relative = self.relative(owner.path, self.expected.root)
                require(int(size.group(1)) == self.expected.inputs[relative]['size'] and owner.stats < 2,
                        'selected stat size/count differs')
                require((owner.stats == 0 and owner.transferred == 0 and not owner.eof) or
                        (owner.stats == 1 and owner.eof), 'selected restat did not follow complete read and EOF')
                require('AT_EMPTY_PATH' in (args[2] if name == 'statx' else args[3]), 'selected stat is not descriptor-relative')
                owner.stats += 1
        else:
            value = self.resolved(args[0], string(args[1]))
            require(value in self.parent_ancestors, 'metadata lookup is outside admitted output parent ancestry')
            require('S_IFDIR|' in (args[4] if name == 'statx' else args[2]), 'output parent metadata is not a directory')

    def transfer(self, name, args, result):
        require(len(args) == 3 and re.fullmatch(r'\d+', args[2]) is not None and re.fullmatch(r'\d+', result) is not None,
                'transfer count/result is not an exact nonnegative integer')
        requested, returned = int(args[2]), int(result)
        if name == 'write' and descriptor(args[0])[0] == 1:
            number, path = descriptor(args[0])
            require(path is not None and path.startswith('/') and (self.stdout_path is None or self.stdout_path == path),
                    'stdout owner changed')
            self.stdout_path = path
            self.complete_publication()
            require(0 < returned <= requested <= len(self.expected.report) - self.stdout_bytes, 'stdout write total differs')
            self.check_buffer(args[1], requested, returned, b'', self.stdout_bytes, self.expected.report)
            self.stdout_bytes += returned
            return
        _, owner = self.owner(args[0], {'input-file', 'output-file', 'system'})
        if owner.kind == 'system':
            require(name == 'read' and requested > 0 and 0 <= returned <= requested and not self.created_dirs,
                    'system descriptor written or read during publication')
            self.check_buffer(args[1], requested, returned, b'', 0)
            return
        root = self.expected.root if owner.kind == 'input-file' else self.expected.prefix
        relative = self.relative(owner.path, root)
        identities = self.expected.inputs if owner.kind == 'input-file' else self.expected.outputs
        prefixes = self.expected.input_prefixes if owner.kind == 'input-file' else self.expected.output_prefixes
        remaining = identities[relative]['size'] - owner.transferred
        if owner.kind == 'input-file':
            require(name == 'read' and owner.stats == 1 and not owner.eof and not self.created_dirs,
                    'selected read is out of order, repeated after EOF, or write-capable')
            if remaining == 0:
                require(requested == 1 and returned == 0, 'selected EOF probe is absent or not exactly one byte')
                owner.eof = True
            else:
                require(0 < returned <= requested <= remaining, 'selected payload read total differs')
            self.input_bytes += returned
        else:
            require(name == 'write' and not owner.mode and not owner.mtime and 0 < returned <= requested <= remaining,
                    'publication write exceeds payload or follows freezing')
            self.output_bytes += returned
        self.check_buffer(args[1], requested, returned, prefixes[relative], owner.transferred,
                          self.expected.provenance if owner.kind == 'output-file' and relative == 'provenance.json' else None)
        owner.transferred += returned

    def close(self, args, result):
        require(len(args) == 1 and result == '0', 'close is malformed or failed')
        number, owner = self.owner(args[0])
        if owner.kind == 'input-file':
            relative = self.relative(owner.path, self.expected.root)
            require(owner.stats == 2 and owner.eof and owner.transferred == self.expected.inputs[relative]['size'],
                    'selected close lacks exact regular bytes, EOF and restat')
            self.selected_closed += 1
        elif owner.kind.startswith('output-'):
            require(owner.mode and owner.mtime, 'publication owner closed before required mode and stock mtime')
            if owner.kind == 'output-file':
                relative = self.relative(owner.path, self.expected.prefix)
                require(owner.transferred == self.expected.outputs[relative]['size'], 'publication payload write is incomplete')
                self.finished_files.add(relative)
            else:
                self.finished_dirs.add(owner.path)
        elif owner.kind == 'system':
            self.system_closed.add(owner.path)
        del self.live[number]

    def mutation(self, name, args, result):
        require(result == '0', 'publication mutation failed')
        if name == 'mkdirat':
            require(len(args) == 3 and args[2] == '0777', 'directory creation mode differs')
            self.complete_inputs()
            value = self.resolved(args[0], string(args[1]))
            require(value in self.output_dirs and value not in self.created_dirs and not self.created_files,
                    'directory creation escapes inventory or follows file publication')
            require(value == self.expected.prefix or posixpath.dirname(value) in self.created_dirs,
                    'directory parent was not exclusively created')
            self.created_dirs.add(value)
        elif name == 'fchmod':
            require(len(args) == 2, 'mode mutation argument count differs')
            _, owner = self.owner(args[0], {'output-file', 'output-directory'})
            require(not owner.mode and owner.mtime and args[1] == ('0444' if owner.kind == 'output-file' else '0555'),
                    'publication mode or timestamp-before-mode order differs')
            if owner.kind == 'output-file':
                relative = self.relative(owner.path, self.expected.prefix)
                require(owner.transferred == self.expected.outputs[relative]['size'], 'file mode set before complete bytes')
            owner.mode = True
        else:
            require(name == 'utimensat' and len(args) == 4 and args[1] == 'NULL' and args[3] == '0',
                    'unclassified publication timestamp mutation')
            _, owner = self.owner(args[0], {'output-file', 'output-directory'})
            stripped = re.sub(r'\s+', '', re.sub(r'/\*.*?\*/', '', args[2]))
            require(stripped == '[UTIME_OMIT,{tv_sec=1704067200,tv_nsec=0}]' and not owner.mtime and not owner.mode,
                    'publication timestamp differs from stock fixed epoch')
            owner.mtime = True

    def mapping(self, args):
        require(len(args) == 6, 'mapping argument count differs')
        raw_flags = set(args[3].split('|'))
        prot = set(args[2].split('|'))
        require(prot <= {'PROT_NONE', 'PROT_READ', 'PROT_WRITE', 'PROT_EXEC'} and 'MAP_PRIVATE' in raw_flags and
                not raw_flags.intersection({'MAP_SHARED', 'MAP_SHARED_VALIDATE'}), 'mapping protections/sharing differ')
        if 'MAP_ANONYMOUS' in raw_flags:
            require(args[4] == '-1' and 'PROT_EXEC' not in prot and
                    raw_flags <= {'MAP_PRIVATE', 'MAP_ANONYMOUS', 'MAP_FIXED', 'MAP_STACK'}, 'anonymous executable/unclassified mapping')
        else:
            _, owner = self.owner(args[4], {'system'})
            require(owner.path in SYSTEM_LIBRARIES | {'/etc/ld.so.cache'} and
                    raw_flags <= {'MAP_PRIVATE', 'MAP_FIXED', 'MAP_DENYWRITE'} and
                    ('PROT_EXEC' not in prot or owner.path in SYSTEM_LIBRARIES), 'mapping acquires non-system/input/output bytes')

    def line(self, line):
        record = re.fullmatch(r'(\d+)\s+(.+)', line.rstrip('\n'))
        require(record is not None, 'trace record lacks a numbered PID')
        if self.pid is None:
            self.pid = int(record.group(1))
        require(int(record.group(1)) == self.pid and self.exits == 0, 'trace contains another PID or records after exit')
        body = record.group(2)
        if body == '+++ exited with 0 +++':
            require(self.exit_groups == 1, 'successful process exit lacks exit_group(0)')
            self.exits += 1
            return
        require('<unfinished ...>' not in body and ' resumed>' not in body, 'trace contains unfinished/resumed syscall')
        match = re.fullmatch(r'([a-z][a-z_0-9]*)\((.*)\)\s+=\s+(.+)', body)
        require(match is not None, 'unclassified process record or signal')
        name, raw, result = match.groups()
        args = split_arguments(raw)
        if name == 'execve':
            require(self.execs == 0 and result == '0' and len(args) == 3 and string(args[0]) == self.expected.program,
                    'additional/unexpected/failed executable')
            require(args[1].startswith('[') and args[1].endswith(']'), 'exec arguments are incomplete')
            command = [string(token) for token in split_arguments(args[1][1:-1])]
            require(command == self.expected.command, 'exec arguments differ from exact tree preparation command')
            self.execs += 1
            return
        require(self.execs == 1 and self.exit_groups == 0, 'syscall precedes exec or follows exit_group')
        if name == 'openat':
            self.open(args, result)
        elif name in ('statx', 'newfstatat'):
            self.stat(name, args, result)
        elif name in ('read', 'write'):
            self.transfer(name, args, result)
        elif name == 'close':
            self.close(args, result)
        elif name in ('mkdirat', 'fchmod', 'utimensat'):
            self.mutation(name, args, result)
        elif name == 'mmap':
            self.mapping(args)
            require(re.fullmatch(r'0x[0-9a-f]+', result) is not None, 'mapping failed')
        elif name == 'mprotect':
            require(len(args) == 3 and args[2] in ('PROT_NONE', 'PROT_READ', 'PROT_READ|PROT_WRITE') and result == '0',
                    'mprotect grants executable/unclassified memory')
        elif name in ('readlink', 'readlinkat'):
            require(len(args) == (3 if name == 'readlink' else 4) and self.input_open_index == 0 and
                    (string(args[0]) if name == 'readlink' else self.resolved(args[0], string(args[1]))) in self.parent_ancestors and
                    result.startswith('-1 EINVAL '), 'readlink is outside ordinary nonalias output parent resolution')
        elif name == 'faccessat':
            require(len(args) == 3 and string(args[1]) == '/etc/ld.so.preload' and args[2] == 'R_OK' and
                    result.startswith('-1 ENOENT '), 'unclassified loader access lookup')
        elif name == 'exit_group':
            require(args == ['0'] and result == '?' and self.stdout_bytes == len(self.expected.report), 'exit status/stdout total differs')
            self.complete_publication()
            self.exit_groups += 1
        elif name in {'brk', 'munmap', 'prlimit64', 'set_tid_address', 'set_robust_list', 'rseq', 'getrandom',
                      'sched_getaffinity', 'rt_sigaction', 'sigaltstack', 'ppoll'}:
            self.ordinary(name, args, result)
        else:
            raise ValueError('unclassified syscall (including child/network/alias/mutation): ' + name)

    def ordinary(self, name, args, result):
        pointer = lambda value: re.fullmatch(r'0x[0-9a-f]+', value) is not None
        if name == 'brk':
            require(len(args) == 1 and (args[0] == 'NULL' or pointer(args[0])) and pointer(result), 'brk shape differs')
        elif name == 'munmap':
            require(len(args) == 2 and pointer(args[0]) and args[1].isdigit() and int(args[1]) > 0 and result == '0',
                    'munmap shape differs')
        elif name == 'prlimit64':
            require(len(args) == 4 and args[:3] == ['0', 'RLIMIT_STACK', 'NULL'] and result == '0',
                    'prlimit accesses/mutates another process or unclassified limit')
        elif name == 'set_tid_address':
            require(len(args) == 1 and pointer(args[0]) and result == str(self.pid), 'thread address/identity differs')
        elif name == 'set_robust_list':
            require(len(args) == 2 and pointer(args[0]) and args[1] == '24' and result == '0', 'robust-list shape differs')
        elif name == 'rseq':
            require(len(args) == 4 and pointer(args[0]) and args[1:] == ['0x20', '0', '0xd428bc00'] and result == '0',
                    'GNU arm64 rseq shape differs')
        elif name == 'getrandom':
            matched = QUOTED.fullmatch(args[0]) if args else None
            require(len(args) == 3 and args[1:] == ['8', 'GRND_NONBLOCK'] and result == '8' and
                    matched is not None and len(decode_bytes(matched.group(1))) == 8, 'startup random seed shape differs')
        elif name == 'sched_getaffinity':
            require(len(args) == 3 and args[:2] == [str(self.pid), '32'] and result.isdigit() and 0 < int(result) <= 32,
                    'affinity query targets another process or cell')
        elif name == 'rt_sigaction':
            require(len(args) == 4 and args[0] in ('SIGPIPE', 'SIGSEGV', 'SIGBUS') and args[3] == '8' and result == '0',
                    'startup signal setup shape differs')
        elif name == 'sigaltstack':
            require(len(args) == 2 and all(value == 'NULL' or value.startswith('{ss_') for value in args) and result == '0',
                    'startup alternate stack setup shape differs')
        else:
            require(name == 'ppoll' and len(args) == 5 and args[1:] == ['3', '{tv_sec=0, tv_nsec=0}', 'NULL', '0'] and
                    result == '0 (Timeout)', 'startup poll is not the zero-event standard-stream check')
            streams = re.findall(r'\{fd=(\d+)<(.*?)>, events=0\}', args[0])
            require(len(streams) == 3 and [number for number, _ in streams] == ['0', '1', '2'] and
                    streams[0][1] == '/dev/null<char 1:3>', 'startup poll contains nonstandard/unowned descriptors')
            for _, path in streams[1:]:
                path_string(path)
                require(not (path == self.expected.root or path.startswith(self.expected.root + '/') or
                             path == self.expected.prefix or path.startswith(self.expected.prefix + '/')),
                        'inherited standard output aliases selected input/publication')
            require(self.stdout_path is None or self.stdout_path == streams[1][1], 'original stdout owner changed')
            self.stdout_path = streams[1][1]

    def finish(self):
        require(self.execs == self.exits == self.exit_groups == 1, 'complete trace lacks one executable and successful exit')
        self.complete_inputs()
        self.complete_publication()
        if self.expected.require_system_reads:
            require(self.system_closed == SYSTEM_LIBRARIES | {'/etc/ld.so.cache', '/proc/' + str(self.pid) + '/maps'},
                    'complete fixed GNU startup system read/close inventory differs')
        require(self.input_bytes == sum(item['size'] for item in self.expected.inputs.values()) and
                self.output_bytes == sum(item['size'] for item in self.expected.outputs.values()) and
                self.stdout_bytes == len(self.expected.report), 'final complete transfer totals differ')
        return {'schema_version': 0, 'program': self.expected.program, 'input_root': self.expected.root,
                'prefix': self.expected.prefix, 'input_layout': self.expected.layout,
                'execve_count': 1, 'successful_exit_count': 1, 'selected_input_files': self.selected_closed,
                'selected_input_bytes': self.input_bytes, 'published_files': len(self.finished_files),
                'published_directories': len(self.finished_dirs), 'published_bytes': self.output_bytes,
                'maximum_live_input_owners': self.max_input_owners, 'stdout_bytes': self.stdout_bytes,
                'initial_output_absence_probe_count': self.output_absence_probes,
                'child_creation_count': 0, 'network_count': 0, 'outside_prefix_mutation_count': 0,
                'unselected_input_read_count': 0, 'input_output_mapping_count': 0,
                'selected_regular_size_eof_restat_close_verified': True,
                'publication_after_complete_input_read_and_close': True,
                'publication_exclusive_modes_mtimes_closes_verified': True,
                'visible_input_output_prefixes_verified': True, 'trace_string_limit': TRACE_BYTES,
                'full_payload_identities_source': 'independent selected file audit; abbreviated trace is not a full byte hash'}


def audit_lines(lines, expected):
    audit = Audit(expected)
    for number, line in enumerate(lines, 1):
        try:
            audit.line(line)
        except ValueError as error:
            raise ValueError(f'line {number}: {error}') from error
    return audit.finish()


def audit_trace(trace, expected):
    opener = gzip.open if str(trace).endswith('.gz') else open
    with opener(trace, 'rt', encoding='utf-8') as stream:
        result = audit_lines(stream, expected)
    result['trace_identity'] = prepare.identity(Path(trace).read_bytes())
    result['report_identity'] = prepare.identity(expected.report)
    return result


def encode_bytes(payload):
    return '"' + ''.join(chr(byte) if 32 <= byte <= 126 and byte not in (34, 92)
                         else '\\%03o' % byte for byte in payload) + '"'


def hostile_controls(lines, expected):
    """Mutate the genuine complete trace, retaining reasons rather than copies."""
    audit_lines(lines, expected)
    selected = expected.root + '/'
    published = expected.prefix + '/'
    def first(predicate):
        return next(index for index, line in enumerate(lines) if predicate(line))
    input_open = first(lambda line: ' openat(' in line and 'O_NONBLOCK' in line)
    input_stat = first(lambda line: ' statx(' in line and selected in line and 'S_IFREG|' in line)
    input_read = first(lambda line: ' read(' in line and selected in line and not ', "", 1) = 0' in line)
    input_eof = first(lambda line: ' read(' in line and selected in line and ', "", 1) = 0' in line)
    input_restat = input_eof + 1
    require(' statx(' in lines[input_restat] and selected in lines[input_restat], 'genuine input EOF is not followed by its restat')
    input_close = input_restat + 1
    directory_open = first(lambda line: ' openat(' in line and 'O_DIRECTORY' in line)
    first_mkdir = first(lambda line: ' mkdirat(' in line)
    output_open = first(lambda line: ' openat(' in line and 'O_WRONLY' in line)
    output_write = first(lambda line: ' write(' in line and published in line)
    output_time = first(lambda line: ' utimensat(' in line and published in line)
    output_mode = first(lambda line: ' fchmod(' in line and '0444)' in line)
    output_close = output_mode + 1
    directory_freeze = first(lambda line: ' openat(' in line and published in line and ', O_RDONLY|O_CLOEXEC)' in line)
    directory_mode = first(lambda line: ' fchmod(' in line and '0555)' in line)
    stdout = first(lambda line: ' write(1<' in line)
    last_stdout = max(index for index, line in enumerate(lines) if ' write(1<' in line)
    last_dir_close = max(index for index, line in enumerate(lines[:stdout]) if ' close(' in line)
    input_root_close = max(index for index, line in enumerate(lines[:first_mkdir]) if ' close(' in line)
    pid = re.match(r'(\d+)', lines[0]).group(1)
    cases = {}
    def modified(label, index, old, new):
        require(old in lines[index], 'control needle not present: ' + label)
        changed = list(lines)
        changed[index] = changed[index].replace(old, new, 1)
        cases[label] = changed
    def removed(label, index):
        cases[label] = lines[:index] + lines[index + 1:]
    def inserted(label, body, index=1):
        cases[label] = lines[:index] + [pid + '  ' + body + '\n'] + lines[index:]
    def moved(label, index, destination):
        require(destination < index, 'control move must be earlier')
        cases[label] = lines[:destination] + [lines[index]] + lines[destination:index] + lines[index + 1:]
    def flip_buffer(label, index):
        match = QUOTED.search(lines[index])
        require(match is not None, 'control transfer lacks a buffer')
        payload = bytearray(decode_bytes(match.group(1)))
        require(payload, 'control transfer lacks visible bytes')
        payload[0] ^= 1
        changed = list(lines)
        changed[index] = lines[index][:match.start()] + encode_bytes(payload) + lines[index][match.end():]
        cases[label] = changed

    modified('another-pid', input_open, pid + ' ', str(int(pid) + 1) + ' ')
    removed('missing-success-exit', len(lines) - 1)
    cases['record-after-exit'] = lines + [lines[directory_open]]
    modified('wrong-provider', 0, '"host-install"', '"host-full"')
    modified('wrong-input-option', 0, '"--runtime-tree"', '"--pbs-install-only"')
    modified('leaf-follows-symlinks', input_open, '|O_NOFOLLOW', '')
    modified('leaf-can-block-fifo', input_open, '|O_NONBLOCK', '')
    modified('directory-follows-symlinks', directory_open, '|O_NOFOLLOW', '')
    modified('directory-not-required', directory_open, '|O_DIRECTORY', '')
    returned_leaf = lines[input_open].split(' = ')[-1].strip()
    leaf_number = returned_leaf.split('<')[0]
    leaf_path = returned_leaf[returned_leaf.index('<') + 1:-1]
    modified('leaf-result-alias', input_open, returned_leaf, leaf_number + '</foreign>')
    modified('leaf-live-fd-reassignment', input_open, ' = ' + returned_leaf, ' = 1<' + leaf_path + '>')
    match = QUOTED.search(lines[input_open])
    modified('unselected-leaf', input_open, match.group(0), '"unselected.dat"')
    cases['repeated-leaf-open'] = lines[:input_open] + [lines[input_open]] + lines[input_open:]
    removed('missing-first-stat', input_stat)
    removed('missing-restat', input_restat)
    removed('missing-payload-read', input_read)
    removed('missing-eof', input_eof)
    removed('missing-leaf-close', input_close)
    removed('missing-retained-directory-close', input_root_close)
    modified('nonregular-selected-leaf', input_stat, 'S_IFREG|', 'S_IFIFO|')
    match = re.search(r'stx_size=(\d+)', lines[input_stat])
    modified('wrong-selected-size', input_stat, match.group(0), 'stx_size=' + str(int(match.group(1)) + 1))
    modified('eof-not-single-byte', input_eof, ', 1) = 0', ', 2) = 0')
    modified('eof-contains-extra-byte', input_eof, '"", 1) = 0', '"x", 1) = 1')
    cases['read-after-eof'] = lines[:input_restat] + [lines[input_read]] + lines[input_restat:]
    flip_buffer('wrong-visible-input-prefix', input_read)
    modified('selected-input-write', input_read, ' read(', ' write(')
    modified('selected-read-fd-alias', input_read, '<' + leaf_path + '>', '</foreign>')
    inserted('selected-input-mapping', 'mmap(NULL, 4096, PROT_READ, MAP_PRIVATE, ' + returned_leaf + ', 0) = 0x123000', input_stat)
    moved('publication-before-admission', first_mkdir, input_open)
    modified('directory-mutation-outside-output', first_mkdir, expected.prefix, '/unrelated')
    cases['duplicate-created-directory'] = lines[:first_mkdir] + [lines[first_mkdir]] + lines[first_mkdir:]
    removed('missing-created-directory', first_mkdir + 1)
    modified('publication-overwrites-existing', output_open, '|O_EXCL', '|O_TRUNC')
    result = lines[output_open].split(' = ')[-1].strip()
    modified('publication-result-alias', output_open, result, result.split('<')[0] + '</unrelated>')
    modified('publication-unselected-file', output_open, QUOTED.search(lines[output_open]).group(0), '"' + expected.prefix + '/unselected.dat"')
    flip_buffer('wrong-visible-output-prefix', output_write)
    modified('publication-output-read', output_write, ' write(', ' read(')
    match = re.search(r', (\d+)\) = (\d+)\s*$', lines[output_write])
    modified('publication-transfer-overflow', output_write, match.group(0).strip(),
             ', ' + str(int(match.group(1)) + 1) + ') = ' + match.group(2))
    removed('publication-file-not-closed', output_close)
    modified('wrong-file-mode', output_mode, '0444', '0644')
    modified('wrong-directory-mode', directory_mode, '0555', '0755')
    modified('wrong-stock-mtime', output_time, 'tv_sec=1704067200', 'tv_sec=1704067201')
    modified('wrong-stock-nanoseconds', output_time, 'tv_nsec=0', 'tv_nsec=1')
    changed = list(lines)
    changed[output_time], changed[output_mode] = changed[output_mode], changed[output_time]
    cases['mode-before-stock-timestamp'] = changed
    moved('directory-freeze-before-files', directory_freeze, output_open)
    removed('published-root-not-closed', last_dir_close)
    moved('stdout-before-complete-publication', stdout, last_dir_close)
    flip_buffer('wrong-visible-json-report', stdout)
    modified('json-report-written-to-stderr', stdout, 'write(1<', 'write(2<')
    stdout_owner = re.search(r'write\(1<([^>]*)>', lines[stdout]).group(1)
    modified('stdout-owner-alias', stdout, '<' + stdout_owner + '>', '</unrelated>')
    removed('missing-final-json-fragment', last_stdout)
    inserted('network-socket', 'socket(AF_INET, SOCK_STREAM, IPPROTO_IP) = 9')
    inserted('child-clone', 'clone(NULL, 0, NULL, NULL, NULL) = ' + str(int(pid) + 1))
    inserted('descriptor-duplication', 'dup(0</dev/null>) = 9</dev/null>')
    inserted('another-executable', 'execve("/python", ["/python"], 0x123) = 0')
    inserted('unknown-kernel-operation', 'pidfd_open(1, 0) = 9')
    inserted('foreign-read-family', 'openat(AT_FDCWD</workspace>, "/tmp/foreign", O_RDONLY|O_CLOEXEC) = 9</tmp/foreign>')
    inserted('anonymous-executable-mapping', 'mmap(NULL, 4096, PROT_READ|PROT_EXEC, MAP_PRIVATE|MAP_ANONYMOUS, -1, 0) = 0x123000')
    inserted('executable-memory-protection', 'mprotect(0x123000, 4096, PROT_READ|PROT_EXEC) = 0')
    inserted('foreign-process-limit-mutation', 'prlimit64(1, RLIMIT_STACK, {rlim_cur=0, rlim_max=0}, NULL) = 0')
    maps = '/proc/' + pid + '/maps'
    cases['missing-system-maps-inventory'] = [line for line in lines if maps not in line and '"/proc/self/maps"' not in line]
    outcomes = {}
    for label, changed in cases.items():
        try:
            audit_lines(changed, expected)
        except ValueError as error:
            outcomes[label] = {'rejected': True, 'reason': str(error)}
        else:
            raise ValueError('hostile process control unexpectedly passed: ' + label)
    return {'schema_version': 0, 'source': 'mutations of the complete successful captured trace',
            'hostile_controls': len(outcomes), 'rejected_controls': len(outcomes), 'all_controls_rejected': True,
            'controls': outcomes}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ('trace', 'program', 'runtime-tree', 'prefix', 'report'):
        parser.add_argument('--' + name, required=True)
    parser.add_argument('--input-audit', type=Path,
                        help='standalone input audit or installation-provenance JSON; otherwise audit the live tree')
    parser.add_argument('--hostile-controls', action='store_true', help='reject mutations of the captured complete trace')
    args = parser.parse_args()
    try:
        input_audit = (prepare.strict_json(args.input_audit.read_bytes()) if args.input_audit is not None else
                       prepare.audit_input(Path(args.runtime_tree)))
        expected = contract(args.program, args.runtime_tree, args.prefix, Path(args.report).read_bytes(), input_audit)
        result = audit_trace(Path(args.trace), expected)
        if args.hostile_controls:
            opener = gzip.open if str(args.trace).endswith('.gz') else open
            with opener(args.trace, 'rt', encoding='utf-8') as stream:
                result = hostile_controls(stream.readlines(), expected) | {'trace_identity': result['trace_identity'],
                                                                          'report_identity': result['report_identity']}
        print(json.dumps(result, sort_keys=True))
        return 0
    except (OSError, ValueError, KeyError, TypeError) as error:
        print('runtime tree process audit: ' + str(error), file=sys.stderr)
        return 1


if __name__ == '__main__':
    raise SystemExit(main())
