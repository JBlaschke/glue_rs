#!/usr/bin/env python3
"""Closed native traces for the exact pinned real pure-Python package corpus.

Historical policies are imported in a fresh private graph. Archive admission
pins this corpus's independent inventory, application and output; CRC controls
pin the first entry read before any provider acquisition. Loader, host snapshot,
cache, descriptor, syscall and selected-image lifetime checks remain inherited.
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
import zlib


spec = importlib.util.spec_from_file_location(
    'real_packages_private_prerequisite_policy',
    Path(__file__).with_name('check-linux-python-host-prerequisites-trace.py'))
PREREQUISITES = importlib.util.module_from_spec(spec)
spec.loader.exec_module(PREREQUISITES)
METADATA = PREREQUISITES.METADATA
SOURCE, PRODUCT, BASE, PBS, TraceError = (
    METADATA.SOURCE, METADATA.PRODUCT, METADATA.BASE, METADATA.PBS, METADATA.TraceError)
ROOT = Path(__file__).resolve().parents[1]
FIXTURE = ROOT / 'fixtures/python-real-packages'
DIRECTORY, PROGRAM, CWD, TARGET = METADATA.DIRECTORY, METADATA.PROGRAM, METADATA.CWD, METADATA.TARGET
PROFILES = ('bundled', 'host', 'install-host')
MODES = PROFILES + tuple(profile + '-corrupt-entry' for profile in PROFILES)
IDENTITY = ('python.real-packages', 'app/main.py', 'launch')
CORRUPT_KEY = 'app/main.py'
MAX_TRACE_BYTES, MAX_LINE_CHARACTERS, MAX_RECORDS = (
    METADATA.MAX_TRACE_BYTES, METADATA.MAX_LINE_CHARACTERS, METADATA.MAX_RECORDS)
# Independent normalized wheel projection, exact entry and baseline output.
# No trace or archive can supply another identity.
INVENTORY_SHA256 = '4f2f7005f070adddc2ce27b682510507a8e41dc6fb004fd9c8e076aadbeb7a71'
APP_SHA256 = '2b7f709ce325f060a28c472618a7aee0338d7c2bb7fd1a99ae907c1f0920ee11'
OUTPUT_SHA256 = 'cdfaac81082bf8d22ff51cb69841a539de866f9f53e2b60b6caa7539b0f560a7'
INVENTORY_FILES, INVENTORY_BYTES = 152, 451195


def profile_for(mode):
    if mode not in MODES:
        raise TraceError('unknown real-package workload')
    return next(profile for profile in reversed(PROFILES) if mode == profile or mode.startswith(profile + '-'))


def rejected(mode):
    profile_for(mode)
    return mode.endswith('-corrupt-entry')


def archive_for(mode):
    profile_for(mode)
    return DIRECTORY + '/' + mode + '.glue'


def read_pinned(path, maximum, sha256):
    with path.open('rb') as stream:
        data = stream.read(maximum + 1)
    if len(data) > maximum or hashlib.sha256(data).hexdigest() != sha256:
        raise TraceError('real-package fixture bytes differ from fixed identity: ' + path.name)
    return data


def application_bytes(mode):
    """Exact entry bytes for the closed first-read control; specs are separate."""
    profile_for(mode)
    return {CORRUPT_KEY: read_pinned(FIXTURE / 'application/app/main.py', 65536, APP_SHA256)}


def expected_application(mode):
    profile_for(mode)
    raw = read_pinned(FIXTURE / 'expected-inventory.json', 256 * 1024, INVENTORY_SHA256)
    inventory = json.loads(raw)
    if (not isinstance(inventory, dict) or set(inventory) != {'schema_version', 'files'} or
            type(inventory['schema_version']) is not int or inventory['schema_version'] != 0 or
            not isinstance(inventory['files'], dict) or len(inventory['files']) != INVENTORY_FILES or
            not 1 <= INVENTORY_FILES <= 1024):
        raise TraceError('real-package normalized inventory schema/count differs')
    total = 0
    specs = {}
    for key, value in inventory['files'].items():
        if (not isinstance(key, str) or not key.startswith('app/') or not key.isascii() or
                any(part in ('', '.', '..') for part in key.split('/')) or '\\' in key or
                any(ord(char) < 32 or ord(char) == 127 for char in key) or
                not isinstance(value, dict) or set(value) != {'size', 'sha256'} or
                type(value['size']) is not int or not 0 <= value['size'] <= 4 * 1024 * 1024 or
                not isinstance(value['sha256'], str) or re.fullmatch('[0-9a-f]{64}', value['sha256']) is None):
            raise TraceError('real-package normalized resource identity/path differs')
        total += value['size']
        specs[key] = value | {'compression': 'stored'}
    entry = application_bytes(mode)[CORRUPT_KEY]
    if (total != INVENTORY_BYTES or total > 8 * 1024 * 1024 or min(specs) != CORRUPT_KEY or specs.get(CORRUPT_KEY) != {
            'size': len(entry), 'sha256': APP_SHA256, 'compression': 'stored'}):
        raise TraceError('real-package entry identity or aggregate budget differs')
    return specs


def corrupt_bytes():
    raw = application_bytes('host')[CORRUPT_KEY]
    return bytes([raw[0] ^ 1]) + raw[1:]


def fixed_visible_payload(token, data):
    visible = re.fullmatch(r'"((?:[^"\\]|\\.)*)"(\.\.\.)?', token)
    if visible is None:
        raise TraceError('real-package CRC bytes lack their exact visible grammar')
    try:
        prefix = bytes(visible[1], 'ascii').decode('unicode_escape').encode('latin1')
    except (ValueError, UnicodeError) as error:
        raise TraceError('real-package CRC bytes are not a complete encoding') from error
    if prefix != data[:256] or bool(visible[2]) != (len(data) > 256):
        raise TraceError('real-package CRC visible bytes or truncation differ')


def expected_output(mode):
    if rejected(mode):
        return b'', b'glue: resource "app/main.py" failed CRC32 verification\n'
    return read_pinned(FIXTURE / 'expected.stdout.txt', 4096, OUTPUT_SHA256), b''


def internal_mode(mode):
    profile_for(mode)
    return mode.removesuffix('-corrupt-entry') + '-corrupt-metadata' if rejected(mode) else mode


def external_mode(mode):
    value = mode.removesuffix('-corrupt-metadata') + '-corrupt-entry' if mode.endswith('-corrupt-metadata') else mode
    profile_for(value)
    return value


# Change only this fresh graph. Internal factory labels preserve its closed
# provider-free rejection predicates, while all actual paths and observations
# remain those of the externally declared real-package workload.
_archive_record = PREREQUISITES.VENV._archive_record
METADATA.IDENTITY = IDENTITY
METADATA.MODES = MODES
METADATA.CORRUPT_KEY = CORRUPT_KEY
METADATA.profile_for = lambda mode: profile_for(external_mode(mode))
METADATA.archive_for = lambda mode: archive_for(external_mode(mode))
METADATA.expected_application = lambda mode: expected_application(external_mode(mode))
METADATA.expected_output = lambda mode: expected_output(external_mode(mode))
METADATA.corrupt_bytes = corrupt_bytes
_provider_contract = METADATA.provider_contract


def provider_contract(mode):
    profile_for(mode)
    return _provider_contract(internal_mode(mode))


def fixed_specs(mode):
    profile_for(mode)
    return METADATA.fixed_specs(internal_mode(mode))


def archive_record(path, mode):
    return _archive_record(path, internal_mode(mode))


def retained_metadata(path, mode, size):
    profile = profile_for(mode)
    with path.open('rb') as stream:
        raw = stream.read(256 * 1024 + 1)
    if len(raw) > 256 * 1024:
        raise TraceError('retained real-package metadata exceeds fixed bound')
    data = json.loads(raw)
    if (not isinstance(data, dict) or set(data) != {'schema_version', 'archives'} or
            type(data.get('schema_version')) is not int or data['schema_version'] != 0 or
            not isinstance(data.get('archives'), dict) or set(data['archives']) != set(MODES)):
        raise TraceError('retained real-package metadata schema/workloads differ')
    record = data['archives'][mode]
    keys = {'bytes', 'sha256', 'manifest_sha256', 'manifest_bytes', 'zip_directory_offset',
            'app_id', 'entry', 'component', 'application', 'provider', 'target', 'readiness'}
    if rejected(mode):
        keys.add('corrupt_offset')
    lower, upper = (73563968, 128 * 1024 * 1024) if profile == 'bundled' else (64, 16 * 1024 * 1024)
    if (not isinstance(record, dict) or set(record) != keys or
            type(record.get('bytes')) is not int or record['bytes'] != size or not lower < size <= upper or
            (record.get('app_id'), record.get('entry'), record.get('component')) != IDENTITY):
        raise TraceError('retained real-package archive identity differs')
    if (not SOURCE.typed_equal(record['application'], expected_application(mode)) or
            not SOURCE.typed_equal(record['provider'], provider_contract(mode)) or
            not SOURCE.typed_equal(record['target'], TARGET)):
        raise TraceError('retained real-package application/provider/target differs')
    if any(not isinstance(record.get(key), str) or re.fullmatch('[0-9a-f]{64}', record[key]) is None
           for key in ('sha256', 'manifest_sha256')):
        raise TraceError('retained real-package digest is noncanonical')
    PRODUCT.validate_readiness(record['readiness'], size,
                               (record['manifest_bytes'], record['zip_directory_offset']))
    manifest_bound = (2 if profile == 'bundled' else 1) * 1024 * 1024
    directory_bound = 2 * 1024 * 1024 if profile == 'bundled' else 256 * 1024
    if record['manifest_bytes'] > manifest_bound or size - record['zip_directory_offset'] > directory_bound:
        raise TraceError('retained real-package manifest/directory exceeds profile bounds')
    if rejected(mode) and (type(record['corrupt_offset']) is not int or
                          not 64 + record['manifest_bytes'] <= record['corrupt_offset'] <=
                          record['zip_directory_offset'] - len(corrupt_bytes())):
        raise TraceError('retained real-package entry CRC offset differs')
    return record


class Checker:
    def __init__(self, mode, size, record):
        self.mode, self.record, self.crc_payload_reads = mode, record, 0
        PRODUCT.validate_readiness(record['readiness'], size,
                                   (record['manifest_bytes'], record['zip_directory_offset']))
        internal = internal_mode(mode)
        self.checker = (METADATA.bundled_checker(internal, size, record)
                        if profile_for(mode) == 'bundled' else PREREQUISITES.host_checker(internal, size, record))
        runtime = getattr(self.checker, 'runtime', self.checker)
        parent = runtime.__class__
        profile = profile_for(mode)
        runtime.terminal_queries = runtime.corpus_remaps = 0
        runtime.corpus_owner = runtime.corpus_result = None
        runtime.corpus_released = False

        class RealPackageRuntime(parent):
            def inherited(self, token):
                number, path, deleted = PBS.descriptor(token) if token != '0</dev/null<char 1:3>>' else (0, '/dev/null', False)
                if deleted or path != {0: '/dev/null', 1: f'/evidence/{mode}.stdout.txt',
                                       2: f'/evidence/{mode}.stderr.txt'}.get(number):
                    raise TraceError('real-package inherited descriptor identity differs')
                return number

            def call(self, name, args, result):
                if self.exit_group or self.completed:
                    raise TraceError('real-package operation follows process exit')
                if name == 'ppoll':
                    expected = '[{fd=0</dev/null<char 1:3>>, events=0}, ' + f'{{fd=1</evidence/{mode}.stdout.txt>, events=0}}, {{fd=2</evidence/{mode}.stderr.txt>, events=0}}]'
                    if args != [expected, '3', '{tv_sec=0, tv_nsec=0}', 'NULL', '0'] or result != '0 (Timeout)':
                        raise TraceError('real-package inherited stream poll differs')
                    return
                if (profile == 'bundled' and rejected(mode) and name == 'read' and len(args) == 3 and
                        self.reader(args[0])[1] == self.archive and self.archive_cursor == record['corrupt_offset']):
                    # The historical small corrupt fixture was printed in full.
                    # Bind this larger entry's observed 256-byte prefix and
                    # ellipsis before reusing every original read/owner/count
                    # predicate and its cursor/range/CRC bookkeeping.
                    fixed_visible_payload(args[1], corrupt_bytes())
                    args = [args[0], json.dumps(corrupt_bytes().decode('ascii')), args[2]]
                if name == 'ioctl' and len(args) == 3 and args[1] == 'TIOCGWINSZ':
                    PBS.pointer(args[2])
                    if (rejected(mode) or self.inherited(args[0]) != 1 or
                            result != '-1 ENOTTY (Inappropriate ioctl for device)' or
                            not self.runtime_ready() or any(self.output) or
                            getattr(self, 'finalized_boundary', False) or self.terminal_queries >= 5 or
                            self.corpus_remaps != (1 if profile == 'install-host' else 0) or
                            profile == 'install-host' and not self.corpus_released):
                        raise TraceError('real-package terminal query differs from the closed argparse phase')
                    self.terminal_queries += 1
                    return
                if (name == 'write' and len(args) == 3 and PBS.descriptor(args[0])[0] < 3 and
                        not rejected(mode) and (
                        self.terminal_queries != 5 or self.corpus_remaps != (1 if profile == 'install-host' else 0))):
                    raise TraceError('real-package publication lacks complete argparse observations')
                return super().call(name, args, result)

            def memory(self, name, args, result):
                # Preserve the original four startup remaps and their counter.
                # The install-only corpus has one subsequent parser allocation;
                # it still needs a live, private RW anonymous owner and may not
                # replace, protect or release any selected image span.
                if name != 'mremap' or profile != 'install-host' or self.remaps != 4:
                    outcome = super().memory(name, args, result)
                    if profile == 'install-host' and name in {'mmap', 'munmap', 'mprotect'}:
                        start = PBS.result_number(result) if name == 'mmap' else 0 if args[0] == 'NULL' else int(args[0], 16)
                        length = PBS.unsigned(args[1])
                        if self.corpus_owner is not None and start < self.corpus_owner + 282624 and self.corpus_owner < start + length:
                            self.corpus_owner = None
                        if (name == 'mmap' and args == ['NULL', '282624', 'PROT_READ|PROT_WRITE', 'MAP_PRIVATE|MAP_ANONYMOUS', '-1', '0'] and
                                self.runtime_ready() and not any(self.output) and not self.terminal_queries and not self.corpus_remaps):
                            self.corpus_owner = start
                        if name == 'munmap' and (start, length) == (self.corpus_result, 565248) and self.corpus_released:
                            raise TraceError('real-package parser backing release repeats')
                        if self.corpus_result is not None and not self.corpus_released and start < self.corpus_result + 565248 and self.corpus_result < start + length:
                            if name != 'munmap' or (start, length) != (self.corpus_result, 565248) or self.corpus_released:
                                raise TraceError('real-package parser backing requires its one complete release')
                            self.corpus_released = True
                    return outcome
                self.arity(name, args, (4,))
                PBS.pointer(args[0])
                start = 0 if args[0] == 'NULL' else int(args[0], 16)
                length, moved = PBS.unsigned(args[1]), PBS.unsigned(args[2])
                value = PBS.result_number(result)
                if (self.corpus_remaps or not self.runtime_ready() or any(self.output) or
                        self.terminal_queries or getattr(self, 'finalized_boundary', False) or
                        (length, moved) != (282624, 565248) or self.anonymous.get(start) != length or self.corpus_owner != start or
                        args[3] != 'MREMAP_MAYMOVE' or start <= 0 or start % 4096 or
                        start + length > 1 << 64 or value is None or value <= 0 or value % 4096 or
                        value + moved > 1 << 64):
                    raise TraceError('real-package parser remap lacks its exact initialized live anonymous owner')
                lower, upper = self.image_base, self.image_base + 20426752
                if lower < start + length and start < upper or lower < value + moved and value < upper:
                    raise TraceError('real-package parser remap overlaps the live selected image')
                if any(address != start and value < address + span and address < value + moved
                       for address, span in self.anonymous.items()):
                    raise TraceError('real-package parser remap replaces another live anonymous owner')
                del self.anonymous[start]
                self.anonymous[value] = moved
                self.corpus_remaps = 1
                self.corpus_owner, self.corpus_result = None, value

            def finish(self):
                super().finish()
                if (self.terminal_queries != (0 if rejected(mode) else 5) or
                        self.corpus_remaps != (1 if mode == 'install-host' else 0) or
                        self.corpus_released != (mode == 'install-host')):
                    raise TraceError('real-package corpus terminal/allocation observations are incomplete')

        runtime.__class__ = RealPackageRuntime

    def line(self, line):
        if rejected(self.mode):
            match = BASE.LINE.fullmatch(line)
            if match is not None and match[2] == 'read':
                args = BASE.split_arguments(match[3])
                runtime = getattr(self.checker, 'runtime', self.checker)
                if len(args) == 3 and PBS.descriptor(args[0])[1] == archive_for(self.mode) and self.checker.uname_queries:
                    data = corrupt_bytes()
                    if self.crc_payload_reads or args[2] != str(len(data)) or match[4] != str(len(data)):
                        raise TraceError('real-package CRC phase requires exactly one complete entry read')
                    fixed_visible_payload(args[1], data)
                    if runtime.archive_cursor != self.record['corrupt_offset']:
                        raise TraceError('real-package CRC exact first-entry offset differs')
                    self.crc_payload_reads += 1
        self.checker.line(line)

    def finish(self):
        self.checker.finish()
        if rejected(self.mode):
            runtime = getattr(self.checker, 'runtime', self.checker)
            if (self.crc_payload_reads != 1 or
                    runtime.archive_read != self.record['readiness']['archive_read_bytes'] + len(corrupt_bytes()) or
                    runtime.archive_cursor != self.record['corrupt_offset'] + len(corrupt_bytes())):
                raise TraceError('real-package CRC rejection lacks the exact first-entry-only phase')
            for lower, upper in ((0, 64 + self.record['manifest_bytes']),
                                 (self.record['zip_directory_offset'], runtime.archive_bytes)):
                if not any(start <= lower and end >= upper for start, end in PRODUCT.merged_ranges(runtime.archive_ranges)):
                    raise TraceError('real-package CRC rejection lacks complete manifest/ZIP admission')


def check_lines(lines, mode, size, record):
    checker, total = Checker(mode, size, record), 0
    for number, line in enumerate(lines, 1):
        total += len(line.encode('utf-8'))
        if number > MAX_RECORDS or total > MAX_TRACE_BYTES or len(line) > MAX_LINE_CHARACTERS + 1 or not line.endswith('\n') or '\r' in line:
            raise TraceError('real-package trace is oversized, noncanonical or incomplete')
        try:
            checker.line(line[:-1])
        except TraceError as error:
            raise TraceError(f'line {number}: {error}') from error
    checker.finish()


def main():
    if len(sys.argv) == 4 and sys.argv[1] == '--emit-metadata':
        directory, output = Path(sys.argv[2]), Path(sys.argv[3])
        output.write_text(json.dumps({'schema_version': 0, 'archives': {
            mode: archive_record(directory / (mode + '.glue'), mode) for mode in MODES}}, indent=2, sort_keys=True) + '\n')
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
        raise TraceError('retained real-package metadata differs from actual archive')
    for path, expected in zip((args.stdout_file, args.stderr_file), expected_output(args.mode)):
        with path.open('rb') as stream:
            if stream.read(len(expected) + 1) != expected:
                raise TraceError('retained real-package output differs')
    if args.trace.stat().st_size > MAX_TRACE_BYTES:
        raise TraceError('raw/compressed real-package trace exceeds bound')
    with (gzip.open if args.trace.suffix == '.gz' else open)(args.trace, 'rb') as stream:
        def lines():
            while line := stream.readline(MAX_LINE_CHARACTERS + 2):
                yield line.decode('utf-8', 'strict')
        check_lines(lines(), args.mode, size, record)
    print('Trace checks passed: exact real-package inventory, provider and entry outcomes; virtual source/metadata/resources; closed loader and host snapshots; no extraction, fallback or extra process')
    return 0


if __name__ == '__main__':
    try:
        raise SystemExit(main())
    except (OSError, EOFError, ValueError, KeyError, TypeError, UnicodeError,
            struct.error, zipfile.BadZipFile, zlib.error, TraceError) as error:
        print('Python real-package trace rejected: ' + str(error), file=sys.stderr)
        raise SystemExit(1)
