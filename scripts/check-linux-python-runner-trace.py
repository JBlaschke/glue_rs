#!/usr/bin/env python3
"""Strict complete-trace replay for the optional pinned Python product route.

Only the exact product command, inherited evidence streams, diagnostic prefix,
and one product readiness query are translated. All acquisition, source import,
native mapping and finalization events use unchanged historical policies.
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


NATIVE = policy('check-linux-python-extension-trace.py', 'runner_native_policy')
BASE, PBS, TraceError = NATIVE.BASE, NATIVE.PBS, NATIVE.TraceError
DIRECTORY = '/build-target/relocated Python runner'
PROGRAM = DIRECTORY + '/glue'
IMPORTS = ('bundled-imports', 'host-imports')
MODES = IMPORTS + NATIVE.CELLS + NATIVE.NEGATIVE
MAX_TRACE_BYTES = NATIVE.MAX_TRACE_BYTES
MAX_LINE_CHARACTERS = NATIVE.MAX_LINE_CHARACTERS
MAX_RECORDS = NATIVE.MAX_RECORDS
OLD_PREFIX = b'glue-python-bootstrap-probe: '
PREFIX = b'glue: '


def archive_for(mode):
    if mode not in MODES:
        raise TraceError('unknown product Python fixture mode')
    return DIRECTORY + '/' + mode + '.glue'


def command_for(mode):
    return [PROGRAM, 'run', archive_for(mode)]


def expected_output(mode):
    archive_for(mode)
    if mode in IMPORTS:
        return NATIVE.BUNDLED.SUCCESS, b''
    stdout, stderr = NATIVE.expected_output(mode)
    if stderr:
        if not stderr.startswith(OLD_PREFIX):
            raise TraceError('parent diagnostic lacks the exact legacy prefix')
        stderr = PREFIX + stderr[len(OLD_PREFIX):]
    return stdout, stderr


def unify(module):
    module.TraceError = TraceError
    for name in ('COMMON', 'PBS', 'BASE'):
        child = getattr(module, name, None)
        if child is not None and child is not module:
            child.TraceError = TraceError


def merged_ranges(ranges):
    merged = []
    for start, end in sorted(ranges):
        if merged and start <= merged[-1][1]:
            merged[-1][1] = max(merged[-1][1], end)
        else:
            merged.append([start, end])
    return merged


def range_digest(ranges):
    return hashlib.sha256(json.dumps(merged_ranges(ranges), separators=(',', ':')).encode('ascii')).hexdigest()


def validate_readiness(record, size, admission):
    NATIVE.validate_admission(size, admission)
    if (not isinstance(record, dict) or set(record) != {'archive_read_bytes', 'archive_cursor', 'ranges_sha256'} or
            type(record.get('archive_read_bytes')) is not int or type(record.get('archive_cursor')) is not int or
            not 64 + admission[0] + size - admission[1] <= record['archive_read_bytes'] <= size + 20 or
            not 64 + admission[0] <= record['archive_cursor'] <= admission[1] or
            not isinstance(record.get('ranges_sha256'), str) or re.fullmatch(r'[0-9a-f]{64}', record['ranges_sha256']) is None):
        raise TraceError('retained product readiness lacks exact bounded metadata admission facts')


class Checker:
    def __init__(self, mode, archive_bytes, corrupt_offset=None, admission=None, readiness=None):
        self.mode = mode
        self.expected = expected_output(mode)
        self.output = [bytearray(), bytearray()]
        self.uname_queries = 0
        self.prefix_rewritten = False
        validate_readiness(readiness, archive_bytes, admission)
        self.readiness = readiness
        if mode in IMPORTS:
            self.parent_policy = policy(
                'check-linux-python-host-import-trace.py' if mode == 'host-imports' else 'check-linux-python-import-trace.py',
                'runner_import_policy')
            unify(self.parent_policy)
            self.parent = self.parent_policy.Checker('success', archive_bytes)
            self.runtime = self.parent
            self.old_program = self.parent_policy.PROGRAM
            self.old_command = ([self.old_program, 'run-host-imports', archive_for(mode)]
                                if mode == 'host-imports' else self.parent_policy.command_for('success'))
        else:
            # Each checker gets independent module globals: the native parent
            # adjusts its private import policy's expected publication line.
            self.parent_policy = policy('check-linux-python-extension-trace.py', 'runner_cell_policy')
            self.parent_policy.TraceError = TraceError
            for module in (self.parent_policy.HOST, self.parent_policy.BUNDLED,
                           self.parent_policy.HOST.COMMON, self.parent_policy.HOST.PBS,
                           self.parent_policy.HOST.BASE, self.parent_policy.PBS, self.parent_policy.BASE):
                unify(module)
            self.parent = self.parent_policy.Checker(mode, archive_bytes, corrupt_offset, admission)
            self.runtime = self.parent.runtime
            self.old_command = self.parent_policy.command_for(mode)
            self.old_program = self.parent_policy.PROGRAM
        self.runtime.archive = archive_for(mode)

    def inherited(self, token):
        number, path, deleted = NATIVE.descriptor(token)
        if number not in {1, 2} or deleted or path != f'/evidence/{self.mode}.{"stdout" if number == 1 else "stderr"}.txt':
            raise TraceError('product diagnostic uses another descriptor or evidence stream')
        return number - 1

    def normalize(self, args):
        if self.mode not in IMPORTS:
            return args
        normalized = []
        for argument in args:
            for found in re.findall(r'/evidence/[^<>\], }]+', argument):
                expected = {f'/evidence/{self.mode}.{stream}.txt' for stream in ('stdout', 'stderr')}
                if found not in expected:
                    raise TraceError('product operation uses another evidence stream')
            for stream in ('stdout', 'stderr'):
                argument = argument.replace(f'/evidence/{self.mode}.{stream}.txt', f'/evidence/success.{stream}.txt')
            normalized.append(argument)
        return normalized

    def call(self, name, args, result):
        runtime = self.runtime
        if runtime.exit_group:
            raise TraceError('product syscall follows exit_group')
        if name == 'execve':
            if len(args) != 3 or args[:2] != [json.dumps(PROGRAM), json.dumps(command_for(self.mode))]:
                raise TraceError('execve differs from the exact glue run command')
            return self.parent.call(name, [json.dumps(self.old_program), json.dumps(self.old_command), args[2]], result)
        if runtime.execs != 1:
            raise TraceError('product trace must begin with its sole execve')
        if name == 'uname':
            # Default strace abbreviates utsname after sysname and nodename.
            pattern = r'\{sysname="Linux", nodename="[A-Za-z0-9][A-Za-z0-9_.-]{0,63}", \.\.\.\}'
            if (len(args) != 1 or re.fullmatch(pattern, args[0]) is None or result != '0' or self.uname_queries or
                    runtime.archive_opened != 1 or not runtime.archive_sized or not runtime.locator_read or
                    runtime.archive_complete() or runtime.created or runtime.image_mappings or
                    runtime.virtual_queries or runtime.tid_queries or runtime.overcommit_reads or any(self.output) or
                    runtime.archive_read != self.readiness['archive_read_bytes'] or
                    runtime.archive_cursor != self.readiness['archive_cursor'] or
                    range_digest(runtime.archive_ranges) != self.readiness['ranges_sha256'] or
                    self.mode not in IMPORTS and (self.parent.native_fds or self.parent.directory_fds)):
                raise TraceError('uname differs from the sole bounded pre-payload product readiness query')
            self.uname_queries = 1
            return
        if name == 'write':
            if len(args) != 3:
                raise TraceError('unexpected product write arity')
            number = NATIVE.descriptor(args[0])[0]
            if number in {1, 2}:
                stream = self.inherited(args[0])
                match = re.fullmatch(r'"((?:[^"\\]|\\.)*)"', args[1])
                if match is None:
                    raise TraceError('product diagnostic does not retain complete bytes')
                payload = bytes(match[1], 'ascii').decode('unicode_escape').encode('latin1')
                if not payload or NATIVE.unsigned(args[2]) != len(payload) or NATIVE.result_number(result) != len(payload):
                    raise TraceError('product diagnostic requires an exact positive complete count')
                self.output[stream].extend(payload)
                if not self.expected[stream].startswith(self.output[stream]):
                    raise TraceError('product diagnostic bytes differ from this exact fixture')
                if stream == 1 and not self.prefix_rewritten:
                    if not payload.startswith(PREFIX):
                        raise TraceError('first product stderr write must contain the complete glue prefix')
                    translated = OLD_PREFIX + payload[len(PREFIX):]
                    args = [args[0], json.dumps(translated.decode('ascii')), str(len(translated))]
                    result = str(len(translated))
                    self.prefix_rewritten = True
        return self.parent.call(name, self.normalize(args), result)

    def line(self, line):
        if self.runtime.completed:
            raise TraceError('product record follows process completion')
        completed = re.fullmatch(r'([1-9][0-9]{0,9})\s+\+\+\+ exited with ([01]) \+\+\+', line)
        if completed:
            return self.parent.line(line)
        match = BASE.LINE.fullmatch(line)
        if match is None:
            raise TraceError('unparsed, abbreviated or incomplete product trace record')
        self.runtime.process(match[1])
        self.call(match[2], BASE.split_arguments(match[3]), match[4])

    def finish(self):
        if self.uname_queries != 1:
            raise TraceError('product target readiness query is missing')
        self.parent.finish()
        if tuple(bytes(stream) for stream in self.output) != self.expected:
            raise TraceError('product stdout/stderr differs from exact retained diagnostics')


def check_lines(lines, mode, archive_bytes, corrupt_offset=None, admission=None, readiness=None):
    checker = Checker(mode, archive_bytes, corrupt_offset, admission, readiness)
    total = 0
    for number, line in enumerate(lines, 1):
        total += len(line.encode('utf-8'))
        if number > MAX_RECORDS or total > MAX_TRACE_BYTES or len(line) > MAX_LINE_CHARACTERS + 1 or not line.endswith('\n') or '\r' in line:
            raise TraceError('product trace is oversized, noncanonical or incomplete')
        try:
            checker.line(line[:-1])
        except TraceError as error:
            raise TraceError(f'line {number}: {error}') from error
    checker.finish()


def check_file(path, mode, archive_bytes, corrupt_offset=None, admission=None, readiness=None):
    if path.stat().st_size > MAX_TRACE_BYTES:
        raise TraceError('product trace input exceeds bounded raw/compressed size')
    with (gzip.open if path.suffix == '.gz' else open)(path, 'rb') as stream:
        def lines():
            while raw := stream.readline(MAX_LINE_CHARACTERS + 2):
                yield raw.decode('utf-8', errors='strict')
        check_lines(lines(), mode, archive_bytes, corrupt_offset, admission, readiness)


def import_record(path):
    size = path.stat().st_size
    if not 0 < size <= 128 * 1024 * 1024:
        raise TraceError('import archive is outside bounded product profile')
    digest = hashlib.sha256()
    with path.open('rb') as stream:
        header = stream.read(64)
        if len(header) != 64 or header[:8] != b'GLUERS00':
            raise TraceError('product archive lacks complete locator')
        length = struct.unpack_from('<Q', header, 16)[0]
        if not 0 < length <= 1024 * 1024 or 64 + length > size:
            raise TraceError('product manifest exceeds locator bounds')
        manifest_bytes = stream.read(length)
        manifest = json.loads(manifest_bytes)
        stream.seek(0)
        while block := stream.read(1024 * 1024):
            digest.update(block)
    with zipfile.ZipFile(path) as archive:
        directory = archive.start_dir
    NATIVE.validate_admission(size, (length, directory))
    provider = manifest['runtimes']['python']['provisioning']['mode']
    if provider != ('host' if path.stem == 'host-imports' else 'bundled') or manifest['native_modules'] or manifest['host_imports']:
        raise TraceError('product import metadata uses another provider/native inventory')
    return {'bytes': size, 'sha256': digest.hexdigest(), 'manifest_sha256': hashlib.sha256(manifest_bytes).hexdigest(),
            'manifest_bytes': length, 'zip_directory_offset': directory, 'runtime': provider}


def emit_metadata(directory, archives, output):
    metadata = {'schema_version': 0, 'files': NATIVE.native_facts(directory),
                'archives': {mode: NATIVE.archive_record(archives / (mode + '.glue')) for mode in NATIVE.CELLS + NATIVE.NEGATIVE},
                'imports': {mode: import_record(archives / (mode + '.glue')) for mode in IMPORTS},
                'readiness': {mode: readiness_record(archives / (mode + '.glue')) for mode in MODES}}
    output.write_text(json.dumps(metadata, indent=2, sort_keys=True) + '\n')


def retained_metadata(path, mode, size, offset):
    if mode not in IMPORTS:
        return NATIVE.retained_metadata(path, mode, size, offset)
    if path.stat().st_size > 64 * 1024:
        raise TraceError('product metadata exceeds bounded profile')
    metadata = json.loads(path.read_text())
    if not isinstance(metadata, dict) or type(metadata.get('schema_version')) is not int or metadata['schema_version'] != 0 or not isinstance(metadata.get('imports'), dict) or set(metadata['imports']) != set(IMPORTS):
        raise TraceError('retained product import metadata inventory differs')
    record = metadata['imports'][mode]
    if not isinstance(record, dict) or type(record.get('bytes')) is not int or record['bytes'] != size or record.get('runtime') != ('host' if mode == 'host-imports' else 'bundled'):
        raise TraceError('retained product import size/provider differs')
    if any(not isinstance(record.get(key), str) or re.fullmatch(r'[0-9a-f]{64}', record[key]) is None for key in ('sha256', 'manifest_sha256')):
        raise TraceError('retained product archive/manifest hash is not canonical')
    NATIVE.validate_admission(size, (record.get('manifest_bytes'), record.get('zip_directory_offset')))
    return record


def readiness_record(path):
    size = path.stat().st_size
    with path.open('rb') as stream:
        header = stream.read(64)
        if len(header) != 64 or header[:8] != b'GLUERS00':
            raise TraceError('product readiness metadata lacks exact locator')
        length = struct.unpack_from('<Q', header, 16)[0]
        with zipfile.ZipFile(path) as archive:
            directory = archive.start_dir
            NATIVE.validate_admission(size, (length, directory))
            ranges = [(0, 64 + length), (directory, size)]
            # Archive::open reads the complete central/footer region, probes
            # twenty bytes before the EOCD, and reads each local header/name/
            # extra. The non-ZIP64 probe overlaps already-read directory bytes.
            stream.seek(size - 42)
            zip64 = stream.read(4) == b'PK\x06\x07'
            count = 64 + length + size - directory + (0 if zip64 else 20)
            cursor = None
            for info in archive.infolist():
                stream.seek(info.header_offset)
                local = stream.read(30)
                if len(local) != 30 or local[:4] != b'PK\x03\x04':
                    raise TraceError('product metadata lacks complete local header')
                names, extra = struct.unpack_from('<HH', local, 26)
                cursor = info.header_offset + 30 + names + extra
                if names != len(info.filename.encode('utf-8')) or extra > 32 or cursor > directory:
                    raise TraceError('product local metadata exceeds canonical ZIP bounds')
                count += 30 + names + extra
                ranges.append((info.header_offset, cursor))
    record = {'archive_read_bytes': count, 'archive_cursor': cursor, 'ranges_sha256': range_digest(ranges)}
    validate_readiness(record, size, (length, directory))
    return record


def retained_readiness(path, mode, size, admission):
    if path.stat().st_size > 64 * 1024:
        raise TraceError('product readiness metadata exceeds bounded profile')
    metadata = json.loads(path.read_text())
    if not isinstance(metadata, dict) or not isinstance(metadata.get('readiness'), dict) or set(metadata['readiness']) != set(MODES):
        raise TraceError('product readiness inventory differs from the nine cells')
    record = metadata['readiness'][mode]
    validate_readiness(record, size, admission)
    return record


def main():
    if len(sys.argv) == 5 and sys.argv[1] == '--emit-runner-metadata':
        try:
            emit_metadata(Path(sys.argv[2]), Path(sys.argv[3]), Path(sys.argv[4]))
        except (OSError, UnicodeError, ValueError, KeyError, struct.error, zipfile.BadZipFile, TraceError) as error:
            print(f'product Python metadata rejected: {error}', file=sys.stderr)
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
                    raise TraceError('retained product stdout/stderr differs from exact fixture output')
        size = args.archive_file.stat().st_size if args.archive_file else args.archive_bytes
        offset = NATIVE.corrupt_offset(args.archive_file) if args.mode == 'corrupt-native' and args.archive_file else args.corrupt_native_offset
        record = retained_metadata(args.native_metadata_file, args.mode, size, offset)
        admission = (record['manifest_bytes'], record['zip_directory_offset'])
        readiness = retained_readiness(args.native_metadata_file, args.mode, size, admission)
        if args.archive_file and (import_record(args.archive_file) if args.mode in IMPORTS else NATIVE.archive_record(args.archive_file)) != record:
            raise TraceError('retained product archive identity differs from actual input')
        if args.archive_file and readiness_record(args.archive_file) != readiness:
            raise TraceError('retained product readiness metadata differs from actual ZIP layout')
        check_file(args.trace, args.mode, size, offset, admission, readiness)
    except (OSError, UnicodeError, EOFError, ValueError, KeyError, struct.error, zipfile.BadZipFile, TraceError) as error:
        print(f'product Python runner trace rejected: {error}', file=sys.stderr)
        return 1
    print('Trace checks passed: exact glue run route and target readiness, one admitted archive, unchanged immutable runtime/source/native provider policy, exact diagnostics/finalization/exit, no fallback, mutation or extra process')
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
