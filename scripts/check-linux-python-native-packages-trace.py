#!/usr/bin/env python3
"""Closed traces for descriptor-backed native members of one archive package.

The independently pinned lifecycle images and a fresh lifecycle checker graph
retain all native/runtime predicates. This adapter binds the separate source
package, public loader bootstrap and exact commands without editing historical
policy bodies. Native ownership/callback semantics are established by reviewed
source and the ordinary stock driver, rather than syscall instruction tracing.
"""
from __future__ import annotations

import argparse
import importlib.util
from pathlib import Path
import sys
import struct
import zipfile
import zlib


def load(filename, name):
    spec = importlib.util.spec_from_file_location(name, Path(__file__).with_name(filename))
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


REFERENCE = load('check-linux-python-native-lifecycle-trace.py', 'native_packages_reference')
ROOT = REFERENCE.ROOT
FIXTURE = ROOT / 'fixtures/python-native-packages'
DIRECTORY = '/build-target/relocated Python native packages'
PROGRAM = DIRECTORY + '/glue-python-bootstrap-probe'
NATIVE_PREFIX = REFERENCE.NATIVE_PREFIX
APP_ID = 'stock-pbs-native-packages'
PACKAGE = 'glue_native_pkg'
NAMES = REFERENCE.NAMES
FULLNAMES = tuple(PACKAGE + '.' + name.removesuffix('.so') for name in NAMES[1:])
NATIVE_PINS = REFERENCE.NATIVE_PINS
CELLS, NEGATIVE, MODES = REFERENCE.CELLS, REFERENCE.NEGATIVE, REFERENCE.MODES
TraceError = REFERENCE.TraceError
require, identity, typed_equal, strict_json = (
    REFERENCE.require, REFERENCE.identity, REFERENCE.typed_equal, REFERENCE.strict_json)
MAX_TRACE_BYTES, MAX_RECORDS, MAX_LINE_CHARACTERS = (
    REFERENCE.MAX_TRACE_BYTES, REFERENCE.MAX_RECORDS, REFERENCE.MAX_LINE_CHARACTERS)
# Only independently inspected stock fixture bytes may finalize these pins.
APP_TAIL_PIN = {'size': 9631, 'sha256': '7f5783c667d79d03ba85d2d9f59040b3e82bb76a2aa6ae67de964c2f7c35e5a5'}
BOOTSTRAP_TAIL_PIN = {'size': 4381, 'sha256': 'af9128cbf72070e6695e1f4e673ca12d9c3359984814d7a6629a994ec6a24cb9'}
PACKAGE_PINS = {
    'app/python/glue_native_pkg/__init__.py': {
        'size': 112, 'sha256': '48085a64e42fb57b7a2ce484eb389cfe1c61b7ca4bafce261aa2e70f187c9c67'},
    'app/python/glue_native_pkg/relative.py': {
        'size': 107, 'sha256': '878998dd35dd34a3e24bd483925f522e2fc7b42a9e3fb65ac5b9afda9ec9ad0c'},
    'app/python/glue_native_pkg/data/text.txt': {
        'size': 16, 'sha256': '581cdf67739405f5bd9eb1b47bf87097686b138d61455fc8b436d457944ff83e'},
    'app/python/glue_native_pkg/data/binary.bin': {
        'size': 10, 'sha256': 'a36788d73d3a369c8d4134645a343362a667de2c5d7bf002760cf7f1e63f2323'},
}
NATIVE_PASS = b'GLUE_PYTHON_NATIVE_PACKAGES_PASS instances=5 collected=2 retained=3 create_retry=2 exec_retry=2\n'
ATEXIT_PASS = b'GLUE_PYTHON_NATIVE_PACKAGES_ATEXIT_PASS retained=3\n'
FINALIZE_PASS = REFERENCE.FINALIZE_PASS


def cell_for(mode):
    return REFERENCE.cell_for(mode)


def prefix_for(mode):
    return REFERENCE.prefix_for(mode)


def archive_for(mode):
    return DIRECTORY + '/' + (mode if mode in NEGATIVE else cell_for(mode)) + '.glue'


def command_for(mode):
    return ([PROGRAM, 'run-native-packages-negative', archive_for(mode), 'app-error']
            if mode.endswith('-app-error') else [PROGRAM, 'run-native-packages', archive_for(mode)])


def finalized():
    require(APP_TAIL_PIN is not None and BOOTSTRAP_TAIL_PIN is not None and PACKAGE_PINS and
            type(NATIVE_PASS) is bytes and type(ATEXIT_PASS) is bytes,
            'native package independent source/stock output pins are not finalized')


def expected_application():
    finalized()
    result = REFERENCE.expected_application()
    result['app/main.py'] = REFERENCE.pinned_bytes(ROOT / 'fixtures/python-imports/input/app/main.py',
                                                 REFERENCE.APP_BASE_PINS['app/main.py'])
    result['app/main.py'] += b'\n' + REFERENCE.pinned_bytes(FIXTURE / 'app.py', APP_TAIL_PIN)
    result['python/archive-importer.py'] += b'\n' + REFERENCE.pinned_bytes(FIXTURE / 'bootstrap.py', BOOTSTRAP_TAIL_PIN)
    for key, pin in PACKAGE_PINS.items():
        result[key] = REFERENCE.pinned_bytes(FIXTURE / 'input' / key, pin)
    return result


def expected_output(mode):
    finalized()
    cell_for(mode)
    if mode in NEGATIVE:
        return REFERENCE.expected_output(mode)
    return (REFERENCE.REFERENCE.BUNDLED.SUCCESS + NATIVE_PASS + ATEXIT_PASS + FINALIZE_PASS,
            REFERENCE.APP_ERROR if mode.endswith('-app-error') else b'')


def configured_graph():
    finalized()
    module = load('check-linux-python-native-lifecycle-trace.py', 'native_packages_private_lifecycle')
    # All assignments belong to a newly evaluated module. Its own fresh native
    # graph still performs the historical startup, source and geometry checks.
    module.TraceError = TraceError
    module.require = require
    module.PROGRAM, module.DIRECTORY, module.APP_ID = PROGRAM, DIRECTORY, APP_ID
    module.command_for, module.archive_for = command_for, archive_for
    module.expected_application = expected_application
    module.expected_output = expected_output
    module.NATIVE_PASS, module.ATEXIT_PASS = NATIVE_PASS, ATEXIT_PASS
    module.BEFORE_FINALIZE = REFERENCE.REFERENCE.BUNDLED.SUCCESS + NATIVE_PASS + ATEXIT_PASS
    module.SUCCESS = module.BEFORE_FINALIZE + FINALIZE_PASS
    original_factory = module.Checker
    module.Checker = lambda mode, record: parser_adapter(original_factory(mode, record), module)
    return module


def parser_adapter(checker, module):
    """Check the observed package parser owner, then normalize only its sizes.

    The fresh lifecycle graph receives its original 307200/610304 tuple after
    this adapter proves the actual 299008/593920 allocation/growth/full release.
    Neither historical method bodies nor their descriptor/image rules change.
    """
    original_call, original_finish = checker.call, checker.finish
    checker.package_parser_owner = None
    checker.package_parser_grown = checker.package_parser_freed = False
    bundled = checker.cell.startswith('bundled-')

    def call(name, args, result):
        if not bundled:
            return original_call(name, args, result)
        value = module.REFERENCE.result_number(result)
        if name == 'mmap' and args == ['NULL', '299008', 'PROT_READ|PROT_WRITE', 'MAP_PRIVATE|MAP_ANONYMOUS', '-1', '0']:
            require(checker.package_parser_owner is None and not checker.package_parser_grown and
                    not checker.package_parser_freed and value is not None and value > 0 and
                    checker.runtime.archive_opened == 1 and checker.runtime.locator_read and
                    not checker.runtime.archive_complete() and not checker.runtime.created,
                    'native package parser allocation is outside its sole private pre-admission phase')
            checker.require_unowned(value, 299008)
            translated = args.copy()
            translated[1] = '307200'
            original_call(name, translated, result)
            checker.package_parser_owner = value
            return
        if name == 'mremap':
            require(checker.package_parser_owner is not None and not checker.package_parser_grown and
                    len(args) == 4 and args == [hex(checker.package_parser_owner), '299008', '593920', 'MREMAP_MAYMOVE'] and
                    value is not None and value > 0 and not checker.runtime.archive_complete() and
                    not checker.runtime.created, 'native package parser growth differs from its exact owned backing')
            checker.require_unowned(value, 593920)
            original_call(name, [args[0], '307200', '610304', args[3]], result)
            checker.package_parser_owner = value
            checker.package_parser_grown = True
            return
        if name == 'munmap' and len(args) == 2 and args[0] != 'NULL' and checker.package_parser_owner is not None:
            start, length = module.address(args[0]), module.PBS.unsigned(args[1])
            span = 593920 if checker.package_parser_grown else 299008
            if start < checker.package_parser_owner + span and checker.package_parser_owner < start + length:
                require(args == [hex(checker.package_parser_owner), '593920'] and value == 0 and
                        checker.package_parser_grown and not checker.package_parser_freed and
                        not checker.runtime.archive_complete(), 'native package parser release is not its full grown owner')
                original_call(name, [args[0], '610304'], result)
                checker.package_parser_owner = None
                checker.package_parser_freed = True
                return
        return original_call(name, args, result)

    def finish():
        if bundled:
            require(checker.package_parser_owner is None and checker.package_parser_grown and
                    checker.package_parser_freed, 'native package parser allocation/growth/release sequence is incomplete')
        return original_finish()

    checker.call, checker.finish = call, finish
    return checker


def expected_manifest(mode):
    return configured_graph().expected_manifest(mode)


def archive_record(path, mode):
    return configured_graph().archive_record(path, mode)


def retained_metadata(path, mode, size=None):
    return configured_graph().retained_metadata(path, mode, size)


def validate_record(record, mode, size):
    return configured_graph().validate_record(record, mode, size)


def native_facts(directory):
    return REFERENCE.native_facts(directory)


def emit_metadata(directory, archives, output):
    return configured_graph().emit_metadata(directory, archives, output)


def Checker(mode, record):
    return configured_graph().Checker(mode, record)


def check_lines(lines, mode, record):
    return configured_graph().check_lines(lines, mode, record)


def check_file(path, mode, record):
    return configured_graph().check_file(path, mode, record)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--emit-native-metadata', nargs=3, type=Path)
    parser.add_argument('trace', nargs='?', type=Path)
    parser.add_argument('--mode', choices=MODES)
    parser.add_argument('--stdout-file', type=Path)
    parser.add_argument('--stderr-file', type=Path)
    parser.add_argument('--archive-file', type=Path)
    parser.add_argument('--native-metadata-file', type=Path)
    args = parser.parse_args()
    if args.emit_native_metadata:
        emit_metadata(*args.emit_native_metadata)
        return 0
    require(args.trace and args.mode and args.stdout_file and args.stderr_file and args.native_metadata_file,
            'native package replay requires trace, mode, output and metadata files')
    record = retained_metadata(args.native_metadata_file, args.mode)
    if args.archive_file:
        require(typed_equal(archive_record(args.archive_file, args.mode), record),
                'native package archive differs from retained fully inspected metadata')
    for path, expected in zip((args.stdout_file, args.stderr_file), expected_output(args.mode)):
        with path.open('rb') as stream:
            require(stream.read(len(expected) + 1) == expected, 'native package captured output differs')
    check_file(args.trace, args.mode, record)
    print('PASS exact native package trace: ' + args.mode)
    return 0


if __name__ == '__main__':
    try:
        raise SystemExit(main())
    except (OSError, EOFError, UnicodeError, ValueError, KeyError, TypeError, struct.error,
            zipfile.BadZipFile, zlib.error, TraceError) as error:
        print('Native package trace rejected: ' + str(error), file=sys.stderr)
        raise SystemExit(1)
