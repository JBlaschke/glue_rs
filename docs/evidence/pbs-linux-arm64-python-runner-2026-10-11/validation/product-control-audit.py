#!/usr/bin/env python3
"""Read-only audit of the clean actual-product capture and its thirty controls.

The launcher ELF listing is obtained separately with the retained offline
readelf command. All archive and output comparisons here use actual inputs;
the large archives are not copied into the audit report.
"""
from __future__ import annotations

import argparse
import hashlib
import importlib.util
import json
from pathlib import Path
import re
import struct
import subprocess
import sys
import zipfile


REPO = next(path for path in Path(__file__).resolve().parents
            if (path / 'scripts/check-linux-python-runner-trace.py').is_file())


def sha(path):
    digest = hashlib.sha256()
    with path.open('rb') as stream:
        while block := stream.read(1024 * 1024):
            digest.update(block)
    return digest.hexdigest()


def require(condition, message):
    if not condition:
        raise ValueError(message)


def identity(path):
    return {'bytes': path.stat().st_size, 'sha256': sha(path)}


def doctor(app_id, mode):
    name = {'bundled-imports': 'controlled bundled Python source/resources',
            'host-imports': 'controlled explicit-host Python source/resources'}.get(
                mode, 'controlled registered Python native extensions')
    return ('Launcher: glue 0.1.0 on linux/aarch64\n'
            'Linked Lua: 5.4.9 (int64, float64)\n'
            'Available: archive packaging, inspection, verification, read-only resources, linked Lua source profile\n'
            'Pending: general runtime/package compatibility, Node adapters, workers, standalone signing\n'
            'Python: controlled CPython 3.13.16 / PBS 20261009 profiles; GNU Linux arm64 execution only\n'
            f'Validated metadata for {app_id}\n'
            f'Ready: {name} build/target prerequisites, CPython 3.13.16 / PBS 20261009\n'
            'Run checks profile archive limits, contents and explicit host prerequisites before loading Python\n').encode('ascii')


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--capture', type=Path, required=True)
    parser.add_argument('--build', type=Path, required=True)
    parser.add_argument('--source-revision', required=True)
    parser.add_argument('--wide-elf', type=Path, required=True)
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    capture, build = args.capture.resolve(), args.build.resolve()
    spec = importlib.util.spec_from_file_location('product_control_audit_policy', REPO / 'scripts/check-linux-python-runner-trace.py')
    checker = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(checker)
    revision = (capture / 'source-revision.txt').read_text().strip()
    require(re.fullmatch(r'[0-9a-f]{40}', args.source_revision) is not None and revision == args.source_revision,
            'source revision differs from the complete clean checkpoint')
    require((capture / 'source-status.txt').read_bytes() == b'', 'capture source was dirty')
    require((capture / 'source-diff.patch').read_bytes() == b'', 'capture source diff was nonempty')
    commands = (capture / 'commands.sh').read_bytes()
    original = subprocess.check_output(['git', 'show', revision + ':fixtures/python-runner/run-linux.sh'], cwd=REPO)
    require(commands == original, 'retained capture commands differ from clean source')
    metadata = capture / 'native-metadata.json'
    facts = json.loads(metadata.read_text())
    archives = build / 'relocated Python runner'
    report = {'schema_version': 0, 'command': sys.argv, 'source_revision': revision,
              'source_branch': (capture / 'source-branch.txt').read_text().strip(),
              'source_clean': True, 'capture_commands': identity(capture / 'commands.sh'),
              'audit_script': identity(Path(__file__)), 'metadata': identity(metadata),
              'scope': 'Nine actual product runs and thirty untraced control commands; complete launcher dynamic symbols; actual archive identities and payload comparisons.',
              'runtime': [], 'controls': [], 'provenance': [], 'launcher': {}}
    for mode in checker.MODES:
        archive_path = archives / (mode + '.glue')
        offset = checker.NATIVE.corrupt_offset(archive_path) if mode == 'corrupt-native' else None
        record = checker.retained_metadata(metadata, mode, archive_path.stat().st_size, offset)
        actual_record = (checker.import_record if mode in checker.IMPORTS else checker.NATIVE.archive_record)(archive_path)
        require(record == actual_record, mode + ': metadata differs from actual archive')
        admission = record['manifest_bytes'], record['zip_directory_offset']
        require(checker.retained_readiness(metadata, mode, record['bytes'], admission) == checker.readiness_record(archive_path),
                mode + ': readiness differs from actual ZIP layout')
        with archive_path.open('rb') as stream:
            locator = stream.read(64)
            raw_manifest = stream.read(struct.unpack_from('<Q', locator, 16)[0])
        manifest = json.loads(raw_manifest)
        with zipfile.ZipFile(archive_path) as archive:
            main = archive.read('app/main.py')
        runtime_stdout, runtime_stderr = checker.expected_output(mode)
        status = 1 if mode in checker.NATIVE.NEGATIVE else 0
        require((capture / (mode + '.exit-status.txt')).read_bytes() == f'{status}\n'.encode('ascii'), mode + ': runtime status')
        require((capture / (mode + '.stdout.txt')).read_bytes() == runtime_stdout, mode + ': runtime stdout')
        require((capture / (mode + '.stderr.txt')).read_bytes() == runtime_stderr, mode + ': runtime stderr')
        trace_check = (capture / (mode + '.trace-check.txt')).read_text()
        require(trace_check.startswith('Trace checks passed: exact glue run route and target readiness,'), mode + ': strict replay marker')
        report['runtime'].append({'mode': mode, 'status': status, 'stdout': identity(capture / (mode + '.stdout.txt')),
                                 'stderr': identity(capture / (mode + '.stderr.txt')), 'trace': identity(capture / (mode + '.trace.txt')),
                                 'trace_check': identity(capture / (mode + '.trace-check.txt')), 'archive': record})
        for operation in ('inspect', 'verify', 'doctor', 'cat'):
            stem = capture / 'cli-controls' / (mode + '.' + operation)
            status_path = Path(str(stem) + '.exit-status.txt')
            if operation in ('doctor', 'cat') and status:
                require(not status_path.exists(), mode + ': unexpected negative doctor/cat control')
                continue
            out_path, err_path = Path(str(stem) + '.stdout.txt'), Path(str(stem) + '.stderr.txt')
            out, err = out_path.read_bytes(), err_path.read_bytes()
            expected_status = 1 if operation == 'verify' and mode == 'corrupt-native' else 0
            require(status_path.read_bytes() == f'{expected_status}\n'.encode('ascii'), mode + ': ' + operation + ' status')
            expected_error = (b'glue: resource "native/libglue_python_dependency.so" failed CRC32 verification\n'
                              if expected_status else b'')
            require(err == expected_error, mode + ': ' + operation + ' stderr')
            if operation == 'inspect':
                require(out == raw_manifest + b'\n', mode + ': inspect exact manifest bytes')
                comparison = 'exact raw archive manifest plus LF'
            elif operation == 'cat':
                require(out == main, mode + ': cat exact verified application bytes')
                comparison = 'exact archive app/main.py payload'
            elif operation == 'doctor':
                require(out == doctor(manifest['app_id'], mode), mode + ': doctor exact declared readiness text')
                comparison = 'exact pinned build/target prerequisite output'
            else:
                expected = (f"Verified {len(manifest['resources'])} resources ({sum(item['size'] for item in manifest['resources'].values())} uncompressed bytes)\n".encode('ascii')
                            if not expected_status else b'')
                require(out == expected, mode + ': verify exact archive inventory count')
                comparison = 'exact manifest resource count/bytes or exact stored CRC rejection'
            command = [checker.PROGRAM, operation, checker.archive_for(mode)]
            command += ['--json'] if operation == 'inspect' else ['app/main.py'] if operation == 'cat' else []
            report['controls'].append({'mode': mode, 'operation': operation, 'command': command, 'status': expected_status,
                                      'stdout': identity(out_path), 'stderr': identity(err_path), 'comparison': comparison})
    require(len(report['controls']) == 30, 'control inventory differs from thirty commands')
    elf = args.wide_elf.read_text()
    require('[...]' not in elf, 'launcher symbol names are abbreviated')
    needed = re.findall(r'Shared library: \[([^]]+)\]', elf)
    require(needed == ['libm.so.6', 'libgcc_s.so.1', 'libc.so.6'], 'launcher has another dynamic dependency')
    undefined = re.findall(r'\bUND[ \t]+([^\s]+)', elf)
    python_imports = [name for name in undefined if name.startswith(('Py', '_Py'))]
    require(not python_imports, 'launcher has direct Python undefined symbols')
    binary = archives / 'glue'
    artifact_lines = (capture / 'artifacts.sha256').read_text().splitlines()
    binary_hash = sha(binary)
    require(any(line == binary_hash + '  ' + checker.PROGRAM for line in artifact_lines), 'launcher hash differs from captured binary identity')
    report['launcher'] = {'binary': identity(binary), 'complete_elf_listing': identity(args.wide_elf),
                          'needed': needed, 'undefined_symbols': len(undefined), 'python_undefined_symbols': python_imports}
    for path in sorted((capture / 'build-provenance').glob('*.txt')):
        require(path.name.startswith('glue-runtime-python-'), 'C provenance uses another crate location')
        if path.name.endswith('.undefined.txt'):
            require(not re.search(r'\bU\s+(?:Py|_Py)', path.read_text()), 'boundary static archive directly imports Python')
        report['provenance'].append({'name': path.name, **identity(path)})
    require(len(report['provenance']) == 8, 'shared C provenance inventory differs')
    report['counts'] = {'runtime_cases': 9, 'controls': 30, 'shared_c_provenance_files': 8}
    report['findings'] = []
    args.output.write_text(json.dumps(report, indent=2, sort_keys=True) + '\n')
    print('Control audit passed: clean source, nine product outputs/replays, thirty exact controls, complete launcher imports and shared C provenance')
    return 0


if __name__ == '__main__':
    try:
        raise SystemExit(main())
    except (OSError, ValueError, KeyError, subprocess.CalledProcessError) as error:
        print(f'product control audit rejected: {error}', file=sys.stderr)
        raise SystemExit(1)
