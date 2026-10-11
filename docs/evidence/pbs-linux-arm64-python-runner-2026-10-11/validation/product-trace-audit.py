#!/usr/bin/env python3
"""Independent mutations of complete actual product traces; no synthetic fixtures.

Every hostile case derives from an independently passing capture, preserving
all unrelated records. This script deliberately does not import unit fixtures.
Its JSON records the rejected edit, actual source/checker/trace identities, and
the exact TraceError. A baseline failure or an admitted hostile edit fails audit.
"""
from __future__ import annotations

import argparse
import copy
import hashlib
import importlib.util
import json
from pathlib import Path
import re
import shutil
import subprocess
import sys
import tempfile
import time


REPO = Path(__file__).resolve().parents[1]
CHECKER = REPO / 'scripts/check-linux-python-runner-trace.py'


def sha(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def load_checker():
    spec = importlib.util.spec_from_file_location('independent_actual_runner_audit', CHECKER)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def first(lines, predicate, start=0):
    for i in range(start, len(lines)):
        if predicate(lines[i]):
            return i
    raise AssertionError('required actual trace anchor is absent')


def rewrite(lines, index, replacement):
    result = lines.copy()
    result[index] = replacement
    return result


def insert(lines, index, line):
    return lines[:index] + [line] + lines[index:]


def remove(lines, index):
    return lines[:index] + lines[index + 1:]


def moved(lines, index, destination):
    result = remove(lines, index)
    result.insert(destination - (index < destination), lines[index])
    return result


def record(pid, body):
    return str(pid) + '    ' + body + '\n'


def change_payload(line, transform):
    match = re.fullmatch(r'([0-9]+\s+)write\(([^,]+), ("(?:[^"\\]|\\.)*"), ([0-9]+)\)\s+= ([0-9]+)\n', line)
    if match is None:
        raise AssertionError('actual output is not a complete successful write')
    payload = transform(json.loads(match[3]))
    count = len(payload.encode('ascii'))
    return f'{match[1]}write({match[2]}, {json.dumps(payload)}, {count}) = {count}\n'


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--capture', type=Path, required=True)
    parser.add_argument('--build', type=Path, required=True)
    parser.add_argument('--output', type=Path, required=True)
    parser.add_argument('--require-clean-capture', action='store_true')
    args = parser.parse_args()
    if not args.output.parent.is_dir():
        parser.error('output parent must already exist; the root creates its fresh validation directory')
    capture, build = args.capture.resolve(), args.build.resolve()
    source_status = (capture / 'source-status.txt').read_text()
    capture_revision = (capture / 'source-revision.txt').read_text().strip()
    repository_revision = subprocess.check_output(['git', 'rev-parse', 'HEAD'], cwd=REPO, text=True).strip()
    repository_status = subprocess.check_output(['git', 'status', '--porcelain'], cwd=REPO, text=True)
    if args.require_clean_capture and source_status:
        parser.error('capture does not declare a clean source checkpoint')
    if args.require_clean_capture and (repository_status or capture_revision != repository_revision):
        parser.error('capture and current checker must share the same clean source checkpoint')
    C = load_checker()
    metadata = json.loads((capture / 'native-metadata.json').read_text())
    report = {
        'schema_version': 0,
        'command': sys.argv,
        'capture': str(capture), 'build': str(build),
        'capture_revision': capture_revision,
        'capture_branch': (capture / 'source-branch.txt').read_text().strip(),
        'capture_source_status': source_status,
        'repository_revision': repository_revision, 'repository_source_status': repository_status,
        'checker_sha256': {path.name: sha(path) for path in sorted((REPO / 'scripts').glob('check-linux-python*trace.py'))},
        'script_sha256': sha(Path(__file__)),
        'baselines': [], 'mutations': [],
    }
    start_time = time.monotonic()
    baselines = {}
    with tempfile.TemporaryDirectory(prefix='glue-product-trace-review-') as temporary:
        metadata_path = Path(temporary) / 'metadata.json'

        def verify(mode, lines, facts=metadata, stdout=None, stderr=None):
            actual = baselines[mode]
            metadata_path.write_text(json.dumps(facts))
            if stdout is None:
                stdout = actual['stdout']
            if stderr is None:
                stderr = actual['stderr']
            if (stdout, stderr) != C.expected_output(mode):
                raise C.TraceError('retained product stdout/stderr differs from exact fixture output')
            record_fact = C.retained_metadata(metadata_path, mode, actual['size'], actual['offset'])
            admission = (record_fact['manifest_bytes'], record_fact['zip_directory_offset'])
            readiness = C.retained_readiness(metadata_path, mode, actual['size'], admission)
            # Actual --archive-file CLI does both comparisons, binding trusted
            # retained metadata to the complete archive and canonical ZIP layout.
            if record_fact != actual['archive_fact']:
                raise C.TraceError('retained product archive identity differs from actual input')
            if readiness != actual['readiness_fact']:
                raise C.TraceError('retained product readiness metadata differs from actual ZIP layout')
            C.check_lines(lines, mode, actual['size'], actual['offset'], admission, readiness)

        def hostile(mode, name, lines=None, facts=metadata, stdout=None, stderr=None):
            actual = baselines[mode]
            if lines is None:
                lines = actual['lines']
            try:
                verify(mode, lines, facts, stdout, stderr)
            except C.TraceError as error:
                result = {'mode': mode, 'mutation': name, 'rejected': True, 'error': str(error)}
            else:
                result = {'mode': mode, 'mutation': name, 'rejected': False}
            report['mutations'].append(result)

        for mode in C.MODES:
            trace = capture / (mode + '.trace.txt')
            archive = build / 'relocated Python runner' / (mode + '.glue')
            lines = trace.read_text().splitlines(keepends=True)
            size = archive.stat().st_size
            offset = C.NATIVE.corrupt_offset(archive) if mode == 'corrupt-native' else None
            archive_fact = (C.import_record if mode in C.IMPORTS else C.NATIVE.archive_record)(archive)
            baselines[mode] = {
                'lines': lines, 'size': size, 'offset': offset,
                'archive_fact': archive_fact, 'readiness_fact': C.readiness_record(archive),
                'stdout': (capture / (mode + '.stdout.txt')).read_bytes(),
                'stderr': (capture / (mode + '.stderr.txt')).read_bytes(),
            }
            verify(mode, lines)
            report['baselines'].append({'mode': mode, 'passed': True, 'records': len(lines),
                                        'trace_sha256': sha(trace), 'archive_sha256': archive_fact['sha256']})

        # Exact command/prefix/path translation must never become a permissive
        # path replacement for a sibling archive, producer, or extra CLI argument.
        for mode, actual in baselines.items():
            lines = actual['lines']
            pid = int(lines[0].split()[0])
            uname = first(lines, lambda line: '    uname(' in line)
            archive_path = C.archive_for(mode)
            archive_read = lambda line: '    read(' in line and archive_path + '>' in line
            close = first(lines, lambda line: '    close(' in line and archive_path + '>' in line)
            publication = first(lines, lambda line: re.search(r'\swrite\([12]</evidence/', line))
            hostile(mode, 'command selects another executable', rewrite(lines, 0, lines[0].replace(C.PROGRAM, '/tmp/glue')))
            hostile(mode, 'command appends an extra run argument', rewrite(lines, 0, lines[0].replace('], ', ', "app-error"], ', 1)))
            hostile(mode, 'readiness query omitted', remove(lines, uname))
            hostile(mode, 'readiness query repeated', insert(lines, uname, lines[uname]))
            hostile(mode, 'readiness after first payload read', moved(lines, uname, first(lines, archive_read, uname + 1) + 1))
            # The same trace keeps every metadata read; only the query moves
            # before completion of the admitted ZIP/header phase.
            metadata_read = next(i for i in range(uname - 1, -1, -1) if archive_read(lines[i]))
            hostile(mode, 'readiness before final metadata read', moved(lines, uname, metadata_read))
            hostile(mode, 'archive owner closed before payload closure', moved(lines, close, uname + 1))
            hostile(mode, 'publication into sibling evidence stream', rewrite(lines, publication,
                    lines[publication].replace('/evidence/' + mode + '.', '/evidence/other.')))
            hostile(mode, 'publication payload changed with consistent count', rewrite(lines, publication,
                    change_payload(lines[publication], lambda payload: 'X' + payload[1:])))
            hostile(mode, 'extra PID on consumed readiness query', rewrite(lines, uname,
                    re.sub(r'^[0-9]+', str(pid + 1), lines[uname])))

        # Failed attempts count as filesystem materialization/process/fallback
        # events. Exercise both inherited import policies and native providers.
        attempts = {
            'failed named temporary materialization': 'openat(AT_FDCWD</build-target/runtime-empty>, "/tmp/glue-native.so", O_RDWR|O_CREAT|O_EXCL|O_CLOEXEC, 0600) = -1 EACCES (Permission denied)',
            'failed unnamed temporary materialization': 'openat(AT_FDCWD</build-target/runtime-empty>, "/tmp", O_RDWR|O_TMPFILE|O_CLOEXEC, 0600) = -1 EACCES (Permission denied)',
            'failed resource file removal': 'unlink("/tmp/glue-resource.py") = -1 EACCES (Permission denied)',
            'failed subprocess creation': 'clone3({}, 64) = -1 ENOSYS (Function not implemented)',
            'failed URI source fallback': 'openat(AT_FDCWD</build-target/runtime-empty>, "glue://stock-pbs-archive-imports/app/missing.py", O_RDONLY|O_CLOEXEC) = -1 ENOENT (No such file or directory)',
            'failed relocated source fallback': 'openat(AT_FDCWD</build-target/runtime-empty>, "/build-target/relocated Python runner/app/missing.py", O_RDONLY|O_CLOEXEC) = -1 ENOENT (No such file or directory)',
            'failed host shared-library fallback': 'openat(AT_FDCWD</build-target/runtime-empty>, "/usr/lib/libpython3.13.so", O_RDONLY|O_CLOEXEC) = -1 ENOENT (No such file or directory)',
        }
        for mode in ('bundled-imports', 'host-imports', 'bundled-archived', 'host-host'):
            lines = baselines[mode]['lines']
            pid = int(lines[0].split()[0])
            before_exit = first(lines, lambda line: '    exit_group(' in line)
            for name, call in attempts.items():
                hostile(mode, name, insert(lines, before_exit, record(pid, call)))

        # Alter a real immutable image's seal proof, alias ordering, permissions,
        # mapping address and lifetime rather than merely adding a generic call.
        lines = baselines['bundled-archived']['lines']
        for image, label in [('glue-python-libpython', 'runtime'), ('glue-python-native-libglue_python_dependency', 'native dependency')]:
            for operation in ('F_ADD_SEALS', 'F_GET_SEALS'):
                index = first(lines, lambda line: image in line and operation in line)
                hostile('bundled-archived', label + ' ' + operation + ' proof omitted', remove(lines, index))
            seal = first(lines, lambda line: image in line and 'F_GET_SEALS' in line)
            mapping = first(lines, lambda line: image in line and '    mmap(' in line and 'PROT_EXEC' in line)
            hostile('bundled-archived', label + ' map before seal proof', moved(lines, mapping, seal))
            hostile('bundled-archived', label + ' writable executable map', rewrite(lines, mapping,
                    lines[mapping].replace('PROT_READ|PROT_EXEC', 'PROT_READ|PROT_WRITE|PROT_EXEC')))
            address = re.search(r'mmap\((0x[0-9a-f]+),', lines[mapping])[1]
            before_output = first(lines, lambda line: re.search(r'\swrite\([12]</evidence/', line))
            pid = int(lines[0].split()[0])
            hostile('bundled-archived', label + ' unmapped before application publication/finalization', insert(lines, before_output,
                    record(pid, f'munmap({address}, 4096) = 0')))
        mapping = first(lines, lambda line: 'glue-python-native-libglue_python_dependency' in line and '    mmap(' in line and 'PROT_EXEC' in line)
        hostile('bundled-archived', 'native map substituted ordinary host image', rewrite(lines, mapping,
                re.sub(r'[0-9]+</memfd:glue-python-native-[^>]+>\(deleted\)', '999</tmp/unverified.so>', lines[mapping])))

        for mode in C.NATIVE.NEGATIVE:
            lines = baselines[mode]['lines']
            error = first(lines, lambda line: re.search(r'\swrite\(2</evidence/', line))
            hostile(mode, 'negative diagnostic uses historical prefix', rewrite(lines, error,
                    change_payload(lines[error], lambda payload: payload.replace('glue: ', 'glue-python-bootstrap-probe: ', 1))))
            uname = first(lines, lambda line: '    uname(' in line)
            hostile(mode, 'negative publication before readiness', moved(lines, error, uname))

        # Bind metadata to observed capture and concrete archive identity. These
        # remain valid JSON and, where possible, use canonical shapes and bounds.
        for mode in ('bundled-imports', 'host-imports', 'bundled-archived', 'host-host', 'corrupt-native'):
            section = 'imports' if mode in C.IMPORTS else 'archives'
            edits = {
                'canonical false archive digest': lambda data: data[section][mode].__setitem__('sha256', '0' * 64),
                'canonical false manifest digest': lambda data: data[section][mode].__setitem__('manifest_sha256', '0' * 64),
                'false manifest size': lambda data: data[section][mode].__setitem__('manifest_bytes', data[section][mode]['manifest_bytes'] + 1),
                'false ZIP directory offset': lambda data: data[section][mode].__setitem__('zip_directory_offset', data[section][mode]['zip_directory_offset'] - 1),
                'false readiness byte count': lambda data: data['readiness'][mode].__setitem__('archive_read_bytes', data['readiness'][mode]['archive_read_bytes'] + 1),
                'false readiness cursor': lambda data: data['readiness'][mode].__setitem__('archive_cursor', data['readiness'][mode]['archive_cursor'] - 1),
                'canonical false readiness range digest': lambda data: data['readiness'][mode].__setitem__('ranges_sha256', '0' * 64),
                'readiness bool substituted for byte count': lambda data: data['readiness'][mode].__setitem__('archive_read_bytes', True),
            }
            for name, edit in edits.items():
                facts = copy.deepcopy(metadata)
                edit(facts)
                hostile(mode, name, facts=facts)

        for mode in ('bundled-archived', 'host-host'):
            for kind in ('declared image hash', 'declared provider', 'native PT_LOAD permissions', 'native declaration path/size'):
                facts = copy.deepcopy(metadata)
                if kind == 'declared image hash':
                    facts['archives'][mode]['declarations']['glue_native_single.so']['sha256'] = '0' * 64
                elif kind == 'declared provider':
                    facts['archives'][mode]['native'] = 'host' if mode == 'bundled-archived' else 'archived'
                elif kind == 'native PT_LOAD permissions':
                    facts['files']['glue_native_single.so']['loads'][0]['flags'] = 7
                elif mode == 'host-host':
                    facts['archives'][mode]['declarations']['glue_native_single.so']['path'] = '/tmp/glue_native_single.so'
                else:
                    facts['archives'][mode]['declarations']['glue_native_single.so']['size'] -= 1
                hostile(mode, kind, facts=facts)

        # Retained stdout/stderr files are independent inputs to the CLI; mutate
        # those without modifying any trace publication record.
        hostile('bundled-imports', 'retained output file appends extra byte', stdout=baselines['bundled-imports']['stdout'] + b'X')
        hostile('wrong-host-image', 'retained error file changes prefix', stderr=baselines['wrong-host-image']['stderr'].replace(b'glue: ', b'probe: ', 1))

    report['elapsed_seconds'] = round(time.monotonic() - start_time, 3)
    report['baseline_count'] = len(report['baselines'])
    report['mutation_count'] = len(report['mutations'])
    report['rejected_count'] = sum(case['rejected'] for case in report['mutations'])
    report['passed'] = report['baseline_count'] == 9 and report['rejected_count'] == report['mutation_count']
    args.output.write_text(json.dumps(report, indent=2, sort_keys=True) + '\n')
    shutil.copyfile(Path(__file__), args.output.with_suffix('.py'))
    args.output.with_suffix('.commands.txt').write_text(' '.join(json.dumps(arg) for arg in [sys.executable] + sys.argv) + '\n')
    print(json.dumps({key: report[key] for key in ('baseline_count', 'mutation_count', 'rejected_count', 'passed', 'elapsed_seconds')}))
    if not report['passed']:
        for case in report['mutations']:
            if not case['rejected']:
                print(json.dumps(case), file=sys.stderr)
        return 1
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
