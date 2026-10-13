#!/usr/bin/env python3
"""Independently verify a complete installed-package product evidence capture.

Run after the native harness. This script imports no product or trace-policy
code. It needs the repository's checked-in expected bytes and exported archives.
"""
from __future__ import annotations

import argparse
import base64
import copy
import csv
import gzip
import hashlib
import io
import json
from pathlib import Path
import re
import struct
import sys
import zipfile

PROFILES = ('bundled', 'host', 'install-host')
MODES = PROFILES + tuple(profile + '-corrupt-metadata' for profile in PROFILES)
DIST = 'glue_meta_demo-1.2.3.dist-info'
RECORD = DIST + '/RECORD'
CORRUPT = 'app/python/' + DIST + '/METADATA'
REVISION = '3f3f31a18b59c664dda2dee36d409029c06dfc9f'


def require(condition, message):
    if not condition:
        raise ValueError(message)


def sha(payload):
    return hashlib.sha256(payload).hexdigest()


def identity(payload):
    return {'size': len(payload), 'sha256': sha(payload)}


def read_json(path):
    return json.loads(path.read_text(encoding='utf-8'))


def read_text(path):
    if path.exists():
        return path.read_text(encoding='utf-8')
    with gzip.open(path.with_suffix(path.suffix + '.gz'), 'rt', encoding='utf-8') as stream:
        return stream.read()


def control(capture, case, operation):
    base = capture / 'cli-controls' / (case + '.' + operation)
    return (Path(str(base) + '.stdout.txt').read_bytes(),
            Path(str(base) + '.stderr.txt').read_bytes(),
            Path(str(base) + '.exit-status.txt').read_text())


def original_record(provenance):
    matches = []
    for newline in ('\n', '\r\n'):
        output = io.StringIO(newline='')
        csv.writer(output, lineterminator=newline).writerows(provenance['original_record_rows'])
        payload = output.getvalue().encode()
        if identity(payload) == provenance['original_record_identity']:
            matches.append(payload)
    require(len(matches) == 1, 'original installed RECORD cannot be reproduced from retained rows/identity')
    return matches[0]


def expected_inputs(template_bytes, template, expected, provenance):
    values = [{'source': 'template', 'path': 'manifest.json', **identity(template_bytes)},
              {'source': 'venv', 'path': 'pyvenv.cfg', **identity(provenance['venv_configuration'].encode())},
              {'source': 'application', 'path': 'app/main.py', **expected['app/main.py']}]
    for path in sorted(expected):
        if path.startswith('app/python/'):
            relative = path.removeprefix('app/python/')
            source = provenance['installed_files'][relative]
            require(source == (provenance['original_record_identity'] if relative == RECORD else expected[path]),
                    'unchanged retained source identity differs: ' + path)
            values.append({'source': 'packages', 'path': relative, **source})
    for path, specification in template['resources'].items():
        if not path.startswith('app/'):
            values.append({'source': 'provider', 'path': path, 'size': specification['size'],
                           'sha256': specification['sha256']})
    return sorted(values, key=lambda value: (value['source'], value['path']))


def doctor_output(profile):
    label = {'bundled': 'bundled', 'host': 'explicit-host', 'install-host': 'install-only host'}[profile]
    return ('Launcher: glue 0.1.0 on linux/aarch64\n'
            'Linked Lua: 5.4.9 (int64, float64)\n'
            'Available: archive packaging, inspection, verification, read-only resources, linked Lua source profile\n'
            'Pending: general runtime/package compatibility, Node adapters, workers, standalone signing\n'
            'Python: controlled CPython 3.13.16 / PBS 20261009 profiles; GNU Linux arm64 execution only\n'
            'Validated metadata for distribution.metadata\n'
            f'Ready: pinned {label} Python distribution metadata application build/target prerequisites, CPython 3.13.16 / PBS 20261009\n'
            'Run checks profile archive limits, contents and explicit host prerequisites before loading Python\n').encode()


def audit(args):
    repo, capture, archives = args.repo, args.capture, args.archives
    require((capture / 'source-revision.txt').read_text().strip() == REVISION, 'capture source revision differs')
    require(not (capture / 'source-status.txt').read_bytes(), 'capture source status was not clean')
    require(not (capture / 'source-diff.patch').read_bytes(), 'capture source diff was not empty')
    fixture = repo / 'fixtures/python-venv-ingestion'
    inventory = read_json(fixture / 'expected-inventory.json')
    require(set(inventory) == {'schema_version', 'files'} and inventory['schema_version'] == 0, 'expected inventory schema differs')
    expected = inventory['files']
    payloads = {path.relative_to(fixture / 'expected-input').as_posix(): path.read_bytes()
                for path in sorted((fixture / 'expected-input').rglob('*')) if path.is_file()}
    require(len(payloads) == 11 and {path: identity(data) for path, data in payloads.items()} == expected,
            'checked-in eleven-file expected projection differs')
    provenance = read_json(capture / 'installation-provenance.json')
    require(provenance['expected_application'] == expected and provenance['python_version'] == [3, 13, 16], 'installation projection or producer differs')
    require(provenance['wheel'] == read_json(fixture / 'wheel-provenance.json'), 'installed wheel provenance differs from checked-in wheel')
    wheel = fixture / 'glue_meta_demo-1.2.3-py3-none-any.whl'
    require(identity(wheel.read_bytes()) == provenance['wheel']['wheel_identity'], 'checked-in wheel identity differs')
    raw_record = original_record(provenance)
    require(provenance['installed_files'][RECORD] == identity(raw_record), 'original RECORD input identity differs')
    omit = sorted([{'path': value['path'], 'reason': 'generated_entry_point_wrapper' if value['kind'] == 'console-wrapper' else 'bytecode_or_cache'}
                   for value in provenance['omissions']], key=lambda value: (value['path'], value['reason']))
    require(len(omit) == 3 and sum(item['reason'] == 'bytecode_or_cache' for item in omit) == 2, 'exact installer omissions differ')
    require(sum(row[0] == '../../../bin/glue-meta-demo' for row in provenance['original_record_rows']) == 1, 'console wrapper source row differs')

    declarations, artifact_records, valid_members, crc_failures = {}, {}, 0, 0
    for mode in MODES:
        profile = mode.removesuffix('-corrupt-metadata')
        template_bytes = (capture / (profile + '.template.json')).read_bytes()
        template = json.loads(template_bytes)
        declaration = copy.deepcopy(template)
        declaration['app_id'] = 'distribution.metadata'
        declaration['resources'] = {path: spec for path, spec in template['resources'].items() if not path.startswith('app/')}
        declaration['resources'].update({path: spec | {'compression': 'stored'} for path, spec in expected.items()})
        path = archives / (mode + '.glue')
        data = path.read_bytes()
        locator = data[:64]
        require(locator[:8] == b'GLUERS00' and locator[8:16] == b'\0' * 8, mode + ': locator differs')
        length, compressed_bytes = struct.unpack_from('<QQ', locator, 16)
        raw = data[64:64 + length]
        require(compressed_bytes == len(data) - 64 - length and hashlib.sha256(raw).digest() == locator[32:64], mode + ': archive regions or manifest hash differ')
        require(json.loads(raw) == declaration and raw == json.dumps(declaration, sort_keys=True, separators=(',', ':'), ensure_ascii=False).encode(), mode + ': canonical final declaration differs')
        declarations[mode] = declaration
        with zipfile.ZipFile(path) as archive:
            members = archive.infolist()
            require(len(members) == len(declaration['resources']) and set(archive.namelist()) == set(declaration['resources']), mode + ': complete ZIP inventory differs')
            for member in members:
                spec = declaration['resources'][member.filename]
                require(member.file_size == spec['size'] and member.compress_type == (zipfile.ZIP_STORED if spec['compression'] == 'stored' else zipfile.ZIP_DEFLATED), mode + ': member size/storage differs')
                if mode.endswith('-corrupt-metadata') and member.filename == CORRUPT:
                    try:
                        archive.read(member.filename)
                    except zipfile.BadZipFile as error:
                        require('CRC' in str(error), mode + ': control did not fail CRC')
                    else:
                        raise ValueError(mode + ': corrupt member unexpectedly verified')
                    name_bytes, extras = struct.unpack_from('<HH', data, member.header_offset + 26)
                    offset = member.header_offset + 30 + name_bytes + extras
                    original = payloads[member.filename]
                    require(data[offset:offset + member.file_size] == bytes([original[0] ^ 1]) + original[1:], mode + ': CRC damage is not exactly the first-byte control')
                    crc_failures += 1
                    continue
                member_bytes = archive.read(member.filename)
                require(identity(member_bytes) == {'size': spec['size'], 'sha256': spec['sha256']}, mode + ': member identity differs: ' + member.filename)
                if member.filename.startswith('app/'):
                    require(member_bytes == payloads[member.filename], mode + ': normalized package payload differs')
                valid_members += 1
        artifact_records[mode] = {'archive_bytes': len(data), 'archive_sha256': sha(data),
                                  'manifest_sha256': sha(raw), 'resource_count': len(declaration['resources']),
                                  'uncompressed_bytes': sum(value['size'] for value in declaration['resources'].values())}

    cli = {}
    reports = {}
    for profile in PROFILES:
        out, err, status = control(capture, profile, 'build')
        require(status == '0\n' and not err, profile + ': build status or stderr differs')
        report = json.loads(out)
        record = artifact_records[profile]
        template_bytes = (capture / (profile + '.template.json')).read_bytes()
        template = json.loads(template_bytes)
        expected_report = {'build': record, 'package_input': 'venv',
                           'distributions': [{'name': 'glue-meta-demo', 'version': '1.2.3', 'directory': DIST,
                                              'original_record_sha256': sha(raw_record), 'original_record_bytes': len(raw_record), 'retained_files': 10}],
                           'inputs': expected_inputs(template_bytes, template, expected, provenance), 'omissions': omit}
        require(report == expected_report, profile + ': transformation/source/artifact report differs')
        reports[profile] = {'input_identities': len(report['inputs']), 'distributions': report['distributions'], 'omissions': report['omissions'], 'archive': record}
        cli[profile + '.build'] = {'exit_status': 0, 'json_report_verified': True}
    diagnostic = ('glue: resource "' + CORRUPT + '" failed CRC32 verification\n').encode()
    for mode in MODES:
        profile = mode.removesuffix('-corrupt-metadata')
        declaration, record = declarations[mode], artifact_records[mode]
        for operation in ('inspect', 'verify', 'doctor', 'cat'):
            out, err, status = control(capture, mode, operation)
            crc = operation == 'verify' and mode.endswith('-corrupt-metadata')
            expected_status = '1\n' if crc else '0\n'
            require(status == expected_status, mode + '.' + operation + ': status differs')
            require(err == (diagnostic if crc else b''), mode + '.' + operation + ': diagnostic differs')
            if crc:
                expected_stdout = b''
            elif operation == 'inspect':
                expected_stdout = json.dumps(declaration, sort_keys=True, separators=(',', ':'), ensure_ascii=False).encode() + b'\n'
            elif operation == 'verify':
                expected_stdout = f'Verified {record["resource_count"]} resources ({record["uncompressed_bytes"]} uncompressed bytes)\n'.encode()
            elif operation == 'doctor':
                expected_stdout = doctor_output(profile)
            else:
                expected_stdout = payloads['app/main.py']
            require(out == expected_stdout, mode + '.' + operation + ': output bytes differ')
            cli[mode + '.' + operation] = {'exit_status': int(status), 'exact_output_verified': True}

    process = {}
    for profile in PROFILES:
        lines = read_text(capture / (profile + '.build-process.trace.txt')).splitlines()
        require(len(lines) == 3, profile + ': build process trace contains extra/truncated records')
        match = re.fullmatch(r'([1-9][0-9]*)\s+execve\(("(?:[^"\\]|\\.)*"), (\[.*\]), 0x[0-9a-f]+ /\* [0-9]+ vars \*/\) = 0', lines[0])
        require(match is not None, profile + ': initial build exec grammar differs')
        pid, program, argv = match[1], json.loads(match[2]), json.loads(match[3])
        expected_argv = ['/build-target/release/glue', 'build-python', '--provider-template', f'/build-target/staging/{profile}/manifest.json',
                         '--provider-root', f'/build-target/staging/{profile}/root', '--app', '/host-build/installed-packages/application',
                         '--venv', '/host-build/installed-packages/venv', '--app-id', 'distribution.metadata', '--entry', 'app/main.py',
                         '--output', f'/build-target/relocated Python metadata/{profile}.glue', '--json']
        require(program == expected_argv[0] and argv == expected_argv, profile + ': build exec target/argv differs')
        require(re.fullmatch(re.escape(pid) + r'\s+exit_group\(0\)\s+= \?', lines[1]) is not None and
                re.fullmatch(re.escape(pid) + r'\s+\+\+\+ exited with 0 \+\+\+', lines[2]) is not None,
                profile + ': single builder PID exit differs')
        process[profile] = {'process_records': 3, 'pids': 1, 'execs': 1, 'child_processes': 0,
                            'interpreter_execs': 0, 'exit_status': 0, 'trace_sha256': sha(('\n'.join(lines) + '\n').encode())}

    artifacts = {}
    for line in (capture / 'artifacts.sha256').read_text().splitlines():
        digest, name = line.split('  ', 1)
        require(re.fullmatch('[0-9a-f]{64}', digest) is not None and name.startswith('/build-target/relocated Python metadata/'), 'artifact checksum grammar differs')
        local = archives / Path(name).name
        require(sha(local.read_bytes()) == digest, 'artifact checksum differs: ' + name)
        artifacts[Path(name).name] = digest
    require(set(artifacts) == {'glue'} | {mode + '.glue' for mode in MODES}, 'complete launcher/archive checksum inventory differs')
    require(len(cli) == 27 and crc_failures == 3, 'CLI/CRC control inventory differs')
    return {'schema_version': 0, 'source_revision': REVISION, 'clean_source_capture': True,
            'normalized_application_files': 11, 'normalized_package_files': 10,
            'cli_controls': len(cli), 'verified_members': valid_members, 'intentional_crc_failures': crc_failures,
            'cli': cli, 'transformations': reports, 'build_processes': process, 'artifacts': artifacts}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    for key in ('repo', 'capture', 'archives', 'output'):
        parser.add_argument('--' + key, type=Path, required=True)
    args = parser.parse_args()
    result = audit(args)
    args.output.write_text(json.dumps(result, sort_keys=True, indent=2) + '\n')
    print(f'Independent product audit passed: {result["cli_controls"]} CLI controls; {result["verified_members"]} verified members; '
          f'{result["intentional_crc_failures"]} intentional CRC failures; three single-process builds')


if __name__ == '__main__':
    try:
        main()
    except (OSError, ValueError, KeyError, TypeError, struct.error, zipfile.BadZipFile) as error:
        print('Independent product audit rejected: ' + str(error), file=sys.stderr)
        raise SystemExit(1)
