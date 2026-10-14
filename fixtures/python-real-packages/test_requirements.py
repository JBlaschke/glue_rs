#!/usr/bin/env python3
"""Independent CLI Requires-Python controls over the genuine pinned installation.

Only command captures and a bounded audit are retained. Mutated package trees and
successful archives live in fixture-owned temporary storage and are removed.
No target interpreter, pip, product parser or runtime validator is invoked here.
"""
from __future__ import annotations

import argparse
import base64
import csv
import hashlib
import io
import json
from pathlib import Path
import shutil
import stat
import struct
import subprocess
import sys
import tempfile
import zipfile

HERE = Path(__file__).resolve().parent
DIST = 'mdurl-0.1.2.dist-info'
METADATA = DIST + '/METADATA'
RECORD = DIST + '/RECORD'
SITE = 'lib/python3.13/site-packages'
SENTINEL = b'pre-existing output must remain unchanged\n'
MODES = ('venv', 'explicit-site-packages')
CASES = (
    ('future-minor', '>=3.14', 'excludes selected CPython 3.13.16'),
    ('wildcard-exclusion', '!=3.13.*', 'excludes selected CPython 3.13.16'),
    ('patch-exclusion', '!=3.13.16', 'excludes selected CPython 3.13.16'),
    ('duplicate', '>=3.9\nRequires-Python: <4', 'duplicate Requires-Python'),
    ('folded', '>=3.9,\n <4', 'folded Requires-Python'),
    ('unsupported', '===3.13.16', 'arbitrary-equality syntax are unsupported'),
    ('empty', '', 'nonempty release specifier'),
    ('explicit-application', '>=3.14', 'excludes selected CPython 3.13.16'),
)
COMPATIBLE = ' ( >=3.10, <4, !=3.12.*, ~=3.13.16 ) '


def require(condition, message):
    if not condition:
        raise ValueError(message)


def identity(payload):
    return {'size': len(payload), 'sha256': hashlib.sha256(payload).hexdigest()}


def regular_bytes(path, maximum=2 * 1024 * 1024):
    info = path.lstat()
    require(stat.S_ISREG(info.st_mode) and info.st_size <= maximum,
            'nonregular/oversized control input: ' + str(path))
    payload = path.read_bytes()
    require(len(payload) == info.st_size, 'control input changed: ' + str(path))
    return payload


def file_identity(path, maximum):
    info = path.lstat()
    require(stat.S_ISREG(info.st_mode) and info.st_size <= maximum,
            'nonregular/oversized control file: ' + str(path))
    digest, length = hashlib.sha256(), 0
    with path.open('rb') as stream:
        for block in iter(lambda: stream.read(65536), b''):
            digest.update(block)
            length += len(block)
    require(length == info.st_size, 'control file changed: ' + str(path))
    return {'size': length, 'sha256': digest.hexdigest()}


def strict_json(payload):
    def pairs(items):
        result = {}
        for key, value in items:
            require(key not in result, 'duplicate JSON field: ' + key)
            result[key] = value
        return result
    return json.loads(payload, object_pairs_hook=pairs,
                      parse_constant=lambda value: (_ for _ in ()).throw(ValueError('nonfinite JSON: ' + value)))


def write_json(path, value):
    payload = (json.dumps(value, indent=2, sort_keys=True) + '\n').encode('utf-8')
    require(len(payload) <= 256 * 1024, 'control JSON exceeds retained bound')
    with path.open('xb') as stream:
        stream.write(payload)


def canonical(name):
    return (bool(name) and not name.startswith('/') and '\\' not in name and
            all(part and part not in ('.', '..') for part in name.split('/')) and
            all(ord(character) >= 32 and ord(character) != 127 for character in name))


def record_hash(payload):
    return 'sha256=' + base64.urlsafe_b64encode(hashlib.sha256(payload).digest()).rstrip(b'=').decode('ascii')


def rows(payload):
    result = list(csv.reader(io.StringIO(payload.decode('utf-8'), newline=''), strict=True))
    require(len(result) <= 1024 and all(len(row) == 3 for row in result), 'control RECORD shape differs')
    require(len({row[0] for row in result}) == len(result), 'control RECORD duplicates a path')
    return result


def csv_bytes(entries):
    stream = io.StringIO(newline='')
    csv.writer(stream, lineterminator='\n').writerows(entries)
    return stream.getvalue().encode('utf-8')


def normalized_record(files):
    return csv_bytes([[name, '', ''] if name == RECORD else
                      [name, record_hash(payload), str(len(payload))]
                      for name, payload in sorted(files.items())])


def replace_requirement(original, requirement):
    headers, separator, body = original.partition(b'\n\n')
    require(separator and b'\r' not in headers, 'original mdurl METADATA framing differs')
    lines = headers.split(b'\n')
    indices = [index for index, line in enumerate(lines) if line.lower().startswith(b'requires-python:')]
    require(len(indices) == 1 and lines[indices[0]] == b'Requires-Python: >=3.7',
            'original mdurl Requires-Python differs')
    lines[indices[0]] = b'Requires-Python: ' + requirement.encode('ascii')
    return b'\n'.join(lines) + separator + body


def prepared_inputs(prepared):
    provenance_bytes = regular_bytes(prepared / 'installation-provenance.json')
    provenance = strict_json(provenance_bytes)
    expected = strict_json(regular_bytes(HERE / 'expected-inventory.json'))
    require(provenance['schema_version'] == expected['schema_version'] == 0 and
            provenance['python_version'] == [3, 13, 16] and not provenance['venv_has_pip'] and
            provenance['installed_file_count'] == 261 and provenance['omission_count'] == 111,
            'prepared installation declarations differ')
    require(provenance['expected_application'] == expected['files'] and len(expected['files']) == 152 and
            strict_json(regular_bytes(prepared / 'expected-inventory.json')) == expected,
            'prepared projection is not the committed real package corpus')
    require(regular_bytes(prepared / 'baseline.stdout.txt') == regular_bytes(HERE / 'expected.stdout.txt') and
            identity(regular_bytes(prepared / 'baseline.stdout.txt')) == provenance['baseline_stdout_identity'],
            'genuine installation baseline differs')
    require(regular_bytes(prepared / 'venv/pyvenv.cfg').decode('utf-8') == provenance['venv_configuration'],
            'prepared conventional venv declaration differs')
    files = {}
    for name, declaration in expected['files'].items():
        require(canonical(name), 'unsafe prepared projection path')
        files[name] = regular_bytes(prepared / 'expected-input' / name)
        require(identity(files[name]) == declaration, 'prepared projected bytes differ: ' + name)
    require(regular_bytes(prepared / 'application/app/main.py') == files['app/main.py'],
            'prepared explicit application differs')
    site, installed = prepared / 'venv' / SITE, {}
    for path in sorted(site.rglob('*')):
        mode = path.lstat().st_mode
        require(stat.S_ISDIR(mode) or stat.S_ISREG(mode), 'prepared installed site contains a link/special file')
        if stat.S_ISREG(mode):
            name = path.relative_to(site).as_posix()
            require(canonical(name), 'unsafe installed path')
            installed[name] = identity(regular_bytes(path))
    require(installed == provenance['installed_files'] and len(installed) == 261 and
            sum(item['size'] for item in installed.values()) <= 8 * 1024 * 1024,
            'prepared installed bytes differ from genuine installation audit')
    for dist, facts in provenance['original_records'].items():
        require(canonical(dist) and dist.endswith('.dist-info'), 'unsafe prepared distribution')
        payload = regular_bytes(site / dist / 'RECORD')
        require(identity(payload) == facts['identity'] and rows(payload) == facts['rows'],
                'prepared original installed RECORD differs: ' + dist)
    mdurl_rows = rows(regular_bytes(site / RECORD))
    require(next(row for row in mdurl_rows if row[0] == METADATA)[1:] ==
            [record_hash(regular_bytes(site / METADATA)), str(installed[METADATA]['size'])],
            'original mdurl metadata RECORD declaration differs')
    return files, {'provenance': identity(provenance_bytes), 'installed_files': len(installed),
                   'application_files': len(files), 'original_mdurl_metadata': identity(files['app/python/' + METADATA]),
                   'original_mdurl_record': identity(regular_bytes(site / RECORD))}


def copy_inputs(prepared, scratch):
    venv, application = scratch / 'venv', scratch / 'application'
    shutil.copytree(prepared / 'venv', venv, symlinks=True)
    shutil.copytree(prepared / 'application', application, symlinks=True)
    for name in ('bin', 'Scripts'):
        path = venv / name
        if path.is_symlink():
            path.unlink()
        elif path.exists():
            shutil.rmtree(path)
        require(not path.exists() and not path.is_symlink(), 'copied interpreter directory remains')
    return venv, application


def mutate(venv, application, expected, requirement, explicit_application=False):
    metadata = replace_requirement(expected['app/python/' + METADATA], requirement)
    site = venv / SITE
    if explicit_application:
        mdurl = {name.removeprefix('app/python/'): data for name, data in expected.items()
                 if name.startswith(('app/python/mdurl/', 'app/python/' + DIST + '/'))}
        require(len(mdurl) == 13 and RECORD in mdurl, 'independent mdurl retained inventory differs')
        mdurl[METADATA] = metadata
        mdurl[RECORD] = normalized_record(mdurl)
        for name, data in mdurl.items():
            path = application / 'app/python' / name
            path.parent.mkdir(parents=True, exist_ok=True)
            with path.open('xb') as stream:
                stream.write(data)
        shutil.rmtree(site / 'mdurl')
        shutil.rmtree(site / DIST)
        record = mdurl[RECORD]
    else:
        (site / METADATA).write_bytes(metadata)
        entries = rows(regular_bytes(site / RECORD))
        matching = [row for row in entries if row[0] == METADATA]
        require(len(matching) == 1, 'mdurl RECORD lost its metadata row')
        matching[0][1:] = [record_hash(metadata), str(len(metadata))]
        record = csv_bytes(entries)
        (site / RECORD).write_bytes(record)
        require(next(row for row in rows(record) if row[0] == METADATA)[1:] ==
                [record_hash(metadata), str(len(metadata))], 'mutated installed RECORD identity differs')
    return metadata, record


def command(args, venv, application, provider_root, output, mode):
    package = ['--venv', str(venv)] if mode == 'venv' else ['--site-packages', str(venv / SITE)]
    return [str(args.glue), 'build-python', '--provider-template', str(args.template),
            '--provider-root', str(provider_root), '--app', str(application), *package,
            '--app-id', 'python.real-packages', '--entry', 'app/main.py', '--output', str(output), '--json']


def invoke(command_value, directory):
    write_json(directory / 'command.json', command_value)
    with (directory / 'stdout.txt').open('xb') as stdout, (directory / 'stderr.txt').open('xb') as stderr:
        result = subprocess.run(command_value, stdout=stdout, stderr=stderr, check=False, timeout=60)
    (directory / 'exit-status.txt').write_text(str(result.returncode) + '\n', encoding='ascii')
    return result.returncode, regular_bytes(directory / 'stdout.txt', 256 * 1024), regular_bytes(directory / 'stderr.txt', 256 * 1024)


def verify_archive(path, expected, report, mode, original_record):
    archive_identity = file_identity(path, 128 * 1024 * 1024)
    with path.open('rb') as stream:
        locator = stream.read(64)
        require(len(locator) == 64 and locator[:16] == b'GLUERS00' + b'\0' * 8, 'compatible archive locator differs')
        manifest_size, zip_size = struct.unpack_from('<QQ', locator, 16)
        require(0 < manifest_size <= 4 * 1024 * 1024 and 64 + manifest_size + zip_size == archive_identity['size'],
                'compatible archive framing differs')
        manifest_bytes = stream.read(manifest_size)
        require(hashlib.sha256(manifest_bytes).digest() == locator[32:64], 'compatible archive manifest identity differs')
        manifest = strict_json(manifest_bytes)
    projected = {name: declaration for name, declaration in manifest['resources'].items() if name.startswith('app/')}
    require(projected == {name: identity(data) | {'compression': 'stored'} for name, data in expected.items()},
            'compatible archive application inventory differs from independent projection')
    with zipfile.ZipFile(path) as archive:
        names = archive.namelist()
        require(len(names) == len(set(names)) and set(names) == set(manifest['resources']) and
                all(canonical(name) for name in names), 'compatible ZIP resource inventory differs')
        for name in names:
            payload = archive.read(name)
            declaration = manifest['resources'][name]
            require(identity(payload) == {key: declaration[key] for key in ('size', 'sha256')},
                    'compatible ZIP resource identity differs: ' + name)
            if name in expected:
                require(payload == expected[name], 'compatible retained application bytes differ: ' + name)
    expected_input = 'venv' if mode == 'venv' else 'site_packages'
    require(report['package_input'] == expected_input and report['build']['archive_bytes'] == archive_identity['size'] and
            report['build']['archive_sha256'] == archive_identity['sha256'] and
            report['build']['manifest_sha256'] == hashlib.sha256(manifest_bytes).hexdigest(),
            'compatible product report differs from independent archive audit')
    declaration = next(item for item in report['distributions'] if item['directory'] == DIST)
    require({'size': declaration['original_record_bytes'], 'sha256': declaration['original_record_sha256']} == identity(original_record),
            'compatible report did not identify the rewritten original installed RECORD')
    return {'archive': archive_identity, 'application_files': len(projected), 'all_resources': len(names),
            'metadata': identity(expected['app/python/' + METADATA]), 'normalized_record': identity(expected['app/python/' + RECORD])}


def audit(args):
    for name in ('glue', 'template', 'provider_root', 'prepared', 'output'):
        setattr(args, name, getattr(args, name).absolute())
    expected, preparation = prepared_inputs(args.prepared)
    template_bytes = regular_bytes(args.template, 4 * 1024 * 1024)
    require(strict_json(template_bytes)['runtimes']['python']['abi']['version'] ==
            {'major': 3, 'minor': 13, 'patch': 16}, 'control template is not pinned CPython 3.13.16')
    binary = file_identity(args.glue, 128 * 1024 * 1024)
    args.output.mkdir(parents=True, exist_ok=False)
    results = {}
    for case, requirement, diagnostic in CASES:
        for mode in MODES:
            for state in ('absent-output', 'existing-output'):
                label = case + '.' + mode + '.' + state
                directory = args.output / label
                directory.mkdir()
                output = directory / 'protected-output.glue'
                if state == 'existing-output':
                    output.write_bytes(SENTINEL)
                with tempfile.TemporaryDirectory(prefix='glue-requirements-') as temporary:
                    scratch = Path(temporary)
                    venv, application = copy_inputs(args.prepared, scratch)
                    metadata, record = mutate(venv, application, expected, requirement, case == 'explicit-application')
                    absent_provider = scratch / 'deliberately-absent-provider'
                    require(not absent_provider.exists(), 'hostile provider root is present')
                    status, stdout, stderr = invoke(command(args, venv, application, absent_provider, output, mode), directory)
                    protected = (not output.exists() and not output.is_symlink()) if state == 'absent-output' else (
                        not output.is_symlink() and output.is_file() and regular_bytes(output) == SENTINEL)
                    message = stderr.decode('utf-8')
                    require(status == 1 and not stdout and 'Requires-Python' in message and diagnostic in message and protected,
                            'requirement control did not reject before provider/publication: ' + label + '; see ' + str(directory))
                    require(not absent_provider.exists() and not (venv / 'bin').exists() and not (venv / 'Scripts').exists(),
                            'requirement control changed unavailable inputs: ' + label)
                    results[label] = {'exit_status': status, 'diagnostic': message, 'metadata': identity(metadata),
                                      'record': identity(record), 'metadata_origin': 'application' if case == 'explicit-application' else 'installed-package',
                                      'provider_root_absent': True, 'interpreter_directories_absent': True,
                                      'output_protected': protected, 'output_before': identity(SENTINEL) if state == 'existing-output' else None,
                                      'output_after': identity(regular_bytes(output)) if state == 'existing-output' else None}
    compatible = {}
    for mode in MODES:
        directory = args.output / ('compatible.' + mode)
        directory.mkdir()
        with tempfile.TemporaryDirectory(prefix='glue-requirements-compatible-') as temporary:
            scratch = Path(temporary)
            venv, application = copy_inputs(args.prepared, scratch)
            metadata, record = mutate(venv, application, expected, COMPATIBLE)
            projected = dict(expected)
            projected['app/python/' + METADATA] = metadata
            mdurl = {name.removeprefix('app/python/'): data for name, data in projected.items()
                     if name.startswith(('app/python/mdurl/', 'app/python/' + DIST + '/'))}
            projected['app/python/' + RECORD] = normalized_record(mdurl)
            output = scratch / 'compatible.glue'
            status, stdout, stderr = invoke(command(args, venv, application, args.provider_root, output, mode), directory)
            require(status == 0 and not stderr, 'compatible requirement build failed; see ' + str(directory))
            compatible[mode] = verify_archive(output, projected, strict_json(stdout), mode, record)
    require(compatible['venv'] == compatible['explicit-site-packages'], 'compatible input forms produced different bytes')
    report = {'schema_version': 0, 'glue': binary, 'template': identity(template_bytes), 'prepared': preparation,
              'hostile_variants': len(CASES), 'hostile_controls': len(results), 'input_modes': list(MODES),
              'absent_output_controls': len(CASES) * len(MODES), 'existing_output_controls': len(CASES) * len(MODES),
              'provider_absent_controls': len(results), 'valid_builds': len(compatible),
              'compatible_requirement': COMPATIBLE, 'compatible': compatible, 'results': results,
              'package_copies_retained': False, 'successful_archives_retained': False}
    require(report['hostile_controls'] == 32 and report['valid_builds'] == 2, 'control counters differ')
    write_json(args.output / 'audit.json', report)
    return report


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ('glue', 'template', 'provider-root', 'prepared', 'output'):
        parser.add_argument('--' + name, required=True, type=Path)
    args = parser.parse_args()
    try:
        report = audit(args)
        print(json.dumps({key: report[key] for key in ('hostile_variants', 'hostile_controls', 'absent_output_controls',
                                                     'existing_output_controls', 'provider_absent_controls', 'valid_builds')}, sort_keys=True))
    except (OSError, ValueError, KeyError, TypeError, StopIteration, csv.Error, zipfile.BadZipFile, subprocess.TimeoutExpired) as error:
        print('Requires-Python CLI audit failed: ' + str(error), file=sys.stderr)
        return 1
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
