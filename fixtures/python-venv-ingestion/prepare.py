#!/usr/bin/env python3
"""Reproduce a tiny pure wheel and install it offline into a real Python 3.13 venv.

This is evidence preparation, not product dependency installation. The product
builder reads the resulting files without running pip or the venv interpreter.
"""
from __future__ import annotations

import argparse
import base64
import csv
import hashlib
import io
import json
import os
from pathlib import Path
import subprocess
import sys
import zipfile

HERE = Path(__file__).resolve().parent
SOURCE = HERE.parent / 'python-metadata' / 'input'
DIST = 'glue_meta_demo-1.2.3.dist-info'
WHEEL_NAME = 'glue_meta_demo-1.2.3-py3-none-any.whl'
RECORD = DIST + '/RECORD'
WHEEL = b'Wheel-Version: 1.0\nGenerator: glue-offline-evidence-v1\nRoot-Is-Purelib: true\nTag: py3-none-any\n'
ENTRY_POINTS = (SOURCE / 'app/python' / DIST / 'entry_points.txt').read_bytes() + b'\n[console_scripts]\nglue-meta-demo = glue_meta_demo:plugin\n'


def identity(payload):
    return {'size': len(payload), 'sha256': hashlib.sha256(payload).hexdigest()}


def record_hash(payload):
    return 'sha256=' + base64.urlsafe_b64encode(hashlib.sha256(payload).digest()).rstrip(b'=').decode('ascii')


def record_bytes(files):
    output = io.StringIO(newline='')
    writer = csv.writer(output, lineterminator='\n')
    for name in sorted(set(files) | {RECORD}):
        writer.writerow([name, '', ''] if name == RECORD else [name, record_hash(files[name]), str(len(files[name]))])
    return output.getvalue().encode('utf-8')


def wheel_files():
    source = SOURCE / 'app/python'
    files = {path.relative_to(source).as_posix(): path.read_bytes() for path in sorted(source.rglob('*')) if path.is_file()}
    files[DIST + '/WHEEL'] = WHEEL
    files[DIST + '/entry_points.txt'] = ENTRY_POINTS
    files[RECORD] = record_bytes(files)
    return files


def wheel_bytes():
    output = io.BytesIO()
    with zipfile.ZipFile(output, 'w', compression=zipfile.ZIP_STORED) as archive:
        for name, payload in sorted(wheel_files().items()):
            member = zipfile.ZipInfo(name, date_time=(1980, 1, 1, 0, 0, 0))
            member.create_system = 3
            member.external_attr = 0o100644 << 16
            member.compress_type = zipfile.ZIP_STORED
            archive.writestr(member, payload)
    return output.getvalue()


def wheel_provenance():
    source = SOURCE / 'app/python'
    return {
        'schema_version': 0,
        'wheel': WHEEL_NAME,
        'wheel_identity': identity(wheel_bytes()),
        'construction': {'zip_compression': 'stored', 'zip_timestamp': '1980-01-01T00:00:00', 'file_mode': '0100644', 'order': 'lexicographic'},
        'source_fixture': 'fixtures/python-metadata/input/app/python',
        'source_files': {path.relative_to(source).as_posix(): identity(path.read_bytes()) for path in sorted(source.rglob('*')) if path.is_file()},
        'wheel_files': {name: identity(payload) for name, payload in sorted(wheel_files().items())},
    }


def installed_projection(venv):
    """Independent expected projection of this exact pip-installed fixture."""
    site = venv / 'lib/python3.13/site-packages'
    rows = list(csv.reader(io.StringIO((site / RECORD).read_text(encoding='utf-8'), newline='')))
    files, omissions = {}, []
    for row in rows:
        if len(row) != 3:
            raise ValueError('pip RECORD did not have exactly three columns')
        name, hash_value, size = row
        if name == '../../../bin/glue-meta-demo':
            omissions.append({'path': name, 'kind': 'console-wrapper', 'hash': hash_value, 'size': size})
            continue
        if '__pycache__' in name.split('/') and name.endswith('.pyc'):
            omissions.append({'path': name, 'kind': 'bytecode', 'hash': hash_value, 'size': size})
            continue
        if name.startswith('/') or '..' in name.split('/') or '\\' in name:
            raise ValueError('unexpected installed fixture path: ' + name)
        path = site / name
        if not path.is_file() or path.is_symlink() or name in files:
            raise ValueError('unexpected installed fixture file: ' + name)
        payload = path.read_bytes()
        if name != RECORD and hash_value and hash_value != record_hash(payload):
            raise ValueError('pip installed fixture hash differs: ' + name)
        if size and int(size) != len(payload):
            raise ValueError('pip installed fixture size differs: ' + name)
        files[name] = payload
    if len(files) != 10 or len(omissions) != 3 or sum(item['kind'] == 'bytecode' for item in omissions) != 2:
        raise ValueError('pip-installed fixture inventory changed')
    expected_members = set(wheel_files()) | {DIST + '/INSTALLER', DIST + '/REQUESTED'}
    if set(files) != expected_members or files[DIST + '/INSTALLER'] != b'pip\n' or files[DIST + '/REQUESTED'] != b'':
        raise ValueError('pip-installed metadata inventory changed')
    for name, payload in wheel_files().items():
        if name != RECORD and files[name] != payload:
            raise ValueError('pip changed a wheel payload: ' + name)
    files[RECORD] = record_bytes(files)
    return files, rows, omissions


def publish_expected(venv, destination):
    files, rows, omissions = installed_projection(venv)
    destination.mkdir(parents=True, exist_ok=False)
    app = (SOURCE / 'app/main.py').read_bytes()
    (destination / 'app').mkdir()
    (destination / 'app/main.py').write_bytes(app)
    for name, payload in sorted(files.items()):
        output = destination / 'app/python' / name
        output.parent.mkdir(parents=True, exist_ok=True)
        output.write_bytes(payload)
    return files, rows, omissions


def run(command, log, environment):
    result = subprocess.run(command, capture_output=True, env=environment, check=False)
    log.write_bytes(result.stdout + result.stderr)
    if result.returncode:
        raise ValueError('offline evidence preparation failed: ' + str(command[0]) + '; see ' + str(log))


def install(producer, output):
    if sys.version_info[:2] != (3, 13):
        raise ValueError('installation evidence must run under stock Python 3.13')
    producer = producer.absolute()
    output = output.absolute()
    output.mkdir(parents=True, exist_ok=False)
    wheel = output / WHEEL_NAME
    wheel.write_bytes(wheel_bytes())
    python = producer / 'bin/python3.13'
    environment = dict(os.environ)
    for name in ('PYTHONPATH', 'PYTHONHOME', 'PYTHONDONTWRITEBYTECODE', 'PIP_TARGET', 'PIP_PREFIX', 'PIP_USER'):
        environment.pop(name, None)
    environment['PIP_CONFIG_FILE'] = '/dev/null'
    environment['LD_LIBRARY_PATH'] = str(producer / 'lib')
    commands = [
        [str(python), '-I', '-m', 'venv', '--without-pip', str(output / 'venv')],
        [str(python), '-I', '-m', 'pip', '--isolated', '--disable-pip-version-check', '--python', str(output / 'venv/bin/python'), 'install', '--no-index', '--find-links', str(output), '--no-deps', '--no-cache-dir', 'glue-meta-demo==1.2.3'],
    ]
    for index, command in enumerate(commands):
        run(command, output / ('command-' + str(index) + '.txt'), environment)
    files, rows, omissions = publish_expected(output / 'venv', output / 'expected-input')
    application = output / 'application/app'
    application.mkdir(parents=True)
    (application / 'main.py').write_bytes((SOURCE / 'app/main.py').read_bytes())
    site = output / 'venv/lib/python3.13/site-packages'
    installed_files = {path.relative_to(site).as_posix(): identity(path.read_bytes()) for path in sorted(site.rglob('*')) if path.is_file()}
    provenance = {
        'schema_version': 0, 'python_version': list(sys.version_info[:3]), 'pip_version': (producer / 'lib/python3.13/site-packages/pip/__init__.py').read_text().split('__version__ = ', 1)[1].splitlines()[0].strip('"'),
        'commands': commands, 'wheel': wheel_provenance(),
        'venv_configuration': (output / 'venv/pyvenv.cfg').read_text(),
        'original_record_identity': identity((site / RECORD).read_bytes()),
        'original_record_rows': rows, 'installed_files': installed_files,
        'omissions': omissions,
        'wrapper_identity': identity((output / 'venv/bin/glue-meta-demo').read_bytes()),
        'expected_application': {'app/main.py': identity((SOURCE / 'app/main.py').read_bytes())} | {'app/python/' + name: identity(payload) for name, payload in sorted(files.items())},
    }
    (output / 'installation-provenance.json').write_text(json.dumps(provenance, indent=2, sort_keys=True) + '\n')
    return provenance


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    sub = parser.add_subparsers(dest='operation', required=True)
    wheel = sub.add_parser('wheel')
    wheel.add_argument('output', type=Path)
    wheel.add_argument('--verify', action='store_true')
    installation = sub.add_parser('install')
    installation.add_argument('producer', type=Path)
    installation.add_argument('output', type=Path)
    projection = sub.add_parser('project')
    projection.add_argument('venv', type=Path)
    projection.add_argument('output', type=Path)
    args = parser.parse_args()
    try:
        if args.operation == 'wheel':
            payload = wheel_bytes()
            if args.verify:
                if args.output.read_bytes() != payload:
                    raise ValueError('wheel bytes differ from deterministic source construction')
            else:
                with args.output.open('xb') as stream:
                    stream.write(payload)
            print(json.dumps(wheel_provenance(), sort_keys=True))
        elif args.operation == 'install':
            print(json.dumps(install(args.producer, args.output), sort_keys=True))
        else:
            files, rows, omissions = publish_expected(args.venv, args.output)
            print(json.dumps({'files': {name: identity(payload) for name, payload in sorted(files.items())}, 'original_record_rows': rows, 'omissions': omissions}, sort_keys=True))
    except (OSError, ValueError, KeyError, csv.Error) as error:
        print('venv evidence preparation rejected: ' + str(error), file=sys.stderr)
        return 1
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
