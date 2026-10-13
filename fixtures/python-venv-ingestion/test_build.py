#!/usr/bin/env python3
"""Independent product admission controls against a real offline installation."""
from __future__ import annotations

import argparse
import base64
import csv
import hashlib
import io
import json
from pathlib import Path
import shutil
import struct
import subprocess
import sys
import zipfile

HERE = Path(__file__).resolve().parent
DIST = 'glue_meta_demo-1.2.3.dist-info'
RECORD = DIST + '/RECORD'
SOURCE = 'glue_meta_demo/__init__.py'
ASSET = 'glue_meta_demo/data/message,one.txt'
SENTINEL = b'pre-existing output must remain unchanged\n'


def sha(payload):
    return hashlib.sha256(payload).hexdigest()


def record_hash(payload):
    return 'sha256=' + base64.urlsafe_b64encode(hashlib.sha256(payload).digest()).rstrip(b'=').decode('ascii')


def read_rows(site):
    return list(csv.reader(io.StringIO((site / RECORD).read_text(encoding='utf-8'), newline='')))


def write_rows(site, rows):
    output = io.StringIO(newline='')
    csv.writer(output, lineterminator='\n').writerows(rows)
    (site / RECORD).write_text(output.getvalue(), encoding='utf-8')


def add(site, name, payload):
    path = site / name
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(payload)
    rows = read_rows(site)
    rows.append([name, record_hash(payload), str(len(payload))])
    write_rows(site, rows)


def replace(site, name, payload):
    (site / name).write_bytes(payload)
    rows = read_rows(site)
    for row in rows:
        if row[0] == name:
            row[1:] = [record_hash(payload), str(len(payload))]
    write_rows(site, rows)


def change_row(site, name, field, value):
    rows = read_rows(site)
    next(row for row in rows if row[0] == name)[field] = value
    write_rows(site, rows)


def extra_distribution(site):
    directory = 'other_demo-1.0.dist-info'
    files = {
        directory + '/METADATA': b'Metadata-Version: 2.3\nName: Other-Demo\nVersion: 1.0\n',
        directory + '/WHEEL': b'Wheel-Version: 1.0\nRoot-Is-Purelib: true\nTag: py3-none-any\n',
    }
    output = io.StringIO(newline='')
    writer = csv.writer(output, lineterminator='\n')
    for name, payload in sorted(files.items()):
        path = site / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(payload)
        writer.writerow([name, record_hash(payload), str(len(payload))])
    writer.writerow([SOURCE, record_hash((site / SOURCE).read_bytes()), str((site / SOURCE).stat().st_size)])
    writer.writerow([directory + '/RECORD', '', ''])
    (site / directory / 'RECORD').write_text(output.getvalue(), encoding='utf-8')


def mutate(case, venv, application, output):
    site = venv / 'lib/python3.13/site-packages'
    if case == 'native':
        add(site, 'glue_meta_demo/native.so', b'unsupported native image\n')
    elif case == 'pth':
        add(site, 'path-hook.pth', b'import omitted_hook_must_not_execute\n')
    elif case == 'editable':
        add(site, DIST + '/direct_url.json', b'{"url":"file:///unavailable/editable/source","dir_info":{"editable":true}}\n')
    elif case == 'egg-info':
        (site / 'legacy.egg-info').mkdir()
        (site / 'legacy.egg-info/PKG-INFO').write_text('Name: Legacy\nVersion: 1\n')
    elif case == 'traversal':
        change_row(site, SOURCE, 0, '../escape.py')
    elif case == 'absolute':
        change_row(site, SOURCE, 0, '/unavailable/absolute.py')
    elif case == 'unknown-wrapper':
        change_row(site, '../../../bin/glue-meta-demo', 0, '../../../bin/not-declared')
    elif case == 'missing':
        (site / SOURCE).unlink()
    elif case == 'bad-sha256':
        change_row(site, SOURCE, 1, 'sha256=' + 'A' * 43)
    elif case == 'bad-size':
        change_row(site, SOURCE, 2, str((site / SOURCE).stat().st_size + 1))
    elif case in ('duplicate-row', 'duplicate-cache', 'duplicate-wrapper'):
        rows = read_rows(site)
        name = SOURCE if case == 'duplicate-row' else '../../../bin/glue-meta-demo' if case == 'duplicate-wrapper' else next(row[0] for row in rows if row[0].endswith('.pyc'))
        rows.append(next(row[:] for row in rows if row[0] == name))
        write_rows(site, rows)
    elif case == 'shared-ownership':
        extra_distribution(site)
    elif case == 'unrecorded':
        (site / 'glue_meta_demo/unrecorded.txt').write_bytes(b'undeclared package bytes\n')
    elif case == 'symlink-file':
        target = venv.parent / 'external-resource.txt'
        target.write_bytes((site / ASSET).read_bytes())
        (site / ASSET).unlink()
        (site / ASSET).symlink_to(target)
    elif case == 'symlink-directory':
        target = venv.parent / 'external-data'
        shutil.move(str(site / 'glue_meta_demo/data'), target)
        (site / 'glue_meta_demo/data').symlink_to(target, target_is_directory=True)
    elif case == 'system-site-packages':
        path = venv / 'pyvenv.cfg'
        path.write_text(path.read_text().replace('include-system-site-packages = false', 'include-system-site-packages = true'))
    elif case == 'wrong-python-version':
        path = venv / 'pyvenv.cfg'
        path.write_text(path.read_text().replace('version = 3.13.16', 'version = 3.14.0'))
    elif case == 'ambiguous-layout':
        # Lib aliases lib on a case-insensitive builder. A second versioned
        # directory represents an actual ambiguity on both Mac and Linux.
        (venv / 'lib/python3.14/site-packages').mkdir(parents=True)
    elif case == 'wheel-platlib':
        name = DIST + '/WHEEL'
        replace(site, name, (site / name).read_bytes().replace(b'Root-Is-Purelib: true', b'Root-Is-Purelib: false'))
    elif case == 'wheel-wrong-tag':
        name = DIST + '/WHEEL'
        replace(site, name, (site / name).read_bytes().replace(b'Tag: py3-none-any', b'Tag: py314-none-any'))
    elif case == 'application-collision':
        path = application / 'app/python' / SOURCE
        path.parent.mkdir(parents=True)
        path.write_bytes((site / SOURCE).read_bytes())
    elif case == 'existing-output':
        output.write_bytes(SENTINEL)
    elif case == 'cache-native':
        add(site, 'glue_meta_demo/__pycache__/native.so', b'native payload inside cache directory\n')
    elif case == 'missing-metadata-row':
        write_rows(site, [row for row in read_rows(site) if row[0] != DIST + '/WHEEL'])
    elif case == 'malformed-csv':
        (site / RECORD).write_text('"unterminated,sha256=AAAA,1\n')
    elif case == 'metadata-bound':
        name = DIST + '/METADATA'
        replace(site, name, (site / name).read_bytes() + b'x' * (64 * 1024))
    elif case == 'byte-budget':
        for index in range(3):
            add(site, 'glue_meta_demo/data/large-' + str(index) + '.txt', b'x' * (4 * 1024 * 1024))
    elif case == 'entry-bound':
        (application / 'app/main.py').write_bytes(b'#' + b'x' * (64 * 1024))
    else:
        raise ValueError('unknown control: ' + case)


CASES = (
    'native', 'pth', 'editable', 'egg-info', 'traversal', 'absolute', 'unknown-wrapper',
    'missing', 'bad-sha256', 'bad-size', 'duplicate-row', 'duplicate-cache',
    'duplicate-wrapper', 'shared-ownership', 'unrecorded', 'symlink-file',
    'symlink-directory', 'system-site-packages', 'wrong-python-version',
    'ambiguous-layout', 'wheel-platlib', 'wheel-wrong-tag', 'application-collision',
    'existing-output', 'cache-native', 'missing-metadata-row', 'malformed-csv',
    'metadata-bound', 'byte-budget', 'entry-bound',
)


def command(args, venv, application, output, explicit_site=False):
    inputs = ['--site-packages', str(venv / 'lib/python3.13/site-packages')] if explicit_site else ['--venv', str(venv)]
    return [str(args.glue), 'build-python', '--provider-template', str(args.template), '--provider-root', str(args.provider_root), '--app', str(application), *inputs, '--app-id', 'distribution.metadata', '--entry', 'app/main.py', '--output', str(output), '--json']


def verify_archive(path):
    expected = json.loads((HERE / 'expected-inventory.json').read_text())['files']
    with path.open('rb') as stream:
        locator = stream.read(64)
        if locator[:8] != b'GLUERS00':
            raise ValueError('archive locator changed')
        length = struct.unpack_from('<Q', locator, 16)[0]
        raw = stream.read(length)
        if sha(raw) != locator[32:64].hex():
            raise ValueError('archive manifest hash differs')
        manifest = json.loads(raw)
    application = {name: spec for name, spec in manifest['resources'].items() if name.startswith('app/')}
    if application != {name: spec | {'compression': 'stored'} for name, spec in expected.items()}:
        raise ValueError('product application inventory differs from independent projection')
    with zipfile.ZipFile(path) as archive:
        for name in expected:
            if archive.read(name) != (HERE / 'expected-input' / name).read_bytes():
                raise ValueError('product normalized bytes differ: ' + name)
    return {'archive_bytes': path.stat().st_size, 'archive_sha256': sha(path.read_bytes()), 'application_files': len(application)}


def invoke(command_value, directory):
    result = subprocess.run(command_value, capture_output=True, check=False)
    (directory / 'stdout.txt').write_bytes(result.stdout)
    (directory / 'stderr.txt').write_bytes(result.stderr)
    (directory / 'exit-status.txt').write_text(str(result.returncode) + '\n')
    (directory / 'command.json').write_text(json.dumps(command_value, indent=2) + '\n')
    return result


def audit(args):
    args.output.mkdir(parents=True, exist_ok=False)
    results = {}
    for mode in ('venv', 'explicit-site-packages'):
        directory = args.output / mode
        directory.mkdir()
        archive = directory / 'application.glue'
        result = invoke(command(args, args.prepared / 'venv', args.prepared / 'application', archive, mode == 'explicit-site-packages'), directory)
        if result.returncode != 0 or result.stderr:
            raise ValueError('valid ' + mode + ' failed; see ' + str(directory))
        results[mode] = {'exit_status': 0, 'output': verify_archive(archive), 'report': json.loads(result.stdout)}
    if results['venv']['output'] != results['explicit-site-packages']['output']:
        raise ValueError('venv and explicit package-directory archives differ')
    for case in CASES:
        directory = args.output / case
        directory.mkdir()
        venv, application, output = directory / 'venv', directory / 'application', directory / 'application.glue'
        shutil.copytree(args.prepared / 'venv', venv, symlinks=True)
        shutil.copytree(args.prepared / 'application', application)
        mutate(case, venv, application, output)
        result = invoke(command(args, venv, application, output), directory)
        protected = output.is_file() and output.read_bytes() == SENTINEL if case == 'existing-output' else not output.exists()
        if result.returncode != 1 or result.stdout or not result.stderr or not protected:
            raise ValueError('hostile ' + case + ' did not reject with protected output; see ' + str(directory))
        results[case] = {'exit_status': result.returncode, 'stderr': result.stderr.decode('utf-8'), 'output_protected': protected}
        shutil.rmtree(venv)
        shutil.rmtree(application)
        for external in ('external-resource.txt', 'external-data'):
            path = directory / external
            if path.is_dir():
                shutil.rmtree(path)
            elif path.exists():
                path.unlink()
    report = {'schema_version': 0, 'valid_builds': 2, 'hostile_controls': len(CASES), 'results': results}
    (args.output / 'audit.json').write_text(json.dumps(report, indent=2, sort_keys=True) + '\n')
    return report


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ('glue', 'template', 'provider-root', 'prepared', 'output'):
        parser.add_argument('--' + name, required=True, type=Path)
    args = parser.parse_args()
    try:
        report = audit(args)
    except (OSError, ValueError, KeyError, TypeError, csv.Error, zipfile.BadZipFile) as error:
        print('installed-input build audit failed: ' + str(error), file=sys.stderr)
        return 1
    print(json.dumps({'valid_builds': report['valid_builds'], 'hostile_controls': report['hostile_controls']}, sort_keys=True))
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
