#!/usr/bin/env python3
"""Stage one exact metadata application and owned runtime rejection controls.

The application is archive data. This helper does not execute the input runtime
or application; target Python is acquired only by the separately traced runner.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path
import shutil
import struct
import sys
import zipfile

HERE = Path(__file__).resolve().parent
APPLICATION = HERE / 'application'
APP_ID, ENTRY, COMPONENT = 'python.stripped-host', 'app/main.py', 'launch'
DIRECTORY = '/build-target/relocated Python stripped host'
PROGRAM = DIRECTORY + '/glue'
PREFIX = '/build-target/Python stripped host'
OLD_PREFIX = '/build-target/Python unstripped host'
MODES = ('stripped', 'unstripped', 'missing-library', 'wrong-library', 'corrupt-library', 'corrupt-entry', 'wrong-profile')
LIBRARY = 'lib/libpython3.13.so.1.0'
BUILD_IDS = {'stripped': 'pbs-20261009-cpython-3.13.16-pgo-lto-host-install-stripped-metadata-apps-v1',
             'unstripped': 'pbs-20261009-cpython-3.13.16-pgo-lto-host-install-metadata-apps-v1'}


def require(condition, message):
    if not condition:
        raise ValueError(message)


def identity(payload):
    return {'size': len(payload), 'sha256': hashlib.sha256(payload).hexdigest()}


def prefix_for(mode):
    require(mode in MODES, 'unknown stripped runtime fixture')
    return OLD_PREFIX if mode == 'unstripped' else PREFIX + (' ' + mode if mode in
            ('missing-library', 'wrong-library', 'corrupt-library') else '')


def profile_for(mode):
    require(mode in MODES, 'unknown stripped runtime fixture')
    return 'unstripped' if mode in ('unstripped', 'wrong-profile') else 'stripped'


def expected_application(mode=None):
    if mode is not None:
        require(mode in MODES, 'unknown application fixture')
    return {path.relative_to(APPLICATION).as_posix(): identity(path.read_bytes()) | {'compression': 'stored'}
            for path in sorted(APPLICATION.rglob('*')) if path.is_file()}


def stage(template, output, mode):
    manifest = json.loads((template / 'manifest.json').read_bytes())
    expected = BUILD_IDS[profile_for(mode)]
    require(manifest['runtimes']['python']['build_id'] == expected, 'runtime template provider identity differs')
    provision = manifest['runtimes']['python']['provisioning']
    require(provision['runtime_library'] == prefix_for(mode) + '/' + LIBRARY and
            provision['stdlib'] == prefix_for(mode) + '/lib/python3.13', 'runtime template paths differ')
    require(not output.exists() and output.parent.is_dir(), 'staging output must be fresh')
    output.mkdir()
    fixed = {'python/archive-importer.py': HERE.parent / 'python-imports/bootstrap.py',
             'python/archive-metadata.py': HERE.parent / 'python-metadata/bootstrap.py'}
    for relative, original in fixed.items():
        spec = identity(original.read_bytes()) | {'compression': 'deflate'}
        require(manifest['resources'][relative] == spec and (template / 'root' / relative).read_bytes() == original.read_bytes(),
                'runtime template helper bytes differ')
        destination = output / relative
        destination.parent.mkdir(parents=True, exist_ok=True)
        destination.write_bytes(original.read_bytes())
    for relative in expected_application():
        destination = output / relative
        destination.parent.mkdir(parents=True, exist_ok=True)
        destination.write_bytes((APPLICATION / relative).read_bytes())
    manifest['app_id'] = APP_ID
    manifest['components'][COMPONENT]['entry_point'] = ENTRY
    manifest['resources'] = {relative: identity(original.read_bytes()) | {'compression': 'deflate'}
                             for relative, original in fixed.items()} | expected_application()
    (output / 'manifest.json').write_text(json.dumps(manifest, indent=2, sort_keys=True) + '\n')
    return {'mode': mode, 'provider_build_id': expected, 'application': expected_application(),
            'manifest': identity((output / 'manifest.json').read_bytes())}


def corrupt_entry(archive, output):
    require(not output.exists(), 'corrupt archive output must be fresh')
    payload = bytearray(archive.read_bytes())
    magic, _ = struct.unpack_from('<8sI', payload)
    require(magic == b'GLUERS00', 'archive frame identity differs')
    # zipfile understands the product's prepended manifest frame and reports
    # absolute local offsets. No ZIP writer or manifest regeneration is used.
    with zipfile.ZipFile(archive) as zipped:
        entry = zipped.getinfo(ENTRY)
        require(entry.compress_type == zipfile.ZIP_STORED and zipped.read(ENTRY) == (APPLICATION / ENTRY).read_bytes(),
                'entry is not exact stored fixture source')
        header = struct.unpack_from('<IHHHHHIIIHH', payload, entry.header_offset)
        require(header[0] == 0x04034B50, 'stored entry local header differs')
        offset = entry.header_offset + 30 + header[-2] + header[-1]
        payload[offset] ^= 1
    output.write_bytes(payload)
    return {'corrupt_offset': offset, 'archive': identity(payload)}


def controls(prepared, unstripped):
    result = {}
    for mode in ('missing-library', 'wrong-library', 'corrupt-library'):
        destination = Path(prefix_for(mode))
        require(not destination.exists(), 'runtime control tree must be fresh')
        shutil.copytree(prepared, destination)
        parent = destination / 'lib'
        parent.chmod(0o755)
        image = destination / LIBRARY
        data = image.read_bytes()
        image.unlink()
        if mode != 'missing-library':
            replacement = (unstripped / LIBRARY).read_bytes() if mode == 'wrong-library' else bytes([data[0] ^ 1]) + data[1:]
            image.write_bytes(replacement)
            image.chmod(0o444)
            os.utime(image, (1704067200, 1704067200))
        parent.chmod(0o555)
        result[mode] = {'prefix': str(destination), 'library': identity(image.read_bytes()) if image.exists() else None}
    return result


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    sub = parser.add_subparsers(dest='action', required=True)
    stager = sub.add_parser('stage')
    stager.add_argument('--template', required=True, type=Path)
    stager.add_argument('--output', required=True, type=Path)
    stager.add_argument('--mode', required=True, choices=MODES)
    damage = sub.add_parser('corrupt-entry')
    damage.add_argument('--archive', required=True, type=Path)
    damage.add_argument('--output', required=True, type=Path)
    rejected = sub.add_parser('controls')
    rejected.add_argument('--prepared', required=True, type=Path)
    rejected.add_argument('--unstripped', required=True, type=Path)
    args = parser.parse_args()
    try:
        result = stage(args.template, args.output, args.mode) if args.action == 'stage' else (
                 corrupt_entry(args.archive, args.output) if args.action == 'corrupt-entry' else
                 controls(args.prepared, args.unstripped))
        print(json.dumps(result, sort_keys=True))
        return 0
    except (OSError, ValueError, KeyError, zipfile.BadZipFile) as error:
        print('stripped runtime fixture: ' + str(error), file=sys.stderr)
        return 1


if __name__ == '__main__':
    raise SystemExit(main())
