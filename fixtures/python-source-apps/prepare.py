#!/usr/bin/env python3
"""Project verified stock runtime inputs plus app files into ordinary build inputs.

This portable build-time helper never executes Python payloads, downloads inputs
or emits an archive. The product `glue build` packages its root and manifest.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import stat
import struct
import sys
import zipfile

BUILD = 'pbs-20261009-cpython-3.13.16-pgo-lto-bundled-source-apps-v1'
VARIANT = 'pgo+lto-full/bundled-source-apps-v1'
FROZEN_SHA = '6a41fc38141d45c5197adfc1b0ee740c6244ea681742c205b8aa7b8449d865d7'
LIBRARY_SHA = '42be968275d5be2d9e632ec9ef6790dd2c10f1d4a710ad1028fc2b687242f219'
HERE = Path(__file__).resolve().parent


def require(condition, message):
    if not condition:
        raise ValueError(message)


def sha(payload):
    return hashlib.sha256(payload).hexdigest()


def canonical(key):
    require(isinstance(key, str) and 0 < len(key) <= 4096 and key.isascii() and len(key.split('/')) <= 64 and
            not any(ord(char) < 32 or ord(char) == 127 or char in '\\<>:"|?*' for char in key), 'noncanonical ASCII resource path')
    for part in key.split('/'):
        stem = part.split('.')[0].upper()
        require(part not in ('', '.', '..') and len(part) <= 255 and not part.endswith((' ', '.')) and
                stem not in {'CON', 'PRN', 'AUX', 'NUL', 'CONIN$', 'CONOUT$'} and
                not re.fullmatch(r'(?:COM|LPT)[1-9]', stem), 'nonportable resource path component')
    return key


def bounded(path, limit):
    with path.open('rb') as stream:
        payload = stream.read(limit + 1)
    require(len(payload) <= limit, 'input grew beyond its bounded payload budget')
    return payload


def walk_files(directory):
    stack, visited, pending_bytes = [directory], 0, len(str(directory))
    while stack:
        current = stack.pop()
        pending_bytes -= len(str(current))
        with os.scandir(current) as entries:
            for item in entries:
                visited += 1
                require(visited <= 65536, 'application tree exceeds bounded visited-node budget')
                path = Path(item.path)
                canonical(path.relative_to(directory).as_posix())
                metadata = item.stat(follow_symlinks=False)
                require(not stat.S_ISLNK(metadata.st_mode), 'application contains a symlink')
                if stat.S_ISDIR(metadata.st_mode):
                    pending_bytes += len(str(path))
                    require(pending_bytes <= 32 * 1024 * 1024, 'application directory metadata exceeds bounded walk budget')
                    stack.append(path)
                else:
                    require(stat.S_ISREG(metadata.st_mode), 'application contains a nonregular file')
                    yield path, metadata.st_size


def prepare(base, application, output, app_id, entry, component):
    require(re.fullmatch(r'[A-Za-z0-9._-]{1,128}', app_id) is not None, 'app ID must be bounded ASCII')
    require(re.fullmatch(r'[A-Za-z0-9._-]{1,128}', component) is not None, 'component ID must be bounded ASCII')
    canonical(entry)
    require(entry.startswith('app/') and entry.endswith('.py'), 'entry must be an app Python source')
    require(not output.exists(), 'staging output already exists')
    require(application.is_dir() and not application.is_symlink(), 'application root must be an ordinary directory')
    app_paths = {}
    app_bytes = 0
    for path, size in walk_files(application):
        key = canonical(path.relative_to(application).as_posix())
        require(key.startswith('app/'), 'application payload must stay under app/')
        lower = key.lower()
        require('__pycache__' not in lower.split('/') and not lower.endswith(('.pyc', '.pyo', '.so', '.pyd', '.dll', '.dylib', '.a', '.o', '.exe', '.node', '.bundle', '.lib')) and '.so.' not in lower.rsplit('/', 1)[-1],
                'bytecode, cache and native payloads are outside source profile')
        require(size <= (64 * 1024 if key == entry else 4 * 1024 * 1024), 'individual app payload exceeds its bound')
        app_paths[key] = (path, size)
        app_bytes += size
        require(len(app_paths) <= 1024 and app_bytes <= 8 * 1024 * 1024, 'application inventory exceeds source profile bounds')
    require(0 < len(app_paths) <= 1024 and app_bytes <= 8 * 1024 * 1024,
            'application inventory exceeds source profile bounds')
    require(entry in app_paths, 'entry source is absent')
    app_files = {key: bounded(path, size) for key, (path, size) in sorted(app_paths.items())}
    require(all(len(app_files[key]) == size for key, (_, size) in app_paths.items()), 'application input size changed')
    require(base.stat().st_size <= 128 * 1024 * 1024, 'base archive exceeds bounded input')
    with base.open('rb') as stream:
        locator = stream.read(64)
        require(len(locator) == 64 and locator[:8] == b'GLUERS00', 'base has no valid locator')
        length = struct.unpack_from('<Q', locator, 16)[0]
        require(0 < length <= 2 * 1024 * 1024, 'base manifest exceeds bounded input')
        raw = stream.read(length)
        require(len(raw) == length and hashlib.sha256(raw).digest() == locator[32:64], 'base manifest hash differs')
    manifest = json.loads(raw)
    require(manifest['app_id'] == 'stock-pbs-archive-imports' and not manifest['native_modules'] and not manifest['host_imports'],
            'base is not the exact controlled bundled archive')
    stock = {key: spec for key, spec in manifest['resources'].items() if not key.startswith('app/')}
    pins = json.loads((HERE.parent / 'python-imports/stdlib-pins.json').read_text())
    expected_sources = {'stdlib/' + key: value for key, value in pins['files'].items()}
    require(len(expected_sources) == 2174 and set(stock) == set(expected_sources) | {'python/libpython3.13.so.1.0', 'python/frozen.json', 'python/archive-importer.py'},
            'base runtime/source inventory differs')
    bootstrap = bounded(HERE.parent / 'python-imports/bootstrap.py', 256 * 1024)
    exact = {'python/libpython3.13.so.1.0': (73563968, LIBRARY_SHA, 'stored'),
             'python/frozen.json': (139523, FROZEN_SHA, 'stored'),
             'python/archive-importer.py': (len(bootstrap), sha(bootstrap), 'deflate')}
    for key, value in expected_sources.items():
        exact[key] = value['size'], value['sha256'], 'deflate'
    for key, (size, digest, compression) in exact.items():
        require(stock[key] == {'size': size, 'sha256': digest, 'compression': compression}, 'base stock declaration differs: ' + key)
    root = output / 'root'
    # Validate every declared preserved member before publishing staging files.
    with zipfile.ZipFile(base) as archive:
        require(len(archive.infolist()) == len(manifest['resources']) and set(archive.namelist()) == set(manifest['resources']),
                'base ZIP inventory differs from manifest')
        for key, spec in stock.items():
            info = archive.getinfo(key)
            require(info.file_size == spec['size'] and info.compress_type == (zipfile.ZIP_STORED if spec['compression'] == 'stored' else zipfile.ZIP_DEFLATED),
                    'base stock ZIP member differs: ' + key)
            payload = archive.read(key)
            require(len(payload) == spec['size'] and sha(payload) == spec['sha256'], 'base stock bytes differ: ' + key)
        root.mkdir(parents=True)
        for key in stock:
            destination = root / canonical(key)
            destination.parent.mkdir(parents=True, exist_ok=True)
            destination.write_bytes(archive.read(key))
    for key, payload in app_files.items():
        destination = root / key
        destination.parent.mkdir(parents=True, exist_ok=True)
        destination.write_bytes(payload)
    manifest['app_id'] = app_id
    manifest['entrypoint'] = component
    manifest['components'] = {component: {'entry_point': entry, 'runtime': 'python', 'native_modules': []}}
    manifest['resources'] = stock | {key: {'size': len(payload), 'sha256': sha(payload), 'compression': 'stored'} for key, payload in app_files.items()}
    runtime = manifest['runtimes']['python']
    runtime['build_id'] = BUILD
    runtime['provisioning']['source']['variant'] = VARIANT
    (output / 'manifest.json').write_text(json.dumps(manifest, sort_keys=True, separators=(',', ':')) + '\n')
    digest, total = hashlib.sha256(), 0
    with base.open('rb') as stream:
        while block := stream.read(min(1024 * 1024, 128 * 1024 * 1024 + 1 - total)):
            total += len(block)
            require(total <= 128 * 1024 * 1024, 'base input grew beyond its bounded budget')
            digest.update(block)
    base_sha = digest.hexdigest()
    (output / 'prepare-summary.json').write_text(json.dumps({'schema_version': 0, 'app_id': app_id, 'component': component, 'entry': entry,
        'base_sha256': base_sha, 'stock_resources': len(stock), 'application_resources': len(app_files),
        'application_bytes': sum(map(len, app_files.values())), 'application': {key: manifest['resources'][key] for key in app_files}}, indent=2, sort_keys=True) + '\n')


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('base', type=Path)
    parser.add_argument('application', type=Path)
    parser.add_argument('output', type=Path)
    parser.add_argument('--app-id', required=True)
    parser.add_argument('--entry', required=True)
    parser.add_argument('--component', default='launch')
    args = parser.parse_args()
    try:
        prepare(args.base, args.application, args.output, args.app_id, args.entry, args.component)
    except (OSError, ValueError, KeyError, struct.error, zipfile.BadZipFile) as error:
        print('source application preparation rejected: ' + str(error), file=sys.stderr)
        return 1
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
