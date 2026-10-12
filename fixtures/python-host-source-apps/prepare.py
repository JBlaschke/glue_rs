#!/usr/bin/env python3
"""Stage explicit pinned host sources and app-only product build inputs.

This bounded build-time helper copies verified bytes. It neither executes app
source nor discovers/downloads providers. ``glue build`` packages each stage.
"""
from __future__ import annotations

import argparse
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import re
import shutil
import struct
import sys
import zipfile

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[1]
SPEC = importlib.util.spec_from_file_location('paired_source_preparer', HERE.parent / 'python-source-apps/prepare.py')
PAIRED = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(PAIRED)
require, canonical, bounded, walk_files = PAIRED.require, PAIRED.canonical, PAIRED.bounded, PAIRED.walk_files
BUILD = 'pbs-20261009-cpython-3.13.16-pgo-lto-host-source-apps-v1'
LIBRARY = 'lib/libpython3.13.so.1.0'
STDLIB = 'lib/python3.13'
CONTROL_SOURCE = 'test/xpickle_worker.py'
CONTROL_CACHE = 'test/test_importlib/namespace_pkgs/module_and_namespace_package/__pycache__'
MODES = ('missing-source', 'wrong-source', 'deep-cache', 'startup-native', 'startup-bytecode', 'missing-library')
LURES = {
    'glue_host_extra.py': b'raise RuntimeError("unverified host source imported")\n',
    'glue_host_extra.pyc': b'unsupported unverified host bytecode\n',
    'glue_host_extra.cpython-313-aarch64-linux-gnu.so': b'unsupported unverified native image\n',
    'simple_value.py': b'answer = -1\n',
    'report_data/__init__.py': b'raise RuntimeError("host package collision imported")\n',
    'report_data/absent.py': b'raise RuntimeError("host owned-child fallback imported")\n',
    'report_parts/extra.py': b'value = -1\n',
    'report_parts/missing.py': b'raise RuntimeError("host namespace fallback imported")\n',
    'xml/etree/absent.py': b'raise RuntimeError("host stdlib descendant fallback imported")\n',
}


def sha(payload):
    return hashlib.sha256(payload).hexdigest()


def identity(path):
    with path.open('rb') as stream:
        digest = hashlib.file_digest(stream, 'sha256').hexdigest()
    return {'size': path.stat().st_size, 'sha256': digest}


def host_prefix(value):
    pins = json.loads((HERE.parent / 'python-imports/stdlib-pins.json').read_text())['files']
    suffixes = {STDLIB + '/' + key for key in pins}
    parents = {str(Path(key).parent) for key in pins}
    suffixes.update(STDLIB + ('/' + parent if parent != '.' else '') + '/__pycache__' for parent in parents)
    require(isinstance(value, str) and value.startswith('/') and value != '/' and value.isascii() and
            all(len(value + '/' + suffix) <= 4096 for suffix in suffixes) and len(value.split('/')) - 1 + 204 <= 256 and not value.endswith('/') and
            not any(ord(c) < 32 or ord(c) == 127 or c == '\\' for c in value) and
            all(part not in ('', '.', '..') for part in value.split('/')[1:]), 'noncanonical absolute ASCII host prefix')
    return value


def stock(base):
    require(base.is_file() and not base.is_symlink() and base.stat().st_size <= 128 * 1024 * 1024,
            'base archive is absent, a symlink or exceeds its bound')
    with base.open('rb') as stream:
        locator = stream.read(64)
        require(len(locator) == 64 and locator[:8] == b'GLUERS00' and locator[8:16] == b'\0' * 8, 'invalid base locator')
        length, payload_length = struct.unpack_from('<QQ', locator, 16)
        require(0 < length <= 1024 * 1024 and 64 + length + payload_length == base.stat().st_size, 'invalid base regions')
        raw = stream.read(length)
        require(len(raw) == length and hashlib.sha256(raw).digest() == locator[32:64], 'base manifest hash differs')
    manifest = json.loads(raw)
    require(manifest['app_id'] == 'stock-pbs-archive-imports' and not manifest['native_modules'] and not manifest['host_imports'],
            'base must be the original controlled bundled import archive')
    pins = json.loads((HERE.parent / 'python-imports/stdlib-pins.json').read_text())
    require(len(pins['files']) == 2174, 'stock source inventory differs')
    helper = bounded(HERE.parent / 'python-imports/bootstrap.py', 256 * 1024)
    specs = {'stdlib/' + key: {'size': value['size'], 'sha256': value['sha256'], 'compression': 'deflate'} for key, value in pins['files'].items()}
    specs.update({'python/libpython3.13.so.1.0': {'size': 73563968, 'sha256': PAIRED.LIBRARY_SHA, 'compression': 'stored'},
                  'python/frozen.json': {'size': 139523, 'sha256': PAIRED.FROZEN_SHA, 'compression': 'stored'},
                  'python/archive-importer.py': {'size': len(helper), 'sha256': sha(helper), 'compression': 'deflate'}})
    require({key: spec for key, spec in manifest['resources'].items() if not key.startswith('app/')} == specs, 'base stock declarations differ')
    with zipfile.ZipFile(base) as archive:
        infos = archive.infolist()
        require(len(infos) == len(manifest['resources']) and set(archive.namelist()) == set(manifest['resources']), 'base ZIP inventory differs')
        for key, spec in specs.items():
            info = archive.getinfo(key)
            require(info.file_size == spec['size'] and info.compress_type == (zipfile.ZIP_STORED if spec['compression'] == 'stored' else zipfile.ZIP_DEFLATED), 'base member size/compression differs')
            digest, total = hashlib.sha256(), 0
            with archive.open(key) as stream:
                while block := stream.read(min(65536, spec['size'] + 1 - total)):
                    total += len(block)
                    require(total <= spec['size'], 'base member exceeds pinned bound')
                    digest.update(block)
            require(total == spec['size'] and digest.hexdigest() == spec['sha256'], 'base member identity differs: ' + key)
    return manifest, pins['files'], helper


def app_inventory(application, entry):
    canonical(entry)
    require(entry.startswith('app/') and entry.endswith('.py'), 'entry must be an app Python source')
    require(application.is_dir() and not application.is_symlink(), 'application root must be an ordinary directory')
    files, total = {}, 0
    for path, size in walk_files(application):
        key = canonical(path.relative_to(application).as_posix())
        lower = key.lower()
        require(key.startswith('app/') and '__pycache__' not in lower.split('/') and
                not lower.endswith(('.pyc', '.pyo', '.so', '.pyd', '.dll', '.dylib', '.a', '.o', '.exe', '.node', '.bundle', '.lib')) and '.so.' not in lower.rsplit('/', 1)[-1],
                'application contains unsupported bytecode/native/cache payload')
        require(size <= (64 * 1024 if key == entry else 4 * 1024 * 1024), 'individual app payload exceeds its bound')
        files[key] = path, size
        total += size
        require(len(files) <= 1024 and total <= 8 * 1024 * 1024, 'application inventory exceeds its bound')
    require(entry in files, 'entry source is absent')
    result = {key: bounded(path, size) for key, (path, size) in sorted(files.items())}
    require(all(len(result[key]) == size for key, (_, size) in files.items()), 'application input size changed')
    return result


def stage(base, application, output, prefix, app_id, entry, component):
    host_prefix(prefix)
    require(re.fullmatch(r'[A-Za-z0-9._-]{1,128}', app_id) is not None and re.fullmatch(r'[A-Za-z0-9._-]{1,128}', component) is not None, 'bounded ASCII app/component identity required')
    require(not output.exists(), 'staging output already exists')
    files = app_inventory(application, entry)
    manifest, _, helper = stock(base)
    files['python/archive-importer.py'] = helper
    manifest['app_id'], manifest['entrypoint'] = app_id, component
    manifest['components'] = {component: {'entry_point': entry, 'runtime': 'python', 'native_modules': []}}
    manifest['resources'] = {key: {'size': len(value), 'sha256': sha(value), 'compression': 'deflate' if key == 'python/archive-importer.py' else 'stored'} for key, value in files.items()}
    runtime = manifest['runtimes']['python']
    runtime['build_id'] = BUILD
    runtime['provisioning'] = {'mode': 'host', 'discovery': 'explicit_paths', 'runtime_library': prefix + '/' + LIBRARY, 'stdlib': prefix + '/' + STDLIB}
    for key, payload in files.items():
        target = output / 'root' / key
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_bytes(payload)
    (output / 'manifest.json').write_text(json.dumps(manifest, sort_keys=True, separators=(',', ':')) + '\n')
    (output / 'prepare-summary.json').write_text(json.dumps({'schema_version': 0, 'app_id': app_id, 'component': component, 'entry': entry, 'prefix': prefix,
        'base': identity(base), 'application_files': len(files) - 1, 'application_bytes': sum(len(v) for k, v in files.items() if k.startswith('app/')),
        'application': {key: spec for key, spec in manifest['resources'].items() if key.startswith('app/')}}, indent=2, sort_keys=True) + '\n')


def install(base, prefix, provenance, controls):
    host_prefix(str(prefix))
    require(not prefix.exists() and not prefix.is_symlink(), 'host installation output already exists')
    manifest, sources, _ = stock(base)
    with zipfile.ZipFile(base) as archive:
        projection = {LIBRARY: 'python/libpython3.13.so.1.0', **{STDLIB + '/' + key: 'stdlib/' + key for key in sources}}
        for relative, member in projection.items():
            target = prefix / relative
            target.parent.mkdir(parents=True, exist_ok=True)
            with archive.open(member) as source, target.open('xb') as sink:
                shutil.copyfileobj(source, sink, length=65536)
            require(identity(target) == {key: manifest['resources'][member][key] for key in ('size', 'sha256')}, 'materialized source identity differs')
    for relative, payload in (LURES.items() if controls else ()):
        target = prefix / STDLIB / relative
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_bytes(payload)
    trees = [prefix]
    if controls:
        for mode in MODES:
            tree = prefix.with_name(prefix.name + ' ' + mode)
            require(not tree.exists(), 'control output already exists')
            for relative in projection:
                if mode == 'missing-library' and relative == LIBRARY or mode == 'missing-source' and relative == STDLIB + '/' + CONTROL_SOURCE:
                    continue
                target = tree / relative
                target.parent.mkdir(parents=True, exist_ok=True)
                if mode == 'wrong-source' and relative == STDLIB + '/' + CONTROL_SOURCE:
                    shutil.copyfile(prefix / relative, target)
                    with target.open('r+b') as stream:
                        byte = stream.read(1)
                        stream.seek(0)
                        stream.write(bytes([byte[0] ^ 1]))
                else:
                    os.link(prefix / relative, target)
            if mode == 'deep-cache':
                target = tree / STDLIB / CONTROL_CACHE / 'unverified.cpython-313.pyc'
            elif mode == 'startup-native':
                target = tree / STDLIB / 'encodings/__init__.cpython-313-aarch64-linux-gnu.so'
            elif mode == 'startup-bytecode':
                target = tree / STDLIB / 'encodings/__init__.pyc'
            else:
                target = None
            if target is not None:
                target.parent.mkdir(parents=True, exist_ok=True)
                target.write_bytes(b'unsupported installed startup/cache control\n')
            trees.append(tree)
    records = {}
    for tree in trees:
        files = {}
        for path in sorted(tree.rglob('*')):
            require(not path.is_symlink(), 'prepared host tree contains a symlink')
            if path.is_file():
                files[path.relative_to(tree).as_posix()] = identity(path)
                path.chmod(0o444)
        for path in sorted(tree.rglob('*'), reverse=True):
            if path.is_dir():
                path.chmod(0o555)
        tree.chmod(0o555)
        records[str(tree)] = files
    provenance.write_text(json.dumps({'schema_version': 0, 'build_time_materialization': True, 'base': identity(base),
        'stock_sources': len(sources), 'stock_source_bytes': sum(s['size'] for s in sources.values()), 'source_inventory': identity(HERE.parent / 'python-imports/stdlib-pins.json'),
        'control_source': CONTROL_SOURCE, 'control_cache': CONTROL_CACHE, 'lures': sorted(LURES) if controls else [], 'runtime_trees': records}, indent=2, sort_keys=True) + '\n')


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    sub = parser.add_subparsers(dest='operation', required=True)
    materialize = sub.add_parser('install')
    materialize.add_argument('base', type=Path)
    materialize.add_argument('prefix', type=Path)
    materialize.add_argument('--provenance', type=Path, required=True)
    materialize.add_argument('--controls', action='store_true')
    prepare = sub.add_parser('stage')
    prepare.add_argument('base', type=Path)
    prepare.add_argument('application', type=Path)
    prepare.add_argument('output', type=Path)
    prepare.add_argument('--prefix', required=True)
    prepare.add_argument('--app-id', required=True)
    prepare.add_argument('--entry', required=True)
    prepare.add_argument('--component', default='launch')
    args = parser.parse_args()
    try:
        if args.operation == 'install':
            install(args.base, args.prefix, args.provenance, args.controls)
        else:
            stage(args.base, args.application, args.output, args.prefix, args.app_id, args.entry, args.component)
    except (OSError, ValueError, KeyError, struct.error, zipfile.BadZipFile) as error:
        print('host source application preparation rejected: ' + str(error), file=sys.stderr)
        return 1
    print('Prepared verified explicit host source application inputs')
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
