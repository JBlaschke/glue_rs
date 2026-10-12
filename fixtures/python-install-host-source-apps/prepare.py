#!/usr/bin/env python3
"""Prepare a pinned stock install-only provider and app-only build inputs.

Installation verifies the whole cached upstream artifact before parsing it.
Staging packages checked-in importer bytes and application bytes; it never
downloads a provider or executes application code.
"""
from __future__ import annotations

import argparse
import hashlib
import importlib.util
import io
import json
import os
from pathlib import Path, PurePosixPath
import re
import shutil
import stat
import sys
import tarfile

HERE = Path(__file__).resolve().parent
SPEC = importlib.util.spec_from_file_location('install_paired_preparer', HERE.parent / 'python-source-apps/prepare.py')
PAIRED = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(PAIRED)
require, canonical, bounded, walk_files = PAIRED.require, PAIRED.canonical, PAIRED.bounded, PAIRED.walk_files
BUILD = 'pbs-20261009-cpython-3.13.16-pgo-lto-host-install-source-apps-v1'
LIBRARY = 'lib/libpython3.13.so.1.0'
STDLIB = 'lib/python3.13'
CONTROL_SOURCE = 'asyncio/taskgroups.py'
CONTROL_CACHE = 'site-packages/pip/_vendor/idna/__pycache__'
CONTROL_STARTUP_CACHE = 'encodings/__pycache__/__init__.cpython-313.pyc'
MODES = ('missing-source', 'wrong-source', 'deep-cache', 'startup-native', 'startup-bytecode', 'missing-library',
         'missing-cache', 'wrong-cache', 'extra-cache')
MAX_ENTRIES, MAX_MEMBER_BYTES, MAX_TOTAL_BYTES = 10000, 256 * 1024 * 1024, 256 * 1024 * 1024
MAX_DIRECTORY_OWNERS, MAX_RETAINED_OWNERS = 256, 763
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
TARGET = {'abi': {'family': 'glibc', 'minimum_version': '2.36'}, 'arch': 'aarch64', 'cpu_features': [],
          'minimum_os_version': '7.1.4', 'os': 'linux', 'page_sizes': [4096]}
STARTUP = ('codecs.py', 'encodings/__init__.py', 'encodings/aliases.py', 'encodings/ascii.py', 'encodings/latin_1.py', 'encodings/utf_8.py')


def sha(payload):
    return hashlib.sha256(payload).hexdigest()


def identity(path):
    with path.open('rb') as stream:
        digest = hashlib.file_digest(stream, 'sha256').hexdigest()
    return {'size': path.stat().st_size, 'sha256': digest}


def pins():
    source_raw, cache_raw = (HERE / 'source-pins.json').read_bytes(), (HERE / 'cache-pins.json').read_bytes()
    source, cache = json.loads(source_raw), json.loads(cache_raw)
    require(source['schema_version'] == cache['schema_version'] == 0 and len(source['files']) == 1037 and
            sum(spec['size'] for spec in source['files'].values()) == 15894268 and len(cache['files']) == 3 and
            sum(spec['size'] for spec in cache['files'].values()) == 21157 and cache['source_inventory_sha256'] == sha(source_raw) and
            source['artifact_size'] == cache['artifact_size'] == 57626877 and source['artifact_sha256'] == cache['artifact_sha256'] ==
            '397ca401f416c3c99330a6be16d735d0cbeaf53e82070b80395b2fb4a8891f34' and
            source['stock_tar_mtime'] == cache['stock_tar_mtime'] == 1704067200, 'checked-in stock inventory differs')
    for key, spec in list(source['files'].items()) + list(cache['files'].items()):
        canonical(key)
        require(type(spec['size']) is int and 0 <= spec['size'] <= 4 * 1024 * 1024 and
                isinstance(spec['sha256'], str) and re.fullmatch('[0-9a-f]{64}', spec['sha256']), 'invalid stock file pin')
    return source, cache


def host_prefix(value):
    source, cache = pins()
    require(isinstance(value, str) and value.startswith('/') and value != '/' and value.isascii() and not value.endswith('/') and
            not any(ord(c) < 32 or ord(c) == 127 or c == '\\' for c in value) and
            all(part not in ('', '.', '..') for part in value.split('/')[1:]), 'noncanonical absolute ASCII host prefix')
    stdlib = Path(value) / STDLIB
    source_paths = [stdlib / key for key in source['files']]
    source_dirs = {stdlib}
    for path in source_paths:
        source_dirs.update(parent for parent in path.parents if parent == stdlib or stdlib in parent.parents)
    cache_dir = stdlib / 'encodings/__pycache__'
    paths = source_paths + [stdlib / key for key in cache['files']] + [path / '__pycache__' for path in source_dirs]
    paths += [stdlib / (name + suffix) for name in ('codecs', 'encodings') for suffix in
              ('.pyc', '.pyo', '.cpython-313-aarch64-linux-gnu.so', '.abi3.so', '.so')]
    paths += [stdlib / 'codecs', stdlib / 'encodings.py', Path(value) / LIBRARY]
    require(all(len(str(path)) <= 4096 for path in paths), 'expanded host paths exceed the profile bound')
    directories = source_dirs | {cache_dir} | set(stdlib.parents)
    require(len(directories) <= MAX_DIRECTORY_OWNERS, 'host source snapshot directory owners exceed 256')
    # The snapshot owns distinct ancestors. The retained library, six startup
    # sources and three cache identities also retain their checked ancestors.
    retained_paths = [Path(value) / LIBRARY] + [stdlib / key for key in STARTUP]
    startup_directories = len(stdlib.parents) + 1 + len((stdlib / 'encodings').parents) + 1
    retained = len(directories) + startup_directories + sum(1 + len(path.parent.parents) + 1 for path in retained_paths) + len(cache['files'])
    require(retained <= MAX_RETAINED_OWNERS, 'host install snapshot retained owners exceed 763')
    return value


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


def stage(application, output, prefix, app_id, entry, component):
    host_prefix(prefix)
    require(re.fullmatch(r'[A-Za-z0-9._-]{1,128}', app_id) is not None and re.fullmatch(r'[A-Za-z0-9._-]{1,128}', component) is not None, 'bounded ASCII app/component identity required')
    require(not output.exists(), 'staging output already exists')
    files = app_inventory(application, entry)
    files['python/archive-importer.py'] = bounded(HERE.parent / 'python-imports/bootstrap.py', 256 * 1024)
    manifest = {'schema_version': 0, 'app_id': app_id, 'entrypoint': component,
        'components': {component: {'entry_point': entry, 'runtime': 'python', 'native_modules': []}},
        'resources': {key: {'size': len(value), 'sha256': sha(value), 'compression': 'deflate' if key == 'python/archive-importer.py' else 'stored'} for key, value in files.items()},
        'runtimes': {'python': {'abi': {'debug': False, 'gil': 'conventional', 'language': 'python', 'version': {'major': 3, 'minor': 13, 'patch': 16}},
            'build_id': BUILD, 'provisioning': {'mode': 'host', 'discovery': 'explicit_paths', 'runtime_library': prefix + '/' + LIBRARY, 'stdlib': prefix + '/' + STDLIB},
            'required_features': [], 'target': 'linux-arm64'}},
        'targets': {'linux-arm64': TARGET}, 'native_modules': {}, 'host_imports': {}}
    for key, payload in files.items():
        target = output / 'root' / key
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_bytes(payload)
    (output / 'manifest.json').write_text(json.dumps(manifest, sort_keys=True, separators=(',', ':')) + '\n')
    (output / 'prepare-summary.json').write_text(json.dumps({'schema_version': 0, 'app_id': app_id, 'component': component, 'entry': entry, 'prefix': prefix,
        'application_files': len(files) - 1, 'application_bytes': sum(len(v) for k, v in files.items() if k.startswith('app/')),
        'source_inventory': identity(HERE / 'source-pins.json'), 'cache_inventory': identity(HERE / 'cache-pins.json'),
        'application': {key: spec for key, spec in manifest['resources'].items() if key.startswith('app/')}}, indent=2, sort_keys=True) + '\n')


def archive_name(name):
    require(isinstance(name, str) and name.startswith('python/') and name.isascii() and len(name) <= 4096 and
            '\\' not in name and not any(ord(c) < 32 or ord(c) == 127 for c in name) and
            all(part not in ('', '.', '..') for part in name.split('/')), 'unsafe stock archive member')
    return name


def link_target(name, target):
    require(target and target.isascii() and not target.startswith('/') and len(target) <= 4096 and '\\' not in target and
            not any(ord(c) < 32 or ord(c) == 127 for c in target), 'unsafe stock archive symlink')
    parts = name.split('/')[:-1]
    for part in target.split('/'):
        require(part != '', 'empty stock symlink component')
        if part == '..':
            require(len(parts) > 1, 'stock symlink escapes installation')
            parts.pop()
        elif part != '.':
            parts.append(part)
    return '/'.join(parts)


def stock_archive(path):
    source, cache = pins()
    before = path.lstat()
    require(stat.S_ISREG(before.st_mode) and before.st_size == source['artifact_size'], 'cached install-only artifact size/type differs')
    descriptor = os.open(path, os.O_RDONLY | os.O_NONBLOCK | os.O_NOFOLLOW | os.O_CLOEXEC)
    with os.fdopen(descriptor, 'rb') as stream:
        opened = os.fstat(stream.fileno())
        require(stat.S_ISREG(opened.st_mode) and opened.st_size == source['artifact_size'] and
                (opened.st_dev, opened.st_ino) == (before.st_dev, before.st_ino), 'cached install-only artifact identity changed')
        payload = stream.read(source['artifact_size'] + 1)
    require(len(payload) == source['artifact_size'] and sha(payload) == source['artifact_sha256'], 'cached install-only artifact digest differs')
    # This parse begins only after the complete artifact identity is checked.
    # Owned compressed bytes also bind every later member read to that identity.
    archive = tarfile.open(fileobj=io.BytesIO(payload), mode='r:gz')
    try:
        inventory, links, total = {}, {}, 0
        for member in archive:
            name = archive_name(member.name.rstrip('/') if member.isdir() else member.name)
            require(name not in inventory and len(inventory) < MAX_ENTRIES and (member.isfile() or member.issym() or member.isdir()), 'duplicate or unsupported stock archive member')
            require(0 <= member.size <= MAX_MEMBER_BYTES and (member.isfile() or member.size == 0), 'stock member size exceeds its bound')
            total += member.size
            require(total <= MAX_TOTAL_BYTES and member.mtime == source['stock_tar_mtime'], 'stock payload bytes or normalized mtime differs')
            inventory[name] = member
            if member.issym():
                links[name] = link_target(name, member.linkname)
        require(len(inventory) == 4526 and total == 182155939, 'stock complete installation inventory differs')
        for name in inventory:
            parts = name.split('/')
            require(all('/'.join(parts[:end]) not in inventory or inventory['/'.join(parts[:end])].isdir() for end in range(1, len(parts))), 'stock member traverses non-directory ancestor')
        for name, target in links.items():
            seen = {name}
            while target in links:
                require(target not in seen, 'stock symlink cycle')
                seen.add(target); target = links[target]
            require(target in inventory and inventory[target].isfile(), 'stock symlink is dangling or not a file')
        py = {key.removeprefix('python/' + STDLIB + '/'): member for key, member in inventory.items()
              if key.startswith('python/' + STDLIB + '/') and key.endswith('.py') and member.isfile()}
        pyc = {key.removeprefix('python/' + STDLIB + '/'): member for key, member in inventory.items()
               if key.startswith('python/' + STDLIB + '/') and ('/__pycache__/' in key or key.endswith(('.pyc', '.pyo'))) and member.isfile()}
        require(set(py) == set(source['files']) and set(pyc) == set(cache['files']), 'stock source/cache inventory differs')
        return archive, inventory, source, cache
    except BaseException:
        archive.close()
        raise


def freeze_tree(tree):
    for path in sorted(tree.rglob('*'), reverse=True):
        if path.is_symlink():
            continue
        path.chmod(0o555 if path.is_dir() or path.stat().st_mode & 0o111 else 0o444)
    tree.chmod(0o555)


def install(artifact, prefix, provenance, controls):
    host_prefix(str(prefix))
    require(not prefix.exists() and not prefix.is_symlink(), 'host installation output already exists')
    archive, members, source, cache = stock_archive(artifact)
    records, links = {}, {}
    with archive:
        outputs = [prefix] + ([prefix.with_name(prefix.name + ' ' + mode) for mode in MODES] if controls else [])
        all_relatives = [str(PurePosixPath(name).relative_to('python')) for name in members]
        if controls:
            all_relatives += [STDLIB + '/' + key for key in LURES]
            all_relatives += [STDLIB + '/' + CONTROL_CACHE + '/unverified.cpython-313.pyc',
                              STDLIB + '/encodings/__init__.cpython-313-aarch64-linux-gnu.so',
                              STDLIB + '/encodings/__init__.pyc', STDLIB + '/encodings/__pycache__/unreviewed.cpython-313.pyc']
        require(all(not tree.exists() and not tree.is_symlink() for tree in outputs), 'host/control installation output already exists')
        require(all(len(str(tree / relative)) <= 4096 for tree in outputs for relative in all_relatives), 'expanded stock installation path exceeds bound')
        for name, member in members.items():
            relative = str(PurePosixPath(name).relative_to('python'))
            target = prefix / relative
            if member.issym():
                links[relative] = {'target': member.linkname, 'mtime': member.mtime}
            elif member.isdir():
                target.mkdir(parents=True, exist_ok=True)
            else:
                target.parent.mkdir(parents=True, exist_ok=True)
                with archive.extractfile(member) as input_stream, target.open('xb') as output_stream:
                    shutil.copyfileobj(input_stream, output_stream, length=65536)
                target.chmod(member.mode & 0o777)
                os.utime(target, (member.mtime, member.mtime))
                record = identity(target)
                require(record['size'] == member.size, 'stock installation copy is incomplete')
                key = relative.removeprefix(STDLIB + '/')
                expected = source['files'].get(key) or cache['files'].get(key)
                if relative == LIBRARY:
                    expected = {'size': 73563968, 'sha256': PAIRED.LIBRARY_SHA}
                require(expected is None or record == expected, 'materialized stock prerequisite identity differs: ' + relative)
                records[relative] = record | {'mtime': member.mtime, 'mode': member.mode & 0o777}
        for relative, link in links.items():
            target = prefix / relative
            target.parent.mkdir(parents=True, exist_ok=True)
            os.symlink(link['target'], target)
            os.utime(target, (link['mtime'], link['mtime']), follow_symlinks=False)
    runtime_trees = {str(prefix): {'removed': [], 'changed': {}, 'added': {}}}
    if controls:
        for relative, payload in LURES.items():
            target = prefix / STDLIB / relative
            target.parent.mkdir(parents=True, exist_ok=True); target.write_bytes(payload)
            os.utime(target, (1704067200, 1704067200))
            runtime_trees[str(prefix)]['added'][STDLIB + '/' + relative] = identity(target)
        for mode in MODES:
            tree = prefix.with_name(prefix.name + ' ' + mode)
            require(not tree.exists() and not tree.is_symlink(), 'control output already exists')
            change = {'removed': [], 'changed': {}, 'added': {}}
            remove = LIBRARY if mode == 'missing-library' else STDLIB + '/' + CONTROL_SOURCE if mode == 'missing-source' else STDLIB + '/' + CONTROL_STARTUP_CACHE if mode == 'missing-cache' else None
            corrupt = STDLIB + '/' + (CONTROL_SOURCE if mode == 'wrong-source' else CONTROL_STARTUP_CACHE) if mode in ('wrong-source', 'wrong-cache') else None
            for relative in records:
                if relative == remove:
                    change['removed'].append(relative); continue
                target = tree / relative; target.parent.mkdir(parents=True, exist_ok=True)
                if relative == corrupt:
                    shutil.copy2(prefix / relative, target)
                    with target.open('r+b') as stream:
                        byte = stream.read(1); stream.seek(0); stream.write(bytes([byte[0] ^ 1]))
                    os.utime(target, (1704067200, 1704067200)); change['changed'][relative] = identity(target)
                else:
                    os.link(prefix / relative, target)
            for relative, link in links.items():
                target = tree / relative; target.parent.mkdir(parents=True, exist_ok=True)
                os.symlink(link['target'], target); os.utime(target, (link['mtime'], link['mtime']), follow_symlinks=False)
            added = CONTROL_CACHE + '/unverified.cpython-313.pyc' if mode == 'deep-cache' else 'encodings/__init__.cpython-313-aarch64-linux-gnu.so' if mode == 'startup-native' else 'encodings/__init__.pyc' if mode == 'startup-bytecode' else 'encodings/__pycache__/unreviewed.cpython-313.pyc' if mode == 'extra-cache' else None
            if added:
                target = tree / STDLIB / added; target.parent.mkdir(parents=True, exist_ok=True)
                target.write_bytes(b'unsupported installed startup/cache control\n'); os.utime(target, (1704067200, 1704067200))
                change['added'][STDLIB + '/' + added] = identity(target)
            runtime_trees[str(tree)] = change
    for tree in map(Path, runtime_trees):
        freeze_tree(tree)
    provenance.write_text(json.dumps({'schema_version': 0, 'build_time_materialization': True,
        'artifact': {'size': source['artifact_size'], 'sha256': source['artifact_sha256']},
        'stock_sources': len(source['files']), 'stock_source_bytes': sum(s['size'] for s in source['files'].values()),
        'stock_caches': len(cache['files']), 'stock_cache_bytes': sum(s['size'] for s in cache['files'].values()), 'stock_tar_mtime': source['stock_tar_mtime'],
        'source_inventory': identity(HERE / 'source-pins.json'), 'cache_inventory': identity(HERE / 'cache-pins.json'),
        'complete_stock_files': records, 'complete_stock_symlinks': links, 'runtime_trees': runtime_trees,
        'control_source': CONTROL_SOURCE, 'control_cache': CONTROL_CACHE, 'control_startup_cache': CONTROL_STARTUP_CACHE,
        'lures': sorted(LURES) if controls else [], 'fixture_transformations': ['read-only file/directory modes'] + (['declared ordinary import lures and damaged control copies'] if controls else [])}, indent=2, sort_keys=True) + '\n')


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    sub = parser.add_subparsers(dest='operation', required=True)
    materialize = sub.add_parser('install')
    materialize.add_argument('artifact', type=Path)
    materialize.add_argument('prefix', type=Path)
    materialize.add_argument('--provenance', type=Path, required=True)
    materialize.add_argument('--controls', action='store_true')
    prepare = sub.add_parser('stage')
    prepare.add_argument('application', type=Path)
    prepare.add_argument('output', type=Path)
    prepare.add_argument('--prefix', required=True)
    prepare.add_argument('--app-id', required=True)
    prepare.add_argument('--entry', required=True)
    prepare.add_argument('--component', default='launch')
    args = parser.parse_args()
    try:
        if args.operation == 'install':
            install(args.artifact, args.prefix, args.provenance, args.controls)
        else:
            stage(args.application, args.output, args.prefix, args.app_id, args.entry, args.component)
    except (OSError, ValueError, KeyError, TypeError, tarfile.TarError) as error:
        print('install-only host source application preparation rejected: ' + str(error), file=sys.stderr)
        return 1
    print('Prepared verified stock install-only host source application inputs')
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
