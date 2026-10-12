#!/usr/bin/env python3
"""Independently audit every stock member after the controlled runtime matrix.

This build-time audit reads the separately retained pinned upstream artifact and
the read-only Linux provider volume. It is not invoked by application execution.
"""
from __future__ import annotations

import hashlib
import io
import json
import os
from pathlib import Path
import stat
import sys
import tarfile

ARTIFACT_SIZE = 57626877
ARTIFACT_SHA = '397ca401f416c3c99330a6be16d735d0cbeaf53e82070b80395b2fb4a8891f34'
MTIME = 1704067200
STDLIB = 'lib/python3.13/'
SOURCE = STDLIB + 'asyncio/taskgroups.py'
CACHE = STDLIB + 'encodings/__pycache__/__init__.cpython-313.pyc'
MODES = ('missing-source', 'wrong-source', 'deep-cache', 'startup-native', 'startup-bytecode', 'missing-library',
         'missing-cache', 'wrong-cache', 'extra-cache')
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
DAMAGED = b'unsupported installed startup/cache control\n'


def require(value, message):
    if not value:
        raise ValueError(message)


def digest(data):
    return hashlib.sha256(data).hexdigest()


def record(data):
    return {'size': len(data), 'sha256': digest(data)}


def main():
    require(len(sys.argv) == 5, 'expected artifact, primary prefix, provenance and output')
    artifact, prefix, provenance, output = map(Path, sys.argv[1:])
    require(artifact.lstat().st_size == ARTIFACT_SIZE and stat.S_ISREG(artifact.lstat().st_mode), 'artifact size/type differs')
    fd = os.open(artifact, os.O_RDONLY | os.O_NONBLOCK | os.O_NOFOLLOW | os.O_CLOEXEC)
    with os.fdopen(fd, 'rb') as stream:
        raw = stream.read(ARTIFACT_SIZE + 1)
    require(len(raw) == ARTIFACT_SIZE and digest(raw) == ARTIFACT_SHA, 'whole artifact identity differs')
    files, links, selected, total = {}, {}, {}, 0
    with tarfile.open(fileobj=io.BytesIO(raw), mode='r:gz') as archive:
        for member in archive:
            total += 1
            require(total <= 10000 and member.name.startswith('python/') and member.name not in selected and
                    all(part not in ('', '.', '..') for part in member.name.split('/')) and
                    member.mtime == MTIME and 0 <= member.size <= 256 * 1024 * 1024, 'unbounded/noncanonical stock member')
            selected[member.name] = True
            name = member.name.removeprefix('python/')
            if member.isfile():
                with archive.extractfile(member) as stream:
                    data = stream.read(member.size + 1)
                require(len(data) == member.size, 'stock member read differs')
                files[name] = record(data) | {'mtime': member.mtime, 'mode': member.mode & 0o777}
                if name in (SOURCE, CACHE):
                    selected[name] = data
            elif member.issym():
                links[name] = {'target': member.linkname, 'mtime': member.mtime}
            else:
                raise ValueError('unexpected stock member type')
    require(total == 4526 and len(files) == 3478 and len(links) == 1048 and sum(x['size'] for x in files.values()) == 182155939,
            'complete independently decoded stock inventory differs')
    declared = json.loads(provenance.read_text())
    require(declared['artifact'] == {'size': ARTIFACT_SIZE, 'sha256': ARTIFACT_SHA} and
            declared['complete_stock_files'] == files and declared['complete_stock_symlinks'] == links and
            declared['stock_tar_mtime'] == MTIME, 'materialization provenance differs from independently decoded artifact')
    expected_trees = [str(prefix)] + [str(prefix.with_name(prefix.name + ' ' + mode)) for mode in MODES]
    require(set(declared['runtime_trees']) == set(expected_trees), 'control tree declaration differs')
    inode_hashes, tree_results = {}, {}
    for mode, tree_name in zip(('primary',) + MODES, expected_trees):
        tree = Path(tree_name)
        expected = dict(files)
        changes = {'removed': [], 'changed': {}, 'added': {}}
        if mode == 'primary':
            for name, data in LURES.items():
                relative = STDLIB + name
                expected[relative] = record(data) | {'mtime': MTIME, 'mode': 0o644}
                changes['added'][relative] = record(data)
        remove = 'lib/libpython3.13.so.1.0' if mode == 'missing-library' else SOURCE if mode == 'missing-source' else CACHE if mode == 'missing-cache' else None
        if remove:
            expected.pop(remove); changes['removed'].append(remove)
        if mode in ('wrong-source', 'wrong-cache'):
            key = SOURCE if mode == 'wrong-source' else CACHE
            data = bytearray(selected[key]); data[0] ^= 1
            expected[key] = record(data) | {'mtime': MTIME, 'mode': files[key]['mode']}
            changes['changed'][key] = record(data)
        add = STDLIB + 'site-packages/pip/_vendor/idna/__pycache__/unverified.cpython-313.pyc' if mode == 'deep-cache' else STDLIB + 'encodings/__init__.cpython-313-aarch64-linux-gnu.so' if mode == 'startup-native' else STDLIB + 'encodings/__init__.pyc' if mode == 'startup-bytecode' else STDLIB + 'encodings/__pycache__/unreviewed.cpython-313.pyc' if mode == 'extra-cache' else None
        if add:
            expected[add] = record(DAMAGED) | {'mtime': MTIME, 'mode': 0o644}
            changes['added'][add] = record(DAMAGED)
        require(declared['runtime_trees'][tree_name] == changes, 'declared fixture transformations differ: ' + mode)
        actual_files, actual_links, directories = {}, {}, set()
        require(stat.S_IMODE(tree.lstat().st_mode) == 0o555 and tree.is_dir() and not tree.is_symlink(), 'provider root is not read-only directory')
        for path in tree.rglob('*'):
            key = path.relative_to(tree).as_posix()
            metadata = path.lstat()
            if stat.S_ISLNK(metadata.st_mode):
                require(metadata.st_mtime_ns == MTIME * 1000000000, 'provider symlink mtime changed: ' + key)
                actual_links[key] = {'target': os.readlink(path), 'mtime': int(metadata.st_mtime)}
                continue
            if stat.S_ISDIR(metadata.st_mode):
                require(stat.S_IMODE(metadata.st_mode) == 0o555, 'provider directory modes changed: ' + key)
                directories.add(key); continue
            require(stat.S_ISREG(metadata.st_mode) and key in expected, 'unknown/nonregular provider member: ' + key)
            spec = expected[key]
            require(metadata.st_size == spec['size'] and metadata.st_mtime_ns == spec['mtime'] * 1000000000 and
                    stat.S_IMODE(metadata.st_mode) == (0o555 if spec['mode'] & 0o111 else 0o444), 'provider size/mtime/mode differs: ' + key)
            inode = (metadata.st_dev, metadata.st_ino, metadata.st_size, metadata.st_mtime_ns)
            if inode not in inode_hashes:
                with path.open('rb') as stream:
                    inode_hashes[inode] = hashlib.file_digest(stream, 'sha256').hexdigest()
            require(inode_hashes[inode] == spec['sha256'], 'provider content differs: ' + key)
            actual_files[key] = spec
        require(set(actual_files) == set(expected) and actual_links == links, 'provider complete regular/symlink inventory differs: ' + mode)
        expected_directories = {str(parent) for name in set(expected) | set(links) for parent in Path(name).parents if str(parent) != '.'}
        require(directories == expected_directories, 'provider directory inventory differs: ' + mode)
        tree_results[mode] = {'regular_files': len(actual_files), 'symlinks': len(actual_links), 'directories': len(directories),
            'regular_bytes': sum(spec['size'] for spec in actual_files.values()), 'complete_inventory_sha256': digest(json.dumps({'files': actual_files, 'links': actual_links}, sort_keys=True, separators=(',', ':')).encode()),
            'read_only': True, 'stock_mtimes_preserved': True, 'declared_changes_only': True}
    output.write_text(json.dumps({'schema_version': 0, 'artifact': {'size': ARTIFACT_SIZE, 'sha256': ARTIFACT_SHA},
        'independent_post_runtime_audit': True, 'complete_stock_files': len(files), 'complete_stock_symlinks': len(links),
        'trees': tree_results, 'distinct_regular_inodes_hashed': len(inode_hashes), 'all_ten_provider_trees_passed': True}, indent=2, sort_keys=True) + '\n')
    print('Independent post-runtime audit passed: complete stock bytes, symlinks, mtimes and read-only modes in all ten provider trees')
    return 0


if __name__ == '__main__':
    try:
        raise SystemExit(main())
    except (OSError, ValueError, KeyError, TypeError, tarfile.TarError) as error:
        print('Stock install-only provider audit rejected: ' + str(error), file=sys.stderr)
        raise SystemExit(1)
