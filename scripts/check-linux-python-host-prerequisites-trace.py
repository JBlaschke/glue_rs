#!/usr/bin/env python3
"""Closed six-workload traces for the pinned host prerequisite projection.

The historical installed-package policy is imported privately and remains
unchanged. Only the install-only stdlib root enumeration differs: the projected
tree contains the exact source/cache parents, omitting LICENSE.txt and
lib-dynload from the complete stock installation. All archive, CRC, loader,
startup, descriptor, syscall and output conditions remain inherited.
"""
from __future__ import annotations

import hashlib
import importlib.util
import json
from pathlib import Path
import re
import struct
import sys
import zipfile
import zlib


spec = importlib.util.spec_from_file_location(
    'prerequisites_private_venv_policy', Path(__file__).with_name('check-linux-python-venv-trace.py'))
VENV = importlib.util.module_from_spec(spec)
spec.loader.exec_module(VENV)
METADATA, TraceError = VENV.METADATA, VENV.TraceError
ROOT = Path(__file__).resolve().parents[1]
SOURCE_SHA = 'ef34cc6063aca5cad149d53dd247359b0154a20a99bf5d9a3f6f6423095dccc3'
CACHE_SHA = 'f14f8825bfa9a853f083733bee21c04cfbab6f509a00f72ca434e2096f643af8'
ARTIFACT_SHA = '397ca401f416c3c99330a6be16d735d0cbeaf53e82070b80395b2fb4a8891f34'


def inventory(payload, sha256, count, total):
    """Bind the directory derivation to independently retained exact pin bytes."""
    if len(payload) > 256 * 1024 or hashlib.sha256(payload).hexdigest() != sha256:
        raise TraceError('host prerequisite trace inventory bytes differ from their fixed identity')
    value = json.loads(payload)
    if (not isinstance(value, dict) or type(value.get('schema_version')) is not int or
            value['schema_version'] != 0 or value.get('artifact_sha256') != ARTIFACT_SHA or
            type(value.get('artifact_size')) is not int or value['artifact_size'] != 57626877 or
            type(value.get('stock_tar_mtime')) is not int or value['stock_tar_mtime'] != 1704067200 or
            not isinstance(value.get('files'), dict) or len(value['files']) != count):
        raise TraceError('host prerequisite trace inventory producer/count differs')
    for path, identity in value['files'].items():
        if (not isinstance(path, str) or not path.isascii() or
                any(part in ('', '.', '..') for part in path.split('/')) or
                '\\' in path or any(ord(char) < 32 or ord(char) == 127 for char in path) or
                not isinstance(identity, dict) or set(identity) != {'size', 'sha256'} or
                type(identity['size']) is not int or not 0 <= identity['size'] <= 4 * 1024 * 1024 or
                not isinstance(identity['sha256'], str) or re.fullmatch('[0-9a-f]{64}', identity['sha256']) is None):
            raise TraceError('host prerequisite trace inventory contains an invalid file identity')
    if sum(identity['size'] for identity in value['files'].values()) != total:
        raise TraceError('host prerequisite trace inventory byte total differs')
    return value


def projected_root_entries():
    directory = ROOT / 'fixtures/python-install-host-source-apps'
    source = inventory((directory / 'source-pins.json').read_bytes(), SOURCE_SHA, 1037, 15894268)
    caches = inventory((directory / 'cache-pins.json').read_bytes(), CACHE_SHA, 3, 21157)
    if caches.get('source_inventory_sha256') != SOURCE_SHA:
        raise TraceError('host prerequisite trace cache/source pairing differs')
    names = {path.split('/')[0] for path in source['files'] | caches['files']}
    return len(names | {'.', '..'})


ROOT_ENTRIES = projected_root_entries()
_host_checker = METADATA.host_checker


def host_checker(mode, size, record):
    checker = _host_checker(mode, size, record)
    if METADATA.profile_for(mode) != 'install-host':
        return checker
    parent = checker.__class__

    class ProjectedInstallHost(parent):
        def initialized_observations(self, threads):
            caches = self.raw_cache_done == set(self.startup_caches)
            return (self.image_ready() and self.raw_done == self.raw_sources and caches and
                    self.virtual_queries == self.overcommit_reads == self.timezone_queries == self.entropy == 1 and self.tid_queries == threads and
                    self.remaps == 4 and
                    self.enums.get(('runtime', self.stdlib)) == ROOT_ENTRIES and
                    self.enums.get(('runtime', self.stdlib + '/encodings')) == 125 and self.import_probes_seen == self.probes)

        def call(self, name, args, result):
            if self.exit_group or self.completed:
                raise TraceError('host prerequisite operation follows process exit')
            if name == 'getdents64' and len(args) == 3:
                number, path = self.reader(args[0])
                state = self.fd_states.get(number)
                if state is not None and state['role'] == 'runtime-enum' and path == self.stdlib:
                    match = re.fullmatch(r'0x[0-9a-f]{1,16} /\* ([0-9]{1,3}) entries \*/', args[1])
                    value = METADATA.PBS.result_number(result)
                    if state['eof'] or not self.image_ready() or state['metadata'] != 1 or args[2] != '32768' or match is None or value is None or not 0 <= value <= 32768 or (value == 0) != (int(match[1]) == 0):
                        raise TraceError('host prerequisite enumeration lacks exact live owner/count grammar')
                    state['bytes'] += int(match[1])
                    if value == 0:
                        if state['eof'] or state['bytes'] != ROOT_ENTRIES:
                            raise TraceError('host prerequisite stdlib entries differ from the pinned projection')
                        state['eof'] = True
                        self.enums['runtime', path] = ROOT_ENTRIES
                    return
            return super().call(name, args, result)

    checker.__class__ = ProjectedInstallHost
    return checker


METADATA.host_checker = host_checker


def __getattr__(name):
    return getattr(VENV, name)


if __name__ == '__main__':
    try:
        raise SystemExit(METADATA.main())
    except (OSError, EOFError, ValueError, KeyError, TypeError, UnicodeError,
            struct.error, zipfile.BadZipFile, zlib.error, TraceError) as error:
        print('Python host prerequisite trace rejected: ' + str(error), file=sys.stderr)
        raise SystemExit(1)
