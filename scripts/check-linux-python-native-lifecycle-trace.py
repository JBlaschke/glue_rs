#!/usr/bin/env python3
"""Independent closed traces for the separately pinned native lifecycle corpus.

Each checker owns a fresh historical native/runtime graph. The descriptor and
source bytes belong only to this corpus; historical modules are never rebound.
Callbacks are measured by trusted native integer instrumentation, not by strace
instruction tracing. This is fixture evidence, not a general extension policy.
"""
from __future__ import annotations

import argparse
import gzip
import hashlib
import importlib.util
import json
from pathlib import Path
import re
import struct
import sys
from types import FunctionType, MappingProxyType
import zipfile
import zlib

ROOT = Path(__file__).resolve().parents[1]
FIXTURE = ROOT / 'fixtures/python-native-lifecycle'
DIRECTORY = '/build-target/relocated Python native lifecycle'
PROGRAM = DIRECTORY + '/glue-python-bootstrap-probe'
NATIVE_PREFIX = '/build-target/host Python native lifecycle'
APP_ID = 'stock-pbs-native-lifecycle'
NAMES = ('libglue_python_lifecycle.so', 'glue_native_lifecycle.so',
         'glue_native_create_error.so', 'glue_native_lifecycle_exec_error.so')
PYTHON_IMPORTS = frozenset(('PyLong_FromLong', 'PyModuleDef_Init', 'PyModule_GetState',
    'PyModule_AddIntConstant', 'PyErr_SetString', 'PyExc_RuntimeError', 'Py_DecRef',
    'PyObject_GetAttrString', 'PyModule_NewObject', 'PyList_New', 'PyList_SetItem', 'Py_IncRef'))
DEPENDENCY_EXPORT = 'glue_python_lifecycle_ledger'
CELLS = ('bundled-archived', 'bundled-host', 'host-archived', 'host-host')
NEGATIVE = ('corrupt-native', 'missing-host-image', 'wrong-host-image')
MODES = CELLS + tuple(cell + '-app-error' for cell in CELLS) + NEGATIVE
NATIVE_PASS = b'GLUE_PYTHON_NATIVE_LIFECYCLE_PASS instances=5 collected=2 retained=3 create_retry=2 exec_retry=2\n'
ATEXIT_PASS = b'GLUE_PYTHON_NATIVE_LIFECYCLE_ATEXIT_PASS retained=3\n'
FINALIZE_PASS = b'GLUE_PYTHON_NATIVE_LIFECYCLE_FINALIZE_PASS allocated=5 freed=5 released=5 owned=0\n'
# Finalized only after independent stock compilation/ELF inspection. Empty pins
# deliberately make admission unavailable rather than admitting unbound images.
NATIVE_PINS = MappingProxyType({
    "glue_native_create_error.so": {
        "exports": {
            "PyInit_glue_native_create_error": "function"
        },
        "header_256_hex": "7f454c460201010000000000000000000300b7000100000000000000000000004000000000000000900c010000000000000000004000380007004000130012000100000005000000000000000000000000000000000000000000000000000000281a000000000000281a0000000000000000010000000000010000000600000008fe00000000000008fe01000000000008fe010000000000200500000000000020050000000000000000010000000000020000000600000008fe00000000000008fe01000000000008fe0100000000007001000000000000700100000000000008000000000000000400000004000000c801000000000000c801000000000000",
        "imports": {
            "PyErr_SetString": "function",
            "PyExc_RuntimeError": "object",
            "PyList_New": "function",
            "PyList_SetItem": "function",
            "PyLong_FromLong": "function",
            "PyModuleDef_Init": "function",
            "PyModule_AddIntConstant": "function",
            "PyModule_GetState": "function",
            "PyModule_NewObject": "function",
            "PyObject_GetAttrString": "function",
            "Py_DecRef": "function",
            "Py_IncRef": "function",
            "glue_python_lifecycle_ledger": "function"
        },
        "loads": [
            {
                "align": 65536,
                "filesz": 6696,
                "flags": 5,
                "memsz": 6696,
                "offset": 0,
                "vaddr": 0
            },
            {
                "align": 65536,
                "filesz": 1312,
                "flags": 6,
                "memsz": 1312,
                "offset": 65032,
                "vaddr": 130568
            }
        ],
        "needed": [
            "libglue_python_lifecycle.so",
            "libpython3.13.so.1.0"
        ],
        "sha256": "7e9437494450d76c2df591ee5e5d53d1875f42054edefe2ad21c77702d6c6b6c",
        "size": 69968,
        "soname": "glue_native_create_error.so"
    },
    "glue_native_lifecycle.so": {
        "exports": {
            "PyInit_glue_native_lifecycle": "function"
        },
        "header_256_hex": "7f454c460201010000000000000000000300b7000100000000000000000000004000000000000000880c010000000000000000004000380007004000130012000100000005000000000000000000000000000000000000000000000000000000181a000000000000181a0000000000000000010000000000010000000600000008fe00000000000008fe01000000000008fe010000000000200500000000000020050000000000000000010000000000020000000600000008fe00000000000008fe01000000000008fe0100000000007001000000000000700100000000000008000000000000000400000004000000c801000000000000c801000000000000",
        "imports": {
            "PyErr_SetString": "function",
            "PyExc_RuntimeError": "object",
            "PyList_New": "function",
            "PyList_SetItem": "function",
            "PyLong_FromLong": "function",
            "PyModuleDef_Init": "function",
            "PyModule_AddIntConstant": "function",
            "PyModule_GetState": "function",
            "PyModule_NewObject": "function",
            "PyObject_GetAttrString": "function",
            "Py_DecRef": "function",
            "Py_IncRef": "function",
            "glue_python_lifecycle_ledger": "function"
        },
        "loads": [
            {
                "align": 65536,
                "filesz": 6680,
                "flags": 5,
                "memsz": 6680,
                "offset": 0,
                "vaddr": 0
            },
            {
                "align": 65536,
                "filesz": 1312,
                "flags": 6,
                "memsz": 1312,
                "offset": 65032,
                "vaddr": 130568
            }
        ],
        "needed": [
            "libglue_python_lifecycle.so",
            "libpython3.13.so.1.0"
        ],
        "sha256": "aa9b255a18d2454a96c218a0ec13030225a215c6d6a425ecc0cb4c906071425f",
        "size": 69960,
        "soname": "glue_native_lifecycle.so"
    },
    "glue_native_lifecycle_exec_error.so": {
        "exports": {
            "PyInit_glue_native_lifecycle_exec_error": "function"
        },
        "header_256_hex": "7f454c460201010000000000000000000300b7000100000000000000000000004000000000000000980c010000000000000000004000380007004000130012000100000005000000000000000000000000000000000000000000000000000000a81a000000000000a81a0000000000000000010000000000010000000600000008fe00000000000008fe01000000000008fe010000000000200500000000000020050000000000000000010000000000020000000600000008fe00000000000008fe01000000000008fe0100000000007001000000000000700100000000000008000000000000000400000004000000c801000000000000c801000000000000",
        "imports": {
            "PyErr_SetString": "function",
            "PyExc_RuntimeError": "object",
            "PyList_New": "function",
            "PyList_SetItem": "function",
            "PyLong_FromLong": "function",
            "PyModuleDef_Init": "function",
            "PyModule_AddIntConstant": "function",
            "PyModule_GetState": "function",
            "PyModule_NewObject": "function",
            "PyObject_GetAttrString": "function",
            "Py_DecRef": "function",
            "Py_IncRef": "function",
            "glue_python_lifecycle_ledger": "function"
        },
        "loads": [
            {
                "align": 65536,
                "filesz": 6824,
                "flags": 5,
                "memsz": 6824,
                "offset": 0,
                "vaddr": 0
            },
            {
                "align": 65536,
                "filesz": 1312,
                "flags": 6,
                "memsz": 1312,
                "offset": 65032,
                "vaddr": 130568
            }
        ],
        "needed": [
            "libglue_python_lifecycle.so",
            "libpython3.13.so.1.0"
        ],
        "sha256": "6662ad4df57b3e9256d6822aee618c9c486441c99d20597bc8ee788f6af894c2",
        "size": 69976,
        "soname": "glue_native_lifecycle_exec_error.so"
    },
    "libglue_python_lifecycle.so": {
        "exports": {
            "glue_python_lifecycle_ledger": "function"
        },
        "header_256_hex": "7f454c460201010000000000000000000300b7000100000000000000000000004000000000000000e00301000000000000000000400038000700400010000f0001000000050000000000000000000000000000000000000000000000000000009c080000000000009c080000000000000000010000000000010000000600000000ff00000000000000ff01000000000000ff010000000000000100000000000090030000000000000000010000000000020000000600000000ff00000000000000ff01000000000000ff010000000000e000000000000000e00000000000000008000000000000000400000004000000c801000000000000c801000000000000",
        "imports": {},
        "loads": [
            {
                "align": 65536,
                "filesz": 2204,
                "flags": 5,
                "memsz": 2204,
                "offset": 0,
                "vaddr": 0
            },
            {
                "align": 65536,
                "filesz": 256,
                "flags": 6,
                "memsz": 912,
                "offset": 65280,
                "vaddr": 130816
            }
        ],
        "needed": [],
        "sha256": "75e0fd7203306d62eeff65b941fa43378e16b6870216104391c2237b450bcf6f",
        "size": 67552,
        "soname": "libglue_python_lifecycle.so"
    }
})
APP_BASE_PINS = {
    "app/main.py": {
        "sha256": "0e4b3bce73eaa08e9acbb9aefeae298a1e43fdd1a62148141718d60b7065694f",
        "size": 9122
    },
    "app/python/glue_demo/__init__.py": {
        "sha256": "27b04513ead8342533059e9a8d46b114878ac9e450ee5e1b248566ec5d4b9038",
        "size": 104
    },
    "app/python/glue_demo/answer.py": {
        "sha256": "d64b06510e86459b77b1eb511fafb91104408aa565d5127137447f2ab43e5e33",
        "size": 82
    },
    "app/python/glue_demo/broken.py": {
        "sha256": "52245b558e197209c65d84b67e6ef2dcb16f9aabafdf83a238ec27f75d2ac0b7",
        "size": 80
    },
    "app/python/glue_demo/bytecode_only.pyc": {
        "sha256": "931ab5355458a466bb8bba37d2c8d7a0bf7ca0008d891ae387be746bf9d7c9f3",
        "size": 30
    },
    "app/python/glue_demo/cycle_a.py": {
        "sha256": "6c6f95e878915459e0b534e292702e38ebb1ffe8b431b64d8907c2125a4857ae",
        "size": 56
    },
    "app/python/glue_demo/cycle_b.py": {
        "sha256": "a4369978c016d47f15063a9cccf2227f4c5c1be2ff46ba9c6beb666f32e0f666",
        "size": 48
    },
    "app/python/glue_demo/data/binary.bin": {
        "sha256": "eb0ee1dbca0e93dbbefa6c93cabdbb88b01a8433ff9460c9d272fbaa526418a1",
        "size": 11
    },
    "app/python/glue_demo/data/text.txt": {
        "sha256": "08bb9f0c0342478c5c9bb4b263ddeb89dc8c5d27dc166b588becc08b2771b30e",
        "size": 21
    },
    "app/python/glue_demo/dependency.py": {
        "sha256": "2da305ced6727b91c95fab67f567acf269fea032a71ea2c0e23251af08026900",
        "size": 16
    },
    "app/python/glue_demo/encoded.py": {
        "sha256": "4911a385af4ef68c2d98f8e5e515216c0776337bc607d054abd2a5077200ac0a",
        "size": 32
    },
    "app/python/glue_demo/nested/__init__.py": {
        "sha256": "eb76618094a48a7bc1e8289d9ca5115fc6a48a3800566b9a742e802e35e61f4c",
        "size": 25
    },
    "app/python/glue_demo/nested/value.py": {
        "sha256": "88f92d58d9706e16b293aacf471dd930213780b70cbf773d31c716c3e1e84682",
        "size": 11
    },
    "app/python/glue_demo/syntax_error.py": {
        "sha256": "a59db05b8f427c429471ec6cb7ae9797fa0dcdc5c501eb85f68fc23670985ea5",
        "size": 52
    },
    "app/python/glue_ns/data/info.txt": {
        "sha256": "3a6efa343a9107c8a8fde38199565accbf668234eaa446b3d7676be1fe5f04a3",
        "size": 19
    },
    "app/python/glue_ns/part.py": {
        "sha256": "0a775022744f64c352863f165f2e125898419999bc57c83204772036d0ef6b2e",
        "size": 12
    },
    "app/python/standalone.py": {
        "sha256": "0a775022744f64c352863f165f2e125898419999bc57c83204772036d0ef6b2e",
        "size": 12
    },
    "python/archive-importer.py": {
        "sha256": "7001318a2554b3800c1abbda6b114c6d0e5d6fed56788dc54727d2637ed2f43f",
        "size": 13510
    }
}
STDLIB_INVENTORY_PIN = {'size': 326131, 'sha256': 'd088049d2c9936748a1fd6139a9b5634ded6b64934b7df1b02638ab4aa3653c8'}
FROZEN_PIN = {"size": 139523, "sha256": "6a41fc38141d45c5197adfc1b0ee740c6244ea681742c205b8aa7b8449d865d7", "compression": "stored"}
APP_TAIL_PIN = {'size': 6586, 'sha256': '038177dfc72a736cf32e0108762da2a78285db1f484f55323a0fb38d1cb6543c'}


def policy():
    spec = importlib.util.spec_from_file_location('native_lifecycle_private_policy',
        Path(__file__).with_name('check-linux-python-extension-trace.py'))
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


REFERENCE = policy()
TraceError = REFERENCE.TraceError
BASE, PBS = REFERENCE.BASE, REFERENCE.PBS
MAX_TRACE_BYTES, MAX_LINE_CHARACTERS, MAX_RECORDS = (
    REFERENCE.MAX_TRACE_BYTES, REFERENCE.MAX_LINE_CHARACTERS, REFERENCE.MAX_RECORDS)
BEFORE_FINALIZE = REFERENCE.BUNDLED.SUCCESS + NATIVE_PASS + ATEXIT_PASS
SUCCESS = BEFORE_FINALIZE + FINALIZE_PASS
APP_ERROR = REFERENCE.APP_ERROR


def require(condition, message):
    if not condition:
        raise TraceError(message)


def identity(payload):
    return {'size': len(payload), 'sha256': hashlib.sha256(payload).hexdigest()}


def typed_equal(left, right):
    options = {'sort_keys': True, 'separators': (',', ':'), 'ensure_ascii': False, 'allow_nan': False}
    return json.dumps(left, **options) == json.dumps(right, **options)


def strict_json(payload):
    def pairs(items):
        result = {}
        for key, value in items:
            require(key not in result, 'duplicate lifecycle JSON field')
            result[key] = value
        return result
    return json.loads(payload, object_pairs_hook=pairs,
        parse_constant=lambda _: (_ for _ in ()).throw(TraceError('nonfinite lifecycle JSON value')))


def pinned_bytes(path, expected):
    with path.open('rb') as stream:
        payload = stream.read(expected['size'] + 1)
    require(typed_equal(identity(payload), expected), 'lifecycle pinned bytes differ: ' + str(path))
    return payload


def pinned_descriptor():
    require(set(NATIVE_PINS) == set(NAMES) and APP_TAIL_PIN is not None,
            'lifecycle independent image/application pins are not finalized')
    return NATIVE_PINS


def cell_for(mode):
    require(mode in MODES, 'unknown native lifecycle workload')
    return ('bundled-archived' if mode == 'corrupt-native' else 'bundled-host' if mode in NEGATIVE
            else mode.removesuffix('-app-error'))


def prefix_for(mode):
    cell_for(mode)
    return NATIVE_PREFIX + (' ' + mode if mode in ('missing-host-image', 'wrong-host-image') else '')


def archive_for(mode):
    return DIRECTORY + '/' + (mode if mode in NEGATIVE else cell_for(mode)) + '.glue'


def command_for(mode):
    return [PROGRAM, 'run-native-lifecycle-negative', archive_for(mode), 'app-error'] if mode.endswith('-app-error') else [PROGRAM, 'run-native-lifecycle', archive_for(mode)]


def expected_output(mode):
    cell_for(mode)
    if mode not in NEGATIVE:
        return SUCCESS, APP_ERROR if mode.endswith('-app-error') else b''
    if mode == 'corrupt-native':
        return b'', b'glue-python-bootstrap-probe: resource "native/libglue_python_lifecycle.so" failed CRC32 verification\n'
    image = NAMES[0] if mode == 'missing-host-image' else NAMES[1]
    path = prefix_for(mode) + '/' + image
    message = f'host path {path}: No such file or directory (os error 2)' if mode == 'missing-host-image' else f'host file identity mismatch: {path}'
    return b'', ('glue-python-bootstrap-probe: ' + message + '\n').encode()


def decode_elf(payload, name):
    require(payload[:16] == b'\x7fELF\x02\x01\x01\x00' + bytes(8) and
            struct.unpack_from('<H', payload, 16)[0] == 3 and struct.unpack_from('<H', payload, 18)[0] == 183,
            'native lifecycle image differs from ELF64LE AArch64 DYN')
    def bounded(offset, size):
        require(0 <= offset <= len(payload) and 0 <= size <= len(payload) - offset, 'native ELF range exceeds image')
        return payload[offset:offset + size]
    phoff, shoff = struct.unpack_from('<QQ', payload, 32)
    phstride, phnum, shstride, shnum = struct.unpack_from('<HHHH', payload, 54)
    require(phstride == 56 and shstride == 64 and 0 < phnum <= 32 and 0 < shnum <= 128, 'native ELF table bounds differ')
    loads = []
    for index in range(phnum):
        kind, flags, offset, virtual, physical, file_size, memory_size, alignment = struct.unpack('<IIQQQQQQ', bounded(phoff + index * 56, 56))
        require(kind != 7, 'native lifecycle TLS is outside profile')
        if kind == 1:
            loads.append({'flags': flags, 'offset': offset, 'vaddr': virtual,
                          'filesz': file_size, 'memsz': memory_size, 'align': alignment})
    sections = [struct.unpack('<IIQQQQIIQQ', bounded(shoff + index * 64, 64)) for index in range(shnum)]
    def text(table, offset):
        require(0 <= offset < len(table) and b'\0' in table[offset:], 'native ELF string is out of bounds')
        return table[offset:table.index(b'\0', offset)].decode('ascii')
    imports, exports, needed, soname = {}, {}, [], None
    for section in sections:
        if section[1] == 11:
            strings = sections[section[6]]
            strings = bounded(strings[4], strings[5])
            require(section[9] == 24, 'native dynamic symbol entry size differs')
            for offset in range(section[4], section[4] + section[5], 24):
                label, info, other, index, value, size = struct.unpack('<IBBHQQ', bounded(offset, 24))
                label = text(strings, label)
                if not label or info >> 4 == 0:
                    continue
                require(info >> 4 == 1 and other == 0 and (info & 15) in (1, 2), 'native symbol binding/type/visibility differs')
                target = imports if index == 0 else exports
                require(label not in target, 'native symbol name repeats')
                target[label] = 'object' if (info & 15) == 1 else 'function'
        elif section[1] == 6:
            strings = sections[section[6]]
            strings = bounded(strings[4], strings[5])
            for offset in range(section[4], section[4] + section[5], 16):
                tag, value = struct.unpack('<qQ', bounded(offset, 16))
                require(tag not in (12, 13, 15, 25, 26, 27, 28, 29, 32, 33), 'native constructors/path-search tags are outside profile')
                if tag == 1:
                    needed.append(text(strings, value))
                elif tag == 14:
                    soname = text(strings, value)
    expected_export = DEPENDENCY_EXPORT if name == NAMES[0] else 'PyInit_' + name.removesuffix('.so')
    expected_imports = {} if name == NAMES[0] else {label: 'object' if label == 'PyExc_RuntimeError' else 'function' for label in PYTHON_IMPORTS | {DEPENDENCY_EXPORT}}
    require(exports == {expected_export: 'function'} and imports == expected_imports,
            'native lifecycle finite imports/sole export differ')
    require(soname == name and set(needed) == (set() if name == NAMES[0] else {'libpython3.13.so.1.0', NAMES[0]}) and
            len(needed) == len(set(needed)), 'native lifecycle SONAME/direct dependencies differ')
    require(len(loads) == 2 and loads[0]['flags'] == 5 and loads[0]['offset'] == loads[0]['vaddr'] == 0 and
            loads[1]['flags'] == 6 and loads[1]['vaddr'] - loads[1]['offset'] == 65536 and
            all(row['align'] == 65536 and row['filesz'] <= row['memsz'] for row in loads), 'native lifecycle PT_LOAD profile differs')
    return identity(payload) | {'loads': loads, 'imports': imports, 'exports': exports,
                                'needed': needed, 'soname': soname, 'header_256_hex': payload[:256].hex()}


def native_facts(directory):
    require({path.name for path in directory.glob('*.so')} == set(NAMES), 'native fixture image inventory differs')
    result = {}
    for name, expected in pinned_descriptor().items():
        path = directory / name
        require(not path.is_symlink() and path.is_file() and path.stat().st_size <= 256 * 1024,
                'native retained image type/size differs')
        payload = pinned_bytes(path, {key: expected[key] for key in ('size', 'sha256')})
        result[name] = decode_elf(payload, name)
        require(typed_equal(result[name], expected), 'native retained ELF facts differ from independent pin')
    return result


def expected_application():
    pinned_descriptor()
    result = {name: pinned_bytes(ROOT / ('fixtures/python-imports/bootstrap.py' if name == 'python/archive-importer.py'
                                          else 'fixtures/python-imports/input/' + name), pin)
              for name, pin in APP_BASE_PINS.items()}
    result['app/main.py'] += b'\n' + pinned_bytes(FIXTURE / 'app.py', APP_TAIL_PIN)
    return result


def expected_manifest(mode):
    runtime, native = cell_for(mode).split('-')
    resources = {name: identity(data) | {'compression': 'stored' if name == 'app/python/glue_demo/__init__.py' else 'deflate'}
                 for name, data in expected_application().items()}
    source = {'artifact': 'cpython-3.13.16+20261009-aarch64-unknown-linux-gnu-pgo+lto-full.tar.zst',
              'release': '20261009', 'revision': 'ccc07c40c2731bfb459c119f2388f65a5a470de6',
              'sha256': '8907ec2f181f0fc5cd08b9d897d36159432405af78f68f8faca728f48940e0ca',
              'variant': 'pgo+lto-full/archive-source-imports-v1'}
    if runtime == 'bundled':
        inventory = strict_json(pinned_bytes(ROOT / 'fixtures/python-imports/stdlib-pins.json', STDLIB_INVENTORY_PIN))
        require(type(inventory['schema_version']) is int and inventory['schema_version'] == 0 and
                inventory['artifact_sha256'] == source['sha256'] and len(inventory['files']) == 2174,
                'independent full source inventory differs')
        resources.update({'stdlib/' + name: spec | {'compression': 'deflate'} for name, spec in inventory['files'].items()})
        resources['python/libpython3.13.so.1.0'] = {'size': 73563968, 'sha256': '42be968275d5be2d9e632ec9ef6790dd2c10f1d4a710ad1028fc2b687242f219', 'compression': 'stored'}
        resources['python/frozen.json'] = dict(FROZEN_PIN)
        provisioning = {'mode': 'bundled', 'provider': 'python_build_standalone', 'runtime_library': 'python/libpython3.13.so.1.0',
                        'source': source, 'stdlib': 'python/frozen.json'}
        build = 'pbs-20261009-cpython-3.13.16-pgo-lto-archive-imports-v1'
    else:
        provisioning = {'mode': 'host', 'discovery': 'explicit_paths',
                        'runtime_library': '/build-target/host Python imports/lib/libpython3.13.so.1.0',
                        'stdlib': '/build-target/host Python imports/lib/python3.13'}
        build = 'pbs-20261009-cpython-3.13.16-pgo-lto-host-archive-imports-v1'
    native_modules, host_imports = {}, {}
    for name in NAMES:
        dependency = name == NAMES[0]
        if native == 'host':
            host_imports[name] = {'class': 'host_module', 'target': 'linux-arm64', 'path': prefix_for(mode) + '/' + name,
                                 'runtime': None if dependency else 'python', 'sha256': NATIVE_PINS[name]['sha256']}
        else:
            resources['native/' + name] = {key: NATIVE_PINS[name][key] for key in ('size', 'sha256')} | {'compression': 'stored'}
            native_modules[name] = {'target': 'linux-arm64', 'resource': 'native/' + name, 'format': 'elf',
                'namespace': 'python-registered', 'runtime': None if dependency else 'python',
                'dependencies': [] if dependency else [{'class': 'archived_module', 'module': NAMES[0]}, {'class': 'runtime', 'runtime': 'python'}],
                'required_features': ['function_exports'] if dependency else ['function_exports', 'data_exports']}
    return {'schema_version': 0, 'app_id': APP_ID, 'entrypoint': 'main',
            'components': {'main': {'entry_point': 'app/main.py', 'runtime': 'python',
                                   'native_modules': sorted(NAMES[1:]) if native == 'archived' else []}},
            'runtimes': {'python': {'abi': {'debug': False, 'gil': 'conventional', 'language': 'python',
                'version': {'major': 3, 'minor': 13, 'patch': 16}}, 'build_id': build, 'provisioning': provisioning,
                'required_features': [], 'target': 'linux-arm64'}},
            'targets': {'linux-arm64': {'abi': {'family': 'glibc', 'minimum_version': '2.36'}, 'arch': 'aarch64',
                'cpu_features': [], 'minimum_os_version': '7.1.4', 'os': 'linux', 'page_sizes': [4096]}},
            'native_modules': native_modules, 'host_imports': host_imports, 'resources': resources}


def emit_metadata(directory, archives, output):
    records = {mode: archive_record(archives / (mode + '.glue'), mode) for mode in CELLS + NEGATIVE}
    output.write_text(json.dumps({'schema_version': 0, 'files': native_facts(directory),
                                  'archives': records}, sort_keys=True, indent=2) + '\n')


def archive_record(path, mode):
    pinned_descriptor()
    size = path.stat().st_size
    require(type(size) is int and 64 < size <= 128 * 1024 * 1024, 'lifecycle archive exceeds fixed bound')
    with path.open('rb') as stream:
        header = stream.read(64)
        require(header[:16] == b'GLUERS00' + bytes(8), 'lifecycle locator identity differs')
        length, zipped = struct.unpack_from('<QQ', header, 16)
        require(0 < length <= 2 * 1024 * 1024 and 64 + length + zipped == size, 'lifecycle archive framing differs')
        raw = stream.read(length)
        require(hashlib.sha256(raw).digest() == header[32:64], 'lifecycle manifest digest differs')
        manifest = strict_json(raw)
        require(raw == json.dumps(manifest, sort_keys=True, separators=(',', ':'), ensure_ascii=False).encode(), 'lifecycle manifest is noncanonical')
        stream.seek(0)
        digest = hashlib.file_digest(stream, 'sha256').hexdigest()
    runtime, native = cell_for(mode).split('-')
    require(typed_equal(manifest, expected_manifest(mode)), 'complete lifecycle manifest/runtime/resource declaration differs')
    applications = expected_application()
    declarations = {}
    for name in NAMES:
        spec = manifest['host_imports'][name] if native == 'host' else manifest['resources']['native/' + name]
        declarations[name] = {'sha256': spec['sha256']}
        if native == 'host':
            declarations[name]['path'] = spec['path']
        else:
            declarations[name].update(size=spec['size'], compression=spec['compression'])
    record = {'bytes': size, 'sha256': digest, 'manifest_sha256': hashlib.sha256(raw).hexdigest(),
              'manifest_bytes': length, 'zip_directory_offset': 0, 'runtime': runtime, 'native': native,
              'declarations': declarations, 'application': {name: identity(data) for name, data in applications.items()}}
    with zipfile.ZipFile(path) as archive:
        record['zip_directory_offset'] = archive.start_dir
        require(len(archive.infolist()) == len(manifest['resources']) and set(archive.namelist()) == set(manifest['resources']), 'lifecycle ZIP member inventory differs')
        for name, declaration in manifest['resources'].items():
            info = archive.getinfo(name)
            require(info.file_size == declaration['size'] and info.compress_type == (zipfile.ZIP_STORED if declaration['compression'] == 'stored' else zipfile.ZIP_DEFLATED), 'lifecycle resource size/storage differs')
            if mode == 'corrupt-native' and name == 'native/' + NAMES[0]:
                try:
                    archive.read(name)
                except zipfile.BadZipFile as error:
                    require('CRC' in str(error), 'lifecycle corrupt image failed outside CRC')
                else:
                    raise TraceError('lifecycle corrupt image unexpectedly verified')
                with path.open('rb') as stream:
                    stream.seek(info.header_offset)
                    local = stream.read(30)
                    names, extra = struct.unpack_from('<HH', local, 26)
                    offset = info.header_offset + 30 + names + extra
                    stream.seek(offset)
                    data = stream.read(info.file_size)
                require(typed_equal(identity(bytes([data[0] ^ 1]) + data[1:]),
                                    {key: NATIVE_PINS[NAMES[0]][key] for key in ('size', 'sha256')}),
                        'lifecycle corrupt image is not the exact one-byte native mutation')
                record['corrupt_native_offset'] = offset
            else:
                data = archive.read(name)
                require(typed_equal(identity(data), {key: declaration[key] for key in ('size', 'sha256')}), 'lifecycle archive resource identity differs')
                if name in applications:
                    require(data == applications[name], 'lifecycle app/helper bytes differ')
                elif name.startswith('native/'):
                    require(typed_equal(identity(data), {key: NATIVE_PINS[name.removeprefix('native/')][key] for key in ('size', 'sha256')}), 'lifecycle archived native pin differs')
    return record


def retained_metadata(path, mode, size=None):
    with path.open('rb') as stream:
        payload = stream.read(256 * 1024 + 1)
    require(len(payload) <= 256 * 1024, 'lifecycle metadata exceeds fixed bound')
    value = strict_json(payload)
    require(type(value) is dict and set(value) == {'schema_version', 'files', 'archives'} and
            type(value['schema_version']) is int and value['schema_version'] == 0 and
            typed_equal(value['files'], dict(pinned_descriptor())) and type(value['archives']) is dict and
            set(value['archives']) == set(CELLS + NEGATIVE), 'lifecycle retained metadata inventory/types differ')
    record = value['archives'][mode if mode in NEGATIVE else cell_for(mode)]
    validate_record(record, mode, record['bytes'] if size is None else size)
    return record


def validate_record(record, mode, size):
    runtime, native = cell_for(mode).split('-')
    keys = {'bytes', 'sha256', 'manifest_sha256', 'manifest_bytes', 'zip_directory_offset', 'runtime', 'native', 'declarations', 'application'}
    if mode == 'corrupt-native':
        keys.add('corrupt_native_offset')
    require(type(record) is dict and set(record) == keys and type(record['bytes']) is int and record['bytes'] == size and
            64 < size <= 128 * 1024 * 1024 and record['runtime'] == runtime and record['native'] == native,
            'lifecycle retained archive identity/schema differs')
    require(all(type(record[key]) is str and re.fullmatch('[0-9a-f]{64}', record[key]) for key in ('sha256', 'manifest_sha256')), 'lifecycle archive digest is noncanonical')
    expected_raw = json.dumps(expected_manifest(mode), sort_keys=True, separators=(',', ':'), ensure_ascii=False).encode()
    require(type(record['manifest_bytes']) is int and record['manifest_bytes'] == len(expected_raw) and
            record['manifest_sha256'] == hashlib.sha256(expected_raw).hexdigest(),
            'lifecycle retained manifest identity differs from the complete expected declaration')
    require(type(record['manifest_bytes']) is int and type(record['zip_directory_offset']) is int and
            0 < record['manifest_bytes'] <= 2 * 1024 * 1024 and
            64 + record['manifest_bytes'] < record['zip_directory_offset'] <= size - 22,
            'lifecycle manifest/ZIP boundaries differ')
    expected_declarations = {name: {'sha256': NATIVE_PINS[name]['sha256']} | (
        {'path': prefix_for(mode) + '/' + name} if native == 'host' else
        {'size': NATIVE_PINS[name]['size'], 'compression': 'stored'}) for name in NAMES}
    require(typed_equal(record['declarations'], expected_declarations) and
            typed_equal(record['application'], {name: identity(data) for name, data in expected_application().items()}),
            'lifecycle native/application declarations differ')
    if mode == 'corrupt-native':
        offset = record['corrupt_native_offset']
        require(type(offset) is int and 64 + record['manifest_bytes'] <= offset <= record['zip_directory_offset'] - NATIVE_PINS[NAMES[0]]['size'], 'lifecycle corruption offset differs')


def visible_buffer(argument):
    match = re.fullmatch(r'"((?:[^"\\]|\\.)*)"(?:\.\.\.)?', argument)
    require(match is not None, 'lifecycle buffer lacks complete visible string prefix')
    return bytes(match[1], 'ascii').decode('unicode_escape').encode('latin1')


def address(argument):
    PBS.pointer(argument)
    require(argument != 'NULL', 'lifecycle owned address must be non-null')
    return int(argument, 16)


def private_graph():
    """Parameterize finite image/fixture identities in a newly loaded graph.

    The two hardcoded historical control constants are replaced only in these
    private functions: the intentionally wrong first root and final CRC chunk.
    All other historical descriptor/startup predicates remain unchanged.
    """
    module = policy()
    for graph in (module, module.BUNDLED, module.HOST, module.HOST.COMMON,
                  module.HOST.PBS, module.HOST.BASE, module.PBS, module.BASE):
        graph.TraceError = TraceError
    for key, value in {'PROGRAM': PROGRAM, 'DIRECTORY': DIRECTORY, 'NATIVE_PREFIX': NATIVE_PREFIX,
        'NAMES': NAMES, 'MODES': MODES, 'CELLS': CELLS, 'NEGATIVE': NEGATIVE,
        'SUCCESS': SUCCESS, 'NATIVE_PASS': NATIVE_PASS, 'CORRUPT_KEY': 'native/' + NAMES[0],
        'CORRUPT_ERROR': expected_output('corrupt-native')[1], 'cell_for': cell_for,
        'archive_for': archive_for, 'prefix_for': prefix_for, 'command_for': command_for,
        'expected_output': expected_output}.items():
        setattr(module, key, value)
    module.SIZES = {name: row['size'] for name, row in NATIVE_PINS.items()}
    module.HASHES = {name: row['sha256'] for name, row in NATIVE_PINS.items()}
    module.EXPECTED_LOADS = {name: row['loads'] for name, row in NATIVE_PINS.items()}
    module.SEGMENTS = {}
    for name, row in NATIVE_PINS.items():
        rx, rw = row['loads']
        module.SEGMENTS[name] = {(rw['vaddr'] + rw['memsz'], 0): 'PROT_READ|PROT_EXEC',
            (((rw['offset'] % 4096 + rw['filesz'] + 4095) // 4096) * 4096, 0xf000): 'PROT_READ|PROT_WRITE'}
    def constant(value):
        if value == 'glue_native_single.so':
            return NAMES[1]
        if type(value) is int and value == 1616:
            return module.SIZES[NAMES[0]] - 65536
        if type(value) is frozenset:
            return frozenset(constant(item) for item in value)
        return value
    for method in ('call', 'control_ready'):
        function = getattr(module.Checker, method)
        code = function.__code__.replace(co_consts=tuple(constant(value) for value in function.__code__.co_consts))
        setattr(module.Checker, method, FunctionType(code, function.__globals__, function.__name__))
    return module


def Checker(mode, record):
    validate_record(record, mode, record['bytes'])
    graph = private_graph()

    class LifecycleChecker(graph.Checker):
        def __init__(self):
            super().__init__(mode, record['bytes'], record.get('corrupt_native_offset'),
                             (record['manifest_bytes'], record['zip_directory_offset']))
            self.parser_owner = None
            self.parser_remaps = self.parser_frees = 0
            self.ledger_bss = False
            self.finalize_marker = False

        def native_ready(self):
            return self.ledger_bss and super().native_ready()

        def call(self, name, args, result):
            if name in {'read', 'write'}:
                require(len(args) == 3, 'native lifecycle read/write syscall arity differs')
            value = graph.result_number(result)
            runtime = self.runtime
            if name == 'write' and args:
                number = graph.descriptor(args[0])[0]
                if number in self.native_fds:
                    image, role = self.native_fds[number]
                    state = self.states[image]
                    if state['created'] and role == 'source' and state['bytes'] < 256:
                        start = state['bytes']
                        count = min(graph.unsigned(args[2]), 256 - start)
                        expected = bytes.fromhex(NATIVE_PINS[image]['header_256_hex'])
                        require(visible_buffer(args[1])[:count] == expected[start:start + count],
                                'native lifecycle population differs from the pinned visible ELF header')
            if name == 'read' and args:
                number = graph.descriptor(args[0])[0]
                if number in self.native_fds:
                    image, role = self.native_fds[number]
                    state = self.states[image]
                    if value and (role == 'alias' or state['cursor'] < 256):
                        expected = bytes.fromhex(NATIVE_PINS[image]['header_256_hex'])
                        if self.mode == 'wrong-host-image' and image == NAMES[1]:
                            expected = bytes([expected[0] ^ 1]) + expected[1:]
                        start = 0 if role == 'alias' else state['cursor']
                        count = min(value, 256 - start)
                        require(visible_buffer(args[1])[:count] == expected[start:start + count],
                                'native lifecycle read differs from the pinned visible ELF header')
            if name == 'mprotect' and len(args) == 3 and args[0] != 'NULL':
                location = address(args[0])
                for image, state in self.states.items():
                    reservation = state['reservation']
                    if reservation is None or not reservation[2] <= location < reservation[3]:
                        continue
                    guard = ((NATIVE_PINS[image]['loads'][0]['memsz'] + 4095) // 4096) * 4096
                    if location in {reservation[2] + 4096, reservation[2] + guard}:
                        require(location == reservation[2] + guard and args[1:] == [str(0x1f000 - guard), 'PROT_NONE'] and
                                value == 0 and not state['guard'] and len(state['maps']) == 1 and
                                state['trimmed'] == len(state['trims']),
                                'native lifecycle gap guard differs from pinned RX extent and loader order')
                        state['guard'] = True
                        return
            if name == 'mmap' and len(args) == 6 and args[0] != 'NULL' and 'MAP_ANONYMOUS' in args[3] and any(
                state['reservation'] is not None and address(args[0]) < state['reservation'][3] and
                state['reservation'][2] < address(args[0]) + graph.unsigned(args[1])
                for state in self.states.values()):
                state = self.states[NAMES[0]]
                base = state['reservation'][2] if state['reservation'] else None
                require(base is not None and args == [hex(base + 0x20000), '656', 'PROT_READ|PROT_WRITE',
                    'MAP_PRIVATE|MAP_FIXED|MAP_ANONYMOUS', '-1', '0'] and value == base + 0x20000 and
                    not self.ledger_bss and state['alias'] is not None and
                    state['maps'] == set(graph.SEGMENTS[NAMES[0]]) and state['guard'] and
                    state['trimmed'] == len(state['trims']) and not state['relro'] and self.preinit(),
                    'native lifecycle BSS map differs from the sole owned ledger tail')
                self.ledger_bss = True
                return
            if name == 'close' and args and graph.descriptor(args[0])[0] == self.states[NAMES[0]]['alias']:
                require(self.ledger_bss, 'ledger loader alias closed before its exact BSS tail was zeroed')
            if self.runtime_policy is graph.BUNDLED:
                if name == 'mremap':
                    require(len(args) == 4 and self.parser_owner is not None and
                            args == [hex(self.parser_owner), '307200', '610304', 'MREMAP_MAYMOVE'] and
                            self.parser_remaps == 0 and not runtime.archive_complete() and not runtime.created and
                            value is not None and value > 0, 'lifecycle parser growth differs from its owned private backing')
                    self.require_unowned(value, 610304)
                    self.parser_owner = value
                    self.parser_remaps = 1
                    return
                if name == 'munmap' and self.parser_owner is not None and args[0] != 'NULL':
                    location, count = address(args[0]), graph.unsigned(args[1])
                    length = 610304 if self.parser_remaps else 307200
                    if location < self.parser_owner + length and self.parser_owner < location + count:
                        require(args == [hex(self.parser_owner), '610304'] and value == 0 and
                                self.parser_remaps == 1 and self.parser_frees == 0 and not runtime.archive_complete(),
                                'lifecycle parser backing release differs from the complete grown owner')
                        self.parser_owner = None
                        self.parser_frees = 1
            if name == 'write' and args and graph.descriptor(args[0])[0] == 1:
                payload = visible_buffer(args[1])
                previous = bytes(self.output[0])
                if previous == BEFORE_FINALIZE or b'GLUE_PYTHON_NATIVE_LIFECYCLE_FINALIZE' in payload:
                    # The trace proves marker order and retained image owners.
                    # Its post-Py_FinalizeEx meaning comes from the SHA-bound
                    # core boundary and independent ordinary stock ledger driver.
                    require(self.initialized and previous == BEFORE_FINALIZE and payload == FINALIZE_PASS and
                            args[2] == str(len(FINALIZE_PASS)) and value == len(FINALIZE_PASS) and
                            not self.finalize_marker and self.native_ready() and
                            all(state['source'] in self.native_fds for state in self.states.values()),
                            'finalize ledger publication is early, repeated, changed or lacks pinned native owners')
                    self.finalize_marker = True
            super().call(name, args, result)
            if self.runtime_policy is graph.BUNDLED and name == 'mmap' and args == [
                'NULL', '307200', 'PROT_READ|PROT_WRITE', 'MAP_PRIVATE|MAP_ANONYMOUS', '-1', '0']:
                require(self.parser_owner is None and self.parser_remaps == 0 and runtime.archive_opened == 1 and
                        runtime.locator_read and not runtime.archive_complete() and not runtime.created,
                        'lifecycle parser allocation occurs outside its sole pre-admission phase')
                self.parser_owner = value

        def finish(self):
            if self.runtime_policy is graph.BUNDLED:
                require(self.parser_remaps == self.parser_frees == 1 and self.parser_owner is None,
                        'lifecycle parser backing allocation/growth/free sequence is incomplete')
                self.runtime.remaps = 1
            if self.initialized:
                require(self.native_ready() and self.finalize_marker, 'native lifecycle closure or final ledger publication is incomplete')
                self.runtime.finish()
            else:
                require(self.control_ready() and self.runtime.execs == 1 and self.runtime.exit_group and
                        self.runtime.completed and not self.runtime.virtual_queries and not self.runtime.overcommit_reads and
                        not self.runtime.tid_queries and not self.finalize_marker and not self.ledger_bss,
                        'lifecycle pre-initialization rejection lacks exact closed failed admission')
            require(tuple(bytes(stream) for stream in self.output) == self.expected, 'lifecycle diagnostic publication differs')

    return LifecycleChecker()


def check_lines(lines, mode, record):
    checker = Checker(mode, record)
    total = 0
    for number, line in enumerate(lines, 1):
        total += len(line.encode('utf-8'))
        require(number <= MAX_RECORDS and total <= MAX_TRACE_BYTES and len(line) <= MAX_LINE_CHARACTERS + 1 and
                line.endswith('\n') and '\r' not in line, 'lifecycle trace is oversized, noncanonical or incomplete')
        try:
            checker.line(line[:-1])
        except TraceError as error:
            raise TraceError(f'line {number}: {error}') from error
    checker.finish()
    return {'mode': mode, 'records': number, 'processes': 1, 'native_images': 4 if checker.initialized else 0,
            'finalize_marker_verified': checker.finalize_marker,
            'ledger_bss_mapping_verified': checker.ledger_bss,
            'parser_growth_and_free_verified': checker.parser_remaps == checker.parser_frees == 1}


def check_file(path, mode, record):
    require(path.stat().st_size <= MAX_TRACE_BYTES, 'lifecycle trace input exceeds bounded raw/compressed size')
    with (gzip.open if path.suffix == '.gz' else open)(path, 'rb') as stream:
        def lines():
            while raw := stream.readline(MAX_LINE_CHARACTERS + 2):
                yield raw.decode('utf-8', errors='strict')
        return check_lines(lines(), mode, record)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--emit-native-metadata', nargs=3, type=Path)
    parser.add_argument('trace', nargs='?', type=Path)
    parser.add_argument('--mode', choices=MODES)
    parser.add_argument('--stdout-file', type=Path)
    parser.add_argument('--stderr-file', type=Path)
    parser.add_argument('--archive-file', type=Path)
    parser.add_argument('--native-metadata-file', type=Path)
    args = parser.parse_args()
    if args.emit_native_metadata:
        emit_metadata(*args.emit_native_metadata)
        return 0
    require(args.trace and args.mode and args.stdout_file and args.stderr_file and args.native_metadata_file,
            'lifecycle replay requires trace, mode, output and metadata files')
    record = retained_metadata(args.native_metadata_file, args.mode)
    if args.archive_file:
        require(typed_equal(archive_record(args.archive_file, args.mode), record), 'lifecycle archive differs from retained inspected metadata')
    for path, expected in zip((args.stdout_file, args.stderr_file), expected_output(args.mode)):
        with path.open('rb') as stream:
            require(stream.read(len(expected) + 1) == expected, 'lifecycle captured output differs')
    check_file(args.trace, args.mode, record)
    print('PASS exact native lifecycle trace: ' + args.mode)
    return 0


if __name__ == '__main__':
    try:
        raise SystemExit(main())
    except (OSError, EOFError, UnicodeError, ValueError, KeyError, TypeError, struct.error,
            zipfile.BadZipFile, zlib.error, TraceError) as error:
        print('Native lifecycle trace rejected: ' + str(error), file=sys.stderr)
        raise SystemExit(1)
