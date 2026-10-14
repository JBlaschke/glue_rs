#!/usr/bin/env python3
"""Independent authenticated tar/ELF inspection of the paired PBS images.

No archive is installed and no target code is executed. ELF facts are decoded
directly from bytes, independently of the Rust loader and admission code.
"""
from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path
import struct
import tarfile

HERE = Path(__file__).resolve().parent
FIXTURES = HERE.parent
API = (
    'Py_GetVersion', 'Py_IsInitialized', 'PyPreConfig_InitIsolatedConfig',
    'Py_PreInitialize', 'PyConfig_InitIsolatedConfig', 'PyConfig_SetString',
    'PyConfig_Clear', 'Py_InitializeFromConfig', 'PyStatus_Exception',
    'PyStatus_IsExit', 'PyImport_AddModuleRef', 'PyModule_GetDict',
    'PyRun_StringFlags', 'Py_DecRef', 'PyErr_GetRaisedException', 'PyObject_Str',
    'PyUnicode_AsUTF8AndSize', 'PyErr_Clear', 'Py_FinalizeEx',
    'PyImport_FrozenModules', 'PyWideStringList_Append', 'PyModule_New',
    'PyCFunction_NewEx', 'PyImport_GetModuleDict', 'PyDict_SetItemString',
    'PyBytes_FromStringAndSize', 'PyErr_SetString', 'PyExc_RuntimeError',
    'PyImport_AppendInittab',
)


def require(condition, message):
    if not condition:
        raise ValueError(message)


def identity(data):
    return {'size': len(data), 'sha256': hashlib.sha256(data).hexdigest()}


def file_identity(path):
    with path.open('rb') as stream:
        return {'size': path.stat().st_size,
                'sha256': hashlib.file_digest(stream, 'sha256').hexdigest()}


def pins():
    return json.loads((HERE / 'pins.json').read_text())


def inspect_tar(path, expected):
    require(file_identity(path) == {k: expected[k] for k in ('size', 'sha256')},
            'compressed artifact identity differs')
    inventory, library, counts, total = {}, None, {}, 0
    with tarfile.open(path, 'r:gz') as archive:
        for member in archive:
            require(member.name not in inventory, 'duplicate tar path')
            require(member.name.startswith('python/') and
                    all(part not in ('', '.', '..') for part in member.name.split('/')),
                    'noncanonical tar path')
            kind = 'file' if member.isfile() else 'symlink' if member.issym() else 'other'
            require(kind != 'other', 'unexpected tar member type')
            record = {'type': kind, 'size': member.size, 'mode': member.mode,
                      'mtime': member.mtime, 'uid': member.uid, 'gid': member.gid,
                      'linkname': member.linkname}
            if member.isfile():
                stream = archive.extractfile(member)
                data = stream.read()
                require(len(data) == member.size, 'short tar member')
                record['sha256'] = hashlib.sha256(data).hexdigest()
                total += len(data)
                if member.name == 'python/lib/libpython3.13.so.1.0':
                    library = data
            inventory[member.name] = record
            counts[kind] = counts.get(kind, 0) + 1
    require(library is not None, 'library absent')
    return inventory, library, {'entries': len(inventory), 'types': counts,
                                'regular_payload_bytes': total}


def inspect_elf(data):
    require(data[:16] == b'\x7fELF\x02\x01\x01\x00' + bytes(8), 'ELF64LE System V identity differs')
    header_values = struct.unpack_from('<HHIQQQIHHHHHH', data, 16)
    header = dict(zip(('type', 'machine', 'version', 'entry', 'phoff', 'shoff',
                       'flags', 'ehsize', 'phentsize', 'phnum', 'shentsize',
                       'shnum', 'shstrndx'), header_values))
    require(header['type'] == 3 and header['machine'] == 183 and
            header['phentsize'] == 56 and header['shentsize'] == 64,
            'unexpected ELF profile')

    def bounded(offset, size):
        require(0 <= offset <= len(data) and 0 <= size <= len(data) - offset,
                'ELF range outside file')
        return data[offset:offset + size]

    sections = []
    for index in range(header['shnum']):
        values = struct.unpack('<IIQQQQIIQQ', bounded(header['shoff'] + index * 64, 64))
        sections.append(dict(zip(('name_offset', 'type', 'flags', 'address', 'offset',
                                  'size', 'link', 'info', 'alignment', 'entry_size'), values)))
    names = sections[header['shstrndx']]
    strings = bounded(names['offset'], names['size'])

    def string(table, offset):
        require(offset < len(table), 'ELF string offset outside table')
        end = table.find(b'\0', offset)
        require(end >= 0, 'unterminated ELF string')
        return table[offset:end].decode('ascii')

    by_name, allocated = {}, {}
    for section in sections:
        name = string(strings, section['name_offset'])
        require(name not in by_name, 'duplicate ELF section name')
        by_name[name] = section
        if section['flags'] & 2:
            record = {key: section[key] for key in ('type', 'flags', 'address', 'offset',
                                                   'size', 'alignment', 'entry_size')}
            record['sha256'] = None if section['type'] == 8 else identity(
                bounded(section['offset'], section['size']))['sha256']
            allocated[name] = record
    programs, load_payloads = [], []
    for index in range(header['phnum']):
        values = struct.unpack('<IIQQQQQQ', bounded(header['phoff'] + index * 56, 56))
        record = dict(zip(('type', 'flags', 'offset', 'address', 'physical_address',
                           'file_size', 'memory_size', 'alignment'), values))
        programs.append(record)
        if record['type'] == 1:
            load_payloads.append(bounded(record['offset'], record['file_size']))
    dynstr = by_name['.dynstr']
    dynstrings = bounded(dynstr['offset'], dynstr['size'])
    dynamic, needed, soname = [], [], None
    dyn = by_name['.dynamic']
    for offset in range(dyn['offset'], dyn['offset'] + dyn['size'], 16):
        tag, value = struct.unpack('<qQ', bounded(offset, 16))
        dynamic.append([tag, value])
        if tag == 1:
            needed.append(string(dynstrings, value))
        elif tag == 14:
            soname = string(dynstrings, value)
    dynsym = by_name['.dynsym']
    symbols = {}
    for offset in range(dynsym['offset'], dynsym['offset'] + dynsym['size'], 24):
        name, info, other, section, value, size = struct.unpack('<IBBHQQ', bounded(offset, 24))
        label = string(dynstrings, name)
        if label in API:
            require(label not in symbols and section not in (0, 0xfff1), 'API symbol undefined/duplicate')
            symbols[label] = {'info': info, 'other': other, 'section_name': string(
                strings, sections[section]['name_offset']), 'value': value, 'size': size}
    require(set(symbols) == set(API), 'selected API export set differs')
    build_ids = []
    for name, section in by_name.items():
        if section['type'] != 7:
            continue
        note = bounded(section['offset'], section['size'])
        offset = 0
        while offset < len(note):
            name_size, description_size, note_type = struct.unpack_from('<III', note, offset)
            offset += 12
            owner = note[offset:offset + name_size]
            offset += (name_size + 3) & ~3
            description = note[offset:offset + description_size]
            offset += (description_size + 3) & ~3
            require(offset <= len(note), 'truncated ELF note')
            if owner == b'GNU\0' and note_type == 3:
                build_ids.append(description.hex())
    return {'header': header, 'program_headers': programs, 'allocated_sections': allocated,
            'dynamic_entries': dynamic, 'needed': needed, 'soname': soname,
            'api_exports': symbols, 'build_ids': build_ids,
            'section_names': sorted(by_name)}, load_payloads


def compare(original, stripped):
    fixed = pins()
    left, left_library, left_totals = inspect_tar(original, fixed['original_artifact'])
    right, right_library, right_totals = inspect_tar(stripped, fixed['stripped_artifact'])
    require(set(left) == set(right), 'complete tar path sets differ')
    metadata_keys = ('type', 'mode', 'mtime', 'uid', 'gid', 'linkname')
    require(all(all(left[name][key] == right[name][key] for key in metadata_keys)
                for name in left), 'tar types/ownership/mode/time/link targets differ')
    changed = {name: {'original': left[name], 'stripped': right[name]}
               for name in sorted(left) if left[name] != right[name]}
    selected = {}
    for kind in ('source', 'cache'):
        inventory = json.loads((FIXTURES / 'python-install-host-source-apps' /
                                (kind + '-pins.json')).read_text())
        for name, expected in inventory['files'].items():
            path = 'python/lib/python3.13/' + name
            require(all({key: side[path][key] for key in ('size', 'sha256')} == expected
                        for side in (left, right)), 'selected source/cache identity differs: ' + name)
            selected[path] = expected
    require(identity(right_library) == fixed['stripped_library'], 'stripped library pin differs')
    a, a_load = inspect_elf(left_library)
    b, b_load = inspect_elf(right_library)
    require(right_library[:256].hex() == fixed['stripped_library_prefix_256_hex'],
            'stripped loader header pin differs')
    require(b['program_headers'] == fixed['stripped_elf_program_headers'] and
            b['build_ids'] == [fixed['gnu_build_id']], 'stripped loader geometry/build ID pin differs')
    require(a['program_headers'] == b['program_headers'], 'ELF program headers differ')
    for key in ('allocated_sections', 'dynamic_entries', 'needed', 'soname', 'api_exports', 'build_ids'):
        require(a[key] == b[key], 'ELF ' + key + ' differs')
    diffs = []
    for index, (first, second) in enumerate(zip(a_load, b_load)):
        require(len(first) == len(second), 'PT_LOAD sizes differ')
        offsets = [i for i, (x, y) in enumerate(zip(first, second)) if x != y]
        diffs.append({'load_index': index, 'original': identity(first), 'stripped': identity(second),
                      'changed_offsets': offsets,
                      'changes': [{'offset': i, 'original': first[i], 'stripped': second[i]} for i in offsets]})
    require(all(not row['changed_offsets'] for row in diffs[1:]), 'later PT_LOAD bytes differ')
    require(all(i in range(40, 48) or i in range(60, 64) for i in diffs[0]['changed_offsets']),
            'first PT_LOAD differences extend beyond section-table header fields')
    return {'schema_version': 0, 'original_artifact': fixed['original_artifact'],
            'stripped_artifact': fixed['stripped_artifact'],
            'original_inventory': left_totals, 'stripped_inventory': right_totals,
            'complete_path_type_mode_time_owner_link_parity': True,
            'changed_records': changed, 'selected_source_cache_files': len(selected),
            'selected_source_cache_bytes': sum(row['size'] for row in selected.values()),
            'selected_source_cache_pin_parity': True,
            'original_library': identity(left_library), 'stripped_library': identity(right_library),
            'original_elf': a, 'stripped_elf': b, 'load_segment_comparison': diffs,
            'execution_observed': False}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--original', type=Path, required=True)
    parser.add_argument('--stripped', type=Path, required=True)
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    require(not args.output.exists(), 'evidence output already exists')
    report = compare(args.original, args.stripped)
    args.output.write_text(json.dumps(report, sort_keys=True, indent=2) + '\n')
    print(json.dumps({key: report[key] for key in ('stripped_artifact', 'stripped_library',
                                                  'selected_source_cache_files',
                                                  'selected_source_cache_bytes', 'execution_observed')}, sort_keys=True))


if __name__ == '__main__':
    main()
