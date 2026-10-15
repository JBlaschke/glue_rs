"""Survey what the pinned native wheel corpus requires from an ELF loader.

Usage:
  python3 -I fixtures/native/corpus/survey.py [--corpus DIR] [--pins PINS]
      [--inspector PATH] [--readelf PATH] [--output survey.json]
      [--markdown summary.md]

The script is a small, section-independent ELF64 reader: every fact comes
from the ELF header, program headers and the dynamic table reached through
PT_DYNAMIC, which is also what the glue-native inspector consults. Section
headers are read only to cross-check the dynamic symbol count. With
`--readelf`, llvm-readelf/readelf output cross-checks NEEDED, SONAME, segment
types, relocation types and version needs. With `--inspector`, the glue-native
`elf-survey` example records the project inspector's first rejection per image
twice: once exactly as a closed fixture profile would call it (expected SONAME
equal to the file name, no declared imports) and once with the image's own
SONAME and every undefined symbol declared, so that the structural rejection is
visible behind the import policy. The script maps and executes nothing from the
corpus; the unpacked wheels are untrusted bytes.
"""

import argparse
import collections
import datetime
import hashlib
import json
import re
import struct
import subprocess
import sys
import tempfile
from pathlib import Path

HERE = Path(__file__).resolve().parent
ROOT = HERE.parent.parent.parent

PT_NAMES = {
    0: 'NULL', 1: 'LOAD', 2: 'DYNAMIC', 3: 'INTERP', 4: 'NOTE', 5: 'SHLIB', 6: 'PHDR', 7: 'TLS',
    0x6474e550: 'GNU_EH_FRAME', 0x6474e551: 'GNU_STACK', 0x6474e552: 'GNU_RELRO',
    0x6474e553: 'GNU_PROPERTY', 0x6474e554: 'GNU_SFRAME',
    0x70000001: 'AARCH64_ARCHEXT', 0x70000002: 'AARCH64_MEMTAG_MTE',
}
DT_NAMES = {
    0: 'NULL', 1: 'NEEDED', 2: 'PLTRELSZ', 3: 'PLTGOT', 4: 'HASH', 5: 'STRTAB', 6: 'SYMTAB',
    7: 'RELA', 8: 'RELASZ', 9: 'RELAENT', 10: 'STRSZ', 11: 'SYMENT', 12: 'INIT', 13: 'FINI',
    14: 'SONAME', 15: 'RPATH', 16: 'SYMBOLIC', 17: 'REL', 18: 'RELSZ', 19: 'RELENT',
    20: 'PLTREL', 21: 'DEBUG', 22: 'TEXTREL', 23: 'JMPREL', 24: 'BIND_NOW', 25: 'INIT_ARRAY',
    26: 'FINI_ARRAY', 27: 'INIT_ARRAYSZ', 28: 'FINI_ARRAYSZ', 29: 'RUNPATH', 30: 'FLAGS',
    32: 'PREINIT_ARRAY', 33: 'PREINIT_ARRAYSZ', 34: 'SYMTAB_SHNDX', 35: 'RELRSZ', 36: 'RELR',
    37: 'RELRENT', 0x6ffffef5: 'GNU_HASH', 0x6ffffef6: 'TLSDESC_PLT', 0x6ffffef7: 'TLSDESC_GOT',
    0x6ffffef8: 'GNU_CONFLICT', 0x6ffffef9: 'GNU_LIBLIST', 0x6ffffefa: 'CONFIG',
    0x6ffffefb: 'DEPAUDIT', 0x6ffffefc: 'AUDIT', 0x6ffffefd: 'PLTPAD', 0x6ffffefe: 'MOVETAB',
    0x6ffffeff: 'SYMINFO', 0x6ffffff0: 'VERSYM', 0x6ffffff9: 'RELACOUNT', 0x6ffffffa: 'RELCOUNT',
    0x6ffffffb: 'FLAGS_1', 0x6ffffffc: 'VERDEF', 0x6ffffffd: 'VERDEFNUM', 0x6ffffffe: 'VERNEED',
    0x6fffffff: 'VERNEEDNUM', 0x7ffffffd: 'AUXILIARY', 0x7fffffff: 'FILTER',
}
DT_BY_NAME = {name: tag for tag, name in DT_NAMES.items()}
DF_BITS = {1: 'ORIGIN', 2: 'SYMBOLIC', 4: 'TEXTREL', 8: 'BIND_NOW', 0x10: 'STATIC_TLS'}
DF_1_BITS = {
    1: 'NOW', 2: 'GLOBAL', 4: 'GROUP', 8: 'NODELETE', 0x10: 'LOADFLTR', 0x20: 'INITFIRST',
    0x40: 'NOOPEN', 0x80: 'ORIGIN', 0x100: 'DIRECT', 0x200: 'TRANS', 0x400: 'INTERPOSE',
    0x800: 'NODEFLIB', 0x1000: 'NODUMP', 0x2000: 'CONFALT', 0x4000: 'ENDFILTEE',
    0x8000: 'DISPRELDNE', 0x10000: 'DISPRELPND', 0x20000: 'NODIRECT', 0x40000: 'IGNMULDEF',
    0x80000: 'NOKSYMS', 0x100000: 'NOHDR', 0x200000: 'EDITED', 0x400000: 'NORELOC',
    0x800000: 'SYMINTPOSE', 0x1000000: 'GLOBAUDIT', 0x2000000: 'SINGLETON', 0x4000000: 'STUB',
    0x8000000: 'PIE',
}
RELOC_NAMES = {
    0: 'NONE', 257: 'ABS64', 258: 'ABS32', 259: 'ABS16', 260: 'PREL64', 261: 'PREL32',
    262: 'PREL16', 1024: 'COPY', 1025: 'GLOB_DAT', 1026: 'JUMP_SLOT', 1027: 'RELATIVE',
    1028: 'TLS_DTPMOD64', 1029: 'TLS_DTPREL64', 1030: 'TLS_TPREL64', 1031: 'TLSDESC',
    1032: 'IRELATIVE',
}
# llvm-readelf spells the three module/offset TLS relocations without the width suffix.
RELOC_ALIASES = {'TLS_DTPMOD': 'TLS_DTPMOD64', 'TLS_DTPREL': 'TLS_DTPREL64', 'TLS_TPREL': 'TLS_TPREL64'}
TLS_RELOCATIONS = {1028, 1029, 1030, 1031}
STB_NAMES = {0: 'LOCAL', 1: 'GLOBAL', 2: 'WEAK', 10: 'GNU_UNIQUE'}
STT_NAMES = {0: 'NOTYPE', 1: 'OBJECT', 2: 'FUNC', 3: 'SECTION', 4: 'FILE', 5: 'COMMON', 6: 'TLS', 10: 'GNU_IFUNC'}
STV_NAMES = {0: 'DEFAULT', 1: 'INTERNAL', 2: 'HIDDEN', 3: 'PROTECTED'}
GNU_WEAK_HOOKS = {'_ITM_deregisterTMCloneTable', '_ITM_registerTMCloneTable', '__gmon_start__'}
DLOPEN_FAMILY = {
    'dlopen', 'dlmopen', 'dlsym', 'dlvsym', 'dlclose', 'dlerror', 'dladdr', 'dladdr1', 'dlinfo',
    'dl_iterate_phdr', '__libc_dlopen_mode', '__libc_dlsym',
}
THREAD_API = {'pthread_create', '__cxa_thread_atexit_impl', 'pthread_key_create', '__tls_get_addr'}
UNWIND_API_PREFIXES = ('_Unwind_', '__gxx_personality', '__cxa_begin_catch', '__cxa_end_catch', '__cxa_throw', '__cxa_rethrow')
# Libraries that manylinux policies treat as always provided by the host, plus
# glibc's own dynamic loader.
MANYLINUX_OS_LIBRARIES = {
    'ld-linux-aarch64.so.1',
    'libc.so.6', 'libm.so.6', 'libdl.so.2', 'libpthread.so.0', 'librt.so.1', 'libutil.so.1',
    'libnsl.so.1', 'libresolv.so.2', 'libcrypt.so.1', 'libgcc_s.so.1', 'libstdc++.so.6',
    'libz.so.1', 'libexpat.so.1', 'libX11.so.6', 'libXext.so.6', 'libXrender.so.1',
    'libICE.so.6', 'libSM.so.6', 'libGL.so.1', 'libgobject-2.0.so.0', 'libgthread-2.0.so.0',
    'libglib-2.0.so.0',
}
# Dynamic tags and segment types the glue-native inspector admits today
# (crates/glue-native/src/elf.rs); used to derive the rejection ladder.
GLUE_ADMITTED_TAGS = {
    'NEEDED', 'PLTRELSZ', 'PLTGOT', 'HASH', 'STRTAB', 'SYMTAB', 'RELA', 'RELASZ', 'RELAENT',
    'STRSZ', 'SYMENT', 'INIT', 'FINI', 'SONAME', 'PLTREL', 'JMPREL', 'BIND_NOW', 'INIT_ARRAY',
    'FINI_ARRAY', 'INIT_ARRAYSZ', 'FINI_ARRAYSZ', 'FLAGS', 'VERSYM', 'RELACOUNT', 'FLAGS_1',
    'VERNEED', 'VERNEEDNUM', 'NULL',
}
GLUE_ADMITTED_SEGMENTS = {'LOAD', 'DYNAMIC', 'GNU_STACK', 'PHDR', 'NOTE', 'GNU_EH_FRAME', 'GNU_RELRO'}
GLUE_LIMITS = {
    'image_bytes': 64 * 1024 * 1024,
    'extension_profile_image_bytes': 256 * 1024,
    'symbols': 65_536,
    'relocations': 65_536,
    'needed': 64,
    'dynamic_entries': 4096,
    'string_table_bytes': 8 * 1024 * 1024,
    'version_need_records': 64,
    'version_requirements': 1024,
    'note_segment_bytes': 4096,
}


def fail(message):
    print('survey: ' + message, file=sys.stderr)
    sys.exit(1)


def sha256(path):
    digest = hashlib.sha256()
    with path.open('rb') as handle:
        for block in iter(lambda: handle.read(1 << 20), b''):
            digest.update(block)
    return digest.hexdigest()


class Elf:
    """A bounded, read-only view of one ELF64 little-endian shared object."""

    def __init__(self, path):
        self.path = path
        self.data = path.read_bytes()
        data = self.data
        if len(data) < 64 or data[:4] != b'\x7fELF':
            raise ValueError('not an ELF file')
        if data[4] != 2 or data[5] != 1:
            raise ValueError('only ELF64 little-endian images are surveyed')
        (self.e_type, self.e_machine, _version, self.e_entry, self.e_phoff, self.e_shoff,
         self.e_flags, _ehsize, self.e_phentsize, self.e_phnum, self.e_shentsize, self.e_shnum,
         self.e_shstrndx) = struct.unpack_from('<HHIQQQIHHHHHH', data, 16)
        self.osabi = data[7]
        self.segments = []
        for index in range(self.e_phnum):
            offset = self.e_phoff + index * self.e_phentsize
            p_type, p_flags, p_offset, p_vaddr, _paddr, p_filesz, p_memsz, p_align = struct.unpack_from('<IIQQQQQQ', data, offset)
            self.segments.append({
                'type': PT_NAMES.get(p_type, hex(p_type)), 'type_value': p_type, 'flags': p_flags,
                'offset': p_offset, 'vaddr': p_vaddr, 'filesz': p_filesz, 'memsz': p_memsz, 'align': p_align,
            })
        self.loads = [s for s in self.segments if s['type'] == 'LOAD']
        self.sections = []
        if self.e_shoff and self.e_shnum and self.e_shoff + self.e_shnum * self.e_shentsize <= len(data):
            for index in range(self.e_shnum):
                offset = self.e_shoff + index * self.e_shentsize
                sh_name, sh_type, sh_flags, sh_addr, sh_offset, sh_size, sh_link, sh_info, _align, sh_entsize = struct.unpack_from('<IIQQQQIIQQ', data, offset)
                self.sections.append({'name_offset': sh_name, 'type': sh_type, 'addr': sh_addr, 'offset': sh_offset, 'size': sh_size, 'entsize': sh_entsize, 'link': sh_link, 'info': sh_info})
            names = self.sections[self.e_shstrndx] if self.e_shstrndx < len(self.sections) else None
            for section in self.sections:
                section['name'] = self.cstring_at(names['offset'] + section['name_offset']) if names else ''
        self.dynamic = self.read_dynamic()

    def cstring_at(self, offset):
        end = self.data.find(b'\0', offset)
        if end < 0:
            raise ValueError('unterminated string')
        return self.data[offset:end].decode('latin-1')

    def file_offset(self, vaddr, size=1):
        for load in self.loads:
            if load['vaddr'] <= vaddr and vaddr + size <= load['vaddr'] + load['filesz']:
                return load['offset'] + (vaddr - load['vaddr'])
        raise ValueError('virtual address %#x is not file-backed' % vaddr)

    def read(self, vaddr, size):
        offset = self.file_offset(vaddr, size)
        return self.data[offset:offset + size]

    def read_dynamic(self):
        dynamic = [s for s in self.segments if s['type'] == 'DYNAMIC']
        if len(dynamic) != 1:
            raise ValueError('expected exactly one PT_DYNAMIC')
        entries = []
        offset = dynamic[0]['offset']
        end = offset + dynamic[0]['filesz']
        while offset + 16 <= end:
            tag, value = struct.unpack_from('<qQ', self.data, offset)
            offset += 16
            if tag == 0:
                break
            entries.append((tag, value))
        return entries

    def tag(self, name):
        values = [value for tag, value in self.dynamic if tag == DT_BY_NAME[name]]
        if len(values) > 1:
            raise ValueError('duplicate dynamic tag ' + name)
        return values[0] if values else None

    def tags(self, name):
        return [value for tag, value in self.dynamic if tag == DT_BY_NAME[name]]


def dynamic_string(elf, strtab, offset):
    return elf.cstring_at(elf.file_offset(strtab + offset))


def gnu_hash_symbol_count(elf, address):
    nbuckets, symoffset, bloom_size, _shift = struct.unpack_from('<IIII', elf.read(address, 16))
    buckets_at = address + 16 + bloom_size * 8
    chains_at = buckets_at + nbuckets * 4
    buckets = struct.unpack_from('<%dI' % nbuckets, elf.read(buckets_at, nbuckets * 4))
    highest = symoffset - 1
    for start in buckets:
        if start == 0:
            continue
        index = start
        while True:
            entry = struct.unpack_from('<I', elf.read(chains_at + (index - symoffset) * 4, 4))[0]
            highest = max(highest, index)
            if entry & 1:
                break
            index += 1
    return highest + 1


def read_symbols(elf, strtab):
    symtab = elf.tag('SYMTAB')
    gnu_hash = elf.tag('GNU_HASH')
    sysv_hash = elf.tag('HASH')
    counts = {}
    if gnu_hash is not None:
        counts['gnu_hash'] = gnu_hash_symbol_count(elf, gnu_hash)
    if sysv_hash is not None:
        counts['sysv_hash'] = struct.unpack_from('<II', elf.read(sysv_hash, 8))[1]
    dynsym = [s for s in elf.sections if s.get('name') == '.dynsym']
    if dynsym:
        counts['dynsym_section'] = dynsym[0]['size'] // 24
    if not counts:
        raise ValueError('no hash table or .dynsym section to size the dynamic symbol table')
    count = max(counts.values())
    versym = elf.tag('VERSYM')
    symbols = []
    for index in range(count):
        st_name, st_info, st_other, st_shndx, st_value, st_size = struct.unpack_from('<IBBHQQ', elf.read(symtab + index * 24, 24))
        version = struct.unpack_from('<H', elf.read(versym + index * 2, 2))[0] if versym is not None else None
        symbols.append({
            'index': index,
            'name': dynamic_string(elf, strtab, st_name),
            'binding': STB_NAMES.get(st_info >> 4, str(st_info >> 4)),
            'type': STT_NAMES.get(st_info & 15, str(st_info & 15)),
            'visibility': STV_NAMES.get(st_other & 3, str(st_other & 3)),
            'defined': st_shndx != 0,
            'shndx': st_shndx,
            'value': st_value,
            'size': st_size,
            'version_index': None if version is None else version & 0x7fff,
            'version_hidden': None if version is None else bool(version & 0x8000),
        })
    return symbols, counts


def read_verneed(elf, strtab):
    address = elf.tag('VERNEED')
    count = elf.tag('VERNEEDNUM') or 0
    needs = {}
    index_names = {}
    for _ in range(count):
        version, aux_count, file_offset, aux, next_offset = struct.unpack_from('<HHIII', elf.read(address, 16))
        if version != 1:
            raise ValueError('unsupported verneed revision')
        library = dynamic_string(elf, strtab, file_offset)
        aux_address = address + aux
        for _ in range(aux_count):
            _hash, flags, other, name_offset, aux_next = struct.unpack_from('<IHHII', elf.read(aux_address, 16))
            name = dynamic_string(elf, strtab, name_offset)
            needs.setdefault(library, []).append({'name': name, 'index': other, 'weak': bool(flags & 2)})
            index_names[other] = (library, name)
            aux_address += aux_next
        address += next_offset
    return needs, index_names


def read_verdef(elf, strtab):
    address = elf.tag('VERDEF')
    count = elf.tag('VERDEFNUM') or 0
    definitions = []
    for _ in range(count):
        version, flags, ndx, aux_count, _hash, aux, next_offset = struct.unpack_from('<HHHHIII', elf.read(address, 20))
        if version != 1:
            raise ValueError('unsupported verdef revision')
        names = []
        aux_address = address + aux
        for _ in range(aux_count):
            name_offset, aux_next = struct.unpack_from('<II', elf.read(aux_address, 8))
            names.append(dynamic_string(elf, strtab, name_offset))
            aux_address += aux_next
        definitions.append({'index': ndx, 'base': bool(flags & 1), 'weak': bool(flags & 2), 'names': names})
        address += next_offset
    return definitions


def read_relocations(elf, symbols):
    out = {'rela': collections.Counter(), 'plt': collections.Counter(), 'rel': collections.Counter()}
    named_with_addend = 0
    tls_symbol_relocations = 0
    details = {'ifunc_targets': 0}
    rela, relasz = elf.tag('RELA'), elf.tag('RELASZ')
    tables = []
    if rela is not None:
        tables.append(('rela', rela, relasz, 24))
    jmprel, pltrelsz = elf.tag('JMPREL'), elf.tag('PLTRELSZ')
    if jmprel is not None:
        entry = 24 if elf.tag('PLTREL') == DT_BY_NAME['RELA'] else 16
        tables.append(('plt', jmprel, pltrelsz, entry))
    rel, relsz = elf.tag('REL'), elf.tag('RELSZ')
    if rel is not None:
        tables.append(('rel', rel, relsz, 16))
    for table, address, size, entry in tables:
        data = elf.read(address, size)
        for offset in range(0, size - size % entry, entry):
            _r_offset, info = struct.unpack_from('<QQ', data, offset)
            kind = info & 0xffffffff
            symbol = info >> 32
            addend = struct.unpack_from('<q', data, offset + 16)[0] if entry == 24 else 0
            out[table][RELOC_NAMES.get(kind, str(kind))] += 1
            if symbol and addend:
                named_with_addend += 1
            if kind in TLS_RELOCATIONS and symbol:
                tls_symbol_relocations += 1
            if kind == 1032:
                details['ifunc_targets'] += 1
    relr_count = None
    relr, relrsz = elf.tag('RELR'), elf.tag('RELRSZ')
    if relr is not None:
        words = struct.unpack_from('<%dQ' % (relrsz // 8), elf.read(relr, relrsz))
        relr_count = 0
        for word in words:
            if word & 1 == 0:
                relr_count += 1
            else:
                relr_count += bin(word >> 1).count('1')
    histogram = collections.Counter()
    for table in out.values():
        histogram.update(table)
    return {
        'tables': {name: dict(sorted(counter.items())) for name, counter in out.items() if counter},
        'histogram': dict(sorted(histogram.items())),
        'total': sum(histogram.values()),
        'relr_entries': relr_count,
        'named_with_addend': named_with_addend,
        'tls_symbol_relocations': tls_symbol_relocations,
    }


def read_notes(elf):
    notes = []
    for segment in elf.segments:
        if segment['type'] != 'NOTE':
            continue
        data = elf.data[segment['offset']:segment['offset'] + segment['filesz']]
        offset = 0
        while offset + 12 <= len(data):
            namesz, descsz, kind = struct.unpack_from('<III', data, offset)
            name = data[offset + 12:offset + 12 + namesz].rstrip(b'\0').decode('latin-1')
            desc_start = offset + 12 + ((namesz + 3) & ~3)
            desc = data[desc_start:desc_start + descsz]
            note = {'owner': name, 'type': kind, 'bytes': descsz}
            if name == 'GNU' and kind == 3:
                note['kind'] = 'BUILD_ID'
                note['build_id'] = desc.hex()
            elif name == 'GNU' and kind == 5:
                note['kind'] = 'PROPERTY_TYPE_0'
                properties = []
                position = 0
                while position + 8 <= len(desc):
                    pr_type, pr_size = struct.unpack_from('<II', desc, position)
                    value = desc[position + 8:position + 8 + pr_size]
                    if pr_type == 0xc0000000 and pr_size >= 4:
                        bits = struct.unpack_from('<I', value)[0]
                        properties.append({'AARCH64_FEATURE_1_AND': [name for bit, name in ((1, 'BTI'), (2, 'PAC'), (4, 'GCS')) if bits & bit]})
                    else:
                        properties.append({'type': hex(pr_type), 'bytes': pr_size})
                    position += 8 + ((pr_size + 7) & ~7)
                note['properties'] = properties
            elif name == 'GNU' and kind == 1:
                note['kind'] = 'ABI_TAG'
            notes.append(note)
            offset = desc_start + ((descsz + 3) & ~3)
    return notes


def classify_needed(name, bundled_sonames):
    if name in bundled_sonames:
        return 'bundled'
    if name in MANYLINUX_OS_LIBRARIES:
        return 'os'
    if name.startswith('libpython'):
        return 'runtime'
    return 'unknown'


def survey_image(path, wheel, bundled_sonames):
    elf = Elf(path)
    strtab = elf.tag('STRTAB')
    needed = [dynamic_string(elf, strtab, offset) for offset in elf.tags('NEEDED')]
    soname = elf.tag('SONAME')
    soname = dynamic_string(elf, strtab, soname) if soname is not None else None
    rpath = elf.tag('RPATH')
    runpath = elf.tag('RUNPATH')
    symbols, symbol_counts = read_symbols(elf, strtab)
    verneed, version_names = read_verneed(elf, strtab)
    verdef = read_verdef(elf, strtab)
    relocations = read_relocations(elf, symbols)
    notes = read_notes(elf)
    flags = elf.tag('FLAGS') or 0
    flags_1 = elf.tag('FLAGS_1') or 0
    undefined = [s for s in symbols if s['index'] and not s['defined']]
    defined = [s for s in symbols if s['index'] and s['defined'] and s['binding'] != 'LOCAL' and s['type'] != 'SECTION']
    tags = [DT_NAMES.get(tag, hex(tag)) for tag, _ in elf.dynamic]
    tag_counts = collections.Counter(tags)
    unknown_tags = sorted(set(tags) - GLUE_ADMITTED_TAGS)
    segment_types = [s['type'] for s in elf.segments]
    unknown_segments = sorted(set(segment_types) - GLUE_ADMITTED_SEGMENTS)
    stack = [s for s in elf.segments if s['type'] == 'GNU_STACK']
    tls = [s for s in elf.segments if s['type'] == 'TLS']
    property_segments = [s for s in elf.segments if s['type'] == 'GNU_PROPERTY']
    version_needs = {}
    for symbol in undefined:
        index = symbol['version_index']
        if index is not None and index >= 2 and index in version_names:
            library, version = version_names[index]
            version_needs.setdefault(library, collections.Counter())[version] += 1
    unversioned_undefined = [s for s in undefined if s['version_index'] in (None, 0, 1)]
    python_imports = sorted(s['name'] for s in unversioned_undefined if s['name'].startswith(('Py', '_Py')))
    private_python = [name for name in python_imports if name.startswith('_Py')]
    weak_undefined = sorted(s['name'] for s in undefined if s['binding'] == 'WEAK')
    weak_hooks = [name for name in weak_undefined if name in GNU_WEAK_HOOKS]
    object_imports = sorted(s['name'] for s in undefined if s['type'] == 'OBJECT')
    glibc_versions = sorted({v['name'] for versions in verneed.values() for v in versions if v['name'].startswith('GLIBC_')}, key=lambda v: tuple(int(x) for x in v.split('_')[1].split('.')))
    constructors = {
        'init': elf.tag('INIT') is not None,
        'fini': elf.tag('FINI') is not None,
        'init_array': (elf.tag('INIT_ARRAYSZ') or 0) // 8,
        'fini_array': (elf.tag('FINI_ARRAYSZ') or 0) // 8,
        'preinit_array': (elf.tag('PREINIT_ARRAYSZ') or 0) // 8,
    }
    facts = {
        'file': wheel['project'] + '-' + wheel['version'] + '/' + path.relative_to(wheel['directory']).as_posix(),
        'wheel': wheel['filename'],
        'project': wheel['project'],
        'role': 'bundled library' if '.libs/' in path.as_posix() else ('extension module (stable ABI)' if '.abi3.' in path.name else 'extension module'),
        'bytes': len(elf.data),
        'sha256': sha256(path),
        'header': {
            'type': 'ET_DYN' if elf.e_type == 3 else str(elf.e_type),
            'machine': 'AArch64' if elf.e_machine == 183 else str(elf.e_machine),
            'osabi': elf.osabi,
            'entry': elf.e_entry,
            'flags': elf.e_flags,
            'section_headers': bool(elf.sections),
        },
        'segments': [
            {'type': s['type'], 'flags': ''.join(flag for bit, flag in ((4, 'R'), (2, 'W'), (1, 'X')) if s['flags'] & bit), 'offset': s['offset'], 'vaddr': s['vaddr'], 'filesz': s['filesz'], 'memsz': s['memsz'], 'align': s['align']}
            for s in elf.segments
        ],
        'load_segments': len(elf.loads),
        'load_alignments': sorted({s['align'] for s in elf.loads}),
        'rwx_segment': any(s['flags'] & 3 == 3 for s in elf.segments),
        'first_load_at_zero': bool(elf.loads) and elf.loads[0]['vaddr'] == 0 and elf.loads[0]['offset'] == 0,
        'gnu_stack': None if not stack else ''.join(flag for bit, flag in ((4, 'R'), (2, 'W'), (1, 'X')) if stack[0]['flags'] & bit),
        'gnu_relro': any(s['type'] == 'GNU_RELRO' for s in elf.segments),
        'gnu_property_segment': bool(property_segments),
        'tls_segment': None if not tls else {'filesz': tls[0]['filesz'], 'memsz': tls[0]['memsz'], 'align': tls[0]['align']},
        'notes': notes,
        'dynamic': {
            'entries': len(elf.dynamic),
            'tags': dict(sorted(tag_counts.items())),
            'tags_outside_glue_admission': unknown_tags,
            'needed': [{'name': name, 'class': classify_needed(name, bundled_sonames)} for name in needed],
            'soname': soname,
            'rpath': dynamic_string(elf, strtab, rpath) if rpath is not None else None,
            'runpath': dynamic_string(elf, strtab, runpath) if runpath is not None else None,
            'flags': [name for bit, name in DF_BITS.items() if flags & bit] + ([hex(flags & ~sum(DF_BITS))] if flags & ~sum(DF_BITS) else []),
            'flags_1': [name for bit, name in DF_1_BITS.items() if flags_1 & bit] + ([hex(flags_1 & ~sum(DF_1_BITS))] if flags_1 & ~sum(DF_1_BITS) else []),
            'bind_now': bool(flags & 8 or flags_1 & 1 or elf.tag('BIND_NOW') is not None),
            'textrel': bool(flags & 4 or elf.tag('TEXTREL') is not None),
            'hash_tables': [name for name in ('HASH', 'GNU_HASH') if elf.tag(name) is not None],
            'string_table_bytes': elf.tag('STRSZ'),
            'tlsdesc_tags': [name for name in ('TLSDESC_PLT', 'TLSDESC_GOT') if elf.tag(name) is not None],
            'constructors': constructors,
        },
        'symbols': {
            'count': len(symbols),
            'count_sources': symbol_counts,
            'defined_exports': len(defined),
            'undefined': len(undefined),
            'undefined_unversioned': len(unversioned_undefined),
            'by_binding': dict(collections.Counter(s['binding'] for s in symbols[1:])),
            'by_type': dict(collections.Counter(s['type'] for s in symbols[1:])),
            'by_visibility': dict(collections.Counter(s['visibility'] for s in symbols[1:])),
            'gnu_unique': sorted(s['name'] for s in symbols if s['binding'] == 'GNU_UNIQUE')[:40],
            'gnu_unique_count': sum(1 for s in symbols if s['binding'] == 'GNU_UNIQUE'),
            'non_default_visibility_count': sum(1 for s in symbols[1:] if s['visibility'] != 'DEFAULT'),
            'ifunc': sorted(s['name'] for s in symbols if s['type'] == 'GNU_IFUNC'),
            'tls': sorted(s['name'] for s in symbols if s['type'] == 'TLS')[:40],
            'tls_count': sum(1 for s in symbols if s['type'] == 'TLS'),
            'absolute_or_common': sum(1 for s in symbols[1:] if s['shndx'] >= 0xff00),
            'version_hidden': sum(1 for s in symbols if s['version_hidden']),
            'defined_versioned': sum(1 for s in symbols if s['defined'] and s['version_index'] is not None and s['version_index'] >= 2),
            'weak_undefined': weak_undefined,
            'weak_undefined_beyond_hooks': [name for name in weak_undefined if name not in GNU_WEAK_HOOKS],
            'weak_hooks': weak_hooks,
            'object_imports': object_imports,
            'python_imports': len(python_imports),
            'python_private_imports': private_python,
            'pyinit_exports': sorted(s['name'] for s in defined if s['name'].startswith('PyInit_')),
            'dlopen_family_imports': sorted(s['name'] for s in undefined if s['name'] in DLOPEN_FAMILY),
            'thread_api_imports': sorted(s['name'] for s in undefined if s['name'] in THREAD_API),
            'unwind_imports': sorted(s['name'] for s in undefined if s['name'].startswith(UNWIND_API_PREFIXES)),
            'unversioned_non_python_imports': sorted(s['name'] for s in unversioned_undefined if not s['name'].startswith(('Py', '_Py')) and s['name'] not in GNU_WEAK_HOOKS),
        },
        'versions': {
            'needs': {library: [v['name'] for v in versions] for library, versions in verneed.items()},
            'needs_by_symbol_count': {library: dict(counter) for library, counter in version_needs.items()},
            'glibc_max': glibc_versions[-1] if glibc_versions else None,
            'definitions': verdef,
        },
        'relocations': relocations,
    }
    facts['glue_native_rejection_ladder'] = rejection_ladder(facts, elf)
    facts['_exports'] = {s['name'] for s in defined}
    facts['_unversioned_imports'] = {s['name']: s['binding'] for s in unversioned_undefined}
    facts['_undefined_names'] = {s['name'] for s in undefined}
    facts['_python_imports'] = python_imports
    return facts


def runtime_exports(path):
    """Defined non-local dynamic symbol names of the selected runtime library."""
    elf = Elf(path)
    symbols, _ = read_symbols(elf, elf.tag('STRTAB'))
    return {s['name'] for s in symbols if s['index'] and s['defined'] and s['binding'] != 'LOCAL' and s['type'] != 'SECTION'}


def rejection_ladder(facts, elf):
    """Every inspector rejection this image would meet, in elf.rs check order."""
    ladder = []
    if facts['header']['entry']:
        ladder.append('header: shared image entry point is nonzero')
    for kind in sorted({s['type'] for s in elf.segments} - GLUE_ADMITTED_SEGMENTS):
        ladder.append('segment: program-header type ' + kind)
    if facts['rwx_segment']:
        ladder.append('segment: writable executable segment')
    for segment in elf.segments:
        if segment['type'] == 'NOTE' and segment['filesz'] > GLUE_LIMITS['note_segment_bytes']:
            ladder.append('segment: note segment exceeds 4096 bytes')
    if any(note.get('kind') != 'BUILD_ID' for note in facts['notes']):
        ladder.append('segment: note other than a GNU build-id')
    if facts['gnu_stack'] != 'RW':
        ladder.append('segment: GNU_STACK missing or executable')
    if not facts['first_load_at_zero']:
        ladder.append('segment: first load segment not at image base zero')
    if facts['bytes'] > GLUE_LIMITS['image_bytes']:
        ladder.append('limit: image exceeds 64 MiB')
    if facts['bytes'] > GLUE_LIMITS['extension_profile_image_bytes']:
        ladder.append('limit: image exceeds the 256 KiB Python extension-profile bound')
    for tag in facts['dynamic']['tags_outside_glue_admission']:
        ladder.append('dynamic: tag ' + tag)
    if len(facts['dynamic']['needed']) > GLUE_LIMITS['needed']:
        ladder.append('dynamic: more than 64 NEEDED entries')
    if not facts['dynamic']['bind_now']:
        ladder.append('dynamic: immediate binding (BIND_NOW) is required')
    if set(facts['dynamic']['flags']) - {'BIND_NOW'} or set(facts['dynamic']['flags_1']) - {'NOW'}:
        ladder.append('dynamic: flags outside immediate binding')
    if facts['dynamic']['soname'] is None:
        ladder.append('dynamic: missing SONAME')
    if 'HASH' not in facts['dynamic']['hash_tables']:
        ladder.append('dynamic: missing SysV DT_HASH')
    if facts['symbols']['count'] > GLUE_LIMITS['symbols']:
        ladder.append('limit: more than 65,536 dynamic symbols')
    if len(facts['versions']['needs']) > GLUE_LIMITS['version_need_records']:
        ladder.append('limit: more than 64 version-need records')
    if facts['versions']['definitions']:
        ladder.append('symbols: VERDEF version definitions (defined symbols with version index above 1)')
    if facts['symbols']['version_hidden']:
        ladder.append('symbols: hidden symbol-version bit')
    if facts['symbols']['gnu_unique_count']:
        ladder.append('symbols: STB_GNU_UNIQUE binding')
    if facts['symbols']['tls_count']:
        ladder.append('symbols: STT_TLS symbols')
    if facts['symbols']['ifunc']:
        ladder.append('symbols: STT_GNU_IFUNC symbols')
    if facts['symbols']['non_default_visibility_count']:
        ladder.append('symbols: non-default visibility (hidden/protected)')
    if facts['symbols']['absolute_or_common']:
        ladder.append('symbols: absolute/common section index')
    if facts['symbols']['undefined']:
        ladder.append('symbols: every undefined symbol must be declared by the import policy (%d undefined)' % facts['symbols']['undefined'])
    if facts['symbols']['weak_undefined_beyond_hooks']:
        ladder.append('symbols: weak undefined symbols beyond the three compiler hooks')
    if facts['symbols']['object_imports']:
        ladder.append('symbols: OBJECT imports require the data-import opt-in')
    if facts['relocations']['total'] > GLUE_LIMITS['relocations']:
        ladder.append('limit: more than 65,536 relocations')
    for kind in sorted(facts['relocations']['histogram']):
        if kind not in ('GLOB_DAT', 'JUMP_SLOT', 'RELATIVE'):
            ladder.append('relocations: type ' + kind)
    if facts['relocations']['named_with_addend']:
        ladder.append('relocations: named relocation with nonzero addend')
    if facts['relocations']['relr_entries'] is not None:
        ladder.append('relocations: RELR table')
    return ladder


def run_inspector(inspector, path, facts, temp):
    def call(arguments):
        completed = subprocess.run([str(inspector), *arguments, str(path)], capture_output=True, text=True, check=False)
        if completed.returncode != 0 and not completed.stdout:
            return 'tool error: ' + completed.stderr.strip()
        return completed.stdout.strip()
    strict = call([])
    allow = temp / (path.name + '.allow')
    data = temp / (path.name + '.data')
    allow.write_text(''.join(name + '\n' for name in sorted(facts['_undefined_names'])))
    data.write_text(''.join(name + '\n' for name in facts['symbols']['object_imports']))
    permissive = call(['--soname', facts['dynamic']['soname'] or path.name, '--allow-file', str(allow), '--data-import-file', str(data)])
    return {'strict_profile_call': strict, 'declared_imports_call': permissive}


def readelf_facts(readelf, path):
    def run(flag):
        return subprocess.run([str(readelf), '-W', flag, str(path)], capture_output=True, text=True, check=True).stdout
    dynamic = run('--dynamic-table')
    needed = re.findall(r'\(NEEDED\)\s+Shared library: \[(.+?)\]', dynamic)
    soname = re.findall(r'\(SONAME\)\s+Library soname: \[(.+?)\]', dynamic)
    rpath = re.findall(r'\((?:RPATH|RUNPATH)\)\s+Library r(?:un)?path: \[(.+?)\]', dynamic)
    headers = run('--program-headers')
    segments = []
    in_table = False
    for line in headers.splitlines():
        if line.startswith('  Type'):
            in_table = True
            continue
        if in_table:
            if not line.strip() or line.startswith(' Section'):
                break
            segments.append(line.split()[0])
    relocations = collections.Counter()
    for line in run('--relocations').splitlines():
        fields = line.split()
        if len(fields) >= 3 and fields[2].startswith('R_AARCH64_'):
            name = fields[2][len('R_AARCH64_'):]
            relocations[RELOC_ALIASES.get(name, name)] += 1
    dynsyms = sum(1 for line in run('--dyn-syms').splitlines() if re.match(r'\s+\d+:\s', line))
    needs = {}
    library = None
    for line in run('--version-info').splitlines():
        if 'Version definitions' in line:
            library = None
            break
        match = re.search(r'File: (\S+)\s+Cnt:', line)
        if match:
            library = match.group(1)
            needs.setdefault(library, [])
            continue
        match = re.search(r'Name: (\S+)\s+Flags:', line)
        if match and library is not None:
            needs[library].append(match.group(1))
    return {
        'needed': needed, 'soname': soname[0] if soname else None, 'rpath': rpath[0] if rpath else None,
        'segments': segments, 'relocations': dict(sorted(relocations.items())), 'dynsym_count': dynsyms,
        'version_needs': {library: sorted(names) for library, names in needs.items()},
    }


def cross_check(facts, reference):
    differences = []
    mine = {
        'needed': [n['name'] for n in facts['dynamic']['needed']],
        'soname': facts['dynamic']['soname'],
        'rpath': facts['dynamic']['rpath'] or facts['dynamic']['runpath'],
        'segments': [s['type'] for s in facts['segments']],
        'relocations': facts['relocations']['histogram'],
        'dynsym_count': facts['symbols']['count'],
        'version_needs': {library: sorted(names) for library, names in facts['versions']['needs'].items()},
    }
    for key, value in mine.items():
        if value != reference[key]:
            differences.append({'fact': key, 'survey': value, 'readelf': reference[key]})
    return {'agreed': not differences, 'differences': differences}


FEATURES = [
    ('gnu_hash_only', 'DT_GNU_HASH without a SysV DT_HASH table', lambda f: f['dynamic']['hash_tables'] == ['GNU_HASH']),
    ('no_soname', 'No DT_SONAME (every extension module)', lambda f: f['dynamic']['soname'] is None),
    ('nonzero_entry', 'Nonzero e_entry in an ET_DYN image', lambda f: bool(f['header']['entry'])),
    ('lazy_binding', 'No BIND_NOW flag; relies on the caller\'s RTLD_NOW or lazy PLT binding', lambda f: not f['dynamic']['bind_now']),
    ('needed_os_glibc', 'NEEDED glibc components (libc, libm, libpthread, libdl, librt)', lambda f: any(n['name'] in {'libc.so.6', 'libm.so.6', 'libpthread.so.0', 'libdl.so.2', 'librt.so.1', 'libutil.so.1'} for n in f['dynamic']['needed'])),
    ('needed_libgcc_s', 'NEEDED libgcc_s.so.1 (unwinder, GCC_* symbol versions)', lambda f: any(n['name'] == 'libgcc_s.so.1' for n in f['dynamic']['needed'])),
    ('needed_libstdcxx', 'NEEDED libstdc++.so.6 (GLIBCXX/CXXABI symbol versions)', lambda f: any(n['name'] == 'libstdc++.so.6' for n in f['dynamic']['needed'])),
    ('needed_bundled', 'NEEDED a library vendored in the wheel\'s .libs directory', lambda f: any(n['class'] == 'bundled' for n in f['dynamic']['needed'])),
    ('needed_unknown', 'NEEDED a library that is neither OS policy, bundled nor runtime', lambda f: any(n['class'] == 'unknown' for n in f['dynamic']['needed'])),
    ('rpath_origin', 'DT_RPATH/DT_RUNPATH with $ORIGIN', lambda f: '$ORIGIN' in (f['dynamic']['rpath'] or f['dynamic']['runpath'] or '')),
    ('python_api_global_scope', 'Undefined Py*/_Py* symbols with no NEEDED provider (resolved through the global scope)', lambda f: f['symbols']['python_imports'] > 0),
    ('python_private_api', 'Undefined private-prefix _Py* symbols', lambda f: bool(f['symbols']['python_private_imports'])),
    ('python_api_missing_from_runtime', 'Python imports the selected runtime does not export (needs --runtime-library)', lambda f: bool(f['symbols'].get('python_imports_missing_from_runtime'))),
    ('no_needed', 'No DT_NEEDED at all; every import binds through the global scope', lambda f: not f['dynamic']['needed']),
    ('unversioned_bundled_imports', 'Unversioned imports satisfied by another image of the same wheel', lambda f: bool(f['symbols'].get('bundled_imports'))),
    ('global_scope_strong_imports', 'Strong unversioned non-Python imports with no NEEDED provider (global scope)', lambda f: bool(f['symbols'].get('global_scope_strong_imports'))),
    ('global_scope_weak_imports', 'Weak unversioned imports that bind through the global scope or stay null', lambda f: bool(f['symbols'].get('global_scope_weak_imports'))),
    ('tls_segment', 'PT_TLS segment (thread-local storage template)', lambda f: f['tls_segment'] is not None),
    ('tls_relocations', 'TLS relocations (TLSDESC/TPREL64/DTPMOD64/DTPREL64)', lambda f: any(k in f['relocations']['histogram'] for k in ('TLSDESC', 'TLS_TPREL64', 'TLS_DTPMOD64', 'TLS_DTPREL64'))),
    ('tls_initial_exec', 'Initial-exec TLS relocations (TLS_TPREL64) that consume static TLS surplus under dlopen', lambda f: 'TLS_TPREL64' in f['relocations']['histogram']),
    ('tls_symbols', 'STT_TLS dynamic symbols', lambda f: f['symbols']['tls_count'] > 0),
    ('thread_local_destructors', 'Imports __cxa_thread_atexit_impl (thread-exit destructors)', lambda f: '__cxa_thread_atexit_impl' in f['symbols']['thread_api_imports']),
    ('thread_creation', 'Imports pthread_create (library-created threads)', lambda f: 'pthread_create' in f['symbols']['thread_api_imports']),
    ('ifunc', 'STT_GNU_IFUNC symbols or IRELATIVE relocations', lambda f: bool(f['symbols']['ifunc']) or 'IRELATIVE' in f['relocations']['histogram']),
    ('abs64_relocations', 'R_AARCH64_ABS64 symbolic relocations (with addends)', lambda f: 'ABS64' in f['relocations']['histogram']),
    ('relr', 'DT_RELR compact relative relocations', lambda f: f['relocations']['relr_entries'] is not None),
    ('rel_table', 'DT_REL (addend-less) relocation table', lambda f: 'rel' in f['relocations']['tables']),
    ('copy_relocations', 'R_AARCH64_COPY relocations', lambda f: 'COPY' in f['relocations']['histogram']),
    ('gnu_unique', 'STB_GNU_UNIQUE symbols (C++ inline/template statics)', lambda f: f['symbols']['gnu_unique_count'] > 0),
    ('non_default_visibility', 'STV_PROTECTED/HIDDEN dynamic symbols', lambda f: f['symbols']['non_default_visibility_count'] > 0),
    ('verdef', 'DT_VERDEF: the image defines its own symbol versions', lambda f: bool(f['versions']['definitions'])),
    ('version_hidden', 'Hidden symbol-version bit on dynamic symbols', lambda f: f['symbols']['version_hidden'] > 0),
    ('weak_undefined', 'Weak undefined symbols beyond the three compiler hooks', lambda f: bool(f['symbols']['weak_undefined_beyond_hooks'])),
    ('object_imports', 'Undefined OBJECT (data) imports', lambda f: bool(f['symbols']['object_imports'])),
    ('constructors', 'DT_INIT/DT_INIT_ARRAY constructors', lambda f: f['dynamic']['constructors']['init'] or f['dynamic']['constructors']['init_array'] > 0),
    ('destructors', 'DT_FINI/DT_FINI_ARRAY destructors', lambda f: f['dynamic']['constructors']['fini'] or f['dynamic']['constructors']['fini_array'] > 0),
    ('unwind_imports', 'Imports libgcc_s unwinder entry points (_Unwind_*) or C++ EH personality', lambda f: bool(f['symbols']['unwind_imports'])),
    ('dlopen_family', 'Imports dlopen/dlsym/dl_iterate_phdr family', lambda f: bool(f['symbols']['dlopen_family_imports'])),
    ('dlopen_runtime_loading', 'Imports dlopen/dlmopen (can load more code at runtime)', lambda f: any(n in ('dlopen', 'dlmopen', '__libc_dlopen_mode') for n in f['symbols']['dlopen_family_imports'])),
    ('gnu_property', 'PT_GNU_PROPERTY / .note.gnu.property (BTI/PAC)', lambda f: f['gnu_property_segment'] or any(n.get('kind') == 'PROPERTY_TYPE_0' for n in f['notes'])),
    ('build_id', 'GNU build-id note', lambda f: any(n.get('kind') == 'BUILD_ID' for n in f['notes'])),
    ('gnu_stack_nonexec', 'PT_GNU_STACK present and non-executable', lambda f: f['gnu_stack'] == 'RW'),
    ('gnu_relro', 'PT_GNU_RELRO', lambda f: f['gnu_relro']),
    ('textrel', 'DT_TEXTREL / DF_TEXTREL', lambda f: f['dynamic']['textrel']),
    ('symbolic', 'DF_SYMBOLIC', lambda f: 'SYMBOLIC' in f['dynamic']['flags']),
    ('many_load_segments', 'More than four PT_LOAD segments (patchelf-extended images)', lambda f: f['load_segments'] > 4),
    ('over_256k', 'Larger than the 256 KiB Python extension-profile bound', lambda f: f['bytes'] > GLUE_LIMITS['extension_profile_image_bytes']),
    ('over_16m', 'Larger than the 16 MiB Lua closure per-image bound', lambda f: f['bytes'] > 16 * 1024 * 1024),
    ('over_64m', 'Larger than the 64 MiB inspector bound', lambda f: f['bytes'] > GLUE_LIMITS['image_bytes']),
    ('symbols_over_cap', 'More than 65,536 dynamic symbols', lambda f: f['symbols']['count'] > GLUE_LIMITS['symbols']),
    ('relocations_over_cap', 'More than 65,536 relocations', lambda f: f['relocations']['total'] > GLUE_LIMITS['relocations']),
]


def feature_matrix(images):
    matrix = {}
    for key, description, predicate in FEATURES:
        members = [image['file'] for image in images if predicate(image)]
        matrix[key] = {'description': description, 'count': len(members), 'images': members}
    return matrix


def markdown(report):
    lines = ['# Native corpus survey summary', '', 'Generated by `fixtures/native/corpus/survey.py` on ' + report['generated']['date'] + '. See `survey.json` for every fact.', '']
    lines += ['## Images', '', 'The inspector column is the first rejection raised by `crates/glue-native/src/elf.rs` when every undefined symbol is declared and the expected SONAME is the image\'s own; the strict closed-profile call is recorded in `survey.json`.', '', '| Image | Wheel | Bytes | SONAME | NEEDED | RPATH | TLS | Relocation types | First inspector rejection |', '| --- | --- | --- | --- | --- | --- | --- | --- | --- |']
    for image in report['images']:
        needed = ', '.join(n['name'] for n in image['dynamic']['needed']) or '(none)'
        tls = 'yes' if image['tls_segment'] else 'no'
        kinds = ', '.join('%s×%d' % (k, v) for k, v in image['relocations']['histogram'].items())
        first = image.get('glue_native_inspector', {}).get('declared_imports_call', 'not run')
        rpath = image['dynamic']['rpath'] or image['dynamic']['runpath'] or ''
        lines.append('| `%s` | %s | %s | %s | %s | %s | %s | %s | %s |' % (image['file'], image['project'], format(image['bytes'], ','), image['dynamic']['soname'] or '', needed, rpath, tls, kinds, first))
    lines += ['', '## Feature matrix', '', 'Count is the number of corpus images (of %d) that exhibit the feature.' % len(report['images']), '', '| Feature | Description | Count | Images |', '| --- | --- | --- | --- |']
    for key, entry in report['feature_matrix'].items():
        names = ', '.join('`' + Path(name).name + '`' for name in entry['images'])
        if len(entry['images']) > 6:
            names = ', '.join('`' + Path(name).name + '`' for name in entry['images'][:5]) + ', … (%d)' % len(entry['images'])
        lines.append('| `%s` | %s | %d | %s |' % (key, entry['description'], entry['count'], names))
    lines += ['', '## Blockers against the current glue-native inspector', '', 'Each line is a rejection the inspector in `crates/glue-native/src/elf.rs` would raise; the count is images affected.', '', '| Rejection | Count |', '| --- | --- |']
    for message, count in report['rejection_ladder_counts']:
        lines.append('| %s | %d |' % (message, count))
    api = report['python_api']
    lines += ['', '## Python API imports', '', 'The 22 extension modules import %d distinct `Py*`/`_Py*` symbols, %d of them with the private `_Py` prefix.' % (api['distinct_symbols'], len(api['private_prefix_symbols']))]
    if 'missing_from_runtime' in api:
        runtime = report['generated']['runtime_library']
        lines.append('Checked against the selected runtime library (%s bytes, SHA-256 `%s`, %d exports): %s' % (format(runtime['bytes'], ','), runtime['sha256'], runtime['exports'], 'every imported symbol is exported.' if not api['missing_from_runtime'] else 'missing exports: ' + ', '.join('`%s`' % name for name in api['missing_from_runtime'])))
    return '\n'.join(lines) + '\n'


def main():
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument('--corpus', type=Path, default=ROOT / 'target' / 'native-corpus')
    parser.add_argument('--pins', type=Path, default=HERE / 'wheel-pins.json')
    parser.add_argument('--inspector', type=Path, help='path to the built glue-native elf-survey example')
    parser.add_argument('--readelf', type=Path, help='llvm-readelf or GNU readelf for cross-checking')
    parser.add_argument('--runtime-library', type=Path, help='the selected libpython3.13.so.1.0, to check every Python import against its exports')
    parser.add_argument('--output', type=Path, default=HERE / 'survey.json')
    parser.add_argument('--markdown', type=Path, default=HERE / 'summary.md')
    arguments = parser.parse_args()
    pins = json.loads(arguments.pins.read_bytes())
    wheels = []
    for pin in pins['wheels']:
        directory = arguments.corpus / 'unpacked' / (pin['project'] + '-' + pin['version'])
        if not directory.is_dir():
            fail('missing ' + str(directory) + '; run fetch-corpus.py first')
        wheel_path = arguments.corpus / 'wheels' / pin['filename']
        if sha256(wheel_path) != pin['sha256']:
            fail('wheel identity differs: ' + pin['filename'])
        wheels.append({**pin, 'directory': directory})
    images = []
    runtime = None
    if arguments.runtime_library:
        exports = runtime_exports(arguments.runtime_library)
        runtime = {
            'file': arguments.runtime_library.name, 'bytes': arguments.runtime_library.stat().st_size,
            'sha256': sha256(arguments.runtime_library), 'exports': len(exports), '_exports': exports,
        }
    python_api = collections.Counter()
    with tempfile.TemporaryDirectory() as temp_name:
        temp = Path(temp_name)
        for wheel in wheels:
            paths = sorted(p for p in wheel['directory'].rglob('*') if p.is_file() and '.so' in p.suffixes)
            bundled = {}
            for path in paths:
                if '.libs/' in path.as_posix():
                    elf = Elf(path)
                    soname = elf.tag('SONAME')
                    if soname is not None:
                        bundled[dynamic_string(elf, elf.tag('STRTAB'), soname)] = path.name
            wheel_images = [(path, survey_image(path, wheel, bundled)) for path in paths]
            exports = {}
            for path, facts in wheel_images:
                for name in facts['_exports']:
                    exports.setdefault(name, path.name)
            for path, facts in wheel_images:
                # Unversioned imports have no NEEDED/version provider of their
                # own: they bind to another image of the wheel, or through the
                # process's global lookup scope (weak ones may stay null).
                bundled_imports = {}
                strong, weak = [], []
                for name, binding in sorted(facts['_unversioned_imports'].items()):
                    if name.startswith(('Py', '_Py')) or name in GNU_WEAK_HOOKS:
                        continue
                    provider = exports.get(name)
                    if provider and provider != path.name:
                        bundled_imports[provider] = bundled_imports.get(provider, 0) + 1
                    elif binding == 'WEAK':
                        weak.append(name)
                    else:
                        strong.append(name)
                facts['symbols']['bundled_imports'] = bundled_imports
                facts['symbols']['global_scope_strong_imports'] = strong
                facts['symbols']['global_scope_weak_imports'] = weak
                python_api.update(facts['_python_imports'])
                if runtime:
                    facts['symbols']['python_imports_missing_from_runtime'] = sorted(name for name in facts['_python_imports'] if name not in runtime['_exports'])
                if arguments.inspector:
                    facts['glue_native_inspector'] = run_inspector(arguments.inspector, path, facts, temp)
                if arguments.readelf:
                    facts['readelf_cross_check'] = cross_check(facts, readelf_facts(arguments.readelf, path))
                for key in ('_exports', '_unversioned_imports', '_undefined_names', '_python_imports'):
                    facts.pop(key, None)
                images.append(facts)
    images.sort(key=lambda image: image['file'])
    ladder_counts = collections.Counter()
    for image in images:
        for message in image['glue_native_rejection_ladder']:
            ladder_counts[re.sub(r' \(\d+ undefined\)', '', message)] += 1
    report = {
        'schema_version': 0,
        'generated': {
            'date': datetime.date.today().isoformat(),
            'tool': 'fixtures/native/corpus/survey.py',
            'pins_sha256': sha256(arguments.pins),
            'inspector': str(arguments.inspector) if arguments.inspector else None,
            'readelf': subprocess.run([str(arguments.readelf), '--version'], capture_output=True, text=True, check=False).stdout.strip().splitlines()[0] if arguments.readelf else None,
            'glue_limits': GLUE_LIMITS,
        },
        'wheels': [{key: pin[key] for key in ('project', 'version', 'filename', 'sha256', 'role')} | {'images': sum(1 for image in images if image['project'] == pin['project'])} for pin in pins['wheels']],
        'images': images,
        'feature_matrix': feature_matrix(images),
        'rejection_ladder_counts': sorted(ladder_counts.items(), key=lambda item: (-item[1], item[0])),
        'python_api': {
            'distinct_symbols': len(python_api),
            'private_prefix_symbols': sorted(name for name in python_api if name.startswith('_Py')),
            'by_image_count': dict(sorted(python_api.items())),
        },
    }
    if runtime:
        report['generated']['runtime_library'] = {key: value for key, value in runtime.items() if key != '_exports'}
        report['python_api']['missing_from_runtime'] = sorted(name for name in python_api if name not in runtime['_exports'])
    if arguments.readelf:
        disagreements = [image['file'] for image in images if not image['readelf_cross_check']['agreed']]
        report['generated']['readelf_disagreements'] = disagreements
    arguments.output.write_text(json.dumps(report, indent=1, sort_keys=True) + '\n')
    arguments.markdown.write_text(markdown(report))
    print('surveyed %d images from %d wheels -> %s, %s' % (len(images), len(wheels), arguments.output, arguments.markdown))
    if arguments.readelf and report['generated']['readelf_disagreements']:
        print('readelf cross-check disagreements: ' + ', '.join(report['generated']['readelf_disagreements']))


if __name__ == '__main__':
    main()
