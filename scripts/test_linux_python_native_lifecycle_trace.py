"""Independent schema/geometry controls and bounded actual lifecycle mutations."""
import copy
import gzip
import hashlib
import importlib.util
import json
from pathlib import Path
import re
import struct
import sys
import tempfile
import unittest
from unittest.mock import patch
import zipfile


spec = importlib.util.spec_from_file_location('lifecycle_policy_test',
    Path(__file__).with_name('check-linux-python-native-lifecycle-trace.py'))
C = importlib.util.module_from_spec(spec)
spec.loader.exec_module(C)


def record(mode='host-host'):
    manifest = C.expected_manifest(mode)
    raw = json.dumps(manifest, sort_keys=True, separators=(',', ':'), ensure_ascii=False).encode()
    runtime, native = C.cell_for(mode).split('-')
    declarations = {name: {'sha256': C.NATIVE_PINS[name]['sha256']} | (
        {'path': C.prefix_for(mode) + '/' + name} if native == 'host' else
        {'size': C.NATIVE_PINS[name]['size'], 'compression': 'stored'}) for name in C.NAMES}
    result = {'bytes': len(raw) + 4096, 'sha256': '0' * 64, 'manifest_sha256': hashlib.sha256(raw).hexdigest(),
        'manifest_bytes': len(raw), 'zip_directory_offset': len(raw) + 2048,
        'runtime': runtime, 'native': native, 'declarations': declarations,
        'application': {name: C.identity(data) for name, data in C.expected_application().items()}}
    if runtime == 'bundled':
        result['bytes'] += 80 * 1024 * 1024
        result['zip_directory_offset'] += 80 * 1024 * 1024
    if mode == 'corrupt-native':
        result['bytes'] += C.NATIVE_PINS[C.NAMES[0]]['size']
        result['zip_directory_offset'] += C.NATIVE_PINS[C.NAMES[0]]['size']
        result['corrupt_native_offset'] = len(raw) + 128
    return result


def write_host_archive(path, manifest=None, changed=None, extra=None):
    manifest = C.expected_manifest('host-host') if manifest is None else manifest
    raw = json.dumps(manifest, sort_keys=True, separators=(',', ':'), ensure_ascii=False).encode()
    with path.open('wb') as stream:
        stream.write(bytes(64) + raw)
        with zipfile.ZipFile(stream, 'w') as archive:
            for name, data in C.expected_application().items():
                compression = zipfile.ZIP_STORED if name == 'app/python/glue_demo/__init__.py' else zipfile.ZIP_DEFLATED
                archive.writestr(name, (changed or {}).get(name, data), compress_type=compression)
            if extra:
                archive.writestr(*extra)
        end = stream.tell()
        stream.seek(0)
        stream.write(b'GLUERS00' + bytes(8) + struct.pack('<QQ', len(raw), end - 64 - len(raw)) + hashlib.sha256(raw).digest())


class MetadataTests(unittest.TestCase):
    def test_exact_host_archive_and_retained_record(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / 'host-host.glue'
            write_host_archive(path)
            value = C.archive_record(path, 'host-host')
            C.validate_record(value, 'host-host', path.stat().st_size)

    def test_unknown_resource_is_rejected_before_zip_read(self):
        value = C.expected_manifest('host-host')
        value['resources']['extra/bomb'] = {'size': 1 << 40, 'sha256': '0' * 64, 'compression': 'deflate'}
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / 'host-host.glue'
            write_host_archive(path, value)
            with patch.object(C.zipfile, 'ZipFile', side_effect=AssertionError('unbounded ZIP read')):
                with self.assertRaisesRegex(C.TraceError, 'complete lifecycle manifest'):
                    C.archive_record(path, 'host-host')

    def test_self_declared_oversize_is_rejected_before_zip_read(self):
        value = C.expected_manifest('host-host')
        value['resources']['app/main.py']['size'] = 1 << 40
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / 'host-host.glue'
            write_host_archive(path, value)
            with patch.object(C.zipfile, 'ZipFile', side_effect=AssertionError('unbounded ZIP read')):
                with self.assertRaises(C.TraceError):
                    C.archive_record(path, 'host-host')

    def test_changed_base_runtime_and_target_are_not_self_authenticating(self):
        for section, key, value in [('abi', 'debug', 0), ('abi', 'debug', 0.0),
                                   ('provisioning', 'stdlib', '/tmp/foreign-python')]:
            manifest = C.expected_manifest('host-host')
            manifest['runtimes']['python'][section][key] = value
            with tempfile.TemporaryDirectory() as directory:
                path = Path(directory) / 'host-host.glue'
                write_host_archive(path, manifest)
                with self.assertRaises(C.TraceError):
                    C.archive_record(path, 'host-host')

    def test_changed_helper_bytes_are_rejected(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / 'host-host.glue'
            write_host_archive(path, changed={'app/python/glue_demo/answer.py': b'x' * 82})
            with self.assertRaisesRegex(C.TraceError, 'resource identity'):
                C.archive_record(path, 'host-host')

    def test_unlisted_zip_member_is_rejected(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / 'host-host.glue'
            write_host_archive(path, extra=('unexpected.txt', b'payload'))
            with self.assertRaisesRegex(C.TraceError, 'ZIP member inventory'):
                C.archive_record(path, 'host-host')

    def test_float_and_boolean_manifest_size_are_rejected(self):
        value = record()
        for size in (float(value['manifest_bytes']), False):
            changed = copy.deepcopy(value)
            changed['manifest_bytes'] = size
            with self.assertRaises(C.TraceError):
                C.validate_record(changed, 'host-host', changed['bytes'])

    def test_changed_retained_manifest_digest_is_rejected(self):
        value = record()
        value['manifest_sha256'] = 'f' * 64
        with self.assertRaisesRegex(C.TraceError, 'complete expected declaration'):
            C.validate_record(value, 'host-host', value['bytes'])

    def test_extra_retained_field_and_omitted_application_are_rejected(self):
        for change in ('extra', 'omitted'):
            value = record()
            if change == 'extra':
                value['unaudited_source'] = '/tmp/tree'
            else:
                del value['application']['python/archive-importer.py']
            with self.assertRaises(C.TraceError):
                C.validate_record(value, 'host-host', value['bytes'])

    def test_float_resource_identity_does_not_equal_integer_pin(self):
        value = record()
        value['application']['app/main.py']['size'] = float(value['application']['app/main.py']['size'])
        with self.assertRaises(C.TraceError):
            C.validate_record(value, 'host-host', value['bytes'])

    def test_duplicate_fields_and_nonfinite_json_are_rejected(self):
        for payload in ('{"a":0,"a":1}', '{"size":NaN}', '{"size":Infinity}'):
            with self.assertRaises(C.TraceError):
                C.strict_json(payload)

    def test_unpinned_elf_api_and_section_size_are_rejected(self):
        with self.assertRaises(C.TraceError):
            C.decode_elf(bytes(512), C.NAMES[0])


class GeometryTests(unittest.TestCase):
    def ledger(self):
        checker = C.Checker('host-host', record())
        state = checker.states[C.NAMES[0]]
        state.update(reservation=(0x4000000, 197264, 0x4000000, 0x4021000),
                     maps={(131728, 0), (4096, 0xf000)}, alias=10, guard=True)
        return checker

    def test_sole_exact_ledger_bss_mapping_is_admitted_once(self):
        checker = self.ledger()
        args = ['0x4020000', '656', 'PROT_READ|PROT_WRITE', 'MAP_PRIVATE|MAP_FIXED|MAP_ANONYMOUS', '-1', '0']
        checker.call('mmap', args, '0x4020000')
        self.assertTrue(checker.ledger_bss)
        with self.assertRaises(C.TraceError):
            checker.call('mmap', args, '0x4020000')

    def test_bss_size_protection_descriptor_and_owner_are_exact(self):
        args = ['0x4020000', '656', 'PROT_READ|PROT_WRITE', 'MAP_PRIVATE|MAP_FIXED|MAP_ANONYMOUS', '-1', '0']
        for index, value in ((1, '657'), (2, 'PROT_READ|PROT_EXEC'), (4, '10'), (0, '0x401f000')):
            changed = args.copy()
            changed[index] = value
            with self.assertRaises(C.TraceError):
                self.ledger().call('mmap', changed, changed[0])

    def test_bss_requires_mapped_data_and_live_alias(self):
        for field, value in (('alias', None), ('maps', {(131728, 0)}), ('guard', False), ('relro', True)):
            checker = self.ledger()
            checker.states[C.NAMES[0]][field] = value
            with self.assertRaises(C.TraceError):
                checker.call('mmap', ['0x4020000', '656', 'PROT_READ|PROT_WRITE',
                    'MAP_PRIVATE|MAP_FIXED|MAP_ANONYMOUS', '-1', '0'], '0x4020000')

    def test_root_guard_matches_two_rx_pages_and_rejects_historical_one_page(self):
        for offset, size, accepted in ((8192, '118784', True), (4096, '122880', False), (8192, '114688', False)):
            checker = C.Checker('host-host', record())
            state = checker.states[C.NAMES[1]]
            state.update(reservation=(0x5000000, 197416, 0x5000000, 0x5021000), maps={(131880, 0)})
            if accepted:
                checker.call('mprotect', [hex(0x5000000 + offset), size, 'PROT_NONE'], '0')
                self.assertTrue(state['guard'])
            else:
                with self.assertRaises(C.TraceError):
                    checker.call('mprotect', [hex(0x5000000 + offset), size, 'PROT_NONE'], '0')

    def test_graph_instances_preserve_all_historical_identity_constants(self):
        before = (C.REFERENCE.NAMES, C.REFERENCE.PROGRAM, C.REFERENCE.SUCCESS, C.REFERENCE.SEGMENTS.copy())
        first, second = C.private_graph(), C.private_graph()
        self.assertIsNot(first.BUNDLED, second.BUNDLED)
        self.assertIsNot(first.HOST.PBS, second.HOST.PBS)
        first.SEGMENTS[C.NAMES[0]].clear()
        self.assertTrue(second.SEGMENTS[C.NAMES[0]])
        self.assertEqual(before, (C.REFERENCE.NAMES, C.REFERENCE.PROGRAM, C.REFERENCE.SUCCESS, C.REFERENCE.SEGMENTS.copy()))

    def test_early_finalization_marker_requires_all_pinned_admission(self):
        checker = C.Checker('host-host', record())
        checker.output[0].extend(C.BEFORE_FINALIZE)
        with self.assertRaises(C.TraceError):
            checker.call('write', ['1</evidence/host-host.stdout.txt>', json.dumps(C.FINALIZE_PASS.decode()), '82'], '82')

    def test_native_population_checks_pinned_visible_header(self):
        checker = C.Checker('bundled-archived', record('bundled-archived'))
        image = C.NAMES[0]
        checker.states[image].update(created=True, source=10)
        checker.native_fds[10] = (image, 'source')
        header = bytes.fromhex(C.NATIVE_PINS[image]['header_256_hex'])
        altered = bytes([header[0] ^ 1]) + header[1:]
        with self.assertRaisesRegex(C.TraceError, 'population differs'):
            checker.call('write', [f'10</memfd:glue-python-native-{image}>(deleted)',
                json.dumps(altered.decode('latin1')) + '...', str(C.NATIVE_PINS[image]['size'])], str(C.NATIVE_PINS[image]['size']))

    def test_parser_growth_requires_original_owner_and_private_flags(self):
        for changed in (['0x6001000', '307200', '610304', 'MREMAP_MAYMOVE'],
                        ['0x6000000', '307200', '610305', 'MREMAP_MAYMOVE'],
                        ['0x6000000', '307200', '610304', 'MREMAP_FIXED']):
            checker = C.Checker('bundled-archived', record('bundled-archived'))
            checker.parser_owner = 0x6000000
            with self.assertRaises(C.TraceError):
                checker.call('mremap', changed, '0x7000000')

    def test_empty_and_incomplete_trace_are_rejected(self):
        for lines in ([], ['7  getpid() = 7\n'], ['7  getpid() = 7']):
            with self.assertRaises(C.TraceError):
                C.check_lines(lines, 'host-host', record())

    def test_short_read_write_arguments_raise_bounded_trace_error(self):
        checker = C.Checker('host-host', record())
        for name, args in (('read', ['10']), ('write', ['1']), ('write', ['1', '"prefix"'])):
            with self.assertRaisesRegex(C.TraceError, 'arity'):
                checker.call(name, args, '1')


def bounded_lines(path):
    C.require(path.stat().st_size <= C.MAX_TRACE_BYTES, 'audit raw/compressed trace exceeds fixed input bound')
    opener = gzip.open if path.suffix == '.gz' else open
    with opener(path, 'rt', encoding='utf-8', newline='') as stream:
        lines = []
        total = 0
        while line := stream.readline(C.MAX_LINE_CHARACTERS + 2):
            total += len(line.encode())
            C.require(len(lines) < C.MAX_RECORDS and total <= C.MAX_TRACE_BYTES and
                      len(line) <= C.MAX_LINE_CHARACTERS + 1 and line.endswith('\n'), 'audit trace exceeds fixed bounds')
            lines.append(line)
        return lines


def locate(lines, predicate):
    return next(index for index, line in enumerate(lines) if predicate(line))


def replace(lines, predicate, transform):
    changed = lines.copy()
    index = locate(changed, predicate)
    changed[index] = transform(changed[index])
    return changed


def delete(lines, predicate):
    changed = lines.copy()
    del changed[locate(changed, predicate)]
    return changed


def duplicate(lines, predicate):
    changed = lines.copy()
    index = locate(changed, predicate)
    changed.insert(index, changed[index])
    return changed


def move_before(lines, predicate, destination):
    changed = lines.copy()
    item = changed.pop(locate(changed, predicate))
    changed.insert(locate(changed, destination), item)
    return changed


def shifted_call(line, amount):
    return re.sub(r'0x[0-9a-f]+', lambda match: hex(int(match[0], 16) + amount), line)


def close_host_source_before_final(lines):
    source = lines[locate(lines, lambda line: 'read(' in line and '/host Python native lifecycle/libglue_python_lifecycle.so>' in line)]
    token = re.search(r'read\(([^,]+),', source)[1]
    pid = source.split()[0]
    changed = lines.copy()
    index = locate(changed, lambda line: 'write(' in line and 'GLUE_PYTHON_NATIVE_LIFECYCLE_FINALIZE_PASS' in line)
    changed.insert(index, f'{pid}  close({token}) = 0\n')
    return changed


def mutations():
    bss = lambda line: 'mmap(' in line and ', 656, PROT_READ|PROT_WRITE,' in line
    root_guard = lambda line: 'mprotect(' in line and ', 118784, PROT_NONE)' in line
    root_rx = lambda line: 'mmap(' in line and ', 131880, PROT_READ|PROT_EXEC,' in line
    parser_growth = lambda line: 'mremap(' in line and ', 307200, 610304,' in line
    parser_free = lambda line: 'munmap(' in line and ', 610304)' in line
    final = lambda line: 'write(' in line and 'GLUE_PYTHON_NATIVE_LIFECYCLE_FINALIZE_PASS' in line
    native_pass = lambda line: 'write(' in line and 'GLUE_PYTHON_NATIVE_LIFECYCLE_PASS ' in line
    atexit = lambda line: 'write(' in line and 'GLUE_PYTHON_NATIVE_LIFECYCLE_ATEXIT_PASS ' in line
    mode = 'bundled-archived'
    cases = [
        (mode, 'missing-ledger-bss', lambda lines: delete(lines, bss)),
        (mode, 'duplicate-ledger-bss', lambda lines: duplicate(lines, bss)),
        (mode, 'ledger-bss-size', lambda lines: replace(lines, bss, lambda line: line.replace(', 656,', ', 657,'))),
        (mode, 'ledger-bss-executable', lambda lines: replace(lines, bss, lambda line: line.replace('PROT_READ|PROT_WRITE', 'PROT_READ|PROT_EXEC'))),
        (mode, 'ledger-bss-foreign-owner', lambda lines: replace(lines, bss, lambda line: shifted_call(line, -4096))),
        (mode, 'ledger-bss-nonanonymous-fd', lambda lines: replace(lines, bss, lambda line: line.replace(', -1, 0)', ', 8, 0)'))),
        (mode, 'ledger-bss-offset', lambda lines: replace(lines, bss, lambda line: line.replace(', -1, 0)', ', -1, 1)'))),
        (mode, 'ledger-bss-before-rw', lambda lines: move_before(lines, bss, lambda line: 'mmap(' in line and 'libglue_python_lifecycle.so' in line and '0xf000' in line)),
        (mode, 'root-historical-gap', lambda lines: replace(lines, root_guard, lambda line: shifted_call(line.replace('118784', '122880'), -4096))),
        (mode, 'root-gap-size', lambda lines: replace(lines, root_guard, lambda line: line.replace('118784', '114688'))),
        (mode, 'missing-root-gap', lambda lines: delete(lines, root_guard)),
        (mode, 'root-rx-span', lambda lines: replace(lines, root_rx, lambda line: line.replace('131880', '131879'))),
        (mode, 'changed-native-header', lambda lines: replace(lines, lambda line: 'read(' in line and 'native-libglue_python_lifecycle.so' in line and ', 832)' in line, lambda line: line.replace('\\177ELF', '~ELF', 1))),
        (mode, 'changed-native-population-header', lambda lines: replace(lines, lambda line: 'write(' in line and 'native-libglue_python_lifecycle.so' in line, lambda line: line.replace('\\177ELF', '~ELF', 1))),
        (mode, 'parser-foreign-owner', lambda lines: replace(lines, parser_growth, lambda line: re.sub(r'mremap\((0x[0-9a-f]+)', lambda match: 'mremap(' + hex(int(match[1], 16) + 4096), line))),
        (mode, 'parser-growth-size', lambda lines: replace(lines, parser_growth, lambda line: line.replace('610304', '610305'))),
        (mode, 'parser-fixed-growth', lambda lines: replace(lines, parser_growth, lambda line: line.replace('MREMAP_MAYMOVE', 'MREMAP_FIXED'))),
        (mode, 'parser-partial-free', lambda lines: replace(lines, parser_free, lambda line: line.replace('610304', '610303'))),
        (mode, 'missing-parser-free', lambda lines: delete(lines, parser_free)),
        (mode, 'missing-final-ledger', lambda lines: delete(lines, final)),
        (mode, 'duplicate-final-ledger', lambda lines: duplicate(lines, final)),
        (mode, 'final-before-atexit', lambda lines: move_before(lines, final, atexit)),
        (mode, 'final-before-main', lambda lines: move_before(lines, final, native_pass)),
        (mode, 'wrong-final-freed-total', lambda lines: replace(lines, final, lambda line: line.replace('freed=5', 'freed=4'))),
        (mode, 'wrong-final-owned-total', lambda lines: replace(lines, final, lambda line: line.replace('owned=0', 'owned=1'))),
        (mode, 'final-wrong-stream', lambda lines: replace(lines, final, lambda line: line.replace('write(1<', 'write(2<').replace('.stdout.txt>', '.stderr.txt>'))),
        (mode, 'final-incomplete-write', lambda lines: replace(lines, final, lambda line: line.replace(', 82) = 82', ', 82) = 81'))),
        ('host-host', 'host-native-source-close-before-final', close_host_source_before_final),
        ('host-host-app-error', 'error-missing-final-ledger', lambda lines: delete(lines, final)),
        ('host-host-app-error', 'error-diagnostic-before-final', lambda lines: move_before(lines, lambda line: 'write(2<' in line and 'intentional Python archive app error' in line, final)),
        ('corrupt-native', 'crc-incomplete-final-native-chunk', lambda lines: replace(lines, lambda line: 'read(' in line and ') = 2016' in line, lambda line: line.replace(') = 2016', ') = 2015'))),
        ('missing-host-image', 'wrong-missing-image-diagnostic', lambda lines: replace(lines, lambda line: 'write(2<' in line and 'libglue_python_lifecycle.so' in line, lambda line: line.replace('libglue_python_lifecycle.so', 'libglue_python_dependency.so'))),
        ('wrong-host-image', 'wrong-image-control-read-not-mutated', lambda lines: replace(lines, lambda line: 'read(' in line and 'glue_native_lifecycle.so>' in line and '"~ELF' in line, lambda line: line.replace('"~ELF', '"\\177ELF', 1))),
    ]
    return cases


def audit_capture(directory, output):
    traces, records, summary = {}, {}, {}
    for mode in C.MODES:
        path = directory / (mode + '.trace.txt')
        if not path.exists():
            path = path.with_suffix(path.suffix + '.gz')
        traces[mode] = bounded_lines(path)
        records[mode] = C.retained_metadata(directory / 'native-metadata.json', mode)
        expected = C.expected_output(mode)
        for kind, value in zip(('stdout', 'stderr'), expected):
            with (directory / (mode + '.' + kind + '.txt')).open('rb') as stream:
                C.require(stream.read(len(value) + 1) == value, 'actual lifecycle capture stream differs')
        with (directory / (mode + '.exit-status.txt')).open('rb') as stream:
            C.require(stream.read(3) == (b'0\n' if mode in C.CELLS else b'1\n'), 'actual lifecycle capture status differs')
        summary[mode] = C.check_lines(traces[mode], mode, records[mode])
    controls = []
    for mode, label, mutate in mutations():
        changed = mutate(traces[mode])
        C.require(changed != traces[mode], 'hostile lifecycle edit did not change its source capture')
        try:
            C.check_lines(changed, mode, records[mode])
        except C.TraceError as error:
            controls.append({'mode': mode, 'control': label, 'rejected': True, 'diagnostic': str(error)})
        else:
            raise C.TraceError('hostile lifecycle trace accepted: ' + label)
    result = {'schema_version': 0, 'original_captures_verified': len(summary),
              'hostile_trace_controls_rejected': len(controls), 'captures': summary, 'controls': controls}
    output.write_text(json.dumps(result, sort_keys=True, indent=2) + '\n')
    print(f'PASS lifecycle captures={len(summary)} hostile-controls={len(controls)}')


if __name__ == '__main__':
    if len(sys.argv) == 4 and sys.argv[1] == '--audit-capture':
        audit_capture(Path(sys.argv[2]), Path(sys.argv[3]))
    else:
        unittest.main()
