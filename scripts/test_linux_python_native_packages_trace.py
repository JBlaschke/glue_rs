"""Finite package-source bindings and focused native-package trace controls."""
import hashlib
import importlib.util
import json
from pathlib import Path
import sys
import tempfile
import unittest
from types import SimpleNamespace
from unittest.mock import patch


def load(filename, name):
    spec = importlib.util.spec_from_file_location(name, Path(__file__).with_name(filename))
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


C = load('check-linux-python-native-packages-trace.py', 'native_packages_checker_test')
HELPERS = load('test_linux_python_native_lifecycle_trace.py', 'native_packages_private_audit_helpers')
HELPERS.C = C


class PackageBindings(unittest.TestCase):
    def test_unfinalized_source_pin_disables_admission(self):
        with patch.object(C, 'APP_TAIL_PIN', None):
            with self.assertRaisesRegex(C.TraceError, 'not finalized'):
                C.configured_graph()

    def test_exact_dotted_names_reuse_leaf_initializer_images(self):
        self.assertEqual(C.FULLNAMES, (
            'glue_native_pkg.glue_native_lifecycle',
            'glue_native_pkg.glue_native_create_error',
            'glue_native_pkg.glue_native_lifecycle_exec_error'))
        for name, fullname in zip(C.NAMES[1:], C.FULLNAMES):
            self.assertEqual(C.NATIVE_PINS[name]['exports'], {'PyInit_' + fullname.rsplit('.', 1)[1]: 'function'})

    def test_exact_package_archive_is_independently_inspected(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / 'host-host.glue'
            HELPERS.write_host_archive(path)
            value = C.archive_record(path, 'host-host')
            C.validate_record(value, 'host-host', path.stat().st_size)

    def test_self_claimed_source_native_collision_is_rejected(self):
        manifest = C.expected_manifest('host-host')
        key = 'app/python/glue_native_pkg/glue_native_lifecycle.py'
        manifest['resources'][key] = {'size': 0, 'sha256': hashlib.sha256(b'').hexdigest(), 'compression': 'deflate'}
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / 'host-host.glue'
            HELPERS.write_host_archive(path, manifest, extra=(key, b''))
            with self.assertRaises(C.TraceError):
                C.archive_record(path, 'host-host')

    def test_extra_unknown_child_cannot_be_added_to_finite_archive(self):
        manifest = C.expected_manifest('host-host')
        manifest['resources']['app/python/glue_native_pkg/unknown.so'] = {
            'size': 1 << 40, 'sha256': '0' * 64, 'compression': 'deflate'}
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / 'host-host.glue'
            HELPERS.write_host_archive(path, manifest)
            graph = C.configured_graph()
            with patch.object(graph.zipfile, 'ZipFile', side_effect=AssertionError('payload decompression preceded admission')):
                with self.assertRaises(C.TraceError):
                    graph.archive_record(path, 'host-host')

    def test_changed_source_helper_and_bootstrap_bytes_are_rejected(self):
        applications = C.expected_application()
        keys = ['python/archive-importer.py', 'app/python/glue_native_pkg/__init__.py',
                'app/python/glue_native_pkg/relative.py']
        for key in keys:
            with tempfile.TemporaryDirectory() as directory:
                path = Path(directory) / 'host-host.glue'
                original = applications[key]
                changed = bytes([original[0] ^ 1]) + original[1:]
                HELPERS.write_host_archive(path, changed={key: changed})
                with self.assertRaises(C.TraceError):
                    C.archive_record(path, 'host-host')

    def test_historical_profile_cannot_be_relabelled_by_mutable_receipt(self):
        value = HELPERS.record()
        old = C.REFERENCE.expected_manifest('host-host')
        raw = json.dumps(old, sort_keys=True, separators=(',', ':'), ensure_ascii=False).encode()
        value['manifest_bytes'] = len(raw)
        value['manifest_sha256'] = hashlib.sha256(raw).hexdigest()
        with self.assertRaises(C.TraceError):
            C.validate_record(value, 'host-host', value['bytes'])

    def test_typed_manifest_and_application_identities_are_exact(self):
        for field in ('manifest_bytes', 'application'):
            value = HELPERS.record()
            if field == 'manifest_bytes':
                value[field] = float(value[field])
            else:
                value[field]['app/main.py']['size'] = float(value[field]['app/main.py']['size'])
            with self.assertRaises(C.TraceError):
                C.validate_record(value, 'host-host', value['bytes'])

    def test_extra_receipt_sources_are_rejected(self):
        value = HELPERS.record()
        value['native_paths'] = {C.FULLNAMES[0]: '/tmp/foreign.so'}
        with self.assertRaises(C.TraceError):
            C.validate_record(value, 'host-host', value['bytes'])

    def test_private_graphs_preserve_every_historical_source_identity(self):
        before = C.REFERENCE.expected_manifest('host-host')
        original_command = C.REFERENCE.command_for('host-host')
        first, second = C.configured_graph(), C.configured_graph()
        self.assertEqual(first.expected_manifest('host-host')['app_id'], C.APP_ID)
        self.assertIsNot(first.REFERENCE, second.REFERENCE)
        self.assertIsNot(first.NATIVE_PINS, second.NATIVE_PINS)
        self.assertEqual(C.REFERENCE.expected_manifest('host-host'), before)
        self.assertEqual(C.REFERENCE.command_for('host-host'), original_command)

    def test_native_origin_prefix_and_physical_images_remain_truthful(self):
        for mode in C.MODES:
            self.assertTrue(C.archive_for(mode).startswith(C.DIRECTORY + '/'))
            self.assertEqual(C.prefix_for(mode), C.REFERENCE.prefix_for(mode))
            self.assertEqual(C.expected_output(mode)[0], b'' if mode in C.NEGATIVE else C.expected_output('host-host')[0])


class ParserAdapterTests(unittest.TestCase):
    def checker(self):
        calls = []
        checker = SimpleNamespace(cell='bundled-archived', runtime=SimpleNamespace(
            archive_opened=1, locator_read=True, archive_complete=lambda: False, created={}),
            require_unowned=lambda start, size: calls.append(('owned', start, size)),
            call=lambda name, args, result: calls.append((name, args, result)),
            finish=lambda: calls.append(('finished',)))
        return C.parser_adapter(checker, C.REFERENCE), calls

    def allocate_and_grow(self, checker):
        checker.call('mmap', ['NULL', '299008', 'PROT_READ|PROT_WRITE',
            'MAP_PRIVATE|MAP_ANONYMOUS', '-1', '0'], '0x4000000')
        checker.call('mremap', ['0x4000000', '299008', '593920', 'MREMAP_MAYMOVE'], '0x5000000')

    def test_actual_owned_pair_and_full_free_precede_normalized_parent_completion(self):
        checker, calls = self.checker()
        self.allocate_and_grow(checker)
        checker.call('munmap', ['0x5000000', '593920'], '0')
        checker.finish()
        self.assertTrue(checker.package_parser_grown and checker.package_parser_freed)
        self.assertIn(('owned', 0x4000000, 299008), calls)
        self.assertIn(('owned', 0x5000000, 593920), calls)
        self.assertIn(('mremap', ['0x4000000', '307200', '610304', 'MREMAP_MAYMOVE'], '0x5000000'), calls)
        self.assertIn(('munmap', ['0x5000000', '610304'], '0'), calls)
        self.assertEqual(calls[-1], ('finished',))

    def test_wrong_size_or_owner_cannot_use_the_historical_growth_tuple(self):
        for old, grown, owner in (('307200', '610304', '0x4000000'),
                                  ('299008', '593921', '0x4000000'),
                                  ('299008', '593920', '0x4001000')):
            checker, _ = self.checker()
            checker.call('mmap', ['NULL', '299008', 'PROT_READ|PROT_WRITE',
                'MAP_PRIVATE|MAP_ANONYMOUS', '-1', '0'], '0x4000000')
            with self.assertRaises(C.TraceError):
                checker.call('mremap', [owner, old, grown, 'MREMAP_MAYMOVE'], '0x5000000')

    def test_missing_or_partial_grown_owner_release_cannot_finish(self):
        checker, calls = self.checker()
        self.allocate_and_grow(checker)
        with self.assertRaises(C.TraceError):
            checker.call('munmap', ['0x5000000', '593919'], '0')
        with self.assertRaises(C.TraceError):
            checker.finish()
        self.assertNotIn(('finished',), calls)


def mutations():
    # Reuse only the independent new image/owner/parser checks relevant to this
    # identical physical closure. Do not repeat historical broad mutation suites.
    selected = {
        'missing-ledger-bss', 'ledger-bss-size', 'ledger-bss-executable',
        'ledger-bss-foreign-owner', 'ledger-bss-before-rw', 'root-historical-gap',
        'root-rx-span', 'changed-native-header', 'changed-native-population-header',
        'missing-final-ledger', 'wrong-final-freed-total', 'wrong-final-owned-total',
        'host-native-source-close-before-final', 'error-missing-final-ledger',
        'crc-incomplete-final-native-chunk', 'wrong-image-control-read-not-mutated',
    }
    cases = [case for case in HELPERS.mutations() if case[1] in selected]
    final = lambda line: 'write(' in line and C.FINALIZE_PASS.decode().rstrip() in line
    native = lambda line: 'write(' in line and C.NATIVE_PASS.decode().rstrip() in line
    atexit = lambda line: 'write(' in line and C.ATEXIT_PASS.decode().rstrip() in line
    cases += [
        ('bundled-archived', 'packages-parser-growth-size', lambda lines: HELPERS.replace(lines,
            lambda line: 'mremap(' in line and ', 299008, 593920,' in line,
            lambda line: line.replace('593920', '593921'))),
        ('bundled-archived', 'packages-missing-parser-free', lambda lines: HELPERS.delete(lines,
            lambda line: 'munmap(' in line and ', 593920)' in line)),
        ('bundled-archived', 'packages-final-before-main', lambda lines: HELPERS.move_before(lines, final, native)),
        ('bundled-archived', 'packages-final-before-atexit', lambda lines: HELPERS.move_before(lines, final, atexit)),
    ]
    return cases


def audit_capture(directory, output):
    selected = mutations()
    original = HELPERS.mutations
    HELPERS.mutations = lambda: selected
    try:
        # Only this newly loaded helper instance receives the finite case list.
        return HELPERS.audit_capture(directory, output)
    finally:
        HELPERS.mutations = original


if __name__ == '__main__':
    if len(sys.argv) == 4 and sys.argv[1] == '--audit-capture':
        audit_capture(Path(sys.argv[2]), Path(sys.argv[3]))
    else:
        unittest.main()
