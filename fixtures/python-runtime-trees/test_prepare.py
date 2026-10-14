#!/usr/bin/env python3
"""Independent hostile controls for selected-tree input and publication audits."""
import copy
import importlib.util
import json
import os
from pathlib import Path
import stat
import sys
import tempfile
import unittest
from unittest.mock import patch

HERE = Path(__file__).resolve().parent
SPEC = importlib.util.spec_from_file_location('runtime_tree_fixture', HERE / 'prepare.py')
C = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(C)


class IndependentSysconfigTests(unittest.TestCase):
    def test_observed_template_agrees_with_independent_original_scalar_changes(self):
        template = (HERE / 'uv-0.12.23-sysconfig.py.in').read_bytes()
        self.assertEqual(C.identity(template), C.TEMPLATE_IDENTITY)
        for root in [Path('/plain-root'), Path('/Python\'s "root'), Path('/root/__GLUE_RUNTIME_TREE_ROOT__')]:
            escaped = json.dumps(str(root), ensure_ascii=False)[1:-1].encode()
            rendered = template.replace(b'__GLUE_RUNTIME_TREE_ROOT__', escaped)
            self.assertEqual(rendered, C.uv_sysconfig(root))
            self.assertTrue(rendered.endswith(b'}\n'))

    def test_original_scalar_inventory_remains_unmodified(self):
        before = (HERE / 'stock-sysconfig.py').read_bytes()
        self.assertEqual(C.identity(before), C.STOCK_IDENTITY)
        variables = C.stock_variables()
        C.uv_sysconfig(Path('/another-root'))
        self.assertEqual((HERE / 'stock-sysconfig.py').read_bytes(), before)
        self.assertEqual(variables['AR'], '/tools/llvm/bin/llvm-ar')
        self.assertNotIn('PYTHON_BUILD_STANDALONE', variables)

    def test_non_ascii_and_relative_uv_roots_reject(self):
        for root in [Path('relative'), Path('/pyth\u00f6n')]:
            with self.assertRaisesRegex(ValueError, 'absolute ASCII'):
                C.uv_sysconfig(root)

    def test_provenance_does_not_claim_a_complete_input_artifact(self):
        source = {'root': '/selected-input', 'sysconfig_normalized': False,
                  'sysconfig_input': C.STOCK_IDENTITY, 'sysconfig_output': C.STOCK_IDENTITY}
        files, provenance = C.expected_provenance(source)
        self.assertEqual(len(files), 1041)
        self.assertEqual(sum(v['size'] for v in files.values()), 89479393)
        self.assertEqual(provenance['installed_tree']['inspection_scope'], 'selected-prerequisites-only')
        for field in ['artifact', 'artifact_entries', 'artifact_payload_bytes', 'omitted_files', 'omitted_bytes']:
            self.assertIsNone(provenance[field])
        self.assertIsNone(provenance['installed_tree']['sysconfig_template'])
        self.assertIs(provenance['is_complete_python_installation'], False)
        self.assertIs(provenance['runtime_execution_observed'], False)

    def test_json_schema_distinguishes_boolean_float_and_integer(self):
        self.assertFalse(C.same_json({'size': 0}, {'size': False}))
        self.assertFalse(C.same_json({'size': 1}, {'size': 1.0}))
        self.assertFalse(C.same_json({'observed': False}, {'observed': 0}))
        with self.assertRaisesRegex(ValueError, 'duplicate JSON'):
            C.strict_json(b'{"size":0,"size":false}')


class SelectedInputTests(unittest.TestCase):
    def setUp(self):
        parent = '/private/tmp' if sys.platform == 'darwin' else '/tmp'
        self.root = Path(tempfile.mkdtemp(prefix='grt-oracle-', dir=parent))
        self.payloads = {C.LIBRARY: b'\x7fELFsample-image', C.SYSCONFIG: (HERE / 'stock-sysconfig.py').read_bytes(),
                         'lib/python3.13/abc.py': b'ANSWER = 7\n',
                         'lib/python3.13/encodings/__pycache__/sample.pyc': bytes(range(256)) * 3}
        for name, payload in self.payloads.items():
            path = self.root / name
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_bytes(payload)
        self.expected = {name: C.identity(payload) for name, payload in self.payloads.items()}
        self.selected = patch.object(C, 'selected_contract', return_value=self.expected)
        self.selected.start()

    def tearDown(self):
        self.selected.stop()
        C.remove_owned_tree(self.root)

    def test_prefix_receipt_binds_exact_first_512_binary_bytes_without_execution(self):
        with patch.object(C.subprocess, 'run', side_effect=AssertionError('input execution is forbidden')):
            result = C.audit_input(self.root)
        self.assertEqual(result['selected_files'], self.expected)
        self.assertEqual(result['selected_file_prefixes'], {name: payload[:512].hex() for name, payload in self.payloads.items()})
        self.assertIs(result['input_python_execution_observed'], False)

    def test_exact_relocated_uv_source_is_accepted_and_original_dictionary_remains_stock(self):
        (self.root / C.SYSCONFIG).write_bytes(C.uv_sysconfig(self.root))
        result = C.audit_input(self.root)
        self.assertEqual(result['input_layout'], 'uv-0.12.23')
        self.assertIs(result['sysconfig_normalized'], True)
        self.assertEqual(result['sysconfig_output'], C.STOCK_IDENTITY)

    def test_different_root_and_semantically_identical_serialization_drift_reject(self):
        formatting_drift = C.uv_sysconfig(self.root).replace(b'    "ABIFLAGS"', b'\t   "ABIFLAGS"', 1)
        for payload in [C.uv_sysconfig(Path('/wrong-root')), formatting_drift]:
            (self.root / C.SYSCONFIG).write_bytes(payload)
            with self.assertRaisesRegex(ValueError, 'all independently expected bytes'):
                C.audit_input(self.root)

    def test_unselected_fifo_and_alias_are_not_inspected_or_certified(self):
        os.mkfifo(self.root / 'unselected-fifo')
        (self.root / 'unselected-library.so').symlink_to('/never-read-outside-target')
        result = C.audit_input(self.root)
        self.assertEqual(set(result['selected_files']), set(self.expected))
        self.assertIs(result['complete_input_inventory_observed'], False)

    def test_selected_alias_rejects_even_when_target_bytes_match(self):
        original = self.root / 'same-bytes.py'
        original.write_bytes(self.payloads['lib/python3.13/abc.py'])
        path = self.root / 'lib/python3.13/abc.py'
        path.unlink()
        path.symlink_to(original)
        with self.assertRaisesRegex(ValueError, 'regular file'):
            C.audit_input(self.root)

    def test_selected_directory_alias_rejects_before_leaf_read(self):
        library = self.root / 'lib'
        library.rename(self.root / 'real-lib')
        library.symlink_to(self.root / 'real-lib', target_is_directory=True)
        with self.assertRaisesRegex(ValueError, 'ordinary directory'):
            C.audit_input(self.root)

    def test_selected_fifo_is_rejected_without_blocking_read(self):
        path = self.root / 'lib/python3.13/abc.py'
        path.unlink()
        os.mkfifo(path)
        with patch.object(C.os, 'read', side_effect=AssertionError('special file must not be read')):
            with self.assertRaisesRegex(ValueError, 'regular file'):
                C.regular_identity(path, 4096)

    def test_oversized_regular_leaf_rejects_before_read(self):
        path = self.root / 'lib/python3.13/abc.py'
        with patch.object(C.os, 'read', side_effect=AssertionError('oversized data must not be read')):
            with self.assertRaisesRegex(ValueError, 'bounded regular'):
                C.regular_identity(path, 3)

    def test_same_size_source_corruption_is_rejected(self):
        path = self.root / 'lib/python3.13/abc.py'
        payload = bytearray(path.read_bytes())
        payload[-2] ^= 1
        path.write_bytes(payload)
        with self.assertRaisesRegex(ValueError, 'selected runtime bytes differ'):
            C.audit_input(self.root)

    def test_source_is_never_evaluated_when_import_side_effect_is_supplied(self):
        marker = self.root / 'must-not-exist'
        (self.root / C.SYSCONFIG).write_text('__import__("pathlib").Path(' + repr(str(marker)) + ').touch()\n')
        with self.assertRaisesRegex(ValueError, 'all independently expected bytes'):
            C.audit_input(self.root)
        self.assertFalse(marker.exists())

    def test_owned_cleanup_does_not_chmod_shared_input_or_follow_alias(self):
        original = self.root / 'retained-input'
        original.write_bytes(b'retained bytes')
        original.chmod(0o444)
        owned = self.root / 'scratch'
        owned.mkdir()
        os.link(original, owned / 'linked')
        (owned / 'external-dir').symlink_to(self.root, target_is_directory=True)
        owned.chmod(0o555)
        C.remove_owned_tree(owned)
        self.assertEqual(original.read_bytes(), b'retained bytes')
        self.assertEqual(stat.S_IMODE(original.lstat().st_mode), 0o444)
        self.assertFalse(owned.exists())

    def test_owned_base_copy_never_hardlinks_or_changes_original_input(self):
        before = {name: ((self.root / name).stat().st_ino, (self.root / name).stat().st_nlink,
                         (self.root / name).stat().st_mode, (self.root / name).stat().st_mtime_ns)
                  for name in self.payloads}
        with patch.object(C.os, 'link', side_effect=AssertionError('original input must not be linked')):
            copied = C.clone_selected(self.root, self.root / 'owned-base', copy_files=True)
        for name, payload in self.payloads.items():
            self.assertEqual((copied / name).read_bytes(), payload)
            self.assertNotEqual((copied / name).stat().st_ino, before[name][0])
            self.assertEqual(((self.root / name).stat().st_ino, (self.root / name).stat().st_nlink,
                              (self.root / name).stat().st_mode, (self.root / name).stat().st_mtime_ns), before[name])

    def test_link_copy_fallback_detaches_partial_destination_and_preserves_source(self):
        for code in [C.errno.EXDEV, C.errno.EACCES, C.errno.EPERM, C.errno.ENOTSUP]:
            def failed_link(source, destination):
                Path(destination).write_bytes(b'partial destination')
                raise OSError(code, 'forced unsupported link')
            with patch.object(C.os, 'link', side_effect=failed_link):
                copied = C.clone_selected(self.root, self.root / ('fallback-' + str(code)))
            for name, payload in self.payloads.items():
                self.assertEqual((copied / name).read_bytes(), payload)
                self.assertEqual((self.root / name).read_bytes(), payload)
                self.assertEqual((self.root / name).stat().st_nlink, 1)


class PublicationTests(unittest.TestCase):
    def setUp(self):
        parent = '/private/tmp' if sys.platform == 'darwin' else '/tmp'
        self.parent = Path(tempfile.mkdtemp(prefix='grt-output-', dir=parent))
        self.root = self.parent / 'published'
        self.root.mkdir()
        self.files = {'lib/empty.py': C.identity(b''), 'lib/value.py': C.identity(b'answer = 7\n')}
        self.provenance = {'installed_tree': {'inspection_scope': 'selected-prerequisites-only', 'sysconfig_normalized': False}}
        payloads = {'lib/empty.py': b'', 'lib/value.py': b'answer = 7\n',
                    'provenance.json': (json.dumps(self.provenance) + '\n').encode()}
        for name, payload in payloads.items():
            path = self.root / name
            path.parent.mkdir(exist_ok=True)
            path.write_bytes(payload)
            path.chmod(0o444)
            os.utime(path, ns=(1704067200000000000, 1704067200000000000))
        for path in [self.root, self.root / 'lib']:
            path.chmod(0o555)
            os.utime(path, ns=(1704067200000000000, 1704067200000000000))
        self.source = {'root': '/selected-input', 'input_layout': 'stock'}
        self.report = {'provider': 'host-install', 'prefix': str(self.root), 'provenance': self.provenance,
                       'provenance_file': {'path': 'provenance.json'} | C.identity(payloads['provenance.json']),
                       'files': self.files, 'file_count': 1041, 'payload_bytes': 89479393,
                       'directory_count': 2, 'file_mode': 0o444, 'directory_mode': 0o555, 'mtime_seconds': 1704067200}
        self.contract = patch.object(C, 'expected_provenance', return_value=(self.files, self.provenance))
        self.contract.start()

    def tearDown(self):
        self.contract.stop()
        C.remove_owned_tree(self.parent)

    def test_publication_bytes_modes_and_nanosecond_times_are_observed(self):
        result = C.audit_output(self.root, self.report, self.source)
        self.assertIs(result['all_file_bytes_modes_times_verified'], True)
        self.assertIs(result['all_directory_modes_times_verified'], True)
        self.assertIs(result['complete_input_installation_certified'], False)

    def test_bool_zero_float_and_extra_schema_report_mutations_reject(self):
        for field, value in [('boolean-size', False), ('float-count', 1041.0), ('integer-boolean', 0), ('extra-schema', {})]:
            report = copy.deepcopy(self.report)
            if field == 'boolean-size':
                report['files']['lib/empty.py']['size'] = value
            elif field == 'float-count':
                report['file_count'] = value
            elif field == 'integer-boolean':
                report['provenance']['installed_tree']['sysconfig_normalized'] = value
            else:
                report['arbitrary_observation'] = value
            with self.assertRaisesRegex(ValueError, 'stdout report'):
                C.audit_output(self.root, report, self.source)

    def test_same_content_output_alias_rejects(self):
        path = self.root / 'lib/value.py'
        original = self.parent / 'same-value'
        original.write_bytes(path.read_bytes())
        (self.root / 'lib').chmod(0o755)
        path.unlink()
        path.symlink_to(original)
        with self.assertRaisesRegex(ValueError, 'link/special'):
            C.audit_output(self.root, self.report, self.source)

    def test_unowned_file_and_unowned_empty_directory_reject(self):
        self.root.chmod(0o755)
        extra = self.root / 'arbitrary-native.so'
        extra.write_bytes(b'not owned')
        with self.assertRaisesRegex(ValueError, 'file inventory'):
            C.audit_output(self.root, self.report, self.source)
        extra.unlink()
        (self.root / 'unowned-directory').mkdir()
        with self.assertRaisesRegex(ValueError, 'directory inventory'):
            C.audit_output(self.root, self.report, self.source)

    def test_directory_subsecond_time_drift_rejects(self):
        os.utime(self.root / 'lib', ns=(1704067200000000000, 1704067200000000001))
        with self.assertRaisesRegex(ValueError, 'directory mode/time'):
            C.audit_output(self.root, self.report, self.source)

    def test_file_mode_and_same_size_payload_drift_reject(self):
        path = self.root / 'lib/value.py'
        path.chmod(0o644)
        with self.assertRaisesRegex(ValueError, 'file mode/time'):
            C.audit_output(self.root, self.report, self.source)
        path.write_bytes(b'answer = 9\n')
        path.chmod(0o444)
        os.utime(path, ns=(1704067200000000000, 1704067200000000000))
        with self.assertRaisesRegex(ValueError, 'output bytes differ'):
            C.audit_output(self.root, self.report, self.source)


if __name__ == '__main__':
    unittest.main()
