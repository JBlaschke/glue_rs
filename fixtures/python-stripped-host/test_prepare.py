#!/usr/bin/env python3
"""Hostile independent-oracle regressions, with tiny fixture-owned payloads."""
from __future__ import annotations

import copy
import importlib.util
import json
import os
from pathlib import Path
import stat
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

HERE = Path(__file__).resolve().parent
spec = importlib.util.spec_from_file_location('stripped_preparation_tests', HERE / 'prepare.py')
oracle = importlib.util.module_from_spec(spec)
spec.loader.exec_module(oracle)


class ContractTests(unittest.TestCase):
    def test_independent_selected_corpus_preserves_producer_inventory(self):
        files, provenance = oracle.expected_provenance()
        self.assertEqual(len(files), 1041)
        self.assertEqual(sum(row['size'] for row in files.values()), 38093257)
        self.assertEqual(provenance['artifact']['sha256'], oracle.inspection.pins()['stripped_artifact']['sha256'])
        for name in ('source_inventory', 'cache_inventory'):
            self.assertEqual(provenance[name]['artifact_sha256'], oracle.TREE.ARTIFACT['sha256'])
        self.assertNotEqual(files[oracle.LIBRARY], oracle.TREE.LIBRARY_IDENTITY)

    def test_empty_payload_boolean_and_float_are_distinct(self):
        for value in (False, 0.0):
            self.assertFalse(oracle.same_json({'size': value}, {'size': 0}))

    def test_duplicate_and_nonfinite_json_evidence_rejected(self):
        for payload in (b'{"size":1,"size":2}', b'{"size":NaN}', b'{"size":Infinity}'):
            with self.assertRaises(ValueError):
                oracle.strict_json(payload)

    def test_loader_pin_geometry_and_header_have_exact_scalar_types(self):
        fixed = oracle.inspection.pins()
        self.assertEqual(len(bytes.fromhex(fixed['stripped_library_prefix_256_hex'])), 256)
        self.assertEqual(len(fixed['stripped_elf_program_headers']), 8)
        self.assertEqual(fixed['stripped_elf_program_headers'][0]['file_size'], 18153048)
        self.assertEqual(fixed['stripped_elf_program_headers'][1]['memory_size'], 2227144)


class PublicationTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory(dir='/private/tmp' if sys.platform == 'darwin' else '/tmp')
        self.parent = Path(self.temporary.name)
        self.root = self.parent / 'published'
        self.root.mkdir()
        self.files = {'lib/empty.py': oracle.identity(b''), 'lib/hello.py': oracle.identity(b'hello\n')}
        self.provenance = {'schema_version': 0, 'files': self.files, 'runtime_execution_observed': False}
        (self.root / 'lib').mkdir()
        (self.root / 'lib/empty.py').write_bytes(b'')
        (self.root / 'lib/hello.py').write_bytes(b'hello\n')
        payload = (json.dumps(self.provenance, sort_keys=True) + '\n').encode()
        (self.root / 'provenance.json').write_bytes(payload)
        self.report = {
            'provider': oracle.PROVIDER, 'prefix': str(self.root), 'provenance': self.provenance,
            'provenance_file': {'path': 'provenance.json'} | oracle.identity(payload),
            'files': self.files, 'file_count': 1041, 'payload_bytes': 38093257,
            'directory_count': 2, 'file_mode': 0o444, 'directory_mode': 0o555,
            'mtime_seconds': oracle.MTIME,
        }
        for path in self.root.rglob('*'):
            path.chmod(0o555 if path.is_dir() else 0o444)
            os.utime(path, ns=(oracle.MTIME * 1000000000,) * 2)
        self.root.chmod(0o555)
        os.utime(self.root, ns=(oracle.MTIME * 1000000000,) * 2)
        self.contract = patch.object(oracle, 'expected_provenance', return_value=(self.files, self.provenance))
        self.contract.start()

    def tearDown(self):
        self.contract.stop()
        oracle.TREE.remove_owned_tree(self.root)
        self.temporary.cleanup()

    def audit(self, report=None):
        return oracle.audit_output(self.root, report if report is not None else self.report)

    def test_correct_output_passes_complete_byte_and_metadata_audit(self):
        self.assertTrue(self.audit()['all_file_bytes_modes_times_verified'])
        self.assertTrue(self.audit()['all_directory_modes_times_verified'])

    def test_zero_byte_boolean_or_float_report_identity_rejected(self):
        for value in (False, 0.0):
            report = copy.deepcopy(self.report)
            report['files']['lib/empty.py']['size'] = value
            with self.assertRaisesRegex(ValueError, 'stdout report'):
                self.audit(report)

    def test_boolean_float_and_unknown_report_fields_rejected(self):
        for field, value in [('file_count', True), ('payload_bytes', 38093257.0), ('unknown_input', '/foreign')]:
            report = copy.deepcopy(self.report)
            report[field] = value
            with self.assertRaisesRegex(ValueError, 'stdout report'):
                self.audit(report)

    def test_file_content_change_rejected(self):
        path = self.root / 'lib/hello.py'
        path.chmod(0o644)
        path.write_bytes(b'jello\n')
        path.chmod(0o444)
        os.utime(path, ns=(oracle.MTIME * 1000000000,) * 2)
        with self.assertRaisesRegex(ValueError, 'payload identity'):
            self.audit()

    def test_file_mode_and_nanosecond_time_rejected(self):
        path = self.root / 'lib/hello.py'
        path.chmod(0o644)
        with self.assertRaisesRegex(ValueError, 'file mode/time'):
            self.audit()
        path.chmod(0o444)
        os.utime(path, ns=(oracle.MTIME * 1000000000 + 1,) * 2)
        with self.assertRaisesRegex(ValueError, 'file mode/time'):
            self.audit()

    def test_directory_mode_and_nanosecond_time_rejected(self):
        path = self.root / 'lib'
        path.chmod(0o755)
        with self.assertRaisesRegex(ValueError, 'directory mode/time'):
            self.audit()
        path.chmod(0o555)
        os.utime(path, ns=(oracle.MTIME * 1000000000 + 1,) * 2)
        with self.assertRaisesRegex(ValueError, 'directory mode/time'):
            self.audit()

    def test_publication_symlink_to_correct_bytes_rejected(self):
        self.root.chmod(0o755)
        (self.root / 'lib').chmod(0o755)
        path = self.root / 'lib/hello.py'
        outside = self.parent / 'same-bytes'
        outside.write_bytes(path.read_bytes())
        path.unlink()
        path.symlink_to(outside)
        with self.assertRaisesRegex(ValueError, 'link/special'):
            self.audit()
        path.unlink()
        path.write_bytes(b'hello\n')

    def test_extra_published_file_rejected(self):
        self.root.chmod(0o755)
        (self.root / 'surprise').write_bytes(b'outside selected projection')
        with self.assertRaisesRegex(ValueError, 'file inventory'):
            self.audit()

    def test_provenance_semantic_boolean_swap_rejected(self):
        path = self.root / 'provenance.json'
        provenance = copy.deepcopy(self.provenance)
        provenance['schema_version'] = False
        path.chmod(0o644)
        path.write_text(json.dumps(provenance) + '\n')
        path.chmod(0o444)
        os.utime(path, ns=(oracle.MTIME * 1000000000,) * 2)
        with self.assertRaisesRegex(ValueError, 'provenance differs'):
            self.audit()


class SelectedInputTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory(dir='/private/tmp' if sys.platform == 'darwin' else '/tmp')
        self.parent = Path(self.temporary.name)

    def tearDown(self):
        self.temporary.cleanup()

    def test_bound_and_symlink_rejections_do_not_read_fifo(self):
        path = self.parent / 'file'
        path.write_bytes(b'abc')
        with self.assertRaisesRegex(ValueError, 'bounded regular'):
            oracle.regular_identity(path, 2)
        alias = self.parent / 'alias'
        alias.symlink_to(path)
        with self.assertRaisesRegex(ValueError, 'bounded regular'):
            oracle.regular_identity(alias, 3)
        fifo = self.parent / 'fifo'
        os.mkfifo(fifo)
        with self.assertRaisesRegex(ValueError, 'bounded regular'):
            oracle.regular_identity(fifo, 3)

    def test_opened_inode_mismatch_rejected(self):
        path = self.parent / 'file'
        path.write_bytes(b'abc')
        other = self.parent / 'other'
        other.write_bytes(b'abc')
        with patch.object(oracle.TREE.os, 'fstat', return_value=other.stat()):
            with self.assertRaisesRegex(ValueError, 'identity changed'):
                oracle.regular_identity(path, 3)

    def test_shortened_read_rejected(self):
        path = self.parent / 'file'
        path.write_bytes(b'abc')
        with patch.object(oracle.TREE.os, 'read', side_effect=[b'a', b'']):
            with self.assertRaisesRegex(ValueError, 'size changed'):
                oracle.regular_identity(path, 3)

    def test_foreign_ancestor_alias_rejected(self):
        real = self.parent / 'real'
        real.mkdir()
        (real / 'file').write_bytes(b'abc')
        alias = self.parent / 'alias'
        alias.symlink_to(real, target_is_directory=True)
        with self.assertRaisesRegex(ValueError, 'ancestor'):
            oracle.regular_identity(alias / 'file', 3)

    def test_bad_elf_and_truncated_elf_rejected_without_loader(self):
        for payload in (b'notELF', b'\x7fELF\x01' + bytes(64),
                        b'\x7fELF\x02\x01\x01\x00' + bytes(8) + bytes(48)):
            with self.assertRaises(ValueError):
                oracle.inspection.inspect_elf(payload)


class HarnessFreshOutputTests(unittest.TestCase):
    def protected_paths(self, existing_side):
        harness = HERE / 'run-linux.sh'
        self.assertTrue(harness.is_file())
        for kind in ('file', 'directory', 'symlink'):
            with self.subTest(existing_side=existing_side, kind=kind), tempfile.TemporaryDirectory() as temporary:
                parent = Path(temporary)
                evidence, build = parent / 'evidence', parent / 'build'
                protected = evidence if existing_side == 'evidence' else build
                missing = build if existing_side == 'evidence' else evidence
                sentinel = b'fresh guard must preserve this\n'
                if kind == 'file':
                    protected.write_bytes(sentinel)
                elif kind == 'directory':
                    protected.mkdir()
                    (protected / 'sentinel').write_bytes(sentinel)
                else:
                    destination = parent / 'sentinel'
                    destination.write_bytes(sentinel)
                    protected.symlink_to(destination)
                tools = parent / 'tools'
                tools.mkdir()
                invoked = parent / 'unexpected-tool'
                for name in ('python3', 'cargo', 'podman', 'rustup'):
                    executable = tools / name
                    executable.write_text('#!/bin/sh\nprintf unexpected > "' + str(invoked) + '"\nexit 73\n')
                    executable.chmod(0o755)
                result = subprocess.run(['sh', str(harness), '--allow-development', str(evidence), str(build)],
                                        capture_output=True, timeout=5,
                                        env=dict(os.environ, PATH=str(tools) + os.pathsep + os.environ['PATH']))
                self.assertNotEqual(result.returncode, 0)
                self.assertFalse(missing.exists() or missing.is_symlink())
                self.assertFalse(invoked.exists(), 'fresh guards must precede all build/vendor/podman commands')
                if kind == 'file':
                    self.assertEqual(protected.read_bytes(), sentinel)
                elif kind == 'directory':
                    self.assertEqual(list(protected.iterdir()), [protected / 'sentinel'])
                    self.assertEqual((protected / 'sentinel').read_bytes(), sentinel)
                else:
                    self.assertTrue(protected.is_symlink())
                    self.assertEqual(protected.read_bytes(), sentinel)

    def test_existing_evidence_never_creates_build_or_runs_tools(self):
        self.protected_paths('evidence')

    def test_existing_build_never_creates_evidence_or_runs_tools(self):
        self.protected_paths('build')


if __name__ == '__main__':
    unittest.main()
