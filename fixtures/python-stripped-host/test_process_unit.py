#!/usr/bin/env python3
"""Preserved ownership graph plus independent two-pass artifact regressions."""
from __future__ import annotations

import copy
import gzip
from pathlib import Path
import tempfile
import unittest

import importlib.util
import sys
HERE = Path(__file__).resolve().parent
spec = importlib.util.spec_from_file_location('_stripped_process_unit_policy', HERE / 'test_process.py')
policy = importlib.util.module_from_spec(spec)
sys.modules[spec.name] = policy
spec.loader.exec_module(policy)
old_units = policy.local('_stripped_private_tree_units', HERE.parent / 'python-runtime-trees/test_process_unit.py',
                         {'prepare': policy.prepare.TREE, 'test_process': policy})


class TreeGraphTests(old_units.ProcessPolicyTests):
    def test_complete_trace_and_exact_command(self):
        self.reject(self.lines[:-1])
        self.reject(self.lines + [self.lines[1]])
        self.reject(self.replace('"--runtime-tree"', '"--pbs-install-only"'))
        self.reject(self.replace('"host-install-stripped"', '"host-install"'))


def artifact_fixture():
    tree, original = old_units.fixture()
    expected = copy.copy(tree)
    expected.root = '/artifact.tar.gz'
    expected.input_kind = 'artifact'
    expected.artifact_prefix = b'compressed\0\xff'
    expected.artifact_identity = policy.prepare.identity(expected.artifact_prefix)
    records = []
    def emit(body):
        records.append('42  ' + body + '\n')
    emit('execve("/glue", [' + ', '.join(old_units.quoted(value.encode()) for value in expected.command) + '], 0x123) = 0')
    emit('statx(AT_FDCWD</workspace>, "/artifact.tar.gz", AT_STATX_SYNC_AS_STAT|AT_SYMLINK_NOFOLLOW, STATX_ALL, {stx_mode=S_IFREG|0644, stx_size=12}) = 0')
    emit('openat(AT_FDCWD</workspace>, "/artifact.tar.gz", O_RDONLY|O_CLOEXEC) = 3</artifact.tar.gz>')
    emit('statx(3</artifact.tar.gz>, "", AT_STATX_SYNC_AS_STAT|AT_EMPTY_PATH, STATX_ALL, {stx_mode=S_IFREG|0644, stx_size=12}) = 0')
    for _ in range(2):
        emit('lseek(3</artifact.tar.gz>, 0, SEEK_SET) = 0')
        emit('read(3</artifact.tar.gz>, ' + old_units.quoted(expected.artifact_prefix) + ', 65536) = 12')
        emit('read(3</artifact.tar.gz>, "", 65536) = 0')
    emit('close(3</artifact.tar.gz>) = 0')
    publication = next(index for index, line in enumerate(original) if ' mkdirat(' in line)
    records.extend(original[publication:])
    return expected, records


class ArtifactGraphTests(unittest.TestCase):
    def setUp(self):
        self.expected, self.lines = artifact_fixture()

    def rejected(self, lines):
        with self.assertRaises(ValueError):
            policy.audit_lines(lines, self.expected)

    def test_two_complete_compressed_passes_then_frozen_publication(self):
        result = policy.audit_lines(self.lines, self.expected)
        self.assertEqual(result['compressed_read_passes'], 2)
        self.assertEqual(result['compressed_input_bytes'], 24)
        self.assertTrue(result['publication_after_complete_input_read_and_close'])

    def test_each_rewind_read_eof_and_close_is_required(self):
        for index, line in enumerate(self.lines):
            if 'lseek(' in line or 'read(3</artifact.tar.gz>' in line or 'close(3</artifact.tar.gz>' in line:
                with self.subTest(line=line):
                    self.rejected(self.lines[:index] + self.lines[index + 1:])

    def test_overflow_wrong_prefix_and_wrong_owner_rejected(self):
        for old, new in [(', 65536) = 12', ', 65536) = 13'),
                         ('"compressed', '"Compressed'),
                         ('read(3</artifact.tar.gz>', 'read(3</foreign>'),
                         ('lseek(3</artifact.tar.gz>, 0,', 'lseek(3</artifact.tar.gz>, 1,')]:
            with self.subTest(old=old):
                changed = [line.replace(old, new, 1) for line in self.lines]
                self.rejected(changed)

    def test_third_pass_and_read_after_close_rejected(self):
        close = next(index for index, line in enumerate(self.lines) if 'close(3</artifact.tar.gz>' in line)
        read = next(line for line in self.lines if 'read(3</artifact.tar.gz>' in line)
        seek = next(line for line in self.lines if 'lseek(' in line)
        self.rejected(self.lines[:close] + [seek] + self.lines[close:])
        self.rejected(self.lines[:close + 1] + [read] + self.lines[close + 1:])

    def test_publication_before_second_complete_input_pass_rejected(self):
        publication = next(index for index, line in enumerate(self.lines) if 'mkdirat(' in line)
        changed = self.lines[:5] + [self.lines[publication]] + self.lines[5:publication] + self.lines[publication + 1:]
        self.rejected(changed)

    def test_artifact_cannot_be_written_or_mapped(self):
        for body in ['write(3</artifact.tar.gz>, "x", 1) = 1',
                     'mmap(NULL, 4096, PROT_READ, MAP_PRIVATE, 3</artifact.tar.gz>, 0) = 0x123000',
                     'openat(AT_FDCWD</workspace>, "/artifact.tar.gz", O_RDWR|O_CLOEXEC) = 4</artifact.tar.gz>']:
            with self.subTest(body=body):
                self.rejected(self.lines[:4] + ['42  ' + body + '\n'] + self.lines[4:])

    def test_all_actual_trace_mutation_classes_reject_synthetic_artifact(self):
        result = policy.hostile_controls(self.lines, self.expected)
        self.assertEqual(result['hostile_controls'], 21)
        self.assertTrue(result['all_controls_rejected'])

    def test_raw_and_gzip_artifact_replay_have_equal_observations(self):
        with tempfile.TemporaryDirectory() as temporary:
            raw = Path(temporary) / 'trace.txt'
            raw.write_text(''.join(self.lines))
            zipped = Path(temporary) / 'trace.txt.gz'
            zipped.write_bytes(gzip.compress(raw.read_bytes(), mtime=0))
            first, second = policy.audit_trace(raw, self.expected), policy.audit_trace(zipped, self.expected)
            first.pop('trace_identity'); second.pop('trace_identity')
            self.assertEqual(first, second)


if __name__ == '__main__':
    unittest.main()
