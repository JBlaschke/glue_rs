#!/usr/bin/env python3
"""Independent fixture controls for exact app projection and CRC damage."""
from pathlib import Path
import base64
import csv
import hashlib
import io
import json
import sys
import tempfile
import unittest
import zipfile

sys.path.insert(0, str(Path(__file__).resolve().parent))
import runtime


class RuntimeFixtureTests(unittest.TestCase):
    def test_distribution_record_is_complete_and_hashes_every_retained_package_file(self):
        root = runtime.APPLICATION / 'app/python'
        record = root / 'glue_stripped_demo-1.0.dist-info/RECORD'
        rows = list(csv.reader(io.StringIO(record.read_text())))
        actual = {path.relative_to(root).as_posix() for path in root.rglob('*') if path.is_file()}
        self.assertEqual({row[0] for row in rows}, actual)
        self.assertEqual(len(rows), len(actual))
        for path, digest, size in rows:
            if path.endswith('/RECORD'):
                self.assertEqual((digest, size), ('', ''))
            else:
                data = (root / path).read_bytes()
                self.assertEqual(int(size), len(data))
                self.assertEqual(digest, 'sha256=' + base64.urlsafe_b64encode(hashlib.sha256(data).digest()).decode().rstrip('='))

    def test_mode_provider_paths_are_separated(self):
        self.assertEqual(runtime.prefix_for('corrupt-entry'), runtime.PREFIX)
        self.assertEqual(runtime.prefix_for('wrong-profile'), runtime.PREFIX)
        self.assertEqual(runtime.profile_for('wrong-profile'), 'unstripped')
        self.assertEqual(runtime.prefix_for('unstripped'), runtime.OLD_PREFIX)
        for mode in ('missing-library', 'wrong-library', 'corrupt-library'):
            self.assertEqual(runtime.prefix_for(mode), runtime.PREFIX + ' ' + mode)
            self.assertEqual(runtime.profile_for(mode), 'stripped')

    def test_crc_control_changes_only_the_first_stored_entry_byte(self):
        with tempfile.TemporaryDirectory() as directory:
            original, damaged = Path(directory) / 'valid.glue', Path(directory) / 'corrupt.glue'
            frame = b'GLUERS00' + bytes(56)
            original.write_bytes(frame)
            with zipfile.ZipFile(original, 'a', compression=zipfile.ZIP_STORED) as zipped:
                for relative in runtime.expected_application():
                    zipped.writestr(relative, (runtime.APPLICATION / relative).read_bytes())
            before = original.read_bytes()
            receipt = runtime.corrupt_entry(original, damaged)
            after = damaged.read_bytes()
            self.assertEqual(len(before), len(after))
            self.assertEqual([index for index, pair in enumerate(zip(before, after)) if pair[0] != pair[1]], [receipt['corrupt_offset']])
            self.assertEqual(before[:64], after[:64])
            self.assertEqual(before[receipt['corrupt_offset']] ^ 1, after[receipt['corrupt_offset']])
            with zipfile.ZipFile(damaged) as zipped:
                with self.assertRaises(zipfile.BadZipFile):
                    zipped.read(runtime.ENTRY)
                self.assertEqual(zipped.read('app/python/stripped_demo/data/value.txt'), b'42\n')
            self.assertEqual(original.read_bytes(), before)

    def test_crc_control_protects_existing_destination(self):
        with tempfile.TemporaryDirectory() as directory:
            original, protected = Path(directory) / 'absent', Path(directory) / 'existing'
            protected.write_bytes(b'protected')
            with self.assertRaises(ValueError):
                runtime.corrupt_entry(original, protected)
            self.assertEqual(protected.read_bytes(), b'protected')

    def test_crc_control_rejects_a_foreign_entry(self):
        with tempfile.TemporaryDirectory() as directory:
            original, damaged = Path(directory) / 'foreign.glue', Path(directory) / 'corrupt.glue'
            original.write_bytes(b'GLUERS00' + bytes(56))
            with zipfile.ZipFile(original, 'a') as zipped:
                zipped.writestr(runtime.ENTRY, b'print("foreign")\n')
            with self.assertRaises(ValueError):
                runtime.corrupt_entry(original, damaged)
            self.assertFalse(damaged.exists())


if __name__ == '__main__':
    unittest.main()
