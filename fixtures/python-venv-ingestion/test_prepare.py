#!/usr/bin/env python3
"""Pin the independently constructed wheel and its expected installed projection."""
import csv
import hashlib
import importlib.util
import io
import json
from pathlib import Path
import unittest
import zipfile

spec = importlib.util.spec_from_file_location('venv_fixture_preparation', Path(__file__).resolve().with_name('prepare.py'))
prepare = importlib.util.module_from_spec(spec)
spec.loader.exec_module(prepare)


class FixtureTests(unittest.TestCase):
    def test_checked_in_wheel_reproduces_exactly(self):
        payload = (prepare.HERE / prepare.WHEEL_NAME).read_bytes()
        self.assertEqual(payload, prepare.wheel_bytes())
        self.assertEqual(hashlib.sha256(payload).hexdigest(), 'ac1701dbdecd3883432a32a1a79204a9c89186fc11554596b3d326010bd5be3a')

    def test_provenance_matches_sources_and_archive(self):
        self.assertEqual(json.loads((prepare.HERE / 'wheel-provenance.json').read_text()), prepare.wheel_provenance())

    def test_wheel_zip_recipe(self):
        with zipfile.ZipFile(io.BytesIO(prepare.wheel_bytes())) as archive:
            self.assertEqual(archive.namelist(), sorted(prepare.wheel_files()))
            self.assertEqual(len(archive.infolist()), 8)
            for member in archive.infolist():
                self.assertEqual(member.date_time, (1980, 1, 1, 0, 0, 0))
                self.assertEqual(member.compress_type, zipfile.ZIP_STORED)
                self.assertEqual(member.external_attr >> 16, 0o100644)

    def test_wheel_record_and_quoted_asset(self):
        files = prepare.wheel_files()
        rows = list(csv.reader(io.StringIO(files[prepare.RECORD].decode())))
        self.assertEqual(len(rows), 8)
        self.assertEqual([row[0] for row in rows], sorted(files))
        self.assertIn('"glue_meta_demo/data/message,one.txt"', files[prepare.RECORD].decode())
        for name, digest, size in rows:
            if name == prepare.RECORD:
                self.assertEqual([digest, size], ['', ''])
            else:
                self.assertEqual(digest, prepare.record_hash(files[name]))
                self.assertEqual(int(size), len(files[name]))

    def test_expected_application_inventory(self):
        root = prepare.HERE / 'expected-input'
        actual = {path.relative_to(root).as_posix(): prepare.identity(path.read_bytes()) for path in sorted(root.rglob('*')) if path.is_file()}
        self.assertEqual(len(actual), 11)
        self.assertEqual(actual, json.loads((prepare.HERE / 'expected-inventory.json').read_text())['files'])

    def test_expected_installed_record(self):
        root = prepare.HERE / 'expected-input/app/python'
        files = {path.relative_to(root).as_posix(): path.read_bytes() for path in sorted(root.rglob('*')) if path.is_file()}
        self.assertEqual(len(files), 10)
        self.assertEqual(files[prepare.RECORD], prepare.record_bytes(files))
        self.assertEqual(set(files), set(prepare.wheel_files()) | {prepare.DIST + '/INSTALLER', prepare.DIST + '/REQUESTED'})

    def test_application_entry_remains_byte_identical(self):
        self.assertEqual((prepare.HERE / 'expected-input/app/main.py').read_bytes(), (prepare.SOURCE / 'app/main.py').read_bytes())

    def test_plugin_and_console_entries_are_preserved(self):
        self.assertEqual(prepare.ENTRY_POINTS, b'[glue.archive.plugins]\nanswer = glue_meta_demo:plugin\n\n[console_scripts]\nglue-meta-demo = glue_meta_demo:plugin\n')
        self.assertIn(b'Root-Is-Purelib: true\nTag: py3-none-any\n', prepare.WHEEL)


if __name__ == '__main__':
    unittest.main(verbosity=2)
