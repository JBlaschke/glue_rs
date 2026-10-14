#!/usr/bin/env python3
"""Independent corruption/ownership controls for the real-package fixture oracle."""
import ast
import base64
import copy
import csv
import hashlib
import importlib.util
import io
import json
import os
from pathlib import Path, PurePosixPath
import shutil
import struct
import sys
import tempfile
import unittest
from unittest.mock import patch
import zipfile

sys.dont_write_bytecode = True
spec = importlib.util.spec_from_file_location('real_package_fixture', Path(__file__).with_name('prepare.py'))
C = importlib.util.module_from_spec(spec)
spec.loader.exec_module(C)


def record_digest(data):
    return 'sha256=' + base64.urlsafe_b64encode(hashlib.sha256(data).digest()).decode().rstrip('=')


def make_installed(root):
    """Tiny generated sidecars plus unmodified wheel payloads; no target imports."""
    venv = root / 'venv'
    site = venv / 'lib/python3.13/site-packages'
    site.mkdir(parents=True)
    (venv / 'bin').mkdir()
    (venv / 'pyvenv.cfg').write_text('home = /unavailable/Python\ninclude-system-site-packages = false\nversion = 3.13.16\n')
    pins = json.loads(C.PIN_FILE.read_bytes())
    for pin in pins['wheels']:
        with zipfile.ZipFile(C.HERE / 'wheels' / pin['filename']) as archive:
            payloads = {name: archive.read(name) for name in archive.namelist()}
        dist = next(name for name in payloads if name.endswith('/RECORD')).split('/')[0]
        payloads[dist + '/INSTALLER'] = b'pip\n'
        payloads[dist + '/REQUESTED'] = b''
        for name, data in list(payloads.items()):
            path = site / name
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_bytes(data)
            os.utime(path, (1704067200, 1704067200))
            if name.endswith('.py'):
                cache = str(PurePosixPath(name).parent / '__pycache__' / (PurePosixPath(name).stem + '.cpython-313.pyc'))
                # The oracle verifies omitted cache ownership/header, never runs
                # or treats this deliberately inert unit payload as real code.
                payloads[cache] = b'\xf3\r\r\n' + struct.pack('<III', 0, 1704067200, len(data)) + b'inert unit observation'
        if dist.startswith('markdown_it_py-'):
            wrapper = b'#!/unavailable/python\nfrom markdown_it.cli.parse import main\n'
            (venv / 'bin/markdown-it').write_bytes(wrapper)
            payloads['../../../bin/markdown-it'] = wrapper
        stream = io.StringIO(newline='')
        writer = csv.writer(stream, lineterminator='\n')
        for name, data in sorted(payloads.items()):
            writer.writerow([name, '', ''] if name == dist + '/RECORD' or name.endswith('.pyc') else [name, record_digest(data), str(len(data))])
        payloads[dist + '/RECORD'] = stream.getvalue().encode()
        for name, data in payloads.items():
            if name.startswith('../../../'):
                continue
            path = site / name
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_bytes(data)
            os.utime(path, (1704067200, 1704067200))
    return venv


def host_archive_fixture(root):
    venv = make_installed(root)
    expected, facts = C.installed_projection(venv)
    helper_files = {'python/archive-importer.py': (C.HERE.parent / 'python-imports/bootstrap.py').read_bytes(),
                    'python/archive-metadata.py': (C.HERE.parent / 'python-metadata/bootstrap.py').read_bytes()}
    files = expected | helper_files
    resources = {name: C.identity(data) | {'compression': 'deflate' if name.startswith('python/') else 'stored'} for name, data in files.items()}
    manifest = {'schema_version': 0, 'app_id': 'python.real-packages', 'entrypoint': 'launch',
                'components': {'launch': {'entry_point': 'app/main.py', 'native_modules': [], 'runtime': 'python'}},
                'runtimes': {'python': {'abi': {'language': 'python', 'version': {'major': 3, 'minor': 13, 'patch': 16}, 'debug': False, 'gil': 'conventional'},
                                      'build_id': 'pbs-20261009-cpython-3.13.16-pgo-lto-host-metadata-apps-v1',
                                      'provisioning': {'mode': 'host', 'discovery': 'explicit_paths',
                                                       'runtime_library': '/unavailable/Python/lib/libpython3.13.so.1.0',
                                                       'stdlib': '/unavailable/Python/lib/python3.13'},
                                      'required_features': [], 'target': 'linux-arm64'}},
                'targets': {'linux-arm64': {'os': 'linux', 'arch': 'aarch64', 'abi': {'family': 'glibc', 'minimum_version': '2.36'},
                                          'minimum_os_version': '7.1.4', 'page_sizes': [4096], 'cpu_features': []}},
                'native_modules': {}, 'host_imports': {}, 'resources': resources}
    raw = json.dumps(manifest, sort_keys=True, separators=(',', ':')).encode()
    payload = io.BytesIO()
    with zipfile.ZipFile(payload, 'w') as archive:
        for name, data in sorted(files.items()):
            archive.writestr(name, data, compress_type=zipfile.ZIP_DEFLATED if name.startswith('python/') else zipfile.ZIP_STORED)
    archive_path = root / 'application.glue'
    archive_path.write_bytes(b'GLUERS00' + b'\0' * 8 + struct.pack('<QQ', len(raw), len(payload.getvalue())) + hashlib.sha256(raw).digest() + raw + payload.getvalue())
    original = facts['installed_files']
    distributions = [{'name': project, 'version': version, 'directory': dist,
                      'retained_files': {'markdown-it-py': 76, 'mdit-py-plugins': 62, 'mdurl': 13}[project],
                      'original_record_sha256': original[dist + '/RECORD']['sha256'],
                      'original_record_bytes': original[dist + '/RECORD']['size']} for project, version, dist in C.PROJECTS]
    retained_inputs = {name.removeprefix('app/python/'): original[name.removeprefix('app/python/')] for name in expected if name.startswith('app/python/')}
    inputs = [{'source': 'packages', 'path': name, **value} for name, value in retained_inputs.items()]
    inputs += [{'source': 'provider', 'path': name, **C.identity(data)} for name, data in helper_files.items()]
    inputs += [{'source': 'application', 'path': 'app/main.py', **C.identity(expected['app/main.py'])},
               {'source': 'venv', 'path': 'pyvenv.cfg', **C.identity((venv / 'pyvenv.cfg').read_bytes())}]
    template = copy.deepcopy(manifest)
    template['app_id'] = 'python.runtime.template'
    placeholder = b"raise RuntimeError('This is a Python runtime template; use glue build-python with its manifest.json and root directory to package an application.')\n"
    template['resources'] = {name: resources[name] for name in helper_files}
    template['resources']['app/main.py'] = {'size': len(placeholder), 'sha256': hashlib.sha256(placeholder).hexdigest(), 'compression': 'stored'}
    template_bytes = (json.dumps(template, sort_keys=True, separators=(',', ':'), ensure_ascii=False) + '\n').encode()
    inputs.append({'source': 'template', 'path': 'manifest.json', 'size': len(template_bytes), 'sha256': hashlib.sha256(template_bytes).hexdigest()})
    report = {'build': {'archive_bytes': archive_path.stat().st_size, 'archive_sha256': C.identity(archive_path.read_bytes())['sha256'],
                        'manifest_sha256': hashlib.sha256(raw).hexdigest(), 'resource_count': len(files),
                        'uncompressed_bytes': sum(map(len, files.values()))}, 'package_input': 'venv',
              'distributions': distributions, 'inputs': inputs,
              'omissions': sorted([{'path': item['path'], 'reason': 'bytecode_or_cache' if item['kind'] == 'bytecode' else 'generated_entry_point_wrapper'}
                                   for item in facts['omissions']], key=lambda item: (item['path'], item['reason']))}
    report_path = root / 'report.json'
    report_path.write_text(json.dumps(report))
    provenance = {'expected_application': C.expected_inventory()['files'], 'omission_count': 111,
                  'original_records': facts['original_records'], 'venv_configuration': (venv / 'pyvenv.cfg').read_text()}
    provenance_path = root / 'provenance.json'
    provenance_path.write_text(json.dumps(provenance))
    return archive_path, report_path, provenance_path, report


class PinAndProjectionTests(unittest.TestCase):
    def test_exact_upstream_artifacts_and_independent_inventory(self):
        owners, facts = C.wheel_corpus()
        self.assertEqual(len(owners), 3)
        self.assertEqual(sum(len(files) for files in owners.values()), 145)
        self.assertEqual(sum(name.endswith('.py') for files in owners.values() for name in files), 110)
        inventory = C.expected_inventory()
        self.assertEqual(inventory, json.loads((C.HERE / 'expected-inventory.json').read_text()))
        self.assertEqual(len(inventory['files']), 152)
        self.assertEqual(sum(value['size'] for value in inventory['files'].values()), 451195)
        self.assertEqual(min(inventory['files']), 'app/main.py')
        for files in owners.values():
            self.assertTrue(any(name.endswith('py.typed') for name in files))
            self.assertTrue(any(name.endswith('/LICENSE') for name in files))
        self.assertEqual(C.identity((C.HERE / 'expected.stdout.txt').read_bytes()), C.identity(C.OUTPUT))

    def test_golden_render_and_full_tokens_are_bound_into_app(self):
        golden = json.loads((C.HERE / 'expected-workload.json').read_text())
        declarations = {node.targets[0].id: ast.literal_eval(node.value) for node in ast.parse(C.APPLICATION.read_text()).body
                        if isinstance(node, ast.Assign) and len(node.targets) == 1 and isinstance(node.targets[0], ast.Name)
                        and node.targets[0].id.startswith('EXPECTED_')}
        self.assertEqual(hashlib.sha256(golden['html'].encode()).hexdigest(), declarations['EXPECTED_HTML_SHA'])
        self.assertEqual(hashlib.sha256(golden['tokens_json'].encode('ascii')).hexdigest(), declarations['EXPECTED_TOKENS_SHA'])
        self.assertEqual(len(json.loads(golden['tokens_json'])), declarations['EXPECTED_TOKEN_COUNT'])
        self.assertIn('caf%C3%A9', golden['html'])
        self.assertIn('footnotes', golden['html'])
        self.assertIn('task-list-item-checkbox', golden['html'])
        self.assertNotIn('import hashlib', C.APPLICATION.read_text())

    def test_typed_equality_distinguishes_bool_float_and_nested_sizes(self):
        for value in (False, 0.0):
            self.assertFalse(C.typed_equal({'size': 0}, {'size': value}))
            self.assertFalse(C.typed_equal({'files': [{'size': 0}]}, {'files': [{'size': value}]}))
        self.assertTrue(C.typed_equal({'a': 0, 'b': False}, {'b': False, 'a': 0}))

    def test_json_and_member_paths_reject_ambiguous_inputs(self):
        for payload in ('{"size":1,"size":2}', '{"size":NaN}'):
            with self.assertRaises(ValueError):
                C.strict_json(payload)
        for path in ('../outside', '/absolute', 'x//y', 'x/./y', 'x\\y', 'x\ny'):
            self.assertFalse(C.canonical_member(path))

    def test_wheel_corruption_or_symlink_rejects_before_payload_oracle(self):
        with tempfile.TemporaryDirectory() as temporary:
            directory = Path(temporary)
            shutil.copytree(C.HERE / 'wheels', directory / 'wheels')
            pin_file = directory / 'wheel-pins.json'
            shutil.copyfile(C.PIN_FILE, pin_file)
            wheel = directory / 'wheels/markdown_it_py-4.2.0-py3-none-any.whl'
            previous = wheel.read_bytes()
            wheel.write_bytes(bytes([previous[0] ^ 1]) + previous[1:])
            with patch.object(C, 'HERE', directory), patch.object(C, 'PIN_FILE', pin_file), self.assertRaisesRegex(ValueError, 'compressed identity'):
                C.wheel_corpus()
            wheel.unlink()
            wheel.symlink_to(C.HERE / 'wheels/markdown_it_py-4.2.0-py3-none-any.whl')
            with patch.object(C, 'HERE', directory), patch.object(C, 'PIN_FILE', pin_file), self.assertRaisesRegex(ValueError, 'nonregular'):
                C.wheel_corpus()

    def test_record_rewrite_sorts_quotes_and_excludes_its_own_digest(self):
        files = {'package/data,one.txt': b'asset', 'z.py': b'last', 'a.py': b'first', 'x.dist-info/RECORD': b'original rows'}
        raw = C.record_bytes(files, 'x.dist-info/RECORD')
        self.assertIn(b'"package/data,one.txt"', raw)
        rows = list(csv.reader(io.StringIO(raw.decode())))
        self.assertEqual([row[0] for row in rows], sorted(files))
        self.assertEqual(next(row for row in rows if row[0].endswith('/RECORD'))[1:], ['', ''])
        self.assertEqual(raw, C.record_bytes(dict(reversed(list(files.items()))), 'x.dist-info/RECORD'))


class InstalledOwnershipTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary.name)
        self.venv = make_installed(self.root)
        self.site = self.venv / 'lib/python3.13/site-packages'

    def tearDown(self):
        self.temporary.cleanup()

    def test_projection_works_without_an_interpreter_and_without_subprocesses(self):
        self.assertFalse((self.venv / 'bin/python').exists())
        with patch.object(C.subprocess, 'run', side_effect=AssertionError('must not execute an interpreter')):
            files, facts = C.publish_expected(self.venv, self.root / 'expected')
        self.assertEqual(files, C.expected_projection())
        self.assertEqual(facts['installed_file_count'], 261)
        self.assertEqual(facts['omission_count'], 111)
        self.assertEqual(sum(item['kind'] == 'bytecode' for item in facts['omissions']), 110)

    def test_changed_upstream_payload_and_consistent_record_still_reject(self):
        path = self.site / 'mdurl/__init__.py'
        data = path.read_bytes()
        path.write_bytes(bytes([data[0] ^ 1]) + data[1:])
        record = self.site / 'mdurl-0.1.2.dist-info/RECORD'
        rows = list(csv.reader(io.StringIO(record.read_text())))
        for row in rows:
            if row[0] == 'mdurl/__init__.py':
                row[1] = record_digest(path.read_bytes())
        stream = io.StringIO(newline=''); csv.writer(stream, lineterminator='\n').writerows(rows); record.write_text(stream.getvalue())
        with self.assertRaises(ValueError):
            C.installed_projection(self.venv)

    def test_unowned_file_or_link_rejects(self):
        path = self.site / 'unowned.pth'
        path.write_bytes(b'import unwanted\n')
        with self.assertRaisesRegex(ValueError, 'site inventory'):
            C.installed_projection(self.venv)
        path.unlink()
        path.symlink_to('/outside')
        with self.assertRaisesRegex(ValueError, 'link/special'):
            C.installed_projection(self.venv)

    def test_cache_header_source_timestamp_or_size_rejects(self):
        cache = self.site / 'mdurl/__pycache__/__init__.cpython-313.pyc'
        original = cache.read_bytes()
        for offset in (0, 4, 8, 12):
            with self.subTest(offset=offset):
                altered = bytearray(original); altered[offset] ^= 1; cache.write_bytes(altered)
                with self.assertRaisesRegex(ValueError, 'cache'):
                    C.installed_projection(self.venv)
        cache.write_bytes(original)

    def test_missing_or_duplicate_record_owner_rejects(self):
        record = self.site / 'mdurl-0.1.2.dist-info/RECORD'
        original = record.read_bytes()
        rows = list(csv.reader(io.StringIO(original.decode())))
        for changed in (rows[:-1], rows + [rows[0]]):
            stream = io.StringIO(newline=''); csv.writer(stream, lineterminator='\n').writerows(changed); record.write_text(stream.getvalue())
            with self.assertRaises(ValueError):
                C.installed_projection(self.venv)
        record.write_bytes(original)

    def test_wrapper_hash_and_existing_output_protection(self):
        wrapper = self.venv / 'bin/markdown-it'
        original = wrapper.read_bytes()
        wrapper.write_bytes(original + b'# changed\n')
        with self.assertRaisesRegex(ValueError, 'wrapper identity'):
            C.installed_projection(self.venv)
        wrapper.write_bytes(original)
        output = self.root / 'protected'
        output.mkdir(); (output / 'sentinel').write_bytes(b'unchanged')
        with self.assertRaises(FileExistsError):
            C.publish_expected(self.venv, output)
        self.assertEqual({path.name for path in output.iterdir()}, {'sentinel'})
        self.assertEqual((output / 'sentinel').read_bytes(), b'unchanged')


class ArchiveOracleTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary.name)
        self.archive, self.report_path, self.provenance, self.report = host_archive_fixture(self.root)

    def tearDown(self):
        self.temporary.cleanup()

    def test_complete_normalized_archive_and_original_input_attestation_pass(self):
        result = C.audit_build(self.report_path, self.archive, self.provenance)
        self.assertEqual(result['application_file_count'], 152)
        self.assertEqual(result['complete_archive_resource_count'], 154)
        self.assertTrue(result['all_resource_bytes_verified'])

    def test_report_omission_distribution_and_input_forgery_reject(self):
        for field in ('omissions', 'distributions', 'inputs'):
            changed = copy.deepcopy(self.report)
            if field == 'omissions':
                changed[field].pop()
            elif field == 'distributions':
                changed[field][0]['version'] = '999'
            else:
                changed[field][0]['sha256'] = '0' * 64
            self.report_path.write_text(json.dumps(changed))
            with self.subTest(field=field), self.assertRaises(ValueError):
                C.audit_build(self.report_path, self.archive, self.provenance)

    def test_crc_damage_and_trailing_framing_reject(self):
        original = self.archive.read_bytes()
        with zipfile.ZipFile(self.archive) as archive:
            member = archive.getinfo('app/main.py')
            names, extra = struct.unpack_from('<HH', original, member.header_offset + 26)
            offset = member.header_offset + 30 + names + extra
        altered = bytearray(original); altered[offset] ^= 1; self.archive.write_bytes(altered)
        with self.assertRaises((ValueError, zipfile.BadZipFile)):
            C.audit_build(self.report_path, self.archive, self.provenance)
        self.archive.write_bytes(original + b'trailing')
        with self.assertRaisesRegex(ValueError, 'framing'):
            C.audit_build(self.report_path, self.archive, self.provenance)

    def rewrite_manifest(self, change):
        original = self.archive.read_bytes()
        old_size, zip_size = struct.unpack_from('<QQ', original, 16)
        manifest = json.loads(original[64:64 + old_size])
        change(manifest)
        raw = json.dumps(manifest, sort_keys=True, separators=(',', ':')).encode()
        new = b'GLUERS00' + b'\0' * 8 + struct.pack('<QQ', len(raw), zip_size) + hashlib.sha256(raw).digest() + raw + original[64 + old_size:]
        self.archive.write_bytes(new)
        report = copy.deepcopy(self.report)
        report['build']['archive_bytes'] = len(new)
        report['build']['manifest_sha256'] = hashlib.sha256(raw).hexdigest()
        report['build']['archive_sha256'] = hashlib.sha256(new).hexdigest()
        self.report_path.write_text(json.dumps(report))

    def test_report_boolean_and_float_size_forgery_rejects(self):
        for value in (False, 0.0):
            changed = copy.deepcopy(self.report)
            item = next(item for item in changed['inputs'] if item['path'].endswith('/REQUESTED'))
            item['size'] = value
            self.report_path.write_text(json.dumps(changed))
            with self.subTest(value=value), self.assertRaisesRegex(ValueError, 'bounded integer'):
                C.audit_build(self.report_path, self.archive, self.provenance)
        for field in ('archive_bytes', 'resource_count', 'uncompressed_bytes'):
            changed = copy.deepcopy(self.report); changed['build'][field] = float(changed['build'][field])
            self.report_path.write_text(json.dumps(changed))
            with self.subTest(field=field), self.assertRaisesRegex(ValueError, 'bounded integer'):
                C.audit_build(self.report_path, self.archive, self.provenance)

    def test_manifest_boolean_or_float_resource_sizes_reject_with_valid_framing(self):
        original = self.archive.read_bytes()
        for value in (False, 0.0):
            self.archive.write_bytes(original)
            self.rewrite_manifest(lambda manifest: manifest['resources']['app/python/mdurl-0.1.2.dist-info/REQUESTED'].__setitem__('size', value))
            with self.subTest(value=value), self.assertRaisesRegex(ValueError, 'bounded integer'):
                C.audit_build(self.report_path, self.archive, self.provenance)

    def test_unknown_missing_duplicate_and_extra_input_paths_reject(self):
        mutations = (
            lambda report: report['inputs'].append({'source': 'arbitrary', 'path': 'hidden.txt', 'size': 0, 'sha256': '0' * 64}),
            lambda report: report.__setitem__('inputs', [item for item in report['inputs'] if item['source'] != 'template']),
            lambda report: report.__setitem__('inputs', [item for item in report['inputs'] if item['source'] != 'venv']),
            lambda report: report['inputs'].append({'source': 'application', 'path': 'app/extra.py', 'size': 0, 'sha256': hashlib.sha256(b'').hexdigest()}),
            lambda report: report['inputs'].append(copy.deepcopy(report['inputs'][0])),
            lambda report: next(item for item in report['inputs'] if item['source'] == 'template').__setitem__('sha256', '0' * 64),
        )
        for mutate in mutations:
            changed = copy.deepcopy(self.report); mutate(changed); self.report_path.write_text(json.dumps(changed))
            with self.subTest(mutate=mutate), self.assertRaises(ValueError):
                C.audit_build(self.report_path, self.archive, self.provenance)

    def test_extra_report_and_nested_schema_fields_reject(self):
        for nested in (None, 'build', 'distributions', 'inputs', 'omissions'):
            changed = copy.deepcopy(self.report)
            target = changed if nested is None else changed[nested] if nested == 'build' else changed[nested][0]
            target['unknown'] = 'unchecked'
            self.report_path.write_text(json.dumps(changed))
            with self.subTest(nested=nested), self.assertRaisesRegex(ValueError, 'exact object fields'):
                C.audit_build(self.report_path, self.archive, self.provenance)

    def test_extra_manifest_schema_and_wrong_abi_types_reject(self):
        original = self.archive.read_bytes()
        for mutate in (
                lambda manifest: manifest.__setitem__('unchecked', True),
                lambda manifest: manifest['resources']['app/main.py'].__setitem__('unchecked', True),
                lambda manifest: manifest.__setitem__('schema_version', False),
                lambda manifest: manifest['runtimes']['python']['abi'].__setitem__('debug', 0),
                lambda manifest: manifest['runtimes']['python']['abi']['version'].__setitem__('minor', 13.0)):
            self.archive.write_bytes(original); self.rewrite_manifest(mutate)
            with self.subTest(mutate=mutate), self.assertRaises(ValueError):
                C.audit_build(self.report_path, self.archive, self.provenance)

    def test_report_hash_cannot_substitute_for_upstream_bytes(self):
        changed = copy.deepcopy(self.report)
        changed['build']['archive_sha256'] = '0' * 64
        self.report_path.write_text(json.dumps(changed))
        with self.assertRaisesRegex(ValueError, 'reported digest'):
            C.audit_build(self.report_path, self.archive, self.provenance)


if __name__ == '__main__':
    unittest.main(verbosity=2)
