"""Retained-metadata controls only; no native acceptance or provisioning."""
from contextlib import redirect_stderr, redirect_stdout
import copy
import hashlib
import io
import json
from pathlib import Path
import tempfile
import unittest

import linux_compatibility as C

ROOT = Path(__file__).resolve().parents[3]
CHECKS = ('native_target', 'build_success', 'runtime_reference', 'input_bytes_preserved',
          'input_prefix_absent', 'relocated', 'payload_read_only', 'payload_unchanged',
          'no_language_tools', 'unrelated_cwd', 'unusable_temp_cache', 'exit_status',
          'stdout', 'stderr', 'execution_completed', 'offline', 'trace_complete',
          'no_extraction', 'trace_oracle', 'signing_policy')


def encoded(value):
    return (json.dumps(value, sort_keys=True) + '\n').encode()


def identity(value):
    return {'size': len(value), 'sha256': hashlib.sha256(value).hexdigest()}


def reference(architecture):
    # Schema follows actual V02 receipts, with synthetic byte identities. These
    # fixtures cannot replace the real checker/traces or count as native evidence.
    target = architecture + '-unknown-linux-gnu'
    return {'case': 'python-source-normalized', 'status': 'passed',
            'target': target, 'host': {'target': target}, 'reference_kind': 'stock',
            'runtime': {'implementation': 'cpython', 'version': '3.13.16',
                'provider': 'bundled', 'target': target,
                'abi': {'language': 'python', 'gil': 'conventional', 'debug': False,
                        'version': {'major': 3, 'minor': 13, 'patch': 16}},
                'inputs': {'runtime-executable': identity(b'synthetic PBS executable'),
                           'stdlib:encodings/__init__.py': identity(b'synthetic stdlib')}},
            'checks': {name: {'status': 'passed'} for name in CHECKS}}


def fixture(architecture='x86_64'):
    manifest = C.official_manifest(architecture)
    base = reference(architecture)
    cases = {}
    for cell in C.cells_for(architecture):
        cwd = '/tmp/owned compatibility/cases/' + cell.label + '/work'
        inputs = cwd + '/build inputs'
        output = cwd.removesuffix('/work')
        environment = {'kind': cell.kind, 'version': [3, 13],
            'runtime': inputs + '/runtime/bin/python3.13',
            'pip_present': cell.kind == 'ordinary', 'framework_input_prepared': False}
        environment_bytes = encoded(environment)
        inventory = {'environment-receipt.json': identity(environment_bytes)}
        receipt = copy.deepcopy(base)
        receipt['case'] = cell.recipe
        prepare_argv = ['/usr/bin/python3', '/checkout/fixtures/mvp/python-matrix/prepare.py',
            inputs, 'bin/python3.13', cell.kind]
        if cell.label == 'python-uv-native':
            prepare_argv.append('--native')
        prepare_argv += ['--receipt-output', output + '/environment-receipt.json']
        selector, value = (('--module', 'main') if cell.label == 'python-uv-module'
                           else ('--console-script', 'sample') if cell.label == 'python-uv-console'
                           else ('--entry', 'main.py'))
        build_argv = ['/owned/glue', 'build', 'python', inputs + '/project', '--env',
            inputs + '/environment', selector, value, '--normalize-native-paths']
        if cell.route == 'uv':
            build_argv += ['--prune', 'app/site/0/_virtualenv.pth']
        else:
            archive = {key: manifest[cell.route][key] for key in ('sha256', 'size')}
            inventory['runtime-input.tar'] = archive
            receipt['runtime']['inputs']['runtime-archive'] = archive
            build_argv += ['--runtime', inputs + '/runtime-input.tar']
        receipt['commands'] = {
            'prepare': {'argv': prepare_argv, 'cwd': cwd, 'executed': True, 'timed_out': False, 'exit': 0},
            'build': {'argv': build_argv, 'executed': True, 'timed_out': False, 'exit': 0}}
        inventory_bytes = encoded(inventory)
        receipt['input_inventory'] = {'path': 'input-inventory.json', **identity(inventory_bytes)}
        cases[cell.label] = C.CaseEvidence(encoded(receipt), environment_bytes, inventory_bytes)
    statuses = [{'case': cell.label, 'exit': 0} for cell in C.cells_for(architecture)]
    return manifest, statuses, cases, encoded(base)


def summary(architecture='x86_64', **overrides):
    manifest, statuses, cases, base = fixture(architecture)
    return C.summarize(architecture, overrides.pop('statuses', statuses),
        overrides.pop('manifest', manifest), overrides.pop('cases', cases),
        result=overrides.pop('result', 0), reference_receipt=overrides.pop('base', base),
        finished_utc='synthetic metadata control', **overrides)


def mutate_case(cases, label, *, receipt=None, environment=None, inventory=None, rebind=False):
    old = cases[label]
    r, e, i = map(json.loads, (old.receipt, old.environment, old.inventory))
    if receipt:
        receipt(r)
    if environment:
        environment(e)
    if inventory:
        inventory(i)
    eb, ib = encoded(e), encoded(i)
    if rebind:
        i['environment-receipt.json'] = identity(eb)
        ib = encoded(i)
        r['input_inventory'] = {'path': 'input-inventory.json', **identity(ib)}
    cases[label] = C.CaseEvidence(encoded(r), eb, ib)


class LinuxCompatibilityControls(unittest.TestCase):
    def test_closed_two_targets_exact_seven_cells_and_four_official_inputs(self):
        for arch in ('x86_64', 'aarch64'):
            plan = C.compatibility_plan(arch)
            self.assertEqual(plan['target'], arch + '-unknown-linux-gnu')
            self.assertEqual(len(plan['cases']), 7)
            self.assertEqual({row['route'] for row in plan['cases']}, {'full', 'install-only', 'stripped', 'uv'})
            self.assertEqual(len(plan['inputs']), 4)
            self.assertEqual(plan['runtime_version'], '3.13.16')
            self.assertFalse(plan['full_m2_acceptance'])
            for item in C.inputs_for(arch):
                self.assertIn(arch + '-unknown-linux-gnu', item.name)
                self.assertRegex(item.sha256, r'^[0-9a-f]{64}$')
                self.assertTrue(item.url.startswith('https://github.com/astral-sh/'))
                self.assertGreater(item.size, 0)
            self.assertIn('pgo+lto-full.tar.zst', plan['inputs']['full']['name'])
            self.assertNotIn('freethreaded', plan['inputs']['full']['name'])
            self.assertNotIn('debug', plan['inputs']['full']['name'])

    def test_unknown_architecture_and_exit_status_refuse(self):
        for arch in ('arm64', 'aarch64-apple-darwin', '', True):
            with self.assertRaises(ValueError):
                C.compatibility_plan(arch)
        for result in (True, -1, 256, '0'):
            with self.assertRaises(ValueError):
                summary(result=result)

    def test_complete_synthetic_metadata_passes_both_targets_without_claiming_execution(self):
        for arch in ('x86_64', 'aarch64'):
            result = summary(arch)
            self.assertEqual((result['status'], result['exit'], result['expected_cases']), ('passed', 0, 7))
            self.assertTrue(all(row['status'] == 'passed' for row in result['cases']))
            self.assertFalse(result['full_m2_acceptance'])
            self.assertFalse(result['native_execution_performed_by_summary'])
            self.assertIn('abi3 admission', result['remaining_compatibility'])

    def test_status_closure_refuses_missing_duplicate_extra_malformed_and_failed_rows(self):
        _, rows, _, _ = fixture()
        changes = [rows[:-1], rows + [{'case': 'extra', 'exit': 0}], rows[:-1] + rows[:1],
                   [{**row, 'exit': True} if i == 0 else row for i, row in enumerate(rows)],
                   [{**row, 'exit': 1} if i == 0 else row for i, row in enumerate(rows)], None]
        for statuses in changes:
            self.assertEqual(summary(statuses=statuses)['status'], 'failed')
        self.assertEqual(summary(result=9)['exit'], 9)

    def test_official_manifest_roster_and_each_identity_field_are_required(self):
        manifest, _, _, _ = fixture()
        for route in manifest:
            for key in ('name', 'sha256', 'size', 'url'):
                altered = copy.deepcopy(manifest)
                altered[route][key] = True if key == 'size' else 'different official input'
                self.assertEqual(summary(manifest=altered)['status'], 'failed')
        for altered in ({}, {**manifest, 'extra': manifest['uv']}):
            self.assertEqual(summary(manifest=altered)['status'], 'failed')

    def test_runtime_target_version_provider_abi_and_missing_checks_cannot_pass(self):
        changes = [lambda r: r.update(target='aarch64-unknown-linux-gnu'),
                   lambda r: r['runtime'].update(version='3.14.8'),
                   lambda r: r['runtime'].update(provider='host'),
                   lambda r: r['runtime']['abi'].update(gil='free-threaded'),
                   lambda r: r['runtime']['abi']['version'].update(minor=True),
                   lambda r: r['checks'].pop('trace_complete'),
                   lambda r: r['checks']['no_extraction'].update(status='unavailable'),
                   lambda r: r.update(case='python-source-normalized')]
        for change in changes:
            _, _, cases, _ = fixture()
            mutate_case(cases, 'python-archive-full', receipt=change)
            self.assertEqual(summary(cases=cases)['status'], 'failed')

    def test_environment_must_match_original_inventory_and_route_kind_version_seed(self):
        for rebind in (False, True):
            for change in [lambda e: e.update(kind='ordinary-no-pip'),
                           lambda e: e.update(version=[3, 14]),
                           lambda e: e.update(pip_present=False)]:
                _, _, cases, _ = fixture()
                mutate_case(cases, 'python-archive-full', environment=change, rebind=rebind)
                self.assertEqual(summary(cases=cases)['status'], 'failed')
        _, _, cases, _ = fixture()
        mutate_case(cases, 'python-uv-source', environment=lambda e: e.update(pip_present=True), rebind=True)
        self.assertEqual(summary(cases=cases)['status'], 'failed')

    def test_archive_override_requires_both_original_and_consumed_pinned_bytes(self):
        for route in ('full', 'install-only', 'stripped'):
            label = 'python-archive-' + route
            for where in ('inventory', 'consumed', 'override'):
                _, _, cases, _ = fixture()
                if where == 'inventory':
                    mutate_case(cases, label, inventory=lambda i: i['runtime-input.tar'].update(sha256='0' * 64), rebind=True)
                elif where == 'consumed':
                    mutate_case(cases, label, receipt=lambda r: r['runtime']['inputs']['runtime-archive'].update(size=1))
                else:
                    mutate_case(cases, label, receipt=lambda r: r['commands']['build']['argv'].remove('--runtime'))
                self.assertEqual(summary(cases=cases)['status'], 'failed')

    def test_environment_receipt_command_is_bound_to_its_case_and_completed_preparation(self):
        for change in [lambda r: r['commands']['prepare'].update(exit=1),
                       lambda r: r['commands']['prepare'].update(cwd=None),
                       lambda r: r['commands']['prepare'].update(cwd=['not', 'a', 'path']),
                       lambda r: r['commands']['prepare']['argv'].__setitem__(4, 'uv'),
                       lambda r: r['commands']['prepare']['argv'].__setitem__(-1, '/tmp/other/environment-receipt.json'),
                       lambda r: r['commands']['prepare']['argv'].__setitem__(2, '/tmp/other inputs'),
                       lambda r: r['commands']['build'].update(timed_out=True)]:
            _, _, cases, _ = fixture()
            mutate_case(cases, 'python-archive-full', receipt=change)
            self.assertEqual(summary(cases=cases)['status'], 'failed')

    def test_uv_requires_explicit_hook_prune_and_unchanged_pbs_runtime_stdlib(self):
        for change in [lambda r: r['commands']['build']['argv'].remove('--prune'),
                       lambda r: r['runtime']['inputs']['runtime-executable'].update(sha256='0' * 64),
                       lambda r: r['runtime']['inputs'].pop('stdlib:encodings/__init__.py'),
                       lambda r: r['commands']['build']['argv'].extend(['--runtime', '/tmp/fake archive'])]:
            _, _, cases, _ = fixture()
            mutate_case(cases, 'python-uv-native', receipt=change)
            self.assertEqual(summary(cases=cases)['status'], 'failed')
        base = reference('x86_64'); base['status'] = 'failed'
        self.assertEqual(summary(base=encoded(base))['status'], 'failed')

    def test_build_must_consume_its_prepared_environment_without_option_aliases(self):
        for label in ('python-archive-full', 'python-uv-source'):
            for change in ('wrong', 'missing', 'duplicate', 'last-token', 'equals-form', 'other-project'):
                _, _, cases, _ = fixture()
                def mutation(receipt):
                    argv = receipt['commands']['build']['argv']
                    index = argv.index('--env')
                    if change == 'wrong':
                        argv[index + 1] = '/unrelated/ordinary-environment'
                    elif change == 'missing':
                        del argv[index:index + 2]
                    elif change == 'duplicate':
                        argv.extend(['--env', '/unrelated/environment'])
                    elif change == 'last-token':
                        del argv[index:index + 2]
                        argv.append('--env')
                    elif change == 'equals-form':
                        argv.append('--env=/unrelated/environment')
                    else:
                        argv[3] = '/unrelated/project'
                mutate_case(cases, label, receipt=mutation)
                result = summary(cases=cases)
                self.assertEqual(result['status'], 'failed', (label, change))
                self.assertIn('build does not consume', ' '.join(result['errors']))

    def test_named_entry_routes_require_exact_selector_and_value(self):
        for label, selector in [('python-archive-full', '--entry'),
                                ('python-uv-source', '--entry'),
                                ('python-uv-module', '--module'),
                                ('python-uv-console', '--console-script'),
                                ('python-uv-native', '--entry')]:
            for change in ('wrong-value', 'missing', 'duplicate', 'shifted-route', 'equals-alias'):
                _, _, cases, _ = fixture()
                def mutate(receipt):
                    argv = receipt['commands']['build']['argv']; index = argv.index(selector)
                    if change == 'wrong-value':
                        argv[index + 1] = 'unrelated'
                    elif change == 'missing':
                        del argv[index:index + 2]
                    elif change == 'duplicate':
                        argv.extend([selector, argv[index + 1]])
                    elif change == 'shifted-route':
                        argv[index:index + 2] = ['--module', 'main'] if selector != '--module' else ['--entry', 'main.py']
                    else:
                        argv.append('--module=main' if selector != '--module' else '--entry=main.py')
                mutate_case(cases, label, receipt=mutate)
                result = summary(cases=cases)
                self.assertEqual(result['status'], 'failed', (label, change))
                self.assertIn('entry selector', ' '.join(result['errors']))

    def test_native_preparation_is_exclusive_to_native_corpus(self):
        for label, change in [('python-uv-native', 'missing'), ('python-uv-native', 'duplicate'),
                              ('python-uv-source', 'extra'), ('python-archive-full', 'extra')]:
            _, _, cases, _ = fixture()
            def mutate(receipt):
                argv = receipt['commands']['prepare']['argv']
                if change == 'missing':
                    argv.remove('--native')
                else:
                    argv.append('--native')
            mutate_case(cases, label, receipt=mutate)
            result = summary(cases=cases)
            self.assertEqual(result['status'], 'failed')
            self.assertIn('native preparation', ' '.join(result['errors']))

    def test_missing_or_malformed_retained_metadata_fail_closed(self):
        _, _, cases, _ = fixture(); cases.pop('python-uv-source')
        self.assertEqual(summary(cases=cases)['status'], 'failed')
        for raw in (b'{"duplicate":0,"duplicate":1}', b'{"number":NaN}', b'{"number":1e999}', b'[]', b'\xff'):
            _, _, cases, _ = fixture(); old = cases['python-archive-full']
            cases['python-archive-full'] = C.CaseEvidence(raw, old.environment, old.inventory)
            self.assertEqual(summary(cases=cases)['status'], 'failed')

    def test_new_recipes_preserve_legacy_inputs_native_corpus_and_explicit_policies(self):
        for corpus in ('source', 'module', 'console', 'native'):
            original = json.loads((ROOT / ('fixtures/mvp/cases/python-uv-' + corpus + '.json')).read_text())
            updated = json.loads((ROOT / ('fixtures/mvp/cases/python-uv-' + corpus + '-normalized.json')).read_text())
            self.assertEqual(updated['inputs'], original['inputs'])
            self.assertEqual(updated['reference'], original['reference'])
            self.assertIn('--normalize-native-paths', updated['build']['argv'])
            self.assertIn('--native-search', updated['build']['argv'])
            self.assertEqual(updated['prepare']['argv'][-2:], ['--receipt-output', '{output}/environment-receipt.json'])
            self.assertIn('app/site/0/_virtualenv.pth', updated['build']['argv'])
        archive = json.loads((ROOT / 'fixtures/mvp/cases/python-archive-compatibility.json').read_text())
        self.assertEqual(archive['case'], 'python-archive-compatibility')
        self.assertIn('--runtime', archive['build']['argv'])

    def test_cli_tabs_and_real_retained_layout_summary(self):
        for command, fields, count in [('inputs', 5, 4), ('cells', 4, 7)]:
            output = io.StringIO()
            with redirect_stdout(output):
                self.assertEqual(C.main([command, '--architecture', 'aarch64']), 0)
            lines = output.getvalue().splitlines()
            self.assertEqual(len(lines), count)
            self.assertTrue(all(len(line.split('\t')) == fields for line in lines))
        manifest, rows, cases, base = fixture()
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            (root / 'compatibility-inputs.json').write_bytes(encoded(manifest))
            (root / 'compatibility-case-status.tsv').write_text(''.join(row['case'] + '\t0\n' for row in rows))
            reference_root = root / 'cases/python-3.13.16-source'; reference_root.mkdir(parents=True)
            (reference_root / 'receipt.json').write_bytes(base)
            for label, evidence in cases.items():
                case = root / 'cases' / label; case.mkdir(parents=True)
                for name, data in [('receipt.json', evidence.receipt), ('environment-receipt.json', evidence.environment), ('input-inventory.json', evidence.inventory)]:
                    (case / name).write_bytes(data)
            self.assertEqual(C.main(['summary', '--architecture', 'x86_64', '--evidence', str(root), '--result', '0']), 0)
            report = json.loads((root / 'compatibility-summary.json').read_text())
            self.assertEqual(report['status'], 'passed')
            (root / 'cases/python-uv-native/environment-receipt.json').unlink()
            self.assertEqual(C.main(['summary', '--architecture', 'x86_64', '--evidence', str(root), '--result', '0']), 1)
            report = json.loads((root / 'compatibility-summary.json').read_text())
            self.assertEqual(report['status'], 'failed')


if __name__ == '__main__':
    unittest.main()
