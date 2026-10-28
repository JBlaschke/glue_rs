#!/usr/bin/env python3
"""Portable conda input controls; never download, install or execute a runtime."""
from contextlib import ExitStack, redirect_stderr, redirect_stdout
from copy import deepcopy
import hashlib
import importlib.util
import io
import json
from pathlib import Path
from tempfile import TemporaryDirectory
from types import SimpleNamespace
import unittest
from unittest.mock import patch


HERE = Path(__file__).resolve().parent
spec = importlib.util.spec_from_file_location('provision_conda', HERE / 'provision-conda.py')
PROVISION = importlib.util.module_from_spec(spec)
spec.loader.exec_module(PROVISION)
X86 = 'x86_64-unknown-linux-gnu'
ARM = 'aarch64-unknown-linux-gnu'
LOCK_PATHS = {
    X86: HERE / 'conda-linux-x86_64-3.14.8.lock.json',
    ARM: HERE / 'conda-linux-aarch64-3.14.8.lock.json',
}
# Preserve the original reviewed x86 input file, including resolution metadata.
X86_LOCK_SHA256 = '6b5e2771379581b5010976ae9a47ce0b691a02932b529478b8eab2f615d4164c'


class ProvisionCondaTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.locks = {target: json.loads(path.read_text())
                     for target, path in LOCK_PATHS.items()}

    def test_both_complete_checked_in_profiles_validate_without_effects(self):
        with patch.object(PROVISION, 'fetch', side_effect=AssertionError('network')), \
                patch.object(PROVISION.subprocess, 'run', side_effect=AssertionError('process')):
            for target, lock in self.locks.items():
                with self.subTest(target=target):
                    before = deepcopy(lock)
                    packages = PROVISION.validate_lock(lock, target)
                    self.assertIs(packages, lock['packages'])
                    self.assertEqual(len(packages), 24)
                    self.assertEqual(lock, before)
                    self.assertEqual({p['name'] for p in packages}, PROVISION.PROFILES[target]['packages'])

    def test_original_x86_default_and_exact_inputs_are_unchanged(self):
        self.assertEqual(hashlib.sha256(LOCK_PATHS[X86].read_bytes()).hexdigest(), X86_LOCK_SHA256)
        self.assertIs(PROVISION.PROFILES[X86]['micromamba'], PROVISION.MICROMAMBA)
        self.assertIs(PROVISION.PROFILES[X86]['pins'], PROVISION.PINS)
        self.assertIs(PROVISION.validate_lock(self.locks[X86]), self.locks[X86]['packages'])
        self.assertEqual(PROVISION.MICROMAMBA, self.locks[X86]['micromamba'])
        self.assertEqual(PROVISION.PINS, self.locks[X86]['requested'])
        with self.assertRaises(ValueError):
            PROVISION.validate_lock(self.locks[ARM])

    def test_profiles_are_closed_and_default_selection_matches_native_host(self):
        self.assertEqual(set(PROVISION.PROFILES), {X86, ARM})
        for target, machine, subdir in ((X86, 'x86_64', 'linux-64'), (ARM, 'aarch64', 'linux-aarch64')):
            with self.subTest(target=target), patch.object(PROVISION.platform, 'system', return_value='Linux'), \
                    patch.object(PROVISION.platform, 'machine', return_value=machine):
                selected = PROVISION.native_profile()
                self.assertIs(selected, PROVISION.PROFILES[target])
                self.assertIs(PROVISION.native_profile(target), selected)
                self.assertEqual(selected['platform'], subdir)
                self.assertIn('/' + subdir + '/', selected['micromamba']['url'])
        for target in ('linux-aarch64', 'aarch64-unknown-linux-musl', '', None, {}, []):
            with self.subTest(target=target), self.assertRaises(ValueError):
                PROVISION.target_profile(target)

    def test_native_guard_precedes_every_provisioning_filesystem_network_and_process_effect(self):
        cases = [('Darwin', 'arm64', None), ('Windows', 'AMD64', X86),
                 ('Linux', 'riscv64', None), ('Linux', 'arm64', ARM),
                 ('Linux', 'aarch64', X86), ('Linux', 'x86_64', ARM)]
        for system, machine, target in cases:
            with self.subTest(system=system, machine=machine, target=target), ExitStack() as stack:
                stack.enter_context(patch.object(PROVISION.platform, 'system', return_value=system))
                stack.enter_context(patch.object(PROVISION.platform, 'machine', return_value=machine))
                sentinels = [stack.enter_context(patch.object(Path, name, side_effect=AssertionError(name)))
                             for name in ('read_text', 'exists', 'is_symlink', 'absolute', 'mkdir')]
                sentinels += [stack.enter_context(patch.object(PROVISION, 'fetch', side_effect=AssertionError('fetch'))),
                              stack.enter_context(patch.object(PROVISION.subprocess, 'run', side_effect=AssertionError('run'))),
                              stack.enter_context(patch.object(PROVISION.tarfile, 'open', side_effect=AssertionError('archive')))]
                argv = ['--work', 'work', '--output', 'output', '--evidence', 'evidence', '--lock', 'input.json']
                if target is not None:
                    argv += ['--target', target]
                with self.assertRaises(ValueError):
                    PROVISION.main(argv)
                for sentinel in sentinels:
                    sentinel.assert_not_called()

    def test_lock_target_tool_and_requested_identity_are_exact(self):
        for target, original in self.locks.items():
            other = ARM if target == X86 else X86
            mutations = [
                ('platform', self.locks[other]['platform']),
                ('micromamba', self.locks[other]['micromamba']),
                ('requested', self.locks[other]['requested']),
                ('schema', True), ('schema', '1'), ('requested', {}),
            ]
            tool = deepcopy(original['micromamba'])
            tool['sha256'] = '0' * 64
            mutations.append(('micromamba', tool))
            for field, value in mutations:
                with self.subTest(target=target, field=field, value=value), self.assertRaises(ValueError):
                    lock = deepcopy(original)
                    lock[field] = value
                    PROVISION.validate_lock(lock, target)

    def test_missing_duplicate_and_replaced_transitive_packages_refuse(self):
        for target, original in self.locks.items():
            removed = deepcopy(original)
            removed['packages'].pop(next(i for i, p in enumerate(removed['packages']) if p['name'] == 'bzip2'))
            duplicate = deepcopy(original)
            duplicate['packages'][0] = deepcopy(duplicate['packages'][1])
            replaced = deepcopy(original)
            package = next(p for p in replaced['packages'] if p['name'] == 'bzip2')
            package['name'] = 'unreviewed'
            package['filename'] = package['filename'].replace('bzip2-', 'unreviewed-')
            package['url'] = package['url'].replace('/bzip2-', '/unreviewed-')
            for lock in (removed, duplicate, replaced):
                with self.subTest(target=target), self.assertRaises(ValueError):
                    PROVISION.validate_lock(lock, target)

    def test_each_selected_pin_rejects_version_build_or_hash_mutation(self):
        for target, original in self.locks.items():
            for name in ('python', 'libffi', 'libstdcxx'):
                for field, value in (('version', '0'), ('build', 'different'), ('sha256', '0' * 64)):
                    with self.subTest(target=target, name=name, field=field), self.assertRaises(ValueError):
                        lock = deepcopy(original)
                        package = next(p for p in lock['packages'] if p['name'] == name)
                        package[field] = value
                        if field != 'sha256':
                            old_filename = package['filename']
                            package['filename'] = '-'.join(package[k] for k in ('name', 'version', 'build')) + '.conda'
                            package['url'] = package['url'].replace(old_filename, package['filename'])
                        PROVISION.validate_lock(lock, target)

    def test_package_urls_are_fixed_channel_https_and_exact_native_subdir(self):
        for target, original in self.locks.items():
            package = next(p for p in original['packages'] if p['name'] == 'python')
            native = PROVISION.PROFILES[target]['platform']
            other = PROVISION.PROFILES[ARM if target == X86 else X86]['platform']
            urls = [package['url'].replace('https:', 'http:'),
                    package['url'].replace('conda.anaconda.org', 'example.invalid'),
                    package['url'].replace('/conda-forge/', '/other/'),
                    package['url'].replace('/' + native + '/', '/' + other + '/'),
                    package['url'].replace('/' + native + '/', '/noarch/'),
                    package['url'] + '?download=1', package['url'] + '#fragment',
                    package['url'].replace('https://', 'https://caller@')]
            for url in urls:
                with self.subTest(target=target, url=url), self.assertRaises(ValueError):
                    lock = deepcopy(original)
                    next(p for p in lock['packages'] if p['name'] == 'python')['url'] = url
                    PROVISION.validate_lock(lock, target)
            lock = deepcopy(original)
            package = next(p for p in lock['packages'] if p['name'] == 'pip')
            package['url'] = package['url'].replace('/noarch/', '/' + native + '/')
            with self.assertRaises(ValueError):
                PROVISION.validate_lock(lock, target)

    def test_malformed_lock_and_package_shapes_refuse(self):
        for invalid in (None, [], 'lock', {}, {'schema': 1}):
            with self.subTest(lock=invalid), self.assertRaises(ValueError):
                PROVISION.validate_lock(invalid)
        for target, original in self.locks.items():
            for packages in (None, {}, 'packages', [None] * 24):
                with self.subTest(target=target, packages=packages), self.assertRaises(ValueError):
                    lock = deepcopy(original)
                    lock['packages'] = packages
                    PROVISION.validate_lock(lock, target)
            for field in ('name', 'version', 'build', 'filename', 'url', 'sha256', 'md5'):
                for value in (None, 1, '', []):
                    with self.subTest(target=target, field=field, value=value), self.assertRaises(ValueError):
                        lock = deepcopy(original)
                        lock['packages'][0][field] = value
                        PROVISION.validate_lock(lock, target)

    def test_package_digest_and_filename_tampering_refuse(self):
        for target, original in self.locks.items():
            for field, value in (('sha256', 'A' * 64), ('sha256', '0' * 63),
                                 ('md5', '0' * 31), ('md5', 'g' * 32),
                                 ('filename', '../outside.conda'), ('filename', 'other.conda')):
                with self.subTest(target=target, field=field, value=value), self.assertRaises(ValueError):
                    lock = deepcopy(original)
                    lock['packages'][0][field] = value
                    PROVISION.validate_lock(lock, target)

    def test_bad_replay_lock_refuses_before_destinations_downloads_or_tool_launch(self):
        for target, original in self.locks.items():
            mutations = []
            incomplete = deepcopy(original)
            incomplete['packages'].pop()
            mutations.append(incomplete)
            wrong_tool = deepcopy(original)
            wrong_tool['micromamba']['sha256'] = '0' * 64
            mutations.append(wrong_tool)
            for lock in mutations:
                with self.subTest(target=target), ExitStack() as stack:
                    stack.enter_context(patch.object(PROVISION.platform, 'system', return_value='Linux'))
                    stack.enter_context(patch.object(PROVISION.platform, 'machine', return_value=PROVISION.PROFILES[target]['machine']))
                    stack.enter_context(patch.object(Path, 'read_text', return_value=json.dumps(lock)))
                    sentinels = [stack.enter_context(patch.object(Path, name, side_effect=AssertionError(name)))
                                 for name in ('exists', 'is_symlink', 'absolute', 'mkdir')]
                    sentinels += [stack.enter_context(patch.object(PROVISION, 'fetch', side_effect=AssertionError('fetch'))),
                                  stack.enter_context(patch.object(PROVISION.subprocess, 'run', side_effect=AssertionError('run')))]
                    with self.assertRaises(ValueError):
                        PROVISION.main(['--work', 'work', '--output', 'output', '--evidence', 'evidence',
                                        '--lock', 'input.json', '--target', target])
                    for sentinel in sentinels:
                        sentinel.assert_not_called()

    def test_cli_has_no_channel_url_or_expected_hash_override(self):
        for extra in (['--target', 'riscv64-unknown-linux-gnu'], ['--channel', 'other'],
                      ['--url', 'https://example.invalid'], ['--sha256', '0' * 64]):
            with self.subTest(extra=extra), redirect_stderr(io.StringIO()), \
                    patch.object(PROVISION, 'native_profile', side_effect=AssertionError('native selection')) as native:
                with self.assertRaises(SystemExit) as stopped:
                    PROVISION.main(['--work', 'work', '--output', 'output', '--evidence', 'evidence'] + extra)
                self.assertEqual(stopped.exception.code, 2)
                native.assert_not_called()

    def test_native_orchestration_binds_tool_resolution_offline_install_and_receipt(self):
        # Only synthetic files and mocked tool calls are used. This covers both
        # resolution and replay without provisioning or executing native inputs.
        for target, lock in self.locks.items():
            for replay in (False, True):
                with self.subTest(target=target, replay=replay), TemporaryDirectory() as temporary, ExitStack() as stack:
                    root = Path(temporary)
                    work, output, evidence = (root / name for name in ('work', 'output', 'evidence'))
                    profile = PROVISION.PROFILES[target]
                    stack.enter_context(patch.object(PROVISION.platform, 'system', return_value='Linux'))
                    stack.enter_context(patch.object(PROVISION.platform, 'machine', return_value=profile['machine']))

                    def download(url, destination, expected, maximum=256 * 1024 * 1024):
                        destination.write_bytes(b'synthetic download; never executable upstream content')

                    fetch = stack.enter_context(patch.object(PROVISION, 'fetch', side_effect=download))
                    bundle = SimpleNamespace(
                        getmember=lambda name: SimpleNamespace(isfile=lambda: True, size=24),
                        extractfile=lambda member: io.BytesIO(b'synthetic non-executable tool'))
                    opened = stack.enter_context(patch.object(PROVISION.tarfile, 'open'))
                    opened.return_value.__enter__.return_value = bundle
                    transaction = {'success': True, 'actions': {'LINK': [
                        {key: package[source] for key, source in {
                            'name': 'name', 'version': 'version', 'build_string': 'build',
                            'fn': 'filename', 'url': 'url', 'sha256': 'sha256', 'md5': 'md5'}.items()}
                        for package in lock['packages']]}}

                    def tool_result(argv, **kwargs):
                        if str(HERE / 'stage-runtime.py') in argv:
                            (root / 'output-stage.json').write_text('{"synthetic":true}\n')
                        stdout = json.dumps(transaction).encode() if '--dry-run' in argv else b'{}\n'
                        return SimpleNamespace(stdout=stdout, stderr=b'', check_returncode=lambda: None)

                    run = stack.enter_context(patch.object(PROVISION.subprocess, 'run', side_effect=tool_result))
                    stack.enter_context(redirect_stdout(io.StringIO()))
                    argv = ['--work', str(work), '--output', str(output), '--evidence', str(evidence)]
                    if replay:
                        argv += ['--lock', str(LOCK_PATHS[target])]
                    # Deliberately omit --target: main must select this host.
                    PROVISION.main(argv)
                    self.assertEqual(fetch.call_args_list[0].args,
                                     (profile['micromamba']['url'], work / 'micromamba.tar.bz2',
                                      profile['micromamba']['sha256'], 16 * 1024 * 1024))
                    self.assertEqual(len(fetch.call_args_list), 25)
                    retained_lock = json.loads((evidence / 'explicit-lock.json').read_text())
                    self.assertEqual(retained_lock['packages'], lock['packages'])
                    commands = [call.args[0] for call in run.call_args_list]
                    resolve = [command for command in commands if '--dry-run' in command]
                    self.assertEqual(len(resolve), 0 if replay else 1)
                    if resolve:
                        self.assertEqual(resolve[0][resolve[0].index('--platform') + 1], profile['platform'])
                        self.assertEqual(resolve[0][-3:], [name + '=' + pin['version'] + '=' + pin['build']
                                                         for name, pin in profile['pins'].items()])
                        self.assertEqual(resolve[0][resolve[0].index('--channel') + 1], PROVISION.CHANNEL)
                    install = [command for command in commands if '--offline' in command]
                    self.assertEqual(len(install), 1)
                    explicit = (work / 'local-explicit.txt').read_text().splitlines()
                    self.assertEqual(explicit[0], '@EXPLICIT')
                    self.assertEqual(len(explicit), 25)
                    self.assertTrue(all(line.startswith((work / 'packages').as_uri() + '/') for line in explicit[1:]))
                    receipt = json.loads((evidence / 'provisioning.json').read_text())
                    self.assertEqual(receipt['platform'], profile['platform'])
                    self.assertEqual(receipt['target'], target)
                    self.assertEqual(receipt['host_machine'], profile['machine'])
                    self.assertEqual(receipt['package_count'], 24)
                    self.assertFalse(receipt['native_images_recompiled'])
                    self.assertFalse(receipt['product_execution_checked'])


if __name__ == '__main__':
    unittest.main()
