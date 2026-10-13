#!/usr/bin/env python3
"""Regression checks for the independent evidence oracle and process audit."""
import importlib.util
import json
from pathlib import Path
import sys
import tempfile
import unittest

sys.dont_write_bytecode = True
spec = importlib.util.spec_from_file_location('runtime_template_audit', Path(__file__).with_name('test_templates.py'))
audit = importlib.util.module_from_spec(spec)
spec.loader.exec_module(audit)


class IndependentOracleTests(unittest.TestCase):
    def test_exact_bundled_inventory_and_budgets(self):
        pins = audit.provider_specs('bundled')
        self.assertEqual(len(pins), 2178)
        self.assertEqual(sum(value['size'] for name, value in pins.items() if name.startswith('stdlib/')), 39158056)
        self.assertEqual(pins['python/frozen.json']['sha256'], audit.FROZEN_SHA)
        self.assertEqual(pins['python/libpython3.13.so.1.0']['sha256'], audit.LIBRARY_SHA)
        self.assertEqual(pins['python/frozen.json']['compression'], 'stored')
        self.assertTrue(all(value['compression'] == 'deflate' for name, value in pins.items() if name.startswith('stdlib/')))

    def test_host_contract_only_packages_two_helpers(self):
        self.assertEqual(audit.provider_specs('host-full'), audit.helper_specs())
        self.assertEqual(audit.provider_specs('host-install'), audit.helper_specs())
        runtime = audit.expected_runtime('host-full', '/unavailable/Python')
        self.assertEqual(runtime['provisioning']['runtime_library'], '/unavailable/Python/lib/libpython3.13.so.1.0')
        self.assertEqual(runtime['provisioning']['discovery'], 'explicit_paths')

    def test_json_oracle_rejects_duplicate_and_nonfinite_data(self):
        for payload in ('{"provider":1,"provider":2}', '{"size":NaN}', '{"size":Infinity}'):
            with self.assertRaises(ValueError):
                audit.strict_json(payload)

    def test_root_inventory_rejects_external_link(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary) / 'root'
            root.mkdir()
            external = Path(temporary) / 'external'
            external.write_bytes(b'outside')
            (root / 'resource').symlink_to(external)
            with self.assertRaisesRegex(ValueError, 'link/special'):
                audit.tree_files(root)

    def test_file_hash_oracle_enforces_bound_and_type(self):
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / 'bytes'
            path.write_bytes(b'payload')
            self.assertEqual(audit.file_identity(path, 7), audit.identity(b'payload'))
            with self.assertRaisesRegex(ValueError, 'bound'):
                audit.file_identity(path, 6)
            link = Path(temporary) / 'link'
            link.symlink_to(path)
            with self.assertRaisesRegex(ValueError, 'regular file'):
                audit.file_identity(link)


class ProcessTraceTests(unittest.TestCase):
    PROGRAM = '/build-target/glue'
    VALID = [
        '1234 execve("/build-target/glue", ["/build-target/glue", "python-template", "--provider", "host-full"], 0xffff /* 5 vars */) = 0\n',
        '1234 openat(AT_FDCWD, "/lib/aarch64-linux-gnu/libc.so.6", O_RDONLY|O_CLOEXEC) = 3\n',
        '1234 newfstatat(AT_FDCWD, "/evidence", {st_mode=S_IFDIR|0755}, 0) = 0\n',
        '1234 +++ exited with 0 +++\n',
    ]

    def check(self, lines, prefix='/unavailable/Python'):
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / 'process.trace.txt'
            path.write_text(''.join(lines), encoding='utf-8')
            return audit.audit_process_trace(path, self.PROGRAM, prefix)

    def test_one_builder_exec_without_provider_lookup_passes(self):
        report = self.check(self.VALID)
        self.assertEqual(report['execve_count'], 1)
        self.assertEqual(report['network_count'], 0)

    def test_child_creation_rejects(self):
        for syscall in ('clone', 'clone3', 'fork', 'vfork', 'execveat'):
            with self.subTest(syscall=syscall), self.assertRaisesRegex(ValueError, 'child creation/network'):
                self.check(self.VALID[:1] + ['1234 ' + syscall + '() = -1 EPERM\n'] + self.VALID[1:])

    def test_network_attempts_reject_even_if_failed(self):
        for syscall in ('socket', 'connect', 'sendto', 'recvmsg'):
            with self.subTest(syscall=syscall), self.assertRaisesRegex(ValueError, 'child creation/network'):
                self.check(self.VALID[:1] + ['1234 ' + syscall + '() = -1 EPERM\n'] + self.VALID[1:])

    def test_target_library_and_prefix_lookup_reject(self):
        for path in ('/unavailable/Python', '/unavailable/Python/lib/libpython3.13.so.1.0'):
            with self.subTest(path=path), self.assertRaisesRegex(ValueError, 'looked up target provider'):
                self.check(self.VALID[:1] + ['1234 openat(AT_FDCWD, ' + json.dumps(path) + ', O_RDONLY) = -1 ENOENT\n'] + self.VALID[1:])

    def test_other_path_under_common_ancestor_can_be_builder_output(self):
        report = self.check(self.VALID[:1] + [
            '1234 newfstatat(AT_FDCWD, "/build-target", {st_mode=S_IFDIR|0755}, 0) = 0\n',
            '1234 openat(AT_FDCWD, "/build-target/template/manifest.json", O_WRONLY) = 3\n'] + self.VALID[1:], '/build-target/host Python')
        self.assertEqual(report['target_provider_lookup_count'], 0)

    def test_additional_exec_or_different_program_reject(self):
        for lines in (self.VALID[:1] + self.VALID, [line.replace('/build-target/glue', '/usr/bin/python3') for line in self.VALID]):
            with self.assertRaises(ValueError):
                self.check(lines)

    def test_missing_process_boundaries_reject(self):
        for lines in ([], self.VALID[1:], self.VALID[:-1]):
            with self.assertRaises(ValueError):
                self.check(lines)

    def test_failed_exec_and_killed_builder_reject(self):
        for lines in ([self.VALID[0].replace('= 0', '= -1 ENOENT')], self.VALID[:1] + ['1234 +++ killed by SIGSEGV +++\n']):
            with self.assertRaises(ValueError):
                self.check(lines)


if __name__ == '__main__':
    unittest.main(verbosity=2)
