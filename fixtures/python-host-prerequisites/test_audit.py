#!/usr/bin/env python3
"""Host prerequisite oracle regression tests using independent tiny observations."""
import importlib.util
import json
import os
from pathlib import Path
import sys
import subprocess
import tempfile
import unittest
from unittest.mock import patch

sys.dont_write_bytecode = True
spec = importlib.util.spec_from_file_location('host_prerequisite_audit', Path(__file__).with_name('test_prepare.py'))
audit = importlib.util.module_from_spec(spec)
spec.loader.exec_module(audit)


class IndependentPinTests(unittest.TestCase):
    def test_exact_full_projection_is_library_and_all_sources(self):
        files, provenance = audit.expected_contract('host-full')
        self.assertEqual(len(files), 2175)
        self.assertEqual(sum(value['size'] for value in files.values()), 112722024)
        self.assertEqual(files['lib/libpython3.13.so.1.0']['sha256'], audit.LIBRARY_SHA)
        self.assertEqual(provenance['omitted_files'], 3350)
        self.assertEqual(provenance['omitted_bytes'], 282397147)
        self.assertIsNone(provenance['cache_inventory'])
        self.assertFalse(provenance['full_install_pairing_observed'])
        self.assertFalse(provenance['runtime_execution_observed'])
        self.assertFalse(provenance['is_complete_python_installation'])
        self.assertTrue(all(name == 'lib/libpython3.13.so.1.0' or name.endswith('.py') for name in files))

    def test_install_projection_has_exactly_three_stock_caches(self):
        files, provenance = audit.expected_contract('host-install')
        self.assertEqual(len(files), 1041)
        self.assertEqual(sum(value['size'] for value in files.values()), 89479393)
        self.assertEqual(provenance['omitted_files'], 2437)
        self.assertEqual(provenance['omitted_bytes'], 92676546)
        caches = {name for name in files if name.endswith('.pyc')}
        self.assertEqual(caches, {'lib/python3.13/encodings/__pycache__/' + name + '.cpython-313.pyc'
                                 for name in ('__init__', 'aliases', 'utf_8')})
        self.assertEqual(sum(files[name]['size'] for name in caches), 21157)
        self.assertEqual(provenance['artifact_entries'], 4526)

    def test_directory_inventory_includes_prefix_and_only_payload_ancestors(self):
        self.assertEqual(audit.expected_directories({'lib/a': {}, 'lib/python/x': {}, 'lib/python/sub/y': {}}),
                         {'.', 'lib', 'lib/python', 'lib/python/sub'})
        for provider in audit.PROVIDERS:
            files, _ = audit.expected_contract(provider)
            directories = audit.expected_directories(files)
            self.assertGreater(len(directories), 20)
            self.assertLess(len(directories), 256)
            self.assertNotIn('bin', directories)
            self.assertNotIn('include', directories)

    def test_json_rejects_duplicate_and_nonfinite_data(self):
        for payload in ('{"files":1,"files":2}', '{"size":NaN}', '{"size":Infinity}'):
            with self.subTest(payload=payload), self.assertRaises(ValueError):
                audit.strict_json(payload)

    def test_json_equality_keeps_schema_booleans_and_numbers_distinct(self):
        self.assertFalse(audit.same_json({'schema_version': False}, {'schema_version': 0}))
        self.assertFalse(audit.same_json({'observed': 0}, {'observed': False}))
        self.assertTrue(audit.same_json({'a': 1, 'b': False}, {'b': False, 'a': 1}))

    def test_file_identity_rejects_links_and_size_growth_bound(self):
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / 'payload'
            path.write_bytes(b'payload')
            self.assertEqual(audit.file_identity(path, 7), audit.identity(b'payload'))
            with self.assertRaisesRegex(ValueError, 'bound'):
                audit.file_identity(path, 6)
            link = Path(temporary) / 'link'
            link.symlink_to(path)
            with self.assertRaisesRegex(ValueError, 'regular file'):
                audit.file_identity(link)


class TreeObservationTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary.name) / 'new-prefix'
        self.root.mkdir()
        self.payloads = {'lib/libpython3.13.so.1.0': b'library', 'lib/python3.13/codecs.py': b'# independent fixture\n'}
        self.files = {name: audit.identity(payload) for name, payload in self.payloads.items()}
        self.provenance = {'schema_version': 0, 'provider': 'host-full', 'files': self.files, 'runtime_execution_observed': False}
        provenance_bytes = (json.dumps(self.provenance, sort_keys=True, separators=(',', ':')) + '\n').encode()
        for name, payload in self.payloads.items():
            path = self.root / name
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_bytes(payload)
        (self.root / 'provenance.json').write_bytes(provenance_bytes)
        for path in self.root.rglob('*'):
            if path.is_file():
                os.utime(path, ns=(audit.MTIME * 1000000000,) * 2)
                path.chmod(audit.FILE_MODE)
        for path in self.root.rglob('*'):
            if path.is_dir():
                path.chmod(audit.DIRECTORY_MODE)
                os.utime(path, ns=(audit.MTIME * 1000000000,) * 2)
        self.root.chmod(audit.DIRECTORY_MODE)
        os.utime(self.root, ns=(audit.MTIME * 1000000000,) * 2)
        self.report = {'provider': 'host-full', 'prefix': str(self.root), 'provenance': self.provenance,
                       'provenance_file': {'path': 'provenance.json'} | audit.identity(provenance_bytes),
                       'files': self.files, 'file_count': 2, 'payload_bytes': sum(map(len, self.payloads.values())),
                       'directory_count': 3, 'file_mode': audit.FILE_MODE, 'directory_mode': audit.DIRECTORY_MODE,
                       'mtime_seconds': audit.MTIME}
        self.patch = patch.object(audit, 'expected_contract', return_value=(self.files, self.provenance))
        self.patch.start()

    def tearDown(self):
        self.patch.stop()
        for path in [self.root, *self.root.rglob('*')]:
            if path.is_dir() and not path.is_symlink():
                path.chmod(0o700)
            elif path.is_file() and not path.is_symlink():
                path.chmod(0o600)
        self.temporary.cleanup()

    def check(self):
        return audit.audit_tree(self.root, 'host-full', self.report)

    def test_independent_bytes_permissions_and_times_pass(self):
        report = self.check()
        self.assertTrue(report['all_file_bytes_modes_times_verified'])
        self.assertTrue(report['all_directory_modes_times_verified'])

    def test_same_size_corruption_rejects(self):
        path = self.root / 'lib/libpython3.13.so.1.0'
        path.chmod(0o600)
        path.write_bytes(b'Library')
        path.chmod(audit.FILE_MODE)
        os.utime(path, ns=(audit.MTIME * 1000000000,) * 2)
        with self.assertRaisesRegex(ValueError, 'payload identity'):
            self.check()

    def test_wrong_file_mode_and_time_reject(self):
        path = self.root / 'lib/python3.13/codecs.py'
        path.chmod(0o644)
        with self.assertRaisesRegex(ValueError, 'file mode'):
            self.check()
        path.chmod(audit.FILE_MODE)
        os.utime(path, ns=((audit.MTIME + 1) * 1000000000,) * 2)
        with self.assertRaisesRegex(ValueError, 'file mtime'):
            self.check()

    def test_wrong_directory_mode_rejects(self):
        (self.root / 'lib').chmod(0o755)
        with self.assertRaisesRegex(ValueError, 'directory mode'):
            self.check()

    def test_wrong_directory_mtime_rejects(self):
        for path in (self.root, self.root / 'lib/python3.13'):
            with self.subTest(path=path):
                os.utime(path, ns=((audit.MTIME + 1) * 1000000000,) * 2)
                with self.assertRaisesRegex(ValueError, 'directory mtime'):
                    self.check()
                os.utime(path, ns=(audit.MTIME * 1000000000,) * 2)

    def test_extra_or_missing_file_rejects(self):
        self.root.chmod(0o700)
        (self.root / 'unexpected.py').write_bytes(b'extra')
        with self.assertRaisesRegex(ValueError, 'file inventory'):
            self.check()
        (self.root / 'unexpected.py').unlink()
        (self.root / 'lib').chmod(0o700)
        (self.root / 'lib/libpython3.13.so.1.0').unlink()
        with self.assertRaisesRegex(ValueError, 'file inventory'):
            self.check()

    def test_extra_empty_directory_rejects(self):
        self.root.chmod(0o700)
        (self.root / 'unexpected').mkdir()
        with self.assertRaisesRegex(ValueError, 'directory inventory'):
            self.check()

    def test_symlink_or_fifo_rejects_without_following(self):
        self.root.chmod(0o700)
        (self.root / 'link').symlink_to('/outside')
        with self.assertRaisesRegex(ValueError, 'link/special'):
            self.check()
        (self.root / 'link').unlink()
        os.mkfifo(self.root / 'fifo')
        with self.assertRaisesRegex(ValueError, 'link/special'):
            self.check()
        (self.root / 'fifo').unlink()

    def test_report_cannot_attest_a_false_payload_identity(self):
        self.report = self.report | {'payload_bytes': self.report['payload_bytes'] + 1}
        with self.assertRaisesRegex(ValueError, 'stdout report'):
            self.check()

    def test_cleanup_refuses_external_links(self):
        self.root.chmod(0o700)
        external = Path(self.temporary.name) / 'external'
        external.write_bytes(b'unchanged')
        (self.root / 'link').symlink_to(external)
        with self.assertRaisesRegex(ValueError, 'link/special'):
            audit.remove_owned_tree(self.root)
        self.assertEqual(external.read_bytes(), b'unchanged')


class HarnessFreshOutputTests(unittest.TestCase):
    def assert_guard(self, protected_side, kind):
        # Stub every post-guard external helper so a regression cannot provision
        # a producer, rewrite vendoring, launch containers or mutate a partner.
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            evidence, build = root / 'evidence', root / 'build'
            protected = evidence if protected_side == 'evidence' else build
            partner = build if protected_side == 'evidence' else evidence
            target = root / 'protected-target'
            if kind == 'file':
                protected.write_bytes(b'untouched existing output\n')
            elif kind == 'directory':
                protected.mkdir()
                (protected / 'sentinel').write_bytes(b'untouched existing output\n')
                (protected / 'nested').mkdir()
                (protected / 'nested/data').write_bytes(b'untouched nested data\n')
            else:
                if kind == 'symlink':
                    target.mkdir()
                    (target / 'sentinel').write_bytes(b'untouched external target\n')
                protected.symlink_to(target, target_is_directory=True)
            tools = root / 'helpers'
            tools.mkdir()
            log = root / 'helper-invocations.txt'
            for name in ('mkdir', 'rustup', 'python3', 'cargo', 'git', 'podman'):
                tool = tools / name
                tool.write_text("#!/bin/sh\nprintf '%s\\n' \"$0\" >> \"$GUARD_TOOL_LOG\"\nexit 97\n")
                tool.chmod(0o700)

            def snapshot():
                result = {}
                for path in [protected, *protected.rglob('*')] if not protected.is_symlink() else [protected]:
                    metadata = path.lstat()
                    relative = str(path.relative_to(root))
                    if path.is_symlink():
                        content = ('symlink', os.readlink(path))
                    elif path.is_file():
                        content = ('file', path.read_bytes())
                    else:
                        content = ('directory', sorted(p.name for p in path.iterdir()))
                    result[relative] = (metadata.st_mode, metadata.st_mtime_ns, content)
                if target.exists():
                    result['protected-target/sentinel'] = (target / 'sentinel').read_bytes()
                    result['protected-target/inventory'] = sorted(p.name for p in target.iterdir())
                return result

            before = snapshot()
            env = os.environ | {'PATH': str(tools) + os.pathsep + os.environ.get('PATH', ''),
                                'GUARD_TOOL_LOG': str(log)}
            outcome = subprocess.run(['/bin/sh', str(Path(__file__).with_name('run-linux.sh')),
                                      '--allow-development', str(evidence), str(build)],
                                     capture_output=True, check=False, env=env, timeout=10)
            self.assertNotEqual(outcome.returncode, 0)
            self.assertEqual(snapshot(), before)
            self.assertFalse(partner.exists())
            self.assertFalse(partner.is_symlink())
            self.assertFalse(log.exists(), 'a helper ran before fresh output protection rejected')

    def test_existing_evidence_paths_reject_before_creating_build_partner(self):
        for kind in ('file', 'directory', 'symlink', 'dangling-symlink'):
            with self.subTest(kind=kind):
                self.assert_guard('evidence', kind)

    def test_existing_build_paths_reject_before_creating_evidence_partner(self):
        for kind in ('file', 'directory', 'symlink', 'dangling-symlink'):
            with self.subTest(kind=kind):
                self.assert_guard('build', kind)


class ProcessTraceTests(unittest.TestCase):
    PROGRAM = '/build-target/glue'
    PREFIX = '/build-target/host Python metadata'
    LIBRARY = PREFIX + '/lib/libpython3.13.so.1.0'
    VALID = [
        '1234 execve("/build-target/glue", ["/build-target/glue", "python-host", "--provider", "host-full", "--pbs-full", "/input/full.tar.zst", "--output", "/build-target/host Python metadata", "--json"], 0xffff /* 5 vars */) = 0\n',
        '1234 openat(AT_FDCWD</builder>, "/lib/aarch64-linux-gnu/libc.so.6", O_RDONLY|O_CLOEXEC) = 3</lib/aarch64-linux-gnu/libc.so.6>\n',
        '1234 mmap(NULL, 4096, PROT_READ, MAP_PRIVATE, 3</lib/aarch64-linux-gnu/libc.so.6>, 0) = 0xffff\n',
        '1234 +++ exited with 0 +++\n',
    ]

    def check(self, lines):
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / 'all.trace.txt'
            path.write_text(''.join(lines), encoding='utf-8')
            return audit.audit_process_trace(path, self.PROGRAM)

    def test_builder_exec_and_ordinary_system_loader_pass(self):
        result = self.check(self.VALID)
        self.assertEqual(result['execve_count'], 1)
        self.assertEqual(result['runtime_acquisition_count'], 0)
        self.assertEqual(result['prefix'], self.PREFIX)

    def test_exclusive_library_publication_and_metadata_pass(self):
        calls = [
            'openat(AT_FDCWD</builder>, "' + self.LIBRARY + '", O_WRONLY|O_CREAT|O_EXCL|O_CLOEXEC, 0666) = 4<' + self.LIBRARY + '>',
            'write(4<' + self.LIBRARY + '>, "\\377\\0binary", 9) = 9',
            'fchmod(4<' + self.LIBRARY + '>, 0444) = 0',
            'utimensat(AT_FDCWD</builder>, "' + self.LIBRARY + '", [{tv_sec=1704067200, tv_nsec=0}, {tv_sec=1704067200, tv_nsec=0}], 0) = 0',
            'newfstatat(AT_FDCWD</builder>, "' + self.LIBRARY + '", {}, 0) = 0',
            'close(4<' + self.LIBRARY + '>) = 0',
        ]
        self.check(self.VALID[:1] + ['1234 ' + call + '\n' for call in calls] + self.VALID[1:])

    def test_binary_payload_nul_and_fake_descriptor_annotations_are_data(self):
        calls = [
            r'read(3</input/full.tar.zst>, "binary\0data4</foreign/libpython3.13.so.1.0>AT_FDCWD</invalid\0path>", 100) = 100',
            r'write(1</evidence/stdout.txt>, "data4</foreign/bin/python3.13>\0tail", 42) = 42',
        ]
        self.check(self.VALID[:1] + ['1234 ' + call + '\n' for call in calls] + self.VALID[1:])

    def test_owned_stdlib_directory_publication_is_not_interpreter_acquisition(self):
        directory = self.PREFIX + '/lib/python3.13'
        calls = [
            'mkdirat(AT_FDCWD</builder>, ' + json.dumps(directory) + ', 0777) = 0',
            'openat(AT_FDCWD</builder>, ' + json.dumps(directory) + ', O_RDONLY|O_CLOEXEC) = 4<' + directory + '>',
            'fchmod(4<' + directory + '>, 0555) = 0',
            'close(4<' + directory + '>) = 0',
        ]
        self.check(self.VALID[:1] + ['1234 ' + call + '\n' for call in calls] + self.VALID[1:])
        with self.assertRaisesRegex(ValueError, 'owned-directory'):
            self.check(self.VALID[:1] + ['1234 ' + calls[1] + '\n'] + self.VALID[1:])
        with self.assertRaisesRegex(ValueError, 'acquired Python interpreter'):
            self.check(self.VALID[:1] + ['1234 ' + call + '\n' for call in calls[:2]] + ['1234 read(4<' + directory + '>, \"\", 1) = -1 EISDIR\n'] + self.VALID[1:])

    def test_failed_and_successful_child_network_or_memfd_attempts_reject(self):
        for syscall in ('clone', 'clone3', 'fork', 'vfork', 'execveat', 'socket', 'connect', 'recvmsg', 'sendmmsg', 'getsockopt', 'memfd_create', 'socketcall', 'io_uring_setup', 'io_uring_enter', 'io_uring_register'):
            with self.subTest(syscall=syscall), self.assertRaisesRegex(ValueError, 'child creation/network/acquisition'):
                self.check(self.VALID[:1] + ['1234 ' + syscall + '() = -1 EPERM\n'] + self.VALID[1:])

    def test_target_library_read_and_mapping_reject_even_if_failed(self):
        for call in (
                'openat(AT_FDCWD, "' + self.LIBRARY + '", O_RDONLY) = -1 EPERM',
                'read(4<' + self.LIBRARY + '>, "", 1) = -1 EBADF',
                'pread64(4<' + self.LIBRARY + '>, "", 1, 0) = 0',
                'mmap(NULL, 4096, PROT_READ, MAP_PRIVATE, 4<' + self.LIBRARY + '>, 0) = -1 EPERM',
                'dup(4<' + self.LIBRARY + '>) = -1 EPERM'):
            with self.subTest(call=call), self.assertRaises(ValueError):
                self.check(self.VALID[:1] + ['1234 ' + call + '\n'] + self.VALID[1:])

    def test_omitted_descriptor_annotation_cannot_hide_later_acquisition(self):
        opened = '1234 openat(AT_FDCWD</builder>, ' + json.dumps(self.LIBRARY) + ', O_WRONLY|O_CREAT|O_EXCL|O_CLOEXEC, 0666) = 4<' + self.LIBRARY + '>\n'
        for call in ('read(4, \"\", 1) = -1 EBADF', 'mmap(NULL, 4096, PROT_READ, MAP_PRIVATE, 4, 0) = -1 EPERM', 'dup(4) = -1 EPERM', 'fcntl(4, F_DUPFD, 5) = -1 EPERM'):
            with self.subTest(call=call), self.assertRaisesRegex(ValueError, 'acquired/read/mapped'):
                self.check(self.VALID[:1] + [opened, '1234 ' + call + '\n'] + self.VALID[1:])
        self.check(self.VALID[:1] + [opened, '1234 fstat(4, {}) = 0\n', '1234 write(4, \"x\", 1) = 1\n', '1234 close(4) = 0\n', '1234 read(4, \"\", 1) = -1 EBADF\n'] + self.VALID[1:])

    def test_unowned_library_descriptor_metadata_rejects(self):
        with self.assertRaisesRegex(ValueError, 'foreign Python library'):
            self.check(self.VALID[:1] + ['1234 fstat(4</elsewhere/libpython3.13.so.1.0>, {}) = 0\n'] + self.VALID[1:])

    def test_library_alias_foreign_path_or_nonexclusive_publication_rejects(self):
        for path, flags in (
                ('/foreign/libpython3.13.so.1.0', 'O_WRONLY|O_CREAT|O_EXCL|O_CLOEXEC'),
                (self.LIBRARY, 'O_WRONLY|O_CREAT|O_CLOEXEC'),
                (self.LIBRARY, 'O_RDWR|O_CREAT|O_EXCL|O_CLOEXEC'),
                (self.LIBRARY, 'O_RDONLY|O_CLOEXEC')):
            with self.subTest(path=path, flags=flags), self.assertRaises(ValueError):
                self.check(self.VALID[:1] + ['1234 openat(AT_FDCWD, ' + json.dumps(path) + ', ' + flags + ') = 4\n'] + self.VALID[1:])

    def test_interpreter_lookup_rejects(self):
        for call in ('access("/prefix/bin/python3.13", X_OK) = 0', 'fstat(3</prefix/bin/python3.13>, {}) = 0', 'openat(AT_FDCWD, "python", O_RDONLY) = -1 ENOENT'):
            with self.subTest(call=call), self.assertRaisesRegex(ValueError, 'target Python interpreter'):
                self.check(self.VALID[:1] + ['1234 ' + call + '\n'] + self.VALID[1:])

    def test_common_parent_and_stdlib_source_observation_are_allowed(self):
        self.check(self.VALID[:1] + [
            '1234 statx(AT_FDCWD</builder>, "/build-target", 0, 0, {}) = 0\n',
            '1234 openat(AT_FDCWD</builder>, "/build-target/host Python metadata/lib/python3.13/codecs.py", O_WRONLY|O_CREAT|O_EXCL|O_CLOEXEC, 0666) = 4\n',
        ] + self.VALID[1:])

    def test_escaped_and_relative_library_paths_cannot_hide_acquisition(self):
        for call in (
                'openat(AT_FDCWD, "/build-target/host Python metadata/lib/\\154ibpython3.13.so.1.0", O_RDONLY) = 3',
                'openat(3</build-target/host Python metadata/lib>, "libpython3.13.so.1.0", O_RDONLY) = 4',
                'newfstatat(3</foreign/libpython3.13.so.1.0>, "", {}, AT_EMPTY_PATH) = 0'):
            with self.subTest(call=call), self.assertRaises(ValueError):
                self.check(self.VALID[:1] + ['1234 ' + call + '\n'] + self.VALID[1:])

    def test_foreign_pid_missing_exit_and_record_after_exit_reject(self):
        for lines in ([], self.VALID[:-1], self.VALID[1:], self.VALID + [self.VALID[1]],
                      self.VALID[:1] + ['9876 close(4) = 0\n'] + self.VALID[1:]):
            with self.subTest(lines=lines), self.assertRaises(ValueError):
                self.check(lines)

    def test_anonymous_executable_mapping_attempts_reject(self):
        for call in (
                'mmap(NULL, 4096, PROT_READ|PROT_EXEC, MAP_PRIVATE|MAP_ANONYMOUS, -1, 0) = 0xabc000',
                'mmap(NULL, 4096, PROT_READ|PROT_EXEC, MAP_PRIVATE, -1, 0) = -1 EINVAL',
                'mmap(NULL, 4096, PROT_READ|PROT_EXEC, MAP_PRIVATE|MAP_ANONYMOUS, 3</lib/aarch64-linux-gnu/libc.so.6>, 0) = 0xabc000',
                'mmap2(NULL, 4096, PROT_EXEC, MAP_PRIVATE|MAP_ANONYMOUS, -1, 0) = -1 EPERM'):
            with self.subTest(call=call), self.assertRaisesRegex(ValueError, 'anonymous executable mapping'):
                self.check(self.VALID[:1] + ['1234 ' + call + '\n'] + self.VALID[1:])

    def test_mprotect_and_pkey_execute_grants_reject(self):
        for call in (
                'mprotect(0xabc000, 4096, PROT_READ|PROT_EXEC) = 0',
                'mprotect(0xabc000, 4096, PROT_EXEC) = -1 EACCES',
                'pkey_mprotect(0xabc000, 4096, PROT_READ|PROT_WRITE|PROT_EXEC, 0) = 0'):
            with self.subTest(call=call), self.assertRaisesRegex(ValueError, 'grant executable memory protection'):
                self.check(self.VALID[:1] + ['1234 ' + call + '\n'] + self.VALID[1:])

    def test_system_file_execution_and_nonexecutable_heap_protections_pass(self):
        calls = [
            'mmap(NULL, 4096, PROT_READ|PROT_EXEC, MAP_PRIVATE|MAP_FIXED|MAP_DENYWRITE, 3</lib/aarch64-linux-gnu/libc.so.6>, 0) = 0xabc000',
            'mmap(NULL, 4096, PROT_READ|PROT_WRITE, MAP_PRIVATE|MAP_ANONYMOUS, -1, 0) = 0xdef000',
            'mprotect(0xabc000, 4096, PROT_READ) = 0',
            'pkey_mprotect(0xdef000, 4096, PROT_READ|PROT_WRITE, 0) = 0',
            'read(3</input/full.tar.zst>, \"PROT_EXEC MAP_ANONYMOUS\", 23) = 23',
        ]
        self.check(self.VALID[:1] + ['1234 ' + call + '\n' for call in calls] + self.VALID[1:])

    def test_truncated_binary_buffers_do_not_truncate_syscall_boundaries(self):
        calls = [
            r'read(3</input/full.tar.zst>, "binary\0data4</foreign/libpython3.13.so.1.0>"..., 16384) = 16384',
            r'write(1</evidence/stdout.txt>, "provider-report-data"..., 123456) = 123456',
        ]
        calls = [call.replace(r'\"', '"') for call in calls]
        self.check(self.VALID[:1] + ['1234 ' + call + '\n' for call in calls] + self.VALID[1:])
        for line in (self.VALID[0].replace('"--json"', '...'),
                     self.VALID[0].replace('"/build-target/host Python metadata"', '"/build-target/host Python meta"...')):
            with self.subTest(line=line), self.assertRaisesRegex(ValueError, 'truncated/malformed'):
                self.check([line] + self.VALID[1:])

    def test_truncated_file_path_arguments_reject(self):
        for call in (
                'openat(AT_FDCWD, \"/build-target/host Python meta\"..., O_RDONLY) = 4',
                'newfstatat(AT_FDCWD, \"/prefix/lib/libpyth\"..., {}, 0) = 0',
                'readlink(\"/alias\", \"/prefix/lib/libpyth\"..., 512) = 1000'):
            with self.subTest(call=call), self.assertRaisesRegex(ValueError, 'path/string argument is truncated'):
                self.check(self.VALID[:1] + ['1234 ' + call + '\n'] + self.VALID[1:])

    def test_extra_failed_killed_and_malformed_execs_reject(self):
        for lines in (self.VALID[:1] + self.VALID,
                      [self.VALID[0].replace(' = 0', ' = -1 ENOENT')] + self.VALID[1:],
                      self.VALID[:1] + ['1234 +++ killed by SIGSEGV +++\n'],
                      [self.VALID[0].replace('"python-host"', '"build-python", "--label", "python-host"')] + self.VALID[1:],
                      [self.VALID[0].replace(' = 0', ' <unfinished ...>')] + self.VALID[1:]):
            with self.subTest(lines=lines), self.assertRaises(ValueError):
                self.check(lines)


if __name__ == '__main__':
    unittest.main(verbosity=2)
