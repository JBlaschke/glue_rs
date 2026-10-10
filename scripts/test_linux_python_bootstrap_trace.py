"""Adversarial checks for the complete stock-PBS startup trace policy."""

import gzip
import importlib.util
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch


SCRIPT = Path(__file__).with_name("check-linux-python-bootstrap-trace.py")
SPEC = importlib.util.spec_from_file_location("python_bootstrap_trace_checker", SCRIPT)
assert SPEC is not None and SPEC.loader is not None
CHECKER = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(CHECKER)
IMAGE = f"3<{CHECKER.MEMFD_PATH}>(deleted)"
ALIAS = f"4<{CHECKER.MEMFD_PATH}>(deleted)"
ARCHIVE = f"3<{CHECKER.ARCHIVE}>"
CWD = CHECKER.CWD


def fixture_lines(mode="success"):
    command = [CHECKER.PROGRAM, "run", CHECKER.ARCHIVE] if mode == "success" else [CHECKER.PROGRAM, "run-negative", CHECKER.ARCHIVE, mode]
    size = CHECKER.ARCHIVE_BYTES
    lines = [
        f'execve({json.dumps(CHECKER.PROGRAM)}, {json.dumps(command)}, 0x1234 /* 18 vars */) = 0',
        f'openat({CWD}, {json.dumps(CHECKER.ARCHIVE)}, O_RDONLY|O_CLOEXEC) = {ARCHIVE}',
        f'lseek({ARCHIVE}, 0, SEEK_END) = {size}',
        f'lseek({ARCHIVE}, 0, SEEK_SET) = 0',
        f'read({ARCHIVE}, "complete archive"..., {size}) = {size}',
        f'lseek({ARCHIVE}, {size - 20}, SEEK_SET) = {size - 20}',
        f'read({ARCHIVE}, "ZIP directory bytes"..., 20) = 20',
        f'close({ARCHIVE}) = 0',
        f'memfd_create("{CHECKER.MEMFD}", MFD_CLOEXEC|MFD_ALLOW_SEALING|0x10) = {IMAGE}',
        f'write({IMAGE}, "unchanged stock library"..., {CHECKER.LIBRARY_BYTES}) = {CHECKER.LIBRARY_BYTES}',
        f'fcntl({IMAGE}, F_ADD_SEALS, F_SEAL_SEAL|F_SEAL_SHRINK|F_SEAL_GROW|F_SEAL_WRITE) = 0',
        f'fcntl({IMAGE}, F_GET_SEALS) = 0xf (seals F_SEAL_SEAL|F_SEAL_SHRINK|F_SEAL_GROW|F_SEAL_WRITE)',
        f'openat({CWD}, "/proc/self/fd/3", O_RDONLY|O_CLOEXEC) = {ALIAS}',
        f'read({ALIAS}, "ELF header"..., 832) = 832',
        f'newfstatat({ALIAS}, "", {{st_mode=S_IFREG|0777, st_size={CHECKER.LIBRARY_BYTES}, ...}}, AT_EMPTY_PATH) = 0',
        f'mmap(0x100000, 20423824, PROT_READ|PROT_EXEC, MAP_PRIVATE|MAP_FIXED|MAP_DENYWRITE, {ALIAS}, 0) = 0x100000',
        f'mmap(0x2000000, 1695744, PROT_READ|PROT_WRITE, MAP_PRIVATE|MAP_FIXED|MAP_DENYWRITE, {ALIAS}, 0x115a000) = 0x2000000',
        f'close({ALIAS}) = 0',
        f'openat({CWD}, "{CHECKER.OVERCOMMIT}", O_RDONLY) = 4<{CHECKER.OVERCOMMIT}>',
        f'read(4<{CHECKER.OVERCOMMIT}>, "0\\n", 32) = 2',
        f'close(4<{CHECKER.OVERCOMMIT}>) = 0',
        'gettid() = 1234',
        f'readlinkat({CWD}, "/__glue_archive__/launcher", 0x1234, 4096) = -1 ENOENT (No such file or directory)',
        f'openat({CWD}, "/usr/share/zoneinfo/UTC0", O_RDONLY|O_CLOEXEC) = -1 ENOENT (No such file or directory)',
    ]
    for index, diagnostic in enumerate(CHECKER.expected_output(mode), 1):
        for start in range(0, len(diagnostic), 128):
            chunk = diagnostic[start:start + 128]
            fd = f'{index}</evidence/{mode}.{"stdout" if index == 1 else "stderr"}.txt>'
            lines.append(f'write({fd}, {json.dumps(chunk.decode("ascii"))}, {len(chunk)}) = {len(chunk)}')
    status = 0 if mode == "success" else 1
    lines.extend([f'exit_group({status}) = ?', f'+++ exited with {status} +++'])
    return lines


def trace(lines=None, mode="success", pid=1234):
    return "".join(f"{pid}  {line}\n" for line in (fixture_lines(mode) if lines is None else lines))


def extra(call, mode="success"):
    lines = fixture_lines(mode)
    lines.insert(-2, call)
    return trace(lines, mode)


class TracePolicyTests(unittest.TestCase):
    def reject(self, text, mode="success", fragment=None):
        with self.assertRaises(CHECKER.TraceError) as caught:
            CHECKER.check_trace(text, mode)
        if fragment:
            self.assertIn(fragment, str(caught.exception))

    def test_complete_positive_and_three_controlled_errors_are_admitted(self):
        for mode in CHECKER.MODES:
            with self.subTest(mode=mode):
                CHECKER.check_trace(trace(mode=mode), mode)

    def test_exec_path_all_arguments_and_success_are_exact(self):
        for old, new in [
            (CHECKER.PROGRAM, "/tmp/launcher"),
            (json.dumps(CHECKER.ARCHIVE) + "]", json.dumps(CHECKER.ARCHIVE) + ", ...]"),
            ('"run"', '"baseline"'),
            (" = 0\n", " = -1 EACCES (Permission denied)\n"),
        ]:
            self.reject(trace().replace(old, new, 1))
        self.reject(extra(fixture_lines()[0]))
        self.reject(extra('execve("/bin/sh", ["sh"], 0x1234 /* 1 vars */) = -1 EACCES (Permission denied)'))
        self.reject(trace(mode="app-error"), "success")

    def test_unknown_syscalls_processes_threads_and_network_fail_even_on_errors(self):
        for call in [
            "unknown_future_syscall(0) = 0",
            "clone(CLONE_VM|CLONE_THREAD, NULL) = -1 EPERM (Operation not permitted)",
            "clone3({}, 64) = -1 ENOSYS (Function not implemented)",
            "socket(AF_INET, SOCK_STREAM, 0) = -1 EPERM (Operation not permitted)",
            "connect(3, {}, 16) = -1 ECONNREFUSED (Connection refused)",
            "io_uring_setup(8, {}) = -1 EPERM (Operation not permitted)",
            "execveat(3, \"\", [], NULL, AT_EMPTY_PATH) = -1 EACCES (Permission denied)",
            "sendfile(1, 3, NULL, 20) = 20",
            "getpid() = 1234",
        ]:
            with self.subTest(call=call):
                self.reject(extra(call))
        lines = fixture_lines()
        text = trace(lines).replace("1234  gettid", "1235  gettid")
        self.reject(text, fragment="additional process")

    def test_filesystem_mutation_attempts_and_hidden_create_unlink_fail(self):
        for call in [
            f'openat({CWD}, "/tmp/hidden", O_WRONLY|O_CREAT|O_EXCL, 0600) = 5</tmp/hidden>',
            'unlink("/tmp/hidden") = 0',
            f'unlinkat({CWD}, "/tmp/hidden", 0) = -1 ENOENT (No such file or directory)',
            'rename("/tmp/a", "/tmp/b") = -1 EROFS (Read-only file system)',
            'mkdir("/tmp/a", 0700) = -1 EACCES (Permission denied)',
            'chmod("/tmp/a", 0700) = -1 EACCES (Permission denied)',
            'ftruncate(3, 0) = -1 EPERM (Operation not permitted)',
            f'pwrite64({IMAGE}, "x", 1, 0) = -1 EPERM (Operation not permitted)',
            f'writev({IMAGE}, [{{iov_base="x", iov_len=1}}], 1) = -1 EPERM (Operation not permitted)',
        ]:
            with self.subTest(call=call):
                self.reject(extra(call))
        lines = fixture_lines()
        lines[-2:-2] = [f'openat({CWD}, "/tmp/hidden", O_WRONLY|O_CREAT|O_EXCL, 0600) = 5</tmp/hidden>', 'unlink("/tmp/hidden") = 0', 'close(5</tmp/hidden>(deleted)) = 0']
        self.reject(trace(lines))

    def test_only_declared_archive_os_reads_and_self_alias_are_admitted(self):
        for path in ["/tmp/python.py", "/usr/lib/python3.13/encodings/__init__.py", "/workspace/target/producer/lib/libpython3.13.so.1.0", "/etc/passwd", "/etc/localtime", "/proc/4321/maps", "/proc/4321/fd/3"]:
            self.reject(extra(f'openat({CWD}, {json.dumps(path)}, O_RDONLY|O_CLOEXEC) = -1 ENOENT (No such file or directory)'))
        for flags in ["O_WRONLY", "O_RDWR", "O_RDONLY|O_TRUNC", "O_RDONLY|O_CREAT", "O_PATH"]:
            self.reject(trace().replace("O_RDONLY|O_CLOEXEC) = " + ARCHIVE, flags + ") = " + ARCHIVE, 1))
        self.reject(trace().replace(json.dumps(CHECKER.ARCHIVE), json.dumps(CHECKER.ARCHIVE) + "...", 1))
        self.reject(trace().replace(CWD, "AT_FDCWD</tmp>", 1))
        self.reject(trace().replace(ARCHIVE, ARCHIVE + "(deleted)", 1))

    def test_archive_reads_seek_results_and_descriptor_lifetime_are_checked(self):
        for old, new in [
            (f'"complete archive"..., {CHECKER.ARCHIVE_BYTES}) = {CHECKER.ARCHIVE_BYTES}', f'"complete archive"..., {CHECKER.ARCHIVE_BYTES}) = {CHECKER.ARCHIVE_BYTES - 1}'),
            (f'SEEK_END) = {CHECKER.ARCHIVE_BYTES}', f'SEEK_END) = {CHECKER.ARCHIVE_BYTES + 1}'),
            (f'read({ARCHIVE}, "ZIP', f'read(8<{CHECKER.ARCHIVE}>, "ZIP'),
            ("SEEK_SET) = 0", "SEEK_SET) = 1"),
        ]:
            self.reject(trace().replace(old, new, 1))
        self.reject(extra(f'read({ARCHIVE}, "closed", 6) = 6'))
        self.reject(extra(f'openat({CWD}, {json.dumps(CHECKER.ARCHIVE)}, O_RDONLY|O_CLOEXEC) = {ARCHIVE}'))

    def test_archive_seek_shift_cannot_hide_missing_bytes_with_duplicated_reads(self):
        lines = fixture_lines()
        index = next(index for index, line in enumerate(lines) if '"complete archive"' in line)
        size = CHECKER.ARCHIVE_BYTES
        lines[index:index + 1] = [
            f'read({ARCHIVE}, "first"..., 10) = 10',
            f'lseek({ARCHIVE}, 10, SEEK_SET) = 10',
            f'read({ARCHIVE}, "second"..., 10) = 10',
            f'lseek({ARCHIVE}, 20, SEEK_SET) = 20',
            f'read({ARCHIVE}, "remaining archive"..., {size - 20}) = {size - 20}',
        ]
        CHECKER.check_trace(trace(lines))
        shifted = [line.replace('10, SEEK_SET) = 10', '11, SEEK_SET) = 11') for line in lines]
        self.reject(trace(shifted), fragment="unread byte range")

    def test_one_named_memfd_requires_anonymous_deleted_annotation(self):
        for old, new in [(CHECKER.MEMFD, "other-image"), ("MFD_ALLOW_SEALING|0x10", "0x10"), ("MFD_ALLOW_SEALING|0x10", "MFD_ALLOW_SEALING"), ("MFD_ALLOW_SEALING|0x10", "MFD_ALLOW_SEALING|0x10|MFD_EXEC"), (IMAGE, IMAGE.removesuffix("(deleted)"))]:
            self.reject(trace().replace(old, new, 1))
        self.reject(extra(f'memfd_create("{CHECKER.MEMFD}", MFD_CLOEXEC|MFD_ALLOW_SEALING|0x10) = 5<{CHECKER.MEMFD_PATH}>(deleted)'))
        self.reject(extra('memfd_create("hidden", MFD_CLOEXEC|MFD_ALLOW_SEALING|0x10) = -1 EPERM (Operation not permitted)'))

    def test_population_full_seal_verification_and_order_are_required(self):
        for transformation in [
            lambda lines: [line for line in lines if "F_ADD_SEALS" not in line],
            lambda lines: [line for line in lines if "F_GET_SEALS" not in line],
            lambda lines: [line.replace("|F_SEAL_WRITE", "") for line in lines],
            lambda lines: [line.replace(" = 0xf", " = 0x7") for line in lines],
            lambda lines: [line.replace(f' = {CHECKER.LIBRARY_BYTES}', f' = {CHECKER.LIBRARY_BYTES - 1}') for line in lines],
        ]:
            self.reject(trace(transformation(fixture_lines())))
        lines = fixture_lines()
        first = next(i for i, line in enumerate(lines) if "F_ADD_SEALS" in line)
        lines.insert(first + 1, f'write({IMAGE}, "x", 1) = -1 EPERM (Operation not permitted)')
        self.reject(trace(lines))
        lines = fixture_lines()
        alias = lines.pop(next(i for i, line in enumerate(lines) if '"/proc/self/fd/3"' in line))
        lines.insert(first, alias)
        self.reject(trace(lines))

    def test_only_two_exact_private_stock_segments_can_execute(self):
        for old, new in [
            ("MAP_PRIVATE|MAP_FIXED|MAP_DENYWRITE", "MAP_SHARED|MAP_FIXED"),
            ("PROT_READ|PROT_EXEC", "PROT_READ|PROT_WRITE|PROT_EXEC"),
            ("20423824", "20423825"),
            ("0x115a000", "0x115b000"),
            (f'{ALIAS}, 0)', f'{ARCHIVE}, 0)'),
        ]:
            self.reject(trace().replace(old, new, 1))
        self.reject(extra('mmap(NULL, 4096, PROT_READ|PROT_EXEC, MAP_PRIVATE|MAP_ANONYMOUS, -1, 0) = 0x1234'))
        self.reject(extra('mprotect(0x1234, 4096, PROT_READ|PROT_EXEC) = 0'))
        lines = fixture_lines()
        lines.insert(-2, next(line for line in lines if line.startswith("mmap")))
        self.reject(trace(lines))

    def test_unknown_closed_and_foreign_descriptors_cannot_read_or_write(self):
        for call in [f'read({ALIAS}, "x", 1) = 1', f'write({ALIAS}, "x", 1) = 1', f'close({IMAGE}) = 0', 'close(1</evidence/success.stdout.txt>) = 0', 'read(9</etc/passwd>, "x", 1) = 1', 'write(4</tmp/hidden>(deleted), "x", 1) = 1', 'dup2(3, 1) = 1']:
            self.reject(extra(call))

    def test_exact_stdout_stderr_content_fd_and_counts_are_required(self):
        for old, new in [
            ('"PASS Python', '"FAIL Python'),
            ("1</evidence/success.stdout.txt>", "2</evidence/success.stderr.txt>"),
            (", 108) = 108", ", 108) = 107"),
            (" = 108", " = -1 EPIPE (Broken pipe)"),
            ('\\n", 108)', '\\n"..., 108)'),
        ]:
            self.reject(trace().replace(old, new, 1))
        self.reject(extra('write(2</evidence/success.stderr.txt>, "hidden error", 12) = 12'))
        self.reject(extra('write(1</evidence/success.stdout.txt>, "x", 1) = 1'))
        for mode in CHECKER.MODES:
            lines = [line for line in fixture_lines(mode) if not (line.startswith("write") and "/evidence/" in line)]
            self.reject(trace(lines, mode), mode)

    def test_only_exact_failed_virtual_and_timezone_lookups_are_admitted(self):
        for old, new in [
            ('"/__glue_archive__/launcher"', '"/usr/bin/python3"'),
            ('"/usr/share/zoneinfo/UTC0"', '"/usr/share/zoneinfo/UTC"'),
            (" = -1 ENOENT (No such file or directory)", ' = 4</usr/share/zoneinfo/UTC0>'),
            (" = -1 ENOENT (No such file or directory)", " = -1 EACCES (Permission denied)"),
        ]:
            self.reject(trace().replace(old, new, 1))
        self.reject(extra(f'openat({CWD}, "/usr/share/zoneinfo/UTC0", O_RDONLY|O_CLOEXEC) = -1 ENOENT (No such file or directory)'))
        self.reject(trace().replace('"0\\n", 32) = 2', '"1\\n", 32) = 2'))

    def test_standard_stream_probes_require_unchanged_inherited_descriptors(self):
        valid = ['fstat(0</dev/null<char 1:3>>, {st_mode=S_IFCHR|0666, st_rdev=makedev(0x1, 0x3), ...}) = 0', 'fcntl(1</evidence/success.stdout.txt>, F_GETFD) = 0', 'lseek(0</dev/null<char 1:3>>, 0, SEEK_CUR) = 0', 'ioctl(2</evidence/success.stderr.txt>, TCGETS, 0x1234) = -1 ENOTTY (Inappropriate ioctl for device)']
        for call in valid:
            CHECKER.check_trace(extra(call))
        for call in ['fcntl(1</evidence/success.stdout.txt>, F_SETFD, 0) = 0', 'ioctl(2</evidence/success.stderr.txt>, TCGETS, {}) = 0', 'lseek(1</evidence/success.stdout.txt>, 0, SEEK_SET) = 0', 'fstat(0</tmp/stdin>, {st_mode=S_IFREG|0644, st_size=0, ...}) = 0']:
            self.reject(extra(call))

    def test_expected_exit_both_records_and_no_later_activity_are_required(self):
        for mode in CHECKER.MODES:
            text = trace(mode=mode)
            lines = fixture_lines(mode)
            self.reject(trace(lines[:-1], mode), mode)
            self.reject(trace([line for line in lines if not line.startswith("exit_group")], mode), mode)
            self.reject(text[:-1], mode)
            status = 0 if mode == "success" else 1
            self.reject(text.replace(f'exited with {status}', f'exited with {1-status}'), mode)
            self.reject(text + '1234  gettid() = 1234\n', mode)
        self.reject(trace() + '\n')
        self.reject(trace().replace('+++ exited with 0 +++', '--- SIGSEGV {si_signo=SIGSEGV} ---'))

    def test_record_byte_line_numeric_and_utf8_bounds_are_strict(self):
        with patch.object(CHECKER, "MAX_TRACE_BYTES", 20):
            self.reject(trace(), fragment="oversized")
        with patch.object(CHECKER, "MAX_RECORDS", 5):
            self.reject(trace(), fragment="record bound")
        self.reject(extra('gettid(' + '0' * 9000 + ') = 1234'))
        self.reject(trace(pid=0))
        self.reject(trace(pid=12345678901))
        self.reject(trace().replace(' = 1234\n', ' = ' + '9' * 100 + '\n'))
        self.reject(trace().replace('"complete archive"', '"incomplete buffer'))
        self.reject(trace().replace('"complete archive"', '"surrogate \ud800"'))
        with self.assertRaises(CHECKER.TraceError):
            CHECKER.Checker(archive_bytes=True)

    def test_gzip_complete_evidence_and_decompression_bounds(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "trace.txt.gz"
            path.write_bytes(gzip.compress(trace().encode(), mtime=0))
            CHECKER.check_file(path)
            with patch.object(CHECKER, "MAX_TRACE_BYTES", path.stat().st_size + 1):
                with self.assertRaises(CHECKER.TraceError):
                    CHECKER.check_file(path)
            path.write_bytes(path.read_bytes()[:-5])
            with self.assertRaises((CHECKER.TraceError, EOFError)):
                CHECKER.check_file(path)
            path.write_bytes(gzip.compress(b"1234  \xff\n", mtime=0))
            with self.assertRaises(UnicodeError):
                CHECKER.check_file(path)

    def test_cli_cross_checks_retained_output_and_error_modes(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            for mode in CHECKER.MODES:
                evidence = root / f"{mode}.trace.txt"
                stdout, stderr = root / "stdout", root / "stderr"
                evidence.write_text(trace(mode=mode))
                output = CHECKER.expected_output(mode)
                stdout.write_bytes(output[0])
                stderr.write_bytes(output[1])
                command = [sys.executable, str(SCRIPT), str(evidence), "--mode", mode, "--stdout-file", str(stdout), "--stderr-file", str(stderr)]
                result = subprocess.run(command, capture_output=True)
                self.assertEqual(result.returncode, 0, result.stderr)
                replay = subprocess.run(command + ["--archive-bytes", str(CHECKER.ARCHIVE_BYTES)], capture_output=True)
                self.assertEqual(replay.returncode, 0, replay.stderr)
                for invalid in (0, CHECKER.LIBRARY_BYTES, 85 * 1024 * 1024):
                    rejected = subprocess.run(command + ["--archive-bytes", str(invalid)], capture_output=True)
                    self.assertEqual(rejected.returncode, 1)
                stderr.write_bytes(output[1] + b"untraced bytes")
                self.assertEqual(subprocess.run(command, capture_output=True).returncode, 1)


if __name__ == "__main__":
    unittest.main()
