"""Adversarial checks for the complete archive-import trace policy."""

import gzip
import importlib.util
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
import zipfile
from unittest.mock import patch


SCRIPT = Path(__file__).with_name("check-linux-python-import-trace.py")
SPEC = importlib.util.spec_from_file_location("python_import_trace_checker", SCRIPT)
assert SPEC is not None and SPEC.loader is not None
CHECKER = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(CHECKER)
IMAGE = f"3<{CHECKER.MEMFD_PATH}>(deleted)"
ALIAS = f"4<{CHECKER.MEMFD_PATH}>(deleted)"
ARCHIVE = f"3<{CHECKER.ARCHIVE}>"
CWD = CHECKER.CWD


def fixture_lines(mode="success"):
    command = CHECKER.command_for(mode)
    archive = f"3<{CHECKER.archive_for(mode)}>"
    size = CHECKER.ARCHIVE_BYTES
    lines = [
        f'execve({json.dumps(CHECKER.PROGRAM)}, {json.dumps(command)}, 0x1234 /* 18 vars */) = 0',
        f'openat({CWD}, {json.dumps(CHECKER.archive_for(mode))}, O_RDONLY|O_CLOEXEC) = {archive}',
        f'lseek({archive}, 0, SEEK_END) = {size}',
        f'lseek({archive}, 0, SEEK_SET) = 0',
        f'read({archive}, "GLUERS00 locator"..., 64) = 64',
        f'mmap(NULL, 299008, PROT_READ|PROT_WRITE, MAP_PRIVATE|MAP_ANONYMOUS, -1, 0) = 0x3000000',
        f'mremap(0x3000000, 299008, 593920, MREMAP_MAYMOVE) = 0x4000000',
        f'read({archive}, "complete archive"..., {size - 64}) = {size - 64}',
        f'lseek({archive}, {size - 20}, SEEK_SET) = {size - 20}',
        f'read({archive}, "ZIP directory bytes"..., 20) = 20',
        f'close({archive}) = 0',
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
        f'getrandom("archived random seed"..., 2496, GRND_NONBLOCK) = 2496',
        'gettid() = 1234',
    ]
    if mode == "corrupt-source":
        lines = lines[:next(index for index, line in enumerate(lines) if line.startswith("memfd_create"))]
        lines.pop()
        lines.extend([
            f'lseek({archive}, {CHECKER.CORRUPT_SOURCE_OFFSET}, SEEK_SET) = {CHECKER.CORRUPT_SOURCE_OFFSET}',
            f'read({archive}, {json.dumps(CHECKER.CORRUPT_SOURCE.decode("ascii"))}, {len(CHECKER.CORRUPT_SOURCE)}) = {len(CHECKER.CORRUPT_SOURCE)}',
            f'close({archive}) = 0',
        ])
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

    def test_success_app_error_and_preinit_integrity_rejection_are_admitted(self):
        for mode in CHECKER.MODES:
            with self.subTest(mode=mode):
                CHECKER.check_trace(trace(mode=mode), mode)

    def test_exec_path_all_arguments_and_success_are_exact(self):
        for old, new in [
            (CHECKER.PROGRAM, "/tmp/launcher"),
            (json.dumps(CHECKER.ARCHIVE) + "]", json.dumps(CHECKER.ARCHIVE) + ", ...]"),
            ('"run-imports"', '"baseline-imports"'),
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
            (f'"complete archive"..., {CHECKER.ARCHIVE_BYTES-64}) = {CHECKER.ARCHIVE_BYTES-64}', f'"complete archive"..., {CHECKER.ARCHIVE_BYTES-64}) = {CHECKER.ARCHIVE_BYTES-65}'),
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
            f'lseek({ARCHIVE}, 74, SEEK_SET) = 74',
            f'read({ARCHIVE}, "second"..., 10) = 10',
            f'lseek({ARCHIVE}, 84, SEEK_SET) = 84',
            f'read({ARCHIVE}, "remaining archive"..., {size - 84}) = {size - 84}',
        ]
        CHECKER.check_trace(trace(lines))
        shifted = [line.replace('74, SEEK_SET) = 74', '75, SEEK_SET) = 75') for line in lines]
        self.reject(trace(shifted), fragment="complete archive")

    def test_one_named_memfd_requires_anonymous_deleted_annotation(self):
        for old, new in [(CHECKER.MEMFD, "other-image"), ("MFD_ALLOW_SEALING|0x10", "0x10"), ("MFD_ALLOW_SEALING|0x10", "MFD_ALLOW_SEALING"), ("MFD_ALLOW_SEALING|0x10", "MFD_ALLOW_SEALING|0x10|MFD_EXEC"), (IMAGE, IMAGE.removesuffix("(deleted)"))]:
            self.reject(trace().replace(old, new, 1))
        self.reject(extra(f'memfd_create("{CHECKER.MEMFD}", MFD_CLOEXEC|MFD_ALLOW_SEALING|0x10) = 5<{CHECKER.MEMFD_PATH}>(deleted)'))
        self.reject(extra('memfd_create("hidden", MFD_CLOEXEC|MFD_ALLOW_SEALING|0x10) = -1 EPERM (Operation not permitted)'))
        self.reject(extra(f'openat({CWD}, "/proc/self/fd/3", O_RDONLY|O_CLOEXEC) = {ALIAS}'))

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
            ('mmap(0x100000, 20423824', 'mmap(NULL, 20423824'),
            (f'{ALIAS}, 0) = 0x100000', f'{ALIAS}, 0) = 0x200000'),
            (f'{ALIAS}, 0)', f'{ARCHIVE}, 0)'),
            (f'{ALIAS}, 0)', f'{IMAGE}, 0)'),
        ]:
            self.reject(trace().replace(old, new, 1))
        self.reject(extra('mmap(NULL, 4096, PROT_READ|PROT_EXEC, MAP_PRIVATE|MAP_ANONYMOUS, -1, 0) = 0x1234'))
        self.reject(extra('mprotect(0x1234, 4096, PROT_READ|PROT_EXEC) = 0'))
        lines = fixture_lines()
        lines.insert(-2, next(line for line in lines if line.startswith("mmap") and ALIAS in line))
        self.reject(trace(lines))

    def test_unknown_closed_and_foreign_descriptors_cannot_read_or_write(self):
        for call in [f'read({ALIAS}, "x", 1) = 1', f'write({ALIAS}, "x", 1) = 1', f'close({IMAGE}) = 0', 'close(1</evidence/success.stdout.txt>) = 0', 'read(9</etc/passwd>, "x", 1) = 1', 'write(4</tmp/hidden>(deleted), "x", 1) = 1', 'dup2(3, 1) = 1']:
            self.reject(extra(call))

    def test_exact_stdout_stderr_content_fd_and_counts_are_required(self):
        for old, new in [
            ('"PASS Python', '"FAIL Python'),
            ("1</evidence/success.stdout.txt>", "2</evidence/success.stderr.txt>"),
            (f", {len(CHECKER.SUCCESS)}) = {len(CHECKER.SUCCESS)}", f", {len(CHECKER.SUCCESS)}) = {len(CHECKER.SUCCESS)-1}"),
            (f" = {len(CHECKER.SUCCESS)}", " = -1 EPIPE (Broken pipe)"),
            (f'\\n", {len(CHECKER.SUCCESS)})', f'\\n"..., {len(CHECKER.SUCCESS)})'),
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

    def test_archive_must_finish_and_close_before_image_population(self):
        lines = fixture_lines()
        close = lines.pop(next(i for i, line in enumerate(lines) if line == f"close({ARCHIVE}) = 0"))
        lines.insert(next(i for i, line in enumerate(lines) if "F_GET_SEALS" in line) + 1, close)
        self.reject(trace(lines), fragment="complete archive verification and closure")
        lines = fixture_lines()
        end = next(i for i, line in enumerate(lines) if line == f"close({ARCHIVE}) = 0") + 1
        reading = lines[1:end]
        del lines[1:end]
        lines[-2:-2] = reading
        self.reject(trace(lines), fragment="complete archive verification and closure")

    def test_pass_cannot_be_published_before_verified_mappings_and_startup(self):
        lines = fixture_lines()
        output = [line for line in lines if line.startswith("write") and "/evidence/" in line]
        lines = [line for line in lines if line not in output]
        lines[1:1] = output
        self.reject(trace(lines), fragment="publication precedes")
        for marker in ("mmap", "readlinkat", "gettid", '"/usr/share/zoneinfo/UTC0"', '"0\\n", 32'):
            modified = [line for line in fixture_lines() if marker not in line]
            self.reject(trace(modified))

    def test_app_error_must_follow_the_complete_pass_output(self):
        lines = fixture_lines("app-error")
        output = [line for line in lines if line.startswith("write") and "/evidence/" in line]
        lines = [line for line in lines if line not in output]
        lines[-2:-2] = list(reversed(output))
        self.reject(trace(lines, "app-error"), "app-error", "follow the complete PASS")

    def test_corruption_diagnostic_requires_archive_read_and_closure_without_image(self):
        for marker in ("openat", "read(", "close("):
            lines = [line for line in fixture_lines("corrupt-source") if not line.startswith(marker)]
            self.reject(trace(lines, "corrupt-source"), "corrupt-source")
        lines = fixture_lines("corrupt-source")
        lines.insert(-2, f'memfd_create("{CHECKER.MEMFD}", MFD_CLOEXEC|MFD_ALLOW_SEALING|0x10) = {IMAGE}')
        self.reject(trace(lines, "corrupt-source"), "corrupt-source")
        self.reject(trace(mode="corrupt-source").replace("CRC32", "SHA-256"), "corrupt-source")
        self.reject(trace(mode="corrupt-source").replace("glue_demo", "undeclared_fixture"), "corrupt-source")
        lines = fixture_lines("corrupt-source")
        output = [line for line in lines if line.startswith("write")]
        lines = [line for line in lines if line not in output]
        lines[1:1] = output
        self.reject(trace(lines, "corrupt-source"), "corrupt-source")

    def test_resource_materialization_attempts_are_rejected_even_when_failed(self):
        for call in [
            f'openat({CWD}, "/unavailable/tmp/archive-resource", O_WRONLY|O_CREAT|O_EXCL|O_CLOEXEC, 0600) = -1 EACCES (Permission denied)',
            'mkdir("/tmp/archive-resource", 0700) = -1 EACCES (Permission denied)',
            f'openat({CWD}, "/__glue_archive__/input/app/archive_fixture/data/value.txt", O_RDONLY|O_CLOEXEC) = -1 ENOENT (No such file or directory)',
            f'newfstatat({CWD}, "/tmp/archive-resource", 0x1234, AT_SYMLINK_NOFOLLOW) = -1 EACCES (Permission denied)',
        ]:
            self.reject(extra(call))

    def test_initialization_queries_cannot_precede_mapping_or_alias_closure(self):
        lines = fixture_lines()
        start = next(i for i, line in enumerate(lines) if CHECKER.OVERCOMMIT in line)
        end = next(i for i, line in enumerate(lines) if 'getrandom("archived random seed"' in line) + 1
        startup = lines[start:end]
        del lines[start:end]
        lines[1:1] = startup
        self.reject(trace(lines), fragment="precedes selected image")
        lines = fixture_lines()
        close = lines.pop(next(i for i, line in enumerate(lines) if line == f"close({ALIAS}) = 0"))
        lines.insert(-2, close)
        self.reject(trace(lines), fragment="precedes selected image")
        for before_seed in (True, False):
            lines = fixture_lines()
            index = max(i for i, line in enumerate(lines) if line.startswith("gettid"))
            thread = lines.pop(index)
            index = next(i for i, line in enumerate(lines) if line.startswith("getrandom")) if before_seed else len(lines)-2
            lines.insert(index, thread)
            self.reject(trace(lines))

    def test_corrupt_rejection_requires_locator_and_exact_selected_stored_read(self):
        for marker in ('"GLUERS00 locator"', json.dumps(CHECKER.CORRUPT_SOURCE.decode("ascii")), "SEEK_END"):
            lines = [line for line in fixture_lines("corrupt-source") if marker not in line]
            self.reject(trace(lines, "corrupt-source"), "corrupt-source")
        for old, new in [
            (json.dumps(CHECKER.CORRUPT_SOURCE.decode("ascii")), '"x"'),
            (f", {len(CHECKER.CORRUPT_SOURCE)}) = {len(CHECKER.CORRUPT_SOURCE)}", ", 1) = 1"),
            ("grom .answer", "from .answer"),
            (f"{CHECKER.CORRUPT_SOURCE_OFFSET}, SEEK_SET) = {CHECKER.CORRUPT_SOURCE_OFFSET}", f"{CHECKER.CORRUPT_SOURCE_OFFSET+1}, SEEK_SET) = {CHECKER.CORRUPT_SOURCE_OFFSET+1}"),
        ]:
            self.reject(trace(mode="corrupt-source").replace(old, new, 1), "corrupt-source")
        with self.assertRaises(CHECKER.TraceError):
            CHECKER.Checker("corrupt-source", corrupt_source_offset=True)
        for offset in (0, 64, CHECKER.ARCHIVE_BYTES, CHECKER.ARCHIVE_BYTES-len(CHECKER.CORRUPT_SOURCE)+1):
            with self.assertRaises(CHECKER.TraceError):
                CHECKER.Checker("corrupt-source", corrupt_source_offset=offset)
        lines = fixture_lines("corrupt-source")
        source = next(i for i, line in enumerate(lines) if json.dumps(CHECKER.CORRUPT_SOURCE.decode("ascii")) in line)
        lines[source+1:source+1] = lines[source-1:source+1]
        self.reject(trace(lines, "corrupt-source"), "corrupt-source")

    def test_only_observed_private_nonexecutable_manifest_remap_is_admitted(self):
        for old, new in [
            ("MREMAP_MAYMOVE", "MREMAP_MAYMOVE|MREMAP_FIXED"),
            ("593920", "593921"),
            ("mremap(0x3000000", "mremap(0x3000001"),
            ("mremap(0x3000000, 299008", "mremap(0x3000000, 299007"),
            ("MREMAP_MAYMOVE) = 0x4000000", "MREMAP_MAYMOVE) = -1 ENOMEM (Cannot allocate memory)"),
        ]:
            self.reject(trace().replace(old, new, 1))
        lines = fixture_lines()
        remap = next(i for i, line in enumerate(lines) if line.startswith("mremap"))
        lines.insert(remap, "munmap(0x3000000, 299008) = 0")
        self.reject(trace(lines))
        lines = fixture_lines()
        lines.insert(remap+1, lines[remap])
        self.reject(trace(lines))
        self.reject(trace([line for line in fixture_lines() if not line.startswith("mremap")]))

    def test_archived_random_seed_requires_once_only_observed_count_flags_and_phase(self):
        for old, new in [
            (", 2496, GRND_NONBLOCK", ", 2495, GRND_NONBLOCK"),
            (", 2496, GRND_NONBLOCK", ", 2496, 0"),
            ("GRND_NONBLOCK) = 2496", "GRND_NONBLOCK) = 2495"),
        ]:
            self.reject(trace().replace(old, new, 1))
        lines = fixture_lines()
        seed = lines.pop(next(i for i, line in enumerate(lines) if line.startswith("getrandom")))
        lines.insert(1, seed)
        self.reject(trace(lines))
        self.reject(extra(seed))
        self.reject(trace([line for line in fixture_lines() if not line.startswith("getrandom")]))

    def test_corrupt_source_metadata_offset_derives_from_embedded_zip(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "fixture.glue"
            with path.open("wb") as stream:
                stream.seek(CHECKER.LIBRARY_BYTES)
                stream.write(b"prefix")
            with zipfile.ZipFile(path, "a") as archive:
                archive.writestr(CHECKER.CORRUPT_SOURCE_KEY, CHECKER.CORRUPT_SOURCE, compress_type=zipfile.ZIP_STORED)
            offset = CHECKER.source_offset(path)
            with path.open("rb") as stream:
                stream.seek(offset)
                self.assertEqual(stream.read(len(CHECKER.CORRUPT_SOURCE)), CHECKER.CORRUPT_SOURCE)
            with zipfile.ZipFile(path, "a") as archive:
                archive.writestr("unused", b"x")
            self.assertEqual(CHECKER.source_offset(path), offset)
            invalid = Path(directory) / "invalid.glue"
            invalid.write_bytes(b"not an archive")
            with self.assertRaises(CHECKER.TraceError):
                CHECKER.source_offset(invalid)

    def test_cli_corrupt_replay_requires_retained_member_offset(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            evidence, stdout, stderr = root / "trace", root / "stdout", root / "stderr"
            evidence.write_text(trace(mode="corrupt-source"))
            output = CHECKER.expected_output("corrupt-source")
            stdout.write_bytes(output[0])
            stderr.write_bytes(output[1])
            command = [sys.executable, str(SCRIPT), str(evidence), "--mode", "corrupt-source", "--stdout-file", str(stdout), "--stderr-file", str(stderr), "--archive-bytes", str(CHECKER.ARCHIVE_BYTES)]
            result = subprocess.run(command, capture_output=True)
            self.assertEqual(result.returncode, 1)
            self.assertIn(b"requires --corrupt-source-offset", result.stderr)
            result = subprocess.run(command + ["--corrupt-source-offset", str(CHECKER.CORRUPT_SOURCE_OFFSET)], capture_output=True)
            self.assertEqual(result.returncode, 0, result.stderr)

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
                if mode == "corrupt-source":
                    command.extend(["--corrupt-source-offset", str(CHECKER.CORRUPT_SOURCE_OFFSET)])
                result = subprocess.run(command, capture_output=True)
                self.assertEqual(result.returncode, 0, result.stderr)
                replay = subprocess.run(command + ["--archive-bytes", str(CHECKER.ARCHIVE_BYTES)], capture_output=True)
                self.assertEqual(replay.returncode, 0, replay.stderr)
                for invalid in (0, CHECKER.LIBRARY_BYTES, 129 * 1024 * 1024):
                    rejected = subprocess.run(command + ["--archive-bytes", str(invalid)], capture_output=True)
                    self.assertEqual(rejected.returncode, 1)
                stderr.write_bytes(output[1] + b"untraced bytes")
                self.assertEqual(subprocess.run(command, capture_output=True).returncode, 1)


if __name__ == "__main__":
    unittest.main()
