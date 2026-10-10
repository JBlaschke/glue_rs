"""Adversarial tests for complete build-time PBS inspection syscall evidence."""

import gzip
import importlib.util
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch


SCRIPT = Path(__file__).with_name("check-linux-pbs-trace.py")
SPEC = importlib.util.spec_from_file_location("pbs_trace_checker", SCRIPT)
assert SPEC is not None and SPEC.loader is not None
CHECKER = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(CHECKER)
REPORT_BYTES = 20
OUT = f"1<{CHECKER.STDOUT}>"


def fixture_lines():
    paths = [CHECKER.PROGRAM, CHECKER.PINS, CHECKER.FULL, CHECKER.INSTALL]
    argv = "[" + ", ".join(json.dumps(path) for path in paths) + "]"
    lines = [f'execve({json.dumps(CHECKER.PROGRAM)}, {argv}, 0x1234 /* 10 vars */) = 0']
    for path in [CHECKER.PINS, CHECKER.FULL, CHECKER.INSTALL]:
        fd = f"3<{path}>"
        lines.append(f'openat(AT_FDCWD</workspace>, {json.dumps(path)}, O_RDONLY|O_CLOEXEC) = {fd}')
        if path == CHECKER.PINS:
            lines.append(f'read({fd}, "pins", 4) = 4')
        else:
            for _ in range(2):
                count = CHECKER.ARTIFACT_SIZES[path]
                lines.extend([f'lseek({fd}, 0, SEEK_SET) = 0', f'read({fd}, "compressed bytes"..., {count}) = {count}'])
        lines.append(f"close({fd}) = 0")
    lines.extend([f'write({OUT}, "report bytes"..., {REPORT_BYTES}) = {REPORT_BYTES}', "exit_group(0) = ?", "+++ exited with 0 +++"])
    return lines


def trace(lines=None, pid=1234):
    return "".join(f"{pid}  {line}\n" for line in (fixture_lines() if lines is None else lines))


def extra(call):
    lines = fixture_lines()
    lines.insert(-2, call)
    return trace(lines)


class TracePolicyTests(unittest.TestCase):
    def reject(self, text, fragment=None):
        with self.assertRaises(CHECKER.TraceError) as caught:
            CHECKER.check_trace(text, REPORT_BYTES)
        if fragment:
            self.assertIn(fragment, str(caught.exception))

    def test_complete_inputs_and_abbreviated_stdout_are_admitted(self):
        CHECKER.check_trace(trace(), REPORT_BYTES)
        lines = fixture_lines()
        lines[-3:-2] = [f'write({OUT}, "first"..., 10) = 10', f'write({OUT}, "second"..., 10) = 10']
        CHECKER.check_trace(trace(lines), REPORT_BYTES)

    def test_inputs_require_two_complete_read_passes_and_exact_rewinds(self):
        for transformation in [
            lambda lines: [line for line in lines if CHECKER.INSTALL not in line or line.startswith("execve")],
            lambda lines: [line for line in lines if not line.startswith("lseek")],
            lambda lines: [line.replace(" = 95632430", " = 95632429") for line in lines],
            lambda lines: [line.replace("SEEK_SET", "SEEK_END") for line in lines],
            lambda lines: [line.replace('"pins", 4) = 4', '"", 4) = 0') for line in lines],
        ]:
            self.reject(trace(transformation(fixture_lines())))

    def test_exact_exec_and_full_arguments_are_required(self):
        for old, new in [
            (CHECKER.PROGRAM, "/build-target/debug/glue-pbs-inspect"),
            (CHECKER.PINS, "/tmp/pins.json"),
            (json.dumps(CHECKER.INSTALL) + "]", json.dumps(CHECKER.INSTALL) + ", ...]"),
            (" = 0\n", " = -1 ENOENT (No such file or directory)\n"),
        ]:
            self.reject(trace().replace(old, new, 1))
        self.reject(extra(fixture_lines()[0]))
        self.reject(extra('execve("/bin/sh", ["sh"], 0x1234 /* 10 vars */) = -1 EACCES (Permission denied)'))

    def test_unknown_calls_threads_network_and_memfds_fail_even_when_rejected(self):
        for call in [
            "unknown_future_syscall(0) = 0",
            "clone(CLONE_VM|CLONE_THREAD, NULL) = -1 EPERM (Operation not permitted)",
            "clone3({}, 64) = -1 ENOSYS (Function not implemented)",
            "socket(AF_INET, SOCK_STREAM, 0) = -1 EPERM (Operation not permitted)",
            'memfd_create("payload", MFD_CLOEXEC) = -1 EPERM (Operation not permitted)',
            "io_uring_setup(8, {}) = -1 EPERM (Operation not permitted)",
            "sendfile(1, 3, NULL, 20) = 20",
            "getpid() = 1234",
        ]:
            with self.subTest(call=call):
                self.reject(extra(call), "unapproved syscall")

    def test_hidden_create_unlink_and_all_mutation_attempts_reject(self):
        for call in [
            'openat(AT_FDCWD</workspace>, "/tmp/payload", O_WRONLY|O_CREAT|O_EXCL, 0600) = 9</tmp/payload>',
            'openat(AT_FDCWD</workspace>, "/tmp/payload", O_WRONLY|O_CREAT, 0600) = -1 EROFS (Read-only file system)',
            'unlink("/tmp/payload") = 0',
            'unlinkat(AT_FDCWD</workspace>, "/tmp/payload", 0) = -1 EPERM (Operation not permitted)',
            'rename("/tmp/a", "/tmp/b") = -1 EROFS (Read-only file system)',
            'mkdir("/tmp/payload", 0700) = 0',
            'truncate("/tmp/payload", 0) = 0',
            'pwrite64(1</evidence/linux/inspection.json>, "x", 1, 0) = 1',
            'ftruncate(1</evidence/linux/inspection.json>, 0) = 0',
        ]:
            with self.subTest(call=call):
                self.reject(extra(call))

    def test_declared_inputs_cannot_be_opened_writable_even_on_failure(self):
        for mode in ["O_RDWR", "O_WRONLY", "O_RDONLY|O_TRUNC", "O_RDONLY|O_CLOEXEC|O_CREAT", "O_PATH"]:
            self.reject(trace().replace("O_RDONLY|O_CLOEXEC", mode, 1))
        self.reject(trace().replace(f" = 3<{CHECKER.PINS}>", " = -1 EACCES (Permission denied)", 1))

    def test_open_paths_and_descriptor_annotations_cannot_be_substituted(self):
        for old, new in [
            (f"3<{CHECKER.PINS}>", "3</tmp/payload>"),
            (f"3<{CHECKER.PINS}>", "3"),
            (f"3<{CHECKER.PINS}>", f"3<{CHECKER.PINS}>(deleted)"),
            ("AT_FDCWD</workspace>", "AT_FDCWD</tmp>"),
        ]:
            self.reject(trace().replace(old, new))
        self.reject(extra('openat(AT_FDCWD</workspace>, "/usr/bin/python3", O_RDONLY|O_CLOEXEC) = 3</usr/bin/python3>'))
        self.reject(extra('openat(AT_FDCWD</workspace>, "/etc/ld.so.cache"..., O_RDONLY|O_CLOEXEC) = 3</etc/ld.so.cache>'))

    def test_closed_and_never_opened_descriptors_cannot_be_read(self):
        for fd in [f"3<{CHECKER.PINS}>", "9</etc/ld.so.cache>", "0</dev/null>", f"1<{CHECKER.STDOUT}>", "9" * 5000 + "</etc/ld.so.cache>", "2147483648</etc/ld.so.cache>"]:
            self.reject(extra(f'read({fd}, "x", 1) = 1'))
        self.reject(extra(f"close({OUT}) = 0"))

    def test_only_unchanged_inherited_stdout_receives_successful_writes(self):
        for fd in ["1", "1</tmp/payload>", f"1<{CHECKER.STDOUT}>(deleted)", f"2<{CHECKER.STDERR}>", f"9<{CHECKER.STDOUT}>"]:
            self.reject(trace().replace(OUT, fd))
        for suffix in [" = 19", " = -1 EIO (Input/output error)", " = ?"]:
            self.reject(trace().replace(f" = {REPORT_BYTES}\n", suffix + "\n"))
        self.reject(trace().replace(f", {REPORT_BYTES})", ", 19)"))
        self.reject(trace([line for line in fixture_lines() if not line.startswith("write")]))
        self.reject(extra(f'write({OUT}, "x", 1) = 1'))
        self.reject(extra(f'writev({OUT}, [{{iov_base="x", iov_len=1}}], 1) = 1'))
        for size in [0, -1, CHECKER.MAX_STDOUT_BYTES + 1]:
            with self.assertRaises(CHECKER.TraceError):
                CHECKER.check_trace(trace(), size)

    def test_no_payload_shared_or_executable_anonymous_mappings(self):
        for call in [
            "mmap(NULL, 4096, PROT_READ, MAP_SHARED|MAP_ANONYMOUS, -1, 0) = 0x1000",
            "mmap(NULL, 4096, PROT_READ|PROT_EXEC, MAP_PRIVATE|MAP_ANONYMOUS, -1, 0) = -1 EPERM (Operation not permitted)",
            "mmap(NULL, 4096, PROT_READ|PROT_WRITE|PROT_EXEC, MAP_PRIVATE|MAP_ANONYMOUS, -1, 0) = 0x1000",
            f"mmap(NULL, 4096, PROT_READ, MAP_PRIVATE, 3<{CHECKER.FULL}>, 0) = 0x1000",
            "mprotect(0x1000, 4096, PROT_READ|PROT_EXEC) = -1 EACCES (Permission denied)",
            "mmap(NULL, 4096, PROT_READ, MAP_SHARED_VALIDATE, 3</etc/ld.so.cache>, 0) = 0x1000",
        ]:
            self.reject(extra(call))
        CHECKER.check_trace(extra("mmap(NULL, 4096, PROT_READ|PROT_WRITE, MAP_PRIVATE|MAP_ANONYMOUS, -1, 0) = 0x1000"), REPORT_BYTES)

    def test_os_startup_libraries_require_known_opens_and_private_mappings(self):
        lines = fixture_lines()
        calls = [
            'openat(AT_FDCWD</workspace>, "/lib/aarch64-linux-gnu/libc.so.6", O_RDONLY|O_CLOEXEC) = 5</usr/lib/aarch64-linux-gnu/libc.so.6>',
            "mmap(NULL, 4096, PROT_READ|PROT_EXEC, MAP_PRIVATE, 5</usr/lib/aarch64-linux-gnu/libc.so.6>, 0) = 0x1000",
            "close(5</usr/lib/aarch64-linux-gnu/libc.so.6>) = 0",
        ]
        lines[1:1] = calls
        CHECKER.check_trace(trace(lines), REPORT_BYTES)
        self.reject(trace(lines).replace("PROT_READ|PROT_EXEC", "PROT_READ|PROT_WRITE|PROT_EXEC"))
        self.reject(trace(lines).replace("MAP_PRIVATE", "MAP_SHARED"))
        self.reject(trace(lines).replace("5</usr/lib/aarch64-linux-gnu/libc.so.6>", "5</usr/lib/aarch64-linux-gnu/libpython3.13.so>"))

    def test_self_maps_read_cannot_target_another_process(self):
        lines = fixture_lines()
        lines[1:1] = [
            'openat(AT_FDCWD</workspace>, "/proc/self/maps", O_RDONLY|O_CLOEXEC) = 5</proc/1234/maps>',
            'read(5</proc/1234/maps>, "maps", 4) = 4',
            'close(5</proc/1234/maps>) = 0',
        ]
        CHECKER.check_trace(trace(lines), REPORT_BYTES)
        self.reject(trace(lines).replace("/proc/1234/maps", "/proc/9999/maps"))
        self.reject(trace(lines).replace('"/proc/self/maps"', '"/proc/9999/maps"'))

    def test_metadata_queries_and_resource_limits_cannot_target_paths_or_mutate(self):
        for call in [
            'newfstatat(AT_FDCWD</workspace>, "/tmp/payload", {st_mode=S_IFREG|0644}, 0) = 0',
            'prlimit64(1235, RLIMIT_STACK, NULL, {rlim_cur=8192}) = 0',
            'prlimit64(0, RLIMIT_STACK, {rlim_cur=1}, NULL) = 0',
            'faccessat(AT_FDCWD</workspace>, "/tmp/payload", W_OK) = 0',
            'fcntl(1</evidence/linux/inspection.json>, F_DUPFD, 3) = 3',
            'ioctl(1</evidence/linux/inspection.json>, FICLONE, 3) = 0',
        ]:
            self.reject(extra(call))

    def test_incomplete_additional_process_and_post_exit_records_reject(self):
        original = trace()
        for text in [
            original.replace("1234  exit_group", "1235  exit_group"),
            original.replace("1234  ", "", 1),
            original.replace("1234  ", "0  ", 1),
            original.replace("1234  ", "12345678901  ", 1),
            original.replace("exit_group(0)", "exit_group(1)"),
            original.replace("+++ exited with 0 +++", "+++ killed by SIGSEGV +++"),
            original.rsplit("\n", 1)[0],
            original + '1234  brk(NULL) = 0x1000\n',
            original.replace("+++ exited with 0 +++\n", ""),
            original.replace("exit_group(0) = ?\n", ""),
            original.replace('"pins", 4) = 4', '"pins", 4 <unfinished ...>'),
            original.replace('"pins", 4) = 4', '"pins", 4) = ?'),
            original.replace('"pins", 4) = 4', '"pins, 4) = 4'),
        ]:
            self.reject(text)

    def test_byte_line_record_bounds_and_strict_utf8(self):
        with patch.object(CHECKER, "MAX_TRACE_BYTES", len(trace().encode()) - 1):
            self.reject(trace(), "bound")
        with patch.object(CHECKER, "MAX_LINE_CHARACTERS", 10):
            self.reject(trace(), "bound")
        with patch.object(CHECKER, "MAX_RECORDS", 2):
            self.reject(trace(), "bound")
        self.reject(trace().replace("\n", "\r\n", 1))
        self.reject(trace().replace("pins", "\ud800", 1), "UTF-8")

    def test_streaming_raw_and_gzip_files_require_complete_valid_bounded_bytes(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            for name, data in [("trace.txt", trace().encode()), ("trace.txt.gz", gzip.compress(trace().encode(), mtime=0))]:
                path = root / name
                path.write_bytes(data)
                CHECKER.check_file(path, REPORT_BYTES)
            compressed = root / "trace.txt.gz"
            compressed.write_bytes(gzip.compress(trace().encode(), mtime=0))
            with patch.object(CHECKER, "MAX_TRACE_BYTES", len(trace().encode()) - 1):
                with self.assertRaises(CHECKER.TraceError):
                    CHECKER.check_file(compressed, REPORT_BYTES)
            with patch.object(CHECKER, "MAX_LINE_CHARACTERS", 10):
                with self.assertRaises(CHECKER.TraceError):
                    CHECKER.check_file(compressed, REPORT_BYTES)
            for raw in [trace().encode() + b"\xff\n", trace().encode()[:-1]]:
                compressed.write_bytes(gzip.compress(raw, mtime=0))
                with self.assertRaises(CHECKER.TraceError):
                    CHECKER.check_file(compressed, REPORT_BYTES)
            compressed.write_bytes(gzip.compress(trace().encode(), mtime=0)[:-4])
            with self.assertRaises((EOFError, OSError)):
                CHECKER.check_file(compressed, REPORT_BYTES)

    def test_cli_uses_retained_report_size_and_reports_rejection(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            path = root / "trace.txt.gz"
            path.write_bytes(gzip.compress(trace().encode(), mtime=0))
            report = root / "inspection.json"
            report.write_bytes(b"x" * REPORT_BYTES)
            command = [sys.executable, str(SCRIPT), str(path), "--stdout-file", str(report)]
            result = subprocess.run(command, capture_output=True, text=True, check=False)
            self.assertEqual(result.returncode, 0, result.stderr)
            report.write_bytes(b"x" * (REPORT_BYTES - 1))
            result = subprocess.run(command, capture_output=True, text=True, check=False)
            self.assertEqual(result.returncode, 1)
            self.assertIn("rejected", result.stderr)


if __name__ == "__main__":
    unittest.main()
