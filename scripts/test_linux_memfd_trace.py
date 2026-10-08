"""Adversarial tests for the narrow, fail-closed native fixture trace policy."""

import importlib.util
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest


SCRIPT = Path(__file__).with_name("check-linux-memfd-trace.py")
SPEC = importlib.util.spec_from_file_location("memfd_trace_checker", SCRIPT)
assert SPEC is not None and SPEC.loader is not None
CHECKER = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(CHECKER)

EXEC = 'execve("/build-target/debug/glue-linux-memfd-probe", ["probe", "run", "/evidence/app.glue"], 0x1234 /* 10 vars */) = 0'
DEPENDENCY = "4</memfd:glue-probe-dependency>(deleted)"
MODULE = "5</memfd:glue-probe-module>(deleted)"
SEALS = "F_SEAL_SEAL|F_SEAL_SHRINK|F_SEAL_GROW|F_SEAL_WRITE"
STDOUT = "1</evidence/probe.stdout.txt>"
STDERR = "2</evidence/probe.stderr.txt>"


def success_message(machine="aarch64"):
    return (
        f"PASS answer=42 data=7 constructors=1 machine={machine} "
        "dependency_seals=0xf module_seals=0xf mechanism=sealed-memfd+/proc/self/fd "
        "runtime=unacquired-fixture-scaffold\n"
    )


def success_call(machine="aarch64"):
    message = success_message(machine)
    count = len(message.encode("ascii"))
    return f"write({STDOUT}, {json.dumps(message)}, {count}) = {count}"


def fixture_lines():
    return [
        EXEC,
        'openat(AT_FDCWD</workspace>, "/evidence/app.glue", O_RDONLY|O_CLOEXEC) = 3</evidence/app.glue>',
        'read(3</evidence/app.glue>, "quoted data: \\\"a,b\\\" ) = 0", 64) = 64',
        "mmap(NULL, 4096, PROT_READ|PROT_WRITE, MAP_PRIVATE|MAP_ANONYMOUS, -1, 0) = 0x1000",
        'memfd_create("glue-probe-dependency", MFD_CLOEXEC|MFD_ALLOW_SEALING|0x10) = ' + DEPENDENCY,
        f'write({DEPENDENCY}, "ELF"..., 1000) = 1000',
        f"fcntl({DEPENDENCY}, F_ADD_SEALS, {SEALS}) = 0",
        f"fcntl({DEPENDENCY}, F_GET_SEALS) = 0xf (seals {SEALS})",
        'memfd_create("glue-probe-module", MFD_CLOEXEC|MFD_ALLOW_SEALING|MFD_EXEC) = ' + MODULE,
        f'pwrite64({MODULE}, "ELF", 3, 0) = 3',
        f"fcntl({MODULE}, F_ADD_SEALS, {SEALS}) = 0",
        f"fcntl({MODULE}, F_GET_SEALS) = 0xf (seals {SEALS})",
        'openat(AT_FDCWD</workspace>, "/proc/self/fd/4", O_RDONLY|O_CLOEXEC) = 6</memfd:glue-probe-dependency>(deleted)',
        "mmap(NULL, 4096, PROT_READ|PROT_EXEC, MAP_PRIVATE, 6</memfd:glue-probe-dependency>(deleted), 0) = 0x2000",
        success_call(),
        "fcntl(3</evidence/app.glue>, F_GETFD) = 0x1 (flags FD_CLOEXEC)",
        "exit_group(0) = ?",
        "+++ exited with 0 +++",
    ]


def trace(lines=None, pid=None):
    lines = fixture_lines() if lines is None else lines
    prefix = "" if pid is None else f"{pid}  "
    return "\n".join(prefix + line for line in lines) + "\n"


def extra_call(call):
    lines = fixture_lines()
    lines.insert(-2, call)
    return trace(lines)


class TracePolicyTests(unittest.TestCase):
    def reject(self, text, message=None):
        with self.assertRaises(CHECKER.TraceError) as context:
            CHECKER.check_trace(text)
        if message is not None:
            self.assertIn(message, str(context.exception))

    def test_complete_fixture_with_and_without_numeric_pid(self):
        CHECKER.check_trace(trace())
        CHECKER.check_trace(trace(pid=2564))
        CHECKER.check_trace(trace([
            success_call("x86_64") if line == success_call() else line
            for line in fixture_lines()
        ]))

    def test_stdout_only_admits_one_exact_complete_success_diagnostic(self):
        message = success_message()
        count = len(message.encode("ascii"))
        for invalid in [
            f'write({STDOUT}, "\\177ELF", 4) = 4',
            f'write({STDOUT}, "arbitrary data", 14) = 14',
            f'write({STDOUT}, {json.dumps(message + "payload")}, {count + 7}) = {count + 7}',
            f'write({STDOUT}, {json.dumps(message[:-1])}, {count - 1}) = {count - 1}',
            f'write({STDOUT}, "PASS"..., {count}) = {count}',
            f'write({STDOUT}, {json.dumps(message)}, {count + 1}) = {count}',
            f'write({STDOUT}, {json.dumps(message)}, {count}) = {count - 1}',
            f'write({STDOUT}, {json.dumps(message)}, {count}) = -1 EIO (Input/output error)',
            f'writev({STDOUT}, [{{iov_base={json.dumps(message)}, iov_len={count}}}], 1) = {count}',
            success_call(),
        ]:
            with self.subTest(invalid=invalid):
                # Exercise the first sink write itself: the otherwise valid
                # trace's expected PASS is appended after the injected bytes.
                lines = fixture_lines()
                lines.insert(lines.index(success_call()), invalid)
                self.reject(trace(lines))
        self.reject(trace([line for line in fixture_lines() if line != success_call()]))
        for altered in [
            message.replace("answer=42", "answer=0"),
            message.replace("machine=aarch64", "machine=unknown"),
            message.replace("constructors=1", "constructors=2"),
            message.replace("dependency_seals=0xf", "dependency_seals=0x7"),
        ]:
            invalid = f"write({STDOUT}, {json.dumps(altered)}, {len(altered)}) = {len(altered)}"
            self.reject(trace([
                invalid if line == success_call() else line for line in fixture_lines()
            ]))

    def test_stderr_receives_no_bytes_in_a_success_trace(self):
        for call in [
            f'write({STDERR}, "ELF", 3) = 3',
            f'write({STDERR}, "", 0) = 0',
            f'write({STDERR}, {json.dumps(success_message())}, 164) = 164',
            f'writev({STDERR}, [{{iov_base="note", iov_len=4}}], 1) = 4',
        ]:
            with self.subTest(call=call):
                self.reject(extra_call(call))

    def test_created_memfd_writes_and_harmless_queries_are_allowed(self):
        for call in [
            f"ftruncate({MODULE}, 4096) = 0",
            f'pwritev({MODULE}, [{{iov_base="data", iov_len=4}}], 1, 0) = 4',
            f'pwritev2({MODULE}, [{{iov_base="data", iov_len=4}}], 1, 0, 0) = 4',
            "ioctl(1</evidence/probe.stdout.txt>, TCGETS, 0x1234) = -1 ENOTTY (Inappropriate ioctl for device)",
            "prlimit64(0, RLIMIT_STACK, NULL, {rlim_cur=8192*1024, rlim_max=RLIM64_INFINITY}) = 0",
            "getrandom(\"random\", 6, GRND_NONBLOCK) = 6",
            "ppoll([{fd=0</dev/null<char 1:3>>, events=0}, {fd=1</evidence/probe.stdout.txt>, events=0}, {fd=2</evidence/probe.stderr.txt>, events=0}], 3, {tv_sec=0, tv_nsec=0}, NULL, 0) = 0 (Timeout)",
        ]:
            with self.subTest(call=call):
                CHECKER.check_trace(extra_call(call))

    def test_writes_require_known_memfds_or_exact_evidence_sinks(self):
        for descriptor in [
            "0", "0</tmp/payload>", "1", "2", "7", "7</tmp/payload>",
            "1</tmp/payload>", "2</tmp/payload>",
            "0</evidence/probe.stdout.txt>", "1</evidence/probe.stderr.txt>",
            "2</evidence/probe.stdout.txt>", "1</evidence/probe.stdout.txt>(deleted)",
            "99</memfd:glue-probe-module>(deleted)",
            "4</memfd:glue-probe-unknown>(deleted)",
            "4</memfd:glue-probe-module>(deleted)",
        ]:
            with self.subTest(descriptor=descriptor):
                self.reject(extra_call(f'write({descriptor}, "x", 1) = 1'))
        for syscall, arguments in [
            ("writev", '[{iov_base="x", iov_len=1}], 1'),
            ("pwrite64", '"x", 1, 0'),
            ("pwritev", '[{iov_base="x", iov_len=1}], 1, 0'),
            ("pwritev2", '[{iov_base="x", iov_len=1}], 1, 0, 0'),
            ("ftruncate", "0"),
        ]:
            with self.subTest(syscall=syscall):
                self.reject(extra_call(f"{syscall}(7</tmp/payload>, {arguments}) = 1"))
        self.reject(extra_call(f'pwrite64({STDOUT}, "x", 1, 0) = 1'))
        self.reject(extra_call(f"ftruncate({STDERR}, 0) = 0"))

    def test_failed_unsafe_attempts_still_reject(self):
        for call in [
            'openat(AT_FDCWD</workspace>, "/tmp/payload", O_WRONLY|O_CREAT, 0600) = -1 EROFS (Read-only file system)',
            'open("/tmp/payload", O_RDONLY|O_TRUNC) = -1 EACCES (Permission denied)',
            'write(7</tmp/payload>, "x", 1) = -1 EBADF (Bad file descriptor)',
            'unlink("/tmp/payload") = -1 EROFS (Read-only file system)',
            'mmap(NULL, 4096, PROT_READ, MAP_SHARED, 3</evidence/app.glue>, 0) = -1 EACCES (Permission denied)',
        ]:
            with self.subTest(call=call):
                self.reject(extra_call(call))

    def test_unknown_path_mutation_async_io_and_copy_calls_reject(self):
        for call in [
            "unknown_future_syscall(0) = 0",
            "io_uring_setup(8, 0x1234) = 7",
            "io_setup(8, 0x1234) = 0",
            "sendfile(1</evidence/probe.stdout.txt>, 3</evidence/app.glue>, NULL, 20) = 20",
            "splice(3</evidence/app.glue>, NULL, 7</tmp/payload>, NULL, 20, 0) = 20",
            "copy_file_range(3</evidence/app.glue>, NULL, 7</tmp/payload>, NULL, 20, 0) = 20",
            'rename("old", "new") = 0',
            'mkdir("/tmp/payload", 0700) = 0',
            'truncate("/tmp/payload", 0) = 0',
            "clone(CLONE_VM|CLONE_THREAD, NULL) = 2565",
        ]:
            with self.subTest(call=call):
                self.reject(extra_call(call), "unapproved syscall")

    def test_shared_path_mappings_reject_even_when_read_only(self):
        for protection in ["PROT_READ", "PROT_READ|PROT_WRITE", "PROT_NONE"]:
            self.reject(extra_call(
                f"mmap(NULL, 4096, {protection}, MAP_SHARED, 3</evidence/app.glue>, 0) = 0x1234"
            ))
        self.reject(extra_call("mmap(NULL, 4096, PROT_READ, MAP_SHARED|MAP_ANONYMOUS, -1, 0) = 0x1234"))
        self.reject(extra_call("mmap(NULL, 4096, PROT_READ, MAP_SHARED_VALIDATE, 3</evidence/app.glue>, 0) = 0x1234"))
        CHECKER.check_trace(extra_call(f"mmap(NULL, 4096, PROT_READ, MAP_SHARED, {MODULE}, 0) = 0x1234"))

    def test_only_readonly_fcntl_queries_and_fixture_seals_are_allowed(self):
        for call in [
            "fcntl(3</evidence/app.glue>, F_SETFL, O_APPEND) = 0",
            "fcntl(3</evidence/app.glue>, F_DUPFD, 0) = 7",
            f"fcntl(3</evidence/app.glue>, F_ADD_SEALS, {SEALS}) = 0",
            f"fcntl({MODULE}, F_ADD_SEALS, F_SEAL_WRITE) = 0",
            "ioctl(7</tmp/payload>, FICLONE, 3</evidence/app.glue>) = 0",
            "madvise(0x1234, 4096, MADV_REMOVE) = 0",
            "prlimit64(0, RLIMIT_STACK, {rlim_cur=1, rlim_max=1}, NULL) = 0",
        ]:
            with self.subTest(call=call):
                self.reject(extra_call(call))

    def test_two_distinct_successful_created_descriptors_must_have_all_seals(self):
        original = fixture_lines()
        for change in [
            lambda lines: [line for line in lines if "F_GET_SEALS" not in line],
            lambda lines: [line.replace(" = 0xf (seals", " = 0x7 (seals") for line in lines],
            lambda lines: [line.replace("5</memfd:glue-probe-module>", "4</memfd:glue-probe-module>") for line in lines],
            lambda lines: [line.replace("4</memfd:glue-probe-dependency>", "0</memfd:glue-probe-dependency>") for line in lines],
            lambda lines: [line.replace("glue-probe-module", "glue-probe-dependency") for line in lines],
            lambda lines: [line.replace(f" = {MODULE}", " = -1 EMFILE (Too many open files)") if "memfd_create" in line else line for line in lines],
        ]:
            with self.subTest(change=change):
                self.reject(trace(change(original)))
        # An alias's successful query cannot replace proof for the original fd.
        self.reject(trace([
            line.replace(DEPENDENCY, "6</memfd:glue-probe-dependency>(deleted)")
            if "F_GET_SEALS" in line and DEPENDENCY in line else line
            for line in original
        ]))

    def test_unknown_memfd_aliases_and_closed_descriptors_reject(self):
        self.reject(extra_call('openat(AT_FDCWD</workspace>, "/proc/self/fd/99", O_RDONLY) = 8</memfd:glue-probe-module>(deleted)'))
        self.reject(extra_call('openat(AT_FDCWD</workspace>, "/proc/999/fd/5", O_RDONLY) = 8</memfd:glue-probe-module>(deleted)'))
        lines = fixture_lines()
        lines.insert(-2, f"close({MODULE}) = 0")
        lines.insert(-2, f'write({MODULE}, "x", 1) = -1 EBADF (Bad file descriptor)')
        self.reject(trace(lines))

    def test_each_creation_requires_an_explicit_exec_flag_without_fallback(self):
        for text in [
            trace().replace("|0x10", ""),
            trace().replace("|MFD_EXEC", ""),
            trace().replace("|0x10", "|0x10|MFD_EXEC"),
            trace().replace("|MFD_ALLOW_SEALING", ""),
            trace().replace("MFD_CLOEXEC|", ""),
        ]:
            with self.subTest(text=text):
                self.reject(text)

    def test_unparsed_unfinished_truncated_and_nonzero_exits_reject(self):
        for text in [
            "", trace(fixture_lines()[:-1]), trace(fixture_lines()[:-2]),
            trace(fixture_lines()[1:]),
            trace().replace("exit_group(0)", "exit_group(1)"),
            trace().replace("exited with 0", "exited with 1"),
            trace().replace("exit_group(0) = ?", "exit_group(0) = 0"),
            extra_call("strace: detached"),
            extra_call(""),
            extra_call('write(1</evidence/probe.stdout.txt>, "x", 1 <unfinished ...>'),
            extra_call("<... write resumed>) = 1"),
            extra_call('write(1</evidence/probe.stdout.txt>, "unterminated, 1) = 1'),
            extra_call("getpid() = unexpected-result"),
            trace() + "getpid() = 1\n",
            trace(fixture_lines()[:-2] + ["+++ exited with 0 +++"]),
            extra_call(EXEC),
        ]:
            with self.subTest(text=text):
                self.reject(text)

    def test_additional_process_pid_rejects(self):
        text = trace(pid=2564).replace("2564  exit_group", "2565  exit_group")
        self.reject(text, "additional process")

    def test_cli_reports_failure_without_success_output(self):
        with tempfile.TemporaryDirectory(prefix="glue trace tests ") as directory:
            path = Path(directory) / "probe.trace.txt"
            path.write_text(trace(), encoding="utf-8")
            passed = subprocess.run([sys.executable, str(SCRIPT), str(path)], capture_output=True, text=True, check=False)
            self.assertEqual(passed.returncode, 0, passed.stderr)
            self.assertIn("Trace checks passed", passed.stdout)
            path.write_text(extra_call('write(1</tmp/payload>, "x", 1) = 1'), encoding="utf-8")
            failed = subprocess.run([sys.executable, str(SCRIPT), str(path)], capture_output=True, text=True, check=False)
            self.assertEqual(failed.returncode, 1)
            self.assertEqual(failed.stdout, "")
            self.assertIn("memfd trace rejected", failed.stderr)


if __name__ == "__main__":
    unittest.main()
