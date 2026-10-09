"""Adversarial checks for the exact relocated source-only Lua trace policy."""

import importlib.util
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest


SCRIPT = Path(__file__).with_name("check-linux-lua-trace.py")
SPEC = importlib.util.spec_from_file_location("lua_trace_checker", SCRIPT)
assert SPEC is not None and SPEC.loader is not None
CHECKER = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(CHECKER)

PROGRAM = CHECKER.PROGRAM
ARCHIVE = CHECKER.ARCHIVE
STDOUT = f"1<{CHECKER.STDOUT}>"
STDERR = f"2<{CHECKER.STDERR}>"
LIBRARY = "/usr/lib/aarch64-linux-gnu/libc.so.6"
EXEC = f'execve({json.dumps(PROGRAM)}, [{json.dumps(PROGRAM)}, "run", {json.dumps(ARCHIVE)}], 0x1234 /* 10 vars */) = 0'


def output_call(data=None, version="5.4"):
    data = CHECKER.expected_stdout(version) if data is None else data
    return f"write({STDOUT}, {json.dumps(data)}, {len(data)}) = {len(data)}"


def fixture_lines(version="5.4"):
    return [
        EXEC,
        'openat(AT_FDCWD</build-target/relocated Lua fixture>, "/lib/aarch64-linux-gnu/libc.so.6", O_RDONLY|O_CLOEXEC) = 3<' + LIBRARY + '>',
        f'mmap(NULL, 4096, PROT_READ|PROT_EXEC, MAP_PRIVATE, 3<{LIBRARY}>, 0) = 0x1000',
        f"close(3<{LIBRARY}>) = 0",
        f"openat(AT_FDCWD</build-target/relocated Lua fixture>, {json.dumps(ARCHIVE)}, O_RDONLY|O_CLOEXEC) = 3<{ARCHIVE}>",
        f'read(3<{ARCHIVE}>, "quoted data: \\\"a,b\\\" ) = 0"..., 64) = 64',
        "mmap(NULL, 4096, PROT_READ|PROT_WRITE, MAP_PRIVATE|MAP_ANONYMOUS, -1, 0) = 0x2000",
        output_call(version=version),
        f"close(3<{ARCHIVE}>) = 0",
        "exit_group(0) = ?",
        "+++ exited with 0 +++",
    ]


def trace(lines=None, pid=None):
    lines = fixture_lines() if lines is None else lines
    prefix = "" if pid is None else f"{pid}  "
    return "\n".join(prefix + line for line in lines) + "\n"


def extra(call):
    lines = fixture_lines()
    lines.insert(-3, call)
    return trace(lines)


class LuaTracePolicyTests(unittest.TestCase):
    def reject(self, text, message=None):
        with self.assertRaises(CHECKER.TraceError) as context:
            CHECKER.check_trace(text)
        if message is not None:
            self.assertIn(message, str(context.exception))

    def test_complete_trace_handles_numeric_pid_and_fragmented_stdout(self):
        CHECKER.check_trace(trace())
        CHECKER.check_trace(trace(pid=42))
        lines = fixture_lines()
        index = lines.index(output_call())
        message = CHECKER.expected_stdout()
        lines[index:index + 1] = [output_call(message[:8]), output_call(message[8:])]
        CHECKER.check_trace(trace(lines))

    def test_version_is_explicit_and_exact(self):
        text = trace(fixture_lines("5.5"))
        self.reject(text)
        CHECKER.check_trace(text, "5.5")
        with self.assertRaises(CHECKER.TraceError):
            CHECKER.check_trace(trace(), "unknown")

    def test_exec_must_name_the_exact_launcher_archive_and_operation(self):
        for replacement in [
            EXEC.replace(PROGRAM, "/bin/echo"),
            EXEC.replace('"run"', '"cat"'),
            EXEC.replace(ARCHIVE, "/workspace/app.glue"),
            EXEC.replace(", 0x1234", ', "unexpected", 0x1234'),
            EXEC.replace(" = 0", " = -1 ENOENT (No such file or directory)"),
        ]:
            with self.subTest(replacement=replacement):
                self.reject(trace([replacement, *fixture_lines()[1:]]))
        self.reject(extra(EXEC))

    def test_extra_processes_threads_and_incomplete_records_fail_closed(self):
        lines = fixture_lines()
        prefixed = [f"42  {line}" for line in lines]
        prefixed[5] = "43  " + lines[5]
        self.reject("\n".join(prefixed))
        for call in [
            "clone(child_stack=NULL, flags=CLONE_VM|CLONE_THREAD) = 43",
            "fork() = 43",
            "read(3,  <unfinished ...>",
            "<... read resumed>) = 1",
            "--- SIGSEGV {si_signo=SIGSEGV} ---",
            "unexpected text",
            "mprotect(NULL, 4096) = 0",
            "brk(NULL) = ?",
        ]:
            with self.subTest(call=call):
                self.reject(extra(call))
        self.reject(trace(lines[:-1]))
        self.reject(trace(lines[1:]))
        self.reject(trace([*lines, "getpid() = 42"]))

    def test_all_file_mutation_attempts_are_rejected_even_if_unsuccessful(self):
        for call in [
            'openat(AT_FDCWD, "/tmp/payload.lua", O_WRONLY|O_CREAT|O_TRUNC, 0600) = -1 EROFS (Read-only file system)',
            f'open({json.dumps(ARCHIVE)}, O_RDONLY|O_CREAT, 0600) = 4<{ARCHIVE}>',
            f'write(3<{ARCHIVE}>, "payload", 7) = -1 EBADF (Bad file descriptor)',
            f'pwrite64(3<{ARCHIVE}>, "payload", 7, 0) = 7',
            f'writev(3<{ARCHIVE}>, [{{iov_base="payload", iov_len=7}}], 1) = 7',
            f'ftruncate(3<{ARCHIVE}>, 0) = 0',
            'truncate("/tmp/payload", 0) = 0',
            'unlink("/tmp/payload") = 0',
            'rename("/tmp/a", "/tmp/b") = 0',
            'mkdir("/tmp/payload", 0700) = 0',
            'chmod("/tmp/payload", 0600) = 0',
            'utimensat(AT_FDCWD, "/tmp/payload", NULL, 0) = 0',
            'mount("none", "/tmp", "tmpfs", 0, NULL) = 0',
            'symlink("/tmp/a", "/tmp/b") = 0',
            'link("/tmp/a", "/tmp/b") = 0',
            'setxattr("/tmp/payload", "user.payload", "x", 1, 0) = 0',
            'fallocate(3, 0, 0, 4096) = 0',
            'openat2(AT_FDCWD, "/tmp/payload", {flags=O_TMPFILE|O_RDWR, mode=0600}, 24) = 4',
        ]:
            with self.subTest(call=call):
                self.reject(extra(call))

    def test_transfer_and_kernel_async_io_paths_are_unapproved(self):
        for call in [
            "sendfile(1, 3, NULL, 4096) = 4096",
            "copy_file_range(3, NULL, 4, NULL, 4096, 0) = 4096",
            "splice(3, NULL, 4, NULL, 4096, 0) = 4096",
            "tee(3, 4, 4096, 0) = 4096",
            "vmsplice(4, [{iov_base=\"payload\", iov_len=7}], 1, 0) = 7",
            "io_uring_setup(8, {}) = 4",
            "io_uring_enter(4, 1, 1, 0, NULL, 0) = 1",
            "io_setup(8, [0x1000]) = 0",
            "io_submit(0x1000, 1, []) = 1",
            'socket(AF_UNIX, SOCK_STREAM, 0) = 4',
            'dup2(3, 1) = 1',
        ]:
            with self.subTest(call=call):
                self.reject(extra(call))

    def test_native_memory_objects_and_shared_or_payload_mappings_are_rejected(self):
        for call in [
            'memfd_create("glue-probe-module", MFD_CLOEXEC|MFD_ALLOW_SEALING|MFD_EXEC) = 4</memfd:glue-probe-module>(deleted)',
            'memfd_create("anything", 0) = -1 EPERM (Operation not permitted)',
            'shmget(IPC_PRIVATE, 4096, IPC_CREAT|0600) = 1',
            f'mmap(NULL, 4096, PROT_READ, MAP_SHARED, 3<{ARCHIVE}>, 0) = 0x1000',
            'mmap(NULL, 4096, PROT_READ|PROT_WRITE, MAP_SHARED|MAP_ANONYMOUS, -1, 0) = 0x1000',
            f'mmap(NULL, 4096, PROT_READ|PROT_EXEC, MAP_PRIVATE, 3<{ARCHIVE}>, 0) = 0x1000',
            'mmap(NULL, 4096, PROT_READ|PROT_EXEC, MAP_PRIVATE|MAP_ANONYMOUS, -1, 0) = 0x1000',
            'mmap(NULL, 4096, PROT_READ, MAP_PRIVATE|MAP_ANONYMOUS, 3, 0) = 0x1000',
            'mprotect(0x1000, 4096, PROT_READ|PROT_EXEC) = 0',
            'fcntl(3, F_ADD_SEALS, F_SEAL_WRITE) = 0',
        ]:
            with self.subTest(call=call):
                self.reject(extra(call))

    def test_no_host_source_dependency_cache_or_device_reads(self):
        for path in [
            "/workspace/fixtures/lua-linked/input/app/main.lua", "/tmp/module.lua",
            "/usr/local/share/lua/5.4/module.lua", "/usr/lib/aarch64-linux-gnu/liblua5.4.so",
            "/root/.cache/payload", "/proc/self/fd/4", "/dev/shm/module",
            "/dev/zero", "/proc/999/maps", "/etc/passwd",
        ]:
            with self.subTest(path=path):
                self.reject(extra(f'openat(AT_FDCWD, {json.dumps(path)}, O_RDONLY) = -1 ENOENT (No such file or directory)'))
                self.reject(extra(f'access({json.dumps(path)}, R_OK) = 0'))
        self.reject(extra('read(4</tmp/module.lua>, "source", 6) = 6'))
        self.reject(extra('read(0</dev/null<char 1:3>>, "", 0) = 0'))

    def test_stdout_is_exact_and_other_descriptors_cannot_receive_payloads(self):
        success = output_call()
        message = CHECKER.expected_stdout()
        for invalid in [
            f'write({STDERR}, "", 0) = 0',
            f'write({STDERR}, {json.dumps(message)}, {len(message)}) = {len(message)}',
            f'write(1, {json.dumps(message)}, {len(message)}) = {len(message)}',
            f'write(1</tmp/payload>, {json.dumps(message)}, {len(message)}) = {len(message)}',
            f'write(1<{CHECKER.STDOUT}>(deleted), {json.dumps(message)}, {len(message)}) = {len(message)}',
            'write(1</evidence/lua.stdout.txt>, "Lua"..., 59) = 59',
            success.replace(f", {len(message)})", f", {len(message) + 1})"),
            success.replace(f" = {len(message)}", f" = {len(message) - 1}"),
            success.replace(f" = {len(message)}", " = -1 EIO (Input/output error)"),
            output_call(message.replace("answer=42", "answer=0")),
            output_call(message + "payload"),
            output_call("ELF payload"),
            f'writev({STDOUT}, [{{iov_base={json.dumps(message)}, iov_len={len(message)}}}], 1) = {len(message)}',
        ]:
            with self.subTest(invalid=invalid):
                self.reject(trace([invalid if line == success else line for line in fixture_lines()]))
        self.reject(extra(success))
        self.reject(trace([line for line in fixture_lines() if line != success]))
        self.reject(trace([output_call(message[:-1]) if line == success else line for line in fixture_lines()]))

    def test_fd_reuse_requires_a_successful_known_readonly_open(self):
        self.reject(extra(f'read(3</tmp/payload>, "x", 1) = 1'))
        self.reject(extra(f'close(3<{ARCHIVE}>) = 0\nread(3<{ARCHIVE}>, "x", 1) = 1'))
        self.reject(extra(f'openat(AT_FDCWD, {json.dumps(ARCHIVE)}, O_RDONLY) = 1<{ARCHIVE}>'))
        self.reject(extra(f'openat(AT_FDCWD, {json.dumps(ARCHIVE)}, O_RDONLY) = 4</tmp/other>'))

    def test_archive_open_read_and_zero_process_exit_are_required(self):
        lines = fixture_lines()
        no_archive = [line for line in lines if ARCHIVE not in line or line == EXEC]
        self.reject(trace(no_archive))
        self.reject(trace([line for line in lines if not line.startswith("read(")]))
        self.reject(trace([line.replace("exit_group(0)", "exit_group(1)") for line in lines]))
        self.reject(trace([line.replace("exited with 0", "exited with 1") for line in lines]))

    def test_cli_reports_success_and_failure(self):
        with tempfile.TemporaryDirectory(prefix="glue-lua-trace-check-") as directory:
            path = Path(directory) / "trace.txt"
            path.write_text(trace(), encoding="utf-8")
            success = subprocess.run([sys.executable, str(SCRIPT), str(path)], capture_output=True, text=True)
            self.assertEqual(success.returncode, 0, success.stderr)
            self.assertIn("Trace checks passed", success.stdout)
            path.write_text(extra('unlink("/tmp/payload") = 0'), encoding="utf-8")
            failure = subprocess.run([sys.executable, str(SCRIPT), str(path)], capture_output=True, text=True)
            self.assertEqual(failure.returncode, 1)
            self.assertIn("Lua trace rejected", failure.stderr)


if __name__ == "__main__":
    unittest.main()
