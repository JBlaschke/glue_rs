"""Adversarial tests for the exact two-image native Lua evidence policy."""

import importlib.util
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch


SPEC = importlib.util.spec_from_file_location(
    "native_lua_trace_policy", Path(__file__).with_name("check-linux-native-lua-trace.py")
)
assert SPEC is not None and SPEC.loader is not None
CHECKER = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(CHECKER)
PID = "42"
DEP = "glue-lua-native-libglue_lua_dep.so"
MOD = "glue-lua-native-libglue_lua_native.so"
ARCHIVE = CHECKER.ARCHIVE
PROGRAM = CHECKER.PROGRAM
STDOUT = CHECKER.STDOUT
SEALS = "F_SEAL_SEAL|F_SEAL_SHRINK|F_SEAL_GROW|F_SEAL_WRITE"


def output(data=None, version="5.4"):
    message = CHECKER.expected_stdout(version, PID) if data is None else data
    return f"write(1<{STDOUT}>, {json.dumps(message)}, {len(message)}) = {len(message)}"


def image_lines(name, number):
    alias = number + 2
    image = f"{number}</memfd:{name}>(deleted)"
    opened = f"{alias}</memfd:{name}>(deleted)"
    return [
        f'memfd_create({json.dumps(name)}, MFD_CLOEXEC|MFD_ALLOW_SEALING|MFD_EXEC) = {image}',
        f'write({image}, "ELF"..., 1024) = 1024',
        f'fcntl({image}, F_ADD_SEALS, {SEALS}) = 0',
        f'fcntl({image}, F_GET_SEALS) = 0xf (seals F_SEAL_SEAL|F_SEAL_SHRINK|F_SEAL_GROW|F_SEAL_WRITE)',
        f'openat(AT_FDCWD, "/proc/self/fd/{number}", O_RDONLY|O_CLOEXEC) = {opened}',
        f'pread64({opened}, "ELF"..., 64, 0) = 64',
        f'mmap(NULL, 4096, PROT_READ|PROT_EXEC, MAP_PRIVATE|MAP_DENYWRITE, {opened}, 0) = 0x2000',
        f'close({opened}) = 0',
    ]


def lines(version="5.4"):
    return [
        f'execve({json.dumps(PROGRAM)}, [{json.dumps(PROGRAM)}, "run", {json.dumps(ARCHIVE)}], 0x123 /* 10 vars */) = 0',
        f'openat(AT_FDCWD, {json.dumps(ARCHIVE)}, O_RDONLY|O_CLOEXEC) = 3<{ARCHIVE}>',
        f'read(3<{ARCHIVE}>, "GLUERS00"..., 64) = 64',
        *image_lines(DEP, 4)[:4],
        *image_lines(MOD, 5)[:4],
        *image_lines(DEP, 4)[4:],
        *image_lines(MOD, 5)[4:],
        f'getpid() = {PID}',
        output(version=version),
        f'close(3<{ARCHIVE}>) = 0',
        'exit_group(0) = ?',
        '+++ exited with 0 +++',
    ]


def trace(records=None, pid=PID):
    records = lines() if records is None else records
    prefix = "" if pid is None else pid + "  "
    return "\n".join(prefix + record for record in records) + "\n"


def extra(record):
    records = lines()
    records.insert(-3, record)
    return trace(records)


class NativeLuaTraceTests(unittest.TestCase):
    def reject(self, text):
        with self.assertRaises(CHECKER.TraceError):
            CHECKER.check_trace(text)

    def test_two_sealed_local_images_with_exact_version_pid_and_fragmented_stdout(self):
        CHECKER.check_trace(trace())
        CHECKER.check_trace(trace(lines("5.5")), "5.5")
        self.reject(trace(lines("5.5")))
        message = CHECKER.expected_stdout("5.4", PID)
        records = lines()
        index = records.index(output())
        records[index:index + 1] = [output(message[:17]), output(message[17:])]
        CHECKER.check_trace(trace(records))

    def test_missing_creation_seal_read_mapping_or_os_call_fails(self):
        for selector in ("memfd_create", "F_ADD_SEALS", "F_GET_SEALS", "mmap", "getpid"):
            records = [record for record in lines() if selector not in record]
            with self.subTest(selector=selector):
                self.reject(trace(records))
        self.reject(trace(pid=None))
        self.reject(trace([record.replace("getpid() = 42", "getpid() = 43") for record in lines()]))

    def test_failed_or_unknown_memfd_creation_and_implicit_exec_are_rejected(self):
        first = next(record for record in lines() if record.startswith("memfd_create"))
        for replacement in (
            first.replace(DEP, "unknown"),
            first.replace("|MFD_EXEC", ""),
            first.replace("MFD_EXEC", "MFD_NOEXEC_SEAL"),
            first.replace("|MFD_ALLOW_SEALING", ""),
            first.split(" = ")[0] + " = -1 EPERM (Operation not permitted)",
        ):
            records = lines()
            records[records.index(first)] = replacement
            self.reject(trace(records))
        self.reject(extra(first))

    def test_all_seals_must_succeed_and_be_verified_before_alias_or_mapping(self):
        for bad in (
            "F_SEAL_SEAL|F_SEAL_SHRINK|F_SEAL_GROW",
            "F_SEAL_SEAL|F_SEAL_SHRINK|F_SEAL_GROW|0x8",
        ):
            self.reject(trace([record.replace(SEALS, bad) for record in lines()]))
        self.reject(trace([record.replace(" = 0xf", " = 0x7") for record in lines()]))
        records = lines()
        seal = next(record for record in records if "F_ADD_SEALS" in record)
        records[records.index(seal)] = seal[:-1] + "-1 EPERM (Operation not permitted)"
        self.reject(trace(records))
        records = lines()
        verify = next(record for record in records if "F_GET_SEALS" in record)
        records.remove(verify)
        records.insert(-3, verify)
        self.reject(trace(records))

    def test_no_image_can_load_before_the_complete_closure_is_sealed(self):
        records = lines()
        module_creation = next(index for index, record in enumerate(records) if record.startswith("memfd_create") and MOD in record)
        open_alias = next(index for index, record in enumerate(records) if '"/proc/self/fd/4"' in record)
        records.insert(module_creation, records.pop(open_alias))
        self.reject(trace(records))
        records = lines()
        direct_map = f'mmap(NULL, 4096, PROT_READ|PROT_EXEC, MAP_PRIVATE, 4</memfd:{DEP}>(deleted), 0) = 0x2000'
        records.insert(module_creation, direct_map)
        self.reject(trace(records))

    def test_memfd_alias_identity_and_process_are_not_path_fallbacks(self):
        for replacement in (
            'openat(AT_FDCWD, "/proc/99/fd/4", O_RDONLY) = 6</memfd:' + DEP + '>(deleted)',
            'openat(AT_FDCWD, "/proc/self/fd/99", O_RDONLY) = 6</memfd:' + DEP + '>(deleted)',
            'openat(AT_FDCWD, "/proc/self/fd/4", O_RDONLY) = 6</memfd:' + MOD + '>(deleted)',
            'openat(AT_FDCWD, "/proc/self/fd/4", O_RDWR) = 6</memfd:' + DEP + '>(deleted)',
            'openat(AT_FDCWD, "/proc/self/fd/4", O_RDONLY) = -1 ENOENT (No such file or directory)',
        ):
            records = lines()
            index = next(index for index, record in enumerate(records) if '"/proc/self/fd/4"' in record)
            records[index] = replacement
            self.reject(trace(records))

    def test_sealed_image_mutations_fail_even_when_kernel_rejects_them(self):
        image = f'4</memfd:{DEP}>(deleted)'
        for call in (
            f'write({image}, "x", 1) = -1 EPERM (Operation not permitted)',
            f'pwrite64({image}, "x", 1, 0) = 1',
            f'writev({image}, [{{iov_base="x", iov_len=1}}], 1) = 1',
            f'ftruncate({image}, 0) = 0',
        ):
            self.reject(extra(call))

    def test_filesystem_mutations_and_shared_or_anonymous_code_maps_are_rejected(self):
        for call in (
            'openat(AT_FDCWD, "/tmp/module.so", O_WRONLY|O_CREAT, 0600) = -1 EROFS (Read-only file system)',
            f'write(3<{ARCHIVE}>, "x", 1) = 1',
            'unlink("/tmp/module.so") = 0',
            'rename("/tmp/a", "/tmp/b") = 0',
            f'mmap(NULL, 4096, PROT_READ, MAP_SHARED, 4</memfd:{DEP}>(deleted), 0) = 0x3000',
            f'mmap(NULL, 4096, PROT_READ|PROT_WRITE|PROT_EXEC, MAP_PRIVATE, 4</memfd:{DEP}>(deleted), 0) = 0x3000',
            'mmap(NULL, 4096, PROT_READ|PROT_EXEC, MAP_PRIVATE|MAP_ANONYMOUS, -1, 0) = 0x3000',
            'mprotect(0x3000, 4096, PROT_READ|PROT_EXEC) = 0',
        ):
            self.reject(extra(call))

    def test_host_sources_lua_libraries_and_soname_search_fallbacks_are_rejected(self):
        for path in (
            "/workspace/fixtures/native/lua-linux/input/app/main.lua",
            "/build-target/native-input/native/libglue_lua_native.so",
            "/lib/aarch64-linux-gnu/liblua5.4.so",
            "/lib/aarch64-linux-gnu/libglue_lua_dep.so",
            "/etc/passwd",
        ):
            self.reject(extra(f'openat(AT_FDCWD, {json.dumps(path)}, O_RDONLY) = -1 ENOENT (No such file or directory)'))

    def test_stdout_and_pid_must_match_the_complete_success_record(self):
        message = CHECKER.expected_stdout("5.4", PID)
        for bad in (message.replace("pid=42", "pid=99"), message.replace("errors=2", "errors=0"), message + "extra\n"):
            self.reject(trace([output(bad) if record == output() else record for record in lines()]))
        self.reject(extra('write(2</evidence/native-lua.stderr.txt>, "unexpected", 10) = 10'))

    def test_extra_processes_unknown_and_incomplete_operations_fail_closed(self):
        for call in (
            "clone(child_stack=NULL, flags=CLONE_THREAD) = 43", "fork() = 43",
            "sendfile(1, 4, NULL, 1024) = 1024", "io_uring_setup(8, {}) = 4",
            "dup2(4, 1) = 1", "getpid() = ?", "read(3, <unfinished ...>",
        ):
            self.reject(extra(call))
        self.reject(trace(lines()[:-1]))
        self.reject(trace([*lines(), "getpid() = 42"]))
        self.reject(trace().replace("42  getpid()", "43  getpid()"))

    def test_trace_byte_record_and_line_limits_accept_boundaries_and_reject_excess(self):
        text = trace()
        with patch.object(CHECKER, "MAX_TRACE_BYTES", len(text.encode("utf-8"))):
            CHECKER.check_trace(text)
            self.reject(text + "\n")
        with patch.object(CHECKER, "MAX_TRACE_BYTES", 15):
            with self.assertRaisesRegex(CHECKER.TraceError, "byte limit"):
                CHECKER.check_trace("é" * 10)
        records = text.splitlines()
        with patch.object(CHECKER, "MAX_RECORDS", len(records)):
            CHECKER.check_trace(text)
        with patch.object(CHECKER, "MAX_RECORDS", len(records) - 1):
            with self.assertRaisesRegex(CHECKER.TraceError, "record limit"):
                CHECKER.check_trace(text)
        largest = max(map(len, records))
        with patch.object(CHECKER, "MAX_LINE_CHARACTERS", largest):
            CHECKER.check_trace(text)
        with patch.object(CHECKER, "MAX_LINE_CHARACTERS", largest - 1):
            with self.assertRaisesRegex(CHECKER.TraceError, "line limit"):
                CHECKER.check_trace(text)

    def test_file_read_is_bounded_before_utf8_decode(self):
        with tempfile.TemporaryDirectory(prefix="glue-native-trace-") as directory:
            path = Path(directory) / "trace.txt"
            with patch.object(CHECKER, "MAX_TRACE_BYTES", 16):
                path.write_bytes(b"x" * 16)
                self.assertEqual(CHECKER.read_trace(path), "x" * 16)
                path.write_bytes(b"\xff" * 17)
                with self.assertRaisesRegex(CHECKER.TraceError, "byte limit"):
                    CHECKER.read_trace(path)
                path.write_bytes(b"\xff")
                with self.assertRaises(UnicodeError):
                    CHECKER.read_trace(path)

    def test_pid_is_bounded_ascii_positive_canonical_decimal(self):
        for pid in ("", "0", "-1", "0042", "٤٢", "1" * 11):
            with self.subTest(pid=pid):
                with self.assertRaises(CHECKER.TraceError):
                    CHECKER.expected_stdout("5.4", pid)
        self.assertIn("pid=9999999999", CHECKER.expected_stdout("5.4", "9999999999"))
        self.reject(trace(pid="1" * 11))

    def test_numeric_parser_failures_become_trace_errors(self):
        # This decimal exceeds Python's default conversion digit cap while
        # remaining under the policy's per-record bound.
        with self.assertRaises(CHECKER.TraceError):
            CHECKER.check_trace(extra("getpid() = " + "9" * 5000))


if __name__ == "__main__":
    unittest.main()
