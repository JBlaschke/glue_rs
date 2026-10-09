"""Adversarial tests for pre-loader native Lua rejection evidence."""

import importlib.util
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch


SCRIPT = Path(__file__).with_name("check-linux-native-lua-rejections.py")
SPEC = importlib.util.spec_from_file_location("native_lua_rejection_policy", SCRIPT)
assert SPEC is not None and SPEC.loader is not None
CHECKER = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(CHECKER)
CASE = "undeclared-import"


def output(case=CASE, data=None):
    data = CHECKER.expected_stderr(case) if data is None else data
    return f'write(2</evidence/native-rejections/{case}.stderr.txt>, {json.dumps(data)}, {len(data)}) = {len(data)}'


def lines(case=CASE):
    archive = f"/build-target/native-rejections/{case}.glue"
    stdout = f"/evidence/native-rejections/{case}.stdout.txt"
    stderr = f"/evidence/native-rejections/{case}.stderr.txt"
    status = CHECKER.STATUSES[case]
    return [
        f'execve({json.dumps(CHECKER.PROGRAM)}, [{json.dumps(CHECKER.PROGRAM)}, "run", {json.dumps(archive)}], 0x123 /* 10 vars */) = 0',
        f'ppoll([{{fd=0</dev/null<char 1:3>>, events=0}}, {{fd=1<{stdout}>, events=0}}, {{fd=2<{stderr}>, events=0}}], 3, {{tv_sec=0, tv_nsec=0}}, NULL, 0) = 0 (Timeout)',
        f'ioctl(2<{stderr}>, TCGETS, 0x123) = -1 ENOTTY (Inappropriate ioctl for device)',
        f'openat(AT_FDCWD, {json.dumps(archive)}, O_RDONLY|O_CLOEXEC) = 3<{archive}>',
        f'read(3<{archive}>, "GLUERS00"..., 64) = 64',
        output(case),
        f'close(3<{archive}>) = 0',
        f'exit_group({status}) = ?',
        f'+++ exited with {status} +++',
    ]


def trace(records=None, pid="42"):
    records = lines() if records is None else records
    prefix = "" if pid is None else pid + "  "
    return "\n".join(prefix + record for record in records) + "\n"


def extra(call):
    records = lines()
    records.insert(-3, call)
    return trace(records)


def write_records(directory):
    for case in CHECKER.CASES:
        (directory / f"{case}.trace.txt").write_text(trace(lines(case)), encoding="utf-8")
        (directory / f"{case}.exit-status.txt").write_bytes(f"{CHECKER.STATUSES[case]}\n".encode("ascii"))
        (directory / f"{case}.stdout.txt").write_bytes(b"")
        expected = CHECKER.expected_stderr(case).encode("ascii")
        (directory / f"{case}.stderr.txt").write_bytes(expected)
        (directory / f"{case}.expected.stderr.txt").write_bytes(expected)


class NativeRejectionTests(unittest.TestCase):
    def reject(self, text, case=CASE):
        with self.assertRaises(CHECKER.TraceError):
            CHECKER.check_trace(text, case)

    def test_all_six_exact_diagnostics_statuses_and_required_numeric_pid(self):
        for case in CHECKER.CASES:
            with self.subTest(case=case):
                CHECKER.check_trace(trace(lines(case)), case)
                self.reject(trace(lines(case), pid=None), case)

    def test_fragmented_stderr_is_bounded_to_the_exact_diagnostic(self):
        records = lines()
        index = records.index(output())
        expected = CHECKER.expected_stderr(CASE)
        records[index:index + 1] = [output(data=expected[:6]), output(data=expected[6:-1]), output(data="\n")]
        CHECKER.check_trace(trace(records), CASE)
        self.reject(trace([output(data=expected[:-1]) if record == output() else record for record in lines()]))
        self.reject(extra(output()))

    def test_checker_instances_do_not_share_case_paths(self):
        first = CHECKER.Checker("wrong-architecture")
        second = CHECKER.Checker("wrong-initializer")
        for left, right in zip(lines("wrong-architecture"), lines("wrong-initializer")):
            first.line("42  " + left)
            second.line("43  " + right)
        first.finish()
        second.finish()

    def test_stdout_and_arbitrary_or_wrong_sink_stderr_are_rejected(self):
        good = output()
        for bad in [
            good.replace("write(2<", "write(1<"),
            good.replace("2</evidence/native-rejections/undeclared-import.stderr.txt>", "2"),
            good.replace("undeclared-import.stderr.txt", "wrong-initializer.stderr.txt"),
            good.replace(".stderr.txt>", ".stderr.txt>(deleted)"),
            output(data="ELF payload"),
            output(data=CHECKER.expected_stderr(CASE) + "extra"),
            output(data="glue: a different failure\n"),
            output(data=""),
            f'write(1</evidence/native-rejections/{CASE}.stdout.txt>, "", 0) = 0',
            f'writev(2</evidence/native-rejections/{CASE}.stderr.txt>, [{{iov_base="glue: ", iov_len=6}}], 1) = 6',
        ]:
            with self.subTest(bad=bad):
                self.reject(trace([bad if record == good else record for record in lines()]))
        self.reject(extra(output(data="ELF payload")))

    def test_write_counts_results_abbreviations_and_failures_fail_closed(self):
        expected = CHECKER.expected_stderr(CASE)
        good = output()
        for bad in [
            good.replace(f", {len(expected)})", f", {len(expected) + 1})"),
            good.replace(f" = {len(expected)}", f" = {len(expected) - 1}"),
            good.replace(f" = {len(expected)}", " = -1 EIO (Input/output error)"),
            f'write(2</evidence/native-rejections/{CASE}.stderr.txt>, "glue: "..., {len(expected)}) = {len(expected)}',
        ]:
            self.reject(trace([bad if record == good else record for record in lines()]))

    def test_every_memfd_attempt_is_rejected_even_if_failed(self):
        for call in [
            'memfd_create("glue-lua-native-libglue_lua_native.so", MFD_CLOEXEC|MFD_ALLOW_SEALING|MFD_EXEC) = 4</memfd:glue-lua-native-libglue_lua_native.so>(deleted)',
            'memfd_create("anything", 0) = -1 EPERM (Operation not permitted)',
        ]:
            self.reject(extra(call))

    def test_exact_archive_launcher_operation_and_successful_archive_reads_are_required(self):
        records = lines()
        for replacement in [
            records[0].replace(CHECKER.PROGRAM, "/bin/echo"),
            records[0].replace('"run"', '"cat"'),
            records[0].replace(CASE, "wrong-initializer"),
            records[0].replace(" = 0", " = -1 ENOENT (No such file or directory)"),
        ]:
            self.reject(trace([replacement, *records[1:]]))
        self.reject(extra(records[0]))
        self.reject(trace([record for record in records if not record.startswith("read(")]))
        self.reject(trace([record for record in records if not record.startswith("openat(")]))
        self.reject(extra('openat(AT_FDCWD, "/build-target/relocated native Lua fixture/app.glue", O_RDONLY) = -1 ENOENT (No such file or directory)'))

    def test_source_policy_rejects_loader_aliases_mutations_and_shared_maps(self):
        for call in [
            'openat(AT_FDCWD, "/proc/self/fd/4", O_RDONLY) = -1 ENOENT (No such file or directory)',
            'openat(AT_FDCWD, "/tmp/payload.so", O_WRONLY|O_CREAT, 0600) = -1 EROFS (Read-only file system)',
            'unlink("/tmp/payload.so") = -1 ENOENT (No such file or directory)',
            'mmap(NULL, 4096, PROT_READ, MAP_SHARED|MAP_ANONYMOUS, -1, 0) = 0x1234',
            'mmap(NULL, 4096, PROT_READ|PROT_EXEC, MAP_PRIVATE|MAP_ANONYMOUS, -1, 0) = 0x1234',
            'sendfile(2, 3, NULL, 4096) = 4096',
            'io_uring_setup(8, {}) = 4',
            'unknown_syscall() = -1 ENOSYS (Function not implemented)',
        ]:
            self.reject(extra(call))

    def test_exit_must_match_each_case_in_both_complete_records(self):
        for case in CHECKER.CASES:
            status = CHECKER.STATUSES[case]
            wrong = 1 if status == 2 else 2
            for replacement in ["exit_group(0) = ?", f"exit_group({wrong}) = ?", f"exit_group({status}) = 0"]:
                self.reject(trace([replacement if record.startswith("exit_group") else record for record in lines(case)]), case)
            for replacement in ["+++ exited with 0 +++", f"+++ exited with {wrong} +++"]:
                self.reject(trace([replacement if record.startswith("+++") else record for record in lines(case)]), case)
        self.reject(trace(lines()[:-1]))
        self.reject(trace([*lines(), "getpid() = 42"]))
        self.reject(trace([*lines()[:-1], output(), lines()[-1]]))

    def test_extra_processes_bad_pids_and_truncated_records_fail_closed(self):
        for call in ['clone(child_stack=NULL, flags=CLONE_VM|CLONE_THREAD) = 43', 'read(3, <unfinished ...>', '<... read resumed>) = 64', '--- SIGSEGV {si_signo=SIGSEGV} ---', 'unparsed text']:
            self.reject(extra(call))
        records = [f"42  {record}" for record in lines()]
        records[4] = "43  " + lines()[4]
        self.reject("\n".join(records))
        for pid in ["0", "042", "9" * 11]:
            self.reject(trace(pid=pid))

    def test_cost_bounds_and_large_numeric_parser_errors_are_fail_closed(self):
        with patch.object(CHECKER, "MAX_TRACE_BYTES", 16):
            self.reject(trace())
        with patch.object(CHECKER, "MAX_LINE_CHARACTERS", 16):
            self.reject(trace())
        with patch.object(CHECKER, "MAX_RECORDS", 1):
            self.reject(trace())
        self.reject(extra("getpid() = " + "9" * 5000))
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "huge.trace"
            path.write_bytes(b"x" * 17)
            with patch.object(CHECKER.SHARED, "MAX_TRACE_BYTES", 16):
                with self.assertRaises(CHECKER.TraceError):
                    CHECKER.SHARED.read_trace(path)

    def test_records_and_cli_require_all_six_matching_captures(self):
        with tempfile.TemporaryDirectory(prefix="glue native rejection ") as directory:
            directory = Path(directory)
            write_records(directory)
            CHECKER.check_records(directory)
            result = subprocess.run([sys.executable, str(SCRIPT), str(directory)], capture_output=True, text=True)
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertIn("6 exact ELF rejection", result.stdout)
            for suffix, bad in [("exit-status.txt", b"0\n"), ("stdout.txt", b"ELF"), ("stderr.txt", b"different\n"), ("expected.stderr.txt", b"different\n")]:
                write_records(directory)
                (directory / f"{CASE}.{suffix}").write_bytes(bad)
                with self.assertRaises(CHECKER.TraceError):
                    CHECKER.check_records(directory)
            result = subprocess.run([sys.executable, str(SCRIPT), str(directory)], capture_output=True, text=True)
            self.assertEqual(result.returncode, 1)
            self.assertIn("evidence rejected", result.stderr)
            self.assertEqual(result.stdout, "")


if __name__ == "__main__":
    unittest.main()
