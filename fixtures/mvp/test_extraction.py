import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

import extraction


class ExtractionTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary.name)
        self.prefix = self.root / "trace"

    def tearDown(self):
        self.temporary.cleanup()

    def trace(self, content, pid=100):
        (self.root / f"trace.{pid}").write_text(content)

    def check(self):
        return extraction.check_trace(self.prefix, Path("/unrelated"), [Path("/application-output")], ["/evidence/run.stdout", "/evidence/run.stderr"])

    def root_trace(self, operation=""):
        return '1.000000 execve("/payload/glue", ["glue"], 0x0) = 0\n' + operation + '2.000000 exit_group(0) = ?\n2.000001 +++ exited with 0 +++\n'

    def test_read_only_archive_and_standard_outputs_pass(self):
        self.trace(self.root_trace('1.010000 openat(AT_FDCWD, "/payload/app.glue", O_RDONLY|O_CLOEXEC) = 3</payload/app.glue>\n1.020000 read(3</payload/app.glue>, "data", 4) = 4\n1.030000 write(1</evidence/run.stdout>, "ok\\n", 3) = 3\n'))
        result = self.check()
        self.assertEqual(result["status"], "passed")
        self.assertEqual(result["io"]["read_bytes"], 4)
        self.assertEqual(result["fds"]["peak_per_process"], 4)

    def test_descriptor_lifecycle_handles_close_ranges_and_exec(self):
        self.trace(self.root_trace('1.010000 pipe2([3<pipe:[1]>, 4<pipe:[1]>], O_CLOEXEC) = 0\n'
                                  '1.020000 close_range(3, 4294967295, CLOSE_RANGE_CLOEXEC) = 0\n'
                                  '1.030000 execve("/payload/helper", ["helper"], 0x0) = 0\n'
                                  '1.040000 dup(1</evidence/run.stdout>) = 3</evidence/run.stdout>\n'
                                  '1.050000 close_range(3, ~0U, 0) = 0\n'
                                  '1.060000 dup(1</evidence/run.stdout>) = 3</evidence/run.stdout>\n'))
        self.assertEqual(self.check()["fds"]["peak_per_process"], 5)

    def test_failed_write_create_unlink_and_shared_map_are_all_rejected(self):
        operations = [
            'openat(AT_FDCWD, "/temp/extracted.so", O_WRONLY|O_CREAT, 0666) = -1 EACCES (Permission denied)',
            'unlink("/temp/extracted.so") = -1 ENOENT (No such file or directory)',
            'write(3</payload/app.glue>, "payload", 7) = -1 EBADF (Bad file descriptor)',
            'mmap(NULL, 4096, PROT_READ|PROT_WRITE, MAP_SHARED, 3</payload/app.glue>, 0) = 0x1234',
            'mount("tmpfs", "/ram-payload", "tmpfs", 0, NULL) = -1 EPERM (Operation not permitted)',
            'io_uring_setup(64, {flags=0}) = 3<anon_inode:[io_uring]>',
            'openat(AT_FDCWD, "/application-output/link", O_WRONLY|O_TRUNC) = 3</payload/app.glue>',
            'symlink("/payload/app.glue", "/application-output/link") = 0',
        ]
        for operation in operations:
            with self.subTest(operation=operation):
                self.trace(self.root_trace('1.100000 ' + operation + '\n'))
                with self.assertRaises(extraction.TraceError): self.check()

    def test_declared_application_output_is_separate_and_allowed(self):
        self.trace(self.root_trace('1.100000 openat(AT_FDCWD, "/application-output/result.txt", O_WRONLY|O_CREAT, 0666) = 3</application-output/result.txt>\n1.200000 write(3</application-output/result.txt>, "user result", 11) = 11\n'))
        self.assertEqual(self.check()["status"], "passed")

    def test_descendant_and_thread_completeness_is_required(self):
        self.trace(self.root_trace('1.100000 clone(child_stack=NULL, flags=CLONE_VM|CLONE_FS) = 101\n'))
        with self.assertRaisesRegex(extraction.TraceError, "process tree trace incomplete"): self.check()
        self.trace('1.200000 set_robust_list(0x0, 24) = 0\n1.300000 exit(0) = ?\n1.300001 +++ exited with 0 +++\n', 101)
        self.assertEqual(self.check()["processes"], 2)
        self.trace('1.200000 openat(AT_FDCWD, "/cache/child-payload", O_WRONLY|O_CREAT, 0666) = 3</cache/child-payload>\n1.300001 +++ exited with 0 +++\n', 101)
        with self.assertRaisesRegex(extraction.TraceError, "open-for-write"): self.check()

    def test_unfinished_records_resume_and_truncation_fail_closed(self):
        self.trace(self.root_trace('1.100000 futex(0x0, FUTEX_WAIT_PRIVATE, 0, NULL <unfinished ...>\n1.200000 <... futex resumed>) = 0\n'))
        self.assertEqual(self.check()["status"], "passed")
        self.trace(self.root_trace('1.100000 futex(0x0, FUTEX_WAIT_PRIVATE, 0, NULL <unfinished ...>\n'))
        with self.assertRaises(extraction.TraceError): self.check()
        self.trace('1.000000 execve("/payload/glue", ["glue"], 0x0) = 0\n')
        with self.assertRaisesRegex(extraction.TraceError, "no terminal"): self.check()

    def test_ad_hoc_policy_never_counts_as_developer_id_or_notarization(self):
        (self.root / "glue").write_bytes(b"\xcf\xfa\xed\xfefixture")
        def codesign(argv, **kwargs):
            text = b"Signature=adhoc\nTeamIdentifier=not set\n" if "-d" in argv else b""
            return SimpleNamespace(returncode=0, stdout=b"", stderr=text)
        with patch.object(extraction.subprocess, "run", side_effect=codesign):
            result = extraction.verify_macos(self.root, "ad-hoc")
            self.assertEqual(result["status"], "passed")
            self.assertIn("not proven", result["notarization"])
            self.assertEqual(extraction.verify_macos(self.root, "developer-id")["status"], "failed")
            self.assertEqual(extraction.verify_macos(self.root, "unconfigured")["status"], "unavailable")


if __name__ == "__main__": unittest.main()
