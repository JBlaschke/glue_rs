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

    def test_successful_clone3_in_out_annotation_preserves_child_tracking(self):
        # Actual arguments from native x86_64 run 38791248353,
        # node-24.22.0-cjs/trace/syscalls.5147; only timestamps are shortened.
        clone = ('1.100000 clone3({flags=CLONE_VM|CLONE_FS|CLONE_FILES|CLONE_SIGHAND|CLONE_THREAD|CLONE_SYSVSEM|CLONE_SETTLS|CLONE_PARENT_SETTID|CLONE_CHILD_CLEARTID, '
                 'child_tid=0x7f9e4ceef990, parent_tid=0x7f9e4ceef990, exit_signal=0, stack=0x7f9e4c6ef000, stack_size=0x7ffdc0, tls=0x7f9e4ceef6c0} => {parent_tid=[5148]}, 88) = 5148\n')
        self.trace(self.root_trace(clone))
        with self.assertRaisesRegex(extraction.TraceError, "process tree trace incomplete"):
            self.check()
        self.trace('1.200000 set_robust_list(0x0, 24) = 0\n1.300000 exit(0) = ?\n1.300001 +++ exited with 0 +++\n', 5148)
        self.assertEqual(self.check()["processes"], 2)
        self.trace('1.200000 openat(AT_FDCWD, "/cache/child-extraction", O_WRONLY|O_CREAT, 0666) = -1 EACCES (Permission denied)\n1.300001 +++ exited with 0 +++\n', 5148)
        with self.assertRaisesRegex(extraction.TraceError, "open-for-write"):
            self.check()

    def test_argument_mutations_preserve_quotes_and_descriptor_angles(self):
        arguments = '"literal => > data", 3</path-ending-in=>, [4<pipe:[99]>], {value=1} => {value=2}, 88'
        self.assertEqual(extraction.BASE.split_arguments(arguments), [
            '"literal => > data"', '3</path-ending-in=>', '[4<pipe:[99]>]',
            '{value=1} => {value=2}', '88'])
        for malformed in ['>', '3</missing', '[3</mismatch>}', '{value=1} > {value=2}',
                          '{value=1} => {value=[2}', '=> {value=2}', '{value=1} =>',
                          '{value=1} =>, 88', '[=> 1]']:
            with self.subTest(malformed=malformed):
                with self.assertRaises(extraction.TraceError):
                    extraction.BASE.split_arguments(malformed)

    def signing_images(self):
        (self.root / "glue").write_bytes(b"\xcf\xfa\xed\xfefixture")
        (self.root / "vendor.dylib").write_bytes(b"\xcf\xfa\xed\xfefixture-vendor")

    def signature_tools(self, classes, verification_exit=0, metadata_exit=0, gatekeeper_exit=0):
        def invoke(argv, **kwargs):
            if argv[0] == "/usr/sbin/spctl":
                return SimpleNamespace(returncode=gatekeeper_exit, stdout=b"", stderr=b"assessment")
            kind = classes[Path(argv[-1]).name]
            text = {"ad-hoc": b"Signature=adhoc\nTeamIdentifier=not set\n",
                    "developer-id": b"Authority=Developer ID Application: Existing Vendor (EXAMPLE)\n",
                    "unknown": b"Signature=unknown\n"}[kind] if "-d" in argv else b""
            return SimpleNamespace(returncode=metadata_exit if "-d" in argv else verification_exit, stdout=b"", stderr=text)
        return invoke

    def test_development_policy_accepts_valid_existing_developer_id_and_preserves_classes(self):
        self.signing_images()
        classes = {"glue":"ad-hoc", "vendor.dylib":"developer-id"}
        with patch.object(extraction.subprocess, "run", side_effect=self.signature_tools(classes)) as run:
            result = extraction.verify_macos(self.root, "ad-hoc")
        self.assertEqual(result["status"], "passed")
        self.assertEqual({image["path"]:image["signature"] for image in result["images"]}, classes)
        self.assertEqual(result["accepted_signature_classes"], ["ad-hoc","developer-id"])
        self.assertTrue(all(call.args[0][0] == "/usr/bin/codesign" for call in run.call_args_list))
        self.assertTrue(all("--sign" not in call.args[0] for call in run.call_args_list))
        self.assertNotIn("gatekeeper", result)

    def test_development_policy_rejects_invalid_unclassified_or_unreadable_signatures(self):
        self.signing_images()
        for classes, verification, metadata in [
            ({"glue":"ad-hoc","vendor.dylib":"developer-id"}, 1, 0),
            ({"glue":"ad-hoc","vendor.dylib":"unknown"}, 0, 0),
            ({"glue":"ad-hoc","vendor.dylib":"developer-id"}, 0, 1),
        ]:
            with self.subTest(classes=classes, verification=verification, metadata=metadata):
                with patch.object(extraction.subprocess, "run", side_effect=self.signature_tools(classes,verification,metadata)):
                    self.assertEqual(extraction.verify_macos(self.root,"ad-hoc")["status"],"failed")

    def test_public_policy_requires_every_developer_id_signature_and_gatekeeper(self):
        self.signing_images()
        for classes, gate, expected in [
            ({"glue":"developer-id","vendor.dylib":"developer-id"},0,"passed"),
            ({"glue":"ad-hoc","vendor.dylib":"developer-id"},0,"failed"),
            ({"glue":"developer-id","vendor.dylib":"developer-id"},1,"failed"),
        ]:
            with self.subTest(classes=classes,gate=gate):
                with patch.object(extraction.subprocess,"run",side_effect=self.signature_tools(classes,gatekeeper_exit=gate)):
                    result=extraction.verify_macos(self.root,"developer-id")
                self.assertEqual(result["status"],expected)
                self.assertEqual(result["accepted_signature_classes"],["developer-id"])
                self.assertIn("not proven",result["notarization"])
                self.assertEqual(result["gatekeeper"]["exit"],gate)

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
