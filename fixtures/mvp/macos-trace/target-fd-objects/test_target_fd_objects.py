"""Native owned-child object observations and injected portable boundaries."""
import hashlib
import json
import os
import platform
import subprocess
import tempfile
import unittest
from pathlib import Path


class TargetFdObjectTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.temporary = None
        selected = os.environ.get("GLUE_TFO_TEST_RETAIN")
        if selected:
            cls.build = Path(selected)
            cls.build.mkdir(parents=True, exist_ok=False, mode=0o700)
        else:
            cls.temporary = tempfile.TemporaryDirectory(prefix="glue fd objects ü ")
            cls.build = Path(cls.temporary.name)
        cls.binary = cls.build / "fd-object-tests"
        source = Path(__file__).resolve().parent
        inputs = [source / "target_fd_objects.c", source / "test_target_fd_objects.c",
                  source.parent / "target-endpoints/target_endpoints.c",
                  source.parent / "target-descriptors/target_descriptors.c"]
        command = ["/usr/bin/cc", "-std=c11", "-Wall", "-Wextra", "-Werror", "-O2"]
        if platform.system() == "Darwin":
            sdk = subprocess.check_output(["/usr/bin/xcrun", "--sdk", "macosx", "--show-sdk-path"], text=True).strip()
            command += ["-isysroot", sdk, "-mmacosx-version-min=11.0"]
        command += [str(path) for path in inputs]
        if platform.system() == "Darwin":
            command += ["-lproc"]
        command += ["-o", str(cls.binary)]
        result = subprocess.run(command, capture_output=True, text=True, timeout=45)
        (cls.build / "compile.stdout").write_text(result.stdout)
        (cls.build / "compile.stderr").write_text(result.stderr)
        record = {"argv": command, "status": result.returncode,
                  "host": platform.platform(),
                  "source_sha256": {str(path): hashlib.sha256(path.read_bytes()).hexdigest() for path in inputs}}
        if result.returncode == 0:
            record["binary_sha256"] = hashlib.sha256(cls.binary.read_bytes()).hexdigest()
        (cls.build / "compile.json").write_text(json.dumps(record, indent=2) + "\n")
        if result.returncode:
            raise AssertionError(result.stderr)

    @classmethod
    def tearDownClass(cls):
        if cls.temporary is not None:
            cls.temporary.cleanup()

    def control(self, name, expected_status=0):
        result = subprocess.run([str(self.binary), name], capture_output=True, text=True, timeout=12)
        if os.environ.get("GLUE_TFO_TEST_RETAIN"):
            (self.build / (name + ".stdout")).write_text(result.stdout)
            (self.build / (name + ".stderr")).write_text(result.stderr)
            (self.build / (name + ".result.json")).write_text(json.dumps({"argv": [str(self.binary), name], "status": result.returncode,
                                                                         "expected_status": expected_status}, indent=2) + "\n")
        if result.returncode == 77:
            self.skipTest("native integration requires a nonroot host and existing FD capacity >=32; no limit is raised")
        self.assertEqual(result.returncode, expected_status, result.stderr)
        return result.stdout

    def test_complete_snapshot_and_conditional_match_with_different_cloexec(self): self.control("success")
    def test_fixed_plan_and_null_error_never_preserve_stale_ready(self): self.control("plans")
    def test_complete_callback_preflight_and_unsupported_refusal(self): self.control("callbacks")
    def test_original_child_and_signal_mask_guards(self): self.control("owner-masks")
    def test_every_sample_syscall_failure_no_retry_or_partial_publication(self): self.control("errors")
    def test_each_backing_flag_change_and_impossible_mode_refuses(self): self.control("changes")
    def test_final_identity_and_signal_guards_suppress_complete_but_stale_samples(self): self.control("final-guards")
    def test_reference_read_errors_and_changes_publish_no_partial_match(self): self.control("match-errors")
    def test_regular_single_link_write_only_distinct_output_requirements(self): self.control("match-shapes")
    def test_snapshot_and_controller_preflight_before_reference_reads(self): self.control("match-preflight")
    def test_stale_errno_and_status_flags_are_preserved(self): self.control("stale-errno-flags")

    @unittest.skipUnless(platform.system() in ("Darwin", "Linux") and os.getuid() != 0 and os.geteuid() != 0,
                         "native fixture requires unprivileged Mac or Linux")
    def test_native_te_mapping_td_closure_snapshot_before_go_and_output_bytes(self): self.control("native-basic")

    @unittest.skipUnless(platform.system() in ("Darwin", "Linux") and os.getuid() != 0 and os.geteuid() != 0,
                         "native fixture requires unprivileged Mac or Linux")
    def test_native_independent_open_same_backing_can_match_without_ofd_claim(self): self.control("native-reopened")

    @unittest.skipUnless(platform.system() in ("Darwin", "Linux") and os.getuid() != 0 and os.geteuid() != 0,
                         "native fixture requires unprivileged Mac or Linux")
    def test_native_wrong_held_sink_never_releases_go_and_reaps_owned_child(self): self.control("native-mismatch")

    @unittest.skipUnless(platform.system() in ("Darwin", "Linux") and os.getuid() != 0 and os.geteuid() != 0,
                         "native fixture requires unprivileged Mac or Linux")
    def test_native_closed_kept_descriptor_refuses_snapshot_without_go(self): self.control("native-missing")

    @unittest.skipUnless(platform.system() in ("Darwin", "Linux") and os.getuid() != 0 and os.geteuid() != 0,
                         "native fixture requires unprivileged Mac or Linux")
    def test_native_unexpected_parent_read_failure_reaps_child_without_go(self): self.control("native-parent-read-failure")

    @unittest.skipUnless(platform.system() in ("Darwin", "Linux") and os.getuid() != 0 and os.geteuid() != 0,
                         "native fixture requires unprivileged Mac or Linux")
    def test_native_read_failure_does_not_hide_unrelated_parent_failure(self):
        output = self.control("native-parent-unrelated-failure", 1)
        self.assertIn("exact_EBADF=1 other_parent_failure=1 actual_child_reap=1 cleanup_failure=0", output)
        self.assertNotIn("expected_parent_read_failure=1", output)

    @unittest.skipUnless(platform.system() in ("Darwin", "Linux") and os.getuid() != 0 and os.geteuid() != 0,
                         "native fixture requires unprivileged Mac or Linux")
    def test_native_read_failure_does_not_hide_real_cleanup_failure(self):
        output = self.control("native-parent-cleanup-failure", 1)
        self.assertIn("exact_EBADF=1 other_parent_failure=0 actual_child_reap=1 cleanup_failure=1", output)
        self.assertNotIn("expected_parent_read_failure=1", output)

    @unittest.skipUnless(platform.system() in ("Darwin", "Linux") and os.getuid() != 0 and os.geteuid() != 0,
                         "native fixture requires unprivileged Mac or Linux")
    def test_native_echild_ownership_loss_is_never_reported_as_actual_reap(self):
        output = self.control("native-parent-ownership-loss", 1)
        self.assertIn("exact_EBADF=1 other_parent_failure=0 actual_child_reap=0 cleanup_failure=1", output)
        self.assertNotIn("expected_parent_read_failure=1", output)

    @unittest.skipUnless(platform.system() in ("Darwin", "Linux") and os.getuid() != 0 and os.geteuid() != 0,
                         "native fixture requires unprivileged Mac or Linux")
    def test_native_child_exit_before_go_epipe_uses_cleanup_and_restores_sigpipe(self):
        output = self.control("native-child-exits-before-go", 1)
        self.assertIn("exited_before_GO: EPIPE=1 actual_child_reap=1 cleanup_failure=0 SIGPIPE_restored=1", output)


if __name__ == "__main__":
    unittest.main()
