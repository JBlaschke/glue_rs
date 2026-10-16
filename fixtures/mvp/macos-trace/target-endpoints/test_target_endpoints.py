"""Native endpoint helpers in owned test subprocesses, without target execution."""
import os
import platform
import subprocess
import tempfile
import unittest
from pathlib import Path


class EndpointPrimitiveTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.temporary = tempfile.TemporaryDirectory(prefix="glue endpoint units ü ")
        cls.binary = Path(cls.temporary.name) / "endpoint-tests"
        source = Path(__file__).resolve().parent
        command = ["/usr/bin/cc", "-std=c11", "-Wall", "-Wextra", "-Werror", "-O2"]
        if platform.system() == "Darwin":
            sdk = subprocess.check_output(["/usr/bin/xcrun", "--sdk", "macosx", "--show-sdk-path"], text=True).strip()
            command += ["-isysroot", sdk, "-mmacosx-version-min=11.0"]
        command += [str(source / "target_endpoints.c"), str(source / "test_target_endpoints.c"), "-o", str(cls.binary)]
        subprocess.run(command, check=True, capture_output=True, timeout=30)

    @classmethod
    def tearDownClass(cls):
        cls.temporary.cleanup()

    def control(self, name):
        result = subprocess.run([str(self.binary), name], stdin=subprocess.DEVNULL,
                                capture_output=True, text=True, timeout=15)
        if result.returncode == 77:
            self.skipTest("native control requires nonroot uid/euid and existing soft FD capacity >=64; no limit raised")
        self.assertEqual(result.returncode, 0, result.stderr)

    def test_all_roles_before_dup_copies_fresh_and_originals_unchanged(self): self.control("success")
    def test_request_alias_and_full_callback_preflight(self): self.control("requests")
    def test_exact_direction_shapes_and_control_nonblocking_policy(self): self.control("roles")
    def test_precise_partial_copy_prefix_and_no_partial_mapping(self): self.control("preparation-failures")
    def test_impossible_dup_returns_never_own_an_original_or_guess_cleanup(self): self.control("uncertain-ownership")
    def test_child_owner_signal_complete_plan_and_same_slot_guards(self): self.control("child-guards")
    def test_mapping_eintr_flags_control_set_and_postverify_fail_closed(self): self.control("mapping-failures")
    def test_error_state_reset_after_ownership_failure(self): self.control("error-reset")

    @unittest.skipIf(os.getuid() == 0 or os.geteuid() == 0, "native control is unprivileged only")
    def test_native_mapped_streams_controls_flags_and_unchanged_enclosing_parent(self): self.control("native-basic")

    @unittest.skipIf(os.getuid() == 0 or os.geteuid() == 0, "native control is unprivileged only")
    def test_native_closed_stdio_and_swapped_source_numbers(self): self.control("native-closed-stdio")

    @unittest.skipIf(os.getuid() == 0 or os.geteuid() == 0, "native control is unprivileged only")
    def test_native_caller_opened_null_input(self): self.control("native-null-input")

    @unittest.skipIf(os.getuid() == 0 or os.geteuid() == 0, "native control is unprivileged only")
    def test_native_numeric_source_alias_rejected_before_allocation(self): self.control("native-alias-reject")

    @unittest.skipIf(os.getuid() == 0 or os.geteuid() == 0, "native control is unprivileged only")
    def test_native_wrong_direction_rejected_before_allocation(self): self.control("native-direction-reject")

    @unittest.skipIf(os.getuid() == 0 or os.geteuid() == 0, "native control is unprivileged only")
    def test_native_invalid_source_rejected_before_allocation(self): self.control("native-invalid-source")

    @unittest.skipIf(os.getuid() == 0 or os.geteuid() == 0, "native control is unprivileged only")
    def test_native_partial_emfile_exact_cleanup_without_source_mutation(self): self.control("native-partial-emfile")

    @unittest.skipIf(os.getuid() == 0 or os.geteuid() == 0, "native control is unprivileged only")
    def test_native_child_lowered_limit_mapping_failure_exits_without_rollback(self): self.control("native-map-limit")

    @unittest.skipIf(os.getuid() == 0 or os.geteuid() == 0, "native control is unprivileged only")
    def test_native_revalidates_copy_cloexec_before_any_mapping(self): self.control("native-copy-flags")


if __name__ == "__main__":
    unittest.main()
