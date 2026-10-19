"""Bounded helper controls; native closure occurs only in owned Mac children."""
import os
import platform
import subprocess
import tempfile
import unittest
from pathlib import Path


class DescriptorPrimitiveTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.temporary = tempfile.TemporaryDirectory(prefix="glue descriptor units ü ")
        cls.binary = Path(cls.temporary.name) / "descriptor-tests"
        source = Path(__file__).resolve().parent
        command = ["/usr/bin/cc", "-std=c11", "-Wall", "-Wextra", "-Werror", "-O2"]
        if platform.system() == "Darwin":
            sdk = subprocess.check_output(["/usr/bin/xcrun", "--sdk", "macosx", "--show-sdk-path"], text=True).strip()
            command += ["-isysroot", sdk, "-mmacosx-version-min=11.0"]
        command += [str(source / "target_descriptors.c"), str(source / "test_target_descriptors.c")]
        if platform.system() == "Darwin":
            command += ["-lproc"]
        command += ["-o", str(cls.binary)]
        subprocess.run(command, check=True, capture_output=True, timeout=30)

    @classmethod
    def tearDownClass(cls):
        cls.temporary.cleanup()

    def control(self, name):
        result = subprocess.run([str(self.binary), name], capture_output=True, text=True, timeout=10)
        if result.returncode == 77:
            self.skipTest("native control requires nonroot Mac and existing soft FD capacity >128; no limit is raised")
        self.assertEqual(result.returncode, 0, result.stderr)
        return result.stdout

    def test_exact_close_once_sparse_numeric_fds_and_empty_close_set(self): self.control("success")
    def test_plan_capacity_layout_and_keep_boundaries(self): self.control("plan-bounds")
    def test_all_callbacks_checked_and_unsupported_adapter_stops(self): self.control("preflight")
    def test_original_controller_child_and_signal_mask_preconditions(self): self.control("child-signals")
    def test_inventory_bytes_clipping_alignment_and_errno(self): self.control("response-bounds")
    def test_duplicate_negative_and_missing_keep_prevent_closure(self): self.control("initial-records")
    def test_close_errors_eintr_never_retry_and_invalid_returns_fail(self): self.control("close-failures")
    def test_rescan_extra_missing_duplicate_capacity_and_error_reject(self): self.control("rescan")
    def test_error_fields_reset_between_calls(self): self.control("error-reset")

    @unittest.skipIf(platform.system() == "Darwin", "native Darwin adapter is supported")
    def test_linux_native_adapter_explicitly_unsupported(self): self.control("native-unsupported")

    @unittest.skipUnless(platform.system() == "Darwin" and os.getuid() != 0 and os.geteuid() != 0,
                         "native closure control requires unprivileged Mac")
    def test_native_sparse_high_fd_closed_and_only_exact_keeps_remain(self): self.control("native-basic")

    @unittest.skipUnless(platform.system() == "Darwin" and os.getuid() != 0 and os.geteuid() != 0,
                         "native closure control requires unprivileged Mac")
    def test_native_sentinel_above_child_lowered_soft_and_hard_limits(self): self.control("native-lowered-limits")

    @unittest.skipUnless(platform.system() == "Darwin" and os.getuid() != 0 and os.geteuid() != 0,
                         "native closure control requires unprivileged Mac")
    def test_native_capacity_equal_rejects_before_closure(self): self.control("native-capacity")

    @unittest.skipUnless(platform.system() == "Darwin" and os.getuid() != 0 and os.geteuid() != 0,
                         "native closure control requires unprivileged Mac")
    def test_native_closed_stdio_is_rejected_without_remapping(self): self.control("native-missing-stdio")

    @unittest.skipUnless(platform.system() == "Darwin" and os.getuid() != 0 and os.geteuid() != 0,
                         "native closure control requires unprivileged Mac")
    def test_native_unblocked_signals_reject_before_inventory(self): self.control("native-unmasked")


if __name__ == "__main__":
    unittest.main()
