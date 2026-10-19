"""Native C primitive controls; no privileged Darwin transition is exercised."""
import os
import platform
import subprocess
import tempfile
import unittest
from pathlib import Path


class CredentialPrimitiveTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.temporary = tempfile.TemporaryDirectory(prefix="glue credential units ü ")
        cls.binary = Path(cls.temporary.name) / "credential-tests"
        source = Path(__file__).resolve().parent
        command = ["/usr/bin/cc", "-std=c11", "-Wall", "-Wextra", "-Werror", "-O2"]
        if platform.system() == "Darwin":
            sdk = subprocess.check_output(["/usr/bin/xcrun", "--sdk", "macosx", "--show-sdk-path"], text=True).strip()
            command += ["-isysroot", sdk, "-mmacosx-version-min=11.0"]
        command += [str(source / "target_credentials.c"), str(source / "test_target_credentials.c"), "-o", str(cls.binary)]
        subprocess.run(command, check=True, capture_output=True, timeout=30)

    @classmethod
    def tearDownClass(cls):
        cls.temporary.cleanup()

    def control(self, name):
        result = subprocess.run([str(self.binary), name], capture_output=True, text=True, timeout=7)
        self.assertEqual(result.returncode, 0, result.stderr)

    def test_exact_syscall_order_and_explicit_zero_supplementary_group(self): self.control("success")
    def test_native_numeric_boundaries_before_cast(self): self.control("numeric-boundaries")
    def test_nonempty_primary_first_unique_bounded_vector(self): self.control("vector-boundaries")
    def test_canonical_decimal_no_type_coercion_or_overflow(self): self.control("parse")
    def test_invalid_request_or_incomplete_operations_cannot_mutate(self): self.control("no-mutation")
    def test_original_controller_pid_and_parent_check(self): self.control("child-guard")
    def test_each_syscall_failure_preserves_errno_and_stops(self): self.control("syscall-failures")
    def test_invalid_adapter_returns_fail_closed(self): self.control("adapter-failures")
    def test_each_real_effective_id_mismatch_stops(self): self.control("id-verification")
    def test_group_count_order_and_values_are_exact(self): self.control("exact-groups")
    def test_parser_pointer_count_bounds_and_named_errors(self): self.control("parse-pointer-bounds")
    def test_error_state_fully_initialized_and_reset_after_partial_failure(self): self.control("error-reset")
    def test_real_adapter_rejects_controller_before_mutation(self): self.control("native-parent-guard")

    @unittest.skipIf(os.geteuid() == 0 or os.getuid() == 0, "nonprivileged host negative control only")
    def test_real_adapter_eperm_only_in_owned_nonprivileged_child(self): self.control("native-denied")


if __name__ == "__main__":
    unittest.main()
