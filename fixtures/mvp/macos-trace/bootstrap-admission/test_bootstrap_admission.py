#!/usr/bin/env python3
"""Native-compiled model controls and explicitly limited read-only native checks."""
import os
from pathlib import Path
import shlex
import subprocess
import tempfile
import unittest

HERE = Path(__file__).resolve().parent


class AdmissionControls(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.storage = tempfile.TemporaryDirectory(prefix="glue-admission-controls-")
        cls.binary = Path(cls.storage.name) / "admission-controls"
        command = shlex.split(os.environ.get("CC", "cc")) + [
            "-std=c11", "-Wall", "-Wextra", "-Werror", "-pedantic",
        ]
        if os.environ.get("BA_SANITIZE") == "1":
            command += ["-fsanitize=address,undefined", "-fno-omit-frame-pointer"]
        command += [str(HERE / "bootstrap_admission.c"),
                    str(HERE / "test_bootstrap_admission.c"), "-o", str(cls.binary)]
        built = subprocess.run(command, capture_output=True, text=True, timeout=60)
        if built.returncode:
            cls.storage.cleanup()
            raise RuntimeError(built.stdout + built.stderr)

    @classmethod
    def tearDownClass(cls):
        cls.storage.cleanup()

    def control(self, case):
        result = subprocess.run([str(self.binary), case], capture_output=True,
                                text=True, timeout=10)
        if result.returncode == 77:
            self.skipTest("explicit native platform/ordinary-user precondition unavailable")
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        if case == "native_readonly":
            self.assertEqual(result.stdout.count("readonly component="), 5)
            print(result.stdout, end="")

    def test_model_complete_walk_and_root_data_boundary(self): self.control("positive")
    def test_model_exact_path_grammar_and_bounds(self): self.control("paths")
    def test_model_complete_preflight_and_no_callbacks_when_unsupported(self): self.control("preflight")
    def test_model_distinct_reviewed_mount_profiles(self): self.control("profile")
    def test_model_real_and_effective_root_both_required(self): self.control("identities")
    def test_model_first_error_errno_and_owned_prefix(self): self.control("errors")
    def test_model_uncertain_open_and_failed_metadata_ownership(self): self.control("uncertainty")
    def test_model_owner_type_mode_single_link(self): self.control("owners_and_modes")
    def test_model_scalar_population_false_success_and_acl_rejection(self): self.control("filesec")
    def test_model_exact_scalar_validity_and_metadata_error_stage(self): self.control("scalar_boundaries")
    def test_model_access_cloexec_async_and_leaf_nonblock(self): self.control("flags")
    def test_model_all_mount_components_and_unterminated_metadata(self): self.control("mounts")
    def test_model_output_reset_and_bounds_canaries(self): self.control("reset_and_canaries")
    def test_native_nonroot_or_unsupported_before_opens(self): self.control("native_preflight")
    def test_native_darwin_readonly_fresh_filesec_queries(self): self.control("native_readonly")


if __name__ == "__main__":
    unittest.main()
