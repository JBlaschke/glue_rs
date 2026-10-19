"""Pure data controls: no bootstrap, target, privilege or VM operations."""
import json
import os
import subprocess
import tempfile
import unittest
from pathlib import Path

class BootstrapWireTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.temp = tempfile.TemporaryDirectory(prefix="glue wire ü ")
        cls.binary = Path(cls.temp.name) / "wire-tests"
        cls.source = Path(__file__).resolve().parent
        command = ["cc", "-std=c11", "-Wall", "-Wextra", "-Werror", "-pedantic", "-O2"]
        if os.environ.get("GLUE_BOOTSTRAP_WIRE_SANITIZE") == "1":
            command += ["-g", "-fsanitize=address,undefined", "-fno-omit-frame-pointer"]
        command += [str(cls.source / name) for name in ["bootstrap_wire.c", "test_bootstrap_wire.c"]]
        command += ["-o", str(cls.binary)]
        result = subprocess.run(command, capture_output=True, text=True, timeout=30)
        if result.returncode:
            raise RuntimeError("C compile failed:\n" + result.stderr)
    @classmethod
    def tearDownClass(cls):
        cls.temp.cleanup()
    def control(self, name, *args):
        result = subprocess.run([str(self.binary), name, *args], capture_output=True, text=True, timeout=10)
        self.assertEqual(result.returncode, 0, result.stderr)
        return result.stdout
    def test_golden_roundtrip(self): self.control("golden")
    def test_independent_network_order_bytes(self):
        expected = json.loads((self.source / "golden-vectors.json").read_text())
        observed = dict(line.split(":", 1) for line in self.control("vectors").splitlines())
        self.assertEqual(observed, expected)
        for name, data in expected.items():
            with self.subTest(name=name):
                self.assertEqual(self.control("decode-go" if name == "go" else "decode-status", data), "decoded\n")
    def test_lengths_and_null_outputs(self): self.control("lengths")
    def test_headers_types_and_reserved_bytes(self): self.control("headers")
    def test_controller_child_and_request_binding(self): self.control("bindings")
    def test_ready_identity_group_fd_and_numeric_boundaries(self): self.control("ready-bounds")
    def test_attempt_error_observations_are_zero(self): self.control("observations")
    def test_closed_error_stage_reason_flag_errno_detail_contract(self): self.control("errors")
    def test_go_length_reserved_and_binding_contract(self): self.control("go")
    def test_sequence_paths_and_non_success_eof(self): self.control("state")
    def test_poison_first_failure_terminal_extra_and_sealed_eof(self): self.control("poison")

if __name__ == "__main__":
    unittest.main()
