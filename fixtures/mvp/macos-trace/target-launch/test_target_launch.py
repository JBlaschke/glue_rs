"""Pure copied launch-plan controls; no target application or native setup."""
import hashlib
import json
import os
from pathlib import Path
import platform
import subprocess
import tempfile
import unittest

HERE = Path(__file__).resolve().parent


class TargetLaunchControls(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.temporary = None
        retain = os.environ.get("GLUE_LAUNCH_TEST_RETAIN")
        if retain:
            cls.build = Path(retain)
            cls.build.mkdir(parents=True, exist_ok=False, mode=0o700)
        else:
            cls.temporary = tempfile.TemporaryDirectory(prefix="glue launch controls ü ")
            cls.build = Path(cls.temporary.name)
        cls.binary = cls.build / "launch-controls"
        sources = [HERE / "target_launch.c", HERE / "test_target_launch.c"]
        argv = ["/usr/bin/cc", "-std=c11", "-Wall", "-Wextra", "-Werror", "-pedantic", "-O1"]
        if os.environ.get("GLUE_LAUNCH_SANITIZE") == "1":
            argv += ["-g", "-fsanitize=address,undefined", "-fno-omit-frame-pointer"]
        argv += [str(path) for path in sources] + ["-o", str(cls.binary)]
        result = subprocess.run(argv, capture_output=True, text=True, timeout=45)
        cls.record("compile", argv, result, sources={str(p): hashlib.sha256(p.read_bytes()).hexdigest()
                                                   for p in [HERE / "target_launch.h", *sources]})
        if result.returncode:
            raise AssertionError(result.stdout + result.stderr)

    @classmethod
    def record(cls, name, argv, result, **extra):
        (cls.build / (name + ".stdout")).write_text(result.stdout)
        (cls.build / (name + ".stderr")).write_text(result.stderr)
        data = {"argv": argv, "status": result.returncode, "host": platform.platform(),
                "scope": "pure compiled data control", **extra}
        if cls.binary.is_file():
            data["binary_sha256"] = hashlib.sha256(cls.binary.read_bytes()).hexdigest()
        (cls.build / (name + ".json")).write_text(json.dumps(data, indent=2) + "\n")

    @classmethod
    def tearDownClass(cls):
        if cls.temporary:
            cls.temporary.cleanup()

    def control(self, name):
        argv = [str(self.binary), name]
        result = subprocess.run(argv, capture_output=True, text=True, timeout=10)
        self.record(name, argv, result)
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)

    def test_exact_compact_literals_and_owned_copy(self): self.control("compact")
    def test_empty_arguments_and_non_utf8_bytes_are_literal(self): self.control("empty-binary")
    def test_closed_target_and_empty_environment(self): self.control("profile")
    def test_argument_count_includes_executable(self): self.control("counts")
    def test_exact_copied_byte_capacity_includes_terminators(self): self.control("bytes")
    def test_executable_path_shape_and_255_byte_limit(self): self.control("paths")
    def test_nul_null_and_absurd_span_lengths_refuse(self): self.control("spans")
    def test_failure_clears_plan_without_crossing_canaries(self): self.control("reset")
    def test_independent_canonical_bytes_and_exact_capacity(self): self.control("canonical-vector")
    def test_canonical_identity_binds_boundaries_order_and_executable(self): self.control("identity")
    def test_malformed_or_moved_plan_and_canonical_failure_clearing(self): self.control("layout")


if __name__ == "__main__":
    unittest.main()
