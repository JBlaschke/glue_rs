"""Host transport/fixture tests; these do not prove DTrace provider availability."""
import hashlib
import json
import platform
import signal
import subprocess
import tempfile
import time
import unittest
from pathlib import Path


@unittest.skipUnless(platform.system() == "Darwin" and platform.machine() == "arm64", "requires native macOS arm64 host")
class NativeCapabilityTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.temporary = tempfile.TemporaryDirectory(prefix="glue native capability ü ")
        cls.root = Path(cls.temporary.name)
        cls.source = Path(__file__).resolve().parent
        cls.toolkit = cls.root / "toolkit"
        subprocess.run([str(cls.source / "prepare-native.sh"), str(cls.toolkit)], check=True, capture_output=True)
        sdk = (cls.toolkit / "sdk-path.txt").read_text().strip()
        cls.unit = cls.root / "synthetic-unit-tests"
        subprocess.run(["/usr/bin/cc", "-isysroot", sdk, "-mmacosx-version-min=11.0", "-arch", "arm64", "-O2", "-std=c11", "-Wall", "-Wextra", "-Werror", str(cls.source / "test-native.c"), "-ldtrace", "-o", str(cls.unit)], check=True, capture_output=True)

    @classmethod
    def tearDownClass(cls):
        cls.temporary.cleanup()

    def test_synthetic_consumer_ledger_and_loss_errors(self):
        result = subprocess.run([str(self.unit)], capture_output=True, text=True, timeout=5)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("not capture evidence", result.stdout)

    def test_setup_failure_never_releases_owned_fixture(self):
        output = self.root / "mock setup failure"
        result = subprocess.run([str(self.unit), "setup-error", str(output)], capture_output=True, text=True, timeout=5)
        self.assertEqual(result.returncode, 77, result.stderr)
        receipt = json.loads((output / "capability.json").read_text())
        self.assertEqual(receipt["status"], "unavailable")
        self.assertFalse(receipt["started"])
        self.assertFalse(receipt["full_trace_acceptance"])
        self.assertEqual((output / "target.stdout").read_bytes(), b"")
        self.assertEqual((output / "events.jsonl").read_bytes(), b"")
        for name, identity in receipt["evidence"].items():
            data = (output / name).read_bytes()
            self.assertEqual(identity, {"size": len(data), "sha256": hashlib.sha256(data).hexdigest()})

    def test_hard_watchdog_bounds_a_stuck_collector(self):
        output = self.root / "mock watchdog"
        output.mkdir()
        start = time.monotonic()
        result = subprocess.run([str(self.unit), "watchdog", str(output)], capture_output=True, timeout=6)
        self.assertEqual(result.returncode, -signal.SIGKILL)
        self.assertLess(time.monotonic() - start, 5)
        self.assertEqual(json.loads((output / "watchdog.json").read_text())["status"], "failed")

    def test_cli_invalid_arguments_fail_before_output_creation(self):
        executable = str(self.toolkit / "capture-native")
        for arguments in [[], ["--timeout", "0"], ["--profile", "missing"], ["--output", "relative", "--", "/bin/true"]]:
            with self.subTest(arguments=arguments):
                result = subprocess.run([executable, *arguments], capture_output=True, timeout=3)
                self.assertEqual(result.returncode, 2)

    def test_owned_lifecycle_modes_execute_and_surviving_children_finish(self):
        for mode in ["read", "thread", "fork", "double-fork", "vfork", "spawn", "spawn-fail-open"]:
            with self.subTest(mode=mode):
                result = subprocess.run([str(self.toolkit / "lifecycle-probe"), mode, str(self.toolkit / "input.txt")], capture_output=True, text=True, timeout=7)
                self.assertEqual(result.returncode, 0, result.stderr)
                self.assertIn("OWNED_READ", result.stdout)
                if mode in {"fork", "double-fork", "vfork", "spawn"}:
                    self.assertIn("OWNED_PARENT_EXIT", result.stdout)

    def test_host_built_toolkit_signatures_and_deployment_floor(self):
        for name in ["capture-native", "owned-probe", "lifecycle-probe"]:
            result = subprocess.run(["/usr/bin/codesign", "--verify", "--strict", str(self.toolkit / name)], capture_output=True)
            self.assertEqual(result.returncode, 0, result.stderr)
            commands = (self.toolkit / (name + "-load-commands.txt")).read_text()
            self.assertIn("minos 11.0", commands)
            self.assertIn("sdk 26.5", commands)


if __name__ == "__main__":
    unittest.main()
