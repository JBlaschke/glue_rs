"""Host transport/fixture tests; these do not prove DTrace provider availability."""
import hashlib
import json
import os
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

    def test_rejected_layout_diagnostics_preserve_exact_bounded_metadata(self):
        for mode, reason, count in [("layout", "record-layout", 6),
                                    ("layout-range", "record-range", 6),
                                    ("layout-wide", "record-count", 21)]:
            with self.subTest(mode=mode):
                result = subprocess.run([str(self.unit), mode], capture_output=True, text=True, timeout=3)
                self.assertEqual(result.returncode, 0, result.stderr)
                diagnostic = json.loads(result.stdout)
                self.assertEqual(diagnostic["kind"], "layout-error")
                self.assertEqual([diagnostic[key] for key in ["cpu", "epid", "probe_id", "provider", "module", "function", "name"]],
                                 [2, 7, 42, "dtrace", "", "", "BEGIN"])
                self.assertEqual(diagnostic["reason"], reason)
                self.assertEqual(diagnostic["event"], 1)
                self.assertEqual(diagnostic["nrecs"], count)
                self.assertEqual(len(diagnostic["records"]), min(count, 20))
                self.assertIsNone(diagnostic["header"][0])
                if mode == "layout-wide":
                    self.assertEqual(diagnostic["header"], [None] * 5)
                    self.assertTrue(all(record["u64"] is None for record in diagnostic["records"]))
                else:
                    self.assertEqual(diagnostic["header"][1:], [1, 1000, 100, 2000])
                    self.assertEqual(diagnostic["records"][0]["size"], 0 if mode == "layout" else 8)
                    self.assertEqual(diagnostic["records"][1]["u64"], 1)
                self.assertLess(len(result.stdout.encode()), 8192)

    def test_v3_exact_layouts_preserve_zero_records_and_explicit_header_indexes(self):
        result = subprocess.run([str(self.unit), "valid-layouts"], capture_output=True, text=True, timeout=3)
        self.assertEqual(result.returncode, 0, result.stderr)
        events = [json.loads(line) for line in result.stdout.splitlines()]
        self.assertEqual([event["kind"] for event in events], list(range(1, 19)))
        for event in events:
            kind = event["kind"]
            zero = 0 if kind in {1, 4, 5, 7} else 6 if kind == 18 else None
            self.assertEqual(event["header_record_indexes"], list(range(1, 6)) if zero == 0 else list(range(5)))
            self.assertTrue(all(record["action"] == 1 for record in event["records"]))
            self.assertEqual(event["record_bytes"], {2: 120, 3: 96, 14: 1080, 15: 120, 16: 64, 18: 64}.get(kind, 56))
            if zero is not None:
                self.assertEqual(event["records"][zero], {"action": 1, "size": 0, "offset": 12 if zero == 0 else 64, "hex": ""})
            self.assertEqual([i for i, record in enumerate(event["records"]) if record["size"] == 0], [] if zero is None else [zero])
            raw_header = [int.from_bytes(bytes.fromhex(event["records"][i]["hex"]), "little") for i in event["header_record_indexes"]]
            self.assertEqual(raw_header, [event[name] for name in ["kind", "timestamp", "pid", "tid", "detail"]])
        self.assertEqual(events[13]["records"][5]["size"], 1024)

    def test_v3_wrong_layouts_fail_before_event_publication(self):
        result = subprocess.run([str(self.unit), "negative-layouts"], capture_output=True, text=True, timeout=3)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("22 exact layout rejection controls passed", result.stdout)

    def test_diagnostic_count_message_bounds_and_original_failure_cause(self):
        result = subprocess.run([str(self.unit), "layout-limit"], capture_output=True, text=True, timeout=3)
        self.assertEqual(result.returncode, 0, result.stderr)
        diagnostics = [json.loads(line) for line in result.stdout.splitlines()]
        self.assertEqual(len(diagnostics), 16)
        self.assertEqual([record["event"] for record in diagnostics], list(range(1, 17)))
        result = subprocess.run([str(self.unit), "libdtrace-error"], capture_output=True, text=True, timeout=3)
        self.assertEqual(result.returncode, 0, result.stderr)
        diagnostic = json.loads(result.stdout)
        self.assertEqual(diagnostic, {"kind": "libdtrace-error", "operation": "work", "error": 5, "message": "x" * 512})

    def test_setup_failure_never_releases_owned_fixture(self):
        output = self.root / "mock setup failure"
        result = subprocess.run([str(self.unit), "setup-error", str(output)], capture_output=True, text=True, timeout=5)
        self.assertEqual(result.returncode, 77, result.stderr)
        receipt = json.loads((output / "capability.json").read_text())
        self.assertEqual(receipt["status"], "unavailable")
        self.assertEqual((receipt["revision"], receipt["protocol"]), (3, "darwin-capability-raw-v3"))
        self.assertFalse(receipt["started"])
        self.assertFalse(receipt["full_trace_acceptance"])
        self.assertTrue(receipt["identity_checks_passed"])
        self.assertEqual((output / "target.stdout").read_bytes(), b"")
        self.assertEqual((output / "events.jsonl").read_bytes(), b"")
        for name, identity in receipt["evidence"].items():
            data = (output / name).read_bytes()
            self.assertEqual(identity, {"size": len(data), "sha256": hashlib.sha256(data).hexdigest()})

    def test_real_file_hashes_cover_old_limit_and_exact_raw_capture_limit(self):
        path = self.root / "large sparse raw trace"
        for size in [64 * 1024 * 1024 + 1, 128 * 1024 * 1024]:
            with self.subTest(size=size):
                with path.open("wb") as output:
                    output.truncate(size)
                expected = hashlib.sha256()
                remaining = size
                block = bytes(1024 * 1024)
                while remaining:
                    count = min(remaining, len(block))
                    expected.update(block[:count])
                    remaining -= count
                result = subprocess.run([str(self.unit), "identity", str(path)], capture_output=True, text=True, timeout=10)
                self.assertEqual(result.returncode, 0, result.stderr)
                proof = json.loads(result.stdout)
                self.assertEqual(proof["status"], "captured")
                self.assertTrue(proof["identity_checks_passed"])
                self.assertEqual(proof["identity"], {"size": size, "sha256": expected.hexdigest()})

    def test_missing_nonregular_and_oversized_identity_cannot_report_captured(self):
        oversized = self.root / "oversized sparse raw trace"
        with oversized.open("wb") as output:
            output.truncate(128 * 1024 * 1024 + 1)
        fifo = self.root / "unopened fifo"
        os.mkfifo(fifo)
        for path in [self.root / "missing identity", self.root, fifo, oversized]:
            with self.subTest(path=path.name):
                result = subprocess.run([str(self.unit), "identity", str(path)], capture_output=True, text=True, timeout=3)
                self.assertEqual(result.returncode, 1, result.stderr)
                proof = json.loads(result.stdout)
                self.assertEqual(proof["status"], "failed")
                self.assertFalse(proof["identity_checks_passed"])
                self.assertIsNone(proof["identity"])

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
