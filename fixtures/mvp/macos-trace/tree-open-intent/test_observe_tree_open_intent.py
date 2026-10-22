"""Complete rehashed synthetic controls; no native capture or kernel evidence."""
import copy
import hashlib
import inspect
import json
from pathlib import Path
import subprocess
import sys
import unittest
from unittest import mock

import observe_tree_open_intent as observer
import test_pair_calls as paired_fixtures


class TreeOpenIntentTests(unittest.TestCase):
    def setUp(self):
        self.control = paired_fixtures.PairingTests()
        self.control.setUp()
        self.addCleanup(self.control.doCleanups)
        self.entry()

    def entry(self, flags=0):
        raw = flags if flags < (1 << 31) else flags | 0xFFFFFFFF00000000
        self.control.events[11] = self.control.frame(2, tid=20, extra=(0x1000, raw, 0, 0, 0, 0, 0, 0))

    def publish(self):
        self.control.publish()

    def observe(self):
        fixture = self.control.control
        return observer.observe_tree_open_intent(fixture.capture, fixture.toolkit)

    def cli(self, *extra):
        fixture = self.control.control
        return subprocess.run([sys.executable, "-B", str(Path(observer.__file__)),
                               "--capture", str(fixture.capture), "--toolkit", str(fixture.toolkit),
                               *extra], capture_output=True, text=True, timeout=15)

    def baseline(self):
        self.publish()
        report = self.observe()
        self.assertEqual(report["classifications"][0]["intent"], "read-access-request")
        return report

    def test_public_paths_api_runs_strict_observer_and_preserves_complete_source(self):
        self.publish()
        fixture = self.control.control
        expected = observer.tree_open.observe_tree_capture(fixture.capture, fixture.toolkit)
        with mock.patch.object(observer.tree_open, "observe_tree_capture", wraps=observer.tree_open.observe_tree_capture) as upstream:
            report = self.observe()
        upstream.assert_called_once_with(fixture.capture, fixture.toolkit)
        self.assertEqual(report["source_observations"], expected)
        self.assertEqual(report["source_observations"]["source_pairs"]["raw_frames"], self.control.events)
        self.assertEqual([call["family"][2] for call in report["source_observations"]["source_pairs"]["calls"]],
                         ["close", "execve", "open", "exit"])
        value = report["classifications"][0]
        self.assertEqual(value["source_observation_index"], 1)
        self.assertEqual(value["source_pair_index"], 3)
        self.assertEqual(value["source_consumer_indexes"], [12, 13, 14])
        self.assertEqual(value["observed_identity"], {"pid": 600, "tid": 20, "exec_epoch": 1})
        self.assertIs(report["full_trace_acceptance"], False)
        self.assertEqual(report["abi_sha256"], hashlib.sha256(observer.intent.ABI_BYTES).hexdigest())
        self.assertEqual(report["classifier_sha256"], hashlib.sha256(Path(observer.intent.__file__).read_bytes()).hexdigest())
        self.assertEqual(report["observer_sha256"], hashlib.sha256(Path(observer.__file__).read_bytes()).hexdigest())

    def test_flag_semantics_read_event_write_and_modifiers(self):
        for flags, intent, reasons in ((0, "read-access-request", []),
                                       (0x01000000, "read-access-request", []),
                                       (0x20100000, "read-access-request", []),
                                       (0x8000, "event-access-request", []),
                                       (1, "write-request", ["write-access"]),
                                       (2, "write-request", ["write-access"]),
                                       (8, "write-request", ["O_APPEND"]),
                                       (0x200, "write-request", ["O_CREAT"]),
                                       (0x400, "write-request", ["O_TRUNC"]),
                                       (0x8000 | 0x200, "write-request", ["O_CREAT"]),
                                       (2 | 8 | 0x200 | 0x400, "write-request", ["write-access", "O_APPEND", "O_CREAT", "O_TRUNC"])):
            with self.subTest(flags=flags):
                self.entry(flags); self.publish()
                report = self.observe(); value = report["classifications"][0]
                self.assertEqual((value["flags_u32"], value["intent"], value["write_reasons"]), (flags, intent, reasons))
                self.assertEqual((value["unmodeled_bits"], value["unknown_bits"]), (0, 0))
                self.assertIs(report["full_trace_acceptance"], False)

    def test_failed_write_request_retains_source_path_and_return(self):
        self.entry(2 | 0x200)
        raw_return = (0xFFFFFFFFFFFFFFFF,) * 3 + (2, 2)
        self.control.events[13] = self.control.frame(3, tid=20, extra=raw_return)
        self.publish()
        report = self.observe(); value = report["classifications"][0]
        source = report["source_observations"]["observations"][0]
        self.assertEqual(value["write_reasons"], ["write-access", "O_CREAT"])
        self.assertEqual(value["no_output_policy"], "reject-write-intent")
        self.assertEqual((source["libc_result"], source["errno"]), (-1, 2))
        self.assertEqual(source["copied_user_path_hex"], b"/synthetic/input".hex())
        self.assertEqual(report["source_observations"]["source_pairs"]["calls"][2]["return_words"], list(raw_return))

    def test_unknown_unmodeled_and_high_flags_remain_unsupported_with_reasons(self):
        for flags, unknown in ((3, 0), (0x00200000, 0), (0x80000000, 0x80000000),
                               (0x80000002, 0x80000000), (0x8001, 0)):
            with self.subTest(flags=flags):
                self.entry(flags); self.publish()
                report = self.observe(); value = report["classifications"][0]
                self.assertEqual((value["flags_u32"], value["intent"], value["no_output_policy"]),
                                 (flags, "unsupported", "reject-unsupported"))
                self.assertEqual(value["unknown_bits"], unknown)
                if flags & 3 in (1, 2):
                    self.assertIn("write-access", value["write_reasons"])
                if flags == 0x00200000:
                    self.assertIn("O_SYMLINK", value["unmodeled_sdk_flags"])
                self.assertEqual(report["source_observations"]["observations"][0]["flags_u32"], flags)
                self.assertIs(report["full_trace_acceptance"], False)

    def test_direct_classifier_used_without_manufacturing_normalized_origin(self):
        self.entry(2); self.publish()
        with mock.patch.object(observer.intent, "decode", side_effect=AssertionError("normalized decoder forbidden")), \
                mock.patch.object(observer.intent, "classify_flags", wraps=observer.intent.classify_flags) as classifier:
            report = self.observe()
        classifier.assert_called_once_with(2)
        self.assertNotIn("raw_normalized_request", report["classifications"][0])
        self.assertEqual(tuple(inspect.signature(observer.observe_tree_open_intent).parameters), ("capture", "toolkit"))
        with self.assertRaises(TypeError):
            observer.observe_tree_open_intent(self.control.control.capture, self.control.control.toolkit, observations={})

    def test_multithread_interleaving_keeps_entry_order_and_links(self):
        frame = self.control.frame
        worker_path = frame(14, tid=30)
        worker_path["records"][5]["hex"] = b"/worker/\xff\0".ljust(1024, b"\0").hex()
        self.control.events[11:14] = [frame(2, tid=20, function="bsdthread_create"),
            frame(9, tid=20, detail=30), frame(3, tid=20, function="bsdthread_create"), frame(10, tid=30),
            frame(2, tid=20, extra=(0x1000, 2, 0, 0, 0, 0, 0, 0)),
            frame(2, tid=30, extra=(0x2000, 0x8000, 0, 0, 0, 0, 0, 0)), worker_path,
            frame(3, tid=30, extra=(7, 7, 0, 0, 0)), frame(14, tid=20), frame(3, tid=20),
            frame(2, tid=30, function="bsdthread_terminate"), frame(11, tid=30)]
        self.publish(); report = self.observe(); first, second = report["classifications"]
        self.assertEqual((first["source_observation_index"], second["source_observation_index"]), (1, 2))
        self.assertEqual((first["observed_identity"]["tid"], second["observed_identity"]["tid"]), (20, 30))
        self.assertEqual((first["intent"], second["intent"]), ("write-request", "event-access-request"))
        self.assertLess(second["source_consumer_indexes"][2], first["source_consumer_indexes"][2])
        source = report["source_observations"]["observations"][1]
        self.assertEqual(source["copied_user_path_hex"], b"/worker/\xff".hex())
        for index, value in enumerate((first, second)):
            original = report["source_observations"]["observations"][index]
            self.assertEqual(value["source_pair_index"], original["source_pair_index"])
            self.assertEqual(value["source_consumer_indexes"], original["source_consumer_indexes"])

    def test_process_and_exec_actor_provenance_preserved(self):
        frame = self.control.frame
        self.control.events[11:11] = [frame(2, tid=20, function="fork"), frame(9, tid=20, detail=30),
            frame(4, tid=20, detail=601), frame(3, tid=20, function="fork"),
            frame(5, pid=601, tid=30, detail=600), frame(10, pid=601, tid=30),
            frame(2, pid=601, tid=30, extra=(0x2000, 0x200, 0, 0, 0, 0, 0, 0)),
            frame(14, pid=601, tid=30), frame(3, pid=601, tid=30),
            frame(2, pid=601, tid=30, function="exit"), frame(6, pid=601, tid=30, detail=1),
            frame(11, pid=601, tid=30), frame(18, pid=0, tid=30, detail=601, extra=(0, 3, 0))]
        self.control.control.report["processes"].append({"pid": 601, "created": True, "terminal": True})
        self.publish(); first, second = self.observe()["classifications"]
        self.assertEqual(first["observed_identity"], {"pid": 601, "tid": 30, "exec_epoch": 0})
        self.assertEqual(second["observed_identity"], {"pid": 600, "tid": 20, "exec_epoch": 1})
        self.assertEqual((first["intent"], second["intent"]), ("write-request", "read-access-request"))

    def test_non_open_pairing_failure_poisons_valid_baseline_before_classifying(self):
        self.baseline()
        self.control.events[2] = self.control.frame(3, function="getpid"); self.publish()
        with mock.patch.object(observer.intent, "classify_flags", side_effect=AssertionError("classification before validation")):
            with self.assertRaisesRegex(ValueError, "family mismatch"):
                self.observe()

    def test_integrity_failure_poisons_valid_baseline_and_cli_has_no_report(self):
        self.baseline()
        (self.control.control.capture / "target.stdout").write_bytes(b"late mutation")
        with self.assertRaisesRegex(ValueError, "hash mismatch"):
            self.observe()
        result = self.cli()
        self.assertEqual(result.returncode, 1)
        self.assertEqual(result.stdout, "")
        self.assertIn("hash mismatch", result.stderr)

    def test_path_and_noncanonical_flag_failures_do_not_become_intent(self):
        self.baseline(); original = copy.deepcopy(self.control.events)
        for invalid in ("path", "flags", "mode"):
            with self.subTest(invalid=invalid):
                self.control.events = copy.deepcopy(original)
                if invalid == "path":
                    del self.control.events[12]
                else:
                    args = (0x1000, 0x80000000, 0, 0, 0, 0, 0, 0) if invalid == "flags" else (0x1000, 0, 0o644, 0, 0, 0, 0, 0)
                    self.control.events[11] = self.control.frame(2, tid=20, extra=args)
                self.publish()
                with self.assertRaisesRegex(ValueError, "path clause|signed syscall|zero-mode"):
                    self.observe()

    def test_inherited_open_bound_refuses_before_classification(self):
        self.baseline()
        with mock.patch.object(observer.tree_open, "MAX_OPENS", 0), \
                mock.patch.object(observer.intent, "classify_flags", side_effect=AssertionError("classification past bound")):
            with self.assertRaisesRegex(ValueError, "bound exceeded"):
                self.observe()

    def test_cli_distinguishes_classification_from_unsupported_and_acceptance(self):
        for flags, status, classification in ((0, 0, "read-access-request"), (2, 0, "write-request"),
                                               (0x80000002, 1, "unsupported")):
            with self.subTest(flags=flags):
                self.entry(flags); self.publish(); result = self.cli()
                self.assertEqual(result.returncode, status, result.stderr)
                self.assertEqual(result.stderr, "")
                report = json.loads(result.stdout)
                self.assertEqual(report["classifications"][0]["intent"], classification)
                self.assertIs(report["full_trace_acceptance"], False)

    def test_full_acceptance_always_refuses_before_input_access(self):
        with self.assertRaisesRegex(observer.UnsupportedTreeOpenIntent, "cannot satisfy"):
            observer.require_full_trace_acceptance({"full_trace_acceptance": True})
        with mock.patch.object(observer, "observe_tree_open_intent", side_effect=AssertionError("input accessed")):
            with mock.patch("sys.stderr"):
                self.assertEqual(observer.main(["--capture", "/absent", "--toolkit", "/absent", "--acceptance"]), 1)
        result = subprocess.run([sys.executable, "-B", str(Path(observer.__file__)), "--capture", "/absent",
                                 "--toolkit", "/absent", "--acceptance"], capture_output=True, text=True, timeout=15)
        self.assertEqual(result.returncode, 1)
        self.assertEqual(result.stdout, "")
        self.assertIn("cannot satisfy", result.stderr)
        self.assertNotIn("No such file", result.stderr)


if __name__ == "__main__":
    unittest.main()
