"""Synthetic rehashed capture controls, never native kernel evidence."""
import hashlib
from pathlib import Path
import subprocess
import sys
import unittest
from unittest import mock

import observe_tree_open as observer
import test_pair_calls as paired_fixtures


class TreeOpenTests(unittest.TestCase):
    def setUp(self):
        self.control = paired_fixtures.PairingTests()
        self.control.setUp()
        self.addCleanup(self.control.doCleanups)
        self.entry()

    def entry(self, words=(0x1000, 0, 0, 0, 0, 0, 0, 0)):
        self.control.events[11] = self.control.frame(2, tid=20, extra=words)

    def returned(self, words):
        self.control.events[13] = self.control.frame(3, tid=20, extra=words)

    def publish(self, profile="tree"):
        self.control.publish(profile)

    def inspect(self):
        c = self.control.control
        return observer.observe_tree_capture(c.capture, c.toolkit)

    def reject(self, pattern):
        with self.assertRaisesRegex(ValueError, pattern):
            self.inspect()

    def test_api_runs_pairer_and_preserves_whole_pairs_frames_and_provenance(self):
        self.publish()
        c = self.control.control
        expected = observer.pairing.pair_capture(c.capture, c.toolkit)
        with mock.patch.object(observer.pairing, "pair_capture", wraps=observer.pairing.pair_capture) as paired:
            result = self.inspect()
        paired.assert_called_once()
        self.assertEqual(result["source_pairs"], expected)
        self.assertEqual(result["source_pairs"]["raw_frames"], self.control.events)
        self.assertIs(result["full_trace_acceptance"], False)
        self.assertEqual(len(result["observations"]), 1)
        value = result["observations"][0]
        self.assertEqual(value["observed_identity"], {"pid": 600, "tid": 20, "exec_epoch": 1})
        self.assertEqual(value["source_pair_index"], 3)
        self.assertEqual(value["source_consumer_indexes"], [12, 13, 14])
        self.assertEqual(value["raw_frames"], self.control.events[11:14])
        self.assertEqual(value["copied_user_path_hex"], b"/synthetic/input".hex())
        self.assertEqual(value["libc_result"], 3)
        self.assertEqual(result["normalizer_sha256"], hashlib.sha256(Path(observer.calibrated.__file__).read_bytes()).hexdigest())

    def test_write_capable_unknown_and_sign_bit_flags_are_preserved_as_data(self):
        for raw_flags, flags in ((2, 2), (0x20100000, 0x20100000),
                                 (0xFFFFFFFF80000002, 0x80000002), (0xFFFFFFFFFFFFFFFF, 0xFFFFFFFF)):
            with self.subTest(flags=flags):
                self.entry((0x1000, raw_flags, 0, 0, 0, 0, 0, 0)); self.publish()
                result = self.inspect(); value = result["observations"][0]
                self.assertEqual(value["flags_u32"], flags)
                self.assertEqual(result["source_pairs"]["calls"][2]["entry_words"][1], raw_flags)
                self.assertIs(result["full_trace_acceptance"], False)
                self.assertNotIn("allowed_write", value)
                self.assertNotIn("fd_object", value)

    def test_enoent_retains_request_flags_path_and_raw_failed_return(self):
        self.entry((0x1000, 2, 0, 0, 0, 0, 0, 0))
        values = [observer.calibrated.UINT64] * 3 + [2, 2]
        self.returned(values); self.publish()
        result = self.inspect(); value = result["observations"][0]
        self.assertEqual((value["libc_result"], value["errno"], value["flags_u32"]), (-1, 2, 2))
        self.assertEqual(result["source_pairs"]["calls"][2]["return_words"], values)
        self.assertEqual(value["copied_user_path_hex"], b"/synthetic/input".hex())

    def test_non_utf8_copied_path_bytes_are_never_decoded_or_rewritten(self):
        raw = b"/synthetic/\xff\xfe\x80\0".ljust(1024, b"\0")
        self.control.events[12]["records"][5]["hex"] = raw.hex(); self.publish()
        value = self.inspect()["observations"][0]
        self.assertEqual(value["copied_user_path_hex"], raw[:raw.index(0)].hex())
        self.assertEqual(value["raw_frames"][1]["records"][5]["hex"], raw.hex())
        self.assertNotIn("resolved_path", value)

    def test_unterminated_ambiguous_and_nonzero_padding_paths_reject(self):
        for raw in (b"x" * 1024, b"x" * 1023 + b"\0", b"/input\0x".ljust(1024, b"\0")):
            with self.subTest(prefix=raw[:12]):
                self.control.events[12]["records"][5]["hex"] = raw.hex(); self.publish()
                self.reject("terminator|padding")

    def test_noncanonical_flags_modes_null_pointer_and_unused_words_reject(self):
        for arguments in ((0, 0, 0, 0, 0, 0, 0, 0), (0x1000, 0x80000000, 0, 0, 0, 0, 0, 0),
                          (0x1000, 1 << 40, 0, 0, 0, 0, 0, 0), (0x1000, 0, 0o644, 0, 0, 0, 0, 0),
                          (0x1000, 0, 0, 1, 0, 0, 0, 0)):
            with self.subTest(arguments=arguments):
                self.entry(arguments); self.publish()
                self.reject("argument|zero-mode")

    def test_uncalibrated_success_errno_and_secondary_return_shapes_reject(self):
        maximum = observer.calibrated.UINT64
        for values in ((maximum, maximum, 0, 0, 0), (3, 3, 1, 0, 0),
                       (maximum, maximum, maximum, 13, 13), (maximum, maximum, 0, 2, 2)):
            with self.subTest(values=values):
                self.returned(values); self.publish()
                self.reject("calibrated tuple|ENOENT")

    def test_multithread_open_interleaving_keeps_entry_order_and_distinct_identities(self):
        f = self.control.frame
        worker_path = f(14, tid=30)
        worker_path["records"][5]["hex"] = b"/worker/input\0".ljust(1024, b"\0").hex()
        self.control.events[11:14] = [f(2, tid=20, function="bsdthread_create"),
                                     f(9, tid=20, detail=30), f(3, tid=20, function="bsdthread_create"),
                                     f(10, tid=30), f(2, tid=20, extra=(0x1000, 2, 0, 0, 0, 0, 0, 0)),
                                     f(2, tid=30, extra=(0x2000, 0x1000000, 0, 0, 0, 0, 0, 0)), worker_path,
                                     f(3, tid=30, extra=(7, 7, 0, 0, 0)), f(14, tid=20), f(3, tid=20),
                                     f(2, tid=30, function="bsdthread_terminate"), f(11, tid=30)]
        self.publish()
        result = self.inspect(); first, second = result["observations"]
        self.assertEqual((first["observed_identity"]["tid"], second["observed_identity"]["tid"]), (20, 30))
        self.assertLess(second["source_consumer_indexes"][2], first["source_consumer_indexes"][2])
        self.assertEqual((first["flags_u32"], second["flags_u32"]), (2, 0x1000000))
        self.assertEqual(second["copied_user_path_hex"], b"/worker/input".hex())
        self.assertEqual(result["source_pairs"]["raw_frames"], self.control.events)

    def test_distinct_processes_and_exec_epochs_are_preserved(self):
        f = self.control.frame
        self.control.events[11:11] = [f(2, tid=20, function="fork"), f(9, tid=20, detail=30),
                                     f(4, tid=20, detail=601), f(3, tid=20, function="fork"),
                                     f(5, pid=601, tid=30, detail=600), f(10, pid=601, tid=30),
                                     f(2, pid=601, tid=30, extra=(0x2000, 0, 0, 0, 0, 0, 0, 0)),
                                     f(14, pid=601, tid=30), f(3, pid=601, tid=30),
                                     f(2, pid=601, tid=30, function="exit"), f(6, pid=601, tid=30, detail=1),
                                     f(11, pid=601, tid=30), f(18, pid=0, tid=30, detail=601, extra=(0, 3, 0))]
        self.control.control.report["processes"].append({"pid": 601, "created": True, "terminal": True})
        self.publish()
        first, second = self.inspect()["observations"]
        self.assertEqual(first["observed_identity"], {"pid": 601, "tid": 30, "exec_epoch": 0})
        self.assertEqual(second["observed_identity"], {"pid": 600, "tid": 20, "exec_epoch": 1})

    def test_non_open_pairing_or_strict_integrity_failure_poisons_whole_result(self):
        self.control.events[2] = self.control.frame(3, function="getpid"); self.publish()
        self.reject("family mismatch")
        self.control.events[2] = self.control.frame(3, function="close"); self.publish()
        (self.control.control.capture / "target.stdout").write_bytes(b"late descendant write")
        self.reject("hash mismatch")

    def test_missing_path_and_actor_swap_reject_before_any_observation(self):
        saved = self.control.events[12]
        del self.control.events[12]; self.publish()
        self.reject("path clause")
        self.control.events.insert(12, saved)
        self.control.header(self.control.events[12], "tid", 99); self.publish()
        self.reject("unknown calling thread")

    def test_diagnostic_bound_and_historical_tree_api_remain_strict(self):
        self.publish()
        with mock.patch.object(observer, "MAX_OPENS", 0):
            self.reject("bound exceeded")
        c = self.control.control
        with self.assertRaisesRegex(observer.calibrated.UnsupportedObservation, "separate identity adapters"):
            observer.calibrated.observe_owned_capture(c.capture, c.toolkit)

    def test_full_acceptance_is_unconditional_rejection_in_api_and_cli(self):
        with self.assertRaises(observer.UnsupportedTreeOpen):
            observer.require_full_trace_acceptance({"full_trace_acceptance": True})
        result = subprocess.run([sys.executable, str(Path(observer.__file__)), "--capture", "/absent", "--toolkit", "/absent", "--acceptance"], capture_output=True, text=True)
        self.assertEqual(result.returncode, 1)
        self.assertEqual(result.stdout, "")
        self.assertIn("cannot satisfy", result.stderr)


if __name__ == "__main__":
    unittest.main()
