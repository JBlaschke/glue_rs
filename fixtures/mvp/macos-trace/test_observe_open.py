"""Synthetic boundary controls for the adapter; actual guest replay is separate."""
import copy
import json
from pathlib import Path
import subprocess
import sys
import unittest
from unittest import mock

import observe_open as observer
import test_read_capability as support


class OpenObservationTests(unittest.TestCase):
    def setUp(self):
        self.fixture = support.CapabilityReaderTests()
        self.fixture.setUp()
        self.addCleanup(self.fixture.tearDown)
        self.fixture.report["host"] = dict(observer.HOST)
        self.request = (0x1234, 0, 0, 0, 0, 0, 0, 0)
        self.returned = (3, 3, 0, 0, 0)
        self.path = b"/synthetic/\xff\0"
        self.prepare()

    def prepare(self):
        self.fixture.events = [support.event(1, 1, 500),
                               support.event(2, 2, extra=self.request),
                               support.event(3, 14, raw_path=self.path),
                               support.event(4, 3, extra=self.returned),
                               support.event(5, 17, 500)]
        self.save()

    def save(self):
        self.fixture.write_events()
        self.fixture.save()

    def inspect(self):
        return observer.observe_owned_capture(self.fixture.capture, self.fixture.toolkit)

    def rejected(self, pattern):
        with self.assertRaisesRegex((observer.UnsupportedObservation, observer.transport.InvalidCapability), pattern):
            self.inspect()

    def test_real_record_api_preserves_raw_frames_and_non_utf8_request_bytes(self):
        result = self.inspect()
        self.assertFalse(result["full_trace_acceptance"])
        call, = result["calls"]
        self.assertEqual(call["copied_user_path_hex"], b"/synthetic/\xff".hex())
        self.assertEqual(call["raw_frames"], self.fixture.events[1:4])
        self.assertEqual((call["libc_result"], call["errno"]), (3, 0))
        self.assertNotIn("resolved_path", call)
        self.assertIn("not kernel attestation", result["scope"])

    def test_calibrated_failure_and_write_flags_remain_observations(self):
        self.returned = (observer.UINT64,) * 3 + (2, 2)
        self.request = (0x1234, 2, 0, 0, 0, 0, 0, 0)
        self.prepare()
        call, = self.inspect()["calls"]
        self.assertEqual((call["flags_u32"], call["libc_result"], call["errno"]), (2, -1, 2))
        self.assertNotIn("allowed", call)

    def test_signed_argument_requires_exact_sign_extension(self):
        self.assertEqual(observer.signed_argument(observer.UINT64, 32), 0xffffffff)
        with self.assertRaises(observer.UnsupportedObservation):
            observer.signed_argument(0xffffffff, 32)
        self.request = (0x1234, 0xffffffff, 0, 0, 0, 0, 0, 0)
        self.prepare()
        self.rejected("noncanonical")

    def test_unknown_return_abi_or_error_cannot_be_normalized(self):
        for returned in ((3, 0, 0, 0, 0), (3, 3, 1, 0, 0), (3, 3, 0, 0, 2),
                         (observer.UINT64,) * 3 + (13, 13), (3, 3, 0, 2, 2)):
            with self.subTest(returned=returned):
                self.returned = returned
                self.prepare()
                self.rejected("tuple")

    def test_unknown_modes_and_argument_shape_reject(self):
        for request in ((0, 0, 0, 0, 0, 0, 0, 0), (1, 0, 0o600, 0, 0, 0, 0, 0),
                        (1, 0, 0, 1, 0, 0, 0, 0)):
            with self.subTest(request=request):
                self.request = request
                self.prepare()
                self.rejected("argument|zero-mode")

    def test_truncated_ambiguous_or_nonzero_padded_path_rejects(self):
        for raw_path in (b"x" * 1024, b"x" * 1023 + b"\0", b"x\0hidden"):
            with self.subTest(raw_path=raw_path[:20]):
                self.path = raw_path
                self.prepare()
                self.rejected("terminator|padding")

    def test_orphan_and_duplicate_phases_reject_even_with_consistent_totals(self):
        for permutation in ((2, 1, 3), (1, 3, 2)):
            with self.subTest(permutation=permutation):
                self.prepare()
                middle = [copy.deepcopy(self.fixture.events[index]) for index in permutation]
                for index, frame in enumerate(middle, 2):
                    frame["event"] = index
                self.fixture.events[1:4] = middle
                self.save()
                self.rejected("orphan|pathless")

    def test_extra_thread_and_different_entry_clause_reject(self):
        self.fixture.events[2]["epid"] = self.fixture.events[1]["epid"]
        self.save()
        self.rejected("separate clause|probe identity changes open phase")
        self.prepare()
        self.fixture.events[2] = support.event(3, 14, pid=600, raw_path=self.path)
        self.fixture.events[2]["tid"] = 999
        self.fixture.events[2]["records"][3]["hex"] = (999).to_bytes(8, "little").hex()
        self.save()
        self.rejected("calling thread")

    def test_host_completion_profile_fixture_and_provenance_are_required(self):
        self.fixture.report["host"]["build"] = "unverified"
        self.fixture.save()
        self.rejected("calibration")
        self.fixture.report["host"] = dict(observer.HOST)
        self.fixture.report["status"] = "failed"
        self.fixture.save()
        self.rejected("completed clean")
        self.fixture.report["status"] = "captured"
        self.fixture.report["argv"].append("unobserved")
        self.fixture.save()
        self.rejected("invocation")
        self.fixture.report["argv"].pop()
        self.fixture.save()
        with (self.fixture.capture / "events.jsonl").open("ab") as stream:
            stream.write(b"corruption\n")
        self.rejected("JSON|hash|truncated")

    def two_calls(self):
        self.fixture.events = [support.event(1, 1, 500),
            support.event(2, 2, extra=self.request), support.event(3, 14, raw_path=self.path),
            support.event(4, 3, extra=self.returned), support.event(5, 2, extra=self.request),
            support.event(6, 14, raw_path=self.path), support.event(7, 3, extra=self.returned), support.event(8, 17, 500)]
        for index, epid in enumerate((1, 2, 3, 4, 2, 3, 4, 5)):
            self.fixture.events[index]["epid"] = epid
        self.fixture.report.update(events=8, open_entries=2, open_returns=2)
        self.save()

    def test_phases_must_share_the_same_syscall_descriptor_family(self):
        self.fixture.events[3]["module"] = "different-module"
        self.save()
        self.rejected("descriptor families")

    def test_enabled_probe_roles_cannot_swap_or_change_across_calls(self):
        self.two_calls()
        self.assertEqual(len(self.inspect()["calls"]), 2)
        self.fixture.events[4]["epid"], self.fixture.events[5]["epid"] = 3, 2
        self.save()
        self.rejected("probe identity|open phase")
        self.two_calls()
        self.fixture.events[4]["epid"] = 99
        self.save()
        self.rejected("probe identity")

    def test_ordered_triples_cannot_move_backwards_between_calls(self):
        self.two_calls()
        for index, timestamp in ((4, 1), (5, 11), (6, 21)):
            frame = self.fixture.events[index]
            frame["timestamp"] = timestamp
            frame["records"][1]["hex"] = timestamp.to_bytes(8, "little").hex()
        self.save()
        self.rejected("moves backwards")

    def test_bound_and_acceptance_rejection_in_api_and_cli(self):
        with mock.patch.object(observer, "MAX_CALLS", 0):
            self.rejected("bound")
        with self.assertRaises(observer.UnsupportedObservation):
            observer.require_full_trace_acceptance({"full_trace_acceptance": True})
        result = subprocess.run([sys.executable, str(Path(observer.__file__)), "--capture", str(self.fixture.capture),
                                 "--toolkit", str(self.fixture.toolkit), "--acceptance"], capture_output=True, timeout=5)
        self.assertEqual(result.returncode, 1)
        self.assertEqual(result.stdout, b"")
        self.assertIn(b"cannot satisfy", result.stderr)


if __name__ == "__main__":
    unittest.main()
