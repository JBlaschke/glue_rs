"""Rebuilt-hash synthetic controls through the strict capture/toolkit API."""
import copy
from pathlib import Path
import subprocess
import sys
import unittest
from unittest import mock

import pair_calls as pairing
import test_read_capability as fixtures


class PairingTests(unittest.TestCase):
    def setUp(self):
        self.control = fixtures.CapabilityReaderTests()
        self.control.setUp()
        self.addCleanup(self.control.tearDown)
        self.control.report.update(host=dict(pairing.HOST), profile="tree",
                                   fixture=pairing.transport.digest((self.control.toolkit / "lifecycle-probe").read_bytes()),
                                   argv=["/synthetic/lifecycle-probe", "read", "/synthetic/input"])
        self.events = [self.frame(1, 500, 501), self.frame(2, function="close"),
                       self.frame(3, function="close"), self.frame(2, function="execve"),
                       self.frame(9, detail=20), self.frame(3, function="execve"), self.frame(11),
                       self.frame(7, tid=20, detail=500), self.frame(5, tid=20, detail=500),
                       self.frame(10, tid=20), self.frame(18, pid=0, detail=600, extra=(0, 1, 0x20)),
                       self.frame(2, tid=20), self.frame(14, tid=20), self.frame(3, tid=20),
                       self.frame(2, tid=20, function="exit"), self.frame(6, tid=20, detail=1),
                       self.frame(11, tid=20), self.frame(18, pid=0, tid=20, detail=600, extra=(0, 2, 0)),
                       self.frame(17, 500, 501)]

    def frame(self, kind, pid=600, tid=10, detail=0, function=None, extra=None):
        if extra is None:
            extra = (0,) * 8 if kind in {2, 15} else (3, 3, 0, 0, 0) if kind == 3 else (0,) if kind == 16 else ()
        value = fixtures.event(1, kind, pid=pid, detail=detail, extra=extra,
                               raw_path=b"/synthetic/input\0" if kind == 14 else None)
        self.header(value, "tid", tid)
        if kind in {2, 3, 14, 15, 16}:
            function = function or ("open" if kind in {2, 3, 14} else "task_self_trap")
            value["function"] = function
            roster = sorted(pairing.BSD | pairing.MACH | {"future_call"})
            number = roster.index(function)
            phase = 0 if kind in {2, 15} else 1 if kind in {3, 16} else 2
            value["probe_id"] = 1000 + 2 * number + int(phase == 1)
            value["epid"] = 1000 + 3 * number + phase
        return value

    def header(self, value, name, word):
        value[name] = word
        slot = value["header_record_indexes"][["kind", "timestamp", "pid", "tid", "detail"].index(name)]
        value["records"][slot]["hex"] = word.to_bytes(8, "little").hex()

    def publish(self, profile="tree"):
        for i, value in enumerate(self.events, 1):
            value["event"] = i
            self.header(value, "timestamp", i * 100)
        c = self.control
        c.events = self.events
        c.report.update(events=len(self.events), profile=profile,
                        open_entries=sum(e["kind"] == 2 and e["function"] == "open" for e in self.events),
                        open_returns=sum(e["kind"] == 3 and e["function"] == "open" for e in self.events))
        (c.capture / "program.d").write_bytes(pairing.transport.producer_program(600, profile))
        c.write_events()
        c.save()

    def inspect(self):
        return pairing.pair_capture(self.control.capture, self.control.toolkit)

    def reject(self, pattern):
        with self.assertRaisesRegex((pairing.UnsupportedPairing, pairing.transport.InvalidCapability), pattern):
            self.inspect()

    def test_public_api_itself_runs_strict_reader_and_retains_all_raw_words(self):
        self.publish()
        with mock.patch.object(pairing.transport, "inspect_capability", wraps=pairing.transport.inspect_capability) as reader:
            result = self.inspect()
        reader.assert_called_once()
        self.assertEqual(result["raw_frames"], self.events)
        self.assertIs(result["full_trace_acceptance"], False)
        self.assertEqual([c["family"][2] for c in result["calls"]], ["close", "execve", "open", "exit"])
        self.assertEqual(result["calls"][2]["entry_words"], [0] * 8)
        self.assertEqual(result["calls"][2]["return_words"], [3, 3, 0, 0, 0])
        self.assertEqual(result["calls"][2]["identity"], {"pid": 600, "tid": 20, "exec_epoch": 1})
        self.assertIn("receipt", result["source_transport"])
        self.assertIn("toolkit_provenance", result["source_transport"])

    def test_explicit_unreturned_outcome_never_fabricates_a_return_or_success(self):
        self.publish()
        call = self.inspect()["calls"][-1]
        self.assertEqual(call["outcome"], "terminated-without-return")
        self.assertIsNone(call["return_index"])
        self.assertIsNone(call["return_words"])
        self.assertEqual(call["termination_indexes"], [16, 17, 18])
        self.assertNotIn("success", call)

    def test_shadow_exit_during_pending_live_mach_call_does_not_flush_it(self):
        self.events.insert(10, self.frame(15, tid=20))
        self.events.insert(12, self.frame(16, tid=20, extra=(0xFFFFFFFFFFFFFFFF,)))
        self.publish("tree-mach")
        result = self.inspect()
        call = next(c for c in result["calls"] if c["family"][0] == "mach_trap")
        self.assertEqual((call["entry_index"], call["return_index"]), (11, 13))
        self.assertEqual(call["return_words"], [0xFFFFFFFFFFFFFFFF])
        self.assertEqual(result["raw_frames"][11]["kind"], 18)

    def test_orphan_return_and_recursive_or_overlapping_entry_reject(self):
        original = copy.deepcopy(self.events)
        for mutation in ("duplicate-return", "nested-entry"):
            self.events = copy.deepcopy(original)
            self.events.insert(3, copy.deepcopy(self.events[2]) if mutation == "duplicate-return" else self.frame(2, function="getpid"))
            if mutation == "nested-entry":
                self.events[2], self.events[3] = self.events[3], self.events[2]
            self.publish()
            self.reject("orphan|recursive|overlapping")

    def test_unknown_name_mismatched_function_and_provider_family_reject(self):
        original = copy.deepcopy(self.events)
        for change in ("unknown", "function", "provider"):
            self.events = copy.deepcopy(original)
            if change == "unknown":
                self.events[3] = self.frame(2, function="future_call")
            elif change == "function":
                self.events[2] = self.frame(3, function="getpid")
            else:
                self.events[2] = self.frame(16)
            self.publish("tree-mach" if change == "provider" else "tree")
            self.reject("uncalibrated|family mismatch")

    def test_missing_and_duplicate_named_open_path_clauses_reject(self):
        original = copy.deepcopy(self.events)
        for duplicate in (False, True):
            self.events = copy.deepcopy(original)
            if duplicate:
                self.events.insert(13, copy.deepcopy(self.events[12]))
            else:
                del self.events[12]
            self.publish()
            self.reject("path clause|duplicate.*path")

    def test_unknown_calling_thread_and_reused_retired_tid_reject(self):
        original = copy.deepcopy(self.events)
        for reuse in (False, True):
            self.events = copy.deepcopy(original)
            if reuse:
                self.header(self.events[4], "detail", 10)
            else:
                self.header(self.events[11], "tid", 99)
            self.publish()
            self.reject("reused thread|unknown calling thread")

    def test_unknown_pending_thread_exit_and_missing_exec_return_reject(self):
        original = copy.deepcopy(self.events)
        for scenario in ("unknown-exit", "missing-exec-return", "pending-across-exec"):
            self.events = copy.deepcopy(original)
            if scenario == "unknown-exit":
                self.events[14] = self.frame(2, tid=20, function="getpid")
            else:
                del self.events[5]
                if scenario == "pending-across-exec":
                    del self.events[5]
            self.publish()
            self.reject("unexplained pending|unresolved call crosses exec")

    def test_context_exit_cannot_retire_an_unrelated_pending_call(self):
        # The actual failed-spawn parent emits kind6 while posix_spawn is pending.
        self.events[11:11] = [self.frame(2, tid=20, function="posix_spawn"),
                              self.frame(6, tid=20, detail=1),
                              self.frame(3, tid=20, function="posix_spawn", extra=(2, 2, 0, 0, 0))]
        self.publish()
        calls = self.inspect()["calls"]
        spawned = next(c for c in calls if c["family"][2] == "posix_spawn")
        self.assertEqual(spawned["outcome"], "provider-return-observed")
        self.assertEqual(spawned["termination_indexes"], [])

    def test_missing_exit_context_process_boundary_or_returning_nonreturn_route_reject(self):
        original = copy.deepcopy(self.events)
        for scenario in ("context", "thread", "returned"):
            self.events = copy.deepcopy(original)
            if scenario == "context":
                del self.events[15]
            elif scenario == "thread":
                del self.events[16]
            else:
                self.events.insert(15, self.frame(3, tid=20, function="exit"))
            self.publish()
            self.reject("exit entry lacks|unexplained pending|nonreturning call|observed retired thread")

    def test_interleaved_threads_keep_independent_pending_calls_and_retire_worker(self):
        self.events[11:14] = [self.frame(2, tid=20, function="bsdthread_create"),
                               self.frame(9, tid=20, detail=30),
                               self.frame(3, tid=20, function="bsdthread_create"), self.frame(10, tid=30),
                               self.frame(2, tid=20), self.frame(2, tid=30, function="getpid"),
                               self.frame(3, tid=30, function="getpid"), self.frame(14, tid=20),
                               self.frame(3, tid=20), self.frame(2, tid=30, function="bsdthread_terminate"),
                               self.frame(11, tid=30)]
        self.publish()
        calls = self.inspect()["calls"]
        main = next(c for c in calls if c["family"][2] == "open")
        worker = next(c for c in calls if c["family"][2] == "getpid")
        retired = next(c for c in calls if c["family"][2] == "bsdthread_terminate")
        self.assertLess(main["entry_index"], worker["entry_index"])
        self.assertLess(worker["return_index"], main["return_index"])
        self.assertEqual(retired["identity"], {"pid": 600, "tid": 30, "exec_epoch": 1})
        self.assertEqual(retired["outcome"], "terminated-without-return")
        self.assertIsNone(retired["return_words"])
        self.assertEqual(len(retired["termination_indexes"]), 2)

    def test_new_probe_identity_for_same_phase_rejects_after_rebuilt_inventory(self):
        more = [self.frame(2, function="close"), self.frame(3, function="close")]
        more[0]["probe_id"] += 10000; more[0]["epid"] += 10000
        self.events[3:3] = more
        self.publish()
        self.reject("phase changes")

    def test_return_control_flow_or_duplicate_errno_fields_reject(self):
        original = copy.deepcopy(self.events)
        for values in ((3, 4, 0, 0, 0), (3, 3, 0, 0, 1), (3, 3, 0, (1 << 64) - 1, (1 << 64) - 1)):
            self.events = copy.deepcopy(original)
            self.events[13] = self.frame(3, tid=20, extra=values)
            self.publish()
            self.reject("unmodeled BSD return")

    def test_temporal_backtrack_and_frame_after_end_reject(self):
        self.publish()
        self.header(self.events[13], "timestamp", 1)
        self.control.write_events(); self.control.save()
        self.reject("temporal event order")
        self.events.append(self.frame(11, tid=20))
        self.publish()
        self.reject("after END")

    def test_bounds_apply_before_unbounded_maps_or_result_growth(self):
        self.publish()
        for name, value, pattern in (("MAX_EVENTS", 5, "event bound"), ("MAX_CALLS", 1, "call bound"),
                                     ("MAX_THREADS", 1, "thread bound"), ("MAX_TIMELINE_BYTES", 1, "byte bound")):
            with self.subTest(name=name), mock.patch.object(pairing, name, value):
                self.reject(pattern)

    def test_invalid_provenance_failed_capture_and_uncalibrated_host_are_rejected(self):
        self.publish()
        self.control.report["status"] = "failed"; self.control.save()
        self.reject("completed clean")
        self.control.report["status"] = "captured"
        self.control.report["host"]["build"] = "unobserved"
        self.control.save(); self.reject("host/profile")
        self.control.report["host"] = dict(pairing.HOST); self.control.save()
        (self.control.toolkit / "capture-native.c").write_text("unreviewed source")
        self.control.manifest(); self.reject("reviewed producer")

    def test_full_acceptance_api_and_cli_unconditionally_reject(self):
        with self.assertRaises(pairing.UnsupportedPairing):
            pairing.require_full_trace_acceptance({"full_trace_acceptance": True})
        result = subprocess.run([sys.executable, str(Path(pairing.__file__)), "--capture", "/absent", "--toolkit", "/absent", "--acceptance"], capture_output=True, text=True)
        self.assertEqual(result.returncode, 1)
        self.assertIn("cannot satisfy", result.stderr)
        self.assertEqual(result.stdout, "")


if __name__ == "__main__":
    unittest.main()
