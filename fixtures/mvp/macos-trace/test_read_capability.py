"""Synthetic format controls only; none of these records is kernel evidence."""
import contextlib
import copy
import io
import json
import os
from pathlib import Path
import platform
import subprocess
import sys
import tempfile
import unittest
from unittest import mock

import read_capability as reader


def encoded(value):
    return (json.dumps(value, separators=(",", ":")) + "\n").encode()


def event(index, kind, pid=600, detail=0, extra=(), raw_path=None):
    provider, function, name, probe = "proc", "", reader.PROC_NAMES.get(kind, ""), 100 + kind
    if kind in {1, 17}:
        provider, name, probe = "dtrace", "BEGIN" if kind == 1 else "END", kind
    elif kind in {2, 3, 14}:
        provider, function, name, probe = "syscall", "open", "return" if kind == 3 else "entry", 11 if kind == 3 else 10
    elif kind in {15, 16}:
        provider, function, name = "mach_trap", "mach_test", "entry" if kind == 15 else "return"
    words = [kind, index * 100, pid, pid + 1, detail, *extra]
    records = [{"action": 1, "size": 8, "offset": 16 + 8 * i, "hex": value.to_bytes(8, "little").hex()} for i, value in enumerate(words)]
    leading = kind in {1, 4, 5, 7}
    if leading:
        records.insert(0, {"action": 1, "size": 0, "offset": 12, "hex": ""})
    if raw_path is not None:
        raw_path = raw_path.ljust(1024, b"\0")
        records.append({"action": 1, "size": 1024, "offset": 56, "hex": raw_path.hex()})
    return {"event": index, "cpu": 0, "epid": kind, "probe_id": probe, "kind": kind,
            "timestamp": words[1], "pid": pid, "tid": words[3], "detail": detail,
            "provider": provider, "module": "", "function": function, "name": name,
            "record_bytes": 1080 if kind == 14 else 16 + 8 * len(words),
            "header_record_indexes": list(range(1 if leading else 0, 6 if leading else 5)), "records": records}


def layout_error():
    """Conspicuously synthetic rejected metadata; not an accepted event."""
    records = [{"action": 1, "size": 0, "offset": 0, "u64": None}]
    records.extend({"action": 1, "size": 8, "offset": i * 8, "u64": value}
                   for i, value in enumerate((1, 1000, 600, 601, 0)))
    return {"kind": "layout-error", "reason": "record-layout", "cpu": -1, "epid": 7,
            "probe_id": 1, "provider": "dtrace", "module": "", "function": "", "name": "BEGIN",
            "event": 1, "nrecs": 6, "record_bytes": 40,
            "header": [record["u64"] for record in records[:5]], "records": records}


class CapabilityReaderTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory(prefix="glue synthetic capability ü ")
        self.root = Path(self.temporary.name).resolve()
        self.toolkit, self.capture = self.root / "toolkit", self.root / "capture"
        self.toolkit.mkdir()
        self.capture.mkdir()
        for name in reader.TOOLKIT:
            if name.endswith(".c"):
                data = (reader.SOURCE / name).read_bytes()
            elif name.endswith("-build.argv"):
                data = b"synthetic-compiler\0synthetic-source.c\0"
            else:
                data = ("SYNTHETIC NOT NATIVE EVIDENCE: " + name).encode()
            (self.toolkit / name).write_bytes(data)
        self.manifest()
        self.events = [event(1, 1, 500), event(2, 2, detail=500, extra=range(8)),
                       event(3, 14, raw_path=b"/synthetic/input\0"),
                       event(4, 3, detail=500, extra=(3, 0, 0, 0, 0)), event(5, 17, 500)]
        self.report = {"revision": 4, "protocol": reader.PROTOCOL, "scope": reader.SCOPE,
                       "status": "captured", "reason": "SYNTHETIC FORMAT TEST ONLY", "profile": "open",
                       "host": {"system": "Darwin", "release": "synthetic", "machine": "arm64", "product_version": "synthetic", "build": "synthetic"},
                       "elapsed_seconds": 0.1, "root_pid": 600, "root_wait_status": 0, "deadline_seconds": 15,
                       "timed_out": False, "interrupted_signal": 0, "started": True, "drained": True,
                       "events": 5, "drops": 0, "errors": 0, "open_entries": 1, "open_returns": 1,
                       "argv": ["/synthetic/owned-probe", "/synthetic/input.txt"],
                       "processes": [{"pid": 600, "created": True, "terminal": True}],
                       "fixture": reader.digest((self.toolkit / "owned-probe").read_bytes()),
                       "collector": reader.digest((self.toolkit / "capture-native").read_bytes()),
                       "evidence": {}, "identity_checks_passed": True, "full_trace_acceptance": False, "settings_changed": False}
        for name in reader.EVIDENCE:
            (self.capture / name).write_bytes(b"")
        (self.capture / "program.d").write_bytes(reader.producer_program(600, "open"))
        self.write_events()
        self.save()

    def tearDown(self):
        self.temporary.cleanup()

    def manifest(self):
        (self.toolkit / "SHA256SUMS").write_text("".join(reader.digest((self.toolkit / name).read_bytes())["sha256"] + "  ./" + name + "\n" for name in sorted(reader.TOOLKIT)))

    def write_events(self):
        (self.capture / "events.jsonl").write_bytes(b"".join(encoded(e) for e in self.events))
        probes = {}
        for e in self.events:
            if e["provider"] != "dtrace":
                probes[e["probe_id"]] = [e[name] for name in ("provider", "module", "function", "name")]
        (self.capture / "probes.tsv").write_text("".join(str(number) + "\t" + "\t".join(names) + "\n" for number, names in probes.items()))

    def save(self):
        self.report["evidence"] = {name: reader.digest((self.capture / name).read_bytes()) for name in reader.EVIDENCE}
        (self.capture / "capability.json").write_bytes(encoded(self.report))

    def inspect(self):
        output = io.BytesIO()
        summary = reader.inspect_capability(self.capture, self.toolkit, output)
        return summary, [json.loads(line) for line in output.getvalue().splitlines()]

    def rejected(self, pattern):
        with self.assertRaisesRegex(reader.InvalidCapability, pattern):
            self.inspect()

    def write_diagnostics(self, diagnostics):
        self.report.update(status="failed", drained=False)
        (self.capture / "errors.jsonl").write_bytes(b"".join(encoded(value) for value in diagnostics))
        self.save()

    def two_open_calls(self):
        self.events = [event(1, 1, 500), event(2, 2, extra=range(8)),
                       event(3, 14, raw_path=b"/synthetic/first\0"),
                       event(4, 3, extra=(3, 3, 0, 0, 0)), event(5, 2, extra=range(10, 18)),
                       event(6, 14, raw_path=b"/synthetic/second\0"),
                       event(7, 3, extra=((1 << 64) - 1,) * 3 + (2, 2)), event(8, 17, 500)]
        self.report.update(events=8, open_entries=2, open_returns=2)
        self.write_events()
        self.save()

    def tree_session(self, events, processes=None):
        self.events = events
        self.report.update(profile="tree", events=len(events),
                           processes=processes or [{"pid": 600, "created": True, "terminal": True}])
        (self.capture / "program.d").write_bytes(reader.producer_program(600, "tree"))
        self.write_events()
        self.save()

    def test_consistent_synthetic_transport_exports_exact_raw_records_only(self):
        summary, timeline = self.inspect()
        self.assertEqual(summary["capture_status"], "captured")
        self.assertIs(summary["full_trace_acceptance"], False)
        self.assertEqual([item["raw"] for item in timeline], self.events)
        self.assertEqual(timeline[2]["raw"]["records"][-1]["hex"], b"/synthetic/input\0".ljust(1024, b"\0").hex())
        self.assertEqual(timeline[3]["raw_uint64_after_header"], [3, 0, 0, 0, 0])
        self.assertNotIn("path", timeline[2])
        self.assertNotIn("success", timeline[3])
        self.assertIn("not producer or kernel attestation", summary["toolkit_provenance"]["scope"])

    def test_acceptance_always_rejected_in_api_and_cli(self):
        with self.assertRaisesRegex(reader.InvalidCapability, "unconditionally rejected"):
            reader.require_full_trace_acceptance({"full_trace_acceptance": True})
        output = self.root / "must not exist"
        result = subprocess.run([sys.executable, str(reader.SOURCE / "read_capability.py"), "--capture", str(self.capture), "--toolkit", str(self.toolkit), "--output", str(output), "--acceptance"], capture_output=True)
        self.assertEqual(result.returncode, 1)
        self.assertIn(b"unconditionally rejected", result.stderr)
        self.assertFalse(output.exists())

    def test_cli_export_exclusive_and_invalid_capture_publishes_nothing(self):
        output = self.root / "raw export"
        args = [sys.executable, str(reader.SOURCE / "read_capability.py"), "--capture", str(self.capture), "--toolkit", str(self.toolkit), "--output", str(output)]
        self.assertEqual(subprocess.run(args, capture_output=True).returncode, 0)
        before = {p.name: p.read_bytes() for p in output.iterdir()}
        self.assertEqual(set(before), {"summary.json", "timeline.jsonl"})
        self.assertEqual(subprocess.run(args, capture_output=True).returncode, 1)
        self.assertEqual(before, {p.name: p.read_bytes() for p in output.iterdir()})
        (self.capture / "events.jsonl").write_bytes(b"corrupt\n")
        args[-1] = str(self.root / "invalid export")
        self.assertEqual(subprocess.run(args, capture_output=True).returncode, 1)
        self.assertFalse(Path(args[-1]).exists())

    def test_export_cleanup_preserves_name_that_lost_exclusive_create(self):
        output = self.root / "concurrent export"
        original_open = os.open
        def concurrent_open(path, flags, *args, **kwargs):
            if path == "summary.json":
                fd = original_open(path, flags, *args, **kwargs)
                os.write(fd, b"foreign concurrent content")
                os.close(fd)
                raise FileExistsError("synthetic concurrent exclusive-create loss")
            return original_open(path, flags, *args, **kwargs)
        with mock.patch.object(reader.os, "open", side_effect=concurrent_open):
            with self.assertRaises(FileExistsError):
                reader.export_files(output, io.BytesIO(b"raw timeline"), b"summary")
        self.assertEqual((output / "summary.json").read_bytes(), b"foreign concurrent content")
        self.assertFalse((output / "timeline.jsonl").exists())

    def test_receipt_missing_footer_duplicate_extra_and_wrong_types(self):
        original = encoded(self.report)
        for malformed in (original[:-1], original[:-3], original.replace(b'"revision":4', b'"revision":4,"revision":4'), original.replace(b'"revision":4', b'"revision":true'), original.replace(b'"status":"captured"', b'"status":[]'), original.replace(b'"elapsed_seconds":0.1', b'"elapsed_seconds":NaN')):
            with self.subTest(malformed=malformed[:70]):
                (self.capture / "capability.json").write_bytes(malformed)
                self.rejected("footer|JSON|header|status|elapsed")
        self.report["unexpected"] = 1
        self.save()
        self.rejected("exact object keys")

    def test_null_and_container_types_are_rejected_for_every_receipt_field(self):
        original = copy.deepcopy(self.report)
        for name in reader.HEADER:
            for wrong_type in (None, [], {}):
                with self.subTest(field=name, value=wrong_type):
                    self.report = copy.deepcopy(original)
                    self.report[name] = wrong_type
                    (self.capture / "capability.json").write_bytes(encoded(self.report))
                    with self.assertRaises(reader.InvalidCapability):
                        self.inspect()

    def test_v2_identity_footer_is_mandatory_typed_and_failure_rejects_all_statuses(self):
        original = copy.deepcopy(self.report)
        del self.report["identity_checks_passed"]
        self.save()
        self.rejected("exact object keys")
        for status in ("captured", "failed", "unavailable"):
            for value in (False, 1, "true"):
                with self.subTest(status=status, value=value):
                    self.report = copy.deepcopy(original)
                    self.report.update(status=status, identity_checks_passed=value)
                    self.save()
                    self.rejected("identity checks failed|boolean required")
        self.report = original
        self.save()
        self.assertTrue(self.inspect()[0]["producer_identity_checks_passed"])

    def test_null_hash_and_byte_mismatch_reject(self):
        (self.capture / "target.stdout").write_bytes(b"different bytes")
        self.rejected("hash mismatch")
        self.save()
        self.report["evidence"]["events.jsonl"] = None
        (self.capture / "capability.json").write_bytes(encoded(self.report))
        self.rejected("exact object keys")

    def test_internal_escape_absolute_names_and_symlinks_rejected(self):
        for name in ("../outside", "/outside", "nested/file"):
            with self.subTest(name=name):
                report = copy.deepcopy(self.report)
                report["evidence"][name] = report["evidence"].pop("target.stdout")
                (self.capture / "capability.json").write_bytes(encoded(report))
                self.rejected("exact object keys")
        self.save()
        (self.capture / "target.stdout").unlink()
        (self.capture / "target.stdout").symlink_to(self.toolkit / "owned-probe")
        self.rejected("linked or nonregular")

    def test_root_alias_parent_alias_hardlink_and_fifo_rejected(self):
        alias = self.root / "capture alias"
        alias.symlink_to(self.capture, target_is_directory=True)
        with self.assertRaisesRegex(reader.InvalidCapability, "real directory"):
            reader.inspect_capability(alias, self.toolkit, io.BytesIO())
        parent_alias = self.root / "parent alias"
        parent_alias.symlink_to(self.root, target_is_directory=True)
        with self.assertRaisesRegex(reader.InvalidCapability, "real directory"):
            reader.inspect_capability(parent_alias / "capture", self.toolkit, io.BytesIO())
        file = self.capture / "target.stdout"
        file.unlink()
        os.link(self.toolkit / "owned-probe", file)
        self.rejected("linked or nonregular")
        file.unlink()
        os.mkfifo(file)
        self.rejected("linked or nonregular")

    def test_source_binary_and_manifest_provenance_rejected(self):
        (self.toolkit / "owned-probe").write_bytes(b"different binary")
        self.rejected("toolkit hash mismatch")
        self.manifest()
        self.rejected("fixture identity")
        self.report["fixture"] = reader.digest((self.toolkit / "owned-probe").read_bytes())
        self.save()
        (self.toolkit / "capture-native.c").write_bytes(b"different source")
        self.manifest()
        self.rejected("reviewed producer")
        manifest = (self.toolkit / "SHA256SUMS").read_bytes()
        (self.toolkit / "SHA256SUMS").write_bytes(manifest.replace(b"./capture-native.c", b"../capture-native.c"))
        self.rejected("unsafe or malformed")

    def test_record_shape_header_hex_offsets_and_sequence_controls(self):
        original = copy.deepcopy(self.events)
        mutations = [lambda e: e[1].update(event=1), lambda e: e[1].update(pid=601),
                     lambda e: e[1]["records"][0].update(size=True),
                     lambda e: e[1]["records"][0].update(hex="00"),
                     lambda e: e[1]["records"][1].update(offset=16),
                     lambda e: e[1]["records"][0].update(action=2),
                     lambda e: e[1]["records"].pop(),
                     lambda e: e[1].update(kind=max(reader.KINDS) + 1), lambda e: e[1].update(extra=1)]
        for mutation in mutations:
            with self.subTest(mutation=mutation):
                self.events = copy.deepcopy(original)
                mutation(self.events)
                self.write_events()
                self.save()
                self.rejected("event index|header|record|action|kind|exact object keys")

    def test_probe_descriptor_and_profile_mismatch(self):
        (self.capture / "probes.tsv").write_bytes(b"10\tsyscall\t\tother\tentry\n11\tsyscall\t\topen\treturn\n")
        self.save()
        self.rejected("not present")
        self.write_events()
        self.report["profile"] = "tree"
        self.save()
        self.rejected("program bytes/root/profile")

    def test_session_epid_bindings_allow_changing_call_data(self):
        self.two_open_calls()
        # An enabling can observe a different process/thread/CPU in this unit
        # model; these values and path/argument/result bytes are per-call data.
        for index in (4, 5, 6):
            value = self.events[index]
            value.update(pid=601, tid=700, cpu=1)
            for name, position in (("pid", 2), ("tid", 3)):
                value["records"][position]["hex"] = value[name].to_bytes(8, "little").hex()
        self.write_events()
        self.save()
        summary, timeline = self.inspect()
        self.assertEqual(summary["capture_status"], "captured")
        self.assertFalse(summary["full_trace_acceptance"])
        self.assertEqual([value["raw"] for value in timeline], self.events)

    def test_session_epid_phase_swaps_reject_after_rebuilt_hashes(self):
        self.two_open_calls()
        self.events[4]["epid"], self.events[6]["epid"] = self.events[6]["epid"], self.events[4]["epid"]
        self.write_events()
        self.save()
        self.rejected("EPID binding changed")

    def test_session_same_clause_cannot_switch_to_fresh_epid(self):
        self.two_open_calls()
        self.events[4]["epid"] = 1000
        self.write_events()
        self.save()
        self.rejected("multiple EPIDs")

    def test_session_epid_cannot_rebind_to_fresh_valid_probe_identity(self):
        self.two_open_calls()
        self.events[4]["probe_id"] = 1000
        self.write_events()  # New probe also enters the rebuilt inventory.
        self.save()
        self.rejected("EPID binding changed")

    def test_session_epid_cannot_change_descriptor_tuple_after_inventory_rebuild(self):
        self.two_open_calls()
        # Give the first call a different, still structurally valid module. The
        # inventory dictionary's last value is the original second-call tuple,
        # so retain both as distinct valid probe IDs to reach session checks.
        self.events[1].update(probe_id=1000, module="first-module")
        self.events[4]["probe_id"] = 1001
        self.events[4]["module"] = "second-module"
        self.write_events()
        self.save()
        self.rejected("EPID binding changed")

    def test_session_epid_cannot_alias_builtin_and_syscall_clause(self):
        self.two_open_calls()
        self.events[1]["epid"] = self.events[0]["epid"]
        self.write_events()
        self.save()
        self.rejected("EPID binding changed")

    def test_session_enabling_limit_rejects_without_large_allocations(self):
        self.two_open_calls()
        with mock.patch.object(reader, "MAX_ENABLINGS", 4):
            self.rejected("enabling count exceeds diagnostic limit")
        # Exactly five stable enabling identities occur, across eight events.
        with mock.patch.object(reader, "MAX_ENABLINGS", 5):
            self.assertEqual(self.inspect()[0]["totals"]["events"], 8)

    def test_prior_raw_receipts_are_explicitly_unsupported(self):
        for revision in (1, 2, 3):
            self.report.update(revision=revision, protocol="darwin-capability-raw-v" + str(revision))
            self.save()
            self.rejected("unsupported capability header")

    def test_v2_exact_clause_layouts_preserve_zero_descriptors(self):
        for kind in reader.KINDS:
            with self.subTest(kind=kind):
                extra = range({2: 8, 3: 5, 15: 8, 16: 1, 18: 3}.get(kind, 0))
                value = event(1, kind, detail=600 if kind in {4, 18} else 0, extra=extra, raw_path=b"synthetic\0" if kind == 14 else None)
                inventory = {} if kind in {1, 17} else {value["probe_id"]: tuple(value[name] for name in ("provider", "module", "function", "name"))}
                exported = reader.typed_event(value, 1, "tree-mach", inventory)
                self.assertEqual(exported["raw"], value)
                self.assertEqual(exported["raw_uint64_after_header"], list(extra))
                zero_indexes = [index for index, record in enumerate(value["records"]) if record["size"] == 0]
                self.assertEqual(zero_indexes, [0] if kind in {1, 4, 5, 7} else [])
                for index in zero_indexes:
                    self.assertEqual(exported["raw"]["records"][index]["hex"], "")

    def test_v2_rejects_unrecognized_zero_width_record_layouts(self):
        original = copy.deepcopy(self.events)
        mutations = [lambda e: e[0]["records"][0].update(offset=16),
                     lambda e: e[0]["records"][0].update(action=0),
                     lambda e: e[0]["records"][0].update(hex="00"),
                     lambda e: e[0]["records"].pop(0),
                     lambda e: e[1]["records"].insert(0, {"action": 1, "size": 0, "offset": 12, "hex": ""}),
                     lambda e: e[0].update(header_record_indexes=[0, 1, 2, 3, 4]),
                     lambda e: e[1].update(header_record_indexes=[False, 1, 2, 3, 4]),
                     lambda e: e[0].update(record_bytes=64),
                     lambda e: e[0]["records"][1].update(offset=24),
                     lambda e: e[2]["records"][-1].update(size=16, hex="00" * 16),
                     lambda e: e[0].update(module="unexpected")]
        for mutation in mutations:
            with self.subTest(mutation=mutation):
                self.events = copy.deepcopy(original)
                mutation(self.events)
                self.write_events()
                self.save()
                self.rejected("layout|action|record|hex|BEGIN")
        value = event(1, 18, detail=600, extra=(0, 0x12340000, 1))
        inventory = {value["probe_id"]: tuple(value[name] for name in ("provider", "module", "function", "name"))}
        value["records"][-1]["offset"] = 48
        with self.assertRaisesRegex(reader.InvalidCapability, "exact clause layout"):
            reader.typed_event(value, 1, "tree", inventory)

    def test_v2_header_bytes_kind_probe_and_profile_must_all_agree(self):
        value = event(1, 4, detail=600)
        inventory = {value["probe_id"]: tuple(value[name] for name in ("provider", "module", "function", "name"))}
        with self.assertRaisesRegex(reader.InvalidCapability, "profile"):
            reader.typed_event(value, 1, "open", inventory)
        value["records"][1]["hex"] = (5).to_bytes(8, "little").hex()
        with self.assertRaisesRegex(reader.InvalidCapability, "decoded header"):
            reader.typed_event(value, 1, "tree", inventory)

    def test_truncated_lines_and_bounded_input(self):
        for raw in (encoded(self.events[0])[:-1], b" " * (reader.MAX_LINE + 1) + b"\n"):
            (self.capture / "events.jsonl").write_bytes(raw)
            self.save()
            self.rejected("truncated JSONL")
        with (self.capture / "events.jsonl").open("wb") as stream:
            stream.truncate(reader.MAX_RAW + 1)
        # Avoid reading a sparse oversized input in the test helper.
        self.report["evidence"]["events.jsonl"] = {"size": 0, "sha256": "0" * 64}
        (self.capture / "capability.json").write_bytes(encoded(self.report))
        self.rejected("file bound/type")

    def test_footer_totals_terminal_and_completion_controls(self):
        for field, value in (("events", 4), ("open_returns", 0), ("drained", False), ("drops", 1), ("root_wait_status", 1), ("full_trace_acceptance", True)):
            with self.subTest(field=field):
                old = self.report[field]
                self.report[field] = value
                self.save()
                self.rejected("total|completion|acceptance")
                self.report[field] = old
        self.report["processes"][0]["terminal"] = False
        self.save()
        self.rejected("ledger/footer")

    def test_nonempty_watchdog_and_missing_end_rejected_after_rehash(self):
        (self.capture / "watchdog.json").write_bytes(b'{"status":"failed"}\n')
        self.save()
        self.rejected("watchdog fired")
        (self.capture / "watchdog.json").write_bytes(b"")
        self.events.pop()
        self.report["events"] = len(self.events)
        self.write_events()
        self.save()
        self.rejected("BEGIN/END")

    def test_unavailable_diagnostic_preserved_without_success(self):
        self.events = []
        self.write_events()
        self.report.update(status="unavailable", started=False, drained=False, events=0, open_entries=0, open_returns=0, root_wait_status=9)
        self.report["processes"][0]["terminal"] = False
        (self.capture / "errors.jsonl").write_bytes(b"dtrace_open: SYNTHETIC setup unavailable\n")
        self.save()
        summary, timeline = self.inspect()
        self.assertEqual(summary["capture_status"], "unavailable")
        self.assertEqual(timeline, [])
        self.assertFalse(summary["full_trace_acceptance"])
        with contextlib.redirect_stdout(io.StringIO()):
            self.assertEqual(reader.main(["--capture", str(self.capture), "--toolkit", str(self.toolkit)]), 1)

    def test_error_callback_counts_and_fields(self):
        self.report.update(status="failed", errors=1, drained=False)
        error = {"kind": "error", "cpu": -1, "fault": 1, "action": 1, "message": "synthetic fault"}
        (self.capture / "errors.jsonl").write_bytes(encoded(error))
        self.save()
        self.assertEqual(self.inspect()[0]["capture_status"], "failed")
        self.report["errors"] = 0
        self.save()
        self.rejected("callback totals")
        error["extra"] = 1
        (self.capture / "errors.jsonl").write_bytes(encoded(error))
        self.save()
        self.rejected("exact object keys")

    def test_drop_callback_counts_keep_failed_capture(self):
        self.report.update(status="failed", drops=3, drained=False)
        drop = {"kind": "drop", "cpu": 0, "drop_kind": 1, "drops": 3, "total": 3, "message": "synthetic drops"}
        (self.capture / "errors.jsonl").write_bytes(encoded(drop))
        self.save()
        self.assertEqual(self.inspect()[0]["capture_status"], "failed")
        self.report["drops"] = 2
        self.save()
        self.rejected("callback totals")

    def test_diagnostics_remain_failed_separate_from_fault_drop_totals(self):
        values = [layout_error(), {"kind": "libdtrace-error", "operation": "drain", "error": -1, "message": "synthetic failure \u00ff"}]
        self.write_diagnostics(values)
        summary, timeline = self.inspect()
        self.assertEqual(summary["producer_diagnostics"], values)
        self.assertEqual(summary["capture_status"], "failed")
        self.assertFalse(summary["full_trace_acceptance"])
        self.assertEqual(len(timeline), 5)
        self.report["errors"] = 2
        self.save()
        self.rejected("callback totals")

    def test_diagnostics_cannot_excuse_event_gaps_or_receipt_totals(self):
        self.write_diagnostics([layout_error()])
        self.events[0]["event"] = 2
        self.write_events()
        self.save()
        self.rejected("event index gap")
        self.events[0]["event"] = 1
        self.report["events"] = 6
        self.write_events()
        self.save()
        self.rejected("receipt total")

    def test_diagnostics_require_failed_started_status_and_combined_count_bound(self):
        value = {"kind": "libdtrace-error", "operation": "work", "error": 5, "message": "synthetic"}
        self.write_diagnostics([value] * 16)
        self.assertEqual(len(self.inspect()[0]["producer_diagnostics"]), 16)
        self.write_diagnostics([value] * 17)
        self.rejected("exceeds sixteen")
        for status, started in (("captured", True), ("unavailable", False), ("failed", False)):
            with self.subTest(status=status, started=started):
                self.write_diagnostics([value])
                self.report.update(status=status, started=started)
                self.save()
                self.rejected("started failed capture")

    def test_layout_diagnostic_exact_keys_types_counts_and_event_bounds(self):
        original = layout_error()
        mutations = [lambda d: d.update(extra=0), lambda d: d.update(reason="new-reason"),
                     lambda d: d.update(cpu=True), lambda d: d.update(epid=1 << 32),
                     lambda d: d.update(nrecs=1 << 31), lambda d: d.update(nrecs=True),
                     lambda d: d.update(record_bytes=-1), lambda d: d.update(header=[]),
                     lambda d: d["records"].pop(), lambda d: d["records"][0].update(extra=0),
                     lambda d: d["records"][0].update(action=-1),
                     lambda d: d["records"][0].update(action=1 << 16),
                     lambda d: d.update(event=0), lambda d: d.update(event=6),
                     lambda d: d.update(provider="x" * 65), lambda d: d.update(probe_id=True),
                     lambda d: d.update(probe_id=None), lambda d: d.update(provider="\u0100")]
        for mutation in mutations:
            with self.subTest(mutation=mutation):
                value = copy.deepcopy(original)
                mutation(value)
                self.write_diagnostics([value])
                with self.assertRaises(reader.InvalidCapability):
                    self.inspect()
        self.write_diagnostics([original, original])
        self.rejected("increasing receipt count")

    def test_layout_diagnostic_null_and_uint64_read_safety(self):
        original = layout_error()
        mutations = [lambda d: d["records"][0].update(u64=1),
                     lambda d: d["records"][1].update(offset=40),
                     lambda d: d["records"][1].update(size=9),
                     lambda d: d.update(record_bytes=8193),
                     lambda d: d["records"][1].update(u64=True),
                     lambda d: d["records"][1].update(u64=1 << 64),
                     lambda d: d["header"].__setitem__(1, True),
                     lambda d: d["header"].__setitem__(1, 2)]
        for mutation in mutations:
            with self.subTest(mutation=mutation):
                value = copy.deepcopy(original)
                mutation(value)
                self.write_diagnostics([value])
                with self.assertRaises(reader.InvalidCapability):
                    self.inspect()
        for count in (-1, -(1 << 31), 0, 21, (1 << 31) - 1):
            with self.subTest(count=count):
                value = copy.deepcopy(original)
                value.update(nrecs=count, record_bytes=(1 << 32) - 1,
                             records=[{"action": 0, "size": 0, "offset": (1 << 32) - 1, "u64": None} for _ in range(max(0, min(count, 20)))],
                             header=[None] * 5, probe_id=None,
                             provider=None, module=None, function=None, name=None)
                self.write_diagnostics([value])
                self.assertEqual(self.inspect()[0]["producer_diagnostics"], [value])
        # A null data pointer means even an in-range record remains unread.
        value = copy.deepcopy(original)
        value["header"] = [None] * 5
        for record in value["records"]:
            record["u64"] = None
        self.write_diagnostics([value])
        self.assertEqual(self.inspect()[0]["producer_diagnostics"], [value])

    def test_libdtrace_diagnostic_exact_schema_message_and_native_integer_bounds(self):
        original = {"kind": "libdtrace-error", "operation": "work", "error": 5, "message": "x" * 512}
        self.write_diagnostics([original])
        self.assertEqual(self.inspect()[0]["producer_diagnostics"], [original])
        mutations = [lambda d: d.update(operation="setup"), lambda d: d.update(error=True),
                     lambda d: d.update(error=1 << 31), lambda d: d.update(message="x" * 513),
                     lambda d: d.update(message="\u0100"), lambda d: d.update(message="nul\0byte"),
                     lambda d: d.update(message=None), lambda d: d.update(extra=0)]
        for mutation in mutations:
            with self.subTest(mutation=mutation):
                value = copy.deepcopy(original)
                mutation(value)
                self.write_diagnostics([value])
                with self.assertRaises(reader.InvalidCapability):
                    self.inspect()

    def test_malformed_truncated_and_changed_diagnostic_stream_rejected(self):
        self.write_diagnostics([layout_error()])
        raw = (self.capture / "errors.jsonl").read_bytes()
        for malformed in (raw[:-1], raw.replace(b'"cpu":-1', b'"cpu":-1,"cpu":-1'), b"{" + b" " * reader.MAX_LINE + b"\n"):
            with self.subTest(malformed=malformed[:50]):
                (self.capture / "errors.jsonl").write_bytes(malformed)
                self.save()
                self.rejected("truncated|duplicate JSON key|line bound")
        self.write_diagnostics([layout_error()])
        (self.capture / "errors.jsonl").write_bytes(raw.replace(b"record-layout", b"record-range"))
        self.rejected("hash mismatch")

    def test_tree_ledger_replay_does_not_end_at_root_exit(self):
        self.report["profile"] = "tree-mach"
        self.events = [event(1, 1, 500), event(2, 4, detail=601), event(3, 18, detail=600, extra=(0, 0x12340000, 1)),
                       event(4, 2, pid=601, extra=range(8)), event(5, 3, pid=601, extra=range(5)),
                       event(6, 15, pid=601, extra=range(8)), event(7, 16, pid=601, extra=(UINT := (1 << 64) - 1,)),
                       event(8, 18, detail=601, extra=(0, 0x12350000, 1)), event(9, 17, 500)]
        self.report.update(events=9, processes=[{"pid": 600, "created": True, "terminal": True}, {"pid": 601, "created": True, "terminal": True}])
        (self.capture / "program.d").write_bytes(reader.producer_program(600, "tree-mach"))
        self.write_events()
        self.save()
        summary, timeline = self.inspect()
        self.assertEqual(len(summary["observed_processes"]), 2)
        self.assertEqual(timeline[6]["raw_uint64_after_header"], [UINT])
        self.report["processes"].pop()
        self.save()
        self.rejected("ledger/footer")

    def test_exit_current_context_does_not_retire_root_or_attribute_target(self):
        self.report["profile"] = "tree"
        self.events = [event(1, 1, 500), event(2, 4, detail=601),
                       event(3, 6, detail=1),  # raw current-context CLD_* only
                       event(4, 2, extra=range(8)), event(5, 14, raw_path=b"/synthetic/input\0"),
                       event(6, 3, extra=(3, 3, 0, 0, 0)),
                       event(7, 18, pid=600, detail=601, extra=((1 << 64) - 1, 0x12350000, 1)),
                       event(8, 18, pid=500, detail=600, extra=(0, 0x12340000, 1)), event(9, 17, 500)]
        self.report.update(events=9, processes=[{"pid": 600, "created": True, "terminal": True},
                                               {"pid": 601, "created": True, "terminal": True}])
        (self.capture / "program.d").write_bytes(reader.producer_program(600, "tree"))
        self.write_events()
        self.save()
        summary, timeline = self.inspect()
        self.assertEqual(timeline[2]["kind_label"], "proc-exit-context")
        self.assertEqual(timeline[6]["kind_label"], "proc-exited-target")
        self.assertEqual(timeline[6]["raw_uint64_after_header"], [(1 << 64) - 1, 0x12350000, 1])
        self.assertEqual(summary["observed_processes"], self.report["processes"])
        # A current-context exit is insufficient for the actual target footer.
        self.events[6] = event(7, 6, pid=601, detail=1)
        self.write_events()
        self.save()
        self.rejected("ledger/footer")

    def test_process_target_details_reject_before_signed_pid_conversion(self):
        for kind in (4, 18):
            for target in (0, True, 1 << 31, (1 << 64) - 1):
                with self.subTest(kind=kind, target=target):
                    value = event(1, kind, detail=int(target), extra=(0, 0x12340000, 1) if kind == 18 else ())
                    value["detail"] = target
                    inventory = {value["probe_id"]: tuple(value[name] for name in ("provider", "module", "function", "name"))}
                    with self.assertRaises(reader.InvalidCapability):
                        reader.typed_event(value, 1, "tree", inventory)

    def test_v3_rejects_old_context_exit_assignment_and_wrong_target_exit_layout(self):
        values = [event(1, 6, detail=1), event(1, 18, detail=600, extra=(0, 0x12340000, 1))]
        values[0]["records"].append({"action": 1, "size": 0, "offset": 56, "hex": ""})
        values[1]["records"][-1]["offset"] = 56
        for value in values:
            inventory = {value["probe_id"]: tuple(value[name] for name in ("provider", "module", "function", "name"))}
            with self.assertRaisesRegex(reader.InvalidCapability, "record|layout"):
                reader.typed_event(value, 1, "tree", inventory)

    def test_v4_shadow_exit_retains_bytes_and_root_continues_until_nonshadow_exit(self):
        self.tree_session([event(1, 1, 500), event(2, 18, pid=0, detail=600, extra=(0, 0x11110000, 0x21)),
                           event(3, 2, extra=range(8)), event(4, 14, raw_path=b"/synthetic/input\0"),
                           event(5, 3, extra=(3, 3, 0, 0, 0)),
                           event(6, 18, pid=0, detail=600, extra=(0, 0x22220000, 1)), event(7, 17, 500)])
        summary, timeline = self.inspect()
        self.assertEqual(summary["capture_status"], "captured")
        self.assertFalse(summary["full_trace_acceptance"])
        self.assertEqual(timeline[1]["raw_uint64_after_header"], [0, 0x11110000, 0x21])
        self.assertEqual(timeline[5]["raw_uint64_after_header"], [0, 0x22220000, 1])
        self.assertEqual(timeline[1]["raw"]["records"], self.events[1]["records"])

    def test_v4_shadow_exit_after_terminal_stays_raw_without_duplicate_retirement(self):
        self.tree_session([event(1, 1, 500), event(2, 2, extra=range(8)),
                           event(3, 14, raw_path=b"/synthetic/input\0"), event(4, 3, extra=(3, 3, 0, 0, 0)),
                           event(5, 18, pid=0, detail=600, extra=(0, 0x22220000, 1)),
                           event(6, 18, pid=0, detail=600, extra=((1 << 64) - 1, 0x11110000, 0x20)),
                           event(7, 17, 500)])
        summary, timeline = self.inspect()
        self.assertEqual(summary["capture_status"], "captured")
        self.assertEqual(timeline[5]["raw_uint64_after_header"], [(1 << 64) - 1, 0x11110000, 0x20])

    def test_v4_shadow_exit_cannot_establish_terminal_completion(self):
        self.tree_session([event(1, 1, 500), event(2, 2, extra=range(8)),
                           event(3, 14, raw_path=b"/synthetic/input\0"), event(4, 3, extra=(3, 3, 0, 0, 0)),
                           event(5, 18, pid=0, detail=600, extra=(0, 0x11110000, 0x21)), event(6, 17, 500)])
        self.rejected("ledger/footer")

    def test_v4_nonshadow_duplicate_terminal_rejects_even_with_new_object_bytes(self):
        self.tree_session([event(1, 1, 500), event(2, 2, extra=range(8)),
                           event(3, 14, raw_path=b"/synthetic/input\0"), event(4, 3, extra=(3, 3, 0, 0, 0)),
                           event(5, 18, pid=0, detail=600, extra=(0, 0x22220000, 1)),
                           event(6, 18, pid=0, detail=600, extra=(0, 0x33330000, 2)), event(7, 17, 500)])
        self.rejected("duplicate nonshadow terminal")

    def test_v4_current_activity_start_and_exec_after_terminal_reject(self):
        for kind in (2, 5, 6, 7, 9, 10):
            with self.subTest(kind=kind):
                self.tree_session([event(1, 1, 500), event(2, 2, extra=range(8)),
                                   event(3, 14, raw_path=b"/synthetic/input\0"), event(4, 3, extra=(3, 3, 0, 0, 0)),
                                   event(5, 18, pid=0, detail=600, extra=(0, 0x22220000, 1)),
                                   event(6, kind, extra=range(8) if kind == 2 else ()), event(7, 17, 500)])
                self.rejected("lifecycle activity")

    def test_v4_lwp_exit_cleanup_after_terminal_stays_context_only(self):
        self.tree_session([event(1, 1, 500), event(2, 2, extra=range(8)),
                           event(3, 14, raw_path=b"/synthetic/input\0"), event(4, 3, extra=(3, 3, 0, 0, 0)),
                           event(5, 18, pid=0, detail=600, extra=(0, 0x22220000, 1)),
                           event(6, 11), event(7, 17, 500)])
        summary, timeline = self.inspect()
        self.assertEqual(summary["capture_status"], "captured")
        self.assertEqual(timeline[5]["kind_label"], "lwp-exit")

    def test_v4_create_cannot_reuse_an_observed_pid(self):
        self.tree_session([event(1, 1, 500), event(2, 4, detail=601), event(3, 4, detail=601),
                           event(4, 2, extra=range(8)), event(5, 14, raw_path=b"/synthetic/input\0"),
                           event(6, 3, extra=(3, 3, 0, 0, 0)), event(7, 17, 500)])
        self.rejected("create reuses")

    def test_v4_unknown_shadow_target_does_not_add_a_ledger_process(self):
        self.tree_session([event(1, 1, 500), event(2, 18, pid=0, detail=601, extra=(0, 0x11110000, 0x21)),
                           event(3, 2, extra=range(8)), event(4, 14, raw_path=b"/synthetic/input\0"),
                           event(5, 3, extra=(3, 3, 0, 0, 0)),
                           event(6, 18, pid=0, detail=600, extra=(0, 0x22220000, 1)), event(7, 17, 500)])
        self.assertEqual(self.inspect()[0]["observed_processes"], [{"pid": 600, "created": True, "terminal": True}])

    def test_v4_unknown_nonshadow_target_cannot_complete_the_observed_tree(self):
        self.tree_session([event(1, 1, 500), event(2, 2, extra=range(8)),
                           event(3, 14, raw_path=b"/synthetic/input\0"), event(4, 3, extra=(3, 3, 0, 0, 0)),
                           event(5, 18, pid=0, detail=601, extra=(0, 0x11110000, 1)),
                           event(6, 18, pid=0, detail=600, extra=(0, 0x22220000, 1)), event(7, 17, 500)],
                          [{"pid": 600, "created": True, "terminal": True}, {"pid": 601, "created": False, "terminal": True}])
        self.rejected("ledger/footer")

    def test_v4_create_cannot_retroactively_complete_an_unknown_terminal_target(self):
        self.tree_session([event(1, 1, 500), event(2, 18, pid=0, detail=601, extra=(0, 0x11110000, 1)),
                           event(3, 4, detail=601), event(4, 2, extra=range(8)),
                           event(5, 14, raw_path=b"/synthetic/input\0"), event(6, 3, extra=(3, 3, 0, 0, 0)), event(7, 17, 500)])
        self.rejected("create reuses")

    def test_v4_exited_identity_fields_have_exact_bounds_and_remain_raw(self):
        for address, flags in ((0, 1), (1, 1 << 32)):
            with self.subTest(address=address, flags=flags):
                value = event(1, 18, detail=600, extra=(0, address, flags))
                inventory = {value["probe_id"]: tuple(value[name] for name in ("provider", "module", "function", "name"))}
                with self.assertRaisesRegex(reader.InvalidCapability, "address|refcount"):
                    reader.typed_event(value, 1, "tree", inventory)
        value = event(1, 18, detail=600, extra=((1 << 64) - 1, 1, (1 << 32) - 1))
        inventory = {value["probe_id"]: tuple(value[name] for name in ("provider", "module", "function", "name"))}
        self.assertEqual(reader.typed_event(value, 1, "tree", inventory)["raw_uint64_after_header"],
                         [(1 << 64) - 1, 1, (1 << 32) - 1])

    def test_v4_rejects_prior_target_exit_shape_instead_of_upgrading_it(self):
        value = event(1, 18, detail=600, extra=(0,))
        value["records"].append({"action": 1, "size": 0, "offset": 64, "hex": ""})
        inventory = {value["probe_id"]: tuple(value[name] for name in ("provider", "module", "function", "name"))}
        with self.assertRaisesRegex(reader.InvalidCapability, "record byte layout|record count"):
            reader.typed_event(value, 1, "tree", inventory)

    @unittest.skipUnless(platform.system() == "Darwin", "producer C generator requires Darwin headers")
    def test_program_template_matches_actual_reviewed_c_generator(self):
        source = self.root / "generator.c"
        source.write_text('#define main capture_main\n#include "capture-native.c"\n#undef main\nint main(int argc,char **argv){return argc!=2 ? 2 : write_program(stdout,600,argv[1]);}\n')
        executable = self.root / "generator"
        subprocess.run(["/usr/bin/cc", "-Wno-deprecated-declarations", "-I", str(reader.SOURCE), str(source), "-ldtrace", "-o", str(executable)], check=True, capture_output=True)
        for profile in ("open", "tree", "tree-mach"):
            with self.subTest(profile=profile):
                result = subprocess.run([str(executable), profile], check=True, capture_output=True)
                self.assertEqual(result.stdout, reader.producer_program(600, profile))

    @unittest.skipUnless(platform.system() == "Darwin", "producer C diagnostics require Darwin headers")
    def test_actual_reviewed_c_diagnostics_match_strict_reader(self):
        executable = self.root / "synthetic-c-diagnostics"
        subprocess.run(["/usr/bin/cc", "-Wno-deprecated-declarations", str(reader.SOURCE / "test-native.c"), "-ldtrace", "-o", str(executable)], check=True, capture_output=True)
        for mode in ("layout", "layout-range", "layout-wide", "layout-limit", "libdtrace-error"):
            with self.subTest(mode=mode):
                result = subprocess.run([str(executable), mode], check=True, capture_output=True)
                values = [json.loads(line) for line in result.stdout.splitlines()]
                self.write_diagnostics(values)
                self.report["events"] = 16 if mode == "layout-limit" else 5
                self.save()
                with contextlib.closing(reader.Directory(self.capture)) as directory:
                    self.assertEqual(reader.error_totals(directory, self.report), values)
        result = subprocess.run([str(executable), "valid-layouts"], check=True, capture_output=True)
        values = [json.loads(line) for line in result.stdout.splitlines()]
        self.assertEqual([value["kind"] for value in values], list(range(1, 19)))
        for value in values:
            with self.subTest(c_producer_kind=value["kind"]):
                inventory = {} if value["provider"] == "dtrace" else {value["probe_id"]: tuple(value[name] for name in ("provider", "module", "function", "name"))}
                exported = reader.typed_event(value, 1, "tree-mach", inventory)
                self.assertEqual(exported["raw"], value)


if __name__ == "__main__":
    unittest.main()
