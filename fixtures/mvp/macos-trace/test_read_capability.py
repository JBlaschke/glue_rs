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
    if raw_path is not None:
        records.append({"action": 1, "size": len(raw_path), "offset": 16 + 8 * len(words), "hex": raw_path.hex()})
    return {"event": index, "cpu": 0, "epid": index, "probe_id": probe, "kind": kind,
            "timestamp": words[1], "pid": pid, "tid": words[3], "detail": detail,
            "provider": provider, "module": "", "function": function, "name": name, "records": records}


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
        self.report = {"revision": 1, "protocol": reader.PROTOCOL, "scope": reader.SCOPE,
                       "status": "captured", "reason": "SYNTHETIC FORMAT TEST ONLY", "profile": "open",
                       "host": {"system": "Darwin", "release": "synthetic", "machine": "arm64", "product_version": "synthetic", "build": "synthetic"},
                       "elapsed_seconds": 0.1, "root_pid": 600, "root_wait_status": 0, "deadline_seconds": 15,
                       "timed_out": False, "interrupted_signal": 0, "started": True, "drained": True,
                       "events": 5, "drops": 0, "errors": 0, "open_entries": 1, "open_returns": 1,
                       "argv": ["/synthetic/owned-probe", "/synthetic/input.txt"],
                       "processes": [{"pid": 600, "created": True, "terminal": True}],
                       "fixture": reader.digest((self.toolkit / "owned-probe").read_bytes()),
                       "collector": reader.digest((self.toolkit / "capture-native").read_bytes()),
                       "evidence": {}, "full_trace_acceptance": False, "settings_changed": False}
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

    def test_consistent_synthetic_transport_exports_exact_raw_records_only(self):
        summary, timeline = self.inspect()
        self.assertEqual(summary["capture_status"], "captured")
        self.assertIs(summary["full_trace_acceptance"], False)
        self.assertEqual([item["raw"] for item in timeline], self.events)
        self.assertEqual(timeline[2]["raw"]["records"][-1]["hex"], b"/synthetic/input\0".hex())
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

    def test_receipt_missing_footer_duplicate_extra_and_wrong_types(self):
        original = encoded(self.report)
        for malformed in (original[:-1], original[:-3], original.replace(b'"revision":1', b'"revision":1,"revision":1'), original.replace(b'"revision":1', b'"revision":true'), original.replace(b'"status":"captured"', b'"status":[]'), original.replace(b'"elapsed_seconds":0.1', b'"elapsed_seconds":NaN')):
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
                     lambda e: e[1].update(kind=18), lambda e: e[1].update(extra=1)]
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

    def test_tree_ledger_replay_does_not_end_at_root_exit(self):
        self.report["profile"] = "tree-mach"
        self.events = [event(1, 1, 500), event(2, 4, detail=601), event(3, 6),
                       event(4, 2, pid=601, extra=range(8)), event(5, 3, pid=601, extra=range(5)),
                       event(6, 15, pid=601, extra=range(8)), event(7, 16, pid=601, extra=(UINT := (1 << 64) - 1,)),
                       event(8, 6, pid=601), event(9, 17, 500)]
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


if __name__ == "__main__":
    unittest.main()
