"""Actual traced-runtime source integration with explicit process/provider stubs.
No native child, provider, privilege transition or configured admission runs.
"""
import hashlib
import json
import os
from pathlib import Path
import platform
import re
import struct
import subprocess
import tempfile
import unittest

HERE = Path(__file__).resolve().parent
BASE = HERE.parent
RUNTIME = BASE / "bootstrap-runtime-runner"
SCENARIOS = (
    "good", "no_readiness", "helper_prefix", "partial_go", "failed_full_go",
    "failed_go_and_close", "full_status_prefix", "echild", "reap_clock",
    "cleanup_clock", "held_reference_open", "cwd_reference_open", "backend_close",
    "snapshot_failure", "destroy_failure", "witness_write", "witness_close",
    "prefix_write", "delivery_write", "sidecar_close", "pending_close",
    "output_close", "simulated_provider_failure", "oversize_output",
    "create_failure", "start_failure",
)


def digest_stub(data):
    result = bytearray(32)
    for i, value in enumerate(data):
        result[i % 32] ^= (value + i) & 255
    return bytes(result)


def quoted_dependencies(paths):
    result = {}
    pending = list(paths)
    while pending:
        path = pending.pop().resolve()
        if path in result:
            continue
        raw = path.read_bytes()
        result[path] = raw
        for name in re.findall(rb'^\s*#include\s+"([^"]+)"', raw, re.MULTILINE):
            pending.append(path.parent / name.decode("utf-8"))
    return result


class RuntimeTraceRunnerControls(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.temp = None
        retain = os.environ.get("GLUE_RUNTIME_TRACE_RUNNER_RETAIN")
        if retain:
            cls.output = Path(retain)
            cls.output.mkdir(parents=True, exist_ok=False, mode=0o700)
        else:
            cls.temp = tempfile.TemporaryDirectory(prefix="glue runtime trace ü ")
            cls.output = Path(cls.temp.name)
        cls.sources = [HERE / "test_runtime_trace_runner.c", HERE / "runtime_trace_protocol.c"]
        cls.sources += [RUNTIME / name for name in ("runtime_catalog.c", "runtime_request.c", "catalog_unconfigured.c")]
        cls.sources += [BASE / name for name in (
            "target-launch/target_launch.c", "trace-session/trace_session.c",
            "bootstrap-request/bootstrap_request.c", "bootstrap-wire/bootstrap_wire.c",
            "bootstrap-object-wire/bootstrap_object_wire.c", "bootstrap-probe/probe_report.c",
            "bootstrap-io/bootstrap_io.c", "bootstrap-signals/bootstrap_signals.c",
            "bootstrap-admission/bootstrap_admission.c", "target-credentials/target_credentials.c",
            "target-endpoints/target_endpoints.c")]
        production = [HERE / ("runtime_trace_" + name + ".c") for name in (
            "child", "parent", "protocol", "support", "files", "admission", "witness", "trace")]
        production += [HERE / "build.sh", BASE / "runtime-boundary/runtime_trace_backend.c",
                       BASE / "runtime-boundary/runtime_trace_program.c", RUNTIME / "test_runtime_child.c"]
        cls.before = quoted_dependencies([*cls.sources, *production, Path(__file__).resolve()])
        (cls.output / "sources.json").write_text(json.dumps({str(p): hashlib.sha256(raw).hexdigest()
            for p, raw in sorted(cls.before.items())}, indent=2) + "\n")
        sanitize = os.environ.get("GLUE_RUNTIME_TRACE_RUNNER_SANITIZE", "0")
        if sanitize not in ("0", "1"):
            raise ValueError("GLUE_RUNTIME_TRACE_RUNNER_SANITIZE must be 0 or 1")
        cls.flags = ["-std=c11", "-D_DEFAULT_SOURCE", "-D_DARWIN_C_SOURCE", "-Wall", "-Wextra", "-Werror", "-pedantic", "-O1", "-g"]
        if sanitize == "1":
            cls.flags += ["-fsanitize=address,undefined", "-fno-omit-frame-pointer"]
        cls.binary = cls.output / "parent-models"
        cls.command("parent-compile", ["/usr/bin/cc", *cls.flags, *map(str, cls.sources), "-o", str(cls.binary)])
        child = cls.output / "child-model.c"
        child.write_text('#include "' + str(HERE / "runtime_trace_profile.h") + '"\n#include "' + str(RUNTIME / "test_runtime_child.c") + '"\n')
        cls.child = cls.output / "child-model"
        cls.command("child-compile", ["/usr/bin/cc", *cls.flags, str(child),
            str(BASE / "bootstrap-wire/bootstrap_wire.c"), str(BASE / "bootstrap-object-wire/bootstrap_object_wire.c"),
            str(BASE / "target-launch/target_launch.c"), "-o", str(cls.child)])

    @classmethod
    def command(cls, label, argv, expected=0):
        result = subprocess.run(argv, capture_output=True, timeout=60)
        for stream in ("stdout", "stderr"):
            (cls.output / (label + "." + stream)).write_bytes(getattr(result, stream))
        (cls.output / (label + ".json")).write_text(json.dumps(
            {"argv": argv, "exit": result.returncode, "expected": expected}, indent=2) + "\n")
        if result.returncode != expected:
            raise AssertionError(label + ": " + result.stderr.decode("utf-8", "replace"))
        return result

    @classmethod
    def tearDownClass(cls):
        if any(p.read_bytes() != raw for p, raw in cls.before.items()):
            raise AssertionError("runtime trace source bytes changed during controls")
        if cls.temp:
            cls.temp.cleanup()

    def scenario(self, index):
        result = self.command(SCENARIOS[index], [str(self.binary), str(index)])
        self.assertEqual(result.stderr, b"")
        data = json.loads(result.stdout)
        stats = data["stats"]
        self.assertLessEqual(stats["go_calls"], 1)
        self.assertLessEqual(stats["destroys"], 1)
        files = {name: bytes.fromhex(value) for name, value in data["files"].items()}
        trace = data["trace"]
        pending = data["pending_result"]
        if trace is not None:
            self.assertEqual(trace["schema"], "glue-runtime-recipe-trace-session-diagnostic-v1")
            self.assertTrue(trace["tracing"])
            self.assertFalse(trace["exec_proved"] or trace["full_acceptance"])
            if trace["session_present"]:
                self.assertEqual(trace["session"]["binding"]["fixture"], 2)
                self.assertEqual(trace["session"]["binding"]["owner_pid"], 100)
                self.assertEqual(trace["session"]["binding"]["target_pid"], 200)
            runtime = trace["runtime_recipe"]
            self.assertFalse(runtime["native_admission"] or runtime["output_capabilities_authorized"])
        if pending is not None:
            self.assertEqual(pending["schema"], "glue-owned-runtime-recipe-traced-diagnostic-v1")
            self.assertTrue(pending["tracing"])
            self.assertFalse(pending["exec_proved"] or pending["full_acceptance"])
            if index != 20:  # A failed pending close can retain unpromoted success JSON.
                self.assertEqual(pending["status"], "passed" if index == 0 else "failed")
        if index == 0:
            if platform.system() == "Darwin":
                self.assertEqual(data["finish"], 0)
                self.assertEqual(stats["promotions"], 1)
                self.assertIsNotNone(pending)
                self.assertEqual(pending["status"], "passed")
            self.assertEqual(data["execute"], 0)
            self.assertEqual(stats["session_prefix"], 1024)
            self.assertEqual(stats["status_bytes"], 1024)
            self.assertEqual(stats["kills"], 0)
            self.assertEqual((stats["creates"], stats["destroys"], stats["final_snapshots"]), (1, 1, 1))
            self.assertEqual(files["app.stdout"], b"\0opaque\n")
            self.assertEqual(files["app.stderr"], b"err")
            self.assertEqual(trace["runtime_recipe"]["selected_exec_entry_count"], 2)
            self.assertEqual(trace["runtime_recipe"]["selected_exec_success_count"], 2)
            self.assertEqual(trace["session"]["cleanup_deadline_ns"], trace["backend"]["cleanup_deadline_ns"])
            status = files["status.bin"]
            self.assertEqual(status[:8], b"GLUEFS02")
            self.assertEqual(status[512:520], b"GLUEFS02")
            self.assertEqual(struct.unpack_from(">I", status, 288 + 12)[0] & 0o170000, 0o020000)
            witness = files["output-witness.bin"]
            self.assertEqual(len(witness), 320)
            self.assertEqual(witness[:8], b"GLUERW01")
            self.assertEqual(struct.unpack_from(">3I", witness, 16), (100, 200, 4))
            self.assertEqual(witness[32:64], status[56:88])
            self.assertEqual(witness[64:96].hex(), trace["session"]["binding"]["catalog_sha256"])
            self.assertEqual(witness[96:128], digest_stub(status[:512]))
            self.assertEqual(witness[160:240], witness[240:320])
            for role in range(2):
                parent = witness[160 + 40 * role:200 + 40 * role]
                child = status[328 + 40 * role:368 + 40 * role]
                self.assertEqual(struct.unpack_from(">2I", parent), (16 + role, 1))
                self.assertEqual(parent[8:], child[8:])
                self.assertEqual(struct.unpack_from(">I", parent, 8)[0], 0x1000001)
            self.assertEqual(files["go-prefix.bin"][12:52], status[48:88])
            self.assertEqual(struct.unpack_from(">9I", files["gate-delivery.bin"], 128), (64, 0, 0, 0, 0, 0, 1, 0, 0))
        if index in (1, 2, 15, 16, 24, 25):
            self.assertEqual(stats["go_calls"], 0)
        if index == 2:
            witness = files["output-witness.bin"]
            self.assertEqual(struct.unpack_from(">I", witness, 24)[0], 3)
            self.assertEqual(witness[280:], bytes(40))
            self.assertNotEqual(witness[168:172], witness[248:252])
            self.assertEqual(stats["creates"], 0)
        if index in (3, 4, 5):
            count = 13 if index == 3 else 64
            self.assertEqual(len(files["go-prefix.bin"]), count)
            fields = struct.unpack_from(">9I", files["gate-delivery.bin"], 128)
            self.assertEqual(fields[:6], (count, 9, 20, 0, count, 0xFFFFFFFF))
            self.assertEqual(files["gate-delivery.bin"][176:176 + count], files["go-prefix.bin"])
            self.assertFalse(trace and trace["session"]["go_complete"])
            if index == 5:
                self.assertEqual(fields[7], 0xFFFFFFFF)
        if index in (1, 3, 4):
            self.assertEqual(trace["backend"]["first_error"]["system_errno"], 0)
            self.assertGreater(trace["backend"]["first_error"]["callback_error"], 0)
            self.assertEqual(pending["parent_error"]["errno"], 0)
        if index in (24, 25):
            error = trace["create_error"] if index == 24 else trace["backend"]["first_error"]
            self.assertEqual(error["system_errno"], 0)
            self.assertEqual(error["libdtrace_code"], 123)
            self.assertGreater(error["callback_error"], 0)
            self.assertEqual(pending["parent_error"]["errno"], 0)
            self.assertEqual(stats["closes"], 0 if index == 24 else 1)
            self.assertEqual(stats["destroys"], 0 if index == 24 else 1)
        if index == 6:
            self.assertEqual((stats["status_bytes"], stats["session_prefix"]), (1537, 1537))
            self.assertEqual(len(files["status.bin"]), 1537)
            self.assertEqual(files["status.bin"][-1], 0xA5)
            self.assertFalse(trace["session"]["bootstrap_sealed"])
        if index in (7, 8, 22):
            self.assertEqual(stats["kills"], 0)
        if index in (5, 7, 10, 11, 12, 13, 14, 16, 19, 20, 21):
            self.assertNotEqual(data["finish"], 0)
            self.assertEqual(stats["promotions"], 0)
        if index in (10, 11):
            self.assertEqual((stats["parent_reported"], stats["destroys"]), (1, 1))
        if index == 9:
            self.assertFalse(trace["parent_cleanup_valid"] or trace["session"]["cleanup_bound"])
            self.assertFalse(trace["session"]["stop_attempted"] or trace["session"]["drain_attempted"])
        if index == 17:
            self.assertEqual(files["go-prefix.bin"], b"")
            self.assertNotIn("gate-delivery.bin", files)
        if index == 18:
            self.assertEqual(len(files["go-prefix.bin"]), 64)
            self.assertEqual(files["gate-delivery.bin"], b"")
        if index == 22:
            self.assertEqual(struct.unpack_from(">2I", files["gate-delivery.bin"], 24), (2, 0))
            self.assertEqual(files["go-prefix.bin"], b"")
            self.assertEqual(pending["wait"]["exit"], 120)
        if index == 23:
            self.assertTrue(pending["streams"]["stdout"]["oversize"])
            self.assertEqual(pending["streams"]["stdout"]["observed_bytes"], 65537)
        if platform.system() == "Darwin" and stats["promotions"]:
            self.assertEqual(data["finish"], 0)
        if platform.system() != "Darwin":
            self.assertEqual(stats["promotions"], 0)

    def test_fixed_profile_child_models_reuse_actual_child_source(self):
        result = self.command("child-model", [str(self.child)])
        self.assertIn(b"runtime-child exact compiled argv empty env", result.stdout)

    def test_old_runtime_and_new_profile_reject_external_tracing_markers(self):
        for number, (header, flags) in enumerate((
                (RUNTIME / "runtime_profile.h", ["-DGLUE_OWNED_TRACING=1", "-DGLUE_RUNTIME_TRACING=1"]),
                (HERE / "runtime_trace_profile.h", ["-DGLUE_RUNTIME_TRACING=1"]),
                (HERE / "runtime_trace_profile.h", ["-DGLUE_OWNED_TRACING=1"]))):
            source = self.output / ("refuse-profile-" + str(number) + ".c")
            source.write_text('#include "' + str(header) + '"\nint main(void){return 0;}\n')
            result = self.command("refuse-profile-" + str(number), ["/usr/bin/cc", "-std=c11", *flags, "-fsyntax-only", str(source)], expected=1)
            self.assertIn(b"error", result.stderr)

    def test_default_catalog_build_refuses_without_outputs(self):
        binary = self.output / "unconfigured"
        self.command("unconfigured-build", [str(HERE / "build.sh"), str(binary)])
        output = self.output / "must-not-create"
        result = self.command("unconfigured-refusal", [str(binary), "--request", str(self.output / "missing-request"), "--output", str(output)], expected=2)
        self.assertEqual(result.stdout, b"")
        self.assertFalse(output.exists())


def scenario_test(index):
    def run(self):
        self.scenario(index)
    return run


for scenario_index, scenario_name in enumerate(SCENARIOS):
    setattr(RuntimeTraceRunnerControls, "test_parent_" + scenario_name, scenario_test(scenario_index))


if __name__ == "__main__":
    unittest.main()
