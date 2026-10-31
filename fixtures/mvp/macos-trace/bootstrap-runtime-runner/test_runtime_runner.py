"""Runtime profile: pure codec, real child models, ordinary file/wait/cleanup controls.
No configured root bootstrap, credential transition or compact application runs.
"""
import hashlib
import json
import os
from pathlib import Path
import platform
import subprocess
import tempfile
import unittest
from unittest.mock import patch
HERE = Path(__file__).resolve().parent
BASE = HERE.parent
NATIVE_UNAVAILABLE = frozenset(
    b"runtime native fixture unavailable: " + reason + b"\n"
    for reason in (b"unsupported-platform", b"actual-identity", b"actual-group-vector", b"descriptor-adapter"))

class RuntimeRecipeControls(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.temp = None
        retain = os.environ.get("GLUE_RUNTIME_TEST_RETAIN")
        if retain:
            cls.build = Path(retain)
            cls.build.mkdir(parents=True, exist_ok=False, mode=0o700)
        else:
            cls.temp = tempfile.TemporaryDirectory(prefix="glue runtime recipe ü ")
            cls.build = Path(cls.temp.name)
        cls.common = [BASE / "bootstrap-wire/bootstrap_wire.c", BASE / "bootstrap-request/bootstrap_request.c", BASE / "target-credentials/target_credentials.c"]
        cls.compile("data", [HERE / "test_runtime_data.c", HERE / "runtime_catalog.c", HERE / "runtime_request.c", HERE / "catalog_unconfigured.c", BASE / "target-launch/target_launch.c", *cls.common])
        cls.compile("child", [HERE / "test_runtime_child.c", BASE / "bootstrap-wire/bootstrap_wire.c", BASE / "bootstrap-object-wire/bootstrap_object_wire.c", BASE / "target-launch/target_launch.c"])
        cls.compile("result", [HERE / "test_runtime_result.c", HERE / "runtime_catalog.c", BASE / "target-launch/target_launch.c", BASE / "bootstrap-admission/bootstrap_admission.c", BASE / "target-endpoints/target_endpoints.c"])
        production = [HERE / ("runtime_" + n + ".c") for n in ("child", "parent", "protocol", "support", "files", "catalog", "request", "admission", "witness")]
        production += [HERE / "catalog_unconfigured.c", BASE / "bootstrap-runner/runner_catalog.c", BASE / "target-launch/target_launch.c", BASE / "target-cwd/target_cwd.c", BASE / "target-fd-objects/target_fd_objects.c", BASE / "bootstrap-object-wire/bootstrap_object_wire.c", BASE / "bootstrap-kit/request_catalog.c", BASE / "bootstrap-probe/probe_report.c", BASE / "bootstrap-io/bootstrap_io.c", BASE / "bootstrap-signals/bootstrap_signals.c", BASE / "bootstrap-admission/bootstrap_admission.c", BASE / "target-descriptors/target_descriptors.c", BASE / "target-endpoints/target_endpoints.c", *cls.common]
        cls.compile("cleanup", [HERE / "test_runtime_cleanup.c", *[p for p in production if p.name != "runtime_parent.c"]])
        cls.compile("unconfigured", [BASE / "bootstrap-runner/owned_bootstrap_main.c", *production])
        cls.compile("request-tool", [HERE / "make_runtime_request.c", HERE / "runtime_catalog.c", HERE / "runtime_request.c", HERE / "catalog_unconfigured.c", BASE / "target-launch/target_launch.c", BASE / "bootstrap-kit/request_catalog.c", BASE / "bootstrap-admission/bootstrap_admission.c", *cls.common])
        cls.compile("exec-fixture", [HERE / "test_runtime_exec_fixture.c"])
        cls.compile("native", [HERE / "test_runtime_native.c", *[p for p in production if p.name != "runtime_child.c"]])

    @classmethod
    def compile(cls, name, sources):
        argv = ["/usr/bin/cc", "-std=c11", "-D_DEFAULT_SOURCE", "-D_DARWIN_C_SOURCE", "-Wall", "-Wextra", "-Werror", "-O1", *map(str, sources)]
        if platform.system() == "Darwin":
            argv += ["-lproc"]
        argv += ["-o", str(cls.build / name)]
        r = subprocess.run(argv, capture_output=True, timeout=60)
        cls.record(name + "-compile", argv, r, sources={str(p): hashlib.sha256(p.read_bytes()).hexdigest() for p in sources})
        if r.returncode:
            raise AssertionError(r.stderr.decode())

    @classmethod
    def record(cls, name, argv, r, **extra):
        (cls.build / (name + ".stdout")).write_bytes(r.stdout)
        (cls.build / (name + ".stderr")).write_bytes(r.stderr)
        (cls.build / (name + ".json")).write_text(json.dumps({"argv": argv, "status": r.returncode, "host": platform.platform(), **extra}, indent=2) + "\n")

    @classmethod
    def tearDownClass(cls):
        if cls.temp:
            cls.temp.cleanup()

    def control(self, binary, *args):
        argv = [str(self.build / binary), *map(str, args)]
        r = subprocess.run(argv, capture_output=True, timeout=15)
        self.record("-".join((binary, *[Path(str(a)).name for a in args[:1]])), argv, r)
        self.assertEqual(r.returncode, 0, r.stderr.decode())

    def native_control(self):
        output = self.build / "native-exec-case"
        argv = [str(self.build / "native"), str(self.build / "exec-fixture"), str(output)]
        r = subprocess.run(argv, capture_output=True, timeout=15)
        refused = False
        try:
            if r.returncode == 77:
                self.assertEqual(r.stdout, b"", "native refusal must precede execution")
                self.assertIn(r.stderr, NATIVE_UNAVAILABLE, "unknown native refusal diagnostic")
                self.assertFalse(os.path.lexists(output), "native refusal occurred after output creation")
                refused = True
                self.skipTest(r.stderr.decode().strip() + "; no native child executed")
            self.assertEqual(r.returncode, 0, r.stderr.decode())
        finally:
            self.record("native-exec-fixture", argv, r,
                native_preflight_refusal_verified=refused,
                native_executed=False if refused else True if r.returncode == 0 else None)

    def test_runtime_request_profile_legacy_refusal_and_all_truncations(self): self.control("data", "wire")
    def test_catalog_exact_plan_lock_target_cwd_and_launcher_bounds(self): self.control("data", "catalog")
    def test_actual_child_source_execs_exact_plan_only_after_drop_and_gate(self): self.control("child")
    def test_actual_parent_cleanup_owns_extra_cwd_and_preserves_parent_cwd(self): self.control("cleanup")
    def test_unconfigured_entry_refuses_before_paths_or_outputs(self):
        output = self.build / "unconfigured-must-not-exist"
        argv = [str(self.build / "unconfigured"), "--request", str(self.build / "missing"), "--output", str(output)]
        r = subprocess.run(argv, capture_output=True, timeout=5)
        self.record("unconfigured-refusal", argv, r)
        self.assertEqual(r.returncode, 2)
        self.assertEqual(r.stdout, b"")
        self.assertFalse(output.exists())
        request_argv = [str(self.build / "request-tool")]
        request = subprocess.run(request_argv, capture_output=True, timeout=5)
        self.record("unconfigured-request-refusal", request_argv, request)
        self.assertEqual(request.returncode, 2)
        self.assertEqual(request.stdout, b"")
        registry = json.loads((HERE / "reviewed-inputs.json").read_bytes())
        self.assertEqual(registry, {"schema": "glue-owned-runtime-recipe-inputs-v1", "source_revision": None, "recipes": [], "proofs": []})

    def result_case(self, mode):
        output = self.build / ("result-case-" + str(mode))
        self.control("result", str(mode), output)
        result = output / ("result.json" if platform.system() == "Darwin" else "result.pending")
        if mode in (3, 4):
            self.assertFalse((output / "result.json").exists())
            self.assertFalse((output / "result.pending").exists())
            return
        data = json.loads(result.read_bytes())
        self.assertEqual(data["schema"], "glue-owned-runtime-recipe-diagnostic-v1")
        self.assertFalse(data["exec_proved"] or data["full_acceptance"])
        self.assertEqual(data["status"], "passed" if mode == 0 else "failed")
        self.assertEqual(data["streams"]["stderr"]["captured_bytes"], 19)
        self.assertEqual(data["streams"]["stdout"]["oversize"], mode == 1)
        if mode == 1:
            self.assertEqual(data["streams"]["stdout"]["observed_bytes"], 65537)
            self.assertFalse(data["streams"]["stdout"]["valid"])
        else:
            self.assertEqual(data["streams"]["stdout"]["captured_bytes"], 257)
            if platform.system() == "Darwin":
                self.assertEqual(data["streams"]["stdout"]["sha256"], hashlib.sha256((output / "app.stdout").read_bytes()).hexdigest())
        if mode == 2:
            self.assertEqual(data["wait"]["exit"], 7)
            self.assertEqual(data["wait"]["raw_status"], 7 << 8)
        if mode == 6:
            self.assertEqual(data["wait"]["exit"], -1)
            self.assertEqual(data["wait"]["signal"], 9)
        self.assertTrue((output / "status.bin").is_file())
        self.assertTrue((output / "launch-plan.bin").is_file())

    @unittest.skipUnless(platform.system() == "Darwin" and os.getuid() != 0, "ordinary Darwin native child control")
    def test_actual_native_child_gate_exec_with_modeled_credentials_and_admission(self):
        self.native_control()

    def test_opaque_nul_binary_streams_and_actual_zero_exit(self): self.result_case(0)
    def test_oversize_is_retained_failure_not_probe_decode(self): self.result_case(1)
    def test_actual_nonzero_exit_and_raw_status_preserved(self): self.result_case(2)
    def test_unclosed_cwd_reference_prevents_result(self): self.result_case(3)
    def test_capture_reader_close_failure_prevents_promotion(self): self.result_case(4)
    def test_missing_go_cannot_promote_success(self): self.result_case(5)
    def test_actual_signal_exit_is_preserved(self): self.result_case(6)


class NativePreflightHarnessControls(unittest.TestCase):
    """Pure wrapper controls; no compiled driver/child/provider is executed."""
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix="glue native harness ")
        self.addCleanup(self.temp.cleanup)
        self.case = RuntimeRecipeControls("test_actual_native_child_gate_exec_with_modeled_credentials_and_admission")
        self.case.build = Path(self.temp.name)

    def invoke(self, status, stdout=b"", stderr=b""):
        result = subprocess.CompletedProcess([], status, stdout, stderr)
        with patch.object(subprocess, "run", return_value=result) as run, \
             patch.object(self.case, "record") as record:
            try:
                return self.case.native_control()
            finally:
                run.assert_called_once()
                record.assert_called_once()
                self.assertIs(record.call_args.args[2], result)

    def test_known_preflight_refusal_is_explicit_skip_with_original_diagnostic(self):
        for diagnostic in sorted(NATIVE_UNAVAILABLE):
            with self.subTest(diagnostic=diagnostic), self.assertRaisesRegex(unittest.SkipTest, "no native child executed"):
                self.invoke(77, stderr=diagnostic)

    def test_verified_refusal_receipt_preserves_native_executed_false(self):
        r=subprocess.CompletedProcess([],77,b"",next(iter(NATIVE_UNAVAILABLE)))
        with patch.object(subprocess,"run",return_value=r),patch.object(self.case,"record") as record, \
             self.assertRaises(unittest.SkipTest):self.case.native_control()
        self.assertIs(record.call_args.kwargs['native_executed'],False)
        self.assertIs(record.call_args.kwargs['native_preflight_refusal_verified'],True)
        self.assertIs(record.call_args.args[2],r)

    def test_original_silent_77_remains_failure_instead_of_unproved_skip(self):
        with self.assertRaisesRegex(AssertionError, "unknown native refusal"):
            self.invoke(77)

    def test_unknown_or_extra_refusal_diagnostics_remain_failures(self):
        for diagnostic in (b"unavailable\n", next(iter(NATIVE_UNAVAILABLE)) + b"late failure\n"):
            with self.subTest(diagnostic=diagnostic), self.assertRaises(AssertionError):
                self.invoke(77, stderr=diagnostic)

    def test_refusal_after_any_case_node_including_dangling_link_remains_failure(self):
        output=self.case.build / "native-exec-case"
        for kind in ('directory','file','dangling-link'):
            with self.subTest(kind=kind):
                if kind=='directory':output.mkdir()
                elif kind=='file':output.write_bytes(b'')
                else:output.symlink_to(self.case.build/'absent-target')
                try:
                    with self.assertRaisesRegex(AssertionError,"after output creation"):
                        self.invoke(77,stderr=next(iter(NATIVE_UNAVAILABLE)))
                finally:
                    if kind=='directory':output.rmdir()
                    else:output.unlink()

    def test_refusal_with_stdout_remains_failure(self):
        with self.assertRaisesRegex(AssertionError, "precede execution"):
            self.invoke(77, stdout=b"execution occurred", stderr=next(iter(NATIVE_UNAVAILABLE)))

    def test_non77_failures_and_signals_remain_failures(self):
        for status in (1,2,-6,-9):
            with self.subTest(status=status), self.assertRaises(AssertionError):
                self.invoke(status, stderr=next(iter(NATIVE_UNAVAILABLE)))

    def test_zero_still_requires_success_status_and_generic_control_rejects_77(self):
        self.assertIsNone(self.invoke(0, stdout=b"modeled fixture success"))
        result = subprocess.CompletedProcess([],77,b"",next(iter(NATIVE_UNAVAILABLE)))
        with patch.object(subprocess,"run",return_value=result),patch.object(self.case,"record"),self.assertRaises(AssertionError):
            self.case.control("other-control")

    def test_subprocess_fault_is_not_converted_to_unavailable(self):
        with patch.object(subprocess,"run",side_effect=subprocess.TimeoutExpired("native",15)), \
             patch.object(self.case,"record") as record, self.assertRaises(subprocess.TimeoutExpired):
            self.case.native_control()
        record.assert_not_called()


if __name__ == "__main__": unittest.main()
