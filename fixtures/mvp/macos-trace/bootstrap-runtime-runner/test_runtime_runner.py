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
HERE = Path(__file__).resolve().parent
BASE = HERE.parent

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
        production = [HERE / ("runtime_" + n + ".c") for n in ("child", "parent", "protocol", "support", "files", "catalog", "request", "admission")]
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
        self.control("native", self.build / "exec-fixture", self.build / "native-exec-case")

    def test_opaque_nul_binary_streams_and_actual_zero_exit(self): self.result_case(0)
    def test_oversize_is_retained_failure_not_probe_decode(self): self.result_case(1)
    def test_actual_nonzero_exit_and_raw_status_preserved(self): self.result_case(2)
    def test_unclosed_cwd_reference_prevents_result(self): self.result_case(3)
    def test_capture_reader_close_failure_prevents_promotion(self): self.result_case(4)
    def test_missing_go_cannot_promote_success(self): self.result_case(5)
    def test_actual_signal_exit_is_preserved(self): self.result_case(6)

if __name__ == "__main__": unittest.main()
