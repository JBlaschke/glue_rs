"""Synthetic collector controls; no native runtime, CFFI or product binary runs.

The host target and a tiny test CFFI wheel pin are mocked. A controlled Python
child stands in for preparation/product execution, exercising the real shared
run_command stream/status capture. None of these records is native acceptance.
"""
from dataclasses import asdict
import hashlib
import importlib.util
import io
import json
import os
from pathlib import Path
import shutil
import sys
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch
import zipfile

SPEC = importlib.util.spec_from_file_location("run_abi_refusal_control", Path(__file__).with_name("run_abi_refusal.py"))
c = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = c
SPEC.loader.exec_module(c)
h, abi = c._dependencies()
SHARED_RUN_COMMAND = h.run_command


def encoded(value):
    return (json.dumps(value, sort_keys=True) + "\n").encode()


def identity(raw):
    return {"size": len(raw), "sha256": hashlib.sha256(raw).hexdigest()}


CHILD = r'''
from pathlib import Path
import json,shutil,sys
kind,mode,inputs,output=sys.argv[1:]
inputs,output=Path(inputs),Path(output)
if kind=='prepare':
    if mode=='prepare-failure':
        print('synthetic preparation refusal',file=sys.stderr)
        raise SystemExit(7)
    site=inputs/'environment/lib/python3.13/site-packages'
    shutil.copytree(inputs/'installed',site)
    (inputs/'environment/pyvenv.cfg').write_text('version = 3.13.16\n')
    if mode=='alter-prepared-backend':
        next(site.glob('_cffi_backend.*')).write_bytes(b'changed prepared backend')
    raise SystemExit(0)
if mode=='create-output':
    (output/'rejected output').mkdir()
if mode=='alter-sentinel':
    (output/'sibling sentinel/sentinel.txt').write_bytes(b'clobbered')
if mode=='alter-input':
    (inputs/'project/main.py').write_bytes(b'changed input')
if mode=='unsafe-input':
    (inputs/'project/escaping-link').symlink_to('/unrelated-outside-tree')
code='output_exists' if mode=='wrong-diagnostic' else 'runtime_abi_mismatch'
print(json.dumps({'code':code,'message':'synthetic diagnostic only','remedy':'supply compatible input'}),file=sys.stderr)
raise SystemExit(0 if mode=='product-success' else 1)
'''


class Fixture:
    def __init__(self, testcase, mode="refusal"):
        self.temporary = tempfile.TemporaryDirectory(prefix="synthetic-abi-refusal-")
        testcase.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name).resolve()
        self.runtime = self.root / "runtime"
        (self.runtime / "bin").mkdir(parents=True)
        self.runtime_bytes = b"synthetic interpreter bytes; never executed"
        (self.runtime / "bin/python3.13").write_bytes(self.runtime_bytes)
        self.glue = self.root / "glue"
        self.glue_bytes = b"synthetic glue bytes; never executed"
        self.glue.write_bytes(self.glue_bytes)
        self.foreign = self.root / "foreign"
        self.site = self.foreign / "site"
        self.site.mkdir(parents=True)
        self.backend = "_cffi_backend.cpython-314-x86_64-linux-gnu.so"
        self.members = {self.backend: b"synthetic CFFI native member; never executed",
                        "cffi/__init__.py": b"raise RuntimeError('must never import this foreign package')\n",
                        "cffi-2.1.1.dist-info/WHEEL": b"Wheel-Version: 1.0\nTag: cp314-cp314-manylinux_2_17_x86_64\n"}
        raw = io.BytesIO()
        with zipfile.ZipFile(raw, "w") as archive:
            for name, data in self.members.items():
                archive.writestr(name, data)
                path = self.site / name
                path.parent.mkdir(parents=True, exist_ok=True)
                path.write_bytes(data)
        self.wheel = raw.getvalue()
        rows = dict(abi._INPUT_ROWS)
        selected = list(rows["x86_64"])
        route, name, _, _, url = selected[3]
        selected[3] = (route, name, identity(self.wheel)["sha256"], len(self.wheel), url)
        rows["x86_64"] = tuple(selected)
        self.pin = patch.object(abi, "_INPUT_ROWS", rows)
        self.pin.start()
        testcase.addCleanup(self.pin.stop)
        self.official = abi.official_manifest("x86_64")
        self.wheel_path = self.foreign / name
        self.wheel_path.write_bytes(self.wheel)
        wheels = []
        for release, route in zip(abi.PACKAGES, ("cryptography", "cffi-cp314", "pycparser")):
            package, version = release.split("==")
            pin = self.official[route]
            wheels.append({"release": release, "metadata": "https://pypi.org/pypi/" + package + "/" + version + "/json",
                           "filename": pin["name"], "url": pin["url"], "size": pin["size"], "sha256": pin["sha256"]})
        (self.foreign / "inputs.json").write_bytes(encoded({"test_only": True, "python": "cp314", "target": "linux-x86_64", "wheels": wheels}))
        self.evidence = self.root / "evidence"
        case = self.evidence / "cases/python-3.13.16-source"
        case.mkdir(parents=True)
        self.reference = {"status": "passed", "target": "x86_64-unknown-linux-gnu", "host": {"target": "x86_64-unknown-linux-gnu"},
            "commit": "a" * 40, "case": "python-source-normalized", "reference_kind": "stock",
            "runtime": {"target": "x86_64-unknown-linux-gnu", "version": "3.13.16", "provider": "bundled", "implementation": "cpython",
                        "abi": {"language": "python", "gil": "conventional", "debug": False, "version": {"major": 3, "minor": 13, "patch": 16}},
                        "inputs": {"runtime-executable": identity(self.runtime_bytes)}},
            "launcher": {"path": "payload/glue", **identity(self.glue_bytes)},
            "checks": {name: {"status": "passed"} for name in abi._REQUIRED_CHECKS}}
        self.reference_path = case / "receipt.json"
        self.reference_path.write_bytes(encoded(self.reference))
        self.args = SimpleNamespace(architecture="x86_64", runtime_root=self.runtime, foreign_input=self.foreign,
                                    glue=self.glue, output=self.root / c.LABEL, evidence=self.evidence)
        self.child = self.root / "synthetic-child.py"
        self.child.write_text(CHILD)
        self.mode = mode
        self.original_run = SHARED_RUN_COMMAND
        self.target = patch.object(h, "native_target", return_value="x86_64-unknown-linux-gnu")
        self.target.start()
        testcase.addCleanup(self.target.stop)
        self.run_patch = patch.object(h, "run_command", side_effect=self.synthetic_run)
        self.run_mock = self.run_patch.start()
        testcase.addCleanup(self.run_patch.stop)

    def synthetic_run(self, name, argv, cwd, environment, output, timeout):
        """Execute only this tiny child; never the hypothetical runtime/product."""
        controlled = [sys.executable, "-I", "-B", str(self.child), name, self.mode,
                      str(self.args.output / "work/build inputs"), str(output)]
        result = self.original_run(name, controlled, cwd, environment, output, timeout)
        # Assessment exercises the intended route; the test receipt explicitly
        # labels this substitution and never counts it as native acceptance.
        result["argv"] = argv
        result["synthetic_controlled_child"] = True
        if self.mode.startswith("oversized-"):
            stream_name = self.mode[len("oversized-"):]
            if stream_name in (name + ".stdout", name + ".stderr"):
                (output / stream_name).write_bytes(b"x" * 1025)
                stream = stream_name.rsplit(".", 1)[1]
                result[stream].update(identity((output / stream_name).read_bytes()))
        if self.mode == "timed-out" and name == "refusal":
            result["timed_out"] = True
        return result

    def collect(self):
        return c.collect(self.args, dependencies=(h, abi))


class CollectorControls(unittest.TestCase):
    def fixture(self, mode="refusal"):
        return Fixture(self, mode)

    def test_wrong_native_target_has_no_output_evidence_or_process_side_effect(self):
        value = self.fixture()
        h.native_target.return_value = "aarch64-unknown-linux-gnu"
        value.args.runtime_root = value.root / "missing-runtime"
        before = h.inventory(value.evidence)
        with self.assertRaisesRegex(c.CollectionError, "wrong native target"):
            value.collect()
        self.assertFalse(value.args.output.exists())
        self.assertEqual(before, h.inventory(value.evidence))
        value.run_mock.assert_not_called()

    def test_unavailable_native_target_fails_before_creation_or_execution(self):
        value = self.fixture()
        h.native_target.side_effect = h.HarnessError("unsupported native host")
        with self.assertRaisesRegex(c.CollectionError, "native target unavailable"):
            value.collect()
        self.assertFalse(value.args.output.exists())
        self.assertFalse((value.evidence / "abi-refusal.json").exists())
        value.run_mock.assert_not_called()

    def test_output_must_be_new_absolute_and_evidence_paths_must_be_fresh(self):
        value = self.fixture()
        value.args.output.mkdir()
        sentinel = value.args.output / "existing.txt"
        sentinel.write_bytes(b"preserve existing output")
        with self.assertRaisesRegex(c.CollectionError, "new absolute"):
            value.collect()
        self.assertEqual(sentinel.read_bytes(), b"preserve existing output")
        value.run_mock.assert_not_called()
        value = self.fixture()
        (value.evidence / "abi-refusal.json").write_bytes(b"prior failed capture")
        with self.assertRaisesRegex(c.CollectionError, "new refusal evidence"):
            value.collect()
        self.assertEqual((value.evidence / "abi-refusal.json").read_bytes(), b"prior failed capture")
        self.assertFalse(value.args.output.exists())
        value.run_mock.assert_not_called()

    def test_invalid_provisioning_receipt_is_rejected_before_execution(self):
        value = self.fixture()
        receipt = json.loads((value.foreign / "inputs.json").read_bytes())
        receipt["python"] = "cp313"
        (value.foreign / "inputs.json").write_bytes(encoded(receipt))
        with self.assertRaisesRegex(c.CollectionError, "provisioning receipt"):
            value.collect()
        self.assertFalse(value.args.output.exists())
        value.run_mock.assert_not_called()

    def test_altered_wheel_or_backend_is_rejected_before_use(self):
        value = self.fixture()
        value.wheel_path.write_bytes(value.wheel + b"altered")
        with self.assertRaisesRegex(c.CollectionError, "wheel bytes differ"):
            value.collect()
        value.run_mock.assert_not_called()
        value = self.fixture()
        (value.site / value.backend).write_bytes(b"altered installed backend")
        with self.assertRaisesRegex(c.CollectionError, "installed CFFI members differ"):
            value.collect()
        value.run_mock.assert_not_called()

    def test_selected_interpreter_and_glue_must_match_checked_base(self):
        value = self.fixture()
        value.glue.write_bytes(b"different product build")
        with self.assertRaisesRegex(c.CollectionError, "glue binary differs"):
            value.collect()
        value.run_mock.assert_not_called()
        value = self.fixture()
        (value.runtime / "bin/python3.13").write_bytes(b"wrong interpreter")
        with self.assertRaisesRegex(c.CollectionError, "selected interpreter differs"):
            value.collect()
        value.run_mock.assert_not_called()

    def test_controlled_child_refusal_retains_complete_bound_observations(self):
        value = self.fixture()
        record = value.collect()
        self.assertEqual(record["status"], "passed", record)
        self.assertEqual(record["assessment"]["status"], "passed", record)
        self.assertTrue(record["command"]["synthetic_controlled_child"])
        self.assertEqual(record["output_before"], {"kind": "absent"})
        self.assertEqual(record["output_after"], {"kind": "absent"})
        self.assertEqual(record["sentinel_before"], record["sentinel_after"])
        before = (value.evidence / "abi-refusal-input-inventory.json").read_bytes()
        after = (value.evidence / "abi-refusal-details/input-inventory-after.json").read_bytes()
        self.assertEqual(before, after)
        self.assertEqual(identity(before), {key: record["input_inventory"][key] for key in ("size", "sha256")})
        self.assertEqual((value.evidence / "provisioning/abi-wheels" / value.wheel_path.name).read_bytes(), value.wheel)
        evidence = abi.RefusalEvidence((value.evidence / "abi-refusal.json").read_bytes(),
            (value.evidence / "abi-refusal.stderr").read_bytes(), before)
        self.assertEqual(abi.assess_refusal("x86_64", evidence, value.reference_path.read_bytes())["status"], "passed")
        self.assertTrue((value.evidence / "abi-refusal-details/prepare.stdout").is_file())

    def test_product_success_wrong_diagnostic_or_timeout_are_never_promoted(self):
        for mode in ("product-success", "wrong-diagnostic", "timed-out"):
            with self.subTest(mode=mode):
                value = self.fixture(mode)
                record = value.collect()
                self.assertEqual(record["status"], "failed", record)
                self.assertEqual(record["assessment"]["status"], "failed", record)
                self.assertEqual(json.loads((value.evidence / "abi-refusal.json").read_bytes())["status"], "failed")

    def test_created_output_or_changed_sentinel_remains_a_failed_observation(self):
        for mode in ("create-output", "alter-sentinel"):
            with self.subTest(mode=mode):
                value = self.fixture(mode)
                record = value.collect()
                self.assertEqual(record["status"], "failed", record)
                self.assertTrue(record["collection_errors"])
                self.assertEqual(record["assessment"]["status"], "failed", record)
                self.assertTrue((value.evidence / "abi-refusal-details/input-inventory-after.json").exists())

    def test_changed_inputs_fail_collection_even_with_correct_refusal_diagnostic(self):
        value = self.fixture("alter-input")
        record = value.collect()
        self.assertEqual(record["status"], "failed", record)
        self.assertIn("before/after input inventories differ", " ".join(record["collection_errors"]))
        self.assertNotEqual((value.evidence / "abi-refusal-input-inventory.json").read_bytes(),
                            (value.evidence / "abi-refusal-details/input-inventory-after.json").read_bytes())

    def test_invalid_after_inventory_is_retained_as_failure_without_losing_diagnostic(self):
        value = self.fixture("unsafe-input")
        record = value.collect()
        self.assertEqual(record["status"], "failed", record)
        self.assertIn("observed tree inventory is invalid", " ".join(record["collection_errors"]))
        self.assertTrue((value.evidence / "abi-refusal.stderr").is_file())
        self.assertTrue((value.evidence / "abi-refusal.json").is_file())

    def test_failed_preparation_keeps_failure_streams_and_never_runs_product(self):
        value = self.fixture("prepare-failure")
        record = value.collect()
        self.assertEqual(record["status"], "failed", record)
        self.assertFalse(record["native_execution_attempted"])
        self.assertEqual(value.run_mock.call_count, 1)
        self.assertIn(b"synthetic preparation refusal", (value.evidence / "abi-refusal-details/prepare.stderr").read_bytes())
        self.assertEqual((value.evidence / "abi-refusal.stderr").read_bytes(), b"")

    def test_prepared_foreign_backend_must_remain_equal_to_actual_wheel_member(self):
        value = self.fixture("alter-prepared-backend")
        record = value.collect()
        self.assertEqual(record["status"], "failed", record)
        self.assertFalse(record["native_execution_attempted"])
        self.assertIn("prepared foreign CFFI member differs", " ".join(record["collection_errors"]))
        self.assertEqual(value.run_mock.call_count, 1)

    def test_retained_wheel_collision_or_symlink_is_not_replaced(self):
        value = self.fixture()
        target = value.evidence / "provisioning/abi-wheels" / value.wheel_path.name
        target.parent.mkdir(parents=True)
        target.write_bytes(b"prior different wheel")
        with self.assertRaisesRegex(c.CollectionError, "existing retained CFFI wheel differs"):
            value.collect()
        self.assertEqual(target.read_bytes(), b"prior different wheel")
        value.run_mock.assert_not_called()
        value = self.fixture()
        original = value.wheel_path.read_bytes()
        value.wheel_path.unlink()
        source = value.root / "symlink-wheel-target"
        source.write_bytes(original)
        value.wheel_path.symlink_to(source)
        with self.assertRaises(OSError):
            value.collect()
        value.run_mock.assert_not_called()

    def test_oversized_command_streams_do_not_discard_failed_record_or_inventories(self):
        for name in ("prepare.stdout", "prepare.stderr", "refusal.stdout", "refusal.stderr"):
            with self.subTest(name=name), patch.object(c, "MAX_STREAM", 512):
                value = self.fixture("oversized-" + name)
                record = value.collect()
                self.assertEqual(record["status"], "failed", record)
                self.assertIn(name + " retention failed", " ".join(record["collection_errors"]))
                self.assertFalse((value.evidence / "abi-refusal-details" / name).exists())
                self.assertEqual(json.loads((value.evidence / "abi-refusal.json").read_bytes())["status"], "failed")
                self.assertEqual((value.evidence / "abi-refusal-input-inventory.json").read_bytes(),
                                 (value.evidence / "abi-refusal-details/input-inventory-after.json").read_bytes())
                if name == "refusal.stderr":
                    self.assertEqual((value.evidence / "abi-refusal.stderr").read_bytes(), b"")

    def test_unreadable_command_streams_preserve_failed_record_and_reachable_observations(self):
        original_read = c._read_regular
        for name in ("prepare.stdout", "prepare.stderr", "refusal.stdout", "refusal.stderr"):
            value = self.fixture()
            def unreadable(path, *args, **kwargs):
                if path.parent == value.args.output and path.name == name:
                    raise PermissionError("synthetic unreadable command stream")
                return original_read(path, *args, **kwargs)
            with self.subTest(name=name), patch.object(c, "_read_regular", side_effect=unreadable):
                record = value.collect()
            self.assertEqual(record["status"], "failed", record)
            self.assertIn(name + " retention failed", " ".join(record["collection_errors"]))
            self.assertFalse((value.evidence / "abi-refusal-details" / name).exists())
            self.assertEqual(json.loads((value.evidence / "abi-refusal.json").read_bytes())["status"], "failed")
            self.assertEqual((value.evidence / "abi-refusal-input-inventory.json").read_bytes(),
                             (value.evidence / "abi-refusal-details/input-inventory-after.json").read_bytes())

    def test_optional_detail_and_wheel_retention_failures_cannot_hide_the_failed_observation(self):
        value = self.fixture()
        original_write = c._write_new
        def failed_detail(path, raw):
            if path == value.evidence / "abi-refusal-details/input-inventory-after.json":
                raise PermissionError("synthetic detail write refusal")
            return original_write(path, raw)
        with patch.object(c, "_write_new", side_effect=failed_detail):
            record = value.collect()
        self.assertEqual(record["status"], "failed", record)
        self.assertIn("after-input inventory retention failed", " ".join(record["collection_errors"]))
        self.assertEqual((value.evidence / "abi-refusal-input-inventory.json").read_bytes(),
                         (value.evidence / record["input_inventory_after_fallback"]["path"]).read_bytes())
        self.assertEqual(json.loads((value.evidence / "abi-refusal.json").read_bytes())["status"], "failed")
        value = self.fixture()
        obstacle = value.evidence / "provisioning"
        obstacle.write_bytes(b"existing unrelated file")
        record = value.collect()
        self.assertEqual(record["status"], "failed", record)
        self.assertIn("CFFI wheel retention failed", " ".join(record["collection_errors"]))
        self.assertEqual(obstacle.read_bytes(), b"existing unrelated file")
        self.assertEqual(json.loads((value.evidence / "abi-refusal.json").read_bytes())["status"], "failed")

    def test_combined_after_inventory_and_fallback_failures_preserve_small_failed_record(self):
        value = self.fixture()
        original_write = c._write_new
        missing = {value.evidence / "abi-refusal-details/input-inventory-after.json",
                   value.evidence / "abi-refusal-input-inventory-after.json"}
        def no_after_inventory(path, raw):
            if path in missing:
                raise OSError("synthetic quota prevents after-inventory retention")
            return original_write(path, raw)
        with patch.object(c, "_write_new", side_effect=no_after_inventory):
            record = value.collect()
        self.assertEqual(record["status"], "failed", record)
        self.assertIn("after-input inventory retention failed", " ".join(record["collection_errors"]))
        self.assertIn("fallback after-input inventory retention failed", " ".join(record["collection_errors"]))
        self.assertNotIn("input_inventory_after_fallback", record)
        self.assertTrue(all(not path.exists() for path in missing))
        self.assertTrue((value.evidence / "abi-refusal-input-inventory.json").is_file())
        self.assertTrue((value.evidence / "abi-refusal.stderr").is_file())
        self.assertEqual(json.loads((value.evidence / "abi-refusal.json").read_bytes())["status"], "failed")


if __name__ == "__main__":
    unittest.main()
