import copy
import json
import os
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

import harness


class HarnessTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory(prefix="glue harness ü ")
        self.root = Path(self.temporary.name)
        self.root.chmod(0o755)
        self.project = self.root / "project"
        self.project.mkdir()
        (self.project / "value.txt").write_text("original native/source bytes")
        self.builder = self.root / "builder.py"
        self.builder.write_text("""
import pathlib,sys,json
output,inputs,mode = pathlib.Path(sys.argv[1]),pathlib.Path(sys.argv[2]),sys.argv[3]
output.mkdir()
script='#!/bin/sh\\n'
script+='if test -e '+repr(str(inputs/'project/value.txt'))+'; then exit 44; fi\\n'
if mode == 'cache-write': script+=': > "$HOME/cache"\\n'
elif mode == 'wrong-exit': script+='exit 7\\n'
elif mode == 'missing-dependency': script+='test -f "'+str(output/'missing.so')+'" || exit 127\\n'
elif mode == 'input-fallback': script+='test -e '+repr(str(inputs/'project/value.txt'))+' || exit 43\\n'
if mode == 'changed-input': (inputs/'project/value.txt').write_text('builder changed original bytes')
script+="printf '%s\\\\n' 'observable expected output'\\n"
(output/'glue').write_text(script)
(output/'glue').chmod(0o755)
(output/'app.glue').write_bytes(b'unit protocol fixture')
(output/'build-report.json').write_text(json.dumps({'runtime':{'implementation':'lua','version':'5.5.1','provider':'bundled','target':sys.argv[4]}}))
""")
        self.recipe = {
            "revision": 1, "case": "unit-fixture", "reference_kind": "stock",
            "inputs": [{"source": str(self.project), "destination": "project"}],
            "build": {"argv": [sys.executable, str(self.builder), "{build}", "{inputs}", "normal", "{target}"]},
            "reference": {"argv": [sys.executable, "-c", "print('observable expected output')"]},
        }

    def tearDown(self):
        # Real payloads stay read-only; allow the unit's temporary fixture cleanup.
        for path in self.root.rglob("*"):
            if path.is_dir() and not path.is_symlink():
                path.chmod(0o755)
        self.temporary.cleanup()

    def execute(self, recipe=None, offline=True):
        proof = {"status": "passed" if offline else "unavailable", "mechanism": "synthetic unit policy, not target evidence"}
        output = self.root / "receipt output"
        with patch.object(harness, "offline_policy", return_value=([], proof)):
            receipt = harness.execute(recipe or self.recipe, harness.native_target(), output, Path(__file__).resolve().parents[2])
        return receipt, output

    def test_relocates_removes_prefix_compares_reference_and_checks_evidence(self):
        receipt, output = self.execute()
        self.assertEqual(receipt["status"], "passed", receipt)
        self.assertEqual(harness.check(output / "receipt.json"), [])
        self.assertFalse((output / "work/build inputs").exists())
        self.assertTrue((output / "payload with spaces ü/glue").exists())
        (output / "run.stdout").write_text("changed output evidence")
        self.assertIn("run stdout evidence changed", harness.check(output / "receipt.json"))

    def test_foreign_target_rejects_before_running_or_creating_output(self):
        foreign = next(target for target in harness.TARGETS if target != harness.native_target())
        output = self.root / "foreign"
        with self.assertRaisesRegex(harness.HarnessError, "foreign execution target"):
            harness.execute(self.recipe, foreign, output, self.root)
        self.assertFalse(output.exists())

    def test_missing_offline_enforcement_is_not_a_pass(self):
        receipt, output = self.execute(offline=False)
        self.assertEqual(receipt["status"], "failed")
        self.assertIn("offline: unavailable", harness.check(output / "receipt.json"))

    def test_wrong_exit_missing_dependency_and_cache_write_are_detected(self):
        for mode in ["wrong-exit", "missing-dependency", "cache-write", "input-fallback"]:
            with self.subTest(mode=mode):
                recipe = copy.deepcopy(self.recipe)
                recipe["build"]["argv"][-2] = mode
                output = self.root / mode
                with patch.object(harness, "offline_policy", return_value=([], {"status": "passed"})):
                    receipt = harness.execute(recipe, harness.native_target(), output, self.root)
                self.assertEqual(receipt["status"], "failed")
                self.assertEqual(receipt["checks"]["exit_status"]["status"], "failed")

    def test_build_input_modification_is_detected(self):
        recipe = copy.deepcopy(self.recipe)
        recipe["build"]["argv"][-2] = "changed-input"
        receipt, _ = self.execute(recipe)
        self.assertEqual(receipt["checks"]["input_bytes_preserved"]["status"], "failed")

    def test_skipped_execution_and_wrong_target_receipts_reject(self):
        receipt, output = self.execute()
        receipt["commands"].pop("run")
        receipt["host"]["target"] = "unexecuted-target"
        (output / "receipt.json").write_text(json.dumps(receipt))
        errors = harness.check(output / "receipt.json")
        self.assertIn("run did not complete", errors)
        self.assertIn("receipt does not prove requested native target execution", errors)

    def test_escaped_input_symlink_and_template_environment_are_bounded(self):
        os.symlink("../outside", self.project / "escape")
        with self.assertRaises(harness.HarnessError):
            harness.inventory(self.project)
        with patch.dict(os.environ, {}, clear=True):
            with self.assertRaisesRegex(harness.HarnessError, "needs build input"):
                harness.expand("${MISSING_TEST_INPUT}", {})


if __name__ == "__main__":
    unittest.main()
