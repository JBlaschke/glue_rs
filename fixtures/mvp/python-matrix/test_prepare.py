"""Actual local venv seeding controls; these are not product acceptance runs."""
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

import prepare


class EnvironmentPreparationTests(unittest.TestCase):
    def test_actual_ordinary_environments_keep_explicit_seed_policy(self):
        for kind, seeded in (("ordinary", True), ("ordinary-no-pip", False)):
            with self.subTest(kind=kind), tempfile.TemporaryDirectory(prefix="glue venv ü ") as temporary:
                environment = prepare.create_environment(Path(temporary), Path(sys.executable), kind)
                result = subprocess.run([str(environment / "bin/python"), "-I", "-B", "-c",
                    "import importlib.util,json,sys; print(json.dumps({'venv':sys.prefix!=sys.base_prefix,'pip':importlib.util.find_spec('pip') is not None}))"],
                    check=True, capture_output=True, text=True,
                    env={**os.environ, "PYTHONDONTWRITEBYTECODE": "1"})
                self.assertEqual(json.loads(result.stdout), {"venv": True, "pip": seeded})
                self.assertEqual((environment / "lib").is_dir(), True)

    def test_unknown_kind_refuses_before_creating_environment(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            with patch.object(prepare, "run", side_effect=AssertionError("unexpected process")):
                with self.assertRaises(ValueError):
                    prepare.create_environment(root, Path(sys.executable), "unknown")
            self.assertFalse((root / "environment").exists())

    def test_descriptor_preparation_keeps_relative_interpreter_link(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            python = root / "runtime/bin/python"
            python.parent.mkdir(parents=True)
            python.write_bytes(b"not executed")
            environment = prepare.create_environment(root, python, "descriptor")
            self.assertTrue((environment / "bin/python").is_symlink())
            self.assertEqual((environment / "bin/python").resolve(), python.resolve())
            self.assertFalse(Path(os.readlink(environment / "bin/python")).is_absolute())

    def test_uv_preparation_keeps_offline_no_download_policy(self):
        with tempfile.TemporaryDirectory() as temporary, patch.dict(os.environ, {"GLUE_MVP_UV": "/owned/uv"}):
            root, python = Path(temporary), Path("/owned/python")
            with patch.object(prepare, "run") as run:
                prepare.create_environment(root, python, "uv")
            run.assert_called_once_with(["/owned/uv", "venv", "--offline", "--no-project",
                "--no-managed-python", "--no-python-downloads", "--python", python, root / "environment"])


if __name__ == "__main__":
    unittest.main()
