#!/usr/bin/env python3
"""Focused recipe checks; --python additionally executes a supplied runtime."""
import argparse
import importlib.util
import json
import os
from pathlib import Path
import shutil
import subprocess
import tempfile
import unittest

SPEC = importlib.util.spec_from_file_location("compact_build", Path(__file__).with_name("build.py"))
recipe = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(recipe)


class BoundsTests(unittest.TestCase):
    def test_probe_output_is_bounded(self):
        with self.assertRaisesRegex(ValueError, "output bound"):
            recipe.bounded_command([os.sys.executable, "-c", "print('x' * 70000)"])

    def test_probe_timeout(self):
        with self.assertRaisesRegex(ValueError, "timeout"):
            recipe.bounded_command([os.sys.executable, "-c", "import time; time.sleep(5)"], timeout=0.05)

    def test_symlink_escape(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory) / "input"
            root.mkdir()
            (root / "escape").symlink_to(Path(directory))
            with self.assertRaises(ValueError):
                list(recipe.input_files(root))


def smoke(executable, receipt):
    metadata = recipe.discover(executable)
    # Copy the supplied installation as a controlled input, then remove that
    # input's entire prefix before launch. Never rename the user's installation.
    with tempfile.TemporaryDirectory(prefix="glue-p00-") as directory:
        work = Path(directory).resolve()
        original = work / "build input"
        shutil.copytree(metadata["prefix"], original, symlinks=True,
                        ignore=shutil.ignore_patterns("__pycache__", "site-packages"))
        relative_executable = Path(metadata["executable"]).relative_to(metadata["prefix"])
        output = work / "built"
        spec = recipe.assemble(original / relative_executable, output)
        moved = work / "relocated café distribution"
        output.rename(moved)
        shutil.rmtree(original)
        empty_cwd = work / "empty cwd"
        empty_cwd.mkdir()
        before = {}
        for path in moved.rglob("*"):
            if path.is_file():
                before[str(path.relative_to(moved))] = recipe.digest(path)
                path.chmod(0o555 if path == moved / spec["executable"] else 0o444)
        for path in sorted(moved.rglob("*"), reverse=True):
            if path.is_dir():
                path.chmod(0o555)
        moved.chmod(0o555)
        command = [str(moved / spec["executable"]), "-I", "-S", "-B",
                   str(moved / "support/python-bootstrap.py"), str(moved / "app.zip"),
                   "compact_probe", "argument café"]
        environment = {"PATH":"", "HOME":"/dev/null", "TMPDIR":"/dev/null/blocked",
                       "PYTHONHOME":"/missing/poison", "PYTHONPATH":"/missing/poison",
                       "PYTHONPYCACHEPREFIX":"/dev/null/blocked"}
        try:
            result = subprocess.run(command, cwd=empty_cwd, env=environment,
                                    capture_output=True, text=True, timeout=20)
            if result.returncode:
                raise RuntimeError(result.stderr)
            observed = json.loads(result.stdout)
            assert observed["status"] == "ok"
            assert observed["argv"] == ["argument café"]
            assert all(str(moved) in p for p in observed["path"])
            assert not original.exists()
            after = {str(p.relative_to(moved)):recipe.digest(p)
                     for p in moved.rglob("*") if p.is_file()}
            assert before == after
            report = {"task":"P00", "runtime":metadata, "command":command,
                      "environment":environment, "exit":result.returncode,
                      "stdout":observed, "stderr":result.stderr,
                      "stdlib_entries":spec["stdlib_entries"],
                      "deployed_files":len(after), "loose_bootstrap_files":1,
                      "checks":["relocated non-ASCII path", "build input removed", "empty cwd",
                                "empty PATH", "poison PYTHONHOME ignored", "read-only payload",
                                "unusable temp/cache", "snapshot unchanged", "metadata",
                                "encodings", "math/ssl", "archived source/resource", "native _dbm"],
                      "gaps":["no syscall trace; snapshot is not no-extraction proof",
                              "no network namespace; no offline network-isolation proof",
                              "Linux cells and non-PBS normalization unexecuted"]}
            Path(receipt).write_text(json.dumps(report, indent=2, ensure_ascii=False) + "\n")
            print(json.dumps({"version":metadata["version"],"checks":len(report["checks"]),
                              "stdlib_entries":spec["stdlib_entries"],"files":len(after),
                              "receipt":str(receipt)}))
        finally:
            # Restore directory modes only to clean up the controlled fixture.
            for path in moved.rglob("*"):
                if path.is_dir():
                    path.chmod(0o755)
            moved.chmod(0o755)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--python")
    parser.add_argument("--receipt")
    args = parser.parse_args()
    tests = unittest.main(argv=[__file__], exit=False)
    if not tests.result.wasSuccessful():
        raise SystemExit(1)
    if args.python:
        if not args.receipt:
            parser.error("--python requires --receipt")
        smoke(args.python, args.receipt)
