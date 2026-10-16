#!/usr/bin/env python3
"""Compile and exercise only private, unprivileged bootstrap pipe controls."""
import os
import pathlib
import shlex
import shutil
import subprocess
import tempfile
import unittest

HERE = pathlib.Path(__file__).resolve().parent


class BootstrapIOTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.temporary = tempfile.TemporaryDirectory(prefix="glue-bootstrap-io-test-")
        cls.addClassCleanup(cls.temporary.cleanup)
        cls.binary = pathlib.Path(cls.temporary.name) / "test-bootstrap-io"
        compiler = shutil.which(os.environ.get("CC", "cc"))
        if compiler is None:
            raise RuntimeError("a native C compiler is required")
        command = [compiler, "-std=c11", "-O2", "-Wall", "-Wextra", "-Werror"]
        command += shlex.split(os.environ.get("BIO_TEST_CFLAGS", ""))
        command += [str(HERE / "bootstrap_io.c"), str(HERE / "test_bootstrap_io.c"),
                    "-o", str(cls.binary)]
        result = subprocess.run(command, capture_output=True, text=True, timeout=30)
        if result.returncode:
            raise RuntimeError(f"compile failed: {result.stdout}{result.stderr}")

    def run_case(self, name):
        result = subprocess.run([str(self.binary), name], capture_output=True,
                                text=True, timeout=8)
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertEqual(result.stdout, f"PASS {name}\n")
        self.assertEqual(result.stderr, "")


def make_case(name):
    def test(self):
        self.run_case(name)
    return test


for _case in ("arguments", "endpoint", "time-bounds", "time-progress", "partial",
              "poll-anomalies", "poll-error-precedence", "storms", "io-anomalies", "eof", "native-roundtrip",
              "native-fragmented", "native-hup", "native-truncated", "native-eof-extra",
              "native-deadline", "native-broken-peer", "native-endpoint"):
    setattr(BootstrapIOTests, "test_" + _case.replace("-", "_"), make_case(_case))

if __name__ == "__main__":
    unittest.main()
