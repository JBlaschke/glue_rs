import copy
import hashlib
import os
import sys
import tempfile
import unittest
from pathlib import Path

import benchmark


class BenchmarkTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory(prefix="glue-costs-")
        self.root = Path(self.temporary.name)
        self.root.chmod(0o755)

    def tearDown(self):
        self.temporary.cleanup()

    def test_native_parent_measures_each_rank_and_does_not_fake_missing_samples(self):
        measurer, provenance = benchmark.compile_measurer(self.root)
        expected = {"exit": 0, "stdout": {"sha256": hashlib.sha256(b"measured\n").hexdigest()}, "stderr": {"sha256": hashlib.sha256(b"").hexdigest()}}
        result = benchmark.measure_ranks([sys.executable, "-c", "data=bytearray(1024*1024); print('measured')"], self.root, os.environ.copy(), self.root / "two-ranks", 2, expected, measurer)
        self.assertTrue(result["semantics_match"])
        self.assertEqual(len(result["results"]), 2)
        for row in result["results"]:
            self.assertTrue(row["measurement_complete"])
            self.assertGreater(row["elapsed_seconds"], 0)
            self.assertGreater(row["peak_rss_bytes"], 0)
        self.assertIn("no Python fork RSS floor", provenance["method"])

    def test_timeout_is_incomplete_with_null_measurements(self):
        measurer, _ = benchmark.compile_measurer(self.root)
        empty = {"sha256": hashlib.sha256(b"").hexdigest()}
        result = benchmark.measure_ranks([sys.executable,"-c","import time; time.sleep(10)"], self.root, os.environ.copy(), self.root/"timeout", 1, {"exit":0,"stdout":empty,"stderr":empty}, measurer, timeout=0.05)
        self.assertFalse(result["semantics_match"])
        self.assertTrue(result["results"][0]["timed_out"])
        self.assertIsNone(result["results"][0]["peak_rss_bytes"])

    def report(self):
        measurement={"semantics_match":True,"elapsed_max_seconds":0.1,"peak_rss_max_bytes":1024,"label":"warm","ranks":1}
        variant={"variant":"baseline","artifact":{"sha256":"input"},"costs":{"deployed_files":6,"native_bytes":0},"io":{"open":10,"stat":20,"read":30},"measurements":[measurement]}
        base=copy.deepcopy(variant);scaled=copy.deepcopy(variant);scaled["variant"]="scaled"
        return {"status":"passed","case":"lua55-project","target":"aarch64-unknown-linux-gnu","host":{"fingerprint":"recorded-host"},"source_entries":10000,"variants":[base,scaled]}

    def test_budget_rejects_linear_file_metadata_and_memory_regressions(self):
        report=self.report();budget=benchmark.proposed_budget(report)
        self.assertEqual(benchmark.check_budget(report,budget),[])
        bad=copy.deepcopy(report);bad["variants"][1]["costs"]["deployed_files"]+=10000
        self.assertIn("source scaling added deployment files",benchmark.check_budget(bad,budget))
        bad=copy.deepcopy(report);bad["variants"][1]["io"]["stat"]+=10000
        self.assertIn("source-entry metadata scaling budget exceeded",benchmark.check_budget(bad,budget))
        bad=copy.deepcopy(report);bad["variants"][0]["measurements"][0]["peak_rss_max_bytes"]*=2
        self.assertIn("RSS budget exceeded",benchmark.check_budget(bad,budget))
        bad["host"]["fingerprint"]="different-host"
        self.assertNotIn("RSS budget exceeded",benchmark.check_budget(bad,budget))

    def test_frozen_required_measurements_cannot_silently_disappear(self):
        report=self.report();report["variants"][0]["fds"]={"peak_per_process":5}
        budget=benchmark.proposed_budget(report)
        report["variants"][0]["io"]=None
        report["variants"][0]["fds"]=None
        report["variants"][0]["measurements"][0]["semantics_match"]=False
        errors=benchmark.check_budget(report,budget)
        self.assertIn("complete startup I/O measurements are missing",errors)
        self.assertIn("descriptor measurement is missing",errors)
        self.assertIn("execution semantics/acceptance failed",errors)

    def test_missing_io_is_unavailable_and_failed_runs_cannot_freeze(self):
        report=self.report();report["variants"][1]["io"]=None
        self.assertEqual(benchmark.comparison(*report["variants"],10000)["metadata_scaling"]["status"],"unavailable")
        report["status"]="incomplete"
        with self.assertRaisesRegex(Exception,"cannot freeze"):
            benchmark.proposed_budget(report)
        report["variants"][0]["measurements"][0]["semantics_match"]=False
        with self.assertRaisesRegex(Exception,"cannot freeze"):
            benchmark.proposed_budget(report)


if __name__ == "__main__": unittest.main()
