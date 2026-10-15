#!/usr/bin/env python3
"""Validate required native acceptance checks and retained output identities."""
import importlib.util
import sys
from pathlib import Path

spec = importlib.util.spec_from_file_location("glue_mvp_harness", Path(__file__).resolve().parents[1] / "fixtures/mvp/harness.py")
harness = importlib.util.module_from_spec(spec)
spec.loader.exec_module(harness)
if len(sys.argv) != 2:
    raise SystemExit("usage: scripts/check-mvp-results.py RECEIPT.json")
try:
    errors = harness.check(Path(sys.argv[1]))
except (OSError, ValueError, TypeError) as error:
    raise SystemExit(f"invalid MVP receipt: {error}")
if errors:
    raise SystemExit("MVP receipt failed:\n" + "\n".join(f"- {error}" for error in errors))
print("MVP receipt passed: all required checks executed")
