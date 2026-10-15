#!/usr/bin/env python3
"""Verify signatures in the final compact layout and report the actual policy."""
import argparse
import importlib.util
import json
import platform
from pathlib import Path

spec = importlib.util.spec_from_file_location("glue_mvp_extraction", Path(__file__).resolve().parents[1] / "fixtures/mvp/extraction.py")
extraction = importlib.util.module_from_spec(spec)
spec.loader.exec_module(extraction)
parser = argparse.ArgumentParser(description=__doc__)
parser.add_argument("payload", type=Path)
parser.add_argument("--policy", choices=["ad-hoc", "developer-id"], required=True)
parser.add_argument("--output", type=Path)
args = parser.parse_args()
if platform.system() != "Darwin": raise SystemExit("macOS signatures must be assessed on a native macOS host")
result = extraction.verify_macos(args.payload, args.policy)
text = json.dumps(result, sort_keys=True, indent=2) + "\n"
if args.output: args.output.write_text(text)
else: print(text, end="")
raise SystemExit(0 if result["status"] == "passed" else 1)
