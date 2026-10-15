#!/usr/bin/env python3
"""Check complete Linux process-tree traces without a fixture byte allowlist."""
import argparse
import importlib.util
import json
from pathlib import Path

spec = importlib.util.spec_from_file_location("glue_mvp_extraction", Path(__file__).resolve().parents[1] / "fixtures/mvp/extraction.py")
extraction = importlib.util.module_from_spec(spec)
spec.loader.exec_module(extraction)
parser = argparse.ArgumentParser(description=__doc__)
parser.add_argument("--prefix", type=Path, required=True)
parser.add_argument("--cwd", type=Path, required=True)
parser.add_argument("--application-output", type=Path, action="append", default=[])
parser.add_argument("--stdio-sink", type=Path, action="append", default=[])
parser.add_argument("--executable")
args = parser.parse_args()
try:
    result = extraction.check_trace(args.prefix, args.cwd, args.application_output, args.stdio_sink, args.executable)
except (OSError, ValueError) as error:
    raise SystemExit(f"MVP extraction trace rejected: {error}")
print(json.dumps(result, sort_keys=True, indent=2))
