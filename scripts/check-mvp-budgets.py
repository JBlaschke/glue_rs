#!/usr/bin/env python3
"""CI gate for the checked-in target/case budget matrix and retained reports."""
import argparse
import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "fixtures/mvp"))
import benchmark


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--target", required=True)
    parser.add_argument("--reports", type=Path, required=True, help="directory containing CASE/benchmark.json")
    parser.add_argument("--config", type=Path, default=Path(__file__).resolve().parents[1]/"fixtures/mvp/budgets/index.json")
    args = parser.parse_args()
    try:
        config = json.loads(args.config.read_text())
        selected = config["targets"][args.target]
        if not selected["budgets"]: raise ValueError("this native target has no accepted numeric budget receipts")
        errors = []
        for item in selected["budgets"]:
            budget = json.loads((args.config.parent/item["budget"]).read_text())
            report = json.loads((args.reports/item["case"]/"benchmark.json").read_text())
            errors.extend(f"{item['case']}: {error}" for error in benchmark.check_budget(report,budget))
        if errors: raise ValueError("; ".join(errors))
        print(f"{args.target}: all {len(selected['budgets'])} cost budgets passed")
        return 0
    except (OSError, ValueError, KeyError, TypeError) as error:
        print(f"MVP cost budget: {error}", file=sys.stderr)
        return 1


if __name__ == "__main__": raise SystemExit(main())
