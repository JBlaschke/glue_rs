#!/usr/bin/env python3
"""Derive a compatibility table from actual V02 receipts, retaining failed gates.

Usage: matrix.py --cell NAME=/absolute/receipt.json ... --output NEWDIR
Raw executions and large inventories stay outside Git (decision 0030).
"""
from pathlib import Path
import argparse
import importlib.util
import json
import re


def load_harness():
    path = Path(__file__).resolve().parents[1] / "harness.py"
    spec = importlib.util.spec_from_file_location("mvp_harness", path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--cell", action="append", required=True, help="stable cell name=actual receipt path")
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    harness = load_harness()
    cells = []
    names = set()
    execution_checks = {"native_target", "build_success", "runtime_reference", "input_bytes_preserved", "input_prefix_absent", "relocated", "payload_read_only", "payload_unchanged", "no_language_tools", "unrelated_cwd", "unusable_temp_cache", "exit_status", "stdout", "stderr", "execution_completed"}
    for item in args.cell:
        name, value = item.split("=", 1)
        if not re.fullmatch(r"[a-z0-9-]+", name) or name in names:
            raise ValueError("invalid or duplicate cell name")
        names.add(name)
        path = Path(value).resolve()
        receipt = json.loads(path.read_text())
        failures = harness.check(path)
        checks = receipt.get("checks", {})
        executed = all(checks.get(check, {}).get("status") == "passed" for check in execution_checks)
        cells.append({"cell": name, "case": receipt.get("case"), "receipt": str(path), "target": receipt.get("target"), "runtime": receipt.get("runtime", {}), "launcher": receipt.get("launcher", {}), "executed_match": executed, "acceptance_passed": not failures, "missing_gates": failures, "checks": checks})
    patch_pairs = []
    for i, first in enumerate(cells):
        for second in cells[i+1:]:
            one, two = first["runtime"], second["runtime"]
            a, b = one.get("version", "").split("."), two.get("version", "").split(".")
            if not (first["executed_match"] and second["executed_match"] and len(a) >= 3 and len(b) >= 3 and a[:2] == b[:2] and a[2:] != b[2:] and first["target"] == second["target"]):
                continue
            identity_a, identity_b = one.get("inputs", {}).get("runtime-executable"), two.get("inputs", {}).get("runtime-executable")
            launcher_a, launcher_b = first["launcher"].get("sha256"), second["launcher"].get("sha256")
            if identity_a and identity_b and identity_a != identity_b and launcher_a and launcher_a == launcher_b:
                patch_pairs.append({"cells": [first["cell"], second["cell"]], "versions": [one["version"], two["version"]], "same_glue_sha256": launcher_a, "different_runtime_digests": True})
    targets = {"aarch64-apple-darwin", "aarch64-unknown-linux-gnu", "x86_64-unknown-linux-gnu"}
    passed_targets = {cell["target"] for cell in cells if cell["acceptance_passed"]}
    versions = sorted({cell["runtime"].get("version", "unknown") for cell in cells if cell["executed_match"]})
    summary = {"revision": 1, "cells": cells, "executed_versions": versions, "additional_patch_without_glue_rebuild": patch_pairs, "unproven_targets": sorted(targets - passed_targets), "m2_evidence_complete": targets <= passed_targets and all(cell["acceptance_passed"] and cell["checks"].get("no_extraction", {}).get("status") == "passed" for cell in cells)}
    args.output.mkdir(parents=True, exist_ok=False)
    (args.output / "matrix.json").write_text(json.dumps(summary, sort_keys=True, indent=2) + "\n")
    rows = ["| Cell | Native target | Exact CPython | Execution/reference | All requested gates |", "| --- | --- | --- | --- | --- |"]
    for cell in cells:
        rows.append(f"| {cell['cell']} | {cell['target']} | {cell['runtime'].get('version', 'unavailable')} | {'passed' if cell['executed_match'] else 'failed'} | {'passed' if cell['acceptance_passed'] else '; '.join(cell['missing_gates'])} |")
    rows += ["", "A matching execution is separate from complete offline, tracing and signing acceptance.", "Unproven native targets: " + (", ".join(summary["unproven_targets"]) or "none") + ".", "Additional patch pairs using the same glue bytes: " + str(len(patch_pairs)) + ".", ""]
    (args.output / "matrix.md").write_text("\n".join(rows))
    print(args.output / "matrix.md")


if __name__ == "__main__":
    main()
