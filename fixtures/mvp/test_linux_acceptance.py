"""Portable planning/closure controls; synthetic metadata is not native evidence."""
import copy
from dataclasses import replace
import hashlib
import io
import json
import os
from pathlib import Path
import re
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

import linux_acceptance as acceptance
import trace_environment


ROOT = Path(__file__).resolve().parents[2]
LABELS = {
    "lua54-project", "lua54-native", "lua55-project", "lua55-native",
    "node-24.22.0-cjs", "node-24.22.0-esm", "node-24.22.0-resources", "node-24.22.0-native",
    "node-26.10.0-cjs", "node-26.10.0-esm", "node-26.10.0-resources", "node-26.10.0-native",
    "python-3.12.15-source", "python-3.12.15-module", "python-3.12.15-console", "python-3.12.15-native",
    "python-3.13.16-source", "python-3.13.16-module", "python-3.13.16-console", "python-3.13.16-native",
    "python-3.14.8-source", "python-3.14.8-module", "python-3.14.8-console", "python-3.14.8-native",
}
BUDGETS = {"lua55-project", "lua55-native", "node-cjs", "python-source-normalized", "python-native-normalized"}


def summary_inputs(architecture):
    profile = acceptance.profile_for(architecture)
    plan = acceptance.acceptance_plan(profile)
    receipts = {case["label"]: {"case": case["recipe"], "target": profile.target, "status": "passed",
                "host": {"target": profile.target}, "runtime": {"target": profile.target,
                    "version": case["runtime_version"], "provider": "bundled"}} for case in plan["cases"]}
    reports = {case: {"case": case, "target": profile.target, "status": "passed", "source_entries": 10000}
               for case in BUDGETS}
    budgets = {case: {"case": case, "target": profile.target, "completeness": "passed", "source_entries": 10000}
               for case in BUDGETS}
    return {"profile": profile,
            "cases": [{"case": case, "exit": 0} for case in sorted(LABELS)],
            "benchmarks": [{"case": case, "exit": 0} for case in sorted(BUDGETS)],
            "result": 0, "budget_mode": "enforce", "trace_error": None,
            "trace_environment": {"architecture": architecture, "policy": "traceable-native-syscalls-v1"},
            "case_receipts": receipts, "benchmark_reports": reports, "proposed_budgets": budgets,
            "finished_utc": "2026-10-28T00:00:00+00:00"}


class NativeLinuxPlanTests(unittest.TestCase):
    def test_both_profiles_keep_complete_original_workloads(self):
        for architecture in ("x86_64", "aarch64"):
            with self.subTest(architecture=architecture):
                profile = acceptance.profile_for(architecture)
                plan = acceptance.acceptance_plan(profile)
                self.assertEqual(len(plan["cases"]), 24)
                self.assertEqual({case["label"] for case in plan["cases"]}, LABELS)
                self.assertEqual(len(plan["benchmarks"]), 5)
                self.assertEqual(set(plan["benchmarks"]), BUDGETS)
                self.assertEqual(plan["source_entries"], 10000)
                self.assertEqual(plan["ranks"], [1, 32])
                self.assertEqual(plan["series"], ["first", "warm"])

    def test_exact_x86_defaults_are_preserved(self):
        profile = acceptance.native_profile(system="Linux", machine="x86_64")
        self.assertEqual((profile.target, profile.node_arch, profile.wheel_target),
                         ("x86_64-unknown-linux-gnu", "x64", "linux-x86_64"))
        self.assertEqual(profile.node_config, "fixtures/mvp/node-project/linux-x86_64.toml")
        self.assertEqual(profile.native_search, "/usr/lib/x86_64-linux-gnu")
        self.assertEqual(profile.conda_lock, "fixtures/mvp/python-matrix/conda-linux-x86_64-3.14.8.lock.json")
        self.assertEqual(profile.benchmark_python_environment, "ordinary")
        self.assertEqual(profile.pbs312_sha256, "5864001bf969db329fadc2b654c4878c6027d170c6bd77e28f88666260bcaf63")
        self.assertEqual(profile.pbs313_sha256, "1cca1041f693f110a2e0d16417090b8996258c7a121e90eeab66c2f40ea407f2")

    def test_arm64_profile_binds_every_platform_input(self):
        profile = acceptance.native_profile("aarch64-unknown-linux-gnu", system="Linux", machine="aarch64")
        self.assertEqual((profile.target, profile.node_arch, profile.wheel_target),
                         ("aarch64-unknown-linux-gnu", "arm64", "linux-arm64"))
        self.assertEqual(profile.node_config, "fixtures/mvp/node-project/linux-arm64.toml")
        self.assertEqual(profile.native_search, "/usr/lib/aarch64-linux-gnu")
        self.assertEqual(profile.conda_lock, "fixtures/mvp/python-matrix/conda-linux-aarch64-3.14.8.lock.json")
        self.assertEqual(profile.benchmark_python_environment, "ordinary-no-pip")
        self.assertEqual(profile.pbs312_sha256, "b342ccfb577fda349d0237c98b24848234ca767c10f034628a5ff9fc858d662f")
        self.assertEqual(profile.pbs313_sha256, "397ca401f416c3c99330a6be16d735d0cbeaf53e82070b80395b2fb4a8891f34")

    def test_unknown_foreign_and_alias_hosts_refuse(self):
        for machine in ("arm64", "i386", "AMD64", "riscv64", "", None, True):
            with self.subTest(machine=machine):
                # None requests host lookup; fix it explicitly for that control.
                with patch.object(acceptance.platform, "machine", return_value=None):
                    with self.assertRaises(ValueError):
                        acceptance.native_profile(system="Linux", machine=machine)
        for system in ("Darwin", "Windows", "FreeBSD", ""):
            with self.assertRaisesRegex(ValueError, "requires GNU Linux"):
                acceptance.native_profile(system=system, machine="aarch64")
        for architecture, foreign in (("x86_64", "aarch64-unknown-linux-gnu"),
                                      ("aarch64", "x86_64-unknown-linux-gnu")):
            for expected in (foreign, "aarch64", "unknown", None, True):
                with self.assertRaisesRegex(ValueError, "expected target"):
                    acceptance.native_profile(expected, system="Linux", machine=architecture)

    def test_tampered_profile_cannot_change_plans_or_summaries(self):
        profile = acceptance.profile_for("aarch64")
        for field, value in (("target", "x86_64-unknown-linux-gnu"), ("node_arch", "x64"),
                             ("wheel_target", "linux-x86_64"), ("conda_lock", "/tmp/input.json"),
                             ("pbs312_sha256", "0" * 64), ("native_search", "/tmp/libs")):
            changed = replace(profile, **{field: value})
            with self.assertRaisesRegex(ValueError, "closed source"):
                acceptance.acceptance_plan(changed)
            inputs = summary_inputs("aarch64")
            inputs["profile"] = changed
            with self.assertRaises(ValueError):
                acceptance.summarize(**inputs)

    def test_plan_containers_are_fresh(self):
        profile = acceptance.profile_for("aarch64")
        plan = acceptance.acceptance_plan(profile)
        plan["cases"].clear()
        plan["profile"]["target"] = "foreign"
        self.assertEqual(len(acceptance.acceptance_plan(profile)["cases"]), 24)
        self.assertEqual(profile.target, "aarch64-unknown-linux-gnu")

    def test_planning_and_summaries_have_no_file_process_or_network_io(self):
        inputs = summary_inputs("aarch64")
        with patch("builtins.open", side_effect=AssertionError("file I/O")), \
             patch.object(Path, "open", side_effect=AssertionError("path I/O")), \
             patch.object(subprocess, "run", side_effect=AssertionError("process I/O")):
            profile = acceptance.native_profile(system="Linux", machine="aarch64")
            self.assertEqual(len(acceptance.acceptance_plan(profile)["cases"]), 24)
            self.assertEqual(acceptance.summarize(**inputs)["status"], "passed")

    def test_shell_foreign_guard_creates_no_ci_root_or_preparation_output(self):
        with tempfile.TemporaryDirectory(prefix="glue native refusal ü ") as temporary:
            root = Path(temporary) / "must remain absent"
            environment = dict(os.environ, GLUE_MVP_CI_ROOT=str(root), GLUE_MVP_CI_EXPECT_TARGET="foreign-target")
            result = subprocess.run(["/bin/bash", str(ROOT / "scripts/ci-mvp-linux.sh")],
                                    env=environment, capture_output=True, timeout=15)
            self.assertEqual(result.returncode, 1, result.stderr)
            self.assertEqual(result.stdout, b"")
            self.assertIn(b"native Linux acceptance:", result.stderr)
            self.assertFalse(root.exists())
            self.assertEqual(list(Path(temporary).iterdir()), [])

    def test_profile_cli_serializes_the_guarded_closed_fields(self):
        with patch.object(acceptance.platform, "system", return_value="Linux"), \
             patch.object(acceptance.platform, "machine", return_value="aarch64"), \
             patch("sys.stdout", new_callable=io.StringIO) as output:
            self.assertEqual(acceptance.main(["profile", "--expected-target", "aarch64-unknown-linux-gnu"]), 0)
        fields = output.getvalue().strip().split("\t")
        self.assertEqual(fields[:4], ["aarch64", "aarch64-unknown-linux-gnu", "arm64", "linux-arm64"])
        self.assertEqual(len(fields), 10)
        self.assertEqual(fields[-1], "ordinary-no-pip")

    def test_reviewed_budget_roster_and_target_paths_are_closed(self):
        index = json.loads((ROOT / "fixtures/mvp/budgets/index.json").read_text())
        for architecture in ("x86_64", "aarch64"):
            profile = acceptance.profile_for(architecture)
            paths = acceptance.reviewed_budget_paths(profile, index)
            self.assertEqual({case for case, _ in paths}, BUDGETS)
            for case, relative in paths:
                self.assertEqual(relative, profile.target + "/" + case + ".json")
            for mutation in ("missing", "duplicate", "foreign", "escape", "unknown", "extra-field"):
                changed = copy.deepcopy(index)
                items = changed["targets"][profile.target]["budgets"]
                if mutation == "missing": items.pop()
                elif mutation == "duplicate": items[0] = copy.deepcopy(items[1])
                elif mutation == "foreign": items[0]["budget"] = "foreign/" + items[0]["case"] + ".json"
                elif mutation == "escape": items[0]["budget"] = "../" + items[0]["budget"]
                elif mutation == "unknown": items[0]["case"] = "unknown"
                else: items[0]["override"] = True
                with self.subTest(architecture=architecture, mutation=mutation):
                    with self.assertRaises(ValueError):
                        acceptance.reviewed_budget_paths(profile, changed)

    def test_shell_routes_each_native_boundary_through_the_closed_profile(self):
        source = (ROOT / "scripts/ci-mvp-linux.sh").read_text()
        # Integration argv checks catch a hardcoded or lost target at any of the
        # actual producer/consumer boundaries, beyond testing profiles in isolation.
        lines = source.replace("\\\n", " ").splitlines()
        boundaries = {"provision-conda.py": '--target "$target"',
                      "python-native/provision.py": '--target "$wheel_target"',
                      "fixtures/mvp/harness.py": '--target "$target"',
                      "scripts/benchmark-mvp.py": '--target "$target"',
                      "fixtures/mvp/trace_environment.py": '--architecture "$architecture"',
                      "fixtures/mvp/python-matrix/run_abi_refusal.py": '--architecture "$architecture"'}
        for command, target_option in boundaries.items():
            invocations = [line for line in lines if command in line]
            self.assertEqual(len(invocations), 2 if command == "python-native/provision.py" else 1, command)
            for invocation in invocations:
                self.assertIn(target_option, invocation, command)
        self.assertNotIn("x86_64", source)
        self.assertNotIn("linux-x64", source)
        self.assertNotIn("linux-arm64", source)
        for binding in ('linux-$node_arch', '20261009-$target-install_only.tar.gz',
                        '--lock "$conda_lock"', 'GLUE_MVP_NODE_CONFIG=$repo_dir/$node_config',
                        'GLUE_MVP_NATIVE_SEARCH=$native_search', '--architecture "$architecture" --evidence'):
            self.assertIn(binding, source)
        self.assertLess(source.index('linux_acceptance.py profile'), source.index('mkdir -p'))
        self.assertIn('linux_acceptance.reviewed_budget_paths(profile,', source)
        self.assertIn("report['target'] != selected_target", source)
        self.assertIn('"GLUE_MVP_PYTHON_ENV_KIND=ordinary"', source)
        overrides = [line for line in lines if 'GLUE_MVP_PYTHON_ENV_KIND=$benchmark_python_environment' in line]
        self.assertEqual(len(overrides), 1)
        self.assertIn('run_benchmark "$recipe"', overrides[0])

    def test_dispatch_matrix_binds_selected_architectures_to_native_runners(self):
        source = (ROOT / ".github/workflows/mvp-native.yml").read_text()
        # The expression's three JSON alternatives are also checked by actionlint.
        # Validate their data here with the same stdlib as portable CI.
        alternatives = [json.loads(value) for value in re.findall(r"'(\[\{[^'\n]+\}\])'", source)]
        self.assertEqual([[row["architecture"] for row in alternative] for alternative in alternatives],
                         [["x86_64", "aarch64"], ["aarch64"], ["x86_64"]])
        expected = {"x86_64": ("ubuntu-24.04", "x86_64-unknown-linux-gnu"),
                    "aarch64": ("ubuntu-24.04-arm", "aarch64-unknown-linux-gnu")}
        for alternative in alternatives:
            for row in alternative:
                self.assertEqual((row["runner"], row["target"]), expected[row["architecture"]])
        self.assertIn("inputs.target == 'both'", source)
        self.assertIn("inputs.target == 'aarch64'", source)
        self.assertIn("options: [x86_64, aarch64, both]", source)
        self.assertIn("default: x86_64", source)
        self.assertIn('GLUE_MVP_CI_EXPECT_TARGET: ${{ matrix.target }}', source)
        self.assertIn('mvp-native-linux-${{ matrix.architecture }}-', source)
        self.assertIn('runs-on: ${{ matrix.runner }}', source)

    def test_native_refusal_finish_gate_cannot_mask_collector_or_input_failure(self):
        source = (ROOT / "scripts/ci-mvp-linux.sh").read_text()
        marker = 'if /usr/bin/python3 - "$evidence/abi-summary.json" <<\'PY\'\n'
        self.assertEqual(source.count(marker), 1)
        program = source.split(marker, 1)[1].split("\nPY\n", 1)[0]
        for mutation in (None, "collector-failed", "input-mutated", "raw-changed", "missing-after"):
            with self.subTest(mutation=mutation), tempfile.TemporaryDirectory() as temporary:
                root = Path(temporary)
                (root / "abi-refusal-details").mkdir()
                before = json.dumps({"file": {"size": 1, "sha256": "a" * 64}}).encode()
                after = (json.dumps({"file": {"size": 2, "sha256": "b" * 64}}).encode()
                         if mutation == "input-mutated" else before)
                record = {"status": "failed" if mutation == "collector-failed" else "passed",
                          "collection_errors": ["mutation"] if mutation == "collector-failed" else []}
                for key, relative, raw in (("input_inventory", "abi-refusal-input-inventory.json", before),
                        ("input_inventory_after", "abi-refusal-details/input-inventory-after.json", after)):
                    record[key] = {"path": relative, "size": len(raw), "sha256": hashlib.sha256(raw).hexdigest()}
                    if mutation == "missing-after" and key == "input_inventory_after":
                        continue
                    if mutation == "raw-changed" and key == "input_inventory_after":
                        raw += b"\n"
                    (root / relative).write_bytes(raw)
                (root / "abi-refusal.json").write_text(json.dumps(record))
                path = root / "abi-summary.json"
                path.write_text(json.dumps({"wrong_abi_refusal": {"status": "passed"}}))
                result = subprocess.run([sys.executable, "-B", "-c", program, str(path)],
                                        capture_output=True, timeout=10)
                self.assertEqual(result.returncode == 0, mutation is None, result.stderr)


class NativeLinuxSummaryTests(unittest.TestCase):
    def test_complete_metadata_for_both_targets_and_budget_modes(self):
        for architecture in ("x86_64", "aarch64"):
            for mode in ("enforce", "observe"):
                inputs = summary_inputs(architecture)
                inputs["budget_mode"] = mode
                before = copy.deepcopy(inputs)
                report = acceptance.summarize(**inputs)
                self.assertEqual(inputs, before)
                self.assertEqual(report["status"], "passed")
                self.assertEqual(report["target"], architecture + "-unknown-linux-gnu")
                self.assertEqual(report["expected_cases"], 24)
                self.assertEqual(set(report["expected_labels"]), LABELS)
                self.assertEqual(set(report["expected_benchmarks"]), BUDGETS)
                self.assertEqual(report["errors"], [])
                if mode == "observe": self.assertIn("proposed pending review", report["scope"])

    def test_missing_duplicate_extra_and_failed_statuses_cannot_pass(self):
        for architecture in ("x86_64", "aarch64"):
            for key in ("cases", "benchmarks"):
                for mutation in ("missing", "duplicate", "extra", "failed", "bool-exit", "malformed"):
                    inputs = summary_inputs(architecture)
                    rows = inputs[key]
                    if mutation == "missing": rows.pop()
                    elif mutation == "duplicate": rows[0] = copy.deepcopy(rows[1])
                    elif mutation == "extra": rows.append({"case": "unexpected", "exit": 0})
                    elif mutation == "failed": rows[0]["exit"] = 2
                    elif mutation == "bool-exit": rows[0]["exit"] = False
                    else: inputs[key] = None
                    with self.subTest(architecture=architecture, key=key, mutation=mutation):
                        self.assertEqual(acceptance.summarize(**inputs)["status"], "failed")

    def test_tampered_retained_case_target_recipe_runtime_and_status_fail(self):
        for field, value in (("target", "foreign"), ("case", "node-native"), ("status", "failed"),
                             ("host", {"target": "foreign"}), ("host", None), ("runtime", None),
                             ("runtime", {"target": "foreign", "version": "5.4.9", "provider": "bundled"}),
                             ("runtime", {"target": "aarch64-unknown-linux-gnu", "version": "5.4.8", "provider": "bundled"}),
                             ("runtime", {"target": "aarch64-unknown-linux-gnu", "version": "5.4.9", "provider": "host"})):
            inputs = summary_inputs("aarch64")
            inputs["case_receipts"]["lua54-native"][field] = value
            report = acceptance.summarize(**inputs)
            self.assertEqual(report["status"], "failed")
            self.assertEqual(report["acceptance_status"], "failed")
        inputs = summary_inputs("aarch64")
        inputs["case_receipts"].pop("python-3.14.8-native")
        self.assertEqual(acceptance.summarize(**inputs)["status"], "failed")

    def test_retained_benchmark_and_budget_mismatch_or_missing_fails(self):
        for key in ("benchmark_reports", "proposed_budgets"):
            for field, value in (("target", "foreign"), ("case", "unknown"),
                                 ("status" if key == "benchmark_reports" else "completeness", "incomplete"),
                                 ("source_entries", 9999)):
                inputs = summary_inputs("x86_64")
                inputs[key]["node-cjs"][field] = value
                report = acceptance.summarize(**inputs)
                self.assertEqual(report["status"], "failed")
                self.assertEqual(report["benchmark_status"], "failed")
            inputs = summary_inputs("x86_64")
            inputs[key]["node-cjs"] = None
            self.assertEqual(acceptance.summarize(**inputs)["status"], "failed")

    def test_missing_wrong_target_and_wrong_policy_proofs_fail(self):
        for proof in (None, {}, {"architecture": "x86_64", "policy": "traceable-native-syscalls-v1"},
                      {"architecture": "aarch64", "policy": "unknown"}):
            inputs = summary_inputs("aarch64")
            inputs["trace_environment"] = proof
            self.assertEqual(acceptance.summarize(**inputs)["status"], "failed")
        inputs = summary_inputs("aarch64")
        inputs["trace_error"] = "retained proof changed"
        self.assertEqual(acceptance.summarize(**inputs)["status"], "failed")

    def test_runner_failure_is_preserved_and_invalid_modes_or_exits_refuse(self):
        inputs = summary_inputs("aarch64")
        inputs["result"] = 42
        report = acceptance.summarize(**inputs)
        self.assertEqual((report["status"], report["exit"]), ("failed", 42))
        for key, value in (("result", -1), ("result", True), ("result", 256), ("budget_mode", "refreeze")):
            inputs = summary_inputs("aarch64")
            inputs[key] = value
            with self.assertRaises(ValueError):
                acceptance.summarize(**inputs)

    def test_summary_cli_writes_failed_metadata_for_incomplete_input(self):
        with tempfile.TemporaryDirectory(prefix="glue closure ü ") as temporary:
            root = Path(temporary)
            # Malformed TSV must fail closed and still leave a useful summary.
            (root / "case-status.tsv").write_text("wrong\tformat\textra\n")
            result = acceptance.main(["summary", "--architecture", "aarch64", "--evidence", str(root),
                                      "--result", "0", "--budget-mode", "enforce"])
            self.assertEqual(result, 1)
            report = json.loads((root / "summary.json").read_text())
            self.assertEqual(report["status"], "failed")
            self.assertEqual(report["target"], "aarch64-unknown-linux-gnu")

    def test_summary_cli_round_trips_target_metadata_with_synthetic_proof(self):
        for architecture in ("x86_64", "aarch64"):
            with tempfile.TemporaryDirectory(prefix="glue summary synthetic ü ") as temporary:
                root = Path(temporary)
                inputs = summary_inputs(architecture)
                for key, name in (("cases", "case-status.tsv"), ("benchmarks", "benchmark-status.tsv")):
                    (root / name).write_text("".join(row["case"] + "\t0\n" for row in inputs[key]))
                for label, receipt in inputs["case_receipts"].items():
                    destination = root / "cases" / label
                    destination.mkdir(parents=True)
                    (destination / "receipt.json").write_text(json.dumps(receipt))
                for label in BUDGETS:
                    destination = root / "benchmarks" / label
                    destination.mkdir(parents=True)
                    (destination / "benchmark.json").write_text(json.dumps(inputs["benchmark_reports"][label]))
                    (root / "proposed-budgets").mkdir(exist_ok=True)
                    (root / "proposed-budgets" / (label + ".json")).write_text(json.dumps(inputs["proposed_budgets"][label]))
                proof_directory = root / "provisioning/trace-environment"
                proof_directory.mkdir(parents=True)
                proof = {"policy": "traceable-native-syscalls-v1", "architecture": architecture, "status": "passed",
                         "before_policy": {"setup_succeeded": False, "setup_errno": 13}}
                for label in ("parent", "inherited_exec_child"):
                    proof[label] = {"no_new_privs": 1, "seccomp_mode": 2, "ordinary_file_io": True,
                                    "native_syscalls_allowed": True,
                                    "syscalls": [{"name": name, "errno": 38} for name in trace_environment.CALLS]}
                    if architecture == "x86_64": proof[label]["abi_guards"] = {"x32_errno": 38, "i386_errno": 38}
                (proof_directory / "proof.json").write_text(json.dumps(proof))
                (proof_directory / "trace_environment.c").write_bytes(b"synthetic source only\n")
                (proof_directory / "glue-trace-environment").write_bytes(b"synthetic; never executed\n")
                trace_environment.check(proof_directory, architecture, record=True)
                self.assertEqual(acceptance.main(["summary", "--architecture", architecture, "--evidence", str(root),
                                 "--result", "0", "--budget-mode", "enforce"]), 0)
                report = json.loads((root / "summary.json").read_text())
                self.assertEqual(report["architecture"], architecture)
                # Tampering with retained transport proof must defeat zero status rows.
                (proof_directory / "glue-trace-environment").write_bytes(b"changed synthetic bytes\n")
                self.assertEqual(acceptance.main(["summary", "--architecture", architecture, "--evidence", str(root),
                                 "--result", "0", "--budget-mode", "enforce"]), 1)


if __name__ == "__main__":
    unittest.main()
