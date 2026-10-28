#!/usr/bin/env python3
"""Closed plans and completeness checks for native GNU Linux acceptance.

Planning and summary functions perform no I/O. The CLI's profile command checks
the actual host before the shell runner creates its CI root or provisions inputs.
These controls never substitute for the retained native receipts and traces.
"""
import argparse
from dataclasses import asdict, dataclass
import datetime
import json
from pathlib import Path
import platform
import sys


NODE_VERSIONS = ("24.22.0", "26.10.0")
PYTHON_INPUTS = (("3.12.15", "bin/python3.12", "cp312"),
                 ("3.13.16", "bin/python3.13", "cp313"),
                 ("3.14.8", "bin/python3.14", "cp314"))
BENCHMARKS = ("lua55-project", "lua55-native", "node-cjs",
              "python-source-normalized", "python-native-normalized")
TRACE_POLICY = "traceable-native-syscalls-v1"


@dataclass(frozen=True)
class LinuxProfile:
    architecture: str
    target: str
    node_arch: str
    wheel_target: str
    node_config: str
    native_search: str
    conda_lock: str
    pbs312_sha256: str
    pbs313_sha256: str


_PROFILES = (
    LinuxProfile("x86_64", "x86_64-unknown-linux-gnu", "x64", "linux-x86_64",
                 "fixtures/mvp/node-project/linux-x86_64.toml", "/usr/lib/x86_64-linux-gnu",
                 "fixtures/mvp/python-matrix/conda-linux-x86_64-3.14.8.lock.json",
                 "5864001bf969db329fadc2b654c4878c6027d170c6bd77e28f88666260bcaf63",
                 "1cca1041f693f110a2e0d16417090b8996258c7a121e90eeab66c2f40ea407f2"),
    LinuxProfile("aarch64", "aarch64-unknown-linux-gnu", "arm64", "linux-arm64",
                 "fixtures/mvp/node-project/linux-arm64.toml", "/usr/lib/aarch64-linux-gnu",
                 "fixtures/mvp/python-matrix/conda-linux-aarch64-3.14.8.lock.json",
                 "b342ccfb577fda349d0237c98b24848234ca767c10f034628a5ff9fc858d662f",
                 "397ca401f416c3c99330a6be16d735d0cbeaf53e82070b80395b2fb4a8891f34"),
)


def profile_for(architecture):
    for profile in _PROFILES:
        if type(architecture) is str and architecture == profile.architecture:
            return profile
    raise ValueError("unsupported native Linux architecture")


def _checked_profile(profile):
    if type(profile) is not LinuxProfile or profile != profile_for(profile.architecture):
        raise ValueError("native Linux profile differs from closed source definition")
    return profile


def native_profile(expected_target="", *, system=None, machine=None):
    """Select only the matching native Linux profile; no I/O or provisioning."""
    system = platform.system() if system is None else system
    machine = platform.machine() if machine is None else machine
    if system != "Linux":
        raise ValueError("native acceptance requires GNU Linux")
    profile = profile_for(machine)
    if type(expected_target) is not str or expected_target not in ("", profile.target):
        raise ValueError("native Linux host differs from expected target")
    return profile


def acceptance_plan(profile):
    profile = _checked_profile(profile)
    cases = []
    for family, version in (("54", "5.4.9"), ("55", "5.5.1")):
        for corpus in ("project", "native"):
            label = "lua" + family + "-" + corpus
            cases.append({"label": label, "recipe": label, "runtime_version": version})
    for version in NODE_VERSIONS:
        for corpus in ("cjs", "esm", "resources", "native"):
            cases.append({"label": "node-" + version + "-" + corpus,
                          "recipe": "node-" + corpus, "runtime_version": version})
    for version, _, _ in PYTHON_INPUTS:
        for corpus in ("source", "module", "console", "native"):
            cases.append({"label": "python-" + version + "-" + corpus,
                          "recipe": "python-" + corpus + "-normalized", "runtime_version": version})
    return {"profile": asdict(profile), "cases": cases, "benchmarks": list(BENCHMARKS),
            "source_entries": 10000, "ranks": [1, 32], "series": ["first", "warm"]}


def reviewed_budget_paths(profile, index):
    """Require exactly the five target-matched paths before reading budgets."""
    profile = _checked_profile(profile)
    items = _mapping(_mapping(_mapping(index).get("targets")).get(profile.target)).get("budgets")
    if (type(items) is not list or len(items) != len(BENCHMARKS)
            or any(type(item) is not dict or set(item) != {"case", "budget"}
                   or type(item["case"]) is not str or type(item["budget"]) is not str
                   for item in items)
            or {item["case"] for item in items} != set(BENCHMARKS)):
        raise ValueError("all five reviewed target budgets are required")
    for item in items:
        if item["budget"] != profile.target + "/" + item["case"] + ".json":
            raise ValueError("unexpected reviewed target budget path")
    return tuple((item["case"], item["budget"]) for item in items)


def _status_rows(rows, expected, label, errors):
    if type(rows) is not list:
        errors.append(label + " statuses are missing")
        return False
    valid = all(type(row) is dict and set(row) == {"case", "exit"}
                and type(row["case"]) is str and type(row["exit"]) is int
                and 0 <= row["exit"] <= 255 for row in rows)
    if not valid:
        errors.append(label + " statuses are malformed")
        return False
    if len(rows) != len(expected) or {row["case"] for row in rows} != set(expected):
        errors.append(label + " statuses are missing, duplicated or unexpected")
        return False
    if any(row["exit"] != 0 for row in rows):
        errors.append(label + " execution failed")
        return False
    return True


def _mapping(value):
    return value if type(value) is dict else {}


def summarize(profile, cases, benchmarks, *, result, budget_mode, trace_environment,
              trace_error=None, case_receipts, benchmark_reports, proposed_budgets,
              finished_utc):
    """Bind status closure to retained target/case identities, never raw traces.

    The shell separately replays all receipts, traces, ranks and budgets before
    recording status zero. This final check also refuses missing or mismatched
    retained metadata. Malformed metadata produces a failed summary.
    """
    plan = acceptance_plan(profile)
    if type(result) is not int or not 0 <= result <= 255:
        raise ValueError("invalid native runner exit status")
    if budget_mode not in ("enforce", "observe"):
        raise ValueError("unsupported native budget mode")
    errors = []
    expected = {case["label"]: case for case in plan["cases"]}
    cases_passed = _status_rows(cases, expected, "acceptance", errors)
    benchmarks_passed = _status_rows(benchmarks, BENCHMARKS, "benchmark", errors)
    for label, case in expected.items():
        receipt = _mapping(_mapping(case_receipts).get(label))
        runtime = _mapping(receipt.get("runtime"))
        if not (receipt.get("status") == "passed"
                and receipt.get("case") == case["recipe"] and receipt.get("target") == profile.target
                and _mapping(receipt.get("host")).get("target") == profile.target
                and runtime.get("target") == profile.target and runtime.get("provider") == "bundled"
                and runtime.get("version") == case["runtime_version"]):
            errors.append("retained acceptance identity/status differs: " + label)
            cases_passed = False
    for label in BENCHMARKS:
        report = _mapping(_mapping(benchmark_reports).get(label))
        budget = _mapping(_mapping(proposed_budgets).get(label))
        if not (report.get("case") == budget.get("case") == label
                and report.get("target") == budget.get("target") == profile.target
                and report.get("status") == budget.get("completeness") == "passed"
                and report.get("source_entries") == budget.get("source_entries") == 10000):
            errors.append("retained benchmark/budget identity/status differs: " + label)
            benchmarks_passed = False
    policy_passed = (isinstance(trace_environment, dict)
                     and trace_environment.get("architecture") == profile.architecture
                     and trace_environment.get("policy") == TRACE_POLICY and trace_error is None)
    if not policy_passed:
        errors.append("trace environment proof is unavailable or target/policy differs")
    passed = result == 0 and cases_passed and benchmarks_passed and policy_passed
    return {"status": "passed" if passed else "failed", "exit": result or (0 if passed else 1),
            "target": profile.target, "architecture": profile.architecture,
            "expected_cases": len(expected), "expected_labels": sorted(expected), "cases": cases,
            "acceptance_status": "passed" if cases_passed else "failed",
            "expected_benchmarks": sorted(BENCHMARKS), "benchmarks": benchmarks,
            "benchmark_status": "passed" if benchmarks_passed else "failed",
            "trace_environment": trace_environment, "trace_environment_error": trace_error,
            "errors": errors, "budget_mode": budget_mode, "finished_utc": finished_utc,
            "scope": "native V02/R02 and R03 under explicit " + TRACE_POLICY + " CI policy; "
                     + ("reviewed " + profile.architecture + " budgets enforced" if budget_mode == "enforce"
                        else "generated " + profile.architecture + " budgets are proposed pending review"),
            "cache_policy": "first/warm fresh processes; no cold filesystem-cache claim",
            "budget_policy": "time/RSS scoped to recorded host boot fingerprint; no universal host limits"}


def _read_status(path):
    if not path.exists():
        return []
    try:
        return [{"case": name, "exit": int(code)}
                for name, code in (line.split("\t") for line in path.read_text().splitlines())]
    except ValueError:
        return None


def _json_or_missing(path):
    try:
        return json.loads(path.read_text())
    except (OSError, ValueError):
        return {}


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest="command", required=True)
    host = commands.add_parser("profile")
    host.add_argument("--expected-target", default="")
    for name in ("plan", "pbs-inputs", "summary"):
        command = commands.add_parser(name)
        command.add_argument("--architecture", required=True)
        if name == "summary":
            command.add_argument("--evidence", type=Path, required=True)
            command.add_argument("--result", type=int, required=True)
            command.add_argument("--budget-mode", choices=("enforce", "observe"), required=True)
    args = parser.parse_args(argv)
    try:
        if args.command == "profile":
            profile = native_profile(args.expected_target)
            print("\t".join(str(value) for value in asdict(profile).values()))
            return 0
        profile = profile_for(args.architecture)
        if args.command == "plan":
            print(json.dumps(acceptance_plan(profile), indent=2))
        elif args.command == "pbs-inputs":
            print("3.12.15 " + profile.pbs312_sha256 + "\n3.13.16 " + profile.pbs313_sha256)
        else:
            import trace_environment
            root = args.evidence
            try:
                policy = trace_environment.check(root / "provisioning/trace-environment", profile.architecture)
                policy_error = None
            except (OSError, ValueError, KeyError, TypeError) as error:
                policy, policy_error = None, str(error)
            plan = acceptance_plan(profile)
            summary = summarize(profile, _read_status(root / "case-status.tsv"),
                _read_status(root / "benchmark-status.tsv"), result=args.result,
                budget_mode=args.budget_mode, trace_environment=policy, trace_error=policy_error,
                case_receipts={case["label"]: _json_or_missing(root / "cases" / case["label"] / "receipt.json")
                               for case in plan["cases"]},
                benchmark_reports={case: _json_or_missing(root / "benchmarks" / case / "benchmark.json")
                                   for case in BENCHMARKS},
                proposed_budgets={case: _json_or_missing(root / "proposed-budgets" / (case + ".json"))
                                  for case in BENCHMARKS},
                finished_utc=datetime.datetime.now(datetime.timezone.utc).isoformat())
            (root / "summary.json").write_text(json.dumps(summary, indent=2) + "\n")
            return 0 if summary["status"] == "passed" else 1
        return 0
    except (OSError, ValueError, TypeError, KeyError) as error:
        print("native Linux acceptance: " + str(error), file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
