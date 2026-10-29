#!/usr/bin/env python3
"""Closed plans and retained metadata checks for seven native Linux Python routes.

This module never provisions or executes runtimes. The native runner separately
replays full V02 receipts/traces before writing each successful status row.
"""
import argparse
from dataclasses import asdict, dataclass
import datetime
import hashlib
import json
import math
from pathlib import Path, PurePosixPath
import sys

VERSION = "3.13.16"
MAX_METADATA_BYTES = 64 * 1024 * 1024
TRACE_POLICY = "traceable-native-syscalls-v1"

@dataclass(frozen=True)
class OfficialInput:
    route: str
    name: str
    sha256: str
    size: int
    url: str

@dataclass(frozen=True)
class Cell:
    label: str
    recipe: str
    route: str
    kind: str

@dataclass(frozen=True)
class CaseEvidence:
    receipt: bytes
    environment: bytes
    inventory: bytes

_INPUT_ROWS = {
    'x86_64': (
        (
            'full',
            'cpython-3.13.16+20261009-x86_64-unknown-linux-gnu-pgo+lto-full.tar.zst',
            'b4fd36646765e6b8387ace2fd5a152d10028a84deb0d1f173f7299429129d202',
            109512857,
            'https://github.com/astral-sh/python-build-standalone/releases/download/20261009/cpython-3.13.16%2B20261009-x86_64-unknown-linux-gnu-pgo%2Blto-full.tar.zst',
        ),
        (
            'install-only',
            'cpython-3.13.16+20261009-x86_64-unknown-linux-gnu-install_only.tar.gz',
            '1cca1041f693f110a2e0d16417090b8996258c7a121e90eeab66c2f40ea407f2',
            75275675,
            'https://github.com/astral-sh/python-build-standalone/releases/download/20261009/cpython-3.13.16%2B20261009-x86_64-unknown-linux-gnu-install_only.tar.gz',
        ),
        (
            'stripped',
            'cpython-3.13.16+20261009-x86_64-unknown-linux-gnu-install_only_stripped.tar.gz',
            '24801ea31c7d406d559a17e2226325c723d50c56900b9c0da7b62adaae2affc9',
            35082735,
            'https://github.com/astral-sh/python-build-standalone/releases/download/20261009/cpython-3.13.16%2B20261009-x86_64-unknown-linux-gnu-install_only_stripped.tar.gz',
        ),
        (
            'uv',
            'uv-x86_64-unknown-linux-gnu.tar.gz',
            'f29c3e94ffabd7e6f3ba521dba169a9b7ec12100bf3257087f0f24f6123f3645',
            16799024,
            'https://github.com/astral-sh/uv/releases/download/0.13.6/uv-x86_64-unknown-linux-gnu.tar.gz',
        ),
    ),
    'aarch64': (
        (
            'full',
            'cpython-3.13.16+20261009-aarch64-unknown-linux-gnu-pgo+lto-full.tar.zst',
            '8907ec2f181f0fc5cd08b9d897d36159432405af78f68f8faca728f48940e0ca',
            95632430,
            'https://github.com/astral-sh/python-build-standalone/releases/download/20261009/cpython-3.13.16%2B20261009-aarch64-unknown-linux-gnu-pgo%2Blto-full.tar.zst',
        ),
        (
            'install-only',
            'cpython-3.13.16+20261009-aarch64-unknown-linux-gnu-install_only.tar.gz',
            '397ca401f416c3c99330a6be16d735d0cbeaf53e82070b80395b2fb4a8891f34',
            57626877,
            'https://github.com/astral-sh/python-build-standalone/releases/download/20261009/cpython-3.13.16%2B20261009-aarch64-unknown-linux-gnu-install_only.tar.gz',
        ),
        (
            'stripped',
            'cpython-3.13.16+20261009-aarch64-unknown-linux-gnu-install_only_stripped.tar.gz',
            '52c6993abd6ac687cceb787ecee83b166271bc06ad80ac9cac82c5d28d3c00bc',
            29327967,
            'https://github.com/astral-sh/python-build-standalone/releases/download/20261009/cpython-3.13.16%2B20261009-aarch64-unknown-linux-gnu-install_only_stripped.tar.gz',
        ),
        (
            'uv',
            'uv-aarch64-unknown-linux-gnu.tar.gz',
            '229e194255c7958d86d56e8790d969a6f74736592133f0dfd0076f754c642c1d',
            15794886,
            'https://github.com/astral-sh/uv/releases/download/0.13.6/uv-aarch64-unknown-linux-gnu.tar.gz',
        ),
    ),
}

_CELLS = (
    Cell("python-archive-full", "python-archive-compatibility", "full", "ordinary"),
    Cell("python-archive-install-only", "python-archive-compatibility", "install-only", "ordinary"),
    Cell("python-archive-stripped", "python-archive-compatibility", "stripped", "ordinary"),
    Cell("python-uv-source", "python-uv-source-normalized", "uv", "uv"),
    Cell("python-uv-module", "python-uv-module-normalized", "uv", "uv"),
    Cell("python-uv-console", "python-uv-console-normalized", "uv", "uv"),
    Cell("python-uv-native", "python-uv-native-normalized", "uv", "uv"),
)
_REQUIRED_CHECKS = (
    "native_target", "build_success", "runtime_reference", "input_bytes_preserved",
    "input_prefix_absent", "relocated", "payload_read_only", "payload_unchanged",
    "no_language_tools", "unrelated_cwd", "unusable_temp_cache", "exit_status",
    "stdout", "stderr", "execution_completed", "offline", "trace_complete",
    "no_extraction", "trace_oracle", "signing_policy",
)


def target_for(architecture):
    if type(architecture) is not str or architecture not in _INPUT_ROWS:
        raise ValueError("unsupported native GNU Linux architecture")
    return architecture + "-unknown-linux-gnu"


def inputs_for(architecture):
    target_for(architecture)
    return tuple(OfficialInput(*row) for row in _INPUT_ROWS[architecture])


def cells_for(architecture):
    target_for(architecture)
    return _CELLS


def official_manifest(architecture):
    return {item.route: {k: v for k, v in asdict(item).items() if k != "route"}
            for item in inputs_for(architecture)}


def compatibility_plan(architecture):
    return {"protocol": "glue-linux-python-compatibility-plan-v1",
            "architecture": architecture, "target": target_for(architecture),
            "runtime_version": VERSION, "runtime_origin": "PBS 20261009 conventional GIL",
            "uv_version": "0.13.6", "inputs": official_manifest(architecture),
            "cases": [asdict(cell) for cell in cells_for(architecture)],
            "uv_runtime_reference": "cases/python-3.13.16-source/receipt.json",
            "trace_policy": TRACE_POLICY, "full_m2_acceptance": False}


def _mapping(value):
    return value if type(value) is dict else {}


def _identity(raw):
    return {"sha256": hashlib.sha256(raw).hexdigest(), "size": len(raw)}


def _identity_matches(value, expected):
    return (type(value) is dict and type(value.get("size")) is int
            and value.get("size") == expected["size"]
            and value.get("sha256") == expected["sha256"])


def _json(raw):
    if type(raw) is not bytes or len(raw) > MAX_METADATA_BYTES:
        raise ValueError("bounded immutable metadata bytes required")
    def pairs(items):
        result = {}
        for key, value in items:
            if key in result:
                raise ValueError("duplicate JSON key")
            result[key] = value
        return result
    def integer(text):
        if len(text) > 32:
            raise ValueError("integer metadata token exceeds bound")
        return int(text)
    def constant(_):
        raise ValueError("nonfinite metadata constant")
    def floating(text):
        value = float(text)
        if not math.isfinite(value):
            raise ValueError("nonfinite metadata number")
        return value
    try:
        value = json.loads(raw, object_pairs_hook=pairs, parse_int=integer,
                           parse_float=floating, parse_constant=constant)
    except (UnicodeError, RecursionError) as error:
        raise ValueError("invalid metadata JSON") from error
    if type(value) is not dict:
        raise ValueError("metadata object required")
    return value


def _base_errors(receipt, target, recipe=None):
    errors = []
    runtime = _mapping(receipt.get("runtime"))
    abi = _mapping(runtime.get("abi"))
    version = _mapping(abi.get("version"))
    if not (receipt.get("status") == "passed" and receipt.get("target") == target
            and _mapping(receipt.get("host")).get("target") == target
            and receipt.get("reference_kind") == "stock"
            and runtime.get("target") == target and runtime.get("version") == VERSION
            and runtime.get("provider") == "bundled" and runtime.get("implementation") == "cpython"
            and abi.get("language") == "python" and abi.get("gil") == "conventional"
            and abi.get("debug") is False
            and all(type(version.get(k)) is int and version[k] == v
                    for k, v in (("major", 3), ("minor", 13), ("patch", 16)))):
        errors.append("runtime/native target, version, provider or ABI identity differs")
    if recipe is not None and receipt.get("case") != recipe:
        errors.append("case recipe identity differs")
    checks = _mapping(receipt.get("checks"))
    if any(_mapping(checks.get(name)).get("status") != "passed" for name in _REQUIRED_CHECKS):
        errors.append("required V02 execution/trace checks are incomplete")
    return errors


def _runtime_source(runtime):
    inputs = _mapping(runtime.get("inputs"))
    return {key: value for key, value in inputs.items()
            if key == "runtime-executable" or key.startswith("stdlib:")}


def _option_value(argv, option):
    """Recipes use one separated option/value, without duplicate '=' forms."""
    if argv.count(option) != 1 or any(word.startswith(option + "=") for word in argv):
        return None
    index = argv.index(option)
    return argv[index + 1] if index + 1 < len(argv) else None


def _case_errors(cell, evidence, target, official, reference):
    if type(evidence) is not CaseEvidence:
        return ["retained case metadata is missing"]
    try:
        receipt, environment, inventory = (_json(evidence.receipt),
            _json(evidence.environment), _json(evidence.inventory))
    except (ValueError, TypeError) as error:
        return ["retained metadata is invalid: " + str(error)]
    errors = _base_errors(receipt, target, cell.recipe)
    runtime = _mapping(receipt.get("runtime"))
    if not (_mapping(receipt.get("input_inventory")).get("path") == "input-inventory.json"
            and _identity_matches(receipt.get("input_inventory"), _identity(evidence.inventory))):
        errors.append("input inventory identity differs")
    if not _identity_matches(inventory.get("environment-receipt.json"), _identity(evidence.environment)):
        errors.append("retained environment receipt differs from original input inventory")
    if not (environment.get("kind") == cell.kind
            and type(environment.get("version")) is list
            and len(environment["version"]) == 2
            and all(type(v) is int for v in environment["version"])
            and environment["version"] == [3, 13]
            and environment.get("pip_present") is (cell.kind == "ordinary")
            and environment.get("framework_input_prepared") is False):
        errors.append("prepared environment kind/version/seed identity differs")
    prepare = _mapping(_mapping(receipt.get("commands")).get("prepare"))
    argv = prepare.get("argv")
    build = _mapping(_mapping(receipt.get("commands")).get("build"))
    build_argv = build.get("argv")
    if not (type(argv) is list and len(argv) >= 7 and all(type(x) is str for x in argv)
            and argv[1].endswith("/fixtures/mvp/python-matrix/prepare.py")
            and argv[3:5] == ["bin/python3.13", cell.kind]
            and argv.count("--receipt-output") == 1
            and prepare.get("executed") is True and prepare.get("timed_out") is False
            and type(prepare.get("exit")) is int and prepare["exit"] == 0):
        errors.append("preparation command or completion differs")
        return errors
    expected_native = 1 if cell.label == "python-uv-native" else 0
    if (argv.count("--native") != expected_native
            or any(word.startswith("--native=") for word in argv)):
        errors.append("native preparation does not match the selected corpus")
    try:
        cwd = PurePosixPath(prepare.get("cwd", ""))
        original_output = cwd.parent
        inputs = cwd / "build inputs"
        retained_arg = argv[argv.index("--receipt-output") + 1]
        if not (cwd.is_absolute() and cwd.name == "work" and original_output.name == cell.label
                and argv[2] == str(inputs)
                and retained_arg == str(original_output / "environment-receipt.json")
                and environment.get("runtime") == str(inputs / "runtime/bin/python3.13")):
            errors.append("environment receipt/command does not bind its own case inputs")
    except (ValueError, TypeError, IndexError):
        errors.append("preparation paths are malformed")
        return errors
    if not (type(build_argv) is list and all(type(x) is str for x in build_argv)
            and build_argv[1:3] == ["build", "python"]
            and "--normalize-native-paths" in build_argv
            and build.get("executed") is True and build.get("timed_out") is False
            and type(build.get("exit")) is int and build["exit"] == 0):
        errors.append("build command or completion differs")
        return errors
    if (_option_value(build_argv, "--env") != str(inputs / "environment")
            or len(build_argv) < 4 or build_argv[3] != str(inputs / "project")):
        errors.append("build does not consume its prepared environment/project")
    selector, entry = (("--module", "main") if cell.label == "python-uv-module"
                       else ("--console-script", "sample") if cell.label == "python-uv-console"
                       else ("--entry", "main.py"))
    if (_option_value(build_argv, selector) != entry
            or any(word == other or word.startswith(other + "=")
                   for other in ("--entry", "--module", "--console-script") if other != selector
                   for word in build_argv)):
        errors.append("build entry selector does not match the selected compatibility route")
    if cell.route == "uv":
        if any(word == "--runtime" or word.startswith("--runtime=") for word in build_argv):
            errors.append("uv tree case must not masquerade as an archive override")
        if _option_value(build_argv, "--prune") != "app/site/0/_virtualenv.pth":
            errors.append("uv executable hook prune is not explicit")
        current_source = _runtime_source(runtime)
        reference_source = _runtime_source(_mapping(reference.get("runtime")))
        if not ("runtime-executable" in current_source and any(k.startswith("stdlib:") for k in current_source)
                and current_source == reference_source):
            errors.append("uv runtime/stdlib does not match the validated PBS reference")
    else:
        archive = official[cell.route]
        archive_identity = {key: archive[key] for key in ("sha256", "size")}
        if not (_identity_matches(inventory.get("runtime-input.tar"), archive_identity)
                and _identity_matches(_mapping(runtime.get("inputs")).get("runtime-archive"), archive_identity)):
            errors.append("original and consumed runtime archive identities do not match pinned route")
        if _option_value(build_argv, "--runtime") != str(inputs / "runtime-input.tar"):
            errors.append("direct runtime archive override is missing or misbound")
    return errors


def summarize(architecture, statuses, input_manifest, case_evidence, *, result,
              reference_receipt, finished_utc):
    """Check seven retained cells; never run a V02 checker or a native command."""
    plan = compatibility_plan(architecture)
    if type(result) is not int or not 0 <= result <= 255:
        raise ValueError("invalid compatibility runner result")
    official = plan["inputs"]
    errors = []
    if not (type(input_manifest) is dict and set(input_manifest) == set(official)
            and all(type(input_manifest[k]) is dict
                    and set(input_manifest[k]) == set(official[k])
                    and type(input_manifest[k].get("size")) is int
                    and input_manifest[k] == official[k] for k in official)):
        errors.append("official compatibility input identities/roster differ")
    expected = {cell.label for cell in cells_for(architecture)}
    if not (type(statuses) is list and len(statuses) == 7
            and all(type(row) is dict and set(row) == {"case", "exit"}
                    and type(row["case"]) is str and type(row["exit"]) is int
                    and 0 <= row["exit"] <= 255 for row in statuses)
            and {row["case"] for row in statuses} == expected):
        errors.append("compatibility statuses are missing, duplicated, malformed or unexpected")
    elif any(row["exit"] != 0 for row in statuses):
        errors.append("one or more compatibility executions failed")
    try:
        reference = _json(reference_receipt)
        reference_errors = _base_errors(reference, plan["target"], "python-source-normalized")
        if reference_errors:
            errors.append("PBS reference receipt is invalid: " + "; ".join(reference_errors))
    except (ValueError, TypeError) as error:
        reference = {}
        errors.append("PBS reference receipt is unavailable: " + str(error))
    cases = []
    for cell in cells_for(architecture):
        cell_errors = _case_errors(cell, _mapping(case_evidence).get(cell.label),
                                   plan["target"], official, reference)
        cases.append({**asdict(cell), "status": "passed" if not cell_errors else "failed",
                      "errors": cell_errors})
        errors.extend(cell.label + ": " + error for error in cell_errors)
    passed = result == 0 and not errors
    return {"protocol": "glue-linux-python-compatibility-summary-v1",
            "status": "passed" if passed else "failed", "exit": result or (0 if passed else 1),
            "target": plan["target"], "runtime_version": VERSION, "expected_cases": 7,
            "cases": cases, "errors": errors, "inputs": input_manifest,
            "trace_policy": TRACE_POLICY, "finished_utc": finished_utc,
            "validation_basis": "Retained metadata closure; runner must independently replay full V02 receipts/traces before recording zero status.",
            "full_m2_acceptance": False, "native_execution_performed_by_summary": False,
            "remaining_compatibility": ["additional patch with unchanged glue bytes", "abi3 admission", "macOS native routes and complete trace/signing gates"]}


def _read(path):
    with path.open("rb") as stream:
        raw = stream.read(MAX_METADATA_BYTES + 1)
    if len(raw) > MAX_METADATA_BYTES:
        raise ValueError("metadata exceeds bound")
    return raw


def _read_or_missing(path):
    try:
        return _read(path)
    except OSError:
        return b""


def _statuses(path):
    try:
        return [{"case": name, "exit": int(code)} for name, code in
                (line.split("\t") for line in _read(path).decode().splitlines())]
    except (OSError, ValueError, UnicodeError):
        return None


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("command", choices=("inputs", "plan", "cells", "summary"))
    parser.add_argument("--architecture", required=True)
    parser.add_argument("--evidence", type=Path)
    parser.add_argument("--result", type=int)
    args = parser.parse_args(argv)
    try:
        plan = compatibility_plan(args.architecture)
        if args.command == "inputs":
            for item in inputs_for(args.architecture):
                print("\t".join(str(value) for value in asdict(item).values()))
        elif args.command == "cells":
            for cell in cells_for(args.architecture):
                print("\t".join(asdict(cell).values()))
        elif args.command == "plan":
            print(json.dumps(plan, indent=2))
        else:
            if args.evidence is None or args.result is None:
                raise ValueError("summary requires --evidence and --result")
            root = args.evidence
            try:
                manifest = _json(_read(root / "compatibility-inputs.json"))
            except (OSError, ValueError):
                manifest = None
            cases = {cell.label: CaseEvidence(
                _read_or_missing(root / "cases" / cell.label / "receipt.json"),
                _read_or_missing(root / "cases" / cell.label / "environment-receipt.json"),
                _read_or_missing(root / "cases" / cell.label / "input-inventory.json"))
                for cell in cells_for(args.architecture)}
            report = summarize(args.architecture, _statuses(root / "compatibility-case-status.tsv"),
                manifest, cases, result=args.result,
                reference_receipt=_read_or_missing(root / "cases/python-3.13.16-source/receipt.json"),
                finished_utc=datetime.datetime.now(datetime.timezone.utc).isoformat())
            (root / "compatibility-summary.json").write_text(json.dumps(report, indent=2) + "\n")
            return 0 if report["status"] == "passed" else 1
        return 0
    except (OSError, ValueError, TypeError, KeyError, IndexError) as error:
        print("Linux compatibility: " + str(error), file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
