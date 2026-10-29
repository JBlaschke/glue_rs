#!/usr/bin/env python3
"""Collect one genuine foreign-minor Python build refusal on its native host.

No sudo, package download, compiler or installer is invoked. The existing
preparer creates its ordinary copied venv, including its normal bundled pip
seed, then copies the independently provisioned foreign wheel tree. It never
imports application code. This collector creates only a new owned output tree
and new evidence records; it never removes an existing capture.
"""
import argparse
import datetime
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import shutil
import stat
import sys

MAX_METADATA = 64 * 1024 * 1024
MAX_WHEEL = 16 * 1024 * 1024
MAX_STREAM = 64 * 1024 * 1024
LABEL = "python-wrong-abi-refusal"
REPOSITORY = Path(__file__).resolve().parents[3]


class CollectionError(ValueError):
    pass


def _require(condition, message):
    if not condition:
        raise CollectionError(message)


def _load(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


def _dependencies():
    sys.dont_write_bytecode = True
    return (_load("abi_refusal_harness", REPOSITORY / "fixtures/mvp/harness.py"),
            _load("abi_refusal_compatibility", Path(__file__).with_name("linux_abi_compatibility.py")))


def _identity(raw):
    return {"size": len(raw), "sha256": hashlib.sha256(raw).hexdigest()}


def _read_regular(path, limit=MAX_METADATA):
    descriptor = os.open(path, os.O_RDONLY | os.O_NOFOLLOW)
    try:
        before = os.fstat(descriptor)
        _require(stat.S_ISREG(before.st_mode) and before.st_nlink == 1,
                 "evidence/source must be a singly linked regular file: " + str(path))
        _require(0 <= before.st_size <= limit, "evidence/source byte bound: " + str(path))
        with os.fdopen(descriptor, "rb", closefd=False) as stream:
            raw = stream.read(limit + 1)
        after = os.fstat(descriptor)
        fields = ("st_dev", "st_ino", "st_size", "st_mtime_ns", "st_ctime_ns", "st_mode", "st_nlink")
        _require(len(raw) <= limit and all(getattr(before, name) == getattr(after, name) for name in fields),
                 "source changed while being read: " + str(path))
        return raw
    finally:
        os.close(descriptor)


def _exists(path):
    return os.path.lexists(path)


def _directory(path, name):
    _require(path.is_absolute(), name + " must be absolute")
    _require(path.is_dir() and not path.is_symlink(), name + " must be an existing ordinary directory")
    _require(path.resolve() == path, name + " must use its physical absolute path")


def _json_bytes(value):
    return (json.dumps(value, indent=2, sort_keys=True) + "\n").encode()


def _write_new(path, raw):
    with path.open("xb") as stream:
        stream.write(raw)


def _state(path):
    try:
        mode = path.lstat().st_mode
    except FileNotFoundError:
        return {"kind": "absent"}
    return {"kind": ("symlink" if stat.S_ISLNK(mode) else "directory" if stat.S_ISDIR(mode)
                     else "regular" if stat.S_ISREG(mode) else "special")}


def _tree_inventory(path, harness):
    _require(path.is_dir() and not path.is_symlink(), "observed tree is not an ordinary directory: " + str(path))
    try:
        return harness.inventory(path)
    except harness.HarnessError as error:
        raise CollectionError("observed tree inventory is invalid: " + str(error)) from error


def _preflight(args, harness, compatibility):
    target = compatibility.target_for(args.architecture)
    # This must precede even output/evidence validation and all process calls.
    try:
        observed_target = harness.native_target()
    except harness.HarnessError as error:
        raise CollectionError("native target unavailable; no output or runtime execution permitted: " + str(error)) from error
    _require(observed_target == target, "wrong native target; no output or runtime execution permitted")
    output, evidence = args.output, args.evidence
    _require(output.is_absolute() and output.name == LABEL and not _exists(output),
             "output must be a new absolute directory ending " + LABEL)
    _directory(output.parent, "output parent")
    _directory(evidence, "evidence root")
    _directory(args.runtime_root, "selected runtime root")
    _directory(args.foreign_input, "foreign provision root")
    _require(not any(source.is_relative_to(output) or output.is_relative_to(source)
                     for source in (evidence, args.runtime_root, args.foreign_input)),
             "output must be separate from runtime/provision/evidence roots")
    _require(args.glue.is_absolute(), "glue binary must be absolute")
    names = ("abi-refusal.json", "abi-refusal.stderr", "abi-refusal-input-inventory.json",
             "abi-refusal-input-inventory-after.json", "abi-refusal-details")
    _require(not any(_exists(evidence / name) for name in names), "new refusal evidence paths are required")
    reference_raw = _read_regular(evidence / "cases/python-3.13.16-source/receipt.json")
    reference = compatibility._json(reference_raw)
    errors = compatibility._base_errors(reference, target, "3.13.16", "python-source-normalized")
    _require(not errors, "checked base source receipt is invalid: " + "; ".join(errors))
    glue_identity = harness.identity(args.glue)
    _require(compatibility._identity_matches(glue_identity, reference["launcher"]),
             "collector glue binary differs from checked base source launcher")
    runtime_inventory = _tree_inventory(args.runtime_root, harness)
    expected_runtime = reference["runtime"]["inputs"]["runtime-executable"]
    _require(compatibility._identity_matches(runtime_inventory.get("bin/python3.13"), expected_runtime),
             "selected interpreter differs from checked base 3.13.16 runtime")
    official = compatibility.official_manifest(args.architecture)
    wheel_receipt = _read_regular(args.foreign_input / "inputs.json")
    errors = compatibility._wheel_receipt_errors(wheel_receipt, "cp314", args.architecture, official)
    _require(not errors, "foreign provisioning receipt is invalid: " + "; ".join(errors))
    wheel_name = official["cffi-cp314"]["name"]
    wheel_raw = _read_regular(args.foreign_input / wheel_name, MAX_WHEEL)
    _require(compatibility._identity_matches(_identity(wheel_raw), official["cffi-cp314"]),
             "genuine cp314 CFFI wheel bytes differ from official source pin")
    members = compatibility.wheel_inventory(wheel_raw)
    backend = "_cffi_backend.cpython-314-" + args.architecture + "-linux-gnu.so"
    _require(backend in members and compatibility._valid_identity(members[backend]),
             "genuine foreign-minor CFFI backend is missing from pinned wheel")
    site = args.foreign_input / "site"
    foreign_inventory = _tree_inventory(site, harness)
    _require(all(foreign_inventory.get(name) == pin for name, pin in members.items()),
             "foreign installed CFFI members differ from pinned wheel bytes")
    wheel_destination = evidence / "provisioning/abi-wheels" / wheel_name
    _require(not any(p.is_symlink() for p in (evidence / "provisioning", evidence / "provisioning/abi-wheels")),
             "wheel evidence directory must not be a symlink")
    if _exists(wheel_destination):
        _require(_identity(_read_regular(wheel_destination, MAX_WHEEL)) == _identity(wheel_raw),
                 "existing retained CFFI wheel differs; it will not be replaced")
    return {"target": target, "reference_raw": reference_raw, "reference": reference,
            "runtime_inventory": runtime_inventory, "foreign_inventory": foreign_inventory,
            "foreign_receipt": wheel_receipt, "wheel_raw": wheel_raw, "wheel_name": wheel_name,
            "wheel_members": members, "backend": backend, "wheel_destination": wheel_destination,
            "glue_identity": glue_identity, "official": official}


def collect(args, dependencies=None):
    """Run only after native and genuine-input preflights; never promote failure."""
    harness, compatibility = dependencies if dependencies is not None else _dependencies()
    prepared = _preflight(args, harness, compatibility)
    output, evidence = args.output, args.evidence
    output.mkdir()
    work = output / "work"
    work.mkdir()
    inputs = work / "build inputs"
    inputs.mkdir()
    sentinel = output / "sibling sentinel"
    sentinel.mkdir()
    _write_new(sentinel / "sentinel.txt", b"Unrelated sibling data must survive a wrong-ABI build.\n")
    rejected = output / "rejected output"
    record = {"protocol": "glue-native-linux-python-wrong-abi-refusal-v1",
              "started_utc": datetime.datetime.now(datetime.timezone.utc).isoformat(),
              "target": prepared["target"], "commit": prepared["reference"]["commit"],
              "runtime_version": "3.13.16", "runtime_executable": prepared["reference"]["runtime"]["inputs"]["runtime-executable"],
              "foreign_wheel": prepared["official"]["cffi-cp314"], "glue": prepared["glue_identity"],
              "output_path": str(rejected), "output_before": _state(rejected),
              "sentinel_path": str(sentinel), "sentinel_before": _tree_inventory(sentinel, harness),
              "native_execution": False, "native_execution_attempted": False,
              "status": "failed", "collection_errors": [],
              "source_identity": {"collector": harness.identity(Path(__file__)),
                  "preparer": harness.identity(REPOSITORY / "fixtures/mvp/python-matrix/prepare.py"),
                  "harness": harness.identity(REPOSITORY / "fixtures/mvp/harness.py"),
                  "assessment": harness.identity(Path(__file__).with_name("linux_abi_compatibility.py"))}}
    before = {}
    after = {}
    stderr = b""
    try:
        shutil.copytree(args.runtime_root, inputs / "runtime", symlinks=True)
        shutil.copytree(REPOSITORY / "fixtures/mvp/python-env/project", inputs / "project", symlinks=True)
        shutil.copytree(args.foreign_input / "site", inputs / "installed", symlinks=True)
        _require(_tree_inventory(inputs / "runtime", harness) == prepared["runtime_inventory"],
                 "copied runtime input inventory differs")
        _require(_tree_inventory(inputs / "installed", harness) == prepared["foreign_inventory"],
                 "copied foreign site inventory differs")
        environment = {**os.environ, "PYTHONDONTWRITEBYTECODE": "1", "UV_PYTHON_DOWNLOADS": "never"}
        prepare_argv = [sys.executable, "-B", str(REPOSITORY / "fixtures/mvp/python-matrix/prepare.py"),
                        str(inputs), "bin/python3.13", "ordinary"]
        preparation = harness.run_command("prepare", prepare_argv, work, environment, output, 240)
        record["preparation"] = preparation
        _require(preparation.get("executed") is True and preparation.get("timed_out") is False
                 and type(preparation.get("exit")) is int and preparation["exit"] == 0,
                 "ordinary copied environment preparation did not complete")
        before = _tree_inventory(inputs, harness)
        for name, pin in prepared["wheel_members"].items():
            _require(before.get("installed/" + name) == pin
                     and before.get("environment/lib/python3.13/site-packages/" + name) == pin,
                     "prepared foreign CFFI member differs from source wheel")
        _require(compatibility._identity_matches(before.get("runtime/bin/python3.13"), record["runtime_executable"]),
                 "prepared selected interpreter changed")
        command = [str(args.glue), "build", "python", str(inputs / "project"),
                   "--env", str(inputs / "environment"), "--entry", "main.py",
                   "--output", str(rejected), "--python", "3.13", "--json"]
        record["native_execution_attempted"] = True
        record["command"] = harness.run_command("refusal", command, work, environment, output, 240)
        record["native_execution"] = True
        stderr = _read_regular(output / "refusal.stderr", MAX_STREAM)
    except (CollectionError, OSError, ValueError, KeyError, TypeError) as error:
        record["collection_errors"].append(str(error))
    # Preserve all reachable observations, even after a failed preparation/build.
    for label, path in (("sentinel_after", sentinel), ("input_after", inputs)):
        try:
            observed = _tree_inventory(path, harness)
            if label == "sentinel_after":
                record[label] = observed
            else:
                after = observed
        except (CollectionError, OSError, ValueError) as error:
            record["collection_errors"].append(label + ": " + str(error))
    record["output_after"] = _state(rejected)
    raw_before = _json_bytes(before)
    raw_after = _json_bytes(after)
    record["input_inventory"] = {"path": "abi-refusal-input-inventory.json", **_identity(raw_before)}
    record["input_inventory_after"] = {"path": "abi-refusal-details/input-inventory-after.json", **_identity(raw_after)}
    if not before or before != after:
        record["collection_errors"].append("before/after input inventories differ or preparation never completed")
    if record.get("sentinel_after") != record["sentinel_before"]:
        record["collection_errors"].append("unrelated sibling sentinel changed")
    if record["output_before"] != {"kind": "absent"} or record["output_after"] != {"kind": "absent"}:
        record["collection_errors"].append("rejected output was not absent before and after")
    try:
        _require(_tree_inventory(args.foreign_input / "site", harness) == prepared["foreign_inventory"],
                 "original independently provisioned site changed")
        _require(harness.identity(args.glue) == prepared["glue_identity"], "original glue binary changed")
    except (CollectionError, OSError, ValueError) as error:
        record["collection_errors"].append(str(error))
    assessment = compatibility.assess_refusal(args.architecture,
        compatibility.RefusalEvidence(_json_bytes(record), stderr, raw_before), prepared["reference_raw"])
    record["assessment"] = assessment
    details = evidence / "abi-refusal-details"

    def optional_retention(label, operation):
        try:
            operation()
            return True
        except (CollectionError, OSError, ValueError) as error:
            record["collection_errors"].append(label + " retention failed: " + str(error))
            return False

    details_ready = optional_retention("detail directory", details.mkdir)
    after_retained = details_ready and optional_retention("after-input inventory",
        lambda: _write_new(details / "input-inventory-after.json", raw_after))
    if not after_retained:
        # Keep the reachable observation even when the canonical detail path
        # cannot be written. This fallback never converts collection to success.
        fallback = "abi-refusal-input-inventory-after.json"
        if optional_retention("fallback after-input inventory", lambda: _write_new(evidence / fallback, raw_after)):
            record["input_inventory_after_fallback"] = {"path": fallback, **_identity(raw_after)}
    if details_ready:
        for name, raw in (("sentinel-before.json", _json_bytes(record["sentinel_before"])),
                          ("sentinel-after.json", _json_bytes(record.get("sentinel_after"))),
                          ("foreign-wheel-inputs.json", prepared["foreign_receipt"]),
                          ("cffi-wheel-members.json", _json_bytes(prepared["wheel_members"]))):
            optional_retention(name, lambda name=name, raw=raw: _write_new(details / name, raw))
    for name in ("prepare.stdout", "prepare.stderr", "refusal.stdout", "refusal.stderr"):
        path = output / name
        if details_ready and _exists(path):
            optional_retention(name, lambda path=path, name=name:
                _write_new(details / name, _read_regular(path, MAX_STREAM)))

    def retain_wheel():
        prepared["wheel_destination"].parent.mkdir(parents=True, exist_ok=True)
        if _exists(prepared["wheel_destination"]):
            _require(_identity(_read_regular(prepared["wheel_destination"], MAX_WHEEL)) == _identity(prepared["wheel_raw"]),
                     "existing retained CFFI wheel changed; it will not be replaced")
        else:
            _write_new(prepared["wheel_destination"], prepared["wheel_raw"])
    optional_retention("CFFI wheel", retain_wheel)
    record["status"] = "passed" if not record["collection_errors"] and assessment["status"] == "passed" else "failed"
    record["finished_utc"] = datetime.datetime.now(datetime.timezone.utc).isoformat()
    _write_new(evidence / "abi-refusal-input-inventory.json", raw_before)
    _write_new(evidence / "abi-refusal.stderr", stderr)
    _write_new(evidence / "abi-refusal.json", _json_bytes(record))
    return record


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--architecture", required=True, choices=("x86_64", "aarch64"))
    parser.add_argument("--runtime-root", type=Path, required=True)
    parser.add_argument("--foreign-input", type=Path, required=True)
    parser.add_argument("--glue", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--evidence", type=Path, required=True)
    args = parser.parse_args(argv)
    try:
        record = collect(args)
        print(json.dumps({"status": record["status"], "target": record["target"],
                          "evidence": str(args.evidence / "abi-refusal.json"),
                          "collection_errors": record["collection_errors"],
                          "assessment": record["assessment"]}))
        return 0 if record["status"] == "passed" else 1
    except (CollectionError, OSError, ValueError, KeyError, TypeError) as error:
        print("Native wrong-ABI collector: " + str(error), file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
