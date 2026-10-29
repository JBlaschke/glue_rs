#!/usr/bin/env python3
"""Closed native Linux patch/abi3 plans and retained proof checks.

No runtime, compiler, product command or package hook runs here. The native
runner independently checks V02 receipts/traces before recording zero statuses.
"""
import argparse
from dataclasses import asdict, dataclass
import datetime
import hashlib
import io
import json
import math
from pathlib import Path, PurePosixPath
import re
import stat
import sys
import unicodedata
import zipfile

MAX_METADATA_BYTES = 64 * 1024 * 1024
MAX_WHEEL_BYTES = 16 * 1024 * 1024
MAX_WHEEL_CONTENTS = 128 * 1024 * 1024
TRACE_POLICY = "traceable-native-syscalls-v1"
PACKAGES = ("cryptography==50.0.2", "cffi==2.1.1", "pycparser==3.0")
ABI3_PROJECT = {"size": 550, "sha256": "1e0c2401e3e48723ba9d9a25e9b4ef8b3d2e118f6c42b60712d840000345bd43"}

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
    reference_stdout: bytes = b""
    run_stdout: bytes = b""


@dataclass(frozen=True)
class RefusalEvidence:
    record: bytes
    stderr: bytes
    inventory: bytes

_INPUT_ROWS = {
    'x86_64': (
        (
            'patch',
            'cpython-3.13.15+20260929-x86_64-unknown-linux-gnu-install_only.tar.gz',
            'd6b4e09474dfc219befabeae16264466f09615a991dcd080ae698833bdb3ed44',
            75170574,
            'https://github.com/astral-sh/python-build-standalone/releases/download/20260929/cpython-3.13.15%2B20260929-x86_64-unknown-linux-gnu-install_only.tar.gz',
        ),
        (
            'cryptography',
            'cryptography-50.0.2-cp39-abi3-manylinux_2_34_x86_64.whl',
            '1981f1db4630889b9ef7803fadef12b056f428cb6b85c27ba57b774793b6093c',
            4780973,
            'https://files.pythonhosted.org/packages/40/cf/6b5c8e2fd9202d98988ab7cb5cc5c991704c4ad55f492ff408e4969f83f1/cryptography-50.0.2-cp39-abi3-manylinux_2_34_x86_64.whl',
        ),
        (
            'cffi-cp313',
            'cffi-2.1.1-cp313-cp313-manylinux2014_x86_64.manylinux_2_17_x86_64.whl',
            'a931079504ecc49efed7744c476a5c343a92fabf66dec2db95edb1b2fdc770e2',
            221824,
            'https://files.pythonhosted.org/packages/95/95/86342356ff5953b3fb06f7ef7c5bee212d45e770abc7218d451b9148313c/cffi-2.1.1-cp313-cp313-manylinux2014_x86_64.manylinux_2_17_x86_64.whl',
        ),
        (
            'cffi-cp314',
            'cffi-2.1.1-cp314-cp314-manylinux2014_x86_64.manylinux_2_17_x86_64.whl',
            'b0431303acaea1089ad4b3e9ce4e6518193def1118d4073ca848635ee4ea2e96',
            221525,
            'https://files.pythonhosted.org/packages/e9/02/4e7d553a7ac4b4238b38b3c1b80d486e9d4436f8d2acbf87a0997fe3f402/cffi-2.1.1-cp314-cp314-manylinux2014_x86_64.manylinux_2_17_x86_64.whl',
        ),
        (
            'pycparser',
            'pycparser-3.0-py3-none-any.whl',
            'b727414169a36b7d524c1c3e31839a521725078d7b2ff038656844266160a992',
            48172,
            'https://files.pythonhosted.org/packages/0c/c3/44f3fbbfa403ea2a7c779186dc20772604442dde72947e7d01069cbe98e3/pycparser-3.0-py3-none-any.whl',
        ),
    ),
    'aarch64': (
        (
            'patch',
            'cpython-3.13.15+20260929-aarch64-unknown-linux-gnu-install_only.tar.gz',
            '8b54ea9550c52f9db265ab5680ce02429be3b4e1628f0b0dd8da2e451e403578',
            57584195,
            'https://github.com/astral-sh/python-build-standalone/releases/download/20260929/cpython-3.13.15%2B20260929-aarch64-unknown-linux-gnu-install_only.tar.gz',
        ),
        (
            'cryptography',
            'cryptography-50.0.2-cp39-abi3-manylinux_2_34_aarch64.whl',
            '0ddc924c04591c2811ca024d62ecad4f7f6f08af8939c211438f48a16bd23602',
            4764319,
            'https://files.pythonhosted.org/packages/bc/ce/7e4f662b1e3c393513569e402cfc85ac7da0bd3d5435e122a3140219eb2d/cryptography-50.0.2-cp39-abi3-manylinux_2_34_aarch64.whl',
        ),
        (
            'cffi-cp313',
            'cffi-2.1.1-cp313-cp313-manylinux2014_aarch64.manylinux_2_17_aarch64.whl',
            'f16c709686a78c727bbbf059f92b0bf41c6fc60deec706d2dc19f529175a6125',
            222369,
            'https://files.pythonhosted.org/packages/37/6f/3b5ce4c3b2192d250f04908f2bfd91ef34552ec8f7716a5d4abdb8d67bb2/cffi-2.1.1-cp313-cp313-manylinux2014_aarch64.manylinux_2_17_aarch64.whl',
        ),
        (
            'cffi-cp314',
            'cffi-2.1.1-cp314-cp314-manylinux2014_aarch64.manylinux_2_17_aarch64.whl',
            '58acb8ab8e295e6c5ea12f888cbb13cf21511ef2a3303a23f4325c29d17fe5c1',
            222328,
            'https://files.pythonhosted.org/packages/67/b8/b42132ca113dc567d37684437b46ca1dafc885902b02a110a02d5b511857/cffi-2.1.1-cp314-cp314-manylinux2014_aarch64.manylinux_2_17_aarch64.whl',
        ),
        (
            'pycparser',
            'pycparser-3.0-py3-none-any.whl',
            'b727414169a36b7d524c1c3e31839a521725078d7b2ff038656844266160a992',
            48172,
            'https://files.pythonhosted.org/packages/0c/c3/44f3fbbfa403ea2a7c779186dc20772604442dde72947e7d01069cbe98e3/pycparser-3.0-py3-none-any.whl',
        ),
    ),
}

_CELLS = (
    Cell("python-patch-3.13.15-source", "python-patch-source-normalized", "patch", "ordinary"),
    Cell("python-abi3-3.13.16", "python-abi3-compatibility", "cp313", "ordinary"),
    Cell("python-abi3-3.14.8", "python-abi3-compatibility", "cp314", "ordinary"),
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
    return {
        "protocol": "glue-linux-python-patch-abi3-plan-v1",
        "architecture": architecture, "target": target_for(architecture),
        "cases": [asdict(cell) for cell in cells_for(architecture)],
        "inputs": official_manifest(architecture), "packages": list(PACKAGES),
        "runtime_versions": {"patch": "3.13.15", "cp313": "3.13.16", "cp314": "3.14.8"},
        "reference_receipts": {
            "3.13.16": "cases/python-3.13.16-source/receipt.json",
            "3.14.8": "cases/python-3.14.8-source/receipt.json",
        },
        "patch_provenance": "abi-patch-runtime.json",
        "wheel_receipts": {tag: "abi-wheel-inputs-" + tag + ".json" for tag in ("cp313", "cp314")},
        "cryptography_wheel": "provisioning/abi-wheels/" + official_manifest(architecture)["cryptography"]["name"],
        "abi3_project": ABI3_PROJECT.copy(), "trace_policy": TRACE_POLICY,
        "refusal_control": refusal_plan(architecture), "full_m2_acceptance": False,
    }


def refusal_plan(architecture):
    return {
        "protocol": "glue-linux-python-wrong-abi-refusal-plan-v1",
        "target": target_for(architecture), "selected_runtime": "3.13.16",
        "foreign_cffi_wheel": official_manifest(architecture)["cffi-cp314"],
        "command_suffix": ["--python", "3.13", "--json"],
        "expected_exit": 1, "expected_code": "runtime_abi_mismatch",
        "output_requirement": "absent before and after the failed build",
        "sentinel_requirement": "nonempty unrelated sibling inventory unchanged",
        "evidence_files": ["abi-refusal.json", "abi-refusal.stderr", "abi-refusal-input-inventory.json"],
        "control_label": "python-wrong-abi-refusal",
        "execution_required": True, "native_execution_performed_by_plan": False,
    }


def _mapping(value):
    return value if type(value) is dict else {}


def _identity(raw):
    return {"sha256": hashlib.sha256(raw).hexdigest(), "size": len(raw)}


def _valid_identity(value):
    return (type(value) is dict and type(value.get("size")) is int
            and value["size"] >= 0 and type(value.get("sha256")) is str
            and re.fullmatch("[0-9a-f]{64}", value["sha256"]) is not None)


def _identity_matches(value, expected):
    return (_valid_identity(value) and _valid_identity(expected)
            and value["size"] == expected["size"]
            and value["sha256"] == expected["sha256"])


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
    def floating(text):
        value = float(text)
        if not math.isfinite(value):
            raise ValueError("nonfinite metadata number")
        return value
    def constant(_):
        raise ValueError("nonfinite metadata constant")
    try:
        value = json.loads(raw, object_pairs_hook=pairs, parse_int=integer,
                           parse_float=floating, parse_constant=constant)
    except (UnicodeError, RecursionError) as error:
        raise ValueError("invalid metadata JSON") from error
    if type(value) is not dict:
        raise ValueError("metadata object required")
    return value


def _option_value(argv, option):
    if argv.count(option) != 1 or any(word.startswith(option + "=") for word in argv):
        return None
    index = argv.index(option)
    return argv[index + 1] if index + 1 < len(argv) else None


def _runtime_source(receipt):
    inputs = _mapping(_mapping(receipt.get("runtime")).get("inputs"))
    return {key: value for key, value in inputs.items()
            if key == "runtime-executable" or key.startswith("stdlib:")}


def _base_errors(receipt, target, version, recipe):
    runtime = _mapping(receipt.get("runtime"))
    abi = _mapping(runtime.get("abi"))
    version_parts = _mapping(abi.get("version"))
    errors = []
    if not (receipt.get("status") == "passed" and receipt.get("target") == target
            and _mapping(receipt.get("host")).get("target") == target
            and receipt.get("reference_kind") == "stock" and receipt.get("case") == recipe
            and runtime.get("target") == target and runtime.get("version") == version
            and runtime.get("provider") == "bundled" and runtime.get("implementation") == "cpython"
            and abi.get("language") == "python" and abi.get("gil") == "conventional"
            and abi.get("debug") is False
            and all(type(version_parts.get(k)) is int and version_parts[k] == v
                    for k, v in zip(("major", "minor", "patch"), map(int, version.split("."))))):
        errors.append("runtime/native target, version, provider, recipe or ABI identity differs")
    checks = _mapping(receipt.get("checks"))
    if any(_mapping(checks.get(name)).get("status") != "passed" for name in _REQUIRED_CHECKS):
        errors.append("required V02 execution/trace checks are incomplete")
    commit = receipt.get("commit")
    if type(commit) is not str or re.fullmatch("[0-9a-f]{40}", commit) is None:
        errors.append("exact source commit is missing")
    if not _valid_identity(receipt.get("launcher")):
        errors.append("included glue launcher identity is missing")
    runtime_inputs = _mapping(runtime.get("inputs"))
    if not _valid_identity(runtime_inputs.get("runtime-executable")):
        errors.append("runtime executable identity is missing")
    return errors


def wheel_inventory(raw):
    """Read bounded ordinary ZIP members, without executing or extracting them.

    This parser alone establishes no official provenance. The summary first
    requires the entire retained wheel's exact source-pinned SHA-256 and size.
    """
    if type(raw) is not bytes or not 0 < len(raw) <= MAX_WHEEL_BYTES:
        raise ValueError("bounded immutable wheel bytes required")
    result = {}
    folded = set()
    try:
        with zipfile.ZipFile(io.BytesIO(raw)) as archive:
            members = archive.infolist()
            if not 1 <= len(members) <= 10000 or sum(x.file_size for x in members) > MAX_WHEEL_CONTENTS:
                raise ValueError("wheel member count/decompressed byte bound")
            for member in members:
                name = member.filename
                path = PurePosixPath(name)
                canonical = str(path) + ("/" if member.is_dir() else "")
                key = unicodedata.normalize("NFD", name.rstrip("/")).casefold()
                if (name != canonical or path.is_absolute() or ".." in path.parts
                        or "\\" in name or "\0" in name or key in folded
                        or member.flag_bits & 1
                        or stat.S_IFMT(member.external_attr >> 16) not in (0, stat.S_IFREG, stat.S_IFDIR)):
                    raise ValueError("unsafe, duplicate or special wheel member")
                folded.add(key)
                if member.is_dir():
                    continue
                if member.file_size > MAX_WHEEL_CONTENTS:
                    raise ValueError("wheel member byte bound")
                data = archive.read(member)
                if len(data) != member.file_size:
                    raise ValueError("wheel member size differs")
                result[name] = _identity(data)
    except (zipfile.BadZipFile, RuntimeError, NotImplementedError, OSError) as error:
        raise ValueError("invalid wheel ZIP") from error
    return result


def _cryptography_members(raw, official):
    if not _identity_matches(_identity(raw), official):
        raise ValueError("retained cryptography wheel differs from official pin")
    members = wheel_inventory(raw)
    prefixes = ("cryptography/", "cryptography-50.0.2.dist-info/")
    if not members or any(not name.startswith(prefixes) for name in members):
        raise ValueError("cryptography wheel member namespace differs")
    native = {name: identity for name, identity in members.items()
              if name.endswith((".so", ".dylib", ".pyd"))}
    if set(native) != {"cryptography/hazmat/bindings/_rust.abi3.so"}:
        raise ValueError("cryptography stable-ABI native member differs")
    return members


def _wheel_receipt_errors(raw, tag, architecture, official):
    try:
        receipt = _json(raw)
    except (ValueError, TypeError) as error:
        return ["wheel provisioning receipt is invalid: " + str(error)]
    expected = {}
    for release, route in zip(PACKAGES, ("cryptography", "cffi-" + tag, "pycparser")):
        name, version = release.split("==")
        pin = official[route]
        expected[release] = {"release": release, "metadata": "https://pypi.org/pypi/" + name + "/" + version + "/json",
                             "filename": pin["name"], "url": pin["url"], "size": pin["size"], "sha256": pin["sha256"]}
    wheels = receipt.get("wheels")
    if not (receipt.get("test_only") is True and receipt.get("python") == tag
            and receipt.get("target") == ("linux-arm64" if architecture == "aarch64" else "linux-x86_64")
            and type(wheels) is list and len(wheels) == 3
            and all(type(row) is dict and set(row) == set(expected[PACKAGES[0]])
                    and type(row.get("release")) is str
                    and type(row.get("size")) is int for row in wheels)
            and {row.get("release") for row in wheels} == set(expected)
            and all(row == expected[row["release"]] for row in wheels)):
        return ["wheel provisioning choices do not match exact per-minor official pins"]
    return []


def _prepared_errors(cell, receipt, environment, inventory, evidence, version):
    errors = []
    minor = version.split(".")[1]
    native = cell.route != "patch"
    if not (_mapping(receipt.get("input_inventory")).get("path") == "input-inventory.json"
            and _identity_matches(receipt.get("input_inventory"), _identity(evidence.inventory))):
        errors.append("original input inventory identity differs")
    if not _identity_matches(inventory.get("environment-receipt.json"), _identity(evidence.environment)):
        errors.append("retained environment receipt differs from original input inventory")
    if not (environment.get("kind") == "ordinary" and environment.get("version") == [3, int(minor)]
            and type(environment.get("version")) is list
            and all(type(v) is int for v in environment["version"])
            and environment.get("pip_present") is True and environment.get("framework_input_prepared") is False):
        errors.append("prepared environment kind/version/seed identity differs")
    commands = _mapping(receipt.get("commands"))
    prepare = _mapping(commands.get("prepare"))
    argv = prepare.get("argv")
    if not (type(argv) is list and all(type(x) is str for x in argv)
            and len(argv) == (8 if native else 7)
            and argv[1].endswith("/fixtures/mvp/python-matrix/prepare.py")
            and argv[3:5] == ["bin/python3." + minor, "ordinary"]
            and argv.count("--native") == int(native)
            and argv.count("--receipt-output") == 1
            and prepare.get("executed") is True and prepare.get("timed_out") is False
            and type(prepare.get("exit")) is int and prepare["exit"] == 0):
        return errors + ["preparation command or completion differs"]
    try:
        cwd = PurePosixPath(prepare.get("cwd", ""))
        output = cwd.parent
        inputs = cwd / "build inputs"
        if not (cwd.is_absolute() and cwd.name == "work" and output.name == cell.label
                and argv[2] == str(inputs)
                and _option_value(argv, "--receipt-output") == str(output / "environment-receipt.json")
                and environment.get("runtime") == str(inputs / "runtime/bin" / ("python3." + minor))):
            errors.append("preparation does not bind its own case inputs")
    except (ValueError, TypeError):
        return errors + ["preparation paths are malformed"]
    build = _mapping(commands.get("build"))
    build_argv = build.get("argv")
    if not (type(build_argv) is list and len(build_argv) >= 4 and all(type(x) is str for x in build_argv)
            and build_argv[1:3] == ["build", "python"]
            and build.get("executed") is True and build.get("timed_out") is False
            and type(build.get("exit")) is int and build["exit"] == 0):
        return errors + ["build command or completion differs"]
    if not (build_argv[3] == str(inputs / "project")
            and _option_value(build_argv, "--env") == str(inputs / "environment")
            and _option_value(build_argv, "--entry") == "main.py"
            and _option_value(build_argv, "--output") == str(cwd / "built")
            and build_argv.count("--normalize-native-paths") == 1
            and not any(word in ("--module", "--console-script", "--runtime")
                        or word.startswith(("--module=", "--console-script=", "--runtime=", "--normalize-native-paths="))
                        for word in build_argv)):
        errors.append("build does not consume the selected prepared tree/file route")
    return errors


def _case_errors(cell, evidence, target, version, references, crypto_members):
    if type(evidence) is not CaseEvidence:
        return ["retained case metadata is missing"], {}
    try:
        receipt, environment, inventory = (_json(evidence.receipt), _json(evidence.environment), _json(evidence.inventory))
    except (ValueError, TypeError) as error:
        return ["retained case metadata is invalid: " + str(error)], {}
    errors = _base_errors(receipt, target, version, cell.recipe)
    errors.extend(_prepared_errors(cell, receipt, environment, inventory, evidence, version))
    reference = references.get("3.13.16" if cell.route == "patch" else version, {})
    if receipt.get("commit") != reference.get("commit"):
        errors.append("compatibility case and checked base source commits differ")
    if not _identity_matches(receipt.get("launcher"), _mapping(reference.get("launcher"))):
        errors.append("included glue launcher differs from checked base source")
    runtime_source = _runtime_source(receipt)
    reference_source = _runtime_source(reference)
    runtime_identity = _mapping(runtime_source.get("runtime-executable"))
    if cell.route == "patch":
        baseline_identity = _mapping(reference_source.get("runtime-executable"))
        if not (_valid_identity(runtime_identity) and _valid_identity(baseline_identity)
                and runtime_identity["sha256"] != baseline_identity["sha256"]):
            errors.append("different patch does not have a different runtime-executable digest")
    else:
        if not (runtime_source == reference_source and "runtime-executable" in runtime_source
                and any(key.startswith("stdlib:") for key in runtime_source)):
            errors.append("abi3 runtime/stdlib differs from checked base source")
        if not _identity_matches(inventory.get("project/main.py"), ABI3_PROJECT):
            errors.append("actual abi3 operation project source differs")
        installed = {name[len("installed/"):]: pin for name, pin in inventory.items()
                     if name.startswith(("installed/cryptography/", "installed/cryptography-50.0.2.dist-info/"))}
        if not crypto_members or installed != crypto_members:
            errors.append("original installed cryptography bytes differ from retained official wheel")
        prefix = "environment/lib/python" + ".".join(version.split(".")[:2]) + "/site-packages/"
        prepared = {name[len(prefix):]: pin for name, pin in inventory.items()
                    if name.startswith((prefix + "cryptography/", prefix + "cryptography-50.0.2.dist-info/"))}
        if prepared != crypto_members:
            errors.append("prepared cryptography members differ from original wheel")
        backend = {name: pin for name, pin in inventory.items() if name.startswith("installed/_cffi_backend.")}
        architecture = target.split("-")[0]
        expected_backend = "installed/_cffi_backend.cpython-" + ("313" if cell.route == "cp313" else "314") + "-" + architecture + "-linux-gnu.so"
        if (set(backend) != {expected_backend} or not _valid_identity(backend.get(expected_backend))
                or inventory.get(prefix + expected_backend[len("installed/"):]) != backend.get(expected_backend)):
            errors.append("cffi backend does not match its runtime minor/target or prepared copy")
        commands = _mapping(receipt.get("commands"))
        for name, raw in (("reference", evidence.reference_stdout), ("run", evidence.run_stdout)):
            stream = _mapping(_mapping(commands.get(name)).get("stdout"))
            try:
                if not (_identity_matches(stream, _identity(raw))
                        and _json(raw) == {"status": "abi3-ok", "cryptography": "50.0.2"}):
                    errors.append(name + " crypto operation result differs")
            except (ValueError, TypeError):
                errors.append(name + " crypto operation result is unavailable or malformed")
    return errors, receipt


def assess_refusal(architecture, evidence, reference_receipt):
    """Assess a separately executed native refusal; never execute its command.

    This does not establish a positive V02 case or alter the three-case status.
    Capture collection and before/after filesystem observations are the native
    runner's responsibility, and must be retained with its exact source head.
    """
    expected = refusal_plan(architecture)
    errors = []
    try:
        if type(evidence) is not RefusalEvidence:
            raise ValueError("retained refusal record, diagnostic and inventory bytes required")
        record = _json(evidence.record)
        reference = _json(reference_receipt)
        reference_errors = _base_errors(reference, expected["target"], "3.13.16", "python-source-normalized")
        if reference_errors:
            errors.append("checked base source is invalid: " + "; ".join(reference_errors))
        inventory = _json(evidence.inventory)
        diagnostic = _json(evidence.stderr)
        command = _mapping(record.get("command"))
        argv = command.get("argv")
        if not (record.get("target") == expected["target"]
                and record.get("runtime_version") == "3.13.16"
                and record.get("commit") == reference.get("commit")
                and _identity_matches(record.get("runtime_executable"),
                                      _mapping(_mapping(reference.get("runtime")).get("inputs")).get("runtime-executable"))
                and record.get("foreign_wheel") == expected["foreign_cffi_wheel"]
                and command.get("executed") is True and command.get("timed_out") is False
                and type(command.get("exit")) is int and command["exit"] == 1
                and _identity_matches(command.get("stderr"), _identity(evidence.stderr))
                and diagnostic.get("code") == "runtime_abi_mismatch"
                and type(argv) is list and all(type(word) is str for word in argv)
                and argv[1:3] == ["build", "python"]
                and _option_value(argv, "--python") == "3.13" and argv.count("--json") == 1
                and record.get("output_before") == {"kind": "absent"}
                and record.get("output_after") == {"kind": "absent"}):
            errors.append("wrong-ABI command, source wheel, diagnostic or absent-output observation differs")
        if not _identity_matches(record.get("input_inventory"), _identity(evidence.inventory)):
            errors.append("refusal input inventory bytes differ")
        backend = "_cffi_backend.cpython-314-" + architecture + "-linux-gnu.so"
        if not (_valid_identity(inventory.get("installed/" + backend))
                and inventory.get("environment/lib/python3.13/site-packages/" + backend) == inventory.get("installed/" + backend)
                and _identity_matches(inventory.get("runtime/bin/python3.13"), record.get("runtime_executable"))):
            errors.append("genuine foreign-minor input or selected interpreter identity is missing")
        if type(argv) is not list or not all(type(word) is str for word in argv):
            argv = []
        try:
            cwd = PurePosixPath(command.get("cwd", ""))
            output = cwd.parent
            inputs = cwd / "build inputs"
            if not (cwd.is_absolute() and cwd.name == "work" and output.name == "python-wrong-abi-refusal"
                    and len(argv) >= 4 and argv[3] == str(inputs / "project")
                    and _option_value(argv, "--env") == str(inputs / "environment")
                    and _option_value(argv, "--entry") == "main.py"
                    and not any(word in ("--runtime", "--module", "--console-script")
                                or word.startswith(("--runtime=", "--module=", "--console-script="))
                                for word in argv)
                    and _option_value(argv, "--output") == str(output / "rejected output")
                    and record.get("output_path") == str(output / "rejected output")
                    and record.get("sentinel_path") == str(output / "sibling sentinel")):
                errors.append("refusal command does not bind its own foreign environment/output/sibling sentinel")
        except (ValueError, TypeError):
            errors.append("refusal command paths are malformed")
        sentinel = record.get("sentinel_before")
        if not (type(sentinel) is dict and sentinel and all(_valid_identity(value) for value in sentinel.values())
                and record.get("sentinel_after") == sentinel):
            errors.append("unrelated sibling sentinel inventory was not preserved")
    except (ValueError, TypeError) as error:
        errors.append("retained refusal metadata is invalid: " + str(error))
    return {"status": "passed" if not errors else "failed", "errors": errors,
            "validation_basis": "Separate native runner observations; metadata assessment does not execute a refusal.",
            "native_execution_performed_by_summary": False}


def summarize(architecture, statuses, input_manifest, case_evidence, *, result,
              reference_receipts, wheel_receipts, patch_provenance,
              cryptography_wheel, finished_utc, refusal_evidence=None):
    plan = compatibility_plan(architecture)
    if type(result) is not int or not 0 <= result <= 255:
        raise ValueError("invalid compatibility runner result")
    official = plan["inputs"]
    errors = []
    if not (type(input_manifest) is dict and set(input_manifest) == set(official)
            and all(type(input_manifest[key]) is dict and set(input_manifest[key]) == set(official[key])
                    and type(input_manifest[key].get("size")) is int
                    and input_manifest[key] == official[key] for key in official)):
        errors.append("official patch/abi3 input identities or roster differ")
    expected = {cell.label for cell in cells_for(architecture)}
    if not (type(statuses) is list and len(statuses) == 3
            and all(type(row) is dict and set(row) == {"case", "exit"}
                    and type(row["case"]) is str and type(row["exit"]) is int
                    and 0 <= row["exit"] <= 255 for row in statuses)
            and {row["case"] for row in statuses} == expected):
        errors.append("patch/abi3 statuses are missing, duplicated, malformed or unexpected")
    elif any(row["exit"] != 0 for row in statuses):
        errors.append("one or more patch/abi3 executions failed")
    references = {}
    for version in ("3.13.16", "3.14.8"):
        try:
            reference = _json(_mapping(reference_receipts).get(version))
            failures = _base_errors(reference, plan["target"], version, "python-source-normalized")
            if failures:
                errors.append(version + " base source receipt is invalid: " + "; ".join(failures))
            references[version] = reference
        except (ValueError, TypeError) as error:
            errors.append(version + " base source receipt is unavailable: " + str(error))
    if references.get("3.13.16", {}).get("commit") != references.get("3.14.8", {}).get("commit"):
        errors.append("base source receipts do not share the same source commit")
    for tag in ("cp313", "cp314"):
        errors.extend(tag + ": " + error for error in _wheel_receipt_errors(
            _mapping(wheel_receipts).get(tag), tag, architecture, official))
    try:
        members = _cryptography_members(cryptography_wheel, official["cryptography"])
    except (ValueError, TypeError) as error:
        members = {}
        errors.append("retained abi3 wheel is invalid: " + str(error))
    receipts = {}
    cases = []
    for cell in cells_for(architecture):
        version = plan["runtime_versions"][cell.route]
        failures, receipt = _case_errors(cell, _mapping(case_evidence).get(cell.label),
                                        plan["target"], version, references, members)
        receipts[cell.route] = receipt
        cases.append({**asdict(cell), "runtime_version": version,
                      "status": "passed" if not failures else "failed", "errors": failures})
        errors.extend(cell.label + ": " + error for error in failures)
    try:
        provenance = _json(patch_provenance)
        patch_identity = _mapping(_mapping(receipts.get("patch", {}).get("runtime")).get("inputs")).get("runtime-executable")
        if not (set(provenance) == {"target", "version", "archive", "runtime_executable", "native_bytes_edited"}
                and provenance.get("target") == plan["target"] and provenance.get("version") == "3.13.15"
                and provenance.get("archive") == official["patch"]
                and type(_mapping(provenance.get("archive")).get("size")) is int
                and _identity_matches(provenance.get("runtime_executable"), _mapping(patch_identity))
                and provenance.get("native_bytes_edited") is False):
            errors.append("recorded patch archive/staged-interpreter provenance differs")
    except (ValueError, TypeError) as error:
        errors.append("recorded patch provisioning provenance is unavailable: " + str(error))
    refusal = ({"status": "unverified", "errors": ["separate actual native wrong-ABI refusal is required"]}
               if refusal_evidence is None else assess_refusal(architecture, refusal_evidence,
                   _mapping(reference_receipts).get("3.13.16")))
    passed = result == 0 and not errors
    return {
        "protocol": "glue-linux-python-patch-abi3-summary-v1",
        "status": "passed" if passed else "failed", "exit": result or (0 if passed else 1),
        "target": plan["target"], "expected_cases": 3, "cases": cases, "errors": errors,
        "inputs": input_manifest, "trace_policy": TRACE_POLICY, "finished_utc": finished_utc,
        "patch_pair": {"versions": ["3.13.15", "3.13.16"],
                       "status": "passed" if cases[0]["status"] == "passed" and not errors else "failed",
                       "provenance_scope": "Recorded official archive-to-staged-interpreter provenance; absent runtime archive is not rehashed."},
        "abi3_input_members": {"wheel": official["cryptography"], "member_count": len(members),
                              "native_members": {name: identity for name, identity in members.items() if name.endswith(".abi3.so")},
                              "scope": "Identical cryptography source wheel/member bytes across minors within this target; explicit native-path normalization remains declared separately."},
        "wrong_abi_refusal": refusal,
        "validation_basis": "Retained metadata and official abi3 wheel/member closure; runner must independently replay full V02 receipts/traces before recording zero status.",
        "full_m2_acceptance": False, "native_execution_performed_by_summary": False,
        "remaining_compatibility": ["macOS native routes and complete trace/signing gates"] +
            ([] if refusal["status"] == "passed" else ["separate actual native wrong-ABI prepublication refusal"]),
    }


def _read(path, limit=MAX_METADATA_BYTES):
    with path.open("rb") as stream:
        raw = stream.read(limit + 1)
    if len(raw) > limit:
        raise ValueError("evidence exceeds byte bound")
    return raw


def _read_or_missing(path, limit=MAX_METADATA_BYTES):
    try:
        return _read(path, limit)
    except OSError:
        return b""


def _statuses(path):
    try:
        return [{"case": name, "exit": int(code)} for name, code in
                (line.split("\t") for line in _read(path).decode().splitlines())]
    except (OSError, ValueError, UnicodeError):
        return None


def _stdout(root, receipt_raw, name):
    try:
        path = _mapping(_mapping(_mapping(_json(receipt_raw).get("commands")).get(name)).get("stdout")).get("path")
        if type(path) is not str or PurePosixPath(path).name != path or "\\" in path:
            return b""
        return _read_or_missing(root / path)
    except (ValueError, TypeError):
        return b""


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("command", choices=("inputs", "cells", "plan", "summary", "refusal-plan"))
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
        elif args.command in ("plan", "refusal-plan"):
            print(json.dumps(plan if args.command == "plan" else refusal_plan(args.architecture), indent=2))
        else:
            if args.evidence is None or args.result is None:
                raise ValueError("summary requires --evidence and --result")
            root = args.evidence
            try:
                manifest = _json(_read(root / "abi-inputs.json"))
            except (OSError, ValueError):
                manifest = None
            cases = {}
            for cell in cells_for(args.architecture):
                directory = root / "cases" / cell.label
                receipt = _read_or_missing(directory / "receipt.json")
                cases[cell.label] = CaseEvidence(receipt,
                    _read_or_missing(directory / "environment-receipt.json"),
                    _read_or_missing(directory / "input-inventory.json"),
                    _stdout(directory, receipt, "reference"), _stdout(directory, receipt, "run"))
            refusal_path = root / "abi-refusal.json"
            report = summarize(args.architecture, _statuses(root / "abi-case-status.tsv"), manifest, cases,
                result=args.result,
                reference_receipts={version: _read_or_missing(root / name) for version, name in plan["reference_receipts"].items()},
                wheel_receipts={tag: _read_or_missing(root / name) for tag, name in plan["wheel_receipts"].items()},
                patch_provenance=_read_or_missing(root / plan["patch_provenance"]),
                cryptography_wheel=_read_or_missing(root / plan["cryptography_wheel"], MAX_WHEEL_BYTES),
                refusal_evidence=RefusalEvidence(_read_or_missing(refusal_path),
                    _read_or_missing(root / "abi-refusal.stderr"),
                    _read_or_missing(root / "abi-refusal-input-inventory.json")) if refusal_path.is_file() else None,
                finished_utc=datetime.datetime.now(datetime.timezone.utc).isoformat())
            (root / "abi-summary.json").write_text(json.dumps(report, indent=2) + "\n")
            return 0 if report["status"] == "passed" else 1
        return 0
    except (OSError, ValueError, TypeError, KeyError, IndexError) as error:
        print("Linux patch/abi3 compatibility: " + str(error), file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
