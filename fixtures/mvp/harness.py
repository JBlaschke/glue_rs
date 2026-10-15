#!/usr/bin/env python3
"""Native target acceptance runner. Commands are argv arrays, never shell text."""
from __future__ import annotations

import argparse
import hashlib
import importlib.util
import json
import os
import platform
import re
import shutil
import signal
import socket
import stat
import subprocess
import sys
import time
from pathlib import Path

REVISION = 1
TARGETS = {"x86_64-unknown-linux-gnu", "aarch64-unknown-linux-gnu", "aarch64-apple-darwin"}
REQUIRED = {
    "native_target", "build_success", "runtime_reference", "input_bytes_preserved",
    "input_prefix_absent", "relocated", "payload_read_only", "payload_unchanged",
    "offline", "no_language_tools", "unrelated_cwd", "unusable_temp_cache",
    "exit_status", "stdout", "stderr", "execution_completed",
}


class HarnessError(Exception):
    pass


def extraction_module():
    spec = importlib.util.spec_from_file_location("glue_mvp_extraction", Path(__file__).with_name("extraction.py"))
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def identity(path: Path) -> dict:
    digest = hashlib.sha256()
    size = 0
    with path.open("rb") as stream:
        while block := stream.read(1024 * 1024):
            digest.update(block)
            size += len(block)
    return {"size": size, "sha256": digest.hexdigest()}


def inventory(root: Path) -> dict:
    result = {}
    for path in sorted(root.rglob("*")):
        relative = path.relative_to(root).as_posix()
        if path.is_symlink():
            target = os.readlink(path)
            if Path(target).is_absolute():
                raise HarnessError(f"absolute symlink cannot survive input-prefix removal: {relative}")
            if not path.resolve().is_relative_to(root.resolve()):
                raise HarnessError(f"input/payload symlink escapes root: {relative}")
            result[relative] = {"symlink": target}
        elif path.is_file():
            result[relative] = identity(path)
        elif not path.is_dir():
            raise HarnessError(f"unsupported input/payload file: {relative}")
        if len(result) > 1_000_000:
            raise HarnessError("input/payload inventory exceeds one million files")
    return result


def native_target() -> str:
    arch = {"arm64": "aarch64", "aarch64": "aarch64", "x86_64": "x86_64", "AMD64": "x86_64"}.get(platform.machine())
    if platform.system() == "Darwin":
        target = f"{arch}-apple-darwin"
    elif platform.system() == "Linux":
        libc = platform.libc_ver()[0]
        if libc != "glibc":
            raise HarnessError(f"GNU Linux cell requires glibc, observed {libc!r}")
        target = f"{arch}-unknown-linux-gnu"
    else:
        raise HarnessError("MVP execution requires native Linux or macOS")
    if target not in TARGETS:
        raise HarnessError(f"native execution cell {target} is not an MVP target")
    return target


def expand(value: str, context: dict[str, str]) -> str:
    def environment(match):
        name = match[1]
        if name not in os.environ:
            raise HarnessError(f"case needs build input environment variable {name}")
        return os.environ[name]
    value = re.sub(r"\$\{([A-Z][A-Z0-9_]*)\}", environment, value)
    for key, replacement in context.items():
        value = value.replace("{" + key + "}", replacement)
    if re.search(r"\{[a-z_]+\}", value):
        raise HarnessError(f"unresolved case template: {value}")
    if "\0" in value:
        raise HarnessError("NUL is not valid in argv/environment")
    return value


def command(spec: dict, context: dict) -> tuple[list[str], Path, dict]:
    if not isinstance(spec.get("argv"), list) or not spec["argv"] or not all(isinstance(a, str) for a in spec["argv"]):
        raise HarnessError("case commands require a nonempty argv string array")
    argv = [expand(a, context) for a in spec["argv"]]
    cwd = Path(expand(spec.get("cwd", "{work}"), context))
    environment = os.environ.copy()
    environment.update({key: expand(value, context) for key, value in spec.get("environment", {}).items()})
    environment.update({"PYTHONDONTWRITEBYTECODE": "1", "NODE_DISABLE_COMPILE_CACHE": "1"})
    return argv, cwd, environment


def run_command(name: str, argv: list[str], cwd: Path, environment: dict, output: Path, timeout: int, *, drop_root=False) -> dict:
    stdout_path, stderr_path = output / f"{name}.stdout", output / f"{name}.stderr"
    started = time.time()
    def demote():
        os.setgroups([])
        os.setgid(65534)
        os.setuid(65534)
    with stdout_path.open("wb") as stdout, stderr_path.open("wb") as stderr:
        child = subprocess.Popen(argv, cwd=cwd, env=environment, stdin=subprocess.DEVNULL, stdout=stdout, stderr=stderr,
                                 start_new_session=True, preexec_fn=demote if drop_root and os.geteuid() == 0 else None)
        timed_out = False
        try:
            code = child.wait(timeout=timeout)
        except subprocess.TimeoutExpired:
            timed_out = True
            os.killpg(child.pid, signal.SIGKILL)
            code = child.wait()
    return {"argv": argv, "cwd": str(cwd), "started": started, "finished": time.time(), "exit": code,
            "timed_out": timed_out, "stdout": {"path": stdout_path.name, **identity(stdout_path)},
            "stderr": {"path": stderr_path.name, **identity(stderr_path)}, "executed": True}


def offline_policy(quarantine: Path) -> tuple[list[str], dict]:
    if platform.system() == "Darwin" and Path("/usr/bin/sandbox-exec").is_file():
        quoted = str(quarantine).replace("\\", "\\\\").replace('"', '\\"')
        profile = f'(version 1)(allow default)(deny network*)(deny file-read* (subpath "{quoted}"))'
        probe = subprocess.run(["/usr/bin/sandbox-exec", "-p", profile, "/usr/bin/true"], capture_output=True, check=False)
        if probe.returncode == 0:
            return ["/usr/bin/sandbox-exec", "-p", profile], {"status": "passed", "mechanism": "macOS sandbox denies network and quarantined input reads"}
        return [], {"status": "unavailable", "reason": probe.stderr.decode(errors="replace")}
    if platform.system() == "Linux":
        # sysfs may still be mounted for the parent namespace after unshare --net.
        # if_nameindex queries the calling thread's active network namespace.
        try:
            interfaces = sorted(name for _, name in socket.if_nameindex())
            namespace = os.readlink("/proc/self/ns/net")
        except (OSError, AttributeError) as error:
            return [], {"status": "unavailable", "reason": f"cannot inspect active network namespace: {error}"}
        if interfaces == ["lo"]:
            return [], {"status": "passed", "mechanism": "native network namespace has loopback only", "interfaces": interfaces,
                        "namespace": namespace}
        return [], {"status": "unavailable", "reason": "run target cell in a --network none container/namespace with its loopback interface present", "interfaces": interfaces, "namespace": namespace}
    return [], {"status": "unavailable", "reason": "no enforced offline mechanism available"}


def make_read_only(root: Path):
    for path in sorted(root.rglob("*"), reverse=True):
        if not path.is_symlink():
            path.chmod(stat.S_IMODE(path.stat().st_mode) & ~0o222)
    root.chmod(stat.S_IMODE(root.stat().st_mode) & ~0o222)


def check(receipt_path: Path) -> list[str]:
    receipt = json.loads(receipt_path.read_text())
    errors = []
    if receipt.get("revision") != REVISION:
        errors.append("unsupported receipt revision")
    if receipt.get("target") not in TARGETS or receipt.get("host", {}).get("target") != receipt.get("target"):
        errors.append("receipt does not prove requested native target execution")
    checks = receipt.get("checks", {})
    for name in sorted(REQUIRED | set(receipt.get("required_checks", []))):
        if checks.get(name, {}).get("status") != "passed":
            errors.append(f"{name}: {checks.get(name, {}).get('status', 'missing')}")
    for name in ["build", "reference", "run"]:
        result = receipt.get("commands", {}).get(name, {})
        if not result.get("executed") or result.get("timed_out") or not isinstance(result.get("exit"), int):
            errors.append(f"{name} did not complete")
        if not 0 < result.get("started", 0) <= result.get("finished", 0):
            errors.append(f"{name} execution timestamps are absent/invalid")
        for stream in ["stdout", "stderr"]:
            evidence = result.get(stream, {})
            relative = evidence.get("path", "")
            path = receipt_path.parent / relative
            if not relative or not path.resolve().is_relative_to(receipt_path.parent.resolve()) or not path.is_file():
                errors.append(f"{name} {stream} evidence is missing/escaped")
            elif identity(path) != {key: evidence.get(key) for key in ["size", "sha256"]}:
                errors.append(f"{name} {stream} evidence changed")
    if receipt.get("reference_kind") != "stock":
        errors.append("stock reference runtime comparison is missing")
    runtime = receipt.get("runtime", {})
    if runtime.get("provider") != "bundled" or runtime.get("target") != receipt.get("target") or not runtime.get("version"):
        errors.append("exact bundled runtime identity/target is missing")
    for name in ["input_inventory", "artifact_inventory"]:
        evidence = receipt.get(name, {})
        path = receipt_path.parent / evidence.get("path", "")
        if not path.is_file() or not path.resolve().is_relative_to(receipt_path.parent.resolve()):
            errors.append(f"{name} evidence is missing/escaped")
        elif identity(path) != {key: evidence.get(key) for key in ["size", "sha256"]}:
            errors.append(f"{name} evidence changed")
    if "no_extraction" in receipt.get("required_checks", []):
        trace = receipt.get("trace", {})
        if trace.get("backend") == "strace":
            try:
                extraction_module().check_trace(receipt_path.parent / trace["prefix"], Path(trace["cwd"]), trace.get("allowed_outputs", []), trace.get("sinks", []), trace.get("executable"))
            except (ValueError, OSError, KeyError) as error:
                errors.append(f"raw extraction trace rejected: {error}")
            for relative, recorded in {**trace.get("evidence", {}), **receipt.get("trace_oracle_evidence", {})}.items():
                path = receipt_path.parent / relative
                if not path.resolve().is_relative_to(receipt_path.parent.resolve()) or not path.is_file() or identity(path) != recorded:
                    errors.append(f"raw trace evidence changed/missing: {relative}")
        else:
            errors.append("complete extraction trace backend/evidence is unavailable")
    return errors


def execute(recipe: dict, target: str, output: Path, repository: Path) -> dict:
    if output.exists():
        raise HarnessError(f"output already exists: {output}")
    observed = native_target()
    if target != observed:
        raise HarnessError(f"refuse foreign execution target {target}; native host is {observed}")
    output.mkdir(parents=False)
    output = output.resolve()
    work = output / "work"
    inputs, built = work / "build inputs", work / "built"
    inputs.mkdir(parents=True)
    payload, quarantine = output / "payload with spaces ü", output / "inaccessible original inputs"
    unrelated = output / "unrelated cwd"
    unrelated.mkdir()
    context = {"repo": str(repository), "work": str(work), "inputs": str(inputs), "build": str(built), "payload": str(payload), "output": str(output), "target": target}
    receipt = {"revision": REVISION, "case": recipe.get("case"), "target": target, "host": {"target": observed,
               "system": platform.platform(), "kernel": platform.release(), "libc": platform.libc_ver(), "python": platform.python_version()},
               "commands": {}, "checks": {}, "reference_kind": recipe.get("reference_kind"),
               "required_checks": sorted(REQUIRED | set(recipe.get("required_checks", [])))}
    checks, commands = receipt["checks"], receipt["commands"]
    trace_requested = recipe.get("trace") == "required" or os.environ.get("GLUE_MVP_TRACE") == "required"
    if trace_requested:
        receipt["required_checks"] = sorted(set(receipt["required_checks"]) | {"trace_complete", "no_extraction", "trace_oracle", "signing_policy"})
    def status(name, passed, **details): checks[name] = {"status": "passed" if passed else "failed", **details}
    status("native_target", True)
    try:
        receipt["commit"] = subprocess.check_output(["git", "rev-parse", "HEAD"], cwd=repository, text=True, stderr=subprocess.DEVNULL).strip()
    except (subprocess.SubprocessError, OSError):
        receipt["commit"] = os.environ.get("GLUE_MVP_COMMIT", "unavailable")
    try:
        for item in recipe.get("inputs", []):
            source = Path(expand(item["source"], context))
            if not source.is_absolute(): source = repository / source
            destination = inputs / item["destination"]
            if not destination.resolve().is_relative_to(inputs.resolve()): raise HarnessError("input destination escapes build prefix")
            if source.is_dir():
                inventory(source)  # reject escapes before copying any linked bytes
                shutil.copytree(source, destination, symlinks=True)
            else:
                destination.parent.mkdir(parents=True, exist_ok=True)
                shutil.copy2(source, destination)
        if "prepare" in recipe:
            argv, cwd, env = command(recipe["prepare"], context)
            commands["prepare"] = run_command("prepare", argv, cwd, env, output, recipe.get("timeout", 120))
            if commands["prepare"]["exit"] != 0: raise HarnessError("fixture preparation failed")
        if "scale_sources" in recipe:
            scale = recipe["scale_sources"]
            count = scale.get("entries")
            if not isinstance(count, int) or not 1 <= count <= 100_000:
                raise HarnessError("source scaling needs 1..100000 entries")
            directory = Path(expand(scale.get("directory", "{inputs}/project/glue_scale_sources"), context))
            if not directory.resolve().is_relative_to(inputs.resolve()):
                raise HarnessError("generated scale sources must stay in build inputs")
            extension = scale.get("extension", "txt")
            content = {"lua": b"return 0\n", "py": b"value = 0\n", "js": b"module.exports = 0;\n", "txt": b"archived scale resource\n"}.get(extension)
            if content is None: raise HarnessError("unsupported scale source extension")
            directory.mkdir(parents=True)
            for index in range(count):
                (directory / f"unused_{index:05d}.{extension}").write_bytes(content)
            receipt["generated_sources"] = {"entries": count, "bytes": count * len(content), "extension": extension}
        if "empty_entry" in recipe:
            path = Path(expand(recipe["empty_entry"], context))
            if not path.resolve().is_relative_to(inputs.resolve()) or not path.is_file():
                raise HarnessError("empty-runtime entry must be an existing source inside build inputs")
            if path.suffix == ".lua": content = b"return\n"
            elif path.suffix == ".py": content = b"pass\n"
            elif path.suffix in {".js", ".cjs", ".mjs"}: content = b"\n"
            else: raise HarnessError("empty-runtime entry needs a supported source extension")
            path.write_bytes(content)
            receipt["empty_runtime_scope"] = "empty entry; selected input dependency closure preserved"
        before = inventory(inputs)
        (output / "input-inventory.json").write_text(json.dumps(before, sort_keys=True, indent=2) + "\n")
        receipt["input_inventory"] = {"path": "input-inventory.json", **identity(output / "input-inventory.json")}
        argv, cwd, env = command(recipe["build"], context)
        commands["build"] = run_command("build", argv, cwd, env, output, recipe.get("timeout", 120))
        status("build_success", commands["build"]["exit"] == 0 and built.is_dir())
        status("input_bytes_preserved", before == inventory(inputs))
        if checks["build_success"]["status"] != "passed": raise HarnessError("distribution build failed")
        argv, cwd, env = command(recipe["reference"], context)
        commands["reference"] = run_command("reference", argv, cwd, env, output, recipe.get("timeout", 120))
        status("runtime_reference", commands["reference"]["executed"] and not commands["reference"]["timed_out"] and recipe.get("reference_kind") == "stock")
        built.rename(payload)
        inputs.rename(quarantine)
        shutil.rmtree(quarantine)
        receipt["input_copy_disposal"] = "copied inputs deleted after byte-preservation and stock-reference checks, before included execution"
        status("relocated", payload.is_dir() and not built.exists(), path=str(payload))
        status("input_prefix_absent", not inputs.exists() and not quarantine.exists(), original_prefix=str(inputs), copied_alias_absent=not quarantine.exists())
        make_read_only(payload)
        status("payload_read_only", all(path.is_symlink() or path.stat().st_mode & 0o222 == 0 for path in [payload, *payload.rglob("*")]))
        payload_before = inventory(payload)
        report = json.loads((payload / "build-report.json").read_text())
        receipt["runtime"] = report["runtime"]
        receipt["artifact"] = {"path": str((payload / "app.glue").relative_to(output)), **identity(payload / "app.glue")}
        receipt["launcher"] = {"path": str((payload / "glue").relative_to(output)), **identity(payload / "glue")}
        (output / "payload-inventory.json").write_text(json.dumps(payload_before, sort_keys=True, indent=2) + "\n")
        receipt["artifact_inventory"] = {"path": "payload-inventory.json", **identity(output / "payload-inventory.json")}
        wrapper, checks["offline"] = offline_policy(quarantine)
        argv, _, _ = command(recipe.get("run", {"argv": ["{payload}/glue", "run", "{payload}/app.glue", "--", *recipe.get("arguments", [])]}), context)
        if Path(argv[0]).resolve() != (payload / "glue").resolve(): raise HarnessError("acceptance must execute the included distribution launcher")
        denied = []
        for name in ["home", "temp", "cache"]:
            path = output / f"unusable-{name}"
            # Regular files guarantee ENOTDIR even for root. Mode-zero directories
            # cannot be reliably inspected through some rootless VM mounts.
            path.write_bytes(b"")
            path.chmod(0o444)
            denied.append(str(path))
        environment = {"PATH": "/glue-no-language-tools", "HOME": denied[0], "TMPDIR": denied[1], "TMP": denied[1], "TEMP": denied[1], "XDG_CACHE_HOME": denied[2], "PYTHONDONTWRITEBYTECODE": "1", "NODE_DISABLE_COMPILE_CACHE": "1", "NODE_PATH": "", "LANG": "C.UTF-8"}
        protected_environment = {key: environment[key] for key in ["PATH", "HOME", "TMPDIR", "TMP", "TEMP", "XDG_CACHE_HOME"]}
        environment.update({key: expand(value, context) for key, value in recipe.get("run_environment", {}).items()})
        if any(environment[key] != value for key, value in protected_environment.items()):
            raise HarnessError("run environment must preserve no-tools PATH and unusable HOME/temp/cache")
        receipt["run_environment"] = environment
        status("no_language_tools", not Path(environment["PATH"]).exists())
        status("unrelated_cwd", unrelated != payload and not unrelated.is_relative_to(payload))
        status("unusable_temp_cache", all(Path(path).is_file() and Path(path).stat().st_mode & 0o222 == 0 for path in denied))
        trace_argv, trace_prefix = [], None
        if trace_requested:
            extraction = extraction_module()
            if platform.system() == "Linux":
                trace_argv, trace_prefix, available = extraction.trace_prefix(output, 65534)
                receipt["trace"] = {"backend": "strace", "prefix": str(trace_prefix.relative_to(output)) if trace_prefix else "", "cwd": str(unrelated), "executable": argv[0], "sinks": [str(output / "run.stdout"), str(output / "run.stderr")], "allowed_outputs": []}
                checks["trace_complete"] = available
                checks["signing_policy"] = {"status": "passed", "reason": "macOS signing gate does not apply to Linux"}
            else:
                checks["trace_complete"] = {"status": "unavailable", "reason": "full native macOS descendant tracing requires an approved DTrace/dtruss host"}
                checks["signing_policy"] = extraction.verify_macos(payload, recipe.get("signing_policy", os.environ.get("GLUE_MVP_SIGNING_POLICY", "unconfigured")))
            for value in recipe.get("application_outputs", []):
                path = Path(expand(value, context))
                if not path.is_relative_to(output / "application-output"):
                    raise HarnessError("legitimate application outputs must stay under {output}/application-output")
                path.mkdir(parents=True, exist_ok=True)
                if os.geteuid() == 0: path.chmod(0o777)
                if trace_prefix: receipt["trace"]["allowed_outputs"].append(str(path))
        commands["run"] = run_command("run", trace_argv + wrapper + argv, unrelated, environment, output, recipe.get("timeout", 120), drop_root=True)
        status("execution_completed", not commands["run"]["timed_out"])
        status("payload_unchanged", payload_before == inventory(payload), note="snapshot comparison alone does not prove no extraction")
        expected = recipe.get("expected_exit", 0)
        status("exit_status", commands["run"]["exit"] == commands["reference"]["exit"] == expected)
        for stream in ["stdout", "stderr"]:
            status(stream, commands["run"][stream]["sha256"] == commands["reference"][stream]["sha256"])
        if trace_requested:
            if trace_prefix:
                try:
                    analysis = extraction.check_trace(trace_prefix, unrelated, receipt["trace"]["allowed_outputs"], receipt["trace"]["sinks"], argv[0])
                    checks["trace_complete"] = {"status": "passed", "processes": analysis["processes"]}
                    checks["no_extraction"] = analysis
                except extraction.TraceError as error:
                    checks["trace_complete"] = {"status": "failed", "reason": str(error)}
                    checks["no_extraction"] = {"status": "failed", "reason": str(error)}
                receipt["trace"]["evidence"] = {str(path.relative_to(output)): identity(path) for path in sorted(trace_prefix.parent.glob(trace_prefix.name + ".*"))}
                checks["trace_oracle"] = extraction.oracle_self_test(output / "trace-controls")
                receipt["trace_oracle_evidence"] = {str(path.relative_to(output)): identity(path) for path in sorted((output / "trace-controls").rglob("syscalls.*"))}
            else:
                checks["no_extraction"] = {"status": "unavailable", "reason": checks["trace_complete"].get("reason", "trace unavailable")}
                checks["trace_oracle"] = {"status": "unavailable", "reason": "cannot inject controls without a complete native tracer"}
    except (HarnessError, OSError, KeyError, ValueError) as error:
        receipt["error"] = str(error)
    (output / "receipt.json").write_text(json.dumps(receipt, sort_keys=True, indent=2) + "\n")
    receipt["status"] = "passed" if not check(output / "receipt.json") else "failed"
    (output / "receipt.json").write_text(json.dumps(receipt, sort_keys=True, indent=2) + "\n")
    return receipt


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--case", required=True)
    parser.add_argument("--target", choices=sorted(TARGETS), required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args(argv)
    if not re.fullmatch(r"[a-z0-9][a-z0-9-]{0,80}", args.case): parser.error("invalid case name")
    repository = Path(__file__).resolve().parents[2]
    cases = Path(os.environ.get("GLUE_MVP_CASES_DIR", repository / "fixtures/mvp/cases"))
    try:
        recipe = json.loads((cases / f"{args.case}.json").read_text())
        if "extends" in recipe:
            parent_name = expand(recipe["extends"], {})
            if not re.fullmatch(r"[a-z0-9][a-z0-9-]{0,80}", parent_name): raise HarnessError("invalid base case name")
            parent = json.loads((cases / f"{parent_name}.json").read_text())
            if "extends" in parent: raise HarnessError("nested case inheritance is unsupported")
            recipe = {**parent, **recipe, "base_case": parent_name}
        if recipe.get("revision") != REVISION or recipe.get("case") != args.case: raise HarnessError("case recipe identity/revision mismatch")
        receipt = execute(recipe, args.target, args.output, repository)
        print(f"{args.case}: {receipt['status']} ({args.output / 'receipt.json'})")
        return 0 if receipt["status"] == "passed" else 1
    except (HarnessError, OSError, ValueError) as error:
        print(f"MVP harness: {error}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
