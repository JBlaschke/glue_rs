#!/usr/bin/env python3
"""Measure declared distributions at one and many ranks; never infer missing cost data."""
from __future__ import annotations

import argparse
import concurrent.futures
import copy
import hashlib
import json
import math
import os
import platform
import signal
import shutil
import statistics
import subprocess
import threading
import time
from pathlib import Path

import harness


def host_identity(target):
    cpu = platform.processor() or platform.machine()
    boot = None
    if platform.system() == "Linux":
        try:
            fields = {line.split(":",1)[0].strip():line.split(":",1)[1].strip() for line in Path("/proc/cpuinfo").read_text().splitlines() if ":" in line}
            cpu = {key:fields[key] for key in ["model name","CPU implementer","CPU architecture","CPU variant","CPU part","CPU revision","Features"] if key in fields} or cpu
            boot = Path("/proc/sys/kernel/random/boot_id").read_text().strip()
        except OSError: pass
    elif platform.system() == "Darwin":
        result = subprocess.run(["/usr/sbin/sysctl","-n","kern.boottime"],capture_output=True,check=False)
        if result.returncode == 0: boot = result.stdout.decode().strip()
    facts = {"target": target, "kernel": platform.release(), "cpu": cpu, "cpu_count": os.cpu_count(), "libc": platform.libc_ver(), "host_boot_id":boot}
    return {**facts, "fingerprint": hashlib.sha256(json.dumps(facts, sort_keys=True).encode()).hexdigest()}


def payload_costs(root):
    files, directories, symlinks = [], [], []
    for path in root.rglob("*"):
        if path.is_symlink(): symlinks.append(path)
        elif path.is_file(): files.append(path)
        elif path.is_dir(): directories.append(path)
    report = json.loads((root / "build-report.json").read_text())
    return {
        "deployed_files": len(files), "deployed_directories": len(directories), "deployed_symlinks": len(symlinks),
        "deployed_bytes": sum(path.stat().st_size for path in files) + sum(len(os.readlink(path).encode()) for path in symlinks),
        "archive_bytes": (root / "app.glue").stat().st_size,
        "runtime_bytes": sum(path.stat().st_size for path in files if path.relative_to(root).parts[0] == "runtime"),
        "native_bytes": sum(path.stat().st_size for path in files if path.relative_to(root).parts[0] == "native"),
        "archived_uncompressed_bytes": report["sizes"]["archived_uncompressed_bytes"],
    }


def process_samples(pid):
    result = {"fds": None, "pss_bytes": None}
    if platform.system() == "Linux":
        try: result["fds"] = len(list(Path(f"/proc/{pid}/fd").iterdir()))
        except (OSError, PermissionError): pass
        try:
            for line in Path(f"/proc/{pid}/smaps_rollup").read_text().splitlines():
                if line.startswith("Pss:"): result["pss_bytes"] = int(line.split()[1]) * 1024
        except (OSError, PermissionError): pass
    return result


def compile_measurer(output):
    executable = output / "measure-process"
    source = Path(__file__).with_name("measure.c")
    argv = ["cc", "-O2", "-std=c11", "-Wall", "-Wextra", "-Werror", "-D_DARWIN_C_SOURCE", "-D_DEFAULT_SOURCE", str(source), "-o", str(executable)]
    result = subprocess.run(argv, capture_output=True, check=False)
    if result.returncode != 0: raise harness.HarnessError("measurement tool compilation failed: " + result.stderr.decode(errors="replace"))
    compiler = shutil.which("cc")
    version = subprocess.run([compiler, "--version"], capture_output=True, check=False) if compiler else None
    return executable, {"argv": argv, "compiler": {"path": compiler, "identity": harness.identity(Path(compiler)) if compiler else None, "version": version.stdout.decode(errors="replace").splitlines()[0] if version and version.stdout else None}, "source": harness.identity(source), "executable": harness.identity(executable), "method": "minimal native parent uses wait4; no Python fork RSS floor"}


def measure_ranks(argv, cwd, environment, output, ranks, expected, measurer, timeout=120):
    output.mkdir()
    def one(rank):
        stdout_path, stderr_path = output / f"rank-{rank}.stdout", output / f"rank-{rank}.stderr"
        metadata, pidfile = output / f"rank-{rank}.json", output / f"rank-{rank}.pid"
        with stdout_path.open("wb") as stdout, stderr_path.open("wb") as stderr:
            measured_argv = [str(measurer), str(metadata), str(pidfile), "65534" if os.geteuid() == 0 else "-1", *argv]
            child = subprocess.Popen(measured_argv, cwd=cwd, env=environment, stdin=subprocess.DEVNULL, stdout=stdout, stderr=stderr, start_new_session=True)
            done, timed_out, observations = threading.Event(), threading.Event(), []
            def sample():
                while not done.is_set():
                    try: observations.append(process_samples(int(pidfile.read_text())))
                    except (OSError, ValueError): pass
                    done.wait(0.005)
            def expire():
                timed_out.set()
                try: os.killpg(child.pid, signal.SIGKILL)
                except ProcessLookupError: pass
            observer = threading.Thread(target=sample, daemon=True)
            observer.start()
            timer = threading.Timer(timeout, expire); timer.daemon=True; timer.start()
            child.wait()
            timer.cancel()
            done.set(); observer.join()
        usage = json.loads(metadata.read_text()) if metadata.is_file() else {"exit": child.returncode, "elapsed_seconds": None, "user_seconds": None, "system_seconds": None, "peak_rss_bytes": None}
        stdout, stderr = harness.identity(stdout_path), harness.identity(stderr_path)
        fds = [sample["fds"] for sample in observations if sample["fds"] is not None]
        pss = [sample["pss_bytes"] for sample in observations if sample["pss_bytes"] is not None]
        return {"rank": rank, **usage, "timed_out": timed_out.is_set(), "measurement_complete": metadata.is_file(),
                "peak_observed_fds": max(fds) if fds else None,
                "peak_observed_pss_bytes": max(pss) if pss else None,
                "stdout": stdout, "stderr": stderr,
                "semantics_match": metadata.is_file() and not timed_out.is_set() and usage["exit"] == expected["exit"] and stdout["sha256"] == expected["stdout"]["sha256"] and stderr["sha256"] == expected["stderr"]["sha256"]}
    with concurrent.futures.ThreadPoolExecutor(max_workers=ranks) as workers:
        results = list(workers.map(one, range(ranks)))
    elapsed = [row["elapsed_seconds"] for row in results if row["elapsed_seconds"] is not None]
    rss = [row["peak_rss_bytes"] for row in results if row["peak_rss_bytes"] is not None]
    return {"ranks": ranks, "results": results, "elapsed_median_seconds": statistics.median(elapsed) if elapsed else None,
            "elapsed_max_seconds": max(elapsed) if elapsed else None,
            "peak_rss_max_bytes": max(rss) if rss else None,
            "semantics_match": all(row["semantics_match"] for row in results),
            "measurement": "native wait4 parent kernel rusage; PSS/FD values are sampled lower bounds"}


def comparison(base, scaled, entries):
    checks = {
        "source_entry_count": {"status": "passed" if entries >= 10_000 else "failed", "entries": entries},
        "deployment_file_scaling": {"status": "passed" if scaled["costs"]["deployed_files"] == base["costs"]["deployed_files"] else "failed",
                                    "delta": scaled["costs"]["deployed_files"] - base["costs"]["deployed_files"]},
        "native_bytes_scaling": {"status": "passed" if scaled["costs"]["native_bytes"] == base["costs"]["native_bytes"] else "failed"},
    }
    checks["runtime_bytes_scaling"] = {"status":"passed" if scaled["costs"].get("runtime_bytes",0)==base["costs"].get("runtime_bytes",0) else "failed"}
    if base.get("io") is not None and scaled.get("io") is not None:
        delta = scaled["io"]["stat"] - base["io"]["stat"]
        checks["metadata_scaling"] = {"status": "passed" if delta <= max(8, entries // 1000) else "failed", "delta": delta}
    else:
        checks["metadata_scaling"] = {"status": "unavailable", "reason": "complete startup trace is required for OS metadata counts"}
    for variant in [base, scaled]:
        for series in variant["measurements"]:
            checks[f"{variant['variant']}_{series['label']}_{series['ranks']}_semantics"] = {"status": "passed" if series["semantics_match"] else "failed"}
    return checks


def proposed_budget(report):
    if report.get("status") != "passed" or any(not measurement["semantics_match"] for variant in report["variants"] for measurement in variant["measurements"]):
        raise harness.HarnessError("cannot freeze budgets from failed/incomplete execution measurements")
    maximum = lambda key: max(measurement[key] for variant in report["variants"] for measurement in variant["measurements"])
    io = [variant["io"] for variant in report["variants"] if variant.get("io")]
    fds = [variant["fds"]["peak_per_process"] for variant in report["variants"] if variant.get("fds")]
    return {
        "revision": 1, "case": report["case"], "target": report["target"], "host_fingerprint": report["host"]["fingerprint"],
        "source_entries": report["source_entries"], "measured_artifacts": [{"archive":variant["artifact"],"launcher":variant.get("launcher"),"runtime_descriptor_sha256":hashlib.sha256(json.dumps(variant.get("runtime"),sort_keys=True).encode()).hexdigest(),"runtime_version":variant.get("runtime",{}).get("version")} for variant in report["variants"]],
        "completeness": report.get("status","not an acceptance report"),
        "limits": {
            "max_deployed_files": max(variant["costs"]["deployed_files"] for variant in report["variants"]),
            "max_deployment_file_delta": 0, "max_native_byte_delta": 0, "max_runtime_byte_delta":0, "max_metadata_call_delta": 10,
            **{f"max_{key}": math.ceil(max(variant["costs"].get(key,0) for variant in report["variants"]) * 1.1) for key in ["deployed_bytes","archive_bytes","runtime_bytes","native_bytes"]},
            "max_elapsed_seconds": math.ceil(maximum("elapsed_max_seconds") * 2000) / 1000,
            "max_peak_rss_bytes": math.ceil(maximum("peak_rss_max_bytes") * 1.25),
            "max_open_calls": max(row["open"] for row in io) + 8 if io else None,
            "max_stat_calls": max(row["stat"] for row in io) + 8 if io else None,
            "max_read_calls": math.ceil(max(row["read"] for row in io) * 1.25) + 8 if io else None,
            "max_seek_calls": max(row["seek"] for row in io)+8 if io and all("seek" in row for row in io) else None,
            "max_read_bytes": math.ceil(max(row["read_bytes"] for row in io)*1.1) if io and all("read_bytes" in row for row in io) else None,
            "max_process_fds": max(fds)+4 if fds else None,
        },
        "policy": "structure limits are fixed; time/RSS apply only to the measured host fingerprint; no universal timing claim",
    }


def check_budget(report, budget):
    errors = []
    if report.get("status") != "passed": errors.append("benchmark acceptance is incomplete or failed")
    if report["case"] != budget["case"] or report["target"] != budget["target"]: errors.append("budget case/target mismatch")
    if report["source_entries"] < budget["source_entries"]: errors.append("source scale workload is smaller than the frozen budget")
    limits = budget["limits"]
    base = next(variant for variant in report["variants"] if variant["variant"] == "baseline")
    scaled = next(variant for variant in report["variants"] if variant["variant"] == "scaled")
    if scaled["costs"]["deployed_files"] - base["costs"]["deployed_files"] > limits["max_deployment_file_delta"]: errors.append("source scaling added deployment files")
    if scaled["costs"]["native_bytes"] - base["costs"]["native_bytes"] > limits["max_native_byte_delta"]: errors.append("source scaling added native bytes")
    if scaled["costs"].get("runtime_bytes",0)-base["costs"].get("runtime_bytes",0)>limits.get("max_runtime_byte_delta",0): errors.append("source scaling added runtime bytes")
    for variant in report["variants"]:
        if variant.get("acceptance_status", "passed") != "passed" or any(not measurement["semantics_match"] for measurement in variant["measurements"]): errors.append("execution semantics/acceptance failed")
        if variant["costs"]["deployed_files"] > limits["max_deployed_files"]: errors.append("deployed file budget exceeded")
        for key in ["deployed_bytes","archive_bytes","runtime_bytes","native_bytes"]:
            if f"max_{key}" in limits and variant["costs"].get(key,0) > limits[f"max_{key}"]: errors.append(f"{key} budget exceeded")
        if limits.get("max_process_fds") is not None:
            if not variant.get("fds"): errors.append("descriptor measurement is missing")
            elif variant["fds"]["peak_per_process"] > limits["max_process_fds"]: errors.append("descriptor budget exceeded")
        if not variant.get("io") and any(limits.get(f"max_{key}_calls") is not None for key in ["open","stat","read","seek"]): errors.append("complete startup I/O measurements are missing")
        if variant.get("io"):
            for key in ["open", "stat", "read", "seek"]:
                limit = limits.get(f"max_{key}_calls")
                if limit is not None and key not in variant["io"]: errors.append(f"{key} syscall measurement missing")
                elif limit is not None and variant["io"][key] > limit: errors.append(f"{key} syscall budget exceeded")
        if limits.get("max_read_bytes") is not None:
            if not variant.get("io") or "read_bytes" not in variant["io"]: errors.append("read byte measurement missing")
            elif variant["io"]["read_bytes"]>limits["max_read_bytes"]: errors.append("read byte budget exceeded")
        if report["host"]["fingerprint"] == budget["host_fingerprint"]:
            for measurement in variant["measurements"]:
                if measurement["elapsed_max_seconds"] > limits["max_elapsed_seconds"]: errors.append("startup time budget exceeded")
                if measurement["peak_rss_max_bytes"] > limits["max_peak_rss_bytes"]: errors.append("RSS budget exceeded")
    if base.get("io") and scaled.get("io") and scaled["io"]["stat"] - base["io"]["stat"] > limits["max_metadata_call_delta"]: errors.append("source-entry metadata scaling budget exceeded")
    return errors


def run(recipe, target, output, repository, ranks, entries, cold_hook=None, empty_entry=None):
    if output.exists(): raise harness.HarnessError("benchmark output already exists")
    if harness.native_target() != target: raise harness.HarnessError("benchmark requires the selected native target")
    output.mkdir()
    measurer, measurement_tool = compile_measurer(output)
    report = {"revision": 1, "case": recipe["case"], "target": target, "host": host_identity(target), "source_entries": entries, "variants": [],
              "cold_cache": {"status": "uncontrolled", "reason": "fresh interpreter processes; OS/filesystem page cache is not called cold without an explicit hook"},
              "limitations": ["sampled PSS/FD peaks are lower bounds; null means unavailable, not zero", "compact native files still perform ordinary OS loader I/O", "complete trace costs cover one startup per variant; rank timings execute the same included distribution without tracing"]}
    report["measurement_tool"] = measurement_tool
    if empty_entry is None:
        build_argv = recipe["build"]["argv"]
        if "--entry" in build_argv: empty_entry = build_argv[build_argv.index("--entry")+1]
        elif recipe["case"].startswith("lua"): empty_entry = "main.lua"
    variants = [("empty-runtime",0)] if empty_entry else []
    variants += [("baseline",0),("scaled",entries)]
    for label, count in variants:
        selected = copy.deepcopy(recipe)
        if label == "empty-runtime": selected["empty_entry"] = "{inputs}/project/" + empty_entry
        if count:
            extension = "lua" if recipe["case"].startswith("lua") else "py" if recipe["case"].startswith("python") else "js" if recipe["case"].startswith("node") else "txt"
            selected["scale_sources"] = {"entries": count, "extension": extension, "directory": selected.get("scale_directory", "{inputs}/project/glue_scale_sources")}
        variant_output = output / label
        receipt = harness.execute(selected, target, variant_output, repository)
        payload = variant_output / "payload with spaces ü"
        if not payload.is_dir(): raise harness.HarnessError(f"{label} distribution build failed; see receipt")
        argv = receipt["commands"]["run"]["argv"]
        if receipt.get("trace", {}).get("backend") == "strace":
            executable = receipt["trace"]["executable"]
            argv = argv[argv.index(executable):]
        measurements = []
        for temperature in ["first", "warm"]:
            if temperature == "first" and cold_hook:
                result = subprocess.run(cold_hook, capture_output=True, check=False)
                report["cold_cache"] = {"status": "operator_hook_executed" if result.returncode == 0 else "failed", "argv": cold_hook, "exit": result.returncode,
                                        "stderr": result.stderr.decode(errors="replace"), "note": "the hook's cache guarantee must be documented by the operator"}
            for rank_count in ranks:
                measured = measure_ranks(argv, Path(receipt["commands"]["run"]["cwd"]), receipt["run_environment"], variant_output / f"{temperature}-{rank_count}", rank_count, receipt["commands"]["reference"], measurer, recipe.get("timeout",120))
                measured["label"] = temperature
                measurements.append(measured)
        trace = receipt["checks"].get("no_extraction", {})
        report["variants"].append({"variant": label, "artifact": receipt["artifact"], "launcher": receipt.get("launcher"), "commit": receipt.get("commit"), "runtime": receipt["runtime"], "costs": payload_costs(payload),
                                   "acceptance_status": receipt["status"], "io": trace.get("io"), "fds":trace.get("fds"), "measurements": measurements})
    base = next(variant for variant in report["variants"] if variant["variant"] == "baseline")
    scaled = next(variant for variant in report["variants"] if variant["variant"] == "scaled")
    report["checks"] = comparison(base, scaled, entries)
    for variant in report["variants"]:
        report["checks"][f"{variant['variant']}_relocated_acceptance"] = {"status": variant["acceptance_status"]}
    report["checks"]["empty_runtime"] = {"status": "passed" if empty_entry and all(measurement["semantics_match"] for measurement in report["variants"][0]["measurements"]) else "unavailable",
                                          "scope": "empty entry; supplied dependency closure preserved"}
    report["checks"]["rank_matrix"] = {"status": "passed" if {1,32}.issubset(ranks) else "failed", "ranks": ranks}
    report["status"] = "passed" if all(check["status"] == "passed" for check in report["checks"].values()) else "incomplete"
    (output / "benchmark.json").write_text(json.dumps(report, sort_keys=True, indent=2) + "\n")
    return report


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--case", required=True)
    parser.add_argument("--repository", type=Path, default=Path(__file__).resolve().parents[2], help="recipe-relative input source root")
    parser.add_argument("--target", choices=sorted(harness.TARGETS), required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--ranks", default="1,32")
    parser.add_argument("--source-entries", type=int, default=10000)
    parser.add_argument("--cold-hook", type=Path, help="JSON argv array for an explicit approved-host cache hook")
    parser.add_argument("--freeze-budget", type=Path, help="write a proposed numeric budget derived from this measured run")
    parser.add_argument("--budget", type=Path, help="check an already frozen budget")
    parser.add_argument("--empty-entry", help="project-relative entry for the empty runtime baseline (inferred from --entry when possible)")
    args = parser.parse_args(argv)
    repository = args.repository.resolve()
    cases = Path(os.environ.get("GLUE_MVP_CASES_DIR", repository / "fixtures/mvp/cases"))
    try:
        ranks = sorted({int(value) for value in args.ranks.split(",")})
        if not ranks or ranks[0] < 1 or ranks[-1] > 256: raise harness.HarnessError("rank counts must be 1..256")
        if not 1 <= args.source_entries <= 100000: raise harness.HarnessError("source entries must be 1..100000")
        recipe = json.loads((cases / f"{args.case}.json").read_text())
        cold_hook = json.loads(args.cold_hook.read_text()) if args.cold_hook else None
        if cold_hook is not None and (not isinstance(cold_hook,list) or not cold_hook or not all(isinstance(arg,str) for arg in cold_hook)):
            raise harness.HarnessError("cold hook must be a nonempty argv string array")
        report = run(recipe, args.target, args.output, repository, ranks, args.source_entries, cold_hook, args.empty_entry)
        if args.freeze_budget: args.freeze_budget.write_text(json.dumps(proposed_budget(report), sort_keys=True, indent=2)+"\n")
        if args.budget:
            errors = check_budget(report,json.loads(args.budget.read_text()))
            if errors: raise harness.HarnessError("; ".join(errors))
        print(f"{args.case}: {report['status']} ({args.output / 'benchmark.json'})")
        return 0 if report["status"] == "passed" else 1
    except (OSError, ValueError, KeyError, harness.HarnessError) as error:
        print(f"MVP benchmark: {error}")
        return 2


if __name__ == "__main__": raise SystemExit(main())
