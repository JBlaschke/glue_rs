#!/usr/bin/env python3
"""Isolated replay of both immutable historical native fixture corpora."""
import hashlib
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import time

REPO = Path(__file__).resolve().parents[2]
OUT = Path(__file__).resolve().parent
IMAGE = "62812c4a0e15bc750ddd6ec68d2a19f8815a14b60d520e201a911e2e29f40abe"
NEW = REPO / "target/python-native-packages-development-build"
PROBE = NEW / "relocated Python native packages/glue-python-bootstrap-probe"
OLD = REPO / "target/python-extensions-final-build"
LIFE = REPO / "target/python-native-lifecycle-clean-final-build"
CELLS = ["bundled-archived", "bundled-host", "host-archived", "host-host"]
MODES = CELLS + [s + "-app-error" for s in CELLS] + ["corrupt-native", "missing-host-image", "wrong-host-image"]
COMMANDS = []

def identity(path):
    path = Path(path)
    h = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            h.update(chunk)
    return {"path": str(path.relative_to(REPO)), "size": path.stat().st_size, "sha256": h.hexdigest()}

def write(path, value):
    path.write_text(json.dumps(value, indent=2, sort_keys=True) + "\n")

def command(argv, directory, name, required=True):
    print(name, flush=True)
    result = subprocess.run(argv, cwd=REPO, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    (directory / (name + ".stdout.txt")).write_bytes(result.stdout)
    (directory / (name + ".stderr.txt")).write_bytes(result.stderr)
    receipt = {"argv": [str(v) for v in argv], "exit_status": result.returncode}
    write(directory / (name + ".command.json"), receipt)
    COMMANDS.append(receipt)
    write(OUT / "commands.json", COMMANDS)
    if required and result.returncode != 0:
        raise RuntimeError(name + " failed: " + result.stderr.decode(errors="replace")[-2000:])
    return result

sources = sorted((REPO / "crates/glue-runtime-python/src").rglob("*.rs"))
sources += [REPO / p for p in ["crates/glue-runtime-python/Cargo.toml", "crates/glue-runtime-python/build.rs", "crates/glue-runtime-python/boundary/bridge.c", "crates/glue-runtime-python/boundary/bridge.h"]]
historical_paths = [OLD / "runtime-commands.sh", OLD / "relocated Python extensions/glue-python-bootstrap-probe", LIFE / "relocated Python native lifecycle/glue-python-bootstrap-probe", REPO / "target/python-native-lifecycle-clean-final/commands.sh", REPO / "target/python-native-lifecycle-clean-final/native-metadata.json", REPO / "docs/evidence/pbs-linux-arm64-python-extensions-2026-10-10/native-metadata.json", REPO / "scripts/check-linux-python-native-lifecycle-trace.py", REPO / "scripts/check-linux-python-extension-trace.py"]
bindings = {"schema_version": 0, "scope": "Current native-package development probe against original registered and lifecycle runtime inputs and unchanged historical policies; only private disposable-volume copies are modified.", "git_revision": subprocess.check_output(["git", "rev-parse", "HEAD"], cwd=REPO, text=True).strip(), "git_tracked_status": subprocess.check_output(["git", "status", "--short", "--untracked-files=no"], cwd=REPO, text=True), "linux_image": IMAGE, "replacement_probe": identity(PROBE), "runtime_sources": [identity(p) for p in sources], "historical_inputs": [identity(p) for p in historical_paths]}
write(OUT / "source-and-launcher-bindings.json", bindings)
subprocess.run(["git", "diff", "--quiet", "HEAD", "--", "fixtures/python-native-lifecycle", "fixtures/python-extensions", "scripts/check-linux-python-native-lifecycle-trace.py", "scripts/check-linux-python-extension-trace.py"], cwd=REPO, check=True)

summaries = []
for family in ["lifecycle", "registered"]:
    evidence = OUT / family
    evidence.mkdir()
    evidence.chmod(0o777)
    volume = "glue-native-packages-historical-" + family + "-" + str(time.time_ns())
    (evidence / "volume-name.txt").write_text(volume + "\n")
    expected = {}
    def include_tree(path, virtual):
        for entry in sorted(path.rglob("*")):
            if entry.is_symlink():
                raise RuntimeError("historical symlink outside admitted regular corpus: " + str(entry))
            if entry.is_file():
                expected[virtual + "/" + entry.relative_to(path).as_posix()] = identity(entry)["sha256"]
    include_tree(OLD / "host Python imports", "/build-target/host Python imports")
    if family == "registered":
        for name in ["host Python extensions", "host Python extensions missing-host-image", "host Python extensions wrong-host-image"]:
            include_tree(OLD / name, "/build-target/" + name)
        relocated = "relocated Python extensions"
        frames = OLD / relocated
        script = OLD / "runtime-commands.sh"
        metadata = REPO / "docs/evidence/pbs-linux-arm64-python-extensions-2026-10-10/native-metadata.json"
        checker = REPO / "scripts/check-linux-python-extension-trace.py"
        setup = 'set -eu; for name in "runtime-commands.sh" "runtime-empty" "relocated Python extensions" "host Python imports" "host Python extensions" "host Python extensions missing-host-image" "host Python extensions wrong-host-image"; do cp -a "/cached/$name" /build-target/; done; rm "/build-target/relocated Python extensions/glue-python-bootstrap-probe"; cp "/new-build/relocated Python native packages/glue-python-bootstrap-probe" "/build-target/relocated Python extensions/glue-python-bootstrap-probe"; chmod 0555 "/build-target/relocated Python extensions/glue-python-bootstrap-probe"; '
    else:
        relocated = "relocated Python native lifecycle"
        frames = LIFE / relocated
        script = REPO / "target/python-native-lifecycle-clean-final/commands.sh"
        metadata = REPO / "target/python-native-lifecycle-clean-final/native-metadata.json"
        checker = REPO / "scripts/check-linux-python-native-lifecycle-trace.py"
        for suffix in ["", " missing-host-image", " wrong-host-image"]:
            native = "/build-target/host Python native lifecycle" + suffix
            for file in sorted((LIFE / "native-images").glob("*.so")):
                if suffix == " missing-host-image" and file.name == "libglue_python_lifecycle.so":
                    continue
                raw = file.read_bytes()
                if suffix == " wrong-host-image" and file.name == "glue_native_lifecycle.so":
                    raw = bytes([raw[0] ^ 1]) + raw[1:]
                expected[native + "/" + file.name] = hashlib.sha256(raw).hexdigest()
        setup = 'set -eu; cp -a "/cached/host Python imports" /build-target/; mkdir "/build-target/runtime-empty" "/build-target/relocated Python native lifecycle"; cp /lifecycle/relocated\\ Python\\ native\\ lifecycle/*.glue "/build-target/relocated Python native lifecycle/"; cp /lifecycle-evidence/commands.sh /build-target/runtime-commands.sh; for suffix in "" " missing-host-image" " wrong-host-image"; do mkdir "/build-target/host Python native lifecycle$suffix"; cp /lifecycle/native-images/*.so "/build-target/host Python native lifecycle$suffix/"; done; chmod u+w "/build-target/host Python native lifecycle wrong-host-image/glue_native_lifecycle.so"; printf "~" | dd of="/build-target/host Python native lifecycle wrong-host-image/glue_native_lifecycle.so" bs=1 count=1 conv=notrunc status=none; rm "/build-target/host Python native lifecycle missing-host-image/libglue_python_lifecycle.so"; cp "/new-build/relocated Python native packages/glue-python-bootstrap-probe" "/build-target/relocated Python native lifecycle/glue-python-bootstrap-probe"; chmod 0555 "/build-target/relocated Python native lifecycle/glue-python-bootstrap-probe" "/build-target/relocated Python native lifecycle" "/build-target/runtime-empty" /build-target/host\\ Python\\ native\\ lifecycle*; chmod 0444 /build-target/host\\ Python\\ native\\ lifecycle*/*.so "/build-target/relocated Python native lifecycle/"*.glue; '
    for file in frames.glob("*.glue"):
        expected["/build-target/" + relocated + "/" + file.name] = identity(file)["sha256"]
    expected["/build-target/" + relocated + "/glue-python-bootstrap-probe"] = identity(PROBE)["sha256"]
    expected["/build-target/runtime-commands.sh"] = identity(script)["sha256"]
    (evidence / "expected-runtime-inputs.sha256").write_text("".join(hash + "  " + name + "\n" for name, hash in sorted(expected.items())))
    shutil.copyfile(metadata, evidence / "native-metadata.json")
    setup += 'test ! -e /build-target/producer; test ! -e /build-target/include; test ! -e /build-target/native-producer; find /build-target -type f -print0 | sort -z | xargs -0 sha256sum > /evidence/runtime-inputs.sha256; sha256sum --quiet -c /evidence/expected-runtime-inputs.sha256'
    try:
        command(["podman", "volume", "create", volume], evidence, "volume-create")
        argv = ["podman", "run", "--rm", "--network=none", "--read-only", "--read-only-tmpfs=false", "--volume", volume + ":/build-target:rw", "--volume", str(OLD) + ":/cached:ro", "--volume", str(NEW) + ":/new-build:ro", "--volume", str(evidence) + ":/evidence:rw"]
        if family == "lifecycle":
            argv += ["--volume", str(LIFE) + ":/lifecycle:ro", "--volume", str(REPO / "target/python-native-lifecycle-clean-final") + ":/lifecycle-evidence:ro"]
        command(argv + [IMAGE, "sh", "-c", setup], evidence, "setup")
        if (evidence / "runtime-inputs.sha256").read_bytes() != (evidence / "expected-runtime-inputs.sha256").read_bytes():
            raise RuntimeError("prepared volume inventory differs from independently hashed expected corpus")
        command(["podman", "run", "--rm", "--network=none", "--read-only", "--read-only-tmpfs=false", "--tmpfs", "/tmp:rw,size=1m", "--tmpfs", "/unavailable:ro,mode=000,size=1m", "--mount", "type=volume,source=" + volume + ",destination=/build-target,ro", "--mount", "type=bind,source=" + str(evidence) + ",destination=/evidence", "--workdir", "/build-target/runtime-empty", IMAGE, "sh", "-c", "chmod 000 /tmp; exec setpriv --reuid=65534 --regid=65534 --clear-groups --no-new-privs sh /build-target/runtime-commands.sh --run"], evidence, "runtime")
        command(["podman", "run", "--rm", "--network=none", "--read-only", "--read-only-tmpfs=false", "--mount", "type=volume,source=" + volume + ",destination=/build-target,ro", "--mount", "type=bind,source=" + str(evidence) + ",destination=/evidence,ro", IMAGE, "sh", "-c", "sha256sum --quiet -c /evidence/runtime-inputs.sha256"], evidence, "after-run-input-hash-check")
        checks = []
        for mode in MODES:
            frame = mode.removesuffix("-app-error")
            status = int((evidence / (mode + ".exit-status.txt")).read_text())
            wanted = 0 if mode in CELLS else 1
            if status != wanted:
                raise RuntimeError("historical exit status differs: " + family + "/" + mode)
            check = command([sys.executable, "-I", "-S", "-B", str(checker), str(evidence / (mode + ".trace.txt")), "--mode", mode, "--stdout-file", str(evidence / (mode + ".stdout.txt")), "--stderr-file", str(evidence / (mode + ".stderr.txt")), "--native-metadata-file", str(evidence / "native-metadata.json"), "--archive-file", str(frames / (frame + ".glue"))], evidence, mode + ".trace-check")
            checks.append({"mode": mode, "runtime_exit_status": status, "trace_check_exit_status": check.returncode})
        summary = {"family": family, "runtime_cases": 11, "normal_successes": 4, "expected_app_errors": 4, "preload_rejections": 3, "strict_trace_replays": 11, "runtime_files": len(expected), "only_replacement_probe_differs_from_historical_inputs": True, "post_run_input_hashes_unchanged": True, "cases": checks}
        write(evidence / "historical-regression-summary.json", summary)
        summaries.append(summary)
    finally:
        command(["podman", "volume", "rm", volume], evidence, "volume-cleanup", required=False)

after = [identity(p) for p in historical_paths]
if after != bindings["historical_inputs"]:
    raise RuntimeError("historical host inputs changed")
if identity(PROBE) != bindings["replacement_probe"]:
    raise RuntimeError("replacement probe changed during regression")
write(OUT / "historical-regression-summary.json", {"schema_version": 0, "runtime_cases": 22, "strict_trace_replays": 22, "normal_successes": 8, "expected_app_errors": 8, "preload_rejections": 6, "historical_host_inputs_unchanged": True, "replacement_probe_unchanged": True, "suites": summaries})
print("PASS both historical native matrices: 22 outcomes and 22 unchanged strict trace replays", flush=True)
