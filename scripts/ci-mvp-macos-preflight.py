#!/usr/bin/env python3
"""Bounded, read-only host inventory. This never establishes native acceptance."""

import hashlib
import json
import os
from pathlib import Path
import selectors
import subprocess
import sys
import time


LIMIT = 256 * 1024
TIMEOUT = 20
COMMANDS = (
    ("os-version", ("/usr/bin/sw_vers", "-productVersion")),
    ("os-build", ("/usr/bin/sw_vers", "-buildVersion")),
    ("architecture", ("/usr/bin/uname", "-m")),
    ("kernel", ("/usr/bin/uname", "-r")),
    ("sip", ("/usr/bin/csrutil", "status")),
    ("sdk-version", ("/usr/bin/xcrun", "--show-sdk-version")),
    ("sdk-path", ("/usr/bin/xcrun", "--show-sdk-path")),
    ("compiler", ("/usr/bin/xcrun", "clang", "--version")),
    # -l lists matching probes; it does not enable probes or start a target.
    ("syscall-entry-list", ("/usr/bin/sudo", "-n", "/usr/sbin/dtrace",
                            "-l", "-n", "syscall:::entry")),
)


def collect(folder, name, argv):
    chunks = {"stdout": bytearray(), "stderr": bytearray()}
    outcome, returncode = "exited", None
    started = time.monotonic()
    proc = None
    launch_error = None
    cleanup_error = None
    with selectors.DefaultSelector() as poll:
        try:
            proc = subprocess.Popen(argv, stdin=subprocess.DEVNULL,
                                    stdout=subprocess.PIPE, stderr=subprocess.PIPE)
            for stream, pipe in (("stdout", proc.stdout), ("stderr", proc.stderr)):
                os.set_blocking(pipe.fileno(), False)
                poll.register(pipe, selectors.EVENT_READ, stream)
            while poll.get_map():
                remaining = TIMEOUT - (time.monotonic() - started)
                if remaining <= 0:
                    outcome = "timeout"
                    break
                for key, _ in poll.select(min(remaining, 0.25)):
                    data = os.read(key.fd, 8192)
                    if not data:
                        poll.unregister(key.fileobj)
                        continue
                    saved = chunks[key.data]
                    room = LIMIT - len(saved)
                    saved.extend(data[:room])
                    if len(data) > room:
                        outcome = "output-limit"
                        break
                if outcome != "exited":
                    break
            if outcome == "exited":
                try:
                    returncode = proc.wait(timeout=max(
                        0.001, TIMEOUT - (time.monotonic() - started)))
                except subprocess.TimeoutExpired:
                    outcome = "timeout"
        except OSError as exc:
            outcome = "launch-or-read-error"
            launch_error = {"errno": exc.errno, "message": str(exc)}
        finally:
            if proc is not None:
                if proc.poll() is None:
                    try:
                        proc.kill()  # Only this inventory command, on timeout/fault.
                    except OSError as exc:
                        cleanup_error = {"errno": exc.errno, "message": str(exc)}
                try:
                    returncode = proc.wait(timeout=1)
                except subprocess.TimeoutExpired:
                    cleanup_error = {"message": "inventory command did not reap within one second"}
                proc.stdout.close()
                proc.stderr.close()
    streams = {}
    for stream, data in chunks.items():
        path = folder / (name + "." + stream)
        path.write_bytes(data)
        streams[stream] = {"file": path.name, "bytes": len(data),
                           "sha256": hashlib.sha256(data).hexdigest()}
    return {"name": name, "argv": list(argv), "outcome": outcome,
            "returncode": returncode, "elapsed_seconds": time.monotonic() - started,
            "launch_error": launch_error, "cleanup_error": cleanup_error,
            "streams": streams}


def main():
    if sys.platform != "darwin" or len(sys.argv) != 2:
        raise SystemExit("usage on macOS: ci-mvp-macos-preflight.py NEW_OUTPUT_DIRECTORY")
    folder = Path(sys.argv[1])
    folder.mkdir(mode=0o700, parents=False, exist_ok=False)
    rows = [collect(folder, name, argv) for name, argv in COMMANDS]
    by_name = {row["name"]: row for row in rows}

    def successful_text(name):
        row = by_name[name]
        if row["outcome"] != "exited" or row["returncode"] != 0:
            return None
        return (folder / (name + ".stdout")).read_text(errors="replace").strip()

    version = successful_text("os-version")
    arch = successful_text("architecture")
    sip = successful_text("sip")
    policy = {"System Integrity Protection status: enabled.": "enabled",
              "System Integrity Protection status: disabled.": "disabled"}.get(
                  sip, "unknown-or-custom")
    try:
        expected_host = int(version.split(".")[0]) >= 26 and arch == "arm64"
    except (AttributeError, ValueError):
        expected_host = False
    listing = by_name["syscall-entry-list"]
    listing_succeeded = listing["outcome"] == "exited" and listing["returncode"] == 0
    receipt = {
        "schema": "glue-macos-host-preflight-v1", "commands": rows,
        "expected_os_arch_observed": expected_host,
        "sip_status_hint": policy, "provider_listing_succeeded": listing_succeeded,
        "native_eligibility": "unmeasured-probe-enablement-and-calibration",
        "native_trace_executed": False, "native_calibration_passed": False,
        "full_acceptance": False,
        "limitations": ["Provider listing does not prove probe enablement.",
                        "No traced target, exec stop or extraction corpus was run.",
                        "No security setting was changed."],
    }
    (folder / "receipt.json").write_text(json.dumps(receipt, indent=2) + "\n")
    print(json.dumps({key: value for key, value in receipt.items() if key != "commands"},
                     indent=2))
    return 0 if expected_host else 1


if __name__ == "__main__":
    raise SystemExit(main())
