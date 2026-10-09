#!/usr/bin/env python3
"""Check the controlled experiment's exact observed results, not a syscall trace."""
import pathlib
import plistlib
import re
import sys

EXPECTED_REJECTIONS = {
    "wrong_architecture": "only little-endian arm64 MH_DYLIB images are supported",
    "install_name": "image install names or dependencies differ from the controlled closure",
    # This genuine chained-fixup image also carries constructor offsets; the
    # parser rejects that unsupported section before reaching the chained command.
    "chained_fixups": "unsupported section __TEXT,__init_offsets flags=0x16",
    # The genuine TLV image sets MH_HAS_TLV_DESCRIPTORS, rejected at the header.
    "tlv": "unsupported Mach-O header flags or reserved field",
    "writable_executable": "invalid segment range, alignment, or protection",
    "undeclared_dependency": "image install names or dependencies differ from the controlled closure",
    "future_minimum": "fixture images must declare macOS 13.0 exactly",
}
EXPECTED_SIGNING_CONTROLS = {
    "no-jit": (
        {},
        "Invalid argument (os error 22)",
    ),
    "debugger-control": (
        {
            "com.apple.security.cs.allow-jit": True,
            "com.apple.security.get-task-allow": True,
        },
        "require valid signed hardened-runtime executable without debugger access",
    ),
}


def require_file(path, expected):
    observed = path.read_bytes()
    if observed != expected:
        raise SystemExit(f"unexpected {path.name}: {observed!r}, expected {expected!r}")


def check_signing_controls(root):
    for name, (expected_entitlements, diagnostic) in EXPECTED_SIGNING_CONTROLS.items():
        case = root / name
        require_file(case / "probe.exit-status.txt", b"1\n")
        require_file(case / "probe.stdout.txt", b"")
        require_file(case / "probe.stderr.txt", f"probe failed: {diagnostic}\n".encode())
        observed = plistlib.loads((case / "entitlements.plist").read_bytes())
        if observed != expected_entitlements:
            raise SystemExit(f"unexpected {name} control entitlements: {observed!r}")
        identity = (case / "identity.stderr.txt").read_text()
        flags = re.search(r"\bflags=0x([0-9a-fA-F]+)\(", identity)
        if "Signature=adhoc" not in identity or flags is None or int(flags[1], 16) & 0x10002 != 0x10002:
            raise SystemExit(f"{name} control must be ad-hoc signed with hardened runtime")


def check_memory_policy(root):
    require_file(root / "probe.exit-status.txt", b"0\n")
    require_file(root / "probe.stderr.txt", b"")
    require_file(
        root / "probe.stdout.txt",
        b"PASS JIT demotion text=-1 errno=13 data=-1 errno=13\n"
        b"PASS owned anonymous data replacement answer=42 data=8\n",
    )
    entitlements = plistlib.loads((root / "signature/entitlements.plist").read_bytes())
    if entitlements != {"com.apple.security.cs.allow-jit": True}:
        raise SystemExit("memory-policy control must carry only allow-jit")
    identity = (root / "signature/identity.stderr.txt").read_text()
    flags = re.search(r"\bflags=0x([0-9a-fA-F]+)\(", identity)
    if "Signature=adhoc" not in identity or flags is None or int(flags[1], 16) & 0x10002 != 0x10002:
        raise SystemExit("memory-policy control must be ad-hoc signed with hardened runtime")


def main():
    if len(sys.argv) == 3 and sys.argv[1] == "--memory-policy":
        check_memory_policy(pathlib.Path(sys.argv[2]))
        print("PASS exact signed JIT demotion and owned data replacement control")
        return
    if len(sys.argv) == 3 and sys.argv[1] == "--signing-controls":
        check_signing_controls(pathlib.Path(sys.argv[2]))
        print("PASS exact signing-control diagnostics, statuses and recorded entitlements")
        return
    if len(sys.argv) != 2:
        raise SystemExit("Usage: check-results.py EVIDENCE_DIRECTORY | --signing-controls RECORD_DIRECTORY | --memory-policy RECORD_DIRECTORY")
    root = pathlib.Path(sys.argv[1])
    check_signing_controls(root / "signing-controls")
    check_memory_policy(root / "memory-policy")
    for name, diagnostic in EXPECTED_REJECTIONS.items():
        case = root / "rejections" / name
        require_file(case / "probe.exit-status.txt", b"1\n")
        require_file(case / "probe.stdout.txt", b"")
        require_file(case / "probe.stderr.txt", f"probe failed: {diagnostic}\n".encode())
    require_file(root / "baseline.exit-status.txt", b"0\n")
    require_file(root / "baseline.stderr.txt", b"")
    require_file(root / "probe.exit-status.txt", b"0\n")
    require_file(root / "probe.stderr.txt", b"")
    pattern = rb"PASS answer=42 data=7 constructors=1 pid=([1-9][0-9]*)\n"
    outputs = [(root / name).read_bytes() for name in ["baseline.stdout.txt", "probe.stdout.txt"]]
    for output in outputs:
        if re.fullmatch(pattern, output) is None:
            raise SystemExit(f"unexpected positive output: {output!r}")
    if re.sub(rb"pid=[1-9][0-9]*", b"pid=PID", outputs[0]) != re.sub(
        rb"pid=[1-9][0-9]*", b"pid=PID", outputs[1]
    ):
        raise SystemExit("ordinary dyld and mapped execution output differ")
    require_file(root / "held-probe.exit-status.txt", b"0\n")
    require_file(root / "held-probe.stderr.txt", b"")
    pid = (root / "held-probe.pid.txt").read_text().strip()
    if re.fullmatch(r"[1-9][0-9]*", pid) is None:
        raise SystemExit("invalid held target PID")
    require_file(root / "held-probe.stdout.txt", f"PASS answer=42 data=7 constructors=1 pid={pid}\n".encode())
    print("PASS exact ordinary/mapped outputs, seven rejection diagnostics, two signing controls, memory-policy control and held target PID")
    print("Scope: these results do not constitute a complete filesystem trace")


if __name__ == "__main__":
    main()
