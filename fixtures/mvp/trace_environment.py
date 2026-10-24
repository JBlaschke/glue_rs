"""Verify retained evidence for the explicit Linux CI trace environment."""
import argparse
import hashlib
import json
from pathlib import Path


POLICY = "traceable-native-syscalls-v1"
CALLS = {
    "io_uring_setup", "io_uring_enter", "io_uring_register", "io_setup",
    "io_destroy", "io_submit", "io_cancel", "io_getevents", "io_pgetevents",
}
FILES = ["trace_environment.c", "glue-trace-environment", "proof.json"]
# Linux UAPI values for the supported captured ABIs, independent of replay host.
LINUX_ENOSYS = {"x86_64": 38, "aarch64": 38}


def identity(path):
    data = path.read_bytes()
    return {"size": len(data), "sha256": hashlib.sha256(data).hexdigest()}


def check_proof(proof, architecture):
    if type(architecture) is not str or architecture not in LINUX_ENOSYS:
        raise ValueError("unsupported Linux trace proof architecture")
    enosys = LINUX_ENOSYS[architecture]
    if (proof.get("policy"), proof.get("architecture"), proof.get("status")) != (POLICY, architecture, "passed"):
        raise ValueError("trace policy, architecture or probe status differs")
    before = proof["before_policy"]
    if type(before["setup_succeeded"]) is not bool or type(before["setup_errno"]) is not int:
        raise ValueError("setup control result is missing")
    if before["setup_succeeded"] != (before["setup_errno"] == 0):
        raise ValueError("setup control result is inconsistent")
    for label in ["parent", "inherited_exec_child"]:
        record = proof[label]
        if record["no_new_privs"] != 1 or record["seccomp_mode"] != 2:
            raise ValueError(label + ": inherited no_new_privs/filter mode absent")
        calls = record["syscalls"]
        if len(calls) != len(CALLS) or {call["name"] for call in calls} != CALLS:
            raise ValueError(label + ": async syscall probes are incomplete")
        if any(call["errno"] != enosys for call in calls):
            raise ValueError(label + ": async syscall did not return ENOSYS")
        if record["ordinary_file_io"] is not True or record["native_syscalls_allowed"] is not True:
            raise ValueError(label + ": ordinary syscall control failed")
        if architecture == "x86_64" and record["abi_guards"] != {"x32_errno": enosys, "i386_errno": enosys}:
            raise ValueError(label + ": x32/i386 ABI guard probe failed")


def check(directory, architecture, record=False):
    proof = json.loads((directory / "proof.json").read_text())
    check_proof(proof, architecture)
    manifest = {
        "policy": POLICY, "architecture": architecture,
        "scope": "CI trace environment; asynchronous kernel I/O disabled; not unrestricted-host acceptance or a security sandbox",
        "setup_control": "available-before-policy" if proof["before_policy"]["setup_succeeded"] else "already-unavailable",
        "files": {name: identity(directory / name) for name in FILES},
    }
    path = directory / "manifest.json"
    if record:
        path.write_text(json.dumps(manifest, indent=2) + "\n")
    elif json.loads(path.read_text()) != manifest:
        raise ValueError("trace environment evidence identity or policy changed")
    return manifest


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("directory", type=Path)
    parser.add_argument("--architecture", choices=["x86_64", "aarch64"], required=True)
    parser.add_argument("--record", action="store_true")
    arguments = parser.parse_args()
    check(arguments.directory, arguments.architecture, arguments.record)
