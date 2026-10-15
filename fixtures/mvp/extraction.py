"""Complete Linux process-tree write oracle and final macOS code verification."""
from __future__ import annotations

import ast
import importlib.util
import json
import os
import re
import shutil
import subprocess
from pathlib import Path

SPEC = importlib.util.spec_from_file_location("glue_existing_trace_parser", Path(__file__).resolve().parents[2] / "scripts/check-linux-memfd-trace.py")
BASE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(BASE)
TraceError = BASE.TraceError

MUTATIONS = {
    "creat": [0], "truncate": [0], "truncate64": [0], "unlink": [0], "unlinkat": [1],
    "mkdir": [0], "mkdirat": [1], "rmdir": [0], "rename": [0, 1], "renameat": [1, 3], "renameat2": [1, 3],
    "link": [0, 1], "linkat": [1, 3], "symlink": [1], "symlinkat": [2], "mknod": [0], "mknodat": [1],
    "chmod": [0], "fchmodat": [1], "fchmodat2": [1], "chown": [0], "lchown": [0], "fchownat": [1],
    "utime": [0], "utimes": [0], "utimensat": [1], "setxattr": [0], "lsetxattr": [0], "removexattr": [0],
}
FD_MUTATIONS = {"write": 0, "writev": 0, "pwrite64": 0, "pwritev": 0, "pwritev2": 0,
                "ftruncate": 0, "ftruncate64": 0, "fchmod": 0, "fchown": 0, "fsetxattr": 0,
                "fremovexattr": 0, "fallocate": 0, "sendfile": 0, "sendfile64": 0, "copy_file_range": 2, "splice": 2}
MOUNTS = {"mount", "umount2", "fsopen", "fsconfig", "fsmount", "move_mount", "open_tree", "mount_setattr"}
OPEN_WRITE = re.compile(r"\bO_(?:WRONLY|RDWR|CREAT|TRUNC|APPEND|TMPFILE)\b")
CALL = re.compile(r"^(\d+\.\d+)\s+([a-z][a-z0-9_]*)\((.*)\)\s+=\s+(.+)$")
FINISHED = re.compile(r"^(?:\d+\.\d+\s+)?\+\+\+ (?:exited with -?\d+|killed by [A-Z0-9]+(?: \(core dumped\))?) \+\+\+$")


def quoted(value: str) -> str:
    if not value.startswith('"') or not value.endswith('"'):
        raise TraceError(f"path is truncated or not a complete quoted string: {value}")
    try:
        text = ast.literal_eval(value)
    except (SyntaxError, ValueError) as error:
        raise TraceError(f"unparsed path: {value}") from error
    try:
        return text.encode("latin1").decode("utf-8")
    except (UnicodeError, AttributeError):
        return text


def records(path: Path) -> tuple[list, bool]:
    if path.stat().st_size > 256 * 1024 * 1024:
        raise TraceError("trace file exceeds 256 MiB")
    result, pending, finished = [], None, False
    for line in path.read_text().splitlines():
        if len(line) > 65536:
            raise TraceError("trace record exceeds 64 KiB")
        if "<unfinished ...>" in line:
            if pending is not None:
                raise TraceError("nested unfinished syscall")
            pending = line.replace("<unfinished ...>", "")
            continue
        if " resumed>" in line:
            resumed = re.match(r"^\d+\.\d+\s+<\.\.\. ([a-z0-9_]+) resumed>(.*)$", line)
            if pending is None or resumed is None or not re.search(rf"\s{resumed[1]}\(", pending):
                raise TraceError("orphan/mismatched resumed syscall")
            line, pending = pending + resumed[2], None
        if FINISHED.fullmatch(line):
            finished = True
            continue
        if re.match(r"^\d+\.\d+\s+--- [A-Z0-9]+ .* ---$", line):
            continue
        match = CALL.fullmatch(line)
        if match is None:
            raise TraceError(f"incomplete/unrecognized trace record: {line[:200]}")
        if finished:
            raise TraceError("syscall after process completion")
        result.append((float(match[1]), match[2], BASE.split_arguments(match[3]), match[4]))
    if pending is not None:
        raise TraceError("unfinished syscall at trace end")
    return result, finished


def check_trace(prefix: Path, cwd: Path, allowed_outputs=(), sinks=(), expected_executable=None) -> dict:
    paths = sorted(prefix.parent.glob(prefix.name + ".[0-9]*"))
    if not paths:
        raise TraceError("no per-process traces were retained")
    events, pids = [], set()
    for path in paths:
        pid = int(path.name.rsplit(".", 1)[1])
        pids.add(pid)
        entries, finished = records(path)
        if not finished:
            raise TraceError(f"process {pid} has no terminal trace record")
        events.extend((timestamp, pid, index, name, args, returned) for index, (timestamp, name, args, returned) in enumerate(entries))
    events.sort()
    first = min(events)
    if first[3] not in {"execve", "execveat"} or not first[5].startswith("0"):
        raise TraceError("root trace must begin with its successful execution")
    if expected_executable is not None:
        index = 0 if first[3] == "execve" else 1
        if quoted(first[4][index]) != expected_executable:
            raise TraceError("root trace does not execute the selected included launcher")
    root_pid = first[1]
    expected, directories, clones, counts = {root_pid}, {root_pid: [cwd]}, [], {}
    descriptors, cloexec = {root_pid: {0,1,2}}, {root_pid: set()}
    peak_fds = 3
    allowed = [Path(os.path.normpath(str(path))) for path in allowed_outputs]
    sink_paths = {str(path) for path in sinks}
    writes, memory_writes, io = 0, 0, {"open": 0, "stat": 0, "read": 0, "read_bytes": 0, "seek":0}

    def path_for(value, pid, directory_fd=None):
        path = Path(quoted(value))
        if path.is_absolute(): return Path(os.path.normpath(str(path)))
        base = directories[pid][0]
        if directory_fd is not None and not directory_fd.startswith("AT_FDCWD"):
            match = re.match(r"^-?\d+<([^<>]+)>$", directory_fd)
            if not match: raise TraceError("relative path lacks decoded directory descriptor")
            base = Path(match[1])
        return Path(os.path.normpath(str(base / path)))

    def writable(path):
        return path == Path("/dev/null") or any(path == root or path.is_relative_to(root) for root in allowed)

    def fd_write(value):
        nonlocal memory_writes
        match = re.match(r"^(-?\d+)(?:<(.+)>)?$", value)
        if not match: raise TraceError(f"write lacks decoded descriptor: {value}")
        number, path = int(match[1]), match[2]
        if path is not None and path.startswith(("/memfd:", "memfd:", "pipe:[", "anon_inode:")):
            if "memfd:" in path: memory_writes += 1
            return
        if path is not None:
            path = quoted('"' + path + '"')
        if number in {1, 2} and (path in sink_paths or path is None): return
        if path is None or not writable(Path(path.removesuffix(" (deleted)"))):
            raise TraceError(f"filesystem write attempt outside declared application output: {value}")

    for _, pid, _, name, args, returned in events:
        if pid not in expected:
            raise TraceError(f"untraced/unrelated process {pid}")
        counts[name] = counts.get(name, 0) + 1
        if name in {"clone", "clone3", "fork", "vfork"}:
            match = re.match(r"^(\d+)", returned)
            if match and int(match[1]) > 0:
                child = int(match[1]); expected.add(child); clones.append([pid, child])
                directories[child] = directories[pid] if "CLONE_FS" in ",".join(args) else list(directories[pid])
                shared = "CLONE_FILES" in ",".join(args)
                descriptors[child] = descriptors[pid] if shared else set(descriptors[pid])
                cloexec[child] = cloexec[pid] if shared else set(cloexec[pid])
        descriptor_result = re.match(r"^(\d+)", returned)
        if name in {"open", "openat", "openat2", "creat", "memfd_create", "socket", "accept", "accept4", "eventfd", "eventfd2", "signalfd", "signalfd4", "inotify_init", "inotify_init1", "timerfd_create", "epoll_create", "epoll_create1", "dup", "dup2", "dup3"} or (name == "fcntl" and len(args)>1 and "F_DUPFD" in args[1]):
            if descriptor_result:
                number = int(descriptor_result[1]); descriptors[pid].add(number)
                if "CLOEXEC" in ",".join(args): cloexec[pid].add(number)
                else: cloexec[pid].discard(number)
        if name in {"pipe", "pipe2", "socketpair"} and returned.startswith("0"):
            output = args[0] if name != "socketpair" else args[3]
            for descriptor in BASE.split_arguments(output.removeprefix("[").removesuffix("]")):
                number = int(re.match(r"^(\d+)",descriptor)[1]); descriptors[pid].add(number)
                if "CLOEXEC" in ",".join(args): cloexec[pid].add(number)
        peak_fds = max(peak_fds,len(descriptors[pid]))
        if name == "close" and returned.startswith("0"):
            number = int(re.match(r"^(\d+)",args[0])[1]); descriptors[pid].discard(number); cloexec[pid].discard(number)
        if name == "close_range" and returned.startswith("0"):
            if "CLOSE_RANGE_UNSHARE" in args[2]:
                descriptors[pid], cloexec[pid] = set(descriptors[pid]), set(cloexec[pid])
            start = int(args[0], 0)
            end = 2**32-1 if args[1] in {"~0U", "UINT_MAX"} else int(args[1], 0)
            affected = {number for number in descriptors[pid] if start <= number <= end}
            if "CLOSE_RANGE_CLOEXEC" in args[2]: cloexec[pid].update(affected)
            else:
                descriptors[pid].difference_update(affected); cloexec[pid].difference_update(affected)
        if name == "fcntl" and len(args)>2 and args[1]=="F_SETFD" and returned.startswith("0"):
            number=int(re.match(r"^(\d+)",args[0])[1])
            if "FD_CLOEXEC" in args[2]: cloexec[pid].add(number)
            else: cloexec[pid].discard(number)
        if name in {"execve", "execveat"} and returned.startswith("0"):
            descriptors[pid] = descriptors[pid] - cloexec[pid]; cloexec[pid] = set()
        if name == "chdir" and returned.startswith("0"):
            directories[pid][0] = path_for(args[0], pid)
        if name == "fchdir" and returned.startswith("0"):
            match = re.match(r"^\d+<([^<>]+)>$", args[0])
            if not match: raise TraceError("fchdir path was not decoded")
            directories[pid][0] = Path(match[1])
        if name in {"open", "openat", "openat2"}:
            io["open"] += 1
            index = 0 if name == "open" else 1
            flags = args[index + 1]
            if OPEN_WRITE.search(flags):
                writes += 1
                path = path_for(args[index], pid, None if index == 0 else args[0])
                if not writable(path): raise TraceError(f"filesystem open-for-write attempt: {path}")
                if re.match(r"^[0-9]+<", returned): fd_write(returned)
        if name in {"symlink", "symlinkat"}:
            destination = path_for(args[1 if name == "symlink" else 2], pid, None if name == "symlink" else args[1])
            target = Path(quoted(args[0]))
            resolved = Path(os.path.normpath(str(target if target.is_absolute() else destination.parent / target)))
            if not writable(resolved): raise TraceError("runtime symlink target escapes declared application output")
        if name in MUTATIONS:
            writes += 1
            for index in MUTATIONS[name]:
                directory_fd = args[index - 1] if name.endswith("at") or name in {"renameat2", "fchmodat2"} else None
                if not writable(path_for(args[index], pid, directory_fd)):
                    raise TraceError(f"filesystem mutation attempt: {name}({args[index]})")
        if name in FD_MUTATIONS:
            writes += 1; fd_write(args[FD_MUTATIONS[name]])
        if name in {"mmap", "mmap2"} and len(args) >= 5 and "PROT_WRITE" in args[2] and "MAP_SHARED" in args[3] and not args[4].startswith("-1"):
            writes += 1; fd_write(args[4])
        if name in MOUNTS:
            raise TraceError(f"mount/FUSE substitute attempt: {name}")
        if name in {"io_uring_setup", "io_setup"} and not returned.startswith("-1"):
            raise TraceError("successful asynchronous I/O setup needs a trace decoder before acceptance")
        if name in {"io_uring_enter", "io_submit", "process_vm_writev", "ptrace"}:
            raise TraceError(f"write mechanism not observable by this trace policy: {name}")
        if name in {"stat", "lstat", "fstat", "newfstatat", "statx", "access", "faccessat", "faccessat2"}: io["stat"] += 1
        if name in {"lseek", "_llseek"}: io["seek"] += 1
        if name in {"read", "readv", "pread64", "preadv", "preadv2"}:
            io["read"] += 1
            match = re.match(r"^(\d+)", returned)
            if match: io["read_bytes"] += int(match[1])
    if expected != pids:
        raise TraceError(f"process tree trace incomplete: expected {sorted(expected)}, retained {sorted(pids)}")
    return {"status": "passed", "processes": len(pids), "process_edges": clones, "syscalls": counts,
            "write_operations_observed": writes, "memory_object_writes": memory_writes, "io": io,
            "fds": {"peak_per_process":peak_fds,"scope":"three initial stdio descriptors plus traced opens/dups/pipes/clones and CLOEXEC/close/close_range lifecycle"},
            "policy": "all filesystem write attempts outside declared app output reject, including failed writes"}


def trace_prefix(output: Path, uid: int | None = None):
    executable = shutil.which("strace")
    if executable is None: return [], None, {"status": "unavailable", "reason": "strace is not installed in this native Linux cell"}
    directory = output / "trace"
    directory.mkdir()
    if uid is not None and os.geteuid() == 0:
        try: os.chown(directory, uid, uid)
        except PermissionError: directory.chmod(0o777)
    prefix = directory / "syscalls"
    return [executable, "-f", "-ff", "-q", "-yy", "-s", "4096", "-ttt", "-o", str(prefix)], prefix, {"status": "pending", "mechanism": "strace complete process tree"}


def oracle_self_test(output: Path) -> dict:
    import sys
    controls = {
        "read-only": ("pass", False),
        "create-unlink": (f"from pathlib import Path; p=Path({str(output / 'extraction-control')!r}); p.write_bytes(b'payload'); p.unlink()", True),
        "denied-write": ("try:\n open('/glue-no-such-parent/extracted-payload','wb')\nexcept OSError:\n pass", True),
        "descendant-write": (f"import subprocess,sys; subprocess.run([sys.executable,'-c',\"open({str(output / 'child-extraction')!r},'wb').write(b'payload')\"],check=True)", True),
    }
    results = {}
    for name, (source, must_reject) in controls.items():
        directory = output / name
        directory.mkdir(parents=True)
        argv, prefix, available = trace_prefix(directory)
        if prefix is None: return available
        result = subprocess.run(argv + [sys.executable, "-c", source], cwd=output, env={**os.environ, "PYTHONDONTWRITEBYTECODE": "1"}, capture_output=True, timeout=30, check=False)
        try:
            analysis = check_trace(prefix, output)
            rejected, reason = False, "read-only process accepted"
        except TraceError as error:
            rejected, reason = True, str(error)
        results[name] = {"status": "passed" if rejected == must_reject and result.returncode == 0 else "failed", "expected_rejection": must_reject, "rejected": rejected, "reason": reason, "exit": result.returncode}
    return {"status": "passed" if all(result["status"] == "passed" for result in results.values()) else "failed", "controls": results}


def verify_macos(root: Path, policy: str) -> dict:
    magic = {b"\xcf\xfa\xed\xfe", b"\xfe\xed\xfa\xcf", b"\xca\xfe\xba\xbe", b"\xca\xfe\xba\xbf", b"\xbe\xba\xfe\xca", b"\xbf\xba\xfe\xca"}
    images = []
    for path in sorted(root.rglob("*")):
        if not path.is_file() or path.is_symlink(): continue
        with path.open("rb") as stream:
            if stream.read(4) not in magic: continue
        verification = subprocess.run(["/usr/bin/codesign", "--verify", "--strict", str(path)], capture_output=True, check=False)
        metadata = subprocess.run(["/usr/bin/codesign", "-d", "--verbose=4", str(path)], capture_output=True, check=False)
        text = metadata.stderr.decode(errors="replace")
        signature = "ad-hoc" if "Signature=adhoc" in text else "developer-id" if "Authority=Developer ID Application:" in text else "unknown"
        images.append({"path": path.relative_to(root).as_posix(), "verification_exit": verification.returncode,
                       "signature": signature, "metadata_exit": metadata.returncode, "metadata": text, "verification_error": verification.stderr.decode(errors="replace")})
    if policy not in {"ad-hoc", "developer-id"}:
        return {"status": "unavailable", "reason": "select the intended ad-hoc or developer-id deployment policy", "images": images}
    accepted = {"ad-hoc", "developer-id"} if policy == "ad-hoc" else {"developer-id"}
    passed = bool(images) and all(image["verification_exit"] == 0 and image["metadata_exit"] == 0 and image["signature"] in accepted for image in images)
    result = {"status": "passed" if passed else "failed", "policy": policy, "accepted_signature_classes": sorted(accepted), "images": images,
              "notarization": "not proven by codesign verification"}
    if policy == "developer-id":
        assessment = subprocess.run(["/usr/sbin/spctl", "--assess", "--type", "execute", "--verbose=4", str(root / "glue")], capture_output=True, check=False)
        result["gatekeeper"] = {"exit": assessment.returncode, "stdout": assessment.stdout.decode(errors="replace"), "stderr": assessment.stderr.decode(errors="replace")}
        if assessment.returncode != 0: result["status"] = "failed"
    return result
