#!/usr/bin/env python3
"""Pair calibrated raw syscall frames; never grant Darwin extraction acceptance."""
import argparse
import hashlib
import json
from pathlib import Path
import sys
import tempfile

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
import read_capability as transport

HOST = {"system": "Darwin", "release": "25.6.0", "machine": "arm64",
        "product_version": "26.6.2", "build": "25G83"}
CALIBRATION = "c14b24662f390336b0deb1a5d82d8ead0a1cd4c873f93e6132878a97c143604a"
MAX_EVENTS, MAX_CALLS, MAX_THREADS = 32768, 16384, 4096
MAX_TIMELINE_BYTES = 16 * 1024 * 1024
BSD = frozenset("""__disable_threadsignal __mac_syscall __semwait_signal access
bsdthread_create bsdthread_register bsdthread_terminate close crossarch_trap csops
csops_audittoken csrctl dup execve exit fcntl fork fsgetpath fstat64 fstatat64
getattrlist getentropy getfsstat64 getpid getppid ioctl issetugid mmap mprotect
munmap open openat posix_spawn proc_info read setitimer setsid shared_region_check_np
shm_open stat64 sysctl thread_selfid ulock_wait ulock_wake write_nocancel""".split())
MACH = frozenset("""_kernelrpc_mach_port_construct_trap _kernelrpc_mach_port_deallocate_trap
_kernelrpc_mach_port_mod_refs_trap _kernelrpc_mach_vm_allocate_trap
_kernelrpc_mach_vm_deallocate_trap _kernelrpc_mach_vm_map_trap
_kernelrpc_mach_vm_protect_trap host_self_trap mach_msg2_trap mach_reply_port
mach_timebase_info_trap task_self_trap""".split())
NONRETURN = frozenset({"exit", "bsdthread_terminate"})


class UnsupportedPairing(ValueError):
    pass


def require(condition, reason):
    if not condition:
        raise UnsupportedPairing(reason)


class _Pairer:
    """Private replay of frames produced by this module's strict-reader call.

    Tokens identify observed lifetimes only. No public API accepts a caller's
    timeline, identity token, validation assertion or normalized state unit.
    """
    def __init__(self, root):
        self.root = root
        self.processes = {root: {"parent": None, "epoch": 0, "terminal": None}}
        self.threads, self.pending = {}, {}
        self.calls, self.frames = [], []
        self.began = self.ended = False
        self.clock = -1
        self.collector = None
        self.phases = {}

    def process(self, pid):
        require(pid in self.processes, "unknown observed process")
        return self.processes[pid]

    def reserve(self, tid, creator):
        require(0 < tid <= transport.UINT32 and tid not in self.threads,
                "unknown-width, duplicate or reused thread declaration")
        require(len(self.threads) < MAX_THREADS, "observed thread bound exceeded")
        self.threads[tid] = {"creator": creator, "pid": None, "epoch": None,
                             "closed": False, "start": False, "lwp_start": False}

    def bind(self, pid, tid):
        process = self.process(pid)
        require(process["terminal"] is None, "thread binds to terminal process")
        require(tid in self.threads, "thread has no observed declaration")
        thread = self.threads[tid]
        require(not thread["closed"], "thread identity reused after exit")
        if thread["pid"] is None:
            require(thread["creator"] in {pid, process["parent"]},
                    "thread declaration belongs to another process family")
            thread.update(pid=pid, epoch=process["epoch"])
        require(thread["pid"] == pid and thread["epoch"] == process["epoch"],
                "thread changes process or exec epoch")
        return thread

    def actor(self, raw, bootstrap=False):
        pid, tid = raw["pid"], raw["tid"]
        process = self.process(pid)
        if bootstrap and not self.threads:
            require(pid == self.root and raw["kind"] == 2 and raw["function"] == "close",
                    "unsupported initial launch-gate thread boundary")
            self.reserve(tid, pid)
            self.bind(pid, tid)
        require(tid in self.threads and self.threads[tid]["pid"] is not None,
                "unknown calling thread")
        thread = self.bind(pid, tid)
        require(process["terminal"] is None, "activity after target process exit")
        return thread

    def append_call(self, call):
        require(len(self.calls) < MAX_CALLS, "paired call bound exceeded")
        self.calls.append(call)

    def take(self, row):
        raw, words = row["raw"], row["raw_uint64_after_header"]
        kind, index = raw["kind"], raw["event"]
        require(index == len(self.frames) + 1 and index <= MAX_EVENTS, "pairing event bound or index gap")
        require(not self.ended and raw["timestamp"] >= self.clock,
                "frame after END or temporal event order moves backwards")
        self.clock = raw["timestamp"]
        self.frames.append(raw)
        if kind == 1:
            require(index == 1 and not self.began, "BEGIN must be the first unique frame")
            self.began, self.collector = True, (raw["pid"], raw["tid"])
            return
        require(self.began, "missing initial BEGIN")
        if kind == 17:
            require((raw["pid"], raw["tid"]) == self.collector, "END collector identity differs")
            require(not self.pending, "unresolved calls at END")
            require(all(p["terminal"] is not None for p in self.processes.values()), "unresolved process lifecycle at END")
            require(all(t["pid"] is not None and t["closed"] for t in self.threads.values()),
                    "unresolved thread lifecycle at END")
            self.ended = True
            return
        if kind in {2, 3, 14, 15, 16}:
            thread = self.actor(raw, bootstrap=kind in {2, 15})
            tid = raw["tid"]
            family = raw["provider"], raw["module"], raw["function"]
            require(raw["provider"] in {"syscall", "mach_trap"} and raw["module"] == ""
                    and raw["function"] in (BSD if raw["provider"] == "syscall" else MACH),
                    "uncalibrated call descriptor family")
            phase = (*family, kind)
            identity = raw["probe_id"], raw["epid"]
            require(phase not in self.phases or self.phases[phase] == identity,
                    "call phase changes its probe/enabling identity")
            self.phases[phase] = identity
            if kind in {2, 15}:
                require(tid not in self.pending, "recursive, duplicate or overlapping call entry")
                self.pending[tid] = {"identity": {"pid": raw["pid"], "tid": tid, "exec_epoch": thread["epoch"]},
                                     "family": list(family), "entry_index": index, "entry_words": list(words),
                                     "return_index": None, "return_words": None, "path_indexes": [],
                                     "termination_indexes": [], "exit_context": None}
            else:
                require(tid in self.pending, "orphan path or return without an entry")
                call = self.pending[tid]
                require(call["identity"] == {"pid": raw["pid"], "tid": tid, "exec_epoch": thread["epoch"]}
                        and call["family"] == list(family), "call process, thread, epoch or descriptor family mismatch")
                if kind == 14:
                    require(self.frames[call["entry_index"] - 1]["kind"] == 2 and not call["path_indexes"],
                            "orphan, duplicate or wrong-family path clause")
                    require(raw["probe_id"] == self.frames[call["entry_index"] - 1]["probe_id"],
                            "path clause does not refer to entry probe")
                    call["path_indexes"].append(index)
                    return
                entry_kind = self.frames[call["entry_index"] - 1]["kind"]
                require((entry_kind, kind) in {(2, 3), (15, 16)}, "mismatched BSD/Mach return family")
                require(raw["function"] not in NONRETURN or raw["provider"] != "syscall",
                        "uncalibrated return from nonreturning call")
                if kind == 3:
                    require(words[0] == words[1] and words[3] == words[4] and words[3] <= transport.INT_MAX,
                            "unmodeled BSD return duplication, errno or control flow")
                require(raw["function"] != "open" or len(call["path_indexes"]) == 1,
                        "named open return lacks its path clause")
                call.update(return_index=index, return_words=list(words), outcome="provider-return-observed")
                self.append_call(call)
                del self.pending[tid]
            return
        if kind == 18:
            target = self.process(raw["detail"])
            require(raw["tid"] in self.threads and self.threads[raw["tid"]]["pid"] == raw["detail"]
                    and self.threads[raw["tid"]]["closed"],
                    "target exit lacks its observed retired thread identity")
            if words[2] & transport.P_REF_SHADOW:
                # Old-exec shadow cleanup may interleave with a live Mach call.
                return
            require(target["terminal"] is None, "duplicate target process termination")
            require(not any(c["identity"]["pid"] == raw["detail"] for c in self.pending.values()),
                    "unexplained pending call at target process termination")
            owned = [t for t in self.threads.values() if t["pid"] == raw["detail"]]
            require(owned and all(t["closed"] for t in owned), "target process exit without prior observed thread exits")
            target["terminal"] = index
            for call in self.calls:
                if call["identity"]["pid"] == raw["detail"] and call["return_index"] is None:
                    call["termination_indexes"].append(index)
            return
        if kind == 11:
            tid = raw["tid"]
            require(tid in self.threads and self.threads[tid]["pid"] is not None, "unknown exiting thread")
            thread = self.threads[tid]
            require(not thread["closed"] and raw["pid"] in {0, thread["pid"]}, "duplicate or mismatched thread exit")
            if tid in self.pending:
                call = self.pending[tid]
                require(call["family"][0] == "syscall" and call["family"][2] in NONRETURN,
                        "unexplained pending call at thread exit")
                require(call["family"][2] != "exit" or call["exit_context"] is not None,
                        "exit entry lacks matching context-exit record")
                call["termination_indexes"] = ([call["exit_context"]] if call["exit_context"] else []) + [index]
                call["outcome"] = "terminated-without-return"
                self.append_call(call)
                del self.pending[tid]
            thread["closed"] = True
            return
        if kind in {5, 7, 10}:
            process = self.process(raw["pid"])
            if kind == 7:
                require(not any(c["identity"]["pid"] == raw["pid"] for c in self.pending.values()),
                        "unresolved call crosses exec-success")
                require(all(t["closed"] for t in self.threads.values() if t["pid"] == raw["pid"]),
                        "exec-success lacks retirement of prior threads")
                process["epoch"] += 1
            thread = self.bind(raw["pid"], raw["tid"])
            flag = "lwp_start" if kind == 10 else "start" if kind == 5 else None
            if flag:
                require(not thread[flag], "duplicate thread/process start")
                thread[flag] = True
            return
        self.actor(raw)
        if kind == 4:
            require(raw["detail"] not in self.processes and len(self.processes) < 256,
                    "process creation reuses identity or exceeds bound")
            self.processes[raw["detail"]] = {"parent": raw["pid"], "epoch": 0, "terminal": None}
        elif kind == 9:
            self.reserve(raw["detail"], raw["pid"])
        elif kind == 6:
            call = self.pending.get(raw["tid"])
            if call and call["family"] == ["syscall", "", "exit"]:
                require(raw["detail"] == 1 and call["exit_context"] is None, "unmodeled exit context")
                call["exit_context"] = index
            # In failed spawn this is the surviving parent's raw context.
        else:
            require(kind in {8, 12, 13}, "unknown lifecycle route")


def pair_capture(capture, toolkit):
    """Validate matching raw-v4 source/toolkit bytes, then pair opaque call frames."""
    with tempfile.TemporaryFile() as timeline:
        source = transport.inspect_capability(capture, toolkit, timeline)
        require(source["capture_status"] == "captured" and not source["producer_diagnostics"],
                "pairing requires a completed clean transport")
        require(source["host"] == HOST and source["profile"] in {"tree", "tree-mach"},
                "host/profile lacks actual tree-call calibration")
        require(source["fixture"] == "lifecycle-probe", "unreviewed owned fixture")
        require(timeline.tell() <= MAX_TIMELINE_BYTES, "verified timeline exceeds pairing diagnostic byte bound")
        replay = _Pairer(source["observed_processes"][0]["pid"])
        timeline.seek(0)
        for line in timeline:
            replay.take(transport.strict_json(line, "strict-reader timeline"))
        require(replay.began and replay.ended and replay.calls, "incomplete or empty paired timeline")
        calls = sorted(replay.calls, key=lambda call: call["entry_index"])
        for call in calls:
            if call["return_index"] is None:
                require(len(call["termination_indexes"]) >= 2, "unreturned entry lacks complete lifecycle boundary")
            del call["exit_context"]
        return {"revision": 1, "protocol": "darwin-raw-call-pairs-v1", "origin": "source-matched-raw-v4-capture",
                "full_trace_acceptance": False, "calibration_sha256": CALIBRATION,
                "scope": "Opaque provider frames and observed PID/TID lifetimes/exec epochs only; no attested kernel generation, FD/path, call success, mutation or Mach effect verdict.",
                "adapter_sha256": hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),
                "source_transport": source, "calls": calls, "raw_frames": replay.frames}


def require_full_trace_acceptance(_pairs=None):
    raise UnsupportedPairing("raw call pairing cannot satisfy full Darwin R02 acceptance")


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--capture", required=True, type=Path)
    parser.add_argument("--toolkit", required=True, type=Path)
    parser.add_argument("--acceptance", action="store_true")
    args = parser.parse_args(argv)
    try:
        if args.acceptance:
            require_full_trace_acceptance()
        result = pair_capture(args.capture, args.toolkit)
        print(json.dumps(result, separators=(",", ":")))
        return 0
    except (UnsupportedPairing, transport.InvalidCapability, OSError, ValueError) as error:
        print(str(error), file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
