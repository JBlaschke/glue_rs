#!/usr/bin/env python3
"""Bounded synthetic normalized state units, never native Darwin acceptance."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import stat
import sys


PROTOCOL = "darwin-normalized-state-unit-v1"
MAX_EVENTS, MAX_CALLS, MAX_OBJECTS = 50000, 10000, 4096
MAX_PROCESSES, MAX_THREADS, MAX_FDS = 64, 256, 1024
MAX_LINE, MAX_BYTES, MAX_FD = 65536, 8 * 1024 * 1024, 1048575
TOTALS = {"processes_created", "processes_exited", "threads_created", "threads_exited", "calls_entered", "calls_returned", "calls_abandoned"}
UNSET = object()


class StateError(ValueError):
    def __init__(self, code, message):
        self.code = code
        super().__init__(code + ": " + message)


def require(condition, message, code="schema"):
    if not condition:
        raise StateError(code, message)


def keys(value, names):
    require(type(value) is dict and value.keys() == set(names), "exact object keys required")


def number(value, low=0, high=(1 << 31) - 1):
    require(type(value) is int and low <= value <= high, "canonical integer outside bound")
    return value


def token(value):
    require(type(value) is str and len(value) <= 64 and re.fullmatch(r"[A-Za-z][A-Za-z0-9_.-]*", value), "invalid generation/object/call token")
    return value


def boolean(value):
    require(type(value) is bool, "boolean required")
    return value


def parse_json(line):
    require(type(line) is bytes and len(line) <= MAX_LINE, "record bound exceeded", "bound")
    def pairs(items):
        result = {}
        for name, value in items:
            require(name not in result, "duplicate JSON key")
            result[name] = value
        return result
    try:
        return json.loads(line, object_pairs_hook=pairs,
                          parse_constant=lambda _: (_ for _ in ()).throw(StateError("schema", "nonfinite JSON value")))
    except (ValueError, UnicodeError, RecursionError) as error:
        raise StateError("schema", "invalid normalized JSON: " + str(error)) from error


class StateMachine:
    """Replay an explicitly ordered unit model, not a source of kernel facts.

    All identities, object kinds, effect ordering and libc-normalized results
    must already be supplied. No current raw/capability format can provide them.
    An error poisons the instance; continuing after incomplete input is forbidden.
    """
    def __init__(self):
        self.processes, self.threads, self.objects = {}, {}, {}
        self.call_ids, self.history, self.write_attempts, self.edges = set(), [], [], []
        self.totals = dict.fromkeys(TOTALS, 0)
        self.index, self.serial, self.peak_fds, self.peak_processes = 0, 0, 0, 0
        self.started = self.closed = self.failed = False

    def object(self, identity, kind=None):
        identity = token(identity)
        require(identity in self.objects, "unknown object identity", "object")
        require(kind is None or self.objects[identity] == kind, "object kind is unsupported for operation", "object")
        return identity

    def declare_object(self, definition, initial=False):
        keys(definition, {"id", "kind"})
        identity = token(definition["id"])
        allowed = {"regular", "directory", "stdio-sink", "anonymous-pipe"} if initial else {"regular", "directory"}
        require(type(definition["kind"]) is str and definition["kind"] in allowed, "unknown or unauthorized object kind", "object")
        require(identity not in self.objects, "object token reused", "object")
        require(len(self.objects) < MAX_OBJECTS, "object bound exceeded", "bound")
        self.objects[identity] = definition["kind"]

    def process(self, identity, epoch=UNSET):
        identity = token(identity)
        require(identity in self.processes and self.processes[identity]["active"], "unknown or terminated process generation", "lifecycle")
        process = self.processes[identity]
        if epoch is not UNSET:
            number(epoch)
            require(epoch == process["exec"], "stale exec generation", "lifecycle")
        return process

    def thread(self, process_id, identity, epoch):
        process = self.process(process_id, epoch)
        identity = token(identity)
        require(identity in self.threads and self.threads[identity]["active"] and self.threads[identity]["process"] == process_id,
                "unknown, foreign or retired thread generation", "lifecycle")
        return process, self.threads[identity]

    def add_process(self, identity, pid, cwd, fds):
        token(identity); number(pid, 1)
        require(identity not in self.processes, "process token reused", "lifecycle")
        require(not any(p["active"] and p["pid"] == pid for p in self.processes.values()), "PID reused while old generation is active", "lifecycle")
        require(len(self.processes) < MAX_PROCESSES, "process bound exceeded", "bound")
        self.object(cwd, "directory")
        self.serial += 1
        self.processes[identity] = {"pid": pid, "cwd": cwd, "cwd_version": self.serial, "fds": fds,
                                    "fd_versions": {fd: entry["version"] for fd, entry in fds.items()}, "fd_table_version": self.serial,
                                    "exec": 0, "active": True}
        self.totals["processes_created"] += 1
        self.peak_processes = max(self.peak_processes, sum(p["active"] for p in self.processes.values()))

    def add_thread(self, process_id, identity, tid):
        self.process(process_id); token(identity); number(tid, 1, (1 << 64) - 1)
        require(identity not in self.threads, "thread generation token reused", "lifecycle")
        require(not any(t["active"] and t["tid"] == tid for t in self.threads.values()), "thread ID reused while active", "lifecycle")
        require(len(self.threads) < MAX_THREADS, "thread bound exceeded", "bound")
        self.threads[identity] = {"process": process_id, "tid": tid, "cwd": None, "cwd_version": 0, "pending": None, "active": True}
        self.totals["threads_created"] += 1

    def binding(self, process, fd):
        number(fd, 0, MAX_FD)
        require(fd in process["fds"], "descriptor has no tracked object", "fd")
        return dict(process["fds"][fd])

    def install(self, process, fd, identity, cloexec, replace=False):
        number(fd, 0, MAX_FD); self.object(identity); boolean(cloexec)
        require(replace or fd not in process["fds"], "returned descriptor already exists", "fd")
        require(fd in process["fds"] or len(process["fds"]) < MAX_FDS, "descriptor bound exceeded", "bound")
        self.serial += 1
        process["fds"][fd] = {"object": identity, "cloexec": cloexec, "version": self.serial}
        process["fd_versions"][fd] = self.serial
        process["fd_table_version"] = self.serial
        self.peak_fds = max(self.peak_fds, len(process["fds"]))

    def remove(self, process, fd):
        del process["fds"][fd]
        self.serial += 1
        process["fd_versions"][fd] = self.serial  # retain absence/change history
        process["fd_table_version"] = self.serial

    def effective_cwd(self, process, thread):
        return thread["cwd"] if thread["cwd"] is not None else process["cwd"]

    def cwd_snapshot(self, process, thread):
        return {"object": self.effective_cwd(process, thread), "thread_version": thread["cwd_version"],
                "process_version": process["cwd_version"] if thread["cwd"] is None else None}

    def enter(self, data):
        keys(data, {"process", "thread", "exec", "call", "operation", "args"})
        process, thread = self.thread(data["process"], data["thread"], data["exec"])
        call = token(data["call"])
        require(thread["pending"] is None and call not in self.call_ids, "overlapping or reused call identity", "pairing")
        require(len(self.call_ids) < MAX_CALLS, "call bound exceeded", "bound")
        operation, args = data["operation"], data["args"]
        require(type(operation) is str and operation in {"fd-open", "fd-close", "fd-dup", "fd-dup2", "fd-flags", "read", "write", "cwd-set", "cwd-from-fd", "thread-cwd-set", "fork-parent", "exec"}, "unknown normalized operation", "unsupported")
        pending = {"call": call, "process": data["process"], "thread": data["thread"], "exec": data["exec"], "operation": operation,
                   "binding": None, "anchor": None, "anchor_binding": None, "cwd_binding": None, "entry_version": self.serial}
        if operation == "fd-open":
            keys(args, {"path_hex", "dirfd", "cloexec"}); boolean(args["cloexec"])
            path = args["path_hex"]
            require(type(path) is str and 0 < len(path) <= 2046 and len(path) % 2 == 0 and re.fullmatch("[0-9a-f]+", path), "bounded normalized pathname bytes required")
            raw = bytes.fromhex(path); require(b"\0" not in raw, "normalized path excludes terminator")
            if args["dirfd"] is not None:
                number(args["dirfd"], -2, MAX_FD); require(args["dirfd"] != -1, "unsupported negative dirfd", "cwd")
            if not raw.startswith(b"/"):
                if args["dirfd"] is None or args["dirfd"] == -2:
                    pending["cwd_binding"] = self.cwd_snapshot(process, thread)
                    pending["anchor"] = pending["cwd_binding"]["object"]
                else:
                    pending["anchor_binding"] = self.binding(process, args["dirfd"])
                    pending["anchor"] = pending["anchor_binding"]["object"]
                    self.object(pending["anchor"], "directory")
        elif operation in {"fd-close", "cwd-from-fd"}:
            keys(args, {"fd"}); pending["binding"] = self.binding(process, args["fd"])
            if operation == "cwd-from-fd": self.object(pending["binding"]["object"], "directory")
        elif operation in {"fd-dup", "fd-dup2"}:
            keys(args, {"source"} if operation == "fd-dup" else {"source", "target"})
            pending["binding"] = self.binding(process, args["source"])
            if operation == "fd-dup2": number(args["target"], 0, MAX_FD)
        elif operation == "fd-flags":
            keys(args, {"fd", "cloexec"}); boolean(args["cloexec"])
            pending["binding"] = self.binding(process, args["fd"])
        elif operation in {"read", "write"}:
            keys(args, {"fd", "bytes"}); number(args["bytes"], 0, 1 << 30)
            pending["binding"] = self.binding(process, args["fd"])
            if operation == "write":
                identity = pending["binding"]["object"]
                self.write_attempts.append({"call": call, "process": data["process"], "object": identity, "kind": self.objects[identity], "bytes": args["bytes"],
                                            "unit_intent": "filesystem-attempt" if self.objects[identity] in {"regular", "directory"} else "declared-sink-or-anonymous-pipe"})
        elif operation in {"cwd-set", "thread-cwd-set"}:
            keys(args, {"object"})
            if operation == "cwd-set" or args["object"] is not None: self.object(args["object"], "directory")
        else:
            keys(args, set())
            if operation == "fork-parent":
                pending["fork_fd_version"] = process["fd_table_version"]
                pending["fork_cwd_version"] = process["cwd_version"]
        pending["args"] = dict(args)  # all supported argument values are scalars
        self.call_ids.add(call); thread["pending"] = pending
        self.totals["calls_entered"] += 1

    def returned(self, data):
        keys(data, {"process", "thread", "exec", "call", "value", "error", "object"})
        process, thread = self.thread(data["process"], data["thread"], data["exec"])
        pending = thread["pending"]
        require(pending is not None and token(data["call"]) == pending["call"], "orphan or mismatched return", "pairing")
        value, error = number(data["value"], -1, (1 << 31) - 1), number(data["error"])
        require((value == -1 and error > 0) or (value >= 0 and error == 0), "canonical result/error inconsistent")
        operation, args, binding = pending["operation"], pending["args"], pending["binding"]
        if operation != "fd-open" or value == -1:
            require(data["object"] is None, "unexpected returned object identity")
        if operation == "fd-close" and value == -1:
            raise StateError("unsupported", "close-on-error descriptor state is not inferred")
        if operation in {"fd-dup", "fd-dup2", "read", "write", "cwd-from-fd"}:
            source = args["source"] if operation in {"fd-dup", "fd-dup2"} else args["fd"]
            require(self.binding(process, source) == binding,
                    "source descriptor changed during pending operation; kernel lookup identity is unobserved", "fd")
        if operation == "fd-dup2":
            require(process["fd_versions"].get(args["target"], 0) <= pending["entry_version"],
                    "destination descriptor changed during pending allocation or dup2", "fd")
        if operation == "fd-open":
            if pending["anchor_binding"] is not None:
                require(self.binding(process, args["dirfd"]) == pending["anchor_binding"], "directory anchor changed during pending open", "cwd")
            if pending["cwd_binding"] is not None:
                require(self.cwd_snapshot(process, thread) == pending["cwd_binding"], "effective cwd changed during pending open", "cwd")
        if value >= 0:
            if operation in {"fd-open", "fd-dup", "fd-dup2"}:
                require(process["fd_versions"].get(value, 0) <= pending["entry_version"],
                        "destination descriptor changed during pending allocation or dup2", "fd")
            if operation == "fd-open":
                self.object(data["object"])
                require(self.objects[data["object"]] in {"regular", "directory"}, "open cannot manufacture an authorized sink or pipe", "object")
                self.install(process, value, data["object"], args["cloexec"])
            elif operation in {"fd-close", "fd-flags"}:
                require(value == 0, "operation requires canonical zero success")
                require(self.binding(process, args["fd"]) == binding, "descriptor changed during pending close/flags operation", "fd")
                if operation == "fd-close": self.remove(process, args["fd"])
                else: self.install(process, args["fd"], binding["object"], args["cloexec"], True)
            elif operation in {"fd-dup", "fd-dup2"}:
                if operation == "fd-dup":
                    available = 0
                    while available in process["fds"]: available += 1
                    require(value == available, "dup did not return the lowest unused descriptor in the normalized order", "fd")
                if operation == "fd-dup2": require(value == args["target"], "dup2 returned a different descriptor", "fd")
                if operation == "fd-dup2" and args["source"] == args["target"]:
                    require(self.binding(process, value) == binding, "descriptor changed during same-fd dup2", "fd")
                else: self.install(process, value, binding["object"], False, operation == "fd-dup2")
            elif operation in {"read", "write"}:
                require(value <= args["bytes"], "returned byte count exceeds request")
            elif operation in {"cwd-set", "cwd-from-fd", "thread-cwd-set"}:
                require(value == 0, "cwd operation requires canonical zero success")
                self.serial += 1
                if operation == "thread-cwd-set":
                    thread["cwd"] = args["object"]; thread["cwd_version"] = self.serial
                else:
                    process["cwd"] = binding["object"] if operation == "cwd-from-fd" else args["object"]
                    process["cwd_version"] = self.serial
            elif operation == "fork-parent":
                require(pending.get("child") is not None and self.processes[pending["child"]]["pid"] == value, "fork parent result lacks matching normalized child birth", "lifecycle")
            else:
                raise StateError("pairing", "exec success requires its explicit nonreturning lifecycle event")
        elif operation == "fork-parent":
            require(pending.get("child") is None, "failed fork already has a child generation", "lifecycle")
        self.complete_call(thread, "returned", value, error)

    def complete_call(self, thread, outcome, value=None, error=None):
        pending = thread["pending"]
        self.history.append({name: pending[name] for name in ("call", "process", "thread", "exec", "operation", "binding", "anchor")} | {"outcome": outcome, "value": value, "error": error})
        thread["pending"] = None
        self.totals["calls_returned" if outcome == "returned" else "calls_abandoned"] += 1

    def retire_threads(self, process_id, calls, reason, single=None):
        require(type(calls) is list and len(calls) <= MAX_THREADS, "abandonment list bound")
        for call in calls: token(call)
        require(len(set(calls)) == len(calls), "duplicate abandoned call", "pairing")
        threads = [t for name, t in self.threads.items() if t["active"] and t["process"] == process_id and (single is None or name == single)]
        expected = {t["pending"]["call"] for t in threads if t["pending"] is not None}
        require(set(calls) == expected, "explicit abandoned calls do not match pending operations", "pairing")
        for thread in threads:
            if thread["pending"] is not None: self.complete_call(thread, reason)
            thread["active"] = False
            self.totals["threads_exited"] += 1

    def apply(self, event, data):
        if event == "start":
            require(not self.started, "duplicate unit start", "lifecycle")
            keys(data, {"process", "pid", "thread", "tid", "objects", "cwd", "fds"})
            require(type(data["objects"]) is list and 1 <= len(data["objects"]) <= 128, "initial object bound", "bound")
            for definition in data["objects"]: self.declare_object(definition, True)
            self.add_process(data["process"], data["pid"], data["cwd"], {})
            self.add_thread(data["process"], data["thread"], data["tid"])
            require(type(data["fds"]) is list and len(data["fds"]) <= 128, "initial descriptor bound", "bound")
            for descriptor in data["fds"]:
                keys(descriptor, {"fd", "object", "cloexec"})
                self.install(self.processes[data["process"]], descriptor["fd"], descriptor["object"], descriptor["cloexec"])
            self.started = True
        else:
            require(self.started, "missing normalized start", "lifecycle")
            if event == "object-declare":
                keys(data, {"object"}); self.declare_object(data["object"])
            elif event == "thread-start":
                keys(data, {"process", "exec", "thread", "tid"}); self.process(data["process"], data["exec"])
                self.add_thread(data["process"], data["thread"], data["tid"])
            elif event == "call-enter": self.enter(data)
            elif event == "call-return": self.returned(data)
            elif event == "process-fork":
                keys(data, {"parent", "thread", "exec", "call", "child", "pid"})
                process, thread = self.thread(data["parent"], data["thread"], data["exec"])
                call = thread["pending"]
                require(call is not None and call["call"] == token(data["call"]) and call["operation"] == "fork-parent" and "child" not in call, "fork birth lacks unique pending parent-side call", "pairing")
                require(thread["cwd"] is None, "fork with thread cwd override is uncalibrated", "unsupported")
                require(process["fd_table_version"] == call["fork_fd_version"] and process["cwd_version"] == call["fork_cwd_version"],
                        "fork inheritance changed before normalized child birth", "unsupported")
                self.add_process(data["child"], data["pid"], process["cwd"], {fd: dict(binding) for fd, binding in process["fds"].items()})
                call["child"] = data["child"]; self.edges.append([data["parent"], data["child"]])
            elif event == "exec-success":
                keys(data, {"process", "thread", "exec", "call", "new_exec", "new_thread", "new_tid", "abandoned_calls"})
                process, thread = self.thread(data["process"], data["thread"], data["exec"])
                require(thread["pending"] is not None and thread["pending"]["call"] == token(data["call"]) and thread["pending"]["operation"] == "exec", "exec lacks pending call", "pairing")
                require(thread["cwd"] is None, "exec with thread cwd override is uncalibrated", "unsupported")
                require(number(data["new_exec"]) == process["exec"] + 1, "exec epoch must advance exactly once", "lifecycle")
                self.retire_threads(data["process"], data["abandoned_calls"], "abandoned-exec")
                for fd in list(process["fds"]):
                    if process["fds"][fd]["cloexec"]: self.remove(process, fd)
                process["exec"] = data["new_exec"]
                self.add_thread(data["process"], data["new_thread"], data["new_tid"])
            elif event == "thread-exit":
                keys(data, {"process", "thread", "exec", "abandoned_calls"}); self.thread(data["process"], data["thread"], data["exec"])
                self.retire_threads(data["process"], data["abandoned_calls"], "abandoned-thread-exit", data["thread"])
            elif event == "process-exit":
                keys(data, {"process", "exec", "exit_status", "abandoned_calls"}); process = self.process(data["process"], data["exec"])
                number(data["exit_status"], 0, 255)
                self.retire_threads(data["process"], data["abandoned_calls"], "abandoned-process-exit")
                process["active"] = False; process["fds"] = {}; process["exit_status"] = data["exit_status"]
                self.totals["processes_exited"] += 1
            elif event == "finish":
                keys(data, {"records", "totals"}); number(data["records"], 1, MAX_EVENTS); keys(data["totals"], TOTALS)
                for value in data["totals"].values(): number(value, 0, MAX_EVENTS)
                require(data["records"] == self.index and data["totals"] == self.totals, "footer count mismatch", "footer")
                require(not any(p["active"] for p in self.processes.values()) and not any(t["active"] or t["pending"] for t in self.threads.values()), "unit tree or pending calls incomplete", "footer")
                self.closed = True
            else: raise StateError("unsupported", "unknown normalized event")

    def feed(self, record):
        try:
            require(not self.failed, "state instance is poisoned by an earlier error", "incomplete")
            require(not self.closed, "record after final footer", "footer")
            keys(record, {"revision", "protocol", "origin", "index", "event", "data"})
            require(type(record["revision"]) is int and record["revision"] == 1 and record["protocol"] == PROTOCOL and record["origin"] == "synthetic-unit", "only the synthetic normalized unit protocol is supported")
            require(number(record["index"], 1, MAX_EVENTS) == self.index + 1, "unit event index gap or duplicate", "incomplete")
            require(type(record["event"]) is str, "event name must be a string")
            self.index += 1
            self.apply(record["event"], record["data"])
        except StateError:
            self.failed = True
            raise

    def finish(self):
        require(self.closed and not self.failed, "missing or invalid final unit footer", "incomplete")
        return {"revision": 1, "protocol": PROTOCOL, "status": "normalized-unit-closed", "full_trace_acceptance": False,
                "scope": "Synthetic normalized state consistency only; no kernel ABI, observation, event ordering, loss accounting or full coverage proof.",
                "records": self.index, "totals": dict(self.totals), "process_edges": self.edges,
                "peak_fds_per_process": self.peak_fds, "peak_live_processes": self.peak_processes,
                "write_attempts": self.write_attempts, "call_history": self.history}


def require_full_trace_acceptance(_state=None):
    raise StateError("unsupported", "synthetic normalized state units cannot satisfy Darwin R02 acceptance")


def replay(path):
    machine, size, checksum = StateMachine(), 0, hashlib.sha256()
    descriptor = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    with os.fdopen(descriptor, "rb") as stream:
        before = os.fstat(stream.fileno())
        require(stat.S_ISREG(before.st_mode) and before.st_nlink == 1 and 0 < before.st_size <= MAX_BYTES, "bounded singly linked regular unit file required", "bound")
        while line := stream.readline(MAX_LINE + 1):
            size += len(line)
            require(size <= MAX_BYTES and len(line) <= MAX_LINE and line.endswith(b"\n"), "truncated or bounded-out unit stream", "incomplete")
            checksum.update(line); machine.feed(parse_json(line))
        after = os.fstat(stream.fileno())
        require((before.st_size, before.st_mtime_ns, before.st_ctime_ns) == (after.st_size, after.st_mtime_ns, after.st_ctime_ns), "unit file changed while reading", "incomplete")
    report = machine.finish()
    report["input"] = {"size": size, "sha256": checksum.hexdigest()}
    return report


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--input", required=True, type=Path)
    parser.add_argument("--acceptance", action="store_true", help="always rejects synthetic units")
    args = parser.parse_args(argv)
    try:
        if args.acceptance: require_full_trace_acceptance()
        print(json.dumps(replay(args.input), sort_keys=True, indent=2))
        return 0
    except (StateError, OSError) as error:
        print("normalized state rejected: " + str(error), file=sys.stderr)
        return 1


if __name__ == "__main__": sys.exit(main())
