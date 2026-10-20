#!/usr/bin/env python3
"""Strict synthetic mapping units; never a native or extraction acceptance API."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import stat
import sys

PROTOCOL = "darwin-normalized-mapping-unit-v1"
MAX_RECORDS, MAX_INPUT_BYTES, MAX_LINE_BYTES = 50000, 8 * 1024 * 1024, 65536
MAX_PROCESSES, MAX_BACKINGS, MAX_CALLS = 64, 4096, 10000
MAX_FRAGMENTS, MAX_ATTEMPTS = 4096, 10000
MAX_ATTEMPT_FRAGMENTS, MAX_SNAPSHOT_FRAGMENTS, MAX_HISTORY = 50000, 50000, 50000
MAX_OUTPUT_BYTES, MAX_DECLARATIONS = 32 * 1024 * 1024, 128
U64, I64 = (1 << 64) - 1, (1 << 63) - 1
PROT_NONE, PROT_READ, PROT_WRITE, PROT_EXEC = 0, 1, 2, 4
MAP_SHARED, MAP_PRIVATE, MAP_ANON = 1, 2, 0x1000
TOTALS = ("processes_created", "processes_retired", "backings_declared",
          "calls_entered", "calls_returned", "mappings_requested", "maps_installed",
          "protects_completed", "unmaps_completed", "exec_boundaries",
          "shared_write_attempts")
SCOPE = ("Synthetic declared mapping consistency and requested shared-file write "
         "capability only; no native ABI, object identity, causal order, store, "
         "writeback, coverage or extraction acceptance.")

class MappingError(ValueError):
    def __init__(self, code, message):
        self.code = code
        self.report = None
        super().__init__(code + ": " + message)

def require(condition, message, code="schema"):
    if not condition:
        raise MappingError(code, message)

def keys(value, names):
    require(type(value) is dict and value.keys() == set(names), "exact object keys required")

def integer(value, low=0, high=U64):
    require(type(value) is int and low <= value <= high, "canonical integer outside bound")
    return value

def token(value):
    require(type(value) is str and 1 <= len(value) <= 64 and
            re.fullmatch(r"[A-Za-z][A-Za-z0-9_.-]*", value) is not None,
            "invalid generation/call token")
    return value

def parse_json(raw):
    require(type(raw) is bytes and len(raw) <= MAX_LINE_BYTES, "line bound", "bound")
    def pairs(items):
        result = {}
        for name, value in items:
            require(name not in result, "duplicate JSON key")
            result[name] = value
        return result
    def parse_integer(text):
        require(len(text) <= 21, "integer token bound", "bound")
        return int(text)
    def not_integer(_):
        raise MappingError("schema", "floating/nonfinite JSON is unsupported")
    try:
        return json.loads(raw, object_pairs_hook=pairs, parse_int=parse_integer,
                          parse_float=not_integer, parse_constant=not_integer)
    except MappingError:
        raise
    except (ValueError, UnicodeError, RecursionError) as error:
        raise MappingError("schema", "invalid JSON") from error

def bounded_json(value):
    """Bound allocation while encoding; never build an oversized full JSON string."""
    chunks, size = [], 0
    for chunk in json.JSONEncoder(ensure_ascii=True, separators=(",", ":")).iterencode(value):
        encoded = chunk.encode("ascii")
        size += len(encoded)
        require(size + 1 <= MAX_OUTPUT_BYTES, "serialized output bound", "bound")
        chunks.append(encoded)
    return b"".join(chunks) + b"\n"

def copy_fragment(fragment):
    return dict(fragment)

def clipped(fragment, start, end):
    result = copy_fragment(fragment)
    result["start"], result["end"] = max(start, fragment["start"]), min(end, fragment["end"])
    if result["offset"] is not None:
        result["offset"] += result["start"] - fragment["start"]
    return result

class MappingMachine:
    def __init__(self):
        self.started = self.closed = self.failed = False
        self.index = 0
        self.page_size = None
        self.processes, self.backings = {}, {}
        self.calls, self.mappings = set(), set()
        self.attempts, self.history = [], []
        self.totals = dict.fromkeys(TOTALS, 0)
        self.live_fragments = self.snapshot_fragments = self.attempt_fragments = 0
        self.history_reserved = 0
        self.materialized = False

    def process(self, identity, epoch):
        token(identity); integer(epoch, 0, (1 << 31) - 1)
        require(identity in self.processes and self.processes[identity]["active"],
                "unknown or retired process generation", "lifecycle")
        process = self.processes[identity]
        require(epoch == process["exec"], "stale exec epoch", "lifecycle")
        return process

    def aligned(self, value, low=0, high=U64):
        integer(value, low, high)
        require(value % self.page_size == 0, "unaligned range or offset", "range")
        return value

    def region(self, address, length):
        self.aligned(address, self.page_size)
        self.aligned(length, self.page_size)
        require(length <= U64 - address, "address range overflow", "range")
        return address, address + length

    def budget(self, *, live=None, snapshots=0, attempts=0, attempt_fragments=0, history=0):
        live = self.live_fragments if live is None else live
        require(0 <= live <= MAX_FRAGMENTS, "live fragment bound", "bound")
        # Snapshot and attempt counters charge both stored fragments and one
        # eventual output copy. Live-state output copies need an extra reserve.
        require(self.snapshot_fragments + snapshots + live <= MAX_SNAPSHOT_FRAGMENTS,
                "aggregate snapshot/output fragment bound", "bound")
        require(len(self.attempts) + attempts <= MAX_ATTEMPTS, "attempt bound", "bound")
        require(self.attempt_fragments + attempt_fragments <= MAX_ATTEMPT_FRAGMENTS,
                "aggregate attempt/output fragment bound", "bound")
        require(self.history_reserved + history <= MAX_HISTORY, "history bound", "bound")

    def covered(self, process, start, end):
        """Return existing references only; copying happens after budget checks."""
        selected = [fragment for fragment in process["fragments"]
                    if fragment["start"] < end and start < fragment["end"]]
        cursor = start
        for fragment in selected:
            require(fragment["start"] <= cursor, "range contains unmodeled gap", "range")
            cursor = min(end, fragment["end"])
        require(cursor == end, "range is not completely modeled", "range")
        return selected

    def enter(self, data):
        keys(data, {"process", "exec", "call", "operation", "args"})
        process = self.process(data["process"], data["exec"])
        call = token(data["call"])
        require(process["pending"] is None, "concurrent process request", "pairing")
        require(call not in self.calls and len(self.calls) < MAX_CALLS, "call generation reused/bounded", "bound")
        operation = data["operation"]
        require(type(operation) is str and operation in {"map", "protect", "unmap"},
                "unsupported mapping operation", "unsupported")
        args = data["args"]
        selected, start, end = [], None, None
        if operation == "map":
            keys(args, {"mapping", "address", "length", "prot", "flags", "offset", "backing"})
            mapping = token(args["mapping"])
            require(mapping not in self.mappings, "mapping generation reused", "lifecycle")
            integer(args["address"], 0, 0)
            self.aligned(args["length"], self.page_size)
            integer(args["prot"], 0, 7); integer(args["flags"], 0, (1 << 32) - 1)
            self.aligned(args["offset"], 0, I64)
            require(args["flags"] in {MAP_SHARED, MAP_PRIVATE, MAP_PRIVATE | MAP_ANON},
                    "unsupported mapping flags", "unsupported")
            if args["flags"] == MAP_PRIVATE | MAP_ANON:
                require(args["backing"] is None and args["offset"] == 0,
                        "anonymous backing/offset is unsupported", "unsupported")
            else:
                backing = token(args["backing"])
                require(backing in self.backings, "unknown backing generation", "object")
                require(args["length"] <= I64 - args["offset"], "file offset range overflow", "range")
            shared_count = int(args["flags"] == MAP_SHARED and bool(args["prot"] & PROT_WRITE))
        else:
            keys(args, {"address", "length", "prot"} if operation == "protect" else {"address", "length"})
            if operation == "protect":
                integer(args["prot"], 0, 7)
            start, end = self.region(args["address"], args["length"])
            selected = self.covered(process, start, end)
            shared_count = sum(fragment["flags"] == MAP_SHARED and fragment["backing"] is not None
                               for fragment in selected) if operation == "protect" and args["prot"] & PROT_WRITE else 0
        self.budget(snapshots=2 * len(selected), attempts=int(shared_count > 0),
                    attempt_fragments=2 * shared_count, history=1)
        snapshot = [clipped(fragment, start, end) for fragment in selected]
        attempt = None
        if shared_count:
            fragments = ([{"mapping": args["mapping"], "backing": args["backing"],
                           "start": None, "end": None, "offset": args["offset"],
                           "flags": args["flags"], "prot": args["prot"]}]
                         if operation == "map" else
                         [copy_fragment(fragment) for fragment in snapshot if fragment["flags"] == MAP_SHARED])
            attempt = {"call": call, "entry_index": self.index, "process": data["process"],
                       "exec": data["exec"], "operation": operation, "address": start,
                       "length": args["length"], "prot": args["prot"],
                       "flags": args["flags"] if operation == "map" else None,
                       "fragments": fragments, "outcome": "pending", "result": None, "error": None}
        self.snapshot_fragments += 2 * len(snapshot)
        self.attempt_fragments += 2 * shared_count
        self.history_reserved += 1
        self.calls.add(call)
        if operation == "map":
            self.mappings.add(args["mapping"])
            self.totals["mappings_requested"] += 1
        if attempt is not None:
            self.attempts.append(attempt)
            self.totals["shared_write_attempts"] += 1
        process["pending"] = {"process": data["process"], "exec": data["exec"], "call": call,
                              "operation": operation, "args": dict(args),
                              "entry_index": self.index, "entry_fragments": snapshot, "attempt": attempt}
        self.totals["calls_entered"] += 1

    def returned(self, data):
        keys(data, {"process", "exec", "call", "operation", "result", "error"})
        process = self.process(data["process"], data["exec"])
        pending = process["pending"]
        call = token(data["call"])
        require(type(data["operation"]) is str and pending is not None and
                (call, data["operation"]) == (pending["call"], pending["operation"]),
                "orphan or mismatched mapping return", "pairing")
        operation, args = pending["operation"], pending["args"]
        error = integer(data["error"], 0, (1 << 31) - 1)
        result = data["result"]
        success = error == 0
        if operation == "map":
            if success:
                start, end = self.region(result, args["length"])
            else:
                require(result is None, "failed map must not declare an address")
        else:
            integer(result, -1, 0)
            require((result == 0 and success) or (result == -1 and error > 0),
                    "inconsistent normalized range return")

        output = []
        result_fragments = []
        if success and operation == "map":
            require(all(end <= fragment["start"] or start >= fragment["end"] for fragment in process["fragments"]),
                    "new map overlaps an existing range", "range")
            self.budget(live=self.live_fragments + 1, snapshots=2)
            fragment = {"mapping": args["mapping"], "backing": args["backing"],
                        "start": start, "end": end,
                        "offset": args["offset"] if args["backing"] is not None else None,
                        "flags": args["flags"], "prot": args["prot"]}
            output = sorted(process["fragments"] + [fragment], key=lambda item: item["start"])
            result_fragments = [copy_fragment(fragment)]
        elif success:
            start, end = self.region(args["address"], args["length"])
            selected = self.covered(process, start, end)
            require(len(selected) == len(pending["entry_fragments"]), "pending range changed", "range")
            for fragment, entry in zip(selected, pending["entry_fragments"]):
                low, high = max(start, fragment["start"]), min(end, fragment["end"])
                offset = None if fragment["offset"] is None else fragment["offset"] + low - fragment["start"]
                require(all(entry[key] == fragment[key] for key in ("mapping", "backing", "flags", "prot")) and
                        (entry["start"], entry["end"], entry["offset"]) == (low, high, offset),
                        "pending range changed", "range")
            new_count = len(process["fragments"])
            for fragment in selected:
                pieces = int(fragment["start"] < start) + int(end < fragment["end"]) + int(operation == "protect")
                new_count += pieces - 1
            result_count = len(selected) if operation == "protect" else 0
            self.budget(live=self.live_fragments - len(process["fragments"]) + new_count,
                        snapshots=2 * result_count)
            for fragment in process["fragments"]:
                if fragment["end"] <= start or fragment["start"] >= end:
                    output.append(fragment)
                    continue
                if fragment["start"] < start:
                    output.append(clipped(fragment, fragment["start"], start))
                if operation == "protect":
                    middle = clipped(fragment, start, end)
                    middle["prot"] = args["prot"]
                    output.append(middle)
                    result_fragments.append(copy_fragment(middle))
                if end < fragment["end"]:
                    output.append(clipped(fragment, end, fragment["end"]))

        attempt = pending["attempt"]
        if attempt is not None:
            attempt.update(outcome="success" if success else "failed", result=result, error=error)
            if success and operation == "map":
                attempt["address"] = start
                attempt["fragments"][0].update(start=start, end=end)
        self.history.append({key: pending[key] for key in
                             ("process", "exec", "call", "operation", "args", "entry_index", "entry_fragments")} |
                            {"return_index": self.index, "outcome": "success" if success else "failed",
                             "result": result, "error": error, "result_fragments": result_fragments})
        self.totals["calls_returned"] += 1
        process["pending"] = None
        if not success:
            if operation != "map":
                raise MappingError("ambiguous-effect", "failed range transition has unknown effects")
            return
        self.snapshot_fragments += 2 * len(result_fragments)
        self.live_fragments += len(output) - len(process["fragments"])
        process["fragments"] = output
        self.totals[{"map": "maps_installed", "protect": "protects_completed",
                     "unmap": "unmaps_completed"}[operation]] += 1

    def apply(self, event, data):
        if event == "start":
            keys(data, {"page_size"})
            require(not self.started and self.index == 1, "start must be first and unique", "lifecycle")
            integer(data["page_size"])
            require(data["page_size"] in {4096, 16384}, "unsupported model page size", "unsupported")
            self.page_size = data["page_size"]; self.started = True
            return
        require(self.started, "missing start", "lifecycle")
        if event == "process":
            keys(data, {"process", "pid", "exec"})
            identity = token(data["process"]); integer(data["pid"], 1, (1 << 31) - 1)
            integer(data["exec"], 0, 0)
            require(identity not in self.processes and len(self.processes) < MAX_PROCESSES,
                    "process generation reused/bounded", "bound")
            require(not any(value["active"] and value["pid"] == data["pid"] for value in self.processes.values()),
                    "PID reused while live", "lifecycle")
            self.processes[identity] = {"pid": data["pid"], "exec": 0, "active": True,
                                       "fragments": [], "pending": None}
            self.totals["processes_created"] += 1
        elif event == "backing":
            keys(data, {"backing", "kind"})
            identity = token(data["backing"])
            require(type(data["kind"]) is str and data["kind"] == "regular", "unsupported backing kind", "object")
            require(identity not in self.backings and len(self.backings) < MAX_BACKINGS,
                    "backing generation reused/bounded", "bound")
            self.backings[identity] = "regular"
            self.totals["backings_declared"] += 1
        elif event == "enter":
            self.enter(data)
        elif event == "returned":
            self.returned(data)
        elif event == "exec":
            keys(data, {"process", "exec", "new_exec"})
            process = self.process(data["process"], data["exec"])
            integer(data["new_exec"], 1, (1 << 31) - 1)
            require(data["new_exec"] == process["exec"] + 1 and not process["fragments"] and process["pending"] is None,
                    "unsupported exec boundary with mappings/pending call or epoch gap", "lifecycle")
            self.budget(history=1)
            self.history_reserved += 1
            self.history.append({"operation": "exec", **data})
            process["exec"] = data["new_exec"]
            self.totals["exec_boundaries"] += 1
        elif event == "retire":
            keys(data, {"process", "exec", "mappings"})
            process = self.process(data["process"], data["exec"])
            names = data["mappings"]
            require(type(names) is list and len(names) <= MAX_FRAGMENTS, "retirement list bound", "bound")
            for name in names:
                token(name)
            require(len(set(names)) == len(names) and set(names) == {f["mapping"] for f in process["fragments"]},
                    "retirement must name exact distinct mapping generations", "lifecycle")
            require(process["pending"] is None, "retirement with pending request", "pairing")
            count = len(process["fragments"])
            self.budget(live=self.live_fragments - count, snapshots=2 * count, history=1)
            snapshot = [copy_fragment(fragment) for fragment in process["fragments"]]
            self.snapshot_fragments += 2 * count
            self.history_reserved += 1
            self.history.append({"operation": "retire", "process": data["process"], "exec": data["exec"],
                                 "mappings": list(names), "entry_fragments": snapshot})
            self.live_fragments -= count
            process["fragments"] = []
            process["active"] = False
            self.totals["processes_retired"] += 1
        elif event == "finish":
            keys(data, {"records", "totals"})
            integer(data["records"], 1, MAX_RECORDS)
            keys(data["totals"], TOTALS)
            for value in data["totals"].values():
                integer(value, 0, MAX_RECORDS)
            require(data["records"] == self.index and data["totals"] == self.totals,
                    "footer counts differ", "incomplete")
            require(all(not p["active"] and p["pending"] is None for p in self.processes.values()),
                    "unretired process or pending request at footer", "incomplete")
            self.closed = True
        else:
            raise MappingError("unsupported", "unknown mapping unit event")

    def feed(self, record):
        try:
            require(not self.failed, "machine already poisoned", "incomplete")
            require(not self.closed, "record after footer", "incomplete")
            require(self.index < MAX_RECORDS, "record bound", "bound")
            keys(record, {"revision", "protocol", "origin", "index", "event", "data"})
            integer(record["revision"], 1, 1)
            require(type(record["protocol"]) is str and record["protocol"] == PROTOCOL and
                    type(record["origin"]) is str and record["origin"] == "synthetic-unit",
                    "unsupported protocol/origin", "unsupported")
            integer(record["index"], 1, MAX_RECORDS)
            require(record["index"] == self.index + 1, "index gap", "pairing")
            require(type(record["event"]) is str, "event must be a string")
            self.index += 1
            self.apply(record["event"], record["data"])
        except MappingError:
            self.failed = True
            raise

    def _report(self, error=None, input_info=None):
        require(not self.materialized, "report already materialized", "incomplete")
        if error is None:
            require(self.closed and not self.failed, "missing or poisoned footer", "incomplete")
            status = "synthetic-mapping-unit-closed"
        else:
            require(self.failed and isinstance(error, MappingError), "poisoned mapping error required")
            status = "rejected-incomplete-synthetic-prefix"
        if input_info is not None:
            keys(input_info, {"sha256", "bytes", "scope"})
            scope = input_info["scope"]
            require(type(scope) is str and scope in {"complete-input", "consumed-prefix"},
                    "invalid input digest scope")
            digest = input_info["sha256"]
            require(type(digest) is str and re.fullmatch(r"[0-9a-f]{64}", digest) is not None,
                    "invalid input digest")
            maximum = MAX_INPUT_BYTES if scope == "complete-input" else MAX_INPUT_BYTES + MAX_LINE_BYTES + 1
            integer(input_info["bytes"], 0, maximum)
        # All internal fragment copies reserve this single output copy at entry.
        self.budget()
        result = {"revision": 1, "protocol": PROTOCOL, "origin": "synthetic-unit",
                  "status": status, "full_trace_acceptance": False, "scope": SCOPE,
                  "records": self.index, "page_size": self.page_size,
                  "totals": dict(self.totals), "attempts": [], "history": [],
                  "processes": {}, "backings": dict(self.backings),
                  "bounds_usage": {"live_fragments": self.live_fragments,
                                   "snapshot_fragment_slots_reserved": self.snapshot_fragments,
                                   "attempt_fragment_slots_reserved": self.attempt_fragments,
                                   "history_records_reserved": self.history_reserved}}
        for attempt in self.attempts:
            result["attempts"].append({**attempt, "fragments": [copy_fragment(f) for f in attempt["fragments"]]})
        for item in self.history:
            out = dict(item)
            for name in ("entry_fragments", "result_fragments"):
                if name in out:
                    out[name] = [copy_fragment(f) for f in out[name]]
            if "args" in out:
                out["args"] = dict(out["args"])
            if "mappings" in out:
                out["mappings"] = list(out["mappings"])
            result["history"].append(out)
        for identity, process in self.processes.items():
            pending = process["pending"]
            out = {key: process[key] for key in ("pid", "exec", "active")}
            out["fragments"] = [copy_fragment(f) for f in process["fragments"]]
            out["pending"] = None if pending is None else {
                **{key: pending[key] for key in ("process", "exec", "call", "operation", "entry_index")},
                "args": dict(pending["args"]),
                "entry_fragments": [copy_fragment(f) for f in pending["entry_fragments"]]}
            result["processes"][identity] = out
        if error is not None:
            result["error"] = {"code": error.code, "message": str(error)}
            result["state_authoritative"] = False
            result["diagnostic_prefix_only"] = True
        if input_info is not None:
            result["input"] = dict(input_info)
        bounded_json(result)
        self.materialized = True
        return result

    def finish(self, input_info=None):
        require(self.closed and not self.failed, "missing or poisoned footer", "incomplete")
        return self._report(input_info=input_info)

    def rejection(self, error, input_info=None):
        self.failed = True
        require(isinstance(error, MappingError), "mapping error required")
        return self._report(error, input_info)

def require_full_trace_acceptance(_value=None):
    raise MappingError("unsupported", "synthetic mapping units cannot satisfy Darwin R02 acceptance")

def replay(path):
    machine, checksum, size = MappingMachine(), hashlib.sha256(), 0
    complete = False
    try:
        descriptor = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
        with os.fdopen(descriptor, "rb") as stream:
            before = os.fstat(stream.fileno())
            require(stat.S_ISREG(before.st_mode) and before.st_nlink == 1 and
                    0 < before.st_size <= MAX_INPUT_BYTES, "bounded singly linked regular input required", "bound")
            while True:
                line = stream.readline(MAX_LINE_BYTES + 1)
                if not line:
                    complete = True
                    break
                size += len(line); checksum.update(line)
                require(size <= MAX_INPUT_BYTES and len(line) <= MAX_LINE_BYTES and line.endswith(b"\n"),
                        "input bound or truncated line", "bound")
                machine.feed(parse_json(line))
            after = os.fstat(stream.fileno())
            require((before.st_dev, before.st_ino, before.st_nlink, before.st_size, before.st_mtime_ns, before.st_ctime_ns) ==
                    (after.st_dev, after.st_ino, after.st_nlink, after.st_size, after.st_mtime_ns, after.st_ctime_ns),
                    "input changed while reading", "incomplete")
        return machine.finish({"sha256": checksum.hexdigest(), "bytes": size, "scope": "complete-input"})
    except (OSError, TypeError, ValueError) as cause:
        if isinstance(cause, MappingError):
            error = cause
        else:
            error = MappingError("input", "input could not be read")
        # A failed output encoder can otherwise retain a full provisional
        # report through traceback frames while constructing the rejection.
        error.__traceback__ = None
        error.__context__ = None
        error.__cause__ = None
    info = {"sha256": checksum.hexdigest(), "bytes": size,
            "scope": "complete-input" if complete else "consumed-prefix"}
    try:
        error.report = machine.rejection(error, info)
    except MappingError:
        # If serialization itself fails, never emit an oversized/partial ledger
        # as a complete diagnostic. The bounded minimal error remains explicit.
        error.report = {"revision": 1, "protocol": PROTOCOL, "origin": "synthetic-unit",
                        "status": "rejected-diagnostic-bound", "full_trace_acceptance": False,
                        "scope": SCOPE, "diagnostic_prefix_only": True,
                        "attempt_ledger_omitted": True, "input": info,
                        "error": {"code": error.code, "message": str(error)}}
    raise error

def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--input", required=True, type=Path)
    parser.add_argument("--acceptance", action="store_true")
    args = parser.parse_args(argv)
    try:
        if args.acceptance:
            require_full_trace_acceptance()
        sys.stdout.buffer.write(bounded_json(replay(args.input)))
        return 0
    except MappingError as error:
        diagnostic = error.report or {"revision": 1, "protocol": PROTOCOL, "origin": "synthetic-unit",
                                     "status": "rejected", "full_trace_acceptance": False,
                                     "scope": SCOPE, "error": {"code": error.code, "message": str(error)}}
        try:
            encoded = bounded_json(diagnostic)
        except MappingError:
            encoded = b'{"status":"rejected-output-bound","full_trace_acceptance":false}\n'
            if len(encoded) > MAX_OUTPUT_BYTES:
                encoded = b""
        sys.stderr.buffer.write(encoded)
        return 1

if __name__ == "__main__":
    raise SystemExit(main())
