#!/usr/bin/env python3
"""Validate owned Darwin capability transport; never grant R02 acceptance.

This is a source-matched format reader, not a Darwin syscall decoder. Manifest
hashes establish byte identity, not authenticity of a capture or its producer.
"""
import argparse
import contextlib
import hashlib
import json
import math
import os
from pathlib import Path
import re
import stat
import sys
import tempfile


PROTOCOL = "darwin-capability-raw-v3"
SCOPE = "owned diagnostic transport only; no complete process-tree or extraction-oracle acceptance"
EVIDENCE = {"program.d", "events.jsonl", "errors.jsonl", "probes.tsv", "target.stdout", "target.stderr", "watchdog.json"}
TOOLKIT = {"capture-native", "lifecycle-probe", "owned-probe", "input.txt", "prepare-native.sh", "CAPTURE_FORMAT.md"} | {
    stem + suffix for stem in ("capture-native", "lifecycle-probe", "owned-probe") for suffix in (".c", "-build.argv")}
HEADER = {"revision", "protocol", "scope", "status", "reason", "profile", "host", "elapsed_seconds", "root_pid", "root_wait_status", "deadline_seconds", "timed_out", "interrupted_signal", "started", "drained", "events", "drops", "errors", "open_entries", "open_returns", "argv", "processes", "fixture", "collector", "evidence", "identity_checks_passed", "full_trace_acceptance", "settings_changed"}
EVENT = {"event", "cpu", "epid", "probe_id", "kind", "timestamp", "pid", "tid", "detail", "provider", "module", "function", "name", "record_bytes", "header_record_indexes", "records"}
KINDS = {1: "begin", 2: "syscall-entry", 3: "syscall-return", 4: "proc-create", 5: "proc-start", 6: "proc-exit-context", 7: "exec-success", 8: "exec-failure", 9: "lwp-create", 10: "lwp-start", 11: "lwp-exit", 12: "spawn-success", 13: "spawn-failure", 14: "open-path", 15: "mach-entry", 16: "mach-return", 17: "end", 18: "proc-exited-target"}
PROC_NAMES = {4: "create", 5: "start", 6: "exit", 7: "exec-success", 8: "exec-failure", 9: "lwp-create", 10: "lwp-start", 11: "lwp-exit", 12: "spawn-success", 13: "spawn-failure", 18: "exited"}
MAX_EVENTS = 1_000_000
MAX_RAW = 128 * 1024 * 1024
MAX_FILE = 64 * 1024 * 1024
MAX_LINE = 64 * 1024
MAX_ENABLINGS = 8192
UINT64 = (1 << 64) - 1
UINT32 = (1 << 32) - 1
INT_MAX = (1 << 31) - 1
LAYOUT_REASONS = {"event-count", "record-count", "record-bytes", "record-range", "header-kind", "header-pid", "event-output", "probe-layout", "probe-id", "record-action", "record-layout", "header-detail", "header-target"}
SOURCE = Path(__file__).resolve().parent


class InvalidCapability(ValueError):
    """Missing, inconsistent, unsupported or bounded-out capability evidence."""


def require(condition, message):
    if not condition:
        raise InvalidCapability(message)


def keys(value, expected, label):
    require(type(value) is dict and value.keys() == expected, label + ": exact object keys required")


def integer(value, low, high, label):
    require(type(value) is int and low <= value <= high, label + ": integer outside bound")
    return value


def string(value, limit, label, empty=True):
    require(type(value) is str and len(value) <= limit and (empty or value != "") and "\0" not in value,
            label + ": invalid or oversized string")
    require(not any(0xD800 <= ord(c) <= 0xDFFF for c in value), label + ": surrogate string")
    return value


def boolean(value, label):
    require(type(value) is bool, label + ": boolean required")


def strict_json(data, label):
    def pairs(items):
        result = {}
        for name, value in items:
            require(name not in result, label + ": duplicate JSON key")
            result[name] = value
        return result
    try:
        return json.loads(data, object_pairs_hook=pairs,
                          parse_constant=lambda _: (_ for _ in ()).throw(InvalidCapability(label + ": nonfinite JSON number")))
    except (ValueError, UnicodeError, RecursionError) as error:
        raise InvalidCapability(label + ": invalid JSON: " + str(error)) from error


def identity(value, label, maximum=MAX_RAW):
    keys(value, {"size", "sha256"}, label)
    integer(value["size"], 0, maximum, label + ".size")
    require(type(value["sha256"]) is str and re.fullmatch("[0-9a-f]{64}", value["sha256"]), label + ": invalid SHA256")
    return value


def digest(data):
    return {"size": len(data), "sha256": hashlib.sha256(data).hexdigest()}


def open_directory(path):
    """Walk every component through held FDs; no symlink/ancestor race."""
    path = Path(path)
    require(path.is_absolute() and ".." not in path.parts, "directory must be absolute without parent traversal")
    descriptor = os.open("/", os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try:
        for part in path.parts[1:]:
            try:
                child = os.open(part, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=descriptor)
            except OSError as error:
                raise InvalidCapability("directory component is not a real directory: " + str(path)) from error
            os.close(descriptor)
            descriptor = child
        return descriptor
    except BaseException:
        os.close(descriptor)
        raise


class Directory:
    """Read flat evidence through a held directory FD without following links."""
    def __init__(self, path):
        self.path = Path(path)
        self.fd = open_directory(path)
        try:
            names = os.listdir(self.fd)
            require(len(names) <= 128, "directory entry bound exceeded")
            self.names = set(names)
            for name in names:
                facts = os.stat(name, dir_fd=self.fd, follow_symlinks=False)
                require(stat.S_ISREG(facts.st_mode) and facts.st_nlink == 1, "linked or nonregular internal file: " + name)
        except BaseException:
            os.close(self.fd)
            raise

    def close(self):
        os.close(self.fd)

    @contextlib.contextmanager
    def open(self, name, maximum):
        require(type(name) is str and name not in {"", ".", ".."} and "/" not in name and "\\" not in name, "unsafe internal filename")
        descriptor = os.open(name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=self.fd)
        with os.fdopen(descriptor, "rb") as stream:
            before = os.fstat(stream.fileno())
            require(stat.S_ISREG(before.st_mode) and before.st_nlink == 1 and 0 <= before.st_size <= maximum, "file bound/type violation: " + name)
            yield stream
            after = os.fstat(stream.fileno())
            require((before.st_dev, before.st_ino, before.st_size, before.st_mtime_ns, before.st_ctime_ns) ==
                    (after.st_dev, after.st_ino, after.st_size, after.st_mtime_ns, after.st_ctime_ns), "file changed while reading: " + name)

    def read(self, name, maximum):
        with self.open(name, maximum) as stream:
            data = stream.read(maximum + 1)
            require(len(data) <= maximum, "file grew beyond bound: " + name)
            return data

    def hash(self, name, maximum):
        hasher, size = hashlib.sha256(), 0
        with self.open(name, maximum) as stream:
            while block := stream.read(65536):
                size += len(block)
                require(size <= maximum, "file grew beyond bound: " + name)
                hasher.update(block)
        return {"size": size, "sha256": hasher.hexdigest()}


def toolkit_provenance(directory):
    manifest = directory.read("SHA256SUMS", MAX_LINE)
    try:
        lines = manifest.decode("ascii").splitlines()
    except UnicodeError as error:
        raise InvalidCapability("toolkit manifest must be ASCII") from error
    require(manifest.endswith(b"\n") and len(lines) == len(TOOLKIT), "toolkit manifest truncated or wrong entry count")
    declared = {}
    for line in lines:
        match = re.fullmatch(r"([0-9a-f]{64})  (?:\./)?([A-Za-z0-9_.-]+)", line)
        require(match is not None, "unsafe or malformed toolkit manifest entry")
        checksum, name = match.groups()
        require(name in TOOLKIT and name not in declared, "unexpected or duplicate toolkit manifest filename")
        declared[name] = checksum
    require(declared.keys() == TOOLKIT, "toolkit manifest names differ")
    identities = {}
    for name, checksum in declared.items():
        actual = directory.hash(name, MAX_FILE)
        require(actual["sha256"] == checksum, "toolkit hash mismatch: " + name)
        identities[name] = actual
    for stem in ("capture-native", "lifecycle-probe", "owned-probe"):
        name = stem + ".c"
        # Sources alongside this reader are the reviewed producer revision, not
        # sources chosen by the capture. A revised producer needs a new review.
        require(identities[name] == digest((SOURCE / name).read_bytes()), "toolkit source differs from this reader's reviewed producer: " + name)
        arguments = directory.read(stem + "-build.argv", MAX_LINE)
        require(arguments.endswith(b"\0") and 2 <= len(arguments.split(b"\0")) <= 128, "invalid retained build argv")
    return {"manifest": digest(manifest), "files": identities,
            "scope": "matching reviewed source bytes and retained byte identities; not producer or kernel attestation"}


def receipt_header(report):
    keys(report, HEADER, "capability")
    require(report["revision"] == 3 and type(report["revision"]) is int and report["protocol"] == PROTOCOL and report["scope"] == SCOPE, "unsupported capability header")
    require(report["full_trace_acceptance"] is False and report["settings_changed"] is False, "capability cannot assert acceptance or changed settings")
    boolean(report["identity_checks_passed"], "identity_checks_passed")
    require(report["identity_checks_passed"], "producer identity checks failed; transport integrity cannot be established")
    require(type(report["status"]) is str and report["status"] in {"captured", "failed", "unavailable"}, "unknown capture status")
    require(type(report["profile"]) is str and report["profile"] in {"open", "tree", "tree-mach"}, "unknown profile")
    string(report["reason"], 4096, "reason", False)
    keys(report["host"], {"system", "release", "machine", "product_version", "build"}, "host")
    for name, value in report["host"].items():
        string(value, 256, "host." + name, False)
    require(report["host"]["system"] == "Darwin" and report["host"]["machine"] == "arm64", "reader supports only producer's native Darwin arm64 byte format")
    elapsed = report["elapsed_seconds"]
    require(type(elapsed) in {int, float} and 0 <= elapsed <= 120 and math.isfinite(elapsed), "invalid elapsed time")
    integer(report["root_pid"], 1, INT_MAX, "root_pid")
    integer(report["root_wait_status"], 0, INT_MAX, "root_wait_status")
    integer(report["deadline_seconds"], 1, 60, "deadline_seconds")
    integer(report["interrupted_signal"], 0, 128, "interrupted_signal")
    for name in ("timed_out", "started", "drained"):
        boolean(report[name], name)
    for name in ("events", "open_entries", "open_returns"):
        integer(report[name], 0, MAX_EVENTS, name)
    for name in ("drops", "errors"):
        integer(report[name], 0, UINT64, name)
    require(type(report["argv"]) is list and 1 <= len(report["argv"]) <= 256, "argv bound")
    for argument in report["argv"]:
        string(argument, 16384, "argv")
    require(report["argv"][0].startswith("/") and sum(map(len, report["argv"])) <= MAX_LINE, "absolute fixture argv and total bound required")
    require(type(report["processes"]) is list and 1 <= len(report["processes"]) <= 256, "process ledger bound")
    pids = set()
    for process in report["processes"]:
        keys(process, {"pid", "created", "terminal"}, "process")
        integer(process["pid"], 1, INT_MAX, "process.pid")
        require(process["pid"] not in pids, "duplicate process ledger PID")
        pids.add(process["pid"])
        boolean(process["created"], "process.created")
        boolean(process["terminal"], "process.terminal")
    require(report["processes"][0]["pid"] == report["root_pid"] and report["processes"][0]["created"], "root missing from initial ledger")
    identity(report["fixture"], "fixture", MAX_FILE)
    identity(report["collector"], "collector", MAX_FILE)
    keys(report["evidence"], EVIDENCE, "evidence")
    for name, value in report["evidence"].items():
        identity(value, "evidence." + name, MAX_RAW if name == "events.jsonl" else MAX_FILE)


def probe_inventory(data):
    require(not data or data.endswith(b"\n"), "truncated probe inventory")
    result = {}
    try:
        lines = data.decode("ascii").splitlines()
    except UnicodeError as error:
        raise InvalidCapability("probe inventory must be ASCII") from error
    require(len(lines) <= 65536, "probe inventory bound")
    for line in lines:
        parts = line.split("\t")
        require(len(parts) == 5 and re.fullmatch("[1-9][0-9]{0,9}", parts[0]), "malformed probe inventory")
        number = integer(int(parts[0]), 1, (1 << 32) - 1, "probe ID")
        require(number not in result and parts[1] in {"syscall", "proc", "mach_trap"}, "duplicate or unsupported inventory probe")
        for value, bound in zip(parts[1:], (63, 63, 127, 63)):
            string(value, bound, "probe descriptor")
        result[number] = tuple(parts[1:])
    return result


def producer_program(root, profile):
    """Exact text produced by the reviewed write_program, not D evaluation."""
    def header(kind, detail):
        return ("trace((uint64_t)%d); trace((uint64_t)timestamp); trace((uint64_t)pid); "
                "trace((uint64_t)tid); trace((uint64_t)(%s));\n") % (kind, detail)
    tree, mach = profile != "open", profile == "tree-mach"
    result = "#pragma D option quiet\n#pragma D option strsize=1024\nBEGIN { watched[%d]=1; " % root
    result += header(1, "0") + "}\nEND { " + header(17, "0") + "}\n"
    result += "syscall::%s:entry /watched[pid]/ { " % ("" if tree else "open")
    result += header(2, "ppid") + "".join("trace((uint64_t)arg%d); " % i for i in range(8)) + "}\n"
    result += "syscall::%s:return /watched[pid]/ { " % ("" if tree else "open")
    result += header(3, "ppid") + "trace((uint64_t)arg0);trace((uint64_t)arg1);trace((uint64_t)arg2);trace((uint64_t)arg3);trace((uint64_t)errno); }\n"
    result += "syscall::open:entry /watched[pid]/ { " + header(14, "0") + "trace(copyinstr(arg0,1024)); }\n"
    if tree:
        result += "proc:::create /watched[pid]/ { watched[args[0]->pr_pid]=1; " + header(4, "args[0]->pr_pid") + "}\n"
        result += "proc:::start /watched[pid] || watched[ppid]/ { watched[pid]=1; " + header(5, "ppid") + "}\n"
        result += "proc:::exec-success /watched[pid] || watched[ppid]/ { watched[pid]=1; " + header(7, "ppid") + "}\n"
        for name, kind, detail in (("exit", 6, "arg0"), ("exec-failure", 8, "arg0"), ("spawn-success", 12, "0"), ("spawn-failure", 13, "arg0"), ("lwp-create", 9, "args[0]->pr_lwpid"), ("lwp-start", 10, "0"), ("lwp-exit", 11, "0")):
            result += "proc:::%s /watched[pid]/ { " % name + header(kind, detail)
            result += "}\n"
        result += "proc:::exited /watched[args[0]->pr_pid]/ { " + header(18, "args[0]->pr_pid")
        result += "trace((uint64_t)arg1); watched[args[0]->pr_pid]=0; }\n"
    if mach:
        for returning in (False, True):
            result += "mach_trap:::%s /watched[pid]/ { " % ("return" if returning else "entry")
            result += header(16 if returning else 15, "ppid")
            result += "".join("trace((uint64_t)arg%d); " % i for i in range(1 if returning else 8)) + "}\n"
    return result.encode("ascii")


def diagnostic_string(value, limit, label):
    # json_string maps each native byte to a JSON character, not UTF-8 text.
    string(value, limit, label)
    require(all(ord(character) <= 255 for character in value), label + ": outside producer byte alphabet")


def layout_diagnostic(entry):
    """Validate rejected-layout metadata without treating it as event data."""
    keys(entry, {"kind", "reason", "cpu", "epid", "probe_id", "provider", "module", "function", "name", "event", "nrecs", "record_bytes", "header", "records"}, "layout diagnostic")
    require(type(entry["reason"]) is str and entry["reason"] in LAYOUT_REASONS, "unknown layout diagnostic reason")
    integer(entry["cpu"], -(1 << 31), INT_MAX, "diagnostic CPU")
    integer(entry["epid"], 0, UINT32, "diagnostic EPID")
    names = ("provider", "module", "function", "name")
    if entry["probe_id"] is None:
        require(all(entry[name] is None for name in names), "absent diagnostic probe has nonnull names")
    else:
        integer(entry["probe_id"], 0, UINT32, "diagnostic probe ID")
        for name, limit in zip(names, (64, 64, 128, 64)):
            diagnostic_string(entry[name], limit, "diagnostic " + name)
    integer(entry["event"], 1, UINT64, "diagnostic event")
    count = integer(entry["nrecs"], -(1 << 31), INT_MAX, "diagnostic nrecs")
    size = integer(entry["record_bytes"], 0, UINT32, "diagnostic record bytes")
    require(type(entry["header"]) is list and len(entry["header"]) == 5, "diagnostic header must have five values")
    records = entry["records"]
    require(type(records) is list and len(records) == max(0, min(count, 20)), "diagnostic descriptor count differs")
    for record in records:
        keys(record, {"action", "size", "offset", "u64"}, "diagnostic descriptor")
        integer(record["action"], 0, (1 << 16) - 1, "diagnostic descriptor action")
        for name in ("size", "offset"):
            integer(record[name], 0, UINT32, "diagnostic descriptor " + name)
        value = record["u64"]
        if value is not None:
            integer(value, 0, UINT64, "diagnostic descriptor u64")
            require(size <= 8192 and record["size"] == 8 and record["offset"] <= size and
                    record["size"] <= size - record["offset"], "diagnostic value outside bounded eight-byte record")
        # A null data pointer also yields null for an otherwise in-range record.
        # Metadata cannot establish that pointer's availability independently.
    for index, value in enumerate(entry["header"]):
        expected = records[index]["u64"] if index < len(records) else None
        require(type(value) is type(expected) and value == expected, "diagnostic header differs from descriptor values")


def libdtrace_diagnostic(entry):
    keys(entry, {"kind", "operation", "error", "message"}, "libdtrace diagnostic")
    require(type(entry["operation"]) is str and entry["operation"] in {"work", "stop", "drain"}, "unknown libdtrace operation")
    integer(entry["error"], -(1 << 31), INT_MAX, "libdtrace error")
    diagnostic_string(entry["message"], 512, "libdtrace message")


def error_totals(directory, report):
    """Check callback transport counts; setup text has no callback meaning."""
    total_drops, total_errors, size = 0, 0, 0
    diagnostics, last_layout_event = [], 0
    hasher = hashlib.sha256()
    with directory.open("errors.jsonl", MAX_FILE) as stream:
        while line := stream.readline(MAX_LINE + 1):
            size += len(line)
            require(size <= MAX_FILE and len(line) <= MAX_LINE and line.endswith(b"\n"), "error line bound or truncated error stream")
            hasher.update(line)
            if not line.startswith(b"{"):
                require(report["status"] == "unavailable", "literal setup diagnostics only allowed before capture starts")
                try:
                    line.decode("utf-8")
                except UnicodeError as error:
                    raise InvalidCapability("setup diagnostic must be UTF-8") from error
                continue
            entry = strict_json(line, "errors.jsonl")
            require(type(entry) is dict and type(entry.get("kind")) is str, "invalid callback error record")
            if entry["kind"] == "drop":
                keys(entry, {"kind", "cpu", "drop_kind", "drops", "total", "message"}, "drop")
                integer(entry["drop_kind"], 0, INT_MAX, "drop kind")
                integer(entry["drops"], 0, UINT64, "drops")
                integer(entry["total"], 0, UINT64, "drop total")
                total_drops += entry["drops"]
            elif entry["kind"] == "error":
                keys(entry, {"kind", "cpu", "fault", "action", "message"}, "error")
                integer(entry["fault"], -(1 << 31), INT_MAX, "fault")
                integer(entry["action"], -(1 << 31), INT_MAX, "error action")
                total_errors += 1
            elif entry["kind"] in {"layout-error", "libdtrace-error"}:
                require(report["status"] == "failed" and report["started"], "producer diagnostics require a started failed capture")
                require(len(diagnostics) < 16, "producer diagnostic count exceeds sixteen")
                if entry["kind"] == "layout-error":
                    layout_diagnostic(entry)
                    require(last_layout_event < entry["event"] <= report["events"], "diagnostic event outside increasing receipt count")
                    last_layout_event = entry["event"]
                else:
                    libdtrace_diagnostic(entry)
                diagnostics.append(entry)
                continue
            else:
                raise InvalidCapability("unknown callback error kind")
            integer(entry["cpu"], -(1 << 31), INT_MAX, "error CPU")
            string(entry["message"], MAX_LINE, "error message")
    require({"size": size, "sha256": hasher.hexdigest()} == report["evidence"]["errors.jsonl"], "error stream hash mismatch")
    require(total_drops == report["drops"] and total_errors == report["errors"], "callback totals differ from retained error records")
    return diagnostics


def typed_event(event, expected_index, profile, inventory):
    keys(event, EVENT, "event")
    require(integer(event["event"], 1, MAX_EVENTS, "event index") == expected_index, "consumer event index gap or duplicate")
    integer(event["cpu"], 0, INT_MAX, "CPU")
    for name in ("epid", "probe_id"):
        integer(event[name], 1, (1 << 32) - 1, name)
    for name in ("kind", "timestamp", "pid", "tid", "detail"):
        integer(event[name], 0, UINT64, name)
    integer(event["pid"], 0, INT_MAX, "PID")
    kind = event["kind"]
    require(kind in KINDS, "unknown typed event kind")
    for name, bound in (("provider", 63), ("module", 63), ("function", 127), ("name", 63)):
        string(event[name], bound, "event." + name)
    if kind in {1, 17}:
        require(event["provider"] == "dtrace" and event["module"] == "" and event["function"] == "" and event["name"] == ("BEGIN" if kind == 1 else "END") and event["detail"] == 0, "invalid BEGIN/END descriptor")
    else:
        require(inventory.get(event["probe_id"]) == tuple(event[name] for name in ("provider", "module", "function", "name")), "event descriptor not present in retained probe inventory")
        if kind in {2, 3, 14}:
            require(event["provider"] == "syscall" and event["name"] == ("return" if kind == 3 else "entry") and event["function"] != "", "invalid BSD probe descriptor")
            if profile == "open" or kind == 14:
                require(event["function"] == "open", "named-open profile descriptor differs")
        elif kind in PROC_NAMES:
            require(profile != "open" and event["provider"] == "proc" and event["name"] == PROC_NAMES[kind], "invalid proc profile/descriptor")
        else:
            require(profile == "tree-mach" and event["provider"] == "mach_trap" and event["function"] != "" and event["name"] == ("entry" if kind == 15 else "return"), "invalid Mach profile/descriptor")
    if kind in {10, 11, 12, 14}:
        require(event["detail"] == 0, "producer constant detail differs")
    if kind in {4, 18}:
        integer(event["detail"], 1, INT_MAX, "process target detail")
    # Source-matched layout, not a generic skip-zero-record policy. The actual
    # v4 guest observed the BEGIN assignment; other clauses remain candidates
    # that must match this exact transport before they can be inspected.
    leading = kind in {1, 4, 5, 7}
    trailing = kind == 18
    word_count = {2: 13, 3: 10, 15: 13, 16: 6, 18: 6}.get(kind, 5)
    layout = ([(0, 12)] if leading else []) + [(8, 16 + i * 8) for i in range(word_count)]
    if trailing:
        layout.append((0, 64))
    if kind == 14:
        layout.append((1024, 56))
    record_bytes = 1080 if kind == 14 else 16 + word_count * 8
    require(type(event["record_bytes"]) is int and event["record_bytes"] == record_bytes, "probe record byte layout differs")
    header_indexes = list(range(1 if leading else 0, 6 if leading else 5))
    indexes = event["header_record_indexes"]
    require(type(indexes) is list and all(type(index) is int for index in indexes) and indexes == header_indexes, "header record indexes differ from exact clause layout")
    records = event["records"]
    require(type(records) is list and len(records) == len(layout), "typed record count differs from producer program")
    words = []
    for record, (size, offset) in zip(records, layout):
        keys(record, {"action", "size", "offset", "hex"}, "record")
        require(type(record["action"]) is int and record["action"] == 1, "unsupported action (producer uses DTRACEACT_DIFEXPR)")
        require(type(record["size"]) is int and type(record["offset"]) is int and record["size"] == size and record["offset"] == offset, "record size/offset differs from exact clause layout")
        raw = record["hex"]
        require(type(raw) is str and len(raw) == 2 * size and re.fullmatch("[0-9a-f]*", raw), "invalid typed record hex/size")
        if size == 8:
            words.append(int.from_bytes(bytes.fromhex(raw), "little"))
    require(words[:5] == [event[name] for name in ("kind", "timestamp", "pid", "tid", "detail")], "decoded header differs from authoritative raw uint64 records")
    return {"consumer_index": expected_index, "kind_label": KINDS[kind], "raw": event,
            "raw_uint64_after_header": words[5:]}


class _EnablingBindings:
    """Session identity checks after typed_event validates each record.

    This fixed generated program is enabled once. An EPID identifies its probe
    and clause layout throughout that handle; each (kind, probe ID) has exactly
    one generated clause. Call-specific values are deliberately not bindings.
    """
    def __init__(self):
        self.by_epid = {}
        self.by_clause = {}

    def observe(self, event):
        epid = event["epid"]
        clause = event["kind"], event["probe_id"]
        signature = (event["probe_id"], *(event[name] for name in ("provider", "module", "function", "name")),
                     event["kind"], event["record_bytes"], tuple(event["header_record_indexes"]),
                     tuple((record["action"], record["size"], record["offset"]) for record in event["records"]))
        if epid in self.by_epid:
            require(self.by_epid[epid] == signature, "EPID binding changed within capture session")
        require(clause not in self.by_clause or self.by_clause[clause] == epid,
                "generated clause has multiple EPIDs within capture session")
        if epid not in self.by_epid:
            require(len(self.by_epid) < MAX_ENABLINGS, "capture enabling count exceeds diagnostic limit")
            self.by_epid[epid] = signature
            self.by_clause[clause] = epid


def inspect_capability(capture, toolkit, timeline):
    """Validate source-matched bytes and export raw records into a binary stream.

    Successful return describes transport consistency only. A failed/unavailable
    producer may be internally consistent but is never a successful capture.
    """
    with contextlib.closing(Directory(capture)) as evidence, contextlib.closing(Directory(toolkit)) as prepared:
        require(evidence.names == EVIDENCE | {"capability.json"}, "capture directory must contain exactly the protocol's eight regular files")
        provenance = toolkit_provenance(prepared)
        receipt_bytes = evidence.read("capability.json", 1024 * 1024)
        require(receipt_bytes.endswith(b"\n"), "capability footer truncated (missing newline)")
        report = strict_json(receipt_bytes, "capability.json")
        receipt_header(report)
        files = provenance["files"]
        require(report["collector"] == files["capture-native"], "collector identity differs from matching toolkit")
        matching = [name for name in ("owned-probe", "lifecycle-probe") if report["fixture"] == files[name]]
        require(len(matching) == 1, "fixture identity not a unique reviewed owned toolkit fixture")
        for name in EVIDENCE - {"events.jsonl"}:
            require(evidence.hash(name, MAX_FILE) == report["evidence"][name], "evidence hash mismatch: " + name)
        require(report["evidence"]["watchdog.json"]["size"] == 0, "watchdog fired: final receipt is invalid")
        diagnostics = error_totals(evidence, report)
        inventory_bytes = evidence.read("probes.tsv", 8 * 1024 * 1024)
        require(digest(inventory_bytes) == report["evidence"]["probes.tsv"], "probe inventory changed after identity read")
        inventory = probe_inventory(inventory_bytes)
        program = evidence.read("program.d", MAX_LINE)
        require(digest(program) == report["evidence"]["program.d"] and program == producer_program(report["root_pid"], report["profile"]), "program bytes/root/profile differ from reviewed producer")
        totals = {"events": 0, "open_entries": 0, "open_returns": 0, "begin": 0, "end": 0}
        bindings = _EnablingBindings()
        ledger = {report["root_pid"]: {"pid": report["root_pid"], "created": True, "terminal": False}}
        hasher, size = hashlib.sha256(), 0
        def process(pid):
            integer(pid, 1, INT_MAX, "observed ledger PID")
            if pid not in ledger:
                require(len(ledger) < 256, "observed process bound exceeded")
                ledger[pid] = {"pid": pid, "created": False, "terminal": False}
            return ledger[pid]
        with evidence.open("events.jsonl", MAX_RAW) as stream:
            while line := stream.readline(MAX_LINE + 1):
                size += len(line)
                require(size <= MAX_RAW and len(line) <= MAX_LINE and line.endswith(b"\n"), "event line/raw bound or truncated JSONL")
                hasher.update(line)
                totals["events"] += 1
                event = strict_json(line, "events.jsonl")
                exported = typed_event(event, totals["events"], report["profile"], inventory)
                bindings.observe(event)
                kind = event["kind"]
                if kind == 1:
                    totals["begin"] += 1
                if kind == 17:
                    totals["end"] += 1
                if kind == 4:
                    process(event["detail"])["created"] = True
                elif kind in {5, 7}:
                    process(event["pid"])["created"] = True
                elif kind == 18:
                    process(event["detail"])["terminal"] = True
                if event["function"] == "open" and kind in {2, 3}:
                    totals["open_entries" if kind == 2 else "open_returns"] += 1
                timeline.write((json.dumps(exported, separators=(",", ":"), ensure_ascii=True) + "\n").encode())
                require(timeline.tell() <= 2 * MAX_RAW, "exported raw timeline bound exceeded")
        require({"size": size, "sha256": hasher.hexdigest()} == report["evidence"]["events.jsonl"], "evidence hash mismatch: events.jsonl")
        for name in ("events", "open_entries", "open_returns"):
            require(totals[name] == report[name], "receipt total differs from retained events: " + name)
        if report["status"] == "captured":
            require(report["started"] and report["drained"] and not report["timed_out"] and report["interrupted_signal"] == 0 and report["root_wait_status"] == 0 and report["drops"] == 0 and report["errors"] == 0, "captured receipt has failed completion fields")
            require(totals["begin"] == 1 and totals["end"] == 1 and totals["open_entries"] > 0 and totals["open_returns"] > 0, "captured receipt lacks required BEGIN/END/open records")
            require(report["evidence"]["errors.jsonl"]["size"] == 0 and report["evidence"]["watchdog.json"]["size"] == 0, "captured receipt retains errors/watchdog failure")
            if report["profile"] == "open":
                ledger[report["root_pid"]]["terminal"] = True  # producer's actual root wait, not an inferred exit probe
            require(list(ledger.values()) == report["processes"] and all(p["created"] and p["terminal"] for p in ledger.values()), "captured observed ledger/footer inconsistent")
        elif report["status"] == "unavailable":
            require(not report["started"] and not report["drained"] and totals["events"] == 0, "unavailable receipt claims started event capture")
        else:
            require(report["started"], "failed receipt must have started (otherwise unavailable)")
        return {"revision": 3, "protocol": PROTOCOL, "diagnostic": "source-matched raw capability transport integrity",
                "transport_integrity": "consistent", "capture_status": report["status"], "capture_reason": report["reason"],
                "producer_identity_checks_passed": report["identity_checks_passed"],
                "producer_diagnostics": diagnostics,
                "full_trace_acceptance": False, "acceptance_rejection": "This capability format cannot satisfy the R02 full-trace oracle.",
                "scope": "No syscall result, pathname, FD, process generation, mutation or kernel coverage interpretation.",
                "host": report["host"], "profile": report["profile"], "argv": report["argv"], "fixture": matching[0],
                "receipt": digest(receipt_bytes), "toolkit_provenance": provenance,
                "reader": digest(Path(__file__).read_bytes()), "totals": totals, "observed_processes": report["processes"]}


def require_full_trace_acceptance(_summary=None):
    raise InvalidCapability("darwin-capability-raw-v3 is capability-only; R02 full-trace acceptance is unconditionally rejected")


def export_files(path, timeline, encoded):
    """Exclusively create a flat export through held, no-follow directory FDs."""
    parent = open_directory(path.parent)
    target = None
    created = False
    created_names = []
    try:
        os.mkdir(path.name, dir_fd=parent)
        created = True
        target = os.open(path.name, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=parent)
        for name, source in (("timeline.jsonl", timeline), ("summary.json", None)):
            descriptor = os.open(name, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o644, dir_fd=target)
            created_names.append(name)
            with os.fdopen(descriptor, "wb") as output:
                if source is None:
                    output.write(encoded)
                else:
                    source.seek(0)
                    while block := source.read(65536):
                        output.write(block)
    except BaseException:
        if target is not None:
            for name in created_names:
                with contextlib.suppress(OSError):
                    os.unlink(name, dir_fd=target)
        if created:
            # A name that lost O_EXCL may belong to another writer. Preserve it
            # and the nonempty directory rather than deleting foreign content.
            with contextlib.suppress(OSError):
                os.rmdir(path.name, dir_fd=parent)
        raise
    finally:
        if target is not None:
            os.close(target)
        os.close(parent)


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--capture", required=True, type=Path)
    parser.add_argument("--toolkit", required=True, type=Path)
    parser.add_argument("--output", type=Path, help="new absolute export directory (summary.json and timeline.jsonl)")
    parser.add_argument("--acceptance", action="store_true", help="always rejects: this format has no acceptance semantics")
    arguments = parser.parse_args(argv)
    try:
        if arguments.acceptance:
            require_full_trace_acceptance()
        if arguments.output:
            require(arguments.output.is_absolute() and arguments.output.name not in {"", ".", ".."}, "export path must be new and absolute")
            os.close(open_directory(arguments.output.parent))
            require(not os.path.lexists(arguments.output), "export directory already exists")
        with tempfile.TemporaryFile() as timeline:
            summary = inspect_capability(arguments.capture, arguments.toolkit, timeline)
            encoded = (json.dumps(summary, indent=2, sort_keys=True) + "\n").encode()
            if arguments.output:
                export_files(arguments.output, timeline, encoded)
            print(encoded.decode(), end="")
            return 0 if summary["capture_status"] == "captured" else 1
    except (InvalidCapability, OSError) as error:
        print("capability rejected: " + str(error), file=sys.stderr)
        return 1


if __name__ == "__main__":
    sys.exit(main())
