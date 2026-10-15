#!/usr/bin/env python3
"""Strict normalized open-request unit semantics; never a full Darwin oracle."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import stat
import sys


SOURCE = Path(__file__).resolve().parent
ABI_BYTES = (SOURCE / "abi.json").read_bytes()
ABI = json.loads(ABI_BYTES)
FLAGS = ABI["constants"]
PROTOCOL = "darwin-normalized-open-unit-v1"
KEYS = {"revision", "protocol", "origin", "operation", "flags", "mode", "path_hex", "dirfd", "result", "error"}
MODIFIERS = ("O_NONBLOCK", "O_NOFOLLOW", "O_EXCL", "O_EVTONLY", "O_NOCTTY", "O_DIRECTORY", "O_CLOEXEC", "O_NOFOLLOW_ANY")
MUTATIONS = ("O_APPEND", "O_CREAT", "O_TRUNC")
MODELED = FLAGS["O_ACCMODE"]
for _name in MODIFIERS + MUTATIONS:
    MODELED |= FLAGS[_name]
KNOWN = 0
for _name, _value in FLAGS.items():
    if _name.startswith("O_"):
        KNOWN |= _value


class UnsupportedUnit(ValueError):
    pass


def require(condition, message):
    if not condition:
        raise UnsupportedUnit(message)


def integer(value, lower, upper, name):
    require(type(value) is int and lower <= value <= upper, name + ": canonical integer outside supported bound")


def load_json(raw):
    require(type(raw) is bytes and len(raw) <= 8192, "normalized record exceeds 8 KiB")
    def pairs(items):
        value = {}
        for key, item in items:
            require(key not in value, "duplicate JSON key")
            value[key] = item
        return value
    try:
        return json.loads(raw, object_pairs_hook=pairs,
                          parse_constant=lambda _: (_ for _ in ()).throw(UnsupportedUnit("nonfinite JSON value")))
    except (ValueError, UnicodeError, RecursionError) as error:
        raise UnsupportedUnit("invalid normalized JSON: " + str(error)) from error


def decode(record):
    """Classify supplied C-normalized requests, without interpreting DTrace ABI.

    Result/error are self-reported libc syscall() results or synthetic unit
    values. They validate the schema and never erase attempted write intent.
    No pathname resolution or returned-descriptor provenance is established.
    """
    require(type(record) is dict and record.keys() == KEYS, "exact normalized record keys required")
    require(type(record["revision"]) is int and record["revision"] == 1 and record["protocol"] == PROTOCOL, "unsupported normalized protocol")
    require(type(record["origin"]) is str and record["origin"] in {"synthetic-unit", "owned-control-self-report"}, "unsupported record origin")
    require(type(record["operation"]) is str and record["operation"] in {"open", "openat"}, "unsupported operation; variants require separate verified adapters")
    for name, high in (("flags", (1 << 32) - 1), ("mode", (1 << 16) - 1), ("error", (1 << 31) - 1)):
        integer(record[name], 0, high, name)
    integer(record["result"], -1, (1 << 31) - 1, "result")
    require((record["result"] == -1 and record["error"] > 0) or (record["result"] >= 0 and record["error"] == 0), "inconsistent canonical libc result/error")
    if record["operation"] == "open":
        require(record["dirfd"] is None, "open has no dirfd")
    else:
        integer(record["dirfd"], -2, (1 << 31) - 1, "dirfd")
        require(record["dirfd"] != -1, "unsupported negative dirfd")
    path = record["path_hex"]
    require(type(path) is str and 0 < len(path) <= 2046 and len(path) % 2 == 0 and re.fullmatch("[0-9a-f]+", path), "bounded path bytes must be lowercase hex")
    require(b"\0" not in bytes.fromhex(path), "normalized path excludes its C terminator; raw copyinstr needs a verified adapter")
    flags = record["flags"]
    mode = flags & FLAGS["O_ACCMODE"]
    reasons = (["write-access"] if mode in (FLAGS["O_WRONLY"], FLAGS["O_RDWR"]) else [])
    reasons += [name for name in MUTATIONS if flags & FLAGS[name]]
    unmodeled = flags & ~MODELED
    unknown = flags & ~KNOWN
    unsupported_names = [name for name, value in FLAGS.items() if name.startswith("O_") and value & unmodeled and value & (value - 1) == 0]
    if mode == FLAGS["O_ACCMODE"] or unmodeled or (flags & FLAGS["O_EVTONLY"] and mode != FLAGS["O_RDONLY"]):
        intent, policy = "unsupported", "reject-unsupported"
    elif reasons:
        intent, policy = "write-request", "reject-write-intent"
    elif flags & FLAGS["O_EVTONLY"]:
        intent, policy = "event-access-request", "intent-only-no-acceptance"
    else:
        intent, policy = "read-access-request", "intent-only-no-acceptance"
    return {"revision": 1, "protocol": "darwin-open-intent-decision-v1", "origin": record["origin"],
            "operation": record["operation"], "intent": intent, "no_output_policy": policy,
            "write_reasons": reasons, "unmodeled_bits": unmodeled, "unknown_bits": unknown,
            "unmodeled_sdk_flags": unsupported_names, "raw_normalized_request": record,
            "abi_sha256": hashlib.sha256(ABI_BYTES).hexdigest(), "full_trace_acceptance": False,
            "scope": "Request intent only; no raw trace ABI, pathname/object, returned-FD, lifecycle or coverage proof."}


def decode_capability(_event):
    raise UnsupportedUnit("raw capability arguments have no calibrated normalized adapter; full trace acceptance is rejected")


def require_full_trace_acceptance(_decisions=None):
    raise UnsupportedUnit("normalized open units cannot satisfy full Darwin R02 trace acceptance")


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--input", required=True, type=Path, help="bounded JSONL of normalized unit records")
    parser.add_argument("--acceptance", action="store_true", help="always rejects normalized unit records")
    args = parser.parse_args(argv)
    try:
        if args.acceptance:
            require_full_trace_acceptance()
        count, size = 0, 0
        decisions = []
        descriptor = os.open(args.input, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
        with os.fdopen(descriptor, "rb") as stream:
            facts = os.fstat(stream.fileno())
            require(stat.S_ISREG(facts.st_mode) and facts.st_nlink == 1 and facts.st_size <= 1024 * 1024, "unit input must be a bounded, unlinked regular file")
            while line := stream.readline(8193):
                count += 1
                size += len(line)
                require(count <= 256 and size <= 1024 * 1024 and len(line) <= 8192 and line.endswith(b"\n"), "unit input bound or truncated JSONL")
                decisions.append(decode(load_json(line)))
        require(count > 0, "empty normalized unit input")
        print(json.dumps({"revision": 1, "decisions": decisions, "full_trace_acceptance": False}, sort_keys=True, indent=2))
        return 1 if any(d["intent"] == "unsupported" for d in decisions) else 0
    except (UnsupportedUnit, OSError) as error:
        print("normalized open unit rejected: " + str(error), file=sys.stderr)
        return 1


if __name__ == "__main__":
    sys.exit(main())
