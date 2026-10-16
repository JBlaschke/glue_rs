#!/usr/bin/env python3
"""Observe calibrated owned BSD open frames; never grant extraction acceptance."""
import argparse
import json
from pathlib import Path
import sys
import tempfile

import read_capability as transport


HOST = {"system": "Darwin", "release": "25.6.0", "machine": "arm64",
        "product_version": "26.6.2", "build": "25G83"}
CALIBRATION = "0b2bdbf754a93d9e80886299e5bd82d78eff1d036393568decefd82a5ecc5715"
MAX_CALLS = 4096
UINT64 = (1 << 64) - 1


class UnsupportedObservation(ValueError):
    pass


def require(condition, reason):
    if not condition:
        raise UnsupportedObservation(reason)


def signed_argument(value, bits):
    """The pinned systrace provider sign-extends signed syscall arguments."""
    mask = (1 << bits) - 1
    low = value & mask
    expected = low if low < (1 << (bits - 1)) else low | (UINT64 ^ mask)
    require(value == expected, "noncanonical signed syscall argument")
    return low


def _normalize_call(entry, path, returned):
    """Called only for typed source-matched frames, with no object inference."""
    frames = [entry["raw"], path["raw"], returned["raw"]]
    first, copied, last = frames
    require(first["probe_id"] == copied["probe_id"] and first["epid"] != copied["epid"],
            "copied path is not the separate clause for the same open probe")
    require(first["timestamp"] <= copied["timestamp"] <= last["timestamp"],
            "open phases have inconsistent timestamps")
    arguments = entry["raw_uint64_after_header"]
    require(len(arguments) == 8 and arguments[0] != 0 and arguments[3:] == [0] * 5,
            "unsupported open argument frame")
    flags = signed_argument(arguments[1], 32)
    require(arguments[2] == 0, "only observed zero-mode requests are calibrated")
    raw_path = bytes.fromhex(copied["records"][5]["hex"])
    nul = raw_path.find(b"\0")
    require(0 <= nul < 1023, "copied pathname lacks an unambiguous bounded terminator")
    require(not any(raw_path[nul + 1:]), "copied pathname padding differs from calibration")
    values = returned["raw_uint64_after_header"]
    require(len(values) == 5, "unsupported open return frame")
    primary, duplicate, secondary, kernel_error, builtin_errno = values
    if kernel_error == 0:
        require(0 <= primary <= transport.INT_MAX and duplicate == primary and secondary == 0 and builtin_errno == 0,
                "successful open return differs from calibrated tuple")
        result, error = primary, 0
    else:
        require(values == [UINT64, UINT64, UINT64, 2, 2],
                "only the observed ENOENT failure tuple is calibrated")
        result, error = -1, 2
    return {"operation": "open", "pid": first["pid"], "tid": first["tid"],
            "flags_u32": flags, "mode": 0, "copied_user_path_hex": raw_path[:nul].hex(),
            "path_nul_index": nul, "libc_result": result, "errno": error,
            "raw_frames": frames}


def observe_owned_capture(capture, toolkit):
    """Verify native capture bytes before pairing the selected named-open stream.

    The source-matched producer and its receipt are not cryptographic kernel
    attestation. This API neither trusts caller-supplied decoded frames nor
    authorizes any filesystem operation from a pathname or numeric descriptor.
    """
    with tempfile.TemporaryFile() as timeline:
        summary = transport.inspect_capability(capture, toolkit, timeline)
        require(summary["capture_status"] == "captured" and not summary["producer_diagnostics"],
                "observations require a completed clean capture")
        require(summary["profile"] == "open", "tree and Mach profiles need separate identity adapters")
        require(summary["host"] == HOST, "host has no matching actual open calibration")
        require(len(summary["observed_processes"]) == 1, "one owned root is required")
        root = summary["observed_processes"][0]["pid"]
        argv = summary["argv"]
        # Native-byte JSON in the producer maps each byte to U+00xx.
        require(all(all(ord(character) <= 255 for character in argument) for argument in argv),
                "argv is not native-byte JSON")
        if summary["fixture"] == "owned-probe":
            require(len(argv) == 2, "unsupported owned-probe invocation")
        else:
            require(summary["fixture"] == "lifecycle-probe" and len(argv) == 3 and argv[1] == "read",
                    "only the observed root read control is supported")
        timeline.seek(0)
        calls, pending, thread = [], None, None
        count, began, ended = 0, False, False
        for line in timeline:
            count += 1
            require(count <= 3 * MAX_CALLS + 2, "open observation event bound exceeded")
            frame = transport.strict_json(line, "verified timeline")
            raw = frame["raw"]
            kind = raw["kind"]
            require(not ended, "frame after END")
            if kind == 1:
                require(count == 1 and not began, "BEGIN must be the first frame")
                began = True
                continue
            require(began, "missing initial BEGIN")
            if kind == 17:
                require(pending is None, "pending open at END")
                ended = True
                continue
            require(kind in {2, 3, 14} and raw["pid"] == root and raw["function"] == "open",
                    "frame outside the selected root named-open stream")
            if thread is None:
                thread = raw["tid"]
            require(thread > 0 and raw["tid"] == thread, "additional or invalid calling thread needs an identity adapter")
            if kind == 2:
                require(pending is None, "nested or duplicate open entry")
                pending = [frame]
            elif kind == 14:
                require(pending is not None and len(pending) == 1, "orphan or duplicate copied path")
                pending.append(frame)
            else:
                require(pending is not None and len(pending) == 2, "orphan or pathless open return")
                calls.append(_normalize_call(*pending, frame))
                require(len(calls) <= MAX_CALLS, "open observation call bound exceeded")
                pending = None
        require(began and ended and pending is None and calls, "incomplete or empty open stream")
        require(len(calls) == summary["totals"]["open_entries"] == summary["totals"]["open_returns"],
                "paired calls differ from verified transport totals")
        return {"revision": 1, "protocol": "darwin-owned-open-observations-v1",
                "origin": "source-matched-capability-records", "calibration_sha256": CALIBRATION,
                "full_trace_acceptance": False,
                "scope": "Copied user pathname and calibrated call results only; no resolved path, FD object, process generation or extraction decision. Capture claims are not kernel attestation.",
                "source_transport": summary, "calls": calls}


def require_full_trace_acceptance(_observations=None):
    raise UnsupportedObservation("owned open observations cannot satisfy full Darwin R02 acceptance")


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--capture", required=True, type=Path)
    parser.add_argument("--toolkit", required=True, type=Path)
    parser.add_argument("--acceptance", action="store_true")
    args = parser.parse_args(argv)
    try:
        if args.acceptance:
            require_full_trace_acceptance()
        print(json.dumps(observe_owned_capture(args.capture, args.toolkit), sort_keys=True, indent=2))
        return 0
    except (UnsupportedObservation, transport.InvalidCapability, OSError) as error:
        print("open observation rejected: " + str(error), file=sys.stderr)
        return 1


if __name__ == "__main__":
    sys.exit(main())
