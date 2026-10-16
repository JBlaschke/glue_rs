#!/usr/bin/env python3
"""Observe calibrated named opens in raw Darwin trees; never authorize effects."""
import argparse
import hashlib
import json
from pathlib import Path
import sys

SOURCE = Path(__file__).resolve().parent
sys.path.insert(0, str(SOURCE.parent))
sys.path.insert(0, str(SOURCE.parent / "call-pairing"))
import observe_open as calibrated
import pair_calls as pairing

MAX_OPENS = 4096


class UnsupportedTreeOpen(ValueError):
    pass


def require(condition, reason):
    if not condition:
        raise UnsupportedTreeOpen(reason)


def observe_tree_capture(capture, toolkit):
    """Run strict pairing before observing copied paths and raw open requests.

    Returned identities are observed session tokens, not kernel generations.
    No public route accepts a caller's pairing/validation claim or grants a
    filesystem decision from these copied bytes or numeric return values.
    """
    pairs = pairing.pair_capture(capture, toolkit)
    observations = []
    for pair_index, call in enumerate(pairs["calls"], 1):
        if call["family"] != ["syscall", "", "open"]:
            continue
        require(len(observations) < MAX_OPENS, "named-open diagnostic bound exceeded")
        require(call["outcome"] == "provider-return-observed" and call["return_index"] is not None
                and len(call["path_indexes"]) == 1, "named open lacks a complete entry/path/return pair")
        indexes = [call["entry_index"], call["path_indexes"][0], call["return_index"]]
        frames = [pairs["raw_frames"][index - 1] for index in indexes]
        entry = {"raw": frames[0], "raw_uint64_after_header": call["entry_words"]}
        path = {"raw": frames[1]}
        returned = {"raw": frames[2], "raw_uint64_after_header": call["return_words"]}
        try:
            observation = calibrated._normalize_call(entry, path, returned)
        except calibrated.UnsupportedObservation as error:
            raise UnsupportedTreeOpen(str(error)) from error
        observation.update(observed_identity=dict(call["identity"]), source_pair_index=pair_index,
                           source_consumer_indexes=indexes)
        observations.append(observation)
    totals = pairs["source_transport"]["totals"]
    require(observations and len(observations) == totals["open_entries"] == totals["open_returns"],
            "named-open observations differ from strict transport totals")
    return {"revision": 1, "protocol": "darwin-tree-open-observations-v1",
            "origin": "strict-source-matched-raw-v4-call-pairs", "full_trace_acceptance": False,
            "calibration_sha256": pairing.CALIBRATION,
            "historical_open_calibration_sha256": calibrated.CALIBRATION,
            "observer_sha256": hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),
            "normalizer_sha256": hashlib.sha256(Path(calibrated.__file__).read_bytes()).hexdigest(),
            "scope": "Copied user pathname bytes, all flag bits and calibrated numeric results only; no kernel-resolved path/FD object, generation, permitted write, successful effect or extraction acceptance.",
            "observations": observations, "source_pairs": pairs}


def require_full_trace_acceptance(_observations=None):
    raise UnsupportedTreeOpen("tree open observations cannot satisfy full Darwin R02 acceptance")


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--capture", required=True, type=Path)
    parser.add_argument("--toolkit", required=True, type=Path)
    parser.add_argument("--acceptance", action="store_true")
    args = parser.parse_args(argv)
    try:
        if args.acceptance:
            require_full_trace_acceptance()
        print(json.dumps(observe_tree_capture(args.capture, args.toolkit), separators=(",", ":")))
        return 0
    except (ValueError, OSError) as error:
        print(str(error), file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
