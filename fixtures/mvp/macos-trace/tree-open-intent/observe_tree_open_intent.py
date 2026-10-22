#!/usr/bin/env python3
"""Classify strictly observed Darwin tree-open flags; never accept extraction."""
import argparse
import hashlib
import json
from pathlib import Path
import sys


SOURCE = Path(__file__).resolve().parent
sys.path.insert(0, str(SOURCE.parent / "tree-open"))
sys.path.insert(0, str(SOURCE.parent / "open-intent"))
import observe_tree_open as tree_open
import open_intent as intent


class UnsupportedTreeOpenIntent(ValueError):
    pass


def observe_tree_open_intent(capture, toolkit):
    """Validate paths through the strict observer, then classify request bits.

    There is no caller-supplied observation or normalized-origin interface.
    Copied paths and numeric descriptors stay in the complete source report;
    flags do not establish kernel lookup identities or permitted effects.
    Unsupported flag combinations remain explicit diagnostic classifications.
    """
    observed = tree_open.observe_tree_capture(capture, toolkit)
    classifications = []
    for index, observation in enumerate(observed["observations"], 1):
        classification = intent.classify_flags(observation["flags_u32"])
        classifications.append({
            "source_observation_index": index,
            "source_pair_index": observation["source_pair_index"],
            "source_consumer_indexes": list(observation["source_consumer_indexes"]),
            "observed_identity": dict(observation["observed_identity"]),
            "flags_u32": observation["flags_u32"],
            **classification,
        })
    return {
        "revision": 1,
        "protocol": "darwin-tree-open-intent-observations-v1",
        "origin": "strict-source-matched-raw-v4-tree-open-observations",
        "full_trace_acceptance": False,
        "abi_sha256": hashlib.sha256(intent.ABI_BYTES).hexdigest(),
        "classifier_sha256": hashlib.sha256(Path(intent.__file__).read_bytes()).hexdigest(),
        "observer_sha256": hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),
        "scope": "Open request flag intent only; no resolved path/FD object, application-output exemption, successful effect, complete coverage or extraction acceptance.",
        "classifications": classifications,
        "source_observations": observed,
    }


def require_full_trace_acceptance(_observations=None):
    raise UnsupportedTreeOpenIntent("tree open intent observations cannot satisfy full Darwin R02 acceptance")


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--capture", required=True, type=Path)
    parser.add_argument("--toolkit", required=True, type=Path)
    parser.add_argument("--acceptance", action="store_true")
    args = parser.parse_args(argv)
    try:
        if args.acceptance:
            require_full_trace_acceptance()
        report = observe_tree_open_intent(args.capture, args.toolkit)
        print(json.dumps(report, separators=(",", ":")))
        return int(any(value["intent"] == "unsupported" for value in report["classifications"]))
    except (ValueError, OSError) as error:
        print("tree open intent observation rejected: " + str(error), file=sys.stderr)
        return 1


if __name__ == "__main__":
    sys.exit(main())
