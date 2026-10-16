#!/usr/bin/env python3
"""Observe packed mach_msg2 scalars; never decide message or filesystem effects."""
import argparse
import copy
import hashlib
import json
from pathlib import Path
import sys

sys.dont_write_bytecode = True
sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "call-pairing"))
import pair_calls as pairing

U32, U64 = (1 << 32) - 1, (1 << 64) - 1
SEND, RECEIVE, VECTOR, KOBJECT = 1, 2, 1 << 32, 1 << 33
PORT_BITS, COMPLEX = 0x001F1F1F, 0x80000000
MAX_MESSAGES = 4096
SOURCE_CONTRACT = {
    "xnu_commit": "f6217f891ac0bb64f3d375211650a4c1ff8ca1ea",
    "assessment_manifest_sha256": "4d3207010288577d61042902eafaccd7ae45d016016449a1f300b32a2d098dd5",
    "sources_sha256": {
        "osfmk/mach/mach_traps.h": "32b236d9cd26bd284c3b2b563b61cea3b943049e5abad5641d2de9d6929e0bac",
        "osfmk/ipc/mach_msg.c": "85a96ee426f6a2efb5eb12b5747e77315091d22ea330a26a88abf67883569609",
        "osfmk/mach/message.h": "ad64b7b413b42e196dc43a54a5978aa049b9133db1fe9369893f12ad4718c615",
        "osfmk/ipc/ipc_policy.c": "161a01701b634adc21607969d417d2a54f5e15c6f6f57eea4b2521a0e09e2309",
    },
    "installed_guest_source_attested": False,
    "supporting_sdk": {
        "version": "27.0",
        "arm/_types.h_sha256": "4f0bde85f9a41cc7d30fff22ebd7e8f4eb206a55a926eda012a2e7481e3524fa",
        "mach/arm/vm_types.h_sha256": "4256065e3413a8a506492ff4e4c46596076a56e44db7c850efbc832c8b12fbb1",
    },
}


class UnsupportedMessageObservation(ValueError):
    pass


def require(condition, reason):
    if not condition:
        raise UnsupportedMessageObservation(reason)


def _words(value, count, label):
    """Private shape guard, not an API accepting native-validation assertions."""
    require(type(value) is list and len(value) == count
            and all(type(word) is int and 0 <= word <= U64 for word in value),
            label + " requires exactly " + str(count) + " uint64 words")


def _scalar_fields(words):
    _words(words, 8, "mach_msg2 entry")
    require(not words[1] & VECTOR,
            "vector mach_msg2 interpretation is unresolved; scalar observation rejected")
    bits, message_id = words[2] & U32, words[4] >> 32
    return {
        "data_pointer_u64": words[0],
        "caller_options_u64": words[1],
        "send_requested_bit": bool(words[1] & SEND),
        "receive_requested_bit": bool(words[1] & RECEIVE),
        "kobject_call_requested_bit": bool(words[1] & KOBJECT),
        "uninterpreted_option_bits_u64": words[1] & ~(SEND | RECEIVE | VECTOR | KOBJECT) & U64,
        "header_bits_u32": bits,
        "remote_disposition_bits": bits & 0x1F,
        "local_disposition_bits": (bits >> 8) & 0x1F,
        "voucher_disposition_bits": (bits >> 16) & 0x1F,
        "complex_bit": bool(bits & COMPLEX),
        "uninterpreted_header_bits_u32": bits & ~(PORT_BITS | COMPLEX) & U32,
        "send_size_u32": words[2] >> 32,
        "remote_port_name_u32": words[3] & U32,
        "local_port_name_u32": words[3] >> 32,
        "voucher_port_name_u32": words[4] & U32,
        "message_id_bits_u32": message_id,
        "message_id_i32": message_id - (1 << 32) if message_id & (1 << 31) else message_id,
        "descriptor_count_u32": words[5] & U32,
        "receive_port_name_u32": words[5] >> 32,
        "receive_size_u32": words[6] & U32,
        "priority_u32": words[6] >> 32,
        "timeout_word_u64": words[7],
        "timeout_low32_under_source_cast": words[7] & U32,
        "timeout_high32_remainder": words[7] >> 32,
    }


def observe_capture(capture, toolkit):
    """Run the strict pairing API, preserving its whole result and raw evidence."""
    pairs = pairing.pair_capture(capture, toolkit)
    messages = []
    for pair_index, call in enumerate(pairs["calls"]):
        if call["family"] != ["mach_trap", "", "mach_msg2_trap"]:
            continue
        require(len(messages) < MAX_MESSAGES, "mach_msg2 observation count exceeds diagnostic bound")
        require(call["return_index"] is not None and call["outcome"] == "provider-return-observed",
                "mach_msg2 return is unresolved")
        _words(call["return_words"], 1, "mach_msg2 return")
        fields = _scalar_fields(call["entry_words"])
        messages.append({
            "pair_index": pair_index,
            "entry_index": call["entry_index"],
            "return_index": call["return_index"],
            "identity": call["identity"],
            "raw_entry_words": list(call["entry_words"]),
            "raw_return_words": list(call["return_words"]),
            "scalar_fields_under_source_contract": fields,
            "semantics": "unresolved",
            "unobserved": ["consumed-message-bytes", "descriptor-contents", "rpc-reply-and-result",
                           "port-object-identities-and-generations", "send-receive-completion-and-effects"],
        })
    enabled = pairs["source_transport"]["profile"] == "tree-mach"
    return {
        "revision": 1,
        "protocol": "darwin-mach-msg2-scalars-v1",
        "origin": "source-matched-raw-v4-through-strict-pairing",
        "full_trace_acceptance": False,
        "source_contract": copy.deepcopy(SOURCE_CONTRACT),
        "observer_sha256": hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),
        "scope": "Packed scalar observations only. Pointers, port names, IDs, raw trap results and message effects remain opaque; no effects allowlist.",
        "kobject_call_caveat": "KOBJECT_CALL is requested intent only. The pinned source permits message queues through the CSR_ALLOW_KERNEL_DEBUGGER SIP-off compatibility path; it cannot attest destination type.",
        "mach_provider_enabled": enabled,
        "message_coverage": ("selected-pairs-observed" if messages else "no-selected-pairs-observed") if enabled else "not-enabled-in-profile",
        "messages": messages,
        "paired_capture": pairs,
    }


def require_full_trace_acceptance(_observation=None):
    raise UnsupportedMessageObservation("packed Mach scalars cannot satisfy full Darwin R02 acceptance")


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--capture", required=True, type=Path)
    parser.add_argument("--toolkit", required=True, type=Path)
    parser.add_argument("--acceptance", action="store_true")
    args = parser.parse_args(argv)
    try:
        if args.acceptance:
            require_full_trace_acceptance()
        result = observe_capture(args.capture, args.toolkit)
        print(json.dumps(result, separators=(",", ":")))
        return 0
    except (UnsupportedMessageObservation, pairing.UnsupportedPairing,
            pairing.transport.InvalidCapability, OSError, ValueError) as error:
        print(str(error), file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
