#!/bin/sh
set -eu

if test "$#" -ne 3; then
    echo 'Usage: capture-signing-controls.sh PROBE VALID_ARCHIVE RECORD_DIRECTORY' >&2
    exit 1
fi
probe=$1
archive=$2
record_dir=$3
fixture_dir=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
test ! -e "$record_dir"
mkdir -p "$record_dir"
for name in no-jit debugger-control; do
    case_dir=$record_dir/$name
    mkdir -p "$case_dir"
    launcher=$case_dir/glue-macos-macho-probe
    cp "$probe" "$launcher"
    codesign --force --sign - --options runtime \
        --entitlements "$fixture_dir/$name.plist" "$launcher" \
        > "$case_dir/sign.stdout.txt" 2> "$case_dir/sign.stderr.txt"
    codesign --verify --strict --verbose=4 "$launcher" \
        > "$case_dir/verify.stdout.txt" 2> "$case_dir/verify.stderr.txt"
    codesign --display --verbose=4 "$launcher" \
        > "$case_dir/identity.stdout.txt" 2> "$case_dir/identity.stderr.txt"
    codesign --display --entitlements - --xml "$launcher" \
        > "$case_dir/entitlements.plist" 2> "$case_dir/entitlements.stderr.txt"
    shasum -a 256 "$launcher" "$archive" > "$case_dir/artifacts.sha256"
    set +e
    "$launcher" run "$archive" > "$case_dir/probe.stdout.txt" \
        2> "$case_dir/probe.stderr.txt"
    status=$?
    set -e
    printf '%s\n' "$status" > "$case_dir/probe.exit-status.txt"
    test "$status" -eq 1
    test ! -s "$case_dir/probe.stdout.txt"
done
python3 - "$record_dir" <<'PY'
import json
import pathlib
import plistlib
import re
import sys

root = pathlib.Path(sys.argv[1])
expected_entitlements = {
    "no-jit": {},
    "debugger-control": {
        "com.apple.security.cs.allow-jit": True,
        "com.apple.security.get-task-allow": True,
    },
}
for name, expected in expected_entitlements.items():
    case = root / name
    entitlements = plistlib.loads((case / "entitlements.plist").read_bytes())
    if entitlements != expected:
        raise SystemExit(f"unexpected {name} signing control entitlements: {entitlements!r}")
    identity = (case / "identity.stderr.txt").read_text()
    flags = re.search(r"\bflags=0x([0-9a-fA-F]+)\(", identity)
    if "Signature=adhoc" not in identity or flags is None or int(flags[1], 16) & 0x10002 != 0x10002:
        raise SystemExit(f"{name} control must be ad-hoc signed with hardened runtime")
policy = {
    "source": "spikes/macos-macho/src/macos.rs csops CS_OPS_STATUS guard",
    "required_process_bits": "0x00010001 (CS_VALID | CS_RUNTIME)",
    "disallowed_process_bits": "0x10000004 (CS_DEBUGGED | CS_GET_TASK_ALLOW)",
    "code_directory_flags_are_not_process_csops_flags": True,
}
(root / "policy-mask.json").write_text(json.dumps(policy, indent=2, sort_keys=True) + "\n")
print("PASS actual ad-hoc hardened-runtime signing controls and rejection statuses")
PY
python3 "$fixture_dir/check-results.py" --signing-controls "$record_dir"
