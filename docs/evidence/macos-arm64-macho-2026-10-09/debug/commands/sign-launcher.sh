#!/bin/sh
set -eu

if test "$#" -ne 2; then
    echo 'Usage: sign-launcher.sh LAUNCHER RECORD_DIRECTORY' >&2
    exit 1
fi
fixture_dir=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
launcher=$1
record_dir=$2
mkdir -p "$record_dir"
codesign --force --sign - --options runtime \
    --entitlements "$fixture_dir/allow-jit.plist" "$launcher" \
    > "$record_dir/sign.stdout.txt" 2> "$record_dir/sign.stderr.txt"
codesign --verify --strict --verbose=4 "$launcher" \
    > "$record_dir/verify.stdout.txt" 2> "$record_dir/verify.stderr.txt"
codesign --display --verbose=4 "$launcher" \
    > "$record_dir/identity.stdout.txt" 2> "$record_dir/identity.stderr.txt"
codesign --display --entitlements - --xml "$launcher" \
    > "$record_dir/entitlements.plist" 2> "$record_dir/entitlements.stderr.txt"
python3 - "$record_dir" <<'PY'
import pathlib
import plistlib
import re
import sys

records = pathlib.Path(sys.argv[1])
observed = plistlib.loads((records / "entitlements.plist").read_bytes())
expected = {"com.apple.security.cs.allow-jit": True}
if observed != expected:
    raise SystemExit(f"unexpected launcher entitlements: {observed!r}")
identity = (records / "identity.stderr.txt").read_text()
flags = re.search(r"\bflags=0x([0-9a-fA-F]+)\(", identity)
if "Signature=adhoc" not in identity or flags is None or int(flags[1], 16) & 0x10002 != 0x10002:
    raise SystemExit("launcher must have ad-hoc hardened-runtime code signature")
print("PASS ad-hoc hardened-runtime signature; only allow-jit entitlement")
PY
