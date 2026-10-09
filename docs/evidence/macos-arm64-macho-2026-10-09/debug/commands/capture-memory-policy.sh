#!/bin/sh
set -eu

if test "$#" -ne 1; then
    echo 'Usage: capture-memory-policy.sh RECORD_DIRECTORY' >&2
    exit 1
fi
record_dir=$1
fixture_dir=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
test ! -e "$record_dir"
mkdir -p "$record_dir"
launcher=$record_dir/memory-policy
xcrun clang -arch arm64 -mmacosx-version-min=13.0 -O2 -g0 -Wall -Wextra -Werror \
    "$fixture_dir/memory-policy.c" -o "$launcher" \
    > "$record_dir/build.stdout.txt" 2> "$record_dir/build.stderr.txt"
sh "$fixture_dir/sign-launcher.sh" "$launcher" "$record_dir/signature" \
    > "$record_dir/signature-check.txt"
shasum -a 256 "$fixture_dir/memory-policy.c" "$launcher" \
    > "$record_dir/artifacts.sha256"
cp "$fixture_dir/capture-memory-policy.sh" "$record_dir/commands.sh"
set +e
"$launcher" > "$record_dir/probe.stdout.txt" 2> "$record_dir/probe.stderr.txt"
status=$?
set -e
printf '%s\n' "$status" > "$record_dir/probe.exit-status.txt"
test "$status" -eq 0
python3 "$fixture_dir/check-results.py" --memory-policy "$record_dir"
