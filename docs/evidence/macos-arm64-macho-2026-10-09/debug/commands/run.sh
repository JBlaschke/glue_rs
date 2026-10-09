#!/bin/sh
set -eu

if test "$#" -ne 3; then
    echo 'Usage: run.sh GLUE_BUILD_CLI MACOS_MACHO_PROBE EVIDENCE_DIRECTORY' >&2
    exit 1
fi
glue=$1
probe=$2
evidence=$3
fixture_dir=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
case "$glue" in /*) ;; *) echo 'CLI path must be absolute.' >&2; exit 1 ;; esac
case "$probe" in /*) ;; *) echo 'Probe path must be absolute.' >&2; exit 1 ;; esac
sh "$fixture_dir/capture-inputs.sh" "$glue" "$evidence"
evidence=$(CDPATH= cd -- "$evidence" && pwd)
sh "$fixture_dir/capture-rejections.sh" "$glue" "$evidence"
sh "$fixture_dir/capture-memory-policy.sh" "$evidence/memory-policy" \
    > "$evidence/memory-policy-check.txt"

relocated=$evidence/relocated\ inputs
mkdir -p "$relocated"
cp "$probe" "$relocated/glue-macos-macho-probe"
mv "$evidence/app.glue" "$relocated/app.glue"
sh "$fixture_dir/sign-launcher.sh" "$relocated/glue-macos-macho-probe" \
    "$evidence/launcher-signature" > "$evidence/launcher-signature-check.txt"
shasum -a 256 "$relocated/glue-macos-macho-probe" "$relocated/app.glue" \
    > "$evidence/execution-artifacts.sha256"
chmod a-w "$relocated/app.glue"

# The entire current-run compiler output inventory is removed before execution,
# including valid and adversarial dylibs and the ordinary-loader executable.
# Deleting inputs is a fixture condition; it does not establish a syscall trace.
rm -rf "$evidence/build-input" "$evidence/build-rejections"
printf '%s\n' 'All current-run native build input trees removed before probe execution.' \
    > "$evidence/input-removal.txt"
unset DYLD_LIBRARY_PATH DYLD_FALLBACK_LIBRARY_PATH DYLD_FRAMEWORK_PATH \
    DYLD_FALLBACK_FRAMEWORK_PATH DYLD_INSERT_LIBRARIES DYLD_ROOT_PATH
launcher=$relocated/glue-macos-macho-probe
sh "$fixture_dir/capture-signing-controls.sh" "$launcher" "$relocated/app.glue" \
    "$evidence/signing-controls" > "$evidence/signing-control-check.txt"
for name in wrong_architecture install_name chained_fixups tlv writable_executable undeclared_dependency future_minimum; do
    case_dir=$evidence/rejections/$name
    set +e
    "$launcher" run "$case_dir/app.glue" > "$case_dir/probe.stdout.txt" \
        2> "$case_dir/probe.stderr.txt"
    status=$?
    set -e
    printf '%s\n' "$status" > "$case_dir/probe.exit-status.txt"
    test "$status" -eq 1
    test ! -s "$case_dir/probe.stdout.txt"
    test -s "$case_dir/probe.stderr.txt"
done

set +e
"$launcher" run "$relocated/app.glue" > "$evidence/probe.stdout.txt" \
    2> "$evidence/probe.stderr.txt"
status=$?
set -e
printf '%s\n' "$status" > "$evidence/probe.exit-status.txt"
test "$status" -eq 0
test ! -s "$evidence/probe.stderr.txt"
python3 - "$evidence" <<'PY'
import pathlib
import re
import sys

root = pathlib.Path(sys.argv[1])
pattern = rb"PASS answer=42 data=7 constructors=1 pid=([1-9][0-9]*)\n"
outputs = [(root / name).read_bytes() for name in ["baseline.stdout.txt", "probe.stdout.txt"]]
for output in outputs:
    if re.fullmatch(pattern, output) is None:
        raise SystemExit(f"unexpected output: {output!r}")
if re.sub(rb"pid=[1-9][0-9]*", b"pid=PID", outputs[0]) != re.sub(
    rb"pid=[1-9][0-9]*", b"pid=PID", outputs[1]
):
    raise SystemExit("ordinary dyld and mapped execution output differ")
print("PASS exact output and ordinary-loader comparison (PID normalized)")
PY

# Observe this actual signed target while it is alive. Hardened-runtime task-port
# policy may deny vmmap; keep that denial as evidence instead of widening rights.
"$launcher" run "$relocated/app.glue" --hold \
    > "$evidence/held-probe.stdout.txt" 2> "$evidence/held-probe.stderr.txt" &
held_pid=$!
printf '%s\n' "$held_pid" > "$evidence/held-probe.pid.txt"
ready_attempts=0
while test ! -s "$evidence/held-probe.stdout.txt" && kill -0 "$held_pid" 2>/dev/null; do
    ready_attempts=$((ready_attempts + 1))
    test "$ready_attempts" -lt 100 || break
    sleep 0.05
done
test -s "$evidence/held-probe.stdout.txt"
set +e
/usr/bin/vmmap -w "$held_pid" > "$evidence/held-probe.vmmap.stdout.txt" \
    2> "$evidence/held-probe.vmmap.stderr.txt"
vmmap_status=$?
wait "$held_pid"
held_status=$?
set -e
printf '%s\n' "$vmmap_status" > "$evidence/held-probe.vmmap.exit-status.txt"
printf '%s\n' "$held_status" > "$evidence/held-probe.exit-status.txt"
test "$held_status" -eq 0
test ! -s "$evidence/held-probe.stderr.txt"
python3 - "$evidence" <<'PY'
import pathlib
import sys

root = pathlib.Path(sys.argv[1])
pid = (root / "held-probe.pid.txt").read_text().strip()
output = (root / "held-probe.stdout.txt").read_text()
expected = f"PASS answer=42 data=7 constructors=1 pid={pid}\n"
if output != expected:
    raise SystemExit("held fixture output does not identify the observed target process")
print("PASS held output identifies vmmap target PID")
PY
python3 "$fixture_dir/check-results.py" "$evidence" > "$evidence/result-check.txt"
cat "$evidence/result-check.txt"
printf '%s\n' "$evidence"
