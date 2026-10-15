#!/bin/sh
# macOS arm64 explicit-host Python startup fixture.
#
# Build-time steps verify the pinned install-only artifact, extract it into a
# fresh read-only prefix, build the probe against that prefix's verified
# headers and derive rejected control installations. Runtime steps receive
# only prepared archives and those immutable installations, with Python and
# loader environment variables poisoned. No syscall tracer is available to an
# unprivileged user on macOS; the harness records that explicitly and keeps
# before/after installation snapshots instead.
#
# usage: sh fixtures/python-host-macos/run-macos.sh OUTPUT_DIR [ARTIFACT]
set -eu

artifact_name='cpython-3.13.16+20261009-aarch64-apple-darwin-install_only.tar.gz'
artifact_sha256=3338fcd572a670ec45ac9ef75480b95595ea9b6b5dd320952fcf5df185089941

[ $# -ge 1 ] && [ $# -le 2 ] || { echo "usage: sh fixtures/python-host-macos/run-macos.sh OUTPUT_DIR [ARTIFACT]" >&2; exit 2; }
root=$(pwd -P)
[ -f "$root/fixtures/python-host-macos/pins.json" ] || { echo "run from the repository root" >&2; exit 2; }
[ "$(uname -sm)" = "Darwin arm64" ] || { echo "requires macOS arm64" >&2; exit 2; }
artifact=${2:-$root/target/pbs-macos/$artifact_name}
[ -f "$artifact" ] || { echo "pinned artifact missing: $artifact" >&2; exit 2; }
[ ! -e "$1" ] || { echo "output directory must be new: $1" >&2; exit 2; }
mkdir -p "$1"
out=$(cd "$1" && pwd -P)
case "$out" in
  *[!A-Za-z0-9/._-]*) echo "output path must be plain ASCII without spaces: $out" >&2; exit 2 ;;
esac
evidence="$out/evidence"
mkdir "$evidence"
probe="$root/target/release/glue-python-bootstrap-probe"
prefix="$out/host Python/python"

record() { printf '%s\n' "$2" >"$evidence/$1"; }
capture() {
  # capture NAME COMMAND...: stdout, stderr and exit status receipts.
  name=$1
  shift
  set +e
  "$@" >"$evidence/$name.stdout.txt" 2>"$evidence/$name.stderr.txt"
  status=$?
  set -e
  printf '%s\n' "$status" >"$evidence/$name.exit-status.txt"
}

# 1. Environment and source identity.
{
  sw_vers
  uname -a
  printf 'hw.pagesize=%s\n' "$(sysctl -n hw.pagesize)"
  rustc --version
  cargo --version
  cargo clippy --version
  cc --version | head -n 1
} >"$evidence/environment.txt"
git -C "$root" rev-parse HEAD >"$evidence/source-revision.txt"
git -C "$root" status --porcelain >"$evidence/source-status.txt"

# 2. Pinned artifact identity.
actual=$(shasum -a 256 "$artifact" | cut -d' ' -f1)
[ "$actual" = "$artifact_sha256" ] || { echo "artifact SHA-256 differs from the pin" >&2; exit 1; }
printf '%s  %s\n' "$actual" "$artifact_name" >"$evidence/artifact.sha256"

# 3. Fresh read-only installation. The artifact ships three encodings caches;
#    the startup profile requires their absence, as on GNU Linux.
mkdir -p "$out/host Python"
tar -xzf "$artifact" -C "$out/host Python"
tar -tzf "$artifact" | grep __pycache__ | LC_ALL=C sort >"$evidence/shipped-caches.txt"
find "$prefix" -depth -path '*/__pycache__*' -delete
chmod -R a-w "$out/host Python"
shasum -a 256 "$prefix/lib/libpython3.13.dylib" >"$evidence/library.sha256"
otool -L "$prefix/lib/libpython3.13.dylib" >"$evidence/library.dependencies.txt"
otool -l "$prefix/lib/libpython3.13.dylib" | grep -E '^\s+cmd |segname|sectname|minos|sdk' >"$evidence/library.load-commands.txt"
codesign -dv "$prefix/lib/libpython3.13.dylib" >"$evidence/library.codesign.txt" 2>&1

# 4. Build, test and lint the probe against the verified header tree.
export GLUE_PYTHON_INCLUDE_DIR="$prefix/include/python3.13"
cargo build --locked --release -p glue-runtime-python -p glue-python-bootstrap-probe --features pbs-bootstrap \
  >"$evidence/build.txt" 2>&1
cargo test --locked --release -p glue-runtime-python -p glue-python-bootstrap-probe --features pbs-bootstrap \
  >"$evidence/tests.txt" 2>&1
cargo clippy --locked --release --all-targets -p glue-runtime-python -p glue-python-bootstrap-probe \
  --features pbs-bootstrap -- -D warnings >"$evidence/clippy.txt" 2>&1
cp "$(ls -t "$root"/target/release/build/glue-runtime-python-*/out/python-bootstrap-provenance.txt | head -n 1)" \
  "$evidence/boundary-provenance.txt"
otool -L "$probe" >"$evidence/launcher.dependencies.txt"
codesign -dv "$probe" >"$evidence/launcher.codesign.txt" 2>&1
shasum -a 256 "$probe" >"$evidence/launcher.sha256"

# 5. Control installations and prepared archives.
python3 -I "$root/fixtures/python-host-macos/prepare-controls.py" "$prefix" "$out/controls" \
  >"$evidence/controls.stdout.txt" 2>"$evidence/controls.stderr.txt"
test ! -s "$evidence/controls.stderr.txt"
mkdir "$out/archives"
for mode in success wrong-library wrong-stdlib missing-encodings symlink-stdlib missing-library cached-bytecode; do
  if [ "$mode" = success ]; then host_prefix="$prefix"; else host_prefix="$out/controls/host Python $mode/python"; fi
  capture "$mode.prepare" "$probe" prepare-host-macos "$artifact" "$host_prefix" "$out/archives/$mode.glue"
  test "$(cat "$evidence/$mode.prepare.exit-status.txt")" -eq 0
  test ! -s "$evidence/$mode.prepare.stderr.txt"
done
chmod -R a-w "$out/archives"
(cd "$out/archives" && shasum -a 256 ./*.glue) >"$evidence/archives.sha256"

# 6. Snapshot the valid installation before any runtime attempt.
snapshot() { (cd "$out/host Python" && find . -exec stat -f '%p %u %g %z %m %c %N' {} + | LC_ALL=C sort); }
snapshot >"$evidence/installation.before.txt"

# 7. Runtime: poisoned Python environment, unavailable home/temp, no loader overrides.
run() {
  # run NAME ARGS...
  name=$1
  shift
  capture "$name" env -i PATH=/usr/bin:/bin HOME=/nonexistent TMPDIR=/nonexistent \
    PYTHONPATH=/forbidden PYTHONHOME=/forbidden PYTHONPYCACHEPREFIX=/forbidden \
    PYTHONIOENCODING=ascii PYTHONUTF8=0 PYTHONSAFEPATH= PYTHONDONTWRITEBYTECODE= \
    "$probe" "$@"
}
run success run-host-macos "$out/archives/success.glue"
run app-error run-host-macos-negative "$out/archives/success.glue" app-error
for mode in wrong-library wrong-stdlib missing-encodings symlink-stdlib missing-library cached-bytecode; do
  run "$mode" run-host-macos "$out/archives/$mode.glue"
done
capture loader-override env -i PATH=/usr/bin:/bin HOME=/nonexistent TMPDIR=/nonexistent \
  DYLD_LIBRARY_PATH=/forbidden "$probe" run-host-macos "$out/archives/success.glue"
capture unsupported-linux-mode "$probe" run-host "$out/archives/success.glue"

# 8. Snapshot after all runtime attempts; the installation must be unchanged.
snapshot >"$evidence/installation.after.txt"
cmp "$evidence/installation.before.txt" "$evidence/installation.after.txt"
find "$out/host Python" "$out/controls" -name '__pycache__' | LC_ALL=C sort >"$evidence/caches-after.txt"
record tracing.txt 'No syscall or filesystem tracer is available to an unprivileged user on this macOS cell: fs_usage, ktrace and dtrace require root. Reproduce with: sudo fs_usage -w -f filesys <probe pid>. Absence of payload writes is supported here only by the read-only installation, the unavailable home/temp paths and the unchanged installation snapshot, not by a trace.'

# 9. Exact result checks.
python3 -I "$root/fixtures/python-host-macos/check-results.py" "$evidence" "$out"
(cd "$evidence" && find . -type f ! -name artifacts.sha256 | sed 's|^\./||' | LC_ALL=C sort | while IFS= read -r file; do shasum -a 256 "$file"; done) >"$evidence/artifacts.sha256"
printf 'macOS host Python evidence: %s\n' "$evidence"
