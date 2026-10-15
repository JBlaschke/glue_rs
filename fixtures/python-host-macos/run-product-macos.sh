#!/bin/sh
# macOS arm64 product route of the explicit-host Python startup profile.
#
# Build-time steps run the default-feature workspace checks, extract the pinned
# install-only artifact into a fresh read-only prefix, build the product
# launcher and the fixture probe with the pinned Python feature against that
# prefix's verified headers, copy both aside, run the feature-enabled tests and
# lints, build a second launcher without the header tree in its own target
# directory, derive the six rejected control installations and prepare every
# archive, including one GNU Linux arm64 declaration staged portably from the
# checked-in metadata fixture. Runtime steps run only the copied launchers
# against those archives and immutable installations, from an empty working
# directory with Python and loader environment variables poisoned. No syscall
# tracer is available to an unprivileged user on macOS; the harness records
# that explicitly and keeps before/after installation snapshots instead.
#
# usage: sh fixtures/python-host-macos/run-product-macos.sh OUTPUT_DIR [ARTIFACT]
set -eu

usage='usage: sh fixtures/python-host-macos/run-product-macos.sh OUTPUT_DIR [ARTIFACT]'
[ $# -ge 1 ] && [ $# -le 2 ] || { echo "$usage" >&2; exit 2; }
root=$(pwd -P)
pins="$root/fixtures/python-host-macos/pins.json"
[ -f "$pins" ] || { echo "run from the repository root" >&2; exit 2; }
[ "$(uname -sm)" = "Darwin arm64" ] || { echo "requires macOS arm64" >&2; exit 2; }
channel=$(sed -n 's/^channel = "\(.*\)"$/\1/p' "$root/rust-toolchain.toml")
for tool in rustc cargo; do
  "$tool" --version | grep -q "^$tool $channel " ||
    { echo "$tool is not the pinned $channel toolchain; see CONTRIBUTING.md" >&2; exit 2; }
done
minor=${channel#*.}
cargo clippy --version | grep -q "^clippy 0.1.${minor%.*} " ||
  { echo "cargo clippy is not the pinned $channel toolchain; see CONTRIBUTING.md" >&2; exit 2; }
artifact_name=$(python3 -I -c 'import json, sys; print(json.load(open(sys.argv[1]))["install_only"]["filename"])' "$pins")
artifact_sha256=$(python3 -I -c 'import json, sys; print(json.load(open(sys.argv[1]))["install_only"]["sha256"])' "$pins")
artifact=${2:-$root/target/pbs-macos/$artifact_name}
[ -f "$artifact" ] || { echo "pinned artifact missing: $artifact" >&2; exit 2; }
[ ! -e "$1" ] || { echo "output directory must be new: $1" >&2; exit 2; }
mkdir -p "$1"
out=$(cd "$1" && pwd -P)
case "$out" in
  *[!A-Za-z0-9/._-]*) echo "output path must be plain ASCII without spaces: $out" >&2; exit 2 ;;
esac
evidence="$out/evidence"
mkdir "$evidence" "$out/launcher" "$out/archives" "$out/linux" "$out/empty"
launcher="$out/launcher/glue"
no_boundary="$out/launcher/glue-no-boundary"
probe="$out/launcher/glue-python-bootstrap-probe"
prefix="$out/host Python/python"
# The declared GNU Linux installation does not exist here and is never opened.
linux_prefix='/nonexistent/pinned Linux Python'
controls='wrong-library wrong-stdlib missing-encodings symlink-stdlib missing-library cached-bytecode'
poison='PATH=/usr/bin:/bin HOME=/nonexistent TMPDIR=/nonexistent PYTHONPATH=/forbidden PYTHONHOME=/forbidden PYTHONPYCACHEPREFIX=/forbidden PYTHONIOENCODING=ascii PYTHONUTF8=0 PYTHONSAFEPATH= PYTHONDONTWRITEBYTECODE='

fail() { echo "run-product-macos: $*" >&2; exit 1; }
record() { printf '%s\n' "$2" >"$evidence/$1"; }
log() {
  # log NAME COMMAND...: combined build-time receipt; a failure stops the harness.
  name=$1
  shift
  "$@" >"$evidence/$name.txt" 2>&1 || fail "$name failed; see $evidence/$name.txt"
}
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
prepared() {
  # prepared NAME: a preparation receipt must report success with an empty stderr.
  [ "$(cat "$evidence/$1.exit-status.txt")" -eq 0 ] || fail "$1 failed; see $evidence/$1.stderr.txt"
  [ ! -s "$evidence/$1.stderr.txt" ] || fail "$1 wrote to stderr; see $evidence/$1.stderr.txt"
}
run() {
  # run NAME COMMAND...: a launcher receipt from the poisoned environment.
  name=$1
  shift
  capture "$name" env -i $poison "$@"
}
snapshot() { (cd "$out/host Python" && find . -exec stat -f '%p %u %g %z %m %c %N' {} + | LC_ALL=C sort); }

# 1. Environment and source identity.
{
  sw_vers
  uname -a
  printf 'hw.pagesize=%s\n' "$(sysctl -n hw.pagesize)"
  printf 'kern.osproductversion=%s\n' "$(sysctl -n kern.osproductversion)"
  rustc --version
  cargo --version
  cargo clippy --version
  cargo fmt --version
  cc --version | head -n 1
  python3 --version
} >"$evidence/environment.txt"
git -C "$root" rev-parse HEAD >"$evidence/source-revision.txt"
git -C "$root" branch --show-current >"$evidence/source-branch.txt"
git -C "$root" status --porcelain >"$evidence/source-status.txt"
cp "$root/fixtures/python-host-macos/run-product-macos.sh" "$evidence/commands.sh"

# 2. Pinned artifact identity.
actual=$(shasum -a 256 "$artifact" | cut -d' ' -f1)
[ "$actual" = "$artifact_sha256" ] || fail "artifact SHA-256 differs from the pin in fixtures/python-host-macos/pins.json"
printf '%s  %s\n' "$actual" "$artifact_name" >"$evidence/artifact.sha256"

# 3. Default-feature workspace checks first: they rebuild target/debug/glue
#    without Python, so the feature-enabled build must follow them.
log fmt cargo fmt --all -- --check
log workspace-tests cargo test --workspace --locked
log workspace-clippy cargo clippy --workspace --all-targets --locked -- -D warnings

# 4. Fresh read-only installation. The artifact ships three encodings caches;
#    the startup profile requires their absence, as on GNU Linux.
mkdir -p "$out/host Python"
tar -xzf "$artifact" -C "$out/host Python"
tar -tzf "$artifact" | grep __pycache__ | LC_ALL=C sort >"$evidence/shipped-caches.txt"
find "$prefix" -depth -path '*/__pycache__*' -delete
chmod -R a-w "$out/host Python"
(cd "$prefix/lib" && shasum -a 256 libpython3.13.dylib) >"$evidence/library.sha256"
otool -L "$prefix/lib/libpython3.13.dylib" >"$evidence/library.dependencies.txt"
codesign -dv "$prefix/lib/libpython3.13.dylib" >"$evidence/library.codesign.txt" 2>&1

# 5. Feature-enabled product launcher and probe against the verified header
#    tree. Both are copied aside at once: later Cargo invocations may rebuild
#    target/debug, and every receipt below uses the copies.
export GLUE_PYTHON_INCLUDE_DIR="$prefix/include/python3.13"
log clean cargo clean -p glue-runtime-python -p glue-runner -p glue-python-bootstrap-probe
log build cargo build --locked -p glue-runner -p glue-python-bootstrap-probe \
  --features glue-runner/python-pbs,glue-python-bootstrap-probe/pbs-bootstrap
cp "$root/target/debug/glue" "$launcher"
cp "$root/target/debug/glue-python-bootstrap-probe" "$probe"
cp "$(ls -t "$root"/target/debug/build/glue-runtime-python-*/out/python-bootstrap-provenance.txt | head -n 1)" \
  "$evidence/boundary-provenance.txt"
(cd "$out/launcher" && shasum -a 256 glue glue-python-bootstrap-probe) >"$evidence/launcher.sha256"
otool -L "$launcher" >"$evidence/launcher.dependencies.txt"
codesign -dv "$launcher" >"$evidence/launcher.codesign.txt" 2>&1
log tests cargo test --locked -p glue-runtime-python -p glue-python-bootstrap-probe --features pbs-bootstrap
log runner-tests cargo test --locked -p glue-runner --features python-pbs
log clippy cargo clippy --locked --all-targets -p glue-runner -p glue-runtime-python -p glue-python-bootstrap-probe \
  --features glue-runner/python-pbs,glue-runtime-python/pbs-bootstrap,glue-python-bootstrap-probe/pbs-bootstrap \
  -- -D warnings

# 6. Feature-enabled launcher without the header tree, in its own target directory.
log no-boundary.build env -u GLUE_PYTHON_INCLUDE_DIR cargo build --locked -p glue-runner --features python-pbs \
  --target-dir "$root/target/no-boundary"
cp "$root/target/no-boundary/debug/glue" "$no_boundary"
cp "$(ls -t "$root"/target/no-boundary/debug/build/glue-runtime-python-*/out/python-bootstrap-provenance.txt | head -n 1)" \
  "$evidence/no-boundary.provenance.txt"
(cd "$out/launcher" && shasum -a 256 glue-no-boundary) >"$evidence/no-boundary.launcher.sha256"

# 7. Control installations and prepared macOS archives.
capture controls python3 -I "$root/fixtures/python-host-macos/prepare-controls.py" "$prefix" "$out/controls"
prepared controls
for mode in success $controls; do
  if [ "$mode" = success ]; then host_prefix="$prefix"; else host_prefix="$out/controls/host Python $mode/python"; fi
  capture "$mode.prepare" "$probe" prepare-host-macos "$artifact" "$host_prefix" "$out/archives/$mode.glue"
  prepared "$mode.prepare"
done
chmod -R a-w "$out/archives"
(cd "$out/archives" && shasum -a 256 *.glue | LC_ALL=C sort -k 2) >"$evidence/archives.sha256"

# 8. One GNU Linux arm64 declaration: the install-only host metadata
#    application, staged portably from the checked-in fixture against the
#    fixed absent prefix and packaged by the product builder.
capture linux-declaration.stage python3 -I "$root/fixtures/python-metadata/prepare.py" install-host \
  "$root/fixtures/python-metadata/input" "$out/linux/stage" --prefix "$linux_prefix"
prepared linux-declaration.stage
run linux-declaration.build "$launcher" build --manifest "$out/linux/stage/manifest.json" \
  --root "$out/linux/stage/root" --output "$out/linux/linux-declaration.glue"
prepared linux-declaration.build
chmod a-w "$out/linux/linux-declaration.glue"
(cd "$out/linux" && shasum -a 256 linux-declaration.glue) >"$evidence/linux-declaration.archive.sha256"

# 9. Snapshot the valid installation before any product receipt.
snapshot >"$evidence/installation.before.txt"

# 10. Product receipts: poisoned Python environment, unavailable home and
#     temporary paths, empty working directory, and no loader override except
#     in the loader-override case.
cd "$out/empty"
run doctor-summary "$launcher" doctor
for mode in success $controls; do
  for verb in inspect verify doctor run; do
    run "$mode.$verb" "$launcher" "$verb" "$out/archives/$mode.glue"
  done
  run "$mode.inspect-json" "$launcher" inspect --json "$out/archives/$mode.glue"
done
capture loader-override.doctor env -i $poison DYLD_LIBRARY_PATH=/forbidden "$launcher" doctor "$out/archives/success.glue"
capture loader-override.run env -i $poison DYLD_LIBRARY_PATH=/forbidden "$launcher" run "$out/archives/success.glue"
for verb in inspect verify doctor run; do
  run "linux-declaration.$verb" "$launcher" "$verb" "$out/linux/linux-declaration.glue"
done
run linux-declaration.inspect-json "$launcher" inspect --json "$out/linux/linux-declaration.glue"
run no-boundary.doctor-summary "$no_boundary" doctor
for verb in inspect verify doctor run; do
  run "no-boundary.$verb" "$no_boundary" "$verb" "$out/archives/success.glue"
done
run no-boundary.inspect-json "$no_boundary" inspect --json "$out/archives/success.glue"
cd "$root"

# 11. Snapshot after all receipts; the installation and the working directory
#     must be unchanged.
snapshot >"$evidence/installation.after.txt"
cmp "$evidence/installation.before.txt" "$evidence/installation.after.txt"
ls -A "$out/empty" >"$evidence/working-directory.txt"
[ ! -s "$evidence/working-directory.txt" ] || fail "the empty working directory gained entries"
find "$out/host Python" "$out/controls" -name '__pycache__' | LC_ALL=C sort >"$evidence/caches-after.txt"
record tracing.txt 'No syscall or filesystem tracer is available to an unprivileged user on this macOS cell: fs_usage, ktrace and dtrace require root. Reproduce with: sudo fs_usage -w -f filesys <glue pid>. Absence of payload writes is supported here only by the read-only installation, the unavailable home/temp paths, the empty working directory and the unchanged installation snapshot, not by a trace.'

# 12. Exact result checks, then the inventory of every receipt but itself.
python3 -I "$root/fixtures/python-host-macos/check-product-results.py" "$evidence" "$out"
(cd "$evidence" && find . -type f ! -name artifacts.sha256 | sed 's|^\./||' | LC_ALL=C sort | while IFS= read -r file; do shasum -a 256 "$file"; done) >"$evidence/artifacts.sha256"
printf 'macOS host Python product-route evidence: %s\n' "$evidence"
