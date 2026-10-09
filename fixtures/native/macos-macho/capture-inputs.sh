#!/bin/sh
set -eu

if test "$#" -ne 2; then
    echo 'Usage: capture-inputs.sh GLUE_BUILD_CLI EVIDENCE_DIRECTORY' >&2
    exit 1
fi
glue=$1
evidence=$2
fixture_dir=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
test ! -e "$evidence"
mkdir -p "$evidence"
evidence=$(CDPATH= cd -- "$evidence" && pwd)
input_root=$evidence/build-input
sh "$fixture_dir/build-fixture.sh" "$input_root" \
    > "$evidence/build-fixture.stdout.txt" 2> "$evidence/build-fixture.stderr.txt"

sw_vers > "$evidence/environment.txt"
uname -a >> "$evidence/environment.txt"
printf 'page_size=' >> "$evidence/environment.txt"
getconf PAGESIZE >> "$evidence/environment.txt"
xcrun clang --version >> "$evidence/environment.txt"
xcrun ld -v >> "$evidence/environment.txt" 2>&1
xcrun --show-sdk-path >> "$evidence/environment.txt"
xcrun --show-sdk-version >> "$evidence/environment.txt"
rustc --version >> "$evidence/environment.txt"
cargo clippy --version >> "$evidence/environment.txt"
git rev-parse HEAD > "$evidence/source-commit.txt"
git status --porcelain=v1 > "$evidence/source-status.txt"
cp "$fixture_dir/build-fixture.sh" "$evidence/build-commands.sh"
mkdir -p "$evidence/commands"
cp "$fixture_dir"/*.sh "$fixture_dir"/*.py "$evidence/commands/"
shasum -a 256 "$fixture_dir"/*.c "$fixture_dir"/*.sh "$fixture_dir"/*.py \
    "$fixture_dir"/*.plist > "$evidence/fixture-source.sha256"
python3 - "$evidence/source.sha256" <<'PY'
import hashlib
import pathlib
import subprocess
import sys

repository = pathlib.Path(subprocess.check_output(["git", "rev-parse", "--show-toplevel"], text=True).strip())
tracked = subprocess.check_output(["git", "ls-files", "-z"]).decode().split("\0")
top = {"Cargo.toml", "Cargo.lock", "rust-toolchain.toml"}
prefixes = ("crates/", "spikes/", "fixtures/native/macos-macho/")
selected = sorted(name for name in tracked if name in top or name.startswith(prefixes))
with pathlib.Path(sys.argv[1]).open("w") as output:
    for name in selected:
        digest = hashlib.sha256((repository / name).read_bytes()).hexdigest()
        output.write(f"{digest}  {name}\n")
PY

for name in libglue_probe_dep libglue_probe_module; do
    image=$input_root/native/$name.dylib
    xcrun otool -l "$image" > "$evidence/$name.load-commands.txt"
    xcrun otool -L "$image" > "$evidence/$name.libraries.txt"
    xcrun nm -m "$image" > "$evidence/$name.symbols.txt"
    xcrun dyld_info -fixups -exports -imports -inits -opcodes "$image" \
        > "$evidence/$name.dyld-info.txt"
    codesign --verify --strict --verbose=4 "$image" \
        > "$evidence/$name.signature-verify.stdout.txt" \
        2> "$evidence/$name.signature-verify.stderr.txt"
    codesign --display --verbose=4 "$image" \
        > "$evidence/$name.signature.stdout.txt" \
        2> "$evidence/$name.signature.stderr.txt"
done
shasum -a 256 "$input_root/native"/*.dylib "$input_root/baseline" \
    > "$evidence/native-inputs.sha256"
set +e
"$input_root/baseline" "$input_root/native/libglue_probe_dep.dylib" \
    "$input_root/native/libglue_probe_module.dylib" \
    > "$evidence/baseline.stdout.txt" 2> "$evidence/baseline.stderr.txt"
status=$?
set -e
printf '%s\n' "$status" > "$evidence/baseline.exit-status.txt"
test "$status" -eq 0
test ! -s "$evidence/baseline.stderr.txt"
python3 "$fixture_dir/manifest.py" "$input_root" > "$evidence/manifest.json"
"$glue" build --manifest "$evidence/manifest.json" --root "$input_root" \
    --output "$evidence/app.glue" > "$evidence/archive-build.stdout.txt" \
    2> "$evidence/archive-build.stderr.txt"
"$glue" inspect "$evidence/app.glue" --json > "$evidence/archive-manifest.json"
shasum -a 256 "$evidence/app.glue" "$glue" > "$evidence/artifacts.sha256"
sh "$fixture_dir/capture-trace-availability.sh" "$evidence/trace-availability"
printf '%s\n' "$evidence"
