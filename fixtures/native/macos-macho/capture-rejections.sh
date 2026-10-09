#!/bin/sh
set -eu

if test "$#" -ne 2; then
    echo 'Usage: capture-rejections.sh GLUE_BUILD_CLI EVIDENCE_DIRECTORY' >&2
    exit 1
fi
glue=$1
evidence=$2
fixture_dir=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
input=$evidence/build-input
rejections=$evidence/build-rejections
python3 "$fixture_dir/rejection-inputs.py" "$input" "$rejections"

for name in chained_fixups tlv; do
    mkdir -p "$rejections/$name/native" "$rejections/$name/scaffold"
    cp "$input/native/libglue_probe_dep.dylib" "$rejections/$name/native/"
    cp "$input/scaffold/main.lua" "$rejections/$name/scaffold/"
done
xcrun clang -arch arm64 -mmacosx-version-min=13.0 -O2 -g0 -Wall -Wextra -Werror \
    -fPIC -fno-stack-protector -fno-unwind-tables -fno-asynchronous-unwind-tables \
    -dynamiclib -Wl,-fixup_chains,-no_compact_unwind \
    -Wl,-install_name,@loader_path/libglue_probe_module.dylib \
    "$fixture_dir/module.c" -L"$input/native" -lglue_probe_dep \
    -o "$rejections/chained_fixups/native/libglue_probe_module.dylib" \
    > "$evidence/chained-fixups-build.stdout.txt" \
    2> "$evidence/chained-fixups-build.stderr.txt"
xcrun clang -arch arm64 -mmacosx-version-min=13.0 -O2 -g0 -Wall -Wextra -Werror \
    -fPIC -fno-stack-protector -fno-unwind-tables -fno-asynchronous-unwind-tables \
    -dynamiclib -Wl,-no_fixup_chains,-bind_at_load,-no_compact_unwind \
    -Wl,-install_name,@loader_path/libglue_probe_module.dylib \
    "$fixture_dir/tlv.c" -o "$rejections/tlv/native/libglue_probe_module.dylib" \
    > "$evidence/tlv-build.stdout.txt" 2> "$evidence/tlv-build.stderr.txt"
mkdir -p "$evidence/rejections"
for name in wrong_architecture install_name chained_fixups tlv writable_executable undeclared_dependency future_minimum; do
    case_dir=$evidence/rejections/$name
    mkdir -p "$case_dir"
    python3 "$fixture_dir/manifest.py" "$rejections/$name" > "$case_dir/manifest.json"
    "$glue" build --manifest "$case_dir/manifest.json" --root "$rejections/$name" \
        --output "$case_dir/app.glue" > "$case_dir/archive-build.stdout.txt" \
        2> "$case_dir/archive-build.stderr.txt"
    image=$rejections/$name/native/libglue_probe_module.dylib
    xcrun otool -l "$image" > "$case_dir/module.load-commands.txt"
    shasum -a 256 "$case_dir/app.glue" "$image" > "$case_dir/artifacts.sha256"
done
