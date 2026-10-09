#!/bin/sh
set -eu

if test "$#" -ne 1; then
    echo 'Usage: build-fixture.sh OUTPUT_ROOT' >&2
    exit 1
fi
test "$(uname -s)" = Darwin
test "$(uname -m)" = arm64
fixture_dir=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
output_root=$1
test ! -e "$output_root"
mkdir -p "$output_root/native" "$output_root/scaffold"
printf '%s\n' '-- Unacquired schema scaffold; the mapping probe never runs Lua.' \
    > "$output_root/scaffold/main.lua"

# The selected classic dyld profile is deliberate. Toolchains unable to emit it
# fail here; no fallback to chained fixups is attempted. The raw load-command
# report is retained so the constructor representation is independently checked.
xcrun clang -arch arm64 -mmacosx-version-min=13.0 -O2 -g0 -Wall -Wextra -Werror \
    -fPIC -fno-stack-protector -fno-unwind-tables -fno-asynchronous-unwind-tables \
    -dynamiclib -Wl,-no_fixup_chains,-bind_at_load,-no_compact_unwind \
    -Wl,-install_name,@loader_path/libglue_probe_dep.dylib \
    "$fixture_dir/dependency.c" -o "$output_root/native/libglue_probe_dep.dylib"
xcrun clang -arch arm64 -mmacosx-version-min=13.0 -O2 -g0 -Wall -Wextra -Werror \
    -fPIC -fno-stack-protector -fno-unwind-tables -fno-asynchronous-unwind-tables \
    -dynamiclib -Wl,-no_fixup_chains,-bind_at_load,-no_compact_unwind \
    -Wl,-install_name,@loader_path/libglue_probe_module.dylib \
    "$fixture_dir/module.c" -L"$output_root/native" -lglue_probe_dep \
    -o "$output_root/native/libglue_probe_module.dylib"
xcrun clang -arch arm64 -mmacosx-version-min=13.0 -O2 -g0 -Wall -Wextra -Werror \
    "$fixture_dir/baseline.c" -o "$output_root/baseline"

# All artifacts are ad-hoc signed; the experiment later signs only its launcher
# with hardened runtime and the single allow-jit entitlement.
codesign --force --sign - "$output_root/native/libglue_probe_dep.dylib"
codesign --force --sign - "$output_root/native/libglue_probe_module.dylib"
codesign --force --sign - "$output_root/baseline"
