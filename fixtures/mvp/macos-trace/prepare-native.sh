#!/bin/sh
# Build owned capability tools on the host; the guest needs no CLT or Python.
set -eu
if [ "$#" -ne 1 ]; then echo 'usage: prepare-native.sh NEW_ABSOLUTE_DIRECTORY' >&2; exit 2; fi
test "$(uname -s)" = Darwin
test "$(uname -m)" = arm64
case "$1" in /*) ;; *) echo 'directory must be absolute' >&2; exit 2;; esac
mkdir "$1"
output_dir=$1
source_dir=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
sdk=$(xcrun --sdk macosx26.5 --show-sdk-path)
printf 'owned trace fixture\n' > "$output_dir/input.txt"
printf '%s\n' "$sdk" > "$output_dir/sdk-path.txt"
/usr/bin/cc --version > "$output_dir/compiler.txt"
for name in capture-native lifecycle-probe owned-probe; do
    cp "$source_dir/$name.c" "$output_dir/$name.c"
    set -- /usr/bin/cc -isysroot "$sdk" -arch arm64 -mmacosx-version-min=11.0 -O2 -std=c11 \
        -D_DARWIN_C_SOURCE -Wall -Wextra -Werror -Wno-deprecated-declarations \
        "$output_dir/$name.c"
    case "$name" in capture-native) set -- "$@" -ldtrace ;; esac
    set -- "$@" -o "$output_dir/$name"
    printf '%s\0' "$@" > "$output_dir/$name-build.argv"
    "$@" > "$output_dir/$name-compile.log" 2>&1
    /usr/bin/codesign --force --sign - --timestamp=none "$output_dir/$name" > "$output_dir/$name-sign.log" 2>&1
    /usr/bin/codesign --verify --strict "$output_dir/$name"
    /usr/bin/codesign -d --verbose=4 "$output_dir/$name" > "$output_dir/$name-signature.stdout" 2> "$output_dir/$name-signature.txt"
    /usr/bin/otool -L "$output_dir/$name" > "$output_dir/$name-libraries.txt"
    /usr/bin/otool -l "$output_dir/$name" > "$output_dir/$name-load-commands.txt"
done
cp "$source_dir/CAPTURE_FORMAT.md" "$source_dir/prepare-native.sh" "$output_dir/"
(cd "$output_dir" && /usr/bin/shasum -a 256 capture-native lifecycle-probe owned-probe input.txt ./*.c ./*.argv prepare-native.sh CAPTURE_FORMAT.md) > "$output_dir/SHA256SUMS"
"$output_dir/owned-probe" "$output_dir/input.txt" > "$output_dir/owned-probe-readiness.stdout"
"$output_dir/lifecycle-probe" read "$output_dir/input.txt" > "$output_dir/lifecycle-readiness.stdout"
printf '%s\n' "$output_dir"
