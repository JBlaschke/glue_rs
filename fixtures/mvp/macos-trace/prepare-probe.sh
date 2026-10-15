#!/bin/sh
# Compile only an independently owned diagnostic fixture; never requests sudo.
set -eu
if [ "$#" -ne 1 ]; then echo 'usage: prepare-probe.sh NEW_DIRECTORY' >&2; exit 2; fi
test "$(uname -s)" = Darwin
case "$1" in /*) ;; *) echo 'directory must be absolute' >&2; exit 2;; esac
mkdir "$1"
source_dir=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
printf 'owned trace fixture\n' > "$1/input.txt"
/usr/bin/cc -O2 -std=c11 -D_DARWIN_C_SOURCE -Wall -Wextra -Werror -Wno-deprecated-declarations \
    "$source_dir/owned-probe.c" -o "$1/owned-probe" > "$1/compile.log" 2>&1
/usr/bin/codesign --force --sign - --timestamp=none "$1/owned-probe" > "$1/sign.log" 2>&1
/usr/bin/codesign --verify --strict "$1/owned-probe"
/usr/bin/codesign -d --verbose=4 "$1/owned-probe" > "$1/signature.stdout" 2> "$1/signature.txt"
"$1/owned-probe" "$1/input.txt" > "$1/fixture.stdout"
printf '%s\n' "$1"
