#!/bin/sh
# Offline build-time generation for an explicit four-resource fixture inventory.
set -eu
if test "$#" -ne 3; then
    echo 'Usage: manifest.sh INPUT_ROOT lua54|lua55 OUTPUT_JSON' >&2
    exit 1
fi
input_root=$1
profile=$2
case "$profile" in
    lua54) release=5.4.9; minor=4; patch=9 ;;
    lua55) release=5.5.1; minor=5; patch=1 ;;
    *) echo 'Expected lua54 or lua55 profile.' >&2; exit 1 ;;
esac
fixture_dir=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
set -- "$3"
for item in MAIN ASSET DEP MOD; do
    case "$item" in
        MAIN) key=app/main.lua ;;
        ASSET) key=assets/message.txt ;;
        DEP) key=native/libglue_lua_dep.so ;;
        MOD) key=native/libglue_lua_native.so ;;
    esac
    size=$(wc -c < "$input_root/$key" | tr -d '[:space:]')
    hash=$(sha256sum "$input_root/$key" | cut -d ' ' -f 1)
    set -- "$@" -e "s/\"@${item}_SIZE@\"/$size/g" -e "s/@${item}_HASH@/$hash/g"
done
output=$1
shift
sed "$@" -e "s/@PROFILE@/$profile/g" -e "s/@RELEASE@/$release/g" \
    -e "s/\"@MINOR@\"/$minor/g" -e "s/\"@PATCH@\"/$patch/g" \
    "$fixture_dir/manifest.template.json" > "$output"
