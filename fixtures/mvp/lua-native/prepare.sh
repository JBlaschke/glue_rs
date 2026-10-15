#!/bin/sh
# Explicit independent fixture construction, never invoked by the packager.
set -eu
if [ "$#" -ne 2 ]; then
    echo 'usage: fixtures/mvp/lua-native/prepare.sh NEW_PROJECT LUA_HEADERS_DIRECTORY' >&2
    exit 2
fi
output=$1
headers=$2
test ! -e "$output"
test -f "$headers/lua.h"
fixture=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
mkdir -p "$output"
case "$(uname -s)" in
    Darwin)
        cc -fPIC -pthread -dynamiclib -Wl,-install_name,@rpath/libsecondary.dylib "$fixture/secondary.c" -o "$output/libsecondary.dylib"
        cc -fPIC -bundle -undefined dynamic_lookup -Wl,-rpath,@loader_path -I"$headers" "$fixture/module.c" -L"$output" -lsecondary -o "$output/module.so"
        ;;
    Linux)
        cc -fPIC -pthread -shared -Wl,-soname,libsecondary.so "$fixture/secondary.c" -o "$output/libsecondary.so"
        cc -fPIC -shared '-Wl,-rpath,$ORIGIN' -I"$headers" "$fixture/module.c" -L"$output" -lsecondary -o "$output/module.so"
        ;;
    *) echo 'native fixture needs Linux or macOS' >&2; exit 2 ;;
esac
for alias in failed missing mismatched; do ln -s module.so "$output/$alias.so"; done
cp "$fixture/main.lua" "$output/main.lua"
