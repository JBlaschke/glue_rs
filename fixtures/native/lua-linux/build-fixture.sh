#!/bin/sh
set -eu

if test "$#" -ne 2; then
    echo 'Usage: build-fixture.sh OUTPUT_ROOT lua54|lua55' >&2
    exit 1
fi
output_root=$1
case "$2" in
    lua54) release=5.4.9 ;;
    lua55) release=5.5.1 ;;
    *) echo 'Expected lua54 or lua55 profile.' >&2; exit 1 ;;
esac
fixture_dir=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
headers=/workspace/target/linux-lua-vendor/lua-src/lua-$release
test -f "$headers/lua.h"
test -f "$headers/lauxlib.h"
mkdir -p "$output_root/native" "$output_root/app" "$output_root/assets"
cp "$fixture_dir/input/app/main.lua" "$output_root/app/main.lua"
cp "$fixture_dir/input/assets/message.txt" "$output_root/assets/message.txt"

# No CRT helper imports, ELF GNU-hash requirement, lazy PLT binding, executable
# stack or search paths. The Lua API remains unresolved until the selected
# launcher supplies it; linking a second liblua would invalidate this test.
cc -O2 -g0 -Wall -Wextra -Werror -fPIC -shared -nostartfiles \
    -Wl,--hash-style=sysv,-z,now,-z,noexecstack,-z,defs \
    -Wl,-soname,libglue_lua_dep.so "$fixture_dir/dependency.c" \
    -o "$output_root/native/libglue_lua_dep.so"
cc -O2 -g0 -Wall -Wextra -Werror -fPIC -shared -nostartfiles \
    -I"$headers" -Wl,--hash-style=sysv,-z,now,-z,noexecstack \
    -Wl,-soname,libglue_lua_native.so "$fixture_dir/module.c" \
    -L"$output_root/native" -lglue_lua_dep \
    -o "$output_root/native/libglue_lua_native.so"
