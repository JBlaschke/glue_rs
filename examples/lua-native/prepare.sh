#!/bin/sh
# Dependency preparation is explicit; glue itself never runs this script.
set -eu

if [ "$#" -ne 1 ]; then
    echo "usage: $0 LUA_5_4_HEADERS_DIRECTORY" >&2
    exit 2
fi
headers=$1
for header in lua.h lauxlib.h luaconf.h; do
    if [ ! -f "$headers/$header" ]; then
        echo "missing Lua header: $headers/$header" >&2
        exit 2
    fi
done
project=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
if [ -e "$project/.deps" ]; then
    echo "dependencies already exist: $project/.deps (keep them, or remove explicitly to rebuild)" >&2
    exit 2
fi
case "$(uname -s)" in
    Darwin|Linux) ;;
    *) echo "this example supports macOS and GNU Linux" >&2; exit 2 ;;
esac

staging=$(mktemp -d "$project/.deps-build.XXXXXX")
trap 'rm -rf "$staging"' EXIT HUP INT TERM
modules="$staging/rocks/lib/lua/5.4"
sources="$staging/rocks/share/lua/5.4"
mkdir -p "$modules" "$sources"
cp "$project/vendor/inspect-3.1.3/inspect.lua" "$sources/inspect.lua"

# CC is the compiler executable, for example /usr/bin/clang or /usr/bin/gcc.
compiler=${CC:-cc}
case "$(uname -s)" in
    Darwin)
        "$compiler" -std=c11 -O2 -Wall -Wextra -Werror -fPIC -dynamiclib \
            -Wl,-install_name,@rpath/libtemperature.dylib \
            "$project/native/temperature.c" -o "$modules/libtemperature.dylib"
        "$compiler" -std=c11 -O2 -Wall -Wextra -Werror -fPIC -bundle \
            -undefined dynamic_lookup -Wl,-rpath,@loader_path \
            -I "$headers" "$project/native/lua_temperature.c" \
            -L "$modules" -ltemperature -o "$modules/temperature.so"
        /usr/bin/codesign --force --sign - "$modules/libtemperature.dylib"
        /usr/bin/codesign --force --sign - "$modules/temperature.so"
        ;;
    Linux)
        "$compiler" -std=c11 -O2 -Wall -Wextra -Werror -fPIC -shared \
            -Wl,-soname,libtemperature.so \
            "$project/native/temperature.c" -o "$modules/libtemperature.so"
        "$compiler" -std=c11 -O2 -Wall -Wextra -Werror -fPIC -shared \
            '-Wl,-rpath,$ORIGIN' -I "$headers" \
            "$project/native/lua_temperature.c" -L "$modules" \
            -ltemperature -o "$modules/temperature.so"
        ;;
esac
mv "$staging" "$project/.deps"
trap - EXIT HUP INT TERM
printf 'Prepared inspect.lua and native temperature dependencies in %s/.deps\n' "$project"
