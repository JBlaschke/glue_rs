#!/bin/sh
# Build-time adversarial variants; every product run is traced in a fresh process.
set -eu
if test "$#" -ne 2; then
    echo 'Usage: reject-linux.sh VALID_INPUT_ROOT lua54|lua55' >&2
    exit 1
fi
valid_input=$1
profile=$2
case "$profile" in
    lua54) release=5.4.9 ;;
    lua55) release=5.5.1 ;;
    *) echo 'Expected lua54 or lua55 profile.' >&2; exit 1 ;;
esac
fixture_dir=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
headers=/workspace/target/linux-lua-vendor/lua-src/lua-$release
glue=/build-target/debug/glue
test -f "$headers/lua.h"
test -f "$valid_input/native/libglue_lua_dep.so"
test -f "$valid_input/native/libglue_lua_native.so"
test -x "$glue"
mkdir /build-target/native-rejections /build-target/native-rejections-input /evidence/native-rejections
cp "$fixture_dir/reject-linux.sh" /evidence/native-rejections/commands.sh

unset LD_LIBRARY_PATH LD_PRELOAD LD_AUDIT LUA_PATH LUA_PATH_5_4 LUA_PATH_5_5 LUA_CPATH LUA_CPATH_5_4 LUA_CPATH_5_5
for variant in wrong-architecture soname-mismatch executable-stack undeclared-needed undeclared-import wrong-initializer; do
    input=/build-target/native-rejections-input/$variant
    archive=/build-target/native-rejections/$variant.glue
    evidence=/evidence/native-rejections/$variant
    mkdir "$input"
    cp -R "$valid_input/." "$input/"
    expected_status=1
    case "$variant" in
        wrong-architecture)
            # Change e_machine from EM_AARCH64 (183) to EM_X86_64 (62).
            printf '\076' | dd of="$input/native/libglue_lua_native.so" bs=1 seek=18 count=1 conv=notrunc status=none
            expected='glue: native Lua closure is unsupported: native_probe: require ET_DYN AArch64'
            expected_status=2
            ;;
        *)
            set --
            soname=libglue_lua_native.so
            stack=noexecstack
            case "$variant" in
                soname-mismatch)
                    soname=libwrong_native.so
                    expected='glue: invalid native Lua closure: native_probe: SONAME "libwrong_native.so" does not match "libglue_lua_native.so"'
                    ;;
                executable-stack)
                    stack=execstack
                    expected='glue: native Lua closure is unsupported: native_probe: unknown segment permissions or writable executable segment'
                    expected_status=2
                    ;;
                undeclared-needed)
                    set -- -Wl,--no-as-needed -lm -Wl,--as-needed
                    expected='glue: invalid native Lua closure: native_probe: ELF NEEDED differs from declared direct dependencies'
                    ;;
                undeclared-import)
                    cat > "$input/forbidden-constructor.c" <<'C'
extern void glue_forbidden_constructor(void);
__attribute__((constructor))
static void forbidden_constructor(void) {
    glue_forbidden_constructor();
}
C
                    cp "$input/forbidden-constructor.c" "$evidence.extra.c"
                    set -- "$input/forbidden-constructor.c"
                    expected='glue: invalid native Lua closure: native_probe: undeclared undefined symbol "glue_forbidden_constructor"'
                    ;;
                wrong-initializer)
                    set -- -Dluaopen_native_probe=luaopen_other
                    expected='glue: invalid native Lua closure: native_probe: payload defines Lua runtime symbol luaopen_other'
                    ;;
            esac
            cc -O2 -g0 -Wall -Wextra -Werror -fPIC -shared -nostartfiles \
                -I"$headers" -Wl,--hash-style=sysv,-z,now -Wl,-z,"$stack" \
                -Wl,-soname,"$soname" "$fixture_dir/module.c" \
                -L"$input/native" -lglue_lua_dep "$@" \
                -o "$input/native/libglue_lua_native.so"
            ;;
    esac
    printf '%s\n' "$expected" > "$evidence.expected.stderr.txt"
    sh "$fixture_dir/manifest.sh" "$input" "$profile" "$evidence.manifest.json"
    sha256sum "$input"/native/*.so "$input/app/main.lua" "$input/assets/message.txt" \
        > "$evidence.inputs.sha256"
    readelf -h -l -d -r -Ws "$input/native/libglue_lua_native.so" > "$evidence.elf.txt"
    "$glue" build --manifest "$evidence.manifest.json" --root "$input" --output "$archive" \
        > "$evidence.build.stdout.txt" 2> "$evidence.build.stderr.txt"
    sha256sum "$archive" > "$evidence.archive.sha256"
    cp "$archive" "$evidence.glue"
    set +e
    strace -f -yy -s 256 -e trace=all -o "$evidence.trace.txt" \
        "$glue" run "$archive" > "$evidence.stdout.txt" 2> "$evidence.stderr.txt"
    status=$?
    set -e
    printf '%s\n' "$status" > "$evidence.exit-status.txt"
    test "$status" -eq "$expected_status"
    test ! -s "$evidence.stdout.txt"
    cmp "$evidence.expected.stderr.txt" "$evidence.stderr.txt"
done
# Build-time inputs and archives stay in ephemeral /build-target until the
# container exits. The host checks every retained full trace after this script.
