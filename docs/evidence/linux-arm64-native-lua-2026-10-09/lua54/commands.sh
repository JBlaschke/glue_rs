#!/bin/sh
set -eu

profile=${GLUE_LUA_PROFILE:-lua54}
case "$profile" in
    lua54) release=5.4.9; minor=5.4 ;;
    lua55) release=5.5.1; minor=5.5 ;;
    *) echo 'Expected lua54 or lua55 profile.' >&2; exit 1 ;;
esac
mkdir -p "$CARGO_HOME"
printf '%s\n' '[source.crates-io]' 'replace-with = "vendored-sources"' \
    '[source.vendored-sources]' 'directory = "/workspace/target/linux-lua-vendor"' \
    > "$CARGO_HOME/config.toml"
set -- --no-default-features --features "glue-runner/$profile,glue-runtime-lua/$profile"
cargo test --workspace --locked --offline --quiet "$@" > /evidence/source-workspace-tests.txt 2>&1
cargo clippy --workspace --locked --offline --all-targets "$@" -- -D warnings \
    > /evidence/source-workspace-clippy.txt 2>&1
set -- --no-default-features --features "glue-runner/$profile,glue-runtime-lua/$profile,glue-runner/linux-native"
cargo build --workspace --locked --offline --quiet "$@"
cargo test --workspace --locked --offline --quiet "$@" > /evidence/workspace-tests.txt 2>&1
cargo clippy --workspace --locked --offline --all-targets "$@" -- -D warnings \
    > /evidence/workspace-clippy.txt 2>&1
find /workspace/crates /workspace/spikes /workspace/fixtures \
    /workspace/scripts -type f \( -name '*.rs' -o -name '*.toml' -o -name '*.c' \
    -o -name '*.h' -o -name '*.lua' -o -name '*.json' -o -name '*.txt' \
    -o -name '*.sh' -o -name '*.py' \) -print0 \
    | LC_ALL=C sort -z | xargs -0 sha256sum > /evidence/source.sha256
sha256sum Cargo.toml Cargo.lock rust-toolchain.toml \
    fixtures/native/linux-memfd/Dockerfile >> /evidence/source.sha256
cp fixtures/native/lua-linux/run-linux.sh /evidence/commands.sh

input_root=/build-target/native-input
sh fixtures/native/lua-linux/build-fixture.sh "$input_root" "$profile"
sh fixtures/native/lua-linux/manifest.sh "$input_root" "$profile" /evidence/manifest.input.json
sha256sum "$input_root"/native/*.so "$input_root/app/main.lua" "$input_root/assets/message.txt" \
    > /evidence/fixture-inputs.sha256
for image in dep native; do
    readelf -d -r -Ws "$input_root/native/libglue_lua_$image.so" > "/evidence/$image.elf.txt"
done

# Use exactly one Cargo-built Lua static core/header set for the ordinary
# loader baseline. Selected-profile build instances must produce equal cores.
selected=
mkdir /evidence/build-provenance
for record in /build-target/debug/build/glue-runtime-lua-*/out/linked-lua-provenance.txt; do
    test -f "$record"
    out=$(dirname "$record")
    instance=$(basename "$(dirname "$out")")
    cp "$record" "/evidence/build-provenance/$instance.txt"
    if test -f "$out/lib/liblua$minor.a"; then
        if test -z "$selected"; then
            selected=$out
        else
            cmp "$selected/lib/liblua$minor.a" "$out/lib/liblua$minor.a"
            cmp "$selected/include/lua.h" "$out/include/lua.h"
        fi
    fi
done
test -n "$selected"
grep -F "source=lua-src-551.0.2/lua-$release" "$selected/linked-lua-provenance.txt" > /evidence/baseline-core-source.txt
sha256sum "$selected/lib/liblua$minor.a" "$selected/include/lua.h" \
    "$selected/include/lauxlib.h" crates/glue-runtime-lua/native-exports.txt \
    > /evidence/baseline-core.sha256
set --
while IFS= read -r symbol; do
    case "$symbol" in
        ''|'#'*) continue ;;
    esac
    set -- "$@" "-Wl,--export-dynamic-symbol=$symbol" "-Wl,-u,$symbol"
done < crates/glue-runtime-lua/native-exports.txt
cc -O2 -g0 -Wall -Wextra -Werror -I"$selected/include" \
    fixtures/native/lua-linux/baseline.c "$selected/lib/liblua$minor.a" \
    "$@" -lm -ldl -o /build-target/native-baseline
nm -D --defined-only /build-target/native-baseline > /evidence/baseline.exports.txt
readelf -d /build-target/native-baseline > /evidence/baseline.dynamic.txt
set +e
/build-target/native-baseline "$input_root" > /evidence/baseline.stdout.txt 2> /evidence/baseline.stderr.txt
baseline_status=$?
set -e
printf '%s\n' "$baseline_status" > /evidence/baseline.exit-status.txt
test "$baseline_status" -eq 0
test ! -s /evidence/baseline.stderr.txt

glue=/build-target/debug/glue
mkdir -p /build-target/package-origin '/build-target/relocated native Lua fixture'
"$glue" build --manifest /evidence/manifest.input.json --root "$input_root" \
    --output /build-target/package-origin/app.glue \
    > /evidence/build.stdout.txt 2> /evidence/build.stderr.txt
mv /build-target/package-origin/app.glue '/build-target/relocated native Lua fixture/app.glue'
rmdir /build-target/package-origin
chmod 0444 '/build-target/relocated native Lua fixture/app.glue'
cp '/build-target/relocated native Lua fixture/app.glue' /evidence/app.glue
sha256sum "$glue" /build-target/native-baseline '/build-target/relocated native Lua fixture/app.glue' \
    > /evidence/artifacts.sha256
readelf -d --dyn-syms "$glue" > /evidence/launcher.elf.txt
nm -D --defined-only "$glue" > /evidence/launcher.exports.txt
sed '/^#/d; /^$/d' crates/glue-runtime-lua/native-exports.txt | LC_ALL=C sort \
    > /evidence/expected-lua-exports.txt
for binary in baseline launcher; do
    awk '$NF ~ /^lua/ { print $NF }' "/evidence/$binary.exports.txt" | LC_ALL=C sort \
        > "/evidence/$binary.lua-exports.txt"
    cmp /evidence/expected-lua-exports.txt "/evidence/$binary.lua-exports.txt"
done
if grep -E 'NEEDED.*\[liblua' /evidence/baseline.dynamic.txt /evidence/launcher.elf.txt; then
    echo 'unexpected separately linked liblua dependency' >&2
    exit 1
fi
cargo tree --workspace --locked --offline -e features -i lua-src \
    --no-default-features --features "glue-runner/$profile,glue-runtime-lua/$profile,glue-runner/linux-native" \
    > /evidence/lua-src-feature-tree.txt
sh fixtures/native/lua-linux/reject-linux.sh "$input_root" "$profile"
rm -r "$input_root"
test ! -e "$input_root"
uname -srvmo > /evidence/environment.txt
rustc --version >> /evidence/environment.txt
cargo clippy --version >> /evidence/environment.txt
cc --version >> /evidence/environment.txt
dpkg-query -W libc6 gcc strace >> /evidence/environment.txt
printf 'page_size=' >> /evidence/environment.txt
getconf PAGESIZE >> /evidence/environment.txt
printf 'vm.memfd_noexec=' >> /evidence/environment.txt
cat /proc/sys/vm/memfd_noexec >> /evidence/environment.txt
printf 'runtime_profile=%s linux-native-v1 c-boundary=1 Lua=%s\n' "$profile" "$release" >> /evidence/environment.txt
unset LD_LIBRARY_PATH LD_PRELOAD LD_AUDIT LUA_PATH LUA_PATH_5_4 LUA_PATH_5_5 LUA_CPATH LUA_CPATH_5_4 LUA_CPATH_5_5
cd '/build-target/relocated native Lua fixture'
set +e
strace -f -yy -s 256 -e trace=all -o /evidence/native-lua.trace.txt \
    "$glue" run '/build-target/relocated native Lua fixture/app.glue' \
    > /evidence/native-lua.stdout.txt 2> /evidence/native-lua.stderr.txt
run_status=$?
set -e
printf '%s\n' "$run_status" > /evidence/native-lua.exit-status.txt
test "$run_status" -eq 0
test ! -s /evidence/native-lua.stderr.txt
