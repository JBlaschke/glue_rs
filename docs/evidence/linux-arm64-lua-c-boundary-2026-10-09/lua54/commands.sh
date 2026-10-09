#!/bin/sh
set -eu

lua_profile=${GLUE_LUA_PROFILE:-lua54}
case "$lua_profile" in
    lua54)
        lua_version=5.4
        manifest=fixtures/lua-linked/manifest.linux-arm64.json
        set --
        ;;
    lua55)
        lua_version=5.5
        manifest=fixtures/lua-linked/manifest.lua55.linux-arm64.json
        set -- --no-default-features --features glue-runner/lua55,glue-runtime-lua/lua55
        ;;
    *) echo 'Expected lua54 or lua55 profile.' >&2; exit 1 ;;
esac
mkdir -p "$CARGO_HOME"
printf '%s\n' '[source.crates-io]' 'replace-with = "vendored-sources"' \
    '[source.vendored-sources]' 'directory = "/workspace/target/linux-lua-vendor"' \
    > "$CARGO_HOME/config.toml"
cargo build --workspace --locked --offline --quiet "$@"
cargo test --workspace --locked --offline --quiet "$@" \
    > /evidence/workspace-tests.txt 2>&1
cargo clippy --workspace --locked --offline --all-targets "$@" -- -D warnings \
    > /evidence/workspace-clippy.txt 2>&1
find /workspace/crates /workspace/spikes /workspace/fixtures/lua-linked /workspace/scripts \
    -type f \( -name '*.rs' -o -name '*.toml' -o -name '*.c' -o -name '*.h' -o -name '*.lua' \
    -o -name '*.json' -o -name '*.txt' -o -name '*.sh' -o -name '*.py' \) \
    -print0 | LC_ALL=C sort -z | xargs -0 sha256sum > /evidence/source.sha256
sha256sum Cargo.toml Cargo.lock rust-toolchain.toml \
    fixtures/native/linux-memfd/Dockerfile >> /evidence/source.sha256
cp fixtures/lua-linked/run-linux.sh /evidence/commands.sh
cp "$manifest" /evidence/manifest.input.json
sha256sum "$manifest" \
    fixtures/lua-linked/input/app/main.lua fixtures/lua-linked/input/app/lib/*.lua \
    fixtures/lua-linked/input/assets/message.txt > /evidence/fixture-inputs.sha256

glue=/build-target/debug/glue
mkdir -p /build-target/package-origin '/build-target/relocated Lua fixture'
"$glue" build --manifest "$manifest" \
    --root fixtures/lua-linked/input --output /build-target/package-origin/app.glue \
    > /evidence/build.stdout.txt 2> /evidence/build.stderr.txt
mv /build-target/package-origin/app.glue '/build-target/relocated Lua fixture/app.glue'
rmdir /build-target/package-origin
chmod 0444 '/build-target/relocated Lua fixture/app.glue'
cp '/build-target/relocated Lua fixture/app.glue' /evidence/app.glue
sha256sum "$glue" '/build-target/relocated Lua fixture/app.glue' \
    > /evidence/artifacts.sha256
readelf -d "$glue" > /evidence/launcher.dynamic.txt
cargo tree --workspace --locked --offline -e features -i lua-src "$@" \
    > /evidence/lua-src-feature-tree.txt
# Cargo build/test and Clippy can produce separate build-script instances. Keep
# every instance rather than assuming one output directory or picking a record.
mkdir /evidence/build-provenance
provenance_count=0
for provenance in /build-target/debug/build/glue-runtime-lua-*/out/linked-lua-provenance.txt; do
    test -f "$provenance"
    instance=$(basename "$(dirname "$(dirname "$provenance")")")
    cp "$provenance" "/evidence/build-provenance/$instance.txt"
    provenance_count=$((provenance_count + 1))
done
test "$provenance_count" -gt 0
uname -srvmo > /evidence/environment.txt
rustc --version >> /evidence/environment.txt
cargo clippy --version >> /evidence/environment.txt
cc --version >> /evidence/environment.txt
dpkg-query -W libc6 gcc strace >> /evidence/environment.txt
printf 'page_size=' >> /evidence/environment.txt
getconf PAGESIZE >> /evidence/environment.txt
printf 'runtime_profile=%s c-boundary=1 lua-src=551.0.2 Lua=%s int64-float64\n' "$lua_profile" "$lua_version" \
    >> /evidence/environment.txt

unset LD_LIBRARY_PATH LD_PRELOAD LD_AUDIT LUA_PATH LUA_PATH_5_4 LUA_PATH_5_5 LUA_CPATH LUA_CPATH_5_4 LUA_CPATH_5_5
cd '/build-target/relocated Lua fixture'
set +e
strace -f -yy -s 256 -e trace=all \
    -o /evidence/lua.trace.txt \
    "$glue" run '/build-target/relocated Lua fixture/app.glue' \
    > /evidence/lua.stdout.txt 2> /evidence/lua.stderr.txt
lua_status=$?
set -e
printf '%s\n' "$lua_status" > /evidence/lua.exit-status.txt
test "$lua_status" -eq 0
