#!/bin/sh
set -eu

test "${GLUE_LUA_VERSION:-5.4}" = 5.4
mkdir -p "$CARGO_HOME"
printf '%s\n' '[source.crates-io]' 'replace-with = "vendored-sources"' \
    '[source.vendored-sources]' 'directory = "/workspace/target/linux-lua-vendor"' \
    > "$CARGO_HOME/config.toml"
cargo build --locked --offline --quiet -p glue-runner
cargo test --locked --offline --quiet -p glue-runtime-lua -p glue-runner \
    > /evidence/runtime-cli-tests.txt 2>&1
cargo clippy --locked --offline -p glue-runtime-lua -p glue-runner --all-targets -- -D warnings \
    > /evidence/runtime-cli-clippy.txt 2>&1
find /workspace/crates /workspace/fixtures/lua-linked /workspace/scripts \
    -type f \( -name '*.rs' -o -name '*.toml' -o -name '*.c' -o -name '*.lua' \
    -o -name '*.json' -o -name '*.txt' -o -name '*.sh' -o -name '*.py' \) \
    -print0 | LC_ALL=C sort -z | xargs -0 sha256sum > /evidence/source.sha256
sha256sum Cargo.toml Cargo.lock rust-toolchain.toml \
    fixtures/native/linux-memfd/Dockerfile >> /evidence/source.sha256
cp fixtures/lua-linked/run-linux.sh /evidence/commands.sh
cp fixtures/lua-linked/manifest.linux-arm64.json /evidence/manifest.input.json
sha256sum fixtures/lua-linked/manifest.linux-arm64.json \
    fixtures/lua-linked/input/app/main.lua fixtures/lua-linked/input/app/lib/*.lua \
    fixtures/lua-linked/input/assets/message.txt > /evidence/fixture-inputs.sha256

glue=/build-target/debug/glue
mkdir -p /build-target/package-origin '/build-target/relocated Lua fixture'
"$glue" build --manifest fixtures/lua-linked/manifest.linux-arm64.json \
    --root fixtures/lua-linked/input --output /build-target/package-origin/app.glue \
    > /evidence/build.stdout.txt 2> /evidence/build.stderr.txt
mv /build-target/package-origin/app.glue '/build-target/relocated Lua fixture/app.glue'
rmdir /build-target/package-origin
chmod 0444 '/build-target/relocated Lua fixture/app.glue'
cp '/build-target/relocated Lua fixture/app.glue' /evidence/app.glue
sha256sum "$glue" '/build-target/relocated Lua fixture/app.glue' \
    > /evidence/artifacts.sha256
readelf -d "$glue" > /evidence/launcher.dynamic.txt
set -- /build-target/debug/build/glue-runtime-lua-*/out/linked-lua-provenance.txt
test "$#" -eq 1
cp "$1" /evidence/linked-lua-provenance.txt
cargo tree --locked --offline -e features -i lua-src > /evidence/lua-src-feature-tree.txt
uname -srvmo > /evidence/environment.txt
rustc --version >> /evidence/environment.txt
cargo clippy --version >> /evidence/environment.txt
cc --version >> /evidence/environment.txt
dpkg-query -W libc6 gcc strace >> /evidence/environment.txt
printf 'page_size=' >> /evidence/environment.txt
getconf PAGESIZE >> /evidence/environment.txt
printf 'runtime_build=mlua-0.12.2 lua-src-551.0.2 Lua-5.4.9 int64-float64\n' \
    >> /evidence/environment.txt

unset LD_LIBRARY_PATH LD_PRELOAD LD_AUDIT LUA_PATH LUA_PATH_5_4 LUA_CPATH LUA_CPATH_5_4
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
