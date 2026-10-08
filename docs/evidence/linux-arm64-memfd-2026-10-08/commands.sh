#!/bin/sh
set -eu

build_dir=/build-target/cabi
mkdir -p "$build_dir"
# Give every Cargo subprocess the same offline source through its temporary home.
mkdir -p "$CARGO_HOME"
printf '%s\n' '[source.crates-io]' 'replace-with = "vendored-sources"' \
    '[source.vendored-sources]' 'directory = "/workspace/target/vendor"' \
    > "$CARGO_HOME/config.toml"
cargo --config 'source.crates-io.replace-with="vendored-sources"' \
    --config 'source.vendored-sources.directory="/workspace/target/vendor"' \
    build --locked --offline --quiet -p glue-linux-memfd-probe
cargo --config 'source.crates-io.replace-with="vendored-sources"' \
    --config 'source.vendored-sources.directory="/workspace/target/vendor"' \
    test --workspace --locked --offline --quiet > /evidence/workspace-tests.txt
cargo --config 'source.crates-io.replace-with="vendored-sources"' \
    --config 'source.vendored-sources.directory="/workspace/target/vendor"' \
    clippy --workspace --all-targets --locked --offline -- -D warnings \
    > /evidence/workspace-clippy.txt 2>&1
find /workspace/crates /workspace/spikes /workspace/fixtures/native/linux-memfd \
    /workspace/scripts -type f \( -name '*.rs' -o -name '*.toml' -o -name '*.c' \
    -o -name '*.sh' -o -name '*.py' -o -name Dockerfile \) -print0 \
    | LC_ALL=C sort -z | xargs -0 sha256sum \
    > /evidence/source.sha256
sha256sum Cargo.toml Cargo.lock rust-toolchain.toml >> /evidence/source.sha256
cp /workspace/fixtures/native/linux-memfd/run.sh /evidence/commands.sh

cc -O2 -g0 -fPIC -shared -Wl,-z,defs -Wl,-soname,libglue_probe_dep.so \
    /workspace/fixtures/native/linux-memfd/dependency.c \
    -o "$build_dir/libglue_probe_dep.so"
cc -O2 -g0 -fPIC -fno-builtin-strlen -shared -Wl,-z,defs \
    -Wl,-soname,libglue_probe_module.so \
    /workspace/fixtures/native/linux-memfd/module.c \
    -L"$build_dir" -lglue_probe_dep -o "$build_dir/libglue_probe_module.so"
cc -O2 -g0 -Wall -Wextra -Werror \
    /workspace/fixtures/native/linux-memfd/baseline.c -ldl -o "$build_dir/baseline"
set +e
LD_LIBRARY_PATH="$build_dir" "$build_dir/baseline" "$build_dir/libglue_probe_module.so" \
    > /evidence/baseline.stdout.txt 2> /evidence/baseline.stderr.txt
baseline_status=$?
set -e
printf '%s\n' "$baseline_status" > /evidence/baseline.exit-status.txt
test "$baseline_status" -eq 0
cat /evidence/baseline.stdout.txt
sha256sum "$build_dir"/libglue_probe_*.so "$build_dir/baseline" \
    > /evidence/native-inputs.sha256

readelf -d "$build_dir/libglue_probe_dep.so" > /evidence/dependency.dynamic.txt
readelf -d "$build_dir/libglue_probe_module.so" > /evidence/module.dynamic.txt
grep -F 'Library soname: [libglue_probe_dep.so]' /evidence/dependency.dynamic.txt
grep -F 'Library soname: [libglue_probe_module.so]' /evidence/module.dynamic.txt
grep -F 'Shared library: [libglue_probe_dep.so]' /evidence/module.dynamic.txt
grep -F 'Shared library: [libc.so.6]' /evidence/module.dynamic.txt
if grep -E 'RPATH|RUNPATH' /evidence/dependency.dynamic.txt /evidence/module.dynamic.txt; then
    echo 'unexpected fixture search path' >&2
    exit 1
fi

probe=/build-target/debug/glue-linux-memfd-probe
"$probe" prepare /evidence/app.glue "$build_dir/libglue_probe_dep.so" "$build_dir/libglue_probe_module.so"
sha256sum "$probe" /evidence/app.glue > /evidence/artifacts.sha256
# Compiler outputs are build-time inputs only; execution has no .so pathname.
rm "$build_dir/libglue_probe_dep.so" "$build_dir/libglue_probe_module.so"

uname -srvmo > /evidence/environment.txt
rustc --version >> /evidence/environment.txt
cargo clippy --version >> /evidence/environment.txt
cc --version >> /evidence/environment.txt
dpkg-query -W libc6 gcc strace >> /evidence/environment.txt
printf 'page_size=' >> /evidence/environment.txt
getconf PAGESIZE >> /evidence/environment.txt
printf 'vm.memfd_noexec=' >> /evidence/environment.txt
cat /proc/sys/vm/memfd_noexec >> /evidence/environment.txt

unset LD_LIBRARY_PATH LD_PRELOAD LD_AUDIT
set +e
strace -f -yy -s 256 -e trace=all \
    -o /evidence/probe.trace.txt \
    "$probe" run /evidence/app.glue \
    > /evidence/probe.stdout.txt 2> /evidence/probe.stderr.txt
probe_status=$?
set -e
printf '%s\n' "$probe_status" > /evidence/probe.exit-status.txt
test "$probe_status" -eq 0
cat /evidence/probe.stdout.txt
