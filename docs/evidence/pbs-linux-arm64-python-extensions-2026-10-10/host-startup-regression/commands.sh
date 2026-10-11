#!/bin/sh
# Host-runtime construction is a build-time fixture operation. The eight traced
# runs only receive read-only prepared archives, library and stdlib sources.
set -eu

image=62812c4a0e15bc750ddd6ec68d2a19f8815a14b60d520e201a911e2e29f40abe
full=cpython-3.13.16+20261009-aarch64-unknown-linux-gnu-pgo+lto-full.tar.zst
install=cpython-3.13.16+20261009-aarch64-unknown-linux-gnu-install_only.tar.gz
relocated='/build-target/relocated Python host'
prefix='/build-target/host Python'

if test "${1:-}" = --build; then
    export PATH=/usr/local/rustup/toolchains/1.88.0-aarch64-unknown-linux-gnu/bin:$PATH
    export CARGO_HOME=/tmp/cargo CARGO_TARGET_DIR=/build-target
    export GLUE_PYTHON_INCLUDE_DIR=/build-target/include/python3.13
    mkdir -p "$CARGO_HOME"
    printf '%s\n' '[source.crates-io]' 'replace-with = "vendored-sources"' \
        '[source.vendored-sources]' 'directory = "/workspace/target/python-bootstrap-vendor"' \
        > "$CARGO_HOME/config.toml"
    /build-target/producer/bin/python3.13 -I -S -B \
        /build-target/producer/freeze-compiler.py /build-target/producer/freeze-input.json \
        /build-target/producer/freeze-provenance.json /build-target/freeze-bundle.json \
        /evidence/freeze-provenance.json > /evidence/freeze.stdout.txt 2> /evidence/freeze.stderr.txt
    test ! -s /evidence/freeze.stderr.txt
    cp /build-target/freeze-bundle.json /evidence/freeze-bundle.json
    cargo test --locked --offline --release -p glue-python-bootstrap-probe --features pbs-bootstrap \
        > /evidence/host-tests.txt 2>&1
    cargo clippy --locked --offline --release --all-targets -p glue-python-bootstrap-probe \
        --features pbs-bootstrap -- -D warnings > /evidence/host-clippy.txt 2>&1
    cargo build --locked --offline --release -p glue-python-bootstrap-probe --features pbs-bootstrap \
        > /evidence/host-build.txt 2>&1
    mkdir "$relocated" /build-target/runtime-empty
    /build-target/release/glue-python-bootstrap-probe prepare \
        "/workspace/target/pbs-inspection/$full" /build-target/freeze-bundle.json /build-target/baseline.glue \
        > /evidence/baseline-prepare.stdout.txt 2> /evidence/baseline-prepare.stderr.txt
    test ! -s /evidence/baseline-prepare.stderr.txt
    sha256sum /build-target/producer/lib/libpython3.13.so.1.0 > /evidence/baseline-library.before.sha256
    set +e
    /build-target/release/glue-python-bootstrap-probe baseline /build-target/baseline.glue \
        /build-target/producer/lib/libpython3.13.so.1.0 \
        > /evidence/baseline.stdout.txt 2> /evidence/baseline.stderr.txt
    status=$?
    set -e
    printf '%s\n' "$status" > /evidence/baseline.exit-status.txt
    test "$status" -eq 0
    test ! -s /evidence/baseline.stderr.txt
    sha256sum /build-target/producer/lib/libpython3.13.so.1.0 > /evidence/baseline-library.after.sha256
    cmp /evidence/baseline-library.before.sha256 /evidence/baseline-library.after.sha256
    /build-target/producer/bin/python3.13 -I -S -B /workspace/fixtures/python-host/prepare-controls.py \
        /build-target/producer "$prefix" /build-target/freeze-bundle.json /evidence/host-runtime-provenance.json \
        > /evidence/controls.stdout.txt 2> /evidence/controls.stderr.txt
    test ! -s /evidence/controls.stderr.txt
    for mode in success wrong-library wrong-stdlib missing-encodings symlink-stdlib missing-library cached-bytecode; do
        host_prefix="$prefix"
        if test "$mode" != success; then host_prefix="$prefix $mode"; fi
        /build-target/release/glue-python-bootstrap-probe prepare-host \
            "/workspace/target/pbs-inspection/$full" /build-target/freeze-bundle.json \
            "$host_prefix" "$relocated/$mode.glue" \
            > "/evidence/$mode.prepare.stdout.txt" 2> "/evidence/$mode.prepare.stderr.txt"
        test ! -s "/evidence/$mode.prepare.stderr.txt"
    done
    cp /build-target/release/glue-python-bootstrap-probe "$relocated/glue-python-bootstrap-probe"
    chmod 0555 "$relocated/glue-python-bootstrap-probe" "$relocated" /build-target/runtime-empty
    chmod 0444 "$relocated/"*.glue
    sha256sum "$relocated/glue-python-bootstrap-probe" "$relocated/"*.glue \
        /evidence/freeze-bundle.json > /evidence/artifacts.sha256
    readelf -d --dyn-syms "$relocated/glue-python-bootstrap-probe" > /evidence/launcher.elf.txt
    cp /workspace/fixtures/python-host/run-linux.sh /build-target/runtime-commands.sh
    mkdir /evidence/build-provenance
    for record in /build-target/release/build/glue-python-bootstrap-probe-*/out/python-bootstrap-provenance.txt; do
        test -f "$record"
        cp "$record" "/evidence/build-provenance/$(basename "$(dirname "$(dirname "$record")")").txt"
        nm -u "$(dirname "$record")/libglue_python_bootstrap_boundary.a" \
            > "/evidence/build-provenance/$(basename "$(dirname "$(dirname "$record")")").undefined.txt"
    done
    uname -srvmo > /evidence/environment.txt
    rustc --version >> /evidence/environment.txt
    cargo clippy --version >> /evidence/environment.txt
    cc --version >> /evidence/environment.txt
    dpkg-query -W libc6 gcc strace >> /evidence/environment.txt
    printf 'page_size=' >> /evidence/environment.txt
    getconf PAGESIZE >> /evidence/environment.txt
    # Ordinary comparison and producer are build-time only. The relocated host
    # tree has no executable interpreter and no cached bytecode.
    rm -rf /build-target/include /build-target/release /build-target/debug \
        /build-target/freeze-bundle.json /build-target/baseline.glue
    find /build-target -type f -o -type l > /evidence/post-removal-files.txt
    test ! -e /build-target/producer
    test ! -e /build-target/include
    test ! -e "$prefix/bin/python3.13"
    test -z "$(find "$prefix" -type f -name '*.pyc' -print)"
    exit 0
fi

if test "${1:-}" = --run; then
    cd /build-target/runtime-empty
    export HOME=/unavailable/home TMPDIR=/unavailable/tmp TZ=UTC0
    export PYTHONHOME=/forbidden/python-home PYTHONPATH=/forbidden/python-path
    export PYTHONUSERBASE=/forbidden/python-userbase PYTHONSTARTUP=/forbidden/startup.py
    export PYTHONPYCACHEPREFIX=/forbidden/pycache PYTHONIOENCODING=ascii PYTHONUTF8=0
    unset LD_LIBRARY_PATH LD_PRELOAD LD_AUDIT LD_DEBUG GLIBC_TUNABLES
    test ! -e /build-target/producer
    test ! -e /build-target/include
    test ! -e "$prefix/bin/python3.13"
    test ! -r /tmp
    test ! -w /tmp
    test ! -x /tmp
    test ! -r /unavailable
    id > /evidence/runtime-identity.txt
    cat /proc/mounts > /evidence/runtime-mounts.txt
    for mode in success wrong-library wrong-stdlib missing-encodings symlink-stdlib missing-library cached-bytecode app-error; do
        if test "$mode" = app-error; then
            set -- "$relocated/glue-python-bootstrap-probe" run-host-negative "$relocated/success.glue" app-error
            expected=1
        else
            set -- "$relocated/glue-python-bootstrap-probe" run-host "$relocated/$mode.glue"
            expected=1
            if test "$mode" = success; then expected=0; fi
        fi
        set +e
        strace -f -s 256 -yy -e trace=all -o "/evidence/$mode.trace.txt" "$@" \
            < /dev/null > "/evidence/$mode.stdout.txt" 2> "/evidence/$mode.stderr.txt"
        status=$?
        set -e
        printf '%s\n' "$status" > "/evidence/$mode.exit-status.txt"
        test "$status" -eq "$expected"
    done
    test ! -s /evidence/success.stderr.txt
    cmp /evidence/success.stdout.txt /evidence/app-error.stdout.txt
    for mode in wrong-library wrong-stdlib missing-encodings symlink-stdlib missing-library cached-bytecode; do
        test ! -s "/evidence/$mode.stdout.txt"
    done
    exit 0
fi

repo=$(CDPATH= cd -- "$(dirname -- "$0")/../.." && pwd)
evidence=${1:-"$repo/target/python-host-validation"}
build=${2:-"$repo/target/python-host-validation-build"}
test ! -e "$evidence"
test ! -e "$build"
mkdir -p "$evidence" "$build"
evidence=$(CDPATH= cd -- "$evidence" && pwd)
build=$(CDPATH= cd -- "$build" && pwd)
cd "$repo"
python3 fixtures/python-bootstrap/freeze.py "target/pbs-inspection/$full" \
    "target/pbs-inspection/$install" "$build/producer" "$build/include/python3.13" \
    /build-target/freeze-bundle.json --provenance /evidence/freeze-provenance.json --provision-only \
    > "$evidence/provision.stdout.txt" 2> "$evidence/provision.stderr.txt"
test ! -s "$evidence/provision.stderr.txt"
cargo vendor --locked --offline target/python-bootstrap-vendor > "$evidence/vendor-config.toml" \
    2> "$evidence/vendor.stderr.txt"
git rev-parse HEAD > "$evidence/source-revision.txt"
git status --porcelain > "$evidence/source-status.txt"
git diff --binary > "$evidence/source-diff.patch"
podman image inspect "$image" > "$evidence/image-inspect.json"
cp fixtures/python-host/run-linux.sh "$evidence/commands.sh"
podman run --rm --network none --read-only --tmpfs /tmp:rw,size=256m \
    --mount "type=bind,source=$repo,destination=/workspace,ro" \
    --mount "type=bind,source=$build,destination=/build-target" \
    --mount "type=bind,source=$evidence,destination=/evidence" \
    --workdir /workspace "$image" sh fixtures/python-host/run-linux.sh --build
chmod 0777 "$evidence"
podman run --rm --network none --read-only --read-only-tmpfs=false \
    --tmpfs /tmp:rw,size=1m --tmpfs /unavailable:ro,mode=000,size=1m \
    --mount "type=bind,source=$build,destination=/build-target,ro" \
    --mount "type=bind,source=$evidence,destination=/evidence" \
    --workdir /build-target/runtime-empty "$image" sh -c \
        'chmod 000 /tmp; exec setpriv --reuid=65534 --regid=65534 --clear-groups --no-new-privs sh /build-target/runtime-commands.sh --run'
for mode in success wrong-library wrong-stdlib missing-encodings symlink-stdlib missing-library cached-bytecode app-error; do
    archive="$build/relocated Python host/$mode.glue"
    if test "$mode" = app-error; then archive="$build/relocated Python host/success.glue"; fi
    python3 scripts/check-linux-python-host-trace.py "$evidence/$mode.trace.txt" \
        --mode "$mode" --stdout-file "$evidence/$mode.stdout.txt" \
        --stderr-file "$evidence/$mode.stderr.txt" --archive-file "$archive" \
        > "$evidence/$mode.trace-check.txt"
done
printf 'Stock-PBS host Python evidence: %s\n' "$evidence"
