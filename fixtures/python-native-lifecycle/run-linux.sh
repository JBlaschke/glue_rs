#!/bin/sh
# Fixture construction and the independent stock comparison are build-time only.
set -eu
image=62812c4a0e15bc750ddd6ec68d2a19f8815a14b60d520e201a911e2e29f40abe
full=cpython-3.13.16+20261009-aarch64-unknown-linux-gnu-pgo+lto-full.tar.zst
install=cpython-3.13.16+20261009-aarch64-unknown-linux-gnu-install_only.tar.gz
relocated='/build-target/relocated Python native lifecycle'
prefix='/build-target/host Python imports'
native='/build-target/host Python native lifecycle'
cells='bundled-archived bundled-host host-archived host-host'
modes="$cells bundled-archived-app-error bundled-host-app-error host-archived-app-error host-host-app-error corrupt-native missing-host-image wrong-host-image"

if test "${1:-}" = --build; then
    cp -a /host-build/producer /build-target/producer
    cp -a /host-build/include /build-target/include
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
    PYTHON=/build-target/producer/bin/python3.13 sh /workspace/fixtures/python-native-lifecycle/build-fixture.sh \
        /build-target/native-producer /build-target/include/python3.13 \
        /build-target/producer/lib/libpython3.13.so.1.0 \
        > /evidence/native-build.stdout.txt 2> /evidence/native-build.stderr.txt
    test ! -s /evidence/native-build.stderr.txt
    mkdir /evidence/native-build
    cp /build-target/native-producer/*.txt /build-target/native-producer/artifacts.sha256 /evidence/native-build/
    cp /workspace/fixtures/python-native-lifecycle/baseline-driver.c /evidence/native-build/
    set +e
    /build-target/native-producer/baseline-driver /build-target/producer /build-target/native-producer \
        /workspace/fixtures/python-native-lifecycle/app.py /build-target/producer/lib/libpython3.13.so.1.0 \
        > /evidence/native-baseline.stdout.txt 2> /evidence/native-baseline.stderr.txt
    status=$?
    set -e
    printf '%s\n' "$status" > /evidence/native-baseline.exit-status.txt
    test "$status" -eq 0
    test ! -s /evidence/native-baseline.stderr.txt
    /build-target/producer/bin/python3.13 -I -S -B \
        /workspace/scripts/test_linux_python_native_lifecycle_trace.py \
        > /evidence/lifecycle-policy-stock-python-tests.txt 2>&1
    cargo test --locked --offline --release -p glue-runtime-python -p glue-python-bootstrap-probe --features pbs-bootstrap \
        > /evidence/extensions-tests.txt 2>&1
    cargo clippy --locked --offline --release --all-targets -p glue-runtime-python -p glue-python-bootstrap-probe \
        --features pbs-bootstrap -- -D warnings > /evidence/extensions-clippy.txt 2>&1
    cargo build --locked --offline --release -p glue-runtime-python -p glue-python-bootstrap-probe --features pbs-bootstrap \
        > /evidence/extensions-build.txt 2>&1
    mkdir "$relocated" /build-target/runtime-empty
    /build-target/release/glue-python-bootstrap-probe prepare-imports \
        "/workspace/target/pbs-inspection/$full" /build-target/freeze-bundle.json /build-target/bundled-base.glue \
        > /evidence/bundled-base.prepare.stdout.txt 2> /evidence/bundled-base.prepare.stderr.txt
    test ! -s /evidence/bundled-base.prepare.stderr.txt
    /build-target/producer/bin/python3.13 -I -S -B /workspace/fixtures/python-host-imports/prepare-controls.py \
        /build-target/producer "$prefix" /build-target/freeze-bundle.json \
        /workspace/fixtures/python-host-imports/stdlib-import-pins.json /evidence/host-runtime-provenance.json \
        > /evidence/host-controls.stdout.txt 2> /evidence/host-controls.stderr.txt
    test ! -s /evidence/host-controls.stderr.txt
    /build-target/release/glue-python-bootstrap-probe prepare-host-imports \
        "/workspace/target/pbs-inspection/$full" "$prefix" /build-target/host-base.glue \
        > /evidence/host-base.prepare.stdout.txt 2> /evidence/host-base.prepare.stderr.txt
    test ! -s /evidence/host-base.prepare.stderr.txt
    for directory in "$native" "$native missing-host-image" "$native wrong-host-image"; do
        mkdir "$directory"
        cp /build-target/native-producer/*.so "$directory/"
    done
    for cell in $cells; do
        runtime=${cell%-*}
        provider=${cell#*-}
        directory=/build-target/native-producer
        if test "$provider" = host; then directory=$native; fi
        /build-target/release/glue-python-bootstrap-probe prepare-native-lifecycle \
            "/build-target/$runtime-base.glue" "$directory" "$provider" "$relocated/$cell.glue" \
            > "/evidence/$cell.prepare.stdout.txt" 2> "/evidence/$cell.prepare.stderr.txt"
        test ! -s "/evidence/$cell.prepare.stderr.txt"
    done
    for mode in missing-host-image wrong-host-image; do
        /build-target/release/glue-python-bootstrap-probe prepare-native-lifecycle /build-target/bundled-base.glue \
            "$native $mode" host "$relocated/$mode.glue" \
            > "/evidence/$mode.prepare.stdout.txt" 2> "/evidence/$mode.prepare.stderr.txt"
        test ! -s "/evidence/$mode.prepare.stderr.txt"
    done
    /build-target/release/glue-python-bootstrap-probe corrupt-native-lifecycle \
        "$relocated/bundled-archived.glue" "$relocated/corrupt-native.glue" \
        > /evidence/corrupt.stdout.txt 2> /evidence/corrupt.stderr.txt
    test ! -s /evidence/corrupt.stderr.txt
    /build-target/producer/bin/python3.13 -I -S -B - "$native" /evidence/native-controls.json <<'PY'
import hashlib
import json
from pathlib import Path
import sys

prefix = Path(sys.argv[1])
records = {}
for path in sorted(prefix.glob('*.so')):
    payload = path.read_bytes()
    records[path.name] = {'size': len(payload), 'sha256': hashlib.sha256(payload).hexdigest()}
wrong = Path(str(prefix) + ' wrong-host-image') / 'glue_native_lifecycle.so'
payload = wrong.read_bytes()
wrong.write_bytes(bytes([payload[0] ^ 1]) + payload[1:])
(Path(str(prefix) + ' missing-host-image') / 'libglue_python_lifecycle.so').unlink()
Path(sys.argv[2]).write_text(json.dumps({'schema_version': 0, 'files': records,
                                      'wrong_image': str(wrong), 'flipped_offset': 0,
                                      'missing_image': str(prefix) + ' missing-host-image/libglue_python_lifecycle.so'},
                                     indent=2, sort_keys=True) + '\n')
PY
    /build-target/producer/bin/python3.13 -I -S -B /workspace/scripts/check-linux-python-native-lifecycle-trace.py \
        --emit-native-metadata "$native" "$relocated" /evidence/native-metadata.json
    for directory in "$native" "$native missing-host-image" "$native wrong-host-image"; do
        chmod 0444 "$directory/"*.so
        chmod 0555 "$directory"
    done
    cp /build-target/release/glue-python-bootstrap-probe "$relocated/glue-python-bootstrap-probe"
    chmod 0555 "$relocated/glue-python-bootstrap-probe" "$relocated" /build-target/runtime-empty
    chmod 0444 "$relocated/"*.glue
    sha256sum "$relocated/glue-python-bootstrap-probe" "$relocated/"*.glue \
        /evidence/freeze-bundle.json > /evidence/artifacts.sha256
    readelf -d --dyn-syms "$relocated/glue-python-bootstrap-probe" > /evidence/launcher.elf.txt
    cp /workspace/fixtures/python-native-lifecycle/run-linux.sh /build-target/runtime-commands.sh
    mkdir /evidence/build-provenance
    for record in /build-target/release/build/glue-runtime-python-*/out/python-bootstrap-provenance.txt; do
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
    for unused in wrong-library wrong-import-source missing-import-source cached-import-bytecode; do
        chmod -R u+w "$prefix $unused"
    done
    mkdir -p /host-build/native-images "/host-build/relocated Python native lifecycle"
    cp /build-target/native-producer/*.so /host-build/native-images/
    cp "$relocated/"*.glue "$relocated/glue-python-bootstrap-probe" "/host-build/relocated Python native lifecycle/"
    rm -rf /build-target/producer /build-target/include /build-target/native-producer \
        /build-target/release /build-target/debug /build-target/freeze-bundle.json \
        /build-target/bundled-base.glue /build-target/host-base.glue \
        "$prefix wrong-library" "$prefix wrong-import-source" \
        "$prefix missing-import-source" "$prefix cached-import-bytecode"
    find /build-target -type f -o -type l > /evidence/post-removal-files.txt
    test ! -e /build-target/producer
    test ! -e /build-target/include
    test ! -e /build-target/native-producer
    test ! -e "$prefix/bin/python3.13"
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
    test ! -e /build-target/native-producer
    test ! -r /tmp
    test ! -w /tmp
    test ! -x /tmp
    test ! -r /unavailable
    id > /evidence/runtime-identity.txt
    cat /proc/mounts > /evidence/runtime-mounts.txt
    for mode in $modes; do
        case "$mode" in
            *-app-error)
                cell=${mode%-app-error}
                set -- "$relocated/glue-python-bootstrap-probe" run-native-lifecycle-negative "$relocated/$cell.glue" app-error
                expected=1 ;;
            corrupt-native|missing-host-image|wrong-host-image)
                set -- "$relocated/glue-python-bootstrap-probe" run-native-lifecycle "$relocated/$mode.glue"
                expected=1 ;;
            *)
                set -- "$relocated/glue-python-bootstrap-probe" run-native-lifecycle "$relocated/$mode.glue"
                expected=0 ;;
        esac
        set +e
        strace -f -s 256 -yy -e trace=all -o "/evidence/$mode.trace.txt" "$@" \
            < /dev/null > "/evidence/$mode.stdout.txt" 2> "/evidence/$mode.stderr.txt"
        status=$?
        set -e
        printf '%s\n' "$status" > "/evidence/$mode.exit-status.txt"
        test "$status" -eq "$expected"
    done
    for cell in $cells; do
        test ! -s "/evidence/$cell.stderr.txt"
        cmp "/evidence/$cell.stdout.txt" "/evidence/$cell-app-error.stdout.txt"
        cmp /evidence/bundled-archived.stdout.txt "/evidence/$cell.stdout.txt"
    done
    for mode in corrupt-native missing-host-image wrong-host-image; do
        test ! -s "/evidence/$mode.stdout.txt"
    done
    exit 0
fi

development=false
if test "${1:-}" = --allow-development; then development=true; shift; fi
repo=$(CDPATH= cd -- "$(dirname -- "$0")/../.." && pwd)
evidence=${1:-"$repo/target/python-native-lifecycle-validation"}
build=${2:-"$repo/target/python-native-lifecycle-validation-build"}
test ! -e "$evidence"
test ! -L "$evidence"
test ! -e "$build"
test ! -L "$build"
mkdir -p "$evidence" "$build"
evidence=$(CDPATH= cd -- "$evidence" && pwd)
build=$(CDPATH= cd -- "$build" && pwd)
cd "$repo"
if test "$development" = false; then test -z "$(git status --porcelain)"; fi
export PATH="$(rustup run 1.88.0 rustc --print sysroot)/bin:$PATH"
python3 fixtures/python-bootstrap/freeze.py "target/pbs-inspection/$full" \
    "target/pbs-inspection/$install" "$build/producer" "$build/include/python3.13" \
    /build-target/freeze-bundle.json --provenance /evidence/freeze-provenance.json --provision-only \
    > "$evidence/provision.stdout.txt" 2> "$evidence/provision.stderr.txt"
test ! -s "$evidence/provision.stderr.txt"
cargo vendor --locked --offline target/python-bootstrap-vendor > "$evidence/vendor-config.toml" 2> "$evidence/vendor.stderr.txt"
git rev-parse HEAD > "$evidence/source-revision.txt"
git branch --show-current > "$evidence/source-branch.txt"
git status --porcelain > "$evidence/source-status.txt"
git diff --binary > "$evidence/source-diff.patch"
python3 - "$evidence/source-inputs.json" <<'PY'
import hashlib
import json
from pathlib import Path
import subprocess
import sys

paths = subprocess.check_output(['git', 'ls-files', '-z', '--', 'Cargo.toml', 'Cargo.lock',
                                 'crates', 'spikes', 'fixtures', 'scripts']).split(b'\0')
inputs = {}
for raw in paths:
    if raw:
        name = raw.decode()
        data = Path(name).read_bytes()
        inputs[name] = {'size': len(data), 'sha256': hashlib.sha256(data).hexdigest()}
Path(sys.argv[1]).write_text(json.dumps({'schema_version': 0, 'files': inputs},
                                      indent=2, sort_keys=True) + '\n')
PY
podman image inspect "$image" > "$evidence/image-inspect.json"
cp fixtures/python-native-lifecycle/run-linux.sh "$evidence/commands.sh"
volume="glue-python-native-lifecycle-$$"
podman volume create "$volume" > "$evidence/volume-name.txt"
trap 'podman volume rm -f "$volume" > "$evidence/volume-removal.stdout.txt" 2> "$evidence/volume-removal.stderr.txt"' 0
podman run --rm --network none --read-only --tmpfs /tmp:rw,size=256m \
    --mount "type=bind,source=$repo,destination=/workspace,ro" \
    --mount "type=volume,source=$volume,destination=/build-target" \
    --mount "type=bind,source=$build,destination=/host-build" \
    --mount "type=bind,source=$evidence,destination=/evidence" \
    --workdir /workspace "$image" sh /workspace/fixtures/python-native-lifecycle/run-linux.sh --build
chmod 0777 "$evidence"
podman run --rm --network none --read-only --read-only-tmpfs=false \
    --tmpfs /tmp:rw,size=1m --tmpfs /unavailable:ro,mode=000,size=1m --tmpfs /home:ro,mode=000,size=1m \
    --mount "type=volume,source=$volume,destination=/build-target,ro" \
    --mount "type=bind,source=$evidence,destination=/evidence" \
    --workdir /build-target/runtime-empty "$image" sh -c \
        'chmod 000 /tmp; exec setpriv --reuid=65534 --regid=65534 --clear-groups --no-new-privs sh /build-target/runtime-commands.sh --run'
if test "$development" = false; then
    python3 scripts/test_linux_python_native_lifecycle_trace.py \
        > "$evidence/lifecycle-policy-tests.txt" 2>&1
    for mode in $modes; do
        cell=${mode%-app-error}
        python3 scripts/check-linux-python-native-lifecycle-trace.py "$evidence/$mode.trace.txt" \
            --mode "$mode" --stdout-file "$evidence/$mode.stdout.txt" --stderr-file "$evidence/$mode.stderr.txt" \
            --native-metadata-file "$evidence/native-metadata.json" \
            --archive-file "$build/relocated Python native lifecycle/$cell.glue" > "$evidence/$mode.trace-check.txt"
    done
    python3 scripts/test_linux_python_native_lifecycle_trace.py --audit-capture "$evidence" \
        "$evidence/lifecycle-hostile-audit.json" > "$evidence/lifecycle-hostile-audit.stdout.txt" \
        2> "$evidence/lifecycle-hostile-audit.stderr.txt"
fi
printf 'Stock-PBS native lifecycle evidence: %s\n' "$evidence"
