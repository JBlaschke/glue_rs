#!/bin/sh
# Build-time staging is separate from unprivileged, read-only runtime evidence.
set -eu
image=62812c4a0e15bc750ddd6ec68d2a19f8815a14b60d520e201a911e2e29f40abe
full=cpython-3.13.16+20261009-aarch64-unknown-linux-gnu-pgo+lto-full.tar.zst
install=cpython-3.13.16+20261009-aarch64-unknown-linux-gnu-install_only.tar.gz
relocated='/build-target/relocated Python metadata'
host_prefix='/build-target/host Python metadata'
install_prefix='/build-target/install Python metadata'
modes='bundled host install-host bundled-bad-record host-bad-record install-host-bad-record bundled-corrupt-metadata host-corrupt-metadata install-host-corrupt-metadata'

if test "${1:-}" = --build; then
    cp -a /host-build/producer /build-target/producer
    cp -a /host-build/include /build-target/include
    export PATH=/usr/local/rustup/toolchains/1.88.0-aarch64-unknown-linux-gnu/bin:$PATH
    export CARGO_HOME=/tmp/cargo CARGO_TARGET_DIR=/build-target
    export GLUE_PYTHON_INCLUDE_DIR=/build-target/include/python3.13
    mkdir -p "$CARGO_HOME"
    printf '%s\n' '[source.crates-io]' 'replace-with = "vendored-sources"' \
        '[source.vendored-sources]' 'directory = "/workspace/target/python-bootstrap-vendor"' > "$CARGO_HOME/config.toml"
    /build-target/producer/bin/python3.13 -I -S -B /build-target/producer/freeze-compiler.py \
        /build-target/producer/freeze-input.json /build-target/producer/freeze-provenance.json \
        /build-target/freeze-bundle.json /evidence/freeze-provenance.json
    cp /build-target/freeze-bundle.json /evidence/freeze-bundle.json
    cargo test --locked --offline --release -p glue-runtime-python -p glue-python-bootstrap-probe --features pbs-bootstrap > /evidence/python-tests.txt 2>&1
    cargo clippy --locked --offline --release --all-targets -p glue-runtime-python -p glue-python-bootstrap-probe --features pbs-bootstrap -- -D warnings > /evidence/python-clippy.txt 2>&1
    cargo test --locked --offline --release -p glue-runner --features python-pbs > /evidence/runner-tests.txt 2>&1
    cargo clippy --locked --offline --release --all-targets -p glue-runner --features python-pbs -- -D warnings > /evidence/runner-clippy.txt 2>&1
    cargo build --locked --offline --release -p glue-runner --features python-pbs -p glue-python-bootstrap-probe --features pbs-bootstrap > /evidence/build.txt 2>&1
    /build-target/producer/bin/python3.13 -I -S -B /workspace/fixtures/python-metadata/test_protocol.py > /evidence/metadata-protocol-tests.txt 2>&1
    /build-target/producer/bin/python3.13 -I -S -B /workspace/fixtures/python-imports/test_importer.py > /evidence/importer-protocol-tests.txt 2>&1
    /build-target/producer/bin/python3.13 -I -S -B /workspace/fixtures/python-source-apps/test_entry.py > /evidence/entry-protocol-tests.txt 2>&1
    mkdir "$relocated" /build-target/runtime-empty /build-target/staging /evidence/cli-controls
    /build-target/release/glue-python-bootstrap-probe prepare-imports "/workspace/target/pbs-inspection/$full" \
        /build-target/freeze-bundle.json /build-target/base.glue > /evidence/base.stdout.txt 2> /evidence/base.stderr.txt
    test ! -s /evidence/base.stderr.txt
    /build-target/producer/bin/python3.13 -I -S -B /workspace/fixtures/python-host-source-apps/prepare.py \
        install /build-target/base.glue "$host_prefix" --provenance /evidence/host-runtime-provenance.json
    /build-target/producer/bin/python3.13 -I -S -B /workspace/fixtures/python-install-host-source-apps/prepare.py \
        install "/workspace/target/pbs-inspection/$install" "$install_prefix" --provenance /evidence/install-runtime-provenance.json
    # These actual host metadata directories must remain invisible to queries.
    /build-target/producer/bin/python3.13 -I -S -B - "$host_prefix" "$install_prefix" <<'PY'
from pathlib import Path
import hashlib, json, os, sys
for prefix, provenance in zip(map(Path, sys.argv[1:]), (Path('/evidence/host-runtime-provenance.json'), Path('/evidence/install-runtime-provenance.json'))):
    additions = {}
    for directory, name, version in [('glue_meta_demo-999.dist-info', 'Glue.Meta-Demo', '999'), ('glue_metadata_physical_lure-99.dist-info', 'Glue-Metadata-Physical-Lure', '99')]:
        target = prefix / 'lib/python3.13/site-packages' / directory / 'METADATA'
        target.parent.mkdir(parents=True, exist_ok=True)
        payload = f'Metadata-Version: 2.3\nName: {name}\nVersion: {version}\n'.encode()
        target.write_bytes(payload); target.chmod(0o444); target.parent.chmod(0o555)
        os.utime(target, (1704067200, 1704067200))
        additions[target.relative_to(prefix).as_posix()] = {'size':len(payload), 'sha256':hashlib.sha256(payload).hexdigest()}
    record = json.loads(provenance.read_text())
    if 'complete_stock_files' in record:
        record['runtime_trees'][str(prefix)]['added'].update(additions)
    else:
        record['runtime_trees'][str(prefix)].update(additions)
    record['metadata_lures'] = additions
    provenance.write_text(json.dumps(record, indent=2, sort_keys=True)+'\n')
PY
    for mode in bundled host install-host bundled-bad-record host-bad-record install-host-bad-record; do
        provider=$mode
        bad=false
        case "$mode" in *-bad-record) provider=${mode%-bad-record}; bad=true ;; esac
        set -- /build-target/producer/bin/python3.13 -I -S -B /workspace/fixtures/python-metadata/prepare.py \
            "$provider" /workspace/fixtures/python-metadata/input "/build-target/staging/$mode"
        case "$provider" in
            bundled) set -- "$@" --base /build-target/base.glue ;;
            host) set -- "$@" --base /build-target/base.glue --prefix "$host_prefix" ;;
            install-host) set -- "$@" --prefix "$install_prefix" ;;
        esac
        if test "$bad" = true; then set -- "$@" --bad-record; fi
        "$@" > "/evidence/$mode.prepare.stdout.txt" 2> "/evidence/$mode.prepare.stderr.txt"
        test ! -s "/evidence/$mode.prepare.stderr.txt"
        cp "/build-target/staging/$mode/manifest.json" "/evidence/$mode.manifest.json"
        cp "/build-target/staging/$mode/metadata-prepare-summary.json" "/evidence/$mode.prepare-summary.json"
        /build-target/release/glue build --manifest "/build-target/staging/$mode/manifest.json" \
            --root "/build-target/staging/$mode/root" --output "$relocated/$mode.glue" \
            > "/evidence/cli-controls/$mode.build.stdout.txt" 2> "/evidence/cli-controls/$mode.build.stderr.txt"
        printf '0\n' > "/evidence/cli-controls/$mode.build.exit-status.txt"
        test ! -s "/evidence/cli-controls/$mode.build.stderr.txt"
    done
    /build-target/producer/bin/python3.13 -I -S -B - "$relocated" <<'PY'
from pathlib import Path
import struct, sys, zipfile
root = Path(sys.argv[1])
key = 'app/python/glue_meta_demo-1.2.3.dist-info/METADATA'
for provider in ['bundled', 'host', 'install-host']:
    source = root / (provider+'.glue')
    with zipfile.ZipFile(source) as archive:
        info = archive.getinfo(key)
    payload = bytearray(source.read_bytes())
    names, extra = struct.unpack_from('<HH', payload, info.header_offset+26)
    payload[info.header_offset+30+names+extra] ^= 1
    (root / (provider+'-corrupt-metadata.glue')).write_bytes(payload)
PY
    cp /build-target/release/glue "$relocated/glue"
    for mode in $modes; do
        for operation in inspect verify doctor cat; do
            set -- /build-target/release/glue "$operation" "$relocated/$mode.glue"
            case "$operation" in inspect) set -- "$@" --json ;; cat) set -- "$@" app/main.py ;; esac
            set +e
            "$@" > "/evidence/cli-controls/$mode.$operation.stdout.txt" 2> "/evidence/cli-controls/$mode.$operation.stderr.txt"
            status=$?
            set -e
            printf '%s\n' "$status" > "/evidence/cli-controls/$mode.$operation.exit-status.txt"
            expected=0
            case "$mode.$operation" in *-corrupt-metadata.verify) expected=1 ;; esac
            test "$status" -eq "$expected"
        done
    done
    sha256sum "$relocated/glue" "$relocated/"*.glue > /evidence/artifacts.sha256
    uname -srvmo > /evidence/environment.txt
    rustc --version >> /evidence/environment.txt
    cc --version >> /evidence/environment.txt
    dpkg-query -W libc6 strace >> /evidence/environment.txt
    getconf PAGESIZE >> /evidence/environment.txt
    mkdir /evidence/build-provenance
    for record in /build-target/release/build/glue-runtime-python-*/out/python-bootstrap-provenance.txt; do
        test -f "$record"
        cp "$record" "/evidence/build-provenance/$(basename "$(dirname "$(dirname "$record")")").txt"
    done
    cp /workspace/fixtures/python-metadata/run-linux.sh /build-target/runtime-commands.sh
    chmod 0555 "$relocated/glue" "$relocated" /build-target/runtime-empty
    chmod 0444 "$relocated/"*.glue
    # Preserve archives outside the runtime volume for independent policy replay.
    /build-target/producer/bin/python3.13 -I -S -B - "$relocated" <<'PY'
from pathlib import Path
import shutil, sys
source = Path(sys.argv[1])
target = Path('/host-build') / source.name
target.mkdir()
for path in source.iterdir():
    shutil.copyfile(path, target / path.name)
PY
    rm -rf /build-target/producer /build-target/include /build-target/release /build-target/debug /build-target/staging \
        /build-target/base.glue /build-target/freeze-bundle.json
    exit 0
fi

if test "${1:-}" = --run; then
    cd /build-target/runtime-empty
    export HOME=/unavailable/home TMPDIR=/unavailable/tmp TZ=UTC0
    export PYTHONHOME=/forbidden/home PYTHONPATH=/forbidden/path PYTHONUSERBASE=/forbidden/userbase
    export PYTHONPYCACHEPREFIX=/forbidden/pycache PYTHONSTARTUP=/forbidden/startup.py
    unset LD_LIBRARY_PATH LD_PRELOAD LD_AUDIT LD_DEBUG GLIBC_TUNABLES
    test ! -e /build-target/producer && test ! -e /build-target/include && test ! -e /build-target/staging
    test ! -r /tmp && test ! -w /tmp && test ! -x /tmp
    id > /evidence/runtime-identity.txt
    cat /proc/mounts > /evidence/runtime-mounts.txt
    for mode in $modes; do
        set +e
        strace -f -s 256 -yy -e trace=all -o "/evidence/$mode.trace.txt" "$relocated/glue" run "$relocated/$mode.glue" \
            < /dev/null > "/evidence/$mode.stdout.txt" 2> "/evidence/$mode.stderr.txt"
        status=$?
        set -e
        printf '%s\n' "$status" > "/evidence/$mode.exit-status.txt"
        expected=1
        case "$mode" in bundled|host|install-host) expected=0 ;; esac
        test "$status" -eq "$expected"
    done
    exit 0
fi

development=false
if test "${1:-}" = --allow-development; then development=true; shift; fi
repo=$(CDPATH= cd -- "$(dirname -- "$0")/../.." && pwd)
evidence=${1:-"$repo/target/python-metadata-validation"}
build=${2:-"$repo/target/python-metadata-validation-build"}
test ! -e "$evidence" && test ! -e "$build"
mkdir -p "$evidence" "$build"
evidence=$(CDPATH= cd -- "$evidence" && pwd)
build=$(CDPATH= cd -- "$build" && pwd)
cd "$repo"
if test "$development" = false; then test -z "$(git status --porcelain)"; fi
export PATH="$(rustup run 1.88.0 rustc --print sysroot)/bin:$PATH"
python3 fixtures/python-bootstrap/freeze.py "target/pbs-inspection/$full" "target/pbs-inspection/$install" \
    "$build/producer" "$build/include/python3.13" /build-target/freeze-bundle.json \
    --provenance /evidence/freeze-provenance.json --provision-only > "$evidence/provision.stdout.txt" 2> "$evidence/provision.stderr.txt"
test ! -s "$evidence/provision.stderr.txt"
cargo vendor --locked --offline target/python-bootstrap-vendor > "$evidence/vendor-config.toml" 2> "$evidence/vendor.stderr.txt"
git rev-parse HEAD > "$evidence/source-revision.txt"
git branch --show-current > "$evidence/source-branch.txt"
git status --porcelain > "$evidence/source-status.txt"
git diff --binary > "$evidence/source-diff.patch"
cp fixtures/python-metadata/run-linux.sh "$evidence/commands.sh"
podman image inspect "$image" > "$evidence/image-inspect.json"
volume="glue-python-metadata-$$"
podman volume create "$volume" > "$evidence/volume-name.txt"
trap 'podman volume rm -f "$volume" > "$evidence/volume-removal.stdout.txt" 2> "$evidence/volume-removal.stderr.txt"' 0
podman run --rm --network none --read-only --tmpfs /tmp:rw,size=256m \
    --mount "type=bind,source=$repo,destination=/workspace,ro" --mount "type=volume,source=$volume,destination=/build-target" \
    --mount "type=bind,source=$build,destination=/host-build" --mount "type=bind,source=$evidence,destination=/evidence" \
    --workdir /workspace "$image" sh /workspace/fixtures/python-metadata/run-linux.sh --build
chmod 0777 "$evidence"
podman run --rm --network none --read-only --read-only-tmpfs=false --tmpfs /tmp:rw,size=1m --tmpfs /unavailable:ro,mode=000,size=1m \
    --mount "type=volume,source=$volume,destination=/build-target,ro" --mount "type=bind,source=$evidence,destination=/evidence" \
    --workdir /build-target/runtime-empty "$image" sh -c \
    'chmod 000 /tmp; exec setpriv --reuid=65534 --regid=65534 --clear-groups --no-new-privs sh /build-target/runtime-commands.sh --run'
if test "$development" = false; then
    python3 scripts/check-linux-python-metadata-trace.py --emit-metadata "$build/relocated Python metadata" "$evidence/source-metadata.json"
    for mode in $modes; do
        python3 scripts/check-linux-python-metadata-trace.py "$evidence/$mode.trace.txt" --mode "$mode" \
            --stdout-file "$evidence/$mode.stdout.txt" --stderr-file "$evidence/$mode.stderr.txt" \
            --metadata-file "$evidence/source-metadata.json" --archive-file "$build/relocated Python metadata/$mode.glue" > "$evidence/$mode.trace-check.txt"
    done
fi
printf 'Python distribution metadata evidence: %s\n' "$evidence"
