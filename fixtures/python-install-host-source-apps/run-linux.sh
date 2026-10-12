#!/bin/sh
# Stock install-only provider preparation and packaging are bounded build-time fixture operations.
set -eu
image=62812c4a0e15bc750ddd6ec68d2a19f8815a14b60d520e201a911e2e29f40abe
full=cpython-3.13.16+20261009-aarch64-unknown-linux-gnu-pgo+lto-full.tar.zst
install=cpython-3.13.16+20261009-aarch64-unknown-linux-gnu-install_only.tar.gz
relocated='/build-target/relocated Python install host source apps'
prefix='/build-target/host Python install source apps'
apps='minimal resources stdlib app-error syntax nul corrupt-source'
controls='missing-source wrong-source deep-cache startup-native startup-bytecode missing-library missing-cache wrong-cache extra-cache'
modes="$apps $controls"

if test "${1:-}" = --build; then
    # A Linux volume preserves stock case-distinct terminfo members that cannot
    # coexist on a usual Mac bind filesystem. Inputs/exports stay separate.
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
        /build-target/freeze-bundle.json /evidence/freeze-provenance.json \
        > /evidence/freeze.stdout.txt 2> /evidence/freeze.stderr.txt
    test ! -s /evidence/freeze.stderr.txt
    cp /build-target/freeze-bundle.json /evidence/freeze-bundle.json
    cargo test --locked --offline --release -p glue-runtime-python -p glue-python-bootstrap-probe --features pbs-bootstrap \
        > /evidence/python-tests.txt 2>&1
    cargo clippy --locked --offline --release --all-targets -p glue-runtime-python -p glue-python-bootstrap-probe --features pbs-bootstrap \
        -- -D warnings > /evidence/python-clippy.txt 2>&1
    cargo build --locked --offline --release -p glue-python-bootstrap-probe --features pbs-bootstrap > /evidence/probe-build.txt 2>&1
    cargo test --locked --offline --release -p glue-runner --features python-pbs > /evidence/runner-tests.txt 2>&1
    cargo clippy --locked --offline --release --all-targets -p glue-runner --features python-pbs -- -D warnings > /evidence/runner-clippy.txt 2>&1
    cargo build --locked --offline --release -p glue-runner --features python-pbs > /evidence/runner-build.txt 2>&1
    /build-target/producer/bin/python3.13 -I -S -B /workspace/fixtures/python-source-apps/test_entry.py > /evidence/entry-protocol-tests.txt 2>&1
    /build-target/producer/bin/python3.13 -I -S -B /workspace/fixtures/python-host-source-apps/test_protocol.py > /evidence/host-protocol-tests.txt 2>&1
    mkdir "$relocated" /build-target/runtime-empty /build-target/staging /evidence/cli-controls
    /build-target/producer/bin/python3.13 -I -S -B /workspace/fixtures/python-install-host-source-apps/prepare.py \
        install "/workspace/target/pbs-inspection/$install" "$prefix" --controls --provenance /evidence/host-runtime-provenance.json \
        > /evidence/install.stdout.txt 2> /evidence/install.stderr.txt
    test ! -s /evidence/install.stderr.txt
    for mode in minimal resources stdlib app-error syntax nul $controls; do
        host_prefix="$prefix"
        case "$mode" in
            minimal) input=/workspace/fixtures/python-source-apps/input-minimal; app=minimal.source; entry=app/launch.py; component=launch ;;
            resources) input=/workspace/fixtures/python-source-apps/input-resources; app=daily.report; entry="app/tasks/report's [daily].py"; component=report ;;
            stdlib) input=/workspace/fixtures/python-host-source-apps/input-stdlib; app=stdlib.source; entry=app/tasks/stdlib.py; component=stdlib ;;
            app-error) input=/workspace/fixtures/python-source-apps/input-error; app=failing.source; entry=app/jobs/fail.py; component=fail ;;
            syntax) input=/workspace/fixtures/python-source-apps/input-syntax; app=syntax.source; entry=app/jobs/invalid.py; component=syntax ;;
            nul) input=/workspace/fixtures/python-source-apps/input-nul; app=nul.source; entry=app/embedded-nul.py; component=nul ;;
            *) input=/workspace/fixtures/python-source-apps/input-minimal; app=minimal.source; entry=app/launch.py; component=launch; host_prefix="$prefix $mode" ;;
        esac
        /build-target/producer/bin/python3.13 -I -S -B /workspace/fixtures/python-install-host-source-apps/prepare.py \
            stage "$input" "/build-target/staging/$mode" \
            --prefix "$host_prefix" --app-id "$app" --entry "$entry" --component "$component" \
            > "/evidence/$mode.prepare.stdout.txt" 2> "/evidence/$mode.prepare.stderr.txt"
        test ! -s "/evidence/$mode.prepare.stderr.txt"
        cp "/build-target/staging/$mode/manifest.json" "/evidence/$mode.manifest.json"
        cp "/build-target/staging/$mode/prepare-summary.json" "/evidence/$mode.prepare-summary.json"
        /build-target/release/glue build --manifest "/build-target/staging/$mode/manifest.json" \
            --root "/build-target/staging/$mode/root" --output "$relocated/$mode.glue" \
            > "/evidence/cli-controls/$mode.build.stdout.txt" 2> "/evidence/cli-controls/$mode.build.stderr.txt"
        printf '0\n' > "/evidence/cli-controls/$mode.build.exit-status.txt"
        test ! -s "/evidence/cli-controls/$mode.build.stderr.txt"
    done
    /build-target/producer/bin/python3.13 -I -S -B - "$relocated" /build-target/staging /evidence <<'PY'
from pathlib import Path
import copy, hashlib, json, struct, sys, zipfile
archives, staging, evidence = map(Path, sys.argv[1:])
source = archives / 'minimal.glue'
with zipfile.ZipFile(source) as archive:
    info = archive.getinfo('app/python/simple_value.py')
    with source.open('rb') as stream:
        stream.seek(info.header_offset)
        header = stream.read(30)
    names, extra = struct.unpack_from('<HH', header, 26)
    offset = info.header_offset + 30 + names + extra
payload = bytearray(source.read_bytes())
payload[offset] ^= 1
(archives / 'corrupt-source.glue').write_bytes(payload)
(evidence / 'corrupt-source.manifest.json').write_bytes((evidence / 'minimal.manifest.json').read_bytes())
(evidence / 'corruption.json').write_text(json.dumps({'key':'app/python/simple_value.py', 'data_offset':offset,
    'only_changed_archive_byte':offset, 'size':info.file_size, 'original_sha256':hashlib.sha256(source.read_bytes()).hexdigest(),
    'corrupt_sha256':hashlib.sha256(payload).hexdigest()}, indent=2) + '\n')
base = json.loads((staging / 'minimal/manifest.json').read_text())
for name, key, content in [('protected-module','app/python/os.py',b'value = 1\n'), ('bytecode','app/python/cache.pyc',b'not bytecode')]:
    changed = copy.deepcopy(base)
    changed['resources'][key] = {'size':len(content), 'sha256':hashlib.sha256(content).hexdigest(), 'compression':'stored'}
    (staging / (name + '.json')).write_text(json.dumps(changed))
changed = copy.deepcopy(base)
changed['resources']['python/archive-importer.py']['sha256'] = '0' * 64
(staging / 'helper-drift.json').write_text(json.dumps(changed))
changed_full = copy.deepcopy(base)
changed_full['runtimes']['python']['build_id'] = 'pbs-20261009-cpython-3.13.16-pgo-lto-host-source-apps-v1'
(staging / 'full-profile-on-stock.json').write_text(json.dumps(changed_full))
raw = source.read_bytes()
manifest_length = struct.unpack_from('<Q', raw,16)[0]
zip_payload = raw[64+manifest_length:]
for name, changed in [('helper-drift',changed),('outside-entry',copy.deepcopy(base))]:
    if name=='outside-entry': changed['components']['launch']['entry_point']='python/archive-importer.py'
    manifest = json.dumps(changed,sort_keys=True,separators=(',',':')).encode()
    header = b'GLUERS00' + struct.pack('<IIQQ',0,0,len(manifest),len(zip_payload)) + hashlib.sha256(manifest).digest()
    (archives / (name+'.glue')).write_bytes(header+manifest+zip_payload)
PY
    for name in protected-module bytecode helper-drift; do
        set +e
        /build-target/release/glue build --manifest "/build-target/staging/$name.json" \
            --root /build-target/missing-input-root --output "/build-target/$name-should-not-exist.glue" \
            > "/evidence/cli-controls/$name.build.stdout.txt" 2> "/evidence/cli-controls/$name.build.stderr.txt"
        status=$?
        set -e
        printf '%s\n' "$status" > "/evidence/cli-controls/$name.build.exit-status.txt"
        test "$status" -eq 1
        test ! -e "/build-target/$name-should-not-exist.glue"
    done
    /build-target/release/glue build --manifest /build-target/staging/full-profile-on-stock.json \
        --root /build-target/staging/minimal/root --output "$relocated/full-profile-on-stock.glue" \
        > /evidence/cli-controls/full-profile-on-stock.build.stdout.txt 2> /evidence/cli-controls/full-profile-on-stock.build.stderr.txt
    printf '0\n' > /evidence/cli-controls/full-profile-on-stock.build.exit-status.txt
    test ! -s /evidence/cli-controls/full-profile-on-stock.build.stderr.txt
    cp /build-target/staging/full-profile-on-stock.json /evidence/full-profile-on-stock.manifest.json
    for operation in doctor run; do
        set +e
        /build-target/release/glue "$operation" "$relocated/full-profile-on-stock.glue" \
            > "/evidence/cli-controls/full-profile-on-stock.$operation.stdout.txt" 2> "/evidence/cli-controls/full-profile-on-stock.$operation.stderr.txt"
        status=$?
        set -e
        printf '%s\n' "$status" > "/evidence/cli-controls/full-profile-on-stock.$operation.exit-status.txt"
        expected=0
        if test "$operation" = run; then expected=1; fi
        test "$status" -eq "$expected"
    done
    cp /build-target/release/glue "$relocated/glue"
    readelf -W -d --dyn-syms "$relocated/glue" > /evidence/launcher.elf.txt
    for mode in $apps; do
        case "$mode" in
            minimal|corrupt-source) entry=app/launch.py ;;
            resources) entry="app/tasks/report's [daily].py" ;;
            stdlib) entry=app/tasks/stdlib.py ;;
            app-error) entry=app/jobs/fail.py ;;
            syntax) entry=app/jobs/invalid.py ;;
            nul) entry=app/embedded-nul.py ;;
        esac
        for operation in inspect verify doctor cat; do
            set -- /build-target/release/glue "$operation" "$relocated/$mode.glue"
            case "$operation" in inspect) set -- "$@" --json ;; cat) set -- "$@" "$entry" ;; esac
            set +e
            "$@" > "/evidence/cli-controls/$mode.$operation.stdout.txt" 2> "/evidence/cli-controls/$mode.$operation.stderr.txt"
            status=$?
            set -e
            printf '%s\n' "$status" > "/evidence/cli-controls/$mode.$operation.exit-status.txt"
            expected=0
            if test "$mode" = corrupt-source && test "$operation" = verify; then expected=1; fi
            test "$status" -eq "$expected"
        done
    done
    for mode in $controls helper-drift outside-entry; do
        set +e
        /build-target/release/glue doctor "$relocated/$mode.glue" \
            > "/evidence/cli-controls/$mode.doctor.stdout.txt" 2> "/evidence/cli-controls/$mode.doctor.stderr.txt"
        status=$?
        set -e
        printf '%s\n' "$status" > "/evidence/cli-controls/$mode.doctor.exit-status.txt"
        expected=0
        case "$mode" in helper-drift|outside-entry) expected=1 ;; esac
        test "$status" -eq "$expected"
    done
    /build-target/producer/bin/python3.13 -I -S -B /workspace/scripts/check-linux-python-install-host-source-app-trace.py \
        --emit-metadata "$relocated" /evidence/source-metadata.json
    sha256sum "$relocated/glue" "$relocated/"*.glue > /evidence/artifacts.sha256
    mkdir /evidence/build-provenance
    for record in /build-target/release/build/glue-runtime-python-*/out/python-bootstrap-provenance.txt; do
        test -f "$record"
        name=$(basename "$(dirname "$(dirname "$record")")")
        cp "$record" "/evidence/build-provenance/$name.txt"
        nm -u "$(dirname "$record")/libglue_python_bootstrap_boundary.a" > "/evidence/build-provenance/$name.undefined.txt"
    done
    uname -srvmo > /evidence/environment.txt
    rustc --version >> /evidence/environment.txt
    cc --version >> /evidence/environment.txt
    dpkg-query -W libc6 gcc strace >> /evidence/environment.txt
    getconf PAGESIZE >> /evidence/environment.txt
    cp /workspace/fixtures/python-install-host-source-apps/run-linux.sh /build-target/runtime-commands.sh
    chmod 0555 "$relocated/glue" "$relocated" /build-target/runtime-empty
    chmod 0444 "$relocated/"*.glue
    mkdir "/host-build/relocated Python install host source apps"
    /build-target/producer/bin/python3.13 -I -S -B - "$relocated" "/host-build/relocated Python install host source apps" <<'PY'
from pathlib import Path
import shutil, sys
source, destination = map(Path, sys.argv[1:])
for path in sorted(source.iterdir()):
    if not path.is_file() or path.is_symlink():
        raise ValueError('unexpected relocated export input')
    shutil.copyfile(path, destination / path.name)
PY
    rm -rf /build-target/producer /build-target/include /build-target/release /build-target/debug \
        /build-target/staging /build-target/freeze-bundle.json
    find /build-target -type f -o -type l > /evidence/post-removal-files.txt
    exit 0
fi

if test "${1:-}" = --run; then
    cd /build-target/runtime-empty
    export HOME=/unavailable/home TMPDIR=/unavailable/tmp TZ=UTC0
    export PYTHONHOME=/forbidden/python-home PYTHONPATH=/forbidden/python-path
    export PYTHONUSERBASE=/forbidden/python-userbase PYTHONSTARTUP=/forbidden/startup.py
    export PYTHONPYCACHEPREFIX=/forbidden/pycache PYTHONIOENCODING=ascii PYTHONUTF8=0
    unset LD_LIBRARY_PATH LD_PRELOAD LD_AUDIT LD_DEBUG GLIBC_TUNABLES
    test ! -e /build-target/producer && test ! -e /build-target/include && test ! -e /build-target/staging
    test -f "$prefix/bin/python3.13"
    test -f "$prefix/lib/python3.13/encodings/__pycache__/__init__.cpython-313.pyc"
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
        case "$mode" in minimal|resources|stdlib) expected=0 ;; esac
        test "$status" -eq "$expected"
    done
    exit 0
fi

development=false
if test "${1:-}" = --allow-development; then
    development=true
    shift
fi
repo=$(CDPATH= cd -- "$(dirname -- "$0")/../.." && pwd)
evidence=${1:-"$repo/target/python-install-host-source-apps-validation"}
build=${2:-"$repo/target/python-install-host-source-apps-validation-build"}
test ! -e "$evidence" && test ! -e "$build"
mkdir -p "$evidence" "$build"
evidence=$(CDPATH= cd -- "$evidence" && pwd)
build=$(CDPATH= cd -- "$build" && pwd)
cd "$repo"
if test "$development" = false; then
    test -z "$(git status --porcelain)" || { printf '%s\n' 'Clean source required; use --allow-development explicitly for a development capture.' >&2; exit 1; }
fi
python3 fixtures/python-bootstrap/freeze.py "target/pbs-inspection/$full" "target/pbs-inspection/$install" \
    "$build/producer" "$build/include/python3.13" /build-target/freeze-bundle.json \
    --provenance /evidence/freeze-provenance.json --provision-only > "$evidence/provision.stdout.txt" 2> "$evidence/provision.stderr.txt"
test ! -s "$evidence/provision.stderr.txt"
cargo vendor --locked --offline target/python-bootstrap-vendor > "$evidence/vendor-config.toml" 2> "$evidence/vendor.stderr.txt"
git rev-parse HEAD > "$evidence/source-revision.txt"
git branch --show-current > "$evidence/source-branch.txt"
git status --porcelain > "$evidence/source-status.txt"
git diff --binary > "$evidence/source-diff.patch"
printf '%s\n' "$development" > "$evidence/development-opt-in.txt"
podman image inspect "$image" > "$evidence/image-inspect.json"
cp fixtures/python-install-host-source-apps/run-linux.sh "$evidence/commands.sh"
volume="glue-install-host-source-app-$$"
podman volume create "$volume" > "$evidence/runtime-volume-name.txt"
podman volume inspect "$volume" > "$evidence/runtime-volume-inspect.json"
trap 'podman volume rm -f "$volume" > "$evidence/runtime-volume-removal.stdout.txt" 2> "$evidence/runtime-volume-removal.stderr.txt"' 0
podman run --rm --network none --read-only --tmpfs /tmp:rw,size=256m \
    --mount "type=bind,source=$repo,destination=/workspace,ro" --mount "type=volume,source=$volume,destination=/build-target" \
    --mount "type=bind,source=$build,destination=/host-build" \
    --mount "type=bind,source=$evidence,destination=/evidence" --workdir /workspace "$image" sh fixtures/python-install-host-source-apps/run-linux.sh --build
chmod 0777 "$evidence"
podman run --rm --network none --read-only --read-only-tmpfs=false --tmpfs /tmp:rw,size=1m --tmpfs /unavailable:ro,mode=000,size=1m \
    --mount "type=volume,source=$volume,destination=/build-target,ro" --mount "type=bind,source=$evidence,destination=/evidence" \
    --workdir /build-target/runtime-empty "$image" sh -c \
    'chmod 000 /tmp; exec setpriv --reuid=65534 --regid=65534 --clear-groups --no-new-privs sh /build-target/runtime-commands.sh --run'
set +e
podman run --rm --network none --read-only --tmpfs /tmp:rw,size=256m \
    --mount "type=bind,source=$repo,destination=/workspace,ro" --mount "type=volume,source=$volume,destination=/build-target,ro" \
    --mount "type=bind,source=$build,destination=/host-build,ro" --mount "type=bind,source=$evidence,destination=/evidence" \
    --workdir /workspace "$image" /host-build/producer/bin/python3.13 -I -S -B \
    fixtures/python-install-host-source-apps/audit_installation.py "target/pbs-inspection/$install" "$prefix" \
    /evidence/host-runtime-provenance.json /evidence/post-runtime-provider-audit.json \
    > "$evidence/post-runtime-provider-audit.stdout.txt" 2> "$evidence/post-runtime-provider-audit.stderr.txt"
audit_status=$?
set -e
printf '%s\n' "$audit_status" > "$evidence/post-runtime-provider-audit.exit-status.txt"
test "$audit_status" -eq 0 && test ! -s "$evidence/post-runtime-provider-audit.stderr.txt"
for mode in $modes; do
    python3 scripts/check-linux-python-install-host-source-app-trace.py "$evidence/$mode.trace.txt" --mode "$mode" \
        --stdout-file "$evidence/$mode.stdout.txt" --stderr-file "$evidence/$mode.stderr.txt" \
        --metadata-file "$evidence/source-metadata.json" --archive-file "$build/relocated Python install host source apps/$mode.glue" \
        > "$evidence/$mode.trace-check.txt"
done
printf 'Stock install-only host source application evidence: %s\n' "$evidence"
