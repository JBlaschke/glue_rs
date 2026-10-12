#!/bin/sh
# Staging, packaging and stock-source construction are build-time operations.
set -eu
image=62812c4a0e15bc750ddd6ec68d2a19f8815a14b60d520e201a911e2e29f40abe
full=cpython-3.13.16+20261009-aarch64-unknown-linux-gnu-pgo+lto-full.tar.zst
install=cpython-3.13.16+20261009-aarch64-unknown-linux-gnu-install_only.tar.gz
relocated='/build-target/relocated Python source apps'
modes='minimal resources app-error syntax nul corrupt-source'

if test "${1:-}" = --build; then
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
    mkdir "$relocated" /build-target/runtime-empty /build-target/staging /evidence/cli-controls
    /build-target/release/glue-python-bootstrap-probe prepare-imports "/workspace/target/pbs-inspection/$full" \
        /build-target/freeze-bundle.json /build-target/base.glue > /evidence/base.prepare.stdout.txt 2> /evidence/base.prepare.stderr.txt
    test ! -s /evidence/base.prepare.stderr.txt
    for mode in minimal resources app-error syntax nul; do
        case "$mode" in
            minimal) input=minimal; app=minimal.source; entry=app/launch.py; component=launch ;;
            resources) input=resources; app=daily.report; entry="app/tasks/report's [daily].py"; component=report ;;
            app-error) input=error; app=failing.source; entry=app/jobs/fail.py; component=fail ;;
            syntax) input=syntax; app=syntax.source; entry=app/jobs/invalid.py; component=syntax ;;
            nul) input=nul; app=nul.source; entry=app/embedded-nul.py; component=nul ;;
        esac
        /build-target/producer/bin/python3.13 -I -S -B /workspace/fixtures/python-source-apps/prepare.py \
            /build-target/base.glue "/workspace/fixtures/python-source-apps/input-$input" "/build-target/staging/$mode" \
            --app-id "$app" --entry "$entry" --component "$component" \
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
    path = staging / 'minimal/root' / key
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(content)
    (staging / (name + '.json')).write_text(json.dumps(changed))
changed = copy.deepcopy(base)
changed['resources']['python/archive-importer.py']['sha256'] = '0' * 64
(staging / 'helper-drift.json').write_text(json.dumps(changed))
raw = source.read_bytes()
manifest_length = struct.unpack_from('<Q', raw,16)[0]
zip_payload = raw[64+manifest_length:]
for name, changed in [('helper-drift',changed),('outside-entry',copy.deepcopy(base))]:
    if name=='outside-entry': changed['components']['launch']['entry_point']='stdlib/contextlib.py'
    manifest = json.dumps(changed,sort_keys=True,separators=(',',':')).encode()
    header = b'GLUERS00' + struct.pack('<IIQQ',0,0,len(manifest),len(zip_payload)) + hashlib.sha256(manifest).digest()
    (archives / (name+'.glue')).write_bytes(header+manifest+zip_payload)
PY
    for name in protected-module bytecode helper-drift; do
        set +e
        /build-target/release/glue build --manifest "/build-target/staging/$name.json" \
            --root /build-target/staging/minimal/root --output "/build-target/$name-should-not-exist.glue" \
            > "/evidence/cli-controls/$name.build.stdout.txt" 2> "/evidence/cli-controls/$name.build.stderr.txt"
        status=$?
        set -e
        printf '%s\n' "$status" > "/evidence/cli-controls/$name.build.exit-status.txt"
        test "$status" -eq 1
        test ! -e "/build-target/$name-should-not-exist.glue"
    done
    cp /build-target/release/glue "$relocated/glue"
    readelf -W -d --dyn-syms "$relocated/glue" > /evidence/launcher.elf.txt
    for mode in $modes; do
        case "$mode" in
            minimal|corrupt-source) entry=app/launch.py ;;
            resources) entry="app/tasks/report's [daily].py" ;;
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
    for name in helper-drift outside-entry; do
        set +e
        /build-target/release/glue doctor "$relocated/$name.glue" \
            > "/evidence/cli-controls/$name.doctor.stdout.txt" 2> "/evidence/cli-controls/$name.doctor.stderr.txt"
        status=$?
        set -e
        printf '%s\n' "$status" > "/evidence/cli-controls/$name.doctor.exit-status.txt"
        test "$status" -eq 1
    done
    /build-target/producer/bin/python3.13 -I -S -B /workspace/scripts/check-linux-python-source-app-trace.py \
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
    cp /workspace/fixtures/python-source-apps/run-linux.sh /build-target/runtime-commands.sh
    chmod 0555 "$relocated/glue" "$relocated" /build-target/runtime-empty
    chmod 0444 "$relocated/"*.glue
    rm -rf /build-target/producer /build-target/include /build-target/release /build-target/debug \
        /build-target/staging /build-target/base.glue /build-target/freeze-bundle.json
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
    test ! -e /build-target/producer
    test ! -e /build-target/include
    test ! -e /build-target/staging
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
        case "$mode" in minimal|resources) expected=0 ;; esac
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
evidence=${1:-"$repo/target/python-source-apps-validation"}
build=${2:-"$repo/target/python-source-apps-validation-build"}
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
cp fixtures/python-source-apps/run-linux.sh "$evidence/commands.sh"
podman run --rm --network none --read-only --tmpfs /tmp:rw,size=256m \
    --mount "type=bind,source=$repo,destination=/workspace,ro" --mount "type=bind,source=$build,destination=/build-target" \
    --mount "type=bind,source=$evidence,destination=/evidence" --workdir /workspace "$image" sh fixtures/python-source-apps/run-linux.sh --build
chmod 0777 "$evidence"
podman run --rm --network none --read-only --read-only-tmpfs=false --tmpfs /tmp:rw,size=1m --tmpfs /unavailable:ro,mode=000,size=1m \
    --mount "type=bind,source=$build,destination=/build-target,ro" --mount "type=bind,source=$evidence,destination=/evidence" \
    --workdir /build-target/runtime-empty "$image" sh -c \
    'chmod 000 /tmp; exec setpriv --reuid=65534 --regid=65534 --clear-groups --no-new-privs sh /build-target/runtime-commands.sh --run'
for mode in $modes; do
    python3 scripts/check-linux-python-source-app-trace.py "$evidence/$mode.trace.txt" --mode "$mode" \
        --stdout-file "$evidence/$mode.stdout.txt" --stderr-file "$evidence/$mode.stderr.txt" \
        --metadata-file "$evidence/source-metadata.json" --archive-file "$build/relocated Python source apps/$mode.glue" \
        > "$evidence/$mode.trace-check.txt"
done
printf 'Bundled source application evidence: %s\n' "$evidence"
