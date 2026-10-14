#!/bin/sh
# Build-time staging is separate from unprivileged, read-only runtime evidence.
set -eu
image=62812c4a0e15bc750ddd6ec68d2a19f8815a14b60d520e201a911e2e29f40abe
full=cpython-3.13.16+20261009-aarch64-unknown-linux-gnu-pgo+lto-full.tar.zst
install=cpython-3.13.16+20261009-aarch64-unknown-linux-gnu-install_only.tar.gz
relocated='/build-target/relocated Python metadata'
host_prefix='/build-target/host Python metadata'
install_prefix='/build-target/install Python metadata'
modes='bundled host install-host bundled-corrupt-entry host-corrupt-entry install-host-corrupt-entry'

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
    cargo test --locked --offline --release -p glue-pack --features python > /evidence/pack-tests.txt 2>&1
    cargo clippy --locked --offline --release --all-targets -p glue-pack --features python -- -D warnings > /evidence/pack-clippy.txt 2>&1
    cargo test --locked --offline --release -p glue-runner --features python-pbs > /evidence/runner-tests.txt 2>&1
    cargo clippy --locked --offline --release --all-targets -p glue-runner --features python-pbs -- -D warnings > /evidence/runner-clippy.txt 2>&1
    cargo build --locked --offline --release -p glue-runner --features python-pbs -p glue-python-bootstrap-probe --features pbs-bootstrap > /evidence/build.txt 2>&1
    /build-target/producer/bin/python3.13 -I -S -B /workspace/fixtures/python-metadata/test_protocol.py > /evidence/metadata-protocol-tests.txt 2>&1
    /build-target/producer/bin/python3.13 -I -S -B /workspace/fixtures/python-imports/test_importer.py > /evidence/importer-protocol-tests.txt 2>&1
    /build-target/producer/bin/python3.13 -I -S -B /workspace/fixtures/python-source-apps/test_entry.py > /evidence/entry-protocol-tests.txt 2>&1
    /build-target/producer/bin/python3.13 -I -S -B /workspace/fixtures/python-runtime-trees/test_prepare.py > /evidence/runtime-tree-oracle-tests.txt 2>&1
    /build-target/producer/bin/python3.13 -I -S -B /workspace/fixtures/python-runtime-trees/test_process_unit.py > /evidence/runtime-tree-process-tests.txt 2>&1
    cp /build-target/release/glue /host-build/fixture-glue
    chmod 0555 /host-build/fixture-glue
    mkdir "$relocated" /build-target/runtime-empty /build-target/staging /evidence/cli-controls
    /build-target/producer/bin/python3.13 -I -S -B /workspace/fixtures/python-runtime-trees/prepare.py install \
        --uv /workspace/target/uv-runtime-tree-downloads/uv \
        --pbs-install-only "/workspace/target/pbs-inspection/$install" \
        --output /host-build/runtime-tree-install --remove-bin \
        > /evidence/runtime-tree-install.stdout.txt 2> /evidence/runtime-tree-install.stderr.txt
    test ! -s /evidence/runtime-tree-install.stderr.txt
    cp /host-build/runtime-tree-install/installation-provenance.json /evidence/runtime-tree-installation.json
    cp /host-build/runtime-tree-install/download-metadata.json /evidence/uv-download-metadata.json
    cp /host-build/runtime-tree-install/command.json /evidence/uv-install-command.json
    cp /host-build/runtime-tree-install/stdout.txt /evidence/uv-install.stdout.txt
    cp /host-build/runtime-tree-install/stderr.txt /evidence/uv-install.stderr.txt
    cp /host-build/runtime-tree-install/exit-status.txt /evidence/uv-install.exit-status.txt
    tree_root=/host-build/runtime-tree-install/install/cpython-3.13.16-linux-aarch64-gnu
    for provider in host install-host; do
        case "$provider" in
            host) selected=host-full; prefix="$host_prefix"; set -- --provider host-full --pbs-full "/workspace/target/pbs-inspection/$full" ;;
            install-host) selected=host-install; prefix="$install_prefix"; set -- --provider host-install --runtime-tree "$tree_root" ;;
        esac
        trace_verbose=
        if test "$provider" = install-host; then trace_verbose=-v; fi
        strace -f $trace_verbose -s 512 -yy -e trace=all -o "/evidence/$provider.host-process.trace.txt" \
            /build-target/release/glue python-host "$@" --output "$prefix" --json \
            > "/evidence/$provider.host-report.json" 2> "/evidence/$provider.host.stderr.txt"
        printf '0\n' > "/evidence/$provider.host.exit-status.txt"
        test ! -s "/evidence/$provider.host.stderr.txt"
        cp "$prefix/provenance.json" "/evidence/$provider.host-provenance.json"
        if test "$provider" = install-host; then
            /build-target/producer/bin/python3.13 -I -S -B /workspace/fixtures/python-runtime-trees/prepare.py audit-output \
                --runtime-tree "$tree_root" --prefix "$prefix" --report "/evidence/$provider.host-report.json" \
                --output "/evidence/$provider.host-tree-audit.json"
            /build-target/producer/bin/python3.13 -I -S -B /workspace/fixtures/python-runtime-trees/test_process.py \
                --trace "/evidence/$provider.host-process.trace.txt" --program /build-target/release/glue \
                --runtime-tree "$tree_root" --prefix "$prefix" --report "/evidence/$provider.host-report.json" \
                --input-audit /evidence/runtime-tree-installation.json \
                > "/evidence/$provider.host-process-check.json"
            /build-target/producer/bin/python3.13 -I -S -B /workspace/fixtures/python-runtime-trees/test_process.py \
                --trace "/evidence/$provider.host-process.trace.txt" --program /build-target/release/glue \
                --runtime-tree "$tree_root" --prefix "$prefix" --report "/evidence/$provider.host-report.json" \
                --input-audit /evidence/runtime-tree-installation.json --hostile-controls \
                > "/evidence/$provider.host-process-hostile-controls.json"
        else
        /build-target/producer/bin/python3.13 -I -S -B /workspace/fixtures/python-host-prerequisites/test_prepare.py \
            --audit-tree "$prefix" --provider "$selected" \
            --report "/evidence/$provider.host-report.json" --output "/evidence/$provider.host-tree-audit.json"
        /build-target/producer/bin/python3.13 -I -S -B /workspace/fixtures/python-host-prerequisites/test_prepare.py \
            --audit-process-trace "/evidence/$provider.host-process.trace.txt" \
            --program /build-target/release/glue > "/evidence/$provider.host-process-check.json"
        fi
    done
    /build-target/producer/bin/python3.13 -I -S -B /workspace/fixtures/python-runtime-trees/prepare.py controls \
        --glue /build-target/release/glue --runtime-tree "$tree_root" --output /evidence/runtime-tree-controls \
        > /evidence/runtime-tree-controls.stdout.txt 2> /evidence/runtime-tree-controls.stderr.txt
    test ! -s /evidence/runtime-tree-controls.stderr.txt
    # Physical metadata lures are independent fixture additions after the product
    # prerequisite trees have been audited. Archive metadata queries must ignore them.
    /build-target/producer/bin/python3.13 -I -S -B - "$host_prefix" "$install_prefix" <<'PY_LURES'
from pathlib import Path
import hashlib, json, os, sys
records = {}
for prefix in map(Path, sys.argv[1:]):
    additions = {}
    for directory, name, version in [('markdown_it_py-999.dist-info', 'markdown-it-py', '999'), ('glue_real_package_physical_lure-99.dist-info', 'glue-real-package-physical-lure', '99')]:
        target = prefix / 'lib/python3.13/site-packages' / directory / 'METADATA'
        target.parent.mkdir(parents=True, exist_ok=True)
        payload = f'Metadata-Version: 2.3\nName: {name}\nVersion: {version}\n'.encode()
        target.write_bytes(payload); target.chmod(0o444); target.parent.chmod(0o555)
        os.utime(target, (1704067200, 1704067200))
        additions[target.relative_to(prefix).as_posix()] = {'size':len(payload), 'sha256':hashlib.sha256(payload).hexdigest()}
    records[str(prefix)] = additions
Path('/evidence/host-metadata-lures.json').write_text(json.dumps(records, indent=2, sort_keys=True)+'\n')
PY_LURES
    /build-target/producer/bin/python3.13 -I -S -B /workspace/fixtures/python-real-packages/prepare.py install \
        /build-target/producer /host-build/installed-packages > /evidence/install.stdout.txt 2> /evidence/install.stderr.txt
    test ! -s /evidence/install.stderr.txt
    cp /host-build/installed-packages/installation-provenance.json /evidence/installation-provenance.json
    cp /host-build/installed-packages/baseline.stdout.txt /evidence/baseline.stdout.txt
    cp /host-build/installed-packages/expected-inventory.json /evidence/expected-inventory.json
    mkdir /evidence/template-cli
    for provider in bundled host install-host; do
        case "$provider" in
            bundled) set -- --provider bundled --pbs-full "/workspace/target/pbs-inspection/$full" --frozen-bootstrap /build-target/freeze-bundle.json ;;
            host) set -- --provider host-full --host-prefix "$host_prefix" ;;
            install-host) set -- --provider host-install --host-prefix "$install_prefix" ;;
        esac
        strace -f -s 4096 -yy -e trace=process,file,network -o "/evidence/$provider.template-process.trace.txt" \
            /build-target/release/glue python-template "$@" --output "/build-target/staging/$provider" --json \
            > "/evidence/template-cli/$provider.stdout.txt" 2> "/evidence/template-cli/$provider.stderr.txt"
        printf '0\n' > "/evidence/template-cli/$provider.exit-status.txt"
        test ! -s "/evidence/template-cli/$provider.stderr.txt"
        cp "/build-target/staging/$provider/manifest.json" "/evidence/$provider.template.json"
        cp "/build-target/staging/$provider/provenance.json" "/evidence/$provider.template-provenance.json"
        strace -f -s 4096 -yy -e trace=process -o "/evidence/$provider.build-process.trace.txt" \
            /build-target/release/glue build-python \
            --provider-template "/build-target/staging/$provider/manifest.json" \
            --provider-root "/build-target/staging/$provider/root" \
            --app /host-build/installed-packages/application --venv /host-build/installed-packages/venv \
            --app-id python.real-packages --entry app/main.py --output "$relocated/$provider.glue" --json \
            > "/evidence/cli-controls/$provider.build.stdout.txt" 2> "/evidence/cli-controls/$provider.build.stderr.txt"
        printf '0\n' > "/evidence/cli-controls/$provider.build.exit-status.txt"
        test ! -s "/evidence/cli-controls/$provider.build.stderr.txt"
        /build-target/release/glue inspect "$relocated/$provider.glue" --json > "/evidence/$provider.manifest.json"
        /build-target/producer/bin/python3.13 -I -S -B /workspace/fixtures/python-real-packages/prepare.py \
            audit-build "/evidence/cli-controls/$provider.build.stdout.txt" "$relocated/$provider.glue" \
            --provenance /evidence/installation-provenance.json > "/evidence/$provider.product-audit.json"
        case "$provider" in
            bundled) set -- ;;
            host) set -- --host-prefix "$host_prefix" ;;
            install-host) set -- --host-prefix "$install_prefix" ;;
        esac
        /build-target/producer/bin/python3.13 -I -S -B /workspace/fixtures/python-runtime-templates/test_templates.py \
            --audit-process-trace "/evidence/$provider.template-process.trace.txt" \
            --program /build-target/release/glue "$@" > "/evidence/$provider.template-process-check.json"
    done
    /build-target/producer/bin/python3.13 -I -S -B /workspace/fixtures/python-runtime-templates/test_audit.py \
        > /evidence/template-oracle-tests.txt 2>&1
    /build-target/producer/bin/python3.13 -I -S -B /workspace/fixtures/python-host-prerequisites/test_audit.py \
        > /evidence/host-oracle-tests.txt 2>&1
    if test -f /workspace/fixtures/python-real-packages/test_prepare.py; then
        /build-target/producer/bin/python3.13 -I -S -B /workspace/fixtures/python-real-packages/test_prepare.py \
            > /evidence/real-package-oracle-tests.txt 2>&1
    else
        test "${GLUE_REAL_PACKAGE_DEVELOPMENT:-false}" = true
        printf 'Development capture: standalone fixture checks pending\n' > /evidence/real-package-oracle-tests.txt
    fi
    /build-target/producer/bin/python3.13 -I -S -B /workspace/fixtures/python-venv-ingestion/prepare.py install \
        /build-target/producer /host-build/regression-packages > /evidence/regression-install.stdout.txt 2> /evidence/regression-install.stderr.txt
    test ! -s /evidence/regression-install.stderr.txt
    /build-target/producer/bin/python3.13 -I -S -B /workspace/fixtures/python-venv-ingestion/test_build.py \
        --glue /build-target/release/glue --template /build-target/staging/install-host/manifest.json \
        --provider-root /build-target/staging/install-host/root --prepared /host-build/regression-packages \
        --output /evidence/build-controls > /evidence/build-controls.stdout.txt 2> /evidence/build-controls.stderr.txt
    test ! -s /evidence/build-controls.stderr.txt
    /build-target/producer/bin/python3.13 -I -S -B /workspace/fixtures/python-real-packages/test_requirements.py \
        --glue /build-target/release/glue --template /build-target/staging/install-host/manifest.json \
        --provider-root /build-target/staging/install-host/root --prepared /host-build/installed-packages \
        --output /evidence/requirement-controls > /evidence/requirement-controls.stdout.txt 2> /evidence/requirement-controls.stderr.txt
    test ! -s /evidence/requirement-controls.stderr.txt
    /build-target/producer/bin/python3.13 -I -S -B - "$relocated" <<'PY'
from pathlib import Path
import struct, sys, zipfile
root = Path(sys.argv[1])
key = 'app/main.py'
for provider in ['bundled', 'host', 'install-host']:
    source = root / (provider+'.glue')
    with zipfile.ZipFile(source) as archive:
        info = archive.getinfo(key)
    payload = bytearray(source.read_bytes())
    names, extra = struct.unpack_from('<HH', payload, info.header_offset+26)
    payload[info.header_offset+30+names+extra] ^= 1
    (root / (provider+'-corrupt-entry.glue')).write_bytes(payload)
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
            case "$mode.$operation" in *-corrupt-entry.verify|*-corrupt-entry.cat) expected=1 ;; esac
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
    cp /workspace/fixtures/python-runtime-trees/run-linux.sh /build-target/runtime-commands.sh
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
    (target / path.name).chmod(path.stat().st_mode & 0o777)
PY
    rm -rf /host-build/runtime-tree-install /build-target/producer /build-target/include /build-target/release /build-target/debug /build-target/staging \
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
evidence=${1:-"$repo/target/python-runtime-trees-validation"}
build=${2:-"$repo/target/python-runtime-trees-validation-build"}
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
python3 fixtures/python-bootstrap/freeze.py "target/pbs-inspection/$full" "target/pbs-inspection/$install" \
    "$build/producer" "$build/include/python3.13" /build-target/freeze-bundle.json \
    --provenance /evidence/freeze-provenance.json --provision-only > "$evidence/provision.stdout.txt" 2> "$evidence/provision.stderr.txt"
test ! -s "$evidence/provision.stderr.txt"
cargo vendor --locked --offline target/python-bootstrap-vendor > "$evidence/vendor-config.toml" 2> "$evidence/vendor.stderr.txt"
git rev-parse HEAD > "$evidence/source-revision.txt"
git branch --show-current > "$evidence/source-branch.txt"
git status --porcelain > "$evidence/source-status.txt"
git diff --binary > "$evidence/source-diff.patch"
cp fixtures/python-runtime-trees/run-linux.sh "$evidence/commands.sh"
podman image inspect "$image" > "$evidence/image-inspect.json"
volume="glue-python-runtime-trees-$$"
podman volume create "$volume" > "$evidence/volume-name.txt"
trap 'podman volume rm -f "$volume" > "$evidence/volume-removal.stdout.txt" 2> "$evidence/volume-removal.stderr.txt"' 0
podman run --rm --network none --read-only --tmpfs /tmp:rw,size=256m \
    --env "GLUE_REAL_PACKAGE_DEVELOPMENT=$development" \
    --mount "type=bind,source=$repo,destination=/workspace,ro" --mount "type=volume,source=$volume,destination=/build-target" \
    --mount "type=bind,source=$build,destination=/host-build" --mount "type=bind,source=$evidence,destination=/evidence" \
    --workdir /workspace "$image" sh /workspace/fixtures/python-runtime-trees/run-linux.sh --build
chmod 0777 "$evidence"
podman run --rm --network none --read-only --read-only-tmpfs=false --tmpfs /tmp:rw,size=1m --tmpfs /unavailable:ro,mode=000,size=1m \
    --mount "type=volume,source=$volume,destination=/build-target,ro" --mount "type=bind,source=$evidence,destination=/evidence" \
    --workdir /build-target/runtime-empty "$image" sh -c \
    'chmod 000 /tmp; exec setpriv --reuid=65534 --regid=65534 --clear-groups --no-new-privs sh /build-target/runtime-commands.sh --run'
if test "$development" = false; then
    python3 scripts/check-linux-python-real-packages-trace.py --emit-metadata "$build/relocated Python metadata" "$evidence/source-metadata.json"
    for mode in $modes; do
        python3 scripts/check-linux-python-real-packages-trace.py "$evidence/$mode.trace.txt" --mode "$mode" \
            --stdout-file "$evidence/$mode.stdout.txt" --stderr-file "$evidence/$mode.stderr.txt" \
            --metadata-file "$evidence/source-metadata.json" --archive-file "$build/relocated Python metadata/$mode.glue" > "$evidence/$mode.trace-check.txt"
    done
fi
printf 'Python installed-runtime-tree evidence: %s\n' "$evidence"
