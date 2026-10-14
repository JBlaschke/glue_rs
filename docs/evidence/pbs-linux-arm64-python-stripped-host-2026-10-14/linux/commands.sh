#!/bin/sh
# Build-time files are removed before the unprivileged read-only runtime phase.
set -eu
image=62812c4a0e15bc750ddd6ec68d2a19f8815a14b60d520e201a911e2e29f40abe
full=cpython-3.13.16+20261009-aarch64-unknown-linux-gnu-pgo+lto-full.tar.zst
original=cpython-3.13.16+20261009-aarch64-unknown-linux-gnu-install_only.tar.gz
stripped=cpython-3.13.16+20261009-aarch64-unknown-linux-gnu-install_only_stripped.tar.gz
relocated='/build-target/relocated Python stripped host'
prefix='/build-target/Python stripped host'
old_prefix='/build-target/Python unstripped host'
modes='stripped unstripped missing-library wrong-library corrupt-library corrupt-entry wrong-profile'

if test "${1:-}" = --build; then
    cp -a /host-build/producer /build-target/producer
    cp -a /host-build/include /build-target/include
    export PATH=/usr/local/rustup/toolchains/1.88.0-aarch64-unknown-linux-gnu/bin:$PATH
    export CARGO_HOME=/tmp/cargo CARGO_TARGET_DIR=/build-target
    export GLUE_PYTHON_INCLUDE_DIR=/build-target/include/python3.13
    mkdir -p "$CARGO_HOME"
    printf '%s\n' '[source.crates-io]' 'replace-with = "vendored-sources"' \
        '[source.vendored-sources]' 'directory = "/workspace/target/python-bootstrap-vendor"' > "$CARGO_HOME/config.toml"
    cargo test --locked --offline --release -p glue-runtime-python -p glue-python-bootstrap-probe --features pbs-bootstrap > /evidence/python-tests.txt 2>&1
    cargo clippy --locked --offline --release --all-targets -p glue-runtime-python -p glue-python-bootstrap-probe --features pbs-bootstrap -- -D warnings > /evidence/python-clippy.txt 2>&1
    cargo test --locked --offline --release -p glue-pack --features python > /evidence/pack-tests.txt 2>&1
    cargo clippy --locked --offline --release --all-targets -p glue-pack --features python -- -D warnings > /evidence/pack-clippy.txt 2>&1
    cargo test --locked --offline --release -p glue-runner --features python-pbs > /evidence/runner-tests.txt 2>&1
    cargo clippy --locked --offline --release --all-targets -p glue-runner --features python-pbs -- -D warnings > /evidence/runner-clippy.txt 2>&1
    cargo build --locked --offline --release -p glue-runner --features python-pbs > /evidence/build.txt 2>&1
    /build-target/producer/bin/python3.13 -I -S -B /workspace/fixtures/python-stripped-host/test_prepare.py > /evidence/preparation-unit-tests.txt 2>&1
    /build-target/producer/bin/python3.13 -I -S -B /workspace/fixtures/python-stripped-host/test_runtime.py > /evidence/runtime-fixture-unit-tests.txt 2>&1
    /build-target/producer/bin/python3.13 -I -S -B /workspace/fixtures/python-stripped-host/test_process_unit.py > /evidence/preparation-process-unit-tests.txt 2>&1
    /build-target/producer/bin/python3.13 -I -S -B /workspace/scripts/test_linux_python_stripped_host_trace.py > /evidence/runtime-policy-unit-tests.txt 2>&1
    /build-target/producer/bin/python3.13 -I -S -B - > /evidence/legacy-python-policy-unit-tests.txt 2>&1 <<'PY_POLICIES'
from pathlib import Path
import sys, unittest
root = Path('/workspace/scripts')
sys.path.insert(0, str(root))
suite = unittest.TestSuite()
for path in sorted(root.glob('test_linux_python_*trace.py')):
    if path.name != 'test_linux_python_stripped_host_trace.py':
        suite.addTests(unittest.defaultTestLoader.loadTestsFromName(path.stem))
assert suite.countTestCases() == 253
assert unittest.TextTestRunner(verbosity=1).run(suite).wasSuccessful()
PY_POLICIES
    uname -a > /evidence/kernel.txt
    getconf GNU_LIBC_VERSION > /evidence/glibc.txt
    rustc --version > /evidence/rust.txt
    strace --version > /evidence/strace.txt
    mkdir "$relocated" /build-target/runtime-empty /build-target/staging
    cp /build-target/release/glue "$relocated/glue"
    chmod 0555 "$relocated/glue"
    for provider in stripped unstripped; do
        case "$provider" in
            stripped) selected=host-install-stripped; artifact="$stripped"; destination="$prefix" ;;
            unstripped) selected=host-install; artifact="$original"; destination="$old_prefix" ;;
        esac
        strace -f -s 512 -yy -v -e trace=all -o "/evidence/$provider.prepare.trace.txt" \
            /build-target/release/glue python-host --provider "$selected" \
            --pbs-install-only "/workspace/target/pbs-inspection/$artifact" --output "$destination" --json \
            > "/evidence/$provider.prepare.json" 2> "/evidence/$provider.prepare.stderr.txt"
        printf '0\n' > "/evidence/$provider.prepare.exit-status.txt"
        test ! -s "/evidence/$provider.prepare.stderr.txt"
        cp "$destination/provenance.json" "/evidence/$provider.provenance.json"
        if test "$provider" = stripped; then
            /build-target/producer/bin/python3.13 -I -S -B /workspace/fixtures/python-stripped-host/prepare.py audit-output \
                --prefix "$destination" --report "/evidence/$provider.prepare.json" --output "/evidence/$provider.output-audit.json"
        else
            /build-target/producer/bin/python3.13 -I -S -B /workspace/fixtures/python-host-prerequisites/test_prepare.py \
                --audit-tree "$destination" --provider host-install --report "/evidence/$provider.prepare.json" \
                --output "/evidence/$provider.output-audit.json"
        fi
    done
    /build-target/producer/bin/python3.13 -I -S -B /workspace/fixtures/python-stripped-host/prepare.py extract-tree \
        --pbs-install-only "/workspace/target/pbs-inspection/$stripped" --output /host-build/stripped-input \
        --audit /evidence/stripped.input-audit.json > /evidence/extract.stdout.txt 2> /evidence/extract.stderr.txt
    test ! -s /evidence/extract.stderr.txt
    strace -f -s 512 -yy -v -e trace=all -o /evidence/stripped-tree.prepare.trace.txt \
        /build-target/release/glue python-host --provider host-install-stripped --runtime-tree /host-build/stripped-input \
        --output '/build-target/Python stripped tree' --json > /evidence/stripped-tree.prepare.json 2> /evidence/stripped-tree.prepare.stderr.txt
    printf '0\n' > /evidence/stripped-tree.prepare.exit-status.txt
    test ! -s /evidence/stripped-tree.prepare.stderr.txt
    /build-target/producer/bin/python3.13 -I -S -B /workspace/fixtures/python-stripped-host/prepare.py audit-output \
        --prefix '/build-target/Python stripped tree' --runtime-tree /host-build/stripped-input \
        --report /evidence/stripped-tree.prepare.json --output /evidence/stripped-tree.output-audit.json
    if test -f /workspace/fixtures/python-stripped-host/test_process.py; then
        /build-target/producer/bin/python3.13 -I -S -B /workspace/fixtures/python-stripped-host/test_process.py \
            --trace /evidence/stripped.prepare.trace.txt --program /build-target/release/glue --prefix "$prefix" \
            --artifact "/workspace/target/pbs-inspection/$stripped" --report /evidence/stripped.prepare.json \
            --output /evidence/stripped.prepare-process-audit.json
        /build-target/producer/bin/python3.13 -I -S -B /workspace/fixtures/python-stripped-host/test_process.py \
            --trace /evidence/stripped-tree.prepare.trace.txt --program /build-target/release/glue --prefix '/build-target/Python stripped tree' \
            --runtime-tree /host-build/stripped-input --input-audit /evidence/stripped.input-audit.json \
            --report /evidence/stripped-tree.prepare.json --output /evidence/stripped-tree.prepare-process-audit.json
        /build-target/producer/bin/python3.13 -I -S -B /workspace/fixtures/python-stripped-host/test_process.py \
            --trace /evidence/stripped.prepare.trace.txt --program /build-target/release/glue --prefix "$prefix" \
            --artifact "/workspace/target/pbs-inspection/$stripped" --report /evidence/stripped.prepare.json \
            --hostile-controls --output /evidence/stripped.prepare-process-hostile-controls.json
        /build-target/producer/bin/python3.13 -I -S -B /workspace/fixtures/python-stripped-host/test_process.py \
            --trace /evidence/stripped-tree.prepare.trace.txt --program /build-target/release/glue --prefix '/build-target/Python stripped tree' \
            --runtime-tree /host-build/stripped-input --input-audit /evidence/stripped.input-audit.json \
            --report /evidence/stripped-tree.prepare.json --hostile-controls \
            --output /evidence/stripped-tree.prepare-process-hostile-controls.json
    elif test "${GLUE_STRIPPED_DEVELOPMENT:-false}" != true; then
        printf 'Required stripped preparation process oracle is missing\n' >&2
        exit 1
    fi
    /build-target/producer/bin/python3.13 -I -S -B /workspace/fixtures/python-stripped-host/prepare.py controls \
        --glue /build-target/release/glue --pbs-install-only "/workspace/target/pbs-inspection/$stripped" \
        --unstripped-artifact "/workspace/target/pbs-inspection/$original" --runtime-tree /host-build/stripped-input \
        --output /evidence/preparation-controls > /evidence/preparation-controls.stdout.txt 2> /evidence/preparation-controls.stderr.txt
    test ! -s /evidence/preparation-controls.stderr.txt
    /build-target/producer/bin/python3.13 -I -S -B /workspace/fixtures/python-stripped-host/runtime.py controls \
        --prepared "$prefix" --unstripped "$old_prefix" > /evidence/runtime-controls.json
    for mode in $modes; do
        case "$mode" in
            corrupt-entry) continue ;;
            unstripped) selected=host-install; destination="$old_prefix" ;;
            wrong-profile) selected=host-install; destination="$prefix" ;;
            missing-library|wrong-library|corrupt-library) selected=host-install-stripped; destination="$prefix $mode" ;;
            stripped) selected=host-install-stripped; destination="$prefix" ;;
        esac
        strace -f -s 512 -yy -e trace=all -o "/evidence/$mode.template.trace.txt" \
            /build-target/release/glue python-template --provider "$selected" --host-prefix "$destination" \
            --output "/build-target/staging/$mode-template" --json > "/evidence/$mode.template.json" 2> "/evidence/$mode.template.stderr.txt"
        test ! -s "/evidence/$mode.template.stderr.txt"
        /build-target/producer/bin/python3.13 -I -S -B /workspace/fixtures/python-stripped-host/runtime.py stage \
            --template "/build-target/staging/$mode-template" --mode "$mode" --output "/build-target/staging/$mode-input" \
            > "/evidence/$mode.stage.json"
        strace -f -s 512 -yy -e trace=process -o "/evidence/$mode.build-process.trace.txt" \
            /build-target/release/glue build --manifest "/build-target/staging/$mode-input/manifest.json" \
            --root "/build-target/staging/$mode-input" --output "$relocated/$mode.glue" \
            > "/evidence/$mode.build.stdout.txt" 2> "/evidence/$mode.build.stderr.txt"
        test ! -s "/evidence/$mode.build.stderr.txt"
        cp "/build-target/staging/$mode-input/manifest.json" "/evidence/$mode.manifest.json"
        /build-target/release/glue verify "$relocated/$mode.glue" > "/evidence/$mode.verify.stdout.txt" 2> "/evidence/$mode.verify.stderr.txt"
    done
    /build-target/producer/bin/python3.13 -I -S -B /workspace/fixtures/python-stripped-host/runtime.py corrupt-entry \
        --archive "$relocated/stripped.glue" --output "$relocated/corrupt-entry.glue" > /evidence/corrupt-entry.mutation.json
    cp "$old_prefix/lib/libpython3.13.so.1.0" /build-target/preloaded-libpython.so
    /build-target/producer/bin/python3.13 -I -S -B - <<'PY_PRELOAD'
from pathlib import Path
import hashlib, json
path = Path('/build-target/preloaded-libpython.so')
payload = path.read_bytes()
expected = {'size': 73563968, 'sha256': '42be968275d5be2d9e632ec9ef6790dd2c10f1d4a710ad1028fc2b687242f219'}
assert {'size': len(payload), 'sha256': hashlib.sha256(payload).hexdigest()} == expected
Path('/evidence/preload-image.json').write_text(json.dumps({'path': str(path), **expected}, sort_keys=True) + '\n')
PY_PRELOAD
    cp /workspace/fixtures/python-stripped-host/run-linux.sh /build-target/runtime-commands.sh
    /build-target/producer/bin/python3.13 -I -S -B - "$relocated" <<'PY_EXPORT'
from pathlib import Path
import shutil, sys
source = Path(sys.argv[1]); destination = Path('/host-build') / source.name
destination.mkdir()
for file in source.iterdir():
    shutil.copyfile(file, destination / file.name)
    (destination / file.name).chmod(file.stat().st_mode & 0o777)
PY_EXPORT
    rm -rf /host-build/stripped-input /build-target/producer /build-target/include /build-target/release /build-target/debug /build-target/staging
    exit 0
fi

if test "${1:-}" = --run; then
    cd /build-target/runtime-empty
    export HOME=/unavailable/home TMPDIR=/unavailable/tmp TZ=UTC0 LC_ALL=C
    export PYTHONHOME=/forbidden/home PYTHONPATH=/forbidden/path PYTHONUSERBASE=/forbidden/userbase
    export PYTHONPYCACHEPREFIX=/forbidden/pycache PYTHONSTARTUP=/forbidden/startup.py
    export OPENSSL_CONF=/dev/null
    unset LD_LIBRARY_PATH LD_PRELOAD LD_AUDIT LD_DEBUG GLIBC_TUNABLES
    test ! -e /build-target/producer
    test ! -e /build-target/include
    test ! -e /build-target/staging
    test ! -r /tmp
    test ! -w /tmp
    test ! -x /tmp
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
        case "$mode" in stripped|unstripped) expected=0 ;; esac
        test "$status" -eq "$expected"
    done
    set +e
    strace -f -s 256 -yy -e trace=all -E LD_PRELOAD=/build-target/preloaded-libpython.so \
        -o /evidence/preload.trace.txt "$relocated/glue" run "$relocated/stripped.glue" \
        < /dev/null > /evidence/preload.stdout.txt 2> /evidence/preload.stderr.txt
    status=$?
    set -e
    printf '%s\n' "$status" > /evidence/preload.exit-status.txt
    test "$status" -eq 1
    test ! -s /evidence/preload.stdout.txt
    printf 'glue: loader override LD_PRELOAD is unsupported\n' > /evidence/preload.expected.stderr.txt
    cmp /evidence/preload.stderr.txt /evidence/preload.expected.stderr.txt
    exit 0
fi

development=false
if test "${1:-}" = --allow-development; then development=true; shift; fi
repo=$(CDPATH= cd -- "$(dirname -- "$0")/../.." && pwd)
evidence=${1:-"$repo/target/python-stripped-host-validation"}
build=${2:-"$repo/target/python-stripped-host-validation-build"}
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
python3 fixtures/python-bootstrap/freeze.py "target/pbs-inspection/$full" "target/pbs-inspection/$original" \
    "$build/producer" "$build/include/python3.13" /build-target/freeze-bundle.json \
    --provenance /evidence/freeze-provenance.json --provision-only > "$evidence/provision.stdout.txt" 2> "$evidence/provision.stderr.txt"
test ! -s "$evidence/provision.stderr.txt"
cargo vendor --locked --offline target/python-bootstrap-vendor > "$evidence/vendor-config.toml" 2> "$evidence/vendor.stderr.txt"
git rev-parse HEAD > "$evidence/source-revision.txt"
git branch --show-current > "$evidence/source-branch.txt"
git status --porcelain > "$evidence/source-status.txt"
git diff --binary > "$evidence/source-diff.patch"
cp fixtures/python-stripped-host/run-linux.sh "$evidence/commands.sh"
podman image inspect "$image" > "$evidence/image-inspect.json"
volume="glue-python-stripped-host-$$"
podman volume create "$volume" > "$evidence/volume-name.txt"
trap 'podman volume rm -f "$volume" > "$evidence/volume-removal.stdout.txt" 2> "$evidence/volume-removal.stderr.txt"' 0
podman run --rm --network none --read-only --tmpfs /tmp:rw,size=256m \
    --env "GLUE_STRIPPED_DEVELOPMENT=$development" \
    --mount "type=bind,source=$repo,destination=/workspace,ro" --mount "type=volume,source=$volume,destination=/build-target" \
    --mount "type=bind,source=$build,destination=/host-build" --mount "type=bind,source=$evidence,destination=/evidence" \
    --workdir /workspace "$image" sh /workspace/fixtures/python-stripped-host/run-linux.sh --build
chmod 0777 "$evidence"
podman run --rm --network none --read-only --read-only-tmpfs=false --tmpfs /tmp:rw,size=1m --tmpfs /home:ro,mode=000,size=1m \
    --tmpfs /unavailable:ro,mode=000,size=1m \
    --mount "type=volume,source=$volume,destination=/build-target,ro" --mount "type=bind,source=$evidence,destination=/evidence" \
    --workdir /build-target/runtime-empty "$image" sh -c \
    'chmod 000 /tmp; exec setpriv --reuid=65534 --regid=65534 --clear-groups --no-new-privs sh /build-target/runtime-commands.sh --run'
if test "$development" = false; then
    python3 scripts/check-linux-python-stripped-host-trace.py --emit-metadata "$build/relocated Python stripped host" "$evidence/archive-metadata.json"
    for mode in $modes; do
        python3 scripts/check-linux-python-stripped-host-trace.py "$evidence/$mode.trace.txt" --mode "$mode" \
            --stdout-file "$evidence/$mode.stdout.txt" --stderr-file "$evidence/$mode.stderr.txt" \
            --metadata-file "$evidence/archive-metadata.json" --archive-file "$build/relocated Python stripped host/$mode.glue" \
            > "$evidence/$mode.trace-check.txt"
    done
    python3 -B scripts/test_linux_python_stripped_host_trace.py \
        --audit-capture "$evidence" "$evidence/runtime-process-hostile-controls.json" \
        --metadata-file "$evidence/archive-metadata.json" > "$evidence/runtime-process-hostile-controls.txt"
fi
printf 'Python stripped-host evidence: %s\n' "$evidence"
