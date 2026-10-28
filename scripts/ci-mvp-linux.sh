#!/usr/bin/env bash
# Explicit CI preparation followed by shared native, offline product recipes.
# No package-manager or compiler is invoked by glue build or the packaged apps.
set -Eeuo pipefail
umask 022

repo_dir=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
cd "$repo_dir"
# Refuse foreign/unknown hosts before CI-root creation, downloads or subprocesses
# involved in preparation. This command reads only source and native host facts.
profile_fields=$(/usr/bin/python3 fixtures/mvp/linux_acceptance.py profile \
    --expected-target "${GLUE_MVP_CI_EXPECT_TARGET:-}")
IFS=$'\t' read -r architecture target node_arch wheel_target node_config native_search conda_lock pbs312_sha256 pbs313_sha256 benchmark_python_environment <<< "$profile_fields"
ci_root=${GLUE_MVP_CI_ROOT:?set a new absolute directory for this CI run}
case "$ci_root" in /*) ;; *) echo 'GLUE_MVP_CI_ROOT must be absolute' >&2; exit 2 ;; esac
test ! -e "$ci_root"
mkdir -p "$ci_root/evidence/provisioning" "$ci_root/evidence/proposed-budgets" "$ci_root/downloads" "$ci_root/runtimes" "$ci_root/inputs" "$ci_root/cases" "$ci_root/benchmarks"
evidence="$ci_root/evidence"
budget_mode=${GLUE_MVP_BUDGET_MODE:-enforce}
case "$budget_mode" in observe|enforce) ;; *) echo 'GLUE_MVP_BUDGET_MODE must be observe or enforce' >&2; exit 2 ;; esac
exec > >(tee "$evidence/harness.log") 2>&1

finish() {
    local result=$?
    local summary_result=0
    trap - EXIT
    if /usr/bin/python3 fixtures/mvp/linux_acceptance.py summary \
        --architecture "$architecture" --evidence "$evidence" --result "$result" --budget-mode "$budget_mode"
    then :; else summary_result=1; fi
    # Tracer files can belong to root/nobody. Only the evidence tree is exposed
    # to upload-artifact; runtime trees, wheels and compiled payloads stay local.
    sudo -n chown -R "$(id -u):$(id -g)" "$evidence" || true
    if test "$result" -eq 0 && test "$summary_result" -ne 0; then result=1; fi
    exit "$result"
}
trap finish EXIT
printf '%s\n' "Proposed first observations only. Review these $architecture reports before accepting limits into Git." \
    > "$evidence/proposed-budgets/README.txt"

# Observation mode is an explicit first-run exception. Normal CI requires all
# reviewed files before provisioning; a missing budget cannot silently refreeze.
/usr/bin/python3 - "$repo_dir" "$evidence" "$budget_mode" "$architecture" <<'PY'
import hashlib, json, shutil, sys
from pathlib import Path
repository, evidence, mode = Path(sys.argv[1]), Path(sys.argv[2]), sys.argv[3]
sys.path.insert(0, str(repository / 'fixtures/mvp'))
import linux_acceptance
profile = linux_acceptance.profile_for(sys.argv[4])
selected_target = profile.target
if mode == 'enforce':
    index = repository / 'fixtures/mvp/budgets/index.json'
    items = linux_acceptance.reviewed_budget_paths(profile, json.loads(index.read_text()))
    destination = evidence / 'accepted-budgets'
    destination.mkdir()
    shutil.copy2(index, destination / 'index.json')
    identities = {}
    for case, relative in items:
        path = index.parent / relative
        budget = json.loads(path.read_text())
        if (budget.get('completeness') != 'passed' or budget.get('target') != selected_target
                or budget.get('case') != case):
            raise SystemExit('reviewed budget is incomplete')
        shutil.copy2(path, destination / path.name)
        identities[path.name] = hashlib.sha256(path.read_bytes()).hexdigest()
    (destination / 'identities.json').write_text(json.dumps(identities, indent=2) + '\n')
(evidence / 'budget-mode.json').write_text(json.dumps({'mode': mode, 'reviewed_limits_required': mode == 'enforce'}, indent=2) + '\n')
PY

toolchain_dir=$(dirname -- "$(rustup which --toolchain 1.88.0 cargo)")
export PATH="$toolchain_dir:$PATH"
export CARGO_TARGET_DIR="$ci_root/target"
test "$(rustc --version | cut -d ' ' -f 2)" = 1.88.0
for prerequisite in cc curl patchelf strace sudo unshare sha256sum tar; do command -v "$prerequisite"; done
sudo -n unshare --net /usr/bin/true
{
    git rev-parse HEAD
    uname -a
    rustc --version
    cargo --version
    cc --version
    patchelf --version
    strace --version
} > "$evidence/toolchain.txt"
git status --short > "$evidence/source-status.txt"
/usr/bin/python3 fixtures/mvp/linux_acceptance.py plan --architecture "$architecture" > "$evidence/acceptance-plan.json"

# A syscall tracer cannot observe io_uring SQE writes. Select the ordinary
# syscall fallback explicitly for the complete test process tree, including
# stock references and all benchmark ranks. This is a CI host policy only.
trace_environment_dir="$evidence/provisioning/trace-environment"
mkdir "$trace_environment_dir"
cp fixtures/mvp/trace_environment.c "$trace_environment_dir/trace_environment.c"
trace_environment="$trace_environment_dir/glue-trace-environment"
cc -O2 -std=c11 -Wall -Wextra -Werror "$trace_environment_dir/trace_environment.c" -o "$trace_environment"
printf '%s\n' 'cc -O2 -std=c11 -Wall -Wextra -Werror trace_environment.c -o glue-trace-environment' \
    > "$trace_environment_dir/build-command.txt"
sudo -n "$trace_environment" --probe > "$trace_environment_dir/proof.json"
/usr/bin/python3 fixtures/mvp/trace_environment.py "$trace_environment_dir" --architecture "$architecture" --record
(cd "$trace_environment_dir" && sha256sum trace_environment.c glue-trace-environment proof.json manifest.json) \
    > "$trace_environment_dir/SHA256SUMS"

download() {
    curl --fail --location --retry 3 --proto '=https' --tlsv1.2 --output "$2" "$1"
}

for version in 24.22.0 26.10.0; do
    archive="node-v$version-linux-$node_arch.tar.xz"
    base="https://nodejs.org/dist/v$version"
    download "$base/SHASUMS256.txt" "$evidence/provisioning/node-$version-SHASUMS256.txt"
    download "$base/$archive" "$ci_root/downloads/$archive"
    /usr/bin/python3 - "$evidence/provisioning/node-$version-SHASUMS256.txt" "$archive" "$ci_root/downloads/$archive" "$evidence/provisioning/node-$version.json" <<'PY'
import hashlib, json, re, sys
from pathlib import Path
manifest, name, archive, output = sys.argv[1:]
matches = [line.split() for line in Path(manifest).read_text().splitlines() if line.split()[-1:] == [name]]
if len(matches) != 1 or len(matches[0]) != 2 or not re.fullmatch('[0-9a-f]{64}', matches[0][0]):
    raise SystemExit('missing/ambiguous official Node checksum')
data = Path(archive).read_bytes()
actual = hashlib.sha256(data).hexdigest()
if actual != matches[0][0]: raise SystemExit('official Node archive checksum mismatch')
Path(output).write_text(json.dumps({'filename': name, 'size': len(data), 'sha256': actual,
                                  'manifest': Path(manifest).name, 'source': 'https://nodejs.org/dist/'}, indent=2) + '\n')
PY
    tar -xJf "$ci_root/downloads/$archive" -C "$ci_root/runtimes"
done

pbs_base=https://github.com/astral-sh/python-build-standalone/releases/download/20261009
while read -r version checksum; do
    archive="cpython-$version+20261009-$target-install_only.tar.gz"
    download "$pbs_base/${archive/+/%2B}" "$ci_root/downloads/$archive"
    printf '%s  %s\n' "$checksum" "$ci_root/downloads/$archive" | sha256sum --check --strict
    printf '%s  %s\n' "$checksum" "$archive" > "$evidence/provisioning/python-$version.sha256"
    printf '%s/%s\n' "$pbs_base" "${archive/+/%2B}" > "$evidence/provisioning/python-$version.url.txt"
    raw_runtime="$ci_root/downloads/python-$version-raw"
    mkdir "$raw_runtime"
    tar -xzf "$ci_root/downloads/$archive" --strip-components=1 -C "$raw_runtime"
    # Independent fixture staging removes installation/development metadata and
    # internalizes safe absolute aliases before the harness copies the input.
    # It preserves all native image bytes; this is not a glue build operation.
    /usr/bin/python3 fixtures/mvp/python-matrix/stage-runtime.py "$raw_runtime" "$ci_root/runtimes/python-$version"
    cp "$ci_root/runtimes/python-$version-stage.json" "$evidence/provisioning/"
    rm -rf "$raw_runtime"
done <<PBS
3.12.15 $pbs312_sha256
3.13.16 $pbs313_sha256
PBS

# This independent conventional runtime avoids the selected PBS libffi static
# trampoline path bug under relocated paths containing spaces. Keep all native
# bytes unchanged and subject it to the same strict extraction oracle.
/usr/bin/python3 fixtures/mvp/python-matrix/provision-conda.py \
    --target "$target" \
    --lock "$conda_lock" \
    --work "$ci_root/downloads/python-3.14.8-conda" \
    --output "$ci_root/runtimes/python-3.14.8" \
    --evidence "$evidence/provisioning/python-3.14.8-conda"

cargo build --release --locked -p glue-runner -p glue-runtime-node > "$evidence/build-release.log" 2>&1
cargo build --release --locked -p glue-runtime-lua --no-default-features --features lua54 --bin glue-lua54 > "$evidence/build-lua54.log" 2>&1
cargo build --release --locked -p glue-runtime-lua --no-default-features --features lua55 --bin glue-lua55 > "$evidence/build-lua55.log" 2>&1
cp "$CARGO_TARGET_DIR/release/libglue_runtime_node.so" "$ci_root/inputs/archive.node"
cargo metadata --locked --format-version 1 > "$ci_root/cargo-metadata.json"
lua_source=$(/usr/bin/python3 - "$ci_root/cargo-metadata.json" <<'PY'
import json, sys
from pathlib import Path
packages = [p for p in json.loads(Path(sys.argv[1]).read_text())['packages'] if p['name'] == 'lua-src' and p['version'] == '551.0.2']
if len(packages) != 1: raise SystemExit('expected exactly the locked Lua source crate')
print(Path(packages[0]['manifest_path']).parent)
PY
)
for family in 54 55; do
    case "$family" in 54) release=5.4.9 ;; 55) release=5.5.1 ;; esac
    source_dir="$lua_source/lua-$release"
    cc -O2 -DLUA_USE_LINUX -DLUA_COMPAT_5_3 -I"$source_dir" \
        "$source_dir"/*.c fixtures/mvp/lua-projects/reference-driver.c \
        -Wl,--export-dynamic -lm -ldl -o "$ci_root/inputs/lua$family-reference"
    fixtures/mvp/lua-native/prepare.sh "$ci_root/inputs/lua$family-native" "$source_dir"
    sha256sum "$source_dir"/*.c "$source_dir"/*.h > "$evidence/provisioning/lua$family-source.sha256"
done
fixtures/mvp/node-native/prepare.sh "$ci_root/runtimes/node-v24.22.0-linux-$node_arch/include/node" "$ci_root/inputs/node-native"
sha256sum "$CARGO_TARGET_DIR/release/glue" "$CARGO_TARGET_DIR/release/glue-lua54" "$CARGO_TARGET_DIR/release/glue-lua55" "$ci_root/inputs/archive.node" > "$evidence/release-tools.sha256"
sha256sum "$ci_root/inputs/node-native"/* "$ci_root/inputs/lua54-native"/* "$ci_root/inputs/lua55-native"/* > "$evidence/provisioning/independent-native-inputs.sha256"

for tag in cp312 cp313 cp314; do
    /usr/bin/python3 fixtures/mvp/python-native/provision.py --fetch --python "$tag" --target "$wheel_target" \
        --output "$ci_root/inputs/python-$tag" numpy==2.5.4 contourpy==1.4.0 pydantic_core==2.50.1 \
        cffi==2.1.1 pycparser==3.0 typing_extensions==4.15.0 > "$evidence/provisioning/wheels-$tag.log" 2>&1
    cp "$ci_root/inputs/python-$tag/inputs.json" "$evidence/provisioning/wheels-$tag.json"
done

common_env=(
    "PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin" "HOME=/root" "LANG=C.UTF-8"
    "GLUE_MVP_GLUE=$CARGO_TARGET_DIR/release/glue" "GLUE_MVP_HELPERS=$CARGO_TARGET_DIR/release"
    "GLUE_MVP_TRACE=required" "GLUE_PATCHELF=$(command -v patchelf)"
    "GLUE_MVP_LUA54=$ci_root/inputs/lua54-reference" "GLUE_MVP_LUA55=$ci_root/inputs/lua55-reference"
    "GLUE_MVP_LUA54_NATIVE=$ci_root/inputs/lua54-native" "GLUE_MVP_LUA55_NATIVE=$ci_root/inputs/lua55-native"
    "GLUE_MVP_NODE_BRIDGE=$ci_root/inputs/archive.node" "GLUE_MVP_NODE_NATIVE=$ci_root/inputs/node-native"
    "GLUE_MVP_NODE_CONFIG=$repo_dir/$node_config"
    "GLUE_MVP_PYTHON_TOOL=/usr/bin/python3" "GLUE_MVP_PYTHON_ENV_KIND=ordinary"
    "GLUE_MVP_NATIVE_SEARCH=$native_search"
    "GLUE_MVP_PYTHON_SECONDARY=$ci_root/inputs/lua55-native/libsecondary.so"
)
overall=0
run_case() {
    local label=$1 recipe=$2
    shift 2
    local output="$ci_root/cases/$label" result=0
    echo "Running native offline acceptance: $label"
    if sudo -n env -i "${common_env[@]}" "$@" "$trace_environment" -- unshare --net /usr/bin/python3 fixtures/mvp/harness.py \
        --case "$recipe" --target "$target" --output "$output" > "$evidence/$label.log" 2>&1; then
        if ! sudo -n /usr/bin/python3 scripts/check-mvp-results.py "$output/receipt.json" >> "$evidence/$label.log" 2>&1; then result=1; fi
    else
        result=$?
    fi
    # Keep the complete checker inputs, then discard bulky test deployment and
    # quarantined source copies. This cleanup occurs after the traced app exits.
    sudo -n /usr/bin/python3 - "$output" "$evidence/cases/$label" <<'PY'
import shutil, sys
from pathlib import Path
source, destination = map(Path, sys.argv[1:])
destination.mkdir(parents=True)
if source.exists():
    for item in source.iterdir():
        if item.is_file() and item.suffix in {'.json', '.stdout', '.stderr', '.log', '.txt'}:
            shutil.copy2(item, destination / item.name)
    for directory in ['trace', 'trace-controls']:
        for path in (source / directory).rglob('syscalls.*'):
            if path.is_file() and not path.is_symlink():
                target = destination / path.relative_to(source)
                target.parent.mkdir(parents=True, exist_ok=True)
                shutil.copy2(path, target)
    shutil.rmtree(source)
PY
    if test "$result" -eq 0; then
        if ! sudo -n /usr/bin/python3 scripts/check-mvp-results.py "$evidence/cases/$label/receipt.json" >> "$evidence/$label.log" 2>&1; then result=1; fi
    fi
    printf '%s\t%s\n' "$label" "$result" >> "$evidence/case-status.tsv"
    cat "$evidence/$label.log"
    if test "$result" -ne 0; then overall=1; fi
}

for family in 54 55; do
    for corpus in project native; do run_case "lua$family-$corpus" "lua$family-$corpus"; done
done
for version in 24.22.0 26.10.0; do
    for corpus in cjs esm resources native; do
        run_case "node-$version-$corpus" "node-$corpus" "GLUE_MVP_NODE_RUNTIME=$ci_root/runtimes/node-v$version-linux-$node_arch"
    done
done
while read -r version relative tag; do
    for corpus in source module console native; do
        run_case "python-$version-$corpus" "python-$corpus-normalized" \
            "GLUE_MVP_PYTHON_ROOT=$ci_root/runtimes/python-$version" "GLUE_MVP_PYTHON_RELATIVE=$relative" \
            "GLUE_MVP_PYTHON_SITE=$ci_root/inputs/python-$tag/site"
    done
done <<'PYTHON'
3.12.15 bin/python3.12 cp312
3.13.16 bin/python3.13 cp313
3.14.8 bin/python3.14 cp314
PYTHON

check_benchmark() {
    sudo -n /usr/bin/python3 - "$repo_dir" "$1" "$2" "$3" "$budget_mode" "$evidence" "$target" <<'PY'
import json, sys
from pathlib import Path
repository, output, budget_path = map(Path, sys.argv[1:4])
case = sys.argv[4]
budget_mode, evidence = sys.argv[5], Path(sys.argv[6])
selected_target = sys.argv[7]
sys.path.insert(0, str(repository / 'fixtures/mvp'))
import benchmark
import harness
report = json.loads((output / 'benchmark.json').read_text())
budget = json.loads(budget_path.read_text())
errors = benchmark.check_budget(report, budget)
if report['case'] != case or report['target'] != selected_target:
    errors.append('unexpected benchmark case/target')
if report['source_entries'] != 10000:
    errors.append('expected 10000 additional source entries')
if budget != benchmark.proposed_budget(report):
    errors.append('generated budget differs from measured first observations')
if budget_mode == 'enforce':
    accepted = json.loads((evidence / 'accepted-budgets' / (case + '.json')).read_text())
    errors.extend('reviewed budget: ' + error for error in benchmark.check_budget(report, accepted))
for key in ['max_elapsed_seconds', 'max_peak_rss_bytes', 'max_open_calls', 'max_stat_calls',
            'max_read_calls', 'max_seek_calls', 'max_read_bytes', 'max_process_fds']:
    if budget['limits'].get(key) is None:
        errors.append('required metric is unavailable: ' + key)
variants = report['variants']
if len(variants) != 3 or {v['variant'] for v in variants} != {'empty-runtime', 'baseline', 'scaled'}:
    errors.append('empty/baseline/scaled benchmark matrix is incomplete')
for variant in variants:
    directory = output / variant['variant']
    errors.extend(harness.check(directory / 'receipt.json'))
    measurements = variant['measurements']
    if len(measurements) != 4 or {(m['label'], m['ranks']) for m in measurements} != {('first', 1), ('first', 32), ('warm', 1), ('warm', 32)}:
        errors.append('first/warm 1/32 rank matrix is incomplete')
    for series in measurements:
        if len(series['results']) != series['ranks'] or {r['rank'] for r in series['results']} != set(range(series['ranks'])):
            errors.append('rank result identities are missing or duplicated')
        for rank in series['results']:
            prefix = directory / f"{series['label']}-{series['ranks']}" / f"rank-{rank['rank']}"
            for stream in ['stdout', 'stderr']:
                if harness.identity(prefix.with_suffix('.' + stream)) != rank[stream]:
                    errors.append('rank stream bytes differ: ' + str(prefix))
            metadata = json.loads(prefix.with_suffix('.json').read_text())
            if any(rank.get(key) != value for key, value in metadata.items()):
                errors.append('rank kernel usage metadata differs: ' + str(prefix))
if errors: raise SystemExit('; '.join(errors))
print(case + ': complete benchmark, retained traces/streams and ' + budget_mode + ' budget checks passed')
PY
}

run_benchmark() {
    local recipe=$1
    shift
    local output="$ci_root/benchmarks/$recipe" budget="$evidence/proposed-budgets/$recipe.json" result=0
    echo "Measuring native first observations: $recipe"
    if sudo -n env -i "${common_env[@]}" "$@" "$trace_environment" -- unshare --net /usr/bin/python3 scripts/benchmark-mvp.py \
        --case "$recipe" --target "$target" --source-entries 10000 --ranks 1,32 \
        --output "$output" --freeze-budget "$budget" > "$evidence/benchmark-$recipe.log" 2>&1; then
        if ! check_benchmark "$output" "$budget" "$recipe" >> "$evidence/benchmark-$recipe.log" 2>&1; then result=1; fi
    else
        result=$?
    fi
    # Retain complete reports, every rank's command streams/kernel measurements,
    # and all acceptance/control traces. Exclude generated deployments and inputs.
    sudo -n /usr/bin/python3 - "$output" "$evidence/benchmarks/$recipe" <<'PY'
import os, shutil, sys
from pathlib import Path
source, destination = map(Path, sys.argv[1:])
destination.mkdir(parents=True)
if source.exists():
    excluded = {'work', 'payload with spaces ü', 'inaccessible original inputs', 'unrelated cwd'}
    for root, directories, files in os.walk(source, followlinks=False):
        directories[:] = [name for name in directories if name not in excluded and not name.startswith('unusable-')]
        for name in files:
            path = Path(root) / name
            if path.is_symlink(): continue
            if path.suffix not in {'.json', '.stdout', '.stderr', '.log', '.txt', '.pid'} and not name.startswith('syscalls.'):
                continue
            target = destination / path.relative_to(source)
            target.parent.mkdir(parents=True, exist_ok=True)
            shutil.copy2(path, target)
    shutil.rmtree(source)
PY
    if test "$result" -eq 0; then
        if ! check_benchmark "$evidence/benchmarks/$recipe" "$budget" "$recipe" >> "$evidence/benchmark-$recipe.log" 2>&1; then result=1; fi
    fi
    printf '%s\t%s\n' "$recipe" "$result" >> "$evidence/benchmark-status.tsv"
    cat "$evidence/benchmark-$recipe.log"
    if test "$result" -ne 0; then overall=1; fi
}

for recipe in lua55-project lua55-native; do run_benchmark "$recipe"; done
run_benchmark node-cjs "GLUE_MVP_NODE_RUNTIME=$ci_root/runtimes/node-v24.22.0-linux-$node_arch"
for recipe in python-source-normalized python-native-normalized; do
    run_benchmark "$recipe" "GLUE_MVP_PYTHON_ROOT=$ci_root/runtimes/python-3.13.16" \
        "GLUE_MVP_PYTHON_RELATIVE=bin/python3.13" "GLUE_MVP_PYTHON_SITE=$ci_root/inputs/python-cp313/site" \
        "GLUE_MVP_PYTHON_ENV_KIND=$benchmark_python_environment"
done

exit "$overall"
