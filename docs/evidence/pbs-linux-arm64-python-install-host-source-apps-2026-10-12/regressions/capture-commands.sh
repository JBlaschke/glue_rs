#!/bin/sh
# Historical harnesses and checkers stay unchanged. Run serially after the
# new host capture, because these harnesses share python-bootstrap-vendor.
# Usage: sh /private/tmp/glue-python-install-host-source-app-regressions.sh CLEAN_COMMIT
set -eu
export PATH=/Users/johannes.blaschke/.rustup/toolchains/1.88.0-aarch64-apple-darwin/bin:$PATH
installhost_repo=/Users/johannes.blaschke/Developer/glue_rs
installhost_expected=${1:?supply the clean implementation commit}
installhost_python_tests=${2:-116}
installhost_logs="$installhost_repo/target/python-install-host-source-apps-regression-orchestration"
cd "$installhost_repo"
test "$(git rev-parse HEAD)" = "$installhost_expected"
test -z "$(git status --porcelain)"
installhost_branch=$(git branch --show-current)
test -n "$installhost_branch"
test ! -e "$installhost_logs"
for installhost_group in host-source source runner native host-import bundled-import frozen host-startup; do
    test ! -e "target/python-install-host-source-apps-$installhost_group-regression-capture"
    test ! -e "target/python-install-host-source-apps-$installhost_group-regression-build"
done
mkdir -p "$installhost_logs"
cp "$0" "$installhost_logs/commands.sh"
printf '%s\n' "$installhost_python_tests" > "$installhost_logs/expected-python-tests.txt"
git rev-parse HEAD > "$installhost_logs/source-revision.txt"
git branch --show-current > "$installhost_logs/source-branch.txt"
git status --porcelain > "$installhost_logs/source-status.txt"
git diff --binary > "$installhost_logs/source-diff.patch"
uname -srvm > "$installhost_logs/environment.txt"
rustc --version >> "$installhost_logs/environment.txt"
cargo --version >> "$installhost_logs/environment.txt"
python3 --version >> "$installhost_logs/environment.txt"
df -h "$installhost_repo" > "$installhost_logs/space-before.txt"

installhost_capture() {
    installhost_group=$1
    installhost_fixture=$2
    test "$(git rev-parse HEAD)" = "$installhost_expected"
    test -z "$(git status --porcelain)"
    test "$(git branch --show-current)" = "$installhost_branch"
    git status --porcelain > "$installhost_logs/$installhost_group.source-status-before.txt"
    git diff --binary > "$installhost_logs/$installhost_group.source-diff-before.patch"
    git rev-parse HEAD > "$installhost_logs/$installhost_group.source-revision-before.txt"
    git branch --show-current > "$installhost_logs/$installhost_group.source-branch-before.txt"
    date -u '+%Y-%m-%dT%H:%M:%SZ' > "$installhost_logs/$installhost_group.started.txt"
    set +e
    sh "fixtures/$installhost_fixture/run-linux.sh" \
        "target/python-install-host-source-apps-$installhost_group-regression-capture" \
        "target/python-install-host-source-apps-$installhost_group-regression-build" \
        > "$installhost_logs/$installhost_group.console.txt" 2>&1
    installhost_result=$?
    set -e
    printf '%s\n' "$installhost_result" > "$installhost_logs/$installhost_group.harness-exit-status.txt"
    test "$(git rev-parse HEAD)" = "$installhost_expected"
    test "$(git branch --show-current)" = "$installhost_branch"
    git branch --show-current > "$installhost_logs/$installhost_group.source-branch-after.txt"
    git rev-parse HEAD > "$installhost_logs/$installhost_group.source-revision-after.txt"
    git diff --binary > "$installhost_logs/$installhost_group.source-diff-after.patch"
    git status --porcelain > "$installhost_logs/$installhost_group.source-status-after.txt"
    test ! -s "$installhost_logs/$installhost_group.source-status-after.txt"
    date -u '+%Y-%m-%dT%H:%M:%SZ' > "$installhost_logs/$installhost_group.finished.txt"
    df -h "$installhost_repo" > "$installhost_logs/$installhost_group.space-after.txt"
    test "$installhost_result" -eq 0
}
installhost_capture host-source python-host-source-apps
installhost_capture source python-source-apps
installhost_capture runner python-runner
installhost_capture native python-extensions
installhost_capture host-import python-host-imports
installhost_capture bundled-import python-imports
installhost_capture frozen python-bootstrap
installhost_capture host-startup python-host

python3 -I -S -B - "$installhost_logs" <<'PY_SUMMARY'
import hashlib,json,re,sys
from pathlib import Path
logs=Path(sys.argv[1]); root=logs.parents[1]
groups={'host-source':13,'source':6,'runner':9,'native':11,'host-import':7,'bundled-import':3,'frozen':4,'host-startup':8}
records={}
expected_tests=int((logs/'expected-python-tests.txt').read_text())
for group,count in groups.items():
    capture=root/'target'/('python-install-host-source-apps-'+group+'-regression-capture')
    build=root/'target'/('python-install-host-source-apps-'+group+'-regression-build')
    traces=sorted(capture.glob('*.trace.txt'))
    assert len(traces)==count,('unexpected trace inventory',group,len(traces),count)
    for timing in ('before','after'):
        assert (logs/(group+'.source-revision-'+timing+'.txt')).read_text().strip()==(logs/'source-revision.txt').read_text().strip()
        assert (logs/(group+'.source-branch-'+timing+'.txt')).read_text().strip()==(logs/'source-branch.txt').read_text().strip()
        assert (logs/(group+'.source-status-'+timing+'.txt')).read_bytes()==b''
        assert (logs/(group+'.source-diff-'+timing+'.patch')).read_bytes()==b''
    record={'capture':str(capture.relative_to(root)),'build':str(build.relative_to(root)),
            'trace_count':count,'harness_status':int((logs/(group+'.harness-exit-status.txt')).read_text()),
            'source_revision':(capture/'source-revision.txt').read_text().strip(),
            'source_status':(capture/'source-status.txt').read_text().strip(),
            'source_diff_bytes':(capture/'source-diff.patch').stat().st_size,
            'trace_sha256':{p.name:hashlib.sha256(p.read_bytes()).hexdigest() for p in traces}}
    assert record['harness_status']==0 and not record['source_status'] and record['source_diff_bytes']==0
    assert record['source_revision']==(logs/'source-revision.txt').read_text().strip()
    test_file={'host-source':'python-tests.txt','source':'python-tests.txt','runner':'python-tests.txt','native':'extensions-tests.txt','host-import':'host-import-tests.txt','bundled-import':'import-tests.txt','frozen':'bootstrap-tests.txt','host-startup':'host-tests.txt'}[group]
    pythonlog=(capture/test_file).read_text()
    tests=re.findall(r'test result: ok\. (\d+) passed;',pythonlog)
    assert tests,('missing optimized shared crate tests',group)
    record['optimized_python_tests']=sum(map(int,tests))
    assert record['optimized_python_tests']==expected_tests,(group,record['optimized_python_tests'],expected_tests)
    record['optimized_python_clippy']='pass'
    if (capture/'runner-tests.txt').exists():
        tests=re.findall(r'test result: ok\. (\d+) passed;',(capture/'runner-tests.txt').read_text())
        assert tests,('missing product CLI tests',group)
        record['runner_tests']=sum(map(int,tests))
        assert record['runner_tests']==14,(group,record['runner_tests'])
        record['runner_clippy']='pass'
    records[group]=record
summary={'source_commit':(logs/'source-revision.txt').read_text().strip(),
         'source_branch':(logs/'source-branch.txt').read_text().strip(),
         'source_clean_before_after':True,'trace_count':sum(groups.values()),'expected_optimized_python_tests':expected_tests,'groups':records,
         'note':'Eight fresh independent old harnesses, unchanged old policies. This orchestration receipt records source branch around captures; four old harnesses do not themselves emit branch receipts.'}
(logs/'regression-capture-summary.json').write_text(json.dumps(summary,sort_keys=True,indent=2)+'\n')
PY_SUMMARY
test "$(git rev-parse HEAD)" = "$installhost_expected"
test -z "$(git status --porcelain)"
test "$(git branch --show-current)" = "$installhost_branch"
printf 'All 61 fresh historical Python capture cells passed: %s\n' "$installhost_logs"
