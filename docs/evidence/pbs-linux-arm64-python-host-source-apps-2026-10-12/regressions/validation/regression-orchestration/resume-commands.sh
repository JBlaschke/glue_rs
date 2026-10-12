#!/bin/sh
# Resume exactly six old groups; preserve the successful source capture and
# all interrupted runner evidence. No old harness/checker changes.
# Usage: sh /private/tmp/glue-python-host-source-app-regressions-resume.sh CLEAN_COMMIT
set -eu
export PATH=/Users/johannes.blaschke/.rustup/toolchains/1.88.0-aarch64-apple-darwin/bin:$PATH
hostsource_repo=/Users/johannes.blaschke/Developer/glue_rs
hostsource_expected=${1:?supply clean implementation commit}
hostsource_logs="$hostsource_repo/target/python-host-source-apps-regression-orchestration"
cd "$hostsource_repo"
test "$(git rev-parse HEAD)" = "$hostsource_expected"
test -z "$(git status --porcelain)"
test "$(cat "$hostsource_logs/source.harness-exit-status.txt")" = 0
test "$(cat "$hostsource_logs/source-revision.txt")" = "$hostsource_expected"
test ! -e "$hostsource_logs/resume-commands.sh"
for hostsource_group in native host-import bundled-import frozen host-startup; do
    test ! -e "target/python-host-source-apps-$hostsource_group-regression-capture"
    test ! -e "target/python-host-source-apps-$hostsource_group-regression-build"
done
cp "$0" "$hostsource_logs/resume-commands.sh"
python3 -I -S -B - "$hostsource_expected" <<'PY_PRESERVE'
from pathlib import Path
import datetime,json,shutil,sys
root=Path.cwd(); logs=root/'target/python-host-source-apps-regression-orchestration'
old=logs/'interruption-01';old.mkdir()
quarantine=root/'target/python-host-source-apps-runner-regression-interrupted-01'
assert not quarantine.exists();quarantine.mkdir()
receipts=[]
for p in sorted(logs.glob('runner.*')):
    assert p.is_file()
    shutil.copyfile(p,old/p.name)
    receipts.append(p.name)
paths={}
for kind in ('capture','build'):
    p=root/'target'/('python-host-source-apps-runner-regression-'+kind)
    if p.exists():
        q=quarantine/kind;p.rename(q);paths[kind]=str(q.relative_to(root))
reason={'recorded_at':datetime.datetime.now(datetime.timezone.utc).isoformat(),
        'source_commit':sys.argv[1],'previous_orchestration_exit_status':126,
        'previous_orchestration_output':'empty; reported by the parent execution session',
        'observed_runner_console_bytes':(old/'runner.console.txt').stat().st_size,
        'reason':'Resume after orchestration exit126 without a diagnostic. Partial runner build/CLI-control artifacts were found on inspection; no runner runtime traces were captured. The cause remains unknown.',
        'orphan_check':'Task harness/build process filter and pinned-image podman ps were empty before resumption.',
        'preserved_runner_receipts':receipts,'preserved_partial_directories':paths,
        'completed_source_group':'kept unchanged; six checked clean traces',
        'resumed_groups':['runner','native','host-import','bundled-import','frozen','host-startup']}
(logs/'resumption.json').write_text(json.dumps(reason,sort_keys=True,indent=2)+'\n')
PY_PRESERVE

hostsource_capture() {
    hostsource_group=$1
    hostsource_fixture=$2
    test "$(git rev-parse HEAD)" = "$hostsource_expected"
    test -z "$(git status --porcelain)"
    git rev-parse HEAD > "$hostsource_logs/$hostsource_group.source-revision-before.txt"
    git branch --show-current > "$hostsource_logs/$hostsource_group.source-branch-before.txt"
    date -u '+%Y-%m-%dT%H:%M:%SZ' > "$hostsource_logs/$hostsource_group.started.txt"
    if sh "fixtures/$hostsource_fixture/run-linux.sh" \
        "target/python-host-source-apps-$hostsource_group-regression-capture" \
        "target/python-host-source-apps-$hostsource_group-regression-build" \
        > "$hostsource_logs/$hostsource_group.console.txt" 2>&1; then
        hostsource_status=0
    else
        hostsource_status=$?
    fi
    printf '%s\n' "$hostsource_status" > "$hostsource_logs/$hostsource_group.harness-exit-status.txt"
    test "$hostsource_status" -eq 0
    test "$(git rev-parse HEAD)" = "$hostsource_expected"
    git status --porcelain > "$hostsource_logs/$hostsource_group.source-status-after.txt"
    test ! -s "$hostsource_logs/$hostsource_group.source-status-after.txt"
    date -u '+%Y-%m-%dT%H:%M:%SZ' > "$hostsource_logs/$hostsource_group.finished.txt"
    df -h "$hostsource_repo" > "$hostsource_logs/$hostsource_group.space-after.txt"
}
hostsource_capture runner python-runner
hostsource_capture native python-extensions
hostsource_capture host-import python-host-imports
hostsource_capture bundled-import python-imports
hostsource_capture frozen python-bootstrap
hostsource_capture host-startup python-host

python3 -I -S -B - "$hostsource_logs" <<'PY_SUMMARY'
import hashlib,json,re,sys
from pathlib import Path
logs=Path(sys.argv[1]); root=logs.parents[1]
groups={'source':6,'runner':9,'native':11,'host-import':7,'bundled-import':3,'frozen':4,'host-startup':8}
records={}
for group,count in groups.items():
    capture=root/'target'/('python-host-source-apps-'+group+'-regression-capture')
    build=root/'target'/('python-host-source-apps-'+group+'-regression-build')
    traces=sorted(capture.glob('*.trace.txt'))
    assert len(traces)==count,('unexpected trace inventory',group,len(traces),count)
    record={'capture':str(capture.relative_to(root)),'build':str(build.relative_to(root)),
            'trace_count':count,'harness_status':int((logs/(group+'.harness-exit-status.txt')).read_text()),
            'source_revision':(capture/'source-revision.txt').read_text().strip(),
            'source_status':(capture/'source-status.txt').read_text().strip(),
            'source_diff_bytes':(capture/'source-diff.patch').stat().st_size,
            'trace_sha256':{p.name:hashlib.sha256(p.read_bytes()).hexdigest() for p in traces}}
    assert record['harness_status']==0 and not record['source_status'] and record['source_diff_bytes']==0
    assert record['source_revision']==(logs/'source-revision.txt').read_text().strip()
    test_file={'source':'python-tests.txt','runner':'python-tests.txt','native':'extensions-tests.txt','host-import':'host-import-tests.txt','bundled-import':'import-tests.txt','frozen':'bootstrap-tests.txt','host-startup':'host-tests.txt'}[group]
    pythonlog=(capture/test_file).read_text()
    tests=re.findall(r'test result: ok\. (\d+) passed;',pythonlog)
    assert tests,('missing optimized shared crate tests',group)
    record['optimized_python_tests']=sum(map(int,tests))
    record['optimized_python_clippy']='pass'
    if (capture/'runner-tests.txt').exists():
        tests=re.findall(r'test result: ok\. (\d+) passed;',(capture/'runner-tests.txt').read_text())
        assert tests,('missing product CLI tests',group)
        record['runner_tests']=sum(map(int,tests))
        record['runner_clippy']='pass'
    records[group]=record
summary={'source_commit':(logs/'source-revision.txt').read_text().strip(),
         'source_branch':(logs/'source-branch.txt').read_text().strip(),
         'source_clean_before_after':True,'trace_count':sum(groups.values()),'groups':records,
         'note':'Seven fresh independent old harnesses, unchanged old policies. This orchestration receipt records source branch around captures; four old harnesses do not themselves emit branch receipts.'}
(logs/'regression-capture-summary.json').write_text(json.dumps(summary,sort_keys=True,indent=2)+'\n')
PY_SUMMARY
test "$(git rev-parse HEAD)" = "$hostsource_expected"
test -z "$(git status --porcelain)"
printf 'All 48 fresh historical Python capture cells passed: %s\n' "$hostsource_logs"
