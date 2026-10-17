#!/usr/bin/env python3
"""Pure host preparation controls. Generated privileged scripts are syntax-only."""
import copy
import hashlib
import importlib.util
from pathlib import Path
import stat
import subprocess
import sys
import tempfile
import unittest
from unittest import mock

HERE = Path(__file__).resolve().parent
spec = importlib.util.spec_from_file_location('trace_vm_prepare', HERE/'prepare.py')
p = importlib.util.module_from_spec(spec)
spec.loader.exec_module(p)


def synthetic():
    # Invented device/FSID/proof strings: no registered or executable evidence.
    components = []
    for i,name in enumerate(('/', 'System', 'Volumes', 'Data', 'Library')):
        data = i >= 3
        components.append(dict(name=name,device=20 if data else 10,inode=100+i,uid=0,gid=0,
            mode=stat.S_IFDIR|0o755,fsid=[-3,4] if data else [1,2],mount_flags=0,
            mount_policy=1 if data else 3,mount_owner=0,descriptor_flags=1,status_flags=0,
            mountpoint='/System/Volumes/Data' if data else '/',filesystem='apfs',
            filesec_population=7,acl_present=0))
    observed = dict(schema='glue-bootstrap-deployment-observation-v1',model='VirtualMac2,1',
        kernel_release='26.6.0',observed_unix_seconds=1,observed_nanoseconds=123,
        ids=[501,501,20,20],groups=[20,0,80],tc_compatible=True,components=components,
        settings_changed=False,executable_admission=False,full_acceptance=False)
    entry = {k:'d'*64 for k in ('manifest_sha256','review_manifest_sha256',
        'inspector_manifest_sha256','wrapper_sha256','binary_sha256')}
    entry.update(inspector_source_commit='e'*40,guest_output_name='glue-bootstrap-deployment-v1-TEST0001',
        kernel_release='26.6.0',os_version='27.0',os_build='26A1')
    result = dict(schema='glue-owned-trace-kit-result-v1',status='built-reproducibly',
        build_id='a'*64,catalog_sha256='b'*64,
        artifacts={n:{'sha256':str(i+1)*64,'size':1234+i} for i,n in enumerate(p.PROGRAMS)},
        new_binaries_executed=False,installed=False,kernel_exec_proof=False,full_acceptance=False)
    return result,observed,entry


def plan():
    return p.make_plan(*synthetic(),'0123456789abcdef')


class PrepareControls(unittest.TestCase):
    def test_unconfigured_before_helpers_or_supplied_io(self):
        with mock.patch.object(p,'primitives',side_effect=AssertionError('helper opened')):
            with self.assertRaisesRegex(ValueError,'not configured'):
                p.prepare(Path('/not/opened'),Path('/not/created'))
            with self.assertRaisesRegex(ValueError,'not configured'):
                p.load_kit(Path('/not/opened'))

    def test_flags_alone_cannot_enable_renderer(self):
        x=plan()
        for key,value in [('APPROVED',{}),('EXECUTION_ENABLED',True),('SIM_POLICY',{})]:
            with self.subTest(key=key), mock.patch.object(p,key,value):
                with self.assertRaises(ValueError): p.render(x)

    def test_closed_cli_and_early_no_output(self):
        with tempfile.TemporaryDirectory(prefix='glue-trace-vm-cli-') as d:
            output=Path(d)/'must-not-exist'
            base=[sys.executable,'-B',str(HERE/'prepare.py'),'--kit',str(Path(d)/'absent-kit'),'--output',str(output)]
            r=subprocess.run(base,capture_output=True,check=False)
            self.assertEqual(r.returncode,1); self.assertIn(b'not configured',r.stderr)
            self.assertEqual(r.stdout,b''); self.assertFalse(output.exists())
            for flag in ('--enable','--profile','--proof','--hash','--target','--pid','--provider'):
                with self.subTest(flag=flag):
                    r=subprocess.run(base+[flag,'override'],capture_output=True,check=False)
                    self.assertEqual(r.returncode,2); self.assertFalse(output.exists())

    def test_exact_reviewed_helpers(self):
        self.assertEqual(hashlib.sha256(p.CORE.read_bytes()).hexdigest(),p.CORE_SHA)
        self.assertEqual(hashlib.sha256(p.WRAPPER.read_bytes()).hexdigest(),p.WRAPPER_SHA)
        with mock.patch.object(p,'CORE_SHA','0'*64):
            with self.assertRaisesRegex(ValueError,'helper source differs'): p.primitives()

    def test_distinct_plan_and_two_trace_bounds(self):
        x=plan(); core,wrapper=p.primitives()
        self.assertEqual(x['schema'],'glue-bootstrap-trace-vm-plan-v1')
        self.assertIsNone(x['approval']); self.assertIs(x['execution_enabled'],False)
        self.assertIsNone(x['sim_policy']); self.assertFalse(x['full_acceptance'])
        self.assertEqual(set(x['artifacts']),set(p.PROGRAMS))
        self.assertEqual(x['budgets'],{'attempt_ms':10000,'cleanup_ms':2000})
        self.assertIn('bootstrap-trace-vm-0123456789abcdef',x['paths']['guest_packet'])
        events=[(n,c) for n,c in x['evidence_limits'].items() if n.endswith('/events.jsonl')]
        self.assertEqual(events,[('cases/positive/events.jsonl',134217728),('cases/simulated/events.jsonl',134217728)])
        self.assertEqual(core.MAX_FILE,8*1024*1024); self.assertEqual(core.MAX_TOTAL,64*1024*1024)
        self.assertEqual(x['evidence_files'],sorted(x['evidence_limits']))
        self.assertEqual(x['event_line_limit'],8192); self.assertEqual(x['event_count_limit'],1000000)
        for c in ('denied','trailing'):
            self.assertFalse(any(n.startswith('cases/'+c+'/') and n.endswith(tuple(p.TRACE_ROLES)) for n in x['evidence_files']))

    def test_reject_unreviewed_identity_and_plan(self):
        result,observed,entry=synthetic()
        for bad in ('','1234','G'*16,'0'*17):
            with self.subTest(nonce=bad),self.assertRaises(ValueError): p.make_plan(result,observed,entry,bad)
        x=plan()
        mutations=[lambda v:v['paths'].update(root_stage='/tmp/override'),
            lambda v:v['outputs'].update(positive='/tmp/override'),
            lambda v:v['evidence_limits'].update({'cases/positive/events.jsonl':2**32}),
            lambda v:v.update(full_acceptance=0),lambda v:v.update(execution_enabled=0),
            lambda v:v.update(extra=True),lambda v:v['budgets'].update(attempt_ms=1)]
        for change in mutations:
            bad=copy.deepcopy(x); change(bad)
            with self.subTest(plan=bad),self.assertRaises(ValueError): p.render(bad)

    def test_reject_legacy_kit_schema_and_extra_artifact(self):
        for mode in ('legacy','extra','scope','boolsize'):
            r,o,e=synthetic()
            if mode=='legacy': r['schema']='glue-bootstrap-kit-result-v1'
            elif mode=='extra': r['artifacts']['bootstrap-runner']=r['artifacts']['context-probe']
            elif mode=='scope': r['kernel_exec_proof']=True
            else: r['artifacts']['context-probe']['size']=True
            with self.subTest(mode=mode),self.assertRaises(ValueError): p.make_plan(r,o,e,'0123456789abcdef')

    def test_render_dag_and_syntax_only(self):
        rendered=p.render(plan())
        self.assertEqual(set(rendered),{'root-stage.sh','outer.sh','launch.sh'})
        root=rendered['root-stage.sh']; outer=rendered['outer.sh']; launch=rendered['launch.sh']
        self.assertIn(hashlib.sha256(root).hexdigest().encode(),outer)
        self.assertIn(str(len(root)).encode(),outer)
        self.assertIn(hashlib.sha256(outer).hexdigest().encode(),launch)
        self.assertIn(str(len(outer)).encode(),launch)
        with tempfile.TemporaryDirectory(prefix='glue-trace-vm-sh-n-') as d:
            for name,data in rendered.items():
                self.assertNotIn(b'@@',data)
                path=Path(d)/name; path.write_bytes(data)
                r=subprocess.run(['/bin/sh','-n',str(path)],capture_output=True,check=False)
                self.assertEqual(r.returncode,0,(name,r.stderr))
                # No invocation of a generated script, command body or phase.

    def test_disabled_guard_precedes_guest_operations(self):
        for name,raw in p.render(plan()).items():
            s=raw.decode(); guard=s.index('[ 0 = 1 ]')
            for marker in ('/usr/bin/id','/bin/mkdir','/usr/bin/shasum'):
                self.assertLess(guard,s.index(marker),(name,marker))

    def test_preflight_before_auth_and_disabled_sip(self):
        s=p.render(plan())['outer.sh'].decode()
        auth=s.index('/usr/bin/sudo -v')
        self.assertLess(s.index('current_deployment_matches || exit 2'),auth)
        self.assertLess(s.index('plutil_capabilities || exit 2'),auth)
        self.assertLess(s.index('System Integrity Protection status: disabled.'),auth)
        self.assertIn('26.6.0',s); self.assertIn("27.0",s)
        self.assertIn(p.INSPECTOR_SHA,s); self.assertIn('components.4.fsid.1',s)
        self.assertIn('ids.3',s); self.assertIn('groups.2',s)

    def test_full_modes_fresh_paths_and_fixed_environment(self):
        scripts=p.render(plan())
        root=scripts['root-stage.sh'].decode(); outer=scripts['outer.sh'].decode()
        for mode in ('0:40755','0:40700','0:41777','0:100600:1','0:100555:1'):
            self.assertIn(mode,root)
        self.assertIn('0:100500:1',outer)
        self.assertNotIn('%Lp',root+outer)
        self.assertIn('[ ! -e "$PREFIX" ] && [ ! -L "$PREFIX" ]',root)
        self.assertIn('codesign --verify --strict',root)
        self.assertIn('/usr/bin/env -i PATH=/usr/bin:/bin:/usr/sbin:/sbin LC_ALL=C TZ=UTC',root)
        for forbidden in ('chmod -R','chown','chmod 0755 "$PREFIX/"','eval ','exec "$@"'):
            self.assertNotIn(forbidden,root)

    def test_gate_before_raw_roster_restore_and_export(self):
        s=p.render(plan())['root-stage.sh'].decode()
        run=s[s.index('run_case()'):s.index('export_file()')]
        self.assertLess(run.index('metadata_gate || return 2'),run.index('output_roster || return 2'))
        self.assertLess(run.index('output_roster || return 2'),run.index('/bin/chmod 0755 "$BUILD"'))
        export=s[s.index('export_file()'):]
        gate=export.index('metadata_gate || return 2')
        self.assertLess(gate,export.index('bounded "$source"'))
        self.assertLess(gate,export.index('digest "$source"'))
        self.assertLess(gate,export.index('/usr/bin/head -c "$cap"'))
        self.assertIn('[ ! -e "$OUTPUT/result.pending" ]',s)
        self.assertIn('SIM uncalibrated',s)
        self.assertIn('[ "$native" = 2 ] && [ ! -e "$OUTPUT" ]',run)
        self.assertIn('/usr/bin/cmp -s "$STAGE/trailing.prefix"',run)

    def test_complete_before_final_inventory_and_fixed_streaming_roster(self):
        s=p.render(plan())['outer.sh'].decode()
        complete=s.index("printf 'complete\\t0\\n'")
        self.assertLess(complete,s.index('/bin/cat > "$WORK/evidence-limits.tsv"'))
        self.assertLess(complete,s.index('/bin/mkdir -m 0700 "$EXPORT"'))
        self.assertIn('[ "$rc" = 0 ] || exit 1',s)
        self.assertIn('134217728\tcases/positive/events.jsonl',s)
        self.assertIn('134217728\tcases/simulated/events.jsonl',s)
        self.assertIn('[ "$total" -le 283115520 ]',s)
        self.assertNotIn('find ',s); self.assertNotIn('cp -R',s)

    def test_read_only_match_rejects_expected_bytes_with_failed_operation(self):
        # Extracted read-only helper only, never any generated phase/template.
        # Covers identities, stat/signature SHA and multiline roster captures.
        with tempfile.TemporaryDirectory(prefix='glue-trace-match-model-') as d:
            stub=Path(d)/'readonly-stub.sh'
            for expected in ('0','0:100500:1','0:40755','Darwin 26.6.0 arm64',
                    'System Integrity Protection status: disabled.','a'*64+'  /fixed/path',
                    'request.bin\nresult.json\ntrace.json'):
                for status in (0,1,2,120):
                    stub.write_text('printf \'%s\\n\' "$1"\nexit '+str(status)+'\n')
                    code=p.READ_MATCH+'\nread_match "$1" /bin/sh "$2" "$1"\n'
                    r=subprocess.run(['/bin/sh','-c',code,'match-model',expected,str(stub)],capture_output=True,check=False)
                    self.assertEqual(r.returncode,0 if status==0 else 2,(expected,status,r.stderr))
                    self.assertEqual(r.stdout,b'')
            stub.write_text("printf 'wrong\\n'\nexit 0\n")
            r=subprocess.run(['/bin/sh','-c',p.READ_MATCH+'\nread_match expected /bin/sh "$1"','match-model',str(stub)],capture_output=True,check=False)
            self.assertNotEqual(r.returncode,0)

    def test_read_only_last_byte_rejects_failed_od_even_after_zero(self):
        with tempfile.TemporaryDirectory(prefix='glue-trace-byte-model-') as d:
            stub=Path(d)/'readonly-od-stub.sh'
            # Stub is an injected synthetic read operation, no generated phase.
            for text,status,accepted in [('   0',0,True),('   1',0,False),
                    ('0 0',0,False),('',0,False),('   0',1,False),('   0',120,False)]:
                stub.write_text('#!/bin/sh\nprintf \'%s\\n\' '+repr(text)+'\nexit '+str(status)+'\n')
                stub.chmod(0o700)
                code=p.LAST_BYTE_ZERO+'\nlast_byte_zero unused 208 "$1"\n'
                r=subprocess.run(['/bin/sh','-c',code,'byte-model',str(stub)],capture_output=True,check=False)
                self.assertEqual(r.returncode==0,accepted,(text,status,r.stderr))
            request=Path(d)/'synthetic-request'; request.write_bytes(b'abc\0')
            r=subprocess.run(['/bin/sh','-c',p.LAST_BYTE_ZERO+'\nlast_byte_zero "$1" 3 /usr/bin/od','byte-model',str(request)],capture_output=True,check=False)
            self.assertEqual(r.returncode,0,r.stderr)

    def test_no_status_losing_comparison_or_raw_pipeline(self):
        rendered=p.render(plan())
        for name,raw in rendered.items():
            text=raw.decode()
            self.assertNotIn('[ "$(/',text,name)
            self.assertNotIn('[ "$(digest',text,name)
            self.assertNotIn('| /usr/bin/',text,name)
        self.assertIn('read_match "$expected" /bin/ls -A1',rendered['root-stage.sh'].decode())
        self.assertIn('last_byte_zero "$STAGE/$C.request.bin" "$count" /usr/bin/od',rendered['root-stage.sh'].decode())


if __name__=='__main__': unittest.main()
