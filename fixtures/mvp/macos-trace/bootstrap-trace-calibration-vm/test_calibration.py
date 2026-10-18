"""Source-only complete synthetic pair controls; no generated phase executes."""
import ast
from copy import deepcopy
from dataclasses import FrozenInstanceError
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import stat
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

HERE=Path(__file__).resolve().parent
import prepare as prep
import checker as check
import fixtures as f

def encode(obj):return (json.dumps(obj,separators=(',',':'),ensure_ascii=True)+'\n').encode()
def synthetic():
    positive,denied,raw=f.pair()
    components=[]
    for i,name in enumerate(('/', 'System', 'Volumes', 'Data', 'Library')):
        components.append(dict(name=name,device=17,inode=100+i,uid=0,gid=0,mode=16877,
            fsid=[-2,3] if i<3 else [4,-5],mount_flags=0,mount_policy=3 if i<3 else 1,
            mount_owner=0,descriptor_flags=1,status_flags=0,mountpoint='/' if i<3 else '/System/Volumes/Data',filesystem='apfs',filesec_population=7,acl_present=0))
    observed=dict(schema='glue-bootstrap-deployment-observation-v1',model='VirtualMac2,1',kernel_release='25.6.0',observed_unix_seconds=1,observed_nanoseconds=2,ids=[501,501,20,20],groups=[20,0,80],tc_compatible=True,components=components,settings_changed=False,executable_admission=False,full_acceptance=False)
    entry={k:'d'*64 for k in ('manifest_sha256','review_manifest_sha256','inspector_manifest_sha256','wrapper_sha256','binary_sha256')}
    entry.update(inspector_source_commit='e'*40,guest_output_name='glue-bootstrap-deployment-v1-TEST0001',kernel_release='25.6.0',os_version='26.6.2',os_build='25G83')
    artifacts={n:dict(sha256=str(i+1)*64,size=100+i) for i,n in enumerate(prep.PROGRAMS)}
    plan=prep.plan_from_identity('b'*64,check.sha(positive['catalog']),artifacts,observed,entry,'0123456789abcdef')
    p,unused=prep.primitives();commands=prep.root_commands(plan);data={'plan.json':p.canonical(plan),'batch.tsv':b'schema\tglue-bootstrap-trace-calibration-batch-v1\npreflight\t0\ninstall\t0\npositive\t0\ndenied\t0\ncomplete\t0\n'}
    def receipt(stem,args,stdout=b'',stderr=b''):
        data.update({stem+'.argv':check.argv_bytes(args),stem+'.status':b'0\n',stem+'.stdout':stdout,stem+'.stderr':stderr})
    receipt('install',commands['install'])
    receipt('install-context',commands['export-install-context'])
    del data['install-context.stdout'];data['install-context.bin']=b'17:42\n'
    for case,payload in [('positive',positive),('denied',denied)]:
        receipt('case-'+case,commands['case-'+case])
        request='requests/'+case
        data.update({request+'.argv':check.argv_bytes(check.environment()+[plan['paths']['build_dir']+'/make-request']),request+'.status':b'0\n',request+'.stderr':b'',request+'.bin':payload['request']})
        prefix='cases/'+case+'/'
        for role,key in [('request.bin','request'),('status.bin','status'),('probe.stdout','probe_stdout'),('probe.stderr','probe_stderr'),('result.json','result'),('trace.json','sidecar')]:data[prefix+role]=payload[key]
        if case=='positive':data.update({prefix+k:v for k,v in raw.items()})
        data.update({prefix+'input.sha256':check.sha(payload['request']).encode()+b'\n',prefix+'native.status':b'0\n' if case=='positive' else b'1\n',prefix+'native.stdout':b'',prefix+'native.stderr':b'',prefix+'native.argv':check.argv_bytes(check.environment()+[plan['paths']['build_dir']+'/owned-trace-runner','--request',plan['paths']['root_stage']+'/'+case+'.request.bin','--output',plan['outputs'][case]])})
        for role in prep.case_roles(case):
            stem='exports/'+case+'/'+role
            data.update({stem+'.argv':check.argv_bytes(commands['export-'+case+':'+role]),stem+'.status':b'0\n',stem+'.stderr':b''})
    receipt={'outer.argv':check.argv_bytes(check.environment()+['/bin/sh',plan['paths']['guest_packet']+'/outer.sh']),'outer.status':b'0\n','outer.stdout':('evidence='+plan['paths']['guest_export']+'\n').encode(),'outer.stderr':b''}
    assert set(data)==set(plan['evidence_files'])
    return plan,positive['catalog'],data,receipt

def write_tree(path,data):
    path.mkdir(mode=0o700)
    for name,raw in data.items():
        target=path/name;target.parent.mkdir(mode=0o700,parents=True,exist_ok=True);target.write_bytes(raw);target.chmod(0o600)
    for directory in path.rglob('*'):
        if directory.is_dir():directory.chmod(0o700)
    manifest=''.join(check.sha(raw)+'  '+name+'\n' for name,raw in sorted(data.items()))
    (path/'SHA256SUMS').write_text(manifest);(path/'SHA256SUMS').chmod(0o600)

def pure(plan,catalog,data):
    def read(name,cap):
        raw=data[name];check.require(len(raw)<=cap,'injected cap');return raw
    gated=check.metadata_pair(plan,read)
    return check.complete_pair(plan,catalog,read,lambda name:iter(data[name].splitlines(keepends=True)),gated)

class CalibrationControls(unittest.TestCase):
    @classmethod
    def setUpClass(cls):cls.fixture=synthetic()
    def baseline(self):
        plan,cat,data,receipt=deepcopy(self.fixture);facts=pure(plan,cat,data)
        self.assertEqual(facts.positive.raw_events,3);self.assertEqual(facts.denied.raw_events,0)
        self.assertFalse(facts.exec_proved);self.assertFalse(facts.full_acceptance)
        return plan,cat,data,receipt
    def test_01_complete_pair_and_all_denied_races(self):
        plan,cat,data,receipt=self.baseline()
        for raw,kill in ((30720,False),(30720,True),(9,True)):
            changed=deepcopy(data);r=json.loads(changed['cases/denied/result.json']);r['wait'].update(raw_status=raw,kill_attempted=kill);changed['cases/denied/result.json']=encode(r)
            self.assertEqual(pure(plan,cat,changed).denied.raw_wait_status,raw)
        with self.assertRaises(FrozenInstanceError):pure(plan,cat,data).full_acceptance=True
    def test_02_physical_complete_pair_and_outer_receipt(self):
        plan,cat,data,receipt=self.baseline()
        with tempfile.TemporaryDirectory(prefix='glue-calibration-synthetic-') as d:
            e=Path(d).resolve()/'e';r=Path(d).resolve()/'r';write_tree(e,data);write_tree(r,receipt)
            facts=check.check_export(plan,cat,e,r);self.assertEqual(facts.positive.raw_events,3)
    def test_03_refusal_before_helpers_and_supplied_paths(self):
        with patch.object(prep,'shared',side_effect=AssertionError('helper IO')):
            for call in (lambda:prep.prepare('/absent','/no-output'),lambda:prep.load_kit('/absent')):
                with self.assertRaisesRegex(ValueError,'not configured'):call()
        with patch.object(check,'preparer',side_effect=AssertionError('helper IO')):
            with self.assertRaisesRegex(ValueError,'not configured'):check.check('/absent','/absent','/absent')
        with tempfile.TemporaryDirectory(prefix='glue-calibration-cli-') as d:
            for module,args in [('prepare.py',['--kit',d+'/missing','--output',d+'/new']),('checker.py',['--packet',d+'/missing','--evidence',d+'/missing','--run-receipt',d+'/missing'])]:
                cmd=[sys.executable,'-B',str(HERE/module),*args];r=subprocess.run(cmd,capture_output=True);self.assertEqual(r.returncode,1);self.assertIn(b'not configured',r.stderr)
                for flag in ('--enable','--case','--proof','--hash','--target','--provider','--approval'):
                    r=subprocess.run(cmd+[flag,'override'],capture_output=True);self.assertEqual(r.returncode,2)
            self.assertFalse((Path(d)/'new').exists())
    def test_04_old_guard_and_extracted_loader_ast(self):
        old=prep.shared();self.assertIsNone(old.APPROVED);self.assertFalse(old.EXECUTION_ENABLED);self.assertIsNone(old.SIM_POLICY)
        with patch.object(old,'primitives',side_effect=AssertionError('helper IO')):
            with self.assertRaisesRegex(ValueError,'not configured'):old.load_kit('/absent')
        # Normalized body pin from the original f8e50d1 loader, excluding only its
        # enabled() guard and renaming the source-defined APPROVED parameter.
        tree=ast.parse((old.HERE/'kit_contract.py').read_bytes());fn=next(n for n in tree.body if isinstance(n,ast.FunctionDef) and n.name=='load_approved_kit')
        self.assertEqual(hashlib.sha256(ast.dump(ast.Module(body=fn.body,type_ignores=[]),include_attributes=False).encode()).hexdigest(),'b4dc77d816cdde6d1f391990a733e8d35977216d85ff37b0a41042ed12457ef6')
    def test_05_fixed_renderer_and_syntax_only(self):
        plan,cat,data,receipt=self.baseline();scripts=prep.render(plan)
        with tempfile.TemporaryDirectory(prefix='glue-calibration-syntax-') as d:
            for name,raw in scripts.items():
                self.assertNotIn(b'@@',raw);self.assertIn(b'[ 0 = 1 ]',raw);path=Path(d)/name;path.write_bytes(raw)
                r=subprocess.run(['/bin/sh','-n',str(path)],capture_output=True);self.assertEqual(r.returncode,0,r.stderr)
        for flag,value in [('EXECUTION_ENABLED',True),('APPROVED',{})]:
            with patch.object(prep,flag,value),self.assertRaises(ValueError):prep.render(plan)
        root=scripts['root-stage.sh'].decode();outer=scripts['outer.sh'].decode()
        self.assertNotIn('case-simulated',root);self.assertNotIn('case-trailing',root);self.assertNotIn('for c in positive simulated',outer)
        self.assertLess(root.index('metadata_gate || return 2',root.index('run_case()')),root.index('output_roster || return 2',root.index('run_case()')))
        self.assertLess(root.index('output_roster || return 2',root.index('run_case()')),root.index('/bin/chmod 0755 "$BUILD"',root.index('run_case()')))
        self.assertIn('install_context_matches || return 2',root);self.assertIn('135',str(plan['evidence_total_limit']//1024//1024))
    def test_06_metadata_fault_stops_before_any_raw_read(self):
        plan,cat,data,receipt=self.baseline()
        for case in prep.CASES:
            changed=deepcopy(data);r=json.loads(changed['cases/'+case+'/result.json']);r['signals']['mask_restored']=False;changed['cases/'+case+'/result.json']=encode(r)
            touched=[]
            def read(name,cap):touched.append(name);return changed[name]
            with self.assertRaises(ValueError):check.metadata_pair(plan,read)
            self.assertFalse(any(n.endswith(('events.jsonl','program.d','probes.tsv','status.bin','request.bin','probe.stdout')) for n in touched))
        changed=deepcopy(data);changed['cases/positive/result.json']=b'{"schema":"x","schema":"x"}'
        with self.assertRaisesRegex(ValueError,'duplicate'):check.metadata_pair(plan,lambda n,c:changed[n])
    def test_07_command_completion_and_exact_argv(self):
        plan,cat,data,receipt=self.baseline()
        for name in data:
            if name.endswith('.argv') or name.endswith('.status'):
                changed=deepcopy(data);changed[name]=b'2\n' if name.endswith('.status') else data[name]+b'override\0'
                with self.subTest(name=name),self.assertRaises(ValueError):pure(plan,cat,changed)
    def test_08_context_catalog_and_complete_case_mutations(self):
        plan,cat,data,receipt=self.baseline()
        for context in (b'17:43\n',b'18:42\n',b'017:42\n',b'17:42',b'0:42\n'):
            changed=deepcopy(data);changed['install-context.bin']=context
            with self.subTest(context=context),self.assertRaises(ValueError):pure(plan,cat,changed)
        for name in ('cases/positive/request.bin','cases/positive/status.bin','cases/positive/probe.stdout','cases/denied/status.bin'):
            changed=deepcopy(data);changed[name]=changed[name][:-1]+b'x'
            with self.subTest(name=name),self.assertRaises(ValueError):pure(plan,cat,changed)
        with self.assertRaisesRegex(ValueError,'catalog'):pure(plan,cat+b'\0',data)
    def test_09_raw_tail_bounds_error_and_consumer_exceptions(self):
        plan,cat,data,receipt=self.baseline()
        for role,raw in [('events.jsonl',data['cases/positive/events.jsonl']+b'{}\n'),('events.jsonl',b'x'*8192+b'\n'),('errors.jsonl',b'fault\n'),('program.d',b'bad')]:
            changed=deepcopy(data);changed['cases/positive/'+role]=raw
            with self.subTest(role=role),self.assertRaises(ValueError):pure(plan,cat,changed)
        touched=[]
        def broken(name):
            try:
                yield data[name].splitlines(keepends=True)[0]
                raise OSError('injected read failure')
            finally:touched.append('closed')
        with self.assertRaises(OSError):check.complete_pair(plan,cat,lambda n,c:data[n],broken,check.metadata_pair(plan,lambda n,c:data[n]))
        self.assertEqual(touched,['closed'])
        def close_fault(name):
            try:yield from data[name].splitlines(keepends=True)
            finally:raise OSError('injected close failure')
        with self.assertRaises(OSError):check.complete_pair(plan,cat,lambda n,c:data[n],close_fault,check.metadata_pair(plan,lambda n,c:data[n]))
    def test_10_physical_links_extra_manifest_hash_and_mutation(self):
        plan,cat,data,receipt=self.baseline()
        for change in ('extra','link','hash','outer','longline','tail'):
            with tempfile.TemporaryDirectory(prefix='glue-calibration-hostile-') as d:
                e=Path(d).resolve()/'e';r=Path(d).resolve()/'r';write_tree(e,data);write_tree(r,receipt)
                if change=='extra':(e/'extra').write_bytes(b'')
                if change=='link':(e/'cases/positive/events.jsonl').unlink();(e/'cases/positive/events.jsonl').symlink_to('/not-read')
                if change=='hash':(e/'cases/positive/program.d').write_bytes(b'bad')
                if change=='outer':(r/'outer.status').write_bytes(b'1\n')
                if change in ('longline','tail'):
                    changed=deepcopy(data);changed['cases/positive/events.jsonl']=(b'x'*8192+b'\n' if change=='longline' else changed['cases/positive/events.jsonl']+b'junk')
                    for x in sorted(e.rglob('*'),reverse=True):
                        if x.is_file():x.unlink()
                        elif x.is_dir():x.rmdir()
                    e.rmdir();write_tree(e,changed)
                with self.subTest(change=change),self.assertRaises((ValueError,OSError)):check.check_export(plan,cat,e,r)
    def test_11_operation_failure_even_with_expected_stdout(self):
        with tempfile.TemporaryDirectory(prefix='glue-calibration-operation-') as d:
            script=Path(d)/'read';script.write_text('#!/bin/sh\nprintf "expected\\n"\nexit 7\n');script.chmod(0o700)
            # Only the small read-only shell helper is run, no generated phase.
            r=subprocess.run(['/bin/sh','-c',prep.READ_MATCH+'\nread_match expected "$1" || exit 2','guard',str(script)],capture_output=True)
            self.assertEqual(r.returncode,2)
        plan,cat,data,receipt=self.baseline()
        with tempfile.TemporaryDirectory(prefix='glue-calibration-read-') as d:
            e=Path(d).resolve()/'e';r=Path(d).resolve()/'r';write_tree(e,data);write_tree(r,receipt)
            with patch.object(check.os,'read',side_effect=OSError('read fault')):
                with self.assertRaises(OSError):check.check_export(plan,cat,e,r)
    def test_12_dependency_pins_and_streaming_no_legacy_limit_change(self):
        self.assertEqual(prep.sha(prep.SHARED.read_bytes()),prep.SHARED_SHA)
        self.assertEqual(check.sha((HERE/'prepare.py').read_bytes()),check.PREPARE_SHA)
        with patch.object(check,'PREPARE_SHA','0'*64),self.assertRaises(ValueError):check.preparer()
        p,unused=prep.primitives();self.assertEqual(p.MAX_FILE,8*1024*1024);self.assertEqual(p.MAX_TOTAL,64*1024*1024)
        plan,cat,data,receipt=self.baseline();self.assertEqual([n for n in plan['evidence_files'] if n.endswith('/events.jsonl')],['cases/positive/events.jsonl'])
        self.assertNotIn('sim_policy',plan)

class PhysicalBoundaryControls(unittest.TestCase):
    def test_13_fifo_refuses_in_bounded_subprocess(self):
        with tempfile.TemporaryDirectory(prefix='glue-calibration-fifo-') as d:
            root=Path(d).resolve();os.mkfifo(root/'result.json',0o600)
            code="import sys;sys.path.insert(0,sys.argv[1]);import checker;\ntry:\n with checker.Tree(sys.argv[2]) as t:t.read('result.json',8192)\nexcept ValueError:sys.exit(0)\nsys.exit(9)"
            r=subprocess.run([sys.executable,'-B','-c',code,str(HERE),str(root)],capture_output=True,timeout=5)
            self.assertEqual(r.returncode,0,r.stderr)
    def test_14_nested_private_directory_and_bounded_inventory(self):
        plan,cat,data,receipt=synthetic()
        with tempfile.TemporaryDirectory(prefix='glue-calibration-directory-') as d:
            e=Path(d).resolve()/'e';r=Path(d).resolve()/'r';write_tree(e,data);write_tree(r,receipt)
            (e/'cases').chmod(0o755)
            with self.assertRaisesRegex(ValueError,'nonprivate'):check.check_export(plan,cat,e,r)
            (e/'cases').chmod(0o700)
            for i in range(150):(e/('extra'+str(i))).write_bytes(b'')
            with self.assertRaises(ValueError):check.check_export(plan,cat,e,r)
    def test_15_actual_read_close_failure_prevents_return(self):
        with tempfile.TemporaryDirectory(prefix='glue-calibration-close-') as d:
            root=Path(d).resolve();(root/'file').write_bytes(b'x')
            with check.Tree(root) as tree:
                real_open=tree.open;real_close=check.os.close;leaf=[];closed=[]
                def open_leaf(name):
                    fd=real_open(name);leaf.append(fd);return fd
                def close(fd):
                    real_close(fd)
                    if fd in leaf:closed.append(fd);raise OSError('injected close error')
                with patch.object(tree,'open',side_effect=open_leaf),patch.object(check.os,'close',side_effect=close):
                    with self.assertRaisesRegex(OSError,'injected close'):tree.read('file',1)
                self.assertEqual(closed,leaf)

class LoaderContractControls(unittest.TestCase):
    def test_16_valid_injected_loader_and_terminal_mutations(self):
        # This isolates the extracted contract after an injected verified-tree
        # boundary. Synthetic Mach-O parser bytes never form/run a native kit.
        base=prep.shared();p,trace=prep.primitives()
        path=HERE.parent/'bootstrap-trace-kit/test_build_kit.py'
        spec=importlib.util.spec_from_file_location('calibration_kit_shapes',path)
        shapes=importlib.util.module_from_spec(spec);spec.loader.exec_module(shapes)
        contract_path=base.HERE/'kit_contract.py'
        spec=importlib.util.spec_from_file_location('calibration_kit_contract',contract_path)
        contract=importlib.util.module_from_spec(spec);spec.loader.exec_module(contract)
        plan,catalog,evidence,receipt=synthetic();entry=plan['proof_entry'];observed=plan['observation']
        lock=shapes.configured_parser_rules();lock['proofs']=[entry]
        data={'catalog.bin':catalog,'recipe.json':encode({'schema':'glue-owned-trace-kit-recipe-v1','sip_policy':'exact-disabled'}),'source-lock.json':p.canonical(lock),'admitted-proof.json':encode({'registry_entry':entry,'observation':observed,'full_acceptance':False})}
        artifacts={}
        for name in prep.PROGRAMS:
            raw=shapes.image(trace.POLICY.artifacts[1].dependencies if name=='owned-trace-runner' else shapes.core.SYSTEM_DEPENDENCIES)
            artifacts[name]={'sha256':check.sha(raw),'size':len(raw),'provenance':trace.macho(raw,artifact=name)}
            data['kit/'+name]=raw
            for trial in ('first','second'):
                data['builds/'+trial+'/'+name]=raw
                for phase in ('compile','sign','verify'):
                    data['logs/'+trial+'-'+name+'-'+phase+'.status.json']=encode(dict(returncode=0,timed_out=False,operation_errno=None,command_cleanup_unresolved=False))
        result=dict(schema='glue-owned-trace-kit-result-v1',status='built-reproducibly',build_id='b'*64,catalog_sha256=check.sha(catalog),artifacts=artifacts,new_binaries_executed=False,installed=False,kernel_exec_proof=False,full_acceptance=False)
        data['result.json']=encode(result);manifest=b'injected verified tree boundary\n'
        approved={name:'f'*64 for name in ('kit_review_manifest_sha256','catalog_review_manifest_sha256','builder_receipt_manifest_sha256')}
        approved.update(kit_manifest_sha256=check.sha(manifest),build_id=result['build_id'],catalog_sha256=check.sha(catalog),recipe_sha256=check.sha(data['recipe.json']),source_lock_sha256=check.sha(data['source-lock.json']),source_revision=lock['source_revision'],observation_sha256=check.sha(p.canonical(observed)),proof_entry=entry,artifacts={n:{k:artifacts[n][k] for k in ('sha256','size')} for n in prep.PROGRAMS})
        class Injected:
            def __getattr__(self,name):return getattr(p,name)
            def verified_tree(self,path,identity):return deepcopy(active)
        with tempfile.TemporaryDirectory(prefix='glue-calibration-loader-') as d:
            directory=Path(d).resolve();(directory/'SHA256SUMS').write_bytes(manifest)
            active=deepcopy(data)
            value=contract.load_approved_kit(directory,approved,lambda:(Injected(),trace))
            self.assertEqual(value[2],result);self.assertEqual(value[3],observed)
            for change in ('scope','trial','status','recipe','proof','observation'):
                active=deepcopy(data)
                if change=='scope':v=deepcopy(result);v['installed']=True;active['result.json']=encode(v)
                if change=='trial':active['builds/second/context-probe']+=b'x'
                if change=='status':active['logs/first-context-probe-compile.status.json']=encode(dict(returncode=0,timed_out=False,operation_errno=None,command_cleanup_unresolved=True))
                if change=='recipe':active['recipe.json']=encode({'schema':'glue-owned-trace-kit-recipe-v1','sip_policy':'enabled'})
                if change=='proof':v=json.loads(active['admitted-proof.json']);v['registry_entry']['manifest_sha256']='0'*64;active['admitted-proof.json']=encode(v)
                if change=='observation':v=json.loads(active['admitted-proof.json']);v['observation']['components'][3]['fsid'][0]+=1;active['admitted-proof.json']=encode(v)
                with self.subTest(change=change),self.assertRaises(ValueError):contract.load_approved_kit(directory,approved,lambda:(Injected(),trace))

if __name__=='__main__':unittest.main()
