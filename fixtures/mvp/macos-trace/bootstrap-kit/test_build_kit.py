"""Synthetic parser/codec controls only. No guest kit or new target execution."""
import copy
import errno
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import platform
import shlex
import shutil
import stat
import struct
import subprocess
import tempfile
import unittest
from unittest.mock import patch

HERE = Path(__file__).resolve().parent
UNCONFIGURED = HERE / 'unconfigured-inputs.fixture.json'
spec = importlib.util.spec_from_file_location('kit_builder', HERE / 'build_kit.py')
kit = importlib.util.module_from_spec(spec)
spec.loader.exec_module(kit)


def sample_observation():
    components = []
    for i, name in enumerate(('/', 'System', 'Volumes', 'Data', 'Library')):
        data = i >= 3
        components.append(dict(name=name, device=20 if data else 10, inode=100+i, uid=0, gid=0,
            mode=stat.S_IFDIR|0o755, fsid=[-3, 4] if data else [1, 2], mount_flags=0,
            mount_policy=1 if data else 3, mount_owner=0, descriptor_flags=1, status_flags=0,
            mountpoint='/System/Volumes/Data' if data else '/', filesystem='apfs', filesec_population=7, acl_present=0))
    return dict(schema='glue-bootstrap-deployment-observation-v1', model='VirtualMac2,1', kernel_release='26.6.0',
                observed_unix_seconds=1, observed_nanoseconds=123, ids=[501,501,20,20], groups=[20,0,80],
                tc_compatible=True, components=components, settings_changed=False, executable_admission=False, full_acceptance=False)


def profile():
    return {'root': {'device': 10, 'fsid': [1,2]}, 'data': {'device': 20, 'fsid': [-3,4]}}


def catalog_oracle():
    out=bytearray(192)
    struct.pack_into('>8sHHIQQiiQii',out,0,b'GLUENC01',1,192,269,1234,10,1,2,20,-3,4)
    out[56:184]=bytes(range(128));struct.pack_into('>HH',out,184,64,13)
    return bytes(out)+b'a'*64+b'context-probe'


def write_tree(root, members):
    for name, data in members.items():
        path=root/name;path.parent.mkdir(parents=True,exist_ok=True);path.write_bytes(data)
    lines=''.join(hashlib.sha256(data).hexdigest()+'  '+name+'\n' for name,data in sorted(members.items())).encode()
    (root/'SHA256SUMS').write_bytes(lines)
    return hashlib.sha256(lines).hexdigest()


def synthetic_macho(commands=None, cpu_subtype=0):
    # Load-command parser data only: dummy signature bytes are NOT a signed or
    # executable native fixture, and never go through the native build entry.
    def string_command(kind,offset,name):
        size=(offset+len(name)+1+7)//8*8
        out=bytearray(size);struct.pack_into('<III',out,0,kind,size,offset);out[offset:offset+len(name)]=name
        return bytes(out)
    commands=list(commands) if commands is not None else [
        string_command(0xc,24,b'/usr/lib/libSystem.B.dylib'),string_command(0xe,12,b'/usr/lib/dyld'),
        struct.pack('<6I',0x32,24,1,0x1a0000,0x1b0000,0),struct.pack('<II',0x1b,24)+bytes(range(1,17))]
    size=sum(map(len,commands))+16
    commands.append(struct.pack('<4I',0x1d,16,32+size,16))
    return struct.pack('<8I',0xfeedfacf,0x100000c,cpu_subtype,2,len(commands),size,0,0)+b''.join(commands)+bytes(16)


def synthetic_proof_trees(proof, inspector, *, output_name='glue-bootstrap-deployment-v1-aB012345', observed=None):
    """Parser fixtures only; no production registry or native construction."""
    binary=b'nonexecutable synthetic parser data';wrapper=b'synthetic wrapper parser data\n'
    binary_sha=hashlib.sha256(binary).hexdigest()
    metadata=dict(schema='glue-bootstrap-inspector-vm-kit-v1',binary_sha256=binary_sha,source_commit='d2bd45d',
        source_manifest_sha256='a'*64,minimum_macos='26.0',signature='strict-verified development ad-hoc',
        guest_execution_completed=False,privilege_required=False,settings_changed=False,purpose='synthetic parser data')
    inspector_id=write_tree(inspector,{'KIT.json':kit.canonical(metadata),'run-inspector.sh':wrapper,'inspect-deployment':binary})
    output=kit.GUEST_RESULTS+'/'+output_name
    commands={'binary-check':['/usr/bin/shasum','-a','256','-c',output+'/binary-check.sha256'],
        'signature':['/usr/bin/codesign','--verify','--strict','--verbose=2',kit.GUEST_KIT+'/inspect-deployment'],
        'sip':['/usr/bin/csrutil','status'],'os':['/usr/bin/sw_vers'],'kernel':['/usr/bin/uname','-mrs'],
        'observation':[kit.GUEST_KIT+'/inspect-deployment']}
    members={'wrapper-source.sh':wrapper,'binary-check.sha256':(binary_sha+'  '+kit.GUEST_KIT+'/inspect-deployment\n').encode(),
        'wrapper.json':kit.canonical(dict(schema='glue-bootstrap-inspection-wrapper-v1',failed=0,settings_changed=False,full_acceptance=False))}
    for name,argv in commands.items():
        members[name+'.argv']=b''.join(x.encode()+b'\0' for x in argv)
        members[name+'.status']=b'0\n';members[name+'.stdout']=b'';members[name+'.stderr']=b''
    members['binary-check.stdout']=(kit.GUEST_KIT+'/inspect-deployment: OK\n').encode()
    members['sip.stdout']=b'System Integrity Protection status: enabled.\n'
    members['kernel.stdout']=b'Darwin 26.6.0 arm64\n'
    members['os.stdout']=b'ProductName:\tmacOS\nProductVersion:\t26.6.2\nBuildVersion:\t25A1\n'
    members['observation.stdout']=kit.canonical(sample_observation() if observed is None else observed)
    proof_id=write_tree(proof,members)
    entry=dict(manifest_sha256=proof_id,review_manifest_sha256='b'*64,inspector_manifest_sha256=inspector_id,
        wrapper_sha256=hashlib.sha256(wrapper).hexdigest(),binary_sha256=binary_sha,inspector_source_commit='d2bd45d',
        guest_output_name=output_name,kernel_release='26.6.0',os_version='26.6.2',os_build='25A1')
    return entry,members


class KitControls(unittest.TestCase):
    def test_unconfigured_fixture_refuses_before_source_proof_or_output_work(self):
        value=kit.registry(UNCONFIGURED.read_bytes())
        self.assertIsNone(value['source_revision']);self.assertEqual(value['sources'],{});self.assertEqual(value['proofs'],[])
        with tempfile.TemporaryDirectory(prefix='glue-kit-deny-') as temp:
            out=Path(temp)/'new-kit'
            with patch.object(kit,'REGISTRY',UNCONFIGURED), \
                 patch.object(kit,'locked_sources',side_effect=AssertionError('must not inspect sources')), \
                 patch.object(kit,'admitted_proof',side_effect=AssertionError('must not inspect proof')), \
                 patch.object(kit,'Build',side_effect=AssertionError('must not create output')):
                with self.assertRaisesRegex(kit.Refusal,'no independently reviewed actual guest proof'):
                    kit.construct(Path(temp),Path(temp),out)
            self.assertFalse(out.exists())

    def test_production_cli_rejects_unreviewed_inputs_without_output(self):
        with tempfile.TemporaryDirectory(prefix='glue-kit-cli-deny-') as temp:
            out=Path(temp)/'new-kit'
            # The configured CLI audits registered sources through Git before
            # rejecting this missing proof. Allow for that work on hosted runners;
            # individual source-check commands already have a 30-second limit.
            done=subprocess.run([os.sys.executable,'-B',str(HERE/'build_kit.py'),'--guest-proof',temp,
                '--inspector-kit',temp,'--output',str(out)],capture_output=True,timeout=60)
            self.assertEqual(done.returncode,1);self.assertFalse(out.exists())
            self.assertEqual(done.stdout,b'')

    def test_closed_cli_no_trust_override(self):
        done=subprocess.run([os.sys.executable,'-B',str(HERE/'build_kit.py'),'--trust','x'],capture_output=True,timeout=5)
        self.assertEqual(done.returncode,2)

    def test_strict_json_and_integer_types(self):
        for raw in (b'{"x":1,"x":2}',b'{"x":NaN}',b'{"x":1e999}',b'{"x":1.0}',b'{"x":'+b'9'*5000+b'}',
                    b'\xff',b'['*2000,b' '* (kit.MAX_JSON+1)):
            with self.subTest(raw=raw[:20]),self.assertRaises(kit.Refusal):kit.strict_json(raw)
        for x in (True,1.0,'1',None,-1,1<<64):
            with self.assertRaises(kit.Refusal):kit.integer(x)

    def test_registry_schema_lists_and_duplicate_proofs(self):
        value=json.loads(UNCONFIGURED.read_bytes())
        for change in ({'unknown':1},{'source_revision':True},{'probe_sources':[{}]}, {'sources':{'../escape':'0'*64}},
                       {'sources':{'fixtures/mvp/macos-trace/bootstrap-kit/reviewed-inputs.json':'0'*64}}):
            trial=copy.deepcopy(value);trial.update(change)
            with self.assertRaises(kit.Refusal):kit.registry(kit.canonical(trial))

    def test_manifest_schema_and_escape(self):
        for raw in (b'',b'0'*64+b'  ../x\n',b'0'*64+b'  /x\n',b'0'*64+b'  a//b\n',b'0'*64+b'  x',
                    (b'0'*64+b'  x\n')*2,b'0'*64+b'  SHA256SUMS\n'):
            with self.assertRaises(kit.Refusal):kit.parse_manifest(raw)

    def test_verified_tree_exact_hashes_extras_links_and_special(self):
        with tempfile.TemporaryDirectory(prefix='glue-kit-tree-') as temp:
            root=Path(temp).resolve();identity=write_tree(root,{'a':b'a','sub/b':b'b'})
            self.assertEqual(kit.verified_tree(root,identity),{'a':b'a','sub/b':b'b'})
            (root/'extra').write_bytes(b'x')
            with self.assertRaises(kit.Refusal):kit.verified_tree(root,identity)
            (root/'extra').unlink();(root/'a').write_bytes(b'changed')
            with self.assertRaises(kit.Refusal):kit.verified_tree(root,identity)
            (root/'a').unlink();(root/'a').symlink_to('sub/b')
            with self.assertRaises((kit.Refusal,OSError)):kit.verified_tree(root,identity)
            (root/'a').unlink();os.link(root/'sub/b',root/'a')
            with self.assertRaises(kit.Refusal):kit.verified_tree(root,identity)
            (root/'a').unlink();os.mkfifo(root/'a')
            with self.assertRaises(kit.Refusal):kit.verified_tree(root,identity)

    def test_physical_ancestors_empty_dirs_and_bounds(self):
        with tempfile.TemporaryDirectory(prefix='glue-kit-physical-') as temp:
            base=Path(temp).resolve();real=base/'real';real.mkdir();identity=write_tree(real,{'x':b'x'})
            (base/'link').symlink_to(real,target_is_directory=True)
            with self.assertRaises(OSError):kit.verified_tree(base/'link',identity)
            (real/'empty').mkdir()
            with self.assertRaises(kit.Refusal):kit.verified_tree(real,identity)
            (real/'empty').rmdir();(real/'x').write_bytes(b'12345')
            fd=kit.open_directory(real)
            try:
                with self.assertRaises(kit.Refusal):kit.read_member(fd,'x',4)
            finally:os.close(fd)

    def test_observation_exact_schema_and_no_coercion(self):
        value=sample_observation();self.assertEqual(kit.observation(kit.canonical(value)),value)
        mutations=[('ids',[0,0,20,20]),('ids',[True,True,20,20]),('groups',[20,20]),('groups',[0,20]),
                   ('tc_compatible',1),('settings_changed',0),('full_acceptance',True),('observed_nanoseconds',1000000000)]
        for key,data in mutations:
            trial=copy.deepcopy(value);trial[key]=data
            with self.subTest(key=key,data=data),self.assertRaises(kit.Refusal):kit.observation(kit.canonical(trial))
        for key,data in [('filesec_population',0),('acl_present',-1),('mode',stat.S_IFDIR|0o777),('uid',501),
                         ('status_flags',64),('descriptor_flags',0),('mount_policy',3),('device',10),('fsid',[1,2])]:
            trial=copy.deepcopy(value);trial['components'][3][key]=data
            with self.subTest(key=key),self.assertRaises(kit.Refusal):kit.observation(kit.canonical(trial))

    def test_catalog_oracle_and_generation_digest_dag(self):
        hashes=[bytes(range(i,i+32)).hex() for i in (0,32,64,96)]
        raw=kit.catalog_bytes('a'*64,profile(),1234,*hashes)
        self.assertEqual(raw,catalog_oracle())
        retained=json.loads((HERE/'golden-vectors.json').read_bytes())['catalog']
        self.assertEqual(retained,{'hex':raw.hex(),'sha256':hashlib.sha256(raw).hexdigest()})
        generated=kit.generated_catalog('a'*64,profile(),1234,hashes,raw)
        self.assertIn(b'nr_compiled_catalog(void)',generated);self.assertIn(b'bk_compiled_request_catalog(void)',generated)
        with self.assertRaises(kit.Refusal):kit.generated_catalog('a'*64,profile(),1234,hashes,raw[:-1])
        for invalid in (True,0,4194305):
            with self.assertRaises(kit.Refusal):kit.catalog_bytes('a'*64,profile(),invalid,*hashes)
        with self.assertRaises(kit.Refusal):kit.catalog_bytes('A'*64,profile(),1234,*hashes)

    def test_missing_proof_admission_is_not_hash_self_consistency(self):
        with tempfile.TemporaryDirectory(prefix='glue-kit-unreviewed-') as temp:
            root=Path(temp).resolve();write_tree(root,{'observation.stdout':kit.canonical(sample_observation())})
            with self.assertRaisesRegex(kit.Refusal,'not been independently reviewed'):
                kit.admitted_proof(root,root,{'proofs':[]})

    def test_synthetic_proof_parser_all_commands_exact_and_failure_rejected(self):
        with tempfile.TemporaryDirectory(prefix='glue-kit-proof-parser-') as temp:
            base=Path(temp).resolve();proof=base/'proof';inspector=base/'inspector';proof.mkdir();inspector.mkdir()
            entry,members=synthetic_proof_trees(proof,inspector)
            admitted,observed=kit.admitted_proof(proof,inspector,{'proofs':[entry]})
            self.assertEqual(admitted,entry);self.assertIs(observed['full_acceptance'],False)
            changes=[('signature.status',b'1\n'),('sip.stdout',b'System Integrity Protection status: disabled.\n'),
                ('observation.argv',b'/different\0'),('kernel.stdout',b'Darwin 26.6.0 x86_64\n'),
                ('binary-check.sha256',b'0'*64+b'  /different\n'),('observation.stdout',b'{"schema":"bad"}'),
                ('wrapper.json',b'{"schema":"glue-bootstrap-inspection-wrapper-v1","failed":false,"settings_changed":false,"full_acceptance":false}')]
            for key,data in changes:
                trial=dict(members);trial[key]=data
                entry['manifest_sha256']=write_tree(proof,trial)
                with self.subTest(key=key),self.assertRaises(kit.Refusal):kit.admitted_proof(proof,inspector,{'proofs':[entry]})

    def test_multiple_boot_proofs_select_exact_manifest_and_preserve_mount_tuples(self):
        # Explicit synthetic parser data: no registry mutation or native run.
        with tempfile.TemporaryDirectory(prefix='glue-kit-reboot-parser-') as temp:
            base=Path(temp).resolve();inspector=base/'inspector';inspector.mkdir()
            entries=[];observations=[];proofs=[]
            for boot,name in enumerate(('aB012345','cD678901')):
                observed=sample_observation()
                for i,component in enumerate(observed['components']):
                    component['device']=30+boot
                    component['fsid']=[40 if i<3 else 30+boot,50+boot]
                proof=base/('proof-'+str(boot));proof.mkdir()
                entry,_=synthetic_proof_trees(proof,inspector,
                    output_name='glue-bootstrap-deployment-v1-'+name,observed=observed)
                entries.append(entry);observations.append(observed);proofs.append(proof)
            rules=kit.registry(kit.canonical(dict(kit.registry(UNCONFIGURED.read_bytes()),proofs=entries)))
            catalogs=[]
            for boot,proof in enumerate(proofs):
                admitted,observed=kit.admitted_proof(proof,inspector,rules)
                self.assertEqual(admitted,entries[boot]);self.assertEqual(observed,observations[boot])
                # The second tuple stays distinct even when both device numbers
                # coincide. Independently decode all six catalog scalar fields.
                mount_profile={key:{k:observed['components'][index][k] for k in ('device','fsid')}
                    for key,index in (('root',0),('data',3))}
                raw=kit.catalog_bytes('a'*64,mount_profile,1234,*(['b'*64]*4))
                self.assertEqual(struct.unpack_from('>QiiQii',raw,24),
                    (30+boot,40,50+boot,30+boot,30+boot,50+boot))
                catalogs.append(raw)
                with self.assertRaisesRegex(kit.Refusal,'not been independently reviewed'):
                    kit.admitted_proof(proof,inspector,{'proofs':[entries[1-boot]]})
            self.assertNotEqual(catalogs[0],catalogs[1])
            mixed=copy.deepcopy(observations[1]);mixed['components'][4]['fsid']=observations[0]['components'][4]['fsid']
            with self.assertRaisesRegex(kit.Refusal,'root/Data transition'):
                kit.observation(kit.canonical(mixed))

    def test_source_lock_refuses_unconfigured_and_dirty_before_reading_sources(self):
        empty=kit.registry(UNCONFIGURED.read_bytes())
        with self.assertRaisesRegex(kit.Refusal,'not configured/frozen'):kit.locked_sources(HERE.parents[3],empty)
        rules=copy.deepcopy(empty);rules.update(source_revision='a'*40,sources={'x.c':'b'*64},probe_sources=['x.c'],runner_sources=['x.c'],request_sources=['x.c'])
        with patch.object(kit,'git',return_value=b' M x.c\n'):
            with self.assertRaisesRegex(kit.Refusal,'dirty/untracked'):kit.locked_sources(HERE.parents[3],rules)

    def test_macho_load_command_provenance_bounds_and_required_uuid(self):
        good=synthetic_macho();self.assertEqual(kit.macho(good)['minimum_macos'],'26.0')
        # No native signature or execution claim comes from this pure parser.
        for data in (good[:-1],good[:32],synthetic_macho(cpu_subtype=2),bytes(32),b'x'*(4194304+1)):
            with self.assertRaises(kit.Refusal):kit.macho(data)
        for offset,value in ((32,0x8000001c),(32+56+32+12,0x190000),(32+56+32+24,0x999)):
            trial=bytearray(good);struct.pack_into('<I',trial,offset,value)
            with self.assertRaises(kit.Refusal):kit.macho(bytes(trial))
        trial=bytearray(good);trial[32+56+32+24+8:32+56+32+24+24]=bytes(16)
        with self.assertRaises(kit.Refusal):kit.macho(bytes(trial))

    def test_output_is_exclusive_and_failure_retained(self):
        with tempfile.TemporaryDirectory(prefix='glue-kit-output-') as temp:
            root=Path(temp).resolve()/'new';build=kit.Build(root,HERE.parents[3]);build.put('sources/x',b'x')
            with self.assertRaises(FileExistsError):kit.Build(root,HERE.parents[3])
            build.finish({'status':'failed','full_acceptance':False})
            identity=hashlib.sha256((root/'SHA256SUMS').read_bytes()).hexdigest()
            self.assertEqual(kit.verified_tree(root,identity)['sources/x'],b'x')

    def test_injected_tool_failures_stay_partial_and_success_can_finish(self):
        # No external command, compiler, process group or descendant is launched.
        for outcome in ('timeout','nonzero','spawn','read-error','growth','success'):
            with self.subTest(outcome=outcome),tempfile.TemporaryDirectory(prefix='glue-kit-injected-tool-') as temp:
                root=Path(temp).resolve()/'new';build=kit.Build(root,HERE.parents[3])
                def tool(argv,**kw):
                    if outcome=='spawn':raise OSError(errno.EACCES,'injected spawn refusal')
                    kw['stdout'].write(b'confirmed-prefix');kw['stderr'].write(b'injected-only\n')
                    if outcome=='timeout':raise subprocess.TimeoutExpired(argv,60)
                    return subprocess.CompletedProcess(argv,17 if outcome=='nonzero' else 0)
                original_read=Path.read_bytes
                def read_output(path):
                    if path==root/'logs/tool.stdout':
                        if outcome=='read-error':raise OSError(errno.EIO,'injected output read failure')
                        if outcome=='growth':return b'x'*(kit.MAX_JSON+1)
                    return original_read(path)
                def run_tool():
                    with patch.object(Path,'read_bytes',read_output):return build.run('tool',['injected-tool'])
                with patch.object(kit.subprocess,'run',side_effect=tool) as mock:
                    if outcome=='success':
                        self.assertEqual(run_tool(),b'confirmed-prefix')
                        self.assertFalse(build.tool_cleanup_unresolved)
                        build.finish({'status':'injected-unit-only','full_acceptance':False})
                        identity=hashlib.sha256((root/'SHA256SUMS').read_bytes()).hexdigest()
                        self.assertIn('result.json',kit.verified_tree(root,identity))
                    else:
                        with self.assertRaises((kit.Refusal,OSError)) as failure:run_tool()
                        self.assertTrue(build.tool_cleanup_unresolved)
                        with patch.object(kit,'tree_members',side_effect=AssertionError('failed tool must not inventory')):
                            build.retain_failure(failure.exception)
                            with self.assertRaises(kit.Refusal):build.finish({'status':'must-not-finalize'})
                        marker=json.loads((root/'failure.partial.json').read_bytes())
                        self.assertIs(marker['possible_live_descendants'],True)
                        self.assertIs(marker['command_cleanup_unresolved'],True)
                        self.assertIs(marker['tree_closed'],False);self.assertIs(marker['inventory_complete'],False)
                        self.assertIs(marker['full_acceptance'],False)
                        self.assertFalse((root/'SHA256SUMS').exists());self.assertFalse((root/'result.json').exists())
                        if outcome in ('read-error','growth'):
                            self.assertFalse((root/'logs/tool.status.json').exists())
                        else:
                            record=json.loads((root/'logs/tool.status.json').read_bytes())
                            self.assertEqual(record['returncode'],17 if outcome=='nonzero' else None)
                            self.assertEqual(record['timed_out'],outcome=='timeout')
                            self.assertEqual(record['operation_errno'],errno.EACCES if outcome=='spawn' else None)
                        # Simulated late writer changes raw bytes; no closed-tree
                        # digest/result is created or retroactively asserted.
                        with (root/'logs/tool.stdout').open('ab') as stream:stream.write(b'late-injected-data')
                        with self.assertRaises(kit.Refusal):build.run('no-retry',['must-not-run'])
                    self.assertEqual(mock.call_count,1)

    def test_output_inside_repository_or_aliased_chain_rejected_without_creation(self):
        out=HERE/'must-not-be-created'
        with self.assertRaisesRegex(kit.Refusal,'outside the repository'):kit.Build(out,HERE.parents[3])
        self.assertFalse(out.exists())
        with tempfile.TemporaryDirectory(prefix='glue-kit-repo-boundary-') as temp:
            base=Path(temp).resolve();repo=base/'repo';repo.mkdir();(repo/'child').mkdir()
            (base/'link').symlink_to(repo,target_is_directory=True)
            for out in (repo/'new',repo/'child/new',base/'link/new',repo/'child/../new'):
                with self.assertRaises((kit.Refusal,OSError)):kit.Build(out,repo)
                self.assertFalse((repo/'new').exists())


class CatalogCControls(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.temp=tempfile.TemporaryDirectory(prefix='glue-kit-pure-')
        cls.binary=Path(cls.temp.name)/'test-request-catalog'
        cc=shutil.which(os.environ.get('CC','cc'))
        if not cc:raise RuntimeError('C compiler required')
        command=[cc,'-std=c11','-Wall','-Wextra','-Werror','-pedantic',*shlex.split(os.environ.get('BK_TEST_CFLAGS','')),
                 str(HERE/'request_catalog.c'),str(HERE/'test_request_catalog.c'),
                 str(HERE.parent/'bootstrap-request/bootstrap_request.c'),str(HERE.parent/'bootstrap-wire/bootstrap_wire.c'),
                 str(HERE.parent/'target-credentials/target_credentials.c'),'-o',str(cls.binary)]
        subprocess.run(command,check=True,timeout=30)

    @classmethod
    def tearDownClass(cls):cls.temp.cleanup()

    def test_c_catalog_metadata_and_identity_boundaries(self):
        subprocess.run([str(self.binary),'controls'],input=catalog_oracle(),check=True,capture_output=True,timeout=5)

    def test_request_bytes_independent_struct_oracle(self):
        actual=subprocess.run([str(self.binary),'emit-request'],input=catalog_oracle(),check=True,capture_output=True,timeout=5).stdout
        cwd=kit.PREFIX.encode()+b'a'*64;exe=cwd+b'/context-probe';out=bytearray(208)
        struct.pack_into('>8sHHIIIII',out,0,b'GLUENR01',1,208,208+len(exe)+len(cwd),1,501,20,3)
        struct.pack_into('>16I',out,32,20,0,80,*([0]*13));struct.pack_into('>8I',out,96,1,1,1,4096,10000,2000,1,0)
        out[128:160]=bytes(range(32));struct.pack_into('>QQII',out,160,20,123,len(exe),len(cwd))
        self.assertEqual(actual,bytes(out)+exe+cwd)
        retained=json.loads((HERE/'golden-vectors.json').read_bytes())['request_send_go']
        self.assertEqual(retained,{'hex':actual.hex(),'sha256':hashlib.sha256(actual).hexdigest()})


class UtilityRefusals(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.temp=tempfile.TemporaryDirectory(prefix='glue-kit-unconfigured-')
        root=Path(cls.temp.name);cls.binary=root/'make-request'
        stub=root/'unconfigured.c'
        stub.write_text('#include "request_catalog.h"\nconst struct bk_request_catalog *bk_compiled_request_catalog(void){return 0;}\n')
        cc=shutil.which(os.environ.get('CC','cc'))
        if not cc:raise RuntimeError('C compiler required')
        command=[cc,'-std=c11','-O2','-g0','-Wall','-Wextra','-Werror']
        # Portable refusal executable targets the actual test host, including
        # macOS15 CI. Production min26 is a separate compile-only check below.
        if os.sys.platform=='darwin':command+=['-mmacosx-version-min='+platform.mac_ver()[0]]
        command += ['-I',str(HERE),str(HERE/'make_request.c'),str(HERE/'request_catalog.c'),str(stub),
                    str(HERE.parent/'bootstrap-admission/bootstrap_admission.c'),
                    str(HERE.parent/'bootstrap-request/bootstrap_request.c'),str(HERE.parent/'bootstrap-wire/bootstrap_wire.c'),
                    str(HERE.parent/'target-credentials/target_credentials.c'),'-o',str(cls.binary)]
        subprocess.run(command,check=True,timeout=30)
        cls.command=command

    @classmethod
    def tearDownClass(cls):cls.temp.cleanup()

    def test_unconfigured_utility_refuses_without_request_bytes(self):
        done=subprocess.run([str(self.binary)],capture_output=True,timeout=5)
        self.assertEqual(done.returncode,1);self.assertEqual(done.stdout,b'')
        self.assertIn(b'unconfigured catalog' if os.sys.platform=='darwin' else b'native Darwin required',done.stderr)

    def test_utility_closed_argv_before_any_observation(self):
        for argv in (['--uid','501'],['--catalog','x'],['--simulate-provider-failure','extra']):
            done=subprocess.run([str(self.binary),*argv],capture_output=True,timeout=5)
            self.assertEqual(done.returncode,2);self.assertEqual(done.stdout,b'')

    @unittest.skipUnless(os.sys.platform=='darwin','exact min26 Mach-O compilation requires Darwin SDK')
    def test_production_minimum_compile_only_never_execute(self):
        exact=Path(self.temp.name)/'make-request-min26'
        # Last deployment option overrides the portable host option. Never run
        # this binary, including when the host happens to support its minimum.
        subprocess.run(self.command[:-2]+['-arch','arm64','-mmacosx-version-min=26.0','-o',str(exact)],check=True,timeout=30)
        self.assertEqual(kit.macho(exact.read_bytes())['minimum_macos'],'26.0')


if __name__=='__main__':unittest.main()
