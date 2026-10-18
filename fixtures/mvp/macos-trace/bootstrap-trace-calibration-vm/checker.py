#!/usr/bin/env python3
"""Bounded fixed-pair checker; no native operation, currently unconfigured CLI."""
import argparse
from dataclasses import dataclass, field
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import re
import stat
import sys

HERE = Path(__file__).resolve().parent
CHECKING_ENABLED = False
PREPARE_SHA = 'c71bfa5c5718cb1830f8bd948b00eb396a030968d4ef9d72ebad2d6031d44951'
LIBRARY_PINS = {
    'owned_trace_check': ('owned-trace-check/owned_trace_check.py', '0e741d951934ec153ed3c89d7e7fab048515aab2c4f2bed40c0e6e27b0d7d66a'),
    'legacy_codecs': ('owned-trace-cases/legacy_codecs.py', '62161b4932ed355f0af7228cb0a9ca6794bcf2aef66ebc84237f862506f9f9a9'),
    'owned_trace_cases': ('owned-trace-cases/owned_trace_cases.py', '185daf20734b47bd6774d187b7b86c0172523b93269f6762d88f43e5fcc1ba96'),
}

def require(value, message):
    if not value: raise ValueError(message)
def sha(data): return hashlib.sha256(data).hexdigest()
def load(name, path, pin):
    require(sha(path.read_bytes()) == pin, 'reviewed checker dependency differs')
    if name in sys.modules:
        module=sys.modules[name]
        require(Path(module.__file__).resolve()==path.resolve(), 'ambient checker module refused')
        return module
    spec=importlib.util.spec_from_file_location(name,path)
    module=importlib.util.module_from_spec(spec); sys.modules[name]=module
    try: spec.loader.exec_module(module)
    except BaseException:
        del sys.modules[name]
        raise
    return module

def preparer(): return load('glue_calibration_prepare',HERE/'prepare.py',PREPARE_SHA)
def libraries():
    return tuple(load(name,HERE.parent/path,pin) for name,(path,pin) in LIBRARY_PINS.items())
def encoded(value): return (json.dumps(value,separators=(',',':'),ensure_ascii=True)+'\n').encode('ascii')
def json_bytes(data):
    def pairs(items):
        out={}
        for key,value in items:
            require(key not in out,'duplicate metadata key');out[key]=value
        return out
    def number(text):
        require(len(text)<=21,'metadata integer token');return int(text)
    def invalid(unused): raise ValueError('metadata noninteger')
    try: return json.loads(data.decode('ascii'),object_pairs_hook=pairs,parse_int=number,parse_float=invalid,parse_constant=invalid)
    except (UnicodeError,json.JSONDecodeError,RecursionError) as error: raise ValueError('invalid metadata JSON') from error

def argv_bytes(args): return b''.join(x.encode()+b'\0' for x in args)
def environment(): return ['/usr/bin/env','-i','PATH=/usr/bin:/bin:/usr/sbin:/sbin','LC_ALL=C','TZ=UTC']

@dataclass(frozen=True,slots=True)
class PairFacts:
    positive: object
    denied: object
    schema: str = field(default='glue-bootstrap-trace-calibration-facts-v1',init=False)
    tracing: bool = field(default=True,init=False)
    exec_proved: bool = field(default=False,init=False)
    full_acceptance: bool = field(default=False,init=False)

def metadata_pair(plan, read):
    """Fixed bounded reads only; read callback must enforce its own physical caps."""
    prep=preparer();p,unused=prep.primitives()
    commands=prep.root_commands(plan)
    expected=prep.plan_from_identity(plan['build_id'],plan['catalog_sha256'],plan['artifacts'],plan['observation'],plan['proof_entry'],plan['nonce'])
    require(p.canonical(plan)==p.canonical(expected),'unreviewed calibration plan')
    require(read('plan.json',262144)==p.canonical(plan),'evidence plan differs')
    require(read('batch.tsv',4096)==b'schema\tglue-bootstrap-trace-calibration-batch-v1\npreflight\t0\ninstall\t0\npositive\t0\ndenied\t0\ncomplete\t0\n','incomplete calibration batch')
    def receipt(stem, args, stdout=None, stderr=b''):
        require(read(stem+'.argv',32768)==argv_bytes(args),'command argv differs')
        require(read(stem+'.status',4)==b'0\n','command completion differs')
        out=read(stem+'.stdout',8192);err=read(stem+'.stderr',8192)
        if stdout is not None: require(out==stdout,'command stdout differs')
        if stderr is not None: require(err==stderr,'command stderr differs')
    receipt('install',commands['install'],stdout=b'',stderr=None)
    require(read('install-context.argv',32768)==argv_bytes(commands['export-install-context']) and read('install-context.status',4)==b'0\n' and read('install-context.stderr',8192)==b'','install context receipt')
    context=read('install-context.bin',64)
    require(re.fullmatch(rb'[1-9][0-9]*:[1-9][0-9]*\n',context) is not None,'install context syntax')
    device,inode=map(int,context.rstrip(b'\n').split(b':'))
    require(device<(1<<64) and inode<(1<<64),'install context bound')
    result={}
    for case in prep.CASES:
        receipt('case-'+case,commands['case-'+case],stdout=b'')
        prefix='cases/'+case+'/'
        native=0 if case=='positive' else 1
        require(read(prefix+'native.status',4)==str(native).encode()+b'\n','native status')
        args=environment()+[plan['paths']['build_dir']+'/owned-trace-runner','--request',plan['paths']['root_stage']+'/'+case+'.request.bin','--output',plan['outputs'][case]]
        require(read(prefix+'native.argv',8192)==argv_bytes(args),'native argv')
        require(read(prefix+'native.stdout',4096)==read(prefix+'native.stderr',4096)==b'','native diagnostic stream')
        request_sha=read(prefix+'input.sha256',65)
        require(re.fullmatch(rb'[0-9a-f]{64}\n',request_sha) is not None,'input digest')
        r=read(prefix+'result.json',8192);t=read(prefix+'trace.json',16384)
        roster=prep.gates().check_metadata(case,native,json_bytes(r),json_bytes(t),request_sha256=request_sha[:-1].decode(),catalog_sha256=plan['catalog_sha256'])
        result[case]=(r,t,frozenset(roster),native)
    return result,(device,inode)

def complete_pair(plan,catalog,read,event_lines, gated):
    """Called only after metadata_pair and physical exact-inventory verification."""
    prep=preparer();raw_module,unused,cases=libraries()
    metadata,context=gated
    commands=prep.root_commands(plan)
    require(sha(catalog)==plan['catalog_sha256'],'catalog binding')
    require(context[0]==plan['observation']['components'][3]['device'],'installed current device')
    facts=[]
    for case in prep.CASES:
        prefix='cases/'+case+'/';r,t,roster,native=metadata[case]
        req=read('requests/'+case+'.bin',16384)
        require(read('requests/'+case+'.status',4)==b'0\n' and read('requests/'+case+'.stderr',4096)==b'','request generator completion')
        require(read('requests/'+case+'.argv',8192)==argv_bytes(environment()+[plan['paths']['build_dir']+'/make-request']),'request generator argv')
        require(read(prefix+'request.bin',16384)==req,'staged request copy')
        require(read(prefix+'input.sha256',65)==sha(req).encode()+b'\n','staged request hash')
        for role in prep.case_roles(case):
            stem='exports/'+case+'/'+role
            require(read(stem+'.argv',32768)==argv_bytes(commands['export-'+case+':'+role]) and read(stem+'.status',4)==b'0\n' and read(stem+'.stderr',8192)==b'','export receipt')
        obj=json_bytes(r);owner=obj['controller_pid'];child=obj['child_pid'];observed=plan['observation'];cwd=plan['paths']['build_dir'].encode()
        actual=cases.CaseBinding(owner,child,observed['ids'][0],observed['ids'][2],tuple(observed['groups']),cwd+b'/context-probe',cwd,*context)
        raw=None
        if case=='positive':
            stream=iter(event_lines(prefix+'events.jsonl'))
            try:
                raw=raw_module.validate_raw(read(prefix+'program.d',16384),read(prefix+'probes.tsv',1048576),read(prefix+'errors.jsonl',65536),stream,owner_pid=owner,target_pid=child)
            finally:
                close=getattr(stream,'close',None)
                if close is not None:close()
        facts.append(cases.validate_case(case,catalog=catalog,request=req,status=read(prefix+'status.bin',769),probe_stdout=read(prefix+'probe.stdout',256),probe_stderr=read(prefix+'probe.stderr',4096),result=r,sidecar=t,raw=raw,actual=actual,roster=roster,cli_status=native))
    return PairFacts(*facts)

def stamp(s): return (s.st_dev,s.st_ino,s.st_mode,s.st_uid,s.st_gid,s.st_nlink,s.st_size,s.st_mtime_ns,s.st_ctime_ns)
class Tree:
    """Held descriptor, no-follow bounded reads; stable owned namespace required."""
    def __init__(self,path):
        self.fd=preparer().primitives()[0].open_directory(Path(path))
        s=os.fstat(self.fd)
        try: require(s.st_uid==os.getuid() and stat.S_IMODE(s.st_mode)==0o700,'owned private tree')
        except BaseException:os.close(self.fd);raise
        self.before=stamp(s)
    def __enter__(self): return self
    def __exit__(self,*unused):
        try: require(stamp(os.fstat(self.fd))==self.before,'tree changed')
        finally: os.close(self.fd)
    def open(self,name):
        parts=name.split('/');require(all(re.fullmatch('[A-Za-z0-9._-]+',n) and n not in ('.','..') for n in parts),'relative member')
        fd=os.dup(self.fd);leaf=None
        try:
            for n in parts[:-1]:
                child=os.open(n,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW|os.O_CLOEXEC,dir_fd=fd)
                try:
                    info=os.fstat(child)
                    require(info.st_uid==os.getuid() and stat.S_IMODE(info.st_mode)==0o700,'nonprivate path directory')
                except BaseException:os.close(child);raise
                previous=fd;fd=child;os.close(previous)
            leaf=os.open(parts[-1],os.O_RDONLY|os.O_NONBLOCK|os.O_NOFOLLOW|os.O_CLOEXEC,dir_fd=fd)
            return leaf
        finally:
            try:os.close(fd)
            except BaseException:
                if leaf is not None:os.close(leaf)
                raise
    def checked(self,name,cap):
        fd=self.open(name)
        try:
            s=os.fstat(fd)
            require(stat.S_ISREG(s.st_mode) and s.st_nlink==1 and s.st_uid==os.getuid() and not s.st_mode&0o022 and 0<=s.st_size<=cap,'physical member bound/identity')
            return fd,stamp(s)
        except BaseException: os.close(fd);raise
    def read(self,name,cap):
        fd,before=self.checked(name,cap)
        try:
            data=bytearray()
            while len(data)<=cap:
                b=os.read(fd,min(65536,cap+1-len(data)))
                if not b:break
                data.extend(b)
            require(len(data)<=cap and len(data)==before[6] and stamp(os.fstat(fd))==before,'changed/oversized member')
            return bytes(data)
        finally: os.close(fd)
    def inventory(self,limits):
        wanted=set(limits)|{'SHA256SUMS'};dirs={''}
        for name in wanted:
            parts=name.split('/')
            dirs.update('/'.join(parts[:i]) for i in range(1,len(parts)))
        names=set();seen=set();total=0;entries=0
        def visit(fd,prefix):
            nonlocal total,entries
            with os.scandir(fd) as listing:
                for entry in listing:
                    entries+=1
                    require(entries<=len(wanted)+len(dirs)-1,'inventory entry bound')
                    n=entry.name;name=prefix+n;s=entry.stat(follow_symlinks=False);key=(s.st_dev,s.st_ino)
                    require(key not in seen,'aliased inventory');seen.add(key)
                    if stat.S_ISDIR(s.st_mode):
                        require(name in dirs and s.st_uid==os.getuid() and stat.S_IMODE(s.st_mode)==0o700,'extra/nonprivate directory')
                        child=os.open(n,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW|os.O_CLOEXEC,dir_fd=fd)
                        try:
                            require(stamp(os.fstat(child))==stamp(s),'changed inventory directory')
                            visit(child,name+'/')
                        finally:os.close(child)
                    else:
                        require(name in wanted and stat.S_ISREG(s.st_mode) and s.st_nlink==1,'extra/special member')
                        require(s.st_size<=limits.get(name,262144),'member inventory cap');names.add(name);total+=s.st_size
                        require(total<=135*1024*1024+262144,'total evidence bound')
        visit(self.fd,'');require(names==wanted,'missing evidence member')
    def lines(self,name,expected_hash):
        fd,before=self.checked(name,128*1024*1024)
        try:
            with os.fdopen(fd,'rb',closefd=False) as stream:
                h=hashlib.sha256();total=0
                while True:
                    line=stream.readline(8192)
                    if not line:break
                    total+=len(line);require(total<=134217728 and len(line)<=8191 and line.endswith(b'\n'),'event stream bound/tail')
                    h.update(line);yield line
                require(total==before[6] and h.hexdigest()==expected_hash and stamp(os.fstat(fd))==before,'event hash/identity changed')
        finally:os.close(fd)

def check_export(plan,catalog,evidence,run_receipt):
    """Trusted canonical plan/catalog caller; CLI additionally requires activation."""
    prep=preparer();p,unused=prep.primitives()
    with Tree(run_receipt) as receipt:
        receipt.inventory({n:c for n,c in [('outer.argv',8192),('outer.status',4),('outer.stdout',65536),('outer.stderr',65536)]})
        require(receipt.read('outer.argv',8192)==argv_bytes(environment()+['/bin/sh',plan['paths']['guest_packet']+'/outer.sh']) and receipt.read('outer.status',4)==b'0\n','outer argv/completion')
        require(receipt.read('outer.stdout',65536)==('evidence='+plan['paths']['guest_export']+'\n').encode() and receipt.read('outer.stderr',65536)==b'','outer streams')
        rm=p.parse_manifest(receipt.read('SHA256SUMS',262144))
        require(set(rm)=={'outer.argv','outer.status','outer.stdout','outer.stderr'},'outer inventory')
        for name,h in rm.items(): require(sha(receipt.read(name,65536))==h,'outer hash')
    with Tree(evidence) as tree:
        gated=metadata_pair(plan,tree.read)
        tree.inventory(plan['evidence_limits'])
        manifest=p.parse_manifest(tree.read('SHA256SUMS',262144))
        require(set(manifest)==set(plan['evidence_files']),'evidence manifest roster')
        def read(name,cap):
            require(name in manifest and cap<=plan['evidence_limits'][name],'evidence role/cap')
            data=tree.read(name,cap);require(sha(data)==manifest[name],'evidence hash');return data
        for case,(r,t,unused,native) in gated[0].items():
            require(sha(r)==manifest['cases/'+case+'/result.json'] and sha(t)==manifest['cases/'+case+'/trace.json'],'gated metadata changed')
        # Also bind the metadata/control bytes already used by the gate.
        for name,cap in plan['evidence_limits'].items():
            if name!='cases/positive/events.jsonl':read(name,cap)
        return complete_pair(plan,catalog,read,lambda name:tree.lines(name,manifest[name]),gated)

def check(packet,evidence,run_receipt):
    require(CHECKING_ENABLED is True,'calibration checker is not configured')
    prep=preparer();prep.enabled()  # before supplied paths/helper imports
    raise ValueError('calibration activation and packet admission require a later reviewed source change')

def main():
    cli=argparse.ArgumentParser(description=__doc__)
    for name in ('packet','evidence','run-receipt'):cli.add_argument('--'+name,required=True,type=Path)
    args=cli.parse_args()
    try:check(args.packet,args.evidence,args.run_receipt)
    except (ValueError,OSError,KeyError) as error:
        print('trace-calibration-check: '+str(error)[:512],file=sys.stderr);return 1
    return 0
if __name__=='__main__':sys.exit(main())
