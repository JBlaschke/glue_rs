#!/usr/bin/env python3
"""Independent real-package capture audit; needs exported matching archives."""
from pathlib import Path
import argparse, gzip, hashlib, importlib.util, json, re, struct, zipfile

REVISION = 'e525db8542886800ff008c300c25bd56e7e3e09a'
PROFILES = ('bundled','host','install-host')
MODES = PROFILES + tuple(p+'-corrupt-entry' for p in PROFILES)

def require(value, message):
    if not value: raise ValueError(message)

def identity(data):
    return {'size':len(data),'sha256':hashlib.sha256(data).hexdigest()}

def doctor(profile):
    label={'bundled':'bundled','host':'explicit-host','install-host':'install-only host'}[profile]
    return ('Launcher: glue 0.1.0 on linux/aarch64\n'
        'Linked Lua: 5.4.9 (int64, float64)\n'
        'Available: archive packaging, inspection, verification, read-only resources, linked Lua source profile\n'
        'Pending: general runtime/package compatibility, Node adapters, workers, standalone signing\n'
        'Python: controlled CPython 3.13.16 / PBS 20261009 profiles; GNU Linux arm64 execution only\n'
        'Validated metadata for python.real-packages\n'
        f'Ready: pinned {label} Python distribution metadata application build/target prerequisites, CPython 3.13.16 / PBS 20261009\n'
        'Run checks profile archive limits, contents and explicit host prerequisites before loading Python\n').encode()

def read_trace(path):
    if path.exists(): return path.read_text()
    with gzip.open(str(path)+'.gz','rt') as stream: return stream.read()

def audit(args):
    repo,capture,archives=args.repo,args.capture,args.archives
    spec=importlib.util.spec_from_file_location('independent_corpus_oracle',repo/'fixtures/python-real-packages/prepare.py')
    C=importlib.util.module_from_spec(spec);spec.loader.exec_module(C)
    require(capture.joinpath('source-revision.txt').read_text().strip()==REVISION,'capture revision differs')
    require(not capture.joinpath('source-status.txt').read_bytes() and not capture.joinpath('source-diff.patch').read_bytes(),'capture was not clean')
    require(capture.joinpath('harness.exit-status.txt').read_text()=='0\n','native harness did not pass')
    entry=C.expected_projection()['app/main.py']
    valid,manifests,raw_manifests={}, {}, {}
    for profile in PROFILES:
        valid[profile]=C.audit_build(capture/'cli-controls'/f'{profile}.build.stdout.txt',archives/(profile+'.glue'),capture/'installation-provenance.json')
        data=archives.joinpath(profile+'.glue').read_bytes();size=struct.unpack_from('<Q',data,16)[0]
        raw_manifests[profile]=data[64:64+size];manifests[profile]=C.strict_json(raw_manifests[profile])
        require(C.typed_equal(C.strict_json(capture.joinpath(profile+'.product-audit.json').read_bytes()),valid[profile]),'original independent product audit differs')
    members,damages,controls,artifacts=0,0,{},{}
    diagnostic=b'glue: resource "app/main.py" failed CRC32 verification\n'
    for mode in MODES:
        profile=mode.removesuffix('-corrupt-entry');bad=mode.endswith('-corrupt-entry')
        path=archives/(mode+'.glue');data=path.read_bytes();size,zip_size=struct.unpack_from('<QQ',data,16)
        raw=data[64:64+size];manifest=manifests[profile]
        require(data[:8]==b'GLUERS00' and data[8:16]==b'\0'*8 and zip_size==len(data)-64-size and hashlib.sha256(raw).digest()==data[32:64] and raw==raw_manifests[profile],'control framing/manifest differs')
        with zipfile.ZipFile(path) as archive:
            infos=archive.infolist();resources=manifest['resources']
            require(len(infos)==len(resources) and set(archive.namelist())==set(resources),'complete ZIP inventory differs')
            for info in infos:
                resource=resources[info.filename]
                require(info.file_size==resource['size'] and info.compress_type==(zipfile.ZIP_STORED if resource['compression']=='stored' else zipfile.ZIP_DEFLATED),'ZIP size/storage differs')
                if bad and info.filename=='app/main.py':
                    try: archive.read(info.filename)
                    except zipfile.BadZipFile as error: require('CRC' in str(error),'damage failed for another reason')
                    else: raise ValueError('damaged entry unexpectedly verified')
                    names,extra=struct.unpack_from('<HH',data,info.header_offset+26);offset=info.header_offset+30+names+extra
                    require(data[offset:offset+len(entry)]==bytes([entry[0]^1])+entry[1:],'damage is not exactly first-byte XOR')
                    damages+=1;continue
                require(C.typed_equal(identity(archive.read(info.filename)),{k:resource[k] for k in ('size','sha256')}),'ZIP payload identity differs')
                members+=1
        artifacts[mode]=identity(data)
        for operation in ('inspect','verify','doctor','cat'):
            prefix=capture/'cli-controls'/(mode+'.'+operation)
            out=Path(str(prefix)+'.stdout.txt').read_bytes();err=Path(str(prefix)+'.stderr.txt').read_bytes();status=Path(str(prefix)+'.exit-status.txt').read_text()
            reject=bad and operation in ('verify','cat')
            require(status==('1\n' if reject else '0\n') and err==(diagnostic if reject else b''),'CLI status/diagnostic differs: '+mode+'.'+operation)
            expected=(b'' if reject else raw+b'\n' if operation=='inspect' else doctor(profile) if operation=='doctor' else entry if operation=='cat' else f'Verified {len(resources)} resources ({sum(v["size"] for v in resources.values())} uncompressed bytes)\n'.encode())
            require(out==expected,'CLI exact output differs: '+mode+'.'+operation)
            controls[mode+'.'+operation]={'exit_status':int(status),'exact_output_verified':True}
    processes={}
    for profile in PROFILES:
        base=capture/'cli-controls'/(profile+'.build')
        require(Path(str(base)+'.exit-status.txt').read_text()=='0\n' and not Path(str(base)+'.stderr.txt').read_bytes(),'build receipt differs')
        controls[profile+'.build']={'exit_status':0,'independent_report_verified':True}
        text=read_trace(capture/(profile+'.build-process.trace.txt'));lines=text.splitlines()
        require(len(lines)==3,'build process trace record count differs')
        match=re.fullmatch(r'([1-9][0-9]*)\s+execve\(("(?:[^"\\]|\\.)*"), (\[.*\]), 0x[0-9a-f]+ /\* [0-9]+ vars \*/\) = 0',lines[0]);require(match is not None,'build exec grammar differs')
        pid,program,argv=match[1],json.loads(match[2]),json.loads(match[3])
        expected=['/build-target/release/glue','build-python','--provider-template',f'/build-target/staging/{profile}/manifest.json','--provider-root',f'/build-target/staging/{profile}/root','--app','/host-build/installed-packages/application','--venv','/host-build/installed-packages/venv','--app-id','python.real-packages','--entry','app/main.py','--output',f'/build-target/relocated Python metadata/{profile}.glue','--json']
        require(program==expected[0] and argv==expected,'build program/argv differs')
        require(re.fullmatch(re.escape(pid)+r'\s+exit_group\(0\)\s+= \?',lines[1]) and re.fullmatch(re.escape(pid)+r'\s+\+\+\+ exited with 0 \+\+\+',lines[2]),'build PID/exit differs')
        processes[profile]={'process_records':3,'pids':1,'execs':1,'child_processes':0,'interpreter_execs':0,'trace_sha256':hashlib.sha256(text.encode()).hexdigest()}
    checks={}
    for line in capture.joinpath('artifacts.sha256').read_text().splitlines():
        digest,name=line.split('  ',1);local=archives/Path(name).name
        require(hashlib.sha256(local.read_bytes()).hexdigest()==digest,'artifact checksum differs')
        checks[Path(name).name]=digest
    require(set(checks)=={'glue'}|{m+'.glue' for m in MODES},'artifact checksum inventory differs')
    require(len(controls)==27 and members==5273 and damages==3,'product audit inventory differs')
    return {'schema_version':0,'source_revision':REVISION,'clean_source_capture':True,'cli_controls':len(controls),'verified_members':members,'intentional_crc_failures':damages,'cli':controls,'valid_archive_audits':valid,'build_processes':processes,'archive_identities':artifacts,'artifacts':checks}

if __name__=='__main__':
    parser=argparse.ArgumentParser(description=__doc__)
    for key in ('repo','capture','archives','output'): parser.add_argument('--'+key,type=Path,required=True)
    args=parser.parse_args()
    try:
        result=audit(args);args.output.write_text(json.dumps(result,sort_keys=True,indent=2)+'\n')
        print('Independent product audit:27 commands,5273 verified members,3 intentional CRC failures,3 single-process builds')
    except (OSError,ValueError,KeyError,TypeError,struct.error,zipfile.BadZipFile) as error:
        parser.exit(1,'Independent product audit rejected: '+str(error)+'\n')
