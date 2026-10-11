#!/usr/bin/env python3
"""Independent hostile edits of six passing complete source-app captures."""
import argparse
import copy
import hashlib
import importlib.util
import json
from pathlib import Path
import re
import shutil
import subprocess
import sys
import tempfile
import time

ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / 'scripts/check-linux-python-source-app-trace.py'


def sha(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def at(lines, text, start=0):
    return next(i for i in range(start, len(lines)) if text in lines[i])


def remove(lines, index):
    return lines[:index] + lines[index + 1:]


def replace(lines, index, line):
    result = lines.copy(); result[index] = line; return result


def move(lines, index, destination):
    result = remove(lines, index); result.insert(destination - (index < destination), lines[index]); return result


def insert(lines, index, line):
    return lines[:index] + [line] + lines[index:]


def call(pid, source):
    return str(pid) + '    ' + source + '\n'


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--capture', type=Path, required=True)
    parser.add_argument('--build', type=Path, required=True)
    parser.add_argument('--output', type=Path, required=True)
    parser.add_argument('--require-clean-capture', action='store_true')
    args = parser.parse_args()
    if not args.output.parent.is_dir(): parser.error('output parent must already exist')
    capture, build = args.capture.resolve(), args.build.resolve()
    revision = (capture / 'source-revision.txt').read_text().strip()
    status = (capture / 'source-status.txt').read_text()
    current_revision = subprocess.check_output(['git', 'rev-parse', 'HEAD'], cwd=ROOT, text=True).strip()
    current_status = subprocess.check_output(['git', 'status', '--porcelain'], cwd=ROOT, text=True)
    if args.require_clean_capture and (status or current_status or revision != current_revision):
        parser.error('capture and current checker must share the same clean source checkpoint')
    spec = importlib.util.spec_from_file_location('independent_source_app_actual_audit', SCRIPT)
    C = importlib.util.module_from_spec(spec); spec.loader.exec_module(C)
    metadata = json.loads((capture / 'source-metadata.json').read_text())
    report = {'command': sys.argv, 'capture_revision': revision, 'capture_status': status,
              'capture_branch': (capture / 'source-branch.txt').read_text().strip(),
              'capture_metadata_sha256': sha(capture / 'source-metadata.json'),
              'repository_revision': current_revision, 'repository_status': current_status,
              'script_sha256': sha(Path(__file__)), 'checker_sha256': {path.name: sha(path) for path in sorted((ROOT / 'scripts').glob('check-linux-python*trace.py'))},
              'baselines': [], 'mutations': []}
    started = time.monotonic(); baselines = {}
    with tempfile.TemporaryDirectory(prefix='glue-source-trace-audit-') as temporary:
        info = Path(temporary) / 'metadata.json'

        def verify(mode, lines, data=metadata):
            baseline = baselines[mode]; info.write_text(json.dumps(data))
            fact = C.retained_metadata(info, mode, baseline['size'])
            if not C.typed_equal(fact, baseline['actual']):
                raise C.TraceError('retained source metadata differs from actual archive')
            C.check_lines(lines, mode, baseline['size'], fact)

        def hostile(mode, name, lines=None, data=metadata):
            if lines is not None and lines == baselines[mode]['lines']:
                raise AssertionError('hostile edit did not change its actual baseline: ' + name)
            try: verify(mode, baselines[mode]['lines'] if lines is None else lines, data)
            except C.TraceError as error: result = {'mode': mode, 'mutation': name, 'rejected': True, 'error': str(error)}
            else: result = {'mode': mode, 'mutation': name, 'rejected': False}
            report['mutations'].append(result)

        for mode in C.MODES:
            trace = capture / (mode + '.trace.txt'); archive = build / 'relocated Python source apps' / (mode + '.glue')
            baseline = {'lines': trace.read_text().splitlines(keepends=True), 'size': archive.stat().st_size, 'actual': C.archive_record(archive, mode)}
            baselines[mode] = baseline
            streams = tuple(capture / (mode + '.' + stream + '.txt') for stream in ('stdout', 'stderr'))
            if tuple(path.read_bytes() for path in streams) != C.expected_output(mode):
                raise RuntimeError('actual retained output differs: ' + mode)
            exit_status = int((capture / (mode + '.exit-status.txt')).read_text().strip())
            expected_status = 0 if mode in ('minimal', 'resources') else 1
            if exit_status != expected_status:
                raise RuntimeError('actual retained exit status differs: ' + mode)
            verify(mode, baseline['lines'])
            report['baselines'].append({'mode': mode, 'trace_sha256': sha(trace), 'records': len(baseline['lines']),
                'archive_sha256': baseline['actual']['sha256'], 'manifest_sha256': baseline['actual']['manifest_sha256'],
                'archive_bytes': baseline['size'], 'stdout_sha256': sha(streams[0]), 'stderr_sha256': sha(streams[1]),
                'stdout_bytes': streams[0].stat().st_size, 'stderr_bytes': streams[1].stat().st_size,
                'exit_status': exit_status, 'passed': True})

        for mode, baseline in baselines.items():
            lines = baseline['lines']; pid = int(lines[0].split()[0]); archive = C.archive_for(mode)
            uname = at(lines, '    uname('); close = at(lines, '    close(', at(lines, 'GLUERS00'))
            close = next(i for i,line in enumerate(lines) if '    close(' in line and archive + '>' in line)
            output = next(i for i,line in enumerate(lines) if re.search(r'\swrite\([12]</evidence/', line))
            payload = next(i for i in range(uname + 1,len(lines)) if '    read(' in lines[i] and archive + '>' in lines[i])
            prior = next(i for i in range(uname - 1,-1,-1) if '    read(' in lines[i] and archive + '>' in lines[i])
            hostile(mode, 'alternate executable', replace(lines,0,lines[0].replace(C.PROGRAM,'/tmp/glue')))
            hostile(mode, 'additional CLI argument', replace(lines,0,lines[0].replace('], ', ', "extra"], ',1)))
            hostile(mode, 'missing readiness', remove(lines,uname))
            hostile(mode, 'repeated readiness', insert(lines,uname,lines[uname]))
            hostile(mode, 'readiness before final metadata', move(lines,uname,prior))
            hostile(mode, 'readiness after payload read', move(lines,uname,payload + 1))
            hostile(mode, 'extra PID on readiness', replace(lines,uname,re.sub(r'^[0-9]+',str(pid + 1),lines[uname])))
            hostile(mode, 'archive close before payload verification', move(lines,close,uname + 1))
            hostile(mode, 'output evidence path substitution', replace(lines,output,lines[output].replace('/evidence/'+mode+'.','/evidence/other.')))
            hostile(mode, 'early output before readiness', move(lines,output,uname))
            hostile(mode, 'wrong completed exit', replace(lines,len(lines)-1,lines[-1].replace('exited with 0','exited with 1') if mode in ('minimal','resources') else lines[-1].replace('exited with 1','exited with 0')))
            exit_at = at(lines,'    exit_group(')
            poll = '[{fd=0</dev/null<char 1:3>>, events=0}, '+f'{{fd=1</evidence/{mode}.stdout.txt>, events=0}}, {{fd=2</evidence/{mode}.stderr.txt>, events=0}}]'
            hostile(mode,'stdio poll after exit_group',insert(lines,exit_at+1,call(pid,f'ppoll({poll}, 3, {{tv_sec=0, tv_nsec=0}}, NULL, 0) = 0 (Timeout)')))

            if mode != 'corrupt-source':
                for text,label in [('F_ADD_SEALS','missing complete seal request'),('F_GET_SEALS','missing seal verification'),('832) = 832','missing alias ELF header'),('st_size=73563968','missing alias FD metadata'),('20489360','missing loader reservation'),('40960, PROT_NONE','missing image guard'),('533648, PROT_READ','missing anonymous BSS'),('1007616, PROT_READ','missing RELRO'),('2496, GRND_NONBLOCK','missing entropy'),('    gettid(','missing thread observation')]:
                    hostile(mode,label,remove(lines,at(lines,text,close + 1)))
                mapping = next(i for i,line in enumerate(lines) if '20423824, PROT_READ|PROT_EXEC' in line)
                base = int(re.search(r'mmap\((0x[0-9a-f]+),',lines[mapping])[1],16)
                hostile(mode,'selected mapping returned another address',replace(lines,mapping,lines[mapping].rsplit(' = ',1)[0]+' = '+hex(base + 4096)+'\n'))
                hostile(mode,'writable executable selected mapping',replace(lines,mapping,lines[mapping].replace('PROT_READ|PROT_EXEC','PROT_READ|PROT_WRITE|PROT_EXEC')))
                hostile(mode,'live mapping unmapped before application/finalization',insert(lines,output,call(pid,f'munmap({base:#x}, 4096) = 0')))
                hostile(mode,'anonymous returned range overlaps image',insert(lines,output,call(pid,f'mmap(NULL, 4096, PROT_READ|PROT_WRITE, MAP_PRIVATE|MAP_ANONYMOUS, -1, 0) = {base:#x}')))
                hostile(mode,'additional workload entropy',insert(lines,output,call(pid,'getrandom("unexpected"..., 2496, GRND_NONBLOCK) = 2496')))
                hostile(mode,'additional thread observation',insert(lines,output,call(pid,f'gettid() = {pid}')))

        attempts = {
            'failed temporary file creation': 'openat(AT_FDCWD</build-target/runtime-empty>, "/tmp/image.so", O_RDWR|O_CREAT|O_EXCL, 0600) = -1 EACCES (Permission denied)',
            'failed O_TMPFILE creation': 'openat(AT_FDCWD</build-target/runtime-empty>, "/tmp", O_RDWR|O_TMPFILE, 0600) = -1 EACCES (Permission denied)',
            'failed source URI fallback': 'openat(AT_FDCWD</build-target/runtime-empty>, "glue://minimal.source/app/launch.py", O_RDONLY|O_CLOEXEC) = -1 ENOENT (No such file or directory)',
            'failed host source fallback': 'openat(AT_FDCWD</build-target/runtime-empty>, "/usr/lib/python3.13/json/__init__.py", O_RDONLY|O_CLOEXEC) = -1 ENOENT (No such file or directory)',
            'failed cache materialization': 'mkdir("/tmp/__pycache__", 0700) = -1 EACCES (Permission denied)',
            'failed subprocess creation': 'clone3({}, 64) = -1 ENOSYS (Function not implemented)',
        }
        for mode in ('minimal','resources','corrupt-source'):
            lines=baselines[mode]['lines']; pid=int(lines[0].split()[0]); position=at(lines,'    exit_group(')
            for name,source in attempts.items(): hostile(mode,name,insert(lines,position,call(pid,source)))

        for mode in ('minimal','resources','corrupt-source'):
            for kind in ('schema-bool','provider-debug-int','host-provider','missing-application','false-app-hash','false-readiness','false-manifest-digest','false-target'):
                data=copy.deepcopy(metadata); fact=data['archives'][mode]
                if kind=='schema-bool': data['schema_version']=False
                elif kind=='provider-debug-int': fact['provider']['abi']['debug']=0
                elif kind=='host-provider': fact['provider']['provisioning']['mode']='host'
                elif kind=='missing-application': fact['application']={}
                elif kind=='false-app-hash': fact['application'][fact['entry']]['sha256']='0'*64
                elif kind=='false-readiness': fact['readiness']['archive_read_bytes']+=1
                elif kind=='false-manifest-digest': fact['manifest_sha256']='0'*64
                else: fact['target']['page_sizes']=[16384]
                hostile(mode,kind,data=data)

        mode='corrupt-source'; lines=baselines[mode]['lines']; fact=baselines[mode]['actual']; archive=C.archive_for(mode)
        selected=next(i for i,line in enumerate(lines) if '    read(' in line and archive+'>' in line and '`nswer' in line and '12) = 12' in line)
        hostile(mode,'selected CRC payload omitted',remove(lines,selected))
        hostile(mode,'selected CRC byte substituted',replace(lines,selected,lines[selected].replace('`nswer','answer')))
        hostile(mode,'selected CRC read repeated',insert(lines,selected,lines[selected]))
        data=copy.deepcopy(metadata); data['archives'][mode]['corrupt_offset']+=1; hostile(mode,'false retained corruption offset',data=data)

    report.update({'elapsed_seconds':round(time.monotonic()-started,3),'baseline_count':len(report['baselines']),
                   'mutation_count':len(report['mutations']),'rejected_count':sum(case['rejected'] for case in report['mutations'])})
    report['passed']=report['baseline_count']==6 and report['rejected_count']==report['mutation_count']
    args.output.write_text(json.dumps(report,indent=2,sort_keys=True)+'\n')
    shutil.copyfile(Path(__file__),args.output.with_suffix('.py'))
    args.output.with_suffix('.commands.txt').write_text(' '.join(json.dumps(arg) for arg in [sys.executable]+sys.argv)+'\n')
    print(json.dumps({key:report[key] for key in ('baseline_count','mutation_count','rejected_count','passed','elapsed_seconds')}))
    for case in report['mutations']:
        if not case['rejected']: print(json.dumps(case),file=sys.stderr)
    return 0 if report['passed'] else 1


if __name__=='__main__':
    raise SystemExit(main())
