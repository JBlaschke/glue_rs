#!/usr/bin/env python3
"""Independent hostile edits of all sixteen complete actual install-only host captures."""
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
SCRIPT = ROOT / 'scripts/check-linux-python-install-host-source-app-trace.py'


def sha(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def at(lines, text, start=0):
    return next(i for i in range(start, len(lines)) if text in lines[i])


def remove(lines, index):
    return lines[:index] + lines[index + 1:]


def replace(lines, index, value):
    result = lines.copy(); result[index] = value; return result


def move(lines, index, destination):
    result = remove(lines, index); result.insert(destination - (index < destination), lines[index]); return result


def insert(lines, index, value):
    return lines[:index] + [value] + lines[index:]


def move_many(lines, indices, destination):
    selected = set(indices)
    retained = [line for i, line in enumerate(lines) if i not in selected]
    position = sum(i not in selected for i in range(destination))
    return retained[:position] + [lines[i] for i in sorted(indices)] + retained[position:]


def call(pid, value):
    return str(pid) + '    ' + value + '\n'


def source_block(lines, path):
    begin = next(i for i, line in enumerate(lines) if re.search(r'\sopenat\(', line) and json.dumps(path) in line and 'O_NOFOLLOW' in line)
    end = next(i for i in range(begin + 1, len(lines)) if re.search(r'\sclose\(', lines[i]) and path + '>' in lines[i])
    token = re.search(r' = ([0-9]+<[^>]+>)', lines[begin])[1]
    reads = [i for i in range(begin, end) if 'read(' + token in lines[i]]
    eof = next(i for i in reads if re.search(r', "", [0-9]+\)\s+= 0', lines[i]))
    after = next(i for i in range(eof + 1, end) if re.search(r'\s(?:statx|fstat|newfstatat)\(' + re.escape(token), lines[i]))
    return begin, end, token, reads, eof, after


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--capture', type=Path, required=True)
    parser.add_argument('--build', type=Path, required=True)
    parser.add_argument('--output', type=Path, required=True)
    parser.add_argument('--require-clean-capture', action='store_true')
    args = parser.parse_args()
    if not args.output.parent.is_dir(): parser.error('output parent must exist')
    capture, build = args.capture.resolve(), args.build.resolve()
    revision = (capture / 'source-revision.txt').read_text().strip()
    status = (capture / 'source-status.txt').read_text()
    current_revision = subprocess.check_output(['git', 'rev-parse', 'HEAD'], cwd=ROOT, text=True).strip()
    current_status = subprocess.check_output(['git', 'status', '--porcelain'], cwd=ROOT, text=True)
    if args.require_clean_capture and (status or current_status or revision != current_revision):
        parser.error('capture and checker must share a clean source checkpoint')
    spec = importlib.util.spec_from_file_location('independent_install_host_source_actual_audit', SCRIPT)
    C = importlib.util.module_from_spec(spec); spec.loader.exec_module(C)
    metadata = json.loads((capture / 'source-metadata.json').read_text())
    report = {'command': sys.argv, 'capture_revision': revision, 'capture_status': status,
              'capture_branch': (capture / 'source-branch.txt').read_text().strip(),
              'capture_metadata_sha256': sha(capture / 'source-metadata.json'),
              'repository_revision': current_revision, 'repository_status': current_status,
              'script_sha256': sha(Path(__file__)),
              'checker_sha256': {p.name: sha(p) for p in sorted((ROOT / 'scripts').glob('check-linux-python*trace.py'))},
              'source_inventory_sha256': sha(ROOT / 'fixtures/python-install-host-source-apps/source-pins.json'),
              'startup_caches': len(C.CACHE_SPECS), 'startup_cache_bytes': sum(x['size'] for x in C.CACHE_SPECS.values()),
              'cache_inventory_sha256': sha(ROOT / 'fixtures/python-install-host-source-apps/cache-pins.json'),
              'stdlib_sources': len(C.SPECS), 'stdlib_bytes': sum(x['size'] for x in C.SPECS.values()),
              'empty_stdlib_sources': sum(x['size'] == 0 for x in C.SPECS.values()),
              'baselines': [], 'mutations': [], 'accepted_rejection_shortcuts': []}
    started = time.monotonic(); baselines = {}
    with tempfile.TemporaryDirectory(prefix='glue-host-source-audit-') as temporary:
        info = Path(temporary) / 'metadata.json'

        def verify(mode, lines, data=metadata):
            baseline = baselines[mode]; info.write_text(json.dumps(data))
            fact = C.retained_metadata(info, mode, baseline['size'])
            if not C.SOURCE.typed_equal(fact, baseline['actual']): raise C.TraceError('retained metadata differs from actual archive')
            C.check_lines(lines, mode, baseline['size'], fact)

        def hostile(mode, name, lines=None, data=metadata):
            if lines is not None and lines == baselines[mode]['lines']: raise AssertionError('no-op mutation: ' + name)
            try: verify(mode, baselines[mode]['lines'] if lines is None else lines, data)
            except C.TraceError as error: outcome = {'mode': mode, 'mutation': name, 'rejected': True, 'error': str(error)}
            else: outcome = {'mode': mode, 'mutation': name, 'rejected': False}
            report['mutations'].append(outcome)

        for mode in C.MODES:
            trace = capture / (mode + '.trace.txt'); archive = build / 'relocated Python install host source apps' / (mode + '.glue')
            baseline = {'lines': trace.read_text().splitlines(keepends=True), 'size': archive.stat().st_size, 'actual': C.archive_record(archive, mode)}
            baselines[mode] = baseline
            streams = tuple(capture / (mode + '.' + name + '.txt') for name in ('stdout', 'stderr'))
            if tuple(p.read_bytes() for p in streams) != C.expected_output(mode): raise RuntimeError('output differs: ' + mode)
            exit_status = int((capture / (mode + '.exit-status.txt')).read_text())
            if exit_status != (0 if mode in C.SUCCESS else 1): raise RuntimeError('exit status differs: ' + mode)
            verify(mode, baseline['lines'])
            report['baselines'].append({'mode': mode, 'trace_sha256': sha(trace), 'records': len(baseline['lines']),
                'archive_sha256': baseline['actual']['sha256'], 'manifest_sha256': baseline['actual']['manifest_sha256'],
                'archive_bytes': baseline['size'], 'stdout_sha256': sha(streams[0]), 'stderr_sha256': sha(streams[1]),
                'stdout_bytes': streams[0].stat().st_size, 'stderr_bytes': streams[1].stat().st_size,
                'exit_status': exit_status, 'passed': True})

        for mode, baseline in baselines.items():
            lines = baseline['lines']; pid = int(lines[0].split()[0]); archive = C.archive_for(mode)
            uname = next(i for i, line in enumerate(lines) if re.search(r'\suname\(', line))
            close = next(i for i, line in enumerate(lines) if re.search(r'\sclose\(', line) and archive + '>' in line)
            output = next(i for i, line in enumerate(lines) if re.search(r'\swrite\([12]</evidence/', line))
            payload = next(i for i in range(uname + 1, len(lines)) if re.search(r'\sread\(', lines[i]) and archive + '>' in lines[i])
            prior = next(i for i in range(uname - 1, -1, -1) if re.search(r'\sread\(', lines[i]) and archive + '>' in lines[i])
            exit_at = next(i for i, line in enumerate(lines) if re.search(r'\sexit_group\(', line))
            hostile(mode, 'alternate executable', replace(lines, 0, lines[0].replace(C.PROGRAM, '/tmp/glue')))
            hostile(mode, 'extra application argument', replace(lines, 0, lines[0].replace('], ', ', "extra"], ', 1)))
            hostile(mode, 'archive path substitution', [line.replace(archive, archive + '.other') for line in lines])
            hostile(mode, 'missing readiness', remove(lines, uname))
            hostile(mode, 'duplicate readiness', insert(lines, uname, lines[uname]))
            hostile(mode, 'readiness before final metadata', move(lines, uname, prior))
            hostile(mode, 'payload before readiness', move(lines, uname, payload + 1))
            hostile(mode, 'extra PID', replace(lines, uname, re.sub(r'^[0-9]+', str(pid + 1), lines[uname])))
            hostile(mode, 'archive closes before payload verification', move(lines, close, uname + 1))
            if mode != 'corrupt-source':
                hostile(mode, 'payload read omitted', remove(lines, payload))
            else:
                # Rejecting the selected bad member does not claim that other
                # positive resource bodies were read. Keep this explicit control
                # separate from required metadata/corrupt-source/lifetime guards.
                shortened = remove(lines, payload)
                verify(mode, shortened)
                report['accepted_rejection_shortcuts'].append({
                    'mode': mode, 'control': 'unrelated pristine entry read omitted before CRC rejection',
                    'accepted': True, 'removed_read_sha256': hashlib.sha256(lines[payload].encode()).hexdigest(),
                    'changed_trace_sha256': hashlib.sha256(''.join(shortened).encode()).hexdigest(),
                    'reason': 'Complete metadata and selected corrupt bytes remain admitted; readers close and no host provider is acquired.'})
            hostile(mode, 'output path substitution', replace(lines, output, lines[output].replace('/evidence/' + mode + '.', '/evidence/other.')))
            hostile(mode, 'publication before readiness', move(lines, output, uname))
            hostile(mode, 'failed output write', replace(lines, output, lines[output].rsplit(' = ', 1)[0] + ' = 0\n'))
            hostile(mode, 'wrong exit group', replace(lines, exit_at, call(pid, 'exit_group(1) = ?' if mode in C.SUCCESS else 'exit_group(0) = ?')))
            hostile(mode, 'wrong process completion', replace(lines, len(lines) - 1, lines[-1].replace('exited with 0', 'exited with 1') if mode in C.SUCCESS else lines[-1].replace('exited with 1', 'exited with 0')))
            poll = '[{fd=0</dev/null<char 1:3>>, events=0}, ' + f'{{fd=1</evidence/{mode}.stdout.txt>, events=0}}, {{fd=2</evidence/{mode}.stderr.txt>, events=0}}]'
            hostile(mode, 'poll after exit_group', insert(lines, exit_at + 1, call(pid, f'ppoll({poll}, 3, {{tv_sec=0, tv_nsec=0}}, NULL, 0) = 0 (Timeout)')))
            attempts = {
                'failed temporary create': 'openat(' + C.COMMON.CWD + ', "/tmp/native.so", O_RDWR|O_CREAT|O_EXCL, 0600) = -1 EACCES (Permission denied)',
                'failed O_TMPFILE': 'openat(' + C.COMMON.CWD + ', "/tmp", O_RDWR|O_TMPFILE, 0600) = -1 EACCES (Permission denied)',
                'failed virtual source fallback': 'openat(' + C.COMMON.CWD + ', "glue://minimal.source/app/launch.py", O_RDONLY|O_CLOEXEC) = -1 ENOENT (No such file or directory)',
                'failed host source lure': 'openat(' + C.COMMON.CWD + ', ' + json.dumps(C.prefix_for(mode) + '/lib/python3.13/glue_host_extra.py') + ', O_RDONLY|O_CLOEXEC) = -1 ENOENT (No such file or directory)',
                'failed native source lure': 'openat(' + C.COMMON.CWD + ', ' + json.dumps(C.prefix_for(mode) + '/lib/python3.13/glue_host_extra.cpython-313-aarch64-linux-gnu.so') + ', O_RDONLY|O_CLOEXEC) = -1 ENOENT (No such file or directory)',
                'failed cache creation': 'mkdir("/tmp/__pycache__", 0700) = -1 EACCES (Permission denied)',
                'failed subprocess': 'clone3({}, 64) = -1 ENOSYS (Function not implemented)',
                'failed extra executable': 'execve("/bin/sh", ["sh"], NULL) = -1 EACCES (Permission denied)',
                'failed network': 'socket(AF_INET, SOCK_STREAM, 0) = -1 EPERM (Operation not permitted)',
                'bundled fallback attempt': 'memfd_create("unexpected", MFD_CLOEXEC|MFD_ALLOW_SEALING) = -1 ENOSYS (Function not implemented)',
            }
            for name, source in attempts.items(): hostile(mode, name, insert(lines, output, call(pid, source)))

            if mode not in C.INITIALIZED: continue
            stdlib = C.prefix_for(mode) + '/lib/python3.13'
            selected_path = stdlib + '/' + C.CONTROL_SOURCE
            begin, end, token, reads, eof, post = source_block(lines, selected_path)
            hostile(mode, 'unused pinned source snapshot omitted', lines[:begin - 1] + lines[end + 1:])
            hostile(mode, 'snapshot EOF omitted', remove(lines, eof))
            hostile(mode, 'snapshot EOF duplicated', insert(lines, eof, lines[eof]))
            hostile(mode, 'snapshot post-read metadata omitted', remove(lines, post))
            hostile(mode, 'snapshot metadata before EOF', move(lines, post, eof))
            hostile(mode, 'snapshot close before EOF', move(lines, end, eof))
            hostile(mode, 'snapshot source descriptor remains open', remove(lines, end))
            hostile(mode, 'snapshot returns one extra source byte', replace(lines, reads[0], re.sub(r' = ([0-9]+)\n$', lambda m: ' = ' + str(int(m[1]) + 1) + '\n', lines[reads[0]])))
            alias = next(i for i, line in enumerate(lines) if re.search(r'\sopenat\(', line) and re.search(r'"/proc/self/fd/[0-9]+"', line))
            zero_key = next(k for k, v in C.SPECS.items() if v['size'] == 0)
            zbegin, zend, ztoken, zreads, zeof, zpost = source_block(lines, stdlib + '/' + zero_key)
            hostile(mode, 'empty pinned source EOF omitted', remove(lines, zeof))
            hostile(mode, 'empty pinned source returns data', replace(lines, zeof, re.sub(r', "", [0-9]+\)\s+= 0', ', "x", 1) = 1', lines[zeof])))
            hostile(mode, 'empty source closes before EOF', move(lines, zend, zeof))
            cache = next(i for i, line in enumerate(lines) if stdlib + '/' + C.CONTROL_CACHE in line and 'ENOENT' in line)
            hostile(mode, 'unused deep cache check omitted', remove(lines, cache))
            shadow = next(i for i, line in enumerate(lines) if stdlib + '/codecs.so"' in line)
            if mode == 'minimal':
                encoding_path = stdlib + '/encodings/__init__.py'
                opens = [i for i, line in enumerate(lines) if 'openat(' in line and json.dumps(encoding_path) in line and 'O_NOFOLLOW' in line]
                fresh = opens[1] - 1
                assert json.dumps(encoding_path) in lines[fresh] and 'AT_SYMLINK_NOFOLLOW' in lines[fresh]
                hostile(mode, 'fresh snapshot pre-stat omitted despite prior startup metadata', remove(lines, fresh))
            else:
                hostile(mode, 'startup native exclusion omitted', remove(lines, shadow))
            enum = next(i for i, line in enumerate(lines) if 'getdents64(' in line and '/encodings>' in line and re.search(r'/\* [1-9][0-9]* entries \*/', line))
            hostile(mode, 'startup directory inventory omitted', remove(lines, enum))
            lib = C.prefix_for(mode) + '/lib/libpython3.13.so.1.0'
            lib_begin = next(i for i, line in enumerate(lines) if 'openat(' in line and json.dumps(lib) in line and 'O_NOFOLLOW' in line)
            libtoken = re.search(r' = ([0-9]+<[^>]+>)', lines[lib_begin])[1]
            libeof = next(i for i in range(lib_begin + 1, alias) if 'read(' + libtoken in lines[i] and re.search(r', "", [0-9]+\)\s+= 0', lines[i]))
            libpost = next(i for i in range(libeof + 1, alias) if re.search(r'\s(?:statx|fstat|newfstatat)\(' + re.escape(libtoken), lines[i]))
            hostile(mode, 'library hash EOF omitted', remove(lines, libeof))
            hostile(mode, 'library metadata before EOF', move(lines, libpost, libeof))
            hostile(mode, 'library descriptor closes before loading', insert(lines, alias, call(pid, 'close(' + libtoken + ') = 0')))
            startup_path = stdlib + '/encodings/latin_1.py'
            startup_open = next(i for i, line in enumerate(lines) if 'openat(' in line and json.dumps(startup_path) in line and 'O_NOFOLLOW' in line)
            startup_token = re.search(r' = ([0-9]+<[^>]+>)', lines[startup_open])[1]
            startup_close = next(i for i in range(startup_open + 1, len(lines)) if 'close(' + startup_token in lines[i])
            if mode == 'minimal':
                lease_closes = []
                for name in C.STARTUP:
                    path = stdlib + '/' + name
                    opened = next(i for i, line in enumerate(lines) if 'openat(' in line and json.dumps(path) in line and 'O_NOFOLLOW' in line)
                    token = re.search(r' = ([0-9]+<[^>]+>)', lines[opened])[1]
                    lease_closes.append(next(i for i in range(opened + 1, len(lines)) if 'close(' + token in lines[i]))
                assert len(lease_closes) == 6
                hostile(mode, 'all six startup owners close before loader', move_many(lines, lease_closes, alias))
            else:
                hostile(mode, 'startup source owner closes before loader', move(lines, startup_close, alias))
            for text, label in [('832) = 832', 'alias header omitted'), ('20489360', 'reservation omitted'), ('40960, PROT_NONE', 'guard omitted'), ('533648, PROT_READ', 'BSS omitted'), ('1007616, PROT_READ', 'RELRO omitted'), ('2496, GRND_NONBLOCK', 'entropy omitted')]:
                hostile(mode, label, remove(lines, at(lines, text, alias)))
            tid = next(i for i, line in enumerate(lines) if re.search(r'\sgettid\(', line)); hostile(mode, 'gettid omitted', remove(lines, tid))
            mapping = next(i for i, line in enumerate(lines) if '20423824, PROT_READ|PROT_EXEC' in line)
            base = int(re.search(r'mmap\((0x[0-9a-f]+),', lines[mapping])[1], 16)
            if mode == 'minimal':
                second = next(i for i in range(mapping + 1, len(lines)) if '1695744, PROT_READ|PROT_WRITE' in lines[i])
                swapped = lines.copy()
                swapped[mapping] = lines[mapping].replace('20423824, PROT_READ|PROT_EXEC', '1695744, PROT_READ|PROT_WRITE').replace(', 0) = ', ', 0x115a000) = ')
                swapped[second] = lines[second].replace('1695744, PROT_READ|PROT_WRITE', '20423824, PROT_READ|PROT_EXEC').replace(', 0x115a000) = ', ', 0) = ')
                hostile(mode, 'selected segments swap RX and RW roles at retained bases', swapped)
            else:
                hostile(mode, 'selected mapping changes returned address', replace(lines, mapping, lines[mapping].rsplit(' = ', 1)[0] + ' = ' + hex(base + 4096) + '\n'))
            hostile(mode, 'selected mapping writable executable', replace(lines, mapping, lines[mapping].replace('PROT_READ|PROT_EXEC', 'PROT_READ|PROT_WRITE|PROT_EXEC')))
            if mode == 'minimal':
                directories = {str(parent) for key in C.SPECS for parent in Path(stdlib + '/' + key).parents} | {stdlib + '/encodings/__pycache__'}
                cache_paths = {stdlib + '/' + key for key in C.CACHE_SPECS}
                startup_paths = {stdlib + '/' + key for key in C.STARTUP}
                closes = []
                for i in range(output + 1, len(lines)):
                    match = re.search(r'\sclose\([0-9]+<([^>]+)>\)', lines[i])
                    if match and match[1] in directories | startup_paths | cache_paths: closes.append(i)
                assert len(closes) == 164
                hostile(mode, 'all164 retained leases close before success stdout', move_many(lines, closes, output))
            else:
                hostile(mode, 'live image unmapped', insert(lines, output, call(pid, f'munmap({base:#x}, 4096) = 0')))
            hostile(mode, 'anonymous returned image overlap', insert(lines, output, call(pid, f'mmap(NULL, 4096, PROT_READ|PROT_WRITE, MAP_PRIVATE|MAP_ANONYMOUS, -1, 0) = {base:#x}')))
            hostile(mode, 'extra thread observation', insert(lines, output, call(pid, f'gettid() = {pid}')))
            remap = next(i for i, line in enumerate(lines) if 'mremap(' in line)
            hostile(mode, 'source parser growth omitted', remove(lines, remap))

        for mode in C.INITIALIZED:
            lines = baselines[mode]['lines']; pid = int(lines[0].split()[0])
            stdlib = C.prefix_for(mode) + '/lib/python3.13'
            alias = next(i for i, line in enumerate(lines) if re.search(r'\sopenat\(', line) and re.search(r'"/proc/self/fd/[0-9]+"', line))
            output = next(i for i, line in enumerate(lines) if re.search(r'\swrite\([12]</evidence/', line))
            cache_dir = stdlib + '/encodings/__pycache__'
            enumerated = next(i for i, line in enumerate(lines) if 'getdents64(' in line and cache_dir + '>' in line and '5 entries' in line)
            ended = next(i for i in range(enumerated + 1, len(lines)) if 'getdents64(' in lines[i] and cache_dir + '>' in lines[i] and '0 entries' in lines[i])
            hostile(mode, 'closed startup cache inventory omitted', remove(lines, enumerated))
            hostile(mode, 'closed startup cache EOF omitted', remove(lines, ended))
            hostile(mode, 'extra unverified cache entry appears in inventory', replace(lines, enumerated, lines[enumerated].replace('5 entries', '6 entries')))
            cache_closes = []
            for key in C.CACHE_SPECS:
                path = stdlib + '/' + key
                begin, end, token, reads, eof, post = source_block(lines, path)
                cache_closes.append(end)
                rewind = next(i for i in range(post + 1, alias) if 'lseek(' + token in lines[i] and 'SEEK_SET' in lines[i])
                hostile(mode, key + ': cache verification read omitted', remove(lines, reads[0]))
                hostile(mode, key + ': cache hash EOF omitted', remove(lines, eof))
                hostile(mode, key + ': cache post-hash metadata omitted', remove(lines, post))
                hostile(mode, key + ': cache metadata before EOF', move(lines, post, eof))
                hostile(mode, key + ': cache rewind omitted', remove(lines, rewind))
                hostile(mode, key + ': cache owner closes before loading', move(lines, end, alias))
                if mode in C.SUCCESS:
                    hostile(mode, key + ': cache owner closes before application output', move(lines, end, output))
                hostile(mode, key + ': fresh cache pre-open metadata omitted', remove(lines, begin - 1))
                header = next(i for i in reads if '\\363\\r\\r\\n' in lines[i])
                hostile(mode, key + ': cache magic differs', replace(lines, header, lines[header].replace('\\363\\r\\r\\n', '\\362\\r\\r\\n', 1)))
                raw_begin = next(i for i in range(alias + 1, len(lines)) if 'openat(' in lines[i] and json.dumps(path) in lines[i])
                if mode not in C.SUCCESS:
                    hostile(mode, key + ': cache owner closes before completed startup', move(lines, end, raw_begin))
                raw_token = re.search(r' = ([0-9]+<[^>]+>)', lines[raw_begin])[1]
                raw_end = next(i for i in range(raw_begin + 1, len(lines)) if 'close(' + raw_token in lines[i])
                raw_read = next(i for i in range(raw_begin + 1, raw_end) if 'read(' + raw_token in lines[i] and not re.search(r', "", [0-9]+\)\s+= 0', lines[i]))
                raw_eof = next(i for i in range(raw_read + 1, raw_end) if 'read(' + raw_token in lines[i] and re.search(r', "", [0-9]+\)\s+= 0', lines[i]))
                hostile(mode, key + ': stale cache read omitted', remove(lines, raw_read))
                hostile(mode, key + ': stale cache EOF omitted', remove(lines, raw_eof))
                source = path.replace('/__pycache__/', '/').removesuffix('.cpython-313.pyc') + '.py'
                source_open = next(i for i in range(raw_end + 1, len(lines)) if 'openat(' in lines[i] and json.dumps(source) in lines[i] and 'O_NOFOLLOW' not in lines[i])
                source_token = re.search(r' = ([0-9]+<[^>]+>)', lines[source_open])[1]
                source_close = next(i for i in range(source_open + 1, len(lines)) if 'close(' + source_token in lines[i])
                block = list(range(source_open, source_close + 1))
                hostile(mode, key + ': source read moves before stale cache', move_many(lines, block, raw_begin))
            hostile(mode, 'all three cache owners close before loading', move_many(lines, cache_closes, alias))
            if mode in C.SUCCESS:
                hostile(mode, 'all three cache owners close before successful application stdout', move_many(lines, cache_closes, output))
            last_raw_close = max(i for i, line in enumerate(lines) if re.search(r'\sclose\(', line) and any(stdlib + '/' + key + '>' in line for key in C.RAW_IMPORTS) and i < output)
            source = stdlib + '/encodings/__init__.py'
            late = call(pid, f'newfstatat({C.COMMON.CWD}, {json.dumps(source)}, {{st_mode=S_IFREG|0444, st_size=6020, ...}}, 0) = 0')
            hostile(mode, 'filesystem source metadata after completed startup closure', insert(lines, last_raw_close + 1, late))

        for mode in ('minimal', 'stdlib', 'corrupt-source', 'missing-source'):
            for kind in ('schema-bool', 'debug-int', 'prefix-lie', 'discovery-lie', 'missing-application', 'false-app-hash', 'false-readiness', 'false-manifest-digest', 'false-target', 'false-size'):
                data = copy.deepcopy(metadata); fact = data['archives'][mode]
                if kind == 'schema-bool': data['schema_version'] = False
                elif kind == 'debug-int': fact['provider']['abi']['debug'] = 0
                elif kind == 'prefix-lie': fact['provider']['provisioning']['stdlib'] += '/other'
                elif kind == 'discovery-lie': fact['provider']['provisioning']['discovery'] = 'environment'
                elif kind == 'missing-application': fact['application'] = {}
                elif kind == 'false-app-hash': fact['application'][fact['entry']]['sha256'] = '0' * 64
                elif kind == 'false-readiness': fact['readiness']['archive_read_bytes'] += 1
                elif kind == 'false-manifest-digest': fact['manifest_sha256'] = '0' * 64
                elif kind == 'false-target': fact['target']['page_sizes'] = [16384]
                else: fact['bytes'] += 1
                hostile(mode, kind, data=data)
        mode = 'corrupt-source'; lines = baselines[mode]['lines']; archive = C.archive_for(mode)
        selected = next(i for i, line in enumerate(lines) if 'read(' in line and archive + '>' in line and '`nswer' in line and '12) = 12' in line)
        hostile(mode, 'corrupt selected bytes omitted', remove(lines, selected))
        hostile(mode, 'corrupt byte substituted', replace(lines, selected, lines[selected].replace('`nswer', 'answer')))
        hostile(mode, 'corrupt read repeats', insert(lines, selected, lines[selected]))
        data = copy.deepcopy(metadata); data['archives'][mode]['corrupt_offset'] += 1; hostile(mode, 'false corrupt offset', data=data)

    report.update({'elapsed_seconds': round(time.monotonic() - started, 3), 'baseline_count': len(report['baselines']),
                   'mutation_count': len(report['mutations']), 'rejected_count': sum(x['rejected'] for x in report['mutations'])})
    report['passed'] = report['baseline_count'] == 16 and report['rejected_count'] == report['mutation_count']
    args.output.write_text(json.dumps(report, indent=2, sort_keys=True) + '\n')
    shutil.copyfile(Path(__file__), args.output.with_suffix('.py'))
    args.output.with_suffix('.commands.txt').write_text(' '.join(json.dumps(x) for x in [sys.executable] + sys.argv) + '\n')
    print(json.dumps({k: report[k] for k in ('baseline_count', 'mutation_count', 'rejected_count', 'passed', 'elapsed_seconds')}))
    for case in report['mutations']:
        if not case['rejected']: print(json.dumps(case), file=sys.stderr)
    return 0 if report['passed'] else 1


if __name__ == '__main__':
    raise SystemExit(main())
