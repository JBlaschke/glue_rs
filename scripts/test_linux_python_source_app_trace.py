"""Hostile controls for the separate bundled source-application trace policy."""

import copy
import gzip
import hashlib
import importlib.util
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest


def load(filename, name):
    spec = importlib.util.spec_from_file_location(name, Path(__file__).with_name(filename))
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


C = load('check-linux-python-source-app-trace.py', 'source_app_policy_test')
B = load('test_linux_python_import_trace.py', 'source_app_base_fixture')
SIZE = B.CHECKER.ARCHIVE_BYTES
CWD = B.CWD
IMAGE, ALIAS = B.IMAGE, B.ALIAS
BASE = 0x5000000
RESERVATION = BASE - 49152
UNAME = 'uname({sysname="Linux", nodename="source-tests", ...}) = 0'


def application(mode):
    input_mode = {'app-error': 'error', 'corrupt-source': 'minimal'}.get(mode, mode)
    directory = Path(__file__).resolve().parents[1] / 'fixtures/python-source-apps' / ('input-' + input_mode)
    return {p.relative_to(directory).as_posix(): {'size': p.stat().st_size,
            'sha256': hashlib.sha256(p.read_bytes()).hexdigest(), 'compression': 'stored'}
            for p in directory.rglob('*') if p.is_file()}


def record(mode='minimal'):
    app_id, entry, component = C.IDENTITIES[mode]
    result = {'bytes': SIZE, 'sha256': 'a' * 64, 'manifest_sha256': 'b' * 64,
              'manifest_bytes': 64, 'zip_directory_offset': SIZE - 22,
              'app_id': app_id, 'entry': entry, 'component': component,
              'application': application(mode),
              'provider': C.provider_contract(), 'target': copy.deepcopy(C.TARGET),
              'readiness': {'archive_read_bytes': 150, 'archive_cursor': 128,
                            'ranges_sha256': C.PRODUCT.range_digest([(0, 128), (SIZE - 22, SIZE)])}}
    if mode == 'corrupt-source':
        result['corrupt_offset'] = 4096
    return result


def fixture(mode='minimal'):
    archive = f'3<{C.archive_for(mode)}>'
    lines = [
        f'execve({json.dumps(C.PROGRAM)}, {json.dumps([C.PROGRAM, "run", C.archive_for(mode)])}, 0x1234 /* 18 vars */) = 0',
        f'openat({CWD}, {json.dumps(C.archive_for(mode))}, O_RDONLY|O_CLOEXEC) = {archive}',
        f'lseek({archive}, 0, SEEK_END) = {SIZE}',
        f'lseek({archive}, 0, SEEK_SET) = 0',
        f'read({archive}, "GLUERS00 locator"..., 64) = 64',
        'mmap(NULL, 266240, PROT_READ|PROT_WRITE, MAP_PRIVATE|MAP_ANONYMOUS, -1, 0) = 0x3000000',
        'mremap(0x3000000, 266240, 528384, MREMAP_MAYMOVE) = 0x4000000',
        f'read({archive}, "complete manifest"..., 64) = 64',
        f'lseek({archive}, {SIZE - 22}, SEEK_SET) = {SIZE - 22}',
        f'read({archive}, "complete ZIP directory"..., 22) = 22',
        f'lseek({archive}, 128, SEEK_SET) = 128',
        UNAME,
    ]
    if mode == 'corrupt-source':
        lines += [f'lseek({archive}, 4096, SEEK_SET) = 4096',
                  f'read({archive}, {json.dumps(C.CORRUPT_BYTES.decode())}, {len(C.CORRUPT_BYTES)}) = {len(C.CORRUPT_BYTES)}',
                  f'close({archive}) = 0']
    else:
        lines += [f'read({archive}, "complete payload"..., {SIZE - 150}) = {SIZE - 150}',
                  f'lseek({archive}, {SIZE - 20}, SEEK_SET) = {SIZE - 20}',
                  f'read({archive}, "ZIP probe"..., 20) = 20',
                  f'close({archive}) = 0',
                  f'memfd_create("{B.CHECKER.MEMFD}", MFD_CLOEXEC|MFD_ALLOW_SEALING|0x10) = {IMAGE}',
                  f'write({IMAGE}, {json.dumps(C.LIBRARY_PREFIX.decode("latin1"))}..., {B.CHECKER.LIBRARY_BYTES}) = {B.CHECKER.LIBRARY_BYTES}',
                  f'fcntl({IMAGE}, F_ADD_SEALS, F_SEAL_SEAL|F_SEAL_SHRINK|F_SEAL_GROW|F_SEAL_WRITE) = 0',
                  f'fcntl({IMAGE}, F_GET_SEALS) = 0xf (seals F_SEAL_SEAL|F_SEAL_SHRINK|F_SEAL_GROW|F_SEAL_WRITE)',
                  f'openat({CWD}, "/proc/self/fd/3", O_RDONLY|O_CLOEXEC) = {ALIAS}',
                  f'read({ALIAS}, {json.dumps(C.LIBRARY_PREFIX.decode("latin1"))}..., 832) = 832',
                  f'newfstatat({ALIAS}, "", {{st_mode=S_IFREG|0777, st_size={B.CHECKER.LIBRARY_BYTES}, ...}}, AT_EMPTY_PATH) = 0',
                  f'mmap(NULL, 20489360, PROT_NONE, MAP_PRIVATE|MAP_ANONYMOUS, -1, 0) = {RESERVATION:#x}',
                  f'mmap({BASE:#x}, 20423824, PROT_READ|PROT_EXEC, MAP_PRIVATE|MAP_FIXED|MAP_DENYWRITE, {ALIAS}, 0) = {BASE:#x}',
                  f'munmap({RESERVATION:#x}, 49152) = 0',
                  f'munmap({BASE + 20426752:#x}, 13456) = 0',
                  f'mprotect({BASE + 0x1150000:#x}, 40960, PROT_NONE) = 0',
                  f'mmap({BASE + 0x115a000:#x}, 1695744, PROT_READ|PROT_WRITE, MAP_PRIVATE|MAP_FIXED|MAP_DENYWRITE, {ALIAS}, 0x115a000) = {BASE + 0x115a000:#x}',
                  f'mmap({BASE + 0x12f8000:#x}, 533648, PROT_READ|PROT_WRITE, MAP_PRIVATE|MAP_FIXED|MAP_ANONYMOUS, -1, 0) = {BASE + 0x12f8000:#x}',
                  f'close({ALIAS}) = 0',
                  f'mprotect({BASE + 0x115a000:#x}, 1007616, PROT_READ) = 0',
                  f'openat({CWD}, "{B.CHECKER.OVERCOMMIT}", O_RDONLY) = 4<{B.CHECKER.OVERCOMMIT}>',
                  f'read(4<{B.CHECKER.OVERCOMMIT}>, "0\\n", 32) = 2',
                  f'close(4<{B.CHECKER.OVERCOMMIT}>) = 0',
                  'gettid() = 1234',
                  f'readlinkat({CWD}, "/__glue_archive__/launcher", 0x1234, 4096) = -1 ENOENT (No such file or directory)',
                  f'openat({CWD}, "/usr/share/zoneinfo/UTC0", O_RDONLY|O_CLOEXEC) = -1 ENOENT (No such file or directory)']
        lines += ['getrandom("source workload seed"..., 2496, GRND_NONBLOCK) = 2496']
    for number, payload in enumerate(C.expected_output(mode), 1):
        if payload:
            lines.append(f'write({number}</evidence/{mode}.{"stdout" if number == 1 else "stderr"}.txt>, {json.dumps(payload.decode())}, {len(payload)}) = {len(payload)}')
    status = 0 if mode in ('minimal', 'resources') else 1
    return lines + [f'exit_group({status}) = ?', f'+++ exited with {status} +++']


def check(lines, mode='minimal', facts=None):
    C.check_lines((f'1234  {line}\n' for line in lines), mode, SIZE, record(mode) if facts is None else facts)


def index(lines, text):
    return next(i for i, line in enumerate(lines) if text in line)


def metadata():
    return {'schema_version': 0, 'archives': {mode: record(mode) for mode in C.MODES}}


def cli(directory, mode='minimal', data=None, compressed=False, lines=None):
    trace = directory / ('trace.txt.gz' if compressed else 'trace.txt')
    raw = ''.join('1234  ' + line + '\n' for line in (fixture(mode) if lines is None else lines)).encode()
    trace.write_bytes(gzip.compress(raw) if compressed else raw)
    stdout, stderr = directory / 'stdout.txt', directory / 'stderr.txt'
    stdout.write_bytes(C.expected_output(mode)[0]); stderr.write_bytes(C.expected_output(mode)[1])
    info = directory / 'metadata.json'; info.write_text(json.dumps(metadata() if data is None else data))
    return subprocess.run([sys.executable, str(Path(C.__file__)), str(trace), '--mode', mode,
                           '--archive-bytes', str(SIZE), '--metadata-file', str(info),
                           '--stdout-file', str(stdout), '--stderr-file', str(stderr)], capture_output=True, text=True)


class SourceAppTraceTests(unittest.TestCase):
    def reject(self, lines, mode='minimal', facts=None):
        with self.assertRaises(C.TraceError):
            check(lines, mode, facts)

    def test_all_six_complete_workloads_are_admitted(self):
        for mode in C.MODES:
            with self.subTest(mode=mode):
                check(fixture(mode), mode)

    def test_exact_exec_command_archive_and_inherited_paths(self):
        lines = fixture()
        for before, after in [(C.PROGRAM, '/tmp/glue'), ('"run"', '"run-imports"'),
                              (C.archive_for('minimal'), C.archive_for('resources')),
                              ('/evidence/minimal.', '/evidence/other.')]:
            self.reject([line.replace(before, after) for line in lines])
        mutant = lines.copy(); mutant[0] = mutant[0].replace('], ', ', "extra"], ', 1); self.reject(mutant)

    def test_readiness_once_after_metadata_before_payload_and_on_one_pid(self):
        lines = fixture(); at = lines.index(UNAME)
        self.reject(lines[:at] + lines[at + 1:])
        self.reject(lines[:at] + [UNAME, UNAME] + lines[at + 1:])
        for destination in (1, index(lines, 'complete manifest'), index(lines, 'complete payload') + 1):
            mutant = lines.copy(); mutant.remove(UNAME); mutant.insert(destination, UNAME); self.reject(mutant)
        for replacement in (UNAME.replace('Linux', 'Darwin'), UNAME.replace('= 0', '= -1 EPERM (Operation not permitted)')):
            mutant = lines.copy(); mutant[at] = replacement; self.reject(mutant)
        with self.assertRaises(C.TraceError):
            C.check_lines((f'{1235 if line == UNAME else 1234}  {line}\n' for line in lines), 'minimal', SIZE, record())

    def test_workload_entropy_and_thread_counts_and_phases_are_exact(self):
        for mode in ('minimal', 'resources', 'app-error', 'syntax', 'nul'):
            lines = fixture(mode)
            self.reject(lines[:-2] + ['getrandom("seed"..., 2496, GRND_NONBLOCK) = 2496'] + lines[-2:], mode)
            self.reject(lines[:-2] + ['gettid() = 1234'] + lines[-2:], mode)
            mutant = lines.copy(); mutant.remove('gettid() = 1234'); self.reject(mutant, mode)
            mutant = lines.copy(); mutant.pop(index(mutant, 'getrandom(')); self.reject(mutant, mode)
            mutant = lines.copy(); at = index(mutant, 'getrandom('); call = mutant.pop(at); mutant.insert(index(mutant, 'readlinkat'), call); self.reject(mutant, mode)
        lines = fixture('corrupt-source')
        for call in ('getrandom("seed"..., 2496, GRND_NONBLOCK) = 2496', 'gettid() = 1234'):
            self.reject(lines[:-2] + [call] + lines[-2:], 'corrupt-source')

    def test_full_image_population_and_both_seal_proofs_precede_alias(self):
        lines = fixture()
        for text in ('write(' + IMAGE, 'F_ADD_SEALS', 'F_GET_SEALS'):
            mutant = lines.copy(); mutant.pop(index(mutant, text)); self.reject(mutant)
        mutant = lines.copy(); at = index(mutant, 'write(' + IMAGE); mutant[at] = mutant[at].replace(str(B.CHECKER.LIBRARY_BYTES), str(B.CHECKER.LIBRARY_BYTES - 1)); self.reject(mutant)
        mutant = lines.copy(); at = index(mutant, 'F_GET_SEALS'); mutant[at] = mutant[at].replace('0xf', '0x7'); self.reject(mutant)
        mutant = lines.copy(); alias = mutant.pop(index(mutant, '"/proc/self/fd/3"')); mutant.insert(index(mutant, 'F_GET_SEALS'), alias); self.reject(mutant)

    def test_loader_reservation_guard_bss_relro_and_trims_are_required_once(self):
        lines = fixture()
        for text in ('20489360', '49152', '13456', '40960', '533648', '1007616'):
            mutant = lines.copy(); mutant.pop(index(mutant, text)); self.reject(mutant)
            mutant = lines.copy(); at = index(mutant, text); mutant.insert(at, mutant[at]); self.reject(mutant)

    def test_aligned_reservation_needs_no_zero_prefix_trim(self):
        lines = fixture(); reserve = index(lines, '20489360')
        lines[reserve] = lines[reserve].replace(hex(RESERVATION), hex(BASE))
        lines.pop(index(lines, '49152'))
        at = index(lines, '13456'); lines[at] = lines[at].replace('13456', str(20489360 - 20426752))
        check(lines)
        at = index(lines, '20423824')
        mutant = lines.copy(); mutant.insert(at + 1, f'munmap({BASE:#x}, 0) = 0'); self.reject(mutant)

    def test_trim_repeats_after_relro_and_zero_length_mutations_are_rejected(self):
        lines = fixture(); at = index(lines, '1007616') + 1
        for call in (f'munmap({RESERVATION:#x}, 49152) = 0',
                     f'munmap({BASE + 20426752:#x}, 13456) = 0',
                     f'mprotect({BASE:#x}, 0, PROT_READ) = 0',
                     f'munmap({BASE:#x}, 0) = 0'):
            with self.subTest(call=call):
                mutant = lines.copy(); mutant.insert(at, call); self.reject(mutant)

    def test_manifest_growth_uses_a_once_only_live_private_backing(self):
        lines = fixture(); at = index(lines, '266240, PROT_READ')
        mutant = lines.copy(); mutant.pop(at); self.reject(mutant)
        mutant = lines.copy(); mutant.insert(at, mutant[at]); self.reject(mutant)
        mutant = lines.copy(); mutant[at] = mutant[at].replace('PROT_READ|PROT_WRITE', 'PROT_READ|PROT_EXEC'); self.reject(mutant)
        mutant = lines.copy(); at = index(mutant, 'mremap('); mutant[at] = mutant[at].replace('266240, 528384', '299008, 593920'); self.reject(mutant)
        mutant = lines.copy(); at = index(mutant, 'mremap('); mutant.insert(at, 'munmap(0x3000000, 266240) = 0'); self.reject(mutant)

    def test_alias_header_metadata_closure_and_relro_precede_startup(self):
        lines = fixture()
        for text in ('read(' + ALIAS, 'st_size=' + str(B.CHECKER.LIBRARY_BYTES), 'close(' + ALIAS):
            with self.subTest(omitted=text):
                mutant = lines.copy(); mutant.pop(index(mutant, text)); self.reject(mutant)
        mutant = lines.copy(); at = index(mutant, '1007616'); call = mutant.pop(at); mutant.insert(index(mutant, 'close(' + ALIAS), call); self.reject(mutant)
        mutant = lines.copy(); at = index(mutant, '1007616'); call = mutant.pop(at); mutant.insert(index(mutant, 'read(4<' + B.CHECKER.OVERCOMMIT), call); self.reject(mutant)

    def test_corrupt_selected_read_must_be_once_final_and_closed_before_publication(self):
        lines = fixture('corrupt-source'); at = index(lines, 'close(3<')
        archive = f'3<{C.archive_for("corrupt-source")}>'
        mutant = lines.copy(); mutant[at:at] = [f'lseek({archive}, 128, SEEK_SET) = 128', f'read({archive}, "later payload", 13) = 13']; self.reject(mutant, 'corrupt-source')
        mutant = lines.copy(); selected = index(mutant, json.dumps(C.CORRUPT_BYTES.decode())); mutant[selected] = mutant[selected].replace(archive, '8<' + C.archive_for('corrupt-source') + '>'); self.reject(mutant, 'corrupt-source')

    def test_selected_file_mappings_keep_private_permissions_result_and_alias_ownership(self):
        lines = fixture(); at = index(lines, '20423824')
        for before, after in [('MAP_PRIVATE', 'MAP_SHARED'), ('PROT_READ|PROT_EXEC', 'PROT_READ|PROT_WRITE|PROT_EXEC'),
                              (ALIAS, IMAGE), (' = 0x5000000', ' = 0x7000000')]:
            mutant = lines.copy(); mutant[at] = mutant[at].replace(before, after); self.reject(mutant)

    def test_live_image_ranges_cannot_be_unmapped_or_overwritten(self):
        lines = fixture()
        for call in (f'munmap({BASE:#x}, 4096) = 0', f'mprotect({BASE + 4096:#x}, 4096, PROT_WRITE) = 0',
                     f'mmap({BASE + 4096:#x}, 4096, PROT_READ|PROT_WRITE, MAP_PRIVATE|MAP_FIXED|MAP_ANONYMOUS, -1, 0) = {BASE + 4096:#x}',
                     f'mmap(NULL, 4096, PROT_READ|PROT_WRITE, MAP_PRIVATE|MAP_ANONYMOUS, -1, 0) = {BASE + 4096:#x}'):
            self.reject(lines[:-2] + [call] + lines[-2:])

    def test_failed_fallback_mutation_network_and_process_attempts_reject(self):
        for mode in ('minimal', 'resources', 'corrupt-source'):
            lines = fixture(mode)
            for call in (f'openat({CWD}, "/tmp/python.py", O_RDONLY|O_CLOEXEC) = -1 ENOENT (No such file or directory)',
                         f'openat({CWD}, "glue://minimal.source/app/launch.py", O_RDONLY|O_CLOEXEC) = -1 ENOENT (No such file or directory)',
                         f'openat({CWD}, "/tmp/helper.so", O_WRONLY|O_CREAT|O_EXCL, 0600) = -1 EACCES (Permission denied)',
                         f'openat({CWD}, "/tmp", O_RDWR|O_TMPFILE, 0600) = -1 EACCES (Permission denied)',
                         'unlink("/tmp/helper.so") = -1 EACCES (Permission denied)',
                         'clone3({}, 64) = -1 ENOSYS (Function not implemented)',
                         'socket(AF_INET, SOCK_STREAM, 0) = -1 EPERM (Operation not permitted)',
                         'execve("/bin/sh", ["sh"], NULL) = -1 EACCES (Permission denied)'):
                self.reject(lines[:-2] + [call] + lines[-2:], mode)

    def test_negative_publication_requires_reader_closure_and_no_late_acquisition(self):
        for mode in ('app-error', 'syntax', 'nul', 'corrupt-source'):
            lines = fixture(mode); publication = index(lines, 'write(2<')
            mutant = lines.copy(); call = mutant.pop(publication); mutant.insert(index(mutant, UNAME), call); self.reject(mutant, mode)
            mutant = lines.copy(); mutant.pop(index(mutant, 'close(3<')); self.reject(mutant, mode)
            self.reject(lines[:-2] + [f'openat({CWD}, "/proc/self/maps", O_RDONLY|O_CLOEXEC) = 8</proc/1234/maps>'] + lines[-2:], mode)

    def test_records_after_exit_group_or_process_completion_reject(self):
        lines = fixture(); poll = '[{fd=0</dev/null<char 1:3>>, events=0}, {fd=1</evidence/minimal.stdout.txt>, events=0}, {fd=2</evidence/minimal.stderr.txt>, events=0}]'
        call = f'ppoll({poll}, 3, {{tv_sec=0, tv_nsec=0}}, NULL, 0) = 0 (Timeout)'
        self.reject(lines[:-1] + [call] + lines[-1:])
        self.reject(lines + [call])

    def test_corrupt_source_requires_exact_selected_bytes_offset_and_no_runtime(self):
        lines = fixture('corrupt-source'); at = index(lines, json.dumps(C.CORRUPT_BYTES.decode()))
        for before, after in [('`nswer', 'answer'), ('12) = 12', '11) = 11')]:
            mutant = lines.copy(); mutant[at] = mutant[at].replace(before, after); self.reject(mutant, 'corrupt-source')
        mutant = lines.copy(); mutant.pop(at); self.reject(mutant, 'corrupt-source')
        mutant = lines.copy(); mutant[at:at] = [lines[at]]; self.reject(mutant, 'corrupt-source')
        self.reject(lines[:-2] + [f'memfd_create("{B.CHECKER.MEMFD}", MFD_CLOEXEC|MFD_ALLOW_SEALING|0x10) = {IMAGE}'] + lines[-2:], 'corrupt-source')

    def test_cli_raw_and_gzip_accept_all_six_workloads(self):
        with tempfile.TemporaryDirectory() as temporary:
            for mode in C.MODES:
                for compressed in (False, True):
                    result = cli(Path(temporary), mode, compressed=compressed)
                    self.assertEqual(result.returncode, 0, result.stderr)

    def test_retained_metadata_shape_inventory_and_provider_drift_reject(self):
        with tempfile.TemporaryDirectory() as temporary:
            for kind in ('schema-bool', 'missing-application', 'application-null', 'extra-provider', 'application-hash', 'wrong-identity', 'readiness-bool'):
                data = metadata(); facts = data['archives']['minimal']
                if kind == 'schema-bool': data['schema_version'] = False
                elif kind == 'missing-application': del facts['application']
                elif kind == 'application-null': facts['application'] = None
                elif kind == 'extra-provider': facts['runtime'] = 'host'
                elif kind == 'application-hash': facts['application']['app/launch.py']['sha256'] = '0' * 64
                elif kind == 'wrong-identity': facts['entry'] = 'app/other.py'
                else: facts['readiness']['archive_read_bytes'] = True
                result = cli(Path(temporary), data=data)
                self.assertEqual(result.returncode, 1, (kind, result.stdout, result.stderr))
                self.assertNotIn('Traceback', result.stderr)

    def test_cli_requires_metadata_and_rejects_truncated_gzip_cleanly(self):
        with tempfile.TemporaryDirectory() as temporary:
            directory = Path(temporary)
            good = cli(directory, compressed=True)
            self.assertEqual(good.returncode, 0, good.stderr)
            missing = good.args.copy(); at = missing.index('--metadata-file'); del missing[at:at + 2]
            self.assertEqual(subprocess.run(missing, capture_output=True).returncode, 2)
            trace = directory / 'trace.txt.gz'; trace.write_bytes(trace.read_bytes()[:-8])
            bad = subprocess.run(good.args, capture_output=True, text=True)
            self.assertEqual(bad.returncode, 1, bad.stderr)
            self.assertNotIn('Traceback', bad.stderr)

    def test_pinned_visible_elf_prefix_cannot_be_omitted_or_substituted(self):
        lines = fixture(); at = index(lines, 'write(' + IMAGE)
        for visible in ('"unverified bytes"...', json.dumps(C.LIBRARY_PREFIX.decode('latin1')),
                        json.dumps((b'~ELF' + C.LIBRARY_PREFIX[4:]).decode('latin1')) + '...'):
            mutant = lines.copy(); mutant[at] = f'write({IMAGE}, {visible}, {B.CHECKER.LIBRARY_BYTES}) = {B.CHECKER.LIBRARY_BYTES}'; self.reject(mutant)

    def test_provider_target_and_application_spec_lies_reject(self):
        with tempfile.TemporaryDirectory() as temporary:
            for kind in ('host', 'gil', 'debug-int', 'revision-bool', 'provider-sha', 'page', 'kernel', 'native-entry', 'count', 'size', 'compression'):
                with self.subTest(kind=kind):
                    data = metadata(); facts = data['archives']['minimal']
                    if kind == 'host': facts['provider']['provisioning']['mode'] = 'host'
                    elif kind == 'gil': facts['provider']['abi']['gil'] = 'free_threaded'
                    elif kind == 'debug-int': facts['provider']['abi']['debug'] = 0
                    elif kind == 'revision-bool': facts['provider']['provisioning']['source']['revision'] = False
                    elif kind == 'provider-sha': facts['provider']['provisioning']['source']['sha256'] = '0' * 64
                    elif kind == 'page': facts['target']['page_sizes'] = [16384]
                    elif kind == 'kernel': facts['target']['minimum_os_version'] = '0'
                    elif kind == 'native-entry': facts['application']['app/hidden.so'] = {'size': 0, 'sha256': '0' * 64, 'compression': 'stored'}
                    elif kind == 'count': del facts['application']['app/python/simple_value.py']
                    elif kind == 'size': facts['application']['app/launch.py']['size'] += 1
                    else: facts['application']['app/launch.py']['compression'] = 'deflate'
                    bad = cli(Path(temporary), data=data)
                    self.assertEqual(bad.returncode, 1, (kind, bad.stdout, bad.stderr))
                    self.assertNotIn('Traceback', bad.stderr)

    def test_corrupt_metadata_complete_admission_cannot_be_faked_by_duplicate_reads(self):
        for section in ('manifest', 'ZIP'):
            with self.subTest(section=section):
                lines = fixture('corrupt-source'); facts = record('corrupt-source')
                if section == 'manifest':
                    at = index(lines, 'complete manifest')
                    archive = f'3<{C.archive_for("corrupt-source")}>'
                    lines[at:at + 1] = [f'lseek({archive}, 0, SEEK_SET) = 0', f'read({archive}, "GLUERS00 repeated"..., 64) = 64']
                    ranges = [(0, 64), (SIZE - 22, SIZE)]
                else:
                    at = index(lines, 'complete ZIP directory')
                    archive = f'3<{C.archive_for("corrupt-source")}>'
                    lines[at - 1:at + 1] = [f'lseek({archive}, 0, SEEK_SET) = 0', f'read({archive}, "repeated locator"..., 22) = 22']
                    ranges = [(0, 128)]
                facts['readiness']['ranges_sha256'] = C.PRODUCT.range_digest(ranges)
                self.reject(lines, 'corrupt-source', facts)

    def test_output_bytes_counts_encoding_status_and_retained_streams_are_exact(self):
        for mode in C.MODES:
            lines = fixture(mode); at = index(lines, 'write(' + ('1<' if mode in ('minimal', 'resources') else '2<'))
            for before, after in [(' = ', ' = '), ('</evidence/', '</tmp/')]:
                mutant = lines.copy()
                if before == ' = ': mutant[at] = mutant[at].rsplit(' = ', 1)[0] + ' = 0'
                else: mutant[at] = mutant[at].replace(before, after)
                self.reject(mutant, mode)
            mutant = lines.copy(); status = 0 if mode in ('minimal', 'resources') else 1
            mutant[-2] = f'exit_group({1 - status}) = ?'; mutant[-1] = f'+++ exited with {1 - status} +++'; self.reject(mutant, mode)
        with tempfile.TemporaryDirectory() as temporary:
            directory = Path(temporary); good = cli(directory)
            stdout = directory / 'stdout.txt'; stdout.write_bytes(stdout.read_bytes() + b'x')
            bad = subprocess.run(good.args, capture_output=True, text=True)
            self.assertEqual(bad.returncode, 1, bad.stderr)
            self.assertNotIn('Traceback', bad.stderr)


class SourcePreparationTests(unittest.TestCase):
    def fixture(self, directory):
        application = directory / 'application'; (application / 'app').mkdir(parents=True)
        (application / 'app/launch.py').write_bytes(b'pass\n')
        return application

    def reject(self, directory, application, expected):
        output = directory / 'output'
        script = Path(__file__).resolve().parents[1] / 'fixtures/python-source-apps/prepare.py'
        result = subprocess.run([sys.executable, str(script), str(directory / 'missing-base.glue'),
                                 str(application), str(output), '--app-id', 'helper.test', '--entry', 'app/launch.py'],
                                capture_output=True, text=True)
        self.assertEqual(result.returncode, 1, result.stderr)
        self.assertIn(expected, result.stderr)
        self.assertNotIn('missing-base', result.stderr)
        self.assertNotIn('Traceback', result.stderr)
        self.assertFalse(output.exists())

    def test_symlink_payload_and_directory_reject_before_base_read(self):
        for kind in ('file', 'directory'):
            with self.subTest(kind=kind), tempfile.TemporaryDirectory() as temporary:
                directory = Path(temporary); app = self.fixture(directory)
                if kind == 'file': (app / 'app/link.py').symlink_to('launch.py')
                else: (app / 'app/linked').symlink_to(app / 'app', target_is_directory=True)
                self.reject(directory, app, 'symlink')

    def test_resource_count_rejects_before_base_read(self):
        with tempfile.TemporaryDirectory() as temporary:
            directory = Path(temporary); app = self.fixture(directory); assets = app / 'app/assets'; assets.mkdir()
            for number in range(1024): (assets / f'{number}.txt').write_bytes(b'')
            self.reject(directory, app, 'inventory exceeds')

    def test_entry_per_file_and_combined_byte_bounds_reject_before_base_read(self):
        for kind in ('entry', 'file', 'total'):
            with self.subTest(kind=kind), tempfile.TemporaryDirectory() as temporary:
                directory = Path(temporary); app = self.fixture(directory)
                if kind == 'entry':
                    with (app / 'app/launch.py').open('wb') as stream: stream.truncate(64 * 1024 + 1)
                elif kind == 'file':
                    with (app / 'app/asset.bin').open('wb') as stream: stream.truncate(4 * 1024 * 1024 + 1)
                else:
                    for number in range(2):
                        with (app / f'app/{number}.bin').open('wb') as stream: stream.truncate(4 * 1024 * 1024)
                self.reject(directory, app, 'individual app payload' if kind != 'total' else 'inventory exceeds')

    def test_cache_and_native_suffixes_reject_case_insensitively_before_base_read(self):
        for key in ('app/value.PYC', 'app/value.pYo', 'app/library.SO', 'app/library.so.1',
                    'app/helper.EXE', 'app/helper.Node', 'app/helper.Bundle', 'app/__PyCache__/value.py'):
            with self.subTest(key=key), tempfile.TemporaryDirectory() as temporary:
                directory = Path(temporary); app = self.fixture(directory); path = app / key
                path.parent.mkdir(parents=True, exist_ok=True); path.write_bytes(b'asset')
                self.reject(directory, app, 'bytecode, cache and native')

    def test_nonportable_device_key_and_outside_root_reject_before_base_read(self):
        for key in ('app/NUL.txt', 'app/com1.py', 'outside.txt'):
            with self.subTest(key=key), tempfile.TemporaryDirectory() as temporary:
                directory = Path(temporary); app = self.fixture(directory); path = app / key
                path.write_bytes(b'asset')
                self.reject(directory, app, 'nonportable' if key.startswith('app/') else 'must stay under app/')


if __name__ == '__main__':
    unittest.main()
