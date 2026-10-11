"""Adversarial checks for the exact optional Python product route."""
import copy
import gzip
import importlib.util
import json
from pathlib import Path
import re
import subprocess
import sys
import tempfile
import unittest


def load(filename, name):
    spec = importlib.util.spec_from_file_location(name, Path(__file__).with_name(filename))
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


C = load('check-linux-python-runner-trace.py', 'runner_checker_test')
E = load('test_linux_python_extension_trace.py', 'runner_native_fixture')
B = E.B
H = E.H
UNAME = 'uname({sysname="Linux", nodename="glue-test", ...}) = 0'


def fixture(mode='bundled-archived'):
    if mode in C.IMPORTS:
        parent = B if mode == 'bundled-imports' else H
        lines = parent.fixture_lines()
        size = parent.CHECKER.ARCHIVE_BYTES
        old = parent.CHECKER.archive_for('success')
        old_stream = 'success'
    else:
        lines, size = E.fixture(mode)
        old = E.C.archive_for(mode)
        old_stream = mode
    lines = [line.replace(old, C.archive_for(mode)).replace('/evidence/' + old_stream + '.', '/evidence/' + mode + '.') for line in lines]
    lines[0] = f'execve({json.dumps(C.PROGRAM)}, {json.dumps(C.command_for(mode))}, 0x1234 /* 18 vars */) = 0'
    if mode in C.NATIVE.NEGATIVE:
        translated = []
        for line in lines:
            if line.startswith('write(2<'):
                match = re.fullmatch(r'write\(([^,]+), ("(?:[^"\\]|\\.)*"), ([0-9]+)\) = ([0-9]+)', line)
                if match:
                    payload = json.loads(match[2]).replace(C.OLD_PREFIX.decode(), C.PREFIX.decode())
                    line = f'write({match[1]}, {json.dumps(payload)}, {len(payload)}) = {len(payload)}'
            translated.append(line)
        lines = translated
    archive = '3<' + C.archive_for(mode) + '>'
    if mode == 'corrupt-native':
        index = next(i for i, line in enumerate(lines) if 'complete ZIP directory' in line) + 1
        lines[index:index] = [f'lseek({archive}, 128, SEEK_SET) = 128', UNAME]
    else:
        index = next(i for i, line in enumerate(lines) if 'complete archive' in line)
        lines[index:index + 1] = [f'read({archive}, "complete manifest"..., 64) = 64',
                                 f'lseek({archive}, {size - 22}, SEEK_SET) = {size - 22}',
                                 f'read({archive}, "complete ZIP directory"..., 22) = 22',
                                 f'lseek({archive}, 128, SEEK_SET) = 128', UNAME,
                                 f'read({archive}, "complete payload"..., {size - 150}) = {size - 150}']
    return lines, size


def check(lines, mode='bundled-archived', size=None):
    if size is None:
        _, size = fixture(mode)
    C.check_lines((f'1234  {line}\n' for line in lines), mode, size,
                  E.OFFSET if mode == 'corrupt-native' else None,
                  (64, size - 22), readiness_fixture(size))


def readiness_fixture(size):
    return {'archive_read_bytes': 150, 'archive_cursor': 128,
            'ranges_sha256': C.range_digest([(0, 128), (size - 22, size)])}


def metadata_fixture():
    metadata = E.retained_metadata_fixture()
    metadata['imports'] = {}
    metadata['readiness'] = {}
    for mode in C.MODES:
        _, size = fixture(mode)
        metadata['readiness'][mode] = readiness_fixture(size)
    for mode in C.IMPORTS:
        _, size = fixture(mode)
        metadata['imports'][mode] = {'bytes': size, 'sha256': 'a' * 64, 'manifest_sha256': 'b' * 64,
                                    'manifest_bytes': 64, 'zip_directory_offset': size - 22,
                                    'runtime': 'host' if mode == 'host-imports' else 'bundled'}
    return metadata


def cli(directory, mode='bundled-archived', metadata=None, compressed=False):
    lines, size = fixture(mode)
    trace = directory / ('trace.txt.gz' if compressed else 'trace.txt')
    raw = ''.join('1234  ' + line + '\n' for line in lines).encode()
    trace.write_bytes(gzip.compress(raw) if compressed else raw)
    stdout, stderr = directory / 'stdout.txt', directory / 'stderr.txt'
    stdout.write_bytes(C.expected_output(mode)[0]); stderr.write_bytes(C.expected_output(mode)[1])
    record = directory / 'metadata.json'
    record.write_text(json.dumps(metadata_fixture() if metadata is None else metadata))
    args = [sys.executable, str(Path(C.__file__)), str(trace), '--mode', mode,
            '--stdout-file', str(stdout), '--stderr-file', str(stderr), '--archive-bytes', str(size),
            '--native-metadata-file', str(record)]
    if mode == 'corrupt-native':
        args += ['--corrupt-native-offset', str(E.OFFSET)]
    return subprocess.run(args, capture_output=True, text=True)


class PythonRunnerTraceTests(unittest.TestCase):
    def reject(self, lines, mode='bundled-archived'):
        with self.assertRaises(C.TraceError):
            check(lines, mode)

    def test_all_nine_product_modes_are_admitted(self):
        for mode in C.MODES:
            with self.subTest(mode=mode):
                lines, size = fixture(mode); check(lines, mode, size)

    def test_only_exact_glue_run_command_is_admitted(self):
        lines, _ = fixture()
        for before, after in [(C.PROGRAM, '/tmp/glue'), ('"run"', '"run-extensions"'),
                              (C.archive_for('bundled-archived'), C.archive_for('host-host'))]:
            mutant = lines.copy(); mutant[0] = mutant[0].replace(before, after); self.reject(mutant)
        mutant = lines.copy(); mutant[0] = mutant[0].replace('], 0x1234', ', "app-error"], 0x1234'); self.reject(mutant)

    def test_readiness_query_is_required_once_with_exact_successful_utsname(self):
        lines, _ = fixture()
        index = lines.index(UNAME)
        self.reject(lines[:index] + lines[index + 1:])
        self.reject(lines[:index] + [UNAME, UNAME] + lines[index + 1:])
        for text in ['uname() = 0', UNAME.replace('Linux', 'Darwin'), UNAME.replace('= 0', '= -1 EPERM (Operation not permitted)'),
                     UNAME.replace('"glue-test"', '"/tmp/host"')]:
            mutant = lines.copy(); mutant[index] = text; self.reject(mutant)

    def test_readiness_query_cannot_precede_archive_admission_or_follow_mapping(self):
        lines, _ = fixture()
        lines.remove(UNAME)
        for index in (1, next(i for i, line in enumerate(lines) if line.startswith('gettid'))):
            mutant = lines.copy(); mutant.insert(index, UNAME); self.reject(mutant)

    def test_readiness_query_cannot_follow_even_partial_payload_reads(self):
        for mode in ('bundled-imports', 'host-imports', 'bundled-archived', 'host-host', 'corrupt-native'):
            lines, size = fixture(mode)
            lines.remove(UNAME)
            index = next(i for i, line in enumerate(lines) if 'complete payload' in line or '"~ELF"' in line)
            if mode == 'corrupt-native':
                lines.insert(index + 1, UNAME)
            else:
                archive = '3<' + C.archive_for(mode) + '>'
                lines[index:index + 1] = [f'read({archive}, "payload prefix"..., 32) = 32', UNAME,
                                         f'read({archive}, "payload remainder"..., {size - 182}) = {size - 182}']
            with self.assertRaisesRegex(C.TraceError, 'pre-payload product readiness'):
                check(lines, mode)

    def test_readiness_requires_exact_metadata_ranges_as_well_as_count_and_cursor(self):
        lines, _ = fixture()
        archive = '3<' + C.archive_for('bundled-archived') + '>'
        index = next(i for i, line in enumerate(lines) if 'complete manifest' in line)
        lines[index:index + 1] = [f'lseek({archive}, 256, SEEK_SET) = 256',
                                 f'read({archive}, "payload replacing manifest"..., 64) = 64']
        with self.assertRaisesRegex(C.TraceError, 'pre-payload product readiness'):
            check(lines)

    def test_consumed_readiness_query_still_checks_process_identity(self):
        lines, size = fixture()
        with self.assertRaises(C.TraceError):
            C.check_lines((f'{1235 if line == UNAME else 1234}  {line}\n' for line in lines), 'bundled-archived', size,
                          admission=(64, size - 22), readiness=readiness_fixture(size))

    def test_exact_evidence_stream_identity_survives_normalization(self):
        for mode in ('bundled-imports', 'host-imports', 'bundled-archived', 'missing-host-image'):
            lines, _ = fixture(mode)
            for before, after in [('/evidence/' + mode + '.', '/evidence/other.'),
                                  ('.stdout.txt>', '.stdout.txt>(deleted)'), ('.stderr.txt>', '.stderr.txt>(deleted)')]:
                if any(before in line for line in lines):
                    self.reject([line.replace(before, after) for line in lines], mode)

    def test_negative_diagnostics_require_product_prefix_and_complete_counts(self):
        for mode in C.NATIVE.NEGATIVE:
            lines, _ = fixture(mode)
            for before, after in [('glue: ', 'glue-python-bootstrap-probe: '), ('2</evidence/', '1</evidence/')]:
                self.reject([line.replace(before, after) for line in lines], mode)
            mutant = lines.copy(); index = next(i for i, line in enumerate(mutant) if line.startswith('write(2<'))
            mutant[index] = mutant[index].rsplit(' = ', 1)[0] + ' = 0'; self.reject(mutant, mode)

    def test_product_prefix_translation_preserves_parent_admission_gate(self):
        for mode in C.NATIVE.NEGATIVE:
            lines, _ = fixture(mode)
            index = next(i for i, line in enumerate(lines) if line.startswith('write(2<'))
            call = lines.pop(index)
            lines.insert(next(i for i, line in enumerate(lines) if 'GLUERS00 locator' in line), call)
            self.reject(lines, mode)

    def test_archive_reopen_and_host_fallbacks_remain_rejected(self):
        for mode in ('bundled-imports', 'host-imports', 'bundled-archived', 'host-host'):
            lines, _ = fixture(mode)
            for call in [f'openat({E.CWD}, {json.dumps(C.archive_for(mode))}, O_RDONLY|O_CLOEXEC) = 999<{C.archive_for(mode)}>',
                         f'openat({E.CWD}, "glue://stock-pbs-archive-imports/app/missing.py", O_RDONLY) = -1 ENOENT (No such file or directory)',
                         'unlink("/tmp/python.so") = -1 ENOENT (No such file or directory)',
                         'clone3({}, 64) = -1 ENOSYS (Function not implemented)']:
                mutant = lines.copy(); mutant.insert(-3, call); self.reject(mutant, mode)

    def test_parent_seals_and_native_mapping_lifetime_are_preserved(self):
        lines, _ = fixture()
        for text in ('F_GET_SEALS', 'verified native image'):
            mutant = lines.copy(); mutant.pop(next(i for i, line in enumerate(mutant) if text in line and 'glue-python-native' in line)); self.reject(mutant)
        mutant = lines.copy(); mutant.insert(-3, 'munmap(0x5002000, 4096) = 0'); self.reject(mutant)

    def test_host_native_input_requires_each_fresh_ancestor_descriptor_check(self):
        lines, _ = fixture('host-host')
        mutant = [line for line in lines if not ('1004</>' in line and 'AT_EMPTY_PATH' in line)]
        self.reject(mutant, 'host-host')

    def test_corrupt_native_requires_manifest_directory_and_selected_member(self):
        lines, _ = fixture('corrupt-native')
        for text in ('complete manifest', 'complete ZIP directory', '~ELF', 'remainder'):
            mutant = lines.copy(); mutant.pop(next(i for i, line in enumerate(mutant) if text in line)); self.reject(mutant, 'corrupt-native')

    def test_cli_plain_and_gzip_replay_all_nine_modes(self):
        with tempfile.TemporaryDirectory() as temporary:
            directory = Path(temporary)
            for mode in C.MODES:
                for compressed in (False, True):
                    result = cli(directory, mode, compressed=compressed)
                    self.assertEqual(result.returncode, 0, result.stderr)
                    self.assertTrue(result.stdout.startswith('Trace checks passed:'))

    def test_cli_rejects_wrong_import_metadata_without_traceback(self):
        with tempfile.TemporaryDirectory() as temporary:
            directory = Path(temporary)
            for kind in ('inventory', 'provider', 'size', 'digest', 'bounds', 'shape'):
                metadata = metadata_fixture(); record = metadata['imports']['host-imports']
                if kind == 'inventory': del metadata['imports']['bundled-imports']
                elif kind == 'provider': record['runtime'] = 'bundled'
                elif kind == 'size': record['bytes'] += 1
                elif kind == 'digest': record['sha256'] = 12
                elif kind == 'bounds': record['manifest_bytes'] = True
                else: metadata['imports'] = None
                result = cli(directory, 'host-imports', metadata)
                self.assertEqual(result.returncode, 1, result.stderr)
                self.assertNotIn('Traceback', result.stderr)

    def test_cli_rejects_wrong_readiness_inventory_and_admission_facts(self):
        with tempfile.TemporaryDirectory() as temporary:
            directory = Path(temporary)
            for kind in ('inventory', 'volume', 'cursor', 'hash', 'boolean', 'shape'):
                metadata = metadata_fixture(); record = metadata['readiness']['host-host']
                if kind == 'inventory': del metadata['readiness']['bundled-imports']
                elif kind == 'volume': record['archive_read_bytes'] += 1
                elif kind == 'cursor': record['archive_cursor'] += 1
                elif kind == 'hash': record['ranges_sha256'] = 'c' * 64
                elif kind == 'boolean': record['archive_read_bytes'] = True
                else: metadata['readiness'] = None
                result = cli(directory, 'host-host', metadata)
                self.assertEqual(result.returncode, 1, result.stderr)
                self.assertNotIn('Traceback', result.stderr)

    def test_cli_requires_metadata_and_rejects_truncated_gzip(self):
        with tempfile.TemporaryDirectory() as temporary:
            directory = Path(temporary)
            good = cli(directory, compressed=True)
            self.assertEqual(good.returncode, 0, good.stderr)
            missing = good.args[:good.args.index('--native-metadata-file')]
            self.assertEqual(subprocess.run(missing, capture_output=True).returncode, 2)
            trace = directory / 'trace.txt.gz'; trace.write_bytes(trace.read_bytes()[:-8])
            result = subprocess.run(good.args, capture_output=True, text=True)
            self.assertEqual(result.returncode, 1, result.stderr)
            self.assertNotIn('Traceback', result.stderr)


if __name__ == '__main__':
    unittest.main()
