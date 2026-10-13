"""Independent boundaries and actual-trace controls for projected host trees."""
from __future__ import annotations

import copy
import gzip
import hashlib
import importlib.util
import json
from pathlib import Path
import re
import sys
import tempfile
import unittest


def load(filename, name):
    spec = importlib.util.spec_from_file_location(name, Path(__file__).with_name(filename))
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


C = load('check-linux-python-host-prerequisites-trace.py', 'host_prerequisites_test_policy')
OLD = load('check-linux-python-venv-trace.py', 'host_prerequisites_historical_policy')
T = load('test_linux_python_venv_trace.py', 'host_prerequisites_private_venv_tests')
T.C = C
T.T.C = C
ROOT = Path(__file__).resolve().parents[1]
HISTORICAL = ROOT / 'docs/evidence/pbs-linux-arm64-python-venv-2026-10-13'


def trace_lines(directory, mode):
    path = directory / (mode + '.trace.txt')
    if not path.exists():
        path = path.with_suffix('.txt.gz')
    with (gzip.open if path.suffix == '.gz' else open)(path, 'rt', encoding='utf-8') as stream:
        return stream.readlines()


def capture_record(directory, mode, policy=C):
    metadata = directory / 'source-metadata.json'
    size = json.loads(metadata.read_text())['archives'][mode]['bytes']
    return policy.retained_metadata(metadata, mode, size)


def reject_trace(lines, mode, record, policy=C):
    try:
        policy.check_lines(lines, mode, record['bytes'], record)
    except policy.TraceError:
        return
    raise AssertionError(f'{mode}: hostile actual trace was admitted')


def directory_mutations(lines):
    """Change concrete observations in the captured complete install workload."""
    stdlib = '/build-target/install Python metadata/lib/python3.13'
    root, encodings = [], []
    for index, line in enumerate(lines):
        match = C.BASE.LINE.fullmatch(line.rstrip('\n'))
        if match is not None and match[2] == 'getdents64':
            args = C.BASE.split_arguments(match[3])
            if len(args) == 3 and args[0].endswith('<' + stdlib + '>'):
                root.append(index)
            elif len(args) == 3 and args[0].endswith('<' + stdlib + '/encodings>'):
                encodings.append(index)
    if len(root) != 2 or len(encodings) != 4:
        raise AssertionError('actual install workload lacks exact root/encodings enumeration pairs')
    data, eof = root
    if '/* 191 entries */' not in lines[data] or '/* 0 entries */' not in lines[eof]:
        raise AssertionError('actual root enumeration does not match projected inventory before mutation')
    mutants = {}
    for count in (190, 192, 193, 194):
        changed = lines.copy()
        changed[data] = changed[data].replace('/* 191 entries */', f'/* {count} entries */')
        mutants[f'projected-root-count-{count}'] = changed
    for count in (124, 126):
        changed = lines.copy()
        changed[encodings[-2]] = changed[encodings[-2]].replace('/* 125 entries */', f'/* {count} entries */')
        mutants[f'projected-encodings-count-{count}'] = changed
    mutants['projected-root-missing-eof'] = lines[:eof] + lines[eof + 1:]
    mutants['projected-root-duplicate-eof'] = lines[:eof] + [lines[eof]] + lines[eof:]
    mutants['projected-root-data-after-eof'] = lines[:eof + 1] + [lines[data]] + lines[eof + 1:]
    changed = lines.copy()
    changed[data] = changed[data].replace(', 32768)', ', 32767)')
    mutants['projected-root-buffer-size'] = changed
    changed = lines.copy()
    changed[data] = changed[data].replace('/* 191 entries */', '/* 0 entries */')
    mutants['projected-root-positive-result-empty-count'] = changed
    changed = lines.copy()
    changed[eof] = changed[eof].replace('/* 0 entries */', '/* 191 entries */')
    mutants['projected-root-zero-result-positive-count'] = changed
    for comment in ('/* 191 entries */...', '/* 0191 entries */', '/* 191 entries', '/* True entries */'):
        changed = lines.copy()
        changed[data] = changed[data].replace('/* 191 entries */', comment)
        mutants['projected-root-comment-' + str(len(mutants))] = changed
    match = C.BASE.LINE.fullmatch(lines[data].rstrip('\n'))
    token = C.BASE.split_arguments(match[3])[0]
    descriptor = int(token.split('<', 1)[0])
    changed = lines.copy()
    changed[data] = changed[data].replace(token, str(descriptor + 1000) + '<' + stdlib + '>')
    mutants['projected-root-unowned-descriptor'] = changed
    changed = lines.copy()
    changed[data] = changed[data].replace(token, str(descriptor) + '</tmp/unverified>')
    mutants['projected-root-wrong-owner-path'] = changed
    metadata = [index for index, line in enumerate(lines[:data])
                if token in line and any(' ' + name + '(' in line for name in ('fstat', 'newfstatat', 'statx'))]
    if not metadata:
        raise AssertionError('actual enumeration lacks a live-owner metadata check before mutation')
    at = metadata[-1]
    mutants['projected-root-missing-owner-metadata'] = lines[:at] + lines[at + 1:]
    open_owner = next(index for index, line in enumerate(lines[:data]) if ' openat(' in line and line.rstrip().endswith('= ' + token))
    mutants['projected-root-unopened-owner'] = lines[:open_owner] + lines[open_owner + 1:]
    image = next(index for index, line in enumerate(lines[:data]) if ' mprotect(' in line and ', 40960, PROT_NONE)' in line)
    premature = lines.copy()
    observation = premature.pop(data)
    premature.insert(image, observation)
    mutants['projected-root-before-image-ready'] = premature
    mutants['projected-root-after-exit'] = lines + [lines[data]]
    mutants['projected-root-truncated-completion'] = lines[:-1]
    return mutants


def audit_capture(directory, output):
    # The original privately imported audit retains every existing hostile case.
    T.audit_capture(directory, output)
    report = json.loads(output.read_text())
    mode = 'install-host'
    record = capture_record(directory, mode)
    lines = trace_lines(directory, mode)
    mutants = directory_mutations(lines)
    for name, changed in mutants.items():
        try:
            reject_trace(changed, mode, record)
        except AssertionError as error:
            raise AssertionError('host prerequisite mutation admitted: ' + name) from error
    report['cases'][mode]['rejected_mutations'].extend(sorted(mutants))
    report['cases'][mode]['rejected_mutations'].sort()
    report['rejected_mutations'] += len(mutants)
    old_record = capture_record(HISTORICAL, mode, OLD)
    historical = trace_lines(HISTORICAL, mode)
    OLD.check_lines(historical, mode, old_record['bytes'], old_record)
    reject_trace(historical, mode, old_record, C)
    reject_trace(lines, mode, record, OLD)
    report['projected_root_entries'] = C.ROOT_ENTRIES
    report['inventory_identities'] = {
        name: {'bytes': path.stat().st_size, 'sha256': hashlib.sha256(path.read_bytes()).hexdigest()}
        for name, path in [('source', ROOT / 'fixtures/python-install-host-source-apps/source-pins.json'),
                           ('cache', ROOT / 'fixtures/python-install-host-source-apps/cache-pins.json')]}
    report['historical_policy_boundary'] = {
        'prior_complete_root_entries': 193,
        'projected_root_entries': C.ROOT_ENTRIES,
        'historical_trace_sha256': hashlib.sha256(''.join(historical).encode()).hexdigest(),
        'projected_trace_sha256': hashlib.sha256(''.join(lines).encode()).hexdigest(),
        'historical_policy_accepts_prior': True,
        'projected_policy_rejects_prior': True,
        'historical_policy_rejects_projected': True,
    }
    output.write_text(json.dumps(report, sort_keys=True, indent=2) + '\n')
    print(f"Host prerequisite trace audit passed: {report['normal_traces']} normal traces; {report['rejected_mutations']} hostile mutations rejected; historical/projected policies remain distinct")


class HostPrerequisiteTraceTests(unittest.TestCase):
    def test_root_count_derives_from_independently_pinned_paths(self):
        files = json.loads((ROOT / 'fixtures/python-install-host-source-apps/source-pins.json').read_text())['files']
        caches = json.loads((ROOT / 'fixtures/python-install-host-source-apps/cache-pins.json').read_text())['files']
        names = {path.split('/')[0] for path in files.keys() | caches.keys()}
        self.assertEqual(len(names), 189)
        self.assertEqual(C.projected_root_entries(), len(names) + 2)
        self.assertEqual(C.ROOT_ENTRIES, 191)
        self.assertNotIn('LICENSE.txt', names)
        self.assertNotIn('lib-dynload', names)

    def test_inventory_identity_count_bytes_and_types_are_closed(self):
        path = ROOT / 'fixtures/python-install-host-source-apps/source-pins.json'
        raw = path.read_bytes()
        self.assertEqual(len(C.inventory(raw, C.SOURCE_SHA, 1037, 15894268)['files']), 1037)
        for payload in (raw[:-1], raw + b'\n', bytes([raw[0] ^ 1]) + raw[1:]):
            with self.assertRaises(C.TraceError):
                C.inventory(payload, C.SOURCE_SHA, 1037, 15894268)
        value = json.loads(raw)
        for change in ('count', 'bytes', 'bool-size', 'artifact', 'path'):
            altered = copy.deepcopy(value)
            key = next(iter(altered['files']))
            if change == 'count':
                del altered['files'][key]
            elif change == 'bytes':
                altered['files'][key]['size'] += 1
            elif change == 'bool-size':
                altered['files'][key]['size'] = True
            elif change == 'artifact':
                altered['artifact_sha256'] = '0' * 64
            else:
                altered['files']['../escape.py'] = altered['files'].pop(key)
            # Re-pin synthetic inputs to exercise semantic checks independently
            # of the earlier byte-identity check; production uses fixed SHA pins.
            payload = json.dumps(altered).encode()
            with self.assertRaises(C.TraceError):
                C.inventory(payload, hashlib.sha256(payload).hexdigest(), 1037, 15894268)

    def checker(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        directory = Path(temporary.name)
        mode = 'install-host'
        path = T.archive_fixture(directory, mode)
        record = C.archive_record(path, mode)
        return C.Checker(mode, record['bytes'], record).checker

    def enum_checker(self):
        checker = self.checker()
        checker.readers[100] = checker.stdlib
        checker.fd_states[100] = {'role': 'runtime-enum', 'metadata': 1, 'bytes': 0, 'eof': False}
        checker.image_ready = lambda: True
        return checker

    def test_root_enumeration_requires_exact_count_and_one_complete_eof(self):
        checker = self.enum_checker()
        token = '100<' + checker.stdlib + '>'
        checker.call('getdents64', [token, '0x1234 /* 191 entries */', '32768'], '6000')
        checker.call('getdents64', [token, '0x1234 /* 0 entries */', '32768'], '0')
        self.assertEqual(checker.enums['runtime', checker.stdlib], 191)
        with self.assertRaises(C.TraceError):
            checker.call('getdents64', [token, '0x1234 /* 0 entries */', '32768'], '0')
        for count in (190, 192, 193, 194):
            checker = self.enum_checker()
            checker.call('getdents64', [token, f'0x1234 /* {count} entries */', '32768'], '6000')
            with self.assertRaises(C.TraceError):
                checker.call('getdents64', [token, '0x1234 /* 0 entries */', '32768'], '0')

    def test_root_enum_retains_metadata_image_result_grammar_and_exit_guards(self):
        for change in ('metadata', 'image', 'completed', 'exit', 'size', 'comment', 'positive-empty', 'zero-positive', 'owner'):
            checker = self.enum_checker()
            token = '100<' + checker.stdlib + '>'
            args, result = [token, '0x1234 /* 191 entries */', '32768'], '6000'
            if change == 'metadata':
                checker.fd_states[100]['metadata'] = 0
            elif change == 'image':
                checker.image_ready = lambda: False
            elif change == 'completed':
                checker.completed = True
            elif change == 'exit':
                checker.exit_group = True
            elif change == 'size':
                args[2] = '32767'
            elif change == 'comment':
                args[1] += '...'
            elif change == 'positive-empty':
                args[1] = '0x1234 /* 0 entries */'
            elif change == 'zero-positive':
                result = '0'
            else:
                args[0] = '101<' + checker.stdlib + '>'
            with self.subTest(change=change), self.assertRaises(C.TraceError):
                checker.call('getdents64', args, result)

    def test_initialized_predicate_retains_all_preexisting_observations(self):
        checker = self.checker()
        checker.image_ready = lambda: True
        checker.raw_done = checker.raw_sources
        checker.raw_cache_done = set(checker.startup_caches)
        checker.virtual_queries = checker.overcommit_reads = checker.timezone_queries = checker.entropy = 1
        checker.tid_queries, checker.remaps = 2, 4
        checker.enums = {('runtime', checker.stdlib): 191, ('runtime', checker.stdlib + '/encodings'): 125}
        checker.import_probes_seen = checker.probes
        self.assertTrue(checker.initialized_observations(2))
        for name in ('virtual_queries', 'overcommit_reads', 'timezone_queries', 'entropy', 'tid_queries', 'remaps'):
            original = getattr(checker, name)
            setattr(checker, name, original + 1)
            self.assertFalse(checker.initialized_observations(2), name)
            setattr(checker, name, original)
        checker.enums['runtime', checker.stdlib] = 193
        self.assertFalse(checker.initialized_observations(2))

    def test_historical_private_graph_is_unmodified_and_full_host_is_delegated(self):
        with tempfile.TemporaryDirectory() as temporary:
            directory = Path(temporary)
            path = T.archive_fixture(directory, 'host')
            record = C.archive_record(path, 'host')
            checker = C.Checker('host', record['bytes'], record).checker
            self.assertEqual(checker.__class__.__name__, 'MetadataHost')
            path = T.archive_fixture(directory, 'install-host')
            record = OLD.archive_record(path, 'install-host')
            historical = OLD.Checker('install-host', record['bytes'], record).checker
            self.assertEqual(historical.__class__.__name__, 'MetadataHost')
            self.assertEqual(self.checker().__class__.__name__, 'ProjectedInstallHost')


if __name__ == '__main__':
    if len(sys.argv) == 4 and sys.argv[1] == '--audit-capture':
        audit_capture(Path(sys.argv[2]), Path(sys.argv[3]))
    else:
        unittest.main()
