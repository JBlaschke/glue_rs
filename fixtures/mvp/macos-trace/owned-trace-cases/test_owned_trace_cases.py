"""Independent complete synthetic payloads; no native/VM/provider/file-case I/O."""
import ast
import copy
from dataclasses import FrozenInstanceError, replace
import hashlib
import json
from pathlib import Path
import struct
import sys
import unittest

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE.parent / 'owned-trace-check'))
import legacy_codecs as codecs
import owned_trace_cases as cases
from owned_trace_check import RawFacts


def sha(data):
    return hashlib.sha256(data).hexdigest()


def encode(value):
    return (json.dumps(value, separators=(',', ':'), ensure_ascii=True) + '\n').encode('ascii')


def pack(buf, off, *values, fmt=None):
    struct.pack_into('>' + (fmt or 'I' * len(values)), buf, off, *values)


def fixture(case='positive', *, wait=30720, kill=False):
    # Separate struct oracle; no codec encoder or implementation templates used.
    catalog = bytearray(269)
    catalog[:8] = b'GLUENC01'
    pack(catalog, 8, 1, 192, 269, fmt='HHI')
    pack(catalog, 16, 52912, 17, -2, 3, 17, 4, -5, fmt='QQiiQii')
    catalog[56:184] = bytes(range(128))
    pack(catalog, 184, 64, 13, 0, fmt='HHI')
    catalog[192:] = b'b' * 64 + b'context-probe'
    catalog = bytes(catalog)
    cwd = b'/System/Volumes/Data/Library/GlueMVPFixtures/' + b'b' * 64
    executable = cwd + b'/context-probe'
    actual = cases.CaseBinding(123, 456, 501, 20, (20, 0, 80), executable, cwd, 17, 42)
    request = bytearray(208 + len(executable) + len(cwd))
    request[:8] = b'GLUENR01'
    pack(request, 8, 1, 208, len(request), fmt='HHI')
    pack(request, 16, 1, 501, 20, 3)
    pack(request, 32, 20, 0, 80)
    pack(request, 96, 1, 1, 1, 4096, 10000, 2000, 1, 0)
    request[128:160] = bytes.fromhex(sha(catalog))
    pack(request, 160, 17, 42, fmt='QQ')
    pack(request, 176, len(executable), len(cwd))
    request[208:] = executable + cwd
    request = bytes(request)
    # Independently computed compiled Darwin signal policy, no imported constant.
    signals = [n for n in range(1, 32) if n not in (9, 17)]
    policy = sha(b'GLUESP01' + struct.pack('>HHII', 1, 29, 136, 15) + struct.pack('>29I', *signals))
    def bw(kind, sequence, stage, reason, error, flags):
        data = bytearray(256); data[:8] = b'GLUEBS01'
        pack(data, 8, 1, kind, 256, fmt='HHI'); pack(data, 16, 123, 456)
        data[24:56] = bytes.fromhex(sha(request))
        pack(data, 56, sequence, stage, error, flags)
        if kind == 1:
            pack(data, 72, 501, 501, 20, 20, 3, 20, 0, 80)
            pack(data, 156, 17, 42, fmt='QQ'); pack(data, 172, 0, 1, 2, 10, 11)
            data[192:224] = bytes.fromhex(policy)
        pack(data, 224, reason, 0xffffffff)
        return bytes(data)
    positive = case == 'positive'
    if positive:
        status = bw(1, 0, 0, 0, 0, 3) + bw(2, 1, 13, 0, 0, 3)
        out = bytearray(256); out[:8] = b'GLUENP01'; pack(out, 8, 1, 256, 1, fmt='HHI')
        out[16:48] = bytes.fromhex(sha(request)); pack(out, 48, 456, 123, 456, 501, 501, 20, 20, 3, 20, 0, 80)
        pack(out, 144, 17, 42, fmt='QQ'); pack(out, 160, 3, 0, 1, 2, 0x100, 0x101, 0x101, 0, 0, 0)
        pack(out, 200, -1, 1, 501, 501, 20, 20, 1, 0, fmt='i7I'); out = bytes(out)
        ce = {'present': False, 'stage': 0, 'reason': 0, 'errno': 0, 'flags': 0, 'detail': 0}
    else:
        status, out = bw(3, 0, 6, 3, 13, 1), b''
        ce = {'present': True, 'stage': 6, 'reason': 3, 'errno': 13, 'flags': 1, 'detail': -1}
    result = {
        'schema': 'glue-owned-traced-bootstrap-diagnostic-v1', 'tracing': True, 'exec_proved': False,
        'full_acceptance': False, 'identity_policy': 'request-declarations-compared-to-observations',
        'consistent_owned_probe': positive, 'controller_pid': 123, 'child_pid': 456,
        'parent_error': {'stage': 0, 'reason': 0, 'errno': 0, 'detail': 0} if positive else {'stage': 10, 'reason': 12, 'errno': 0, 'detail': -1},
        'cleanup_error': {'stage': 0, 'reason': 0, 'errno': 0, 'detail': 0},
        'helpers': {'admission': {'stage': 0, 'reason': 0, 'errno': 0, 'component': 0, 'metadata_step': 0},
                    'endpoints': {'stage': 0, 'reason': 0, 'errno': 0, 'role': 5, 'fd': -1},
                    'signal_prepare': {'stage': 0, 'reason': 0, 'errno': 0}},
        'child_error': ce,
        'protocol': {'records': 2 if positive else 1, 'bytes': len(status), 'wire_fault': 0,
                     'io_stage': 0, 'io_reason': 0, 'io_errno': 0, 'eof_class': 3 if positive else 2},
        'go': {'action': 1, 'attempted': positive, 'possibly_released': positive, 'bytes': 64 if positive else 0,
               'stage': 0, 'reason': 0, 'errno': 0, 'closed': True},
        'ready_matched': positive, 'probe_matched': positive,
        'wait': {'forked': True, 'reaped': True, 'lost': False, 'kill_attempted': False if positive else kill,
                 'raw_status': 0 if positive else wait},
        'signals': {'prepared': True, 'restore_called': True, 'pipe_restored': True, 'mask_restored': True,
                    'restore_stage': 0, 'restore_reason': 0, 'restore_errno': 0},
        'identities': {'request_sha256': sha(request), 'catalog_sha256': sha(catalog), 'signal_policy_sha256': policy,
                       'status_sha256': sha(status), 'stdout_sha256': sha(out), 'stderr_sha256': sha(b''),
                       'probe_sha256': catalog[56:88].hex(), 'runner_static_sources_sha256': catalog[120:152].hex(),
                       'build_recipe_sha256': catalog[152:184].hex()},
        'stdout_capture_valid': True, 'stderr_capture_valid': True, 'stdout_bytes': len(out), 'stderr_bytes': 0,
        'trace_sidecar': 'trace.json', 'trace_finalization_safe': True, 'trace_success_eligible': positive,
    }
    zero_binding = {'fixture': 0, 'owner_pid': 0, 'target_pid': 0, 'request_sha256': '0' * 64, 'catalog_sha256': '0' * 64}
    actual_binding = {'fixture': 1, 'owner_pid': 123, 'target_pid': 456, 'request_sha256': sha(request), 'catalog_sha256': sha(catalog)}
    session = {
        'binding': actual_binding if positive else zero_binding,
        'attempt_deadline_ns': 11000000000 if positive else 0, 'cleanup_deadline_ns': 8000000000 if positive else 0,
        'cleanup_ms': 2000 if positive else 0, 'cleanup_attempted': int(positive), 'cleanup_bound': int(positive),
        'error': {'stage': 0, 'reason': 0, 'callback_error': 0, 'detail': 0},
        'cleanup_error': {'stage': 0, 'reason': 0, 'callback_error': 0, 'detail': 0},
        'configured': int(positive), 'initialized': int(positive), 'start_attempted': int(positive), 'backend_touched': int(positive),
        'last_ns': 6500000000 if positive else 0, 'total_pumps': 5 if positive else 0,
        'child': int(positive), 'wait_status': 0, 'kill_claimed': 0, 'started': int(positive),
        'provider_ready': int(positive), 'begin': int(positive), 'terminal': int(positive), 'end': int(positive),
        'pumps': [3, 2, 0] if positive else [0, 0, 0], 'events': 5 if positive else 0,
        'go_claim_attempted': int(positive), 'go_possibly_released': int(positive), 'go_result_seen': int(positive),
        'go_complete': int(positive), 'go_bytes': 64 if positive else 0, 'bootstrap_seen': int(positive),
        'bootstrap_sealed': int(positive), 'bootstrap_prefix_bytes': 512 if positive else 0,
        'gate_close_seen': int(positive), 'gate_closed': int(positive), 'stop_attempted': int(positive), 'stopped': int(positive),
        'drain_attempted': int(positive), 'drained': int(positive), 'close_attempted': int(positive), 'closed': int(positive),
        'parent_close_seen': int(positive), 'parent_closed': int(positive),
    }
    backend = {
        'binding': actual_binding if positive else zero_binding,
        'original_attempt_deadline_ns': 11000000000 if positive else 0, 'cleanup_deadline_ns': 8000000000 if positive else 0,
        'first_error': {'stage': 0, 'reason': 0, 'system_errno': 0, 'libdtrace_code': 0, 'callback_error': 0, 'message_hex': ''},
        'close_error': {'stage': 0, 'reason': 0, 'system_errno': 0, 'libdtrace_code': 0, 'callback_error': 0, 'message_hex': ''},
        'writer_close_error': {'stage': 0, 'reason': 0, 'system_errno': 0, 'libdtrace_code': 0, 'callback_error': 0, 'message_hex': ''},
        'writer_close_files': ['program.d', 'probes.tsv', 'events.jsonl', 'errors.jsonl'],
        'writer_close_attempted_mask': 15 if positive else 0, 'writer_close_failed_mask': 0, 'writer_close_errno': [0, 0, 0, 0],
        'events': 6 if positive else 0, 'raw_bytes': 6000 if positive else 0, 'diagnostic_bytes': 0,
        'inventory_bytes': 1000 if positive else 0, 'drops': 0, 'faults': 0, 'inventory_probes': 17 if positive else 0,
        'expected_matches': 17 if positive else 0, 'enabled_matches': 17 if positive else 0, 'enablings': 4 if positive else 0,
        'begin': int(positive), 'terminal': int(positive), 'end': int(positive),
        'start_attempted': int(positive), 'started': int(positive), 'stop_attempted': int(positive), 'stopped': int(positive),
        'drain_attempted': int(positive), 'drained': int(positive), 'close_attempted': int(positive), 'resources_closed': int(positive),
    }
    sidecar = {'schema': 'glue-owned-trace-session-diagnostic-v1', 'tracing': True, 'exec_proved': False,
        'full_acceptance': False, 'parent_cleanup_deadline_ns': 8000000000, 'parent_cleanup_valid': 1,
        'create_attempted': int(positive), 'session_present': int(positive), 'snapshot_valid': int(positive),
        'backend_destroyed': int(positive), 'finalization_safe': 1, 'success_eligible': int(positive),
        'create_error': {'stage': 0, 'reason': 0, 'system_errno': 0, 'libdtrace_code': 0, 'callback_error': 0, 'message_hex': ''},
        'session': session, 'backend': backend}
    inventory_counts = tuple(int(i not in (0, 14)) for i in range(19))
    event_counts = tuple({1: 1, 2: 1, 11: 1, 17: 1, 18: 2}.get(i, 0) for i in range(19))
    # Synthetic input at the accepted RawFacts boundary; no provenance/ABI claim.
    raw = RawFacts(123, 456, 4300, 'a' * 64, 1000, 'b' * 64, 17, inventory_counts, 4,
        6, 6000, 'c' * 64, 0, sha(b''), event_counts, 1, 4, 6, 1, 1, 123, (1 << 64) - 1, 0x1234, 0x1c2) if positive else None
    roster = frozenset(('request.bin', 'status.bin', 'probe.stdout', 'probe.stderr', 'result.json', 'trace.json'))
    if positive:
        roster |= frozenset(('program.d', 'probes.tsv', 'events.jsonl', 'errors.jsonl'))
    return dict(catalog=catalog, request=request, status=status, probe_stdout=out, probe_stderr=b'', result=encode(result),
                sidecar=encode(sidecar), raw=raw, actual=actual, roster=roster, cli_status=0 if positive else 1)


def leaves(value, path=()):
    if type(value) is dict:
        for key, child in value.items():
            yield from leaves(child, path + (key,))
    elif type(value) is list:
        for i, child in enumerate(value):
            yield from leaves(child, path + (i,))
    else:
        yield path, value


def set_path(value, path, replacement):
    parent = value
    for part in path[:-1]:
        parent = parent[part]
    parent[path[-1]] = replacement


class CaseControls(unittest.TestCase):
    def refuse(self, case='positive', data=None, match='.'):
        with self.assertRaisesRegex(cases.CaseRefusal, match):
            cases.validate_case(case, **(fixture(case) if data is None else data))

    def test_complete_independent_positive_and_denied_baselines(self):
        for case in ('positive', 'denied'):
            data = fixture(case)
            result = cases.validate_case(case, **data)
            self.assertEqual(result.case, case)
            self.assertEqual(result.request_sha256, sha(data['request']))
            self.assertEqual(result.raw_events, 6 if case == 'positive' else 0)
            self.assertEqual(result.session_events, 5 if case == 'positive' else 0)
            self.assertEqual(len(result.declared_roster), 10 if case == 'positive' else 6)
            self.assertFalse(result.exec_proved or result.full_acceptance)
            with self.assertRaises(FrozenInstanceError):
                result.raw_events = 0

    def test_closed_denied_wait_kill_matrix(self):
        for wait, kill in ((30720, False), (30720, True), (9, True)):
            result = cases.validate_case('denied', **fixture('denied', wait=wait, kill=kill))
            self.assertEqual((result.raw_wait_status, result.kill_attempted), (wait, kill))
        for wait, kill in ((9, False), (0, False), (0, True), (120, False), (11, True), (30721, False)):
            self.refuse('denied', fixture('denied', wait=wait, kill=kill), 'wait/kill')

    def test_unknown_and_sim_refuse_before_payload_inspection(self):
        class Poison:
            def __getattribute__(self, name):
                raise AssertionError('payload inspected')
        data = {name: Poison() for name in fixture()}
        for case in ('simulated', 'SIM', 'trailing', '', None, True, 1):
            self.refuse(case, data, 'uncalibrated')

    def test_each_result_field_mutation_has_complete_baseline(self):
        for case in ('positive', 'denied'):
            baseline = fixture(case); cases.validate_case(case, **baseline)
            original = json.loads(baseline['result'])
            for path, value in leaves(original):
                changed = copy.deepcopy(original)
                replacement = (not value) if type(value) is bool else value + 1 if type(value) is int else value + 'x'
                if case == 'denied' and path == ('wait', 'kill_attempted'):
                    replacement = 0  # True is a separately allowed source race pair.
                set_path(changed, path, replacement)
                with self.subTest(case=case, path=path):
                    self.refuse(case, baseline | {'result': encode(changed)}, 'result|wait/kill|wait kill')

    def test_each_sidecar_field_mutation_has_complete_baseline(self):
        for case in ('positive', 'denied'):
            baseline = fixture(case); cases.validate_case(case, **baseline)
            original = json.loads(baseline['sidecar'])
            for path, value in leaves(original):
                changed = copy.deepcopy(original)
                replacement = (not value) if type(value) is bool else value + 1 if type(value) is int else value + 'x'
                if path == ('parent_cleanup_deadline_ns',) or (case == 'positive' and path == ('session', 'last_ns')):
                    replacement = 0  # Positive values can be legitimate declarations.
                set_path(changed, path, replacement)
                with self.subTest(case=case, path=path):
                    self.refuse(case, baseline | {'sidecar': encode(changed)})

    def test_types_unknown_missing_nested_keys_and_provenance_namespaces(self):
        baseline = fixture(); cases.validate_case('positive', **baseline)
        for field in ('result', 'sidecar'):
            original = json.loads(baseline[field])
            def objects(value, path=()):
                if type(value) is dict:
                    yield path, value
                    for key, child in value.items():
                        yield from objects(child, path + (key,))
            for path, value in objects(original):
                for key in list(value)[:1]:
                    changed = copy.deepcopy(original); parent = changed
                    for part in path: parent = parent[part]
                    del parent[key]
                    self.refuse(data=baseline | {field: encode(changed)})
                changed = copy.deepcopy(original); parent = changed
                for part in path: parent = parent[part]
                parent['unknown'] = 0
                self.refuse(data=baseline | {field: encode(changed)})
            for path, value in leaves(original):
                if type(value) in (int, bool):
                    changed = copy.deepcopy(original)
                    set_path(changed, path, bool(value) if type(value) is int else int(value))
                    self.refuse(data=baseline | {field: encode(changed)})
        for path, old, new in ((('session', 'error'), 'callback_error', 'system_errno'),
                               (('backend', 'first_error'), 'system_errno', 'errno'),
                               (('backend', 'close_error'), 'libdtrace_code', 'fault'),
                               (('create_error',), 'callback_error', 'errno')):
            changed = json.loads(baseline['sidecar']); obj = changed
            for part in path: obj = obj[part]
            obj[new] = obj.pop(old)
            self.refuse(data=baseline | {'sidecar': encode(changed)}, match='keys')

    def test_json_bounds_duplicates_numbers_and_canonical_encoding(self):
        baseline = fixture(); cases.validate_case('positive', **baseline)
        for field, cap in (('result', 8192), ('sidecar', 16384)):
            good = baseline[field]
            for bad in (good[:-1], good + b' ', good.replace(b'"tracing":true', b'"tracing":true,"tracing":true'),
                        good.replace(b'"controller_pid":123', b'"controller_pid":123.0') if field == 'result' else
                        good.replace(b'"parent_cleanup_valid":1', b'"parent_cleanup_valid":1.0'),
                        good.replace(b':0,', b':NaN,', 1), b'x' * (cap + 1), b'\xff', bytearray(good)):
                self.refuse(data=baseline | {field: bad})

    def test_actual_roster_cli_and_payload_identity_links(self):
        baseline = fixture(); cases.validate_case('positive', **baseline)
        for field, value in (('controller_pid', 456), ('controller_pid', True), ('child_pid', 789), ('uid', 502),
                             ('gid', 21), ('groups', [20, 0, 80]), ('groups', (20, 80)), ('cwd_device', 18),
                             ('cwd_inode', 43), ('cwd', baseline['actual'].cwd + b'x'),
                             ('executable', baseline['actual'].executable + b'x')):
            self.refuse(data=baseline | {'actual': replace(baseline['actual'], **{field: value})})
        for roster in (set(baseline['roster']), baseline['roster'] - {'program.d'}, baseline['roster'] | {'result.pending'}):
            self.refuse(data=baseline | {'roster': roster}, match='roster')
        for cli in (1, 2, False, '0'):
            self.refuse(data=baseline | {'cli_status': cli})
        denied = fixture('denied'); cases.validate_case('denied', **denied)
        self.refuse('denied', denied | {'roster': baseline['roster']}, 'roster')
        self.refuse('denied', denied | {'raw': baseline['raw']}, 'cannot carry raw')
        self.refuse(data=baseline | {'raw': None}, match='RawFacts')

    def test_request_catalog_status_probe_individual_wire_mutations(self):
        baseline = fixture(); cases.validate_case('positive', **baseline)
        for field, offsets in (('catalog', (0, 8, 16, 56, 120, 152, 184, 192, 256)),
                               ('request', (0, 8, 16, 20, 32, 104, 112, 116, 128, 160, 168, 184, 208)),
                               ('status', (0, 10, 16, 20, 24, 56, 68, 72, 92, 156, 164, 172, 192, 232, 266)),
                               ('probe_stdout', (0, 8, 16, 48, 52, 56, 60, 80, 144, 152, 160, 164, 188, 200, 204, 224, 228, 232))):
            for off in offsets:
                changed = bytearray(baseline[field]); changed[off] ^= 1
                with self.subTest(field=field, off=off):
                    self.refuse(data=baseline | {field: bytes(changed)})
        for field in ('catalog', 'request', 'status', 'probe_stdout'):
            self.refuse(data=baseline | {field: baseline[field] + b'\0'})
        self.refuse(data=baseline | {'probe_stderr': b'x'}, match='stderr')
        self.refuse(data=baseline | {'probe_stdout': b'x' * 257}, match='capture byte')
        self.refuse(data=baseline | {'probe_stderr': b'x' * 4097}, match='capture byte')
        denied = fixture('denied'); cases.validate_case('denied', **denied)
        for offset in (10, 56, 60, 64, 68, 224):
            changed = bytearray(denied['status']); changed[offset + 3 if offset != 10 else offset + 1] ^= 1
            self.refuse('denied', denied | {'status': bytes(changed)})

    def test_raw_session_backend_counts_and_source_deadline_relations(self):
        baseline = fixture(); cases.validate_case('positive', **baseline)
        for field, value in (('owner_pid', 124), ('target_pid', 457), ('events', 7), ('raw_bytes', 6001),
                             ('inventory_bytes', 1001), ('inventory_probes', 18), ('observed_enablings', 5),
                             ('shadow_exits', 2), ('post_terminal_lwp_exits', 2), ('error_bytes', 1),
                             ('begin_event', 2), ('end_event', 5), ('terminal_event', 6),
                             ('raw_sha256', 'not-a-hash'), ('error_bytes', False),
                             ('inventory_kind_counts', (0,) * 19), ('event_kind_counts', (0,) * 19),
                             ('observed_enablings', 7)):
            self.refuse(data=baseline | {'raw': replace(baseline['raw'], **{field: value})})
        for path, value in ((('session', 'last_ns'), 8000000000), (('session', 'last_ns'), 1),
                            (('session', 'pumps'), [0, 5, 0]), (('session', 'pumps'), [3, 2, 1]),
                            (('session', 'pumps'), [65536, 1, 0]), (('session', 'total_pumps'), 6),
                            (('session', 'go_bytes'), 63), (('backend', 'writer_close_attempted_mask'), 7),
                            (('backend', 'writer_close_failed_mask'), 8), (('backend', 'writer_close_errno'), [0, 0, 0, 4])):
            changed = json.loads(baseline['sidecar']); set_path(changed, path, value)
            self.refuse(data=baseline | {'sidecar': encode(changed)})
        # Coherent alternate declared clocks remain declarations. No original
        # start-clock or DTrace timestamp relation is invented by this checker.
        changed = json.loads(baseline['sidecar'])
        changed['session']['attempt_deadline_ns'] = 2
        changed['backend']['original_attempt_deadline_ns'] = 2
        self.assertEqual(cases.validate_case('positive', **(baseline | {'sidecar': encode(changed)})).attempt_deadline_ns, 2)

    def test_exact_pure_codec_dependency_closure_and_ast_equivalence(self):
        legacy = (HERE.parent / 'bootstrap-vm' / 'checker.py').read_bytes()
        self.assertEqual(sha(legacy), '0d42737849bd96ab9fdf6e92a4d4418b799b70caeac43f98d38c4335d03b2e0e')
        raw = (HERE.parent / 'owned-trace-check' / 'owned_trace_check.py').read_bytes()
        self.assertEqual(sha(raw), '1d8616b51002225c8b9abf4a18940c48f01d1ef97a3f7c54e120153ca8c978ec')
        self.assertEqual(codecs.RAW_SOURCE_SHA256, sha(raw))
        helper = (HERE.parent / 'syscall-contract' / 'syscall_contract.py').read_bytes()
        self.assertEqual(sha(helper), '35a4229894dd0373de1b312747e8acd1a23ae2074566391e8d28855ca0624dbf')
        def definitions(source):
            result = {}
            for node in ast.parse(source).body:
                if isinstance(node, (ast.FunctionDef, ast.ClassDef)):
                    result[node.name] = ast.dump(node, include_attributes=False)
                elif isinstance(node, ast.Assign) and isinstance(node.targets[0], ast.Name):
                    result[node.targets[0].id] = ast.dump(node, include_attributes=False)
            return result
        vendored_source = (HERE / 'legacy_codecs.py').read_bytes()
        original, vendored = definitions(legacy), definitions(vendored_source)
        for name in codecs.SELECTED_SYMBOLS:
            self.assertEqual(vendored[name], original[name], name)
        self.assertEqual(set(vendored) - set(codecs.SELECTED_SYMBOLS), {'LEGACY_SOURCE_SHA256', 'RAW_SOURCE_SHA256', 'SELECTED_SYMBOLS'})
        imports = {n.names[0].name for n in ast.parse(vendored_source).body if isinstance(n, ast.Import)}
        self.assertEqual(imports, {'hashlib', 'json', 're', 'struct'})
        tree = ast.parse((HERE / 'owned_trace_cases.py').read_bytes())
        imports = {n.module if isinstance(n, ast.ImportFrom) else n.names[0].name for n in tree.body if isinstance(n, (ast.Import, ast.ImportFrom))}
        self.assertEqual(imports, {'dataclasses', 'json', 'legacy_codecs', 'owned_trace_check'})
        self.assertTrue({'check_case', 'check', '_producer', '_packet', '_gate', '_tree', 'main'}.isdisjoint(vendored))


if __name__ == '__main__':
    unittest.main()
