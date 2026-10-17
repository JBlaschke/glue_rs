"""Pure bytes-only controls; fixtures are independently transcribed literals.

No raw reader, native executable, filesystem API, subprocess, generated phase or
packet implementation is called. Successful metadata collection is never a SIM
outcome calibration. All negative fixtures first pass as complete baselines.
"""
from copy import deepcopy
from dataclasses import FrozenInstanceError
import json
import unittest

import fixtures as f
from sim_metadata import DiagnosticRefusal, sim_metadata_collectable


def encoded(value):
    return (json.dumps(value, separators=(',', ':'), ensure_ascii=True) + '\n').encode('ascii')


def get(value, path):
    for part in path:
        value = value[part]
    return value


def put(value, path, replacement):
    get(value, path[:-1])[path[-1]] = replacement


def nodes(value, path=()):
    yield path, value
    if isinstance(value, dict):
        for key, item in value.items():
            yield from nodes(item, path + (key,))
    elif isinstance(value, list):
        for i, item in enumerate(value):
            yield from nodes(item, path + (i,))


class MetadataControls(unittest.TestCase):
    def collect(self, result, trace, status=1, **kwargs):
        return sim_metadata_collectable(status, encoded(result), encoded(trace),
            expected_request_sha256=kwargs.get('request', f.REQUEST),
            expected_catalog_sha256=kwargs.get('catalog', f.CATALOG))

    def baseline(self, factory=f.started_no_go, shape='started'):
        result, trace = factory()
        facts = self.collect(result, trace)
        self.assertEqual(facts.resource_shape, shape)
        self.assertFalse(facts.sim_case_pass)
        self.assertFalse(facts.sim_calibration_accepted)
        self.assertFalse(facts.exec_proved)
        self.assertFalse(facts.full_acceptance)
        return result, trace

    def refuse(self, result, trace, message=None, **kwargs):
        with self.assertRaisesRegex(DiagnosticRefusal, message or '.'):
            self.collect(result, trace, **kwargs)

    def mutate(self, result, trace, which, path, replacement, message=None):
        result, trace = deepcopy(result), deepcopy(trace)
        put(result if which == 'result' else trace, path, replacement)
        self.refuse(result, trace, message)

    def test_01_complete_independent_resource_shape_baselines(self):
        cases = [('failed-create', f.failed_create),
                 ('allocated-not-started', f.allocated_not_started),
                 ('allocated-not-started', lambda: f.allocated_not_started(1, 1)),
                 *[('failed-start', lambda mask=mask: f.failed_start(mask))
                   for mask in (0, 1, 3, 7, 15)],
                 ('started', f.post_start_clock_failure), ('started', f.started_no_go)]
        for shape, factory in cases:
            with self.subTest(shape=shape, factory=factory):
                result, trace = self.baseline(factory, shape)
                facts = self.collect(result, trace)
                self.assertEqual(facts.result_bytes, encoded(result))
                self.assertEqual(facts.trace_bytes, encoded(trace))
                self.assertEqual(facts.native_status, 1)
                self.assertEqual(facts.status, 'metadata-collectable-for-review')

    def test_02_unknown_sim_wait_kill_observations_are_not_calibrated(self):
        result, trace = self.baseline()
        # Includes denied-looking exit120/SIGKILL, READY-write exit121, signal,
        # stopped/continued-looking values, zero and the native signed bound.
        for raw in (0, 9, 30720, 30976, 139, 4991, 65535, 2147483647):
            for killed in (False, True):
                with self.subTest(raw=raw, killed=killed):
                    r, t = deepcopy(result), deepcopy(trace)
                    r['wait'].update(raw_status=raw, kill_attempted=killed)
                    t['session'].update(wait_status=raw, kill_claimed=int(killed))
                    t['session']['cleanup_error'] = (
                        {'stage': 6, 'reason': 14, 'callback_error': 0, 'detail': raw} if raw else
                        {'stage': 9, 'reason': 14, 'callback_error': 0, 'detail': 4})
                    facts = self.collect(r, t)
                    self.assertEqual(facts.result['wait']['raw_status'], raw)
                    self.assertEqual(facts.result['wait']['kill_attempted'], killed)
                    self.assertFalse(facts.sim_case_pass)
                    self.assertFalse(facts.sim_calibration_accepted)
        for path, value in [(('session', 'wait_status'), 9), (('session', 'kill_claimed'), 1)]:
            self.mutate(result, trace, 'trace', path, value, 'wait/kill')

    def test_03_every_object_has_exact_keys_at_every_depth(self):
        for factory, shape in [(f.failed_create, 'failed-create'), (f.started_no_go, 'started')]:
            result, trace = self.baseline(factory, shape)
            for which, original in [('result', result), ('trace', trace)]:
                for path, value in nodes(original):
                    if not isinstance(value, dict):
                        continue
                    for operation in ('extra', 'missing'):
                        changed = deepcopy(original)
                        target = get(changed, path)
                        if operation == 'extra':
                            target['unexpected'] = 0
                        else:
                            del target[next(iter(target))]
                        with self.subTest(which=which, path=path, operation=operation):
                            self.refuse(changed if which == 'result' else result,
                                        changed if which == 'trace' else trace, 'exact keys/type')

    def test_04_leaf_types_are_strict_including_boolean_integer_aliases(self):
        result, trace = self.baseline()
        for which, original in [('result', result), ('trace', trace)]:
            for path, value in nodes(original):
                if isinstance(value, (dict, list)):
                    continue
                wrong = int(value) if type(value) is bool else (False if type(value) is int else 0)
                with self.subTest(which=which, path=path, wrong=wrong):
                    self.mutate(result, trace, which, path, wrong, 'type|hex|boolean')
        for which, path in [('result', ('wait', 'raw_status')),
                            ('trace', ('session', 'events'))]:
            self.mutate(result, trace, which, path, None)

    def test_05_arrays_are_exact_and_writer_names_have_fixed_order(self):
        result, trace = self.baseline()
        for path in [('session', 'pumps'), ('backend', 'writer_close_errno'),
                     ('backend', 'writer_close_files')]:
            for value in ([], get(trace, path)[:-1], get(trace, path) + [0], {}):
                self.mutate(result, trace, 'trace', path, value, 'exact array')
        for i, name in enumerate(('program.d', 'probes.tsv', 'events.jsonl', 'errors.jsonl')):
            self.assertEqual(trace['backend']['writer_close_files'][i], name)
            self.mutate(result, trace, 'trace', ('backend', 'writer_close_files', i), name.upper())
        self.mutate(result, trace, 'trace', ('backend', 'writer_close_files'),
                    ['probes.tsv', 'program.d', 'events.jsonl', 'errors.jsonl'])

    def test_06_fixed_schema_cli_no_go_and_no_acceptance_declarations(self):
        result, trace = self.baseline()
        for status in (0, 2, 120, -1, True, False, '1', 1.0, None):
            self.refuse(result, trace, 'actual native CLI1', status=status)
        mutations = [
            ('result', ('schema',), 'glue-owned-bootstrap-diagnostic-v1'),
            ('trace', ('schema',), 'glue-owned-trace-session-diagnostic-v2'),
            ('result', ('tracing',), False), ('trace', ('tracing',), False),
            ('result', ('exec_proved',), True), ('trace', ('exec_proved',), True),
            ('result', ('full_acceptance',), True), ('trace', ('full_acceptance',), True),
            ('result', ('consistent_owned_probe',), True),
            ('result', ('probe_matched',), True), ('result', ('ready_matched',), False),
            ('result', ('go', 'action'), 1), ('result', ('go', 'attempted'), True),
            ('result', ('go', 'possibly_released'), True), ('result', ('go', 'bytes'), 64),
            ('result', ('go', 'closed'), False),
            ('result', ('trace_sidecar',), '../trace.json'),
            ('result', ('trace_finalization_safe',), False),
            ('result', ('trace_success_eligible',), True),
            ('trace', ('finalization_safe',), 0), ('trace', ('success_eligible',), 1),
            ('trace', ('create_attempted',), 0)]
        for which, path, value in mutations:
            with self.subTest(which=which, path=path):
                self.mutate(result, trace, which, path, value)
        for key in ('go_claim_attempted', 'go_possibly_released', 'go_result_seen',
                    'go_complete', 'go_bytes', 'bootstrap_sealed'):
            self.mutate(result, trace, 'trace', ('session', key), 1)
        for key in ('stage', 'reason', 'errno'):
            self.mutate(result, trace, 'result', ('go', key), 1)

    def test_07_identity_request_catalog_and_actual_pid_relations(self):
        result, trace = self.baseline()
        for digest in ('', 'f' * 63, 'A' * 64, 'gg' * 32, 0, b'11' * 32):
            for field in ('request', 'catalog'):
                self.refuse(result, trace, **{field: digest})
        for field in ('request', 'catalog'):
            self.refuse(result, trace, **{field: 'ff' * 32})
        for key in ('request_sha256', 'catalog_sha256'):
            self.mutate(result, trace, 'result', ('identities', key), 'aa' * 32)
        self.mutate(result, trace, 'result', ('child_pid',), 4101)
        for section in ('session', 'backend'):
            for key, value in [('fixture', 2), ('owner_pid', 4102), ('target_pid', 4101),
                               ('request_sha256', 'aa' * 32), ('catalog_sha256', 'bb' * 32)]:
                self.mutate(result, trace, 'trace', (section, 'binding', key), value)

    def test_08_result_closure_ready_helpers_and_capture_declarations(self):
        result, trace = self.baseline()
        for key in ('forked', 'reaped'):
            self.mutate(result, trace, 'result', ('wait', key), False)
        self.mutate(result, trace, 'result', ('wait', 'lost'), True)
        for key in ('prepared', 'restore_called', 'pipe_restored', 'mask_restored'):
            self.mutate(result, trace, 'result', ('signals', key), False)
        for key in ('restore_stage', 'restore_reason', 'restore_errno'):
            self.mutate(result, trace, 'result', ('signals', key), 1)
        for key in ('stdout_capture_valid', 'stderr_capture_valid'):
            self.mutate(result, trace, 'result', (key,), False)
        for section in ('admission', 'signal_prepare'):
            for key in result['helpers'][section]:
                self.mutate(result, trace, 'result', ('helpers', section, key), 1)
        for key, value in [('stage', 1), ('reason', 1), ('errno', 1), ('role', 0), ('fd', 0)]:
            self.mutate(result, trace, 'result', ('helpers', 'endpoints', key), value)
        self.mutate(result, trace, 'result', ('protocol', 'records'), 0)
        self.mutate(result, trace, 'result', ('protocol', 'bytes'), 255)

    def test_09_allocated_session_closure_and_original_deadline(self):
        result, trace = self.baseline()
        for key in ('snapshot_valid', 'backend_destroyed'):
            self.mutate(result, trace, 'trace', (key,), 0)
        for key in ('configured', 'gate_close_seen', 'gate_closed', 'close_attempted',
                    'closed', 'parent_close_seen', 'parent_closed', 'cleanup_attempted', 'bootstrap_seen'):
            self.mutate(result, trace, 'trace', ('session', key), 0)
        for child in (0, 2):
            self.mutate(result, trace, 'trace', ('session', 'child'), child)
        for value in (0, 1999, 2001):
            self.mutate(result, trace, 'trace', ('session', 'cleanup_ms'), value)
        self.mutate(result, trace, 'trace', ('session', 'attempt_deadline_ns'), 0)
        self.mutate(result, trace, 'trace', ('backend', 'original_attempt_deadline_ns'), 10000000001)
        self.mutate(result, trace, 'trace', ('session', 'cleanup_deadline_ns'), 12000000001)
        self.mutate(result, trace, 'trace', ('backend', 'cleanup_deadline_ns'), 12000000001)
        self.mutate(result, trace, 'trace', ('session', 'bootstrap_prefix_bytes'), 256)
        self.mutate(result, trace, 'trace', ('session', 'total_pumps'), 3)

    def test_10_failed_create_is_exactly_unallocated_not_fake_closed(self):
        result, trace = self.baseline(f.failed_create, 'failed-create')
        for key in ('snapshot_valid', 'backend_destroyed'):
            self.mutate(result, trace, 'trace', (key,), 1)
        for path in [('session', 'configured'), ('session', 'closed'),
                     ('session', 'wait_status'), ('backend', 'started'),
                     ('backend', 'resources_closed'), ('backend', 'writer_close_attempted_mask'),
                     ('backend', 'binding', 'owner_pid')]:
            self.mutate(result, trace, 'trace', path, 1)
        for key, value in [('stage', 0), ('stage', 2), ('reason', 0), ('reason', 6),
                           ('libdtrace_code', 1)]:
            self.mutate(result, trace, 'trace', ('create_error', key), value)
        allocated_result, allocated_trace = self.baseline(f.allocated_not_started, 'allocated-not-started')
        self.mutate(allocated_result, allocated_trace, 'trace', ('create_error', 'reason'), 1)

    def test_11_unstarted_session_no_native_callback_or_lifecycle_claim(self):
        for factory in (f.allocated_not_started, lambda: f.allocated_not_started(1, 1)):
            result, trace = self.baseline(factory, 'allocated-not-started')
            for key in ('start_attempted', 'started', 'close_attempted', 'resources_closed',
                        'events', 'raw_bytes', 'inventory_probes', 'cleanup_deadline_ns'):
                self.mutate(result, trace, 'trace', ('backend', key), 1)
            for key in ('started', 'provider_ready', 'begin', 'terminal', 'end', 'events',
                        'stop_attempted', 'stopped', 'drain_attempted', 'drained'):
                self.mutate(result, trace, 'trace', ('session', key), 1)
        result, trace = self.baseline(lambda: f.allocated_not_started(1, 1), 'allocated-not-started')
        self.mutate(result, trace, 'trace', ('session', 'initialized'), 0)
        self.mutate(result, trace, 'trace', ('session', 'start_attempted'), 0)

    def test_12_failed_start_prefix_ownership_and_full_start_inventory(self):
        for mask in (0, 1, 3, 7, 15):
            result, trace = self.baseline(lambda mask=mask: f.failed_start(mask), 'failed-start')
            for key in ('close_attempted', 'resources_closed'):
                self.mutate(result, trace, 'trace', ('backend', key), 0)
            for key in ('initialized', 'start_attempted', 'backend_touched'):
                self.mutate(result, trace, 'trace', ('session', key), 0)
            for bad_mask in (2, 4, 5, 6, 8, 9, 10, 11, 12, 13, 14):
                self.mutate(result, trace, 'trace', ('backend', 'writer_close_attempted_mask'), bad_mask)
            self.mutate(result, trace, 'trace', ('backend', 'writer_close_failed_mask'), 1)
            self.mutate(result, trace, 'trace', ('backend', 'writer_close_errno', 0), 5)
            self.mutate(result, trace, 'trace', ('backend', 'writer_close_error'),
                {'stage': 6, 'reason': 5, 'system_errno': 5, 'libdtrace_code': 0,
                 'callback_error': 5, 'message_hex': '636c6f7365'}, 'writer ownership')
            self.mutate(result, trace, 'trace', ('backend', 'close_error'),
                {'stage': 6, 'reason': 4, 'system_errno': 0, 'libdtrace_code': 0,
                 'callback_error': 60, 'message_hex': '74696d65'}, 'close')
            if mask != 15:
                for key in ('inventory_probes', 'inventory_bytes', 'diagnostic_bytes',
                            'expected_matches', 'enabled_matches', 'drops', 'faults'):
                    self.mutate(result, trace, 'trace', ('backend', key), 1)
        result, trace = self.baseline(f.post_start_clock_failure, 'started')
        for key, value in [('inventory_probes', 16), ('expected_matches', 16),
                           ('enabled_matches', 16), ('writer_close_attempted_mask', 7)]:
            self.mutate(result, trace, 'trace', ('backend', key), value)
        for section, keys in [('session', ('provider_ready', 'begin', 'terminal', 'end', 'events',
                                          'stop_attempted', 'stopped', 'drain_attempted', 'drained')),
                              ('backend', ('events', 'raw_bytes', 'enablings', 'begin', 'terminal',
                                           'end', 'stop_attempted', 'stopped', 'drain_attempted', 'drained'))]:
            for key in keys:
                self.mutate(result, trace, 'trace', (section, key), 1)

    def test_13_full_mask_failed_setup_preserves_partial_inventory_diagnostics(self):
        result, trace = self.baseline(lambda: f.failed_start(15), 'failed-start')
        trace['backend'].update(inventory_bytes=1024, inventory_probes=12,
            expected_matches=11, enabled_matches=8, diagnostic_bytes=65536,
            drops=18446744073709551615, faults=7)
        trace['backend']['first_error'] = {'stage': 2, 'reason': 6, 'system_errno': 0,
            'libdtrace_code': -17, 'callback_error': 5, 'message_hex': 'ff8041'}
        result['parent_error']['errno'] = result['cleanup_error']['errno'] = 0
        facts = self.collect(result, trace)
        for key in ('inventory_bytes', 'inventory_probes', 'expected_matches',
                    'enabled_matches', 'diagnostic_bytes', 'drops', 'faults'):
            self.assertEqual(facts.trace['backend'][key], trace['backend'][key])
        self.assertEqual(facts.trace['backend']['first_error']['libdtrace_code'], -17)
        self.assertFalse(facts.sim_calibration_accepted)

    def test_14_started_terminal_end_stop_drain_failures_remain_literal(self):
        result, trace = self.baseline()
        # Native stopped flag may survive a failed callback's later clock check;
        # TS never marks stopped/drained successful in that failure shape.
        variants = [({}, {}),
            ({'terminal': 0, 'end': 0, 'events': 2, 'stopped': 0, 'drain_attempted': 0, 'drained': 0},
             {'terminal': 0, 'end': 0, 'events': 1, 'enablings': 1, 'raw_bytes': 512,
              'stopped': 1, 'drain_attempted': 0, 'drained': 0,
              'first_error': {'stage': 4, 'reason': 3, 'system_errno': 5,
                              'libdtrace_code': 0, 'callback_error': 5,
                              'message_hex': '6d6f6e6f746f6e696320636c6f636b206661696c6564'}}),
            ({'terminal': 0, 'end': 0, 'events': 2, 'drained': 0},
             {'terminal': 0, 'end': 0, 'events': 1, 'enablings': 1, 'raw_bytes': 512, 'drained': 0,
              'first_error': {'stage': 5, 'reason': 15, 'system_errno': 0,
                              'libdtrace_code': 0, 'callback_error': 92,
                              'message_hex': '647261696e206c61636b732061637475616c20444f4e452f424547494e2f7465726d696e616c2f454e44'}}),
            ({'terminal': 1, 'end': 0, 'drained': 0}, {'terminal': 1, 'end': 0, 'drained': 0})]
        for session_changes, backend_changes in variants:
            with self.subTest(session=session_changes, backend=backend_changes):
                r, t = deepcopy(result), deepcopy(trace)
                t['session'].update(session_changes)
                t['backend'].update(backend_changes)
                facts = self.collect(r, t)
                for section in ('session', 'backend'):
                    for key in ('terminal', 'end', 'stopped', 'drained'):
                        self.assertEqual(facts.trace[section][key], t[section][key])
                self.assertFalse(facts.sim_case_pass)
        # Resource closure failure remains a refusal despite diagnostic freedom.
        self.mutate(result, trace, 'trace', ('backend', 'resources_closed'), 0)
        self.mutate(result, trace, 'trace', ('session', 'closed'), 0)

    def test_15_cleanup_clock_failure_keeps_original_observations_without_new_bound(self):
        result, trace = self.baseline(f.allocated_not_started, 'allocated-not-started')
        trace['parent_cleanup_valid'] = 0
        trace['parent_cleanup_deadline_ns'] = 10000000000
        trace['session'].update(cleanup_bound=0, cleanup_deadline_ns=0, last_ns=123)
        trace['session']['cleanup_error'] = {'stage': 7, 'reason': 3, 'callback_error': 5, 'detail': 0}
        result['cleanup_error'] = {'stage': 15, 'reason': 8, 'errno': 5, 'detail': -1}
        facts = self.collect(result, trace)
        self.assertEqual(facts.trace['parent_cleanup_valid'], 0)
        self.assertEqual(facts.trace['session']['last_ns'], 123)
        self.assertEqual(facts.trace['session']['cleanup_deadline_ns'], 0)
        self.mutate(result, trace, 'trace', ('session', 'cleanup_deadline_ns'), 1)

    def test_16_namespaces_and_bounded_observations_remain_distinct(self):
        result, trace = self.baseline()
        result['parent_error'] = {'stage': 17, 'reason': 9, 'errno': 0, 'detail': -2147483648}
        result['cleanup_error'] = {'stage': 15, 'reason': 8, 'errno': 2147483647, 'detail': 2147483647}
        trace['session']['error'] = {'stage': 11, 'reason': 16, 'callback_error': 2147483647,
                                   'detail': 18446744073709551615}
        trace['backend']['first_error'] = {'stage': 5, 'reason': 6, 'system_errno': 0,
            'libdtrace_code': -2147483648, 'callback_error': 5, 'message_hex': 'ff' * 512}
        facts = self.collect(result, trace)
        self.assertEqual(facts.result['parent_error']['errno'], 0)
        self.assertEqual(facts.result['cleanup_error']['errno'], 2147483647)
        self.assertEqual(facts.trace['session']['error']['callback_error'], 2147483647)
        self.assertEqual(facts.trace['backend']['first_error']['system_errno'], 0)
        self.assertEqual(facts.trace['backend']['first_error']['libdtrace_code'], -2147483648)
        self.assertEqual(facts.trace['backend']['first_error']['message_hex'], 'ff' * 512)
        for which, path, value in [
            ('result', ('parent_error', 'stage'), 18), ('result', ('parent_error', 'reason'), 16),
            ('result', ('parent_error', 'errno'), -1), ('result', ('parent_error', 'detail'), 2147483648),
            ('trace', ('session', 'error', 'stage'), 12), ('trace', ('session', 'error', 'reason'), 17),
            ('trace', ('session', 'error', 'callback_error'), -1),
            ('trace', ('session', 'error', 'detail'), 18446744073709551616),
            ('trace', ('backend', 'first_error', 'stage'), 7),
            ('trace', ('backend', 'first_error', 'reason'), 16),
            ('trace', ('backend', 'first_error', 'system_errno'), -1),
            ('trace', ('backend', 'first_error', 'callback_error'), -1),
            ('trace', ('backend', 'first_error', 'libdtrace_code'), -2147483649),
            ('trace', ('backend', 'first_error', 'message_hex'), 'a'),
            ('trace', ('backend', 'first_error', 'message_hex'), 'AA'),
            ('trace', ('backend', 'first_error', 'message_hex'), '410042'),
            ('trace', ('backend', 'first_error', 'message_hex'), 'ff' * 513)]:
            with self.subTest(path=path, value=value):
                self.mutate(result, trace, which, path, value)
        for which, path in [('result', ('parent_error',)), ('trace', ('session', 'error')),
                            ('trace', ('backend', 'first_error'))]:
            zero = {'stage': 0, 'reason': 0, 'errno': 0, 'detail': 0} if which == 'result' else (
                {'stage': 0, 'reason': 0, 'callback_error': 0, 'detail': 0} if path[0] == 'session' else
                {'stage': 0, 'reason': 0, 'system_errno': 0, 'libdtrace_code': 0,
                 'callback_error': 0, 'message_hex': ''})
            zero['stage'] = 1
            self.mutate(result, trace, which, path, zero)
        # Field names cannot collapse callback status into native POSIX/library
        # provenance, even if the substituted numeric value is identical.
        for path, old, new in [(('session', 'error'), 'callback_error', 'system_errno'),
                               (('backend', 'first_error'), 'system_errno', 'errno'),
                               (('backend', 'first_error'), 'libdtrace_code', 'native_errno')]:
            changed = deepcopy(trace)
            error = get(changed, path)
            error[new] = error.pop(old)
            self.refuse(result, changed, 'exact keys/type')

    def test_17_child_bw_error_and_protocol_enum_bounds(self):
        result, trace = self.baseline()
        for path, value in [(('child_error', 'stage'), 14), (('child_error', 'reason'), 18),
                            (('child_error', 'flags'), 4), (('child_error', 'detail'), -2),
                            (('child_error', 'detail'), 2147483648),
                            (('child_error', 'errno'), 1),
                            (('protocol', 'wire_fault'), 12), (('protocol', 'eof_class'), 4),
                            (('protocol', 'io_stage'), 10), (('protocol', 'io_reason'), 21),
                            (('protocol', 'io_errno'), -1)]:
            self.mutate(result, trace, 'result', path, value)
        self.mutate(result, trace, 'result', ('child_error', 'present'), False)
        changed = deepcopy(result)
        changed['child_error'].update(reason=3, errno=5)
        self.collect(changed, trace)
        self.mutate(changed, trace, 'result', ('child_error', 'errno'), 0)

    def test_18_counter_digest_and_message_bounds(self):
        result, trace = self.baseline()
        bounds = [('result', ('controller_pid',), 1, 2147483647),
                  ('result', ('child_pid',), 1, 2147483647),
                  ('result', ('stdout_bytes',), 0, 256), ('result', ('stderr_bytes',), 0, 4096),
                  ('result', ('protocol', 'records'), 1, 3), ('result', ('protocol', 'bytes'), 256, 769),
                  ('trace', ('session', 'events'), 0, 1000000),
                  ('trace', ('session', 'total_pumps'), 0, 65536),
                  ('trace', ('backend', 'events'), 0, 1000000),
                  ('trace', ('backend', 'raw_bytes'), 0, 134217728),
                  ('trace', ('backend', 'diagnostic_bytes'), 0, 65536),
                  ('trace', ('backend', 'inventory_bytes'), 0, 1048576),
                  ('trace', ('backend', 'inventory_probes'), 0, 8192),
                  ('trace', ('backend', 'expected_matches'), 0, 8192),
                  ('trace', ('backend', 'enabled_matches'), 0, 4294967295),
                  ('trace', ('backend', 'enablings'), 0, 8192),
                  ('trace', ('backend', 'drops'), 0, 18446744073709551615),
                  ('trace', ('backend', 'faults'), 0, 18446744073709551615),
                  ('trace', ('parent_cleanup_deadline_ns',), 0, 18446744073709551615)]
        for which, path, low, high in bounds:
            for value in (low - 1, high + 1):
                with self.subTest(which=which, path=path, value=value):
                    self.mutate(result, trace, which, path, value)
        for key in result['identities']:
            for invalid in ('0' * 63, '0' * 65, 'FF' * 32, 'gg' * 32):
                self.mutate(result, trace, 'result', ('identities', key), invalid)
        # Check accepted upper byte counters independently of unknown raw bytes.
        trace['backend'].update(raw_bytes=134217728, diagnostic_bytes=65536,
            inventory_bytes=1048576, drops=18446744073709551615, faults=18446744073709551615)
        result.update(stdout_bytes=256, stderr_bytes=4096)
        self.collect(result, trace)

    def test_19_immutable_ascii_duplicate_free_bounded_json(self):
        result, trace = self.baseline()
        rb, tb = encoded(result), encoded(trace)
        def raw_refuse(r, t, message=None):
            with self.assertRaisesRegex(DiagnosticRefusal, message or '.'):
                sim_metadata_collectable(1, r, t, expected_request_sha256=f.REQUEST,
                                          expected_catalog_sha256=f.CATALOG)
        for r in (bytearray(rb), memoryview(rb), rb.decode('ascii'), b'', b'[]', b'null', b'{',
                  b'\xff', rb + b'{}', rb.replace(b'4101', b'4101.0', 1),
                  rb.replace(b'4101', b'NaN', 1), rb.replace(b'4101', b'Infinity', 1),
                  rb.replace(b'4101', b'1234567890123456789012', 1),
                  b'[' * 1500 + b'0' + b']' * 1500):
            raw_refuse(r, tb)
        for t in (bytearray(tb), memoryview(tb), b'', b'{}', b'\xff', tb + b'[]',
                  tb.replace(b'12000000000', b'1e1', 1)):
            raw_refuse(rb, t)
        # Duplicate same-value keys at top level AND inside native error objects.
        for key, value in [(b'schema', b'"glue-owned-traced-bootstrap-diagnostic-v1"'),
                           (b'errno', b'0')]:
            marker = b'"' + key + b'":' + value
            self.assertIn(marker, rb)
            raw_refuse(rb.replace(marker, marker + b',' + marker, 1), tb, 'duplicate key')
        marker = b'"callback_error":92'
        self.assertIn(marker, tb)
        raw_refuse(rb, tb.replace(marker, marker + b',' + marker, 1), 'duplicate key')
        # Escaped spelling still duplicates after JSON key decoding.
        raw_refuse(rb.replace(b'"tracing":true', b'"tracing":true,"trac\\u0069ng":true', 1), tb,
                   'duplicate key')
        # Padding to the exact producer limits passes; one more byte refuses.
        padded_r = rb + b' ' * (8192 - len(rb))
        padded_t = tb + b' ' * (16384 - len(tb))
        facts = sim_metadata_collectable(1, padded_r, padded_t,
            expected_request_sha256=f.REQUEST, expected_catalog_sha256=f.CATALOG)
        self.assertIs(facts.result_bytes, padded_r)
        self.assertIs(facts.trace_bytes, padded_t)
        raw_refuse(padded_r + b' ', padded_t, 'byte bound')
        raw_refuse(padded_r, padded_t + b' ', 'byte bound')

    def test_20_returned_facts_are_deeply_immutable_and_bytes_retained(self):
        result, trace = self.baseline()
        rb, tb = encoded(result), encoded(trace)
        facts = sim_metadata_collectable(1, rb, tb, expected_request_sha256=f.REQUEST,
                                         expected_catalog_sha256=f.CATALOG)
        self.assertIs(facts.result_bytes, rb)
        self.assertIs(facts.trace_bytes, tb)
        self.assertEqual(facts.schema, 'glue-owned-trace-sim-diagnostic-facts-v1')
        self.assertFalse(hasattr(facts, '__dict__'))
        for name in ('native_status', 'resource_shape', 'result', 'trace', 'result_bytes',
                     'trace_bytes', 'status', 'sim_case_pass', 'sim_calibration_accepted',
                     'exec_proved', 'full_acceptance'):
            with self.assertRaises(FrozenInstanceError):
                setattr(facts, name, True)
        for obj in (facts.result, facts.result['wait'], facts.trace,
                    facts.trace['session']['binding'], facts.trace['backend']['first_error']):
            self.assertFalse(hasattr(obj, '__dict__'))
            with self.assertRaises(FrozenInstanceError):
                obj.items = ()
            with self.assertRaises(TypeError):
                obj['anything'] = True
        for array in (facts.trace['session']['pumps'], facts.trace['backend']['writer_close_errno'],
                      facts.trace['backend']['writer_close_files']):
            self.assertIs(type(array), tuple)
            with self.assertRaises(TypeError):
                array[0] = 99
        def no_mutable(value):
            self.assertNotIsInstance(value, (dict, list, set, bytearray))
            if hasattr(value, 'items'):
                self.assertIs(type(value.items), tuple)
                for key, item in value.items:
                    self.assertIs(type(key), str)
                    no_mutable(item)
            elif type(value) is tuple:
                for item in value:
                    no_mutable(item)
        no_mutable(facts.result)
        no_mutable(facts.trace)
        result['wait']['raw_status'] = 7
        trace['backend']['writer_close_errno'][0] = 5
        self.assertEqual(facts.result['wait']['raw_status'], 30720)
        self.assertEqual(facts.trace['backend']['writer_close_errno'], (0, 0, 0, 0))
        with self.assertRaises(KeyError):
            facts.result['missing']


if __name__ == '__main__':
    unittest.main()
