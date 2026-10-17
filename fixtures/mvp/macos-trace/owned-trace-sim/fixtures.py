"""Independent literal producer declarations for pure SIM metadata controls.

These values were transcribed from runner_files.c/runner_trace.c, trace_session.c/.h
and owned_trace_backend.c/.h. No implementation schema, serializer or positive
case fixture is imported. Functions return complete fresh objects before a test
changes a single observation. None of these declarations is native evidence.
"""
from copy import deepcopy

REQUEST = '11' * 32
CATALOG = '22' * 32

# READY has been completely consumed, but tracing fails before a status read.
RESULT = {
    'schema': 'glue-owned-traced-bootstrap-diagnostic-v1', 'tracing': True,
    'exec_proved': False, 'full_acceptance': False,
    'identity_policy': 'request-declarations-compared-to-observations',
    'consistent_owned_probe': False, 'controller_pid': 4101, 'child_pid': 4102,
    'parent_error': {'stage': 17, 'reason': 9, 'errno': 5, 'detail': 0},
    'cleanup_error': {'stage': 0, 'reason': 0, 'errno': 0, 'detail': 0},
    'helpers': {
        'admission': {'stage': 0, 'reason': 0, 'errno': 0, 'component': 0, 'metadata_step': 0},
        'endpoints': {'stage': 0, 'reason': 0, 'errno': 0, 'role': 5, 'fd': -1},
        'signal_prepare': {'stage': 0, 'reason': 0, 'errno': 0}},
    'child_error': {'present': False, 'stage': 0, 'reason': 0, 'errno': 0, 'flags': 0, 'detail': 0},
    'protocol': {'records': 1, 'bytes': 256, 'wire_fault': 0, 'io_stage': 0,
                 'io_reason': 0, 'io_errno': 0, 'eof_class': 0},
    'go': {'action': 2, 'attempted': False, 'possibly_released': False,
           'bytes': 0, 'stage': 0, 'reason': 0, 'errno': 0, 'closed': True},
    'ready_matched': True, 'probe_matched': False,
    'wait': {'forked': True, 'reaped': True, 'lost': False,
             'kill_attempted': False, 'raw_status': 30720},
    'signals': {'prepared': True, 'restore_called': True, 'pipe_restored': True,
                'mask_restored': True, 'restore_stage': 0, 'restore_reason': 0, 'restore_errno': 0},
    'identities': {'request_sha256': REQUEST, 'catalog_sha256': CATALOG,
                   'signal_policy_sha256': '33' * 32, 'status_sha256': '44' * 32,
                   'stdout_sha256': 'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855',
                   'stderr_sha256': 'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855',
                   'probe_sha256': '00' * 32, 'runner_static_sources_sha256': '77' * 32,
                   'build_recipe_sha256': '88' * 32},
    'stdout_capture_valid': True, 'stderr_capture_valid': True,
    'stdout_bytes': 0, 'stderr_bytes': 0, 'trace_sidecar': 'trace.json',
    'trace_finalization_safe': True, 'trace_success_eligible': False}

# A failed otb_create exposes neither context nor operations. nr_attempt's zero
# initialization survives in both snapshots, with fixed writer names emitted
# unconditionally by nr_trace_write_sidecar. Parent cleanup still has a deadline.
FAILED_CREATE = {
    'schema': 'glue-owned-trace-session-diagnostic-v1', 'tracing': True,
    'exec_proved': False, 'full_acceptance': False,
    'parent_cleanup_deadline_ns': 12000000000, 'parent_cleanup_valid': 1,
    'create_attempted': 1, 'session_present': 0, 'snapshot_valid': 0,
    'backend_destroyed': 0, 'finalization_safe': 1, 'success_eligible': 0,
    'create_error': {'stage': 1, 'reason': 5, 'system_errno': 5,
                     'libdtrace_code': 0, 'callback_error': 5,
                     'message_hex': '696e76616c696420636f6e6669726d65642052454144592f62696e64696e672f6469726563746f72792f646561646c696e65'},
    'session': {
        'binding': {'fixture': 0, 'owner_pid': 0, 'target_pid': 0,
                    'request_sha256': '00' * 32, 'catalog_sha256': '00' * 32},
        'attempt_deadline_ns': 0, 'cleanup_deadline_ns': 0, 'cleanup_ms': 0,
        'cleanup_attempted': 0, 'cleanup_bound': 0,
        'error': {'stage': 0, 'reason': 0, 'callback_error': 0, 'detail': 0},
        'cleanup_error': {'stage': 0, 'reason': 0, 'callback_error': 0, 'detail': 0},
        'configured': 0, 'initialized': 0, 'start_attempted': 0, 'backend_touched': 0,
        'last_ns': 0, 'total_pumps': 0, 'child': 0, 'wait_status': 0,
        'kill_claimed': 0, 'started': 0, 'provider_ready': 0, 'begin': 0,
        'terminal': 0, 'end': 0, 'pumps': [0, 0, 0], 'events': 0,
        'go_claim_attempted': 0, 'go_possibly_released': 0, 'go_result_seen': 0,
        'go_complete': 0, 'go_bytes': 0, 'bootstrap_seen': 0, 'bootstrap_sealed': 0,
        'bootstrap_prefix_bytes': 0, 'gate_close_seen': 0, 'gate_closed': 0,
        'stop_attempted': 0, 'stopped': 0, 'drain_attempted': 0, 'drained': 0,
        'close_attempted': 0, 'closed': 0, 'parent_close_seen': 0, 'parent_closed': 0},
    'backend': {
        'binding': {'fixture': 0, 'owner_pid': 0, 'target_pid': 0,
                    'request_sha256': '00' * 32, 'catalog_sha256': '00' * 32},
        'original_attempt_deadline_ns': 0, 'cleanup_deadline_ns': 0,
        'first_error': {'stage': 0, 'reason': 0, 'system_errno': 0,
                        'libdtrace_code': 0, 'callback_error': 0, 'message_hex': ''},
        'close_error': {'stage': 0, 'reason': 0, 'system_errno': 0,
                        'libdtrace_code': 0, 'callback_error': 0, 'message_hex': ''},
        'writer_close_error': {'stage': 0, 'reason': 0, 'system_errno': 0,
                               'libdtrace_code': 0, 'callback_error': 0, 'message_hex': ''},
        'writer_close_files': ['program.d', 'probes.tsv', 'events.jsonl', 'errors.jsonl'],
        'writer_close_attempted_mask': 0, 'writer_close_failed_mask': 0,
        'writer_close_errno': [0, 0, 0, 0],
        'events': 0, 'raw_bytes': 0, 'diagnostic_bytes': 0, 'inventory_bytes': 0,
        'drops': 0, 'faults': 0, 'inventory_probes': 0, 'expected_matches': 0,
        'enabled_matches': 0, 'enablings': 0, 'begin': 0, 'terminal': 0, 'end': 0,
        'start_attempted': 0, 'started': 0, 'stop_attempted': 0, 'stopped': 0,
        'drain_attempted': 0, 'drained': 0, 'close_attempted': 0, 'resources_closed': 0}}

# ts_init marks configured before its clock check. A later clock recovery permits
# parent cleanup/reap and TS close (which skips the untouched backend callback).
# This full session literal is separate from the failed-create zero snapshot.
ALLOCATED_SESSION = {
    'binding': {'fixture': 1, 'owner_pid': 4101, 'target_pid': 4102,
                'request_sha256': REQUEST, 'catalog_sha256': CATALOG},
    'attempt_deadline_ns': 10000000000, 'cleanup_deadline_ns': 12000000000,
    'cleanup_ms': 2000, 'cleanup_attempted': 1, 'cleanup_bound': 1,
    'error': {'stage': 1, 'reason': 3, 'callback_error': 5, 'detail': 0},
    'cleanup_error': {'stage': 6, 'reason': 14, 'callback_error': 0, 'detail': 30720},
    'configured': 1, 'initialized': 0, 'start_attempted': 0, 'backend_touched': 0,
    'last_ns': 11000000000, 'total_pumps': 0, 'child': 1, 'wait_status': 30720,
    'kill_claimed': 0, 'started': 0, 'provider_ready': 0, 'begin': 0,
    'terminal': 0, 'end': 0, 'pumps': [0, 0, 0], 'events': 0,
    'go_claim_attempted': 0, 'go_possibly_released': 0, 'go_result_seen': 0,
    'go_complete': 0, 'go_bytes': 0, 'bootstrap_seen': 1, 'bootstrap_sealed': 0,
    'bootstrap_prefix_bytes': 256, 'gate_close_seen': 1, 'gate_closed': 1,
    'stop_attempted': 0, 'stopped': 0, 'drain_attempted': 0, 'drained': 0,
    'close_attempted': 1, 'closed': 1, 'parent_close_seen': 1, 'parent_closed': 1}

# start's first output open fails. The callback was touched, so close must run,
# even with no writer FD ever allocated. Native first_error and mapped TS error
# remain independent declarations. No provider work has happened.
FAILED_START_SESSION = {
    'binding': {'fixture': 1, 'owner_pid': 4101, 'target_pid': 4102,
                'request_sha256': REQUEST, 'catalog_sha256': CATALOG},
    'attempt_deadline_ns': 10000000000, 'cleanup_deadline_ns': 12000000000,
    'cleanup_ms': 2000, 'cleanup_attempted': 1, 'cleanup_bound': 1,
    'error': {'stage': 2, 'reason': 6, 'callback_error': 13, 'detail': 0},
    'cleanup_error': {'stage': 6, 'reason': 14, 'callback_error': 0, 'detail': 30720},
    'configured': 1, 'initialized': 1, 'start_attempted': 1, 'backend_touched': 1,
    'last_ns': 11000000000, 'total_pumps': 0, 'child': 1, 'wait_status': 30720,
    'kill_claimed': 0, 'started': 0, 'provider_ready': 0, 'begin': 0,
    'terminal': 0, 'end': 0, 'pumps': [0, 0, 0], 'events': 0,
    'go_claim_attempted': 0, 'go_possibly_released': 0, 'go_result_seen': 0,
    'go_complete': 0, 'go_bytes': 0, 'bootstrap_seen': 1, 'bootstrap_sealed': 0,
    'bootstrap_prefix_bytes': 256, 'gate_close_seen': 1, 'gate_closed': 1,
    'stop_attempted': 0, 'stopped': 0, 'drain_attempted': 0, 'drained': 0,
    'close_attempted': 1, 'closed': 1, 'parent_close_seen': 1, 'parent_closed': 1}

# A complete consumed BEGIN, closed SIM gate and failed terminal delivery during
# drain: TS sets terminal before rejecting it for no GO; no END is synthesized.
# This full session literal does not reuse the metadata implementation's schema.
STARTED_SESSION = {
    'binding': {'fixture': 1, 'owner_pid': 4101, 'target_pid': 4102,
                'request_sha256': REQUEST, 'catalog_sha256': CATALOG},
    'attempt_deadline_ns': 10000000000, 'cleanup_deadline_ns': 12000000000,
    'cleanup_ms': 2000, 'cleanup_attempted': 1, 'cleanup_bound': 1,
    'error': {'stage': 5, 'reason': 13, 'callback_error': 0, 'detail': 512},
    'cleanup_error': {'stage': 6, 'reason': 14, 'callback_error': 0, 'detail': 30720},
    'configured': 1, 'initialized': 1, 'start_attempted': 1, 'backend_touched': 1,
    'last_ns': 11000000000, 'total_pumps': 12, 'child': 1, 'wait_status': 30720,
    'kill_claimed': 0, 'started': 1, 'provider_ready': 1, 'begin': 1,
    'terminal': 1, 'end': 0, 'pumps': [12, 0, 0], 'events': 3,
    'go_claim_attempted': 0, 'go_possibly_released': 0, 'go_result_seen': 0,
    'go_complete': 0, 'go_bytes': 0, 'bootstrap_seen': 1, 'bootstrap_sealed': 0,
    'bootstrap_prefix_bytes': 512, 'gate_close_seen': 1, 'gate_closed': 1,
    'stop_attempted': 1, 'stopped': 1, 'drain_attempted': 1, 'drained': 0,
    'close_attempted': 1, 'closed': 1, 'parent_close_seen': 1, 'parent_closed': 1}


def failed_create():
    return deepcopy(RESULT), deepcopy(FAILED_CREATE)


def allocated_not_started(initialized=0, start_attempted=0):
    result, trace = failed_create()
    result['parent_error'] = {'stage': 17, 'reason': 9, 'errno': 0, 'detail': 3}
    result['cleanup_error'] = {'stage': 12, 'reason': 9, 'errno': 0, 'detail': 3}
    trace.update(session_present=1, snapshot_valid=1, backend_destroyed=1,
        create_error={'stage': 0, 'reason': 0, 'system_errno': 0,
                      'libdtrace_code': 0, 'callback_error': 0, 'message_hex': ''},
        session=deepcopy(ALLOCATED_SESSION))
    session = trace['session']
    session['initialized'] = initialized
    session['start_attempted'] = start_attempted
    if start_attempted:
        session['error'] = {'stage': 2, 'reason': 3, 'callback_error': 5, 'detail': 0}
    trace['backend']['binding'] = {
        'fixture': 1, 'owner_pid': 4101, 'target_pid': 4102,
        'request_sha256': REQUEST, 'catalog_sha256': CATALOG}
    trace['backend']['original_attempt_deadline_ns'] = 10000000000
    return result, trace


def failed_start(mask=0):
    result, trace = allocated_not_started()
    result['parent_error'] = {'stage': 17, 'reason': 9, 'errno': 13, 'detail': 6}
    result['cleanup_error'] = {'stage': 12, 'reason': 9, 'errno': 13, 'detail': 6}
    trace['session'] = deepcopy(FAILED_START_SESSION)
    # Every prefix follows program/probes/events/errors open order; stat failure
    # after the last successful open is possible even for the full mask15.
    trace['backend'].update(start_attempted=1, close_attempted=1, resources_closed=1,
        cleanup_deadline_ns=12000000000, writer_close_attempted_mask=mask,
        first_error={'stage': 2, 'reason': 5, 'system_errno': 13,
                     'libdtrace_code': 0, 'callback_error': 13,
                     'message_hex': '6f75747075742073746174206661696c6564'})
    if mask == 0:
        trace['backend']['first_error']['message_hex'] = '6578636c7573697665206f7574707574206f70656e206661696c6564'
    return result, trace


def post_start_clock_failure():
    result, trace = failed_start(15)
    result['parent_error'] = {'stage': 17, 'reason': 9, 'errno': 5, 'detail': 6}
    result['cleanup_error'] = {'stage': 12, 'reason': 9, 'errno': 5, 'detail': 6}
    trace['session']['error'] = {'stage': 2, 'reason': 6, 'callback_error': 5, 'detail': 0}
    trace['backend'].update(started=1, inventory_probes=17, expected_matches=17,
        enabled_matches=17, inventory_bytes=2048,
        first_error={'stage': 2, 'reason': 3, 'system_errno': 5,
                     'libdtrace_code': 0, 'callback_error': 5,
                     'message_hex': '6d6f6e6f746f6e696320636c6f636b206661696c6564'})
    return result, trace


def started_no_go():
    result, trace = failed_start(15)
    result['parent_error'] = {'stage': 12, 'reason': 12, 'errno': 0, 'detail': -1}
    result['cleanup_error'] = {'stage': 15, 'reason': 9, 'errno': 0, 'detail': 13}
    result['protocol'].update(records=2, bytes=512, eof_class=2)
    result['child_error'].update(present=True, stage=9, reason=10, flags=3, detail=-1)
    trace['session'] = deepcopy(STARTED_SESSION)
    trace['backend'].update(started=1, events=2, raw_bytes=1024, diagnostic_bytes=180,
        inventory_bytes=2048, inventory_probes=17, expected_matches=17,
        enabled_matches=17, enablings=2, begin=1, terminal=1,
        stop_attempted=1, stopped=1, drain_attempted=1, drained=0,
        first_error={'stage': 5, 'reason': 14, 'system_errno': 0,
                     'libdtrace_code': 0, 'callback_error': 92,
                     'message_hex': '636f6f7264696e61746f722072656a6563746564206576656e74'})
    return result, trace
