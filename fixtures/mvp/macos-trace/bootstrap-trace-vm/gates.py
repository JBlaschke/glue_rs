"""Small metadata predicates shared by disabled renderer and synthetic controls.

No file/evidence reader, raw decoder, liveness oracle or offline checker exists
here. A pinned producer's promoted metadata is a workflow observation only.
"""
RESULT_SCHEMA = 'glue-owned-traced-bootstrap-diagnostic-v1'
TRACE_SCHEMA = 'glue-owned-trace-session-diagnostic-v1'
BACKEND_FILES = ('program.d', 'probes.tsv', 'events.jsonl', 'errors.jsonl')
BASE_FILES = ('request.bin', 'status.bin', 'probe.stdout', 'probe.stderr', 'result.json', 'trace.json')

RESULT_COMMON = {
    'schema': RESULT_SCHEMA, 'tracing': True, 'exec_proved': False, 'full_acceptance': False,
    'wait.forked': True, 'wait.reaped': True, 'wait.lost': False,
    'signals.restore_called': True, 'signals.pipe_restored': True, 'signals.mask_restored': True,
    'signals.restore_stage': 0, 'signals.restore_reason': 0, 'signals.restore_errno': 0,
    'stdout_capture_valid': True, 'stderr_capture_valid': True,
    'trace_sidecar': 'trace.json', 'trace_finalization_safe': True, 'go.closed': True,
}
TRACE_COMMON = {'schema': TRACE_SCHEMA, 'tracing': True, 'exec_proved': False,
                'full_acceptance': False, 'finalization_safe': 1}
SESSION_CLOSED = {'create_attempted': 1, 'session_present': 1, 'snapshot_valid': 1,
    'backend_destroyed': 1, 'session.configured': 1, 'session.child': 1,
    'session.gate_close_seen': 1, 'session.gate_closed': 1, 'session.close_attempted': 1,
    'session.closed': 1, 'session.parent_close_seen': 1, 'session.parent_closed': 1,
    'backend.close_attempted': 1, 'backend.resources_closed': 1,
    'backend.writer_close_attempted_mask': 15, 'backend.writer_close_failed_mask': 0,
    **{'backend.writer_close_errno.' + str(i): 0 for i in range(4)}}
POSITIVE_RESULT = {'consistent_owned_probe': True, 'ready_matched': True, 'probe_matched': True,
    'trace_success_eligible': True, 'wait.raw_status': 0, 'wait.kill_attempted': False,
    'go.action': 1, 'go.attempted': True, 'go.possibly_released': True, 'go.bytes': 64,
    'child_error.present': False, 'protocol.records': 2, 'protocol.bytes': 512,
    'protocol.eof_class': 3, 'stdout_bytes': 256, 'stderr_bytes': 0,
    **{k:0 for k in ('parent_error.stage','parent_error.reason','parent_error.errno','parent_error.detail',
        'cleanup_error.stage','cleanup_error.reason','cleanup_error.errno','cleanup_error.detail',
        'protocol.wire_fault','protocol.io_stage','protocol.io_reason','protocol.io_errno',
        'go.stage','go.reason','go.errno')}}
POSITIVE_TRACE = {'success_eligible': 1, 'parent_cleanup_valid': 1,
    **{k:1 for k in ('session.initialized','session.start_attempted','session.backend_touched',
        'session.started','session.provider_ready','session.begin','session.terminal','session.end',
        'session.go_claim_attempted','session.go_possibly_released','session.go_result_seen','session.go_complete',
        'session.bootstrap_seen','session.bootstrap_sealed','session.cleanup_attempted','session.cleanup_bound',
        'session.stop_attempted','session.stopped','session.drain_attempted','session.drained',
        'backend.start_attempted','backend.started','backend.begin','backend.terminal','backend.end',
        'backend.stop_attempted','backend.stopped','backend.drain_attempted','backend.drained')},
    'session.wait_status': 0, 'session.kill_claimed': 0, 'session.go_bytes': 64,
    'session.bootstrap_prefix_bytes': 512, 'session.cleanup_ms': 2000,
    'backend.drops': 0, 'backend.faults': 0, 'backend.diagnostic_bytes': 0,
    **{'session.' + e + '.' + k:0 for e in ('error','cleanup_error') for k in ('stage','reason','callback_error','detail')},
    **{'backend.' + e + '.' + k:0 for e in ('first_error','close_error','writer_close_error')
       for k in ('stage','reason','system_errno','libdtrace_code','callback_error')}}
DENIED_RESULT = {'consistent_owned_probe': False, 'ready_matched': False, 'probe_matched': False,
    'trace_success_eligible': False,
    'go.action': 1, 'go.attempted': False, 'go.possibly_released': False, 'go.bytes': 0,
    'child_error.present': True, 'child_error.stage': 6, 'child_error.reason': 3,
    'child_error.errno': 13, 'child_error.flags': 1, 'child_error.detail': -1,
    'protocol.records': 1, 'protocol.bytes': 256, 'protocol.eof_class': 2,
    'stdout_bytes': 0, 'stderr_bytes': 0,
    **{k:0 for k in ('cleanup_error.stage','cleanup_error.reason','cleanup_error.errno','cleanup_error.detail',
        'protocol.wire_fault','protocol.io_stage','protocol.io_reason','protocol.io_errno')}}
DENIED_TRACE = {'success_eligible': 0, 'create_attempted': 0, 'session_present': 0,
    'snapshot_valid': 0, 'backend_destroyed': 0, 'session.configured': 0,
    'backend.start_attempted': 0, 'backend.close_attempted': 0, 'backend.resources_closed': 0,
    'backend.events': 0, 'backend.raw_bytes': 0, 'backend.inventory_bytes': 0,
    'backend.diagnostic_bytes': 0, 'backend.writer_close_attempted_mask': 0,
    'backend.writer_close_failed_mask': 0,
    **{'backend.writer_close_errno.' + str(i):0 for i in range(4)}}
SIM_RESULT = {'consistent_owned_probe': False, 'ready_matched': True,
    'trace_success_eligible': False, 'go.action': 2, 'go.attempted': False,
    'go.possibly_released': False, 'go.bytes': 0}
SIM_TRACE = {'success_eligible': 0, 'session.go_claim_attempted': 0,
    'session.go_possibly_released': 0, 'session.go_result_seen': 0,
    'session.go_complete': 0, 'session.go_bytes': 0}



# Fixed source contract, not runtime budget/profile selectors.
U64 = (1 << 64) - 1
PID_MAX = (1 << 31) - 1
CLEANUP_NS = 2000000000
EMPTY_SHA256 = 'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855'
IDENTITIES = ('request_sha256', 'catalog_sha256', 'signal_policy_sha256',
              'status_sha256', 'stdout_sha256', 'stderr_sha256', 'probe_sha256',
              'runner_static_sources_sha256', 'build_recipe_sha256')
TS_ZERO = ('attempt_deadline_ns', 'cleanup_deadline_ns', 'cleanup_ms',
    'cleanup_attempted', 'cleanup_bound', 'configured', 'initialized',
    'start_attempted', 'backend_touched', 'last_ns', 'total_pumps', 'child',
    'wait_status', 'kill_claimed', 'started', 'provider_ready', 'begin', 'terminal',
    'end', 'events', 'go_claim_attempted', 'go_possibly_released', 'go_result_seen',
    'go_complete', 'go_bytes', 'bootstrap_seen', 'bootstrap_sealed',
    'bootstrap_prefix_bytes', 'gate_close_seen', 'gate_closed', 'stop_attempted',
    'stopped', 'drain_attempted', 'drained', 'close_attempted', 'closed',
    'parent_close_seen', 'parent_closed')
OTB_ZERO = ('original_attempt_deadline_ns', 'cleanup_deadline_ns', 'events',
    'raw_bytes', 'diagnostic_bytes', 'inventory_bytes', 'drops', 'faults',
    'inventory_probes', 'expected_matches', 'enabled_matches', 'enablings',
    'begin', 'terminal', 'end', 'start_attempted', 'started', 'stop_attempted',
    'stopped', 'drain_attempted', 'drained', 'close_attempted', 'resources_closed',
    'writer_close_attempted_mask', 'writer_close_failed_mask')


def predicates(case):
    if case not in ('positive', 'simulated', 'denied'):
        raise ValueError('metadata case selector')
    result, trace = dict(RESULT_COMMON), dict(TRACE_COMMON)
    result.update({'identity_policy': 'request-declarations-compared-to-observations',
                   'signals.prepared': True, 'identities.stderr_sha256': EMPTY_SHA256})
    trace.update({'parent_cleanup_valid': 1})
    for error in ('create_error', 'backend.first_error', 'backend.close_error',
                  'backend.writer_close_error'):
        trace.update({error + '.' + key: 0 for key in
                      ('stage', 'reason', 'system_errno', 'libdtrace_code', 'callback_error')})
        trace[error + '.message_hex'] = ''
    for key in ('stage', 'reason', 'errno', 'component', 'metadata_step'):
        result['helpers.admission.' + key] = 0
    for key in ('stage', 'reason', 'errno', 'role', 'fd'):
        result['helpers.endpoints.' + key] = 0
    for key in ('stage', 'reason', 'errno'):
        result['helpers.signal_prepare.' + key] = 0
    for i, name in enumerate(BACKEND_FILES):
        trace['backend.writer_close_files.' + str(i)] = name
    if case == 'positive':
        result.update(POSITIVE_RESULT); trace.update(SESSION_CLOSED); trace.update(POSITIVE_TRACE)
        result.update({'child_error.' + key: 0 for key in
                       ('stage', 'reason', 'errno', 'flags', 'detail')})
    elif case == 'denied':
        result.update(DENIED_RESULT); trace.update(DENIED_TRACE)
        # Reap may observe child120 before cleanup kill, child120 after a kill
        # attempt raced with its exit, or actual SIGKILL9 after that attempt.
        # The closed pair matrix is checked relationally, not normalized.
        result.update({'parent_error.stage': 10, 'parent_error.reason': 12,
                       'parent_error.errno': 0, 'parent_error.detail': -1,
                       'go.stage': 0, 'go.reason': 0, 'go.errno': 0,
                       'identities.stdout_sha256': EMPTY_SHA256})
        trace.update({'session.' + key: 0 for key in TS_ZERO})
        trace.update({'backend.' + key: 0 for key in OTB_ZERO})
        trace.update({'session.pumps.' + str(i): 0 for i in range(3)})
        for prefix in ('session.binding', 'backend.binding'):
            trace.update({prefix + '.' + key: 0 for key in ('fixture', 'owner_pid', 'target_pid')})
            trace.update({prefix + '.' + key: '0' * 64 for key in ('request_sha256', 'catalog_sha256')})
        for prefix in ('session.error', 'session.cleanup_error'):
            trace.update({prefix + '.' + key: 0 for key in ('stage', 'reason', 'callback_error', 'detail')})
    else:
        # Source/render inspection only. No SIM metadata is ever accepted.
        result.update(SIM_RESULT); trace.update(SESSION_CLOSED); trace.update(SIM_TRACE)
    return result, trace


def lookup(obj, key):
    for part in key.split('.'):
        obj = obj[int(part)] if type(obj) is list and part.isdecimal() else obj[part]
    return obj


def relations(case):
    """One fixed relation table drives Python and emitted shell checks."""
    rel = [('range', 'result', 'controller_pid', 1, PID_MAX),
           ('range', 'result', 'child_pid', 1, PID_MAX),
           ('different', 'integer', 'result', 'controller_pid', 'result', 'child_pid'),
           ('range', 'trace', 'parent_cleanup_deadline_ns', 1, U64)]
    rel += [('sha', 'result', 'identities.' + key) for key in IDENTITIES]
    rel += [('sha', 'expected', key) for key in ('request_sha256', 'catalog_sha256')]
    rel += [('equal', 'string', 'result', 'identities.' + key, 'expected', key)
            for key in ('request_sha256', 'catalog_sha256')]
    if case != 'positive':
        return rel + ([('denied_wait',)] if case == 'denied' else [])
    for prefix in ('session', 'backend'):
        rel += [('equal', 'integer', 'trace', prefix + '.binding.owner_pid', 'result', 'controller_pid'),
                ('equal', 'integer', 'trace', prefix + '.binding.target_pid', 'result', 'child_pid'),
                ('literal', 'trace', prefix + '.binding.fixture', 1)]
        rel += [('equal', 'string', 'trace', prefix + '.binding.' + key, 'expected', key)
                for key in ('request_sha256', 'catalog_sha256')]
    rel += [('range', 'trace', key, low, high) for key, low, high in (
        ('session.attempt_deadline_ns', 1, U64), ('session.cleanup_deadline_ns', 1, U64),
        ('backend.original_attempt_deadline_ns', 1, U64), ('backend.cleanup_deadline_ns', 1, U64),
        ('session.last_ns', 0, U64), ('session.total_pumps', 1, 65536),
        ('session.pumps.0', 1, 65536), ('session.pumps.1', 0, 65536), ('session.pumps.2', 0, 65536),
        ('session.events', 4, 1000000), ('backend.events', 3, 1000000),
        ('backend.raw_bytes', 1, 134217728), ('backend.inventory_bytes', 1, 1048576),
        ('backend.inventory_probes', 17, 8192), ('backend.expected_matches', 17, 8192),
        ('backend.enabled_matches', 17, 8192), ('backend.enablings', 3, 8192))]
    rel += [('equal', 'integer', 'trace', left, 'trace', right) for left, right in (
        ('session.attempt_deadline_ns', 'backend.original_attempt_deadline_ns'),
        ('parent_cleanup_deadline_ns', 'session.cleanup_deadline_ns'),
        ('parent_cleanup_deadline_ns', 'backend.cleanup_deadline_ns'),
        ('backend.inventory_probes', 'backend.expected_matches'),
        ('backend.inventory_probes', 'backend.enabled_matches'))]
    rel += [('le', 'trace', left, 'trace', right) for left, right in (
        ('backend.enablings', 'backend.inventory_probes'),
        ('backend.enablings', 'backend.events'), ('backend.events', 'backend.raw_bytes'),
        ('backend.inventory_probes', 'backend.inventory_bytes'))]
    return rel + [('pumps',), ('event_count',), ('cleanup_remaining',)]


def arrays():
    return (('backend.writer_close_files', 4), ('backend.writer_close_errno', 4),
            ('session.pumps', 3))


def _value(objects, which, key, kind):
    value = lookup(objects[which], key)
    if type(value) is not kind:
        raise ValueError('typed metadata relation: ' + which + '.' + key)
    return value


def _relations(case, objects):
    for row in relations(case):
        op, *args = row
        if op == 'range':
            which, key, low, high = args
            value = _value(objects, which, key, int)
            ok = low <= value <= high
        elif op == 'sha':
            which, key = args
            value = _value(objects, which, key, str)
            ok = len(value) == 64 and all(c in '0123456789abcdef' for c in value)
        elif op == 'literal':
            which, key, wanted = args
            ok = _value(objects, which, key, int) == wanted
        elif op in ('equal', 'different', 'le'):
            if op == 'le':
                kind, (a, ak, b, bk) = int, args
            else:
                text_kind, a, ak, b, bk = args
                kind = int if text_kind == 'integer' else str
            av, bv = _value(objects, a, ak, kind), _value(objects, b, bk, kind)
            ok = av <= bv if op == 'le' else av != bv if op == 'different' else av == bv
        else:
            session, backend = objects['trace']['session'], objects['trace']['backend']
            if op == 'denied_wait':
                raw = _value(objects, 'result', 'wait.raw_status', int)
                killed = _value(objects, 'result', 'wait.kill_attempted', bool)
                ok = (raw, killed) in ((30720, False), (30720, True), (9, True))
            elif op == 'pumps':
                ok = session['total_pumps'] == sum(session['pumps'])
            elif op == 'event_count':
                # PROVIDER_READY adds one TS event; shadow/post-terminal cleanup
                # raw records can omit TS delivery. Equality would be unsound.
                ok = session['events'] <= backend['events'] + 1
            elif op == 'cleanup_remaining':
                # Retained monotonic source consistency only. Original cleanup-
                # entry and attempt-start observations are not serialized.
                ok = 0 < session['cleanup_deadline_ns'] - session['last_ns'] <= CLEANUP_NS
            else:
                raise ValueError('unknown fixed metadata relation')
        if not ok:
            raise ValueError('metadata relation: ' + ':'.join(map(str, row)))


def check_metadata(case, native, result, trace, *, request_sha256, catalog_sha256):
    """Pure pre-export gate, without raw I/O, mode changes or kernel proof.

    Expected hashes come from trusted staged input/fixed plan, not the receipt.
    Controller/child IDs are producer observations checked across records; this
    is not independent kernel liveness. Refusal never changes retained facts.
    """
    if case not in ('positive', 'simulated', 'denied'):
        raise ValueError('metadata case selector')
    if type(native) is not int or native != (0 if case == 'positive' else 1):
        raise ValueError('unknown native terminal status')
    if case == 'simulated':
        raise ValueError('SIM trace matrix is uncalibrated')
    try:
        for obj, wanted in zip((result, trace), predicates(case)):
            for key, value in wanted.items():
                actual = lookup(obj, key)
                if type(actual) is not type(value) or actual != value:
                    raise ValueError('unresolved/unreviewed metadata: ' + key)
        for key, length in arrays():
            value = lookup(trace, key)
            if type(value) is not list or len(value) != length:
                raise ValueError('metadata array shape: ' + key)
        _relations(case, {'result': result, 'trace': trace, 'expected': {
            'request_sha256': request_sha256, 'catalog_sha256': catalog_sha256}})
    except (KeyError, IndexError, TypeError) as exc:
        raise ValueError('missing typed closure metadata') from exc
    return tuple(sorted(BASE_FILES + (() if case == 'denied' else BACKEND_FILES)))


_SHELL_HELPERS = r'''
# Reads only already bounded metadata, never raw case artifacts.
gate_value() {
    if [ "$1" = expected ]; then
        case "$2:$3" in
            request_sha256:string) printf '%s\n' "${expected_request_sha256-}" ;;
            catalog_sha256:string) printf '%s\n' "${expected_catalog_sha256-}" ;;
            *) return 2 ;;
        esac
    else meta_value "$@"; fi
}
gate_le() {
    [ "${#1}" -lt "${#2}" ] && return 0
    [ "${#1}" -eq "${#2}" ] || return 2
    [ "$1" = "$2" ] || [ "$1" \< "$2" ]
}
gate_uint() {
    case "$1" in ''|*[!0-9]*) return 2 ;; esac
    [ "$1" = 0 ] || [ "${1#0}" = "$1" ] || return 2
    gate_le "$1" 18446744073709551615
}
gate_range() {
    gr_v=$(gate_value "$1" "$2" integer) || return 2
    gate_uint "$gr_v" && gate_le "$3" "$gr_v" && gate_le "$gr_v" "$4"
}
gate_sha() {
    gs_v=$(gate_value "$1" "$2" string) || return 2
    [ "${#gs_v}" -eq 64 ] || return 2
    case "$gs_v" in *[!0-9a-f]*) return 2 ;; esac
}
gate_equal() {
    ge_a=$(gate_value "$2" "$3" "$1") || return 2
    ge_b=$(gate_value "$4" "$5" "$1") || return 2
    [ "$ge_a" = "$ge_b" ]
}
gate_different() {
    gd_a=$(gate_value "$2" "$3" "$1") || return 2
    gd_b=$(gate_value "$4" "$5" "$1") || return 2
    [ "$gd_a" != "$gd_b" ]
}
gate_order() {
    go_a=$(gate_value "$1" "$2" integer) || return 2
    go_b=$(gate_value "$3" "$4" integer) || return 2
    gate_uint "$go_a" && gate_uint "$go_b" && gate_le "$go_a" "$go_b"
}
gate_pumps() {
    gp_a=$(gate_value trace session.pumps.0 integer) || return 2
    gp_b=$(gate_value trace session.pumps.1 integer) || return 2
    gp_c=$(gate_value trace session.pumps.2 integer) || return 2
    gp_t=$(gate_value trace session.total_pumps integer) || return 2
    # Every operand was bounded <=65536 before this safe fixed addition.
    [ "$gp_t" = "$((gp_a + gp_b + gp_c))" ]
}
gate_event_count() {
    gc_t=$(gate_value trace session.events integer) || return 2
    gc_b=$(gate_value trace backend.events integer) || return 2
    gate_le "$gc_t" "$((gc_b + 1))"
}
gate_denied_wait() {
    gw_raw=$(gate_value result wait.raw_status integer) || return 2
    gw_kill=$(gate_value result wait.kill_attempted bool) || return 2
    case "$gw_raw:$gw_kill" in 30720:false|30720:true|9:true) return 0 ;; *) return 2 ;; esac
}
gate_cleanup_remaining() {
    gx_a=$(gate_value trace session.cleanup_deadline_ns integer) || return 2
    gx_b=$(gate_value trace session.last_ns integer) || return 2
    gate_le "$gx_b" "$gx_a" && [ "$gx_b" != "$gx_a" ] || return 2
    # Decimal subtraction avoids signed shell overflow for uint64 clocks.
    gx_borrow=0; gx_difference=
    while [ -n "$gx_a$gx_b" ]; do
        gx_rest=${gx_a%?}; gx_ad=${gx_a#"$gx_rest"}; gx_a=$gx_rest
        gx_rest=${gx_b%?}; gx_bd=${gx_b#"$gx_rest"}; gx_b=$gx_rest
        gx_digit=$((${gx_ad:-0} - ${gx_bd:-0} - gx_borrow))
        if [ "$gx_digit" -lt 0 ]; then gx_digit=$((gx_digit + 10)); gx_borrow=1; else gx_borrow=0; fi
        gx_difference=$gx_digit$gx_difference
    done
    [ "$gx_borrow" = 0 ] || return 2
    while [ "${gx_difference#0}" != "$gx_difference" ] && [ "$gx_difference" != 0 ]; do gx_difference=${gx_difference#0}; done
    gate_le "$gx_difference" 2000000000
}
'''


def shell_checks():
    """Fixed shell checks with injected bounded metadata reader primitives.

    meta_value(which,key,type), meta_type(which,key,type), meta_absent(which,key),
    meta_expect(which,key,type,expected); $native is the observed CLI status.
    Trusted variables: expected_request_sha256 and expected_catalog_sha256.
    No raw read, mode change, external helper or generated phase is emitted.
    """
    import shlex
    lines = [_SHELL_HELPERS.strip()]
    for case in ('positive', 'simulated', 'denied'):
        lines.append('gate_' + case + '() {')
        lines.append('    [ "$native" = ' + ('0' if case == 'positive' else '1') + ' ] || return 2')
        if case == 'simulated':
            lines.append('    return 2 # SIM uncalibrated; retain actual wait/kill facts')
            lines.append('}')
            continue
        for which, wanted in zip(('result', 'trace'), predicates(case)):
            for key, value in wanted.items():
                kind = 'bool' if type(value) is bool else 'integer' if type(value) is int else 'string'
                text = ('true' if value else 'false') if type(value) is bool else str(value)
                lines.append('    meta_expect ' + which + ' ' + shlex.quote(key) + ' ' + kind + ' ' + shlex.quote(text) + ' || return 2')
        for key, length in arrays():
            lines.append('    meta_type trace ' + key + ' array || return 2')
            lines.append('    meta_absent trace ' + key + '.' + str(length) + ' || return 2')
        for row in relations(case):
            op, *args = row
            if op == 'literal':
                command = ['meta_expect', args[0], args[1], 'integer', str(args[2])]
            else:
                name = {'range': 'range', 'sha': 'sha', 'equal': 'equal',
                        'different': 'different', 'le': 'order', 'pumps': 'pumps',
                        'event_count': 'event_count', 'cleanup_remaining': 'cleanup_remaining',
                        'denied_wait': 'denied_wait'}[op]
                command = ['gate_' + name, *map(str, args)]
            lines.append('    ' + ' '.join(shlex.quote(x) for x in command) + ' || return 2')
        lines += ['    return 0', '}']
    return '\n'.join(lines)
