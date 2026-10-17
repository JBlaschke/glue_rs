"""Pure SIM diagnostic metadata eligibility, never SIM acceptance or I/O."""
from dataclasses import dataclass, field
import json
import re

U64 = (1 << 64) - 1
U32 = (1 << 32) - 1
INT = (1 << 31) - 1
FILES = ('program.d', 'probes.tsv', 'events.jsonl', 'errors.jsonl')
PREFIX_MASKS = (0, 1, 3, 7, 15)


class DiagnosticRefusal(ValueError):
    """No diagnostic collection eligibility is returned."""


def require(ok, message):
    if not ok:
        raise DiagnosticRefusal(message)


def integer(low=0, high=U64):
    return ('integer', low, high)


def literal(value):
    return ('literal', value)


BIT = integer(0, 1)
ENUM = integer(0, INT)
SIGNED = integer(-(1 << 31), INT)
SHA = ('hex', 64, 64)
NATIVE_ERROR = dict(stage=integer(0, 17), reason=integer(0, 15), errno=ENUM, detail=SIGNED)
TS_ERROR = dict(stage=integer(0, 11), reason=integer(0, 16), callback_error=ENUM, detail=integer())
OTB_ERROR = dict(stage=integer(0, 6), reason=integer(0, 15), system_errno=ENUM,
    libdtrace_code=SIGNED, callback_error=ENUM, message_hex=('hex', 0, 1024))
BINDING = dict(fixture=integer(0, U32), owner_pid=integer(0, INT),
    target_pid=integer(0, INT), request_sha256=SHA, catalog_sha256=SHA)
SESSION_BITS = '''cleanup_attempted cleanup_bound configured initialized start_attempted
    backend_touched kill_claimed started provider_ready begin terminal end go_claim_attempted
    go_possibly_released go_result_seen go_complete bootstrap_seen bootstrap_sealed gate_close_seen
    gate_closed stop_attempted stopped drain_attempted drained close_attempted closed
    parent_close_seen parent_closed'''.split()
SESSION = {key: BIT for key in SESSION_BITS}
SESSION.update(binding=BINDING, attempt_deadline_ns=integer(), cleanup_deadline_ns=integer(),
    cleanup_ms=integer(0, 2000), error=TS_ERROR, cleanup_error=TS_ERROR,
    last_ns=integer(), total_pumps=integer(0, 65536), child=integer(0, 2),
    wait_status=integer(0, U32), pumps=[integer(0, 65536)] * 3,
    events=integer(0, 1000000), go_bytes=integer(0, 64), bootstrap_prefix_bytes=integer(0, 769))
BACKEND_BITS = '''begin terminal end start_attempted started stop_attempted stopped
    drain_attempted drained close_attempted resources_closed'''.split()
BACKEND = {key: BIT for key in BACKEND_BITS}
BACKEND.update(binding=BINDING, original_attempt_deadline_ns=integer(), cleanup_deadline_ns=integer(),
    first_error=OTB_ERROR, close_error=OTB_ERROR, writer_close_error=OTB_ERROR,
    writer_close_files=[literal(x) for x in FILES], writer_close_attempted_mask=integer(0, 15),
    writer_close_failed_mask=integer(0, 15), writer_close_errno=[ENUM] * 4,
    events=integer(0, 1000000), raw_bytes=integer(0, 134217728),
    diagnostic_bytes=integer(0, 65536), inventory_bytes=integer(0, 1048576),
    drops=integer(), faults=integer(), inventory_probes=integer(0, 8192),
    expected_matches=integer(0, 8192), enabled_matches=integer(0, U32), enablings=integer(0, 8192))
TRACE = dict(schema=literal('glue-owned-trace-session-diagnostic-v1'), tracing=literal(True),
    exec_proved=literal(False), full_acceptance=literal(False), parent_cleanup_deadline_ns=integer(),
    parent_cleanup_valid=BIT, create_attempted=BIT, session_present=BIT, snapshot_valid=BIT,
    backend_destroyed=BIT, finalization_safe=BIT, success_eligible=BIT,
    create_error=OTB_ERROR, session=SESSION, backend=BACKEND)
RESULT = dict(schema=literal('glue-owned-traced-bootstrap-diagnostic-v1'), tracing=literal(True),
    exec_proved=literal(False), full_acceptance=literal(False),
    identity_policy=literal('request-declarations-compared-to-observations'),
    consistent_owned_probe=literal(False), controller_pid=integer(1, INT), child_pid=integer(1, INT),
    parent_error=NATIVE_ERROR, cleanup_error=NATIVE_ERROR,
    helpers=dict(admission=dict(stage=ENUM, reason=ENUM, errno=ENUM, component=integer(), metadata_step=ENUM),
        endpoints=dict(stage=ENUM, reason=ENUM, errno=ENUM, role=ENUM, fd=SIGNED),
        signal_prepare=dict(stage=ENUM, reason=ENUM, errno=ENUM)),
    child_error=dict(present=('bool',), stage=integer(0, 13), reason=integer(0, 17),
        errno=ENUM, flags=integer(0, 3), detail=integer(-1, INT)),
    protocol=dict(records=integer(1, 3), bytes=integer(256, 769), wire_fault=integer(0, 11),
        io_stage=integer(0, 9), io_reason=integer(0, 20), io_errno=ENUM, eof_class=integer(0, 3)),
    go=dict(action=literal(2), attempted=literal(False), possibly_released=literal(False),
        bytes=literal(0), stage=literal(0), reason=literal(0), errno=literal(0), closed=literal(True)),
    ready_matched=literal(True), probe_matched=literal(False),
    wait=dict(forked=literal(True), reaped=literal(True), lost=literal(False),
        kill_attempted=('bool',), raw_status=integer(0, INT)),
    signals=dict(prepared=literal(True), restore_called=literal(True), pipe_restored=literal(True),
        mask_restored=literal(True), restore_stage=literal(0), restore_reason=literal(0), restore_errno=literal(0)),
    identities={key: SHA for key in '''request_sha256 catalog_sha256 signal_policy_sha256 status_sha256
        stdout_sha256 stderr_sha256 probe_sha256 runner_static_sources_sha256 build_recipe_sha256'''.split()},
    stdout_capture_valid=literal(True), stderr_capture_valid=literal(True),
    stdout_bytes=integer(0, 256), stderr_bytes=integer(0, 4096),
    trace_sidecar=literal('trace.json'), trace_finalization_safe=literal(True), trace_success_eligible=literal(False))


def _validate(value, spec, name):
    if type(spec) is dict:
        require(type(value) is dict and value.keys() == spec.keys(), name + ' exact keys/type')
        for key, item in spec.items():
            _validate(value[key], item, name + '.' + key)
    elif type(spec) is list:
        require(type(value) is list and len(value) == len(spec), name + ' exact array')
        for i, item in enumerate(spec):
            _validate(value[i], item, name + '.' + str(i))
    elif spec[0] == 'literal':
        require(type(value) is type(spec[1]) and value == spec[1], name + ' literal/type')
    elif spec[0] == 'integer':
        require(type(value) is int and spec[1] <= value <= spec[2], name + ' integer type/range')
    elif spec[0] == 'bool':
        require(type(value) is bool, name + ' boolean')
    else:
        require(type(value) is str and spec[1] <= len(value) <= spec[2] and
            len(value) % 2 == 0 and re.fullmatch('[0-9a-f]*', value) is not None, name + ' hex')


def _parse(raw, limit, name):
    require(type(raw) is bytes and 0 < len(raw) <= limit, name + ' immutable byte bound/type')
    def pairs(items):
        result = {}
        for key, value in items:
            require(key not in result, name + ' duplicate key')
            result[key] = value
        return result
    def number(text):
        require(len(text) <= 21, name + ' integer token bound')
        return int(text)
    def invalid(_):
        raise DiagnosticRefusal(name + ' non-integer number')
    try:
        return json.loads(raw.decode('ascii'), object_pairs_hook=pairs,
            parse_int=number, parse_float=invalid, parse_constant=invalid)
    except (UnicodeError, json.JSONDecodeError, RecursionError) as error:
        raise DiagnosticRefusal(name + ' invalid ASCII JSON') from error


def _zero(value, key=''):
    if type(value) is dict:
        return all(_zero(x, name) for name, x in value.items())
    if type(value) is list:
        return all(_zero(x, key) for x in value)
    if type(value) is str:
        return value == ('0' * 64 if key.endswith('_sha256') else '')
    return type(value) is int and value == 0


def _zero_backend(backend, allocated):
    exempt = {'writer_close_files'} | ({'binding', 'original_attempt_deadline_ns'} if allocated else set())
    require(all(_zero(value, key) for key, value in backend.items() if key not in exempt),
            'unstarted backend must declare no lifecycle/writers/counters/errors')


def _same_binding(binding, result, request, catalog):
    require(binding == dict(fixture=1, owner_pid=result['controller_pid'], target_pid=result['child_pid'],
        request_sha256=request, catalog_sha256=catalog), 'session/backend identity binding')


def _error_shapes(result, trace):
    errors = [result['parent_error'], result['cleanup_error'], trace['create_error'],
        trace['session']['error'], trace['session']['cleanup_error']]
    errors += [trace['backend'][key] for key in ('first_error', 'close_error', 'writer_close_error')]
    for error in errors:
        require((error['stage'] > 0 and error['reason'] > 0) or _zero(error),
                'zero/nonzero error namespace shape')
    for error in [trace['create_error']] + [trace['backend'][key] for key in
            ('first_error', 'close_error', 'writer_close_error')]:
        require('00' not in [error['message_hex'][i:i+2] for i in range(0, len(error['message_hex']), 2)],
                'native bounded error string cannot contain NUL')
        if error['reason']:
            require(error['callback_error'] > 0 and
                (error['reason'] == 6 or error['libdtrace_code'] == 0) and
                (error['reason'] in (3, 5, 13) or error['system_errno'] == 0),
                'native error namespaces differ')
    child = result['child_error']
    if not child['present']:
        require(all(value == 0 for key, value in child.items() if key != 'present'), 'absent child error must be zero')
    else:
        require(child['stage'] > 0 and child['reason'] > 0 and
            ((child['reason'] == 3 and child['errno'] > 0) or
             (child['reason'] != 3 and child['errno'] == 0)), 'reported child error namespace')


def _collection_shape(result, trace, request, catalog):
    _error_shapes(result, trace)
    require(result['controller_pid'] != result['child_pid'], 'distinct reported controller/child PIDs')
    require(result['identities']['request_sha256'] == request and
        result['identities']['catalog_sha256'] == catalog, 'staged request/catalog identities')
    require(trace['create_attempted'] == 1 and trace['finalization_safe'] == 1 and
        trace['success_eligible'] == 0, 'SIM setup/finalization/no-success declaration')
    require(trace['parent_cleanup_deadline_ns'] > 0, 'parent cleanup deadline declaration')
    helpers = result['helpers']
    require(_zero(helpers['admission']) and _zero(helpers['signal_prepare']) and
        helpers['endpoints'] == dict(stage=0, reason=0, errno=0, role=5, fd=-1),
        'successful READY helper declarations')
    session, backend = trace['session'], trace['backend']
    if trace['session_present'] == 0:
        require(trace['snapshot_valid'] == trace['backend_destroyed'] == 0,
                'failed create cannot declare snapshot/destroy')
        require(_zero(session), 'failed create zero session snapshot')
        _zero_backend(backend, False)
        require(trace['create_error']['stage'] == 1 and 1 <= trace['create_error']['reason'] <= 5 and
                trace['create_error']['libdtrace_code'] == 0,
                'failed create requires its bounded error namespace')
        return 'failed-create'
    require(trace['snapshot_valid'] == trace['backend_destroyed'] == 1,
            'allocated backend snapshot/destroy unresolved')
    require(_zero(trace['create_error']), 'allocated backend cannot carry failed-create error')
    _same_binding(session['binding'], result, request, catalog)
    _same_binding(backend['binding'], result, request, catalog)
    require(session['configured'] == 1 and session['child'] == 1 and
        all(session[key] == 1 for key in ('gate_close_seen', 'gate_closed', 'close_attempted',
            'closed', 'parent_close_seen', 'parent_closed', 'bootstrap_seen', 'cleanup_attempted')),
            'session reap/gate/backend/parent closure')
    require(session['wait_status'] == result['wait']['raw_status'] and
        session['kill_claimed'] == int(result['wait']['kill_attempted']), 'actual wait/kill declarations differ')
    require(all(session[key] == 0 for key in ('go_claim_attempted', 'go_possibly_released',
        'go_result_seen', 'go_complete', 'go_bytes', 'bootstrap_sealed')), 'session cannot claim SIM GO/sealed success')
    require(session['cleanup_ms'] == 2000 and session['attempt_deadline_ns'] > 0 and
        session['attempt_deadline_ns'] == backend['original_attempt_deadline_ns'], 'original deadline/budget identity')
    require(sum(session['pumps']) == session['total_pumps'], 'session pump total identity')
    require(not session['cleanup_bound'] or session['cleanup_deadline_ns'] == trace['parent_cleanup_deadline_ns'],
        'declared cleanup deadline identity')
    require(session['cleanup_bound'] or session['cleanup_deadline_ns'] == 0,
        'unbound cleanup deadline must remain zero')
    require(not backend['cleanup_deadline_ns'] or backend['cleanup_deadline_ns'] == trace['parent_cleanup_deadline_ns'],
        'backend cleanup deadline identity')
    require(not session['bootstrap_seen'] or session['bootstrap_prefix_bytes'] == result['protocol']['bytes'],
        'literal bootstrap prefix identity')
    require(session['backend_touched'] == backend['start_attempted'], 'start resource shape differs')
    if backend['start_attempted'] == 0:
        _zero_backend(backend, True)
        require(all(session[key] == 0 for key in ('started', 'provider_ready', 'begin', 'terminal', 'end',
            'events', 'total_pumps', 'stop_attempted', 'stopped', 'drain_attempted', 'drained')),
            'allocated backend cannot declare started lifecycle')
        require((session['initialized'], session['start_attempted']) in ((0, 0), (1, 1)),
                'unknown fixed-caller allocated init/start shape')
        return 'allocated-not-started'
    require(session['initialized'] == session['start_attempted'] == session['backend_touched'] == 1,
            'backend start requires configured initialized session')
    require(backend['close_attempted'] == backend['resources_closed'] == 1,
            'started/failed-start backend resources unresolved')
    require(backend['writer_close_attempted_mask'] in PREFIX_MASKS and
        backend['writer_close_failed_mask'] == 0 and backend['writer_close_errno'] == [0, 0, 0, 0] and
        _zero(backend['writer_close_error']), 'writer ownership unresolved or non-prefix shape')
    require(_zero(backend['close_error']), 'failed backend close cannot declare a closed session')
    require(not backend['started'] or backend['writer_close_attempted_mask'] == 15,
            'fully started backend requires every writer close attempt')
    require(not session['started'] or backend['started'], 'session started without backend start')
    if not session['started']:
        require(all(session[key] == 0 for key in ('events', 'total_pumps', 'provider_ready', 'begin',
            'terminal', 'end', 'stop_attempted', 'stopped', 'drain_attempted', 'drained')) and
            all(backend[key] == 0 for key in ('events', 'raw_bytes', 'enablings', 'begin', 'terminal',
                'end', 'stop_attempted', 'stopped', 'drain_attempted', 'drained')),
            'unstarted session cannot pump/consume/stop/drain')
    if backend['started']:
        require(backend['inventory_probes'] >= 17 and backend['inventory_probes'] ==
            backend['expected_matches'] == backend['enabled_matches'], 'started backend exact enabled inventory')
    if backend['writer_close_attempted_mask'] != 15:
        require(all(backend[key] == 0 for key in ('started', 'events', 'raw_bytes', 'diagnostic_bytes',
            'inventory_bytes', 'drops', 'faults', 'inventory_probes', 'expected_matches', 'enabled_matches', 'enablings',
            'begin', 'terminal', 'end', 'stop_attempted', 'stopped', 'drain_attempted', 'drained')),
            'partial writer creation cannot declare later backend lifecycle')
    return 'started' if backend['started'] else 'failed-start'


@dataclass(frozen=True, slots=True)
class FrozenObject:
    items: tuple

    def __getitem__(self, key):
        for name, value in self.items:
            if name == key:
                return value
        raise KeyError(key)


def _freeze(value):
    if type(value) is dict:
        return FrozenObject(tuple((key, _freeze(item)) for key, item in value.items()))
    if type(value) is list:
        return tuple(_freeze(item) for item in value)
    return value


@dataclass(frozen=True, slots=True)
class DiagnosticFacts:
    native_status: int
    resource_shape: str
    request_sha256: str
    catalog_sha256: str
    result_bytes: bytes
    trace_bytes: bytes
    result: FrozenObject
    trace: FrozenObject
    schema: str = field(default='glue-owned-trace-sim-diagnostic-facts-v1', init=False)
    status: str = field(default='metadata-collectable-for-review', init=False)
    sim_case_pass: bool = field(default=False, init=False)
    sim_calibration_accepted: bool = field(default=False, init=False)
    exec_proved: bool = field(default=False, init=False)
    full_acceptance: bool = field(default=False, init=False)


def sim_metadata_collectable(native_status: int, result_bytes: bytes, trace_bytes: bytes, *,
        expected_request_sha256: str, expected_catalog_sha256: str) -> DiagnosticFacts:
    """Check pinned producer declarations only; no file/promotion authentication.

    Caller must separately verify actual promoted-file identity, pending absence,
    fixed invocation/outer status, stable namespace and checked metadata copying.
    Opaque BW/raw/error/clock observations never become calibrated SIM outcomes.
    """
    require(type(native_status) is int and native_status == 1, 'SIM diagnostic requires actual native CLI1')
    _validate(expected_request_sha256, SHA, 'expected request digest')
    _validate(expected_catalog_sha256, SHA, 'expected catalog digest')
    result = _parse(result_bytes, 8192, 'result')
    trace = _parse(trace_bytes, 16384, 'sidecar')
    _validate(result, RESULT, 'result')
    _validate(trace, TRACE, 'sidecar')
    shape = _collection_shape(result, trace, expected_request_sha256, expected_catalog_sha256)
    return DiagnosticFacts(native_status, shape, expected_request_sha256, expected_catalog_sha256,
        result_bytes, trace_bytes, _freeze(result), _freeze(trace))
