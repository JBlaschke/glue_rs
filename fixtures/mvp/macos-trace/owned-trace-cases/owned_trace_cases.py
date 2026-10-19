"""Pure later-layer consistency of two closed traced cases, never admission."""
from dataclasses import dataclass
import json

import legacy_codecs as codec
from owned_trace_check import RawFacts

BASE_ROSTER = frozenset(('request.bin', 'status.bin', 'probe.stdout', 'probe.stderr', 'result.json', 'trace.json'))
RAW_ROSTER = frozenset(('program.d', 'probes.tsv', 'events.jsonl', 'errors.jsonl'))
ZERO_SHA = '0' * 64
U64 = (1 << 64) - 1
INT = (1 << 31) - 1
PREFIX = b'/System/Volumes/Data/Library/GlueMVPFixtures/'


class CaseRefusal(ValueError):
    """No complete case facts are returned for inconsistent or unknown inputs."""


def require(ok, message):
    if not ok:
        raise CaseRefusal(message)


def uint(value, low=0, high=U64, label='integer'):
    require(type(value) is int and low <= value <= high, label + ' type/range')
    return value


def exact(value, expected, label):
    require(type(value) is type(expected), label + ' type')
    if type(expected) is dict:
        require(value.keys() == expected.keys(), label + ' keys')
        for key in expected:
            exact(value[key], expected[key], label + '.' + key)
    elif type(expected) in (list, tuple):
        require(len(value) == len(expected), label + ' length')
        for i, item in enumerate(expected):
            exact(value[i], item, label + '[' + str(i) + ']')
    else:
        require(value == expected, label + ' mismatch')


@dataclass(frozen=True)
class CaseBinding:
    controller_pid: int
    child_pid: int
    uid: int
    gid: int
    groups: tuple[int, ...]
    executable: bytes
    cwd: bytes
    cwd_device: int
    cwd_inode: int


@dataclass(frozen=True)
class CaseFacts:
    case: str
    controller_pid: int
    child_pid: int
    request_sha256: str
    catalog_sha256: str
    build_id: str
    cli_status: int
    raw_wait_status: int
    kill_attempted: bool
    declared_roster: tuple[str, ...]
    status_records: int
    eof_class: int
    raw_sha256: str | None
    raw_events: int
    session_events: int
    attempt_deadline_ns: int | None
    cleanup_deadline_ns: int
    tracing: bool = True
    exec_proved: bool = False
    full_acceptance: bool = False


def _otb_error():
    return dict(stage=0, reason=0, system_errno=0, libdtrace_code=0, callback_error=0, message_hex='')


def _ts_error():
    return dict(stage=0, reason=0, callback_error=0, detail=0)


def _binding(owner=0, child=0, request=ZERO_SHA, catalog=ZERO_SHA):
    return dict(fixture=int(owner != 0), owner_pid=owner, target_pid=child,
                request_sha256=request, catalog_sha256=catalog)


def _session_zero():
    fields = '''attempt_deadline_ns cleanup_deadline_ns cleanup_ms cleanup_attempted cleanup_bound
        configured initialized start_attempted backend_touched last_ns total_pumps child wait_status
        kill_claimed started provider_ready begin terminal end events go_claim_attempted
        go_possibly_released go_result_seen go_complete go_bytes bootstrap_seen bootstrap_sealed
        bootstrap_prefix_bytes gate_close_seen gate_closed stop_attempted stopped drain_attempted
        drained close_attempted closed parent_close_seen parent_closed'''.split()
    return dict.fromkeys(fields, 0) | dict(binding=_binding(), error=_ts_error(), cleanup_error=_ts_error(), pumps=[0, 0, 0])


def _backend_zero():
    fields = '''original_attempt_deadline_ns cleanup_deadline_ns writer_close_attempted_mask writer_close_failed_mask
        events raw_bytes diagnostic_bytes inventory_bytes drops faults inventory_probes expected_matches enabled_matches
        enablings begin terminal end start_attempted started stop_attempted stopped drain_attempted drained
        close_attempted resources_closed'''.split()
    return dict.fromkeys(fields, 0) | dict(binding=_binding(), first_error=_otb_error(), close_error=_otb_error(),
        writer_close_error=_otb_error(), writer_close_files=['program.d', 'probes.tsv', 'events.jsonl', 'errors.jsonl'],
        writer_close_errno=[0, 0, 0, 0])


def _sidecar(data):
    require(type(data) is bytes and len(data) <= 16384, 'sidecar byte bound/type')
    def pairs(items):
        out = {}
        for key, value in items:
            require(key not in out, 'sidecar duplicate JSON key')
            out[key] = value
        return out
    def integer(text):
        require(len(text) <= 21, 'sidecar integer token bound')
        return int(text)
    def invalid_number(_):
        raise CaseRefusal('sidecar non-integer number')
    try:
        value = json.loads(data.decode('ascii'), object_pairs_hook=pairs, parse_int=integer,
                           parse_float=invalid_number, parse_constant=invalid_number)
        require(data == (json.dumps(value, separators=(',', ':'), ensure_ascii=True) + '\n').encode('ascii'),
                'sidecar canonical JSON')
        return value
    except (UnicodeError, json.JSONDecodeError, RecursionError) as error:
        raise CaseRefusal('sidecar invalid JSON') from error


def _trace(trace, positive, binding, raw):
    require(type(trace) is dict, 'sidecar object')
    # Extract only independently bounded varying observations; the full exact
    # templates below validate every other field, key, type and zero state.
    cleanup = uint(trace.get('parent_cleanup_deadline_ns'), 1, label='parent cleanup deadline')
    session, backend = _session_zero(), _backend_zero()
    attempt = None
    if positive:
        require(type(raw) is RawFacts, 'accepted RawFacts required')
        uint(raw.owner_pid, 1, INT, 'raw owner PID'); uint(raw.target_pid, 1, INT, 'raw target PID')
        require(raw.owner_pid == binding['owner_pid'] and raw.target_pid == binding['target_pid'], 'raw PID binding')
        codec.hexsha(raw.raw_sha256)
        require(type(trace.get('session')) is dict, 'session object')
        values = trace['session']
        attempt = uint(values.get('attempt_deadline_ns'), 1, label='attempt deadline')
        last = uint(values.get('last_ns'), 1, label='last clock')
        require(last < cleanup and cleanup - last <= 2000000000, 'declared cleanup clock order/bound')
        pumps = values.get('pumps')
        require(type(pumps) is list and len(pumps) == 3, 'session pumps shape')
        for n in pumps:
            uint(n, 0, 65536, 'session pump')
        require(pumps[0] >= 1 and pumps[1] >= 1 and pumps[2] == 0 and sum(pumps) <= 65536, 'clean case pump counts')
        for field, lo, hi in (('events', 3, 1000000), ('raw_bytes', 1, 134217728),
                             ('inventory_bytes', 1, 1048576), ('inventory_probes', 17, 8192),
                             ('observed_enablings', 3, 8192), ('shadow_exits', 0, 1000000),
                             ('post_terminal_lwp_exits', 0, 1000000)):
            uint(getattr(raw, field), lo, hi, 'raw ' + field)
        uint(raw.error_bytes, 0, 0, 'raw diagnostic bytes')
        uint(raw.begin_event, 1, 1, 'raw BEGIN ordinal')
        uint(raw.end_event, raw.events, raw.events, 'raw END ordinal')
        uint(raw.terminal_event, 2, raw.end_event - 1, 'raw terminal ordinal')
        require(raw.observed_enablings <= min(raw.inventory_probes, raw.events), 'raw observed enabling count')
        for counts, total, label in ((raw.inventory_kind_counts, raw.inventory_probes, 'inventory'),
                                      (raw.event_kind_counts, raw.events, 'event')):
            require(type(counts) is tuple and len(counts) == 19, 'raw ' + label + ' histogram shape')
            for n in counts:
                uint(n, 0, total, 'raw histogram count')
            require(sum(counts) == total and counts[0] == counts[14] == 0, 'raw ' + label + ' histogram totals')
        require(all(raw.inventory_kind_counts[k] >= 1 for k in range(1, 19) if k != 14), 'raw required inventory kinds')
        require(raw.event_kind_counts[1] == raw.event_kind_counts[17] == 1 and
                raw.event_kind_counts[18] == raw.shadow_exits + 1 and
                raw.event_kind_counts[11] >= raw.post_terminal_lwp_exits and
                all(raw.event_kind_counts[k] == 0 for k in (4, 12, 13)), 'raw lifecycle histogram facts')
        projected = raw.events + 1 - raw.shadow_exits - raw.post_terminal_lwp_exits
        uint(projected, 4, 1000000, 'projected session events')
        session.update(dict.fromkeys('''cleanup_attempted cleanup_bound configured initialized start_attempted backend_touched
            started provider_ready begin terminal end go_claim_attempted go_possibly_released go_result_seen go_complete
            bootstrap_seen bootstrap_sealed gate_close_seen gate_closed stop_attempted stopped drain_attempted drained
            close_attempted closed parent_close_seen parent_closed'''.split(), 1))
        session.update(binding=binding, attempt_deadline_ns=attempt, cleanup_deadline_ns=cleanup, cleanup_ms=2000,
                       last_ns=last, total_pumps=sum(pumps), pumps=pumps, child=1, events=projected,
                       go_bytes=64, bootstrap_prefix_bytes=512)
        backend.update(dict.fromkeys('start_attempted started stop_attempted stopped drain_attempted drained close_attempted resources_closed'.split(), 1))
        backend.update(binding=binding, original_attempt_deadline_ns=attempt, cleanup_deadline_ns=cleanup,
                       writer_close_attempted_mask=15, events=raw.events, raw_bytes=raw.raw_bytes,
                       inventory_bytes=raw.inventory_bytes, inventory_probes=raw.inventory_probes,
                       expected_matches=raw.inventory_probes, enabled_matches=raw.inventory_probes,
                       enablings=raw.observed_enablings, begin=1, terminal=1, end=1)
    else:
        require(raw is None, 'denied cannot carry raw facts')
    expected = dict(schema='glue-owned-trace-session-diagnostic-v1', tracing=True, exec_proved=False,
        full_acceptance=False, parent_cleanup_deadline_ns=cleanup, parent_cleanup_valid=1,
        create_attempted=int(positive), session_present=int(positive), snapshot_valid=int(positive),
        backend_destroyed=int(positive), finalization_safe=1, success_eligible=int(positive),
        create_error=_otb_error(), session=session, backend=backend)
    exact(trace, expected, 'sidecar')
    return attempt, cleanup, session['events']


def _check(case, *, catalog, request, status, probe_stdout, probe_stderr, result, sidecar, raw, actual, roster, cli_status):
    positive = case == 'positive'
    require(type(actual) is CaseBinding, 'actual binding type')
    owner, child = uint(actual.controller_pid, 1, INT, 'controller PID'), uint(actual.child_pid, 1, INT, 'child PID')
    require(owner != child, 'distinct actual PIDs')
    uint(actual.uid, 1, INT, 'UID'); uint(actual.gid, 1, INT, 'GID')
    require(type(actual.groups) is tuple and 1 <= len(actual.groups) <= 16, 'actual groups type/count')
    for group in actual.groups:
        uint(group, 0, INT, 'actual group')
    require(actual.groups[0] == actual.gid and len(set(actual.groups)) == len(actual.groups), 'actual canonical groups')
    require(type(actual.executable) is bytes and type(actual.cwd) is bytes, 'actual path types')
    uint(actual.cwd_device, 1, U64, 'actual cwd device'); uint(actual.cwd_inode, 1, U64, 'actual cwd inode')
    require(type(roster) is frozenset and all(type(n) is str for n in roster) and
            roster == BASE_ROSTER | (RAW_ROSTER if positive else frozenset()), 'declared case roster')
    uint(cli_status, 0, INT, 'CLI status')
    require(cli_status == (0 if positive else 1), 'case CLI status')
    require(type(probe_stdout) is bytes and len(probe_stdout) <= 256 and
            type(probe_stderr) is bytes and len(probe_stderr) <= 4096, 'capture byte bounds/types')
    cat, req = codec.decode_catalog(catalog), codec.decode_request(request)
    require(req['release'] == 1 and req['attempt_ms'] == 10000 and req['cleanup_ms'] == 2000, 'fixed request budget/release')
    require(req['catalog_sha256'] == cat['sha256'], 'request catalog binding')
    require(actual.cwd == PREFIX + cat['build_id'].encode('ascii') and actual.executable == actual.cwd + b'/context-probe', 'fixed catalog build paths')
    require((req['uid'], req['gid'], tuple(req['groups']), req['executable'], req['cwd'], req['cwd_device'], req['cwd_inode']) ==
            (actual.uid, actual.gid, actual.groups, actual.executable, actual.cwd, actual.cwd_device, actual.cwd_inode) and
            actual.cwd_device == cat['data_mount']['device'], 'request actual context')
    records, eof = codec.decode_stream(status, (owner, child, req['sha256']))
    require([r['kind'] for r in records] == ([1, 2] if positive else [3]), 'case status record kinds')
    ids = [actual.uid, actual.uid, actual.gid, actual.gid]
    if positive:
        ready = records[0]
        require(ready['flags'] == 3 and ready['ids'] == ids and tuple(ready['groups']) == actual.groups and
                (ready['cwd_device'], ready['cwd_inode']) == (actual.cwd_device, actual.cwd_inode) and
                ready['signal_policy_sha256'] == codec.SIGNAL_POLICY_SHA, 'READY context')
        probe = codec.decode_probe(probe_stdout, req['sha256'])
        require((probe['pid'], probe['ppid'], probe['pgid']) == (child, owner, child) and probe['ids'] == ids and
                tuple(probe['groups']) == actual.groups and (probe['cwd_device'], probe['cwd_inode']) ==
                (actual.cwd_device, actual.cwd_inode) and probe['stdio_descriptor_flags'] == [0, 0, 0], 'NP actual context')
    else:
        require(not probe_stdout, 'denied stdout must be empty')
        require(all(records[0][k] == v for k, v in dict(stage=6, reason=3, errno=13, flags=1, detail=-1).items()), 'exact denied child ERROR')
    require(not probe_stderr, 'stderr must be empty')
    output = codec.result_json(result)
    require(type(output) is dict and type(output.get('wait')) is dict, 'result/wait object')
    wait = output['wait']
    require(type(wait.get('kill_attempted')) is bool, 'wait kill boolean')
    raw_wait = uint(wait.get('raw_status'), 0, INT, 'raw wait status')
    require((raw_wait, wait['kill_attempted']) in (((0, False),) if positive else
            ((30720, False), (30720, True), (9, True))), 'closed wait/kill matrix')
    err = dict(stage=0, reason=0, errno=0, detail=0)
    child_error = dict(present=False, stage=0, reason=0, errno=0, flags=0, detail=0) if positive else dict(present=True, stage=6, reason=3, errno=13, flags=1, detail=-1)
    expected = dict(schema='glue-owned-traced-bootstrap-diagnostic-v1', tracing=True, exec_proved=False,
        full_acceptance=False, identity_policy='request-declarations-compared-to-observations',
        consistent_owned_probe=positive, controller_pid=owner, child_pid=child,
        parent_error=err if positive else dict(stage=10, reason=12, errno=0, detail=-1), cleanup_error=err,
        helpers=dict(admission=dict(stage=0, reason=0, errno=0, component=0, metadata_step=0),
                     endpoints=dict(stage=0, reason=0, errno=0, role=5, fd=-1), signal_prepare=dict(stage=0, reason=0, errno=0)),
        child_error=child_error, protocol=dict(records=len(records), bytes=len(status), wire_fault=0, io_stage=0,
        io_reason=0, io_errno=0, eof_class=3 if positive else 2), go=dict(action=1, attempted=positive,
        possibly_released=positive, bytes=64 if positive else 0, stage=0, reason=0, errno=0, closed=True),
        ready_matched=positive, probe_matched=positive,
        wait=dict(forked=True, reaped=True, lost=False, kill_attempted=wait['kill_attempted'], raw_status=raw_wait),
        signals=dict(prepared=True, restore_called=True, pipe_restored=True, mask_restored=True, restore_stage=0, restore_reason=0, restore_errno=0),
        identities=dict(request_sha256=req['sha256'], catalog_sha256=cat['sha256'], signal_policy_sha256=codec.SIGNAL_POLICY_SHA,
            status_sha256=codec.sha(status), stdout_sha256=codec.sha(probe_stdout), stderr_sha256=codec.sha(probe_stderr),
            probe_sha256=cat['probe_sha256'], runner_static_sources_sha256=cat['runner_static_sources_sha256'], build_recipe_sha256=cat['build_recipe_sha256']),
        stdout_capture_valid=True, stderr_capture_valid=True, stdout_bytes=len(probe_stdout), stderr_bytes=0,
        trace_sidecar='trace.json', trace_finalization_safe=True, trace_success_eligible=positive)
    exact(output, expected, 'result')
    binding = _binding(owner, child, req['sha256'], cat['sha256'])
    attempt, cleanup, session_events = _trace(_sidecar(sidecar), positive, binding, raw)
    require(eof == (3 if positive else 2), 'case EOF')
    return CaseFacts(case, owner, child, req['sha256'], cat['sha256'], cat['build_id'], cli_status, raw_wait,
        wait['kill_attempted'], tuple(sorted(roster)), len(records), eof, raw.raw_sha256 if positive else None,
        raw.events if positive else 0, session_events, attempt, cleanup)


def validate_case(case, *, catalog: bytes, request: bytes, status: bytes, probe_stdout: bytes,
                  probe_stderr: bytes, result: bytes, sidecar: bytes, raw: RawFacts | None,
                  actual: CaseBinding, roster: frozenset[str], cli_status: int) -> CaseFacts:
    """Later pure consistency layer; caller input provenance/roster is trusted.

    No filesystem absence, authentication, outer/export safety, native clock
    provenance or deadline origin is established. RawFacts must come from the
    separately pinned raw validator; their provenance is a caller declaration.
    """
    require(type(case) is str and case in ('positive', 'denied'), 'SIM/unknown case uncalibrated')
    try:
        return _check(case, catalog=catalog, request=request, status=status, probe_stdout=probe_stdout,
                      probe_stderr=probe_stderr, result=result, sidecar=sidecar, raw=raw,
                      actual=actual, roster=roster, cli_status=cli_status)
    except codec.Refusal as error:
        raise CaseRefusal('codec: ' + str(error)) from error
