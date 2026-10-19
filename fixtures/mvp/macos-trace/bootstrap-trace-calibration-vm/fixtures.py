"""Independent C/BW/NP and raw scalar serializers reused from closed fixture sources.
No producer or validation generator defines these bytes; identities are synthetic.
"""
import json
import struct
import hashlib
import checker
raw_module,codecs,cases=checker.libraries()
OWNER=123
TARGET=456
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
    raw = None  # The pair obtains actual RawFacts only through validate_raw.
    roster = frozenset(('request.bin', 'status.bin', 'probe.stdout', 'probe.stderr', 'result.json', 'trace.json'))
    if positive:
        roster |= frozenset(('program.d', 'probes.tsv', 'events.jsonl', 'errors.jsonl'))
    return dict(catalog=catalog, request=request, status=status, probe_stdout=out, probe_stderr=b'', result=encode(result),
                sidecar=encode(sidecar), raw=raw, actual=actual, roster=roster, cli_status=0 if positive else 1)


PROGRAM = b'''#pragma D option quiet
BEGIN { watched[456]=1;trace((uint64_t)1);trace((uint64_t)timestamp);trace((uint64_t)pid);trace((uint64_t)tid);trace((uint64_t)(0));}
END {trace((uint64_t)17);trace((uint64_t)timestamp);trace((uint64_t)pid);trace((uint64_t)tid);trace((uint64_t)(0));}
syscall:::entry /watched[pid]/ {trace((uint64_t)2);trace((uint64_t)timestamp);trace((uint64_t)pid);trace((uint64_t)tid);trace((uint64_t)(ppid));trace((uint64_t)arg0);trace((uint64_t)arg1);trace((uint64_t)arg2);trace((uint64_t)arg3);trace((uint64_t)arg4);trace((uint64_t)arg5);trace((uint64_t)arg6);trace((uint64_t)arg7);}
syscall:::return /watched[pid]/ {trace((uint64_t)3);trace((uint64_t)timestamp);trace((uint64_t)pid);trace((uint64_t)tid);trace((uint64_t)(ppid));trace((uint64_t)arg0);trace((uint64_t)arg1);trace((uint64_t)arg2);trace((uint64_t)arg3);trace((uint64_t)errno);}
mach_trap:::entry /watched[pid]/ {trace((uint64_t)15);trace((uint64_t)timestamp);trace((uint64_t)pid);trace((uint64_t)tid);trace((uint64_t)(ppid));trace((uint64_t)arg0);trace((uint64_t)arg1);trace((uint64_t)arg2);trace((uint64_t)arg3);trace((uint64_t)arg4);trace((uint64_t)arg5);trace((uint64_t)arg6);trace((uint64_t)arg7);}
mach_trap:::return /watched[pid]/ {trace((uint64_t)16);trace((uint64_t)timestamp);trace((uint64_t)pid);trace((uint64_t)tid);trace((uint64_t)(ppid));trace((uint64_t)arg0);}
proc:::create /watched[pid]/ {watched[pid]=1;trace((uint64_t)4);trace((uint64_t)timestamp);trace((uint64_t)pid);trace((uint64_t)tid);trace((uint64_t)(args[0]->pr_pid));}
proc:::start /watched[pid]/ {watched[pid]=1;trace((uint64_t)5);trace((uint64_t)timestamp);trace((uint64_t)pid);trace((uint64_t)tid);trace((uint64_t)(ppid));}
proc:::exec-success /watched[pid]/ {watched[pid]=1;trace((uint64_t)7);trace((uint64_t)timestamp);trace((uint64_t)pid);trace((uint64_t)tid);trace((uint64_t)(ppid));}
proc:::exit /watched[pid]/ {trace((uint64_t)6);trace((uint64_t)timestamp);trace((uint64_t)pid);trace((uint64_t)tid);trace((uint64_t)(arg0));}
proc:::exec-failure /watched[pid]/ {trace((uint64_t)8);trace((uint64_t)timestamp);trace((uint64_t)pid);trace((uint64_t)tid);trace((uint64_t)(arg0));}
proc:::lwp-create /watched[pid]/ {trace((uint64_t)9);trace((uint64_t)timestamp);trace((uint64_t)pid);trace((uint64_t)tid);trace((uint64_t)(args[0]->pr_lwpid));}
proc:::lwp-start /watched[pid]/ {trace((uint64_t)10);trace((uint64_t)timestamp);trace((uint64_t)pid);trace((uint64_t)tid);trace((uint64_t)(0));}
proc:::lwp-exit /watched[pid]/ {trace((uint64_t)11);trace((uint64_t)timestamp);trace((uint64_t)pid);trace((uint64_t)tid);trace((uint64_t)(0));}
proc:::spawn-success /watched[pid]/ {trace((uint64_t)12);trace((uint64_t)timestamp);trace((uint64_t)pid);trace((uint64_t)tid);trace((uint64_t)(0));}
proc:::spawn-failure /watched[pid]/ {trace((uint64_t)13);trace((uint64_t)timestamp);trace((uint64_t)pid);trace((uint64_t)tid);trace((uint64_t)(arg0));}
proc:::exited /watched[args[0]->pr_pid]/ {trace((uint64_t)18);trace((uint64_t)timestamp);trace((uint64_t)pid);trace((uint64_t)tid);trace((uint64_t)(args[0]->pr_pid));trace((uint64_t)arg1);trace((uint64_t)args[0]->pr_addr);trace((uint64_t)((struct proc *)args[0]->pr_addr)->p_refcount);}
'''
# (provider,module,function,name), selected categories all17; no kind14.
NAMES = {
    1: ('dtrace', '', '', 'BEGIN'), 17: ('dtrace', '', '', 'END'),
    2: ('syscall', '', 'read', 'entry'), 3: ('syscall', '', 'read', 'return'),
    15: ('mach_trap', '', 'mach_msg2_trap', 'entry'),
    16: ('mach_trap', '', 'mach_msg2_trap', 'return'),
    4: ('proc', 'mach_kernel', '', 'create'), 5: ('proc', '', '', 'start'),
    6: ('proc', '', '', 'exit'), 7: ('proc', '', '', 'exec-success'),
    8: ('proc', '', '', 'exec-failure'), 9: ('proc', '', '', 'lwp-create'),
    10: ('proc', '', '', 'lwp-start'), 11: ('proc', '', '', 'lwp-exit'),
    12: ('proc', '', '', 'spawn-success'), 13: ('proc', '', '', 'spawn-failure'),
    18: ('proc', '', '', 'exited'),
}
# Explicit native sizes + zero-descriptor presence, independent fixture table.
SHAPES = {1: (56, True), 2: (120, False), 3: (96, False), 4: (56, True),
          5: (56, True), 6: (56, False), 7: (56, True), 8: (56, False),
          9: (56, False), 10: (56, False), 11: (56, False),
          12: (56, False), 13: (56, False), 15: (120, False),
          16: (64, False), 17: (56, False), 18: (80, False)}
PROBES = ''.join(str(100 + k) + '\t' + '\t'.join(NAMES[k]) + '\n'
                 for k in sorted(NAMES)).encode('ascii')


def event(kind, *, actor=None, detail=None, refcount=0x1c2):
    total, assignment = SHAPES[kind]
    actor = (OWNER if kind in (1, 17) else TARGET) if actor is None else actor
    if detail is None:
        detail = OWNER if kind in (2, 3, 5, 7, 15, 16) else TARGET if kind == 18 else 0
    values = [kind, 0x102030405060708, actor, 0xffeeddccbbaa, detail]
    if kind == 18:
        values += [0xffffffffffffffff, 0xabcdef123456, refcount]
    else:
        values += list(range(0x11110000, 0x11110000 + (total - 56) // 8))
    records = [{'action': 1, 'size': 0, 'offset': 12, 'hex': ''}] if assignment else []
    for i, value in enumerate(values):
        records.append({'action': 1, 'size': 8, 'offset': 16 + i * 8,
                        'hex': struct.pack('<Q', value).hex()})
    return dict(event=0, cpu=7, epid=1000 + kind, probe_id=100 + kind,
                record_bytes=total, header_record_indexes=list(range(int(assignment), int(assignment) + 5)),
                kind=kind, timestamp=values[1], pid=actor, tid=values[3], detail=detail,
                **dict(zip(('provider', 'module', 'function', 'name'), NAMES[kind])), records=records)


def line(record, ordinal, size=None):
    record = dict(record, event=ordinal)
    data = json.dumps(record, separators=(',', ':'), ensure_ascii=True).encode('ascii') + b'\n'
    if size is not None:
        assert size >= len(data)
        data = data[:-1] + b' ' * (size - len(data)) + b'\n'
    return data


def lines(records):
    return [line(record, i) for i, record in enumerate(records, 1)]


def pair():
    positive=fixture('positive');denied=fixture('denied')
    capture=b''.join(lines([event(1),event(18),event(17)]))
    side=json.loads(positive['sidecar'])
    side['session'].update(events=4)
    side['backend'].update(events=3,raw_bytes=len(capture),inventory_bytes=len(PROBES),enablings=3)
    positive['sidecar']=encode(side)
    return positive,denied,{'program.d':PROGRAM,'probes.tsv':PROBES,'events.jsonl':capture,'errors.jsonl':b''}
