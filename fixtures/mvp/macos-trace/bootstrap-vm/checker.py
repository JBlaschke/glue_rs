#!/usr/bin/env python3
"""Read-only consistency check for the one closed NONTRACING VM batch.

No command, target, wrapper, compiler or retained binary is executed. A passing
result is an owned-fixture consistency observation, never kernel exec proof.
"""
import argparse
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import re
import struct
import sys

HERE = Path(__file__).resolve().parent
INT = (1 << 31) - 1
U64 = (1 << 64) - 1
CASES = ('positive', 'simulated', 'denied', 'trailing')
BATCH = (b'schema\tglue-bootstrap-vm-batch-v1\npreflight\t0\ninstall\t0\n'
         b'positive\t0\nsimulated\t0\ndenied\t0\ntrailing\t0\ncomplete\t0\n')
RECEIPT_NAMES = {'outer.argv', 'outer.stdout', 'outer.stderr', 'outer.status'}
# The exact compiled Darwin policy: SDK sys/signal.h NSIG=32, KILL=9,
# STOP=17; bootstrap_signals.c bs_policy_bytes writes every other 1..31.
_SIGNALS = [n for n in range(1, 32) if n not in (9, 17)]
SIGNAL_POLICY_SHA = hashlib.sha256(b'GLUESP01' + struct.pack('>HHII', 1, len(_SIGNALS),
                                 20 + 4 * len(_SIGNALS), 15) +
                                 struct.pack('>' + 'I' * len(_SIGNALS), *_SIGNALS)).hexdigest()


class Refusal(ValueError):
    """A bounded, fail-closed diagnostic; callers must retain original inputs."""


def require(ok, message):
    if not ok:
        raise Refusal(message)


def sha(data):
    return hashlib.sha256(data).hexdigest()


def number(n, lo=0, hi=INT):
    require(type(n) is int and lo <= n <= hi, 'integer type/range')
    return n


def keys(v, names):
    require(type(v) is dict and set(v) == set(names.split()), 'object keys')
    return v


def boolean(v):
    require(type(v) is bool, 'boolean type')
    return v


def hexsha(v):
    require(type(v) is str and re.fullmatch('[0-9a-f]{64}', v), 'SHA-256 syntax')
    return v


def result_json(data):
    require(type(data) is bytes and len(data) <= 8192, 'result JSON bound')
    def pairs(items):
        out = {}
        for key, value in items:
            require(key not in out, 'duplicate JSON key')
            out[key] = value
        return out
    def integer(text):
        require(len(text) <= 21, 'JSON integer bound')
        return int(text)
    def non_integer(_text):
        raise Refusal('non-integer JSON number')
    try:
        value = json.loads(data.decode('ascii'), object_pairs_hook=pairs, parse_int=integer,
                           parse_float=non_integer, parse_constant=non_integer)
        require(data == (json.dumps(value, separators=(',', ':'), ensure_ascii=True) + '\n').encode('ascii'),
                'canonical producer JSON encoding')
        return value
    except (ValueError, UnicodeError, RecursionError) as exc:
        raise Refusal('invalid result JSON: ' + str(exc)[:128]) from exc


def uint(data, at, width=4):
    return int.from_bytes(data[at:at + width], 'big')


def groups(gid, count, slots):
    require(type(slots) is list and len(slots) == 16, 'group slots')
    number(gid, 1)
    number(count, 1, 16)
    for n in slots:
        number(n)
    require(slots[0] == gid and len(set(slots[:count])) == count and
            not any(slots[count:]), 'canonical ordered groups')
    return slots[:count]


def path_bytes(value, cwd=False):
    require(1 <= len(value) <= 4095 and value[:1] == b'/' and b'\0' not in value,
            'absolute request path')
    if cwd and value == b'/':
        return value
    require(value != b'/' and all(1 <= len(c) <= 255 and c not in (b'.', b'..')
                                for c in value[1:].split(b'/')), 'request path components')
    return value


def decode_request(data):
    require(type(data) is bytes and 208 <= len(data) <= 16384, 'BR length')
    require(data[:8] == b'GLUENR01' and uint(data, 8, 2) == 1 and
            uint(data, 10, 2) == 208 and uint(data, 12) == len(data), 'BR header')
    require(not any(data[184:208]), 'BR reserved')
    uid, gid, count = (uint(data, x) for x in (20, 24, 28))
    number(uid, 1)
    slots = list(struct.unpack_from('>16I', data, 32))
    actual = groups(gid, count, slots)
    require([uint(data, x) for x in (16, 96, 100, 108, 120, 124)] ==
            [1, 1, 1, 4096, 1, 0], 'BR selectors')
    release = uint(data, 104)
    require(release in (1, 2), 'BR release')
    number(uint(data, 112), 1, 10000)
    number(uint(data, 116), 1, 2000)
    a, b = uint(data, 176), uint(data, 180)
    require(a + b == len(data) - 208, 'BR path lengths')
    exe, cwd = path_bytes(data[208:208 + a]), path_bytes(data[208 + a:], True)
    return {'uid': uid, 'gid': gid, 'groups': actual, 'slots': slots,
            'release': release, 'attempt_ms': uint(data, 112), 'cleanup_ms': uint(data, 116),
            'catalog_sha256': data[128:160].hex(), 'cwd_device': uint(data, 160, 8),
            'cwd_inode': uint(data, 168, 8), 'executable': exe, 'cwd': cwd, 'sha256': sha(data)}


def decode_catalog(data):
    require(type(data) is bytes and len(data) == 269, 'catalog length')
    require(data[:12] == b'GLUENC01\0\1\0\300' and uint(data, 12) == 269 and
            data[184:192] == b'\0\100\0\15\0\0\0\0' and
            data[256:] == b'context-probe', 'catalog header')
    probe_size = number(uint(data, 16, 8), 1, 4194304)
    build = data[192:256].decode('ascii', 'strict')
    hexsha(build)
    mounts = []
    for off in (24, 40):
        device = number(uint(data, off, 8), 1, U64)
        fsid = list(struct.unpack_from('>ii', data, off + 8))
        require(any(fsid), 'empty FSID')
        mounts.append({'device': device, 'fsid': fsid})
    require(mounts[0] != mounts[1], 'identical root/Data mount tuples')
    return {'probe_size': probe_size, 'root_mount': mounts[0], 'data_mount': mounts[1],
            'probe_sha256': data[56:88].hex(), 'probe_sources_sha256': data[88:120].hex(),
            'runner_static_sources_sha256': data[120:152].hex(),
            'build_recipe_sha256': data[152:184].hex(), 'build_id': build, 'sha256': sha(data)}


def decode_status(data, binding):
    require(type(data) is bytes and len(data) == 256, 'BW length')
    require(data[:8] == b'GLUEBS01' and uint(data, 8, 2) == 1 and
            uint(data, 12) == 256 and not any(data[232:]), 'BW header/reserved')
    controller, child = uint(data, 16), uint(data, 20)
    number(controller, 1); number(child, 1)
    require(controller != child and (controller, child, data[24:56].hex()) == binding, 'BW binding')
    kind, seq, stage, err, flags, reason, detail = (
        uint(data, 10, 2), uint(data, 56), uint(data, 60), uint(data, 64),
        uint(data, 68), uint(data, 224), uint(data, 228))
    detail = -1 if detail == (1 << 32) - 1 else number(detail)
    require(kind in (1, 2, 3) and flags & ~3 == 0, 'BW kind/flags')
    ids = [uint(data, x) for x in (72, 76, 80, 84)]
    slots = list(struct.unpack_from('>16I', data, 92))
    fds = list(struct.unpack_from('>5I', data, 172))
    out = {'kind': kind, 'sequence': seq, 'stage': stage, 'errno': err, 'flags': flags,
           'reason': reason, 'detail': detail, 'ids': ids, 'slots': slots,
           'cwd_device': uint(data, 156, 8), 'cwd_inode': uint(data, 164, 8),
           'kept_fds': fds, 'signal_policy_sha256': data[192:224].hex()}
    if kind == 1:
        require((seq, stage, reason, err, detail) == (0, 0, 0, 0, -1) and flags & 1,
                'BW READY phase')
        number(ids[0], 1); number(ids[2], 1)
        require(ids[1] == ids[0] and ids[3] == ids[2], 'BW READY IDs')
        out['groups'] = groups(ids[2], uint(data, 88), slots)
        require(fds[:3] == [0, 1, 2] and fds[3] != fds[4], 'BW READY FDs')
        number(fds[3], 3); number(fds[4], 3)
    else:
        require(not any(data[72:224]), 'BW non-READY observations')
        if kind == 2:
            require((seq, stage, reason, err, detail) == (1, 13, 0, 0, -1) and flags & 1,
                    'BW ATTEMPT phase')
        else:
            require(1 <= stage <= 13 and 1 <= reason <= 17, 'BW ERROR selectors')
            require((reason == 3 and 1 <= err <= INT) or (reason != 3 and err == 0), 'BW errno')
            require((seq == 0 and stage <= 8) or (seq == 1 and 9 <= stage <= 12) or
                    (seq == 2 and stage == 13), 'BW ERROR phase')
            require(not (stage < 5 and flags & 1) and not (stage >= 6 and not flags & 1) and
                    not (stage < 7 and flags & 2), 'BW ERROR mutation phase')
    return out


def decode_stream(data, binding):
    require(type(data) is bytes and len(data) in (256, 512, 768), 'status stream length')
    records, phase, ready_flags = [], 0, None
    for at in range(0, len(data), 256):
        s = decode_status(data[at:at + 256], binding)
        require(s['sequence'] == len(records) and phase != 3 and
                s['kind'] in ({0: (1, 3), 1: (2, 3), 2: (3,)}[phase]), 'status order/extra')
        if phase:
            require(s['flags'] == ready_flags, 'status changed flags')
        if s['kind'] == 1:
            ready_flags = s['flags']
        phase = s['kind']
        records.append(s)
    return records, 2 if phase == 3 else 3 if phase == 2 else 1


def decode_probe(data, request_sha):
    require(type(data) is bytes and len(data) == 256, 'NP length')
    require(data[:8] == b'GLUENP01' and uint(data, 8, 2) == 1 and
            uint(data, 10, 2) == 256 and uint(data, 12) == 1 and
            data[16:48].hex() == request_sha and not any(data[232:]), 'NP header/binding')
    pid, ppid, pgid = (uint(data, x) for x in (48, 52, 56))
    number(pid, 1); number(ppid, 1)
    require(pid != ppid and pgid == pid, 'NP process context')
    ids = [uint(data, x) for x in (60, 64, 68, 72)]
    for n in ids:
        number(n, 1)
    require(ids[0] == ids[1] and ids[2] == ids[3], 'NP equal IDs')
    actual = groups(ids[2], uint(data, 76), list(struct.unpack_from('>16I', data, 80)))
    require(uint(data, 160) == 3 and list(struct.unpack_from('>3I', data, 164)) == [0, 1, 2], 'NP FD set')
    status, descriptors = list(struct.unpack_from('>3I', data, 176)), list(struct.unpack_from('>3I', data, 188))
    for i, (f, d) in enumerate(zip(status, descriptors)):
        number(f); number(d)
        require(f & 3 == (0 if i == 0 else 1) and not f & (4 | 64 | 32768) and not d & 1,
                'NP stdio policy')
    require(struct.unpack_from('>i', data, 200)[0] == -1 and uint(data, 204) == 1 and
            [uint(data, x) for x in (208, 212, 216, 220)] == ids and
            uint(data, 224) == 1 and uint(data, 228) == 0, 'NP root-regain/signals/env')
    return {'pid': pid, 'ppid': ppid, 'pgid': pgid, 'ids': ids, 'groups': actual,
            'cwd_device': uint(data, 144, 8), 'cwd_inode': uint(data, 152, 8),
            'stdio_status_flags': status, 'stdio_descriptor_flags': descriptors}


def _error(v, fields='stage reason errno detail', detail=True):
    keys(v, fields)
    for k, n in v.items():
        number(n, -1 if k in ('detail', 'role', 'fd') else 0)
    if detail:
        require(all(v[k] == 0 for k in ('stage', 'reason', 'errno')), 'unexpected producer/helper error')


def check_case(case, data, plan, catalog):
    """Pure byte validator. Public callers must use check(), which verifies origins."""
    require(case in CASES[:3], 'case selector')
    reqbytes, statusbytes = data['request.bin'], data['status.bin']
    request = decode_request(reqbytes)
    release = 2 if case == 'simulated' else 1
    expected_ids = plan['expected_ids']
    require([request['uid']] * 2 + [request['gid']] * 2 == expected_ids and
            request['groups'] == plan['expected_groups'] and request['release'] == release and
            request['attempt_ms'] == 10000 and request['cleanup_ms'] == 2000 and
            request['catalog_sha256'] == catalog['sha256'] and
            request['executable'] == (plan['build_dir'] + '/context-probe').encode('ascii') and
            request['cwd'] == plan['build_dir'].encode('ascii') and
            request['cwd_device'] == catalog['data_mount']['device'] and request['cwd_inode'] != 0,
            'request/profile mismatch')
    result = result_json(data['result.json'])
    keys(result, 'schema tracing exec_proved full_acceptance identity_policy consistent_owned_probe controller_pid child_pid parent_error cleanup_error helpers child_error protocol go ready_matched probe_matched wait signals identities stdout_capture_valid stderr_capture_valid stdout_bytes stderr_bytes')
    require(result['schema'] == 'glue-owned-bootstrap-diagnostic-v1' and
            result['identity_policy'] == 'request-declarations-compared-to-observations', 'result schema')
    for name in ('tracing', 'exec_proved', 'full_acceptance'):
        require(boolean(result[name]) is False, 'result scope overclaim')
    for name in ('consistent_owned_probe', 'ready_matched', 'probe_matched', 'stdout_capture_valid', 'stderr_capture_valid'):
        boolean(result[name])
    owner, child = number(result['controller_pid'], 1), number(result['child_pid'], 1)
    require(owner != child, 'result PIDs')
    records, eof = decode_stream(statusbytes, (owner, child, request['sha256']))
    protocol = keys(result['protocol'], 'records bytes wire_fault io_stage io_reason io_errno eof_class')
    for v in protocol.values():
        number(v)
    require(protocol == {'records': len(records), 'bytes': len(statusbytes), 'wire_fault': 0,
                         'io_stage': 0, 'io_reason': 0, 'io_errno': 0, 'eof_class': eof}, 'protocol/result mismatch')
    _error(result['parent_error'], detail=False)
    wanted_error = {'stage': 0, 'reason': 0, 'errno': 0, 'detail': 0} if case == 'positive' else {
        'stage': 12 if case == 'simulated' else 10, 'reason': 12, 'errno': 0, 'detail': -1}
    require(result['parent_error'] == wanted_error, 'expected parent outcome')
    _error(result['cleanup_error'])
    require(result['cleanup_error']['detail'] == 0, 'cleanup unresolved')
    helpers = keys(result['helpers'], 'admission endpoints signal_prepare')
    _error(helpers['admission'], 'stage reason errno component metadata_step')
    _error(helpers['endpoints'], 'stage reason errno role fd')
    _error(helpers['signal_prepare'], 'stage reason errno')
    require(helpers['admission']['component'] == 0 and helpers['admission']['metadata_step'] == 0 and
            helpers['endpoints']['role'] == 5 and helpers['endpoints']['fd'] == -1, 'helper observations')
    wait = keys(result['wait'], 'forked reaped lost kill_attempted raw_status')
    for k in ('forked', 'reaped', 'lost', 'kill_attempted'):
        boolean(wait[k])
    number(wait['raw_status'], 0)
    require(wait['forked'] and wait['reaped'] and not wait['lost'], 'unreaped/lost child')
    sig = keys(result['signals'], 'prepared restore_called pipe_restored mask_restored restore_stage restore_reason restore_errno')
    require(all(boolean(sig[k]) for k in ('prepared', 'restore_called', 'pipe_restored', 'mask_restored')), 'signal restoration')
    require(all(number(sig[k]) == 0 for k in ('restore_stage', 'restore_reason', 'restore_errno')), 'signal restore errors')
    identities = keys(result['identities'], 'request_sha256 catalog_sha256 signal_policy_sha256 status_sha256 stdout_sha256 stderr_sha256 probe_sha256 runner_static_sources_sha256 build_recipe_sha256')
    for v in identities.values():
        hexsha(v)
    require(identities['signal_policy_sha256'] == SIGNAL_POLICY_SHA, 'canonical Darwin signal policy')
    for field, expected in (('request_sha256', request['sha256']), ('catalog_sha256', catalog['sha256']),
                            ('status_sha256', sha(statusbytes)), ('stdout_sha256', sha(data['probe.stdout'])),
                            ('stderr_sha256', sha(data['probe.stderr'])), ('probe_sha256', catalog['probe_sha256']),
                            ('runner_static_sources_sha256', catalog['runner_static_sources_sha256']),
                            ('build_recipe_sha256', catalog['build_recipe_sha256'])):
        require(identities[field] == expected, 'result digest mismatch: ' + field)
    require(result['stdout_capture_valid'] and result['stderr_capture_valid'] and
            number(result['stdout_bytes'], 0, 256) == len(data['probe.stdout']) and
            number(result['stderr_bytes'], 0, 4096) == len(data['probe.stderr']) and
            not data['probe.stderr'], 'capture validity/bytes')
    go = keys(result['go'], 'action attempted possibly_released bytes stage reason errno closed')
    for k in ('attempted', 'possibly_released', 'closed'):
        boolean(go[k])
    for k in ('action', 'bytes', 'stage', 'reason', 'errno'):
        number(go[k])
    require(go == {'action': release, 'attempted': case == 'positive', 'possibly_released': case == 'positive',
                   'bytes': 64 if case == 'positive' else 0, 'stage': 0, 'reason': 0, 'errno': 0, 'closed': True},
            'GO outcome')
    ce = keys(result['child_error'], 'present stage reason errno flags detail')
    boolean(ce['present'])
    for k in ('stage', 'reason', 'errno', 'flags', 'detail'):
        number(ce[k], -1 if k == 'detail' else 0)
    require(result['consistent_owned_probe'] is (case == 'positive') and
            result['probe_matched'] is (case == 'positive') and
            result['ready_matched'] is (case != 'denied'), 'case result booleans')
    ready = records[0] if records[0]['kind'] == 1 else None
    if ready:
        require(ready['flags'] == 3 and ready['ids'] == expected_ids and
                ready['groups'] == request['groups'] and ready['cwd_device'] == request['cwd_device'] and
                ready['cwd_inode'] == request['cwd_inode'] and
                ready['signal_policy_sha256'] == identities['signal_policy_sha256'], 'READY observations')
    probe = None
    if case == 'positive':
        require([s['kind'] for s in records] == [1, 2] and eof == 3 and
                wait['raw_status'] == 0 and not wait['kill_attempted'] and
                ce == {'present': False, 'stage': 0, 'reason': 0, 'errno': 0, 'flags': 0, 'detail': 0}, 'positive status/wait')
        probe = decode_probe(data['probe.stdout'], request['sha256'])
        require((probe['pid'], probe['ppid'], probe['pgid']) == (child, owner, child) and
                probe['ids'] == expected_ids and probe['groups'] == request['groups'] and
                probe['cwd_device'] == request['cwd_device'] and probe['cwd_inode'] == request['cwd_inode'] and
                probe['stdio_descriptor_flags'] == [0, 0, 0], 'NP/request context mismatch')
    else:
        require(not data['probe.stdout'] and eof == 2 and
                [s['kind'] for s in records] == ([1, 3] if case == 'simulated' else [3]) and
                wait['raw_status'] in (9, 120 << 8), 'negative raw streams/wait')
        expected = {'present': True, 'stage': 9 if case == 'simulated' else 6,
                    'reason': 10 if case == 'simulated' else 3, 'errno': 0 if case == 'simulated' else 13,
                    'flags': 3 if case == 'simulated' else 1, 'detail': -1}
        require(ce == expected and all(records[-1][k] == expected[k] for k in ('stage', 'reason', 'errno', 'flags', 'detail')),
                'negative child ERROR')
    return {'case': case, 'request_sha256': request['sha256'], 'controller_pid': owner, 'child_pid': child,
            'status_records': len(records), 'eof_class': eof, 'raw_wait_status': wait['raw_status'],
            'status_sha256': sha(statusbytes), 'stdout_sha256': sha(data['probe.stdout']),
            'stderr_sha256': sha(data['probe.stderr']), 'ready_kept_fds': ready['kept_fds'] if ready else None,
            'probe': probe, 'tracing': False, 'exec_proved': False, 'full_acceptance': False}


def _producer():
    path = HERE / 'prepare.py'
    require(path.is_file() and not path.is_symlink(), 'adjacent reviewed preparer missing')
    spec = importlib.util.spec_from_file_location('owned_vm_preparer', path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def _tree(p, root, expected_names):
    fd = p.open_directory(root)
    try:
        manifest = p.read_member(fd, 'SHA256SUMS', p.MAX_JSON)
    finally:
        os.close(fd)
    data = p.verified_tree(root, sha(manifest))
    require(set(data) == set(expected_names), 'fixed inventory members')
    return data, sha(manifest)


def _gate(p, root, names):
    # Intentionally BEFORE tree enumeration or case hashing. The trusted producer
    # only exports after these terminal records; this is not kernel liveness proof.
    fd = p.open_directory(root)
    try:
        for name, expected in names.items():
            require(p.read_member(fd, name, len(expected)) == expected, 'incomplete terminal gate: ' + name)
    finally:
        os.close(fd)


def _packet(producer, packet):
    p = producer.primitives()
    names = {'plan.json', 'derived-subset.json', 'root-stage.sh', 'outer.sh', 'launch.sh'}
    names |= {'payload/' + n for n in producer.PROGRAMS}
    names |= {'metadata/' + n for n in producer.METADATA}
    data, inventory_sha = _tree(p, packet, names)
    manifest = data['metadata/build-SHA256SUMS']
    require(sha(manifest) == producer.APPROVED['kit_manifest_sha256'], 'detached full kit inventory')
    original = p.parse_manifest(manifest)
    selected = []
    for member, original_name in ([('payload/' + n, 'kit/' + n) for n in producer.PROGRAMS] +
                                  [('metadata/' + n, old) for n, old in producer.METADATA.items()]):
        expected = sha(manifest) if original_name == 'SHA256SUMS' else original.get(original_name)
        require(sha(data[member]) == expected, 'selected kit member binding')
        selected.append({'member': member, 'original': original_name, 'sha256': expected})
    p.strict_json(data['derived-subset.json'])
    expected_subset = {'schema': 'glue-bootstrap-vm-subset-v1', 'approval': producer.APPROVED,
                       'selected': selected, 'original_inventory_is_detached_metadata': True, 'full_acceptance': False}
    require(data['derived-subset.json'] == p.canonical(expected_subset), 'canonical derived subset declaration')
    result = p.strict_json(data['metadata/build-result.json'])
    proof = p.strict_json(data['metadata/admitted-proof.json'])
    observed = p.observation(p.canonical(proof['observation']))
    require(result['schema'] == 'glue-bootstrap-kit-result-v1' and result['status'] == 'built-reproducibly' and
            all(result[k] is False for k in ('new_binaries_executed', 'installed', 'kernel_exec_proof', 'full_acceptance')) and
            proof['full_acceptance'] is False and proof['registry_entry']['manifest_sha256'] ==
            producer.APPROVED_PROOF_MANIFEST_SHA, 'kit/proof scope')
    plan = p.strict_json(data['plan.json'])
    require(type(plan) is dict and type(plan.get('nonce')) is str, 'plan object')
    require(data['plan.json'] == p.canonical(producer.make_plan(result, observed, plan['nonce'])),
            'canonical plan/profile/source mismatch')
    for name, value in producer.render(plan).items():
        require(data[name] == value, 'source-derived script differs')
    catalog = decode_catalog(data['metadata/catalog.bin'])
    require(catalog['sha256'] == producer.APPROVED['catalog_sha256'] and
            catalog['build_id'] == plan['build_id'] and catalog['root_mount'] == plan['root_mount'] and
            catalog['data_mount'] == plan['data_mount'], 'catalog/profile fields')
    for name in producer.PROGRAMS:
        a = keys(plan['artifacts'][name], 'size sha256')
        require(number(a['size'], 1, 4194304) == len(data['payload/' + name]) and
                hexsha(a['sha256']) == sha(data['payload/' + name]), 'plan artifacts')
    require(catalog['probe_sha256'] == plan['artifacts']['context-probe']['sha256'] and
            catalog['probe_size'] == plan['artifacts']['context-probe']['size'], 'catalog probe identity')
    return p, plan, catalog, inventory_sha


def check(packet, evidence, run_receipt):
    """Verify completed exports only. No caller-provided expected identity overrides."""
    producer = _producer()
    p, plan, catalog, packet_sha = _packet(producer, packet)
    require(producer.EXECUTION_ENABLED is True and plan['execution_enabled'] is True,
            'source execution policy remains disabled pending review')
    _gate(p, run_receipt, {'outer.status': b'0\n'})
    receipt, receipt_sha = _tree(p, run_receipt, RECEIPT_NAMES)
    require(receipt['outer.status'] == b'0\n' and
            receipt['outer.argv'] == b'/bin/sh\0' + (plan['guest_packet'] + '/outer.sh').encode('ascii') + b'\0' and
            receipt['outer.stdout'] == ('evidence=' + plan['guest_export'] + '\n').encode('ascii') and
            not receipt['outer.stderr'], 'normal outer receipt binding')
    gates = {'batch.tsv': BATCH, 'install.status': b'0\n'}
    gates.update({'case-' + c + '.status': b'0\n' for c in CASES})
    gates.update({'requests/' + c + '.status': b'0\n' for c in CASES[:3]})
    gates.update({'cases/' + case + '/native.status': status for case, status in
                  zip(CASES, (b'0\n', b'1\n', b'1\n', b'2\n'))})
    _gate(p, evidence, gates)
    data, evidence_sha = _tree(p, evidence, producer.evidence_names())
    require(all(data[name] == value for name, value in gates.items()), 'terminal metadata changed')
    require(data['plan.json'] == p.canonical(plan), 'evidence/packet plan differs')
    reports, requests = [], {}
    for case in CASES[:3]:
        raw = data['requests/' + case + '.bin']
        require(not data['requests/' + case + '.stderr'], 'request writer stderr')
        require(data['cases/' + case + '/native.status'] == (b'0\n' if case == 'positive' else b'1\n'), 'native case status')
        require(data['cases/' + case + '/input.sha256'] == (sha(raw) + '\n').encode('ascii') and
                data['cases/' + case + '/request.bin'] == raw, 'consumed request bytes differ')
        require(not data['case-' + case + '.stdout'] and not data['case-' + case + '.stderr'], 'case wrapper output')
        values = {n: data['cases/' + case + '/' + n] for n in
                  ('request.bin', 'status.bin', 'probe.stdout', 'probe.stderr', 'result.json')}
        reports.append(check_case(case, values, plan, catalog))
        requests[case] = decode_request(raw)
    require(data['requests/positive.bin'] == data['requests/denied.bin'], 'denied pre-generated request differs')
    s, q = requests['simulated'].copy(), requests['positive'].copy()
    for v in (s, q):
        v.pop('sha256'); v.pop('release')
    require(s == q, 'simulated request differs outside release')
    trailing = data['requests/trailing.bin']
    require(trailing == data['requests/positive.bin'] + b'\0' and
            data['cases/trailing/input.sha256'] == (sha(trailing) + '\n').encode('ascii') and
            data['cases/trailing/native.status'] == b'2\n' and data['cases/trailing/output.absent'] == b'true\n' and
            not data['case-trailing.stdout'] and not data['case-trailing.stderr'], 'trailing expected refusal')
    return {'schema': 'glue-bootstrap-vm-check-v1', 'status': 'consistent-owned-nontracing-batch',
            'packet_manifest_sha256': packet_sha, 'evidence_manifest_sha256': evidence_sha,
            'run_receipt_manifest_sha256': receipt_sha, 'build_id': catalog['build_id'],
            'catalog_sha256': catalog['sha256'], 'root_mount': catalog['root_mount'],
            'data_mount': catalog['data_mount'], 'signal_policy_sha256': SIGNAL_POLICY_SHA,
            'checker_source_sha256': sha(Path(__file__).read_bytes()),
            'preparer_source_sha256': sha((HERE / 'prepare.py').read_bytes()),
            'kit_parser_source_sha256': producer.PARSER_SHA, 'cases': reports,
            'trailing': 'canonical-positive-plus-one-NUL-refused-before-output',
            'stdio_flag_boundary': 'raw NP policy checked; exact pre/post vector equality is a producer observation',
            'tracing': False, 'exec_proved': False, 'full_acceptance': False}


def require_full_acceptance(*_args):
    raise Refusal('NONTRACING self-reports cannot grant kernel exec or full Darwin acceptance')


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--packet', required=True, type=Path)
    parser.add_argument('--evidence', required=True, type=Path)
    parser.add_argument('--run-receipt', required=True, type=Path)
    args = parser.parse_args()
    try:
        result = check(args.packet, args.evidence, args.run_receipt)
    except (Refusal, ValueError, OSError, KeyError, UnicodeError) as exc:
        print('bootstrap-vm-checker: ' + str(exc)[:512], file=sys.stderr)
        return 1
    print(json.dumps(result, sort_keys=True, separators=(',', ':')))
    return 0


if __name__ == '__main__':
    sys.exit(main())
