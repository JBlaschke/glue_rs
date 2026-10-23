"""Exact pinned pure legacy codec subset; no legacy full checker is imported.

Source bootstrap-vm/checker.py at ac7e27a5f2d70805dde4a813af2ab2a95ca89ba8.
SHA256 0d42737849bd96ab9fdf6e92a4d4418b799b70caeac43f98d38c4335d03b2e0e.
Selected definitions/constants below are AST-identical to that source. No
filesystem, producer, packet, full case checker or CLI definition is included.
"""
import hashlib
import json
import re
import struct

LEGACY_SOURCE_SHA256 = '0d42737849bd96ab9fdf6e92a4d4418b799b70caeac43f98d38c4335d03b2e0e'
RAW_SOURCE_SHA256 = '1d8616b51002225c8b9abf4a18940c48f01d1ef97a3f7c54e120153ca8c978ec'
SELECTED_SYMBOLS = ('INT', 'U64', '_SIGNALS', 'SIGNAL_POLICY_SHA', 'Refusal', 'require', 'sha', 'number', 'keys', 'boolean', 'hexsha', 'result_json', 'uint', 'groups', 'path_bytes', 'decode_request', 'decode_catalog', 'decode_status', 'decode_stream', 'decode_probe')

INT = (1 << 31) - 1

U64 = (1 << 64) - 1

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
