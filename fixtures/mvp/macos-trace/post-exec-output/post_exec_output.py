"""Strict GLUEPX01 byte observations; no native, state or sink authority.

This decoder takes original complete assets, never stopped/match booleans. It
can recompute only conditional metadata consistency. Native provenance, raw
correlation, quiescence, OFD identity and prospective policy admission remain
separate requirements. Later observations cannot authorize earlier writes.
"""
from dataclasses import asdict, dataclass
import hashlib

# Explicit source-defined Darwin LP64 fields. Pad/spares/fsid are retained
# bit-pattern observations, never descriptor generations or policy identities.
_FIELDS = (
    ('fi_openflags', 4, False), ('fi_status', 4, False),
    ('fi_offset', 8, True), ('fi_type', 4, True), ('fi_guardflags', 4, False),
    ('vst_dev', 4, False), ('vst_mode', 2, False), ('vst_nlink', 2, False),
    ('vst_ino', 8, False), ('vst_uid', 4, False), ('vst_gid', 4, False),
    ('vst_atime', 8, True), ('vst_atimensec', 8, True),
    ('vst_mtime', 8, True), ('vst_mtimensec', 8, True),
    ('vst_ctime', 8, True), ('vst_ctimensec', 8, True),
    ('vst_birthtime', 8, True), ('vst_birthtimensec', 8, True),
    ('vst_size', 8, True), ('vst_blocks', 8, True),
    ('vst_blksize', 4, True), ('vst_flags', 4, False),
    ('vst_gen', 4, False), ('vst_rdev', 4, False),
    ('vst_qspare0', 8, True), ('vst_qspare1', 8, True),
    ('vi_type', 4, True), ('vi_pad', 4, True),
    ('vi_fsid0', 4, True), ('vi_fsid1', 4, True),
)
_INT_MAX = (1 << 31) - 1
_FMASK, _WRITTEN = 0x404000cf, 0x10000


def _need(condition, message):
    if not condition:
        raise ValueError(message)


def _u(raw, start, size):
    return int.from_bytes(raw[start:start + size], 'big')


def _i(raw, start, size=4):
    return int.from_bytes(raw[start:start + size], 'big', signed=True)


def _zero(raw):
    return not any(raw)


def _asset(raw, size, name):
    _need(type(raw) is bytes and len(raw) == size, name + ' exact bytes')


@dataclass(frozen=True)
class QueryObservation:
    pid: int
    fd: int
    before: int
    after: int
    buffer_address: int
    result: int
    saved_errno: int
    flags: int
    role: int
    round: int
    payload: bytes
    decoded_fields: tuple

    @property
    def fields(self):
        return dict(self.decoded_fields)

    @property
    def opaque_buffer(self):
        return self.payload if self.flags & 4 else None


@dataclass(frozen=True)
class WaitObservation:
    before: int
    after: int
    returned_pid: int
    status: int
    saved_errno: int
    flags: int


@dataclass(frozen=True)
class StoppedOutputObservation:
    owner_pid: int
    child_pid: int
    sequence: int
    deadline: int
    exec_ordinal: int
    new_tid: int
    state: int
    reason: int
    saved_errno: int
    flags: int
    last_clock: int
    accepted_wait: int
    error_count: int
    request_sha256: str
    catalog_sha256: str
    ready_sha256: str
    program_sha256: str
    original_witness_sha256: str
    observation_sha256: str
    queries: tuple
    waits: tuple
    conditional_backing_match: bool
    native_origin_authenticated: bool = False
    raw_correlation_verified: bool = False
    quiescence_proved: bool = False
    ofd_identity_proved: bool = False
    descriptor_generation_proved: bool = False
    state_feed_eligible: bool = False
    authorizes_sink_exemptions: bool = False
    full_flags_proved: bool = False
    full_trace_acceptance: bool = False

    def to_dict(self):
        result = asdict(self)
        for row in result['queries']:
            row['payload'] = row['payload'].hex()
            row['decoded_fields'] = dict(row['decoded_fields'])
        return result


def _original(raw, packet):
    _asset(raw, 320, 'original GLUERW')
    _need(raw[:8] == b'GLUERW01' and _u(raw, 8, 4) == 1 and
          _u(raw, 12, 4) == 320 and raw[16:24] == packet[16:24] and
          _u(raw, 24, 4) == 4 and _zero(raw[28:32]) and
          raw[32:128] == packet[96:192], 'original witness binding/header')
    _need(_zero(raw[128:140]) and raw[140:148] == b'\xff' * 8 and
          _zero(raw[148:160]) and raw[160:240] == raw[240:320],
          'original complete successful stable observations')
    _need(hashlib.sha256(raw).digest() == packet[224:256], 'original witness digest')
    rows = []
    for offset in (160, 200):
        row = (_u(raw, offset, 4), _u(raw, offset + 4, 4),
               _u(raw, offset + 8, 4), _u(raw, offset + 12, 4),
               _u(raw, offset + 16, 8), _u(raw, offset + 24, 8),
               _u(raw, offset + 32, 8))
        fd, descriptor, status, mode, _, _, links = row
        _need(3 <= fd <= _INT_MAX and descriptor <= _INT_MAX and descriptor & 1 and
              status <= _INT_MAX and status & 3 == 1 and mode <= 0xffff and
              mode & 0o170000 == 0o100000 and links == 1, 'original output shape')
        rows.append(row)
    _need(rows[0][0] != rows[1][0] and rows[0][4:6] != rows[1][4:6],
          'original distinct outputs')
    return tuple(rows)


def _fields(raw):
    offset, result = 0, []
    for name, width, signed in _FIELDS:
        result.append((name, int.from_bytes(raw[offset:offset + width], 'big', signed=signed)))
        offset += width
    _need(offset == 176, 'fixed field codec size')
    return tuple(result)


def _backing(fields):
    dev = fields['vst_dev']
    if dev & 0x80000000:
        dev |= 0xffffffff00000000
    return fields['vst_mode'], dev, fields['vst_ino'], fields['vst_nlink']


def _matches(queries, original):
    if len(queries) != 8 or any(not row.flags & 2 for row in queries):
        return False
    first = [queries[0].fields, queries[1].fields]
    for index, row in enumerate(queries):
        f, role, parent = row.fields, index & 1, index < 2 or index >= 6
        flags, status = f['fi_openflags'], f['fi_status']
        if (flags & ~(_FMASK | _WRITTEN) or flags & 0x40000003 != 2 or
                status & ~3 or bool(status & 2) != parent or
                f['fi_type'] != 1 or f['fi_guardflags'] != 0 or
                f['vi_type'] != 1 or f['vst_mode'] & 0o170000 != 0o100000 or
                f['vst_nlink'] != 1 or
                _backing(f) != _backing(first[role]) or
                flags & _FMASK != first[role]['fi_openflags'] & _FMASK or
                _backing(f) != original[role][3:7]):
            return False
    return (first[0]['vst_dev'], first[0]['vst_ino']) != (first[1]['vst_dev'], first[1]['vst_ino'])


def _timeline(waits, queries, state, reason, deadline, last):
    # A before-clock was validated before every issued operation. An invalid
    # after-clock ends the attempt immediately, so only the last row may retain
    # that diagnosed failure. An invalid before/final clock creates no call row.
    calls = [(w.before, w.after, bool(w.flags & 2)) for w in waits]
    calls += [(q.before, q.after, bool(q.flags & 8)) for q in queries]
    previous, bad_after = 0, False
    for index, (before, after, have_after) in enumerate(calls):
        _need(previous <= before < deadline, 'issued call before-clock chronology')
        if not have_after:
            _need(index + 1 == len(calls) and state >= 3 and reason == 5 and
                  last == before, 'missing after-clock must be final diagnosed failure')
            bad_after = True
        elif after < before or after >= deadline:
            expected_reason = 5 if after < before else 6
            _need(index + 1 == len(calls) and state >= 3 and
                  reason == expected_reason and last == after,
                  'invalid after-clock must be final diagnosed failure')
            bad_after = True
        else:
            previous = after
    if bad_after:
        return
    if state == 2 or reason == 13:
        _need(calls and previous <= last < deadline, 'final publication clock')
    elif reason == 5:
        _need(last <= previous, 'failed before/final clock retained value')
    elif reason == 6:
        _need(last >= deadline, 'late before/final clock retained value')
    else:
        _need(last == previous, 'last clock must match issued-call prefix')


def decode_observation(packet: bytes, original_witness: bytes) -> StoppedOutputObservation:
    """Decode complete original assets; recompute conditional consistency only."""
    _asset(packet, 4096, 'GLUEPX01')
    _need(packet[:8] == b'GLUEPX01' and _u(packet, 8, 2) == 1 and
          _u(packet, 10, 2) == 256 and _u(packet, 12, 4) == 4096 and
          _zero(packet[84:96]), 'observation canonical header')
    owner, child = _u(packet, 16, 4), _u(packet, 20, 4)
    _need(0 < owner <= _INT_MAX and 0 < child <= _INT_MAX and owner != child,
          'observation PID domain')
    sequence, deadline, epoch, tid = (_u(packet, p, 8) for p in (24, 32, 40, 48))
    _need(all((sequence, deadline, epoch, tid)), 'observation nonzero binding')
    nq, nw, state, reason = (_u(packet, p, 2) for p in (56, 58, 60, 62))
    saved, flags, last = _i(packet, 64), _u(packet, 68, 4), _u(packet, 72, 8)
    accepted, errors = _u(packet, 80, 2), _u(packet, 82, 2)
    _need(nq <= 8 and nw <= 64 and 1 <= state <= 5 and reason <= 13 and
          saved >= 0 and not flags & ~63 and accepted <= nw and errors <= 1,
          'observation counts/state/flags')
    _need(all(any(packet[p:p + 32]) for p in (96, 128, 160, 192, 224)),
          'observation digest declarations')
    original = _original(original_witness, packet)
    _need(_zero(packet[256 + nq * 224:2048]) and
          _zero(packet[2048 + nw * 32:4096]), 'unread rows must be zero')
    waits, stop_index = [], 0
    for index in range(nw):
        raw = packet[2048 + index * 32:2080 + index * 32]
        before, after = _u(raw, 0, 8), _u(raw, 8, 8)
        pid, status, err, wf = _i(raw, 16), _i(raw, 20), _i(raw, 24), _u(raw, 28, 4)
        _need(err >= 0 and not wf & ~63 and wf & 1 and
              (wf & 2 or after == 0) and (pid == -1 or err == 0), 'wait row shape')
        expected = 1 | (wf & 2)
        if pid == child:
            expected |= 32
            if status & 0x7f != 0x7f:
                expected |= 4
            elif status == 0x117f:
                expected |= 16
                stop_index = index + 1
        elif pid == -1 and err == 10:  # fixed Darwin ECHILD
            expected |= 8
        _need(wf == expected, 'wait outcome flags')
        if index + 1 < nw:
            _need(wf == 3 and (pid == 0 or pid == -1 and err == 4) and
                  before <= after < deadline, 'wait after nonretry/lifecycle outcome')
        waits.append(WaitObservation(before, after, pid, status, err, wf))
    _need(accepted == stop_index and bool(flags & 2) == bool(accepted) and
          bool(flags & 4) == bool(accepted), 'accepted stop and attempt binding')
    _need(not nq or accepted == nw > 0, 'query prefix requires accepted final stop')
    queries, ranges = [], []
    for index in range(nq):
        raw = packet[256 + index * 224:480 + index * 224]
        pid, fd = _u(raw, 0, 4), _i(raw, 4)
        before, after, address = (_u(raw, p, 8) for p in (8, 16, 24))
        result, err, qf = _i(raw, 32), _i(raw, 36), _u(raw, 40, 2)
        role, round_number = raw[42], raw[43]
        parent = index < 2 or index >= 6
        _need(pid == (owner if parent else child) and
              fd == (original[index & 1][0] if parent else 1 + (index & 1)) and
              role == 1 + (index & 1) and round_number == (1 if index < 4 else 2) and
              _zero(raw[44:48]), 'query fixed order/role/arguments')
        _need(0 < address <= (1 << 64) - 177 and
              all(address + 176 <= a or b <= address for a, b in ranges),
              'query original distinct buffer spans')
        ranges.append((address, address + 176))
        _need(err >= 0 and not qf & ~15 and qf & 1 and
              bool(qf & 2) == (result == 176) and bool(qf & 4) == (result != 176) and
              (qf & 8 or after == 0) and (result != 176 or err == 0), 'query full/opaque flags')
        if index + 1 < nq:
            _need(qf == 11 and before <= after < deadline, 'query after failed/late sample')
        fields = _fields(raw[48:224]) if qf & 2 else ()
        queries.append(QueryObservation(pid, fd, before, after, address, result, err,
                                        qf, role, round_number, raw[48:224], fields))
    matched = _matches(queries, original)
    if reason == 6:
        _need(last >= deadline, 'deadline failure must retain late clock')
    if state in (1, 2):
        _need(reason == saved == errors == 0, 'successful/active header error')
    else:
        _need(3 <= reason <= 13 and errors == 1, 'failed header error')
    if state == 1:
        _need(flags == 1 and not nq and not accepted and nw < 64 and
              (not waits or waits[-1].flags == 3 and
               (waits[-1].returned_pid == 0 or
                waits[-1].returned_pid == -1 and waits[-1].saved_errno == 4)), 'active state')
    elif state == 2:
        _need(flags == 15 and nq == 8 and accepted == nw > 0 and matched and
              waits[-1].flags == 51 and all(q.flags == 11 for q in queries),
              'complete state must recompute backing match')
    elif state == 3:
        _need(flags == (7 if accepted else 1) and
              (not waits or not waits[-1].flags & 12), 'refused ownership/state')
    elif state == 4:
        _need(flags == 16 and not nq and not accepted and waits and
              waits[-1].flags & 4 and reason in (5, 6, 9), 'terminal wait retires ownership')
    else:
        _need(flags == 32 and not nq and not accepted and waits and
              waits[-1].flags & 8 and reason in (5, 6, 10), 'ECHILD retires ownership')
    if state == 3 and reason == 7:
        _need(nw == 64 and not nq and not accepted and all(
            w.flags == 3 and (w.returned_pid == 0 or
                             w.returned_pid == -1 and w.saved_errno == 4) for w in waits),
            'wait limit outcome')
    if state == 3 and reason == 12:
        _need(queries and queries[-1].flags == 13 and
              saved == queries[-1].saved_errno, 'query failure outcome')
    if state == 3 and reason == 13:
        _need(nq == 8 and all(q.flags == 11 for q in queries) and not matched,
              'mismatch must be recomputed')
    _timeline(waits, queries, state, reason, deadline, last)
    digests = tuple(packet[p:p + 32].hex() for p in (96, 128, 160, 192, 224))
    return StoppedOutputObservation(owner, child, sequence, deadline, epoch, tid,
        state, reason, saved, flags, last, accepted, errors, *digests,
        hashlib.sha256(packet).hexdigest(), tuple(queries), tuple(waits), state == 2 and matched)
