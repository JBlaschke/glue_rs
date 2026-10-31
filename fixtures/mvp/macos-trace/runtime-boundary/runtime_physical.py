"""Private fixed physical codecs; no public normalized/profile input.

The caller is the identity-checked boundary module. Its already checked RAW
module supplies the legacy decoder, exception class and bounded primitives.
No second dynamic import creates a different exception or phase-type graph.
"""
from dataclasses import dataclass


@dataclass(frozen=True)
class StoppedPhysicalEvent:
    kind: int
    epid: int
    probe: int
    words: tuple
    cpu: int
    memory: bytes


def _legacy_event(raw, line, ordinal, inventory):
    return raw._event(line, ordinal, inventory)


def _stopped_shape(kind):
    # Fixed protocol47ee60db, not a caller-extensible descriptor table.
    if kind == 2:
        return 8, 13, 0
    if kind in (3, 22, 23):
        return 0, 10, 0
    if kind == 7:
        return 4, 5, 0
    if kind == 8:
        return 1, 5, 0
    if kind == 15:
        return 0, 13, 0
    if kind == 16:
        return 0, 6, 0
    if kind == 18:
        return 0, 8, 0
    if kind == 19:
        return 0, 7, 0
    if kind == 20:
        return 0, 10, 176
    if kind == 21:
        return 0, 10, 4
    return int(kind in (1, 4, 5)), 5, 0


def _stopped_probe_kind(raw, names, base_kind, kind):
    if kind < 19:
        return kind == base_kind
    provider, _, function, name = names
    if kind == 19:
        return base_kind == 10 and provider == 'proc' and name == 'lwp-start'
    if provider != 'syscall' or name != 'return' or base_kind != 3:
        return False
    if kind == 20:
        return function == 'proc_info'
    if kind == 21:
        return function in ('wait4', 'wait4_nocancel')
    if kind == 22:
        return function == 'kill'
    return kind == 23 and function in ('proc_info', 'wait4', 'wait4_nocancel')


def _stopped_event(raw, line, ordinal, inventory):
    """Decode one original new-profile record without native-origin claims."""
    event = raw._object(line)
    raw._keys(event, raw._EVENT_KEYS, 'stopped event object keys')
    raw._integer(event['event'], ordinal, ordinal, 'stopped event ordinal')
    cpu = raw._integer(event['cpu'], 0, raw.PID_MAX, 'stopped CPU range')
    epid = raw._integer(event['epid'], 1, raw.U32, 'stopped EPID range')
    probe = raw._integer(event['probe_id'], 1, raw.U32, 'stopped probe ID range')
    raw._require(probe in inventory, 'stopped unlisted probe ID')
    names, base_kind = inventory[probe]
    raw._require(tuple(event[k] for k in ('provider', 'module', 'function', 'name')) == names,
                 'stopped probe identity')
    kind = raw._integer(event['kind'], 1, 23, 'stopped kind range')
    raw._require(_stopped_probe_kind(raw, names, base_kind, kind),
                 'stopped kind differs from fixed probe class')
    leading, count, memory_size = _stopped_shape(kind)
    size = 16 + count * 8 + memory_size
    raw._integer(event['record_bytes'], size, size, 'stopped record byte size')
    indexes = event['header_record_indexes']
    raw._require(type(indexes) is list and all(type(i) is int for i in indexes) and
                 indexes == list(range(leading, leading + 5)), 'stopped header indexes')
    expected = [(1, 0, 12)] * leading
    expected += [(1, 8, 16 + 8 * i) for i in range(count)]
    if memory_size:
        expected.append((6, memory_size, 16 + count * 8))
    if kind == 19:
        expected += [(514, 0, 72), (1, 0, 72)]
    records = event['records']
    raw._require(type(records) is list and len(records) == len(expected),
                 'stopped exact descriptor count')
    words, memory = [], b''
    for record, (action, width, offset) in zip(records, expected):
        raw._keys(record, raw._RECORD_KEYS, 'stopped record keys')
        raw._integer(record['action'], action, action, 'stopped native action')
        raw._integer(record['size'], width, width, 'stopped record width')
        raw._integer(record['offset'], offset, offset, 'stopped record offset')
        value = record['hex']
        raw._require(type(value) is str and len(value) == width * 2 and
                     raw._HEX.fullmatch(value), 'stopped original record hex')
        original = bytes.fromhex(value)
        if action == 1 and width == 8:
            words.append(int.from_bytes(original, 'little'))
        elif action == 6:
            memory = original
    for key, value in zip(('kind', 'timestamp', 'pid', 'tid', 'detail'), words):
        raw._integer(event[key], 0, raw.U64, 'stopped header range')
        raw._require(event[key] == value, 'stopped raw/header disagreement')
    raw._integer(words[1], 1, raw.U64, 'stopped timestamp range')
    raw._integer(words[2], 1, raw.PID_MAX, 'stopped actor PID range')
    raw._integer(words[3], 1, raw.U64, 'stopped thread ID range')
    return StoppedPhysicalEvent(kind, epid, probe, tuple(words), cpu, memory)
