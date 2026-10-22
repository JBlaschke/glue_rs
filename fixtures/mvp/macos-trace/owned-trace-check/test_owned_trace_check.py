"""Independent serialized fixtures; no producer/native program or provider runs."""
import copy
from dataclasses import FrozenInstanceError
import hashlib
import importlib.util
import json
from pathlib import Path
import struct
import tracemalloc
import unittest
from unittest.mock import patch

import owned_trace_check as check

OWNER, TARGET = 3131, 4242
CONTRACT = (Path(__file__).parent.parent / 'syscall-contract' / 'contracts.json').read_bytes()
# Literal fixture, independently transcribed from the fixed source contract.
# No producer is imported and the validator's generator never builds fixtures.
PROGRAM = b'''#pragma D option quiet
BEGIN { watched[4242]=1;trace((uint64_t)1);trace((uint64_t)timestamp);trace((uint64_t)pid);trace((uint64_t)tid);trace((uint64_t)(0));}
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


def validate(records=None, **kwargs):
    return check.validate_raw(kwargs.pop('program', PROGRAM), kwargs.pop('probes', PROBES),
                              kwargs.pop('errors', b''),
                              kwargs.pop('event_lines', lines(records if records is not None else
                                      [event(1), event(18), event(17)])),
                              owner_pid=kwargs.pop('owner_pid', OWNER),
                              target_pid=kwargs.pop('target_pid', TARGET), **kwargs)


def change_scalar(record, index, value):
    # Adjust raw+header together when testing semantics rather than disagreement.
    leading = int(SHAPES[record['kind']][1])
    record['records'][index + leading]['hex'] = struct.pack('<Q', value).hex()
    if index < 5:
        record[('kind', 'timestamp', 'pid', 'tid', 'detail')[index]] = value


def observe(records=None, **kwargs):
    return check.observe_raw_bsd(kwargs.pop('program', PROGRAM), kwargs.pop('probes', PROBES),
        kwargs.pop('errors', b''), kwargs.pop('event_lines', lines(records if records is not None else
            [event(1), event(18), event(17)])), owner_pid=kwargs.pop('owner_pid', OWNER),
        target_pid=kwargs.pop('target_pid', TARGET), contract_bytes=kwargs.pop('contract_bytes', CONTRACT),
        **kwargs)


def bsd(kind, function, words):
    record = event(kind)
    record['function'] = function
    for index, word in enumerate(words, 5):
        change_scalar(record, index, word)
    return record


def bsd_probes(function):
    return PROBES.replace(b'\tread\t', b'\t' + function.encode('ascii') + b'\t')


def ticked(records):
    """Independent synthetic source timestamps, not a native ordering claim."""
    records = copy.deepcopy(records)
    for index, record in enumerate(records):
        change_scalar(record, 1, 100 + index)
    return records


def threaded(kind, tid=1000, **kwargs):
    record = event(kind, **kwargs)
    change_scalar(record, 3, tid)
    return record


def paired_records():
    return ticked([event(1), threaded(2), threaded(3), threaded(11), event(18), event(17)])


def multi_thread_records(count, *, closing=False):
    records = [event(1), threaded(2), threaded(3)]
    for tid in range(1001, 1000 + count):
        records.extend([threaded(9, detail=tid), threaded(10, tid=tid), threaded(2, tid=tid),
                        threaded(3, tid=tid), threaded(11, tid=tid)])
    if closing:
        records.append(threaded(6))
    return ticked(records + [threaded(11), event(18), event(17)])


def pair_owned(records=None, **kwargs):
    return check.pair_raw_owned(kwargs.pop('program', PROGRAM), kwargs.pop('probes', PROBES),
        kwargs.pop('errors', b''), kwargs.pop('event_lines', lines(records if records is not None else
            paired_records())), owner_pid=kwargs.pop('owner_pid', OWNER),
        target_pid=kwargs.pop('target_pid', TARGET), contract_bytes=kwargs.pop('contract_bytes', CONTRACT),
        **kwargs)


class RawControls(unittest.TestCase):
    def refuse(self, records=None, match=None, **kwargs):
        with self.assertRaisesRegex(check.RawValidationError, match or '.'):
            validate(records, **kwargs)

    def test_literal_program_and_immutable_minimal_facts(self):
        result = validate()
        self.assertEqual((result.events, result.inventory_probes, result.observed_enablings), (3, 17, 3))
        self.assertEqual((result.begin_event, result.terminal_event, result.end_event), (1, 2, 3))
        self.assertEqual(result.program_sha256, hashlib.sha256(PROGRAM).hexdigest())
        self.assertEqual(result.inventory_sha256, hashlib.sha256(PROBES).hexdigest())
        self.assertEqual(result.raw_sha256, hashlib.sha256(b''.join(lines([event(1), event(18), event(17)]))).hexdigest())
        self.assertEqual(result.terminal_raw_exit, (1 << 64) - 1)
        with self.assertRaises(FrozenInstanceError):
            result.events = 0
        self.assertEqual(result.error_bytes, 0)
        self.assertEqual(result.inventory_kind_counts[14], 0)

    def test_all_permitted_shapes_and_cleanup(self):
        records = [event(1)] + [event(k) for k in (2, 3, 5, 6, 7, 8, 9, 10, 11, 15, 16)]
        records += [event(18, refcount=0x1e2), event(2), event(18, actor=9876),
                    event(18, actor=9876, refcount=0x1e2), event(11), event(17)]
        result = validate(records)
        self.assertEqual(result.shadow_exits, 2)
        self.assertEqual(result.post_terminal_lwp_exits, 1)
        self.assertEqual(result.terminal_actor_pid, 9876)  # actor need not be target
        self.assertEqual(result.observed_enablings, 14)
        self.assertLess(result.observed_enablings, result.inventory_probes)  # unused probes are valid

    def test_program_single_byte_clause_and_target_mutations(self):
        for bad in (PROGRAM + b'\n', PROGRAM[:-1], PROGRAM.replace(b'4242', b'4243'),
                    PROGRAM.replace(b'mach_trap', b'syscall'), PROGRAM.replace(b'p_refcount', b'p_refcnt'),
                    PROGRAM.replace(b'uint64_t', b'uint32_t', 1), PROGRAM.replace(b'\n', b'\r\n')):
            with self.subTest(bad=bad[:30]):
                self.refuse(program=bad, match='fixed program')
        new_target = 2147483647
        self.assertEqual(validate(program=PROGRAM.replace(b'4242', str(new_target).encode()),
                         target_pid=new_target, records=[event(1), event(18, detail=new_target), event(17)]).target_pid,
                         new_target)

    def test_inventory_categories_names_fields_and_unique_ids(self):
        rows = PROBES.splitlines(keepends=True)
        for row in rows:
            self.refuse(probes=PROBES.replace(row, b''), match='required inventory')
        for bad in (PROBES[:-1], PROBES + b'\n', PROBES + rows[0],
                    PROBES + rows[0].replace(b'101\t', b'999\t'),
                    PROBES.replace(b'101\t', b'000101\t'), PROBES.replace(b'101\t', b'0\t'),
                    PROBES.replace(b'101\t', b'4294967296\t'),
                    PROBES.replace(b'101\t', b'1' * 2000 + b'\t'),
                    PROBES.replace(b'mach_trap', b'unknown'),
                    PROBES.replace(b'read', b''), PROBES.replace(b'read', b'r/ead'),
                    PROBES.replace(b'read', b'R' * 128),
                    PROBES.replace(b'exited', b'unknown'),
                    PROBES.replace(b'dtrace\t\t\tBEGIN', b'dtrace\tx\t\tBEGIN'),
                    PROBES.replace(b'proc', b'pr\xffc'), PROBES.replace(b'\n', b'\r\n')):
            with self.subTest(bad=bad[:30]):
                self.refuse(probes=bad)
        # Other exact native names/modules allowed; only emitted IDs need appear in events.
        extra = b'999\tsyscall\tcom.apple.kernel\twrite\tentry\n'
        self.assertEqual(validate(probes=PROBES + extra).inventory_probes, 18)

    def test_pre_stream_bounds_identity_and_error_opacity(self):
        class Untouched:
            def __iter__(self):
                raise AssertionError('event source touched before static refusal')
        for kwargs in ({'program': b'x' * 16385}, {'probes': b'x' * 1048577},
                       {'errors': b'x' * 65537}, {'errors': b'{}\n'}, {'errors': b'partial\xff'},
                       {'program': bytearray(PROGRAM)}, {'owner_pid': True}, {'target_pid': 0},
                       {'target_pid': OWNER}, {'owner_pid': 1 << 31}, {'target_pid': -1},
                       {'owner_pid': 1.0}, {'target_pid': '4242'}, {'program': PROGRAM + b'\0'}):
            self.refuse(event_lines=Untouched(), **kwargs)
        too_many = b''.join(str(i + 1).encode() + b'\tsyscall\t\tf' + str(i).encode() + b'\tentry\n'
                            for i in range(8193))
        self.refuse(probes=too_many, event_lines=Untouched(), match='probe bound')

    def test_line_bounds_truncation_and_early_refusal(self):
        bad_lines = [b'x' * 8192, b'{}', b'', b'{}\n{}\n', b'{}\r\n', bytearray(b'{}\n'),
                     '{}\n', b'\xff\n', b'\xef\xbb\xbf{}\n']
        for bad in bad_lines:
            with self.subTest(bad=repr(bad)[:50]):
                self.refuse(event_lines=iter([bad]))
        def hostile():
            yield b'x' * 8192
            raise AssertionError('read beyond first refusal')
        with patch.object(check, '_object', side_effect=AssertionError('decoded overlong line')):
            self.refuse(event_lines=hostile(), match='line byte bound')
        self.refuse(event_lines=[lines([event(1)])[0][:-1]], match='complete LF')
        self.refuse(event_lines=iter(()), match='incomplete')

    def test_json_key_and_number_grammar_hostility(self):
        baseline = lines([event(1), event(18), event(17)])
        self.assertEqual(validate(event_lines=baseline).events, 3)
        good = baseline[0]
        bad = [(good.replace(b'"event":1', b'"event":1,"event":1'), 'duplicate JSON key'),
               (good.replace(b'"action":1', b'"action":1,"action":1', 1), 'duplicate JSON key'),
               (good.replace(b'"event":1', b'"event":1.0'), 'non-integer JSON number'),
               (good.replace(b'"event":1', b'"event":1e0'), 'non-integer JSON number'),
               (good.replace(b'"event":1', b'"event":NaN'), 'non-integer JSON number'),
               (good.replace(b'"event":1', b'"event":Infinity'), 'non-integer JSON number'),
               (good.replace(b'"event":1', b'"event":' + b'1' * 100), 'JSON integer token bound'),
               (good.replace(b'"cpu":7,', b''), 'event object keys'),
               (good.replace(b'"cpu":7', b'"extra":0,"cpu":7'), 'event object keys'),
               (b'[]\n', 'event object keys'), (b'null\n', 'event object keys'),
               (b'"text"\n', 'event object keys'),
               (b'[' * 1500 + b']' * 1499 + b'\n', 'malformed JSON event'),
               (good.replace(b'"records":[', b'"records":{'), 'malformed JSON event'),
               (good[:-3] + b'\n', 'malformed JSON event')]
        for item, reason in bad:
            with self.subTest(item=item[:40]):
                self.refuse(event_lines=[item] + baseline[1:], match=reason)
        # Source failures propagate, never produce partial facts.
        def broken_source():
            yield good
            raise OSError('source failed')
        with self.assertRaisesRegex(OSError, 'source failed'):
            validate(event_lines=broken_source())

    def test_strict_integer_types_and_ranges(self):
        original = event(1)
        baseline = lines([original, event(18), event(17)])
        self.assertEqual(validate(event_lines=baseline).events, 3)
        for key in ('event', 'cpu', 'epid', 'probe_id', 'record_bytes', 'kind', 'timestamp', 'pid', 'tid', 'detail'):
            for value in (True, False, None, '1', 1.0, -1, 1 << 64):
                item = event(1)
                item[key] = value
                first = line(item, 1) if key != 'event' else json.dumps(item).encode() + b'\n'
                self.refuse(event_lines=[first] + baseline[1:],
                            match='JSON number|ordinal|range|size|inventory|integer')
        for key, value, reason in (('cpu', 1 << 31, 'CPU range'), ('epid', 0, 'EPID range'),
                                  ('epid', 1 << 32, 'EPID range'), ('probe_id', 0, 'probe ID range'),
                                  ('probe_id', 1 << 32, 'probe ID range')):
            item = event(1); item[key] = value
            self.refuse(event_lines=[line(item, 1)] + baseline[1:], match=reason)
        for key, reason in (('action', 'record action'), ('size', 'record width'), ('offset', 'record offset')):
            item = event(1); item['records'][0][key] = True
            self.refuse(event_lines=[line(item, 1)] + baseline[1:], match=reason)
        item = event(1); item['header_record_indexes'][0] = True
        self.refuse(event_lines=[line(item, 1)] + baseline[1:], match='header record indexes')

    def test_every_descriptor_and_header_single_mutation(self):
        def context(item, original_kind):
            # Every unmodified record sits in a complete accepted lifecycle.
            if original_kind == 1:
                return [item, event(18), event(17)]
            if original_kind == 17:
                return [event(1), event(18), item]
            if original_kind == 18:
                return [event(1), item, event(17)]
            return [event(1), item, event(18), event(17)]

        for kind in (1, 2, 3, 5, 6, 7, 8, 9, 10, 11, 15, 16, 17, 18):
            original = event(kind)
            baseline = context(original, kind)
            self.assertEqual(validate(baseline).events, len(baseline))
            for index in range(len(original['records'])):
                for key, value, reason in (('action', 2, 'record action'),
                                           ('size', 4, 'record width'),
                                           ('offset', 13, 'record offset'),
                                           ('hex', '', 'scalar hex')):
                    item = copy.deepcopy(original)
                    if item['records'][index][key] == value:
                        value = '00'  # zero assignment requires empty bytes
                    item['records'][index][key] = value
                    with self.subTest(kind=kind, index=index, key=key):
                        self.refuse(context(item, kind), match=reason)
            for key, value, reason in (('record_bytes', original['record_bytes'] + 8, 'record byte size'),
                                      ('header_record_indexes', [0, 1, 2, 3, 99], 'header record indexes'),
                                      ('records', original['records'][:-1], 'record count'),
                                      ('records', original['records'] + original['records'][:1], 'record count')):
                item = copy.deepcopy(original); item[key] = value
                self.refuse(context(item, kind), match=reason)
            for index in range(len(original['records'])):
                for key in ('action', 'size', 'offset', 'hex'):
                    item = copy.deepcopy(original); del item['records'][index][key]
                    self.refuse(context(item, kind), match='record object keys')
                item = copy.deepcopy(original); item['records'][index]['extra'] = 0
                self.refuse(context(item, kind), match='record object keys')
            for field in ('kind', 'timestamp', 'pid', 'tid', 'detail'):
                item = copy.deepcopy(original); item[field] += 1
                reason = 'event kind differs from inventory' if field == 'kind' else 'raw/header disagreement'
                self.refuse(context(item, kind), match=reason)
            first_scalar = int(SHAPES[kind][1])
            for value in ('gg' * 8, 'AA' * 8, '00 ' * 8, '0' * 15, '0' * 17, 0):
                item = copy.deepcopy(original); item['records'][first_scalar]['hex'] = value
                self.refuse(context(item, kind), match='scalar hex')
            item = copy.deepcopy(original)
            item['records'][first_scalar + 1]['hex'] = struct.pack('>Q', item['timestamp']).hex()
            self.refuse(context(item, kind), match='raw/header disagreement')

    def test_old_standalone_mutation_context_was_not_a_valid_baseline(self):
        # Regression explanation: the old lone-record context rejected unchanged
        # non-BEGIN events, so a loose layout check could still look green there.
        for kind in (2, 3, 5, 6, 7, 8, 9, 10, 11, 15, 16, 17, 18):
            self.refuse(event_lines=[line(event(kind), 1)], match='event before BEGIN')
        self.refuse(event_lines=[line(event(1), 1)], match='incomplete')

    def test_inventory_event_binding_and_epid_bijection(self):
        for key, value in (('provider', 'mach_trap'), ('module', 'changed'),
                           ('function', 'changed'), ('name', 'changed'), ('probe_id', 999), ('kind', 14)):
            item = event(2); item[key] = value
            self.refuse([event(1), item, event(18), event(17)])
        item = event(2); item['epid'] = 1001
        self.refuse([event(1), item, event(18), event(17)], match='EPID rebound')
        first, second = event(2), event(2); second['epid'] += 300
        self.refuse([event(1), first, second, event(18), event(17)], match='multiple EPIDs')
        self.assertEqual(validate([event(1), first, first, event(18), event(17)]).observed_enablings, 4)

    def test_identity_scalar_semantics(self):
        for kind, index, value in ((1, 2, TARGET), (17, 2, TARGET), (1, 4, 1), (17, 4, 1),
                                  (2, 2, OWNER), (3, 4, TARGET), (5, 4, TARGET), (7, 4, TARGET),
                                  (15, 4, TARGET), (16, 4, TARGET), (10, 4, 1), (11, 4, 1),
                                  (18, 4, OWNER), (18, 6, 0), (18, 7, 1 << 32),
                                  (2, 1, 0), (2, 2, 1 << 31), (2, 3, 0), (18, 2, 0)):
            item = event(kind); change_scalar(item, index, value)
            records = [item, event(18), event(17)] if kind == 1 else \
                      [event(1), event(18), item] if kind == 17 else \
                      [event(1), item, event(17)] if kind == 18 else \
                      [event(1), item, event(18), event(17)]
            baseline = [event(1), event(18), event(17)] if kind in (1, 17, 18) else \
                       [event(1), event(kind), event(18), event(17)]
            self.assertEqual(validate(baseline).events, len(baseline))
            self.refuse(records, match='identity|parent|detail|exited|timestamp range|actor PID range|thread ID range')
        # No cross-domain or even raw timestamp-order assertion: both remain opaque.
        items = [event(1), event(2), event(18), event(17)]
        change_scalar(items[1], 1, 1)
        self.assertEqual(validate(items).events, 4)

    def test_lifecycle_no_descendant_no_terminal_substitutes(self):
        for records in ([event(18), event(17)], [event(2), event(1), event(18), event(17)],
                        [event(1), event(1), event(18), event(17)],
                        [event(1), event(17), event(18)], [event(1), event(18)],
                        [event(1), event(6), event(17)],
                        [event(1), event(18, refcount=0x1e2), event(17)],
                        [event(1), event(18), event(18), event(17)],
                        [event(1), event(18), event(2), event(17)],
                        [event(1), event(18), event(17), event(11)],
                        [event(1), event(18), event(17), event(17)]):
            self.refuse(records)
        for kind in (4, 12, 13):
            self.refuse([event(1), event(kind, detail=4444 if kind == 4 else 0), event(18), event(17)],
                        match='descendant/spawn')
        bad = lines([event(1), event(18), event(17)])
        bad[1] = bad[1].replace(b'"event":2', b'"event":3')
        self.refuse(event_lines=bad, match='ordinal')
        self.refuse(event_lines=lines([event(1), event(18), event(17)]) + [b'partial'], match='complete LF')

    def test_inventory_capacity_exact_and_over(self):
        rows = [PROBES]
        for i in range(8192 - len(NAMES)):
            rows.append(f'{10000 + i}\tsyscall\t\tf{i}\tentry\n'.encode())
        cap = b''.join(rows)
        result = validate(probes=cap)
        self.assertEqual(result.inventory_probes, 8192)
        self.refuse(probes=cap + b'999999\tsyscall\t\tx\tentry\n', match='probe bound')

    def test_fixed_stream_budget_boundaries(self):
        # The byte cap prevents1M valid current-shape events, but the independent
        # event-count guard still has a fixed boundary and must fail before parse.
        check._stream_budget(999999, 134217727, 1)
        with self.assertRaisesRegex(check.RawValidationError, 'event count bound'):
            check._stream_budget(1000000, 0, 1)
        with self.assertRaisesRegex(check.RawValidationError, 'raw byte bound'):
            check._stream_budget(0, 134217728, 1)
        check._stream_budget(0, 134217728, 0)

    def test_stream_exact_128mib_and_early_overflow(self):
        # Padding is valid JSON whitespace, keeping <=8191 per physical line.
        # A generator produces128MiB without retaining any full capture/list.
        activity_count = 134217728 // 8191
        first = line(event(1), 1)
        terminal = line(event(18), activity_count + 2)
        end = line(event(17), activity_count + 3)
        payload_bytes = 134217728 - len(first) - len(terminal) - len(end)
        size, large_count = divmod(payload_bytes, activity_count)
        seen, expected_hash = [0], hashlib.sha256()
        def stream():
            for item in [first]:
                expected_hash.update(item); seen[0] += 1; yield item
            for i in range(activity_count):
                item = line(event(2), i + 2, size + (i < large_count))
                expected_hash.update(item); seen[0] += 1; yield item
            for item in (terminal, end):
                expected_hash.update(item); seen[0] += 1; yield item
        tracemalloc.start()
        try:
            result = validate(event_lines=stream())
            _, peak = tracemalloc.get_traced_memory()
        finally:
            tracemalloc.stop()
        self.assertEqual(result.raw_bytes, 134217728)
        self.assertEqual(result.events, activity_count + 3)
        self.assertEqual(result.raw_sha256, expected_hash.hexdigest())
        self.assertLess(peak, 8 * 1024 * 1024)
        self.assertEqual(seen[0], activity_count + 3)
        def overflow():
            yield from stream()
            yield b'{}\n'
            raise AssertionError('read beyond raw byte bound')
        self.refuse(event_lines=overflow(), match='raw byte bound')


class BsdObservationControls(unittest.TestCase):
    def test_minimal_and_complete_raw_facts_differential(self):
        variants = [
            [event(1), event(18), event(17)],
            [event(1), event(2), event(3), event(18), event(17)],
            [event(1), event(15), event(16), event(18), event(17)],
            [event(1)] + [event(k) for k in (2, 3, 5, 6, 7, 8, 9, 10, 11, 15, 16)] +
                [event(18, refcount=0x1e2), event(2), event(18, actor=9876),
                 event(18, actor=9876, refcount=0x1e2), event(11), event(17)],
        ]
        for records in variants:
            with self.subTest(kinds=[r['kind'] for r in records]):
                result = observe(records)
                self.assertEqual(result.raw, validate(records))
                # Independent checks, rather than trusting only two APIs that
                # deliberately share one validator.
                self.assertEqual(result.raw.raw_sha256, hashlib.sha256(b''.join(lines(records))).hexdigest())
                self.assertEqual(result.raw.events, len(records))
                self.assertEqual(len(result.observations), sum(r['kind'] in (2, 3) for r in records))
                self.assertFalse(result.full_trace_acceptance)
                self.assertEqual(result.contract_sha256, hashlib.sha256(CONTRACT).hexdigest())
        empty = observe(variants[2])
        self.assertEqual(empty.observations, ())
        self.assertEqual(empty.raw.event_kind_counts[15:17], (1, 1))
        self.assertEqual(empty.coverage, check.BsdCoverage(0, 0, 0, 0, 0, 0, 0, ()))

    def test_known_entry_exact_metadata_words_and_selectors(self):
        words = [0, 1, (1 << 31) - 1, 1 << 31, (1 << 63) - 1, 1 << 63, (1 << 64) - 2, (1 << 64) - 1]
        record = bsd(2, 'mmap', words)
        record['cpu'] = 2147483647
        change_scalar(record, 3, (1 << 64) - 1)
        result = observe([event(1), record, event(18), event(17)], probes=bsd_probes('mmap'))
        phase, = result.observations
        self.assertEqual((phase.ordinal, phase.cpu, phase.probe_id, phase.epid), (2, 2147483647, 102, 1002))
        self.assertEqual((phase.provider, phase.module, phase.function, phase.name), ('syscall', '', 'mmap', 'entry'))
        self.assertEqual(phase.raw_scalars, (2, 0x102030405060708, TARGET, (1 << 64) - 1, OWNER, *words))
        self.assertTrue(phase.source_contract_known)
        self.assertIsNone(phase.returned)
        self.assertIsNone(phase.unsupported_reason)
        facts = phase.entry
        self.assertEqual(facts.raw_words, tuple(words))
        self.assertEqual(dict(facts.fields), {'address': words[0], 'length': words[1], 'protection': words[2],
                                            'flags': words[3], 'fd': words[4], 'offset': words[5]})
        self.assertEqual((facts.name, facts.number, facts.family, facts.source_argument_count),
                         ('mmap', 197, 'mapping', 6))
        self.assertTrue(facts.entry_attempt_observed)
        self.assertIn('file-backed-object-and-offset', facts.requirements)
        self.assertFalse(facts.full_trace_acceptance)
        self.assertEqual(result.coverage, check.BsdCoverage(1, 0, 1, 0, 0, 0, 0, ()))

    def test_failed_write_phases_stay_independent_and_entry_retained(self):
        entry_words = [9, 0x12345678, 123, 0, 0, 0, 0, 0]
        return_words = [(1 << 64) - 1, (1 << 64) - 1, 0, 13, 13]
        entered = bsd(2, 'write', entry_words)
        returned = bsd(3, 'write', return_words)
        # Different TIDs and raw reversed timestamps are still only phases;
        # transport validation supplies no call pairing or timestamp-order claim.
        change_scalar(returned, 3, 99)
        change_scalar(returned, 1, 1)
        result = observe([event(1), returned, entered, event(18), event(17)], probes=bsd_probes('write'))
        first, second = result.observations
        self.assertIsNone(first.entry)
        self.assertEqual(first.returned.kernel_error_bits, 13)
        self.assertEqual(first.raw_scalars[5:], tuple(return_words))
        self.assertIsNone(second.returned)
        self.assertEqual(dict(second.entry.fields), {'fd': 9})
        self.assertTrue(second.entry.entry_attempt_observed)
        self.assertIn('rights-and-output-policy', second.entry.requirements)
        self.assertEqual(result.coverage, check.BsdCoverage(1, 1, 1, 0, 1, 0, 0, ()))

    def test_unknown_nonreturn_and_unpaired_phases_are_not_invented(self):
        for function in ('unknown_bsd', 'exit', 'read'):
            with self.subTest(function=function):
                records = [event(1), bsd(2, function, [0] * 8), event(18), event(17)]
                result = observe(records, probes=bsd_probes(function))
                phase, = result.observations
                self.assertFalse(phase.source_contract_known)
                self.assertEqual(phase.unsupported_reason, 'no pinned BSD source contract')
                self.assertIsNone(phase.entry)
                self.assertIsNone(phase.returned)
                self.assertEqual(result.coverage.unknown_names, ((function, 1),))
        result = observe([event(1), bsd(3, 'unknown_bsd', [3, 3, 4, 0, 0]), event(18), event(17)],
                         probes=bsd_probes('unknown_bsd'))
        self.assertFalse(result.observations[0].source_contract_known)
        self.assertEqual(result.observations[0].returned.primary_result_bits, 3)
        self.assertEqual(result.coverage.unknown_names, (('unknown_bsd', 1),))

    def test_unsupported_return_shapes_remain_transport_valid(self):
        cases = [([3, 4, 0, 0, 0], 'provider primary return duplication differs'),
                 ([3, 3, 0, 1, 2], 'provider kernel error and builtin errno differ')]
        for words, reason in cases:
            records = [event(1), bsd(3, 'write', words), event(18), event(17)]
            result = observe(records, probes=bsd_probes('write'))
            self.assertEqual(result.raw, validate(records, probes=bsd_probes('write')))
            phase, = result.observations
            self.assertIsNone(phase.returned)
            self.assertEqual(phase.raw_scalars[5:], tuple(words))
            self.assertEqual(phase.unsupported_reason, reason)
            self.assertEqual(result.coverage.unsupported_return_shapes, 1)
        words = [(1 << 64) - 1] * 5
        result = observe([event(1), bsd(3, 'write', words), event(18), event(17)], probes=bsd_probes('write'))
        self.assertTrue(result.observations[0].returned.control_flow_unmodeled)
        self.assertEqual(result.coverage.control_flow_unmodeled_returns, 1)

    def test_deep_immutability_and_input_detachment(self):
        records = [event(1), bsd(2, 'openat', [1, 2, 3, 4, 5, 6, 7, 8]), event(18), event(17)]
        result = observe(records, probes=bsd_probes('openat'))
        phase, = result.observations
        expected = phase.raw_scalars
        change_scalar(records[1], 5, 777)
        records[1]['function'] = 'changed'
        self.assertEqual(phase.raw_scalars, expected)
        for obj, field in ((result, 'protocol'), (result.raw, 'events'), (phase, 'ordinal'),
                           (phase.entry, 'name'), (result.coverage, 'entries')):
            with self.assertRaises(FrozenInstanceError):
                setattr(obj, field, None)
        for collection in (result.observations, phase.raw_scalars, phase.entry.fields,
                           phase.entry.raw_words, phase.entry.requirements,
                           result.coverage.unknown_names):
            self.assertIs(type(collection), tuple)
        with self.assertRaises(TypeError):
            phase.entry.fields[0] = ('dirfd', 777)

    def test_transport_mutations_refuse_identically_without_partial_result(self):
        baseline = [event(1), event(2), event(15), event(18), event(17)]
        self.assertEqual(observe(baseline).raw, validate(baseline))
        bad = []
        for position, key, value in ((0, 'cpu', True), (1, 'epid', 0), (2, 'provider', 'changed'),
                                     (3, 'detail', 0), (4, 'record_bytes', 12)):
            records = copy.deepcopy(baseline)
            records[position][key] = value
            bad.append({'event_lines': lines(records)})
        for position in (0, 1, 2, 3, 4):
            records = copy.deepcopy(baseline)
            records[position]['records'][-1]['action'] = 2
            bad.append({'event_lines': lines(records)})
        bad += [{'event_lines': lines(baseline[:-1])},
                {'event_lines': lines(baseline[:3] + baseline[4:])},
                {'event_lines': lines(baseline) + [b'{}\n']},
                {'event_lines': lines(baseline[:-1]) + [b'partial']},
                {'program': PROGRAM + b'\n'}, {'probes': PROBES[:-1]}, {'errors': b'fault'}]
        for kwargs in bad:
            with self.subTest(kwargs=str(kwargs)[:80]):
                messages = []
                for operation in (validate, observe):
                    with self.assertRaises(check.RawValidationError) as error:
                        operation(**kwargs)
                    messages.append(str(error.exception))
                    self.assertFalse(hasattr(error.exception, 'report'))
                self.assertEqual(*messages)
        for operation in (validate, observe):
            def source_failure():
                yield from lines(baseline[:-1])
                raise OSError('late source failure')
            with self.assertRaisesRegex(OSError, 'late source failure') as error:
                operation(event_lines=source_failure())
            self.assertFalse(hasattr(error.exception, 'report'))

    def test_projection_exact_bound_and_early_overflow_old_api_unchanged(self):
        def stream(count):
            yield line(event(1), 1)
            for index in range(count):
                yield line(event(2), index + 2)
            yield line(event(18), count + 2)
            yield line(event(17), count + 3)
        result = observe(event_lines=stream(4096))
        self.assertEqual(len(result.observations), 4096)
        self.assertEqual(result.raw, validate(event_lines=stream(4096)))
        self.assertEqual(result.coverage.unknown_names, (('read', 4096),))
        self.assertEqual(validate(event_lines=stream(4097)).events, 4100)
        def overflow():
            yield line(event(1), 1)
            for index in range(4097):
                yield line(event(2), index + 2)
            raise AssertionError('source consumed after projection overflow')
        with self.assertRaisesRegex(check.RawValidationError, 'BSD phase projection bound') as error:
            observe(event_lines=overflow())
        self.assertFalse(hasattr(error.exception, 'report'))

    def test_contract_asset_pin_and_acceptance_refusal_before_stream(self):
        class Untouched:
            def __iter__(self):
                raise AssertionError('source consumed before static refusal')
        self.assertEqual((len(CONTRACT), hashlib.sha256(CONTRACT).hexdigest()),
                         (96972, '31f96f93c2ca1bd58ae322a6d3c223dd764e5a763088cfed2dbf78a8a21104e2'))
        for raw in (None, CONTRACT.decode(), bytearray(CONTRACT), CONTRACT[:-1], CONTRACT + b' ',
                    b'!' + CONTRACT[1:]):
            with self.assertRaisesRegex(check.RawValidationError, 'pinned BSD contract'):
                observe(contract_bytes=raw, event_lines=Untouched())
        with self.assertRaisesRegex(check.RawValidationError, 'cannot establish full Darwin R02'):
            check.require_full_trace_acceptance()

    def test_no_implicit_asset_reads_on_import_or_apis(self):
        def no_io(*args, **kwargs):
            raise AssertionError('unexpected explicit filesystem I/O')
        with patch('builtins.open', no_io), patch('io.open', no_io), patch('os.open', no_io):
            spec = importlib.util.spec_from_file_location('_owned_bsd_import_control', Path(check.__file__))
            imported = importlib.util.module_from_spec(spec)
            spec.loader.exec_module(imported)
            records = [event(1), bsd(2, 'write', [9, 2, 3, 4, 5, 6, 7, 8]), event(18), event(17)]
            # Code imports are allowed during normal module import, while the
            # fixed contract asset is not read. Once imported, neither API may
            # load code or open an asset even when projecting a known entry.
            with patch('importlib.machinery.SourceFileLoader.get_code', no_io), \
                    patch('importlib.machinery.SourceFileLoader.get_data', no_io), \
                    patch('_io.open_code', no_io), patch('io.open_code', no_io), \
                    patch.object(imported, '_contract_helpers', no_io):
                result = imported.validate_raw(PROGRAM, bsd_probes('write'), b'', lines(records),
                                               owner_pid=OWNER, target_pid=TARGET)
                projected = imported.observe_raw_bsd(PROGRAM, bsd_probes('write'), b'', lines(records),
                    owner_pid=OWNER, target_pid=TARGET, contract_bytes=CONTRACT)
                self.assertEqual(result, projected.raw)
                self.assertEqual(dict(projected.observations[0].entry.fields), {'fd': 9})
                closed = paired_records()
                for record in closed:
                    if record['kind'] in (2, 3):
                        record['function'] = 'write'
                paired = imported.pair_raw_owned(PROGRAM, bsd_probes('write'), b'', lines(closed),
                    owner_pid=OWNER, target_pid=TARGET, contract_bytes=CONTRACT)
                self.assertEqual(paired.raw.events, 6)
                self.assertEqual(paired.counts.pairs, 1)


class OwnedPairControls(unittest.TestCase):
    def refuse(self, records, reason, **kwargs):
        # Establish the complete transport is accepted before testing a narrower
        # pairing refusal; deliberate transport mutations use another control.
        self.assertEqual(validate(records, **kwargs).events, len(records))
        self.assertEqual(observe(records, **kwargs).raw, validate(records, **kwargs))
        with self.assertRaisesRegex(check.RawValidationError, reason) as error:
            pair_owned(records, **kwargs)
        self.assertFalse(hasattr(error.exception, 'report'))

    def test_closed_pair_raw_provenance_counts_and_old_api_differential(self):
        records = paired_records()
        result = pair_owned(records)
        self.assertEqual(result.raw, validate(records))
        self.assertEqual(result.raw, observe(records).raw)
        self.assertEqual(result.raw.raw_sha256, hashlib.sha256(b''.join(lines(records))).hexdigest())
        self.assertEqual(result.raw.events, 6)
        paired, = result.pairs
        self.assertEqual(paired.correlation_id, (2, 3))
        self.assertEqual((paired.entry.ordinal, paired.entry.cpu, paired.entry.epid, paired.entry.probe_id),
                         (2, 7, 1002, 102))
        self.assertEqual((paired.entry.provider, paired.entry.module, paired.entry.function, paired.entry.name),
                         ('syscall', '', 'read', 'entry'))
        self.assertEqual(paired.entry.raw_scalars, (2, 101, TARGET, 1000, OWNER, *range(0x11110000, 0x11110008)))
        self.assertEqual(paired.returned.raw_scalars, (3, 102, TARGET, 1000, OWNER, *range(0x11110000, 0x11110005)))
        self.assertEqual([p.ordinal for p in result.lifecycle], [1, 4, 5, 6])
        self.assertEqual(result.counts, check.OwnedPairCounts(2, 1, 1, 0, 1, 0, 0, 1, 4))
        self.assertEqual(result.bsd_coverage.unknown_names, (('read', 2),))
        self.assertEqual(result.unpaired_phase_count, 0)
        self.assertFalse(result.full_trace_acceptance)
        self.assertFalse(result.state_feed_eligible)

    def test_bsd_and_mach_interleave_on_declared_threads_and_sort_by_entry(self):
        records = ticked([event(1), threaded(2), threaded(9, detail=2000), threaded(10, tid=2000),
            threaded(15, tid=2000), threaded(16, tid=2000), threaded(11, tid=2000), threaded(3),
            threaded(11), event(18, actor=9876), event(17)])
        result = pair_owned(records)
        self.assertEqual(result.raw, validate(records))
        self.assertEqual([p.correlation_id for p in result.pairs], [(2, 8), (5, 6)])
        mach = result.pairs[1]
        self.assertIs(type(mach.entry), check.OwnedRawPhase)
        self.assertIs(type(mach.returned), check.OwnedRawPhase)
        self.assertEqual(mach.entry.raw_scalars[5:], tuple(range(0x11110000, 0x11110008)))
        self.assertEqual(mach.returned.raw_scalars[5:], (0x11110000,))
        self.assertFalse(hasattr(mach.returned, 'returned'))  # opaque Mach bits
        self.assertEqual(result.counts, check.OwnedPairCounts(4, 2, 1, 1, 2, 1, 1, 2, 7))
        self.assertEqual(result.raw.terminal_actor_pid, 9876)

    def test_initial_mach_entry_can_seed_thread_with_opaque_return(self):
        records = ticked([event(1), threaded(15), threaded(16), threaded(11), event(18), event(17)])
        change_scalar(records[2], 5, check.U64)
        result = pair_owned(records)
        self.assertEqual(result.raw, validate(records))
        self.assertEqual(result.raw, observe(records).raw)
        self.assertEqual((result.counts.bsd_pairs, result.counts.mach_pairs), (0, 1))
        self.assertEqual(result.bsd_coverage, check.BsdCoverage(0, 0, 0, 0, 0, 0, 0, ()))
        self.assertEqual(result.pairs[0].returned.raw_scalars[5:], (check.U64,))
        self.assertIs(type(result.pairs[0].entry), check.OwnedRawPhase)
        self.assertFalse(result.state_feed_eligible)

    def test_known_failed_write_and_unsupported_raw_return_stay_in_pair(self):
        entered = bsd(2, 'write', [9, 0x12345678, 4096, 0, 0, 0, 0, 0])
        returned = bsd(3, 'write', [check.U64, check.U64, 0, 13, 13])
        for item in (entered, returned):
            change_scalar(item, 3, 1000)
        records = ticked([event(1), entered, returned, threaded(11), event(18), event(17)])
        result = pair_owned(records, probes=bsd_probes('write'))
        paired, = result.pairs
        self.assertTrue(paired.entry.entry.entry_attempt_observed)
        self.assertEqual(dict(paired.entry.entry.fields), {'fd': 9})
        self.assertIn('rights-and-output-policy', paired.entry.entry.requirements)
        self.assertEqual(paired.returned.returned.kernel_error_bits, 13)
        self.assertEqual(result.bsd_coverage.supported_return_shapes, 1)
        change_scalar(records[2], 6, 0)
        unsupported = pair_owned(records, probes=bsd_probes('write')).pairs[0]
        self.assertEqual(unsupported.entry, paired.entry)
        self.assertIsNone(unsupported.returned.returned)
        self.assertEqual(unsupported.returned.unsupported_reason, 'provider primary return duplication differs')
        self.assertEqual(unsupported.returned.raw_scalars[5:], (check.U64, 0, 0, 13, 13))

    def test_orphans_overlaps_and_pending_nonreturn_entries_refuse(self):
        for kind in (3, 16):
            self.refuse(ticked([event(1), threaded(kind), threaded(11), event(18), event(17)]),
                        'first target observation is not call entry')
        self.refuse(ticked([event(1), threaded(2), threaded(3), threaded(3), threaded(11), event(18), event(17)]),
                    'orphan return')
        for second in (2, 15):
            self.refuse(ticked([event(1), threaded(2), threaded(second), threaded(3), threaded(11), event(18), event(17)]),
                        'overlapping call entry')
        for route, reason in ((11, 'pending call at thread exit'), (18, 'pending call at target terminal')):
            records = ticked([event(1), threaded(2), threaded(route), event(18), event(17)] if route == 11 else
                             [event(1), threaded(2), event(18), event(17)])
            self.refuse(records, reason)
        for function in ('exit', 'bsdthread_terminate'):
            records = ticked([event(1), threaded(2), threaded(11), event(18), event(17)])
            records[1]['function'] = function
            self.refuse(records, 'pending call at thread exit', probes=bsd_probes(function))

    def test_exact_provider_module_function_and_thread_matching(self):
        self.refuse(ticked([event(1), threaded(2), threaded(16), threaded(11), event(18), event(17)]),
                    'call family or actor mismatch')
        for field, value in (('module', 'alternate'), ('function', 'alternate_call')):
            records = paired_records()
            records[2][field] = value
            probe_fields = ['syscall', '', 'read', 'return']
            probe_fields[1 if field == 'module' else 2] = value
            probes = PROBES.replace(b'103\tsyscall\t\tread\treturn\n',
                                    ('103\t' + '\t'.join(probe_fields) + '\n').encode())
            self.refuse(records, 'call family or actor mismatch', probes=probes)
        records = paired_records()
        change_scalar(records[2], 3, 2000)
        self.refuse(records, 'thread not active')

    def test_first_entry_and_lifecycle_start_subset(self):
        for kind in (5, 6, 9, 10, 11):
            self.refuse(ticked([event(1), threaded(kind, detail=2000 if kind == 9 else None),
                               threaded(2), threaded(3), threaded(11), event(18), event(17)]),
                        'first target observation is not call entry')
        self.refuse(ticked([event(1), threaded(2), threaded(3), threaded(5), threaded(11), event(18), event(17)]),
                    'proc:start launch boundary unsupported')
        self.refuse(ticked([event(1), event(18), event(17)]), 'first target observation is not call entry')

    def test_thread_declaration_start_exit_and_no_reuse(self):
        initial = [event(1), threaded(2), threaded(3)]
        finish = [threaded(11), event(18), event(17)]
        for middle, reason in (
            ([threaded(10, tid=2000)], 'start without fresh declaration'),
            ([threaded(9, detail=0)], 'declared TID range'),
            ([threaded(9, detail=1000)], 'TID reused or duplicate'),
            ([threaded(9, detail=2000), threaded(9, detail=2000)], 'TID reused or duplicate'),
            ([threaded(9, tid=2000, detail=3000)], 'thread not active'),
            ([threaded(9, detail=2000), threaded(2, tid=2000)], 'thread not active'),
            ([threaded(9, detail=2000), threaded(11, tid=2000)], 'thread not active'),
            ([threaded(9, detail=2000), threaded(10, tid=2000), threaded(10, tid=2000)], 'start without fresh declaration'),
            ([threaded(9, detail=2000)], 'unretired thread at END'),
            ([threaded(11, tid=2000)], 'thread not active'),
            ([threaded(11), threaded(11)], 'thread not active'),
            ([threaded(11), threaded(2)], 'thread not active'),
            ([threaded(9, detail=2000), threaded(10, tid=2000), threaded(11, tid=2000),
              threaded(9, detail=2000)], 'TID reused or duplicate'),
        ):
            with self.subTest(reason=reason, kinds=[r['kind'] for r in middle]):
                self.refuse(ticked(initial + middle + finish), reason)

    def test_exec_and_every_shadow_transition_refuse(self):
        for kind in (7, 8):
            for pending in (False, True):
                middle = [threaded(2)] + ([] if pending else [threaded(3)])
                self.refuse(ticked([event(1)] + middle + [threaded(kind), threaded(11), event(18), event(17)]),
                            'exec transition unsupported')
        for middle in ([threaded(2)], [threaded(2), threaded(3)],
                       [threaded(2), threaded(3), threaded(11)]):
            self.refuse(ticked([event(1)] + middle + [event(18, refcount=0x1e2), event(18), event(17)]),
                        'shadow-exited transition unsupported')

    def test_exit_context_requires_no_pending_and_starts_closing(self):
        records = ticked([event(1), threaded(2), threaded(3), threaded(6, detail=999),
                          threaded(11), event(18), event(17)])
        result = pair_owned(records)
        self.assertEqual(result.lifecycle[1].raw_scalars[4], 999)
        self.assertEqual(result.counts.retired_tids, 1)
        self.refuse(ticked([event(1), threaded(2), threaded(6), threaded(3), threaded(11), event(18), event(17)]),
                    'pending call at exit context')
        self.refuse(ticked([event(1), threaded(2), threaded(9, detail=2000), threaded(10, tid=2000),
                            threaded(6, tid=2000), threaded(3), threaded(11, tid=2000), threaded(11),
                            event(18), event(17)]), 'pending call at exit context')
        records = ticked([event(1), threaded(2), threaded(3), threaded(6, tid=2000),
                          threaded(11), event(18), event(17)])
        self.refuse(records, 'thread not active')
        for forbidden in (threaded(2), threaded(6), threaded(9, detail=2000), threaded(10)):
            records = ticked([event(1), threaded(2), threaded(3), threaded(6), forbidden,
                              threaded(11), event(18), event(17)])
            self.refuse(records, 'activity after closing context')

    def test_terminal_cleanup_and_all_threads_retired_at_end(self):
        records = ticked([event(1), threaded(2), threaded(3), event(18, actor=9876), threaded(11), event(17)])
        result = pair_owned(records)
        self.assertEqual(result.raw.terminal_actor_pid, 9876)
        self.assertEqual([p.raw_scalars[0] for p in result.lifecycle], [1, 18, 11, 17])
        self.refuse(ticked([event(1), threaded(2), threaded(3), event(18), event(17)]),
                    'unretired thread at END')
        self.refuse(ticked([event(1), threaded(2), threaded(3), event(18), threaded(11, tid=2000), event(17)]),
                    'thread not active')

    def test_timestamp_guard_all_records_and_exact_tie_buckets(self):
        records = paired_records()
        change_scalar(records[2], 1, records[1]['timestamp'])
        self.assertEqual(pair_owned(records).counts.pairs, 1)  # pure call-phase tie
        for index, timestamp, reason in ((2, 99, 'timestamp moves backwards'),
                                          (1, 100, 'ambiguous lifecycle timestamp tie'),
                                          (3, 102, 'ambiguous lifecycle timestamp tie'),
                                          (4, 103, 'ambiguous lifecycle timestamp tie'),
                                          (5, 104, 'ambiguous lifecycle timestamp tie')):
            records = paired_records()
            change_scalar(records[index], 1, timestamp)
            self.refuse(records, reason)

    def test_phase_pair_and_thread_exact_bounds(self):
        def many_pairs(count):
            records = [event(1)]
            for _ in range(count):
                records.extend([threaded(2), threaded(3)])
            return ticked(records + [threaded(11), event(18), event(17)])
        result = pair_owned(many_pairs(2048))
        self.assertEqual((result.counts.call_phases, result.counts.pairs), (4096, 2048))
        # observe_raw_bsd has its own4096-phase limit, so establish only transport
        # validity for the over-bound case, not a fictitious scalar-observer pass.
        over = many_pairs(2049)
        self.assertEqual(validate(over).events, len(over))
        with self.assertRaisesRegex(check.RawValidationError, 'call phase bound'):
            pair_owned(over)
        result = pair_owned(multi_thread_records(256))
        self.assertEqual((result.counts.observed_tids, result.counts.retired_tids), (256, 256))
        self.assertEqual((result.counts.declared_tids, result.counts.started_declared_tids), (255, 255))
        self.refuse(multi_thread_records(257), 'observed TID bound')

    def test_maximum_closed_context_and_source_exception_no_prefix(self):
        # 255 declared threads each create/start/exit, initial exit, one closing
        # context, BEGIN/terminal/END:770. Independent1024context and2048pair
        # guards cannot be exceeded without an earlier TID/phase refusal. Use a
        # complete maximum-context fixture rather than fabricate1024 valid ones.
        maximum = multi_thread_records(256, closing=True)
        result = pair_owned(maximum)
        self.assertEqual(result.raw, validate(maximum))
        self.assertEqual(result.counts.lifecycle_records, 770)
        self.assertEqual(result.counts.observed_tids, 256)
        self.assertEqual(sum(p.raw_scalars[0] == 6 for p in result.lifecycle), 1)
        records = paired_records()
        for tail in (b'partial', b'{}\n'):
            with self.assertRaises(check.RawValidationError) as error:
                pair_owned(event_lines=lines(records) + [tail])
            self.assertFalse(hasattr(error.exception, 'report'))
        def failure():
            yield from lines(records)
            raise OSError('source failed after END')
        with self.assertRaisesRegex(OSError, 'source failed after END') as error:
            pair_owned(event_lines=failure())
        self.assertFalse(hasattr(error.exception, 'report'))

    def test_transport_corruption_is_still_shared_and_no_result_is_released(self):
        records = paired_records()
        bad = []
        for index in range(len(records)):
            mutated = copy.deepcopy(records)
            mutated[index]['records'][-1]['action'] = 2
            bad.append(lines(mutated))
        actor_mismatch = copy.deepcopy(records)
        change_scalar(actor_mismatch[1], 2, OWNER)
        bad.append(lines(actor_mismatch))
        bad += [lines(records[:-1]), lines(records[:4] + records[5:])]
        for raw in bad:
            reasons = []
            for operation in (validate, observe, pair_owned):
                with self.assertRaises(check.RawValidationError) as error:
                    operation(event_lines=raw)
                reasons.append(str(error.exception))
                self.assertFalse(hasattr(error.exception, 'report'))
            self.assertEqual(reasons[0], reasons[1])
            self.assertEqual(reasons[1], reasons[2])

    def test_frozen_result_detachment_and_static_contract_refusal(self):
        records = paired_records()
        result = pair_owned(records)
        entered = result.pairs[0].entry
        change_scalar(records[1], 5, 999)
        self.assertEqual(entered.raw_scalars[5], 0x11110000)
        for value, field in ((result, 'protocol'), (result.counts, 'pairs'),
                             (result.pairs[0], 'entry'), (entered, 'ordinal'),
                             (result.lifecycle[0], 'cpu'), (result.raw, 'events')):
            with self.assertRaises(FrozenInstanceError):
                setattr(value, field, None)
        for value in (result.pairs, result.lifecycle, entered.raw_scalars,
                      result.pairs[0].correlation_id, result.bsd_coverage.unknown_names):
            self.assertIs(type(value), tuple)
        class Untouched:
            def __iter__(self):
                raise AssertionError('source consumed before static refusal')
        for raw in (None, bytearray(CONTRACT), CONTRACT[:-1], b'!' + CONTRACT[1:]):
            with self.assertRaisesRegex(check.RawValidationError, 'pinned BSD contract'):
                pair_owned(contract_bytes=raw, event_lines=Untouched())


if __name__ == '__main__':
    unittest.main()
