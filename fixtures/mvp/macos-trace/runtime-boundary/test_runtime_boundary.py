"""Independent physical raw and launch-byte controls; no provider or launch."""
import copy
from dataclasses import FrozenInstanceError, replace
import hashlib
import json
from pathlib import Path
import shutil
import struct
import subprocess
import tempfile
import unittest
from unittest.mock import patch

import runtime_boundary as boundary

HERE = Path(__file__).resolve().parent
BASE = HERE.parent
OWNER, TARGET, OLD, NEW, GATE, STATUS = 3131, 4242, 101, 202, 8, 9
CONTRACT = (BASE / 'syscall-contract/contracts.json').read_bytes()
TARGET_BYTES = b'protected-test-target'


def put(buffer, at, width, value):
    buffer[at:at + width] = value.to_bytes(width, 'big')


def launch():
    build = b'fixture-runtime'
    cwd = b'/System/Volumes/Data/Library/GlueMVPFixtures/' + build
    executable = cwd + b'/context-probe'
    catalog = bytearray(192 + len(build) + 13)
    catalog[:8] = b'GLUENC01'
    for at, width, value in ((8, 2, 1), (10, 2, 192), (12, 4, len(catalog)),
                             (16, 8, len(TARGET_BYTES)), (24, 8, 1), (32, 4, 2),
                             (36, 4, 3), (40, 8, 4), (48, 4, 5), (52, 4, 6),
                             (184, 2, len(build)), (186, 2, 13)):
        put(catalog, at, width, value)
    catalog[56:88] = hashlib.sha256(TARGET_BYTES).digest()
    for at, value in ((88, b'p'), (120, b'r'), (152, b'b')):
        catalog[at:at + 32] = value * 32
    catalog[192:] = build + b'context-probe'
    request = bytearray(208 + len(executable) + len(cwd))
    request[:8] = b'GLUENR01'
    for at, width, value in ((8, 2, 1), (10, 2, 208), (12, 4, len(request)), (16, 4, 1),
                             (20, 4, 501), (24, 4, 20), (28, 4, 2), (32, 4, 20),
                             (36, 4, 0), (96, 4, 1), (100, 4, 1), (104, 4, 1),
                             (108, 4, 4096), (112, 4, 100), (116, 4, 100), (120, 4, 1),
                             (160, 8, 77), (168, 8, 88), (176, 4, len(executable)), (180, 4, len(cwd))):
        put(request, at, width, value)
    request[128:160] = hashlib.sha256(catalog).digest()
    request[208:] = executable + cwd
    binding = OWNER.to_bytes(4, 'big') + TARGET.to_bytes(4, 'big') + hashlib.sha256(request).digest()

    def status(kind):
        out = bytearray(512)
        out[:8] = b'GLUEFS02'
        for at, width, value in ((8, 2, 2), (10, 2, kind), (12, 4, 512),
                                 (16, 4, 5 if kind == 1 else 0), (20, 4, 256)):
            put(out, at, width, value)
        p = bytearray(256)
        p[:8] = b'GLUEBS01'
        p[16:56] = binding
        for at, width, value in ((8, 2, 1), (10, 2, kind), (12, 4, 256),
                                 (56, 4, 0 if kind == 1 else 1), (60, 4, 0 if kind == 1 else 13),
                                 (68, 4, 3), (228, 4, 0xffffffff)):
            put(p, at, width, value)
        if kind == 1:
            for at, width, value in ((72, 4, 501), (76, 4, 501), (80, 4, 20), (84, 4, 20),
                                     (88, 4, 2), (92, 4, 20), (156, 8, 77), (164, 8, 88)):
                put(p, at, width, value)
            p[192:224] = b's' * 32
            for i, fd in enumerate((0, 1, 2, GATE, STATUS)):
                put(p, 172 + i * 4, 4, fd)
                at = 288 + 40 * i
                for offset, width, value in ((0, 4, fd), (4, 4, int(i >= 3)),
                    (8, 4, (1 if i in (1, 2, 4) else 0) | (4 if i >= 3 else 0)),
                    (12, 4, 0o100600 if i in (1, 2) else 0o010600),
                    (16, 8, 77), (24, 8, 1000 + i), (32, 8, 1)):
                    put(out, at + offset, width, value)
        out[32:288] = p
        return bytes(out)
    go = bytearray(64)
    go[:8] = b'GLUEFG02'
    put(go, 8, 2, 2)
    put(go, 10, 2, 64)
    go[12:52] = binding
    return boundary.LaunchEvidence(bytes(request), bytes(catalog), status(1), bytes(go), status(2), TARGET_BYTES)


# Independent probe and scalar tables; fixtures do not call the reader template.
CALL_NAMES = ('read', 'read_nocancel', 'write', 'write_nocancel', 'poll', 'poll_nocancel',
              'close', 'close_nocancel', 'execve', 'getpid', 'getppid', 'fcntl', 'fstat64',
              'fcntl_nocancel', 'fstat', 'sigaction', 'exit', 'fork', 'vfork', 'posix_spawn', '__mac_execve',
              'sendmsg', 'recvmsg', 'fileport_makefd', 'mystery')
PROC_NAMES = {4: 'create', 5: 'start', 6: 'exit', 7: 'exec-success', 8: 'exec-failure',
              9: 'lwp-create', 10: 'lwp-start', 11: 'lwp-exit', 12: 'spawn-success',
              13: 'spawn-failure', 18: 'exited'}
NAMES = [('dtrace', '', '', 'BEGIN'), ('dtrace', '', '', 'END')]
NAMES += [('syscall', '', name, phase) for name in CALL_NAMES for phase in ('entry', 'return')]
NAMES += [('mach_trap', '', 'mach_msg2_trap', phase) for phase in ('entry', 'return')]
NAMES += [('proc', '', '', name) for name in PROC_NAMES.values()]
IDENTITY = {names: i + 1 for i, names in enumerate(NAMES)}
INVENTORY = ''.join(str(IDENTITY[names]) + '\t' + '\t'.join(names) + '\n' for names in NAMES).encode()


def spec(kind, name='', tid=OLD, detail=None, args=()):
    return dict(kind=kind, function=name, tid=tid, detail=detail, args=tuple(args))


def call(name, args=(), result=0, tid=OLD):
    return [spec(2, name, tid, args=tuple(args) + (0,) * (8 - len(args))),
            spec(3, name, tid, args=(result, result, 0, 0, 0))]


def happy(attachment='poll'):
    data = [spec(1)]
    if attachment:
        value = 1 if attachment != 'write' else 512
        data.append(spec(3, attachment, args=(value, value, 0, 0, 0)))
    already = 1 if attachment == 'read' else 0
    data += call('read', (GATE, 0x1000, 64 - already), 64 - already)
    data += call('read', (GATE, 0x1000, 1), 0)
    data += call('close', (GATE,), 0)
    data += call('write', (STATUS, 0x2000, 512), 512)
    data += [spec(2, 'execve', args=(0x3000, 0x4000, 0x5000, 0, 0, 0, 0, 0)),
             spec(11), spec(18, detail=TARGET, args=(0, 0x123456, 0x20)),
             spec(7, tid=NEW), spec(5, tid=NEW), spec(10, tid=NEW)]
    data += call('getpid', (), TARGET, NEW)
    data += call('write', (1, 0x6000, 4), 4, NEW)
    data += [spec(2, 'exit', NEW, args=(0,) * 8), spec(6, tid=NEW, detail=1),
             spec(11, tid=NEW), spec(18, tid=NEW, detail=TARGET, args=(0, 0x123457, 0x100)), spec(17)]
    return data


def lines(data):
    result = []
    for ordinal, item in enumerate(data, 1):
        k = item['kind']
        actor = OWNER if k in (1, 17) else TARGET
        detail = item['detail']
        if detail is None:
            detail = OWNER if k in (2, 3, 5, 7, 15, 16) else 0
        if k in (1, 17):
            names = ('dtrace', '', '', 'BEGIN' if k == 1 else 'END')
        elif k in (2, 3):
            names = ('syscall', '', item['function'], 'entry' if k == 2 else 'return')
        elif k in (15, 16):
            names = ('mach_trap', '', 'mach_msg2_trap', 'entry' if k == 15 else 'return')
        else:
            names = ('proc', '', '', PROC_NAMES[k])
        words = (k, 100 + ordinal, actor, item['tid'], detail) + item['args']
        expected = {2: 13, 3: 10, 15: 13, 16: 6, 18: 8}.get(k, 5)
        assert len(words) == expected, item
        leading = int(k in (1, 4, 5, 7))
        records = [dict(action=1, size=0, offset=12, hex='')] if leading else []
        records += [dict(action=1, size=8, offset=16 + 8 * i, hex=struct.pack('<Q', value).hex())
                    for i, value in enumerate(words)]
        record = dict(event=ordinal, cpu=0, epid=IDENTITY[names], probe_id=IDENTITY[names],
                      record_bytes=16 + 8 * expected, header_record_indexes=list(range(leading, leading + 5)),
                      kind=k, timestamp=words[1], pid=actor, tid=item['tid'], detail=detail,
                      **dict(zip(('provider', 'module', 'function', 'name'), names)), records=records)
        result.append(json.dumps(record, separators=(',', ':')).encode() + b'\n')
    return result


def paired(data=None, **kwargs):
    return boundary.pair_runtime_raw(kwargs.pop('program', boundary.expected_program(TARGET)),
        kwargs.pop('probes', INVENTORY), kwargs.pop('errors', b''),
        kwargs.pop('event_lines', lines(happy() if data is None else data)),
        owner_pid=kwargs.pop('owner_pid', OWNER), target_pid=kwargs.pop('target_pid', TARGET),
        contract_bytes=kwargs.pop('contract_bytes', CONTRACT),
        launch_evidence=kwargs.pop('launch_evidence', launch()), **kwargs)


class RuntimeBoundaryControls(unittest.TestCase):
    def refuse(self, data=None, pattern='.', **kwargs):
        with self.assertRaisesRegex(boundary.RawValidationError, pattern) as caught:
            paired(data, **kwargs)
        return caught.exception

    def test_selected_image_and_every_original_phase_retained(self):
        result = paired()
        self.assertEqual(result.source.raw.events, len(happy()))
        self.assertEqual([p.ordinal for p in result.source.phases], list(range(1, len(happy()) + 1)))
        self.assertEqual((result.selected_exec.old_tid, result.selected_exec.new_tid), (OLD, NEW))
        self.assertIsNone(result.selected_exec.returned)
        self.assertEqual(result.selected_exec.entry.function, 'execve')
        self.assertEqual(result.selected_exec.proc_start.ordinal + 1, result.selected_exec.lwp_start.ordinal)
        self.assertTrue(result.terminating_call)
        self.assertEqual(result.attachment_return.source_route, 'gate-poll-in-flight')
        self.assertEqual([p.image_epoch for p in result.pairs], [0, 0, 0, 0, 1, 1])
        self.assertFalse(result.native_calibration or result.full_trace_acceptance or result.state_feed_eligible)
        self.assertFalse(result.launch.native_origin_authenticated or result.launch.protected_target_admitted)
        self.assertFalse(result.output_capabilities_seeded or result.selected_exec.pathname_observed)

    def test_three_closed_attachment_routes_and_no_orphan(self):
        for name, route in (('read', 'GO-read-in-flight'), ('write', 'READY-write-tail'), ('poll', 'gate-poll-in-flight')):
            with self.subTest(name=name):
                result = paired(happy(name))
                self.assertEqual(result.attachment_return.source_route, route)
                self.assertFalse(result.attachment_return.entry_observed or result.attachment_return.complete_interval)
        self.assertIsNone(paired(happy(None)).attachment_return)

    def test_old_thread_exit_and_shadow_are_optional_retained_context(self):
        data = [s for s in happy() if not (s['tid'] == OLD and s['kind'] in (11, 18))]
        result = paired(data)
        self.assertEqual(result.source.raw.shadow_exits, 0)
        self.assertEqual(result.selected_exec.old_tid, OLD)

    def test_explicit_ejustreturn_is_not_an_ordinary_success_pair(self):
        data = happy()
        at = next(i for i, s in enumerate(data) if s['kind'] == 2 and s['function'] == 'execve')
        data.insert(at + 1, spec(3, 'execve', args=(0, 0, 0, (1 << 64) - 2, (1 << 64) - 2)))
        result = paired(data)
        self.assertIsNotNone(result.selected_exec.returned)
        self.assertFalse(any(p.entry.function == 'execve' for p in result.pairs))

    def test_partial_gate_reads_and_partial_attempt_writes(self):
        data = happy(None)
        at = 1
        data[at:at + 2] = call('read', (GATE, 0x1000, 64), 20) + call('read', (GATE, 0x1014, 44), 44)
        at = next(i for i, s in enumerate(data) if s['kind'] == 2 and s['function'] == 'write')
        data[at:at + 2] = call('write', (STATUS, 0x2000, 512), 200) + call('write', (STATUS, 0x20c8, 312), 312)
        self.assertEqual(len(paired(data).pairs), 8)

    def test_ready_bio_rows_require_nonblock_without_rejecting_high_bits(self):
        evidence = launch()
        for i, missing in ((3, 0), (4, 1)):
            value = bytearray(evidence.ready)
            put(value, 288 + i * 40 + 8, 4, missing)
            self.refuse(launch_evidence=replace(evidence, ready=bytes(value)), pattern='descriptor shape')
        value = bytearray(evidence.ready)
        put(value, 288 + 3 * 40 + 8, 4, 0x01000004)
        put(value, 288 + 4 * 40 + 8, 4, 0x02000005)
        result = paired(launch_evidence=replace(evidence, ready=bytes(value)))
        self.assertEqual(result.launch.objects[3].status_flags, 0x01000004)
        self.assertEqual(result.launch.objects[4].status_flags, 0x02000005)

    def test_prefix_getfl_checks_required_bits_and_preserves_changed_flags(self):
        data = happy(None)
        data[1:1] = call('fcntl', (GATE, 3, 0), 0x01000004)
        at = next(i for i, s in enumerate(data) if s['kind'] == 2 and s['function'] == 'write')
        data[at:at] = call('fcntl', (STATUS, 3, 0), 0x02000005)
        result = paired(data)
        observations = [p.returned.raw_scalars[5] for p in result.pairs if p.entry.function == 'fcntl']
        self.assertEqual(observations, [0x01000004, 0x02000005])
        self.assertNotEqual(observations[1], result.launch.objects[4].status_flags)
        for fd, value in ((GATE, 0), (GATE, 5), (STATUS, 1), (STATUS, 4), (STATUS, 0x80000005)):
            invalid = happy(None)
            at = (1 if fd == GATE else next(i for i, s in enumerate(invalid) if s['kind'] == 2 and s['function'] == 'write'))
            invalid[at:at] = call('fcntl', (fd, 3, 0), value)
            self.refuse(invalid, 'F_GETFL access/nonblock')

    def test_prefix_fstat_success_is_exact_zero_for_both_names(self):
        for name in ('fstat', 'fstat64'):
            data = happy(None)
            data[1:1] = call(name, (GATE, 0x8000), 0)
            self.assertTrue(any(p.entry.function == name for p in paired(data).pairs))
            data[2]['args'] = (1, 1, 0, 0, 0)
            self.refuse(data, 'fstat exact-zero')

    def test_nocancel_prefix_routes_use_the_same_source_rules(self):
        data = happy()
        for item in data:
            if item['kind'] in (2, 3) and item['function'] in ('read', 'write', 'poll', 'close'):
                item['function'] += '_nocancel'
        data[2:2] = call('fcntl_nocancel', (GATE, 3, 0), 4)
        result = paired(data)
        self.assertEqual(result.attachment_return.source_route, 'gate-poll-in-flight')
        self.assertTrue(any(p.entry.function == 'fcntl_nocancel' for p in result.pairs))

    def test_impossible_short_requests_do_not_match_fixed_bio_engine(self):
        data = happy(None)
        data[1:3] = call('read', (GATE, 0x1000, 63), 63) + call('read', (GATE, 0x1000, 1), 1)
        self.refuse(data, 'exact remaining gate read')
        data = happy()
        at = next(i for i, s in enumerate(data) if s['kind'] == 2 and s['function'] == 'write')
        data[at:at + 2] = call('write', (STATUS, 0x2000, 511), 511) + call('write', (STATUS, 0x21ff, 1), 1)
        self.refuse(data, 'exact remaining EXEC_ATTEMPT')
        data = happy()
        at = next(i for i, s in enumerate(data) if s['kind'] == 2 and s['function'] == 'read' and s['args'][2] == 1)
        data[at]['args'] = (GATE, 0x1000, 64, 0, 0, 0, 0, 0)
        self.refuse(data, 'exact remaining gate read')
        data = happy()
        at = next(i for i, s in enumerate(data) if s['kind'] == 2 and s['function'] == 'close')
        data[at:at] = call('read', (GATE, 0x1000, 1), 0)
        self.refuse(data, 'exact remaining gate read')

    def test_source_defined_retries_preserve_failed_intervals_and_counts(self):
        for function, error in (('read', 4), ('read', 35), ('write', 4), ('write', 35), ('poll', 4)):
            with self.subTest(function=function, error=error):
                data = happy(None)
                at = (1 if function in ('read', 'poll') else
                      next(i for i, s in enumerate(data) if s['kind'] == 2 and s['function'] == 'write'))
                args = (GATE, 0x1000, 64) if function == 'read' else ((STATUS, 0x2000, 512) if function == 'write' else (0x7000, 1, 100))
                failed = call(function, args)
                failed[1]['args'] = (0xffffffffffffffff,) * 3 + (error, error)
                data[at:at] = failed
                result = paired(data)
                retained = next(p for p in result.pairs if p.returned.raw_scalars[-2:] == (error, error))
                self.assertEqual(retained.entry.function, function)
                self.assertEqual(retained.returned.raw_scalars[5:8], (0xffffffffffffffff,) * 3)
                self.assertFalse(result.full_trace_acceptance)
        data = happy(None)
        failed = call('poll', (0x7000, 1, 100))
        failed[1]['args'] = (0xffffffffffffffff,) * 3 + (35, 35)
        data[1:1] = failed
        self.refuse(data, 'successful return')

    def test_exec_thread_declaration_is_resolved_by_success_without_fake_pair(self):
        data = happy()
        at = next(i for i, s in enumerate(data) if s['kind'] == 2 and s['function'] == 'execve')
        data.insert(at + 1, spec(9, detail=NEW))
        result = paired(data)
        self.assertEqual(result.selected_exec.new_tid, NEW)
        data[at + 1]['detail'] = 303
        self.refuse(data, 'thread lifetime')

    def test_duplicate_old_exec_exit_is_not_retired_twice(self):
        data = happy()
        at = next(i for i, s in enumerate(data) if s['kind'] == 7)
        data.insert(at + 1, spec(11))
        self.refuse(data, 'duplicate old exec')

    def test_late_malformed_transport_overrides_semantic_refusal(self):
        data = happy()
        at = next(i for i, s in enumerate(data) if s['kind'] == 2 and s['tid'] == NEW)
        data[at:at] = call('fork', (), 0, NEW)
        physical = lines(data)
        physical[-1] = b'{malformed}\n'
        error = self.refuse(event_lines=physical)
        self.assertFalse(hasattr(error, 'capture'))

    def test_retained_bound_and_ambiguous_lifecycle_time_refuse(self):
        with patch.object(boundary, 'MAX_PHASES', 10):
            self.refuse(pattern='bound')
        physical = lines(happy())
        at = next(i for i, s in enumerate(happy()) if s['kind'] == 5)
        record = json.loads(physical[at])
        record['timestamp'] -= 1
        leading = 1
        record['records'][leading + 1]['hex'] = struct.pack('<Q', record['timestamp']).hex()
        physical[at] = json.dumps(record, separators=(',', ':')).encode() + b'\n'
        self.refuse(event_lines=physical, pattern='timestamp')

    def test_same_tid_exec_success_is_refused(self):
        data = happy()
        for s in data:
            if s['tid'] == NEW:
                s['tid'] = OLD
        self.refuse(data, 'selected exec transition')

    def test_second_or_arbitrary_attachment_return_refused(self):
        for name in ('close', 'getpid', 'mystery'):
            data = happy()
            data[1] = spec(3, name, args=(1, 1, 0, 0, 0))
            self.refuse(data, 'attachment return')
        data = happy()
        data.insert(2, spec(3, 'poll', args=(1, 1, 0, 0, 0)))
        self.refuse(data, 'arbitrary orphan')

    def test_attachment_error_and_invalid_result_do_not_become_prefix(self):
        for words in ((2, 2, 0, 0, 0), (1, 2, 0, 0, 0), (1, 1, 1, 0, 0), (0xffffffffffffffff,) * 5):
            data = happy()
            data[1]['args'] = words
            self.refuse(data)

    def test_wrong_gate_or_status_and_missing_gate_eof_refused(self):
        for function, arg0 in (('read', STATUS), ('close', 1), ('write', 1)):
            data = happy()
            at = next(i for i, s in enumerate(data) if s['kind'] == 2 and s['function'] == function)
            data[at]['args'] = (arg0,) + data[at]['args'][1:]
            self.refuse(data, 'bootstrap')
        data = happy()
        at = next(i for i, s in enumerate(data) if s['kind'] == 2 and s['function'] == 'read' and s['args'][2] == 1)
        del data[at:at + 2]
        self.refuse(data, 'close prerequisite')

    def test_failed_close_or_partial_attempt_cannot_establish_exec(self):
        for function in ('close', 'write'):
            data = happy()
            at = next(i for i, s in enumerate(data) if s['kind'] == 3 and s['function'] == function)
            data[at]['args'] = (0xffffffffffffffff, 0xffffffffffffffff, 0xffffffffffffffff, 5, 5)
            self.refuse(data, 'successful return')
        data = happy()
        at = next(i for i, s in enumerate(data) if s['kind'] == 3 and s['function'] == 'write')
        data[at]['args'] = (511, 511, 0, 0, 0)
        self.refuse(data, 'complete status')

    def test_exec_start_sequence_and_later_exec_strict(self):
        for kind in (5, 10):
            data = [s for s in happy() if s['kind'] != kind]
            self.refuse(data, 'must precede')
        data = happy()
        at = next(i for i, s in enumerate(data) if s['kind'] == 2 and s['tid'] == NEW)
        data[at:at] = [spec(2, 'execve', NEW, args=(1, 2, 3, 0, 0, 0, 0, 0))]
        self.refuse(data, 'later/duplicate exec')
        data = happy()
        at = next(i for i, s in enumerate(data) if s['kind'] == 7)
        data.insert(at, spec(8, detail=2))
        self.refuse(data, 'exec-failure')

    def test_creation_rights_and_mach_fail_after_full_transport(self):
        for entry in ('fork', 'vfork', 'posix_spawn', '__mac_execve', 'sendmsg', 'recvmsg', 'fileport_makefd'):
            data = happy()
            at = next(i for i, s in enumerate(data) if s['kind'] == 2 and s['tid'] == NEW)
            data[at:at] = call(entry, (), 0, NEW)
            error = self.refuse(data, 'unsupported syscall')
            self.assertEqual(error.capture.raw.events, len(data))
        for inserted in ([spec(4, detail=8888)], [spec(12)], [spec(13, detail=2)],
                         [spec(15, tid=NEW, args=(0,) * 8), spec(16, tid=NEW, args=(0,))]):
            data = happy()
            at = next(i for i, s in enumerate(data) if s['kind'] == 2 and s['tid'] == NEW)
            data[at:at] = inserted
            error = self.refuse(data)
            self.assertEqual(error.capture.raw.events, len(data))

    def test_unknown_runtime_call_retained_without_no_write_claim(self):
        data = happy()
        at = next(i for i, s in enumerate(data) if s['kind'] == 2 and s['tid'] == NEW)
        data[at:at] = call('mystery', (1, 2, 3), 0, NEW)
        pair = next(p for p in paired(data).pairs if p.entry.function == 'mystery')
        self.assertFalse(pair.entry.source_contract_known)
        self.assertEqual(pair.entry.unsupported_reason, 'no pinned BSD source contract')

    def test_declared_runtime_thread_pair_and_retirement(self):
        data = happy()
        at = next(i for i, s in enumerate(data) if s['kind'] == 2 and s['tid'] == NEW)
        data[at:at] = [spec(9, tid=NEW, detail=303), spec(10, tid=303)] + call('write', (2, 99, 1), 1, 303) + [spec(11, tid=303)]
        result = paired(data)
        self.assertTrue(any(p.entry.raw_scalars[3] == 303 for p in result.pairs))
        data = [s for s in data if not (s['kind'] == 11 and s['tid'] == 303)]
        self.refuse(data, 'thread lifetime')

    def test_unknown_thread_old_tid_reuse_and_unpaired_exit_refused(self):
        data = happy()
        at = next(i for i, s in enumerate(data) if s['kind'] == 2 and s['tid'] == NEW)
        data[at]['tid'] = 303
        self.refuse(data, 'inactive/undeclared')
        data = happy()
        at = next(i for i, s in enumerate(data) if s['kind'] == 2 and s['tid'] == NEW)
        data[at:at] = [spec(9, tid=NEW, detail=OLD)]
        self.refuse(data, 'declaration/reuse')
        data = happy()
        at = next(i for i, s in enumerate(data) if s['kind'] == 2 and s['function'] == 'exit')
        data[at]['function'] = 'read'
        self.refuse(data, 'unresolved call')

    def test_late_transport_failure_has_no_capture_or_successful_prefix(self):
        physical = lines(happy())
        for suffix in (b'{}\n', physical[-1]):
            self.refuse(event_lines=physical + [suffix])
        self.refuse(event_lines=physical[:-1], pattern='incomplete')
        self.refuse(errors=b'{"drop":1}\n', pattern='nonempty errors')
        malformed = physical.copy()
        malformed[-1] = malformed[-1].replace(b'"cpu":0', b'"cpu":false')
        error = self.refuse(event_lines=malformed)
        self.assertFalse(hasattr(error, 'capture'))

    def test_generator_consumed_once_and_late_iterator_failure_propagates(self):
        class Once:
            calls = 0
            def __iter__(self):
                self.calls += 1
                if self.calls != 1:
                    raise AssertionError('second consumption')
                yield from lines(happy())
        source = Once()
        self.assertEqual(paired(event_lines=source).source.raw.events, len(happy()))
        self.assertEqual(source.calls, 1)
        def bad():
            yield from lines(happy())
            raise RuntimeError('late source fault')
        with self.assertRaisesRegex(RuntimeError, 'late source fault'):
            paired(event_lines=bad())

    def test_legacy_and_runtime_programs_refuse_each_other(self):
        self.refuse(program=boundary._RAW._expected_program(TARGET), pattern='fixed runtime')
        with self.assertRaisesRegex(boundary.RawValidationError, 'fixed program'):
            boundary._RAW.validate_raw(boundary.expected_program(TARGET), INVENTORY, b'',
                                        lines(happy()), owner_pid=OWNER, target_pid=TARGET)
        with self.assertRaisesRegex(boundary.RawValidationError, 'first target|exec transition|orphan'):
            boundary._RAW.pair_raw_owned(boundary._RAW._expected_program(TARGET), INVENTORY, b'',
                lines(happy()), owner_pid=OWNER, target_pid=TARGET, contract_bytes=CONTRACT)

    def test_launch_byte_binding_and_closed_profile(self):
        evidence = launch()
        result = boundary.validate_launch_evidence(evidence, owner_pid=OWNER, target_pid=TARGET)
        self.assertEqual(result.request_sha256, hashlib.sha256(evidence.request).hexdigest())
        self.assertEqual(result.target_sha256, hashlib.sha256(TARGET_BYTES).hexdigest())
        self.assertEqual(result.kept_fds, (0, 1, 2, GATE, STATUS))
        self.assertFalse(result.output_objects_matched or result.protected_target_admitted)
        for name in ('request', 'catalog', 'ready', 'go', 'exec_attempt', 'target_artifact'):
            value = getattr(evidence, name)
            changed = value[:-1] + bytes((value[-1] ^ 1,))
            self.refuse(launch_evidence=replace(evidence, **{name: changed}))
        self.refuse(owner_pid=OWNER + 1, pattern='bound')
        self.refuse(target_pid=TARGET + 1, pattern='bound')

    def test_each_wire_reserved_region_and_legacy_envelopes_refuse(self):
        evidence = launch()
        for name, indexes in (('request', (184, 207)), ('catalog', (188, 191)),
                              ('ready', (24, 31, 32 + 232, 511)), ('go', (52, 63)),
                              ('exec_attempt', (288, 487, 511))):
            for index in indexes:
                changed = bytearray(getattr(evidence, name))
                changed[index] = 1
                self.refuse(launch_evidence=replace(evidence, **{name: bytes(changed)}))
        self.refuse(launch_evidence=replace(evidence, ready=evidence.ready[32:288]))
        self.refuse(launch_evidence=replace(evidence, go=b'GLUEGO01' + evidence.go[8:]))

    def test_all_status_prefix_lengths_and_late_fifth_row(self):
        evidence = launch()
        for size in range(512):
            with self.subTest(size=size):
                self.refuse(launch_evidence=replace(evidence, ready=evidence.ready[:size]))
        changed = bytearray(evidence.ready)
        put(changed, 288 + 4 * 40, 4, STATUS + 1)
        self.refuse(launch_evidence=replace(evidence, ready=bytes(changed)), pattern='row')

    def test_source_contract_bytes_and_no_asset_io_after_import(self):
        self.refuse(contract_bytes=CONTRACT[:-1], pattern='contract bytes')
        self.refuse(contract_bytes=CONTRACT[:-1] + b'x', pattern='digest')
        with patch('builtins.open', side_effect=AssertionError('unexpected file IO')), \
             patch.object(Path, 'open', side_effect=AssertionError('unexpected asset IO')):
            self.assertEqual(paired().selected_exec.new_tid, NEW)

    def test_frozen_results_and_fresh_serialization(self):
        result = paired()
        with self.assertRaises(FrozenInstanceError):
            result.full_trace_acceptance = True
        with self.assertRaises(FrozenInstanceError):
            result.source.phases[0].ordinal = 99
        serial = result.to_dict()
        serial['source']['phases'].clear()
        serial['launch']['objects'][0]['fd'] = 999
        self.assertEqual(len(result.to_dict()['source']['phases']), len(happy()))
        self.assertEqual(result.launch.objects[0].fd, 0)

    def test_independent_launch_vectors_pass_existing_c_decoders(self):
        compiler = shutil.which('cc')
        self.assertIsNotNone(compiler)
        with tempfile.TemporaryDirectory(prefix='glue-runtime-launch-wire-') as temp:
            binary = Path(temp) / 'launch-wire'
            sources = [HERE / 'test_runtime_launch_wire.c',
                       BASE / 'bootstrap-request/bootstrap_request.c',
                       BASE / 'bootstrap-wire/bootstrap_wire.c',
                       BASE / 'bootstrap-object-wire/bootstrap_object_wire.c',
                       BASE / 'target-credentials/target_credentials.c']
            subprocess.run([compiler, '-std=c11', '-Wall', '-Wextra', '-Werror', '-pedantic',
                            *map(str, sources), '-o', str(binary)], check=True)
            evidence = launch()
            def run(e):
                wire = len(e.request).to_bytes(4, 'big') + e.request + e.ready + e.go + e.exec_attempt
                return subprocess.run([str(binary)], input=wire).returncode
            self.assertEqual(run(evidence), 0)
            for name, at in (('request', 184), ('ready', 511), ('go', 63), ('exec_attempt', 487)):
                value = bytearray(getattr(evidence, name))
                value[at] = 1
                self.assertNotEqual(run(replace(evidence, **{name: bytes(value)})), 0)

    def test_actual_c_producer_matches_independent_reader_template(self):
        compiler = shutil.which('cc')
        self.assertIsNotNone(compiler)
        with tempfile.TemporaryDirectory(prefix='glue-runtime-program-') as temp:
            source, binary = Path(temp) / 'producer.c', Path(temp) / 'producer'
            source.write_text('#include "runtime_trace_program.h"\n#include <stdio.h>\n#include <stdlib.h>\nint main(int n,char **v){char out[RT_PROGRAM_CAPACITY];size_t used;if(n!=2||rt_program((uint32_t)strtoul(v[1],NULL,10),out,&used))return 1;return fwrite(out,1,used,stdout)==used?0:2;}\n')
            subprocess.run([compiler, '-std=c11', '-Wall', '-Wextra', '-Werror', '-pedantic',
                            '-I', str(HERE), str(source), str(HERE / 'runtime_trace_program.c'), '-o', str(binary)], check=True)
            for pid in (1, TARGET, (1 << 31) - 1):
                actual = subprocess.run([str(binary), str(pid)], check=True, stdout=subprocess.PIPE).stdout
                self.assertEqual(actual, boundary.expected_program(pid))
            for pid in (0, 1 << 31):
                self.assertNotEqual(subprocess.run([str(binary), str(pid)], stdout=subprocess.PIPE).returncode, 0)


if __name__ == '__main__':
    unittest.main()
