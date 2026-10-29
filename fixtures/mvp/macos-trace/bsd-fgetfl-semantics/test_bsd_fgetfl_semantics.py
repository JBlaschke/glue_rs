"""Independent physical-byte controls; no producer or sibling test imports."""
import copy
from dataclasses import FrozenInstanceError
import io
import json
from pathlib import Path
import struct
import subprocess
import unittest
from unittest.mock import patch
import urllib.request

import bsd_fgetfl_semantics as B

OWNER, TARGET, TID = 3131, 4242, 700
U64 = (1 << 64) - 1
CONTRACT = (Path(__file__).parent.parent / 'syscall-contract/contracts.json').read_bytes()
# Exact immutable transport program literal reused as source bytes, without
# importing or invoking its producer, validator or the earlier control suite.
PROGRAM = b'#pragma D option quiet\nBEGIN { watched[4242]=1;trace((uint64_t)1);trace((uint64_t)timestamp);trace((uint64_t)pid);trace((uint64_t)tid);trace((uint64_t)(0));}\nEND {trace((uint64_t)17);trace((uint64_t)timestamp);trace((uint64_t)pid);trace((uint64_t)tid);trace((uint64_t)(0));}\nsyscall:::entry /watched[pid]/ {trace((uint64_t)2);trace((uint64_t)timestamp);trace((uint64_t)pid);trace((uint64_t)tid);trace((uint64_t)(ppid));trace((uint64_t)arg0);trace((uint64_t)arg1);trace((uint64_t)arg2);trace((uint64_t)arg3);trace((uint64_t)arg4);trace((uint64_t)arg5);trace((uint64_t)arg6);trace((uint64_t)arg7);}\nsyscall:::return /watched[pid]/ {trace((uint64_t)3);trace((uint64_t)timestamp);trace((uint64_t)pid);trace((uint64_t)tid);trace((uint64_t)(ppid));trace((uint64_t)arg0);trace((uint64_t)arg1);trace((uint64_t)arg2);trace((uint64_t)arg3);trace((uint64_t)errno);}\nmach_trap:::entry /watched[pid]/ {trace((uint64_t)15);trace((uint64_t)timestamp);trace((uint64_t)pid);trace((uint64_t)tid);trace((uint64_t)(ppid));trace((uint64_t)arg0);trace((uint64_t)arg1);trace((uint64_t)arg2);trace((uint64_t)arg3);trace((uint64_t)arg4);trace((uint64_t)arg5);trace((uint64_t)arg6);trace((uint64_t)arg7);}\nmach_trap:::return /watched[pid]/ {trace((uint64_t)16);trace((uint64_t)timestamp);trace((uint64_t)pid);trace((uint64_t)tid);trace((uint64_t)(ppid));trace((uint64_t)arg0);}\nproc:::create /watched[pid]/ {watched[pid]=1;trace((uint64_t)4);trace((uint64_t)timestamp);trace((uint64_t)pid);trace((uint64_t)tid);trace((uint64_t)(args[0]->pr_pid));}\nproc:::start /watched[pid]/ {watched[pid]=1;trace((uint64_t)5);trace((uint64_t)timestamp);trace((uint64_t)pid);trace((uint64_t)tid);trace((uint64_t)(ppid));}\nproc:::exec-success /watched[pid]/ {watched[pid]=1;trace((uint64_t)7);trace((uint64_t)timestamp);trace((uint64_t)pid);trace((uint64_t)tid);trace((uint64_t)(ppid));}\nproc:::exit /watched[pid]/ {trace((uint64_t)6);trace((uint64_t)timestamp);trace((uint64_t)pid);trace((uint64_t)tid);trace((uint64_t)(arg0));}\nproc:::exec-failure /watched[pid]/ {trace((uint64_t)8);trace((uint64_t)timestamp);trace((uint64_t)pid);trace((uint64_t)tid);trace((uint64_t)(arg0));}\nproc:::lwp-create /watched[pid]/ {trace((uint64_t)9);trace((uint64_t)timestamp);trace((uint64_t)pid);trace((uint64_t)tid);trace((uint64_t)(args[0]->pr_lwpid));}\nproc:::lwp-start /watched[pid]/ {trace((uint64_t)10);trace((uint64_t)timestamp);trace((uint64_t)pid);trace((uint64_t)tid);trace((uint64_t)(0));}\nproc:::lwp-exit /watched[pid]/ {trace((uint64_t)11);trace((uint64_t)timestamp);trace((uint64_t)pid);trace((uint64_t)tid);trace((uint64_t)(0));}\nproc:::spawn-success /watched[pid]/ {trace((uint64_t)12);trace((uint64_t)timestamp);trace((uint64_t)pid);trace((uint64_t)tid);trace((uint64_t)(0));}\nproc:::spawn-failure /watched[pid]/ {trace((uint64_t)13);trace((uint64_t)timestamp);trace((uint64_t)pid);trace((uint64_t)tid);trace((uint64_t)(arg0));}\nproc:::exited /watched[args[0]->pr_pid]/ {trace((uint64_t)18);trace((uint64_t)timestamp);trace((uint64_t)pid);trace((uint64_t)tid);trace((uint64_t)(args[0]->pr_pid));trace((uint64_t)arg1);trace((uint64_t)args[0]->pr_addr);trace((uint64_t)((struct proc *)args[0]->pr_addr)->p_refcount);}\n'

# kind: physical total bytes, leading zero-sized assignment, probe identity
SHAPES = {
    1: (56, True, ('dtrace', '', '', 'BEGIN')),
    17: (56, False, ('dtrace', '', '', 'END')),
    2: (120, False, ('syscall', '', 'fcntl', 'entry')),
    3: (96, False, ('syscall', '', 'fcntl', 'return')),
    15: (120, False, ('mach_trap', '', 'mach_msg2_trap', 'entry')),
    16: (64, False, ('mach_trap', '', 'mach_msg2_trap', 'return')),
    11: (56, False, ('proc', '', '', 'lwp-exit')),
    18: (80, False, ('proc', '', '', 'exited')),
}
# Full static inventory has every required provider/lifecycle probe, regardless
# of whether this particular synthetic original-byte stream uses that probe.
INVENTORY = (
    ('dtrace', '', '', 'BEGIN'), ('dtrace', '', '', 'END'),
    ('syscall', '', 'fcntl', 'entry'), ('syscall', '', 'fcntl', 'return'),
    ('mach_trap', '', 'mach_msg2_trap', 'entry'), ('mach_trap', '', 'mach_msg2_trap', 'return'),
    ('proc', 'mach_kernel', '', 'create'), ('proc', '', '', 'start'),
    ('proc', '', '', 'exit'), ('proc', '', '', 'exec-success'),
    ('proc', '', '', 'exec-failure'), ('proc', '', '', 'lwp-create'),
    ('proc', '', '', 'lwp-start'), ('proc', '', '', 'lwp-exit'),
    ('proc', '', '', 'spawn-success'), ('proc', '', '', 'spawn-failure'),
    ('proc', '', '', 'exited'),
)


def physical(kind, words=(), *, name=None, tid=TID):
    total, assignment, identity = SHAPES[kind]
    actor = OWNER if kind in (1, 17) else TARGET
    detail = OWNER if kind in (2, 3, 15, 16) else TARGET if kind == 18 else 0
    values = (kind, 0, actor, tid, detail) + tuple(words)
    if kind == 18:
        values += (U64, 0x1234567890, 0x1c2)
    if kind in (1, 17, 11):
        assert words == ()
    assert len(values) * 8 + 16 == total
    if name is not None:
        identity = identity[:2] + (name, identity[3])
    records = ([dict(action=1, size=0, offset=12, hex='')] if assignment else [])
    for index, value in enumerate(values):
        records.append(dict(action=1, size=8, offset=16 + 8 * index,
                            hex=struct.pack('<Q', value).hex()))
    return dict(event=0, cpu=3, epid=0, probe_id=0, record_bytes=total,
        header_record_indexes=list(range(int(assignment), int(assignment) + 5)),
        kind=kind, timestamp=0, pid=actor, tid=tid, detail=detail,
        **dict(zip(('provider', 'module', 'function', 'name'), identity)), records=records)


def call(*, name='fcntl', fd=7, command=3, argument=0, primary=0, secondary=0,
         error=0, tail=(0, 0, 0, 0, 0), returned=None):
    entry = physical(2, (fd, command, argument) + tuple(tail), name=name)
    result = ((primary, primary, secondary, error, error) if returned is None else returned)
    return [entry, physical(3, result, name=name)]


def original_bytes(body=None):
    rows = [physical(1), *(call() if body is None else body), physical(11), physical(18), physical(17)]
    return encode(rows)


def encode(rows):
    rows = copy.deepcopy(rows)
    identities = {identity: index for index, identity in enumerate(INVENTORY, 100)}
    for index, row in enumerate(rows, 1):
        names = tuple(row[key] for key in ('provider', 'module', 'function', 'name'))
        if names not in identities:
            identities[names] = max(identities.values()) + 1
        row.update(event=index, timestamp=index * 11, probe_id=identities[names],
                   epid=1000 + identities[names])
        # Replace the physical timestamp payload, not just normalized metadata.
        row['records'][int(SHAPES[row['kind']][1]) + 1]['hex'] = struct.pack('<Q', index * 11).hex()
    probes = b''.join((str(number) + '\t' + '\t'.join(names) + '\n').encode('ascii')
                      for names, number in identities.items())
    lines = tuple(json.dumps(row, separators=(',', ':')).encode('ascii') + b'\n' for row in rows)
    return probes, lines


def decode(body=None, **kwargs):
    probes, lines = original_bytes(body)
    return B.decode_owned_fgetfl_semantics(kwargs.pop('program', PROGRAM),
        kwargs.pop('probes', probes), kwargs.pop('errors', b''), kwargs.pop('event_lines', lines),
        owner_pid=kwargs.pop('owner_pid', OWNER), target_pid=kwargs.pop('target_pid', TARGET),
        contract_bytes=kwargs.pop('contract_bytes', CONTRACT), **kwargs)


def row(**kwargs):
    return decode(call(**kwargs)).operations[0]


class FgetflControls(unittest.TestCase):
    def test_twenty_one_literal_source_constructions_through_both_names(self):
        # Literal source flags/result pairs independently encode expected OFLAGS.
        golden = (
            (1, 0), (2, 1), (3, 2), (5, 4), (6, 5), (7, 6),
            (9, 8), (10, 9), (11, 10), (13, 12), (14, 13), (15, 14),
            (0x10002, 0x10001), (0x10003, 0x10002),
            (0x10006, 0x10005), (0x10007, 0x10006),
            (0x1000a, 0x10009), (0x1000b, 0x1000a),
            (0x1000e, 0x1000d), (0x1000f, 0x1000e), (0x40000000, 0x40000000),
        )
        for name in ('fcntl', 'fcntl_nocancel'):
            for flags, result in golden:
                with self.subTest(name=name, flags=flags):
                    item = row(name=name, primary=result)
                    self.assertEqual(item.status, 'conditional-conversion')
                    self.assertEqual((item.request.command_name, item.request.operation),
                                     ('F_GETFL', 'query-status-flags'))
                    self.assertEqual(item.observation.primary_uint32, result)
                    feasible = [p.fileglob_flags_uint32 for p in item.observation.algebraic_preimages
                                if p.source_feasibility == 'some-source-feasible-ordinary-subset']
                    self.assertEqual(feasible, [flags])
                    self.assertEqual(item.rule.kind, 'observe-conditional-OFLAGS-conversion')
                    self.assertIn('actual-state-unproved', item.observation.feasibility)

    def test_fexec_uses_mask_branch_and_retains_all_four_access_preimages(self):
        item = row(primary=0x40000000)
        preimages = item.observation.algebraic_preimages
        self.assertEqual([p.fileglob_flags_uint32 for p in preimages],
                         [0x40000000, 0x40000001, 0x40000002, 0x40000003])
        self.assertEqual([p.source_feasibility for p in preimages],
                         ['some-source-feasible-ordinary-subset'] + ['reachability-unproved'] * 3)
        self.assertEqual(item.observation.actual_fileglob_flags, 'unobserved')
        for invalid in (0x40000001, 0x40000002, 0x40000003, 0x3fffffff):
            item = row(primary=invalid)
            self.assertEqual((item.status, item.observation.algebraic_preimages),
                             ('unresolved-conversion', ()))
            self.assertIn('no-algebraic-preimage', item.unsupported_reasons)

    def test_event_only_both_policy_branches_and_local_fread_are_unresolved(self):
        item = row(primary=0x8000)
        self.assertEqual(item.status, 'unresolved-conversion')
        self.assertIsNone(item.rule)
        self.assertEqual([(p.fileglob_flags_uint32, p.adjusted_flags_uint32, p.policy_condition)
                          for p in item.observation.algebraic_preimages], [
            (0x8001, 0x8001, 'event-only; process-disallow-rw-clear'),
            (0x8001, 0x8001, 'event-only; process-disallow-rw-set'),
            (0x8000, 0x8001, 'event-only; process-disallow-rw-set'),
        ])
        self.assertEqual(item.observation.event_only_process_policy, 'unobserved; no branch selected')
        self.assertTrue(all(p.source_feasibility == 'reachability-unproved'
                            for p in item.observation.algebraic_preimages))
        # The process can change policy after open: an event-only zero-access
        # flag under the clear policy borrows across low bits on unsigned -1.
        item = row(primary=0x7fff)
        self.assertEqual([(p.fileglob_flags_uint32, p.policy_condition)
                          for p in item.observation.algebraic_preimages],
                         [(0x8000, 'event-only; process-disallow-rw-clear')])

    def test_fexec_event_only_keeps_all_policy_and_access_alternatives(self):
        item = row(primary=0x40008000)
        actual = {(p.fileglob_flags_uint32, p.adjusted_flags_uint32, p.policy_condition)
                  for p in item.observation.algebraic_preimages}
        expected = {(0x40008000 + access, 0x40008000 + access,
                     'event-only; process-disallow-rw-clear') for access in range(4)}
        expected |= {(raw, adjusted, 'event-only; process-disallow-rw-set')
                     for raw, adjusted in ((0x40008000, 0x40008001),
                                           (0x40008001, 0x40008001),
                                           (0x40008002, 0x40008003),
                                           (0x40008003, 0x40008003))}
        self.assertEqual((actual, len(item.observation.algebraic_preimages)), (expected, 8))
        self.assertEqual(item.status, 'unresolved-conversion')

    def test_private_flags_remain_visible_beyond_fmask_without_permission(self):
        vectors = ((0x10000, 'FWASWRITTEN'), (0x1000, 'FMARK'), (0x2000, 'FDEFER'),
                   (0x4000, 'FWASLOCKED'), (0x20000, 'O_NOCTTY-private-F_NOCACHE_EXT'),
                   (0x40000, 'FNOCACHE'), (0x80000, 'FNORDAHEAD'),
                   (0x800000, 'FNODIRECT'), (0x2000000, 'FENCRYPTED'),
                   (0x4000000, 'FSINGLE_WRITER'), (0x10000000, 'FUNENCRYPTED'))
        for flag, name in vectors:
            with self.subTest(flag=flag):
                item = row(primary=flag)
                self.assertEqual(item.status, 'unresolved-conversion')
                self.assertIsNone(item.rule)
                candidate = item.observation.algebraic_preimages[0]
                self.assertEqual(candidate.fileglob_flags_uint32, flag + 1)
                self.assertIn(name, candidate.named_flags)
                self.assertEqual(candidate.unknown_bits_uint32, 0)
        # Actual writable FWASWRITTEN subset has a separate supported rule.
        item = row(primary=0x10001)
        self.assertEqual(item.status, 'conditional-conversion')
        self.assertEqual(item.observation.algebraic_preimages[0].fileglob_flags_uint32, 0x10002)

    def test_unknown_bits_and_unsigned_wrap_are_not_repaired(self):
        for physical_word, signed, uint32, flags, unknown in (
            (U64, -1, 0xffffffff, 0, 0),
            (U64 - 0x7fffffff, -0x80000000, 0x80000000, 0x80000001, 0x80000000),
            (0x7fffffff, 0x7fffffff, 0x7fffffff, 0x80000000, 0x80000000),
            (0x200, 0x200, 0x200, 0x201, 0x200),
        ):
            with self.subTest(physical_word=physical_word):
                report = decode(call(primary=physical_word))
                item = report.operations[0]
                self.assertEqual((item.outcome.disposition, item.outcome.primary_result),
                                 ('kernel-success', signed))
                self.assertEqual((item.status, item.observation.primary_signed32,
                                  item.observation.primary_uint32),
                                 ('unresolved-conversion', signed, uint32))
                self.assertEqual((item.observation.algebraic_preimages[0].fileglob_flags_uint32,
                                  item.observation.algebraic_preimages[0].unknown_bits_uint32),
                                 (flags, unknown))
                self.assertEqual(report.source.pairs[0].returned.raw_scalars[5], physical_word)

    def test_split_sync_header_values_are_unbound_without_source_bytes(self):
        # Numeric bits are retained without importing host SDK constants into
        # the fixed source model or silently calling every bit a known status.
        for bits in (0x80, 0x400000):
            item = row(primary=bits)
            self.assertEqual(item.status, 'unresolved-conversion')
            candidate = item.observation.algebraic_preimages[0]
            self.assertEqual(candidate.unknown_bits_uint32, bits)
            self.assertEqual(candidate.fileglob_flags_uint32, bits + 1)

    def test_noncanonical_result_words_do_not_acquire_uint32_bit_views(self):
        for physical_word in (0x80000000, 0xffffffff, 1 << 32, 1 << 63):
            item = row(primary=physical_word)
            self.assertEqual(item.status, 'unsupported')
            self.assertIsNone(item.observation)
            self.assertIsNone(item.rule)
            self.assertIn('canonically sign-extended signed32', ' '.join(item.unsupported_reasons))

    def test_initialized_secondary_and_nonnegative_fd_are_necessary(self):
        for args in (dict(secondary=1), dict(secondary=U64), dict(fd=U64)):
            item = row(**args)
            self.assertEqual(item.status, 'unresolved-conversion')
            self.assertIsNone(item.rule)
            self.assertEqual(item.observation.primary_uint32, 0)
        self.assertIn('secondary', ' '.join(row(secondary=1).unsupported_reasons))
        self.assertIn('nonnegative descriptor', ' '.join(row(fd=U64).unsupported_reasons))

    def test_ignored_signed64_argument_and_all_tail_words_stay_original(self):
        tail = (U64, 1 << 63, 0x123456789abcdef0, 17, 0x80000000)
        for bits, signed in ((0, 0), (U64, -1), (1 << 63, -(1 << 63)),
                             (0x123456789abcdef0, 0x123456789abcdef0)):
            report = decode(call(argument=bits, tail=tail))
            item = report.operations[0]
            self.assertEqual((item.status, item.request.argument, item.request.argument_role),
                             ('conditional-conversion', signed, 'ignored-by-command'))
            self.assertEqual(report.source.pairs[0].entry.raw_scalars[5:], (7, 3, bits) + tail)

    def test_noncanonical_fd_and_command_bits_stay_attempts_without_repair(self):
        item = row(fd=0xffffffff)
        self.assertEqual(item.status, 'unsupported')
        self.assertEqual(item.request.attempt_kind, 'descriptor-status-flag-query-attempt')
        self.assertIsNone(item.request.fd)
        item = row(command=(1 << 32) + 3)
        self.assertEqual(item.status, 'unsupported')
        self.assertIsNone(item.request.operation)
        self.assertEqual(item.request.attempt_kind, 'unmodeled-fcntl-command')

    def test_kernel_errors_and_control_flow_retain_original_outcomes(self):
        for name in ('fcntl', 'fcntl_nocancel'):
            item = row(name=name, fd=U64, argument=U64, primary=U64, secondary=U64, error=9)
            self.assertEqual((item.status, item.outcome.kernel_error, item.request.argument),
                             ('kernel-error', 9, -1))
            self.assertIsNone(item.observation)
            self.assertIsNone(item.rule)
            self.assertIn('not an absence-of-effects', ' '.join(item.effect_uncertainties))
        for error, primary in ((U64, U64), (U64 - 1, 0)):
            item = row(primary=primary, secondary=primary, error=error)
            self.assertEqual(item.status, 'unsupported')
            self.assertIsNone(item.rule)

    def test_four_scalar_rows_keep_exact_legacy_types_and_serialization(self):
        for name in ('fcntl', 'fcntl_nocancel'):
            for command, argument, primary in ((0, 3, 11), (1, U64, 1), (2, U64, 0), (67, 3, 11)):
                probes, lines = original_bytes(call(name=name, command=command, argument=argument, primary=primary))
                old = B._SCALAR.decode_owned_fcntl_semantics(PROGRAM, probes, b'', lines,
                    owner_pid=OWNER, target_pid=TARGET, contract_bytes=CONTRACT)
                new = B.decode_owned_fgetfl_semantics(PROGRAM, probes, b'', lines,
                    owner_pid=OWNER, target_pid=TARGET, contract_bytes=CONTRACT)
                self.assertIs(type(new.operations[0]), type(old.operations[0]))
                self.assertEqual(new.operations, old.operations)
                self.assertEqual(new.source, old.source)
                self.assertEqual(new.counts.legacy_source_consistent_successes, 1)
        self.assertEqual(row(command=1, primary=1).status, 'source-consistent')

    def test_setfl_unknown_and_non_fcntl_rows_stay_legacy_unsupported(self):
        for command in (4, 5, 6, 999):
            item = row(command=command)
            self.assertEqual(item.status, 'unsupported')
            self.assertIsNone(item.rule)
            self.assertIn('no harmless-operation permission', ' '.join(item.effect_uncertainties))
        item = row(command=4, primary=U64, secondary=U64, error=5)
        self.assertIn('driver ioctl failure or partial rollback', ' '.join(item.effect_uncertainties))
        for name in ('read', 'future_unknown_syscall'):
            item = row(name=name)
            self.assertEqual((item.status, item.request.is_fcntl), ('unsupported', False))

    def test_every_bsd_call_and_mach_lifecycle_phase_remains_retained(self):
        body = [physical(15, (9, 8, 7, 6, 5, 4, 3, 2)), physical(16, (0x1234,))]
        for name in ('fcntl', 'fcntl_nocancel', 'read', 'future_unknown_syscall'):
            body += call(name=name)
        report = decode(body)
        self.assertEqual((report.counts.bsd_pairs, report.counts.fgetfl_pairs,
                          report.counts.conditional_conversions, report.counts.unsupported,
                          report.counts.uninterpreted_mach_pairs), (4, 2, 2, 2, 1))
        self.assertEqual([item.source_pair_index for item in report.operations], [1, 2, 3, 4])
        self.assertEqual(report.source.pairs[0].entry.raw_scalars[5:], (9, 8, 7, 6, 5, 4, 3, 2))
        self.assertEqual([event.raw_scalars[0] for event in report.source.lifecycle], [1, 11, 18, 17])
        for item in report.operations:
            self.assertEqual(item.correlation_id, report.source.pairs[item.source_pair_index].correlation_id)

    def test_single_raw_pass_private_decoder_only_and_single_stream_consumption(self):
        probes, lines = original_bytes(call())
        class Once:
            count = 0
            def __iter__(self):
                self.count += 1
                if self.count != 1:
                    raise AssertionError('original stream consumed again')
                return iter(lines)
        stream = Once()
        with patch.object(B._SCALAR._RAW, 'pair_raw_owned', wraps=B._SCALAR._RAW.pair_raw_owned) as pairing, \
             patch.object(B._SCALAR, 'decode_owned_fcntl_semantics', side_effect=AssertionError('public scalar API')), \
             patch.object(B._SCALAR._ENTRY, 'decode_owned_bsd_entries', side_effect=AssertionError('public ABI API')), \
             patch.object(B._SCALAR._OUTCOME, 'decode_owned_bsd_outcomes', side_effect=AssertionError('public outcome API')):
            report = B.decode_owned_fgetfl_semantics(PROGRAM, probes, b'', stream,
                owner_pid=OWNER, target_pid=TARGET, contract_bytes=CONTRACT)
        self.assertEqual((pairing.call_count, stream.count, report.counts.conditional_conversions), (1, 1, 1))

    def test_static_refusal_precedes_original_stream_consumption(self):
        def forbidden():
            raise AssertionError('consumed before static refusal')
            yield b''
        for kwargs in (dict(program=PROGRAM + b' '), dict(contract_bytes=CONTRACT + b' '), dict(errors=b'ERROR')):
            with self.assertRaises(B.RawValidationError):
                decode(event_lines=forbidden(), **kwargs)

    def test_late_transport_refusal_precedes_any_semantic_prefix(self):
        probes, lines = original_bytes(call())
        with patch.object(B, '_decode_operation', side_effect=AssertionError('semantic prefix')):
            for altered in (lines + (b'{broken\n',), lines[:-1], lines[:2] + lines[3:]):
                with self.assertRaises(B.RawValidationError):
                    B.decode_owned_fgetfl_semantics(PROGRAM, probes, b'', altered,
                        owner_pid=OWNER, target_pid=TARGET, contract_bytes=CONTRACT)
        # Original metadata and physical scalar disagreement must refuse.
        bad = json.loads(lines[1])
        bad['records'][0]['hex'] = struct.pack('<Q', 3).hex()
        with self.assertRaises(B.RawValidationError):
            decode(event_lines=lines[:1] + (json.dumps(bad).encode(),) + lines[2:])

    def test_iterator_failure_before_semantics_cannot_return_a_prefix(self):
        probes, lines = original_bytes(call())
        def broken():
            yield from lines[:-1]
            raise RuntimeError('injected original-byte iterator fault')
        with patch.object(B, '_decode_operation', side_effect=AssertionError('semantic prefix')):
            with self.assertRaisesRegex(RuntimeError, 'iterator fault'):
                B.decode_owned_fgetfl_semantics(PROGRAM, probes, b'', broken(),
                    owner_pid=OWNER, target_pid=TARGET, contract_bytes=CONTRACT)

    def test_caller_capture_constants_policy_authority_are_not_api_inputs(self):
        for name, value in (('source', {}), ('capture', {}), ('pairs', ()),
                            ('F_GETFL', 3), ('FMASK', 15), ('process_policy', False),
                            ('disallow_rw', True), ('native_abi_calibrated', True)):
            with self.assertRaises(TypeError):
                decode(**{name: value})
        with self.assertRaises(B.RawValidationError):
            decode(event_lines=[{}])

    def test_no_files_processes_or_network_access_after_import(self):
        probes, lines = original_bytes(call())
        with patch('builtins.open', side_effect=AssertionError('file open')), \
             patch.object(Path, 'open', side_effect=AssertionError('path open')), \
             patch.object(subprocess, 'run', side_effect=AssertionError('subprocess')), \
             patch.object(subprocess, 'Popen', side_effect=AssertionError('subprocess')), \
             patch.object(urllib.request, 'urlopen', side_effect=AssertionError('network')):
            report = B.decode_owned_fgetfl_semantics(PROGRAM, probes, b'', lines,
                owner_pid=OWNER, target_pid=TARGET, contract_bytes=CONTRACT)
        self.assertEqual(report.counts.conditional_conversions, 1)

    def test_each_fixed_dependency_is_checked_before_any_helper_executes(self):
        original_open = Path.open
        for relative, _ in B.DEPENDENCY_IDENTITIES:
            spec = B.importlib.util.spec_from_file_location('_fgetfl_identity_control', B.__file__)
            fresh = B.importlib.util.module_from_spec(spec)
            def corrupted(path, *args, **kwargs):
                if str(path).endswith(relative):
                    return io.BytesIO(b'corrupted source bytes')
                return original_open(path, *args, **kwargs)
            with patch.object(Path, 'open', corrupted), \
                 patch.object(B.importlib.util, 'module_from_spec', side_effect=AssertionError('helper executed')):
                with self.assertRaisesRegex(ValueError, 'dependency identity differs'):
                    spec.loader.exec_module(fresh)

    def test_immutable_output_detached_nested_serialization_and_false_acceptance(self):
        report = decode()
        with self.assertRaises(FrozenInstanceError):
            report.status = 'complete'
        with self.assertRaises(FrozenInstanceError):
            report.operations[0].observation.algebraic_preimages[0].fileglob_flags_uint32 = 0
        plain = report.to_dict()
        plain['operations'][0]['observation']['algebraic_preimages'][0]['named_flags'].append('FAKE')
        plain['source']['pairs'][0]['entry']['raw_scalars'][5] = 99
        self.assertNotIn('FAKE', report.to_dict()['operations'][0]['observation']['algebraic_preimages'][0]['named_flags'])
        self.assertEqual(report.source.pairs[0].entry.raw_scalars[5], 7)
        self.assertEqual(report.status, 'incomplete')
        for field in ('native_abi_calibrated', 'successful_effect_ordering', 'state_feed_eligible',
                      'application_output_authorized', 'extraction_acceptance', 'full_trace_acceptance'):
            self.assertIs(getattr(report, field), False)

    def test_numeric_stdio_and_mach_only_empty_bsd_do_not_grant_acceptance(self):
        for fd in (0, 1, 2):
            report = decode(call(fd=fd))
            self.assertEqual(report.operations[0].rule.source_fd, fd)
            self.assertFalse(report.application_output_authorized)
            self.assertFalse(report.state_feed_eligible)
        report = decode([physical(15, (0,) * 8), physical(16, (0,))])
        self.assertEqual((report.operations, report.counts.bsd_pairs, report.counts.uninterpreted_mach_pairs), ((), 0, 1))
        self.assertEqual(report.status, 'incomplete')
        self.assertFalse(report.full_trace_acceptance)


if __name__ == '__main__':
    unittest.main()
