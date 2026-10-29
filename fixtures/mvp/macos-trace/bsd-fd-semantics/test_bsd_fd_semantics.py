"""Independent provider tuples for executable descriptor operation rules."""
import copy
from dataclasses import FrozenInstanceError
import json
import os
from pathlib import Path
import socket
import struct
import subprocess
import unittest
from unittest.mock import patch
import urllib.request

import bsd_fd_semantics as B

OWNER, TARGET, TID = 3131, 4242, 700
U64, U32 = (1 << 64) - 1, (1 << 32) - 1
INT_MAX = (1 << 31) - 1
CONTRACT = (Path(__file__).parent.parent / 'syscall-contract' / 'contracts.json').read_bytes()
# Literal source-format transport fixture; no producer/generator is executed.
PROGRAM = b'#pragma D option quiet\nBEGIN { watched[4242]=1;trace((uint64_t)1);trace((uint64_t)timestamp);trace((uint64_t)pid);trace((uint64_t)tid);trace((uint64_t)(0));}\nEND {trace((uint64_t)17);trace((uint64_t)timestamp);trace((uint64_t)pid);trace((uint64_t)tid);trace((uint64_t)(0));}\nsyscall:::entry /watched[pid]/ {trace((uint64_t)2);trace((uint64_t)timestamp);trace((uint64_t)pid);trace((uint64_t)tid);trace((uint64_t)(ppid));trace((uint64_t)arg0);trace((uint64_t)arg1);trace((uint64_t)arg2);trace((uint64_t)arg3);trace((uint64_t)arg4);trace((uint64_t)arg5);trace((uint64_t)arg6);trace((uint64_t)arg7);}\nsyscall:::return /watched[pid]/ {trace((uint64_t)3);trace((uint64_t)timestamp);trace((uint64_t)pid);trace((uint64_t)tid);trace((uint64_t)(ppid));trace((uint64_t)arg0);trace((uint64_t)arg1);trace((uint64_t)arg2);trace((uint64_t)arg3);trace((uint64_t)errno);}\nmach_trap:::entry /watched[pid]/ {trace((uint64_t)15);trace((uint64_t)timestamp);trace((uint64_t)pid);trace((uint64_t)tid);trace((uint64_t)(ppid));trace((uint64_t)arg0);trace((uint64_t)arg1);trace((uint64_t)arg2);trace((uint64_t)arg3);trace((uint64_t)arg4);trace((uint64_t)arg5);trace((uint64_t)arg6);trace((uint64_t)arg7);}\nmach_trap:::return /watched[pid]/ {trace((uint64_t)16);trace((uint64_t)timestamp);trace((uint64_t)pid);trace((uint64_t)tid);trace((uint64_t)(ppid));trace((uint64_t)arg0);}\nproc:::create /watched[pid]/ {watched[pid]=1;trace((uint64_t)4);trace((uint64_t)timestamp);trace((uint64_t)pid);trace((uint64_t)tid);trace((uint64_t)(args[0]->pr_pid));}\nproc:::start /watched[pid]/ {watched[pid]=1;trace((uint64_t)5);trace((uint64_t)timestamp);trace((uint64_t)pid);trace((uint64_t)tid);trace((uint64_t)(ppid));}\nproc:::exec-success /watched[pid]/ {watched[pid]=1;trace((uint64_t)7);trace((uint64_t)timestamp);trace((uint64_t)pid);trace((uint64_t)tid);trace((uint64_t)(ppid));}\nproc:::exit /watched[pid]/ {trace((uint64_t)6);trace((uint64_t)timestamp);trace((uint64_t)pid);trace((uint64_t)tid);trace((uint64_t)(arg0));}\nproc:::exec-failure /watched[pid]/ {trace((uint64_t)8);trace((uint64_t)timestamp);trace((uint64_t)pid);trace((uint64_t)tid);trace((uint64_t)(arg0));}\nproc:::lwp-create /watched[pid]/ {trace((uint64_t)9);trace((uint64_t)timestamp);trace((uint64_t)pid);trace((uint64_t)tid);trace((uint64_t)(args[0]->pr_lwpid));}\nproc:::lwp-start /watched[pid]/ {trace((uint64_t)10);trace((uint64_t)timestamp);trace((uint64_t)pid);trace((uint64_t)tid);trace((uint64_t)(0));}\nproc:::lwp-exit /watched[pid]/ {trace((uint64_t)11);trace((uint64_t)timestamp);trace((uint64_t)pid);trace((uint64_t)tid);trace((uint64_t)(0));}\nproc:::spawn-success /watched[pid]/ {trace((uint64_t)12);trace((uint64_t)timestamp);trace((uint64_t)pid);trace((uint64_t)tid);trace((uint64_t)(0));}\nproc:::spawn-failure /watched[pid]/ {trace((uint64_t)13);trace((uint64_t)timestamp);trace((uint64_t)pid);trace((uint64_t)tid);trace((uint64_t)(arg0));}\nproc:::exited /watched[args[0]->pr_pid]/ {trace((uint64_t)18);trace((uint64_t)timestamp);trace((uint64_t)pid);trace((uint64_t)tid);trace((uint64_t)(args[0]->pr_pid));trace((uint64_t)arg1);trace((uint64_t)args[0]->pr_addr);trace((uint64_t)((struct proc *)args[0]->pr_addr)->p_refcount);}\n'
NAMES = {1: ('dtrace', '', '', 'BEGIN'), 17: ('dtrace', '', '', 'END'), 2: ('syscall', '', 'read', 'entry'), 3: ('syscall', '', 'read', 'return'), 15: ('mach_trap', '', 'mach_msg2_trap', 'entry'), 16: ('mach_trap', '', 'mach_msg2_trap', 'return'), 4: ('proc', 'mach_kernel', '', 'create'), 5: ('proc', '', '', 'start'), 6: ('proc', '', '', 'exit'), 7: ('proc', '', '', 'exec-success'), 8: ('proc', '', '', 'exec-failure'), 9: ('proc', '', '', 'lwp-create'), 10: ('proc', '', '', 'lwp-start'), 11: ('proc', '', '', 'lwp-exit'), 12: ('proc', '', '', 'spawn-success'), 13: ('proc', '', '', 'spawn-failure'), 18: ('proc', '', '', 'exited')}
SHAPES = {1: (56, True), 2: (120, False), 3: (96, False), 4: (56, True), 5: (56, True), 6: (56, False), 7: (56, True), 8: (56, False), 9: (56, False), 10: (56, False), 11: (56, False), 12: (56, False), 13: (56, False), 15: (120, False), 16: (64, False), 17: (56, False), 18: (80, False)}

# name, entry words, primary success, expected operation, conditional rule
GOLDEN_OPERATIONS = (
    ('close', (7,), 0, 'fd-close', 'release-descriptor-slot'),
    ('close_nocancel', (7,), 0, 'fd-close', 'release-descriptor-slot'),
    ('dup', (7,), 11, 'fd-dup', 'create-descriptor-alias'),
    ('dup2', (7, 11), 11, 'fd-dup2', 'replace-target-with-alias'),
    ('write', (7, 0x1234, 9), 4, 'fd-write', 'reported-write-bytes'),
    ('write_nocancel', (7, 0x1234, 9), 4, 'fd-write', 'reported-write-bytes'),
    ('pwrite', (7, 0x1234, 9, 16), 4, 'fd-pwrite', 'reported-write-bytes'),
    ('pwrite_nocancel', (7, 0x1234, 9, 16), 4, 'fd-pwrite', 'reported-write-bytes'),
    ('fsync', (7,), 0, 'fd-flush', 'file-integrity-flush'),
    ('fsync_nocancel', (7,), 0, 'fd-flush', 'file-integrity-flush'),
    ('ftruncate', (7, 16), 0, 'fd-truncate', 'object-specific-truncate'),
)


def frame(kind, *, name=None, words=None, tid=TID, actor=None, detail=None):
    total, assignment = SHAPES[kind]
    actor = (OWNER if kind in (1, 17) else TARGET) if actor is None else actor
    if detail is None:
        detail = OWNER if kind in (2, 3, 5, 7, 15, 16) else TARGET if kind == 18 else 0
    values = [kind, 100, actor, tid, detail]
    if kind == 18:
        values += [U64, 0xabcdef123456, 0x1c2]
    else:
        values += [0] * ((total - 56) // 8) if words is None else list(words)
    assert len(values) == (total - 16) // 8
    records = [{'action': 1, 'size': 0, 'offset': 12, 'hex': ''}] if assignment else []
    records += [{'action': 1, 'size': 8, 'offset': 16 + i * 8,
                 'hex': struct.pack('<Q', value).hex()} for i, value in enumerate(values)]
    row = dict(event=0, cpu=7, epid=1000 + kind, probe_id=100 + kind,
        record_bytes=total, header_record_indexes=list(range(int(assignment), int(assignment) + 5)),
        kind=kind, timestamp=100, pid=actor, tid=tid, detail=detail,
        **dict(zip(('provider', 'module', 'function', 'name'), NAMES[kind])), records=records)
    if name is not None:
        row['function'] = name
    return row


def call(name='close', arguments=(7,), result=0, secondary=0, error=0, *, returned=None):
    words = tuple(arguments) + (0,) * (8 - len(arguments))
    returned = (result, result, secondary, error, error) if returned is None else returned
    return [frame(2, name=name, words=words), frame(3, name=name, words=returned)]


def fixture(body=None):
    return [frame(1), *(call() if body is None else body), frame(11), frame(18), frame(17)]


def inputs(records):
    records = [copy.deepcopy(row) for row in records]
    probes = {100 + kind: names for kind, names in NAMES.items()}
    ids = {names: number for number, names in probes.items()}
    for index, row in enumerate(records, 1):
        names = tuple(row[key] for key in ('provider', 'module', 'function', 'name'))
        if names not in ids:
            number = max(probes) + 1
            probes[number] = names
            ids[names] = number
        row.update(event=index, probe_id=ids[names], epid=10000 + ids[names], timestamp=index * 10)
        row['records'][1 + int(SHAPES[row['kind']][1])]['hex'] = struct.pack('<Q', row['timestamp']).hex()
    inventory = ''.join(str(number) + '\t' + '\t'.join(names) + '\n'
                        for number, names in probes.items()).encode('ascii')
    lines = [json.dumps(row, separators=(',', ':')).encode('ascii') + b'\n' for row in records]
    return inventory, lines


def decode(body=None, *, records=None, **kwargs):
    probes, lines = inputs(fixture(body) if records is None else records)
    return B.decode_owned_fd_semantics(kwargs.pop('program', PROGRAM),
        kwargs.pop('probes', probes), kwargs.pop('errors', b''),
        kwargs.pop('event_lines', lines), owner_pid=kwargs.pop('owner_pid', OWNER),
        target_pid=kwargs.pop('target_pid', TARGET),
        contract_bytes=kwargs.pop('contract_bytes', CONTRACT), **kwargs)


def failed(name, arguments, error=13):
    return call(name, arguments, U64, U64, error)


class FdSemanticsControls(unittest.TestCase):
    def test_all_eleven_names_produce_the_independent_expected_operation_rules(self):
        body = [phase for name, args, result, _, _ in GOLDEN_OPERATIONS for phase in call(name, args, result)]
        report = decode(body)
        self.assertEqual((report.counts.bsd_pairs, report.counts.recognized_operation_pairs,
                          report.counts.source_consistent_successes), (11, 11, 11))
        for row, (name, args, primary, operation, rule) in zip(report.operations, GOLDEN_OPERATIONS):
            self.assertEqual((row.source_name, row.request.operation, row.status,
                              row.outcome.primary_result, row.postcondition.kind),
                             (name, operation, 'source-consistent', primary, rule))
            pair = report.source.pairs[row.source_pair_index]
            self.assertEqual(row.correlation_id, pair.correlation_id)
            self.assertEqual(pair.entry.raw_scalars[5:5 + len(args)], args)
            self.assertTrue(row.request.entry_attempt_observed)

    def test_all_161_known_declarations_and_unknown_name_get_explicit_rows(self):
        specifications = {name: (args, result) for name, args, result, _, _ in GOLDEN_OPERATIONS}
        body = []
        for declaration in json.loads(CONTRACT)['calls']:
            name = declaration['name']
            args, result = specifications.get(name, ((0,) * len(declaration['arguments']), 0))
            body += call(name, args, result)
        body += call('future_fs_operation', (U64,) * 8, 0)
        report = decode(body)
        self.assertEqual((report.counts.bsd_pairs, report.counts.recognized_operation_pairs,
                          report.counts.known_unhandled_pairs, report.counts.unknown_bsd_pairs), (162, 11, 150, 1))
        self.assertEqual(len(report.operations), 162)
        unknown = report.operations[-1]
        self.assertEqual((unknown.status, unknown.arguments, unknown.request.attempt_kind),
                         ('unsupported', (), 'unmodeled-bsd-attempt'))
        self.assertIsNone(unknown.postcondition)
        self.assertEqual(report.source.pairs[-1].entry.raw_scalars[5:], (U64,) * 8)

    def test_known_unhandled_controls_vectors_and_absent_read_routes_stay_unmodeled(self):
        for name in ('fcntl', 'writev', 'guarded_write_np', 'read', 'pread'):
            row = decode(call(name, (0,) * 8, 0)).operations[0]
            self.assertEqual((row.status, row.request.operation, row.request.attempt_kind),
                             ('unsupported', None, 'unmodeled-bsd-attempt'))
            self.assertIsNone(row.postcondition)
            self.assertTrue(row.request.entry_attempt_observed)
            self.assertTrue(row.unsupported_reasons)

    def test_close_flush_truncate_primary_zero_domain_is_executable(self):
        for name, args in (('close', (7,)), ('close_nocancel', (7,)),
                           ('fsync', (7,)), ('fsync_nocancel', (7,)), ('ftruncate', (7, 9))):
            for primary in (1, 7, U64):
                row = decode(call(name, args, primary)).operations[0]
                self.assertEqual(row.outcome.disposition, 'kernel-success')
                self.assertEqual(row.status, 'unsupported')
                self.assertIsNone(row.postcondition)
                self.assertIn('zero primary', ' '.join(row.unsupported_reasons))

    def test_closed_int_secondary_result_is_checked_and_retained_unchanged(self):
        for name, args, primary in (('close', (7,), 0), ('fsync', (7,), 0),
                                    ('ftruncate', (7, 9), 0), ('dup', (7,), 11), ('dup2', (7, 11), 11)):
            for secondary, typed in ((1, 1), (U64, -1)):
                row = decode(call(name, args, primary, secondary)).operations[0]
                self.assertEqual((row.status, row.outcome.secondary_result), ('unsupported', typed))
                self.assertIn('secondary', ' '.join(row.unsupported_reasons))
                self.assertIsNone(row.postcondition)

    def test_negative_signed_fd_cannot_have_a_supported_success(self):
        for name, args in (('close', (U64,)), ('fsync', (U64,)), ('ftruncate', (U64, 9)),
                           ('write', (U64, 0, 1)), ('pwrite', (U64, 0, 1, 0))):
            row = decode(call(name, args, 0)).operations[0]
            self.assertEqual((row.request.fd, row.status), (-1, 'unsupported'))
            self.assertIn('negative', ' '.join(row.unsupported_reasons))

    def test_failed_close_keeps_negative_fd_and_ambiguous_slot_state(self):
        row = decode(failed('close', (U64,), 9)).operations[0]
        self.assertEqual((row.status, row.request.fd, row.outcome.kernel_error), ('kernel-error', -1, 9))
        self.assertIsNone(row.postcondition)
        self.assertIn('slot may already be released', ' '.join(row.effect_uncertainties))

    def test_dup_distinct_descriptor_domain_and_allocation_relation(self):
        for primary in (0, 11, INT_MAX):
            row = decode(call('dup', (7,), primary)).operations[0]
            self.assertEqual(row.status, 'source-consistent')
            rule = row.postcondition
            self.assertEqual((rule.source_fd, rule.target_fd, rule.cloexec_rule), (7, primary, 'cleared'))
            self.assertEqual(rule.ofd_relation, 'kernel-chosen-shared-open-file-description')
            self.assertEqual(rule.allocation_rule, 'lowest-free-at-allocation-point')
        for primary in (7, U64):
            row = decode(call('dup', (7,), primary)).operations[0]
            self.assertEqual(row.status, 'unsupported')
            self.assertIn('distinct nonnegative', ' '.join(row.unsupported_reasons))

    def test_unsigned_dup_inputs_above_signed_domain_are_not_reinterpreted(self):
        for name, args in (('dup', (U32,)), ('dup2', (7, U32)), ('dup2', (U32, 7))):
            row = decode(failed(name, args, 9)).operations[0]
            self.assertEqual(row.status, 'unsupported')
            self.assertIn('unsigned descriptor', ' '.join(row.unsupported_reasons))
            self.assertEqual(row.outcome.kernel_error, 9)
            self.assertTrue(row.request.entry_attempt_observed)
            self.assertIn(U32, [arg.value for arg in row.arguments])

    def test_dup2_success_requires_requested_target(self):
        row = decode(call('dup2', (7, 11), 12)).operations[0]
        self.assertEqual((row.status, row.request.target_fd, row.outcome.primary_result), ('unsupported', 11, 12))
        self.assertIn('requested target', ' '.join(row.unsupported_reasons))
        self.assertIsNone(row.postcondition)

    def test_dup2_self_preserves_flags_and_does_not_allocate_or_replace(self):
        row = decode(call('dup2', (7, 7), 7)).operations[0]
        self.assertEqual(row.status, 'source-consistent')
        self.assertEqual((row.postcondition.kind, row.postcondition.cloexec_rule,
                          row.postcondition.allocation_rule, row.postcondition.ofd_relation),
                         ('preserve-same-descriptor', 'preserved', 'no-allocation', 'same-descriptor'))

    def test_dup2_distinct_target_alias_clears_cloexec_conditionally(self):
        row = decode(call('dup2', (7, 11), 11)).operations[0]
        self.assertEqual((row.postcondition.kind, row.postcondition.source_fd,
                          row.postcondition.target_fd, row.postcondition.cloexec_rule),
                         ('replace-target-with-alias', 7, 11, 'cleared'))
        self.assertTrue(row.postcondition.required_witnesses)

    def test_failed_dup2_target_state_is_explicitly_ambiguous(self):
        row = decode(failed('dup2', (7, 11))).operations[0]
        self.assertEqual((row.status, row.request.source_fd, row.request.target_fd), ('kernel-error', 7, 11))
        self.assertIsNone(row.postcondition)
        self.assertIn('target may already be closed or reserved', ' '.join(row.effect_uncertainties))

    def test_write_zero_short_full_and_maximum_counts(self):
        for name in ('write', 'write_nocancel', 'pwrite', 'pwrite_nocancel'):
            for requested, reported in ((0, 0), (9, 1), (9, 9), (INT_MAX, INT_MAX)):
                args = (7, U64, requested) + ((16,) if name.startswith('pwrite') else ())
                row = decode(call(name, args, reported)).operations[0]
                self.assertEqual((row.status, row.request.requested_bytes,
                                  row.postcondition.reported_bytes), ('source-consistent', requested, reported))
                self.assertEqual(row.request.attempt_kind, 'payload-write-attempt')
                self.assertEqual(row.request.buffer_address, U64)

    def test_write_success_rejects_negative_excess_or_frontdoor_oversize_count(self):
        for requested, primary in ((9, U64), (9, 10), (INT_MAX + 1, 0), (U64, 1)):
            row = decode(call('write', (7, 0, requested), primary)).operations[0]
            self.assertEqual(row.status, 'unsupported')
            self.assertIn('INT_MAX', ' '.join(row.unsupported_reasons))
            self.assertEqual(row.request.attempt_kind, 'payload-write-attempt')
            self.assertIsNone(row.postcondition)

    def test_failed_oversize_write_keeps_attempt_and_does_not_invent_zero_progress(self):
        row = decode(failed('write', (7, 0, U64), 22)).operations[0]
        self.assertEqual((row.status, row.request.requested_bytes, row.request.attempt_kind),
                         ('kernel-error', U64, 'payload-write-attempt'))
        self.assertIsNone(row.outcome.primary_result)
        self.assertIsNone(row.postcondition)
        self.assertIn('partial written bytes may be hidden', ' '.join(row.effect_uncertainties))

    def test_failed_write_error_classes_never_prove_no_partial_progress(self):
        for name in ('write', 'pwrite'):
            args = (7, 0x1234, 9) + ((16,) if name == 'pwrite' else ())
            for error in (4, 35, 32, 5):
                row = decode(failed(name, args, error)).operations[0]
                self.assertEqual((row.status, row.outcome.kernel_error), ('kernel-error', error))
                self.assertIn('absence of effects', ' '.join(row.effect_uncertainties))
                self.assertIsNone(row.postcondition)

    def test_pwrite_preserves_explicit_offset_and_rejects_only_minus_one_wrapper_success(self):
        for name in ('pwrite', 'pwrite_nocancel'):
            for bits, expected in ((0, 0), (16, 16), (U64 - 1, -2), (1 << 63, -(1 << 63))):
                row = decode(call(name, (7, 0, 9, bits), 4)).operations[0]
                self.assertEqual((row.status, row.request.position_mode,
                                  row.request.requested_offset, row.postcondition.requested_offset),
                                 ('source-consistent', 'explicit', expected, expected))
            bad = decode(call(name, (7, 0, 9, U64), 0)).operations[0]
            self.assertEqual((bad.status, bad.request.requested_offset), ('unsupported', -1))
            self.assertIn('offset -1', ' '.join(bad.unsupported_reasons))

    def test_failed_negative_pwrite_keeps_signed_request(self):
        row = decode(failed('pwrite', (7, 0, 9, U64), 22)).operations[0]
        self.assertEqual((row.status, row.request.requested_offset, row.request.attempt_kind),
                         ('kernel-error', -1, 'payload-write-attempt'))
        self.assertIsNone(row.postcondition)

    def test_implicit_write_position_does_not_invent_file_offset_or_range(self):
        row = decode(call('write', (7, 0, 9), 4)).operations[0]
        self.assertEqual(row.request.position_mode, 'implicit')
        self.assertIsNone(row.request.requested_offset)
        self.assertIsNone(row.postcondition.requested_offset)
        self.assertEqual(row.postcondition.object_domain, 'unresolved-fileops-target')

    def test_ftruncate_zero_positive_and_negative_lengths(self):
        for length in (0, 16, (1 << 63) - 1):
            row = decode(call('ftruncate', (7, length), 0)).operations[0]
            self.assertEqual((row.status, row.request.requested_length,
                              row.postcondition.requested_length, row.postcondition.object_domain),
                             ('source-consistent', length, length, 'vnode-or-posix-shared-memory'))
        bad = decode(call('ftruncate', (7, U64), 0)).operations[0]
        self.assertEqual((bad.status, bad.request.requested_length), ('unsupported', -1))
        self.assertIn('negative requested length', ' '.join(bad.unsupported_reasons))

    def test_truncate_request_is_not_resulting_size_and_needs_object_specific_witnesses(self):
        for length in (0, 1, 4097):
            report = decode(call('ftruncate', (7, length), 0))
            rule = report.operations[0].postcondition
            self.assertEqual((rule.kind, rule.requested_length), ('object-specific-truncate', length))
            witnesses = ' '.join(rule.required_witnesses)
            for requirement in ('vnode-versus-POSIX-shm', 'page size', 'prior allocation', 'object lifetime'):
                self.assertIn(requirement, witnesses)
            serialized = report.to_dict()['operations'][0]['postcondition']
            self.assertNotIn('actual_size', serialized)
            self.assertNotIn('resulting_size', serialized)
            self.assertEqual(serialized['requested_length'], length)
            self.assertFalse(report.state_feed_eligible)

    def test_failed_flush_and_truncate_stay_distinct_attempts_with_uncertain_effects(self):
        for name, args, kind in (('fsync', (7,), 'flush-attempt'),
                                 ('fsync_nocancel', (7,), 'flush-attempt'),
                                 ('ftruncate', (7, U64), 'truncate-attempt')):
            row = decode(failed(name, args, 5)).operations[0]
            self.assertEqual((row.status, row.request.attempt_kind), ('kernel-error', kind))
            self.assertIsNone(row.postcondition)
            self.assertIn('absence of effects', ' '.join(row.effect_uncertainties))

    def test_recognized_noncanonical_arguments_do_not_erase_write_flush_truncate_attempt(self):
        for name, args, kind in (('write', (U32, 0, 9), 'payload-write-attempt'),
                                 ('fsync', (U32,), 'flush-attempt'),
                                 ('ftruncate', (U32, 9), 'truncate-attempt')):
            row = decode(failed(name, args)).operations[0]
            self.assertEqual((row.status, row.request.fd, row.request.attempt_kind), ('unsupported', None, kind))
            self.assertIsNone(row.arguments[0].value)
            self.assertEqual(row.outcome.kernel_error, 13)
            self.assertTrue(row.request.entry_attempt_observed)

    def test_control_flow_and_malformed_provider_results_are_unsupported_not_success(self):
        for returned in ((U64, U64, U64, U64, U64), (0, 0, 0, U64 - 1, U64 - 1),
                         (0, 1, 0, 0, 0), (U64, U64, U64, 2, 3)):
            row = decode(call('write', (7, 0, 9), returned=returned)).operations[0]
            self.assertEqual((row.status, row.request.attempt_kind), ('unsupported', 'payload-write-attempt'))
            self.assertIsNone(row.postcondition)
            self.assertTrue(row.unsupported_reasons)

    def test_mixed_mach_pairs_and_lifecycle_are_retained_without_filtering(self):
        mach = [frame(15, words=(0,) * 8), frame(16, words=(0,))]
        report = decode(mach + call() + mach + failed('write', (7, 0, 9)))
        self.assertEqual([row.source_pair_index for row in report.operations], [1, 3])
        self.assertEqual((report.counts.bsd_pairs, report.counts.uninterpreted_mach_pairs,
                          report.counts.source_consistent_successes, report.counts.kernel_errors), (2, 2, 1, 1))
        self.assertEqual([phase.raw_scalars[0] for phase in report.source.lifecycle], [1, 11, 18, 17])
        self.assertEqual(report.source.pairs[0].entry.raw_scalars[0], 15)

    def test_no_bsd_activity_does_not_imply_acceptance(self):
        report = decode([frame(15, words=(0,) * 8), frame(16, words=(0,))])
        self.assertEqual(report.operations, ())
        self.assertEqual((report.counts.bsd_pairs, report.counts.uninterpreted_mach_pairs), (0, 1))
        self.assertEqual(report.status, 'incomplete')
        self.assertFalse(report.full_trace_acceptance)

    def test_numeric_stdio_fds_receive_no_output_exemption(self):
        for fd in (0, 1, 2, 7):
            report = decode(call('write', (fd, 0, 9), 4))
            row = report.operations[0]
            self.assertEqual((row.request.fd, row.request.attempt_kind), (fd, 'payload-write-attempt'))
            self.assertFalse(report.state_feed_eligible)
            self.assertIn('application-output', ' '.join(report.missing_capabilities))

    def test_every_result_and_rule_requires_missing_native_binding_and_order_witnesses(self):
        report = decode()
        self.assertEqual((report.protocol, report.status), ('darwin-owned-bsd-fd-semantics-v1', 'incomplete'))
        self.assertFalse(report.native_abi_calibrated)
        self.assertFalse(report.successful_effect_ordering)
        self.assertFalse(report.state_feed_eligible)
        self.assertFalse(report.full_trace_acceptance)
        self.assertIn('kernel lookup', ' '.join(report.operations[0].postcondition.required_witnesses))
        self.assertIn('slot state at return', ' '.join(report.operations[0].effect_uncertainties))
        self.assertEqual(len(report.source_identities), 7)

    def test_all_results_frozen_and_serialization_detaches_nested_objects(self):
        report = decode()
        for obj, key in ((report, 'status'), (report.operations[0], 'status'),
                         (report.operations[0].request, 'fd'), (report.operations[0].outcome, 'disposition'),
                         (report.operations[0].postcondition, 'kind'), (report.counts, 'bsd_pairs')):
            with self.assertRaises(FrozenInstanceError):
                setattr(obj, key, 'changed')
        first = report.to_dict()
        first['operations'][0]['request']['fd'] = 999
        first['operations'][0]['arguments'][0]['roles'].append('invented')
        first['source']['pairs'][0]['entry']['raw_scalars'][5] = 999
        second = report.to_dict()
        self.assertEqual(second['operations'][0]['request']['fd'], 7)
        self.assertEqual(second['source']['pairs'][0]['entry']['raw_scalars'][5], 7)
        self.assertNotIn('invented', second['operations'][0]['arguments'][0]['roles'])
        self.assertEqual(json.loads(json.dumps(second)), second)

    def test_one_strict_pairing_pass_and_no_public_raw_reader_reconsumption(self):
        probes, lines = inputs(fixture())
        done, iterations = [], []
        class Once:
            def __iter__(self):
                iterations.append(True)
                if len(iterations) != 1:
                    raise AssertionError('stream consumed twice')
                yield from lines
                done.append(True)
        original = B._decode_operation
        def checked(*args):
            self.assertEqual(done, [True])
            return original(*args)
        with patch.object(B._RAW, 'pair_raw_owned', wraps=B._RAW.pair_raw_owned) as pairer, \
             patch.object(B._ENTRY, 'decode_owned_bsd_entries', side_effect=AssertionError('second reader')), \
             patch.object(B._OUTCOME, 'decode_owned_bsd_outcomes', side_effect=AssertionError('second reader')), \
             patch.object(B, '_decode_operation', side_effect=checked) as decoder:
            report = decode(probes=probes, event_lines=Once())
            self.assertEqual(len(report.operations), 1)
            self.assertEqual((pairer.call_count, decoder.call_count, len(iterations)), (1, 1, 1))

    def test_static_invalidity_precedes_event_consumption(self):
        def forbidden():
            raise AssertionError('events must not be consumed')
            yield b''
        for kwargs in ({'contract_bytes': CONTRACT + b'\n'}, {'contract_bytes': bytearray(CONTRACT)},
                       {'program': PROGRAM + b'\n'}, {'errors': b'bad\n'},
                       {'owner_pid': True}, {'target_pid': False}):
            with self.assertRaises(B.RawValidationError):
                decode(event_lines=forbidden(), **kwargs)

    def test_unpaired_orphan_and_mismatched_input_refuse_before_semantics(self):
        for body in ([frame(2, name='write', words=(0,) * 8)],
                     [frame(3, name='write', words=(0,) * 5)],
                     [frame(2, name='write', words=(0,) * 8), frame(3, name='close', words=(0,) * 5)]):
            with patch.object(B, '_decode_operation', side_effect=AssertionError('no prefix')) as decoder:
                with self.assertRaises(B.RawValidationError):
                    decode(body)
                decoder.assert_not_called()

    def test_late_malformed_event_returns_no_operation_prefix(self):
        probes, lines = inputs(fixture())
        lines[-1] = b'{"late":"malformed"}\n'
        with patch.object(B, '_decode_operation', side_effect=AssertionError('no prefix')) as decoder:
            with self.assertRaises(B.RawValidationError):
                decode(probes=probes, event_lines=iter(lines))
            decoder.assert_not_called()

    def test_late_iterator_failure_propagates_before_semantics(self):
        probes, lines = inputs(fixture())
        class SourceFailure(RuntimeError):
            pass
        def broken():
            yield from lines
            raise SourceFailure('late source failure')
        with patch.object(B, '_decode_operation', side_effect=AssertionError('no prefix')) as decoder:
            with self.assertRaisesRegex(SourceFailure, 'late source'):
                decode(probes=probes, event_lines=broken())
            decoder.assert_not_called()

    def test_no_input_asset_process_or_network_access_after_import(self):
        with patch('builtins.open', side_effect=AssertionError('file access')), \
             patch.object(Path, 'open', side_effect=AssertionError('path access')), \
             patch.object(os, 'open', side_effect=AssertionError('descriptor access')), \
             patch.object(subprocess, 'run', side_effect=AssertionError('process access')), \
             patch.object(socket, 'socket', side_effect=AssertionError('network access')), \
             patch.object(urllib.request, 'urlopen', side_effect=AssertionError('URL access')), \
             patch.object(B._RAW._CONTRACT_HELPERS, 'load_table', side_effect=AssertionError('asset fallback')):
            report = decode()
            report.to_dict()
            self.assertEqual(report.counts.bsd_pairs, 1)

    def test_no_predecoded_pairs_or_caller_calibration_and_profile_assertions(self):
        for kwargs in ({'source': decode().source}, {'native_abi_calibrated': True},
                       {'profile': 'caller-selected'}, {'state_feed_eligible': True}):
            with self.assertRaises(TypeError):
                decode(**kwargs)


if __name__ == '__main__':
    unittest.main()
