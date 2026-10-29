"""Independent serialized vectors for four scalar descriptor commands."""
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

import bsd_fcntl_semantics as B

OWNER, TARGET, TID = 3131, 4242, 700
U64, U32 = (1 << 64) - 1, (1 << 32) - 1
INT_MAX = (1 << 31) - 1
CONTRACT = (Path(__file__).parent.parent / 'syscall-contract' / 'contracts.json').read_bytes()
# Literal transport fixture, independent of producer/validator generators.
PROGRAM = b'#pragma D option quiet\nBEGIN { watched[4242]=1;trace((uint64_t)1);trace((uint64_t)timestamp);trace((uint64_t)pid);trace((uint64_t)tid);trace((uint64_t)(0));}\nEND {trace((uint64_t)17);trace((uint64_t)timestamp);trace((uint64_t)pid);trace((uint64_t)tid);trace((uint64_t)(0));}\nsyscall:::entry /watched[pid]/ {trace((uint64_t)2);trace((uint64_t)timestamp);trace((uint64_t)pid);trace((uint64_t)tid);trace((uint64_t)(ppid));trace((uint64_t)arg0);trace((uint64_t)arg1);trace((uint64_t)arg2);trace((uint64_t)arg3);trace((uint64_t)arg4);trace((uint64_t)arg5);trace((uint64_t)arg6);trace((uint64_t)arg7);}\nsyscall:::return /watched[pid]/ {trace((uint64_t)3);trace((uint64_t)timestamp);trace((uint64_t)pid);trace((uint64_t)tid);trace((uint64_t)(ppid));trace((uint64_t)arg0);trace((uint64_t)arg1);trace((uint64_t)arg2);trace((uint64_t)arg3);trace((uint64_t)errno);}\nmach_trap:::entry /watched[pid]/ {trace((uint64_t)15);trace((uint64_t)timestamp);trace((uint64_t)pid);trace((uint64_t)tid);trace((uint64_t)(ppid));trace((uint64_t)arg0);trace((uint64_t)arg1);trace((uint64_t)arg2);trace((uint64_t)arg3);trace((uint64_t)arg4);trace((uint64_t)arg5);trace((uint64_t)arg6);trace((uint64_t)arg7);}\nmach_trap:::return /watched[pid]/ {trace((uint64_t)16);trace((uint64_t)timestamp);trace((uint64_t)pid);trace((uint64_t)tid);trace((uint64_t)(ppid));trace((uint64_t)arg0);}\nproc:::create /watched[pid]/ {watched[pid]=1;trace((uint64_t)4);trace((uint64_t)timestamp);trace((uint64_t)pid);trace((uint64_t)tid);trace((uint64_t)(args[0]->pr_pid));}\nproc:::start /watched[pid]/ {watched[pid]=1;trace((uint64_t)5);trace((uint64_t)timestamp);trace((uint64_t)pid);trace((uint64_t)tid);trace((uint64_t)(ppid));}\nproc:::exec-success /watched[pid]/ {watched[pid]=1;trace((uint64_t)7);trace((uint64_t)timestamp);trace((uint64_t)pid);trace((uint64_t)tid);trace((uint64_t)(ppid));}\nproc:::exit /watched[pid]/ {trace((uint64_t)6);trace((uint64_t)timestamp);trace((uint64_t)pid);trace((uint64_t)tid);trace((uint64_t)(arg0));}\nproc:::exec-failure /watched[pid]/ {trace((uint64_t)8);trace((uint64_t)timestamp);trace((uint64_t)pid);trace((uint64_t)tid);trace((uint64_t)(arg0));}\nproc:::lwp-create /watched[pid]/ {trace((uint64_t)9);trace((uint64_t)timestamp);trace((uint64_t)pid);trace((uint64_t)tid);trace((uint64_t)(args[0]->pr_lwpid));}\nproc:::lwp-start /watched[pid]/ {trace((uint64_t)10);trace((uint64_t)timestamp);trace((uint64_t)pid);trace((uint64_t)tid);trace((uint64_t)(0));}\nproc:::lwp-exit /watched[pid]/ {trace((uint64_t)11);trace((uint64_t)timestamp);trace((uint64_t)pid);trace((uint64_t)tid);trace((uint64_t)(0));}\nproc:::spawn-success /watched[pid]/ {trace((uint64_t)12);trace((uint64_t)timestamp);trace((uint64_t)pid);trace((uint64_t)tid);trace((uint64_t)(0));}\nproc:::spawn-failure /watched[pid]/ {trace((uint64_t)13);trace((uint64_t)timestamp);trace((uint64_t)pid);trace((uint64_t)tid);trace((uint64_t)(arg0));}\nproc:::exited /watched[args[0]->pr_pid]/ {trace((uint64_t)18);trace((uint64_t)timestamp);trace((uint64_t)pid);trace((uint64_t)tid);trace((uint64_t)(args[0]->pr_pid));trace((uint64_t)arg1);trace((uint64_t)args[0]->pr_addr);trace((uint64_t)((struct proc *)args[0]->pr_addr)->p_refcount);}\n'
NAMES = {1: ('dtrace', '', '', 'BEGIN'), 17: ('dtrace', '', '', 'END'), 2: ('syscall', '', 'read', 'entry'), 3: ('syscall', '', 'read', 'return'), 15: ('mach_trap', '', 'mach_msg2_trap', 'entry'), 16: ('mach_trap', '', 'mach_msg2_trap', 'return'), 4: ('proc', 'mach_kernel', '', 'create'), 5: ('proc', '', '', 'start'), 6: ('proc', '', '', 'exit'), 7: ('proc', '', '', 'exec-success'), 8: ('proc', '', '', 'exec-failure'), 9: ('proc', '', '', 'lwp-create'), 10: ('proc', '', '', 'lwp-start'), 11: ('proc', '', '', 'lwp-exit'), 12: ('proc', '', '', 'spawn-success'), 13: ('proc', '', '', 'spawn-failure'), 18: ('proc', '', '', 'exited')}
SHAPES = {1: (56, True), 2: (120, False), 3: (96, False), 4: (56, True), 5: (56, True), 6: (56, False), 7: (56, True), 8: (56, False), 9: (56, False), 10: (56, False), 11: (56, False), 12: (56, False), 13: (56, False), 15: (120, False), 16: (64, False), 17: (56, False), 18: (80, False)}

# command number, argument bits, primary success, name, operation, rule
GOLDEN_COMMANDS = (
    (0, 3, 11, 'F_DUPFD', 'duplicate-minimum', 'create-minimum-descriptor-alias'),
    (1, 0, 1, 'F_GETFD', 'query-cloexec', 'observe-descriptor-cloexec-at-kernel-read'),
    (2, 1, 0, 'F_SETFD', 'set-cloexec', 'set-descriptor-cloexec-bit'),
    (67, 3, 11, 'F_DUPFD_CLOEXEC', 'duplicate-minimum-cloexec', 'create-minimum-descriptor-alias'),
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


def call(name='fcntl', fd=7, command=1, argument=0, result=1, secondary=0, error=0, *, returned=None):
    returned = (result, result, secondary, error, error) if returned is None else returned
    return [frame(2, name=name, words=(fd, command, argument, 0, 0, 0, 0, 0)),
            frame(3, name=name, words=returned)]


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
    return B.decode_owned_fcntl_semantics(kwargs.pop('program', PROGRAM),
        kwargs.pop('probes', probes), kwargs.pop('errors', b''),
        kwargs.pop('event_lines', lines), owner_pid=kwargs.pop('owner_pid', OWNER),
        target_pid=kwargs.pop('target_pid', TARGET),
        contract_bytes=kwargs.pop('contract_bytes', CONTRACT), **kwargs)


def failed(command=2, argument=0, *, fd=7, error=13, name='fcntl'):
    return call(name, fd, command, argument, U64, U64, error)


class FcntlControls(unittest.TestCase):
    def test_four_literal_commands_through_both_syscall_names(self):
        body = [phase for syscall in ('fcntl', 'fcntl_nocancel')
                for command, argument, result, _, _, _ in GOLDEN_COMMANDS
                for phase in call(syscall, 7, command, argument, result)]
        report = decode(body)
        self.assertEqual((report.counts.bsd_pairs, report.counts.fcntl_pairs,
                          report.counts.recognized_command_pairs, report.counts.source_consistent_successes),
                         (8, 8, 8, 8))
        for row, expected in zip(report.operations, GOLDEN_COMMANDS * 2):
            command, argument, primary, name, operation, rule = expected
            self.assertEqual((row.request.command, row.request.command_name,
                              row.request.operation, row.outcome.primary_result, row.rule.kind),
                             (command, name, operation, primary, rule))
            pair = report.source.pairs[row.source_pair_index]
            self.assertEqual(row.correlation_id, pair.correlation_id)
            self.assertEqual(pair.entry.raw_scalars[5:8], (7, command, argument))
            self.assertEqual(row.status, 'source-consistent')

    def test_every_known_declaration_and_unknown_bsd_pair_gets_an_explicit_row(self):
        body = []
        for item in json.loads(CONTRACT)['calls']:
            if item['name'] in ('fcntl', 'fcntl_nocancel'):
                body += call(item['name'])
            else:
                body += [frame(2, name=item['name'], words=(0,) * 8),
                         frame(3, name=item['name'], words=(0,) * 5)]
        body += call('future_fs_operation')
        report = decode(body)
        self.assertEqual((report.counts.bsd_pairs, report.counts.fcntl_pairs,
                          report.counts.non_fcntl_pairs, report.counts.source_consistent_successes), (162, 2, 160, 2))
        self.assertEqual(report.operations[-1].request.attempt_kind, 'unmodeled-bsd-attempt')
        self.assertEqual(report.operations[-1].arguments, ())
        self.assertIsNone(report.operations[-1].rule)

    def test_getfd_accepts_only_zero_or_exact_cloexec_bit(self):
        for result in (0, 1):
            row = decode(call(command=1, result=result)).operations[0]
            self.assertEqual((row.status, row.rule.observed_cloexec), ('source-consistent', bool(result)))
            self.assertEqual(row.rule.affected_scope, 'kernel-chosen-fileproc-descriptor-entry')
            self.assertIsNone(row.rule.ofd_relation)
        for result in (2, 3, INT_MAX, U64):
            row = decode(call(command=1, result=result)).operations[0]
            self.assertEqual(row.status, 'unsupported')
            self.assertIn('F_GETFD success', ' '.join(row.unsupported_reasons))
            self.assertIsNone(row.rule)

    def test_getfd_ignores_full_argument_without_dropping_its_original_bits(self):
        for bits in (0, 1, U64, 1 << 63, 0x123456789abcdef0):
            report = decode(call(command=1, argument=bits, result=1))
            row = report.operations[0]
            expected = bits - (1 << 64) if bits >= (1 << 63) else bits
            self.assertEqual((row.request.argument_role, row.request.argument), ('ignored-by-command', expected))
            self.assertEqual(report.source.pairs[0].entry.raw_scalars[7], bits)
            self.assertTrue(row.rule.observed_cloexec)

    def test_setfd_uses_only_source_cloexec_bit_in_full_signed_long(self):
        vectors = ((0, False), (1, True), (2, False), (3, True),
                   (0x80000000, False), (0x80000001, True),
                   (1 << 63, False), (U64, True), (U64 - 1, False))
        for bits, expected in vectors:
            report = decode(call(command=2, argument=bits, result=0))
            row = report.operations[0]
            signed = bits - (1 << 64) if bits >= (1 << 63) else bits
            self.assertEqual((row.status, row.request.argument, row.request.requested_cloexec),
                             ('source-consistent', signed, expected))
            self.assertEqual(row.request.argument_role, 'FD_CLOEXEC-bit-only')
            self.assertEqual(row.rule.requested_cloexec, expected)
            self.assertEqual(row.rule.affected_scope, 'kernel-chosen-fileproc-descriptor-entry')
            self.assertEqual(report.source.pairs[0].entry.raw_scalars[7], bits)

    def test_setfd_zero_primary_domain_preserves_inconsistent_original_result(self):
        for primary in (1, 7, U64):
            row = decode(call(command=2, result=primary)).operations[0]
            self.assertEqual(row.outcome.disposition, 'kernel-success')
            self.assertEqual(row.status, 'unsupported')
            self.assertIsNone(row.rule)
            self.assertIn('zero primary', ' '.join(row.unsupported_reasons))

    def test_setfd_guarded_clear_failure_has_no_inferred_resulting_bit(self):
        row = decode(failed(command=2, argument=0)).operations[0]
        self.assertEqual((row.status, row.request.requested_cloexec, row.outcome.kernel_error),
                         ('kernel-error', False, 13))
        self.assertEqual(row.request.attempt_kind, 'descriptor-flag-change-attempt')
        self.assertIsNone(row.rule)
        self.assertIn('guarded clearing can fail', ' '.join(row.effect_uncertainties))
        self.assertIn('not an absence-of-effects', ' '.join(row.effect_uncertainties))

    def test_dup_minimum_and_distinct_result_are_executable_domains(self):
        for command in (0, 67):
            for minimum, result in ((0, 0), (3, 11), (11, 11), (INT_MAX, INT_MAX)):
                row = decode(call(command=command, argument=minimum, result=result)).operations[0]
                self.assertEqual(row.status, 'source-consistent')
                self.assertEqual((row.rule.source_fd, row.rule.target_fd, row.rule.minimum_descriptor),
                                 (7, result, minimum))
            for minimum, result in ((3, 2), (0, 7), (0, U64), (U64, 0)):
                row = decode(call(command=command, argument=minimum, result=result)).operations[0]
                self.assertEqual(row.status, 'unsupported')
                self.assertIn('minimum <= result', ' '.join(row.unsupported_reasons))
                self.assertIsNone(row.rule)

    def test_dup_commands_have_distinct_new_descriptor_cloexec_rules(self):
        for command, expected in ((0, 'clear'), (67, 'set')):
            row = decode(call(command=command, argument=3, result=11)).operations[0]
            self.assertEqual(row.rule.cloexec_rule, expected)
            self.assertEqual(row.rule.ofd_relation, 'finishdup-kernel-chosen-shared-fileglob')
            self.assertEqual(row.rule.allocation_rule,
                             'lowest-free-at-or-above-minimum-at-allocation-point')

    def test_dup_long_outside_signed32_subset_is_never_truncated(self):
        for command in (0, 67):
            for bits in (1 << 31, 1 << 32, U32, 1 << 63, U64 - (1 << 31)):
                row = decode(failed(command=command, argument=bits, error=22)).operations[0]
                self.assertEqual(row.status, 'unsupported')
                self.assertIsNone(row.request.minimum_descriptor)
                self.assertIn('canonical signed32 range', ' '.join(row.unsupported_reasons))
                self.assertEqual(row.outcome.kernel_error, 22)
                self.assertTrue(row.request.entry_attempt_observed)
                self.assertIsNone(row.rule)

    def test_failed_canonical_negative_dup_minimum_stays_an_attempt(self):
        for bits, expected in ((U64, -1), (U64 - INT_MAX, -(1 << 31))):
            row = decode(failed(command=0, argument=bits, error=22)).operations[0]
            self.assertEqual((row.status, row.request.minimum_descriptor), ('kernel-error', expected))
            self.assertEqual(row.request.attempt_kind, 'descriptor-allocation-attempt')
            self.assertIsNone(row.rule)
            self.assertIn('allocation reservations', ' '.join(row.effect_uncertainties))

    def test_negative_source_fd_cannot_have_supported_success_but_failure_is_retained(self):
        for command, argument, result, _, _, _ in GOLDEN_COMMANDS:
            row = decode(call(fd=U64, command=command, argument=argument, result=result)).operations[0]
            self.assertEqual((row.status, row.request.fd), ('unsupported', -1))
            self.assertIn('nonnegative descriptor', ' '.join(row.unsupported_reasons))
            failed_row = decode(failed(command=command, argument=argument, fd=U64, error=9)).operations[0]
            self.assertEqual((failed_row.status, failed_row.request.fd), ('kernel-error', -1))
            self.assertIsNone(failed_row.rule)

    def test_noncanonical_fd_or_command_words_have_no_repaired_interpretation(self):
        for fd, command in ((U32, 2), (7, U32)):
            row = decode(failed(command=command, argument=1, fd=fd)).operations[0]
            self.assertEqual(row.status, 'unsupported')
            self.assertIn('canonical typing', ' '.join(row.unsupported_reasons))
            self.assertIsNone(row.rule)
            self.assertTrue(row.request.entry_attempt_observed)
        row = decode(failed(command=2, argument=1, fd=U32)).operations[0]
        self.assertEqual(row.request.attempt_kind, 'descriptor-flag-change-attempt')
        self.assertTrue(row.request.requested_cloexec)

    def test_secondary_result_is_checked_and_preserved_for_every_scalar_command(self):
        for command, argument, result, _, _, _ in GOLDEN_COMMANDS:
            for secondary, typed in ((1, 1), (U64, -1)):
                row = decode(call(command=command, argument=argument, result=result, secondary=secondary)).operations[0]
                self.assertEqual((row.status, row.outcome.secondary_result), ('unsupported', typed))
                self.assertIn('secondary', ' '.join(row.unsupported_reasons))
                self.assertIsNone(row.rule)

    def test_status_flags_pointer_and_unknown_commands_remain_unmodeled(self):
        for command in (3, 4, 5, 7, 8, 9, 36, 64, 0x10000, INT_MAX, U64):
            report = decode(call(command=command, argument=U64, result=0))
            row = report.operations[0]
            self.assertEqual((row.status, row.request.operation, row.request.argument_role,
                              row.request.attempt_kind),
                             ('unsupported', None, 'unmodeled', 'unmodeled-fcntl-command'))
            self.assertEqual(row.request.argument, -1)
            self.assertIsNone(row.rule)
            self.assertTrue(row.request.entry_attempt_observed)
            self.assertEqual(report.counts.unhandled_command_pairs, 1)

    def test_setfl_partial_change_and_rollback_gap_is_explicit(self):
        row = decode(failed(command=4, argument=1)).operations[0]
        self.assertEqual(row.status, 'unsupported')
        self.assertEqual(row.outcome.kernel_error, 13)
        self.assertIn('shared flags before driver ioctl failure or partial rollback',
                      ' '.join(row.effect_uncertainties))
        self.assertIsNone(row.rule)

    def test_non_fcntl_bsd_calls_never_acquire_descriptor_command_permission(self):
        for name in ('close', 'write', 'future_fs_operation'):
            row = decode(call(name=name)).operations[0]
            self.assertFalse(row.request.is_fcntl)
            self.assertEqual((row.status, row.request.operation, row.request.attempt_kind),
                             ('unsupported', None, 'unmodeled-bsd-attempt'))
            self.assertIsNone(row.rule)

    def test_failures_and_control_flow_never_infer_no_effect_or_state_rule(self):
        for command, argument, _, _, _, _ in GOLDEN_COMMANDS:
            row = decode(failed(command=command, argument=argument, error=5)).operations[0]
            self.assertEqual(row.status, 'kernel-error')
            self.assertIn('not an absence-of-effects', ' '.join(row.effect_uncertainties))
            self.assertIsNone(row.rule)
        for returned in ((U64, U64, U64, U64, U64), (0, 0, 0, U64 - 1, U64 - 1),
                         (0, 1, 0, 0, 0), (U64, U64, U64, 2, 3)):
            row = decode(call(command=2, returned=returned)).operations[0]
            self.assertEqual(row.status, 'unsupported')
            self.assertEqual(row.request.attempt_kind, 'descriptor-flag-change-attempt')
            self.assertIsNone(row.rule)

    def test_mach_pairs_and_lifecycle_remain_retained_with_original_pair_indices(self):
        mach = [frame(15, words=(0,) * 8), frame(16, words=(0,))]
        report = decode(mach + call() + mach + failed())
        self.assertEqual([row.source_pair_index for row in report.operations], [1, 3])
        self.assertEqual((report.counts.bsd_pairs, report.counts.uninterpreted_mach_pairs,
                          report.counts.source_consistent_successes, report.counts.interpreted_kernel_errors),
                         (2, 2, 1, 1))
        self.assertEqual([phase.raw_scalars[0] for phase in report.source.lifecycle], [1, 11, 18, 17])

    def test_mach_only_input_stays_incomplete_without_fabricated_commands(self):
        report = decode([frame(15, words=(0,) * 8), frame(16, words=(0,))])
        self.assertEqual(report.operations, ())
        self.assertEqual((report.counts.bsd_pairs, report.counts.uninterpreted_mach_pairs), (0, 1))
        self.assertEqual(report.status, 'incomplete')
        self.assertFalse(report.full_trace_acceptance)

    def test_flags_are_descriptor_specific_and_query_is_not_a_slot_at_return_assertion(self):
        report = decode()
        rule = report.operations[0].rule
        self.assertEqual(rule.affected_scope, 'kernel-chosen-fileproc-descriptor-entry')
        self.assertIsNone(rule.ofd_relation)
        self.assertIn('kernel lookup', ' '.join(rule.required_witnesses))
        self.assertIn('slot-at-return', ' '.join(rule.required_witnesses))
        self.assertFalse(report.successful_effect_ordering)

    def test_numeric_stdio_fds_have_no_output_or_native_acceptance_exemption(self):
        for fd in (0, 1, 2, 7):
            report = decode(call(fd=fd, command=2, argument=1, result=0))
            self.assertEqual(report.operations[0].request.fd, fd)
            self.assertFalse(report.native_abi_calibrated)
            self.assertFalse(report.state_feed_eligible)
            self.assertFalse(report.full_trace_acceptance)
            self.assertIn('application-output', ' '.join(report.missing_capabilities))

    def test_nested_immutability_and_detached_serialization(self):
        report = decode()
        for obj, key in ((report, 'status'), (report.operations[0], 'status'),
                         (report.operations[0].request, 'fd'), (report.operations[0].rule, 'kind'),
                         (report.operations[0].outcome, 'disposition'), (report.counts, 'bsd_pairs')):
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

    def test_single_strict_pairing_pass_without_reconsuming_through_public_helpers(self):
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

    def test_orphan_unpaired_and_mismatched_input_refuse_before_semantics(self):
        for body in ([frame(2, name='fcntl', words=(0,) * 8)],
                     [frame(3, name='fcntl', words=(0,) * 5)],
                     [frame(2, name='fcntl', words=(0,) * 8), frame(3, name='close', words=(0,) * 5)]):
            with patch.object(B, '_decode_operation', side_effect=AssertionError('no prefix')) as decoder:
                with self.assertRaises(B.RawValidationError):
                    decode(body)
                decoder.assert_not_called()

    def test_late_malformed_event_produces_no_command_prefix(self):
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

    def test_no_asset_descriptor_subprocess_or_network_access_after_import(self):
        with patch('builtins.open', side_effect=AssertionError('file access')), \
             patch.object(Path, 'open', side_effect=AssertionError('path access')), \
             patch.object(os, 'open', side_effect=AssertionError('descriptor access')), \
             patch.object(subprocess, 'run', side_effect=AssertionError('process access')), \
             patch.object(socket, 'socket', side_effect=AssertionError('network access')), \
             patch.object(urllib.request, 'urlopen', side_effect=AssertionError('URL access')), \
             patch.object(B._RAW._CONTRACT_HELPERS, 'load_table', side_effect=AssertionError('asset fallback')):
            report = decode()
            report.to_dict()
            self.assertEqual(report.counts.fcntl_pairs, 1)

    def test_caller_profiles_constants_and_predecoded_assertions_are_not_inputs(self):
        for kwargs in ({'source': decode().source}, {'native_abi_calibrated': True},
                       {'profile': 'caller-selected'}, {'command_constants': {}}, {'state_feed_eligible': True}):
            with self.assertRaises(TypeError):
                decode(**kwargs)


if __name__ == '__main__':
    unittest.main()
