"""Independent serialized provider vectors; no native producer or state engine."""
import copy
from dataclasses import FrozenInstanceError
import hashlib
import json
import os
import socket
import subprocess
import urllib.request
from pathlib import Path
import struct
import unittest
from unittest.mock import patch

import bsd_outcomes as B

OWNER, TARGET, TID = 3131, 4242, 700
U64 = (1 << 64) - 1
INT_MAX = (1 << 31) - 1
CONTRACT = (Path(__file__).parent.parent / 'syscall-contract' / 'contracts.json').read_bytes()
# Independently serialized fixed program, copied from reviewed transport controls.
# Neither the native producer nor the validator's generator constructs this data.
PROGRAM = b'#pragma D option quiet\nBEGIN { watched[4242]=1;trace((uint64_t)1);trace((uint64_t)timestamp);trace((uint64_t)pid);trace((uint64_t)tid);trace((uint64_t)(0));}\nEND {trace((uint64_t)17);trace((uint64_t)timestamp);trace((uint64_t)pid);trace((uint64_t)tid);trace((uint64_t)(0));}\nsyscall:::entry /watched[pid]/ {trace((uint64_t)2);trace((uint64_t)timestamp);trace((uint64_t)pid);trace((uint64_t)tid);trace((uint64_t)(ppid));trace((uint64_t)arg0);trace((uint64_t)arg1);trace((uint64_t)arg2);trace((uint64_t)arg3);trace((uint64_t)arg4);trace((uint64_t)arg5);trace((uint64_t)arg6);trace((uint64_t)arg7);}\nsyscall:::return /watched[pid]/ {trace((uint64_t)3);trace((uint64_t)timestamp);trace((uint64_t)pid);trace((uint64_t)tid);trace((uint64_t)(ppid));trace((uint64_t)arg0);trace((uint64_t)arg1);trace((uint64_t)arg2);trace((uint64_t)arg3);trace((uint64_t)errno);}\nmach_trap:::entry /watched[pid]/ {trace((uint64_t)15);trace((uint64_t)timestamp);trace((uint64_t)pid);trace((uint64_t)tid);trace((uint64_t)(ppid));trace((uint64_t)arg0);trace((uint64_t)arg1);trace((uint64_t)arg2);trace((uint64_t)arg3);trace((uint64_t)arg4);trace((uint64_t)arg5);trace((uint64_t)arg6);trace((uint64_t)arg7);}\nmach_trap:::return /watched[pid]/ {trace((uint64_t)16);trace((uint64_t)timestamp);trace((uint64_t)pid);trace((uint64_t)tid);trace((uint64_t)(ppid));trace((uint64_t)arg0);}\nproc:::create /watched[pid]/ {watched[pid]=1;trace((uint64_t)4);trace((uint64_t)timestamp);trace((uint64_t)pid);trace((uint64_t)tid);trace((uint64_t)(args[0]->pr_pid));}\nproc:::start /watched[pid]/ {watched[pid]=1;trace((uint64_t)5);trace((uint64_t)timestamp);trace((uint64_t)pid);trace((uint64_t)tid);trace((uint64_t)(ppid));}\nproc:::exec-success /watched[pid]/ {watched[pid]=1;trace((uint64_t)7);trace((uint64_t)timestamp);trace((uint64_t)pid);trace((uint64_t)tid);trace((uint64_t)(ppid));}\nproc:::exit /watched[pid]/ {trace((uint64_t)6);trace((uint64_t)timestamp);trace((uint64_t)pid);trace((uint64_t)tid);trace((uint64_t)(arg0));}\nproc:::exec-failure /watched[pid]/ {trace((uint64_t)8);trace((uint64_t)timestamp);trace((uint64_t)pid);trace((uint64_t)tid);trace((uint64_t)(arg0));}\nproc:::lwp-create /watched[pid]/ {trace((uint64_t)9);trace((uint64_t)timestamp);trace((uint64_t)pid);trace((uint64_t)tid);trace((uint64_t)(args[0]->pr_lwpid));}\nproc:::lwp-start /watched[pid]/ {trace((uint64_t)10);trace((uint64_t)timestamp);trace((uint64_t)pid);trace((uint64_t)tid);trace((uint64_t)(0));}\nproc:::lwp-exit /watched[pid]/ {trace((uint64_t)11);trace((uint64_t)timestamp);trace((uint64_t)pid);trace((uint64_t)tid);trace((uint64_t)(0));}\nproc:::spawn-success /watched[pid]/ {trace((uint64_t)12);trace((uint64_t)timestamp);trace((uint64_t)pid);trace((uint64_t)tid);trace((uint64_t)(0));}\nproc:::spawn-failure /watched[pid]/ {trace((uint64_t)13);trace((uint64_t)timestamp);trace((uint64_t)pid);trace((uint64_t)tid);trace((uint64_t)(arg0));}\nproc:::exited /watched[args[0]->pr_pid]/ {trace((uint64_t)18);trace((uint64_t)timestamp);trace((uint64_t)pid);trace((uint64_t)tid);trace((uint64_t)(args[0]->pr_pid));trace((uint64_t)arg1);trace((uint64_t)args[0]->pr_addr);trace((uint64_t)((struct proc *)args[0]->pr_addr)->p_refcount);}\n'

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
SHAPES = {1: (56, True), 2: (120, False), 3: (96, False), 4: (56, True),
          5: (56, True), 6: (56, False), 7: (56, True), 8: (56, False),
          9: (56, False), 10: (56, False), 11: (56, False),
          12: (56, False), 13: (56, False), 15: (120, False),
          16: (64, False), 17: (56, False), 18: (80, False)}

# Independent literal roster, transcribed from pinned declarations; expectations
# are not obtained from the decoder's table or selected through its return type.
INT_NAMES = '''__mac_execve __mac_get_file __mac_get_link __mac_get_mount
__mac_mount __mac_set_fd __mac_set_file __mac_set_link __pthread_chdir
__pthread_fchdir access access_extended aio_cancel aio_error aio_fsync aio_read
aio_suspend aio_suspend_nocancel aio_write bind change_fdguard_np chdir chflags
chmod chmod_extended chown chroot clonefileat close close_nocancel connect
connect_nocancel connectx copyfile delete dup dup2 exchangedata execve faccessat
fchdir fchflags fchmod fchmod_extended fchmodat fchown fchownat fclonefileat fcntl
fcntl_nocancel ffsctl fhopen fileport_makefd fileport_makeport fmount fremovexattr
fs_snapshot fsctl fsetattrlist fsetxattr fstatat fstatat64 fsync fsync_nocancel
ftruncate funmount futimes getattrlist getattrlistat graftdmg guarded_close_np
guarded_open_dprotected_np guarded_open_np ioctl kevent kevent64 kevent_id
kevent_qos lchown link linkat lio_listio lstat lstat64 lstat_extended madvise
map_with_linking_np mincore mkdir mkdir_extended mkdirat mkfifo mkfifo_extended
mkfifoat mknod mknodat mount mprotect mremap_encrypted msync msync_nocancel munmap
open open_dprotected_np open_extended open_nocancel openat openat_dprotected_np
openat_nocancel openbyid_np pathconf posix_spawn readlink readlinkat recvmsg
recvmsg_nocancel removexattr rename renameat renameatx_np revoke rmdir sem_unlink
sendfile sendmsg sendmsg_nocancel setattrlist setattrlistat setxattr shm_open
shm_unlink stat stat64 stat_extended symlink symlinkat truncate undelete ungraftdmg
unlink unlinkat unmount utimes'''.split()
SSIZE_NAMES = '''aio_return getxattr guarded_pwrite_np guarded_write_np
guarded_writev_np listxattr pwrite pwrite_nocancel pwritev pwritev_nocancel
recvmsg_x sendmsg_x write write_nocancel writev writev_nocancel'''.split()
ADDR_NAMES = ['mmap', 'sem_open']


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


def call(name='open', words=(3, 3, 0, 0, 0), arguments=(0,) * 8):
    return [frame(2, name=name, words=arguments), frame(3, name=name, words=words)]


def fixture(body=None):
    body = call() if body is None else body
    return [frame(1), *copy.deepcopy(body), frame(11), frame(18), frame(17)]


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
        raw_index = 1 + int(SHAPES[row['kind']][1])
        row['records'][raw_index]['hex'] = struct.pack('<Q', row['timestamp']).hex()
    inventory = ''.join(str(number) + '\t' + '\t'.join(names) + '\n'
                        for number, names in probes.items()).encode('ascii')
    lines = [json.dumps(row, separators=(',', ':')).encode('ascii') + b'\n' for row in records]
    return inventory, lines


def decode(body=None, *, records=None, **kwargs):
    probes, lines = inputs(fixture(body) if records is None else records)
    return B.decode_owned_bsd_outcomes(kwargs.pop('program', PROGRAM),
        kwargs.pop('probes', probes), kwargs.pop('errors', b''),
        kwargs.pop('event_lines', lines), owner_pid=kwargs.pop('owner_pid', OWNER),
        target_pid=kwargs.pop('target_pid', TARGET),
        contract_bytes=kwargs.pop('contract_bytes', CONTRACT), **kwargs)


def result_for(name, primary, secondary=0, error=0):
    return decode(call(name, (primary, primary, secondary, error, error))).outcomes[0]


class OutcomeControls(unittest.TestCase):
    def test_all_161_declarations_use_independent_literal_return_roster(self):
        expected = [(name, 'int') for name in INT_NAMES]
        expected += [(name, 'user_ssize_t') for name in SSIZE_NAMES]
        expected += [(name, 'user_addr_t') for name in ADDR_NAMES]
        self.assertEqual((len(INT_NAMES), len(SSIZE_NAMES), len(ADDR_NAMES)), (143, 16, 2))
        self.assertEqual(len({name for name, _ in expected}), 161)
        self.assertEqual({row['name'] for row in json.loads(CONTRACT)['calls']},
                         {name for name, _ in expected})
        body = [phase for name, _ in expected for phase in call(name, (7, 7, 0, 0, 0))]
        result = decode(body)
        self.assertEqual(len(result.outcomes), 161)
        for row, (name, return_type) in zip(result.outcomes, expected):
            self.assertEqual((row.source_name, row.return_type, row.disposition,
                row.primary_result, row.secondary_result, row.kernel_error),
                (name, return_type, 'kernel-success', 7, 0, 0))
            pair = result.source.pairs[row.source_pair_index]
            self.assertEqual(row.correlation_id, pair.correlation_id)
            self.assertEqual(pair.entry.function, name)

    def test_signed32_primary_and_secondary_boundaries(self):
        for value in (-(1 << 31), -1, 0, INT_MAX):
            bits = value % (1 << 64)
            row = result_for('pathconf', bits, bits)
            self.assertEqual((row.disposition, row.primary_result, row.secondary_result),
                             ('kernel-success', value, value))

    def test_signed32_noncanonical_widening_is_not_truncated(self):
        for primary, secondary in ((1 << 31, 0), (0xffffffff, 0), (1 << 63, 0),
                                   (0, 0xffffffff), (0, U64 - (1 << 31))):
            with self.subTest(primary=primary, secondary=secondary):
                row = result_for('open', primary, secondary)
                self.assertEqual(row.disposition, 'unsupported')
                self.assertIn('signed32', row.unsupported_reason)
                self.assertIsNone(row.primary_result)

    def test_ssize_signed64_boundaries_and_zero_secondary(self):
        for bits, value in ((0, 0), (1 << 63, -(1 << 63)), (U64, -1),
                            ((1 << 63) - 1, (1 << 63) - 1)):
            row = result_for('aio_return', bits)
            self.assertEqual((row.disposition, row.primary_result, row.secondary_result),
                             ('kernel-success', value, 0))

    def test_addresses_retain_full_unsigned64_bits_without_validity_claim(self):
        for value in (0, 1 << 31, 1 << 63, U64):
            row = result_for('mmap', value)
            self.assertEqual((row.disposition, row.primary_result), ('kernel-success', value))
        self.assertFalse(decode(call('mmap')).state_feed_eligible)

    def test_nonzero_secondary_for_lp64_64bit_results_is_unsupported(self):
        for name in ('write', 'sem_open'):
            for secondary in (1, U64):
                row = result_for(name, 7, secondary)
                self.assertEqual(row.disposition, 'unsupported')
                self.assertIn('secondary', row.unsupported_reason)

    def test_positive_kernel_errors_include_private_codes_above_elast(self):
        for name in ('open', 'write', 'mmap'):
            for error in (1, 2, 107, 256, 512, INT_MAX):
                row = result_for(name, U64, U64, error)
                self.assertEqual((row.disposition, row.kernel_error), ('kernel-error', error))
                self.assertIsNone(row.primary_result)
                self.assertIsNone(row.secondary_result)
                self.assertIsNone(row.unsupported_reason)

    def test_kernel_error_requires_both_failure_result_words(self):
        for primary, secondary in ((0, 0), (0, U64), (U64, 0), (42, 42)):
            row = result_for('open', primary, secondary, 2)
            self.assertEqual(row.disposition, 'unsupported')
            self.assertIn('all-ones', row.unsupported_reason)
            self.assertIsNone(row.kernel_error)

    def test_provider_duplication_and_errno_disagreement_remain_unsupported(self):
        for words in ((3, 4, 0, 0, 0), (U64, U64, U64, 2, 3)):
            result = decode(call('open', words))
            row = result.outcomes[0]
            self.assertEqual(row.disposition, 'unsupported')
            self.assertIsNone(result.source.pairs[0].returned.returned)
            self.assertTrue(row.unsupported_reason)
            self.assertEqual(result.counts.unsupported, 1)

    def test_successful_minus_one_is_distinct_from_kernel_failure(self):
        for name in ('pathconf', 'aio_return'):
            successful = result_for(name, U64)
            failed = result_for(name, U64, U64, 2)
            self.assertEqual((successful.disposition, successful.primary_result,
                              successful.kernel_error), ('kernel-success', -1, 0))
            self.assertEqual((failed.disposition, failed.primary_result,
                              failed.kernel_error), ('kernel-error', None, 2))

    def test_restart_and_justreturn_never_become_ordinary_outcomes(self):
        for name in ('open', 'write', 'mmap'):
            for error, primary, control in ((U64, U64, 'ERESTART'),
                                            (U64 - 1, 0, 'EJUSTRETURN')):
                row = result_for(name, primary, primary, error)
                self.assertEqual((row.disposition, row.control_flow), ('unsupported', control))
                self.assertIsNone(row.kernel_error)
                self.assertIsNone(row.primary_result)
                self.assertIn('control flow', row.unsupported_reason)

    def test_malformed_pseudo_error_frames_retain_control_code_and_gap(self):
        for error, primary in ((U64, 0), (U64 - 1, U64)):
            row = result_for('open', primary, primary, error)
            self.assertEqual(row.disposition, 'unsupported')
            self.assertIsNotNone(row.control_flow)
            self.assertIn('differ', row.unsupported_reason)

    def test_other_negative_or_noncanonical_kernel_codes_are_not_errno(self):
        for error in (U64 - 4, U64 - 5, U64 - 6, U64 - 7, U64 - 107,
                      1 << 31, 0xffffffff, 1 << 63):
            row = result_for('open', U64, U64, error)
            self.assertEqual(row.disposition, 'unsupported')
            self.assertIsNone(row.kernel_error)
            self.assertIsNone(row.control_flow)
            self.assertIn('kernel return code', row.unsupported_reason)

    def test_unknown_call_retains_its_original_pair_without_interpretation(self):
        result = decode(call('future_fs_operation', (9, 9, 0, 0, 0)))
        row = result.outcomes[0]
        self.assertEqual((row.source_name, row.return_type, row.disposition),
                         ('future_fs_operation', None, 'unsupported'))
        self.assertFalse(result.source.pairs[0].entry.source_contract_known)
        self.assertEqual(result.source.pairs[0].returned.raw_scalars[5:], (9, 9, 0, 0, 0))

    def test_mach_pairs_and_lifecycle_stay_retained_and_uninterpreted(self):
        mach = [frame(15, words=(0,) * 8), frame(16, words=(0,))]
        result = decode(mach + call() + mach + call('write', (4, 4, 0, 0, 0)))
        self.assertEqual([row.source_pair_index for row in result.outcomes], [1, 3])
        self.assertEqual((result.counts.bsd_pairs, result.counts.kernel_successes,
                          result.counts.uninterpreted_mach_pairs), (2, 2, 2))
        self.assertEqual([phase.raw_scalars[0] for phase in result.source.lifecycle], [1, 11, 18, 17])
        self.assertEqual(result.source.pairs[0].entry.raw_scalars[0], 15)

    def test_mach_only_stream_has_no_invented_bsd_success(self):
        result = decode([frame(15, words=(0,) * 8), frame(16, words=(0,))])
        self.assertEqual(result.outcomes, ())
        self.assertEqual((result.counts.bsd_pairs, result.counts.kernel_successes,
                          result.counts.uninterpreted_mach_pairs), (0, 0, 1))
        self.assertEqual(result.status, 'incomplete')

    def test_mixed_counts_do_not_suppress_failed_or_unsupported_attempts(self):
        body = call('open', (3, 3, 0, 0, 0))
        body += call('write', (U64, U64, U64, 13, 13), (2, 0x1234, 20, 0, 0, 0, 0, 0))
        body += call('future_fs_operation', (0, 0, 0, 0, 0))
        result = decode(body)
        self.assertEqual((result.counts.kernel_successes, result.counts.kernel_errors,
                          result.counts.unsupported), (1, 1, 1))
        self.assertEqual(dict(result.source.pairs[1].entry.entry.fields)['fd'], 2)
        self.assertEqual(result.source.pairs[1].entry.entry.requirements,
                         ('fd-generation', 'open-file-description-object', 'rights-and-output-policy'))
        self.assertFalse(result.successful_effect_ordering)

    def test_no_descriptor_stdio_or_output_exemption_is_manufactured(self):
        for fd in (0, 1, 2, 7):
            result = decode(call('write', (1, 1, 0, 0, 0), (fd, 0, 1, 0, 0, 0, 0, 0)))
            self.assertEqual(result.outcomes[0].disposition, 'kernel-success')
            self.assertFalse(result.state_feed_eligible)
            self.assertIn('application-output object binding and extraction policy resolution',
                          result.missing_capabilities)

    def test_every_result_remains_incomplete_and_not_native_state_or_acceptance(self):
        result = decode()
        self.assertEqual(result.protocol, 'darwin-owned-bsd-outcomes-v1')
        self.assertEqual(result.status, 'incomplete')
        self.assertFalse(result.native_abi_calibrated)
        self.assertFalse(result.successful_effect_ordering)
        self.assertFalse(result.state_feed_eligible)
        self.assertFalse(result.full_trace_acceptance)
        self.assertEqual(result.source_commit, 'f6217f891ac0bb64f3d375211650a4c1ff8ca1ea')
        self.assertEqual(len(result.source_identities), 3)

    def test_all_nested_results_are_frozen_and_serialization_is_detached(self):
        result = decode()
        for item, key in ((result, 'status'), (result.outcomes[0], 'disposition'),
                          (result.counts, 'bsd_pairs'), (result.source.raw, 'events')):
            with self.assertRaises(FrozenInstanceError):
                setattr(item, key, 'changed')
        first = result.to_dict()
        first['outcomes'][0]['primary_result'] = 999
        first['source']['pairs'][0]['entry']['raw_scalars'][5] = 999
        first['source_identities'][0][1] = 'changed'
        second = result.to_dict()
        self.assertEqual(second['outcomes'][0]['primary_result'], 3)
        self.assertEqual(second['source']['pairs'][0]['entry']['raw_scalars'][5], 0)
        self.assertEqual(json.loads(json.dumps(second)), second)

    def test_exact_asset_and_static_transport_fail_before_event_consumption(self):
        def forbidden():
            raise AssertionError('events must not be consumed')
            yield b''
        for kwargs in ({'contract_bytes': CONTRACT + b'\n'},
                       {'contract_bytes': bytearray(CONTRACT)},
                       {'program': PROGRAM + b'\n'}, {'errors': b'bad\n'},
                       {'owner_pid': True}, {'target_pid': False}):
            with self.subTest(keys=list(kwargs)):
                with self.assertRaises(B.RawValidationError):
                    decode(event_lines=forbidden(), **kwargs)

    def test_orphan_mismatch_and_pending_calls_refuse_without_decoding(self):
        for body in ([frame(3, name='open', words=(0,) * 5)],
                     [frame(2, name='open', words=(0,) * 8)],
                     [frame(2, name='open', words=(0,) * 8),
                      frame(3, name='close', words=(0,) * 5)]):
            with patch.object(B, '_decode_pair', side_effect=AssertionError('no prefix')) as decoder:
                with self.assertRaises(B.RawValidationError):
                    decode(body)
                decoder.assert_not_called()

    def test_late_malformed_event_refuses_before_any_outcome_is_decoded(self):
        probes, lines = inputs(fixture())
        lines[-1] = b'{"late":"malformed"}\n'
        with patch.object(B, '_decode_pair', side_effect=AssertionError('no prefix')) as decoder:
            with self.assertRaises(B.RawValidationError):
                decode(probes=probes, event_lines=iter(lines))
            decoder.assert_not_called()

    def test_late_iterator_failure_propagates_before_decoding(self):
        probes, lines = inputs(fixture())
        class SourceFailure(RuntimeError):
            pass
        def broken():
            yield from lines
            raise SourceFailure('late source failure')
        with patch.object(B, '_decode_pair', side_effect=AssertionError('no prefix')) as decoder:
            with self.assertRaisesRegex(SourceFailure, 'late source'):
                decode(probes=probes, event_lines=broken())
            decoder.assert_not_called()

    def test_single_pass_source_is_completely_exhausted_before_decoding(self):
        probes, lines = inputs(fixture())
        done = []
        def once():
            yield from lines
            done.append(True)
        original = B._decode_pair
        def checked(*args):
            self.assertEqual(done, [True])
            return original(*args)
        with patch.object(B, '_decode_pair', side_effect=checked) as decoder:
            result = decode(probes=probes, event_lines=once())
            self.assertEqual(len(result.outcomes), 1)
            self.assertEqual(decoder.call_count, 1)

    def test_no_input_asset_process_or_network_access_after_import(self):
        with patch('builtins.open', side_effect=AssertionError('file access')), \
             patch.object(Path, 'open', side_effect=AssertionError('path access')), \
             patch.object(os, 'open', side_effect=AssertionError('descriptor access')), \
             patch.object(subprocess, 'run', side_effect=AssertionError('process access')), \
             patch.object(socket, 'socket', side_effect=AssertionError('network access')), \
             patch.object(urllib.request, 'urlopen', side_effect=AssertionError('URL access')), \
             patch.object(B._RAW._CONTRACT_HELPERS, 'load_table',
                          side_effect=AssertionError('asset fallback')):
            result = decode()
            result.to_dict()
            self.assertEqual(result.counts.kernel_successes, 1)

    def test_no_public_caller_assertion_or_predecoded_pair_input(self):
        with self.assertRaises(TypeError):
            decode(source=decode().source)
        with self.assertRaises(TypeError):
            decode(native_abi_calibrated=True)
        with self.assertRaises(TypeError):
            decode(profile='caller-selected')


if __name__ == '__main__':
    unittest.main()
