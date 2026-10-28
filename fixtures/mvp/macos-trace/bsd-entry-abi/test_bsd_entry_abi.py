"""Independent serialized entry vectors; no producer, pairing or native execution."""
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

import bsd_entry_abi as B

OWNER, TARGET, TID = 3131, 4242, 700
U64, U32 = (1 << 64) - 1, (1 << 32) - 1
INT_MAX = (1 << 31) - 1
CONTRACT = (Path(__file__).parent.parent / 'syscall-contract' / 'contracts.json').read_bytes()
# Literal fixed transport fixture; no production generator constructs it.
PROGRAM = b'#pragma D option quiet\nBEGIN { watched[4242]=1;trace((uint64_t)1);trace((uint64_t)timestamp);trace((uint64_t)pid);trace((uint64_t)tid);trace((uint64_t)(0));}\nEND {trace((uint64_t)17);trace((uint64_t)timestamp);trace((uint64_t)pid);trace((uint64_t)tid);trace((uint64_t)(0));}\nsyscall:::entry /watched[pid]/ {trace((uint64_t)2);trace((uint64_t)timestamp);trace((uint64_t)pid);trace((uint64_t)tid);trace((uint64_t)(ppid));trace((uint64_t)arg0);trace((uint64_t)arg1);trace((uint64_t)arg2);trace((uint64_t)arg3);trace((uint64_t)arg4);trace((uint64_t)arg5);trace((uint64_t)arg6);trace((uint64_t)arg7);}\nsyscall:::return /watched[pid]/ {trace((uint64_t)3);trace((uint64_t)timestamp);trace((uint64_t)pid);trace((uint64_t)tid);trace((uint64_t)(ppid));trace((uint64_t)arg0);trace((uint64_t)arg1);trace((uint64_t)arg2);trace((uint64_t)arg3);trace((uint64_t)errno);}\nmach_trap:::entry /watched[pid]/ {trace((uint64_t)15);trace((uint64_t)timestamp);trace((uint64_t)pid);trace((uint64_t)tid);trace((uint64_t)(ppid));trace((uint64_t)arg0);trace((uint64_t)arg1);trace((uint64_t)arg2);trace((uint64_t)arg3);trace((uint64_t)arg4);trace((uint64_t)arg5);trace((uint64_t)arg6);trace((uint64_t)arg7);}\nmach_trap:::return /watched[pid]/ {trace((uint64_t)16);trace((uint64_t)timestamp);trace((uint64_t)pid);trace((uint64_t)tid);trace((uint64_t)(ppid));trace((uint64_t)arg0);}\nproc:::create /watched[pid]/ {watched[pid]=1;trace((uint64_t)4);trace((uint64_t)timestamp);trace((uint64_t)pid);trace((uint64_t)tid);trace((uint64_t)(args[0]->pr_pid));}\nproc:::start /watched[pid]/ {watched[pid]=1;trace((uint64_t)5);trace((uint64_t)timestamp);trace((uint64_t)pid);trace((uint64_t)tid);trace((uint64_t)(ppid));}\nproc:::exec-success /watched[pid]/ {watched[pid]=1;trace((uint64_t)7);trace((uint64_t)timestamp);trace((uint64_t)pid);trace((uint64_t)tid);trace((uint64_t)(ppid));}\nproc:::exit /watched[pid]/ {trace((uint64_t)6);trace((uint64_t)timestamp);trace((uint64_t)pid);trace((uint64_t)tid);trace((uint64_t)(arg0));}\nproc:::exec-failure /watched[pid]/ {trace((uint64_t)8);trace((uint64_t)timestamp);trace((uint64_t)pid);trace((uint64_t)tid);trace((uint64_t)(arg0));}\nproc:::lwp-create /watched[pid]/ {trace((uint64_t)9);trace((uint64_t)timestamp);trace((uint64_t)pid);trace((uint64_t)tid);trace((uint64_t)(args[0]->pr_lwpid));}\nproc:::lwp-start /watched[pid]/ {trace((uint64_t)10);trace((uint64_t)timestamp);trace((uint64_t)pid);trace((uint64_t)tid);trace((uint64_t)(0));}\nproc:::lwp-exit /watched[pid]/ {trace((uint64_t)11);trace((uint64_t)timestamp);trace((uint64_t)pid);trace((uint64_t)tid);trace((uint64_t)(0));}\nproc:::spawn-success /watched[pid]/ {trace((uint64_t)12);trace((uint64_t)timestamp);trace((uint64_t)pid);trace((uint64_t)tid);trace((uint64_t)(0));}\nproc:::spawn-failure /watched[pid]/ {trace((uint64_t)13);trace((uint64_t)timestamp);trace((uint64_t)pid);trace((uint64_t)tid);trace((uint64_t)(arg0));}\nproc:::exited /watched[args[0]->pr_pid]/ {trace((uint64_t)18);trace((uint64_t)timestamp);trace((uint64_t)pid);trace((uint64_t)tid);trace((uint64_t)(args[0]->pr_pid));trace((uint64_t)arg1);trace((uint64_t)args[0]->pr_addr);trace((uint64_t)((struct proc *)args[0]->pr_addr)->p_refcount);}\n'
NAMES = {1: ('dtrace', '', '', 'BEGIN'), 17: ('dtrace', '', '', 'END'), 2: ('syscall', '', 'read', 'entry'), 3: ('syscall', '', 'read', 'return'), 15: ('mach_trap', '', 'mach_msg2_trap', 'entry'), 16: ('mach_trap', '', 'mach_msg2_trap', 'return'), 4: ('proc', 'mach_kernel', '', 'create'), 5: ('proc', '', '', 'start'), 6: ('proc', '', '', 'exit'), 7: ('proc', '', '', 'exec-success'), 8: ('proc', '', '', 'exec-failure'), 9: ('proc', '', '', 'lwp-create'), 10: ('proc', '', '', 'lwp-start'), 11: ('proc', '', '', 'lwp-exit'), 12: ('proc', '', '', 'spawn-success'), 13: ('proc', '', '', 'spawn-failure'), 18: ('proc', '', '', 'exited')}
SHAPES = {1: (56, True), 2: (120, False), 3: (96, False), 4: (56, True), 5: (56, True), 6: (56, False), 7: (56, True), 8: (56, False), 9: (56, False), 10: (56, False), 11: (56, False), 12: (56, False), 13: (56, False), 15: (120, False), 16: (64, False), 17: (56, False), 18: (80, False)}

# Independent per-declaration golden ABI classes for every argument position.
# S=signed32, U=unsigned32, L=signed64, V=unsigned64, A=opaque-address64.
# These are literal vectors, not runtime expectations derived from the decoder.
GOLDEN_CALLS = (
    ('__mac_execve', 'AAAA'),
    ('__mac_get_file', 'AA'),
    ('__mac_get_link', 'AA'),
    ('__mac_get_mount', 'AA'),
    ('__mac_mount', 'AASAA'),
    ('__mac_set_fd', 'SA'),
    ('__mac_set_file', 'AA'),
    ('__mac_set_link', 'AA'),
    ('__pthread_chdir', 'A'),
    ('__pthread_fchdir', 'S'),
    ('access', 'AS'),
    ('access_extended', 'AVAU'),
    ('aio_cancel', 'SA'),
    ('aio_error', 'A'),
    ('aio_fsync', 'SA'),
    ('aio_read', 'A'),
    ('aio_return', 'A'),
    ('aio_suspend', 'ASA'),
    ('aio_suspend_nocancel', 'ASA'),
    ('aio_write', 'A'),
    ('bind', 'SAU'),
    ('change_fdguard_np', 'SAUAUA'),
    ('chdir', 'A'),
    ('chflags', 'AS'),
    ('chmod', 'AS'),
    ('chmod_extended', 'AUUSA'),
    ('chown', 'ASS'),
    ('chroot', 'A'),
    ('clonefileat', 'SASAU'),
    ('close', 'S'),
    ('close_nocancel', 'S'),
    ('connect', 'SAU'),
    ('connect_nocancel', 'SAU'),
    ('connectx', 'SAUUAUAA'),
    ('copyfile', 'AASS'),
    ('delete', 'A'),
    ('dup', 'U'),
    ('dup2', 'UU'),
    ('exchangedata', 'AAV'),
    ('execve', 'AAA'),
    ('faccessat', 'SASS'),
    ('fchdir', 'S'),
    ('fchflags', 'SS'),
    ('fchmod', 'SS'),
    ('fchmod_extended', 'SUUSA'),
    ('fchmodat', 'SASS'),
    ('fchown', 'SSS'),
    ('fchownat', 'SAUUS'),
    ('fclonefileat', 'SSAU'),
    ('fcntl', 'SSL'),
    ('fcntl_nocancel', 'SSL'),
    ('ffsctl', 'SVAU'),
    ('fhopen', 'AS'),
    ('fileport_makefd', 'U'),
    ('fileport_makeport', 'SA'),
    ('fmount', 'ASSA'),
    ('fremovexattr', 'SAS'),
    ('fs_snapshot', 'USAAAU'),
    ('fsctl', 'AVAU'),
    ('fsetattrlist', 'SAAVV'),
    ('fsetxattr', 'SAAVUS'),
    ('fstatat', 'SAAS'),
    ('fstatat64', 'SAAS'),
    ('fsync', 'S'),
    ('fsync_nocancel', 'S'),
    ('ftruncate', 'SL'),
    ('funmount', 'SS'),
    ('futimes', 'SA'),
    ('getattrlist', 'AAAVV'),
    ('getattrlistat', 'SAAAVV'),
    ('getxattr', 'AAAVUS'),
    ('graftdmg', 'SAUA'),
    ('guarded_close_np', 'SA'),
    ('guarded_open_dprotected_np', 'AAUSSSS'),
    ('guarded_open_np', 'AAUSS'),
    ('guarded_pwrite_np', 'SAAVL'),
    ('guarded_write_np', 'SAAV'),
    ('guarded_writev_np', 'SAAS'),
    ('ioctl', 'SVA'),
    ('kevent', 'SASASA'),
    ('kevent64', 'SASASUA'),
    ('kevent_id', 'VASASAAU'),
    ('kevent_qos', 'SASASAAU'),
    ('lchown', 'AUU'),
    ('link', 'AA'),
    ('linkat', 'SASAS'),
    ('lio_listio', 'SASA'),
    ('listxattr', 'AAVS'),
    ('lstat', 'AA'),
    ('lstat64', 'AA'),
    ('lstat_extended', 'AAAA'),
    ('madvise', 'AVS'),
    ('map_with_linking_np', 'AUAU'),
    ('mincore', 'AVA'),
    ('mkdir', 'AS'),
    ('mkdir_extended', 'AUUSA'),
    ('mkdirat', 'SAS'),
    ('mkfifo', 'AS'),
    ('mkfifo_extended', 'AUUSA'),
    ('mkfifoat', 'SAS'),
    ('mknod', 'ASS'),
    ('mknodat', 'SASS'),
    ('mmap', 'AVSSSL'),
    ('mount', 'AASA'),
    ('mprotect', 'AVS'),
    ('mremap_encrypted', 'AVUUU'),
    ('msync', 'AVS'),
    ('msync_nocancel', 'AVS'),
    ('munmap', 'AV'),
    ('open', 'ASS'),
    ('open_dprotected_np', 'ASSSS'),
    ('open_extended', 'ASUUSA'),
    ('open_nocancel', 'ASS'),
    ('openat', 'SASS'),
    ('openat_dprotected_np', 'SASSSSS'),
    ('openat_nocancel', 'SASS'),
    ('openbyid_np', 'AAS'),
    ('pathconf', 'AS'),
    ('posix_spawn', 'AAAAA'),
    ('pwrite', 'SAVL'),
    ('pwrite_nocancel', 'SAVL'),
    ('pwritev', 'SASL'),
    ('pwritev_nocancel', 'SASL'),
    ('readlink', 'AAS'),
    ('readlinkat', 'SAAV'),
    ('recvmsg', 'SAS'),
    ('recvmsg_nocancel', 'SAS'),
    ('recvmsg_x', 'SAUS'),
    ('removexattr', 'AAS'),
    ('rename', 'AA'),
    ('renameat', 'SASA'),
    ('renameatx_np', 'SASAU'),
    ('revoke', 'A'),
    ('rmdir', 'A'),
    ('sem_open', 'ASSS'),
    ('sem_unlink', 'A'),
    ('sendfile', 'SSLAAS'),
    ('sendmsg', 'SAS'),
    ('sendmsg_nocancel', 'SAS'),
    ('sendmsg_x', 'SAUS'),
    ('setattrlist', 'AAAVV'),
    ('setattrlistat', 'SAAAVU'),
    ('setxattr', 'AAAVUS'),
    ('shm_open', 'ASS'),
    ('shm_unlink', 'A'),
    ('stat', 'AA'),
    ('stat64', 'AA'),
    ('stat_extended', 'AAAA'),
    ('symlink', 'AA'),
    ('symlinkat', 'ASA'),
    ('truncate', 'AL'),
    ('undelete', 'A'),
    ('ungraftdmg', 'AV'),
    ('unlink', 'A'),
    ('unlinkat', 'SAS'),
    ('unmount', 'AS'),
    ('utimes', 'AA'),
    ('write', 'SAV'),
    ('write_nocancel', 'SAV'),
    ('writev', 'SAU'),
    ('writev_nocancel', 'SAU'),
)
EXPECTED_CLASSES = {'S': 'signed32', 'U': 'unsigned32', 'L': 'signed64',
                    'V': 'unsigned64', 'A': 'opaque-address64'}

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


def entry(name='open', words=(0,) * 8):
    return frame(2, name=name, words=words)


def fixture(body=None):
    body = [entry()] if body is None else body
    return [frame(1), *body, frame(18), frame(17)]


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
    return B.decode_owned_bsd_entries(kwargs.pop('program', PROGRAM),
        kwargs.pop('probes', probes), kwargs.pop('errors', b''),
        kwargs.pop('event_lines', lines), owner_pid=kwargs.pop('owner_pid', OWNER),
        target_pid=kwargs.pop('target_pid', TARGET),
        contract_bytes=kwargs.pop('contract_bytes', CONTRACT), **kwargs)


def argument(name, index, word):
    words = [0] * 8
    words[index] = word
    return decode([entry(name, words)]).entries[0].arguments[index]


def role(entry_row, name):
    return next(arg for arg in entry_row.arguments if name in arg.roles)


def golden_value(letter, index):
    if letter == 'S':
        return U64 - index, -index - 1
    if letter == 'U':
        return U32 - index, U32 - index
    if letter == 'L':
        return (1 << 64) - (1 << 40) - index, -(1 << 40) - index
    if letter == 'V':
        return (1 << 63) + index, (1 << 63) + index
    return U64 - index * 256, U64 - index * 256


class EntryAbiControls(unittest.TestCase):
    def test_all_161_declarations_and_530_positions_match_literal_golden_vectors(self):
        self.assertEqual(len(GOLDEN_CALLS), 161)
        self.assertEqual(len({name for name, _ in GOLDEN_CALLS}), 161)
        self.assertEqual(sum(len(vector) for _, vector in GOLDEN_CALLS), 530)
        body = []
        for name, vector in GOLDEN_CALLS:
            words = [golden_value(letter, i)[0] for i, letter in enumerate(vector)]
            words += [0xabcdef0000000000 + i for i in range(len(words), 8)]
            body.append(entry(name, words))
        result = decode(body)
        self.assertEqual((result.counts.bsd_entries, result.counts.fully_typed_entries,
                          result.counts.declared_arguments, result.counts.typed_arguments), (161, 161, 530, 530))
        self.assertEqual(result.counts.unsupported_arguments, 0)
        self.assertEqual(dict(result.counts.abi_class_arguments), {
            'signed32': 189, 'unsigned32': 53, 'signed64': 11,
            'unsigned64': 35, 'opaque-address64': 242})
        spellings = set()
        for row, (name, vector) in zip(result.entries, GOLDEN_CALLS):
            phase = result.source.observations[row.phase_index]
            self.assertEqual((row.source_name, row.ordinal, row.status), (name, phase.ordinal, 'typed'))
            self.assertEqual(len(row.arguments), len(vector))
            for i, (arg, letter) in enumerate(zip(row.arguments, vector)):
                self.assertEqual((arg.argument_index, arg.abi_class, arg.value),
                                 (i, EXPECTED_CLASSES[letter], golden_value(letter, i)[1]))
                self.assertEqual(arg.unsupported_reason, None)
                self.assertEqual(phase.raw_scalars[5 + i], golden_value(letter, i)[0])
                spellings.add(arg.source_type)
        self.assertEqual(len(spellings), 49)

    def test_signed32_canonical_boundaries(self):
        for value in (-(1 << 31), -2, -1, 0, INT_MAX):
            arg = argument('openat', 0, value % (1 << 64))
            self.assertEqual((arg.abi_class, arg.width_bits, arg.signed, arg.value),
                             ('signed32', 32, True, value))

    def test_signed32_noncanonical_words_are_not_masked(self):
        for word in (1 << 31, U32, 1 << 32, 1 << 63, U64 - (1 << 31)):
            arg = argument('openat', 0, word)
            self.assertIsNone(arg.value)
            self.assertIn('sign-extended', arg.unsupported_reason)
            self.assertEqual((arg.width_bits, arg.signed), (32, True))

    def test_unsigned32_aliases_zero_extend_despite_signed_generator_casts(self):
        vectors = [('dup', 0, 'u_int'), ('connectx', 3, 'unsigned int'),
                   ('clonefileat', 4, 'uint32_t'), ('fchownat', 2, 'uid_t'),
                   ('fchownat', 3, 'gid_t'), ('connect', 2, 'socklen_t'),
                   ('fileport_makefd', 0, 'mach_port_name_t'),
                   ('connectx', 2, 'sae_associd_t')]
        for name, index, spelling in vectors:
            for word in (0, 1 << 31, U32):
                arg = argument(name, index, word)
                self.assertEqual((arg.source_type, arg.abi_class, arg.value, arg.signed),
                                 (spelling, 'unsigned32', word, False))
            for word in (1 << 32, U64):
                arg = argument(name, index, word)
                self.assertIsNone(arg.value)
                self.assertIn('zero-extended', arg.unsupported_reason)

    def test_signed64_long_and_offset_values_keep_full_width(self):
        for name, index, spelling in (('fcntl', 2, 'long'), ('mmap', 5, 'off_t')):
            for value in (-(1 << 63), -(1 << 40), -1, 0, (1 << 63) - 1):
                arg = argument(name, index, value % (1 << 64))
                self.assertEqual((arg.source_type, arg.abi_class, arg.value), (spelling, 'signed64', value))

    def test_unsigned64_size_and_integer_aliases_keep_high_bits(self):
        vectors = [('ioctl', 1, 'u_long'), ('fsetxattr', 3, 'size_t'),
                   ('mmap', 1, 'size_ut'), ('kevent_id', 0, 'uint64_t'),
                   ('pwrite', 2, 'user_size_t')]
        for name, index, spelling in vectors:
            for word in (0, 1 << 32, 1 << 63, U64):
                arg = argument(name, index, word)
                self.assertEqual((arg.source_type, arg.abi_class, arg.value),
                                 (spelling, 'unsigned64', word))

    def test_pointer_and_user_address_values_are_opaque_unmodified_bits(self):
        vectors = [('openat', 1, 'user_addr_t'), ('mmap', 0, 'caddr_ut'),
                   ('ioctl', 2, 'caddr_t'), ('__mac_get_file', 0, 'char *'),
                   ('__mac_execve', 1, 'char **'), ('symlinkat', 0, 'user_addr_t *'),
                   ('connectx', 7, 'sae_connid_t *')]
        for name, index, spelling in vectors:
            for word in (0, 0xff123456789abcde, U64):
                arg = argument(name, index, word)
                self.assertEqual((arg.source_type, arg.abi_class, arg.value),
                                 (spelling, 'opaque-address64', word))

    def test_dirfd_flags_mode_and_path_roles_preserve_exact_source_positions(self):
        result = decode([entry('openat', (U64 - 1, 0xfeedface, U64, 0x10000, 0, 0, 0, 0))])
        row = result.entries[0]
        self.assertEqual((role(row, 'dirfd').argument_index, role(row, 'dirfd').value), (0, -2))
        self.assertEqual((role(row, 'path').argument_index, role(row, 'path').value), (1, 0xfeedface))
        self.assertEqual((role(row, 'flags').argument_index, role(row, 'flags').value), (2, -1))
        self.assertEqual((role(row, 'mode').argument_index, role(row, 'mode').width_bits,
                          role(row, 'mode').value), (3, 32, 0x10000))

    def test_guarded_open_flags_are_distinct_from_guard_and_guardflags(self):
        result = decode([entry('guarded_open_np', (1, U64, U32, U64 - 1, 7, 0, 0, 0))])
        row = result.entries[0]
        self.assertEqual((role(row, 'guard').argument_index, role(row, 'guard').abi_class), (1, 'opaque-address64'))
        self.assertEqual((role(row, 'guardflags').argument_index, role(row, 'guardflags').value), (2, U32))
        self.assertEqual((role(row, 'flags').argument_index, role(row, 'flags').value), (3, -2))

    def test_sendfile_source_destination_and_offset_are_not_interchanged(self):
        row = decode([entry('sendfile', (3, 7, U64 - 7, 0x1234, 0x5678, 9, 0, 0))]).entries[0]
        self.assertEqual((role(row, 'source_fd').value, role(row, 'destination_fd').value), (3, 7))
        self.assertEqual((role(row, 'offset').argument_index, role(row, 'offset').value), (2, -8))
        self.assertEqual(role(row, 'length_pointer').abi_class, 'opaque-address64')

    def test_only_declared_arguments_are_typed_and_unused_words_stay_in_source(self):
        words = (U32, 10, 20, 30, 40, 50, 60, U64)
        result = decode([entry('dup', words)])
        self.assertEqual(len(result.entries[0].arguments), 1)
        self.assertEqual(result.entries[0].arguments[0].value, U32)
        self.assertEqual(result.source.observations[0].raw_scalars[5:], words)
        self.assertEqual(result.counts.declared_arguments, 1)

    def test_partial_unsupported_entry_keeps_other_arguments_and_raw_bits(self):
        result = decode([entry('openat', (U32, U64, 7, 8, 0, 0, 0, 0))])
        row = result.entries[0]
        self.assertEqual(row.status, 'unsupported')
        self.assertIsNone(row.arguments[0].value)
        self.assertEqual([arg.value for arg in row.arguments[1:]], [U64, 7, 8])
        self.assertEqual(result.source.observations[0].raw_scalars[5], U32)
        self.assertEqual((result.counts.typed_arguments, result.counts.unsupported_arguments,
                          result.counts.fully_typed_entries), (3, 1, 0))

    def test_failed_and_unpaired_attempts_are_not_removed_or_paired(self):
        body = [entry('open'), frame(3, name='open', words=(U64, U64, U64, 13, 13)),
                entry('write'), entry('close')]
        result = decode(body)
        self.assertEqual([row.source_name for row in result.entries], ['open', 'write', 'close'])
        self.assertEqual([row.phase_index for row in result.entries], [0, 2, 3])
        self.assertEqual(result.source.coverage.returns, 1)
        self.assertEqual(result.source.observations[1].returned.kernel_error_bits, 13)
        self.assertEqual(result.counts.fully_typed_entries, 3)

    def test_orphan_and_unsupported_returns_remain_visible_without_blocking_entries(self):
        body = [frame(3, name='open', words=(1, 2, 0, 0, 0)), entry('dup')]
        result = decode(body)
        self.assertIsNone(result.source.observations[0].returned)
        self.assertEqual(result.source.coverage.unsupported_return_shapes, 1)
        self.assertEqual(result.entries[0].phase_index, 1)
        self.assertEqual(result.entries[0].status, 'typed')

    def test_unknown_entry_retains_full_raw_words_without_invented_arguments(self):
        words = (U64,) * 8
        result = decode([entry('future_fs_operation', words)])
        row = result.entries[0]
        self.assertEqual((row.source_name, row.status, row.arguments), ('future_fs_operation', 'unsupported', ()))
        self.assertTrue(row.unsupported_reason)
        self.assertEqual(result.source.observations[0].raw_scalars[5:], words)
        self.assertEqual((result.counts.unknown_entries, result.counts.unsupported_entries), (1, 1))

    def test_empty_bsd_and_other_provider_counts_remain_explicit(self):
        result = decode([frame(15, words=(0,) * 8), frame(16, words=(0,))])
        self.assertEqual(result.entries, ())
        self.assertEqual(result.source.raw.event_kind_counts[15:17], (1, 1))
        self.assertEqual(result.source.raw.event_kind_counts[18], 1)
        self.assertEqual(result.counts.bsd_entries, 0)
        self.assertEqual(result.status, 'incomplete')

    def test_numeric_descriptors_flags_and_offsets_get_no_operation_policy(self):
        for fd in (0, 1, 2, U64):
            result = decode([entry('close', (fd, 0, 0, 0, 0, 0, 0, 0))])
            self.assertEqual(result.entries[0].arguments[0].value, -1 if fd == U64 else fd)
            self.assertFalse(result.state_feed_eligible)
            self.assertFalse(result.full_trace_acceptance)
        self.assertIn('process, cwd, image and descriptor-generation semantics', result.missing_capabilities)

    def test_every_result_stays_incomplete_without_native_calibration(self):
        result = decode()
        self.assertEqual(result.protocol, 'darwin-owned-bsd-entry-abi-v1')
        self.assertEqual(result.status, 'incomplete')
        self.assertFalse(result.native_abi_calibrated)
        self.assertFalse(result.state_feed_eligible)
        self.assertFalse(result.full_trace_acceptance)
        self.assertEqual(result.source_commit, 'f6217f891ac0bb64f3d375211650a4c1ff8ca1ea')
        self.assertEqual(len(result.source_identities), 19)

    def test_nested_results_are_frozen_and_serialization_has_no_mutable_alias(self):
        result = decode()
        for item, key in ((result, 'status'), (result.entries[0], 'status'),
                          (result.entries[0].arguments[0], 'value'),
                          (result.counts, 'bsd_entries'), (result.source.raw, 'events')):
            with self.assertRaises(FrozenInstanceError):
                setattr(item, key, 'changed')
        first = result.to_dict()
        first['entries'][0]['arguments'][0]['value'] = 999
        first['entries'][0]['arguments'][0]['roles'].append('invented')
        first['source']['observations'][0]['raw_scalars'][5] = 999
        second = result.to_dict()
        self.assertEqual(second['entries'][0]['arguments'][0]['value'], 0)
        self.assertNotIn('invented', second['entries'][0]['arguments'][0]['roles'])
        self.assertEqual(second['source']['observations'][0]['raw_scalars'][5], 0)
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

    def test_late_malformed_event_returns_no_typed_prefix(self):
        probes, lines = inputs(fixture())
        lines[-1] = b'{"late":"malformed"}\n'
        with patch.object(B, '_decode_entry', side_effect=AssertionError('no prefix')) as decoder:
            with self.assertRaises(B.RawValidationError):
                decode(probes=probes, event_lines=iter(lines))
            decoder.assert_not_called()

    def test_late_iterator_failure_propagates_before_any_typing(self):
        probes, lines = inputs(fixture())
        class SourceFailure(RuntimeError):
            pass
        def broken():
            yield from lines
            raise SourceFailure('late source failure')
        with patch.object(B, '_decode_entry', side_effect=AssertionError('no prefix')) as decoder:
            with self.assertRaisesRegex(SourceFailure, 'late source'):
                decode(probes=probes, event_lines=broken())
            decoder.assert_not_called()

    def test_single_pass_input_finishes_before_first_entry_is_typed(self):
        probes, lines = inputs(fixture())
        done = []
        def once():
            yield from lines
            done.append(True)
        original = B._decode_entry
        def checked(*args):
            self.assertEqual(done, [True])
            return original(*args)
        with patch.object(B, '_decode_entry', side_effect=checked) as decoder:
            result = decode(probes=probes, event_lines=once())
            self.assertEqual(len(result.entries), 1)
            self.assertEqual(decoder.call_count, 1)

    def test_no_input_asset_process_or_network_access_after_import(self):
        with patch('builtins.open', side_effect=AssertionError('file access')), \
             patch.object(Path, 'open', side_effect=AssertionError('path access')), \
             patch.object(os, 'open', side_effect=AssertionError('descriptor access')), \
             patch.object(subprocess, 'run', side_effect=AssertionError('process access')), \
             patch.object(socket, 'socket', side_effect=AssertionError('network access')), \
             patch.object(urllib.request, 'urlopen', side_effect=AssertionError('URL access')), \
             patch.object(B._RAW._CONTRACT_HELPERS, 'load_table', side_effect=AssertionError('asset fallback')):
            result = decode()
            result.to_dict()
            self.assertEqual(result.counts.bsd_entries, 1)

    def test_no_public_caller_profile_assertion_or_predecoded_input(self):
        for kwargs in ({'source': decode().source}, {'native_abi_calibrated': True},
                       {'profile': 'caller-selected'}):
            with self.assertRaises(TypeError):
                decode(**kwargs)


if __name__ == '__main__':
    unittest.main()
