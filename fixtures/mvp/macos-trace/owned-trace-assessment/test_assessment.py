"""Portable serialized controls; no provider, native producer or capture access."""
import builtins
import copy
from contextlib import ExitStack
from dataclasses import FrozenInstanceError
import hashlib
import importlib.machinery
import importlib.util
import io
import json
import os
from pathlib import Path
import shutil
import socket
import struct
import subprocess
import tempfile
import unittest
from unittest.mock import patch

import assessment as A

BASE = Path(__file__).resolve().parent.parent
CONTRACT = (BASE / 'syscall-contract/contracts.json').read_bytes()
OWNER, TARGET = 3131, 4242
U64 = (1 << 64) - 1
# Exact literal fixture, shared with the prior independent raw-reader controls.
# No collector/producer code is imported or used to generate serialized events.
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
PROBES = ''.join(str(100 + k) + '\t' + '\t'.join(NAMES[k]) + '\n'
                 for k in sorted(NAMES)).encode('ascii')


def event(kind, *, function=None, words=None, actor=None, detail=None, refcount=0x1c2):
    total, assignment = SHAPES[kind]
    actor = (OWNER if kind in (1, 17) else TARGET) if actor is None else actor
    if detail is None:
        detail = OWNER if kind in (2, 3, 5, 7, 15, 16) else TARGET if kind == 18 else 0
    scalars = [kind, 100, actor, 0xffeeddccbbaa, detail]
    if kind == 18:
        scalars += [U64, 0xabcdef123456, refcount]
    else:
        scalars += [0] * ((total - 56) // 8) if words is None else list(words)
    records = [{'action': 1, 'size': 0, 'offset': 12, 'hex': ''}] if assignment else []
    records += [{'action': 1, 'size': 8, 'offset': 16 + i * 8,
                 'hex': struct.pack('<Q', word).hex()} for i, word in enumerate(scalars)]
    row = dict(event=0, cpu=7, epid=1000 + kind, probe_id=100 + kind,
        record_bytes=total, header_record_indexes=list(range(int(assignment), int(assignment) + 5)),
        kind=kind, timestamp=scalars[1], pid=actor, tid=scalars[3], detail=detail,
        **dict(zip(('provider', 'module', 'function', 'name'), NAMES[kind])), records=records)
    if function is not None:
        row['function'] = function
    return row


def envelope(body=()):
    return [event(1), *body, event(18), event(17)]


def encode(records):
    return [json.dumps(dict(row, event=i), separators=(',', ':')).encode() + b'\n'
            for i, row in enumerate(records, 1)]


def inventory(records):
    # Assign distinct inventory identities for each BSD name and phase, preserving
    # every required kind even when it is unobserved. No runtime table is used.
    probes = dict((100 + k, names) for k, names in NAMES.items())
    ids = {names: probe for probe, names in probes.items()}
    for row in records:
        names = tuple(row[key] for key in ('provider', 'module', 'function', 'name'))
        if names not in ids:
            probe = max(probes) + 1
            probes[probe] = names
            ids[names] = probe
        row['probe_id'] = ids[names]
        row['epid'] = 10000 + ids[names]
    return ''.join(str(probe) + '\t' + '\t'.join(names) + '\n'
                   for probe, names in probes.items()).encode('ascii')


def assess(body=(), *, records=None, **kwargs):
    records = envelope(body) if records is None else copy.deepcopy(records)
    probes = inventory(records)
    return A.assess_owned_raw(kwargs.pop('program', PROGRAM), kwargs.pop('probes', probes),
        kwargs.pop('errors', b''), kwargs.pop('event_lines', encode(records)),
        owner_pid=kwargs.pop('owner_pid', OWNER), target_pid=kwargs.pop('target_pid', TARGET),
        contract_bytes=kwargs.pop('contract_bytes', CONTRACT), **kwargs)


# Independent expected selector vectors. Groups compact only identical source
# declarations; these literal positions are never derived from contracts.json,
# entry_facts or an assessment result. Eight distinct full-width words expose
# signed conversions, selector swaps and accidental pointer normalization.
EXPECTED_GROUPS = (
    ('spawn-or-exec', '__mac_execve', 'fname:0'),
    ('spawn-or-exec', 'execve', 'argv:1 envp:2 executable_path:0'),
    ('spawn-or-exec', 'posix_spawn', 'argv:3 envp:4 executable_path:1 pid_output:0 spawn_descriptor:2'),
    ('path-observation', '__mac_get_file __mac_get_link', 'path_p:0'),
    ('path-observation', '__mac_get_mount getattrlist getxattr listxattr lstat lstat64 lstat_extended pathconf readlink stat stat64 stat_extended', 'path:0'),
    ('path-observation', 'access', 'flags:1 path:0'),
    ('path-observation', 'faccessat fstatat fstatat64 getattrlistat readlinkat', 'dirfd:0 path:1'),
    ('opaque-control', '__mac_mount mount', 'data:3 filesystem_type:0 flags:2 mount_path:1'),
    ('opaque-control', 'access_extended', ''),
    ('opaque-control', 'ffsctl', 'argument:2 command:1 fd:0 options:3'),
    ('opaque-control', 'fmount', 'data:3 fd:1 filesystem_type:0 flags:2'),
    ('opaque-control', 'fs_snapshot', 'data:4 dirfd:1 flags:5 name1:2 name2:3 operation:0'),
    ('opaque-control', 'fsctl', 'argument:2 command:1 options:3 path:0'),
    ('opaque-control', 'funmount', 'fd:0 flags:1'),
    ('opaque-control', 'graftdmg', 'mountdir:1'),
    ('opaque-control', 'ioctl', 'argument:2 command:1 fd:0'),
    ('opaque-control', 'ungraftdmg', 'flags:1 mountdir:0'),
    ('opaque-control', 'unmount', 'flags:1 path:0'),
    ('fd-mutation', '__mac_set_fd fchmod fchmod_extended fchown fremovexattr fsetattrlist fsetxattr fsync fsync_nocancel ftruncate futimes guarded_pwrite_np guarded_write_np guarded_writev_np pwrite pwrite_nocancel pwritev pwritev_nocancel write write_nocancel writev writev_nocancel', 'fd:0'),
    ('fd-mutation', 'fchflags', 'fd:0 flags:1'),
    ('fd-mutation', 'sendfile', 'destination_fd:1 flags:5 headers_and_trailers:4 length_pointer:3 offset:2 source_fd:0'),
    ('path-mutation', '__mac_set_file __mac_set_link', 'path_p:0'),
    ('path-mutation', 'chflags', 'flags:1 path:0'),
    ('path-mutation', 'chmod chmod_extended chown delete lchown mkdir mkdir_extended mkfifo mkfifo_extended mknod removexattr revoke rmdir setattrlist setxattr truncate undelete unlink utimes', 'path:0'),
    ('path-mutation', 'fchmodat fchownat mkdirat mkfifoat mknodat setattrlistat unlinkat', 'dirfd:0 path:1'),
    ('path-mutation', 'clonefileat linkat renameatx_np', 'destination_dirfd:2 destination_path:3 flags:4 source_dirfd:0 source_path:1'),
    ('path-mutation', 'copyfile exchangedata link rename', 'destination_path:1 source_path:0'),
    ('path-mutation', 'fclonefileat', 'destination_dirfd:1 destination_path:2 flags:3 source_fd:0'),
    ('path-mutation', 'renameat', 'destination_dirfd:2 destination_path:3 source_dirfd:0 source_path:1'),
    ('path-mutation', 'symlink', 'literal_target:0 new_path:1'),
    ('path-mutation', 'symlinkat', 'dirfd:1 literal_target:0 new_path:2'),
    ('cwd-state', '__pthread_chdir chdir chroot', 'path:0'),
    ('cwd-state', '__pthread_fchdir fchdir', 'fd:0'),
    ('asynchronous', 'aio_cancel', 'aiocb:1 fd:0'),
    ('asynchronous', 'aio_error aio_read aio_return aio_write', 'aiocb:0'),
    ('asynchronous', 'aio_fsync', 'aiocb:1 operation:0'),
    ('asynchronous', 'aio_suspend aio_suspend_nocancel', 'aiocb_list:0 count:1 timeout:2'),
    ('asynchronous', 'kevent', 'fd:0'),
    ('asynchronous', 'kevent64', 'fd:0 flags:5'),
    ('asynchronous', 'kevent_id', 'flags:7'),
    ('asynchronous', 'kevent_qos', 'fd:0 flags:7'),
    ('asynchronous', 'lio_listio', 'aiocb_list:1 count:2 mode:0 signal:3'),
    ('rights-or-namespace', 'bind connect connect_nocancel', 's:0'),
    ('rights-or-namespace', 'connectx', 'flags:3'),
    ('rights-or-namespace', 'fileport_makefd', 'port:0'),
    ('rights-or-namespace', 'fileport_makeport', 'fd:0 port_output:1'),
    ('rights-or-namespace', 'recvmsg recvmsg_nocancel sendmsg sendmsg_nocancel', 'flags:2 s:0'),
    ('rights-or-namespace', 'recvmsg_x sendmsg_x', 'flags:3 s:0'),
    ('rights-or-namespace', 'sem_open sem_unlink shm_open shm_unlink', ''),
    ('fd-state', 'change_fdguard_np close close_nocancel dup guarded_close_np', 'fd:0'),
    ('fd-state', 'dup2', 'from:0 to:1'),
    ('fd-state', 'fcntl fcntl_nocancel', 'argument:2 command:1 fd:0'),
    ('indirect-open', 'fhopen', 'filehandle:0 flags:1'),
    ('indirect-open', 'openbyid_np', 'flags:2 fsid:0 objid:1'),
    ('open-request', 'guarded_open_dprotected_np', 'class:4 dpflags:5 flags:3 guard:1 guardflags:2 mode:6 path:0'),
    ('open-request', 'guarded_open_np', 'flags:3 guard:1 guardflags:2 mode:4 path:0'),
    ('open-request', 'open open_nocancel', 'flags:1 mode:2 path:0'),
    ('open-request', 'open_dprotected_np', 'class:2 dpflags:3 flags:1 mode:4 path:0'),
    ('open-request', 'open_extended', 'flags:1 gid:3 mode:4 path:0 security:5 uid:2'),
    ('open-request', 'openat openat_nocancel', 'dirfd:0 flags:2 mode:3 path:1'),
    ('open-request', 'openat_dprotected_np', 'authfd:6 class:3 dirfd:0 dpflags:4 flags:2 mode:5 path:1'),
    ('mapping', 'madvise map_with_linking_np mincore mremap_encrypted', ''),
    ('mapping', 'mmap', 'address:0 fd:4 flags:3 length:1 offset:5 protection:2'),
    ('mapping', 'mprotect', 'address:0 length:1 protection:2'),
    ('mapping', 'msync msync_nocancel', 'address:0 flags:2 length:1'),
    ('mapping', 'munmap', 'address:0 length:1'),
)
EXPECTED = {}
for family, names, selectors in EXPECTED_GROUPS:
    for name in names.split():
        assert name not in EXPECTED
        EXPECTED[name] = (family, tuple((role, int(index)) for role, index in
                                      (selector.split(':') for selector in selectors.split())))

FAMILY_COUNTS = {'asynchronous': 13, 'cwd-state': 5, 'fd-mutation': 24,
    'fd-state': 8, 'indirect-open': 2, 'mapping': 9, 'opaque-control': 12,
    'open-request': 9, 'path-mutation': 40, 'path-observation': 20,
    'rights-or-namespace': 16, 'spawn-or-exec': 3}
# Literal Darwin common flag positions, separately asserted from field vectors.
OPEN_POSITIONS = {'open': 1, 'open_nocancel': 1, 'open_dprotected_np': 1,
    'open_extended': 1, 'openat': 2, 'openat_nocancel': 2,
    'openat_dprotected_np': 2, 'guarded_open_np': 3,
    'guarded_open_dprotected_np': 3}
VECTOR = (U64, 1 << 63, (1 << 32) + 17, 0x7ffffffffffffffe,
          0x123456789abcdef0, 0xfeedface12345678, 0x100000000000002, 0xabcdef01abcdef02)


class AssessmentControls(unittest.TestCase):
    def assert_incomplete(self, result):
        self.assertEqual(result.status, 'incomplete')
        self.assertFalse(result.full_trace_acceptance)
        self.assertFalse(result.state_feed_eligible)
        self.assertFalse(result.source.full_trace_acceptance)
        self.assertEqual(result.missing_capabilities, A.MISSING_CAPABILITIES)
        self.assertEqual(len(result.missing_capabilities), 8)

    def test_all_161_declarations_independent_vectors_and_12_routes(self):
        self.assertEqual(len(EXPECTED), 161)
        body = [event(2, function=name, words=VECTOR) for name in EXPECTED]
        result = assess(body)
        self.assert_incomplete(result)
        self.assertEqual((result.coverage.bsd_entries, result.coverage.known_entries,
                          result.coverage.unknown_entries), (161, 161, 0))
        self.assertEqual(dict(result.coverage.source_family_entries), FAMILY_COUNTS)
        self.assertEqual(len(A.REQUEST_CATEGORIES), 13)
        self.assertEqual(sum(dict(result.coverage.request_category_entries).values()), 161)
        table = {call['name']: call for call in json.loads(CONTRACT)['calls']}
        self.assertEqual(set(table), set(EXPECTED))
        for index, row in enumerate(result.requests):
            with self.subTest(name=row.source_name):
                family, selectors = EXPECTED[row.source_name]
                self.assertEqual(row.phase_index, index)
                self.assertEqual(row.ordinal, index + 2)
                self.assertEqual(row.family, family)
                self.assertIn(row.category, A.REQUEST_CATEGORIES)
                self.assertNotEqual(row.category, 'unsupported-bsd-request')
                phase = result.source.observations[row.phase_index]
                self.assertEqual(phase.entry.fields, tuple((role, VECTOR[i]) for role, i in selectors))
                self.assertEqual(phase.entry.raw_words, VECTOR)
                self.assertEqual(phase.raw_scalars[5:], VECTOR)
                self.assertEqual(phase.entry.requirements, tuple(table[row.source_name]['requirements']))
                self.assertTrue(phase.entry.entry_attempt_observed)
                self.assertIn('source requirements remain unresolved', row.unresolved_reasons)

    def test_all_nine_flag_slots_only_selected_word_and_variant_requirements(self):
        body = []
        for name, slot in OPEN_POSITIONS.items():
            words = list(VECTOR)
            words[slot] = 2 | 512  # O_RDWR | O_CREAT, no ABI narrowing elsewhere.
            body.append(event(2, function=name, words=words))
        result = assess(body)
        for row in result.requests:
            phase = result.source.observations[row.phase_index]
            self.assertEqual(row.open_flags.raw_word, 514)
            self.assertEqual(row.open_flags.intent, 'write-request')
            self.assertEqual(row.open_flags.write_reasons, ('write-access', 'O_CREAT'))
            self.assertTrue(phase.entry.requirements)
            self.assertIn('object binding and application-output policy unresolved', row.unresolved_reasons)
            # Every other selected source field is still the original uint64.
            for role, index in EXPECTED[row.source_name][1]:
                self.assertEqual(dict(phase.entry.fields)[role], 514 if role == 'flags' else VECTOR[index])
        self.assert_incomplete(result)

    def test_common_flag_intents_and_unsupported_reasons_are_preserved(self):
        cases = ((0, 'read-access-request', (), 0, 0),
                 (1, 'write-request', ('write-access',), 0, 0),
                 (8, 'write-request', ('O_APPEND',), 0, 0),
                 (512 | 1024, 'write-request', ('O_CREAT', 'O_TRUNC'), 0, 0),
                 (32768, 'event-access-request', (), 0, 0),
                 (3, 'unsupported', (), 0, 0),
                 (32769, 'unsupported', ('write-access',), 0, 0),
                 (0x80000000, 'unsupported', (), 0x80000000, 0x80000000),
                 (128, 'unsupported', (), 128, 0),
                 ((1 << 32) - 1, 'unsupported', ('O_APPEND', 'O_CREAT', 'O_TRUNC'),
                  ((1 << 32) - 1) & ~A._OPEN.MODELED, ((1 << 32) - 1) & ~A._OPEN.KNOWN))
        for flags, intent, reasons, unmodeled, unknown in cases:
            with self.subTest(flags=flags):
                result = assess([event(2, function='open', words=(7, flags, 0, 0, 0, 0, 0, 0))])
                fact = result.requests[0].open_flags
                self.assertEqual((fact.intent, fact.write_reasons, fact.unmodeled_bits, fact.unknown_bits),
                                 (intent, reasons, unmodeled, unknown))
                self.assertEqual(fact.unsupported_reason is not None, intent == 'unsupported')
                self.assert_incomplete(result)
        sync = assess([event(2, function='open', words=(7, 128, 0, 0, 0, 0, 0, 0))])
        self.assertEqual(sync.requests[0].open_flags.unmodeled_sdk_flags, ('O_SYNC',))

    def test_high_flag_bits_never_masked_or_sign_extended(self):
        for flags in (1 << 32, (1 << 32) | 514, U64, 0xffffffff80000001):
            with self.subTest(flags=flags), patch.object(A._OPEN, 'classify_flags',
                    side_effect=AssertionError('noncanonical flags reached classifier')):
                result = assess([event(2, function='open', words=(7, flags, 0, 0, 0, 0, 0, 0))])
                fact = result.requests[0].open_flags
                self.assertEqual((fact.raw_word, fact.intent, fact.write_reasons), (flags, 'unsupported', ()))
                self.assertIsNone(fact.unknown_bits)
                self.assertIsNone(fact.unmodeled_bits)
                self.assertIn('no truncation', fact.unsupported_reason)

    def test_failed_or_unpaired_entries_and_orphan_returns_remain_visible(self):
        body = [event(3, function='open', words=(9, 9, 0, 0, 0)),
                event(2, function='open', words=(7, 513, 0, 0, 0, 0, 0, 0)),
                event(3, function='open', words=(U64, U64, U64, 13, 13)),
                event(2, function='write', words=(1, 7, 9, 0, 0, 0, 0, 0))]
        result = assess(body)
        self.assertEqual([r.phase_index for r in result.requests], [1, 3])
        self.assertEqual(result.requests[0].open_flags.intent, 'write-request')
        self.assertEqual(result.requests[1].category, 'fd-operation-request')
        self.assertEqual(result.coverage.supported_return_shapes, 2)
        self.assertEqual(result.source.observations[2].returned.kernel_error_bits, 13)
        # The strict pairer's narrower route must not control this entry API.
        records = envelope(body)
        with self.assertRaises(A.RawValidationError):
            A._RAW.pair_raw_owned(PROGRAM, inventory(records), b'', encode(records),
                owner_pid=OWNER, target_pid=TARGET, contract_bytes=CONTRACT)
        self.assert_incomplete(result)

    def test_unknown_calls_and_unsupported_return_shapes_retained(self):
        result = assess([event(2, function='read', words=VECTOR),
            event(2, function='aio_writev', words=VECTOR),
            event(3, function='open', words=(1, 2, 3, 4, 5)),
            event(3, function='unknown', words=(U64, U64, 0, U64, U64))])
        self.assertEqual((result.coverage.unknown_entries, result.coverage.bsd_returns,
                          result.coverage.unsupported_return_shapes,
                          result.coverage.control_flow_unmodeled_returns), (2, 2, 1, 1))
        self.assertEqual(dict(result.coverage.unknown_names), {'read': 1, 'aio_writev': 1, 'unknown': 1})
        self.assertEqual([r.category for r in result.requests], ['unsupported-bsd-request'] * 2)
        self.assertEqual(result.source.observations[2].raw_scalars[5:], (1, 2, 3, 4, 5))
        self.assertIsNotNone(result.source.observations[2].unsupported_reason)
        self.assertIsNone(result.requests[0].family)
        self.assertIsNone(result.requests[0].open_flags)

    def test_fd_family_never_means_payload_write_or_standard_stream_permission(self):
        names = ('fsync', 'sendfile', 'write', 'fcntl', 'ioctl', 'aio_read', 'stat', 'mmap')
        result = assess([event(2, function=name, words=VECTOR) for name in names])
        self.assertEqual([r.category for r in result.requests[:3]], ['fd-operation-request'] * 3)
        self.assertIn('flush and transfer', result.requests[0].unresolved_reasons[0])
        self.assertIn('no harmless-read authorization', result.requests[6].unresolved_reasons[0])
        for fd in (0, 1, 2, U64):
            report = assess([event(2, function='write', words=(fd, 7, 9, 0, 0, 0, 0, 0))])
            self.assertEqual(dict(report.source.observations[0].entry.fields), {'fd': fd})
            self.assert_incomplete(report)

    def test_symlink_literals_two_bases_and_mapping_objects_not_converted(self):
        result = assess([event(2, function=name, words=VECTOR)
                         for name in ('symlink', 'symlinkat', 'renameat', 'mmap', 'fhopen', 'shm_open')])
        entries = [result.source.observations[row.phase_index].entry for row in result.requests]
        self.assertEqual(dict(entries[0].fields), {'literal_target': VECTOR[0], 'new_path': VECTOR[1]})
        self.assertEqual(dict(entries[1].fields), {'dirfd': VECTOR[1], 'literal_target': VECTOR[0], 'new_path': VECTOR[2]})
        self.assertEqual(dict(entries[2].fields)['destination_dirfd'], VECTOR[2])
        self.assertEqual(dict(entries[3].fields)['fd'], VECTOR[4])
        self.assertIsNone(result.requests[4].open_flags)
        self.assertEqual(entries[5].fields, ())  # no invented shm_open selector

    def test_zero_bsd_mach_and_every_permitted_lifecycle_count_explicit(self):
        result = assess([event(k) for k in (5, 6, 7, 8, 9, 10, 11, 15, 16)])
        self.assertEqual(result.requests, ())
        self.assertEqual((result.coverage.bsd_entries, result.coverage.bsd_returns,
                          result.coverage.mach_entries, result.coverage.mach_returns), (0, 0, 1, 1))
        self.assertEqual(dict(result.coverage.source_family_entries), {k: 0 for k in FAMILY_COUNTS})
        self.assertEqual(result.coverage.lifecycle_kind_counts,
            ((4, 'create', 0), (5, 'start', 1), (6, 'exit', 1), (7, 'exec-success', 1),
             (8, 'exec-failure', 1), (9, 'lwp-create', 1), (10, 'lwp-start', 1),
             (11, 'lwp-exit', 1), (12, 'spawn-success', 0), (13, 'spawn-failure', 0), (18, 'exited', 1)))
        self.assertEqual((result.coverage.begin_records, result.coverage.end_records), (1, 1))
        self.assert_incomplete(result)
        self.assert_incomplete(assess())

    def test_shadow_exec_and_post_terminal_cleanup_do_not_erase_entries(self):
        records = [event(1), event(7), event(8), event(18, refcount=0x1e2),
                   event(2, function='open', words=(7, 512, 0, 0, 0, 0, 0, 0)),
                   event(18, actor=9876), event(11), event(17)]
        result = assess(records=records)
        self.assertEqual(len(result.requests), 1)
        self.assertEqual((result.source.raw.shadow_exits, result.source.raw.post_terminal_lwp_exits), (1, 1))
        self.assertEqual(result.requests[0].open_flags.write_reasons, ('O_CREAT',))
        self.assert_incomplete(result)

    def test_full_source_observation_exactly_equal_once_and_immutable_serialization(self):
        records = envelope([event(2, function='open', words=(7, 514, 0, 0, 0, 0, 0, 0)),
                            event(3, function='open', words=(U64, U64, 0, 13, 13))])
        probes = inventory(records)
        expected = A._RAW.observe_raw_bsd(PROGRAM, probes, b'', encode(records),
            owner_pid=OWNER, target_pid=TARGET, contract_bytes=CONTRACT)
        with patch.object(A._RAW, 'observe_raw_bsd', return_value=expected) as observe:
            result = A.assess_owned_raw(PROGRAM, probes, b'', encode(records),
                owner_pid=OWNER, target_pid=TARGET, contract_bytes=CONTRACT)
        self.assertEqual(result.source, expected)
        self.assertEqual(observe.call_count, 1)
        self.assertIs(result.source, expected)
        for obj, field, value in ((result, 'status', 'clean'),
                (result.requests[0], 'family', 'other'), (result.requests[0].open_flags, 'intent', 'allowed'),
                (result.source.observations[0].entry, 'fields', ()),
                (result.coverage, 'bsd_entries', 0)):
            with self.assertRaises(FrozenInstanceError):
                setattr(obj, field, value)
        first = result.to_dict()
        first['source']['observations'][0]['entry']['fields'][0][1] = 0
        first['requests'][0]['open_flags']['write_reasons'].append('fabricated')
        first['coverage']['source_family_entries'][0][1] = 99
        second = result.to_dict()
        self.assertEqual(second['source']['observations'][0]['entry']['fields'][0], ['flags', 514])
        self.assertEqual(second['requests'][0]['open_flags']['write_reasons'], ['write-access', 'O_CREAT'])
        self.assertEqual(second['coverage']['source_family_entries'][0][1], 0)
        self.assertEqual(json.loads(json.dumps(second)), second)
        self.assertNotIn('no_output_policy', second['requests'][0]['open_flags'])

    def test_assessment_and_serialization_do_no_runtime_io_or_helper_loading(self):
        records = envelope([event(2, function='open', words=(7, 514, 0, 0, 0, 0, 0, 0))])
        probes, lines = inventory(records), encode(records)
        def refuse(*_args, **_kwargs):
            raise AssertionError('runtime I/O or helper load')
        with ExitStack() as stack:
            for obj, name in ((builtins, 'open'), (io, 'open'), (io, 'open_code'),
                (os, 'open'), (Path, 'open'), (Path, 'read_bytes'),
                (importlib.util, 'spec_from_file_location'),
                (importlib.machinery.SourceFileLoader, 'get_code'),
                (importlib.machinery.SourceFileLoader, 'exec_module'),
                (A._RAW, '_contract_helpers'), (A._RAW._CONTRACT_HELPERS, 'load_table'),
                (subprocess, 'Popen'), (socket, 'socket')):
                stack.enter_context(patch.object(obj, name, refuse))
            result = A.assess_owned_raw(PROGRAM, probes, b'', iter(lines),
                owner_pid=OWNER, target_pid=TARGET, contract_bytes=CONTRACT)
            self.assertEqual(result.to_dict()['status'], 'incomplete')
            self.assertEqual(result.requests[0].open_flags.intent, 'write-request')

    def test_complete_phase_bound_exact_and_one_over(self):
        result = assess([event(2, function='open', words=(7, 0, 0, 0, 0, 0, 0, 0))] * 4096)
        self.assertEqual((len(result.requests), len(result.source.observations)), (4096, 4096))
        self.assert_incomplete(result)
        with self.assertRaisesRegex(A.RawValidationError, 'BSD phase projection bound'):
            assess([event(2, function='open', words=(7, 0, 0, 0, 0, 0, 0, 0))] * 4097)

    def test_late_transport_corruption_and_iterator_failure_return_no_prefix(self):
        records = envelope([event(2, function='open', words=(7, 514, 0, 0, 0, 0, 0, 0))])
        probes = inventory(records)
        good = encode(records)
        bad_lines = (good[:-1], good + [b'{}\n'], good[:-1] + [good[-1][:-1]],
                     good[:-1] + [b'{"event": 4, "event": 4}\n'])
        for lines in bad_lines:
            with self.subTest(lines=len(lines)), self.assertRaises(A.RawValidationError):
                A.assess_owned_raw(PROGRAM, probes, b'', iter(lines),
                    owner_pid=OWNER, target_pid=TARGET, contract_bytes=CONTRACT)
        class TailFailure(RuntimeError):
            pass
        def late_failure():
            yield from good
            raise TailFailure('failure after END')
        with self.assertRaisesRegex(TailFailure, 'after END'):
            A.assess_owned_raw(PROGRAM, probes, b'', late_failure(),
                owner_pid=OWNER, target_pid=TARGET, contract_bytes=CONTRACT)

    def test_static_contract_program_and_error_refusals_never_touch_stream(self):
        class Untouched:
            def __iter__(self):
                raise AssertionError('stream touched before static refusal')
        for kwargs in ({'contract_bytes': bytearray(CONTRACT)}, {'contract_bytes': CONTRACT + b'\n'},
                       {'program': PROGRAM + b'\n'}, {'errors': b'error\n'}, {'target_pid': OWNER}):
            with self.subTest(kwargs=list(kwargs)), self.assertRaises(A.RawValidationError):
                assess(event_lines=Untouched(), **kwargs)
        # The API accepts original bytes only, never caller validation assertions.
        with self.assertRaises(TypeError):
            A.assess_owned_raw(raw_facts=assess().source.raw)

    def test_import_preflights_exact_dependencies_before_any_helper_execution(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary) / 'trace'
            folder = root / 'owned-trace-assessment'
            folder.mkdir(parents=True)
            module_path = folder / 'assessment.py'
            shutil.copyfile(Path(__file__).with_name('assessment.py'), module_path)
            for relative, digest in A.DEPENDENCY_IDENTITIES:
                path = root / relative
                path.parent.mkdir(exist_ok=True)
                shutil.copyfile(BASE / relative, path)
                self.assertEqual(hashlib.sha256(path.read_bytes()).hexdigest(), digest)
            # contracts.json is deliberately absent: import cannot need it.
            spec = importlib.util.spec_from_file_location('_assessment_copy', module_path)
            copied = importlib.util.module_from_spec(spec)
            spec.loader.exec_module(copied)
            self.assertEqual(copied.DEPENDENCY_IDENTITIES, A.DEPENDENCY_IDENTITIES)
            for relative, _digest in A.DEPENDENCY_IDENTITIES:
                path = root / relative
                original = path.read_bytes()
                for missing in (False, True):
                    with self.subTest(relative=relative, missing=missing):
                        path.unlink() if missing else path.write_bytes(original + b'\n')
                        spec = importlib.util.spec_from_file_location('_assessment_bad', module_path)
                        failed = importlib.util.module_from_spec(spec)
                        # If any helper begins loading, this is an incomplete
                        # dependency preflight even when upstream modules are warm.
                        with patch.object(importlib.util, 'spec_from_file_location',
                                side_effect=AssertionError('helper import before exact closure')), \
                                self.assertRaises((ValueError, OSError)):
                            spec.loader.exec_module(failed)
                        path.write_bytes(original)


if __name__ == '__main__':
    unittest.main()
