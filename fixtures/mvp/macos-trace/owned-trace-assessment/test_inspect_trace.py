"""Synthetic standalone inspector controls; never native capture/admission."""
from contextlib import redirect_stderr, redirect_stdout
import hashlib
import io
import json
import os
from pathlib import Path
import stat
import struct
import subprocess
import sys
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch

import inspect_trace as I

OWNER, TARGET = 3131, 4242
# Independently held literal program and serialized record shapes. No producer,
# native packet, admission helper or existing control module is imported.
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
PROBES = ''.join(str(100 + kind) + '\t' + '\t'.join(names) + '\n'
                 for kind, names in sorted(NAMES.items())).encode('ascii')


def event(kind, ordinal):
    assignment = kind == 1
    actor = OWNER if kind in (1, 17) else TARGET
    scalars = [kind, 100, actor, 0xffeeddccbbaa, TARGET if kind == 18 else 0]
    if kind == 18:
        scalars += [(1 << 64) - 1, 0xabcdef123456, 0x1c2]
    records = [{'action': 1, 'size': 0, 'offset': 12, 'hex': ''}] if assignment else []
    records += [{'action': 1, 'size': 8, 'offset': 16 + i * 8,
                 'hex': struct.pack('<Q', word).hex()} for i, word in enumerate(scalars)]
    return (json.dumps(dict(event=ordinal, cpu=7, epid=1000 + kind,
        probe_id=100 + kind, record_bytes=80 if kind == 18 else 56,
        header_record_indexes=list(range(int(assignment), int(assignment) + 5)),
        kind=kind, timestamp=100, pid=actor, tid=scalars[3], detail=scalars[4],
        **dict(zip(('provider', 'module', 'function', 'name'), NAMES[kind])),
        records=records), separators=(',', ':')) + '\n').encode('ascii')


EVENTS = event(1, 1) + event(18, 2) + event(17, 3)
CONTENTS = {'program.d': PROGRAM, 'probes.tsv': PROBES,
            'errors.jsonl': b'', 'events.jsonl': EVENTS}
CLI = Path(__file__).with_name('inspect_trace.py')


class InspectorControls(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory(prefix='glue-inspector-synthetic-')
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name) / 'diagnostic'
        self.root.mkdir(mode=0o700)
        for name, data in CONTENTS.items():
            self.write(name, data)

    def write(self, name, data):
        path = self.root / name
        path.write_bytes(data)
        path.chmod(0o600)
        return path

    def inspect(self):
        return I.inspect_directory(self.root, owner_pid=OWNER, target_pid=TARGET)

    def refuse(self):
        with self.assertRaises((I.InspectorError, OSError, ValueError)):
            self.inspect()

    def cli(self, *extra):
        return subprocess.run([sys.executable, str(CLI), '--input', str(self.root),
            '--owner-pid', str(OWNER), '--target-pid', str(TARGET), *extra],
            stdout=subprocess.PIPE, stderr=subprocess.PIPE, check=False)

    def test_synthetic_report_binds_complete_files_and_is_never_admission(self):
        result = self.inspect()
        self.assertEqual(result['protocol'], 'darwin-owned-trace-diagnostic-v1')
        self.assertEqual(result['origin'], 'caller-supplied/unverified')
        self.assertEqual(result['status'], 'incomplete')
        for key in ('native_admission', 'export_admission',
                    'full_trace_acceptance', 'state_feed_eligible'):
            self.assertIs(result[key], False)
        self.assertEqual(result['declared_pids'], {'owner_pid': OWNER, 'target_pid': TARGET})
        self.assertEqual(set(result['input_files']), set(CONTENTS))
        for name, data in CONTENTS.items():
            self.assertEqual(result['input_files'][name]['byte_count'], len(data))
            self.assertEqual(result['input_files'][name]['sha256'], hashlib.sha256(data).hexdigest())
        self.assertEqual(result['assessment']['status'], 'incomplete')
        self.assertEqual(result['assessment']['source']['raw']['events'], 3)
        self.assertEqual(result['assessment']['coverage']['bsd_entries'], 0)
        self.assertFalse(result['assessment']['full_trace_acceptance'])
        self.assertFalse(result['assessment']['state_feed_eligible'])
        self.assertTrue(result['source_identities'])

    def test_cli_success_is_canonical_json_and_invalid_input_has_no_stdout(self):
        completed = self.cli()
        self.assertEqual(completed.returncode, 0, completed.stderr)
        report = json.loads(completed.stdout)
        canonical = (json.dumps(report, sort_keys=True, separators=(',', ':'),
                                ensure_ascii=True) + '\n').encode('ascii')
        self.assertEqual(completed.stdout, canonical)
        self.assertEqual(completed.stderr, b'')
        self.write('events.jsonl', EVENTS + b'not-json\n')
        failed = self.cli()
        self.assertEqual(failed.returncode, 1)
        self.assertEqual(failed.stdout, b'')
        self.assertLess(len(failed.stderr), 1024)
        self.assertNotIn(b'not-json', failed.stderr)

    def test_import_and_acceptance_refusal_are_lazy_before_arguments_or_input(self):
        code = ('import builtins, importlib.util, sys; '
                'original = builtins.open; '
                'import inspect_trace as I; '
                'assert "assessment" not in sys.modules; '
                'I._load_assessment = lambda: (_ for _ in ()).throw(AssertionError("loaded")); '
                'I.os.open = lambda *a, **k: (_ for _ in ()).throw(AssertionError("opened")); '
                'raise SystemExit(I.main(["--acceptance"]))')
        completed = subprocess.run([sys.executable, '-c', code], cwd=CLI.parent,
            stdout=subprocess.PIPE, stderr=subprocess.PIPE, check=False)
        self.assertEqual(completed.returncode, 1, completed.stderr)
        self.assertEqual(completed.stdout, b'')
        self.assertNotIn(b'loaded', completed.stderr)
        self.assertNotIn(b'opened', completed.stderr)
        for argv in ([], ['--unknown'], ['--input', str(self.root)],
                     ['--max-bytes', '4'], ['--source-hash', 'caller-value']):
            stdout, stderr = io.StringIO(), io.StringIO()
            with redirect_stdout(stdout), redirect_stderr(stderr):
                try:
                    status = I.main(argv)
                except SystemExit as exc:
                    status = exc.code
            self.assertEqual(status, 2)
            self.assertEqual(stdout.getvalue(), '')

    def test_privileged_and_real_effective_identity_mismatches_precede_input_access(self):
        base = {'getuid': 501, 'geteuid': 501, 'getgid': 20, 'getegid': 20}
        for override in ({'getuid': 0, 'geteuid': 0}, {'getuid': 0},
                         {'geteuid': 0}, {'getgid': 0, 'getegid': 0},
                         {'getuid': 502}, {'getegid': 21}):
            with self.subTest(override=override):
                values = dict(base, **override)
                with patch.multiple(I.os, **{key: lambda value=value: value
                                            for key, value in values.items()}), \
                     patch.object(I.os, 'open', side_effect=AssertionError('input opened')):
                    with self.assertRaises(I.InspectorError):
                        self.inspect()

    def test_foreign_root_and_leaf_ownership_are_rejected(self):
        root_fd = os.open(self.root, os.O_RDONLY | os.O_DIRECTORY)
        leaf_fd = os.open(self.root / 'program.d', os.O_RDONLY)
        original = I.os.fstat
        try:
            for fd, check in ((root_fd, lambda: I._check_root(self.root, root_fd)),
                              (leaf_fd, lambda: I._check_leaf(root_fd, 'program.d', leaf_fd))):
                info = original(fd)
                changed = {key: getattr(info, key) for key in dir(info) if key.startswith('st_')}
                changed['st_uid'] = os.getuid() + 1
                with self.subTest(fd=fd), patch.object(I.os, 'fstat', return_value=SimpleNamespace(**changed)):
                    with self.assertRaises(I.InspectorError):
                        check()
        finally:
            os.close(leaf_fd)
            os.close(root_fd)

    def test_special_mode_bits_are_rejected_even_if_chmod_would_clear_them(self):
        root_fd = os.open(self.root, os.O_RDONLY | os.O_DIRECTORY)
        leaf_fd = os.open(self.root / 'program.d', os.O_RDONLY)
        original = I.os.fstat
        try:
            for fd, check in ((root_fd, lambda: I._check_root(self.root, root_fd)),
                              (leaf_fd, lambda: I._check_leaf(root_fd, 'program.d', leaf_fd))):
                info = original(fd)
                for bit in (stat.S_ISUID, stat.S_ISGID):
                    changed = {key: getattr(info, key) for key in dir(info) if key.startswith('st_')}
                    changed['st_mode'] |= bit
                    with self.subTest(fd=fd, bit=bit), patch.object(I.os, 'fstat', return_value=SimpleNamespace(**changed)):
                        with self.assertRaises(I.InspectorError):
                            check()
        finally:
            os.close(leaf_fd)
            os.close(root_fd)

    def test_event_transport_cap_exact_and_one_over_without_retaining_stream(self):
        # Logical bytes use repeated literal bounded lines; no producer or giant
        # retained buffer supplies the reader. The real small-line boundary is
        # separately exercised against actual temporary files.
        for length in (134217728, 134217729):
            remaining = length
            def read(fd, size):
                nonlocal remaining
                if not remaining:
                    return b''
                count = min(size, remaining, 8191)
                remaining -= count
                return b'x' * (count - 1) + b'\n'
            total = 0
            with self.subTest(length=length), patch.object(I.os, 'read', side_effect=read):
                if length == 134217728:
                    for line in I._event_lines(123):
                        total += len(line)
                    self.assertEqual(total, length)
                else:
                    with self.assertRaises(I.InspectorError):
                        for line in I._event_lines(123):
                            total += len(line)

    def test_numeric_directory_and_leaf_modes_are_exact(self):
        for mode in (0o755, 0o750, 0o1700):
            with self.subTest(root_mode=mode):
                self.root.chmod(mode)
                self.refuse()
        self.root.chmod(0o700)
        for mode in (0o644, 0o400, 0o1600):
            with self.subTest(leaf_mode=mode):
                (self.root / 'program.d').chmod(mode)
                self.refuse()
        (self.root / 'program.d').chmod(0o600)
        self.assertEqual(self.inspect()['status'], 'incomplete')

    def test_root_symlink_and_nondirectory_are_refused(self):
        alias = self.root.parent / 'alias'
        alias.symlink_to(self.root, target_is_directory=True)
        for path in (alias, str(alias) + '/', str(alias) + '/.',
                     str(alias) + '/./', str(self.root) + '/.',
                     str(self.root) + '/..', str(self.root) + '/../', '', '.', '..'):
            with self.subTest(path=path), self.assertRaises((I.InspectorError, OSError, ValueError)):
                I.inspect_directory(path, owner_pid=OWNER, target_pid=TARGET)
        with self.assertRaises((I.InspectorError, OSError, ValueError)):
            I.inspect_directory(self.root / 'program.d', owner_pid=OWNER, target_pid=TARGET)

    def test_actual_fifo_symlink_hardlink_and_directory_leaves_are_refused(self):
        leaf = self.root / 'program.d'
        for kind in ('fifo', 'symlink', 'hardlink', 'directory'):
            with self.subTest(kind=kind):
                leaf.unlink()
                if kind == 'fifo':
                    os.mkfifo(leaf, 0o600)
                elif kind == 'symlink':
                    leaf.symlink_to(self.root / 'events.jsonl')
                elif kind == 'hardlink':
                    os.link(self.root / 'events.jsonl', leaf)
                else:
                    leaf.mkdir(mode=0o600)
                self.refuse()
                if leaf.is_dir():
                    leaf.rmdir()
                else:
                    leaf.unlink()
                self.write('program.d', PROGRAM)

    def test_exact_roster_missing_and_extra_entries_refuse(self):
        (self.root / 'errors.jsonl').unlink()
        self.refuse()
        self.write('errors.jsonl', b'')
        for name in ('sidecar.json', '.hidden'):
            extra = self.write(name, b'ignored')
            self.refuse()
            extra.unlink()

    def test_roster_scan_stops_at_fifth_entry(self):
        visited = []
        class Scan:
            def __enter__(self):
                return self
            def __exit__(self, *args):
                return False
            def close(self):
                pass
            def __iter__(self):
                for name in (*CONTENTS, 'extra', 'must-not-visit'):
                    visited.append(name)
                    if name == 'must-not-visit':
                        raise AssertionError('scanned past fifth entry')
                    yield type('Entry', (), {'name': name})()
        with patch.object(I.os, 'scandir', return_value=Scan()):
            with self.assertRaises(I.InspectorError):
                I._check_roster(123)
        self.assertEqual(len(visited), 5)

    def test_held_input_flags_and_anchored_leaf_opens(self):
        original = I.os.open
        seen = []
        def recording(path, flags, *args, **kwargs):
            if os.fspath(path) == str(self.root) or os.fspath(path) in CONTENTS:
                seen.append((os.fspath(path), flags, kwargs.get('dir_fd')))
            return original(path, flags, *args, **kwargs)
        with patch.object(I.os, 'open', side_effect=recording):
            self.inspect()
        self.assertEqual(len(seen), 5)
        root_call = next(row for row in seen if row[0] == str(self.root))
        self.assertTrue(root_call[1] & os.O_DIRECTORY)
        for name, flags, anchor in seen:
            for required in (os.O_NOFOLLOW, os.O_CLOEXEC, os.O_NONBLOCK):
                self.assertTrue(flags & required)
            if name in CONTENTS:
                self.assertIsInstance(anchor, int)

    def test_static_byte_caps_exact_and_one_over_use_bounded_reads(self):
        for cap in (16384, 1048576, 65536):
            with self.subTest(cap=cap):
                path = self.write('scratch', b'x' * cap)
                fd = os.open(path, os.O_RDONLY)
                try:
                    self.assertEqual(I._read_static(fd, cap), b'x' * cap)
                finally:
                    os.close(fd)
                path.write_bytes(b'x' * (cap + 1))
                fd = os.open(path, os.O_RDONLY)
                try:
                    with self.assertRaises(I.InspectorError):
                        I._read_static(fd, cap)
                finally:
                    os.close(fd)
                path.unlink()
        self.assertEqual((I.MAX_PROGRAM_BYTES, I.MAX_INVENTORY_BYTES, I.MAX_ERROR_BYTES,
                          I.MAX_RAW_BYTES, I.MAX_EVENT_BYTES, I.MAX_OUTPUT_BYTES),
                         (16384, 1048576, 65536, 134217728, 8191, 16777216))

    def test_event_line_cap_exact_one_over_and_unterminated_tail(self):
        for data, valid in ((b'x' * 8190 + b'\n', True),
                            (b'x' * 8191 + b'\n', False),
                            (b'x' * 8191, True), (b'x' * 8192, False)):
            with self.subTest(size=len(data), valid=valid):
                path = self.write('scratch', data)
                fd = os.open(path, os.O_RDONLY)
                try:
                    if valid:
                        self.assertEqual(b''.join(I._event_lines(fd)), data)
                    else:
                        with self.assertRaises(I.InspectorError):
                            list(I._event_lines(fd))
                finally:
                    os.close(fd)
                path.unlink()

    def test_static_semantic_failure_precedes_event_consumption(self):
        self.write('program.d', PROGRAM + b'corrupt')
        consumed = []
        def forbidden(fd):
            consumed.append(fd)
            raise AssertionError('events consumed')
            yield b''
        with patch.object(I, '_event_lines', side_effect=forbidden):
            self.refuse()
        self.assertEqual(consumed, [])

    def test_late_malformed_transport_returns_no_diagnostic(self):
        self.write('events.jsonl', EVENTS + b'{}\n')
        self.refuse()

    def test_read_failure_suppresses_report_and_closes_all_input_fds(self):
        real_open, real_read, real_close = I.os.open, I.os.read, I.os.close
        held, closed = {}, []
        def opening(path, flags, *args, **kwargs):
            fd = real_open(path, flags, *args, **kwargs)
            if os.fspath(path) == str(self.root) or os.fspath(path) in CONTENTS:
                held[fd] = os.fspath(path)
            return fd
        def reading(fd, size):
            if held.get(fd) == 'events.jsonl':
                raise OSError('synthetic read failure')
            return real_read(fd, size)
        def closing(fd):
            if fd in held:
                closed.append(fd)
            return real_close(fd)
        with patch.object(I.os, 'open', side_effect=opening), \
             patch.object(I.os, 'read', side_effect=reading), \
             patch.object(I.os, 'close', side_effect=closing):
            self.refuse()
        self.assertEqual(len(held), 5)
        self.assertCountEqual(closed, held)

    def test_close_failure_attempts_every_close_once_and_main_keeps_stdout_empty(self):
        real_open, real_close = I.os.open, I.os.close
        held, closed = {}, []
        def opening(path, flags, *args, **kwargs):
            fd = real_open(path, flags, *args, **kwargs)
            if os.fspath(path) == str(self.root) or os.fspath(path) in CONTENTS:
                held[fd] = os.fspath(path)
            return fd
        def closing(fd):
            is_input = fd in held
            if is_input:
                closed.append(fd)
            real_close(fd)
            if is_input and held[fd] == 'program.d':
                raise OSError('synthetic close failure')
        stdout, stderr = io.StringIO(), io.StringIO()
        with patch.object(I.os, 'open', side_effect=opening), \
             patch.object(I.os, 'close', side_effect=closing), \
             redirect_stdout(stdout), redirect_stderr(stderr):
            status = I.main(['--input', str(self.root), '--owner-pid', str(OWNER),
                             '--target-pid', str(TARGET)])
        self.assertEqual(status, 1)
        self.assertEqual(stdout.getvalue(), '')
        self.assertEqual(len(held), 5)
        self.assertCountEqual(closed, held)

    def test_leaf_replacement_after_read_and_root_rename_are_detected(self):
        original = I._read_static
        changed = []
        def replace_after_read(fd, cap):
            data = original(fd, cap)
            if cap == I.MAX_PROGRAM_BYTES and not changed:
                changed.append(True)
                (self.root / 'program.d').unlink()
                self.write('program.d', PROGRAM)
            return data
        with patch.object(I, '_read_static', side_effect=replace_after_read):
            self.refuse()
        moved = self.root.with_name('moved')
        changed.clear()
        def rename_after_read(fd, cap):
            data = original(fd, cap)
            if cap == I.MAX_PROGRAM_BYTES and not changed:
                changed.append(True)
                self.root.rename(moved)
                self.root.mkdir(mode=0o700)
                for name, value in CONTENTS.items():
                    self.write(name, value)
            return data
        with patch.object(I, '_read_static', side_effect=rename_after_read):
            self.refuse()

    def test_roster_change_after_read_is_detected(self):
        original = I._read_static
        changed = []
        def after(fd, cap):
            data = original(fd, cap)
            if cap == I.MAX_PROGRAM_BYTES and not changed:
                changed.append(True)
                self.write('extra-after-open', b'')
            return data
        with patch.object(I, '_read_static', side_effect=after):
            self.refuse()

    def test_fixed_source_loading_preflights_before_any_module_execution(self):
        original = I._trusted_bytes
        seen = []
        def recording(relative, size, digest):
            seen.append((relative, size, digest))
            return original(relative, size, digest)
        with patch.object(I, '_trusted_bytes', side_effect=recording):
            module, contract = I._load_assessment()
        self.assertEqual(tuple(seen), I.SOURCE_IDENTITIES)
        self.assertEqual(len(contract), 96972)
        self.assertEqual(hashlib.sha256(contract).hexdigest(),
                         '31f96f93c2ca1bd58ae322a6d3c223dd764e5a763088cfed2dbf78a8a21104e2')
        self.assertTrue(callable(module.assess_owned_raw))
        with patch.object(I, '_trusted_bytes', side_effect=I.InspectorError('source changed')), \
             patch.object(I.importlib.util, 'spec_from_file_location') as importer:
            with self.assertRaises(I.InspectorError):
                I._load_assessment()
            importer.assert_not_called()

    def test_all_leaf_metadata_and_size_caps_precede_any_input_read(self):
        self.write('program.d', b'x' * (16384 + 1))
        real_read = I.os.read
        input_fds = set()
        real_open = I.os.open
        reads = []
        def opening(path, flags, *args, **kwargs):
            fd = real_open(path, flags, *args, **kwargs)
            if os.fspath(path) in CONTENTS:
                input_fds.add(fd)
            return fd
        def reading(fd, count):
            if fd in input_fds:
                reads.append(fd)
            return real_read(fd, count)
        with patch.object(I.os, 'open', side_effect=opening), \
             patch.object(I.os, 'read', side_effect=reading):
            self.refuse()
        self.assertEqual(reads, [])

    def test_stdout_failure_returns_failure_after_validating_and_closing(self):
        class Broken:
            def write(self, data):
                raise BrokenPipeError('synthetic broken stdout')
            def flush(self):
                raise AssertionError('flush after failed write')
        stderr = io.StringIO()
        with patch.object(I.sys, 'stdout', SimpleNamespace(buffer=Broken())), \
             redirect_stderr(stderr):
            status = I.main(['--input', str(self.root), '--owner-pid', str(OWNER),
                             '--target-pid', str(TARGET)])
        self.assertEqual(status, 1)
        self.assertLess(len(stderr.getvalue()), 1024)

    def test_output_bound_includes_final_lf_and_no_partial_oversize_stdout(self):
        overhead = len((json.dumps({'x': ''}, sort_keys=True, separators=(',', ':')) + '\n').encode())
        exact = {'x': 'x' * (16777216 - overhead)}
        encoded = I._encode_report(exact)
        self.assertEqual(len(encoded), 16777216)
        self.assertTrue(encoded.endswith(b'\n'))
        with self.assertRaises(I.InspectorError):
            I._encode_report({'x': exact['x'] + 'x'})
        stdout, stderr = io.StringIO(), io.StringIO()
        with patch.object(I, 'inspect_directory', return_value={'x': exact['x'] + 'x'}), \
             redirect_stdout(stdout), redirect_stderr(stderr):
            status = I.main(['--input', str(self.root), '--owner-pid', str(OWNER),
                             '--target-pid', str(TARGET)])
        self.assertEqual(status, 1)
        self.assertEqual(stdout.getvalue(), '')


if __name__ == '__main__':
    unittest.main()
