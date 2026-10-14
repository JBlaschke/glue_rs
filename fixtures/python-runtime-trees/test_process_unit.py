#!/usr/bin/env python3
"""Hostile controls for the independent installed-tree process oracle."""
from __future__ import annotations

import gzip
import json
from pathlib import Path
import tempfile
import unittest
import sys

sys.path.insert(0, str(Path(__file__).resolve().parent))
import prepare
import test_process as policy


def quoted(payload):
    return '"' + ''.join(chr(value) if 32 <= value <= 126 and value not in (34, 92)
                         else '\\%03o' % value for value in payload) + '"'


def fixture():
    payloads = {'lib/empty.py': b'', 'lib/source.py': b'source\0\xff'}
    outputs = payloads | {'provenance.json': b'{}\n'}
    expected = policy.Contract('/glue', '/input', '/output',
                               {key: prepare.identity(value) for key, value in payloads.items()}, payloads,
                               {key: prepare.identity(value) for key, value in outputs.items()}, outputs,
                               b'report\n', outputs['provenance.json'], 'stock', require_system_reads=False)
    records = []
    def emit(value):
        records.append('42  ' + value + '\n')
    emit('execve("/glue", [' + ', '.join(quoted(value.encode()) for value in expected.command) + '], 0x123 /* 1 var */) = 0')
    emit('openat(AT_FDCWD</workspace>, "/", O_RDONLY|O_NOFOLLOW|O_DIRECTORY|O_CLOEXEC) = 3</>')
    emit('openat(3</>, "input", O_RDONLY|O_NOFOLLOW|O_DIRECTORY|O_CLOEXEC) = 4</input>')
    emit('close(3</>) = 0')
    for path, payload in sorted(payloads.items()):
        emit('openat(4</input>, "lib", O_RDONLY|O_NOFOLLOW|O_DIRECTORY|O_CLOEXEC) = 3</input/lib>')
        emit('openat(3</input/lib>, ' + quoted(Path(path).name.encode()) + ', O_RDONLY|O_NOFOLLOW|O_NONBLOCK|O_CLOEXEC) = 5</input/' + path + '>')
        metadata = 'statx(5</input/' + path + '>, "", AT_STATX_SYNC_AS_STAT|AT_EMPTY_PATH, STATX_ALL, {stx_mode=S_IFREG|0644, stx_size=' + str(len(payload)) + ', ...}) = 0'
        emit(metadata)
        if payload:
            emit('read(5</input/' + path + '>, ' + quoted(payload) + ', ' + str(len(payload)) + ') = ' + str(len(payload)))
        emit('read(5</input/' + path + '>, "", 1) = 0')
        emit(metadata)
        emit('close(5</input/' + path + '>) = 0')
        emit('close(3</input/lib>) = 0')
    emit('close(4</input>) = 0')
    for name in ('/output', '/output/lib'):
        emit('mkdirat(AT_FDCWD</workspace>, "' + name + '", 0777) = 0')
    for path in [*sorted(payloads), 'provenance.json']:
        payload = outputs[path]
        name = '/output/' + path
        emit('openat(AT_FDCWD</workspace>, "' + name + '", O_WRONLY|O_CREAT|O_EXCL|O_CLOEXEC, 0666) = 3<' + name + '>')
        if payload:
            emit('write(3<' + name + '>, ' + quoted(payload) + ', ' + str(len(payload)) + ') = ' + str(len(payload)))
        emit('utimensat(3<' + name + '>, NULL, [UTIME_OMIT, {tv_sec=1704067200, tv_nsec=0} /* stock epoch */], 0) = 0')
        emit('fchmod(3<' + name + '>, 0444) = 0')
        emit('close(3<' + name + '>) = 0')
    for name in ('/output/lib', '/output'):
        emit('openat(AT_FDCWD</workspace>, "' + name + '", O_RDONLY|O_CLOEXEC) = 3<' + name + '>')
        emit('utimensat(3<' + name + '>, NULL, [UTIME_OMIT, {tv_sec=1704067200, tv_nsec=0}], 0) = 0')
        emit('fchmod(3<' + name + '>, 0555) = 0')
        emit('close(3<' + name + '>) = 0')
    emit('write(1</evidence/report.json>, "report\\n", 7) = 7')
    emit('exit_group(0) = ?')
    emit('+++ exited with 0 +++')
    return expected, records


class ProcessPolicyTests(unittest.TestCase):
    def setUp(self):
        self.expected, self.lines = fixture()

    def reject(self, lines):
        with self.assertRaises(ValueError):
            policy.audit_lines(lines, self.expected)

    def replace(self, needle, replacement, occurrence=0):
        lines = self.lines[:]
        indices = [index for index, value in enumerate(lines) if needle in value]
        self.assertGreater(len(indices), occurrence)
        lines[indices[occurrence]] = lines[indices[occurrence]].replace(needle, replacement)
        return lines

    def test_complete_owned_traversal_and_publication(self):
        result = policy.audit_lines(self.lines, self.expected)
        self.assertEqual(result['selected_input_files'], 2)
        self.assertEqual(result['published_files'], 3)
        self.assertTrue(result['publication_after_complete_input_read_and_close'])

    def test_pid_child_network_and_unclassified_operations(self):
        for body in ('socket(AF_INET, SOCK_STREAM, IPPROTO_IP) = 6', 'clone(NULL, 0, NULL, NULL, NULL) = 43',
                     'dup(4</input>) = 6</input>', 'getdents64(4</input>, [], 32768) = 0',
                     'unlink("/unrelated") = 0', 'execve("/python", ["/python"], 0x123) = 0'):
            with self.subTest(body=body):
                self.reject(self.lines[:2] + ['42  ' + body + '\n'] + self.lines[2:])
        self.reject(self.replace('42  close(3</>)', '43  close(3</>)'))

    def test_complete_trace_and_exact_command(self):
        self.reject(self.lines[:-1])
        self.reject(self.lines + [self.lines[1]])
        self.reject(self.replace('"--runtime-tree"', '"--pbs-install-only"'))
        self.reject(self.replace('"host-install"', '"host-full"'))

    def test_selected_no_follow_nonblocking_and_parent_ownership(self):
        self.reject(self.replace('O_RDONLY|O_NOFOLLOW|O_NONBLOCK|O_CLOEXEC', 'O_RDONLY|O_NOFOLLOW|O_CLOEXEC'))
        self.reject(self.replace('O_RDONLY|O_NOFOLLOW|O_DIRECTORY|O_CLOEXEC', 'O_RDONLY|O_DIRECTORY|O_CLOEXEC'))
        self.reject(self.replace('openat(3</input/lib>, "empty.py"', 'openat(4</input>, "lib/empty.py"'))
        self.reject(self.replace('= 5</input/lib/empty.py>', '= 5</foreign/empty.py>'))

    def test_unselected_and_repeated_input_leaves(self):
        self.reject(self.replace('"source.py"', '"unselected.py"'))
        target = next(index for index, line in enumerate(self.lines) if 'openat(3</input/lib>, "source.py"' in line)
        self.reject(self.lines[:target] + [self.lines[target]] + self.lines[target:])

    def test_regular_size_eof_restat_and_close(self):
        self.reject(self.replace('S_IFREG|0644', 'S_IFIFO|0644'))
        self.reject(self.replace('stx_size=8', 'stx_size=9'))
        self.reject(self.replace('read(5</input/lib/source.py>, "", 1) = 0', 'read(5</input/lib/source.py>, "", 1) = 1'))
        self.reject(self.replace('read(5</input/lib/source.py>, "", 1)', 'read(5</input/lib/source.py>, "", 2)'))
        for needle in ('read(5</input/lib/source.py>, "", 1)', 'close(5</input/lib/source.py>)', 'close(4</input>)'):
            index = next(index for index, line in enumerate(self.lines) if needle in line)
            self.reject(self.lines[:index] + self.lines[index + 1:])
        index = [index for index, line in enumerate(self.lines) if 'statx(5</input/lib/source.py>' in line][-1]
        self.reject(self.lines[:index] + self.lines[index + 1:])

    def test_byte_prefix_and_full_transfer_count(self):
        self.reject(self.replace('"source\\000\\377"', '"Source\\000\\377"'))
        self.reject(self.replace('"source\\000\\377", 8) = 8', '"source\\000\\377", 9) = 8'))
        self.reject(self.replace('"source\\000\\377", 8) = 8', '"source\\000\\377", 8) = 7'))

    def test_publication_after_every_selected_owner_is_closed(self):
        index = next(index for index, line in enumerate(self.lines) if 'mkdirat(' in line)
        early = self.lines[index]
        self.reject(self.lines[:4] + [early] + self.lines[4:index] + self.lines[index + 1:])

    def test_publication_exclusive_inventory_and_no_alias(self):
        self.reject(self.replace('O_WRONLY|O_CREAT|O_EXCL|O_CLOEXEC', 'O_WRONLY|O_CREAT|O_TRUNC|O_CLOEXEC'))
        self.reject(self.replace('= 3</output/lib/empty.py>', '= 3</unrelated>'))
        self.reject(self.replace('"/output/lib/empty.py"', '"/output/unselected.py"'))
        self.reject(self.replace('write(3</output/lib/source.py>', 'read(3</output/lib/source.py>'))

    def test_stock_mode_time_and_freeze_order(self):
        self.reject(self.replace('0444) = 0', '0644) = 0'))
        self.reject(self.replace('0555) = 0', '0755) = 0'))
        self.reject(self.replace('tv_sec=1704067200', 'tv_sec=1704067201'))
        self.reject(self.replace('tv_nsec=0', 'tv_nsec=1'))
        index = next(index for index, line in enumerate(self.lines) if 'fchmod(3</output/lib/empty.py>' in line)
        changed = self.lines[:]
        changed[index], changed[index - 1] = changed[index - 1], changed[index]
        self.reject(changed)

    def test_stdout_last_complete_exact_and_unreassigned(self):
        self.reject(self.replace('"report\\n"', '"REPORT\\n"'))
        self.reject(self.replace('write(1</evidence/report.json>', 'write(2</evidence/report.json>'))
        index = next(index for index, line in enumerate(self.lines) if 'write(1<' in line)
        self.reject(self.lines[:4] + [self.lines[index]] + self.lines[4:index] + self.lines[index + 1:])

    def test_system_reads_are_closed_and_mappings_cannot_acquire_input(self):
        for body in ('openat(AT_FDCWD</workspace>, "/tmp/extra", O_RDONLY|O_CLOEXEC) = 6</tmp/extra>',
                     'mmap(NULL, 4096, PROT_READ, MAP_PRIVATE, 4</input>, 0) = 0x123000',
                     'mmap(NULL, 4096, PROT_READ|PROT_EXEC, MAP_PRIVATE|MAP_ANONYMOUS, -1, 0) = 0x123000',
                     'mprotect(0x123000, 4096, PROT_READ|PROT_EXEC) = 0'):
            with self.subTest(body=body):
                self.reject(self.lines[:4] + ['42  ' + body + '\n'] + self.lines[4:])

    def test_raw_and_gzip_replay_have_same_observations(self):
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / 'trace.txt'
            compressed = Path(temporary) / 'trace.txt.gz'
            path.write_text(''.join(self.lines))
            compressed.write_bytes(gzip.compress(path.read_bytes(), mtime=0))
            raw = policy.audit_trace(path, self.expected)
            replay = policy.audit_trace(compressed, self.expected)
            raw.pop('trace_identity'); replay.pop('trace_identity')
            self.assertEqual(raw, replay)

    def test_parser_preserves_buffer_descriptor_text_and_escaped_bytes(self):
        self.assertEqual(policy.decode_bytes('a\\000\\xff\\n\\"'), b'a\0\xff\n"')
        self.assertEqual(policy.split_arguments('3</root>, "6</fake>,(x)", {a=[1, 2]}'),
                         ['3</root>', '"6</fake>,(x)"', '{a=[1, 2]}'])
        with self.assertRaises(ValueError):
            policy.split_arguments('3</root>, "unfinished')


if __name__ == '__main__':
    unittest.main()
