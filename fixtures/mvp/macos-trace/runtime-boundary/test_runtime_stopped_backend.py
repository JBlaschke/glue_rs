#!/usr/bin/env python3
"""Pure formatting and injected record controls; never links a provider.

The SDK-only driver defines every libdtrace symbol itself. Its artifact check
covers C serialization and the fixed physical decoder, not a native trace or
complete launch/GLUEPX recipe. Portable hosts still exercise pure formatting
and forced-unavailable factory/getter refusal.
"""
import hashlib
import json
import os
from pathlib import Path
import platform
import subprocess
import tempfile
import unittest

import runtime_stopped as stopped

HERE = Path(__file__).resolve().parent
FLAGS = ['-std=c11', '-Wall', '-Wextra', '-Werror', '-pedantic', '-O1']
MODES = (
    'constructor', 'old-options', 'selector', 'duplicate-match', 'enabled-count',
    'destructive-denied', 'good', 'marker-order', 'layout', 'partial-write',
    'drop', 'fault', 'late-exec', 'bad-marker', 'call-id', 'return-shape',
    'return-function', 'return-error', 'return-duplicate', 'pending-end',
    'close-failure', 'clock-failure', 'wrong-marker-tid', 'wrong-marker-signal',
    'wrong-marker-epoch', 'malformed-name',
)
_COMMAND = 0
_WORKSPACE = 0


def compiler():
    if platform.system() == 'Darwin':
        return ['/usr/bin/xcrun', '--sdk', 'macosx', 'clang']
    return [os.environ.get('CC', 'cc')]


def flags():
    result = list(FLAGS)
    if os.environ.get('GLUE_RUNTIME_STOPPED_SANITIZE') == '1':
        result += ['-g', '-fno-omit-frame-pointer', '-fsanitize=address,undefined']
    return result


def source_hashes():
    names = (
        'runtime_trace_backend.c', 'runtime_trace_backend.h',
        'runtime_trace_program.c', 'runtime_trace_program.h',
        'runtime_stopped_trace.h', 'test_runtime_stopped_backend.c',
        'test_runtime_stopped_program.c', 'test_runtime_stopped_backend.py',
        'runtime_stopped.py', 'runtime_physical.py', 'runtime_boundary.py',
        'runtime_images.py', 'runtime_recipe.py',
    )
    paths = [HERE / name for name in names]
    paths += [HERE.parent / 'trace-session' / 'trace_session.h',
              HERE.parent / 'post-exec-output' / 'post_exec_output.py']
    return {str(p): hashlib.sha256(p.read_bytes()).hexdigest() for p in paths}


class Workspace:
    def __init__(self, prefix):
        global _WORKSPACE
        self.temporary = None
        retain = os.environ.get('GLUE_RUNTIME_STOPPED_RETAIN')
        if retain:
            root = Path(retain)
            root.mkdir(parents=True, exist_ok=True, mode=0o700)
            _WORKSPACE += 1
            path = root / ('%03d-' % _WORKSPACE + prefix)
            path.mkdir(mode=0o700)
            self.path = path
        else:
            self.temporary = tempfile.TemporaryDirectory(prefix=prefix)
            self.path = Path(self.temporary.name)

    def cleanup(self):
        if self.temporary:
            self.temporary.cleanup()

    def __enter__(self):
        return self.path

    def __exit__(self, *unused):
        self.cleanup()


def command(argv):
    global _COMMAND
    argv = [str(a) for a in argv]
    before = source_hashes()
    result = subprocess.run(argv, capture_output=True, timeout=45)
    after = source_hashes()
    retain = os.environ.get('GLUE_RUNTIME_STOPPED_RETAIN')
    if retain:
        root = Path(retain) / 'commands'
        root.mkdir(parents=True, exist_ok=True, mode=0o700)
        _COMMAND += 1
        stem = '%03d' % _COMMAND
        (root / (stem + '.stdout')).write_bytes(result.stdout)
        (root / (stem + '.stderr')).write_bytes(result.stderr)
        entry = {'argv': argv, 'exit': result.returncode,
                 'source_before': before, 'source_after': after,
                 'source_unchanged': before == after}
        (root / (stem + '.json')).write_text(json.dumps(entry, indent=2) + '\n')
    if before != after:
        raise AssertionError('stopped producer/reader source changed during command')
    result.check_returncode()
    return result


class StoppedFormatterTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.workspace = Workspace('glue-stopped-formatter-')
        cls.binary = cls.workspace.path / 'formatter'
        try:
            command([*compiler(), *flags(), HERE / 'test_runtime_stopped_program.c',
                     HERE / 'runtime_trace_program.c', '-o', cls.binary])
        except Exception:
            cls.workspace.cleanup()
            raise

    @classmethod
    def tearDownClass(cls):
        cls.workspace.cleanup()

    def test_bounds_and_cleared_outputs(self):
        result = command([self.binary, 'bounds'])
        self.assertEqual(result.stdout, b'PASS formatter bounds\n')
        self.assertEqual(result.stderr, b'')

    def test_exact_independent_program_bytes(self):
        for owner, target in ((1, 2), (17, 2147483647), (2147483647, 2147483646)):
            with self.subTest(owner=owner, target=target):
                result = command([self.binary, owner, target])
                self.assertEqual(result.stdout, stopped.expected_stopped_program(
                    owner, target, b'\x01' + bytes(31), b'\x02' + bytes(31)))
                self.assertEqual(result.stderr, b'')


class StoppedUnavailableTests(unittest.TestCase):
    def test_unavailable_factory_and_getter_clear_every_output(self):
        with Workspace('glue-stopped-unavailable-') as directory:
            main = directory / 'main.c'
            main.write_text(r'''#include "runtime_stopped_trace.h"
#include <assert.h>
#include <errno.h>
#include <string.h>
int main(void) {
 for(int omitted=0;omitted<4;omitted++) {
  struct rt_backend *b=(void*)1;struct ts_operations o;struct rt_error e;
  memset(&o,0xa5,sizeof(o));memset(&e,0xa5,sizeof(e));
  assert(rt_stopped_recipe_create(omitted==1?NULL:&b,99,NULL,1,1,
      omitted==2?NULL:&o,omitted==3?NULL:&e)==-1);
  if(omitted!=1)assert(!b);
  if(omitted!=2)for(unsigned i=0;i<sizeof(o);i++)assert(!((unsigned char*)&o)[i]);
  if(omitted!=3) {
   assert(e.stage==RT_CREATE&&e.reason==RT_ARGUMENT&&e.callback_error==ENOTSUP);
   assert(!e.system_errno&&!e.libdtrace_code);
  }
 }
 struct rt_stopped_identity id;memset(&id,0xa5,sizeof(id));
 assert(rt_stopped_identity(NULL,&id)==-1);
 for(unsigned i=0;i<sizeof(id);i++)assert(!((unsigned char*)&id)[i]);
 assert(rt_stopped_identity(NULL,NULL)==-1);return 0;
}
''')
            binary = directory / 'unavailable'
            command([*compiler(), *flags(), '-U__APPLE__', '-I', HERE, main,
                     HERE / 'runtime_trace_backend.c', HERE / 'runtime_trace_program.c',
                     '-o', binary])
            result = command([binary])
            self.assertEqual((result.stdout, result.stderr), (b'', b''))


@unittest.skipUnless(platform.system() == 'Darwin', 'actual Darwin SDK headers required')
class InjectedStoppedBackendTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.workspace = Workspace('glue-stopped-injected-')
        cls.binary = cls.workspace.path / 'backend'
        try:
            # No -ldtrace. All provider functions are defined in this test TU.
            command([*compiler(), *flags(), HERE / 'test_runtime_stopped_backend.c',
                     HERE / 'runtime_trace_program.c', '-o', cls.binary])
        except Exception:
            cls.workspace.cleanup()
            raise

    @classmethod
    def tearDownClass(cls):
        cls.workspace.cleanup()

    def run_mode(self, mode, directory=None):
        argv = [self.binary, mode] + ([] if directory is None else [directory])
        result = command(argv)
        self.assertEqual(result.stdout,
            ('PASS ' + mode + ' (injected records; no provider action)\n').encode())
        self.assertEqual(result.stderr, b'')

    def test_actual_original_c_records_match_fixed_physical_decoder(self):
        # These injected streams lack the full bootstrap/GLUEPX recipe. Only
        # the private physical transport is checked; no normalized public API.
        for mode in ('good', 'marker-order'):
            with self.subTest(mode=mode), Workspace('glue-stopped-artifacts-') as directory:
                self.run_mode(mode, directory)
                self.assertEqual({p.name for p in directory.iterdir()}, {
                    'program.d', 'probes.tsv', 'events.jsonl', 'errors.jsonl',
                    'typed-identity.json'})
                for p in directory.iterdir():
                    self.assertTrue(p.is_file() and not p.is_symlink())
                    self.assertLessEqual(p.stat().st_size, 1 << 20)
                identity = json.loads((directory / 'typed-identity.json').read_bytes())
                program = (directory / 'program.d').read_bytes()
                expected = stopped.expected_stopped_program(identity['owner'], identity['target'],
                    bytes.fromhex(identity['request_sha256']), bytes.fromhex(identity['catalog_sha256']))
                self.assertEqual(program, expected)
                self.assertEqual(hashlib.sha256(program).hexdigest(), identity['program_sha256'])
                lines = (directory / 'events.jsonl').read_bytes().splitlines(keepends=True)
                capture = stopped._V1._transport_stopped(program,
                    (directory / 'probes.tsv').read_bytes(), (directory / 'errors.jsonl').read_bytes(),
                    iter(lines), identity['owner'], identity['target'], expected)
                self.assertEqual(identity['events'], len(capture.phases))
                self.assertEqual(identity['events'], 21)
                self.assertFalse(identity['native_admission'])
                for key, kind in (('entry_ordinal', 2), ('exec_success_ordinal', 7),
                                  ('lwp_start_ordinal', 10), ('marker_ordinal', 19)):
                    phase = capture.phases[identity[key] - 1]
                    self.assertEqual(phase.ordinal, identity[key])
                    self.assertEqual(phase.raw_scalars[0], kind)
                payload_sizes = {p.source_ordinal: len(p.payload) for p in capture.memory}
                self.assertEqual(sorted(payload_sizes.values()), [4, 4, 4, 176, 176])
                self.assertEqual({capture.phases[i - 1].raw_scalars[0]
                                  for i in payload_sizes}, {20, 21})
                self.assertEqual(set(p.raw_scalars[0] for p in capture.phases) & set(range(19, 24)),
                                 set(range(19, 24)))


def _mode_test(mode):
    def check(self):
        self.run_mode(mode)
    check.__name__ = 'test_model_' + mode.replace('-', '_')
    check.__doc__ = 'Injected C model mode: ' + mode + '; no provider action.'
    return check


for _mode in MODES:
    setattr(InjectedStoppedBackendTests, 'test_model_' + _mode.replace('-', '_'), _mode_test(_mode))


if __name__ == '__main__':
    unittest.main()
