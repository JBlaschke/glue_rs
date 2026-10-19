#!/usr/bin/env python3
"""Isolated signal-policy models and owned unprivileged Darwin processes."""
import os
import pathlib
import platform
import shlex
import shutil
import subprocess
import tempfile
import unittest
HERE = pathlib.Path(__file__).resolve().parent
class BootstrapSignals(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        temp = tempfile.TemporaryDirectory(prefix='glue-bootstrap-signals-')
        cls.addClassCleanup(temp.cleanup)
        cls.binary = pathlib.Path(temp.name) / 'test-signals'
        cc = shutil.which(os.environ.get('CC', 'cc'))
        if not cc:
            raise RuntimeError('native C compiler required')
        command = [cc, '-std=c11', '-O2', '-Wall', '-Wextra', '-Werror']
        command += shlex.split(os.environ.get('BS_TEST_CFLAGS', ''))
        command += [str(HERE / 'bootstrap_signals.c'), str(HERE / 'test_bootstrap_signals.c'), '-o', str(cls.binary)]
        result = subprocess.run(command, capture_output=True, text=True, timeout=30)
        if result.returncode:
            raise RuntimeError(result.stdout + result.stderr)
    def case(self, name):
        r = subprocess.run([str(self.binary), name], capture_output=True, text=True, timeout=8)
        self.assertEqual(r.returncode, 0, r.stdout+r.stderr)
        self.assertEqual(r.stdout, 'PASS '+name+'\n')
        self.assertEqual(r.stderr, '')
def make(name):
    def test(self):
        self.case(name)
    return test
for name in ('arguments', 'unsafe-actions', 'parent-roundtrip', 'prepare-failures',
             'child-success', 'ownership', 'child-failures', 'release-failures',
             'restore-failures', 'policy'):
    setattr(BootstrapSignals, 'test_'+name.replace('-', '_'), make(name))
for name in ('native-roundtrip', 'native-pending', 'native-inherited-ignore', 'native-unsafe-chld'):
    setattr(BootstrapSignals, 'test_'+name.replace('-', '_'),
            unittest.skipUnless(platform.system() == 'Darwin' and '-fsanitize=' not in os.environ.get('BS_TEST_CFLAGS', ''),
                                'requires native Darwin without sanitizer-installed handlers')(make(name)))
BootstrapSignals.test_native_unsupported = unittest.skipIf(platform.system() == 'Darwin',
    'Darwin native adapter is supported')(make('native-unsupported'))
if __name__ == '__main__':
    unittest.main()
