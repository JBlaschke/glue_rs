"""Only injected pipe/observer models; no tracing provider or target execution."""
import os
from pathlib import Path
import shlex
import subprocess
import tempfile
import unittest

HERE = Path(__file__).resolve().parent


class ObservedIOTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.temp = tempfile.TemporaryDirectory(prefix='glue-observed-io-models-')
        cls.addClassCleanup(cls.temp.cleanup)
        cls.binary = Path(cls.temp.name) / 'model'
        argv = shlex.split(os.environ.get('CC', 'cc')) + [
            '-std=c11', '-Wall', '-Wextra', '-Werror', '-pedantic', '-O1']
        argv += shlex.split(os.environ.get('BIO_TEST_CFLAGS', ''))
        argv += [str(HERE/'bootstrap_io.c'), str(HERE/'test_observed_io.c'), '-o', str(cls.binary)]
        done = subprocess.run(argv, capture_output=True, timeout=30)
        if done.returncode:
            raise RuntimeError(done.stdout.decode(errors='replace') + done.stderr.decode(errors='replace'))

    def check_case(self, case):
        done = subprocess.run([str(self.binary), case], capture_output=True, timeout=10)
        self.assertEqual(done.returncode, 0, done.stderr)
        self.assertEqual(done.stdout, case.encode() + b'\n')
        self.assertEqual(done.stderr, b'')


def model(case):
    return lambda self: self.check_case(case)


for name in ('arguments', 'success', 'progress', 'observer-failures', 'confirmed-prefix',
             'poll-priority', 'deadlines', 'bounds', 'eof'):
    setattr(ObservedIOTests, 'test_' + name.replace('-', '_'), model(name))


if __name__ == '__main__':
    unittest.main()
