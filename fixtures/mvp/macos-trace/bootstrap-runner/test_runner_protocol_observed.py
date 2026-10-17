"""Injected status/observer controls; no native runner or tracing execution."""
import os
from pathlib import Path
import shlex
import subprocess
import tempfile
import unittest

HERE = Path(__file__).resolve().parent
BASE = HERE.parent
CASES = ('arguments', 'sequences', 'progress', 'before-record', 'failed-prefixes',
         'eof-failures', 'trailing-precedence', 'io-precedence', 'deadlines',
         'wire-errors', 'legacy')


class ObservedProtocolTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.temp = tempfile.TemporaryDirectory(prefix='glue-observed-status-models-')
        cls.addClassCleanup(cls.temp.cleanup)
        cls.binary = Path(cls.temp.name) / 'model'
        argv = shlex.split(os.environ.get('CC', 'cc')) + [
            '-std=c11', '-Wall', '-Wextra', '-Werror', '-pedantic', '-O1']
        argv += shlex.split(os.environ.get('NR_STATUS_TEST_CFLAGS', ''))
        argv += list(map(str, [HERE/'runner_protocol.c', HERE/'test_runner_protocol_observed.c',
                              BASE/'bootstrap-request/bootstrap_request.c',
                              BASE/'bootstrap-wire/bootstrap_wire.c',
                              BASE/'bootstrap-probe/probe_report.c',
                              BASE/'bootstrap-io/bootstrap_io.c',
                              BASE/'target-credentials/target_credentials.c']))
        argv += ['-o', str(cls.binary)]
        done = subprocess.run(argv, capture_output=True, timeout=60)
        if done.returncode:
            raise RuntimeError(done.stdout.decode(errors='replace') + done.stderr.decode(errors='replace'))

    def check_case(self, case):
        done = subprocess.run([str(self.binary), case], capture_output=True, timeout=10)
        self.assertEqual(done.returncode, 0, done.stderr)
        self.assertEqual(done.stdout, case.encode() + b'\n')
        self.assertEqual(done.stderr, b'')


def model(case):
    return lambda self: self.check_case(case)


for name in CASES:
    setattr(ObservedProtocolTests, 'test_' + name.replace('-', '_'), model(name))


if __name__ == '__main__':
    unittest.main()
