"""Actual traced parent/TS integration through isolated native boundaries."""
import json
import os
from pathlib import Path
import platform
import shlex
import subprocess
import tempfile
import unittest

HERE = Path(__file__).resolve().parent
BASE = HERE.parent
CASES = ('lifecycle', 'failures', 'poisoned-status', 'wait-ownership', 'closure',
         'simulated', 'readiness', 'cleanup-clock')


@unittest.skipUnless(platform.system() == 'Darwin', 'source-isolated promotion controls use the Darwin finalizer')
class OwnedTraceParentTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.temp = tempfile.TemporaryDirectory(prefix='glue-owned-trace-parent-models-')
        cls.addClassCleanup(cls.temp.cleanup)
        cls.binary = Path(cls.temp.name) / 'models'
        sources = [HERE/'test_owned_trace_parent.c', HERE/'runner_catalog.c',
                   HERE/'catalog_unconfigured.c', HERE/'runner_protocol.c',
                   BASE/'trace-session/trace_session.c',
                   BASE/'bootstrap-request/bootstrap_request.c',
                   BASE/'bootstrap-wire/bootstrap_wire.c',
                   BASE/'bootstrap-probe/probe_report.c',
                   BASE/'bootstrap-io/bootstrap_io.c',
                   BASE/'bootstrap-signals/bootstrap_signals.c',
                   BASE/'bootstrap-admission/bootstrap_admission.c',
                   BASE/'target-credentials/target_credentials.c',
                   BASE/'target-descriptors/target_descriptors.c',
                   BASE/'target-endpoints/target_endpoints.c']
        argv = shlex.split(os.environ.get('CC', 'cc')) + [
            '-std=c11', '-D_DEFAULT_SOURCE', '-D_DARWIN_C_SOURCE',
            '-DGLUE_OWNED_TRACING', '-Wall', '-Wextra', '-Werror', '-pedantic', '-O1']
        argv += shlex.split(os.environ.get('NR_TRACE_TEST_CFLAGS', ''))
        argv += list(map(str, sources))
        if platform.system() == 'Darwin':
            argv += ['-lproc']
        done = subprocess.run(argv + ['-o', str(cls.binary)], capture_output=True, timeout=60)
        if done.returncode:
            raise RuntimeError(done.stdout.decode(errors='replace') + done.stderr.decode(errors='replace'))

    def check_case(self, case):
        done = subprocess.run([str(self.binary), case], capture_output=True, timeout=10)
        self.assertEqual(done.returncode, 0, done.stderr)
        self.assertEqual(done.stdout, case.encode() + b'\n')
        self.assertEqual(done.stderr, b'')

    def test_distinct_json_receipt(self):
        done = subprocess.run([str(self.binary), 'json'], capture_output=True, timeout=10)
        self.assertEqual(done.returncode, 0, done.stderr)
        trace, result = map(json.loads, done.stdout.splitlines())
        self.assertEqual(trace['schema'], 'glue-owned-trace-session-diagnostic-v1')
        self.assertEqual(result['schema'], 'glue-owned-traced-bootstrap-diagnostic-v1')
        self.assertIs(result['tracing'], True)
        self.assertIs(result['exec_proved'], False)
        self.assertIs(result['full_acceptance'], False)
        self.assertTrue(result['trace_success_eligible'])
        self.assertEqual(trace['session']['binding']['target_pid'], 200)
        self.assertEqual(trace['session']['attempt_deadline_ns'], 2000000000)
        self.assertEqual(trace['session']['cleanup_deadline_ns'], trace['backend']['cleanup_deadline_ns'])
        self.assertIn('callback_error', trace['session']['error'])
        self.assertNotIn('system_errno', trace['session']['error'])
        self.assertEqual(trace['backend']['close_error']['system_errno'], 0)
        self.assertEqual(trace['backend']['writer_close_attempted_mask'], 15)
        self.assertEqual(trace['backend']['writer_close_failed_mask'], 0)
        self.assertEqual(trace['backend']['writer_close_errno'], [0, 0, 0, 0])

    def test_native_and_callback_error_fields(self):
        done = subprocess.run([str(self.binary), 'start-failure-json'], capture_output=True, timeout=10)
        self.assertEqual(done.returncode, 0, done.stderr)
        trace, result = map(json.loads, done.stdout.splitlines())
        native = trace['backend']['first_error']
        self.assertEqual(native['system_errno'], 0)
        self.assertEqual(native['libdtrace_code'], 123)
        self.assertGreater(native['callback_error'], 0)
        self.assertEqual(bytes.fromhex(native['message_hex']), b'library failure')
        self.assertEqual(result['parent_error']['errno'], 0)
        self.assertFalse(result['trace_success_eligible'])


def model(case):
    return lambda self: self.check_case(case)


for name in CASES:
    setattr(OwnedTraceParentTests, 'test_' + name.replace('-', '_'), model(name))


if __name__ == '__main__':
    unittest.main()
