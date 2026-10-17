"""Build/run only injected coordinator models; no native collector/kit/backend."""
import os
from pathlib import Path
import shlex
import subprocess
import tempfile
import unittest

HERE = Path(__file__).resolve().parent


class SessionModels(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.temp = tempfile.TemporaryDirectory(prefix='glue-trace-session-models-')
        cls.binary = Path(cls.temp.name) / 'models'
        command = shlex.split(os.environ.get('CC', 'cc')) + [
            '-std=c11', '-Wall', '-Wextra', '-Werror', '-pedantic', '-O1']
        if os.environ.get('GLUE_TRACE_SESSION_SANITIZE') == '1':
            command += ['-g', '-fsanitize=address,undefined', '-fno-omit-frame-pointer']
        done = subprocess.run(command + [str(HERE/'trace_session.c'),
                              str(HERE/'test_trace_session.c'), '-o', str(cls.binary)],
                              capture_output=True, timeout=60)
        if done.returncode:
            raise RuntimeError(done.stdout.decode(errors='replace') + done.stderr.decode(errors='replace'))

    @classmethod
    def tearDownClass(cls):
        cls.temp.cleanup()

    def check_model(self, name):
        done = subprocess.run([str(self.binary), name], capture_output=True, timeout=10)
        self.assertEqual(done.returncode, 0, done.stderr)
        self.assertEqual(done.stdout, name.encode() + b'\n')
        self.assertEqual(done.stderr, b'')

    def test_success_and_post_reap_queued_terminal(self): self.check_model('success')
    def test_missing_late_duplicate_begin_and_binding(self): self.check_model('readiness')
    def test_fixed_attempt_and_request_cleanup_deadlines(self): self.check_model('deadlines')
    def test_partial_failed_late_go_never_replays(self): self.check_model('go')
    def test_opaque_partial_bw_and_separate_parent_completion(self): self.check_model('bootstrap')
    def test_cleanup_pumping_and_original_error_precedence(self): self.check_model('cleanup')
    def test_reaped_and_echild_end_kill_eligibility(self): self.check_model('wait')
    def test_backend_faults_once_only_close_and_failure_finalization(self): self.check_model('backend')
    def test_stop_terminal_end_and_single_drain_order(self): self.check_model('drain')
    def test_arguments_owner_snapshot_and_resource_bounds(self): self.check_model('boundaries')


if __name__ == '__main__':
    unittest.main()
