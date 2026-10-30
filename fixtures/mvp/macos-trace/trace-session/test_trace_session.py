"""Build/run only injected coordinator models; no native collector/kit/backend."""
import hashlib
import json
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
        cls.temp = None
        retain = os.environ.get('GLUE_TRACE_SESSION_RETAIN')
        if retain:
            cls.output = Path(retain)
            cls.output.mkdir(parents=True, exist_ok=False, mode=0o700)
        else:
            cls.temp = tempfile.TemporaryDirectory(prefix='glue-trace-session-models-')
            cls.output = Path(cls.temp.name)
        cls.binary = cls.output / 'models'
        cls.sources = {str(p): hashlib.sha256(p.read_bytes()).hexdigest() for p in (HERE/'trace_session.c', HERE/'trace_session.h', HERE/'test_trace_session.c', Path(__file__).resolve())}
        (cls.output/'sources.json').write_text(json.dumps(cls.sources, indent=2)+'\n')
        command = shlex.split(os.environ.get('CC', 'cc')) + [
            '-std=c11', '-Wall', '-Wextra', '-Werror', '-pedantic', '-O1']
        if os.environ.get('GLUE_TRACE_SESSION_SANITIZE') == '1':
            command += ['-g', '-fsanitize=address,undefined', '-fno-omit-frame-pointer']
        command += [str(HERE/'trace_session.c'), str(HERE/'test_trace_session.c'), '-o', str(cls.binary)]
        done = subprocess.run(command, capture_output=True, timeout=60)
        cls.record('compile', command, done)
        if done.returncode:
            raise RuntimeError(done.stdout.decode(errors='replace') + done.stderr.decode(errors='replace'))

    @classmethod
    def tearDownClass(cls):
        if cls.sources != {p: hashlib.sha256(Path(p).read_bytes()).hexdigest() for p in cls.sources}:
            raise AssertionError('session sources changed during controls')
        if cls.temp:
            cls.temp.cleanup()

    @classmethod
    def record(cls, label, argv, done):
        for stream in ('stdout', 'stderr'):
            (cls.output/(label+'.'+stream)).write_bytes(getattr(done, stream))
        (cls.output/(label+'.json')).write_text(json.dumps({'argv': argv, 'exit': done.returncode}, indent=2)+'\n')

    def check_model(self, name):
        for selected in (name, 'runtime-'+name):
            with self.subTest(profile=selected):
                argv = [str(self.binary), selected]
                done = subprocess.run(argv, capture_output=True, timeout=10)
                self.record(selected, argv, done)
                self.assertEqual(done.returncode, 0, done.stderr)
                self.assertEqual(done.stdout, selected.encode() + b'\n')
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
    def test_malformed_or_owner_failed_close_report_cannot_be_repaired(self): self.check_model('close-reports')
    def test_arguments_owner_snapshot_and_resource_bounds(self): self.check_model('boundaries')

    def test_fixed_factories_refuse_other_fixture_and_no_repair(self): self.check_model('profiles')
    def test_exact_legacy_and_runtime_status_prefix_bounds(self): self.check_model('status-bounds')


if __name__ == '__main__':
    unittest.main()
