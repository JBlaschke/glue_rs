"""Borrowed held-CWD controls: injected faults and ordinary owned native children."""
import hashlib
import json
import os
from pathlib import Path
import platform
import subprocess
import tempfile
import unittest

HERE = Path(__file__).resolve().parent

class TargetCwdControls(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.temporary = None
        retain = os.environ.get('GLUE_CWD_TEST_RETAIN')
        if retain:
            cls.build = Path(retain)
            cls.build.mkdir(parents=True, exist_ok=False, mode=0o700)
        else:
            cls.temporary = tempfile.TemporaryDirectory(prefix='glue held cwd ü ')
            cls.build = Path(cls.temporary.name)
        sources = [HERE / 'target_cwd.c', HERE / 'test_target_cwd.c', HERE.parent / 'target-descriptors/target_descriptors.c']
        argv = ['/usr/bin/cc', '-std=c11', '-D_DEFAULT_SOURCE', '-D_DARWIN_C_SOURCE', '-Wall', '-Wextra', '-Werror', '-O1']
        if os.environ.get('GLUE_CWD_SANITIZE') == '1':
            argv += ['-g', '-fsanitize=address,undefined', '-fno-omit-frame-pointer']
        argv += [str(p) for p in sources]
        if platform.system() == 'Darwin':
            argv += ['-lproc']
        cls.binary = cls.build / 'cwd-controls'
        argv += ['-o', str(cls.binary)]
        result = subprocess.run(argv, capture_output=True, text=True, timeout=45)
        cls.record('compile', argv, result, sources={str(p): hashlib.sha256(p.read_bytes()).hexdigest() for p in sources})
        if result.returncode:
            raise AssertionError(result.stderr)

    @classmethod
    def record(cls, name, argv, result, **extra):
        (cls.build / (name + '.stdout')).write_text(result.stdout)
        (cls.build / (name + '.stderr')).write_text(result.stderr)
        data = {'argv': argv, 'status': result.returncode, 'host': platform.platform(), **extra}
        if cls.binary.is_file():
            data['binary_sha256'] = hashlib.sha256(cls.binary.read_bytes()).hexdigest()
        (cls.build / (name + '.json')).write_text(json.dumps(data, indent=2) + '\n')

    @classmethod
    def tearDownClass(cls):
        if cls.temporary:
            cls.temporary.cleanup()

    def control(self, name):
        argv = [str(self.binary), name]
        result = subprocess.run(argv, capture_output=True, text=True, timeout=12)
        self.record(name, argv, result, scope='native operation with injected later fault' if name in ('native-6', 'native-7') else 'actual owned native operation' if name.startswith('native-') else 'injected model only')
        if result.returncode == 77:
            self.skipTest('ordinary native permission/FD-capacity/TD-adapter precondition unavailable; no privilege or limits changed')
        self.assertEqual(result.returncode, 0, result.stderr)
        return result.stdout

    def test_complete_sample_and_single_change(self): self.control('success')
    def test_invalid_requests_never_mutate_or_preserve_stale_ready(self): self.control('requests')
    def test_complete_operations_preflight(self): self.control('operations')
    def test_actual_owner_and_child_guards(self): self.control('owners')
    def test_blocked_mask_adapter_contract(self): self.control('masks')
    def test_each_syscall_failure_has_no_retry_and_preserves_attempt(self): self.control('failures')
    def test_anomalous_returns_and_missing_errno_refuse(self): self.control('adapters')
    def test_each_pre_post_metadata_and_full_flag_change_refuses(self): self.control('changes')
    def test_effective_cwd_shadow_cannot_masquerade_as_selection(self): self.control('shadows')
    def test_original_deadline_and_cooperative_callback_failures(self): self.control('deadlines')
    def test_final_identity_and_signal_guards_keep_mutation_state(self): self.control('final-guards')
    def test_packed_existing_wire_detail_is_bounded(self): self.control('details')
    def test_native_rename_and_replace_selects_held_original_parent_cwd_unchanged(self): self.control('native-1')
    def test_native_wrong_held_directory_refuses_before_change(self): self.control('native-2')
    def test_native_closed_descriptor_refuses_before_change(self): self.control('native-3')
    def test_native_regular_file_refuses_before_change(self): self.control('native-4')
    def test_native_open_then_no_search_is_live_permission_check(self): self.control('native-5')
    def test_native_real_change_then_injected_readback_failure_has_no_ready(self): self.control('native-6')
    def test_native_real_change_then_injected_late_result_has_no_ready(self): self.control('native-7')
    def test_native_td_closes_borrowed_directory_while_cwd_persists(self): self.control('native-8')

if __name__ == '__main__':
    unittest.main()
