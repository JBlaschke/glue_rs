"""Object READY adoption: actual runner models and ordinary gated transport."""
import hashlib
import json
import os
from pathlib import Path
import platform
import subprocess
import tempfile
import unittest

HERE = Path(__file__).resolve().parent
BASE = HERE.parent

class ObjectRunnerControls(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.temporary = None
        selected = os.environ.get('GLUE_OBJECT_RUNNER_TEST_RETAIN')
        if selected:
            cls.build = Path(selected)
            cls.build.mkdir(parents=True, exist_ok=False, mode=0o700)
        else:
            cls.temporary = tempfile.TemporaryDirectory(prefix='glue object runner ü ')
            cls.build = Path(cls.temporary.name)
        common = [BASE / 'bootstrap-wire/bootstrap_wire.c', BASE / 'bootstrap-object-wire/bootstrap_object_wire.c']
        protocol = common + [HERE / 'object_protocol.c', BASE / 'bootstrap-io/bootstrap_io.c',
                             BASE / 'bootstrap-request/bootstrap_request.c', BASE / 'bootstrap-probe/probe_report.c',
                             BASE / 'target-credentials/target_credentials.c']
        cls.compile('io', [HERE / 'test_object_io.c', BASE / 'bootstrap-io/bootstrap_io.c'])
        cls.compile('child', [HERE / 'test_object_child.c'] + common)
        cls.compile('parent', [HERE / 'test_object_parent.c', BASE / 'bootstrap-signals/bootstrap_signals.c',
                               BASE / 'bootstrap-runner/runner_catalog.c', BASE / 'bootstrap-runner/catalog_unconfigured.c'] + protocol)
        cls.compile('native', [HERE / 'test_object_native.c', BASE / 'target-fd-objects/target_fd_objects.c',
                               BASE / 'target-descriptors/target_descriptors.c', BASE / 'target-endpoints/target_endpoints.c'] + protocol,
                    ['-lproc'] if platform.system() == 'Darwin' else [])

    @classmethod
    def compile(cls, name, inputs, libraries=()):
        argv = ['/usr/bin/cc', '-std=c11', '-D_DEFAULT_SOURCE', '-D_DARWIN_C_SOURCE', '-Wall', '-Wextra', '-Werror', '-O1']
        if os.environ.get('GLUE_OBJECT_RUNNER_SANITIZE') == '1':
            argv += ['-g', '-fsanitize=address,undefined', '-fno-omit-frame-pointer']
        argv += [str(p) for p in inputs] + list(libraries) + ['-o', str(cls.build / name)]
        result = subprocess.run(argv, capture_output=True, text=True, timeout=60)
        cls.record(name + '-compile', argv, result,
                   source_sha256={str(p): hashlib.sha256(p.read_bytes()).hexdigest() for p in inputs})
        if result.returncode:
            raise AssertionError(result.stderr)

    @classmethod
    def record(cls, name, argv, result, **extra):
        (cls.build / (name + '.stdout')).write_text(result.stdout)
        (cls.build / (name + '.stderr')).write_text(result.stderr)
        record = {'argv': argv, 'status': result.returncode, 'host': platform.platform(), **extra}
        binary = cls.build / name.removesuffix('-compile')
        if name.endswith('-compile') and binary.is_file():
            record['binary_sha256'] = hashlib.sha256(binary.read_bytes()).hexdigest()
        (cls.build / (name + '.json')).write_text(json.dumps(record, indent=2) + '\n')

    @classmethod
    def tearDownClass(cls):
        if cls.temporary is not None:
            cls.temporary.cleanup()

    def control(self, binary, *arguments):
        argv = [str(self.build / binary), *arguments]
        result = subprocess.run(argv, capture_output=True, text=True, timeout=15)
        self.record('-'.join((binary, *arguments)), argv, result)
        if result.returncode == 77:
            self.skipTest('native preconditions: nonroot, existing FD capacity>=32 and actual canonical group vector<=16; no limits or groups changed')
        self.assertEqual(result.returncode, 0, result.stderr)
        return result.stdout

    def test_fixed512_io_preserves_legacy_sizes_and_late_delivery_failure(self): self.control('io')
    def test_actual_child_capture_order_errors_and_legacy_go_refusal(self): self.control('child')
    def test_actual_parent_complete_wire_match_before_trace_go_and_ref_cleanup(self): self.control('parent')

    @unittest.skipUnless(platform.system() in ('Darwin', 'Linux') and os.getuid() != 0 and os.geteuid() != 0, 'ordinary native Mac/Linux only')
    def test_native_actual_snapshot_wire_match_go_and_output_bytes(self): self.control('native', 'good')

    @unittest.skipUnless(platform.system() in ('Darwin', 'Linux') and os.getuid() != 0 and os.geteuid() != 0, 'ordinary native Mac/Linux only')
    def test_native_legacy_status_prefix_never_admits_ready(self): self.control('native', 'legacy-status')

    @unittest.skipUnless(platform.system() in ('Darwin', 'Linux') and os.getuid() != 0 and os.geteuid() != 0, 'ordinary native Mac/Linux only')
    def test_native_truncated_status_never_admits_ready(self): self.control('native', 'truncated-status')

    @unittest.skipUnless(platform.system() in ('Darwin', 'Linux') and os.getuid() != 0 and os.geteuid() != 0, 'ordinary native Mac/Linux only')
    def test_native_wrong_held_reference_never_sends_go(self): self.control('native', 'wrong-reference')

    @unittest.skipUnless(platform.system() in ('Darwin', 'Linux') and os.getuid() != 0 and os.geteuid() != 0, 'ordinary native Mac/Linux only')
    def test_native_legacy_go_cannot_release_object_child(self): self.control('native', 'legacy-go')

    def test_source_selected_native_build_preserves_admission_refusal(self):
        if os.environ.get('GLUE_OBJECT_RUNNER_SANITIZE') == '1':
            self.skipTest('standalone CLI build belongs to ordinary build controls')
        argv = ['sh', str(HERE / 'build.sh'), str(self.build / 'object-runner-cli')]
        result = subprocess.run(argv, capture_output=True, text=True, timeout=60)
        self.record('object-cli-build', argv, result)
        self.assertEqual(result.returncode, 0, result.stderr)
        if os.getuid() == 0 or os.geteuid() == 0:
            return
        output = self.build / 'must-not-exist'
        argv = [str(self.build / 'object-runner-cli'), '--request', str(self.build / 'missing'), '--output', str(output)]
        result = subprocess.run(argv, capture_output=True, text=True, timeout=5)
        self.record('object-cli-refusal', argv, result)
        self.assertEqual(result.returncode, 2)
        self.assertFalse(output.exists())
        self.assertEqual(result.stdout, '')

    @unittest.skipUnless(platform.system() == 'Darwin', 'traced profile is Darwin-only')
    def test_source_selected_traced_profile_links_without_provider_execution(self):
        if os.environ.get('GLUE_OBJECT_RUNNER_SANITIZE') == '1':
            self.skipTest('standalone CLI build belongs to ordinary build controls')
        argv = ['sh', str(HERE / 'build-traced.sh'), str(self.build / 'traced-object-cli')]
        result = subprocess.run(argv, capture_output=True, text=True, timeout=60)
        self.record('traced-object-cli-build', argv, result)
        self.assertEqual(result.returncode, 0, result.stderr)

if __name__ == '__main__':
    unittest.main()
