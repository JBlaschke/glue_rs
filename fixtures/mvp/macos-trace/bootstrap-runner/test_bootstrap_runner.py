#!/usr/bin/env python3
"""Pure models and native refusal only: never runs a target or privileged path."""
import hashlib
import os
from pathlib import Path
import platform
import shlex
import struct
import subprocess
import tempfile
import unittest
HERE=Path(__file__).resolve().parent
BASE=HERE.parent
PURE=[HERE/'runner_catalog.c',HERE/'runner_protocol.c',HERE/'test_runner_protocol.c',
      BASE/'bootstrap-request/bootstrap_request.c',BASE/'bootstrap-wire/bootstrap_wire.c',
      BASE/'bootstrap-probe/probe_report.c',BASE/'bootstrap-io/bootstrap_io.c',
      BASE/'target-credentials/target_credentials.c']
class Models(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.temp=tempfile.TemporaryDirectory(prefix='glue-bootstrap-runner-tests-')
        cls.out=Path(cls.temp.name)
        cls.binary=cls.out/'models'
        cmd=shlex.split(os.environ.get('CC','cc'))+['-std=c11','-D_DEFAULT_SOURCE','-D_DARWIN_C_SOURCE','-Wall','-Wextra','-Werror','-O1']
        if os.environ.get('GLUE_RUNNER_SANITIZE')=='1':
            cmd+=['-g','-fsanitize=address,undefined','-fno-omit-frame-pointer']
        subprocess.run(cmd+list(map(str,PURE))+['-o',str(cls.binary)],check=True,timeout=60)
    @classmethod
    def tearDownClass(cls):cls.temp.cleanup()
    def test_protocol_comparison_models(self):
        p=subprocess.run([str(self.binary)],check=True,capture_output=True,timeout=10)
        self.assertEqual(p.stdout.splitlines(),[b'sequences',b'malformed-prefix-extra-poison',b'late-eof-and-complete-prefix',b'requested-ready-and-probe-comparisons',b'catalog-canonical-bounds'])
    def test_source_isolated_parent_ownership_models(self):
        binary=self.out/'parent-models'
        sources=[HERE/'test_runner_parent.c',HERE/'runner_catalog.c',HERE/'catalog_unconfigured.c',
                 HERE/'runner_protocol.c',HERE/'runner_support.c',HERE/'runner_files.c',
                 BASE/'bootstrap-request/bootstrap_request.c',BASE/'bootstrap-wire/bootstrap_wire.c',
                 BASE/'bootstrap-probe/probe_report.c',BASE/'bootstrap-io/bootstrap_io.c',
                 BASE/'bootstrap-signals/bootstrap_signals.c',BASE/'bootstrap-admission/bootstrap_admission.c',
                 BASE/'target-credentials/target_credentials.c',BASE/'target-descriptors/target_descriptors.c',
                 BASE/'target-endpoints/target_endpoints.c']
        cmd=shlex.split(os.environ.get('CC','cc'))+['-std=c11','-D_DEFAULT_SOURCE','-D_DARWIN_C_SOURCE','-Wall','-Wextra','-Werror','-O1']
        if os.environ.get('GLUE_RUNNER_SANITIZE')=='1':cmd+=['-g','-fsanitize=address,undefined','-fno-omit-frame-pointer']
        libs=['-lproc'] if platform.system()=='Darwin' else []
        subprocess.run(cmd+list(map(str,sources))+libs+['-o',str(binary)],check=True,timeout=60)
        subprocess.run([str(binary)],check=True,capture_output=True,timeout=10)
    def test_source_isolated_capture_close_finalization(self):
        binary=self.out/'finalization-models'
        sources=[HERE/'test_runner_finalization.c',BASE/'bootstrap-probe/probe_report.c']
        cmd=shlex.split(os.environ.get('CC','cc'))+['-std=c11','-D_DEFAULT_SOURCE','-D_DARWIN_C_SOURCE','-Wall','-Wextra','-Werror','-O1']
        if os.environ.get('GLUE_RUNNER_SANITIZE')=='1':cmd+=['-g','-fsanitize=address,undefined','-fno-omit-frame-pointer']
        subprocess.run(cmd+list(map(str,sources))+['-o',str(binary)],check=True,timeout=60)
        subprocess.run([str(binary)],check=True,capture_output=True,timeout=10)
    def test_source_isolated_child_sequence_models(self):
        binary=self.out/'child-models'
        sources=[HERE/'test_runner_child.c',BASE/'bootstrap-wire/bootstrap_wire.c']
        cmd=shlex.split(os.environ.get('CC','cc'))+['-std=c11','-D_DEFAULT_SOURCE','-D_DARWIN_C_SOURCE','-Wall','-Wextra','-Werror','-O1']
        if os.environ.get('GLUE_RUNNER_SANITIZE')=='1':cmd+=['-g','-fsanitize=address,undefined','-fno-omit-frame-pointer']
        subprocess.run(cmd+list(map(str,sources))+['-o',str(binary)],check=True,timeout=60)
        subprocess.run([str(binary)],check=True,capture_output=True,timeout=10)
    def test_independent_catalog_golden(self):
        actual=subprocess.run([str(self.binary),'catalog'],check=True,capture_output=True,timeout=10).stdout
        expected=bytearray(192)
        expected[:8]=b'GLUENC01'
        struct.pack_into('>HHIQ',expected,8,1,192,212,123)
        struct.pack_into('>QiiQii',expected,24,1,2,-3,4,-5,6)
        expected[56:184]=bytes(range(128))
        struct.pack_into('>HH',expected,184,7,13)
        expected+=b'build-1context-probe'
        self.assertEqual(actual,expected)
        self.assertEqual(hashlib.sha256(actual).digest(),hashlib.sha256(expected).digest())
    def test_native_build_and_refusal_before_output(self):
        if os.environ.get('GLUE_RUNNER_SANITIZE')=='1':self.skipTest('full native CLI is not linked into sanitizer models')
        binary=self.out/'native'
        subprocess.run(['sh',str(HERE/'build.sh'),str(binary)],check=True,timeout=60)
        if platform.system()=='Darwin' and os.getuid()==0:self.skipTest('never execute native CLI as root in these controls')
        output=self.out/'must-not-exist'
        p=subprocess.run([str(binary),'--request',str(self.out/'missing-request'),'--output',str(output)],capture_output=True,timeout=5)
        self.assertEqual(p.returncode,2)
        self.assertFalse(output.exists())
        self.assertEqual(p.stdout,b'')
    def test_cli_argument_refusal(self):
        if os.environ.get('GLUE_RUNNER_SANITIZE')=='1':self.skipTest('full native CLI is not linked into sanitizer models')
        binary=self.out/'args-native'
        subprocess.run(['sh',str(HERE/'build.sh'),str(binary)],check=True,timeout=60)
        for args in ([],['--request','x'],['--other','x','--output','y']):
            with self.subTest(args=args):
                self.assertEqual(subprocess.run([str(binary),*args],capture_output=True,timeout=5).returncode,2)
if __name__=='__main__':unittest.main(verbosity=2)
