#!/usr/bin/env python3
"""Read-only native observation and enclosing-parent invariants."""
import fcntl
import json
import os
from pathlib import Path
import platform
import signal
import subprocess
import tempfile
import unittest
HERE = Path(__file__).resolve().parent

def snapshot():
    return (os.getuid(), os.geteuid(), os.getgid(), os.getegid(), tuple(os.getgroups()),
            os.getcwd(), tuple(signal.pthread_sigmask(signal.SIG_BLOCK, [])),
            signal.getsignal(signal.SIGPIPE),
            tuple((fcntl.fcntl(fd, fcntl.F_GETFD), fcntl.fcntl(fd, fcntl.F_GETFL)) for fd in range(3)))

class DeploymentInspectorTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        temp = tempfile.TemporaryDirectory(prefix='glue-deployment-inspector-')
        cls.addClassCleanup(temp.cleanup)
        cls.binary = Path(temp.name) / 'inspect'
        command = ['cc', '-std=c11', '-O2', '-Wall', '-Wextra', '-Werror',
                   str(HERE / 'inspect_deployment.c'),
                   str(HERE.parent / 'bootstrap-admission/bootstrap_admission.c'), '-o', str(cls.binary)]
        r = subprocess.run(command, capture_output=True, text=True, timeout=30)
        if r.returncode:
            raise RuntimeError(r.stdout+r.stderr)
    def call(self, *args):
        before = snapshot()
        r = subprocess.run([str(self.binary), *args], capture_output=True, timeout=5)
        self.assertEqual(snapshot(), before)
        return r
    def test_no_arbitrary_arguments(self):
        r = self.call('/tmp/anything')
        self.assertEqual((r.returncode, r.stdout, r.stderr),
                         (2, b'', b'inspector: no arguments accepted\n'))
    def test_linux_native_explicitly_unsupported(self):
        if platform.system() != 'Linux':
            self.skipTest('Linux-only unsupported check')
        r = self.call()
        self.assertEqual((r.returncode, r.stdout, r.stderr),
                         (1, b'', b'inspector: native Darwin required\n'))
    def test_native_readonly_directory_profile_and_identity(self):
        if platform.system() != 'Darwin':
            self.skipTest('requires native Darwin API')
        if not all((os.getuid(), os.geteuid(), os.getgid(), os.getegid())):
            self.skipTest('requires actual ordinary user')
        paths = ['/', '/System', '/System/Volumes', '/System/Volumes/Data', '/System/Volumes/Data/Library']
        before = [os.stat(p) for p in paths]
        r = self.call()
        self.assertEqual((r.returncode, r.stderr), (0, b''))
        self.assertLess(len(r.stdout), 16384)
        def exact(pairs):
            result = {}
            for key, value in pairs:
                self.assertNotIn(key, result)
                result[key] = value
            return result
        d = json.loads(r.stdout, object_pairs_hook=exact)
        self.assertEqual(set(d), {'schema','model','kernel_release','observed_unix_seconds',
                                 'observed_nanoseconds','ids','groups','tc_compatible','components',
                                 'settings_changed','executable_admission','full_acceptance'})
        self.assertEqual(d['schema'], 'glue-bootstrap-deployment-observation-v1')
        self.assertEqual(d['ids'], [os.getuid(), os.geteuid(), os.getgid(), os.getegid()])
        self.assertEqual(d['groups'], os.getgroups())
        g = d['groups']
        compatible = (1 <= len(g) <= 16 and g[0] == os.getgid() and len(set(g)) == len(g)
                      and all(0 <= n <= 2147483647 for n in g) and os.getuid() == os.geteuid()
                      and os.getgid() == os.getegid())
        self.assertEqual(d['tc_compatible'], compatible)
        self.assertGreater(d['observed_unix_seconds'], 0)
        self.assertTrue(0 <= d['observed_nanoseconds'] < 1000000000)
        self.assertRegex(d['model'], r'^[A-Za-z0-9,_.-]+$')
        self.assertRegex(d['kernel_release'], r'^[A-Za-z0-9,_.-]+$')
        self.assertEqual(len(d['components']), 5)
        for i, c in enumerate(d['components']):
            self.assertEqual(set(c), {'name','device','inode','uid','gid','mode','fsid','mount_flags',
                                     'mount_policy','mount_owner','descriptor_flags','status_flags',
                                     'mountpoint','filesystem','filesec_population','acl_present'})
            self.assertEqual(c['name'], ['/', 'System', 'Volumes', 'Data', 'Library'][i])
            self.assertEqual(c['device'], before[i].st_dev & 0xFFFFFFFF)
            self.assertEqual((c['inode'], c['mode'], c['uid'], c['gid']),
                             (before[i].st_ino, before[i].st_mode, before[i].st_uid, before[i].st_gid))
            self.assertEqual(c['filesec_population'], 7)
            self.assertEqual(c['acl_present'], 0)
            self.assertEqual(c['mount_owner'], 0)
            self.assertEqual(c['filesystem'], 'apfs')
            self.assertEqual(c['mountpoint'], '/' if i < 3 else '/System/Volumes/Data')
            self.assertEqual(c['mount_policy'], 3 if i < 3 else 1)
            self.assertEqual(len(c['fsid']), 2)
            self.assertTrue(all(type(n) is int and -(2**31) <= n < 2**31 for n in c['fsid']))
            after = os.stat(paths[i])
            self.assertEqual((after.st_dev, after.st_ino, after.st_mode, after.st_uid, after.st_gid),
                             (before[i].st_dev, before[i].st_ino, before[i].st_mode, before[i].st_uid, before[i].st_gid))
        self.assertEqual([d[x] for x in ('settings_changed','executable_admission','full_acceptance')],
                         [False, False, False])

if __name__ == '__main__':
    unittest.main()
