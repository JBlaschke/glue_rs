"""Native ordinary-user owned-process controls; run only after source review."""
import fcntl
import hashlib
import os
from pathlib import Path
import platform
import signal
import struct
import subprocess
import tempfile
import unittest

HERE = Path(__file__).resolve().parent
DIGEST = hashlib.sha256(b"owned probe native unit request v1\n").hexdigest()


def snapshot():
    return (os.getuid(), os.geteuid(), os.getgid(), os.getegid(), tuple(os.getgroups()),
            os.getcwd(), os.getpgrp(), tuple((fcntl.fcntl(fd, fcntl.F_GETFL),
                                           fcntl.fcntl(fd, fcntl.F_GETFD)) for fd in range(3)),
            tuple(signal.pthread_sigmask(signal.SIG_BLOCK, [])), signal.getsignal(signal.SIGPIPE))


class NativeContextProbeTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.temporary = tempfile.TemporaryDirectory(prefix="glue-owned-probe-")
        cls.addClassCleanup(cls.temporary.cleanup)
        cls.directory = Path(cls.temporary.name)
        cls.probe, cls.driver = cls.directory / "context-probe", cls.directory / "context-driver"
        common = ["cc", "-std=c11", "-Wall", "-Wextra", "-Werror", "-O2"]
        libs = ["-lproc"] if platform.system() == "Darwin" else []
        subprocess.run(common + [str(HERE / "probe_report.c"), str(HERE / "context_probe.c"),
                                 *libs, "-o", str(cls.probe)], check=True, capture_output=True, timeout=30)
        subprocess.run(common + [str(HERE / "test_context_probe_driver.c"), "-o", str(cls.driver)],
                       check=True, capture_output=True, timeout=30)

    def call(self, args, env=None, own_group=True):
        before = snapshot()
        p = subprocess.Popen(args, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
                             stderr=subprocess.PIPE, env={} if env is None else env,
                             cwd=self.directory, close_fds=True, start_new_session=own_group)
        try:
            stdout, stderr = p.communicate(timeout=3)
        except subprocess.TimeoutExpired:
            # Popen owns this exact unreaped child; the test driver never forks.
            if p.poll() is None:
                p.kill()
            stdout, stderr = p.communicate(timeout=2)
            self.fail(f"owned child exceeded deadline: {p.returncode}, {len(stdout)}, {stderr!r}")
        self.assertEqual(snapshot(), before)
        return p.returncode, stdout, stderr

    def darwin(self):
        if platform.system() != "Darwin":
            self.skipTest("native probe is Darwin-only")
        if not all((os.getuid(), os.geteuid(), os.getgid(), os.getegid())):
            self.skipTest("native controls require an ordinary user, no host root")

    def canonical_groups(self):
        self.darwin()
        groups = os.getgroups()
        if (not 1 <= len(groups) <= 16 or groups[0] != os.getgid()
                or len(set(groups)) != len(groups) or any(not 0 <= g <= 2147483647 for g in groups)
                or os.getuid() != os.geteuid() or os.getgid() != os.getegid()):
            self.skipTest("actual kernel IDs/ordered group vector outside declared bounds; no normalization")

    def controlled(self, mode, expected_stage=None):
        self.canonical_groups()
        code, out, err = self.call([str(self.driver), str(self.probe), mode, DIGEST])
        if code == 77:
            self.skipTest("existing soft FD capacity cannot reach4096; no limit raised")
        if expected_stage:
            self.assertEqual(code, 1, err)
            self.assertEqual(out, b"")
            self.assertRegex(err.decode(), rf"^GLUENP01 error stage={expected_stage} errno=[0-9]+\n$")
        return code, out, err

    def test_exact_argv_lowercase_digest_and_no_action(self):
        for extra in ([], ["--request-sha256", "A" * 64], ["--request-sha256", "0" * 63],
                      ["--request-sha256", DIGEST, "extra"], ["--anything", DIGEST]):
            code, out, err = self.call([str(self.probe), *extra])
            self.assertEqual(code, 1)
            self.assertEqual(out, b"")
            self.assertEqual(err, b"GLUENP01 error stage=argument errno=0\n")

    def test_linux_native_explicitly_unsupported(self):
        if platform.system() != "Linux":
            self.skipTest("Linux-only unsupported adapter control")
        code, out, err = self.call([str(self.probe), "--request-sha256", DIGEST])
        self.assertEqual(code, 1)
        self.assertEqual(out, b"")
        self.assertRegex(err.decode(), r"^GLUENP01 error stage=platform errno=[1-9][0-9]*\n$")

    def test_native_nonempty_environment_fails_before_report(self):
        self.darwin()
        code, out, err = self.call([str(self.probe), "--request-sha256", DIGEST], env={"GLUE_UNIT": "1"})
        self.assertEqual((code, out, err), (1, b"", b"GLUENP01 error stage=environment errno=0\n"))

    def test_native_missing_owned_process_group_rejects(self):
        self.darwin()
        code, out, err = self.call([str(self.probe), "--request-sha256", DIGEST], own_group=False)
        self.assertEqual((code, out, err), (1, b"", b"GLUENP01 error stage=process errno=0\n"))

    def test_native_noncanonical_actual_groups_are_rejected_without_normalization(self):
        self.darwin()
        groups = os.getgroups()
        if 1 <= len(groups) <= 16 and groups[0] == os.getgid() and len(set(groups)) == len(groups):
            self.skipTest("actual group vector is canonical; positive control covers it")
        code, out, err = self.call([str(self.probe), "--request-sha256", DIGEST])
        self.assertEqual((code, out, err), (1, b"", b"GLUENP01 error stage=groups errno=0\n"))

    def test_native_positive_actual_failed_root_regain_and_context(self):
        code, out, err = self.controlled("positive")
        self.assertEqual((code, len(out), err), (0, 256, b""))
        self.assertEqual(struct.unpack_from(">8sHHI32s", out, 0),
                         (b"GLUENP01", 1, 256, 1, bytes.fromhex(DIGEST)))
        pid, parent, pgid = struct.unpack_from(">3I", out, 48)
        self.assertGreater(pid, 0)
        self.assertEqual(parent, os.getpid())
        self.assertEqual(pgid, pid)
        ids = (os.getuid(), os.geteuid(), os.getgid(), os.getegid())
        self.assertEqual(struct.unpack_from(">4I", out, 60), ids)
        count = struct.unpack_from(">I", out, 76)[0]
        self.assertEqual(struct.unpack_from(">16I", out, 80), tuple(os.getgroups()) + (0,) * (16 - count))
        cwd = self.directory.stat()
        self.assertEqual(struct.unpack_from(">QQ", out, 144), (cwd.st_dev & 0xFFFFFFFF, cwd.st_ino))
        self.assertEqual(struct.unpack_from(">I3I", out, 160), (3, 0, 1, 2))
        status = struct.unpack_from(">3I", out, 176)
        self.assertEqual(tuple(x & 3 for x in status), (0, 1, 1))
        self.assertFalse(any(x & (4 | 64 | 32768) for x in status))
        self.assertEqual(struct.unpack_from(">3I", out, 188), (0, 0, 0))
        self.assertEqual(struct.unpack_from(">iI4III", out, 200), (-1, 1, *ids, 1, 0))
        self.assertEqual(out[232:], bytes(24))

    def test_native_extra_live_fd_rejects(self): self.controlled("extra-fd", "descriptors")
    def test_native_sparse_high_fd_rejects(self): self.controlled("high-fd", "descriptors")
    def test_native_nonblocking_stdout_rejects(self): self.controlled("nonblock", "stdio")
    def test_native_wrong_stdin_direction_rejects(self): self.controlled("wrong-direction", "stdio")
    def test_native_cloexec_closed_stdin_rejects(self): self.controlled("closed-stdin", "stdio")
    def test_native_ignored_sigpipe_rejects(self): self.controlled("ignored-pipe", "signals")
    def test_native_blocked_catchable_mask_rejects(self): self.controlled("blocked-mask", "signals")


if __name__ == "__main__":
    unittest.main()
