"""Native execution tests for the CI-only trace environment (not product tests)."""
import errno
import json
import platform
import shutil
import subprocess
import tempfile
import unittest
from pathlib import Path

import trace_environment


SUPPORTED = platform.system() == "Linux" and platform.machine() in {"x86_64", "aarch64"}
ASYNC_CALLS = {
    "io_uring_setup", "io_uring_enter", "io_uring_register", "io_setup",
    "io_destroy", "io_submit", "io_cancel", "io_getevents", "io_pgetevents",
}


@unittest.skipUnless(SUPPORTED, "requires native 64-bit Linux x86_64 or arm64")
class TraceEnvironmentTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.temporary = tempfile.TemporaryDirectory(prefix="glue trace policy ü ")
        cls.root = Path(cls.temporary.name)
        cls.helper = cls.root / "trace environment"
        subprocess.run([
            "cc", "-O2", "-std=c11", "-Wall", "-Wextra", "-Werror",
            str(Path(__file__).with_name("trace_environment.c")), "-o", str(cls.helper),
        ], check=True, capture_output=True)

    @classmethod
    def tearDownClass(cls):
        cls.temporary.cleanup()

    def run_helper(self, *arguments):
        return subprocess.run([str(self.helper), *arguments], capture_output=True, text=True)

    def assert_filtered(self, proof):
        self.assertEqual(proof["no_new_privs"], 1)
        self.assertEqual(proof["seccomp_mode"], 2)
        self.assertTrue(proof["ordinary_file_io"])
        self.assertTrue(proof["native_syscalls_allowed"])
        self.assertEqual({call["name"] for call in proof["syscalls"]}, ASYNC_CALLS)
        self.assertEqual(len(proof["syscalls"]), len(ASYNC_CALLS))
        self.assertTrue(all(call["errno"] == errno.ENOSYS for call in proof["syscalls"]))
        if platform.machine() == "x86_64":
            self.assertEqual(proof["abi_guards"], {"x32_errno": errno.ENOSYS, "i386_errno": errno.ENOSYS})

    def test_actual_syscalls_filter_and_fork_exec_inheritance(self):
        result = self.run_helper("--probe")
        self.assertEqual(result.returncode, 0, result.stderr)
        proof = json.loads(result.stdout)
        self.assertEqual(proof["status"], "passed")
        self.assertEqual(proof["architecture"], platform.machine())
        self.assertEqual(proof["policy"], "traceable-native-syscalls-v1")
        self.assertIsInstance(proof["before_policy"]["setup_succeeded"], bool)
        self.assertEqual(proof["before_policy"]["setup_succeeded"], proof["before_policy"]["setup_errno"] == 0)
        self.assert_filtered(proof["parent"])
        self.assert_filtered(proof["inherited_exec_child"])

    def test_arbitrary_command_and_second_exec_inherit_filter(self):
        result = self.run_helper("--", "/bin/sh", "-c", 'exec "$1" --probe-child', "probe", str(self.helper))
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assert_filtered(json.loads(result.stdout))

    def test_preserves_argv_and_command_exit_status(self):
        result = self.run_helper("--", "/bin/sh", "-c", 'printf "%s" "$1"; exit 42', "args", "literal $() ü space")
        self.assertEqual(result.returncode, 42)
        self.assertEqual(result.stdout, "literal $() ü space")

    def test_invalid_argv_and_exec_errors_fail(self):
        for arguments in [(), ("--",), ("--", ""), ("--probe", "extra"), ("command",)]:
            with self.subTest(arguments=arguments):
                self.assertEqual(self.run_helper(*arguments).returncode, 2)
        self.assertEqual(self.run_helper("--", str(self.root / "missing")).returncode, 127)
        self.assertEqual(self.run_helper("--", str(self.root)).returncode, 126)

    def test_filter_installation_failure_never_executes_command(self):
        # An outer independent filter blocks PR_SET_SECCOMP in the helper.
        # It still permits PR_SET_NO_NEW_PRIVS, exec, and ordinary syscalls.
        source = self.root / "deny-install.c"
        source.write_text(r"""
#define _GNU_SOURCE
#include <errno.h>
#include <linux/filter.h>
#include <linux/seccomp.h>
#include <stddef.h>
#include <sys/prctl.h>
#include <sys/syscall.h>
#include <unistd.h>
int main(int argc, char **argv) {
    if (argc < 2) return 2;
    struct sock_filter rules[] = {
        BPF_STMT(BPF_LD | BPF_W | BPF_ABS, offsetof(struct seccomp_data, nr)),
        BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, __NR_prctl, 0, 3),
        BPF_STMT(BPF_LD | BPF_W | BPF_ABS, offsetof(struct seccomp_data, args[0])),
        BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, PR_SET_SECCOMP, 0, 1),
        BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ERRNO | EPERM),
        BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ALLOW),
    };
    struct sock_fprog program = {sizeof(rules) / sizeof(rules[0]), rules};
    if (prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) || prctl(PR_SET_SECCOMP, SECCOMP_MODE_FILTER, &program)) return 3;
    execv(argv[1], argv + 1);
    return 4;
}
""")
        outer = self.root / "deny-install"
        subprocess.run(["cc", "-O2", "-std=c11", "-Wall", "-Wextra", "-Werror", str(source), "-o", str(outer)], check=True)
        marker = self.root / "must not exist"
        result = subprocess.run([str(outer), str(self.helper), "--", "/usr/bin/touch", str(marker)], capture_output=True, text=True)
        self.assertEqual(result.returncode, 1, result.stderr)
        self.assertIn("install trace environment policy", result.stderr)
        self.assertFalse(marker.exists())

    def test_retained_proof_source_and_helper_hashes_are_rechecked(self):
        directory = self.root / "retained evidence"
        directory.mkdir()
        shutil.copy2(self.helper, directory / "glue-trace-environment")
        shutil.copy2(Path(__file__).with_name("trace_environment.c"), directory)
        result = self.run_helper("--probe")
        self.assertEqual(result.returncode, 0, result.stderr)
        (directory / "proof.json").write_text(result.stdout)
        manifest = trace_environment.check(directory, platform.machine(), record=True)
        self.assertEqual(trace_environment.check(directory, platform.machine()), manifest)
        with (directory / "glue-trace-environment").open("ab") as output:
            output.write(b"changed")
        with self.assertRaisesRegex(ValueError, "identity or policy changed"):
            trace_environment.check(directory, platform.machine())

    def test_incomplete_or_non_enosys_proof_rejects(self):
        result = self.run_helper("--probe")
        self.assertEqual(result.returncode, 0, result.stderr)
        original = json.loads(result.stdout)
        for change in ["missing-call", "wrong-errno", "missing-inheritance"]:
            with self.subTest(change=change):
                proof = json.loads(result.stdout)
                if change == "missing-call":
                    proof["parent"]["syscalls"].pop()
                elif change == "wrong-errno":
                    proof["inherited_exec_child"]["syscalls"][0]["errno"] = errno.EPERM
                else:
                    proof["inherited_exec_child"]["no_new_privs"] = 0
                with self.assertRaises(ValueError):
                    trace_environment.check_proof(proof, platform.machine())
        trace_environment.check_proof(original, platform.machine())


if __name__ == "__main__":
    unittest.main()
