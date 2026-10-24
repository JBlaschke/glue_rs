"""Portable proof replay and native tests for the CI-only trace environment."""
import errno
import hashlib
import json
import platform
import shutil
import subprocess
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

import trace_environment


SUPPORTED = platform.system() == "Linux" and platform.machine() in {"x86_64", "aarch64"}
ASYNC_CALLS = {
    "io_uring_setup", "io_uring_enter", "io_uring_register", "io_setup",
    "io_destroy", "io_submit", "io_cancel", "io_getevents", "io_pgetevents",
}

# Literal serialized Linux observations, independent of host errno or checker
# constants. These are portable fixtures, not native execution evidence.
LINUX_PROOF = b'''{
  "policy":"traceable-native-syscalls-v1","architecture":"x86_64","status":"passed",
  "before_policy":{"setup_succeeded":false,"setup_errno":13},
  "parent":{"no_new_privs":1,"seccomp_mode":2,"ordinary_file_io":true,"native_syscalls_allowed":true,
    "abi_guards":{"x32_errno":38,"i386_errno":38},"syscalls":[
      {"name":"io_uring_setup","errno":38},{"name":"io_uring_enter","errno":38},
      {"name":"io_uring_register","errno":38},{"name":"io_setup","errno":38},
      {"name":"io_destroy","errno":38},{"name":"io_submit","errno":38},
      {"name":"io_cancel","errno":38},{"name":"io_getevents","errno":38},
      {"name":"io_pgetevents","errno":38}]},
  "inherited_exec_child":{"no_new_privs":1,"seccomp_mode":2,"ordinary_file_io":true,"native_syscalls_allowed":true,
    "abi_guards":{"x32_errno":38,"i386_errno":38},"syscalls":[
      {"name":"io_uring_setup","errno":38},{"name":"io_uring_enter","errno":38},
      {"name":"io_uring_register","errno":38},{"name":"io_setup","errno":38},
      {"name":"io_destroy","errno":38},{"name":"io_submit","errno":38},
      {"name":"io_cancel","errno":38},{"name":"io_getevents","errno":38},
      {"name":"io_pgetevents","errno":38}]}
}'''


def portable_proof(architecture):
    proof = json.loads(LINUX_PROOF)
    if architecture == "aarch64":
        proof["architecture"] = "aarch64"
        for label in ("parent", "inherited_exec_child"):
            del proof[label]["abi_guards"]
    return proof


class PortableProofTests(unittest.TestCase):
    def write_fixture(self, directory, architecture):
        # Only ordinary synthetic bytes are retained; nothing is compiled or
        # executed by these portable file/manifest controls.
        (directory / "trace_environment.c").write_bytes(b"/* synthetic source identity */\n")
        (directory / "glue-trace-environment").write_bytes(b"synthetic helper; never executed\n")
        (directory / "proof.json").write_text(json.dumps(portable_proof(architecture)) + "\n")

    def test_supported_serialized_proof_ignores_replay_host_errno(self):
        for architecture in ("x86_64", "aarch64"):
            proof = json.loads(json.dumps(portable_proof(architecture)))
            before = json.dumps(proof, sort_keys=True)
            # On Linux CI this still exercises the macOS value; on macOS it
            # exercises the real bug without borrowing errno values from it.
            with patch.object(errno, "ENOSYS", 78):
                trace_environment.check_proof(proof, architecture)
            self.assertEqual(json.dumps(proof, sort_keys=True), before)

    def test_async_errno_requires_linux_value_in_each_process(self):
        for architecture in ("x86_64", "aarch64"):
            for label in ("parent", "inherited_exec_child"):
                for value in (0, 1, 37, 39, 78, None):
                    with self.subTest(architecture=architecture, label=label, errno=value):
                        proof = portable_proof(architecture)
                        proof[label]["syscalls"][0]["errno"] = value
                        with patch.object(errno, "ENOSYS", 78):
                            with self.assertRaisesRegex(ValueError, "async syscall did not return ENOSYS"):
                                trace_environment.check_proof(proof, architecture)

    def test_x86_guard_errno_requires_linux_value(self):
        for label in ("parent", "inherited_exec_child"):
            for guard in ("x32_errno", "i386_errno"):
                for value in (0, 1, 78):
                    proof = portable_proof("x86_64")
                    proof[label]["abi_guards"][guard] = value
                    with patch.object(errno, "ENOSYS", 78):
                        with self.assertRaisesRegex(ValueError, "x32/i386 ABI guard"):
                            trace_environment.check_proof(proof, "x86_64")

    def test_unsupported_architecture_and_declared_mismatch_refuse(self):
        for architecture in ("arm64", "i386", "x32", "riscv64", "unknown", None, True, ["x86_64"]):
            with self.subTest(architecture=architecture):
                with self.assertRaisesRegex(ValueError, "unsupported Linux trace proof architecture"):
                    trace_environment.check_proof(portable_proof("x86_64"), architecture)
        with self.assertRaisesRegex(ValueError, "architecture or probe status differs"):
            trace_environment.check_proof(portable_proof("x86_64"), "aarch64")

    def test_existing_proof_controls_remain_required(self):
        for label in ("parent", "inherited_exec_child"):
            for change in ("missing-call", "duplicate-call", "no_new_privs", "seccomp_mode",
                           "ordinary_file_io", "native_syscalls_allowed"):
                proof = portable_proof("x86_64")
                if change == "missing-call":
                    proof[label]["syscalls"].pop()
                elif change == "duplicate-call":
                    proof[label]["syscalls"][-1] = proof[label]["syscalls"][0]
                else:
                    proof[label][change] = 0
                with self.subTest(label=label, change=change):
                    with self.assertRaises(ValueError):
                        trace_environment.check_proof(proof, "x86_64")
        for changes in ({"setup_succeeded":True,"setup_errno":13},
                        {"setup_succeeded":False,"setup_errno":0},
                        {"setup_succeeded":1,"setup_errno":0}):
            proof = portable_proof("x86_64")
            proof["before_policy"] = changes
            with self.assertRaises(ValueError):
                trace_environment.check_proof(proof, "x86_64")

    def test_file_checker_retains_source_helper_proof_and_manifest_checks(self):
        for architecture in ("x86_64", "aarch64"):
            with tempfile.TemporaryDirectory(prefix="glue portable proof ü ") as temporary:
                directory = Path(temporary)
                self.write_fixture(directory, architecture)
                originals = {name:(directory / name).read_bytes() for name in
                             ("trace_environment.c", "glue-trace-environment", "proof.json")}
                with patch.object(errno, "ENOSYS", 78):
                    manifest = trace_environment.check(directory, architecture, record=True)
                    self.assertEqual(trace_environment.check(directory, architecture), manifest)
                self.assertEqual(manifest["architecture"], architecture)
                self.assertEqual(manifest["policy"], "traceable-native-syscalls-v1")
                self.assertEqual(manifest["setup_control"], "already-unavailable")
                self.assertEqual(manifest["files"], {name:{"size":len(raw),"sha256":hashlib.sha256(raw).hexdigest()}
                                                     for name,raw in originals.items()})
                for name,raw in originals.items():
                    (directory / name).write_bytes(raw + b"\n")  # proof remains valid JSON
                    with self.assertRaisesRegex(ValueError, "identity or policy changed"):
                        trace_environment.check(directory, architecture)
                    (directory / name).write_bytes(raw)
                manifest_path = directory / "manifest.json"
                original_manifest = manifest_path.read_bytes()
                changed = json.loads(original_manifest)
                changed["policy"] = "different-policy"
                manifest_path.write_text(json.dumps(changed))
                with self.assertRaisesRegex(ValueError, "identity or policy changed"):
                    trace_environment.check(directory, architecture)
                manifest_path.write_bytes(original_manifest)
                self.assertEqual(trace_environment.check(directory, architecture), manifest)

    def test_invalid_proof_cannot_record_a_manifest(self):
        with tempfile.TemporaryDirectory() as temporary:
            directory = Path(temporary)
            self.write_fixture(directory, "x86_64")
            proof = portable_proof("x86_64")
            proof["inherited_exec_child"]["syscalls"][0]["errno"] = 78
            (directory / "proof.json").write_text(json.dumps(proof))
            with self.assertRaisesRegex(ValueError, "async syscall did not return ENOSYS"):
                trace_environment.check(directory, "x86_64", record=True)
            self.assertFalse((directory / "manifest.json").exists())


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
