"""Compile/run the actual bounded writer; observer stop/lease remains modeled."""
import hashlib
import json
import os
from pathlib import Path
import platform
import subprocess
import sys
import tempfile
import unittest

HERE = Path(__file__).resolve().parent
OBSERVER = HERE.parent / "post-exec-output"


class RetentionControls(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.temp = None
        if os.environ.get("PXRET_CONTROL_DIR"):
            cls.output = Path(os.environ["PXRET_CONTROL_DIR"])
            cls.output.mkdir(parents=True, exist_ok=False)
        else:
            cls.temp = tempfile.TemporaryDirectory(prefix="glue-retention-controls-")
            cls.output = Path(cls.temp.name)
        cls.sanitize = os.environ.get("PXRET_SANITIZE", "0")
        if cls.sanitize not in ("0", "1"):
            raise ValueError("PXRET_SANITIZE must be0/1")
        sources = list(HERE.glob("*.c")) + list(HERE.glob("*.h"))
        sources += [OBSERVER / n for n in ("post_exec_output.c", "post_exec_output.h", "post_exec_output_test.h")]
        cls.before = {p: p.read_bytes() for p in sources}
        cls.flags = ["/usr/bin/cc", "-std=c11", "-Wall", "-Wextra", "-Werror", "-O2"]
        if cls.sanitize == "1":
            cls.flags += ["-O1", "-g", "-fsanitize=address,undefined", "-fno-omit-frame-pointer"]
        if platform.system() == "Darwin":
            sdk = subprocess.run(["/usr/bin/xcrun", "--sdk", "macosx", "--show-sdk-path"],
                                 capture_output=True, text=True, check=True, timeout=15).stdout.strip()
            cls.flags += ["-isysroot", sdk, "-mmacosx-version-min=11.0"]
        cls.binary = cls.output / "retention-controls"
        argv = cls.flags + ["-DPX_TESTING", "-DPXRET_TESTING", str(OBSERVER / "post_exec_output.c"),
            str(HERE / "post_exec_retention.c"), str(HERE / "test_post_exec_retention.c")]
        if platform.system() == "Darwin":
            argv += ["-lproc"]
        argv += ["-o", str(cls.binary)]
        result = subprocess.run(argv, capture_output=True, timeout=60)
        (cls.output / "compile.stdout").write_bytes(result.stdout)
        (cls.output / "compile.stderr").write_bytes(result.stderr)
        cls.compile_record = {"argv": argv, "exit_status": result.returncode, "python": sys.version,
            "host": platform.platform(), "sanitize": cls.sanitize,
            "sources": {str(p): hashlib.sha256(v).hexdigest() for p, v in cls.before.items()},
            "native_observer_stop_or_lease": False, "provider_or_signals": False}
        if result.returncode == 0:
            cls.compile_record["binary_sha256"] = hashlib.sha256(cls.binary.read_bytes()).hexdigest()
        (cls.output / "compile.json").write_text(json.dumps(cls.compile_record, indent=2) + "\n")
        if result.returncode:
            raise AssertionError(result.stderr.decode("utf-8", "replace"))

    @classmethod
    def tearDownClass(cls):
        changed = [str(p) for p, old in cls.before.items() if p.read_bytes() != old]
        (cls.output / "source-after.json").write_text(json.dumps({"changed": changed,
            "sources": {str(p): hashlib.sha256(p.read_bytes()).hexdigest() for p in cls.before}}, indent=2) + "\n")
        if cls.temp is not None:
            cls.temp.cleanup()
        if changed:
            raise AssertionError("source changed during controls: " + ", ".join(changed))

    def control(self, name, real_file=False):
        argv = [str(self.binary), name]
        if real_file:
            directory = self.output / (name + "-owned-directory")
            directory.mkdir(mode=0o700)
            argv.append(str(directory))
        result = subprocess.run(argv, capture_output=True, timeout=45)
        (self.output / (name + ".stdout")).write_bytes(result.stdout)
        (self.output / (name + ".stderr")).write_bytes(result.stderr)
        (self.output / (name + ".result.json")).write_text(json.dumps({"argv": argv,
            "exit_status": result.returncode, "file_io": "real" if real_file else "modeled",
            "observer_stop_lease": "modeled", "provider_or_signals": False}, indent=2) + "\n")
        self.assertEqual(result.returncode, 0, result.stderr.decode("utf-8", "replace"))
        return result.stdout

    def test_original_encoder_content_is_written_once_then_file_synced_and_closed(self):
        self.control("success")

    def test_pending_failed_terminal_lost_owner_uid_and_deadline_refuse_before_open(self):
        self.control("bad-observers")

    def test_borrowed_directory_and_new_file_flags_owner_mode_type_size_and_links(self):
        self.control("metadata")

    def test_all4095_short_lengths_and64_call_EINTR_bound(self):
        self.assertIn(b"short_lengths=4095 eintr_boundaries=2", self.control("short-writes"))

    def test_native_return_errno_prefix_zero_oversize_sync_and_unresolved_close(self):
        self.control("syscalls")

    def test_every_clock_point_and_late_open_write_sync_close_preserve_actual_facts(self):
        self.assertIn(b"clock_points=63 after_call_lateness=4", self.control("clocks"))

    def test_bad_arguments_pure_zeroed_getters_no_replay_or_free_cleanup(self):
        self.control("arguments")

    def test_real_owned_file4096_exact_bytes_and_borrowed_fd_unchanged(self):
        self.assertIn(b"file_io=real observer_stop_and_lease=model provider=none signals=none",
                      self.control("real", True))

    def test_real_existing_file_is_never_overwritten_or_reopened(self):
        self.control("existing", True)

    def test_real_borrowed_fd_without_cloexec_is_refused_without_mutation(self):
        self.control("no-cloexec", True)

    def test_real_existing_symlink_is_never_followed_or_replaced(self):
        self.control("symlink", True)

    def test_production_object_exposes_no_test_factory_or_signal_interface(self):
        output = self.output / "production-writer.o"
        argv = self.flags + ["-c", str(HERE / "post_exec_retention.c"), "-o", str(output)]
        result = subprocess.run(argv, capture_output=True, timeout=45)
        (self.output / "production-compile.stderr").write_bytes(result.stderr)
        self.assertEqual(result.returncode, 0, result.stderr.decode("utf-8", "replace"))
        symbols = subprocess.run(["/usr/bin/nm", "-g", str(output)], capture_output=True,
                                 check=True, timeout=15).stdout.decode("utf-8", "replace")
        (self.output / "production-symbols.txt").write_text(symbols)
        self.assertNotIn("px_retention_model_new", symbols)
        self.assertNotIn("_kill", symbols)
        self.assertNotIn("_waitpid", symbols)
        self.assertIn("px_observer_encode", symbols)
        self.assertIn("px_observer_owns_child", symbols)


if __name__ == "__main__":
    unittest.main()
