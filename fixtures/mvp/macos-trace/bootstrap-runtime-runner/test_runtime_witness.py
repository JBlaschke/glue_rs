"""Portable byte/adapter controls; no provider, owned child or native admission.

The production witness module is linked unchanged with explicit test-only SHA,
new-file writer and first-error stubs. Expected wire bytes are independently
assembled here. There is no C decoder or truncation-acceptance assertion.
"""
import errno
import hashlib
import json
import os
from pathlib import Path
import re
import struct
import subprocess
import tempfile
import unittest

HERE = Path(__file__).resolve().parent


def sources():
    pending = [HERE / "test_runtime_witness.c", HERE / "runtime_witness.c"]
    found = {}
    while pending:
        path = pending.pop().resolve()
        if path in found:
            continue
        data = path.read_bytes()
        found[path] = data
        for include in re.findall(rb'^\s*#include\s+"([^"]+)"', data, re.MULTILINE):
            pending.append(path.parent / include.decode("ascii"))
    found[Path(__file__).resolve()] = Path(__file__).read_bytes()
    return found


def identity(data):
    return {"size": len(data), "sha256": hashlib.sha256(data).hexdigest()}


def ready_digest(changed=False):
    # Explicit deterministic SHA stub, never a claim of cryptographic hashing.
    ready = bytes((11 + i * 9 + int(changed)) & 255 for i in range(512))
    return bytes(ready[(i * 7) % 512] ^ i ^ 0xA5 for i in range(32))


def header(magic, length, ready=None):
    result = bytearray(length)
    struct.pack_into(">8sIIII", result, 0, magic, 1, length, 0x1234, 0x3456)
    result[32:64] = bytes(range(32))
    result[64:96] = bytes(range(0x40, 0x60))
    result[96:128] = bytes(range(0x80, 0xA0)) if ready is None else ready
    return result


def expected_output(count, ready=None, failed=True):
    result = header(b"GLUERW01", 320, ready)
    struct.pack_into(">I", result, 24, count)
    # Fixed transport enum words: reference-second=11, syscall=6.
    error = (11, 6, errno.EIO, 1, 17) if failed else (0, 0, 0, 0xFFFFFFFF, 0xFFFFFFFF)
    struct.pack_into(">5I", result, 128, *error)
    for i in range(count):
        struct.pack_into(">4I3Q", result, 160 + i * 40,
                         23 if i % 2 else 17, 0x12345678 + i, 0x71234567 + i,
                         0xFEDCBA98 + i, 0x0123456789ABCDEF + i,
                         0xFEDCBA9876543210 + i, 0x1122334455667788 + i)
    return bytes(result)


def expected_delivery(mode, ready=None):
    result = header(b"GLUERD01", 240, ready)
    action, attempted, count = (2, 0, 0) if mode == 4 else (1, 1, 19 if mode == 1 else 64)
    struct.pack_into(">2I", result, 24, action, attempted)
    # write=7/observer=9, syscall=11/observer=20; success error-count is zero.
    error = (7, 11, errno.EPIPE, 19) if mode == 1 else (9, 20, 0, 64) if mode == 2 else (0, 0, 0, 0)
    written = 0xFFFFFFFF if mode in (1, 2) else 0
    closed, saved = (0xFFFFFFFF, errno.EIO) if mode == 3 else (0, 0)
    struct.pack_into(">9I", result, 128, count, *error, written, 1, closed, saved)
    result[176:176 + count] = bytes((i * 3 + 7) & 255 for i in range(count))
    return bytes(result)


class RuntimeWitnessControls(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.temporary = None
        retain = os.environ.get("GLUE_RUNTIME_WITNESS_RETAIN")
        if retain:
            cls.output = Path(retain)
            cls.output.mkdir(parents=True, exist_ok=False, mode=0o700)
        else:
            cls.temporary = tempfile.TemporaryDirectory(prefix="glue runtime witness ü ")
            cls.output = Path(cls.temporary.name)
        cls.before = sources()
        cls.source_identities = {str(p): identity(data) for p, data in sorted(cls.before.items())}
        (cls.output / "sources.json").write_text(json.dumps(cls.source_identities, indent=2) + "\n")
        sanitizer = os.environ.get("GLUE_RUNTIME_WITNESS_SANITIZERS", "0")
        if sanitizer not in ("0", "1"):
            raise ValueError("GLUE_RUNTIME_WITNESS_SANITIZERS must be 0 or 1")
        cls.binary = cls.output / "witness-controls"
        argv = ["/usr/bin/cc", "-std=c11", "-D_DEFAULT_SOURCE", "-D_DARWIN_C_SOURCE",
                "-Wall", "-Wextra", "-Werror", "-O1", "-g"]
        if sanitizer == "1":
            argv += ["-fsanitize=address,undefined", "-fno-omit-frame-pointer"]
        argv += [str(HERE / "test_runtime_witness.c"), str(HERE / "runtime_witness.c"), "-o", str(cls.binary)]
        result = subprocess.run(argv, capture_output=True, timeout=60)
        cls.record("compile", argv, result)
        if result.returncode:
            raise AssertionError(result.stderr.decode("utf-8", "replace"))

    @classmethod
    def record(cls, label, argv, result):
        streams = {}
        for stream in ("stdout", "stderr"):
            data = getattr(result, stream)
            name = label + "." + stream
            (cls.output / name).write_bytes(data)
            streams[stream] = {"path": name, **identity(data)}
        (cls.output / (label + ".json")).write_text(json.dumps(
            {"argv": argv, "status": result.returncode, **streams}, indent=2) + "\n")

    @classmethod
    def tearDownClass(cls):
        after = sources()
        if after != cls.before:
            raise AssertionError("witness source/header bytes changed during controls")
        if cls.temporary:
            cls.temporary.cleanup()

    def control(self, *arguments):
        argv = [str(self.binary), *map(str, arguments)]
        result = subprocess.run(argv, capture_output=True, timeout=10)
        self.record("-".join(map(str, arguments)), argv, result)
        self.assertEqual(result.returncode, 0, result.stderr.decode("utf-8", "replace"))
        self.assertEqual(result.stderr, b"")
        return result.stdout

    def test_original_sample_prefixes_zero_through_four_have_no_unread_rows(self):
        for count in range(5):
            with self.subTest(count=count):
                actual = self.control("output", count)
                self.assertEqual(actual, expected_output(count))
                self.assertEqual(actual[160 + 40 * count:], bytes(160 - 40 * count))

    def test_output_full_words_errors_bounds_and_refusals(self):
        self.assertIn(b"full integer widths retained", self.control("output-refusals"))

    def test_successful_go_has_64_prefix_bytes_and_zero_error_byte_count(self):
        self.assertEqual(self.control("delivery", 0), expected_delivery(0))

    def test_partial_failed_go_retains_19_opaque_confirmed_bytes(self):
        self.assertEqual(self.control("delivery", 1), expected_delivery(1))

    def test_failed_full_go_keeps_failure_and_all_64_confirmed_bytes(self):
        self.assertEqual(self.control("delivery", 2), expected_delivery(2))

    def test_gate_close_failure_keeps_its_separate_native_errno(self):
        self.assertEqual(self.control("delivery", 3), expected_delivery(3))

    def test_provider_failure_action_has_unattempted_empty_go(self):
        self.assertEqual(self.control("delivery", 4), expected_delivery(4))

    def test_delivery_invalid_ranges_clear_all_advertised_bytes(self):
        self.assertIn(b"complete cleared output", self.control("delivery-refusals"))

    def test_actual_ready_adapter_binds_parent_ids_hashes_and_first_512_bytes(self):
        self.assertEqual(self.control("ready"), expected_output(4, ready_digest(), failed=False))

    def test_actual_ready_mutation_changes_only_bound_stub_digest(self):
        self.assertEqual(self.control("ready-changed"), expected_output(4, ready_digest(True), failed=False))
        self.assertNotEqual(ready_digest(True), ready_digest())

    def test_actual_ready_adapter_retains_match_failure_and_completed_prefix(self):
        self.assertEqual(self.control("ready-prefix"), expected_output(2, ready_digest()))

    def test_actual_delivery_adapters_keep_all_result_and_close_outcomes(self):
        for mode in range(5):
            with self.subTest(mode=mode):
                self.assertEqual(self.control("adapter-delivery", mode), expected_delivery(mode, ready_digest()))

    def test_actual_adapters_refuse_invalid_binding_and_retain_write_failures(self):
        self.assertIn(b"preserves first error", self.control("adapter-refusals"))


if __name__ == "__main__":
    unittest.main()
