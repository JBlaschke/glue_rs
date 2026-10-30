"""Independent bytes, lifecycle and bounded owned-child observer controls.

Model callbacks are test-only. The sole native fixture self-execs a same-UID child,
observes its self-SIGSTOP, then continues and actually reaps only that child.
There is no provider, debugger, privilege, foreign process or admission action.
"""
import dataclasses
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import platform
import struct
import subprocess
import sys
import tempfile
import unittest

HERE = Path(__file__).resolve().parent
FALSE_AUTHORITY = (
    "native_origin_authenticated", "raw_correlation_verified", "quiescence_proved",
    "ofd_identity_proved", "descriptor_generation_proved", "state_feed_eligible",
    "authorizes_sink_exemptions", "full_flags_proved", "full_trace_acceptance",
)
FIELDS = (
    [(0, 4), (4, 4), (8, 8), (16, 4), (20, 4), (24, 4), (28, 2), (30, 2),
     (32, 8), (40, 4), (44, 4)]
    + [(offset, 8) for offset in range(48, 128, 8)]
    + [(128, 4), (132, 4), (136, 4), (140, 4), (144, 8), (152, 8),
       (160, 4), (164, 4), (168, 4), (172, 4)]
)
assert [i for offset, width in FIELDS for i in range(offset, offset + width)] == list(range(176))


def swap_fields(native):
    result = bytearray(176)
    for offset, width in FIELDS:
        result[offset:offset + width] = native[offset:offset + width][::-1]
    return bytes(result)


def original_fixture():
    result = bytearray(320)
    struct.pack_into(">8s6I", result, 0, b"GLUERW01", 1, 320, 0x1234, 0x3456, 4, 0)
    result[32:64] = bytes(range(32))
    result[64:96] = bytes(range(64, 96))
    result[96:128] = bytes(range(128, 160))
    struct.pack_into(">5I", result, 128, 0, 0, 0, 0xFFFFFFFF, 0xFFFFFFFF)
    for row in range(4):
        role = row % 2
        struct.pack_into(">4I3Q", result, 160 + 40 * row,
                         17 if role == 0 else 23, 1, 1, 0o100600,
                         0xFFFFFFFFFEDCBA98, 0x0123456789ABC001 + role, 1)
    return bytes(result)


def native_fields(query):
    result = bytearray(176)
    role = 2 if query % 2 else 1
    def put(offset, width, value):
        result[offset:offset + width] = value.to_bytes(width, "little")
    put(0, 4, 2 | (0x10000 if query % 2 else 0))
    put(4, 4, (2 if query < 2 or query >= 6 else 0) | (query % 2))
    put(8, 8, 0x8102030405060708 + query)
    put(16, 4, 1)
    put(24, 4, 0xFEDCBA98)
    put(28, 2, 0o100600)
    put(30, 2, 1)
    put(32, 8, 0x0123456789ABC000 + role)
    put(40, 4, 0x89ABCDEF)
    put(44, 4, 0xFEDCBA98)
    for offset in range(48, 128, 8):
        put(offset, 8, 0x9100000000000000 + (offset << 16) + query)
    for offset, value in ((128, 0x81234567), (132, 0x87654321),
                          (136, 0xDABEF00D), (140, 0xF0010203),
                          (160, 1), (164, 0x91ABCDEF),
                          (168, 0x89ABCDEF), (172, 0xFEDCBA98)):
        put(offset, 4, value)
    put(144, 8, 0xFEDCBA9876543210)
    put(152, 8, 0x89ABCDEF01234567)
    return bytes(result)


def expected_packet(metadata):
    result = bytearray(4096)
    struct.pack_into(">8sHHIII", result, 0, b"GLUEPX01", 1, 256, 4096, 0x1234, 0x3456)
    struct.pack_into(">4Q", result, 24, 0x0123456789ABCDEF, 1000000, 7, 0xAABBCCDDEEFF0011)
    struct.pack_into(">4HiIQHH", result, 56, 8, 1, 2, 0, 0, 15, metadata["lastclock"], 1, 0)
    for index in range(4):
        result[96 + 32 * index:128 + 32 * index] = bytes(range(index * 64, index * 64 + 32))
    result[224:256] = hashlib.sha256(original_fixture()).digest()
    for query in range(8):
        parent = query < 2 or query >= 6
        role = query % 2 + 1
        fd = (17 if role == 1 else 23) if parent else role
        start = 256 + 224 * query
        struct.pack_into(">IiQQQiiHBB", result, start, 0x1234 if parent else 0x3456, fd,
                         metadata["before"][query], metadata["after"][query],
                         metadata["addresses"][query], 176, 0, 11, role, 1 if query < 4 else 2)
        result[start + 48:start + 224] = swap_fields(native_fields(query))
    struct.pack_into(">QQiiiI", result, 2048,
                     metadata["wait_before"], metadata["wait_after"], 0x3456, 0x117F, 0, 51)
    return bytes(result)


class PostExecOutputControls(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.temporary = None
        selected = os.environ.get("GLUE_PX_TEST_RETAIN")
        if selected:
            cls.output = Path(selected).resolve()
            cls.output.mkdir(parents=True, exist_ok=False, mode=0o700)
        else:
            cls.temporary = tempfile.TemporaryDirectory(prefix="glue stopped output ü ")
            cls.output = Path(cls.temporary.name)
        names = ("post_exec_output.c", "post_exec_output.h", "post_exec_output_test.h",
                 "post_exec_output.py", "test_post_exec_output.c", "test_post_exec_output.py")
        cls.before = {HERE / name: (HERE / name).read_bytes() for name in names}
        identities = {str(path): {"bytes": len(data), "sha256": hashlib.sha256(data).hexdigest()}
                      for path, data in sorted(cls.before.items())}
        (cls.output / "sources-before.json").write_text(json.dumps(identities, indent=2) + "\n")
        sanitize = os.environ.get("GLUE_PX_TEST_SANITIZE", "0")
        if sanitize not in ("0", "1"):
            raise ValueError("GLUE_PX_TEST_SANITIZE must be 0 or 1")
        cls.binary = cls.output / "post-exec-output-controls"
        argv = ["/usr/bin/cc", "-std=c11", "-Wall", "-Wextra", "-Werror", "-O2", "-DPX_TESTING"]
        if sanitize == "1":
            argv += ["-O1", "-g", "-fsanitize=address,undefined", "-fno-omit-frame-pointer"]
        if platform.system() == "Darwin":
            sdk_command = ["/usr/bin/xcrun", "--sdk", "macosx", "--show-sdk-path"]
            sdk = subprocess.run(sdk_command, capture_output=True, check=True, text=True, timeout=15).stdout.strip()
            argv += ["-isysroot", sdk, "-mmacosx-version-min=11.0"]
        argv += [str(HERE / "post_exec_output.c"), str(HERE / "test_post_exec_output.c")]
        if platform.system() == "Darwin":
            argv += ["-lproc"]
        argv += ["-o", str(cls.binary)]
        result = subprocess.run(argv, capture_output=True, timeout=45)
        (cls.output / "compile.stdout").write_bytes(result.stdout)
        (cls.output / "compile.stderr").write_bytes(result.stderr)
        record = {"argv": argv, "exit_status": result.returncode,
                  "python": sys.version, "host": platform.platform(), "sanitize": sanitize,
                  "source_sha256": identities}
        if result.returncode == 0:
            record["binary_sha256"] = hashlib.sha256(cls.binary.read_bytes()).hexdigest()
        (cls.output / "compile.json").write_text(json.dumps(record, indent=2) + "\n")
        if result.returncode:
            raise AssertionError(result.stderr.decode("utf-8", "replace"))
        spec = importlib.util.spec_from_file_location("stopped_output_decoder_under_test", HERE / "post_exec_output.py")
        cls.decoder = importlib.util.module_from_spec(spec)
        sys.modules[spec.name] = cls.decoder
        spec.loader.exec_module(cls.decoder)
        cls.packet_path = cls.output / "model-success.packet"
        cls.run_control("success", cls.packet_path, label="fixture-success")
        cls.packet = cls.packet_path.read_bytes()
        cls.original = Path(str(cls.packet_path) + ".original").read_bytes()
        cls.metadata = json.loads(Path(str(cls.packet_path) + ".meta").read_text())

    @classmethod
    def tearDownClass(cls):
        changed = [str(path) for path, before in cls.before.items() if path.read_bytes() != before]
        after = {str(path): {"bytes": path.stat().st_size,
                            "sha256": hashlib.sha256(path.read_bytes()).hexdigest()}
                 for path in sorted(cls.before)}
        (cls.output / "sources-after.json").write_text(json.dumps({"sources": after, "changed": changed}, indent=2) + "\n")
        if cls.temporary is not None:
            cls.temporary.cleanup()
        if changed:
            raise AssertionError("sources changed during controls: " + ", ".join(changed))

    @classmethod
    def run_control(cls, name, path=None, label=None, expected=0):
        argv = [str(cls.binary), name]
        if path is not None:
            argv.append(str(path))
        result = subprocess.run(argv, capture_output=True, timeout=18)
        selected = label or name
        (cls.output / (selected + ".stdout")).write_bytes(result.stdout)
        (cls.output / (selected + ".stderr")).write_bytes(result.stderr)
        (cls.output / (selected + ".result.json")).write_text(json.dumps(
            {"argv": argv, "exit_status": result.returncode, "expected_status": expected}, indent=2) + "\n")
        if result.returncode != expected:
            raise AssertionError("%s exit %s (expected %s): %s" % (
                name, result.returncode, expected, result.stderr.decode("utf-8", "replace")))
        return result.stdout

    def decode(self, packet=None, original=None):
        return self.decoder.decode_observation(self.packet if packet is None else packet,
                                               self.original if original is None else original)

    def refuses(self, packet, original=None):
        with self.assertRaises(ValueError):
            self.decode(bytes(packet), self.original if original is None else bytes(original))

    def test_full_packet_matches_independent_BE_header_fields_rows_and_wait(self):
        self.assertEqual(self.original, original_fixture())
        self.assertEqual(hashlib.sha256(self.original).hexdigest(),
                         "a23f350c99fe9a510ed8cc583d70a63336e36c4ff87f538eb4c8a41ab58cfb1f")
        self.assertEqual(self.packet, expected_packet(self.metadata))

    def test_pure_codec_preserves_every_native_byte_field_spare_pad_and_high_bit(self):
        path = self.output / "codec.bytes"
        self.run_control("codec", path)
        raw = bytes((index * 53 + 11) & 255 for index in range(176))
        self.assertEqual(path.read_bytes(), swap_fields(raw))

    def test_each_short_zero_oversize_query_original_prefix_and_no_replay(self):
        self.run_control("queries")

    def test_full_metadata_flag_domains_access_descriptor_and_backing_refusals(self):
        self.run_control("mutations")

    def test_actual_wait_retry_stop_terminal_ECHILD_and_unexpected_PID(self):
        self.run_control("waits")

    def test_full_stop_status_high_bits_are_retained_and_never_normalized_to_SIGSTOP(self):
        changed = bytearray(self.packet)
        struct.pack_into(">I", changed, 2048 + 20, 0x8000117F)
        self.refuses(changed)
        path = self.output / "high-stop.packet"
        self.run_control("high-stop", path)
        packet = path.read_bytes()
        result = self.decoder.decode_observation(packet, Path(str(path) + ".original").read_bytes())
        self.assertEqual(struct.unpack_from(">I", packet, 2048 + 20)[0], 0x8000117F)
        self.assertEqual(struct.unpack_from(">I", packet, 68)[0], 1)
        self.assertEqual(struct.unpack_from(">H", packet, 56)[0], 0)
        self.assertFalse(result.conditional_backing_match)

    def test_finite_wait_journal_never_calls_a_65th_wait(self):
        self.run_control("journal")

    def test_clock_failures_lateness_regression_and_retirement_before_after_clock(self):
        self.run_control("clocks")

    def test_argument_original_binding_callback_and_owner_preflight(self):
        self.run_control("arguments")

    def test_policy_owner_and_late_final_guards_retain_prefix_without_a_match(self):
        self.run_control("final-guards")

    def test_model_backing_match_grants_no_native_raw_state_or_exemption_authority(self):
        result = self.decode()
        self.assertTrue(result.conditional_backing_match)
        for name in FALSE_AUTHORITY:
            self.assertIs(getattr(result, name), False, name)
            self.assertIs(result.to_dict()[name], False, name)
        self.assertTrue(dataclasses.is_dataclass(result))
        with self.assertRaises(dataclasses.FrozenInstanceError):
            result.conditional_backing_match = False

    def test_every_truncation_extra_bytes_wrong_asset_type_refuses(self):
        for size in range(4096):
            with self.subTest(size=size):
                self.refuses(self.packet[:size])
        self.refuses(self.packet + b"\0")
        for wrong in (bytearray(self.packet), memoryview(self.packet), None, "GLUEPX01"):
            with self.assertRaises((ValueError, TypeError)):
                self.decoder.decode_observation(wrong, self.original)

    def test_framing_reserved_unknown_flags_counts_and_state_contradictions_refuse(self):
        for offset in (0, 8, 10, 12, 16, 20, 56, 58, 60, 62,
                       64, 68, 80, 82, 84, 95, 96, 128, 160, 224, 300, 2048 + 28, 2080):
            with self.subTest(offset=offset):
                changed = bytearray(self.packet)
                changed[offset] ^= 0x80
                self.refuses(changed)
        for offset in (24, 32, 40, 48):
            changed = bytearray(self.packet)
            struct.pack_into(">Q", changed, offset, 0)
            self.refuses(changed)
        changed = bytearray(self.packet)
        struct.pack_into(">I", changed, 68, 15 | 0x80000000)
        self.refuses(changed)
        changed = bytearray(self.packet)
        struct.pack_into(">H", changed, 56, 9)
        self.refuses(changed)
        changed = bytearray(self.packet)
        struct.pack_into(">H", changed, 58, 65)
        self.refuses(changed)

    def test_each_query_role_round_PID_fd_address_flags_and_after_time_is_bound(self):
        for query in range(8):
            start = 256 + 224 * query
            for relative in (0, 4, 8, 16, 32, 36, 40, 42, 43, 44):
                with self.subTest(query=query, field=relative):
                    changed = bytearray(self.packet)
                    changed[start + relative] ^= 0x80
                    self.refuses(changed)
        changed = bytearray(self.packet)
        changed[256 + 24:256 + 32] = bytes(8)
        self.refuses(changed)
        changed = bytearray(self.packet)
        changed[256 + 224 + 24:256 + 224 + 32] = changed[256 + 24:256 + 32]
        self.refuses(changed)

    def test_complete_claim_cannot_mask_backing_access_or_cloexec_disagreement(self):
        for query, relative, width, value in (
            (0, 0, 4, 1), (0, 0, 4, 0x40000002), (0, 0, 4, 0x80000002),
            (0, 4, 4, 0), (2, 4, 4, 2), (0, 20, 4, 1), (0, 24, 4, 0x7EDCBA98),
            (4, 32, 8, 0x0123456789ABCD00), (0, 28, 2, 0o40600),
            (0, 30, 2, 2), (0, 16, 4, 2), (0, 160, 4, 2),
        ):
            with self.subTest(query=query, field=relative):
                changed = bytearray(self.packet)
                start = 256 + query * 224 + 48 + relative
                changed[start:start + width] = value.to_bytes(width, "big")
                self.refuses(changed)

    def test_mutable_offset_timestamps_spares_pad_and_SHARED_are_retained_without_OFD_claim(self):
        changed = bytearray(self.packet)
        for query in range(8):
            base = 256 + query * 224 + 48
            changed[base + 8:base + 16] = (0xFEDCBA9876543200 + query).to_bytes(8, "big")
            changed[base + 48:base + 56] = (0x89ABCDEF01234000 + query).to_bytes(8, "big")
            changed[base + 144:base + 152] = (0xBADC0FFEE0000000 + query).to_bytes(8, "big")
            changed[base + 164:base + 168] = (0x12345678 + query).to_bytes(4, "big")
            old_status = struct.unpack_from(">I", changed, base + 4)[0]
            struct.pack_into(">I", changed, base + 4, old_status ^ 1)
        result = self.decode(bytes(changed))
        self.assertTrue(result.conditional_backing_match)
        for name in FALSE_AUTHORITY:
            self.assertIs(getattr(result, name), False)

    def test_nonzero_declared_epoch_program_and_addresses_are_not_authenticated(self):
        changed = bytearray(self.packet)
        for offset in (24, 40, 48):
            struct.pack_into(">Q", changed, offset, 0xFEDCBA9876543210)
        changed[192:224] = bytes(range(1, 33))
        for query in range(8):
            struct.pack_into(">Q", changed, 256 + query * 224 + 24, 0x7000000000000000 + query * 256)
        result = self.decode(bytes(changed))
        self.assertTrue(result.conditional_backing_match)
        for name in FALSE_AUTHORITY:
            self.assertIs(getattr(result, name), False)

    def test_decoded_fields_preserve_all_SDK_names_signed_widths_and_reserved_bits(self):
        result = self.decode()
        names = (
            ("fi_openflags", False), ("fi_status", False), ("fi_offset", True),
            ("fi_type", True), ("fi_guardflags", False), ("vst_dev", False),
            ("vst_mode", False), ("vst_nlink", False), ("vst_ino", False),
            ("vst_uid", False), ("vst_gid", False), ("vst_atime", True),
            ("vst_atimensec", True), ("vst_mtime", True), ("vst_mtimensec", True),
            ("vst_ctime", True), ("vst_ctimensec", True), ("vst_birthtime", True),
            ("vst_birthtimensec", True), ("vst_size", True), ("vst_blocks", True),
            ("vst_blksize", True), ("vst_flags", False), ("vst_gen", False),
            ("vst_rdev", False), ("vst_qspare0", True), ("vst_qspare1", True),
            ("vi_type", True), ("vi_pad", True), ("vi_fsid0", True), ("vi_fsid1", True),
        )
        for query in range(8):
            raw = native_fields(query)
            expected = {name: int.from_bytes(raw[offset:offset + width], "little", signed=signed)
                        for ((name, signed), (offset, width)) in zip(names, FIELDS)}
            self.assertEqual(result.queries[query].fields, expected)
            self.assertEqual(result.queries[query].payload, swap_fields(raw))

    def test_original_asset_hash_and_deep_success_shape_are_required(self):
        for size in range(320):
            with self.subTest(size=size):
                self.refuses(self.packet, self.original[:size])
        self.refuses(self.packet, self.original + b"\0")
        for offset in (0, 8, 12, 16, 20, 24, 28, 32, 64, 96, 128, 140, 148,
                       160, 167, 171, 172, 176, 192, 240, 319):
            with self.subTest(offset=offset):
                original = bytearray(self.original)
                original[offset] ^= 0x80
                packet = bytearray(self.packet)
                packet[224:256] = hashlib.sha256(original).digest()
                self.refuses(packet, original)
        original = bytearray(self.original)
        for row in (1, 3):
            start = 160 + row * 40
            original[start + 16:start + 32] = original[176:192]
        packet = bytearray(self.packet)
        packet[224:256] = hashlib.sha256(original).digest()
        self.refuses(packet, original)

    def test_actual_C_failed_short_prefix_is_opaque_and_never_decoded_as_success(self):
        path = self.output / "failure-short.packet"
        self.run_control("failure-short", path)
        packet = path.read_bytes()
        result = self.decoder.decode_observation(packet, Path(str(path) + ".original").read_bytes())
        self.assertFalse(result.conditional_backing_match)
        self.assertEqual(struct.unpack_from(">H", packet, 56)[0], 3)
        row = 256 + 2 * 224
        self.assertEqual(struct.unpack_from(">H", packet, row + 40)[0], 13)
        self.assertEqual(packet[row + 48:row + 224], native_fields(2))
        self.assertEqual(result.queries[-1].fields, {})
        self.assertEqual(result.queries[-1].opaque_buffer, native_fields(2))
        self.assertEqual(packet[row + 224:2048], bytes(5 * 224))
        for name in FALSE_AUTHORITY:
            self.assertIs(getattr(result, name), False)

    def test_failed_packet_issued_call_chronology_and_header_tail_cannot_drift(self):
        path = self.output / "chronology-short.packet"
        self.run_control("failure-short", path, label="chronology-short")
        packet = path.read_bytes()
        original = Path(str(path) + ".original").read_bytes()
        self.assertFalse(self.decoder.decode_observation(packet, original).conditional_backing_match)
        mutations = []
        changed = bytearray(packet)
        previous_after = struct.unpack_from(">Q", changed, 256 + 224 + 16)[0]
        struct.pack_into(">Q", changed, 256 + 2 * 224 + 8, previous_after - 1)
        mutations.append(changed)
        changed = bytearray(packet)
        wait_after = struct.unpack_from(">Q", changed, 2048 + 8)[0]
        struct.pack_into(">Q", changed, 256 + 8, wait_after - 1)
        mutations.append(changed)
        changed = bytearray(packet)
        struct.pack_into(">Q", changed, 256 + 16, struct.unpack_from(">Q", changed, 32)[0])
        mutations.append(changed)
        changed = bytearray(packet)
        struct.pack_into(">Q", changed, 72, struct.unpack_from(">Q", changed, 72)[0] + 1)
        mutations.append(changed)
        for index, changed in enumerate(mutations):
            with self.subTest(mutation=index):
                self.refuses(changed, original)

    def test_actual_C_after_clock_failure_rollback_late_and_final_deadline_prefixes(self):
        for name in ("failure-clock", "rollback-clock", "late-clock", "final-deadline"):
            path = self.output / (name + ".packet")
            self.run_control(name, path)
            packet = path.read_bytes()
            result = self.decoder.decode_observation(packet, Path(str(path) + ".original").read_bytes())
            self.assertFalse(result.conditional_backing_match)
            expected_count = 8 if name == "final-deadline" else 1
            self.assertEqual(struct.unpack_from(">H", packet, 56)[0], expected_count)
            self.assertEqual(struct.unpack_from(">H", packet, 256 + 40)[0], 3 if name == "failure-clock" else 11)
            self.assertEqual(packet[304:480], swap_fields(native_fields(0)))
            self.assertIsNone(result.queries[0].opaque_buffer)
            self.assertEqual(len(result.queries[0].fields), 31)
            if name == "rollback-clock":
                self.assertLess(result.queries[0].after, result.queries[0].before)
            if name in ("late-clock", "final-deadline"):
                self.assertGreaterEqual(result.last_clock, result.deadline)
            for authority in FALSE_AUTHORITY:
                self.assertIs(getattr(result, authority), False)

    def test_actual_C_terminal_and_ECHILD_after_clock_failure_cannot_restore_ownership(self):
        for name, flag in (("terminal-clock", 16), ("lost-clock", 32)):
            path = self.output / (name + ".packet")
            self.run_control(name, path)
            packet = path.read_bytes()
            result = self.decoder.decode_observation(packet, Path(str(path) + ".original").read_bytes())
            flags = struct.unpack_from(">I", packet, 68)[0]
            self.assertEqual(flags & 1, 0)
            self.assertEqual(flags & flag, flag)
            self.assertFalse(result.conditional_backing_match)

    def test_native_unprivileged_owned_exec_child_self_stop_query_continue_actual_reap(self):
        path = self.output / "native.packet"
        if platform.system() != "Darwin":
            self.run_control("native", path, expected=77)
            self.skipTest("fixed native observer is Darwin LP64 little-endian only")
        if os.getuid() == 0 or os.getuid() != os.geteuid():
            self.skipTest("native fixture requires an unprivileged equal real/effective UID")
        output = self.run_control("native", path).decode("utf-8", "replace")
        self.assertIn("continued=1 actual_child_reap=1 ownership_lost=0 killed=0 status=0 failed=0", output)
        packet = path.read_bytes()
        original = Path(str(path) + ".original").read_bytes()
        self.assertEqual(packet[224:256], hashlib.sha256(original).digest())
        self.assertTrue(self.decoder.decode_observation(packet, original).conditional_backing_match)
        for name in FALSE_AUTHORITY:
            self.assertIs(getattr(self.decoder.decode_observation(packet, original), name), False)


if __name__ == "__main__":
    unittest.main()
