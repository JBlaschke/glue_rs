"""Portable, pure-data controls; no bootstrap, target, tracing or VM execution."""
import os
from pathlib import Path
import struct
import subprocess
import tempfile
import unittest


def independent_vectors():
    """Construct bytes from fixed offsets, without calling the C encoder."""
    controller, child = 0x01020304, 0x11223344
    binding = struct.pack(">II", controller, child) + bytes(range(32))
    result = {}
    # name, kind, sequence, stage, errno, mutation bits, reason, detail
    records = (
        ("ready", 1, 0, 0, 0, 3, 0, -1),
        ("attempt", 2, 1, 13, 0, 3, 0, -1),
        ("error0", 3, 0, 1, 0, 0, 1, -1),
        ("error1", 3, 1, 9, 0, 3, 4, 17),
        ("error2", 3, 2, 13, 2, 3, 3, -1),
    )
    for name, kind, sequence, stage, system_errno, flags, reason, detail in records:
        payload = bytearray(256)
        struct.pack_into(">8sHHI", payload, 0, b"GLUEBS01", 1, kind, 256)
        payload[16:56] = binding
        struct.pack_into(">IIII", payload, 56, sequence, stage, system_errno, flags)
        if kind == 1:
            struct.pack_into(">IIIII", payload, 72, 1001, 1001, 1002, 1002, 2)
            struct.pack_into(">II", payload, 92, 1002, 7)
            struct.pack_into(">QQ", payload, 156, 0x0123456789ABCDEF, 0xFEDCBA9876543210)
            struct.pack_into(">IIIII", payload, 172, 0, 1, 2, 17, 23)
            payload[192:224] = bytes(range(255, 223, -1))
        struct.pack_into(">II", payload, 224, reason, detail & 0xFFFFFFFF)
        envelope = bytearray(512)
        struct.pack_into(">8sHHIII", envelope, 0, b"GLUEFS02", 2, kind,
                         512, 5 if kind == 1 else 0, 256)
        envelope[32:288] = payload
        if kind == 1:
            for i, fd in enumerate((0, 1, 2, 17, 23)):
                struct.pack_into(">IIIIQQQ", envelope, 288 + 40 * i, fd,
                                 0x10203040 + i, 0x21314151 + i, 0x89ABCDEF - i,
                                 0x0102030405060708 + i, 0xF1E2D3C4B5A69788 + i,
                                 0xFEDCBA9876543210 - i)
        result[name] = envelope.hex()
    go = bytearray(64)
    struct.pack_into(">8sHH", go, 0, b"GLUEFG02", 2, 64)
    go[12:52] = binding
    result["go"] = go.hex()
    return result


class BootstrapObjectWireTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.temp = tempfile.TemporaryDirectory(prefix="glue object wire ü ")
        cls.binary = Path(cls.temp.name) / "object-wire-tests"
        cls.source = Path(__file__).resolve().parent
        command = ["cc", "-std=c11", "-Wall", "-Wextra", "-Werror", "-pedantic", "-O2"]
        if os.environ.get("GLUE_BOOTSTRAP_OBJECT_WIRE_SANITIZE") == "1":
            command += ["-g", "-fsanitize=address,undefined", "-fno-omit-frame-pointer"]
        # Fixed dependencies: this module and test, plus the canonical BW codec.
        # TFO supplies only host types; its native adapter is never linked.
        command += [str(cls.source / "bootstrap_object_wire.c"),
                    str(cls.source / "test_bootstrap_object_wire.c"),
                    str(cls.source.parent / "bootstrap-wire" / "bootstrap_wire.c"),
                    "-o", str(cls.binary)]
        result = subprocess.run(command, capture_output=True, text=True, timeout=30)
        if result.returncode:
            cls.temp.cleanup()
            raise RuntimeError("C compile failed:\n" + result.stderr)

    @classmethod
    def tearDownClass(cls):
        cls.temp.cleanup()

    def control(self, name, *args):
        result = subprocess.run([str(self.binary), name, *args], capture_output=True,
                                text=True, timeout=10)
        self.assertEqual(result.returncode, 0, result.stderr)
        return result.stdout

    def test_independent_big_endian_vectors(self):
        actual = dict(line.split(":", 1) for line in self.control("vectors").splitlines())
        self.assertEqual(actual, independent_vectors())

    def test_decodes_independent_vectors(self):
        for name, data in independent_vectors().items():
            with self.subTest(name=name):
                command = "decode-go" if name == "go" else "decode-status"
                self.assertEqual(self.control(command, data), "decoded\n")

    def test_roundtrip_and_exact_legacy_payload(self): self.control("roundtrip")
    def test_every_partial_length_and_null_output_clearing(self): self.control("lengths")
    def test_outer_inner_headers_and_every_reserved_byte(self): self.control("headers")
    def test_all_rows_full_flags_unsigned_metadata_and_zero_body(self): self.control("rows")
    def test_binding_and_inherited_bw_canonical_guards(self): self.control("canonical")
    def test_no_new_status_prefix_is_legacy_ready(self): self.control("profiles")
    def test_go_strict_binding_length_and_profile_separation(self): self.control("go")
    def test_late_bad_row_clears_both_outputs_and_nonready_clears_snapshot(self): self.control("no-stale")


if __name__ == "__main__":
    unittest.main()
