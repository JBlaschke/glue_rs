"""Pure codec controls: compiled helper never links native observation code."""
import hashlib
import json
import os
from pathlib import Path
import shlex
import shutil
import struct
import subprocess
import tempfile
import unittest

HERE = Path(__file__).resolve().parent


def independent_vector(index):
    request = b"glue probe synthetic request v1\n" + bytes([index])
    digest = hashlib.sha256(request).digest()
    data = bytearray(256)
    struct.pack_into(">8sHHI32s", data, 0, b"GLUENP01", 1, 256, 1, digest)
    maximum = 2147483647
    pids = [456, 123, 456] if not index else [maximum, 1, maximum]
    ids = [501, 501, 20, 20] if not index else [maximum] * 4
    groups = [20, 0, 80] if not index else [maximum] + list(range(15))
    struct.pack_into(">3I4II", data, 48, *pids, *ids, len(groups))
    struct.pack_into(">16I", data, 80, *(groups + [0] * (16 - len(groups))))
    struct.pack_into(">QQ", data, 144, 0x0102030405060708 if not index else (1 << 64) - 1,
                     0xF0E0D0C0B0A09080 if not index else 0)
    struct.pack_into(">I3I", data, 160, 3, 0, 1, 2)
    struct.pack_into(">3I3I", data, 176, *([0, 1, 1] if not index else [65536, 65537, 33554433]),
                     *([0, 0, 0] if not index else [2, 0, 0]))
    struct.pack_into(">iI4III", data, 200, -1, 1, *ids, 1, 0)
    return {"index": index, "synthetic_request_hex": request.hex(),
            "request_sha256": digest.hex(), "report_hex": data.hex(),
            "report_sha256": hashlib.sha256(data).hexdigest()}


class ProbeReportTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.temporary = tempfile.TemporaryDirectory(prefix="glue-probe-pure-")
        cls.addClassCleanup(cls.temporary.cleanup)
        cls.binary = Path(cls.temporary.name) / "pure-tests"
        compiler = shutil.which(os.environ.get("CC", "cc"))
        if not compiler:
            raise RuntimeError("native C compiler required for pure codec")
        command = [compiler, "-std=c11", "-Wall", "-Wextra", "-Werror", "-O2"]
        command += shlex.split(os.environ.get("NP_TEST_CFLAGS", ""))
        command += [str(HERE / "probe_report.c"), str(HERE / "test_probe_report.c"), "-o", str(cls.binary)]
        subprocess.run(command, check=True, capture_output=True, timeout=30)

    def control(self, name):
        p = subprocess.run([str(self.binary), name], capture_output=True, timeout=5)
        self.assertEqual(p.returncode, 0, p.stderr)
        self.assertEqual(p.stdout, (name + "\n").encode())

    def test_independent_struct_hashlib_golden_vectors(self):
        vectors = json.loads((HERE / "golden-vectors.json").read_text())
        self.assertEqual(vectors["vectors"], [independent_vector(i) for i in range(2)])
        for v in vectors["vectors"]:
            result = subprocess.run([str(self.binary), "golden", str(v["index"]), v["request_sha256"]],
                                    capture_output=True, timeout=5)
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertEqual(result.stdout.hex(), v["report_hex"])
            self.assertEqual(hashlib.sha256(result.stdout).hexdigest(), v["report_sha256"])
            decoded = subprocess.run([str(self.binary), "decode", v["request_sha256"]],
                                     input=result.stdout, capture_output=True, timeout=5)
            self.assertEqual(decoded.returncode, 0, decoded.stderr)
            self.assertEqual(decoded.stdout, result.stdout)

    def test_malformed_wire_fields_and_all_reserved_bytes(self):
        v = independent_vector(0)
        good = bytes.fromhex(v["report_hex"])
        mutations = [(offset, 1) for offset in range(232, 256)]
        mutations += [(0, 1), (8, 1), (10, 2), (12, 1), (16, 1),
                      (48, 255), (63, 0), (79, 17), (95, 20), (143, 1),
                      (163, 4), (167, 3), (179, 4), (191, 1), (203, 0),
                      (207, 0), (211, 0), (227, 0), (231, 1)]
        for offset, value in mutations:
            damaged = bytearray(good)
            damaged[offset] = value
            with self.subTest(offset=offset):
                p = subprocess.run([str(self.binary), "decode", v["request_sha256"]],
                                   input=damaged, capture_output=True, timeout=5)
                self.assertEqual(p.returncode, 1, p.stderr)
                self.assertEqual(p.stdout, b"")
        for data in [good[:-1], good + b"X", b"", b"X" * 257]:
            p = subprocess.run([str(self.binary), "decode", v["request_sha256"]],
                               input=data, capture_output=True, timeout=5)
            self.assertEqual(p.returncode, 1)
            self.assertEqual(p.stdout, b"")


def make_case(name):
    def test(self):
        self.control(name)
    return test


for _case in ("argument", "lengths", "header", "identity", "groups", "process",
              "stdio", "root-policy", "hex", "roundtrip"):
    setattr(ProbeReportTests, "test_" + _case.replace("-", "_"), make_case(_case))

if __name__ == "__main__":
    unittest.main()
