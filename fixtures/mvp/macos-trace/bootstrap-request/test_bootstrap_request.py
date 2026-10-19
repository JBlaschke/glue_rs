"""Pure request/READY controls; no target execution or credential transition."""
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


def independent_vector(maximum=False):
    """Python struct oracle, independent of the C codec helpers."""
    exe = b'/System/Volumes/Data/Library/GlueMVPFixtures/build/context-probe'
    cwd = b'/System/Volumes/Data/Library/GlueMVPFixtures/build/cwd'
    uid, gid, groups = 501, 20, [20, 0, 80]
    catalog = bytes(range(32))
    dev, ino = 0x0102030405060708, 0xf0e0d0c0b0a09080
    release = 1
    if maximum:
        exe, cwd = b'/a/\xc3\xa9', b'/'
        uid = gid = 0x7fffffff
        groups = [gid] + list(range(15))
        catalog = bytes(32)
        dev = ino = 0xffffffffffffffff
        release = 2
    total = 208 + len(exe) + len(cwd)
    out = bytearray(208)
    struct.pack_into('>8sHHIIIII', out, 0, b'GLUENR01', 1, 208, total, 1, uid, gid, len(groups))
    struct.pack_into('>16I', out, 32, *(groups + [0] * (16 - len(groups))))
    struct.pack_into('>8I', out, 96, 1, 1, release, 4096, 10000, 2000, 1, 0)
    out[128:160] = catalog
    struct.pack_into('>QQII', out, 160, dev, ino, len(exe), len(cwd))
    return bytes(out) + exe + cwd


class RequestTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.temp = tempfile.TemporaryDirectory(prefix='glue-pure-request-')
        cls.binary = Path(cls.temp.name) / 'request-test'
        cc = shutil.which(os.environ.get('CC', 'cc'))
        if not cc:
            raise RuntimeError('required C compiler unavailable')
        command = [cc, '-std=c11', '-Wall', '-Wextra', '-Werror', '-pedantic',
                   *shlex.split(os.environ.get('BR_TEST_CFLAGS', '')),
                   str(HERE / 'bootstrap_request.c'), str(HERE / 'test_bootstrap_request.c'),
                   str(HERE.parent / 'bootstrap-wire' / 'bootstrap_wire.c'),
                   str(HERE.parent / 'target-credentials' / 'target_credentials.c'),
                   '-o', str(cls.binary)]
        subprocess.run(command, check=True, timeout=30)

    @classmethod
    def tearDownClass(cls):
        cls.temp.cleanup()

    def run_case(self, name):
        return subprocess.run([str(self.binary), name], check=True, capture_output=True, timeout=10).stdout

    def test_golden_vectors(self):
        retained = json.loads((HERE / 'golden-vectors.json').read_text())
        self.assertEqual(set(retained), {'normal', 'maximum'})
        for name, maximum in [('normal', False), ('maximum', True)]:
            with self.subTest(name=name):
                oracle = independent_vector(maximum)
                self.assertEqual(retained[name]['hex'], oracle.hex())
                self.assertEqual(retained[name]['sha256'], hashlib.sha256(oracle).hexdigest())
                self.assertEqual(self.run_case('golden-' + name), oracle)

    def test_roundtrip_and_borrowed_span_lifetime(self):
        self.run_case('roundtrip')

    def test_hostile_exact_lengths(self):
        self.run_case('lengths')

    def test_every_byte_mutation_is_rejected_or_exactly_canonical(self):
        self.run_case('mutation-canonicality')

    def test_closed_selectors_and_reserved_bytes(self):
        self.run_case('selectors')

    def test_credentials_and_unused_groups(self):
        self.run_case('groups')

    def test_raw_path_components_and_bounds(self):
        self.run_case('paths')

    def test_every_ready_requested_observation(self):
        self.run_case('ready-observations')

    def test_ready_canonical_fields_and_wrong_kinds(self):
        self.run_case('ready-canonical')

    def test_ready_bindings_topology_and_native_widths(self):
        self.run_case('ready-bindings')

    def test_output_clearing_nulls_and_canaries(self):
        self.run_case('clearing')


if __name__ == '__main__':
    unittest.main()
