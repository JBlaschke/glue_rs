#!/usr/bin/env python3
"""Synthetic byte/data controls only: no target, kit or shell execution."""
import copy
import importlib.util
import json
import os
from pathlib import Path
import struct
import stat
import tempfile
import unittest
from unittest.mock import patch

HERE = Path(__file__).resolve().parent
spec = importlib.util.spec_from_file_location('bootstrap_checker', HERE / 'checker.py')
c = importlib.util.module_from_spec(spec)
spec.loader.exec_module(c)


def canonical(value):
    return (json.dumps(value, sort_keys=True, separators=(',', ':')) + '\n').encode()


def pack(buf, off, *values, fmt=None):
    struct.pack_into('>' + (fmt or 'I' * len(values)), buf, off, *values)


def fixture():
    """Independent struct oracle, conspicuously synthetic and never native proof."""
    build = 'b' * 64
    catalog = bytearray(269)
    catalog[:8] = b'GLUENC01'
    pack(catalog, 8, 1, 192, 269, fmt='HHI')
    pack(catalog, 16, 52912, 17, -2, 3, 17, 4, -5, fmt='QQiiQii')
    catalog[56:184] = bytes(range(128))
    pack(catalog, 184, 64, 13, 0, fmt='HHI')
    catalog[192:] = build.encode() + b'context-probe'
    catalog = bytes(catalog)
    plan = {'build_dir': '/System/Volumes/Data/Library/GlueMVPFixtures/' + build,
            'expected_ids': [501, 501, 20, 20], 'expected_groups': [20, 0, 80]}
    return plan, catalog


def request(plan, catalog, release=1):
    exe = (plan['build_dir'] + '/context-probe').encode()
    cwd = plan['build_dir'].encode()
    b = bytearray(208 + len(exe) + len(cwd))
    b[:8] = b'GLUENR01'
    pack(b, 8, 1, 208, len(b), fmt='HHI')
    pack(b, 16, 1, 501, 20, 3)
    pack(b, 32, 20, 0, 80)
    pack(b, 96, 1, 1, release, 4096, 10000, 2000, 1, 0)
    b[128:160] = bytes.fromhex(c.sha(catalog))
    pack(b, 160, 17, 42, fmt='QQ')
    pack(b, 176, len(exe), len(cwd))
    b[208:] = exe + cwd
    return bytes(b)


def status(req, kind, seq, stage=0, reason=0, err=0, flags=3):
    b = bytearray(256)
    b[:8] = b'GLUEBS01'
    pack(b, 8, 1, kind, 256, fmt='HHI')
    pack(b, 16, 123, 456)
    b[24:56] = bytes.fromhex(c.sha(req))
    pack(b, 56, seq, stage, err, flags)
    if kind == 1:
        pack(b, 72, 501, 501, 20, 20, 3, 20, 0, 80)
        pack(b, 156, 17, 42, fmt='QQ')
        pack(b, 172, 0, 1, 2, 10, 11)
        b[192:224] = bytes.fromhex(c.SIGNAL_POLICY_SHA)
    pack(b, 224, reason, 0xffffffff)
    return bytes(b)


def probe(req):
    b = bytearray(256)
    b[:8] = b'GLUENP01'
    pack(b, 8, 1, 256, 1, fmt='HHI')
    b[16:48] = bytes.fromhex(c.sha(req))
    pack(b, 48, 456, 123, 456, 501, 501, 20, 20, 3, 20, 0, 80)
    pack(b, 144, 17, 42, fmt='QQ')
    pack(b, 160, 3, 0, 1, 2, 0x100, 0x101, 0x101, 0, 0, 0)
    pack(b, 200, -1, 1, 501, 501, 20, 20, 1, 0, fmt='i7I')
    return bytes(b)


def case_fixture(case='positive'):
    plan, catbytes = fixture()
    cat = c.decode_catalog(catbytes)
    req = request(plan, catbytes, 2 if case == 'simulated' else 1)
    ready = status(req, 1, 0)
    if case == 'positive':
        raw, out, ce = ready + status(req, 2, 1, stage=13), probe(req), {
            'present': False, 'stage': 0, 'reason': 0, 'errno': 0, 'flags': 0, 'detail': 0}
    else:
        ce = {'present': True, 'stage': 9 if case == 'simulated' else 6,
              'reason': 10 if case == 'simulated' else 3, 'errno': 0 if case == 'simulated' else 13,
              'flags': 3 if case == 'simulated' else 1, 'detail': -1}
        error = status(req, 3, 1 if case == 'simulated' else 0,
                       ce['stage'], ce['reason'], ce['errno'], ce['flags'])
        raw, out = (ready + error if case == 'simulated' else error), b''
    error = {'stage': 0, 'reason': 0, 'errno': 0, 'detail': 0}
    result = {
        'schema': 'glue-owned-bootstrap-diagnostic-v1', 'tracing': False, 'exec_proved': False,
        'full_acceptance': False, 'identity_policy': 'request-declarations-compared-to-observations',
        'consistent_owned_probe': case == 'positive', 'controller_pid': 123, 'child_pid': 456,
        'parent_error': error.copy() if case == 'positive' else {'stage': 12 if case == 'simulated' else 10,
                                                               'reason': 12, 'errno': 0, 'detail': -1},
        'cleanup_error': error.copy(),
        'helpers': {'admission': {'stage': 0, 'reason': 0, 'errno': 0, 'component': 0, 'metadata_step': 0},
                    'endpoints': {'stage': 0, 'reason': 0, 'errno': 0, 'role': 5, 'fd': -1},
                    'signal_prepare': {'stage': 0, 'reason': 0, 'errno': 0}},
        'child_error': ce,
        'protocol': {'records': len(raw) // 256, 'bytes': len(raw), 'wire_fault': 0,
                     'io_stage': 0, 'io_reason': 0, 'io_errno': 0, 'eof_class': 3 if case == 'positive' else 2},
        'go': {'action': 2 if case == 'simulated' else 1, 'attempted': case == 'positive',
               'possibly_released': case == 'positive', 'bytes': 64 if case == 'positive' else 0,
               'stage': 0, 'reason': 0, 'errno': 0, 'closed': True},
        'ready_matched': case != 'denied', 'probe_matched': case == 'positive',
        'wait': {'forked': True, 'reaped': True, 'lost': False, 'kill_attempted': case != 'positive',
                 'raw_status': 0 if case == 'positive' else 9},
        'signals': {'prepared': True, 'restore_called': True, 'pipe_restored': True, 'mask_restored': True,
                    'restore_stage': 0, 'restore_reason': 0, 'restore_errno': 0},
        'identities': {'request_sha256': c.sha(req), 'catalog_sha256': c.sha(catbytes),
                       'signal_policy_sha256': c.SIGNAL_POLICY_SHA, 'status_sha256': c.sha(raw),
                       'stdout_sha256': c.sha(out), 'stderr_sha256': c.sha(b''),
                       'probe_sha256': cat['probe_sha256'], 'runner_static_sources_sha256': cat['runner_static_sources_sha256'],
                       'build_recipe_sha256': cat['build_recipe_sha256']},
        'stdout_capture_valid': True, 'stderr_capture_valid': True, 'stdout_bytes': len(out), 'stderr_bytes': 0}
    return plan, cat, {'request.bin': req, 'status.bin': raw, 'probe.stdout': out,
                       'probe.stderr': b'', 'result.json': canonical(result)}


def rehash(data):
    r = c.result_json(data['result.json'])
    for key, name in (('request_sha256', 'request.bin'), ('status_sha256', 'status.bin'),
                      ('stdout_sha256', 'probe.stdout'), ('stderr_sha256', 'probe.stderr')):
        r['identities'][key] = c.sha(data[name])
    data['result.json'] = canonical(r)


class WireTests(unittest.TestCase):
    def test_independent_checked_in_golden_vectors(self):
        base = HERE.parent
        wire = json.loads((base / 'bootstrap-wire/golden-vectors.json').read_bytes())
        binding = (123, 456, bytes(range(32)).hex())
        for name in ('ready', 'attempt', 'gate-error', 'exec-error'):
            self.assertIn(c.decode_status(bytes.fromhex(wire[name]), binding)['kind'], (1, 2, 3))
        reqs = json.loads((base / 'bootstrap-request/golden-vectors.json').read_bytes())
        for value in reqs.values():
            decoded = c.decode_request(bytes.fromhex(value['hex']))
            self.assertEqual(decoded['uid'], 501 if value is reqs['normal'] else c.INT)
        probes = json.loads((base / 'bootstrap-probe/golden-vectors.json').read_bytes())
        for value in probes['vectors']:
            raw = bytes.fromhex(value['report_hex'])
            self.assertEqual(c.sha(raw), value['report_sha256'])
            self.assertEqual(c.decode_probe(raw, value['request_sha256'])['ids'][0],
                             501 if value['index'] == 0 else c.INT)

    def test_all_three_synthetic_outcomes(self):
        for case in ('positive', 'simulated', 'denied'):
            with self.subTest(case=case):
                plan, cat, data = case_fixture(case)
                r = c.check_case(case, data, plan, cat)
                self.assertFalse(r['full_acceptance'])
                self.assertEqual(r['status_records'], 1 if case == 'denied' else 2)

    def test_br_lengths_reserved_selectors_paths_groups(self):
        plan, cat = fixture()
        raw = request(plan, cat)
        bads = [raw[:-1], raw + b'\0']
        for off, value in ((184, 1), (20, 0), (24, 0), (28, 17), (96, 2), (104, 3),
                           (112, 0), (116, 2001), (120, 0), (124, 1), (44, 9), (36, 20)):
            b = bytearray(raw); pack(b, off, value); bads.append(bytes(b))
        b = bytearray(raw); b[208] = ord('x'); bads.append(bytes(b))
        for value in bads:
            with self.subTest(raw=value[:32]), self.assertRaises(c.Refusal):
                c.decode_request(value)
        for path in (b'/a//b', b'/a/../b', b'/a/./b', b'/a/', b'/', b'/a\0b'):
            with self.assertRaises(c.Refusal): c.path_bytes(path)

    def test_catalog_signed_fsid_and_same_device(self):
        _, raw = fixture()
        v = c.decode_catalog(raw)
        self.assertEqual(v['root_mount'], {'device': 17, 'fsid': [-2, 3]})
        self.assertEqual(v['data_mount'], {'device': 17, 'fsid': [4, -5]})
        for off in (188, 192, 256):
            b = bytearray(raw); b[off] = 255
            with self.assertRaises((c.Refusal, UnicodeError)): c.decode_catalog(bytes(b))
        b = bytearray(raw); b[40:56] = b[24:40]
        with self.assertRaises(c.Refusal): c.decode_catalog(bytes(b))

    def test_status_binding_order_flags_and_observation_zero(self):
        plan, cat = fixture(); req = request(plan, cat)
        ready, attempt = status(req, 1, 0), status(req, 2, 1, stage=13)
        binding = (123, 456, c.sha(req))
        self.assertEqual(c.decode_stream(ready, binding)[1], 1)  # Incomplete, not accepted as a case.
        for raw in (ready + ready, attempt, ready + attempt + attempt,
                    ready + status(req, 2, 1, stage=13, flags=1), ready[:-1], b''):
            with self.assertRaises(c.Refusal): c.decode_stream(raw, binding)
        for offset in (16, 24, 72, 232):
            b = bytearray(attempt); b[offset] ^= 1
            with self.assertRaises(c.Refusal): c.decode_status(bytes(b), binding)

    def test_probe_canonical_context_and_raw_flag_preservation(self):
        plan, cat = fixture(); req = request(plan, cat); raw = probe(req)
        self.assertEqual(c.decode_probe(raw, c.sha(req))['stdio_status_flags'], [256, 257, 257])
        for off, val in ((16, 0), (56, 123), (60, 0), (76, 17), (92, 20), (160, 5),
                         (176, 4), (180, 64 | 1), (184, 32768 | 1), (188, 1),
                         (200, 0), (204, 13), (208, 502), (224, 0), (228, 1), (232, 1)):
            b = bytearray(raw); pack(b, off, val)
            with self.subTest(off=off), self.assertRaises(c.Refusal): c.decode_probe(bytes(b), c.sha(req))

    def test_result_duplicate_float_bool_huge_or_extra_keys(self):
        for raw in (b'{"a":1,"a":2}', b'{"a":1.0}', b'{"a":NaN}', b'{"a":' + b'1' * 5000 + b'}'):
            with self.assertRaises(c.Refusal): c.result_json(raw)
        plan, cat, data = case_fixture()
        for key, value in (('child_pid', True), ('full_acceptance', True), ('extra', 0)):
            d = data.copy(); r = c.result_json(d['result.json']); r[key] = value; d['result.json'] = canonical(r)
            with self.assertRaises(c.Refusal): c.check_case('positive', d, plan, cat)

    def test_rebuilt_hash_raw_record_mutations_still_reject(self):
        for filename, offset in (('probe.stdout', 52), ('status.bin', 92), ('status.bin', 256 + 68),
                                 ('probe.stdout', 152), ('request.bin', 104)):
            plan, cat, data = case_fixture()
            raw = bytearray(data[filename]); raw[offset] ^= 1; data[filename] = bytes(raw); rehash(data)
            with self.subTest(file=filename, offset=offset), self.assertRaises(c.Refusal):
                c.check_case('positive', data, plan, cat)

    def test_result_claims_do_not_replace_raw_or_closure(self):
        changes = [('wait', 'reaped', False), ('wait', 'lost', True), ('cleanup_error', 'errno', 5),
                   ('signals', 'mask_restored', False), ('signals', 'restore_errno', 4),
                   ('go', 'closed', False), ('protocol', 'bytes', 256), ('helpers', 'x', {})]
        for group, key, value in changes:
            plan, cat, data = case_fixture()
            r = c.result_json(data['result.json']); r[group][key] = value; data['result.json'] = canonical(r)
            with self.subTest(group=group, key=key), self.assertRaises(c.Refusal): c.check_case('positive', data, plan, cat)

    def test_negative_wait_retained_without_inventing_natural_exit(self):
        for case in ('simulated', 'denied'):
            for raw in (9, 120 << 8):
                plan, cat, data = case_fixture(case)
                r = c.result_json(data['result.json']); r['wait']['raw_status'] = raw
                data['result.json'] = canonical(r)
                self.assertEqual(c.check_case(case, data, plan, cat)['raw_wait_status'], raw)
        plan, cat, data = case_fixture('simulated')
        r = c.result_json(data['result.json']); r['go']['possibly_released'] = True; data['result.json'] = canonical(r)
        with self.assertRaises(c.Refusal): c.check_case('simulated', data, plan, cat)
        r['go']['possibly_released'] = False; r['wait']['raw_status'] = 0; data['result.json'] = canonical(r)
        with self.assertRaises(c.Refusal): c.check_case('simulated', data, plan, cat)

    def test_no_full_acceptance(self):
        with self.assertRaises(c.Refusal): c.require_full_acceptance()


class TreeUtilities:
    @classmethod
    def setUpClass(cls):
        ppath = HERE.parent / 'bootstrap-kit/build_kit.py'
        s = importlib.util.spec_from_file_location('kit_primitives_for_tests', ppath)
        cls.p = importlib.util.module_from_spec(s); s.loader.exec_module(cls.p)

    def write(self, path, files):
        for name, data in files.items():
            target = path / name; target.parent.mkdir(parents=True, exist_ok=True); target.write_bytes(data)
        (path / 'SHA256SUMS').write_bytes(b''.join((c.sha(data) + '  ' + name + '\n').encode()
                                                  for name, data in sorted(files.items())))


class TreeTests(TreeUtilities, unittest.TestCase):

    def test_exact_inventory_hash_links_special_and_escape(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp).resolve(); self.write(root, {'a': b'x'})
            self.assertEqual(c._tree(self.p, root, {'a'})[0], {'a': b'x'})
            (root / 'extra').write_bytes(b'')
            with self.assertRaises(ValueError): c._tree(self.p, root, {'a'})
            (root / 'extra').unlink(); (root / 'a').unlink(); (root / 'a').symlink_to('/etc/hosts')
            with self.assertRaises((ValueError, OSError)): c._tree(self.p, root, {'a'})
            (root / 'a').unlink(); (root / 'a').write_bytes(b'x'); os.link(root / 'a', root / 'extra')
            with self.assertRaises(ValueError): c._tree(self.p, root, {'a'})
            (root / 'extra').unlink(); (root / 'a').unlink(); os.mkfifo(root / 'a')
            with self.assertRaises(ValueError): c._tree(self.p, root, {'a'})
            (root / 'a').unlink(); (root / 'a').write_bytes(b'x')
            (root / 'SHA256SUMS').write_text(c.sha(b'x') + '  ../escape\n')
            with self.assertRaises(ValueError): c._tree(self.p, root, {'a'})

    def test_terminal_gate_never_opens_case_payload(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp).resolve()
            (root / 'batch.tsv').write_bytes(c.BATCH.replace(b'complete\t0', b'complete\t1'))
            # A FIFO payload would block a naive reader. Gate never opens it.
            os.mkfifo(root / 'status.bin')
            seen = []
            original = self.p.read_member
            def read(fd, name, maximum):
                seen.append(name); return original(fd, name, maximum)
            with patch.object(self.p, 'read_member', side_effect=read):
                with self.assertRaises(c.Refusal): c._gate(self.p, root, {'batch.tsv': c.BATCH})
            self.assertEqual(seen, ['batch.tsv'])

    def test_failed_outer_status_checked_before_inventory(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp).resolve(); (root / 'outer.status').write_bytes(b'1\n')
            with self.assertRaises(c.Refusal): c._gate(self.p, root, {'outer.status': b'0\n'})


class SyntheticWorkflowTests(TreeUtilities, unittest.TestCase):
    """Full checker paths with a visibly synthetic, unit-only approval replacement.

    No artifact is native proof and no rendered script is ever executed. Public
    CLI has no such replacement/enable option; the real source policy stays off.
    """
    def setup_workflow(self, root, enabled=True):
        producer = c._producer()
        oldplan, rawcat = fixture()
        binary = b'synthetic-non-executable-probe\n' * 100
        rawcat = bytearray(rawcat)
        pack(rawcat, 16, len(binary), fmt='Q')
        rawcat[56:88] = bytes.fromhex(c.sha(binary))
        rawcat = bytes(rawcat)
        artifacts = {'context-probe': binary, 'bootstrap-runner': b'synthetic runner, never executed',
                     'make-request': b'synthetic request writer, never executed'}
        result = {'schema': 'glue-bootstrap-kit-result-v1', 'status': 'built-reproducibly',
                  'build_id': 'b' * 64, 'catalog_sha256': c.sha(rawcat),
                  'new_binaries_executed': False, 'installed': False, 'kernel_exec_proof': False, 'full_acceptance': False,
                  'artifacts': {n: {'size': len(b), 'sha256': c.sha(b)} for n, b in artifacts.items()}}
        components = []
        for i, name in enumerate(('/', 'System', 'Volumes', 'Data', 'Library')):
            data = i >= 3
            components.append({'name': name, 'device': 17, 'inode': i + 1, 'uid': 0, 'gid': 0,
                               'mode': stat.S_IFDIR | 0o755, 'fsid': [4, -5] if data else [-2, 3],
                               'mount_flags': 0, 'mount_policy': 1 if data else 3, 'mount_owner': 0,
                               'descriptor_flags': 1, 'status_flags': 0, 'mountpoint': '/System/Volumes/Data' if data else '/',
                               'filesystem': 'apfs', 'filesec_population': 7, 'acl_present': 0})
        observed = {'schema': 'glue-bootstrap-deployment-observation-v1', 'model': 'VirtualMac2,1',
                    'kernel_release': '25.6.0', 'observed_unix_seconds': 1, 'observed_nanoseconds': 0,
                    'ids': [501, 501, 20, 20], 'groups': [20, 0, 80], 'tc_compatible': True,
                    'components': components, 'settings_changed': False, 'executable_admission': False, 'full_acceptance': False}
        original = {'catalog.bin': rawcat, 'result.json': canonical(result),
                    'admitted-proof.json': canonical({'observation': observed, 'full_acceptance': False,
                        'registry_entry': {'manifest_sha256': 'ec28e38b3066112d874a54b0dfb4bb9c20fae3f39dc90697bf7d4ea684a84c8a'}}),
                    'recipe.json': b'{}\n', 'source-lock.json': b'{}\n'}
        original.update({'kit/' + n: value for n, value in artifacts.items()})
        fullmanifest = b''.join((c.sha(value) + '  ' + name + '\n').encode() for name, value in sorted(original.items()))
        approval = producer.APPROVED.copy()
        approval.update(kit_manifest_sha256=c.sha(fullmanifest), build_id='b' * 64, catalog_sha256=c.sha(rawcat))
        producer.APPROVED = approval
        producer.EXECUTION_ENABLED = enabled
        plan = producer.make_plan(result, observed, '0123456789abcdef')
        files, selected = {}, []
        for name in producer.PROGRAMS:
            value = original['kit/' + name]
            files['payload/' + name] = value
            selected.append({'member': 'payload/' + name, 'original': 'kit/' + name, 'sha256': c.sha(value)})
        for name, old in producer.METADATA.items():
            value = fullmanifest if old == 'SHA256SUMS' else original[old]
            files['metadata/' + name] = value
            selected.append({'member': 'metadata/' + name, 'original': old, 'sha256': c.sha(value)})
        files.update(producer.render(plan))
        files['plan.json'] = canonical(plan)
        files['derived-subset.json'] = canonical({'schema': 'glue-bootstrap-vm-subset-v1', 'approval': approval,
                         'selected': selected, 'original_inventory_is_detached_metadata': True, 'full_acceptance': False})
        packet, evidence, receipt = root / 'packet', root / 'evidence', root / 'receipt'
        for path in (packet, evidence, receipt): path.mkdir()
        self.write(packet, files)
        ev = {'plan.json': files['plan.json'], 'batch.tsv': c.BATCH, 'install.status': b'0\n',
              'install.stdout': b'', 'install.stderr': b'synthetic strict-signature tool output\n'}
        for case in c.CASES:
            for stream in ('stdout', 'stderr'): ev['case-' + case + '.' + stream] = b''
            ev['case-' + case + '.status'] = b'0\n'
            if case == 'trailing': continue
            _, _, values = case_fixture(case)
            req = request(plan, rawcat, 2 if case == 'simulated' else 1)
            # Rebuild independent wire binding for this synthetic catalog only.
            values['request.bin'] = req
            statusraw = bytearray(values['status.bin'])
            for offset in range(0, len(statusraw), 256): statusraw[offset + 24:offset + 56] = bytes.fromhex(c.sha(req))
            values['status.bin'] = bytes(statusraw)
            if case == 'positive': values['probe.stdout'] = probe(req)
            r = c.result_json(values['result.json'])
            r['identities']['catalog_sha256'] = c.sha(rawcat)
            r['identities']['probe_sha256'] = c.sha(binary)
            values['result.json'] = canonical(r); rehash(values)
            ev['requests/' + case + '.bin'] = req
            ev['requests/' + case + '.status'] = b'0\n'
            ev['requests/' + case + '.stderr'] = b''
            ev['cases/' + case + '/native.status'] = b'0\n' if case == 'positive' else b'1\n'
            ev['cases/' + case + '/input.sha256'] = (c.sha(req) + '\n').encode()
            for name, value in values.items(): ev['cases/' + case + '/' + name] = value
        trailing = ev['requests/positive.bin'] + b'\0'
        ev['requests/trailing.bin'] = trailing
        ev['cases/trailing/input.sha256'] = (c.sha(trailing) + '\n').encode()
        ev['cases/trailing/native.status'] = b'2\n'
        ev['cases/trailing/output.absent'] = b'true\n'
        self.write(evidence, ev)
        self.write(receipt, {'outer.argv': b'/bin/sh\0' + (plan['guest_packet'] + '/outer.sh').encode() + b'\0',
                            'outer.status': b'0\n', 'outer.stdout': ('evidence=' + plan['guest_export'] + '\n').encode(),
                            'outer.stderr': b''})
        return producer, packet, evidence, receipt

    def check(self, values):
        producer, packet, evidence, receipt = values
        with patch.object(c, '_producer', return_value=producer):
            return c.check(packet, evidence, receipt)

    def rewrite_inventory(self, root):
        files = {p.relative_to(root).as_posix(): p.read_bytes() for p in root.rglob('*')
                 if p.is_file() and p.name != 'SHA256SUMS'}
        self.write(root, files)

    def test_entire_synthetic_completed_batch(self):
        with tempfile.TemporaryDirectory() as tmp:
            report = self.check(self.setup_workflow(Path(tmp).resolve()))
            self.assertEqual(len(report['cases']), 3)
            self.assertFalse(report['tracing']); self.assertFalse(report['exec_proved']); self.assertFalse(report['full_acceptance'])

    def test_source_disabled_refuses_before_export_reads(self):
        with tempfile.TemporaryDirectory() as tmp:
            values = self.setup_workflow(Path(tmp).resolve(), False)
            values[2].rename(values[2].with_name('unopened-evidence'))
            with self.assertRaisesRegex(c.Refusal, 'disabled'): self.check(values)

    def test_outer_receipt_and_unexpected_cli2_gate_before_case_reads(self):
        for mode in ('outer', 'cli2', 'partial'):
            with tempfile.TemporaryDirectory() as tmp:
                values = self.setup_workflow(Path(tmp).resolve())
                if mode == 'outer':
                    (values[3] / 'outer.status').write_bytes(b'1\n')
                elif mode == 'cli2':
                    (values[2] / 'cases/simulated/native.status').write_bytes(b'2\n')
                else:
                    (values[2] / 'batch.tsv').write_bytes(c.BATCH.replace(b'complete\t0\n', b''))
                (values[2] / 'cases/positive/status.bin').unlink()
                os.mkfifo(values[2] / 'cases/positive/status.bin')
                with self.subTest(mode=mode), self.assertRaisesRegex(ValueError, 'terminal gate'):
                    self.check(values)

    def test_rebuilt_manifest_cannot_fix_semantic_case_or_receipt(self):
        for mode in ('trailing', 'input', 'result', 'receipt', 'extra', 'typed-plan'):
            with tempfile.TemporaryDirectory() as tmp:
                values = self.setup_workflow(Path(tmp).resolve())
                root = values[2]
                if mode == 'trailing': (root / 'requests/trailing.bin').write_bytes(b'bad')
                if mode == 'input': (root / 'cases/positive/input.sha256').write_bytes(b'0' * 64 + b'\n')
                if mode == 'result':
                    path = root / 'cases/positive/result.json'; v = c.result_json(path.read_bytes())
                    v['go']['bytes'] = 63; path.write_bytes(canonical(v))
                if mode == 'receipt':
                    root = values[3]; (root / 'outer.argv').write_bytes(b'/bin/sh\0/arbitrary\0')
                if mode == 'extra': (root / 'result.pending').write_bytes(b'not closed')
                if mode == 'typed-plan':
                    root = values[1]; path = root / 'plan.json'; v = json.loads(path.read_bytes())
                    v['full_acceptance'] = 0; path.write_bytes(canonical(v))
                self.rewrite_inventory(root)
                with self.subTest(mode=mode), self.assertRaises(ValueError): self.check(values)


if __name__ == '__main__':
    unittest.main()
