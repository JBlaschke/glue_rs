"""Private synthetic packet admission controls; never construct or run a native kit."""
from copy import deepcopy
from dataclasses import FrozenInstanceError, dataclass
import hashlib
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

import checker as check
import prepare as prep
import test_calibration as calibration


HERE = Path(__file__).resolve().parent
_PACKET_NAMES = frozenset((
    'payload/context-probe', 'payload/owned-trace-runner', 'payload/make-request',
    'metadata/catalog.bin', 'metadata/recipe.json', 'metadata/source-lock.json',
    'metadata/admitted-proof.json', 'metadata/build-result.json',
    'metadata/build-SHA256SUMS', 'plan.json', 'derived-subset.json',
    'root-stage.sh', 'outer.sh', 'launch.sh',
))
_DYNAMIC_NAMES = ('plan.json', 'derived-subset.json', 'root-stage.sh', 'outer.sh', 'launch.sh')


def _sha(raw):
    return hashlib.sha256(raw).hexdigest()


def _canonical(value):
    return (json.dumps(value, sort_keys=True, separators=(',', ':'), ensure_ascii=True)
            + '\n').encode('ascii')


def _manifest(data):
    return ''.join(_sha(raw) + '  ' + name + '\n'
                   for name, raw in sorted(data.items()) if name != 'SHA256SUMS').encode('ascii')


def _with_manifest(data):
    copied = dict(data)
    copied['SHA256SUMS'] = _manifest(copied)
    return copied


def _flip(raw):
    return bytes((raw[0] ^ 1,)) + raw[1:]


@dataclass(frozen=True)
class _Fixture:
    policy: object
    plan: dict
    packet: dict
    catalog: bytes
    evidence: dict
    receipt: dict


def _fixture():
    """The explicit private identity map admits these invented bytes only.

    This bypasses the full-kit loader at its documented private packet boundary.
    The payloads are ordinary labels, not Mach-O files or purported signed kits.
    No production approval, registry, policy global or actual kit is changed.
    """
    old_plan, catalog, evidence, receipt = calibration.synthetic()
    observed, entry = deepcopy(old_plan['observation']), deepcopy(old_plan['proof_entry'])
    payloads = {
        name: ('PRIVATE SYNTHETIC PACKET PAYLOAD: ' + name + '\n').encode('ascii')
        for name in ('context-probe', 'owned-trace-runner', 'make-request')
    }
    artifacts = {name: {'sha256': _sha(raw), 'size': len(raw)}
                 for name, raw in payloads.items()}
    source_revision = 'e' * 40
    recipe = {'schema': 'glue-owned-trace-kit-recipe-v1', 'sip_policy': 'exact-disabled',
              'fixture': 'private-packet-boundary-only'}
    lock = {'schema': 'glue-owned-trace-kit-inputs-v1', 'source_revision': source_revision,
            'sources': {'synthetic/fixture.c': _sha(b'private synthetic source\n')},
            'proofs': [entry]}
    proof = {'registry_entry': entry, 'observation': observed, 'full_acceptance': False}
    result = {'schema': 'glue-owned-trace-kit-result-v1', 'status': 'built-reproducibly',
              'build_id': old_plan['build_id'], 'catalog_sha256': _sha(catalog),
              'artifacts': artifacts, 'new_binaries_executed': False, 'installed': False,
              'kernel_exec_proof': False, 'full_acceptance': False}
    originals = {'catalog.bin': catalog, 'recipe.json': _canonical(recipe),
                 'source-lock.json': _canonical(lock), 'admitted-proof.json': _canonical(proof),
                 'result.json': _canonical(result)}
    # A private detached inventory of these synthetic selected bytes. It is never
    # passed off as a complete native builder output or sent to load_kit/prepare.
    kit_manifest = _manifest({**originals, **{'kit/' + n: raw for n, raw in payloads.items()}})
    approved = {
        'kit_manifest_sha256': _sha(kit_manifest),
        'kit_review_manifest_sha256': 'a' * 64,
        'catalog_review_manifest_sha256': 'c' * 64,
        'builder_receipt_manifest_sha256': 'f' * 64,
        'build_id': result['build_id'], 'catalog_sha256': _sha(catalog),
        'recipe_sha256': _sha(originals['recipe.json']),
        'source_lock_sha256': _sha(originals['source-lock.json']),
        'source_revision': source_revision, 'observation_sha256': _sha(_canonical(observed)),
        'proof_entry': entry, 'artifacts': artifacts,
    }
    metadata_map = (
        ('catalog.bin', 'catalog.bin'), ('recipe.json', 'recipe.json'),
        ('source-lock.json', 'source-lock.json'), ('admitted-proof.json', 'admitted-proof.json'),
        ('build-result.json', 'result.json'), ('build-SHA256SUMS', 'SHA256SUMS'),
    )
    metadata = {name: kit_manifest if original == 'SHA256SUMS' else originals[original]
                for name, original in metadata_map}
    policy = prep._Admission(_canonical(approved),
                             tuple((name, _sha(raw), len(raw)) for name, raw in metadata.items()),
                             True)
    plan = prep.plan_from_identity(result['build_id'], _sha(catalog), artifacts,
                                   observed, entry, old_plan['nonce'], _policy=policy)
    selected = [dict(member='payload/' + name, original='kit/' + name,
                     sha256=_sha(payloads[name]), size=len(payloads[name]))
                for name in ('context-probe', 'owned-trace-runner', 'make-request')]
    selected += [dict(member='metadata/' + name, original=original,
                      sha256=_sha(metadata[name]), size=len(metadata[name]))
                 for name, original in metadata_map]
    subset = {'schema': 'glue-bootstrap-trace-calibration-subset-v1', 'approval': approved,
              'selected': selected, 'original_inventory_is_detached_metadata': True,
              'full_acceptance': False}
    packet = {'payload/' + name: raw for name, raw in payloads.items()}
    packet.update({'metadata/' + name: raw for name, raw in metadata.items()})
    packet.update({'plan.json': _canonical(plan), 'derived-subset.json': _canonical(subset)})
    packet.update(prep.render(plan, _policy=policy))
    assert set(packet) == _PACKET_NAMES and len(packet) == 14

    # Reuse the separately serialized complete BW/NP/raw pair, changing only its
    # plan and the root command argv affected by the private configured renderer.
    # Build paths/nonces, request/status/probe/raw/result/sidecar bytes stay fixed.
    commands = prep.root_commands(plan, _policy=policy)
    evidence['plan.json'] = _canonical(plan)
    evidence['install.argv'] = check.argv_bytes(commands['install'])
    evidence['install-context.argv'] = check.argv_bytes(commands['export-install-context'])
    for case in ('positive', 'denied'):
        evidence['case-' + case + '.argv'] = check.argv_bytes(commands['case-' + case])
        for role in prep.case_roles(case):
            evidence['exports/' + case + '/' + role + '.argv'] = check.argv_bytes(
                commands['export-' + case + ':' + role])
    return _Fixture(policy, plan, _with_manifest(packet), catalog, evidence, receipt)


class _FakeTree:
    """Explicit in-memory packet boundary with caller-enforced size limits."""
    def __init__(self, data):
        self.data = dict(data)
        self.operations = []
        self.inventoried = False

    def read(self, name, cap):
        self.operations.append(('read', name, cap))
        if name != 'SHA256SUMS' and not self.inventoried:
            raise AssertionError('payload read before inventory')
        raw = self.data[name]
        if type(raw) is not bytes or len(raw) > cap:
            raise ValueError('injected read cap')
        return raw

    def inventory(self, limits, *, total_limit):
        self.operations.append(('inventory',))
        self.inventoried = True
        if set(self.data) != set(limits) | {'SHA256SUMS'}:
            raise ValueError('injected physical roster')
        if any(len(raw) > limits.get(name, 4096) for name, raw in self.data.items()):
            raise ValueError('injected physical cap')
        if sum(map(len, self.data.values())) > total_limit:
            raise ValueError('injected total cap')


def _write_packet(path, packet):
    path.mkdir(mode=0o700)
    for name, raw in packet.items():
        member = path / name
        member.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
        member.write_bytes(raw)
        member.chmod(0o555 if name.startswith('payload/') or name.endswith('.sh') else 0o444)


class PacketAdmissionControls(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.fixture = _fixture()

    def baseline(self):
        fixture = deepcopy(self.fixture)
        tree = _FakeTree(fixture.packet)
        plan, catalog = check._packet(tree, prep, fixture.policy)
        self.assertEqual(plan, fixture.plan)
        self.assertEqual(catalog, fixture.catalog)
        self.assertEqual(tree.operations[0], ('read', 'SHA256SUMS', 4096))
        self.assertEqual(tree.operations[1], ('inventory',))
        self.assertEqual(set(fixture.packet), _PACKET_NAMES | {'SHA256SUMS'})
        return fixture

    def test_01_private_complete_fourteen_member_packet(self):
        fixture = self.baseline()
        self.assertIs(type(fixture.policy.approved_json), bytes)
        self.assertIs(type(fixture.policy.metadata), tuple)
        self.assertEqual(len(fixture.policy.metadata), 6)
        self.assertTrue(all(type(row) is tuple for row in fixture.policy.metadata))
        with self.assertRaises(FrozenInstanceError):
            fixture.policy.execution = False
        self.assertNotEqual(fixture.policy.approved_json, prep.POLICY.approved_json)
        self.assertEqual(fixture.packet['plan.json'], _canonical(fixture.plan))

    def test_02_each_fixed_member_byte_mutation_with_original_manifest(self):
        fixture = self.baseline()
        for name in sorted(_PACKET_NAMES - set(_DYNAMIC_NAMES)):
            data = dict(fixture.packet)
            data[name] = _flip(data[name])
            tree = _FakeTree(data)
            with self.subTest(member=name), self.assertRaisesRegex(ValueError, 'approved member differs'):
                check._packet(tree, prep, fixture.policy)
            self.assertTrue(tree.inventoried)
            self.assertIn(('read', name, len(data[name])), tree.operations)

    def test_03_regenerated_static_manifest_forgery_stops_before_inventory(self):
        fixture = self.baseline()
        for name in sorted(_PACKET_NAMES - set(_DYNAMIC_NAMES)):
            data = dict(fixture.packet)
            data[name] = _flip(data[name])
            tree = _FakeTree(_with_manifest(data))
            with self.subTest(member=name), self.assertRaisesRegex(ValueError, 'approved manifest link'):
                check._packet(tree, prep, fixture.policy)
            self.assertEqual(tree.operations, [('read', 'SHA256SUMS', 4096)])

    def test_04_canonical_plan_and_identity_mutations(self):
        fixture = self.baseline()
        mutations = (
            ('path', lambda p: p['paths'].update(root_stage='/tmp/override')),
            ('budget', lambda p: p['budgets'].update(attempt_ms=1)),
            ('approval', lambda p: p['approval'].update(kit_manifest_sha256='0' * 64)),
            ('artifact', lambda p: p['artifacts']['context-probe'].update(sha256='0' * 64)),
            ('nonce', lambda p: p.update(nonce='G' * 16)),
            ('scope', lambda p: p.update(full_acceptance=True)),
            ('extra', lambda p: p.update(unreviewed=True)),
        )
        for name, mutate in mutations:
            plan = deepcopy(fixture.plan)
            mutate(plan)
            for regenerate in (False, True):
                data = dict(fixture.packet)
                data['plan.json'] = _canonical(plan)
                if regenerate:
                    data = _with_manifest(data)
                with self.subTest(change=name, regenerated=regenerate), self.assertRaises(ValueError):
                    check._packet(_FakeTree(data), prep, fixture.policy)
        data = dict(fixture.packet)
        data['plan.json'] = b' ' + data['plan.json']
        with self.assertRaisesRegex(ValueError, 'canonical plan'):
            check._packet(_FakeTree(_with_manifest(data)), prep, fixture.policy)

    def test_05_scripts_and_subset_cannot_be_self_rehashed(self):
        fixture = self.baseline()
        for name in _DYNAMIC_NAMES[1:]:
            for regenerate in (False, True):
                data = dict(fixture.packet)
                data[name] = _flip(data[name])
                if regenerate:
                    data = _with_manifest(data)
                with self.subTest(member=name, regenerated=regenerate), self.assertRaisesRegex(ValueError, 'canonical member'):
                    check._packet(_FakeTree(data), prep, fixture.policy)

    def test_06_manifest_grammar_roster_and_bound_precede_inventory(self):
        fixture = self.baseline()
        manifest = fixture.packet['SHA256SUMS']
        lines = manifest.splitlines(keepends=True)
        cases = {
            'malformed': b'not a manifest\n', 'oversized': b'x' * 4097,
            'missing': b''.join(lines[1:]), 'duplicate': manifest + lines[0],
            'extra': manifest + b'0' * 64 + b'  unexpected\n',
            'self': manifest + b'0' * 64 + b'  SHA256SUMS\n',
            'traversal': b'0' * 64 + b'  ../escape\n',
            'nonascii': b'\xff' + manifest[1:], 'missing-LF': manifest[:-1],
            'noncanonical-order': b''.join(reversed(lines)),
        }
        for name, raw in cases.items():
            data = dict(fixture.packet)
            data['SHA256SUMS'] = raw
            tree = _FakeTree(data)
            with self.subTest(change=name), self.assertRaises(ValueError):
                check._packet(tree, prep, fixture.policy)
            self.assertEqual(tree.operations, [('read', 'SHA256SUMS', 4096)])

    def test_07_physical_complete_packet(self):
        fixture = self.baseline()
        with tempfile.TemporaryDirectory(prefix='glue-private-packet-') as directory:
            packet = Path(directory).resolve() / 'packet'
            _write_packet(packet, fixture.packet)
            plan, catalog = check.load_packet(packet, _policy=fixture.policy)
            self.assertEqual(plan, fixture.plan)
            self.assertEqual(catalog, fixture.catalog)

    def test_08_physical_modes_roster_links_and_caps_refuse(self):
        fixture = self.baseline()
        for change in ('root-mode', 'nested-mode', 'file-mode', 'symlink', 'hardlink',
                       'missing', 'extra', 'payload-cap', 'manifest-cap'):
            with self.subTest(change=change), tempfile.TemporaryDirectory(prefix='glue-private-packet-refusal-') as directory:
                packet = Path(directory).resolve() / 'packet'
                _write_packet(packet, fixture.packet)
                member = packet / 'payload/context-probe'
                if change == 'root-mode': packet.chmod(0o755)
                elif change == 'nested-mode': (packet / 'payload').chmod(0o755)
                elif change == 'file-mode': (packet / 'plan.json').chmod(0o666)
                elif change == 'symlink':
                    member.unlink()
                    member.symlink_to('/not-opened')
                elif change == 'hardlink':
                    member.unlink()
                    os.link(packet / 'payload/make-request', member)
                elif change == 'missing': member.unlink()
                elif change == 'extra': (packet / 'extra').write_bytes(b'extra')
                elif change == 'payload-cap':
                    member.chmod(0o600)
                    member.write_bytes(fixture.packet['payload/context-probe'] + b'x')
                else:
                    (packet / 'SHA256SUMS').chmod(0o600)
                    (packet / 'SHA256SUMS').write_bytes(b'x' * 4097)
                with self.assertRaises((ValueError, OSError)):
                    check.load_packet(packet, _policy=fixture.policy)

    def test_09_fifo_refusal_has_bounded_subprocess(self):
        fixture = self.baseline()
        policy_json = json.dumps({'approved_json': fixture.policy.approved_json.decode('ascii'),
                                  'metadata': fixture.policy.metadata})
        code = (
            'import json,sys\n'
            'sys.path.insert(0,sys.argv[1])\n'
            'import checker,prepare\n'
            'v=json.loads(sys.argv[3])\n'
            'policy=prepare._Admission(v["approved_json"].encode("ascii"),'
            'tuple(tuple(row) for row in v["metadata"]),True)\n'
            'try:\n checker.load_packet(sys.argv[2],_policy=policy)\n'
            'except ValueError:\n sys.exit(0)\n'
            'sys.exit(9)\n'
        )
        for name in ('SHA256SUMS', 'payload/context-probe'):
            with self.subTest(member=name), tempfile.TemporaryDirectory(prefix='glue-private-packet-fifo-') as directory:
                packet = Path(directory).resolve() / 'packet'
                _write_packet(packet, fixture.packet)
                (packet / name).unlink()
                os.mkfifo(packet / name, 0o600)
                result = subprocess.run([sys.executable, '-B', '-c', code, str(HERE),
                                         str(packet), policy_json], capture_output=True, timeout=5)
                self.assertEqual(result.returncode, 0, result.stderr)
                self.assertEqual(result.stdout, b'')

    def test_10_unconfigured_refusal_precedes_helpers_and_paths(self):
        with patch.object(check, 'preparer', side_effect=AssertionError('helper opened')), \
             patch.object(check, 'Tree', side_effect=AssertionError('path opened')):
            with self.assertRaisesRegex(ValueError, 'not configured'):
                check.load_packet('/not-opened', _policy=prep.UNCONFIGURED)
            with self.assertRaisesRegex(ValueError, 'not configured'):
                check.check('/not-opened', '/not-opened', '/not-opened', _policy=prep.UNCONFIGURED)
        with patch.object(prep, 'shared', side_effect=AssertionError('helper opened')):
            with self.assertRaisesRegex(ValueError, 'not configured'):
                prep.load_kit('/not-opened', _policy=prep.UNCONFIGURED)

    def test_11_default_production_policy_rejects_synthetic_self_consistency(self):
        fixture = self.baseline()
        tree = _FakeTree(fixture.packet)
        with self.assertRaisesRegex(ValueError, 'approved manifest link'):
            check._packet(tree, prep, prep.POLICY)
        self.assertEqual(tree.operations, [('read', 'SHA256SUMS', 4096)])
        with tempfile.TemporaryDirectory(prefix='glue-private-packet-production-refusal-') as directory:
            packet = Path(directory).resolve() / 'packet'
            _write_packet(packet, fixture.packet)
            with patch.object(check.Tree, 'inventory', side_effect=AssertionError('inventory before identity')):
                with self.assertRaisesRegex(ValueError, 'approved manifest link'):
                    check.load_packet(packet)

    def test_12_packet_admission_precedes_export_checker(self):
        fixture = self.baseline()
        operations = []
        sentinel = object()
        def load(path, *, _policy):
            operations.append(('packet', path))
            self.assertEqual(_policy, fixture.policy)
            return fixture.plan, fixture.catalog
        def export(plan, catalog, evidence, receipt, *, _policy):
            operations.append(('export', evidence, receipt))
            self.assertEqual(plan, fixture.plan)
            self.assertEqual(catalog, fixture.catalog)
            self.assertEqual(_policy, fixture.policy)
            return sentinel
        with patch.object(check, 'load_packet', side_effect=load), \
             patch.object(check, 'check_export', side_effect=export):
            self.assertIs(check.check('packet', 'evidence', 'receipt', _policy=fixture.policy), sentinel)
        self.assertEqual(operations, [('packet', 'packet'), ('export', 'evidence', 'receipt')])
        with patch.object(check, 'load_packet', side_effect=ValueError('packet refused')), \
             patch.object(check, 'check_export', side_effect=AssertionError('export checker called')):
            with self.assertRaisesRegex(ValueError, 'packet refused'):
                check.check('packet', 'evidence', 'receipt', _policy=fixture.policy)

    def test_13_complete_packet_to_independent_pair_composition(self):
        fixture = self.baseline()
        with tempfile.TemporaryDirectory(prefix='glue-private-packet-composition-') as directory:
            root = Path(directory).resolve()
            packet, evidence, receipt = (root / name for name in ('packet', 'evidence', 'receipt'))
            _write_packet(packet, fixture.packet)
            calibration.write_tree(evidence, fixture.evidence)
            calibration.write_tree(receipt, fixture.receipt)
            facts = check.check(packet, evidence, receipt, _policy=fixture.policy)
            self.assertEqual(facts.positive.raw_events, 3)
            self.assertEqual(facts.denied.raw_events, 0)
            self.assertFalse(facts.exec_proved)
            self.assertFalse(facts.full_acceptance)

    def test_14_dynamic_member_manifest_hash_is_still_required(self):
        fixture = self.baseline()
        for name in _DYNAMIC_NAMES:
            data = dict(fixture.packet)
            original = _sha(data[name]).encode('ascii') + b'  ' + name.encode('ascii') + b'\n'
            replacement = b'0' * 64 + b'  ' + name.encode('ascii') + b'\n'
            data['SHA256SUMS'] = data['SHA256SUMS'].replace(original, replacement)
            self.assertNotEqual(data['SHA256SUMS'], fixture.packet['SHA256SUMS'])
            with self.subTest(member=name), self.assertRaisesRegex(ValueError, 'canonical member'):
                check._packet(_FakeTree(data), prep, fixture.policy)

    def test_15_all_six_preparer_metadata_postconditions(self):
        fixture = self.baseline()
        mapping = (
            ('catalog.bin', 'catalog.bin'), ('recipe.json', 'recipe.json'),
            ('source-lock.json', 'source-lock.json'), ('admitted-proof.json', 'admitted-proof.json'),
            ('build-result.json', 'result.json'), ('build-SHA256SUMS', 'SHA256SUMS'),
        )
        data = {original: fixture.packet['metadata/' + name]
                for name, original in mapping if original != 'SHA256SUMS'}
        manifest = fixture.packet['metadata/build-SHA256SUMS']
        self.assertIsNone(prep._verify_metadata(data, manifest, _policy=fixture.policy))
        for name, original in mapping:
            changed = dict(data)
            changed_manifest = manifest
            if original == 'SHA256SUMS':
                changed_manifest = _flip(manifest)
            else:
                changed[original] = _flip(changed[original])
            with self.subTest(metadata=name), self.assertRaisesRegex(ValueError, 'approved kit metadata differs'):
                prep._verify_metadata(changed, changed_manifest, _policy=fixture.policy)
        for rows in (fixture.policy.metadata[:-1], tuple(reversed(fixture.policy.metadata))):
            policy = prep._Admission(fixture.policy.approved_json, rows, True)
            with self.assertRaisesRegex(ValueError, 'metadata policy roster'):
                prep._verify_metadata(data, manifest, _policy=policy)


if __name__ == '__main__':
    unittest.main()
