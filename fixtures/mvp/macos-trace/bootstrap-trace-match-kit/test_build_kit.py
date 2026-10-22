"""Source and synthetic controls only; no native build or actual proof access."""
import copy
from dataclasses import FrozenInstanceError, fields, replace
import hashlib
import importlib.util
import inspect
from pathlib import Path
import struct
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch


HERE = Path(__file__).resolve().parent
UNCONFIGURED = HERE / 'unconfigured-inputs.fixture.json'
spec = importlib.util.spec_from_file_location('trace_match_kit', HERE / 'build_kit.py')
match = importlib.util.module_from_spec(spec)
spec.loader.exec_module(match)
core = match.core
UNCONFIGURED_POLICY = replace(
    match.POLICY, registry_relative=match.BASE + 'bootstrap-trace-match-kit/unconfigured-inputs.fixture.json')
spec = importlib.util.spec_from_file_location(
    'trace_match_parser_fixtures', HERE.parent / 'bootstrap-trace-kit' / 'test_build_kit.py')
parent_fixtures = importlib.util.module_from_spec(spec)
spec.loader.exec_module(parent_fixtures)
fixtures = parent_fixtures.fixtures

HISTORICAL_PINS = {
    'bootstrap-kit/build_kit.py': '440cdc2cadf5d86acae91e313c266b815d1c40130b4ce53d58a77e36b13fff48',
    'bootstrap-kit/reviewed-inputs.json': '0f9d7cfe9e164a3ae8e085f7c9987f27f0ed99d348ff8b36d8d4d7d06e734ec1',
    'bootstrap-trace-kit/build_kit.py': '53a136ec3b3728bbb5e977bc0d962c287f49e21b43614082caead8e2597d44f1',
    'bootstrap-trace-kit/reviewed-inputs.json': 'de0dea7e3b5f594333427ebe0d70e983121a93b78c8838775742023899128d85',
    'bootstrap-trace-kit/test_build_kit.py': '15bf5da8684d0bfe0589af565ce468c67cb5d2be19bd44e9958c308c2a3c072b',
    'bootstrap-trace-vm/prepare.py': '3549edd7c6418ea9f40c9c791c919573dcf9ae6ea9d9eb609a849787de4e1719',
    'bootstrap-trace-vm/kit_contract.py': 'a16e2e25b78acb5c7d85ffbf9805941f9634b84003c43b515d3f8ccbd1de2fc2',
    'bootstrap-trace-calibration-vm/prepare.py': '32728f45845e1d7aec1f3e3c99a7fb17edca710d0f84e177a6a6bafd684e5487',
}
# The host reader deliberately advances with reviewed source dependencies;
# native builders, registries and packet preparation above remain historical.
REVIEWED_HOST_READER_PINS = {
    'bootstrap-trace-calibration-vm/checker.py': '0249c241d801fb736e346cd0a6640bbd4285256df19f2abbd00337b4b1a368ba',
}


def configured_parser_rules():
    """Synthetic source identities for parser tests, never production admission."""
    rules = parent_fixtures.configured_parser_rules()
    rules['sources'][match.WRAPPER] = 'd' * 64
    return rules


class MatchKitControls(unittest.TestCase):
    def test_unconfigured_fixture_refuses_before_source_proof_or_output(self):
        self.assertEqual(hashlib.sha256(UNCONFIGURED.read_bytes()).hexdigest(),
                         '218255f76dcb5da45760c0c84a1e7b17098063055452f752c8eef7850109685d')
        rules = core.registry(UNCONFIGURED.read_bytes(), policy=UNCONFIGURED_POLICY)
        self.assertEqual(rules, {'schema': 'glue-owned-trace-kit-inputs-v1', 'source_revision': None,
                                 'sources': {}, 'probe_sources': [], 'runner_sources': [],
                                 'request_sources': [], 'proofs': []})
        with tempfile.TemporaryDirectory(prefix='glue-match-kit-empty-') as temporary:
            root = Path(temporary).resolve(); output = root / 'new'
            with patch.object(core, 'locked_sources', side_effect=AssertionError('source work forbidden')), \
                    patch.object(core, 'admitted_proof', side_effect=AssertionError('proof work forbidden')), \
                    patch.object(core, 'Build', side_effect=AssertionError('output or tool work forbidden')):
                with self.assertRaisesRegex(core.Refusal, 'no independently reviewed actual guest proof'):
                    core.construct(root / 'absent-proof', root / 'absent-inspector', output,
                                   policy=UNCONFIGURED_POLICY)
            self.assertFalse(output.exists())

    def test_explicit_unconfigured_fixture_cli_refuses_without_output(self):
        with tempfile.TemporaryDirectory(prefix='glue-match-kit-fixture-cli-') as temporary:
            root = Path(temporary).resolve(); output = root / 'new'
            # This test-only CLI fixes the fixture policy without changing any
            # production wrapper, module global or public command-line option.
            fixture_main = ('import importlib.util,sys; p=sys.argv.pop(1); '
                            's=importlib.util.spec_from_file_location("empty_match_fixture_cli",p); '
                            'm=importlib.util.module_from_spec(s); s.loader.exec_module(m); '
                            'sys.exit(m.core.main(policy=m.UNCONFIGURED_POLICY))')
            argv = [sys.executable, '-B', '-c', fixture_main, str(HERE / 'test_build_kit.py'),
                    '--guest-proof', str(root / 'absent'), '--inspector-kit', str(root / 'absent-inspector'),
                    '--output', str(output)]
            result = subprocess.run(argv, capture_output=True, timeout=5)
            self.assertEqual(result.returncode, 1)
            self.assertEqual(result.stdout, b'')
            self.assertIn(b'no independently reviewed actual guest proof', result.stderr)
            self.assertFalse(output.exists())

    def test_production_registry_and_cli_are_explicitly_unconfigured(self):
        # Update this explicit production expectation only in the later actual
        # admission step. Empty-fixture refusal controls remain independent.
        self.assertEqual(match.registry(match.REGISTRY.read_bytes()), {
            'schema': 'glue-owned-trace-kit-inputs-v1', 'source_revision': None,
            'sources': {}, 'probe_sources': [], 'runner_sources': [], 'request_sources': [], 'proofs': []})
        self.assertEqual(match.REGISTRY.read_bytes(), UNCONFIGURED.read_bytes())
        with tempfile.TemporaryDirectory(prefix='glue-match-kit-cli-') as temporary:
            root = Path(temporary).resolve(); output = root / 'new'
            argv = [sys.executable, '-B', str(HERE / 'build_kit.py'), '--guest-proof', str(root / 'absent'),
                    '--inspector-kit', str(root / 'absent-inspector'), '--output', str(output)]
            result = subprocess.run(argv, capture_output=True, timeout=5)
            self.assertEqual(result.returncode, 1)
            self.assertEqual(result.stdout, b'')
            self.assertIn(b'no independently reviewed actual guest proof', result.stderr)
            self.assertFalse(output.exists())
            for option in ('--trust', '--hash', '--sip', '--profile', '--libraries', '--target', '--registry', '--source-revision'):
                with self.subTest(option=option):
                    result = subprocess.run(argv + [option, 'override'], capture_output=True, timeout=5)
                    self.assertEqual(result.returncode, 2)
                    self.assertEqual(result.stdout, b'')
                    self.assertIn(b'unrecognized arguments', result.stderr)
                    self.assertFalse(output.exists())

    def test_policy_is_frozen_and_only_routing_and_helper_closure_differ(self):
        parent = match.trace.POLICY
        changed = {field.name for field in fields(parent) if getattr(parent, field.name) != getattr(match.POLICY, field.name)}
        self.assertEqual(changed, {'registry_relative', 'guard_paths', 'required_helpers', 'excluded_runner_parts'})
        self.assertEqual(match.POLICY.registry_relative, match.BASE + 'bootstrap-trace-match-kit/reviewed-inputs.json')
        self.assertEqual(match.POLICY.required_helpers,
                         (match.BASE + 'bootstrap-kit/build_kit.py', match.BASE + 'bootstrap-trace-kit/build_kit.py', match.WRAPPER))
        self.assertEqual(match.POLICY.guard_paths, match.POLICY.required_helpers + (match.REGISTRY_RELATIVE,))
        self.assertEqual(match.POLICY.excluded_runner_parts, parent.excluded_runner_parts + ('/bootstrap-trace-match-kit/',))
        with self.assertRaises(FrozenInstanceError):
            match.POLICY.sip_stdout = b'override'
        with self.assertRaises(FrozenInstanceError):
            match.POLICY.artifacts[1].dependencies = core.SYSTEM_DEPENDENCIES
        self.assertEqual((core.REGISTRY, core.LEGACY_POLICY.sip_stdout),
                         (HERE.parent / 'bootstrap-kit/reviewed-inputs.json', b'System Integrity Protection status: enabled.\n'))
        self.assertEqual(parent.registry_relative, match.BASE + 'bootstrap-trace-kit/reviewed-inputs.json')
        self.assertEqual(len(parent.required_helpers), 2)
        self.assertEqual(replace(UNCONFIGURED_POLICY, registry_relative=match.POLICY.registry_relative), match.POLICY)
        with self.assertRaises(FrozenInstanceError):
            UNCONFIGURED_POLICY.registry_relative = match.POLICY.registry_relative

    def test_public_entries_close_over_constant_policy_and_do_not_mutate_defaults(self):
        before = core.REGISTRY, core.HERE, core.LEGACY_POLICY, match.trace.POLICY
        arguments = (Path('/synthetic/proof'), Path('/synthetic/inspector'), Path('/synthetic/output'))
        with patch.object(core, 'construct', return_value=7) as construct:
            self.assertEqual(match.construct(*arguments), 7)
        construct.assert_called_once_with(*arguments, policy=match.POLICY)
        with patch.object(core, 'admitted_proof', return_value=('entry', 'observation')) as admission:
            self.assertEqual(match.admitted_proof(*arguments), ('entry', 'observation'))
        admission.assert_called_once_with(*arguments, policy=match.POLICY)
        with patch.object(core, 'main', return_value=8) as main:
            self.assertEqual(match.main(), 8)
        main.assert_called_once_with(policy=match.POLICY)
        self.assertEqual((core.REGISTRY, core.HERE, core.LEGACY_POLICY, match.trace.POLICY), before)
        for entry in (match.registry, match.admitted_proof, match.construct, match.main, match.macho):
            self.assertNotIn('policy', inspect.signature(entry).parameters)
        with self.assertRaises(TypeError):
            match.construct(*arguments, policy=core.LEGACY_POLICY)

    def test_synthetic_configured_registry_preserves_fixed_compile_lists(self):
        rules = configured_parser_rules()
        self.assertEqual(match.registry(core.canonical(rules)), rules)
        self.assertEqual([len(rules[key]) for key in ('probe_sources', 'runner_sources', 'request_sources')], [2, 19, 6])
        for mutation in ('self-reference', 'missing-trace-unit', 'reordered', 'extra-key', 'partial-null', 'wrong-schema'):
            with self.subTest(mutation=mutation):
                trial = copy.deepcopy(rules)
                if mutation == 'self-reference': trial['sources'][match.REGISTRY_RELATIVE] = 'e' * 64
                if mutation == 'missing-trace-unit': trial['runner_sources'].remove(match.BASE + 'bootstrap-runner/runner_trace.c')
                if mutation == 'reordered': trial['runner_sources'].reverse()
                if mutation == 'extra-key': trial['profile'] = 'override'
                if mutation == 'partial-null': trial['source_revision'] = None
                if mutation == 'wrong-schema': trial['schema'] = core.LEGACY_POLICY.registry_schema
                with self.assertRaises(core.Refusal):
                    match.registry(core.canonical(trial))

    def test_unconfigured_and_dirty_source_locks_refuse_before_source_reads(self):
        rules = core.registry(UNCONFIGURED.read_bytes(), policy=UNCONFIGURED_POLICY)
        with patch.object(core, 'git', side_effect=AssertionError('git forbidden')), \
                patch.object(core, 'open_directory', side_effect=AssertionError('source read forbidden')):
            with self.assertRaisesRegex(core.Refusal, 'not configured/frozen'):
                core.locked_sources(HERE.parents[3], rules, policy=UNCONFIGURED_POLICY)
        with patch.object(core, 'git', return_value=b' M synthetic\n'), \
                patch.object(core, 'open_directory', side_effect=AssertionError('dirty source read forbidden')):
            with self.assertRaisesRegex(core.Refusal, 'dirty/untracked'):
                core.locked_sources(HERE.parents[3], configured_parser_rules(), policy=match.POLICY)

    def test_isolated_source_lock_requires_third_helper_and_all_head_guards(self):
        with tempfile.TemporaryDirectory(prefix='glue-match-kit-source-model-') as temporary:
            repo = Path(temporary).resolve(); rules = configured_parser_rules()
            data = {name: ('synthetic locked source ' + name + '\n').encode() for name in rules['sources']}
            rules['sources'] = {name: hashlib.sha256(raw).hexdigest() for name, raw in data.items()}
            data[match.REGISTRY_RELATIVE] = core.canonical(rules)
            for name, raw in data.items():
                path = repo / name; path.parent.mkdir(parents=True, exist_ok=True); path.write_bytes(raw)
            calls = []
            head_difference = None
            def git_model(repository, *args):
                self.assertEqual(repository, repo); calls.append(args)
                if args in (('status', '--porcelain=v1', '--untracked-files=all'),
                            ('merge-base', '--is-ancestor', rules['source_revision'], 'HEAD')):
                    return b''
                self.assertEqual(args[0], 'show')
                revision, name = args[1].split(':', 1)
                self.assertIn(revision, ('HEAD', rules['source_revision']))
                return data[name] + (b'uncommitted' if revision == 'HEAD' and name == head_difference else b'')
            with patch.object(core, 'git', side_effect=git_model):
                baseline = core.locked_sources(repo, rules, policy=match.POLICY)
                self.assertEqual(baseline, {name: data[name] for name in rules['sources']})
                for name in match.POLICY.guard_paths:
                    self.assertIn(('show', 'HEAD:' + name), calls)
                for head_difference in match.POLICY.guard_paths:
                    with self.subTest(guard=head_difference), self.assertRaisesRegex(core.Refusal, 'uncommitted builder/registry'):
                        core.locked_sources(repo, rules, policy=match.POLICY)
                head_difference = None
                missing = copy.deepcopy(rules); del missing['sources'][match.WRAPPER]
                with self.assertRaisesRegex(core.Refusal, 'builder absent from closure'):
                    core.locked_sources(repo, missing, policy=match.POLICY)
                broken = copy.deepcopy(rules); broken['sources'][match.WRAPPER] = '0' * 64
                with self.assertRaisesRegex(core.Refusal, 'source lock mismatch'):
                    core.locked_sources(repo, broken, policy=match.POLICY)

    def test_literal_disabled_proof_required_and_observations_preserved(self):
        with tempfile.TemporaryDirectory(prefix='glue-match-kit-proof-model-') as temporary:
            root = Path(temporary).resolve(); proof = root / 'proof'; inspector = root / 'inspector'
            proof.mkdir(); inspector.mkdir()
            observed = fixtures.sample_observation()
            for index, component in enumerate(observed['components']):
                component['device'] = 77; component['fsid'] = [88 if index < 3 else 77, 99]
            entry, members = fixtures.synthetic_proof_trees(proof, inspector, observed=observed)
            with self.assertRaisesRegex(core.Refusal, 'not exactly disabled'):
                match.admitted_proof(proof, inspector, {'proofs': [entry]})
            members['sip.stdout'] = b'System Integrity Protection status: disabled.\n'
            entry['manifest_sha256'] = fixtures.write_tree(proof, members)
            admitted, actual = match.admitted_proof(proof, inspector, {'proofs': [entry]})
            self.assertEqual((admitted, actual), (entry, observed))
            for sip in (b'System Integrity Protection status: disabled.',
                        b'System Integrity Protection status: disabled.\r\n',
                        b' System Integrity Protection status: disabled.\n',
                        b'System Integrity Protection status: disabled.\ncustom\n'):
                trial = dict(members); trial['sip.stdout'] = sip
                candidate = dict(entry, manifest_sha256=fixtures.write_tree(proof, trial))
                with self.subTest(sip=sip), self.assertRaisesRegex(core.Refusal, 'not exactly disabled'):
                    match.admitted_proof(proof, inspector, {'proofs': [candidate]})

    def test_proof_command_signature_os_and_model_tampering_refuses(self):
        with tempfile.TemporaryDirectory(prefix='glue-match-kit-proof-fields-') as temporary:
            root = Path(temporary).resolve(); proof = root / 'proof'; inspector = root / 'inspector'
            proof.mkdir(); inspector.mkdir()
            entry, members = fixtures.synthetic_proof_trees(proof, inspector)
            members['sip.stdout'] = match.POLICY.sip_stdout
            entry['manifest_sha256'] = fixtures.write_tree(proof, members)
            self.assertEqual(match.admitted_proof(proof, inspector, {'proofs': [entry]})[0], entry)
            for name, raw in (('signature.status', b'1\n'), ('observation.argv', b'/other\0'),
                              ('kernel.stdout', b'Darwin 26.6.0 x86_64\n'), ('os.stdout', b'ProductName: macOS\n'),
                              ('observation.stdout', core.canonical(dict(fixtures.sample_observation(), model='other')))):
                trial = dict(members); trial[name] = raw
                candidate = dict(entry, manifest_sha256=fixtures.write_tree(proof, trial))
                with self.subTest(name=name), self.assertRaises(core.Refusal):
                    match.admitted_proof(proof, inspector, {'proofs': [candidate]})

    def test_unregistered_proof_refuses_before_inspector_traversal(self):
        with tempfile.TemporaryDirectory(prefix='glue-match-kit-unregistered-') as temporary:
            root = Path(temporary).resolve()
            fixtures.write_tree(root, {'observation.stdout': b'synthetic unregistered bytes\n'})
            with patch.object(core, 'verified_tree', side_effect=AssertionError('unregistered traversal forbidden')):
                with self.assertRaisesRegex(core.Refusal, 'not been independently reviewed'):
                    match.admitted_proof(root, root / 'absent-inspector', {'proofs': []})

    def test_exact_inherited_compile_link_sign_and_recipe_rules(self):
        rules = configured_parser_rules()
        arguments = (b'synthetic compiler description\n', '/Library/Developer/SDKs/Synthetic.sdk', '26.0', rules)
        self.assertEqual(core.recipe_for(*arguments, policy=match.POLICY),
                         core.recipe_for(*arguments, policy=match.trace.POLICY))
        for artifact in match.POLICY.artifacts:
            command = core.compile_command(['clang', 'synthetic-common'], Path('/sources'), rules,
                                           Path('/catalog.c'), Path('/output'), artifact.name, policy=match.POLICY)
            self.assertEqual(command, core.compile_command(['clang', 'synthetic-common'], Path('/sources'), rules,
                                                          Path('/catalog.c'), Path('/output'), artifact.name,
                                                          policy=match.trace.POLICY))
            units = [str(Path('/sources') / name) for name in rules[artifact.source_key]]
            self.assertEqual(command[2:2 + len(artifact.compiler_flags) + len(units)], list(artifact.compiler_flags) + units)
            self.assertEqual('-DGLUE_OWNED_TRACING' in command, artifact.name == 'owned-trace-runner')
            self.assertEqual('-ldtrace' in command, artifact.name == 'owned-trace-runner')
            self.assertEqual('/catalog.c' in command, artifact.name != 'context-probe')
        with self.assertRaises(core.Refusal):
            core.compile_command([], Path('/sources'), rules, Path('/catalog'), Path('/output'),
                                 'arbitrary', policy=match.POLICY)

    def test_strict_macho_dependencies_and_invalid_native_shapes(self):
        system = (b'/usr/lib/libSystem.B.dylib',); traced = system + (b'/usr/lib/libdtrace.dylib',)
        self.assertEqual(match.macho(parent_fixtures.image(traced))['dependencies'], [item.decode() for item in traced])
        for artifact in ('context-probe', 'make-request'):
            self.assertEqual(match.macho(parent_fixtures.image(system), artifact=artifact)['dependencies'], [item.decode() for item in system])
            with self.assertRaises(core.Refusal): match.macho(parent_fixtures.image(traced), artifact=artifact)
        for dependencies in (system, traced[::-1], traced + system, traced + (b'/usr/lib/other.dylib',)):
            with self.subTest(dependencies=dependencies), self.assertRaises(core.Refusal):
                match.macho(parent_fixtures.image(dependencies))
        for load_kind in (0x80000018, 0x8000001f, 0x80000023, 0x20):
            with self.subTest(load_kind=load_kind), self.assertRaises(core.Refusal):
                match.macho(parent_fixtures.image(traced, load_kind=load_kind))
        good = parent_fixtures.image(traced)
        for raw in (good[:-1], bytes(32)):
            with self.assertRaises(core.Refusal): match.macho(raw)
        raw = bytearray(good); struct.pack_into('<I', raw, 8, 2)
        with self.assertRaises(core.Refusal): match.macho(bytes(raw))
        for artifact in ('bootstrap-runner', '../owned-trace-runner', '', None, True):
            with self.subTest(artifact=artifact), self.assertRaises(core.Refusal):
                match.macho(good, artifact=artifact)

    def test_historical_native_inputs_and_reviewed_current_host_reader(self):
        for relative, expected in HISTORICAL_PINS.items():
            with self.subTest(relative=relative):
                self.assertEqual(hashlib.sha256((HERE.parent / relative).read_bytes()).hexdigest(), expected)
        for relative, expected in REVIEWED_HOST_READER_PINS.items():
            with self.subTest(current_host_reader=relative):
                self.assertNotIn(relative, HISTORICAL_PINS)
                self.assertEqual(hashlib.sha256((HERE.parent / relative).read_bytes()).hexdigest(), expected)
        production = match.trace.registry(match.trace.REGISTRY.read_bytes())
        self.assertEqual(production['source_revision'], 'e2c728bcdb25ceb151f8f434859c668faf0abcd0')
        self.assertEqual(len(production['sources']), 41)
        self.assertEqual(core.digest(core.canonical(production['sources'])),
                         '75fce31776344598d92f8705e5a831a2451687e99b423fc200e89c35e053f997')
        self.assertEqual(len(production['proofs']), 1)


if __name__ == '__main__':
    unittest.main()
