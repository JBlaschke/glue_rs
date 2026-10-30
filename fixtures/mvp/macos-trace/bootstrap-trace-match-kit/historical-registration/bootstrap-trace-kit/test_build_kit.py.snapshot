"""Synthetic tracing-profile controls. No admitted kit or provider executes."""
import copy
from dataclasses import FrozenInstanceError, replace
import importlib.util
import json
import os
from pathlib import Path
import platform
import struct
import subprocess
import tempfile
import unittest
from unittest.mock import patch

HERE = Path(__file__).resolve().parent
UNCONFIGURED = HERE / 'unconfigured-inputs.fixture.json'
spec = importlib.util.spec_from_file_location('owned_trace_kit', HERE / 'build_kit.py')
trace = importlib.util.module_from_spec(spec)
spec.loader.exec_module(trace)
core = trace.core
UNCONFIGURED_POLICY = replace(trace.POLICY, registry_relative=trace.BASE + 'bootstrap-trace-kit/unconfigured-inputs.fixture.json')
spec = importlib.util.spec_from_file_location('legacy_kit_fixtures', HERE.parent / 'bootstrap-kit' / 'test_build_kit.py')
fixtures = importlib.util.module_from_spec(spec)
spec.loader.exec_module(fixtures)


def configured_parser_rules():
    """Deliberately synthetic strings, never a production source registration."""
    rules = trace.registry(UNCONFIGURED.read_bytes())
    rules['source_revision'] = 'a' * 40
    for artifact in trace.POLICY.artifacts:
        rules[artifact.source_key] = list(artifact.expected_sources)
        for name in artifact.expected_sources:
            rules['sources'][name] = 'b' * 64
    for name in trace.POLICY.required_helpers:
        rules['sources'][name] = 'c' * 64
    return rules


def string_command(kind, offset, name):
    n = (offset + len(name) + 1 + 7) // 8 * 8
    raw = bytearray(n)
    struct.pack_into('<III', raw, 0, kind, n, offset)
    raw[offset:offset + len(name)] = name
    return bytes(raw)


def image(dependencies, *, load_kind=12):
    # Raw parser data only: dummy signature bytes never form an executable.
    commands = [string_command(load_kind, 24, name) for name in dependencies]
    commands += [string_command(14, 12, b'/usr/lib/dyld'),
                 struct.pack('<6I', 0x32, 24, 1, 0x1a0000, 0x1b0000, 0),
                 struct.pack('<II', 0x1b, 24) + bytes(range(1, 17))]
    return fixtures.synthetic_macho(commands)


def command_offset(data, wanted):
    at = 32
    for unused in range(struct.unpack_from('<I', data, 16)[0]):
        kind, length = struct.unpack_from('<II', data, at)
        if kind == wanted:
            return at
        at += length
    raise AssertionError('missing synthetic command')


class TraceKitControls(unittest.TestCase):
    def test_unconfigured_fixture_refuses_and_production_registry_is_frozen(self):
        rules = trace.registry(UNCONFIGURED.read_bytes())
        self.assertIsNone(rules['source_revision'])
        self.assertEqual(rules['sources'], {})
        self.assertEqual(rules['proofs'], [])
        self.assertTrue(all(rules[k] == [] for k in ('probe_sources', 'runner_sources', 'request_sources')))
        self.assertEqual(replace(UNCONFIGURED_POLICY, registry_relative=trace.POLICY.registry_relative), trace.POLICY)
        production = trace.registry(trace.REGISTRY.read_bytes())
        self.assertEqual(production['source_revision'], '4744e339da48543f1d4d8f1dd14f7f543f47d41e')
        self.assertEqual(len(production['sources']), 41)
        self.assertEqual(core.digest(core.canonical(production['sources'])),
                         '99e0222e2b511edf0d64e76db7af20fca38af2f22da30ef6fdec36f1266c6aef')
        self.assertEqual(len(production['proofs']), 1)
        self.assertEqual(production['proofs'][0]['manifest_sha256'],
                         'cd57a36af2a9db11f7d24105485137f7afb2ad9743161db190d7ed6c7ca361fd')
        self.assertEqual(production['proofs'][0]['review_manifest_sha256'],
                         '2b3c60fc811ed292cd3e33a33851ba751a1de8c3667c5c2df8f4062000d80dfb')
        with tempfile.TemporaryDirectory(prefix='glue-trace-kit-deny-') as temp:
            out = Path(temp) / 'new'
            with patch.object(core, 'locked_sources', side_effect=AssertionError('source work forbidden')), \
                 patch.object(core, 'admitted_proof', side_effect=AssertionError('proof work forbidden')), \
                 patch.object(core, 'Build', side_effect=AssertionError('output/build work forbidden')):
                with self.assertRaisesRegex(core.Refusal, 'no independently reviewed actual guest proof'):
                    core.construct(Path(temp) / 'missing-proof', Path(temp) / 'missing-inspector', out,
                                   policy=UNCONFIGURED_POLICY)
            self.assertFalse(out.exists())

    def test_closed_production_cli_and_no_output_for_explicit_empty_fixture(self):
        with tempfile.TemporaryDirectory(prefix='glue-trace-kit-cli-') as temp:
            out = Path(temp) / 'new'
            arguments = ['--guest-proof', temp + '/missing', '--inspector-kit', temp + '/missing-inspector',
                         '--output', str(out)]
            # Explicit test-only empty-profile CLI: no production profile/global override.
            fixture_main = ('import importlib.util,sys; p=sys.argv.pop(1); '
                            's=importlib.util.spec_from_file_location("empty_trace_fixture_cli",p); '
                            'm=importlib.util.module_from_spec(s); s.loader.exec_module(m); '
                            'sys.exit(m.core.main(policy=m.UNCONFIGURED_POLICY))')
            fixture_argv = [os.sys.executable, '-B', '-c', fixture_main, str(HERE / 'test_build_kit.py'), *arguments]
            result = subprocess.run(fixture_argv, capture_output=True, timeout=5)
            self.assertEqual(result.returncode, 1)
            self.assertEqual(result.stdout, b'')
            self.assertIn(b'no independently reviewed actual guest proof', result.stderr)
            self.assertFalse(out.exists())
            argv = [os.sys.executable, '-B', str(HERE / 'build_kit.py'), *arguments]
            for option in ('--trust', '--hash', '--sip', '--profile', '--libraries', '--target', '--registry', '--source-revision'):
                with self.subTest(option=option):
                    result = subprocess.run(argv + [option, 'override'], capture_output=True, timeout=5)
                    self.assertEqual(result.returncode, 2)
                    self.assertEqual(result.stdout, b'')
                    self.assertFalse(out.exists())

    def test_frozen_profiles_preserve_legacy_module_defaults(self):
        before = core.REGISTRY, core.HERE, core.LEGACY_POLICY
        with self.assertRaises(FrozenInstanceError):
            trace.POLICY.sip_stdout = core.LEGACY_POLICY.sip_stdout
        with self.assertRaises(FrozenInstanceError):
            trace.POLICY.artifacts[1].dependencies = core.SYSTEM_DEPENDENCIES
        trace.registry(trace.REGISTRY.read_bytes())
        trace.macho(image(core.SYSTEM_DEPENDENCIES), artifact='context-probe')
        self.assertEqual((core.REGISTRY, core.HERE, core.LEGACY_POLICY), before)
        self.assertEqual(core.LEGACY_POLICY.sip_stdout, b'System Integrity Protection status: enabled.\n')
        for field in ('registry_schema', 'recipe_schema', 'build_id_schema', 'result_schema', 'partial_failure_schema', 'signing_prefix'):
            self.assertNotEqual(getattr(trace.POLICY, field), getattr(core.LEGACY_POLICY, field))

    def test_registry_schema_self_reference_and_fixed_compile_units(self):
        legacy = core.registry((HERE.parent / 'bootstrap-kit' / 'unconfigured-inputs.fixture.json').read_bytes())
        with self.assertRaises(core.Refusal):
            trace.registry(core.canonical(legacy))
        with self.assertRaises(core.Refusal):
            core.registry(trace.REGISTRY.read_bytes())
        rules = configured_parser_rules()
        self.assertEqual(trace.registry(core.canonical(rules)), rules)
        self.assertEqual([len(a.expected_sources) for a in trace.POLICY.artifacts], [2, 19, 6])
        for change in ('self', 'missing-trace-unit', 'reordered', 'unexpected-key', 'partial-unconfigured'):
            trial = copy.deepcopy(rules)
            if change == 'self': trial['sources'][trace.POLICY.registry_relative] = 'd' * 64
            if change == 'missing-trace-unit': trial['runner_sources'].remove(trace.BASE + 'bootstrap-runner/runner_trace.c')
            if change == 'reordered': trial['runner_sources'].reverse()
            if change == 'unexpected-key': trial['profile'] = 'smaller'
            if change == 'partial-unconfigured': trial['source_revision'] = None
            with self.subTest(change=change), self.assertRaises(core.Refusal):
                trace.registry(core.canonical(trial))

    def test_source_lock_and_unreviewed_proof_refuse_before_followups(self):
        empty = trace.registry(UNCONFIGURED.read_bytes())
        with patch.object(core, 'git', side_effect=AssertionError('source inspection forbidden')), \
             patch.object(core, 'open_directory', side_effect=AssertionError('tree open forbidden')):
            with self.assertRaisesRegex(core.Refusal, 'not configured/frozen'):
                core.locked_sources(HERE.parents[3], empty, policy=trace.POLICY)
        with tempfile.TemporaryDirectory(prefix='glue-trace-kit-unreviewed-') as temp:
            root = Path(temp).resolve()
            fixtures.write_tree(root, {'observation.stdout': core.canonical(fixtures.sample_observation())})
            with patch.object(core, 'verified_tree', side_effect=AssertionError('unreviewed tree forbidden')):
                with self.assertRaisesRegex(core.Refusal, 'not been independently reviewed'):
                    trace.admitted_proof(root, root, {'proofs': []})

    def test_exact_sip_profile_separation_and_literal_postboot_mounts(self):
        with tempfile.TemporaryDirectory(prefix='glue-trace-kit-proof-') as temp:
            root = Path(temp).resolve(); proof = root / 'proof'; inspector = root / 'inspector'
            proof.mkdir(); inspector.mkdir()
            observed = fixtures.sample_observation()
            for i, component in enumerate(observed['components']):
                component['device'] = 77
                component['fsid'] = [88 if i < 3 else 77, 99]
            entry, members = fixtures.synthetic_proof_trees(proof, inspector, observed=observed)
            with self.assertRaisesRegex(core.Refusal, 'not exactly disabled'):
                trace.admitted_proof(proof, inspector, {'proofs': [entry]})
            members['sip.stdout'] = trace.POLICY.sip_stdout
            entry['manifest_sha256'] = fixtures.write_tree(proof, members)
            admitted, actual = trace.admitted_proof(proof, inspector, {'proofs': [entry]})
            self.assertEqual(admitted, entry); self.assertEqual(actual, observed)
            with self.assertRaisesRegex(core.Refusal, 'not exactly enabled'):
                core.admitted_proof(proof, inspector, {'proofs': [entry]})
            profile = {name: {key: actual['components'][i][key] for key in ('device', 'fsid')}
                       for name, i in (('root', 0), ('data', 3))}
            catalog = core.catalog_bytes('a' * 64, profile, 1234, *(['b' * 64] * 4))
            self.assertEqual(struct.unpack_from('>QiiQii', catalog, 24), (77, 88, 99, 77, 77, 99))
            for sip in (trace.POLICY.sip_stdout.rstrip(b'\n'), trace.POLICY.sip_stdout.replace(b'\n', b'\r\n'),
                        b' ' + trace.POLICY.sip_stdout, trace.POLICY.sip_stdout + b'custom configuration\n'):
                trial = dict(members); trial['sip.stdout'] = sip
                entry['manifest_sha256'] = fixtures.write_tree(proof, trial)
                with self.subTest(sip=sip), self.assertRaisesRegex(core.Refusal, 'not exactly disabled'):
                    trace.admitted_proof(proof, inspector, {'proofs': [entry]})

    def test_tracing_keeps_exact_inspector_command_os_and_model_admission(self):
        with tempfile.TemporaryDirectory(prefix='glue-trace-kit-proof-fields-') as temp:
            root = Path(temp).resolve(); proof = root / 'proof'; inspector = root / 'inspector'
            proof.mkdir(); inspector.mkdir()
            entry, members = fixtures.synthetic_proof_trees(proof, inspector)
            members['sip.stdout'] = trace.POLICY.sip_stdout
            variants = [('signature.status', b'1\n'), ('observation.argv', b'/different\0'),
                        ('kernel.stdout', b'Darwin 26.6.0 x86_64\n'), ('os.stdout', b'ProductName: macOS\n'),
                        ('observation.stdout', core.canonical(dict(fixtures.sample_observation(), model='other')))]
            for key, value in variants:
                trial = dict(members); trial[key] = value
                changed = dict(entry, manifest_sha256=fixtures.write_tree(proof, trial))
                with self.subTest(key=key), self.assertRaises(core.Refusal):
                    trace.admitted_proof(proof, inspector, {'proofs': [changed]})
            entry['manifest_sha256'] = fixtures.write_tree(proof, members)
            wrong_source = dict(entry, inspector_source_commit='0' * 40)
            with self.assertRaisesRegex(core.Refusal, 'inspector kit schema/scope'):
                trace.admitted_proof(proof, inspector, {'proofs': [wrong_source]})

    def test_exact_artifact_dependency_policy_and_unknown_selectors(self):
        system = core.SYSTEM_DEPENDENCIES; traced = system + (b'/usr/lib/libdtrace.dylib',)
        self.assertEqual(trace.macho(image(traced))['dependencies'], [n.decode() for n in traced])
        for name in ('context-probe', 'make-request'):
            self.assertEqual(trace.macho(image(system), artifact=name)['dependencies'], [n.decode() for n in system])
            with self.assertRaises(core.Refusal): trace.macho(image(traced), artifact=name)
        with self.assertRaises(core.Refusal): trace.macho(image(system))
        with self.assertRaises(core.Refusal): core.macho(image(traced))
        for deps in (traced[::-1], traced + (b'/usr/lib/other.dylib',), traced + system,
                     (b'/usr/lib/libdtrace.dylib',), system + (b'/usr/lib/libdtrace.1.dylib',)):
            with self.subTest(deps=deps), self.assertRaises(core.Refusal): trace.macho(image(deps))
        for name in ('bootstrap-runner', '../owned-trace-runner', '', None, True):
            with self.subTest(name=name), self.assertRaises(core.Refusal): trace.macho(image(traced), artifact=name)

    def test_tracing_retains_all_macho_constraints(self):
        deps = core.SYSTEM_DEPENDENCIES + (b'/usr/lib/libdtrace.dylib',)
        good = image(deps)
        for kind in (0x80000018, 0x8000001f, 0x80000023, 0x20):
            with self.subTest(kind=kind), self.assertRaises(core.Refusal): trace.macho(image(deps, load_kind=kind))
        variants = [good[:-1], bytes(32)]
        for offset, value in ((8, 2), (command_offset(good, 0x32) + 12, 0x190000), (32, 0x8000001c)):
            raw = bytearray(good); struct.pack_into('<I', raw, offset, value); variants.append(bytes(raw))
        raw = bytearray(good); at = command_offset(good, 0x1b); raw[at + 8:at + 24] = bytes(16); variants.append(bytes(raw))
        for raw in variants:
            with self.subTest(size=len(raw)), self.assertRaises(core.Refusal): trace.macho(raw)

    def test_legacy_recipe_golden_and_runner_only_flags(self):
        rules = {'probe_sources': ['probe.c'], 'runner_sources': ['runner.c'], 'request_sources': ['request.c']}
        args = (b'synthetic compiler parser fixture\n', '/Library/Developer/SDKs/Synthetic.sdk', '26.0', rules)
        legacy = core.recipe_for(*args)
        # Frozen independently from the pre-refactor recipe literal at6c75976.
        self.assertEqual(core.digest(core.canonical(legacy)), '055ac5b31d3a7a201e4912f893cd8ee837d8d42ba3be4a6c64ba994d9cdb8083')
        traced = core.recipe_for(*args, policy=trace.POLICY)
        self.assertNotEqual(core.digest(core.canonical(traced)), core.digest(core.canonical(legacy)))
        self.assertEqual(traced['sip_policy'], 'exact-disabled')
        fixed = configured_parser_rules()
        for artifact in trace.POLICY.artifacts:
            command = core.compile_command(['clang'], Path('/synthetic-sources'), fixed,
                                           Path('/catalog.c'), Path('/output'), artifact.name, policy=trace.POLICY)
            self.assertEqual('-ldtrace' in command, artifact.name == 'owned-trace-runner')
            self.assertEqual('-DGLUE_OWNED_TRACING' in command, artifact.name == 'owned-trace-runner')
            self.assertEqual('/catalog.c' in command, artifact.name != 'context-probe')
        with self.assertRaises(core.Refusal):
            core.compile_command([], Path('/sources'), fixed, Path('/catalog'), Path('/out'), 'arbitrary', policy=trace.POLICY)

    def test_failure_schemas_are_distinct_without_any_tool(self):
        with tempfile.TemporaryDirectory(prefix='glue-trace-kit-failure-') as temp:
            root = Path(temp).resolve()
            build = core.Build(root / 'closed-model', HERE.parents[3], policy=trace.POLICY)
            build.retain_failure(core.Refusal('synthetic parser-only failure'))
            result = json.loads((build.output / 'result.json').read_bytes())
            self.assertEqual(result['schema'], trace.POLICY.result_schema)
            self.assertFalse(result['new_binaries_executed'])
            build = core.Build(root / 'partial-model', HERE.parents[3], policy=trace.POLICY)
            build.tool_cleanup_unresolved = True; build.active_tool = 'synthetic-no-process'
            build.retain_failure(core.Refusal('synthetic unresolved model'))
            partial = json.loads((build.output / 'failure.partial.json').read_bytes())
            self.assertEqual(partial['schema'], trace.POLICY.partial_failure_schema)
            self.assertFalse((build.output / 'SHA256SUMS').exists())

    @unittest.skipUnless(platform.system() == 'Darwin', 'actual SDK metadata requires Darwin')
    def test_sdk_dependency_metadata_compile_link_only(self):
        with tempfile.TemporaryDirectory(prefix='glue-trace-kit-sdk-') as temp:
            root = Path(temp); source = root / 'main.c'; binary = root / 'never-executed'
            source.write_text('#include <dtrace.h>\nint main(void){int e=0;dtrace_hdl_t*h=dtrace_open(DTRACE_VERSION,DTRACE_O_LP64,&e);if(h)dtrace_close(h);return 0;}\n')
            command = ['/usr/bin/xcrun', '--sdk', 'macosx', 'clang', *core.BASE_FLAGS,
                       str(source), '-lproc', '-ldtrace', '-o', str(binary)]
            subprocess.run(command, check=True, capture_output=True, timeout=30)
            self.assertEqual(trace.macho(binary.read_bytes())['dependencies'],
                             ['/usr/lib/libSystem.B.dylib', '/usr/lib/libdtrace.dylib'])
            # NEVER execute binary, including when this host supports its target.


if __name__ == '__main__':
    unittest.main()
