"""Closed object-kit policy/refusal controls; no actual proof or kit is accessed."""
import copy
from dataclasses import FrozenInstanceError
import importlib.util
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

HERE = Path(__file__).resolve().parent
spec = importlib.util.spec_from_file_location('object_kit_policy_controls', HERE / 'build_kit.py')
kit = importlib.util.module_from_spec(spec)
spec.loader.exec_module(kit)

class ObjectKitControls(unittest.TestCase):
    def test_checked_in_profile_is_exact_empty_and_refuses_before_source_or_output(self):
        data = kit.REGISTRY.read_bytes()
        self.assertEqual(data, (HERE / 'unconfigured-inputs.fixture.json').read_bytes())
        rules = kit.registry(data)
        self.assertIsNone(rules['source_revision'])
        self.assertFalse(rules['sources'] or rules['proofs'])
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary); output = root / 'new'
            with patch.object(kit.core, 'locked_sources', side_effect=AssertionError('source IO forbidden')), \
                 patch.object(kit.core, 'admitted_proof', side_effect=AssertionError('proof IO forbidden')), \
                 patch.object(kit.core, 'Build', side_effect=AssertionError('output forbidden')):
                with self.assertRaisesRegex(kit.core.Refusal, 'no independently reviewed actual guest proof'):
                    kit.construct(root / 'missing-proof', root / 'missing-inspector', output)
            self.assertFalse(output.exists())

    def test_partial_null_profile_and_cross_schema_refuse(self):
        empty = kit.registry(kit.REGISTRY.read_bytes())
        for key, value in [('sources', {'x.c': 'a' * 64}), ('proofs', [{}]), ('schema', 'glue-bootstrap-kit-inputs-v1')]:
            changed = copy.deepcopy(empty); changed[key] = value
            with self.subTest(key=key), self.assertRaises(kit.core.Refusal):
                kit.registry(kit.core.canonical(changed))

    def test_fixed_source_profile_and_enabled_sip_preserve_legacy_builder_policy(self):
        self.assertEqual(kit.POLICY.sip_stdout, b'System Integrity Protection status: enabled.\n')
        self.assertFalse(kit.POLICY.tracing)
        self.assertEqual(kit.core.LEGACY_POLICY.registry_relative, 'fixtures/mvp/macos-trace/bootstrap-kit/reviewed-inputs.json')
        self.assertEqual([a.name for a in kit.POLICY.artifacts], ['context-probe', 'bootstrap-fd-objects-runner', 'make-request'])
        runner = kit.POLICY.artifacts[1]
        self.assertEqual(runner.compiler_flags, ())
        self.assertEqual(len(runner.expected_sources), 19)
        self.assertIn(kit.BASE + 'target-cwd/target_cwd.c', runner.expected_sources)
        self.assertIn(kit.BASE + 'bootstrap-object-runner/object_parent.c', runner.expected_sources)
        self.assertIn(kit.BASE + 'bootstrap-object-wire/bootstrap_object_wire.c', runner.expected_sources)
        self.assertIn(kit.BASE + 'target-fd-objects/target_fd_objects.c', runner.expected_sources)
        self.assertNotIn(kit.BASE + 'bootstrap-runner/runner_parent.c', runner.expected_sources)
        self.assertEqual(runner.link_flags, ('-lproc',))
        with self.assertRaises(FrozenInstanceError):
            kit.POLICY.sip_label = 'disabled'

    def test_fixed_source_lists_refuse_legacy_or_reordered_runner(self):
        rules = kit.registry(kit.REGISTRY.read_bytes())
        rules['source_revision'] = 'a' * 40
        for key, values in [('probe_sources', kit.PROBE_SOURCES), ('runner_sources', kit.RUNNER_SOURCES), ('request_sources', kit.REQUEST_SOURCES)]:
            rules[key] = list(values)
            rules['sources'].update({name: 'b' * 64 for name in values})
        self.assertEqual(kit.registry(kit.core.canonical(rules)), rules)
        for change in ('reorder', 'legacy'):
            changed = copy.deepcopy(rules)
            if change == 'reorder': changed['runner_sources'].reverse()
            else:
                name = kit.BASE + 'bootstrap-runner/runner_parent.c'
                changed['runner_sources'][6] = name; changed['sources'][name] = 'c' * 64
            with self.subTest(change=change), self.assertRaisesRegex(kit.core.Refusal, 'compile sources differ'):
                kit.registry(kit.core.canonical(changed))

    def test_profile_source_choice_enters_recipe_and_compile_argv(self):
        rules = {'probe_sources': list(kit.PROBE_SOURCES), 'runner_sources': list(kit.RUNNER_SOURCES), 'request_sources': list(kit.REQUEST_SOURCES)}
        recipe = kit.core.recipe_for(b'compiler', '/Library/SDK', '26.0', rules, policy=kit.POLICY)
        self.assertEqual(recipe['schema'], 'glue-bootstrap-fd-objects-kit-recipe-v1')
        self.assertEqual(recipe['runner_sources'], list(kit.RUNNER_SOURCES))
        command = kit.core.compile_command(['clang'], Path('/frozen'), rules, Path('/catalog.generated.c'), Path('/out'), 'bootstrap-fd-objects-runner', policy=kit.POLICY)
        self.assertIn('/frozen/' + kit.BASE + 'bootstrap-object-runner/object_parent.c', command)
        self.assertNotIn('/frozen/' + kit.BASE + 'bootstrap-runner/runner_parent.c', command)
        self.assertEqual(command[-3:], ['-lproc', '-o', '/out'])

    def test_closed_cli_has_no_profile_trust_source_or_sip_overrides(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary); output = root / 'new'
            argv = [sys.executable, '-B', str(HERE / 'build_kit.py'), '--guest-proof', str(root / 'missing'), '--inspector-kit', str(root / 'missing-inspector'), '--output', str(output)]
            done = subprocess.run(argv, capture_output=True, timeout=5)
            self.assertEqual(done.returncode, 1)
            self.assertIn(b'no independently reviewed actual guest proof', done.stderr)
            self.assertFalse(output.exists())
            for option in ('--trust', '--profile', '--source-revision', '--registry', '--sip'):
                with self.subTest(option=option):
                    done = subprocess.run(argv + [option, 'override'], capture_output=True, timeout=5)
                    self.assertEqual(done.returncode, 2)
                    self.assertFalse(output.exists())

if __name__ == '__main__':
    unittest.main()
