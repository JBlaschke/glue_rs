"""Focused v3 controls over independently encoded original physical records.

The unchanged v1 fixture owns its literal inventory/physical encoder. Reusing
those bytes and recipe evidence does not invoke a policy/producer normalizer.
No target, provider or native fixture runs.
"""
from dataclasses import FrozenInstanceError, fields, replace
import io
from pathlib import Path
import unittest
from unittest.mock import patch

import test_runtime_fd_policy as vectors
import runtime_fd_policy as policy

call, event, stream, physical = vectors.call, vectors.event, vectors.stream, vectors.physical
U64, NEW, OLD = vectors.U64, vectors.NEW, vectors.OLD


def query(primary=0, *, fd=5, argument=0, name='fcntl', tid=NEW, errno=0):
    return call(name, (fd, 3, argument), primary, tid, errno=errno)


def opened(fd=5):
    return call('open', (0x7000, 0, 0), fd)


def evaluate(rows=None, **kwargs):
    return policy.evaluate_runtime_fd_status_policy_raw(
        kwargs.pop('program', vectors.recipe_vectors.recipe._IMAGES.expected_images_program(vectors.TARGET)),
        kwargs.pop('probes', vectors.INVENTORY), kwargs.pop('errors', b''),
        kwargs.pop('event_lines', physical(stream() if rows is None else rows)),
        owner_pid=kwargs.pop('owner_pid', vectors.OWNER), target_pid=kwargs.pop('target_pid', vectors.TARGET),
        contract_bytes=kwargs.pop('contract_bytes', vectors.base.CONTRACT),
        launch_evidence=kwargs.pop('launch_evidence', vectors.evidence()), **kwargs)


def binding(result, fd):
    return next(row for row in result.final_bindings if row.fd == fd)


def state_shape(result):
    # Capture-local analysis keys include the ENTIRE raw capture hash, so adding
    # query bytes changes their spelling even before the query. Compare state
    # structure with stable local names, retaining every key-equality relation.
    keys = {}
    def local(key):
        if key is None:
            return None
        return keys.setdefault(key, 'capture-local-key-' + str(len(keys)))
    history = tuple(replace(t, binding_key=local(t.binding_key)) for t in result.transitions)
    states = tuple(replace(s, analysis_binding_key=local(s.analysis_binding_key))
                   for s in result.final_bindings)
    return history, states


class StatusQueryControls(unittest.TestCase):
    accounted = vectors.RuntimeFDPolicyControls.accounted
    no_authority = vectors.RuntimeFDPolicyControls.no_authority

    def test_twenty_one_literal_constructions_both_names_are_finite_query_only(self):
        golden = (
            (1, 0), (2, 1), (3, 2), (5, 4), (6, 5), (7, 6),
            (9, 8), (10, 9), (11, 10), (13, 12), (14, 13), (15, 14),
            (0x10002, 0x10001), (0x10003, 0x10002),
            (0x10006, 0x10005), (0x10007, 0x10006),
            (0x1000a, 0x10009), (0x1000b, 0x1000a),
            (0x1000e, 0x1000d), (0x1000f, 0x1000e), (0x40000000, 0x40000000),
        )
        before = evaluate(stream(opened()))
        for name in ('fcntl', 'fcntl_nocancel'):
            for flags, primary in golden:
                with self.subTest(name=name, flags=flags):
                    result = evaluate(stream(opened() + query(primary, name=name)))
                    command, = result.fcntl_attempts
                    attempt = result.attempts[command.attempt_index]
                    self.assertEqual((result.protocol, result.status),
                        ('darwin-runtime-fd-status-policy-v3', 'source-conditional-clean'))
                    self.assertIs(type(result), policy.RuntimeFdFcntlPolicy)
                    self.assertIsInstance(command.operation, policy._FGETFL.FgetflOperation)
                    self.assertEqual(command.operation.status, 'conditional-conversion')
                    preimages = command.operation.observation.algebraic_preimages
                    self.assertEqual([p.fileglob_flags_uint32 for p in preimages
                                      if p.source_feasibility == 'some-source-feasible-ordinary-subset'], [flags])
                    self.assertEqual(attempt.intent, 'descriptor-status-flag-query-attempt')
                    self.assertIsNone(attempt.flags_u32)
                    window = next(w for w in result.windows if w.attempt_index == command.attempt_index)
                    self.assertEqual((window.lookup_slots, window.mutation_slots,
                                      window.allocation, window.unknown_effects), ((5,), (), False, False))
                    self.assertEqual(state_shape(result), state_shape(before))
                    created, = [t for t in result.transitions if t.fd == 5]
                    self.assertEqual(binding(result, 5).analysis_binding_key, created.binding_key)
                    self.assertFalse(any(t.ordinal == attempt.return_ordinal for t in result.transitions))
                    self.no_authority(result)

    def test_full_signed64_ignored_argument_tail_and_original_pair_index_retained(self):
        rows = stream(opened() + query(0x10001, argument=U64, name='fcntl_nocancel'))
        entered = next(r for r in rows if r['kind'] == 2 and r['function'] == 'fcntl_nocancel')
        entered['args'] = (5, 3, U64, 0x1234, U64, 1 << 63, 7, 0xfeed)
        result = evaluate(rows)
        command, = result.fcntl_attempts
        operation = command.operation
        attempt = result.attempts[command.attempt_index]
        pair = result.recipe.images.pairs[operation.source_pair_index]
        self.assertIs(pair.entry, attempt.entry)
        self.assertEqual(operation.correlation_id, pair.correlation_id)
        self.assertNotEqual(command.attempt_index, operation.source_pair_index)
        self.assertEqual((command.request.argument, command.request.argument_role), (-1, 'ignored-by-command'))
        self.assertEqual(attempt.entry.raw_scalars[5:], entered['args'])
        self.assertEqual((operation.observation.primary_signed32, operation.observation.primary_uint32),
                         (65537, 65537))
        self.accounted(result)

    def test_event_only_alternatives_remain_unresolved_and_sticky_from_entry(self):
        result = evaluate(stream(opened() + query(0x8000) + opened(6) + call('dup', (6,), 7)))
        command, = result.fcntl_attempts
        operation = command.operation
        self.assertEqual(operation.status, 'unresolved-conversion')
        self.assertIsNone(operation.rule)
        self.assertEqual([(p.fileglob_flags_uint32, p.adjusted_flags_uint32, p.policy_condition)
                          for p in operation.observation.algebraic_preimages], [
            (0x8001, 0x8001, 'event-only; process-disallow-rw-clear'),
            (0x8001, 0x8001, 'event-only; process-disallow-rw-set'),
            (0x8000, 0x8001, 'event-only; process-disallow-rw-set'),
        ])
        self.assertEqual(operation.observation.event_only_process_policy, 'unobserved; no branch selected')
        attempt = result.attempts[command.attempt_index]
        horizon = [t for t in result.transitions if 'certainty retired from ENTRY' in t.reason]
        self.assertTrue(horizon)
        self.assertTrue(all(t.ordinal == attempt.entry_ordinal for t in horizon))
        self.assertEqual(result.status, 'incomplete')
        self.assertTrue(all(s.analysis_binding_key is None for s in result.final_bindings))

    def test_private_unknown_and_impossible_results_do_not_mask_into_permission(self):
        for primary in (0x10000, 0x20000, 0x1000, 0x200, 0x80, 0x400000,
                        0x40008000, 0x40000001, 0x3fffffff, U64):
            with self.subTest(primary=primary):
                result = evaluate(stream(opened() + query(primary) + opened(6)))
                command, = result.fcntl_attempts
                self.assertEqual(command.operation.status, 'unresolved-conversion')
                self.assertIsNone(command.operation.rule)
                self.assertIsNotNone(command.operation.observation)
                self.assertEqual(result.status, 'incomplete')
                self.assertTrue(all(s.analysis_binding_key is None for s in result.final_bindings))
                self.assertEqual(result.attempts[command.attempt_index].returned.raw_scalars[5], primary)

    def test_signed32_typing_secondary_fd_and_controlflow_never_repair(self):
        for primary in (0x80000000, 0xffffffff, 1 << 32, 1 << 63):
            result = evaluate(stream(opened() + query(primary)))
            command, = result.fcntl_attempts
            self.assertEqual(command.operation.status, 'unsupported')
            self.assertIsNone(command.operation.observation)
            self.assertTrue(all(s.analysis_binding_key is None for s in result.final_bindings))
        result = evaluate(stream(opened() + query(U64 - 0x7fffffff)))
        observed = result.fcntl_attempts[0].operation.observation
        self.assertEqual((observed.primary_signed32, observed.primary_uint32), (-0x80000000, 0x80000000))
        for error, word in ((U64, U64), (U64 - 1, 0)):
            body = query()
            body[1]['args'] = (word, word, word, error, error)
            result = evaluate(stream(opened() + body))
            self.assertEqual(result.fcntl_attempts[0].operation.status, 'unsupported')
            self.assertIsNone(result.fcntl_attempts[0].operation.observation)
            self.assertIsNone(binding(result, 5).analysis_binding_key)
        for mutate in ('secondary', 'fd', 'noncanonical-fd'):
            body = query()
            if mutate == 'secondary':
                body[1]['args'] = (0, 0, 1, 0, 0)
            else:
                body[0]['args'] = ((U64 if mutate == 'fd' else 0xffffffff), 3, 0, 0, 0, 0, 0, 0)
            result = evaluate(stream(opened() + body))
            self.assertIsNone(result.fcntl_attempts[0].operation.rule)
            self.assertIsNone(binding(result, 5).analysis_binding_key)

    def test_canonical_failed_query_has_gap_without_observation_or_state_revision(self):
        baseline = evaluate(stream(opened()))
        for name in ('fcntl', 'fcntl_nocancel'):
            for fd in (5, U64):
                with self.subTest(name=name, fd=fd):
                    result = evaluate(stream(opened() + query(fd=fd, argument=U64, name=name, errno=9)))
                    command, = result.fcntl_attempts
                    self.assertEqual(command.operation.status, 'kernel-error')
                    self.assertEqual(command.operation.outcome.kernel_error, 9)
                    self.assertIsNone(command.operation.observation)
                    self.assertIsNone(command.operation.rule)
                    self.assertTrue(any(g.code == 'failed-status-query' for g in result.gaps))
                    self.assertEqual(state_shape(result), state_shape(baseline))
                    window = next(w for w in result.windows if w.attempt_index == command.attempt_index)
                    self.assertFalse(window.unknown_effects)
                    self.assertEqual(result.status, 'incomplete')

    def test_known_absence_guard_remains_and_does_not_create_present_binding(self):
        result = evaluate(stream(opened() + call('close', (5,), 0) + query()))
        self.assertTrue(any(g.code == 'inconsistent-present-lookup' for g in result.gaps))
        self.assertEqual(binding(result, 5).state, 'unknown')
        self.assertIsNone(binding(result, 5).analysis_binding_key)
        self.assertIsNone(binding(result, 5).cloexec)
        self.assertEqual(result.fcntl_attempts[0].operation.status, 'conditional-conversion')
        self.assertEqual(result.status, 'incomplete')

    def test_touching_and_overlapping_query_mutation_windows_preserve_conflicts(self):
        for name, args in (('close', (5,)), ('fcntl_nocancel', (5, 2, 1)), ('dup2', (6, 5))):
            a, b = query()
            c, d = call(name, args, 5 if name == 'dup2' else 0, 303)
            body = opened() + opened(6) + [event(9, tid=NEW, detail=303), event(10, tid=303),
                                           a, c, d, b, event(11, tid=303)]
            result = evaluate(stream(body))
            command = next(r for r in result.fcntl_attempts if r.request.command == 3)
            self.assertTrue(any(5 in conflict.slots for conflict in result.conflicts))
            self.assertEqual(result.status, 'incomplete')
            self.assertFalse(any(t.ordinal == result.attempts[command.attempt_index].return_ordinal
                                 for t in result.transitions))
        a, b = query()
        c, d = call('fcntl_nocancel', (5, 2, 1), 0, 303)
        rows = stream(opened() + [event(9, tid=NEW, detail=303), event(10, tid=303),
                                  a, b, c, d, event(11, tid=303)])
        returned_index = next(i for i, r in enumerate(rows) if r['kind'] == 3 and r['function'] == 'fcntl')
        rows[returned_index + 1]['timestamp'] = 100 + returned_index + 1
        self.assertTrue(evaluate(rows).conflicts)

    def test_prior_opaque_horizon_and_alias_setfl_are_not_repaired_by_query(self):
        for command in (4, 999):
            body = opened() + call('dup', (5,), 6) + call('fcntl', (5, command, 0), errno=5)
            before = evaluate(stream(body))
            after = evaluate(stream(body + query(fd=6)))
            self.assertEqual(after.fcntl_attempts[-1].operation.status, 'conditional-conversion')
            self.assertEqual(state_shape(after), state_shape(before))
            self.assertTrue(all(s.analysis_binding_key is None for s in after.final_bindings))
            self.assertEqual(after.status, 'incomplete')
            if command == 4:
                self.assertIn('driver ioctl failure or partial rollback',
                    ' '.join(after.fcntl_attempts[0].operation.effect_uncertainties))

    def test_later_exec_retires_state_and_query_never_revives_ready_outputs(self):
        tid = 1002
        body = opened() + query() + [
            event(2, 'execve', NEW, args=(0x8000, 0x9000, 0xa000, 0, 0, 0, 0, 0)),
            event(9, tid=NEW, detail=tid), event(11, tid=NEW),
            event(18, tid=NEW, detail=vectors.TARGET, args=(0, 0x220000, 0x20)),
            event(7, tid=tid), event(5, tid=tid), event(10, tid=tid),
        ]
        before = evaluate(stream(body, terminal_tid=tid))
        after = evaluate(stream(body + query(fd=5, tid=tid) + query(fd=1, tid=tid), terminal_tid=tid))
        self.assertEqual(len(after.recipe.images.transitions), 2)
        self.assertEqual(state_shape(after), state_shape(before))
        self.assertIsNone(binding(after, 5).analysis_binding_key)
        self.assertIsNone(binding(after, 1).analysis_binding_key)
        self.no_authority(after)
        written = evaluate(stream(body + query(fd=1, tid=tid) +
                                  call('write', (1, 0x7000, 1), 1, tid), terminal_tid=tid))
        self.assertTrue(any(g.code == 'unresolved-output-binding' for g in written.gaps))
        self.no_authority(written)

    def test_bootstrap_and_whole_mach_failure_project_request_only(self):
        rows = stream(query())
        rows[2:2] = query(0x01000004, fd=vectors.GATE, argument=U64, tid=OLD)
        result = evaluate(rows)
        bootstrap = next(r for r in result.fcntl_attempts
                         if result.attempts[r.attempt_index].context == 'bootstrap')
        self.assertEqual((bootstrap.request.command_name, bootstrap.request.operation,
                          bootstrap.request.argument), ('F_GETFL', 'query-status-flags', -1))
        self.assertIsNone(bootstrap.operation)
        body = query(argument=U64) + [event(15, 'write', NEW, args=(0,) * 8),
                                     event(16, 'write', NEW, args=(0,))]
        result = evaluate(stream(body))
        command, = result.fcntl_attempts
        self.assertEqual((command.request.command_name, command.request.argument), ('F_GETFL', -1))
        self.assertIsNone(command.operation)
        self.assertIsNone(result.attempts[command.attempt_index].outcome)
        self.assertEqual((result.windows, result.transitions, result.final_bindings), ((), (), ()))
        self.assertTrue(any(a.intent == 'opaque-mach-attempt' for a in result.attempts))
        self.accounted(result)

    def test_v1_v2_scopes_and_classes_remain_exact_and_four_scalar_rows_stay_legacy(self):
        rows = stream(opened() + query())
        old = vectors.evaluate(rows)
        newer = policy.evaluate_runtime_fd_fcntl_policy_raw(
            vectors.recipe_vectors.recipe._IMAGES.expected_images_program(vectors.TARGET),
            vectors.INVENTORY, b'', physical(rows), owner_pid=vectors.OWNER,
            target_pid=vectors.TARGET, contract_bytes=vectors.base.CONTRACT,
            launch_evidence=vectors.evidence())
        self.assertIs(type(old), policy.RuntimeFdPolicy)
        self.assertIs(type(newer), policy.RuntimeFdFcntlPolicy)
        self.assertEqual((old.protocol, newer.protocol),
                         ('darwin-runtime-fd-policy-v1', 'darwin-runtime-fd-fcntl-policy-v2'))
        self.assertNotIn('fcntl_attempts', old.to_dict())
        self.assertEqual(newer.fcntl_attempts[0].operation.status, 'unsupported')
        self.assertIsNone(newer.fcntl_attempts[0].request.operation)
        self.assertEqual((old.status, newer.status), ('incomplete', 'incomplete'))
        self.assertEqual([f.name for f in fields(policy.RuntimeFdFcntlPolicy)],
                         [f.name for f in fields(policy.RuntimeFdPolicy)] + ['fcntl_attempts'])
        self.assertEqual(len(policy.HANDLED_RUNTIME_NAMES), 15)
        for command, argument, primary in ((0, 6, 6), (1, U64, 0), (2, U64, 0), (67, 6, 6)):
            value = evaluate(stream(opened() + call('fcntl', (5, command, argument), primary)))
            self.assertIsInstance(value.fcntl_attempts[0].operation, policy._FCNTL.FcntlOperation)
            self.assertEqual(value.fcntl_attempts[0].operation.status, 'source-consistent')

    def test_single_recipe_original_stream_and_private_associated_pair_only(self):
        raw = physical(stream(opened() + query(0x10001)))
        class Once:
            calls = 0
            def __iter__(self):
                self.calls += 1
                if self.calls != 1:
                    raise AssertionError('raw replay')
                yield from raw
        original, seen = Once(), []
        decoder = policy._FGETFL._decode_operation
        def checked(index, pair, calls, types):
            seen.append((index, pair))
            return decoder(index, pair, calls, types)
        with patch.object(policy._RECIPE, 'pair_runtime_recipe_raw', wraps=policy._RECIPE.pair_runtime_recipe_raw) as recipe, \
             patch.object(policy._FGETFL, '_decode_operation', side_effect=checked), \
             patch.object(policy._FGETFL, 'decode_owned_fgetfl_semantics', side_effect=AssertionError('public reparse')), \
             patch.object(policy._FCNTL, 'decode_owned_fcntl_semantics', side_effect=AssertionError('public reparse')), \
             patch.object(policy._FGETFL._SCALAR._RAW, 'pair_raw_owned', side_effect=AssertionError('second raw pairing')):
            result = evaluate(event_lines=original)
        self.assertEqual((recipe.call_count, original.calls, len(seen)), (1, 1, 1))
        for index, pair in seen:
            self.assertIs(pair, result.recipe.images.pairs[index])
        self.accounted(result)

    def test_late_physical_and_iterator_faults_cannot_return_decoded_prefix(self):
        raw = physical(stream(opened() + query()))
        def broken():
            yield from raw
            raise RuntimeError('late original-byte fault')
        with patch.object(policy._FGETFL, '_decode_operation', side_effect=AssertionError('semantic prefix')):
            with self.assertRaisesRegex(RuntimeError, 'original-byte fault'):
                evaluate(event_lines=broken())
            with self.assertRaises(ValueError):
                evaluate(event_lines=raw + [b'{broken\n'])
            with self.assertRaises(ValueError):
                evaluate(event_lines=raw[:-1])

    def test_immutable_detached_result_has_no_late_io_or_caller_authority_inputs(self):
        raw = physical(stream(query(0x40000000, fd=1)))
        evidence = vectors.evidence()
        with patch('builtins.open', side_effect=AssertionError('late open')), \
             patch.object(Path, 'read_bytes', side_effect=AssertionError('late bytes')):
            result = evaluate(event_lines=raw, launch_evidence=evidence)
        with self.assertRaises(FrozenInstanceError):
            result.fcntl_attempts[0].operation.observation.primary_uint32 = 0
        plain = result.to_dict()
        plain['fcntl_attempts'][0]['operation']['observation']['algebraic_preimages'].clear()
        self.assertEqual(len(result.fcntl_attempts[0].operation.observation.algebraic_preimages), 4)
        self.assertIsNone(binding(result, 1).analysis_binding_key)
        self.no_authority(result)
        for name, value in (('profile', 'v3'), ('status_queries', True), ('capture', {}),
                            ('process_policy', False), ('constants', {'F_GETFL': 3}),
                            ('native_admission', True)):
            with self.assertRaises(TypeError):
                evaluate(**{name: value})

    def test_new_helper_identity_is_checked_before_any_helper_import(self):
        original_open = Path.open
        spec = policy.importlib.util.spec_from_file_location('_status_identity_control', policy.__file__)
        fresh = policy.importlib.util.module_from_spec(spec)
        def corrupted(path, *args, **kwargs):
            if str(path).endswith('bsd-fgetfl-semantics/bsd_fgetfl_semantics.py'):
                return io.BytesIO(b'altered helper source')
            return original_open(path, *args, **kwargs)
        with patch.object(Path, 'open', corrupted), \
             patch.object(policy.importlib.util, 'module_from_spec', side_effect=AssertionError('helper import')):
            with self.assertRaisesRegex(ValueError, 'fixed helper identity'):
                spec.loader.exec_module(fresh)


if __name__ == '__main__':
    unittest.main()
