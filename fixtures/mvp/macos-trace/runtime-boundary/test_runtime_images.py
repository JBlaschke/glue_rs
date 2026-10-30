"""Physical v2 image/thread controls; no provider, target or native admission."""
import copy
from dataclasses import FrozenInstanceError, replace
from pathlib import Path
import shutil
import subprocess
import tempfile
import unittest
from unittest.mock import patch

import runtime_images as images
import test_runtime_boundary as fixture

OWNER, TARGET, OLD, NEW = fixture.OWNER, fixture.TARGET, fixture.OLD, fixture.NEW
S, call = fixture.spec, fixture.call


def evidence():
    value = fixture.launch()
    return images.LaunchEvidence(value.request, value.catalog, value.ready, value.go,
                                 value.exec_attempt, value.target_artifact)


def chain(count=2):
    data = fixture.happy()
    end = next(i for i, row in enumerate(data) if row['kind'] == 2 and row['function'] == 'exit')
    data = data[:end]
    current = NEW
    for epoch in range(2, count + 1):
        new = 1000 + epoch
        data += [S(2, 'execve', current, args=(0x3000 + epoch, 0x4000, 0x5000, 0, 0, 0, 0, 0)),
                 S(9, tid=current, detail=new), S(11, tid=current),
                 S(18, tid=current, detail=TARGET, args=(0, 0x200000 + epoch, 0x20)),
                 S(7, tid=new), S(5, tid=new), S(10, tid=new)]
        data += call('write', (1, 0x6000, 4), 4, new)
        current = new
    return data + [S(2, 'exit', current, args=(0,) * 8), S(6, tid=current, detail=1),
                   S(11, tid=current), S(18, tid=current, detail=TARGET,
                                        args=(0, 0x300000, 0x100)), S(17)]


def paired(data=None, **kwargs):
    return images.pair_runtime_images_raw(kwargs.pop('program', images.expected_images_program(TARGET)),
        kwargs.pop('probes', fixture.INVENTORY), kwargs.pop('errors', b''),
        kwargs.pop('event_lines', fixture.lines(chain() if data is None else data)),
        owner_pid=OWNER, target_pid=TARGET, contract_bytes=kwargs.pop('contract_bytes', fixture.CONTRACT),
        launch_evidence=kwargs.pop('launch_evidence', evidence()), **kwargs)


def ordinary_thread(tid=303, creator=NEW):
    return [S(9, tid=creator, detail=tid), S(10, tid=tid)] + \
        call('write', (2, 0x8000, 1), 1, tid) + [S(11, tid=tid)]


class RuntimeImagesControls(unittest.TestCase):
    def refuse(self, data=None, pattern='.', **kwargs):
        with self.assertRaisesRegex(images.RawValidationError, pattern) as caught:
            paired(data, **kwargs)
        return caught.exception

    def test_multiple_images_bind_original_entries_and_distinct_thread_instances(self):
        data = chain(3)
        result = paired(data)
        self.assertEqual(result.protocol, 'darwin-runtime-images-pairs-v2')
        self.assertEqual(result.source.raw.events, len(data))
        self.assertEqual([t.new_image_epoch for t in result.transitions], [1, 2, 3])
        self.assertEqual([t.old_image_epoch for t in result.transitions], [0, 1, 2])
        self.assertEqual([t.tid for t in result.threads], [OLD, NEW, 1002, 1003])
        self.assertEqual([p.image_epoch for p in result.pairs], [0, 0, 0, 0, 1, 1, 2, 3])
        self.assertTrue(all(t.entry.function == 'execve' and not t.successful_return_invented
                            for t in result.transitions))
        self.assertFalse(any(p.entry.function == 'execve' for p in result.pairs))
        self.assertFalse(result.native_calibration or result.state_feed_eligible or result.full_trace_acceptance)
        self.assertFalse(result.output_capabilities_seeded or result.protected_target_attested)

    def test_later_images_never_reuse_the_initial_artifact_or_requested_path(self):
        result = paired(chain(4))
        initial = result.transitions[0]
        self.assertEqual(initial.requested_path, result.launch.executable)
        self.assertEqual(initial.artifact_sha256, result.launch.target_sha256)
        self.assertFalse(initial.pathname_observed or initial.native_identity_attested)
        for transition in result.transitions[1:]:
            self.assertIsNone(transition.requested_path)
            self.assertIsNone(transition.artifact_sha256)
            self.assertEqual(transition.identity_basis, 'opaque-execve-pointer-words-only')
            self.assertFalse(transition.pathname_observed or transition.native_identity_attested)

    def test_one_and_exact_maximum_image_chains(self):
        self.assertEqual(len(paired(chain(1)).transitions), 1)
        self.assertEqual(len(paired(chain(16)).transitions), 16)
        error = self.refuse(chain(17), 'exec bound')
        self.assertEqual(error.capture.raw.events, len(chain(17)))

    def test_v1_and_v2_programs_refuse_each_other_without_a_fallback(self):
        self.refuse(program=fixture.boundary.expected_program(TARGET), pattern='fixed runtime')
        with self.assertRaisesRegex(fixture.boundary.RawValidationError, 'fixed runtime'):
            fixture.paired(program=images.expected_images_program(TARGET))
        with self.assertRaises(fixture.boundary.RawValidationError):
            fixture.paired(chain(2))

    def test_unknown_runtime_calls_remain_raw_not_harmless_classifications(self):
        data = chain(2)
        at = next(i for i, r in enumerate(data) if r['kind'] == 2 and r['tid'] == NEW)
        data[at:at] = call('mystery', (1, 2, 3), 0, NEW)
        result = paired(data)
        unknown = next(p for p in result.pairs if p.entry.function == 'mystery')
        self.assertFalse(unknown.entry.source_contract_known)
        self.assertIsNotNone(unknown.entry.unsupported_reason)

    def test_ordinary_thread_instances_have_declaration_start_retirement(self):
        data = chain(2)
        at = next(i for i, r in enumerate(data) if r['kind'] == 2 and r['tid'] == NEW)
        data[at:at] = ordinary_thread()
        result = paired(data)
        thread = next(t for t in result.threads if t.tid == 303)
        self.assertEqual((thread.generation, thread.image_epoch, thread.origin), (1, 1, 'lwp-declared'))
        self.assertTrue(thread.declaration.ordinal < thread.start.ordinal < thread.retirement.ordinal)
        self.assertEqual(thread.end_reason, 'lwp-exit-observed')
        self.assertFalse(thread.kernel_generation_attested)
        birth = next(b for b in result.lifecycle_bindings if b.role == 'ordinary-lwp-declaration')
        self.assertEqual(birth.thread_instance, thread.capture_instance)
        self.assertEqual(result.threads[birth.source_actor_instance].tid, NEW)
        self.assertEqual(thread.declaration.raw_scalars[3], NEW)
        pair = next(p for p in result.pairs if p.entry.raw_scalars[3] == 303)
        self.assertEqual(pair.thread_instance, thread.capture_instance)

    def test_observed_retirement_allows_explicit_new_capture_generation(self):
        data = chain(2)
        at = next(i for i, r in enumerate(data) if r['kind'] == 2 and r['tid'] == NEW)
        data[at:at] = ordinary_thread() + ordinary_thread()
        result = paired(data)
        reused = [t for t in result.threads if t.tid == 303]
        self.assertEqual([t.generation for t in reused], [1, 2])
        self.assertNotEqual(reused[0].capture_instance, reused[1].capture_instance)
        self.assertLess(reused[0].retirement.ordinal, reused[1].declaration.ordinal)
        pairs = [p for p in result.pairs if p.entry.raw_scalars[3] == 303]
        self.assertEqual([p.thread_instance for p in pairs], [t.capture_instance for t in reused])

    def test_reuse_without_observed_retirement_and_duplicate_start_exit_refuse(self):
        data = chain(2)
        at = next(i for i, r in enumerate(data) if r['kind'] == 2 and r['tid'] == NEW)
        for extra in ([S(9, tid=NEW, detail=303), S(10, tid=303), S(9, tid=NEW, detail=303)],
                      ordinary_thread() + [S(11, tid=303)],
                      [S(9, tid=NEW, detail=303), S(10, tid=303), S(10, tid=303)]):
            changed = copy.deepcopy(data)
            changed[at:at] = extra
            self.refuse(changed)

    def test_active_reserved_and_pending_other_actors_block_exec(self):
        data = chain(2)
        at = next(i for i, r in enumerate(data) if r['kind'] == 2 and r['function'] == 'execve' and r['tid'] == NEW)
        for extra in ([S(9, tid=NEW, detail=303)],
                      [S(9, tid=NEW, detail=303), S(10, tid=303)],
                      [S(9, tid=NEW, detail=303), S(10, tid=303), S(2, 'read', 303, args=(0,) * 8)]):
            changed = copy.deepcopy(data)
            changed[at:at] = extra
            self.refuse(changed, 'nonquiescent')
        changed = copy.deepcopy(data)
        changed[at:at] = [S(2, 'read', NEW, args=(0,) * 8)]
        self.refuse(changed, 'overlapping entry')

    def test_activity_and_second_exec_during_transition_refuse(self):
        data = chain(2)
        at = next(i for i, r in enumerate(data) if r['kind'] == 2 and r['function'] == 'execve' and r['tid'] == NEW)
        for name in ('write', 'execve'):
            changed = copy.deepcopy(data)
            changed.insert(at + 1, S(2, name, NEW, args=(1,) * 8))
            self.refuse(changed, 'overlapping/concurrent')

    def test_initial_declaration_must_resolve_without_losing_reserved_actor(self):
        data = chain(2)
        at = next(i for i, r in enumerate(data) if r['kind'] == 2 and r['function'] == 'execve')
        data.insert(at + 1, S(9, detail=999))
        error = self.refuse(data, 'unresolved initial exec thread declaration')
        self.assertEqual(error.capture.raw.events, len(data))
        data[at + 1]['detail'] = NEW
        result = paired(data)
        self.assertEqual(result.threads[1].declaration.raw_scalars[4], NEW)
        self.assertEqual(len(result.transitions), 2)

    def test_new_exec_actor_must_match_declaration_and_start_sequence(self):
        data = chain(2)
        at = next(i for i, r in enumerate(data) if r['kind'] == 9)
        data[at]['detail'] = 999
        self.refuse(data, 'declared new actor')
        for omitted in (5, 10):
            data = chain(2)
            at = next(i for i, r in enumerate(data) if r['kind'] == omitted and r['tid'] == 1002)
            del data[at]
            self.refuse(data, 'must precede')
        data = chain(2)
        for r in data:
            if r['kind'] in (7, 5, 10) and r['tid'] == 1002:
                r['tid'] = NEW
        self.refuse(data, 'identity/pending')

    def test_new_image_can_reuse_only_a_tid_with_an_observed_old_exit(self):
        data = chain(2)
        for r in data:
            if r['kind'] == 9 and r['detail'] == 1002:
                r['detail'] = OLD
            if r['tid'] == 1002:
                r['tid'] = OLD
        result = paired(data)
        reused = [t for t in result.threads if t.tid == OLD]
        self.assertEqual([t.generation for t in reused], [1, 2])
        # Remove specifically the initial old-thread exit, preserving final exit.
        data = chain(2)
        data = [r for r in data if not (r['kind'] == 11 and r['tid'] == OLD)]
        for r in data:
            if r['kind'] == 9 and r['detail'] == 1002:
                r['detail'] = OLD
            if r['tid'] == 1002:
                r['tid'] = OLD
        self.refuse(data, 'before observed retirement')

    def test_old_image_replacement_does_not_invent_a_kernel_thread_exit(self):
        data = [r for r in chain(2) if not (r['kind'] == 11 and r['tid'] in (OLD, NEW))]
        result = paired(data)
        for thread in result.threads[:-1]:
            self.assertIsNone(thread.retirement)
            self.assertIsNotNone(thread.image_replaced_at)
            self.assertEqual(thread.end_reason, 'image-replaced')

    def test_late_ejustreturn_is_retained_only_for_its_original_transition(self):
        data = [r for r in chain(2) if not (r['kind'] == 11 and r['tid'] == OLD)]
        at = next(i for i, r in enumerate(data) if r['kind'] == 2 and r['tid'] == NEW)
        data.insert(at, S(3, 'execve', OLD, args=(0, 0, 0, (1 << 64) - 2, (1 << 64) - 2)))
        data.insert(at + 1, S(11, tid=OLD))
        result = paired(data)
        self.assertEqual(result.transitions[0].returned.raw_scalars[3], OLD)
        self.assertFalse(any(p.entry.function == 'execve' for p in result.pairs))
        self.assertEqual(result.transitions[0].new_thread_instance, 1)

    def test_initial_late_return_can_interleave_each_real_startup_boundary(self):
        for preceding in (7, 5):
            data = [r for r in chain(1) if not (r['kind'] == 11 and r['tid'] == OLD)]
            at = next(i for i, r in enumerate(data) if r['kind'] == preceding)
            data.insert(at + 1, S(3, 'execve', OLD, args=(0, 0, 0, (1 << 64) - 2, (1 << 64) - 2)))
            result = paired(data)
            self.assertIsNotNone(result.transitions[0].returned)
            self.assertFalse(result.transitions[0].successful_return_invented)

    def test_prior_image_late_projection_never_resurrects_a_live_actor(self):
        data = [r for r in chain(3) if not (r['kind'] == 11 and r['tid'] == OLD)]
        at = next(i for i, r in enumerate(data) if r['kind'] == 2 and r['function'] == 'exit')
        data[at:at] = [S(3, 'execve', OLD, args=(0, 0, 0, (1 << 64) - 2, (1 << 64) - 2)), S(11, tid=OLD)]
        result = paired(data)
        self.assertEqual(len(result.transitions), 3)
        self.assertEqual(result.transitions[0].returned.raw_scalars[3], OLD)
        self.assertEqual(result.threads[0].image_epoch, 0)
        self.assertEqual(result.threads[0].end_reason, 'image-replaced')
        self.assertFalse(any(p.thread_instance == 0 and p.image_epoch > 0 for p in result.pairs))

    def test_older_replaced_thread_exit_can_interleave_later_image_startup(self):
        data = [r for r in chain(3) if not (r['kind'] == 11 and r['tid'] == OLD)]
        at = next(i for i, r in enumerate(data) if r['kind'] == 7 and r['tid'] == 1002)
        data.insert(at + 1, S(11, tid=OLD))
        result = paired(data)
        self.assertEqual(len(result.transitions), 3)
        self.assertLess(result.transitions[1].success.ordinal, result.threads[0].retirement.ordinal)
        self.assertLess(result.threads[0].retirement.ordinal, result.transitions[1].proc_start.ordinal)
        self.assertEqual(result.threads[0].image_epoch, 0)
        changed = [r for r in chain(3) if not (r['kind'] == 11 and r['tid'] == OLD)]
        at = next(i for i, r in enumerate(changed) if r['kind'] == 7 and r['tid'] == 1002)
        changed.insert(at + 1, S(11, tid=1002))
        self.refuse(changed, 'must precede')

    def test_later_canonical_pre_success_return_remains_a_transition(self):
        data = chain(2)
        at = next(i for i, r in enumerate(data) if r['kind'] == 2 and r['function'] == 'execve' and r['tid'] == NEW)
        data.insert(at + 1, S(3, 'execve', NEW, args=(0, 0, 0, (1 << 64) - 2, (1 << 64) - 2)))
        result = paired(data)
        self.assertIsNotNone(result.transitions[1].returned)
        self.assertFalse(any(p.entry.function == 'execve' for p in result.pairs))

    def test_late_later_image_return_and_old_exit_can_interleave_startup(self):
        data = chain(2)
        data = [r for r in data if not (r['kind'] == 11 and r['tid'] == NEW)]
        at = next(i for i, r in enumerate(data) if r['kind'] == 7 and r['tid'] == 1002)
        data.insert(at + 1, S(3, 'execve', NEW, args=(0, 0, 0, (1 << 64) - 2, (1 << 64) - 2)))
        data.insert(at + 2, S(11, tid=NEW))
        result = paired(data)
        self.assertIsNotNone(result.transitions[1].returned)
        self.assertLess(result.transitions[1].returned.ordinal, result.transitions[1].proc_start.ordinal)

    def test_duplicate_noncanonical_or_after_retirement_exec_return_refuses(self):
        data = [r for r in chain(2) if not (r['kind'] == 11 and r['tid'] == OLD)]
        at = next(i for i, r in enumerate(data) if r['kind'] == 2 and r['tid'] == NEW)
        projection = S(3, 'execve', OLD, args=(0, 0, 0, (1 << 64) - 2, (1 << 64) - 2))
        changed = copy.deepcopy(data); changed[at:at] = [projection, copy.deepcopy(projection)]
        self.refuse(changed, 'duplicate/noncanonical')
        changed = copy.deepcopy(data); changed[at:at] = [S(11, tid=OLD), projection]
        self.refuse(changed, 'after retirement')
        changed = copy.deepcopy(data); projection = copy.deepcopy(projection)
        projection['args'] = (0, 0, 0, 0, 0); changed.insert(at, projection)
        self.refuse(changed, 'noncanonical')

    def test_shadows_are_unbound_nonlive_context_even_across_later_images(self):
        data = chain(3)
        shadow = [r for r in data if r['kind'] == 18 and r['args'][-1] & 0x20]
        data = [r for r in data if r not in shadow]
        at = next(i for i, r in enumerate(data) if r['kind'] == 2 and r['function'] == 'exit')
        data[at:at] = list(reversed(shadow))
        result = paired(data)
        self.assertEqual(len(result.transitions), 3)
        self.assertEqual(len(result.unbound_shadows), 3)
        self.assertTrue(result.unresolved_shadow_attribution)
        for context in result.unbound_shadows:
            self.assertIsNone(context.image_epoch)
            self.assertIsNone(context.thread_instance)
            self.assertFalse(context.live_pid_terminal or context.image_attribution_resolved)
            self.assertFalse(context.filesystem_effects_interpreted)
        self.assertFalse(result.state_feed_eligible or result.full_trace_acceptance)

    def test_shadow_absence_and_bound_never_manufacture_image_lifetimes(self):
        data = [r for r in chain(3) if not (r['kind'] == 18 and r['args'][-1] & 0x20)]
        result = paired(data)
        self.assertEqual(len(result.transitions), 3)
        self.assertEqual(result.unbound_shadows, ())
        self.assertFalse(result.unresolved_shadow_attribution or result.state_feed_eligible)
        with patch.object(images, 'MAX_SHADOW_CONTEXT', 1):
            self.refuse(chain(2), 'shadow context bound')

    def test_nonshadow_terminal_does_not_become_ignored_context(self):
        data = chain(2)
        at = next(i for i, r in enumerate(data) if r['kind'] == 18)
        data[at]['args'] = (0, 0x123456, 0x100)
        self.refuse(data)

    def test_nonreturning_process_exit_keeps_entry_without_successful_call(self):
        result = paired(chain(3))
        terminal = result.terminating_call
        self.assertEqual(terminal.image_epoch, 3)
        self.assertEqual(terminal.entry.function, 'exit')
        self.assertEqual(terminal.entry.raw_scalars[3], terminal.exit_context.raw_scalars[3])
        self.assertFalse(terminal.successful_return_invented)
        self.assertFalse(any(p.entry.function == 'exit' for p in result.pairs))

    def test_process_exit_retires_only_observed_thread_lifetimes(self):
        data = chain(1)
        at = next(i for i, r in enumerate(data) if r['kind'] == 2 and r['tid'] == NEW)
        data[at:at] = [S(9, tid=NEW, detail=303), S(10, tid=303)]
        at = next(i for i, r in enumerate(data) if r['kind'] == 6)
        data.insert(at + 1, S(11, tid=303))
        result = paired(data)
        worker = next(t for t in result.threads if t.tid == 303)
        self.assertGreater(worker.retirement.ordinal, result.terminating_call.exit_context.ordinal)
        self.assertEqual(worker.end_reason, 'lwp-exit-observed')
        self.assertFalse(result.terminating_call.successful_return_invented)

    def test_unmodeled_pending_thread_exit_and_process_exit_refuse(self):
        data = chain(2)
        at = next(i for i, r in enumerate(data) if r['kind'] == 2 and r['tid'] == NEW)
        data[at:at] = [S(9, tid=NEW, detail=303), S(10, tid=303),
                       S(2, 'mystery', 303, args=(0,) * 8), S(11, tid=303)]
        self.refuse(data, 'unmodeled pending call')
        data = chain(2)
        at = next(i for i, r in enumerate(data) if r['kind'] == 2 and r['function'] == 'exit')
        data[at]['function'] = 'write'
        self.refuse(data, 'unresolved ordinary call')

    def test_unretired_or_unstarted_thread_cannot_finish_a_capture(self):
        for extra in ([S(9, tid=NEW, detail=303)], [S(9, tid=NEW, detail=303), S(10, tid=303)]):
            data = chain(1)
            at = next(i for i, r in enumerate(data) if r['kind'] == 2 and r['tid'] == NEW)
            data[at:at] = extra
            self.refuse(data, 'thread lifetime')
        with patch.object(images, 'MAX_THREAD_INSTANCES', 2):
            data = chain(1)
            at = next(i for i, r in enumerate(data) if r['kind'] == 2 and r['tid'] == NEW)
            data[at:at] = ordinary_thread()
            self.refuse(data, 'instance bound')

    def test_late_unsupported_effects_fail_the_whole_validated_stream(self):
        for entry in ('fork', 'posix_spawn', '__mac_execve', 'sendmsg', 'recvmsg'):
            data = chain(3)
            at = next(i for i, r in enumerate(data) if r['kind'] == 2 and r['function'] == 'exit')
            data[at:at] = call(entry, (), 0, 1003)
            error = self.refuse(data, 'unsupported syscall')
            self.assertEqual(error.capture.raw.events, len(data))
        for extra in ([S(4, detail=9999)], [S(12)], [S(13, detail=2)],
                      [S(15, tid=1003, args=(0,) * 8), S(16, tid=1003, args=(0,))], [S(8, tid=1003, detail=2)]):
            data = chain(3)
            at = next(i for i, r in enumerate(data) if r['kind'] == 2 and r['function'] == 'exit')
            data[at:at] = extra
            self.assertEqual(self.refuse(data).capture.raw.events, len(data))

    def test_late_transport_and_iterator_failure_cannot_return_an_earlier_image(self):
        physical = fixture.lines(chain(3))
        self.refuse(event_lines=physical + [b'{}\n'])
        self.refuse(event_lines=physical[:-1], pattern='incomplete')
        self.refuse(errors=b'{"drop":1}\n', pattern='nonempty errors')
        data = chain(3)
        at = next(i for i, r in enumerate(data) if r['kind'] == 2 and r['function'] == 'exit')
        data[at:at] = call('fork', (), 0, 1003)
        physical = fixture.lines(data); physical[-1] = b'{broken}\n'
        self.assertFalse(hasattr(self.refuse(event_lines=physical), 'capture'))
        def broken():
            yield from fixture.lines(chain(2))
            raise RuntimeError('late iterator error')
        with self.assertRaisesRegex(RuntimeError, 'late iterator error'):
            paired(event_lines=broken())

    def test_single_physical_consumption_and_no_asset_io_after_import(self):
        class Once:
            count = 0
            def __iter__(self):
                self.count += 1
                if self.count != 1: raise AssertionError('second physical consumption')
                yield from fixture.lines(chain(3))
        source = Once()
        with patch('builtins.open', side_effect=AssertionError('unexpected file IO')), \
             patch.object(Path, 'open', side_effect=AssertionError('unexpected asset IO')):
            self.assertEqual(len(paired(event_lines=source).transitions), 3)
        self.assertEqual(source.count, 1)

    def test_same_timestamp_lifecycle_and_orphan_return_refuse(self):
        physical = fixture.lines(chain(2))
        import json, struct
        at = next(i for i, r in enumerate(chain(2)) if r['kind'] == 9)
        record = json.loads(physical[at]); record['timestamp'] -= 1
        record['records'][1]['hex'] = struct.pack('<Q', record['timestamp']).hex()
        physical[at] = json.dumps(record, separators=(',', ':')).encode() + b'\n'
        self.refuse(event_lines=physical, pattern='timestamp')
        data = chain(2)
        at = next(i for i, r in enumerate(data) if r['kind'] == 2 and r['function'] == 'exit')
        data.insert(at, S(3, 'read', 1002, args=(1, 1, 0, 0, 0)))
        self.refuse(data, 'orphan return')

    def test_immutable_thread_generations_and_fresh_serialization(self):
        result = paired(chain(3))
        with self.assertRaises(FrozenInstanceError): result.full_trace_acceptance = True
        with self.assertRaises(FrozenInstanceError): result.threads[0].generation = 999
        serial = result.to_dict(); serial['threads'].clear(); serial['transitions'][1]['artifact_sha256'] = 'fake'
        self.assertEqual(len(result.to_dict()['threads']), 4)
        self.assertIsNone(result.transitions[1].artifact_sha256)

    def test_actual_c_v2_producer_matches_independent_template_and_preserves_v1(self):
        here = Path(__file__).resolve().parent
        compiler = shutil.which('cc'); self.assertIsNotNone(compiler)
        with tempfile.TemporaryDirectory(prefix='glue-images-program-') as temp:
            source, binary = Path(temp) / 'producer.c', Path(temp) / 'producer'
            source.write_text('#include "runtime_trace_program.h"\n#include <stdio.h>\n#include <stdlib.h>\nint main(int n,char **v){char out[RT_PROGRAM_CAPACITY];size_t used;if(n!=3)return 1;int result=v[1][0]==\'1\'?rt_program((uint32_t)strtoul(v[2],NULL,10),out,&used):rt_images_program((uint32_t)strtoul(v[2],NULL,10),out,&used);if(result)return 2;return fwrite(out,1,used,stdout)==used?0:3;}\n')
            subprocess.run([compiler, '-std=c11', '-Wall', '-Wextra', '-Werror', '-pedantic', '-I', str(here),
                            str(source), str(here / 'runtime_trace_program.c'), '-o', str(binary)], check=True)
            for pid in (1, TARGET, (1 << 31) - 1):
                actual = subprocess.run([str(binary), '2', str(pid)], check=True, stdout=subprocess.PIPE).stdout
                self.assertEqual(actual, images.expected_images_program(pid))
                legacy = subprocess.run([str(binary), '1', str(pid)], check=True, stdout=subprocess.PIPE).stdout
                self.assertEqual(legacy, fixture.boundary.expected_program(pid))
                self.assertNotEqual(actual, legacy)
            for pid in (0, 1 << 31):
                self.assertNotEqual(subprocess.run([str(binary), '2', str(pid)], stdout=subprocess.PIPE).returncode, 0)


if __name__ == '__main__':
    unittest.main()
