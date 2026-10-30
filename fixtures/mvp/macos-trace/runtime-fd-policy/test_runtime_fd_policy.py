"""Independent original-byte controls for the finite runtime FD request policy.

These controls never launch a target or provider.  The positive baseline has no
post-exec query/write routes that could accidentally mask the operation tested.
"""
import copy
from dataclasses import FrozenInstanceError, replace
import json
from pathlib import Path
import struct
import sys
import unittest
from unittest.mock import patch

BOUNDARY = Path(__file__).resolve().parents[1] / 'runtime-boundary'
sys.path.insert(0, str(BOUNDARY))
import test_runtime_boundary as base
import test_runtime_recipe as recipe_vectors
import runtime_fd_policy as policy

OWNER, TARGET, OLD, NEW = base.OWNER, base.TARGET, base.OLD, base.NEW
GATE, STATUS = base.GATE, base.STATUS
U64 = (1 << 64) - 1
INT_MAX = (1 << 31) - 1

# Independent inventory and physical record encoder.  No policy/reader template
# or normalized operation factory is used to create event bytes.
CALLS = (
    'read', 'read_nocancel', 'write', 'write_nocancel', 'poll', 'poll_nocancel',
    'close', 'close_nocancel', 'execve', 'getpid', 'getppid', 'fcntl', 'fstat64',
    'fcntl_nocancel', 'fstat', 'sigaction', 'exit', 'fork', 'vfork', 'posix_spawn',
    '__mac_execve', 'sendmsg', 'recvmsg', 'fileport_makefd', 'mystery',
    'dup', 'dup2', 'pwrite', 'pwrite_nocancel', 'fsync', 'fsync_nocancel',
    'ftruncate', 'open', 'open_nocancel', 'openat', 'openat_nocancel',
    'rename', 'unlink', 'mkdir', 'fchmod',
)
PROC = {4: 'create', 5: 'start', 6: 'exit', 7: 'exec-success', 8: 'exec-failure',
        9: 'lwp-create', 10: 'lwp-start', 11: 'lwp-exit', 12: 'spawn-success',
        13: 'spawn-failure', 18: 'exited'}
NAMES = [('dtrace', '', '', 'BEGIN'), ('dtrace', '', '', 'END')]
NAMES += [('syscall', '', name, phase) for name in CALLS for phase in ('entry', 'return')]
NAMES += [('mach_trap', '', name, phase)
          for name in ('mach_msg2_trap', 'write', 'open') for phase in ('entry', 'return')]
NAMES += [('proc', '', '', name) for name in PROC.values()]
IDS = {name: i + 1 for i, name in enumerate(NAMES)}
INVENTORY = ''.join(str(IDS[n]) + '\t' + '\t'.join(n) + '\n' for n in NAMES).encode()


def event(kind, name='', tid=OLD, *, args=(), detail=None, timestamp=None):
    return dict(kind=kind, function=name, tid=tid, args=tuple(args),
                detail=detail, timestamp=timestamp)


def call(name, args=(), result=0, tid=NEW, *, errno=0):
    words = (U64, U64, U64, errno, errno) if errno else (result, result, 0, 0, 0)
    return [event(2, name, tid, args=tuple(args) + (0,) * (8 - len(args))),
            event(3, name, tid, args=words)]


def stream(body=(), *, attachment='poll', terminal_tid=NEW):
    rows = [event(1)]
    if attachment:
        result = 512 if attachment == 'write' else 1
        rows.append(event(3, attachment, args=(result, result, 0, 0, 0)))
    already = 1 if attachment == 'read' else 0
    rows += call('read', (GATE, 0x1000, 64 - already), 64 - already, OLD)
    rows += call('read', (GATE, 0x1000, 1), 0, OLD)
    rows += call('close', (GATE,), 0, OLD)
    rows += call('write', (STATUS, 0x2000, 512), 512, OLD)
    rows += [event(2, 'execve', args=(0x3000, 0x4000, 0x5000, 0, 0, 0, 0, 0)),
             event(11), event(18, detail=TARGET, args=(0, 0x123456, 0x20)),
             event(7, tid=NEW), event(5, tid=NEW), event(10, tid=NEW)]
    rows += copy.deepcopy(list(body))
    rows += [event(2, 'exit', terminal_tid, args=(0,) * 8), event(6, tid=terminal_tid, detail=1),
             event(11, tid=terminal_tid), event(18, tid=terminal_tid, detail=TARGET,
                                        args=(0, 0x123457, 0x100)), event(17)]
    return rows


def physical(rows):
    result = []
    for ordinal, row in enumerate(rows, 1):
        kind = row['kind']
        actor = OWNER if kind in (1, 17) else TARGET
        detail = row['detail']
        if detail is None:
            detail = OWNER if kind in (2, 3, 5, 7, 15, 16) else 0
        if kind in (1, 17):
            names = ('dtrace', '', '', 'BEGIN' if kind == 1 else 'END')
        elif kind in (2, 3):
            names = ('syscall', '', row['function'], 'entry' if kind == 2 else 'return')
        elif kind in (15, 16):
            names = ('mach_trap', '', row['function'] or 'mach_msg2_trap',
                     'entry' if kind == 15 else 'return')
        else:
            names = ('proc', '', '', PROC[kind])
        timestamp = row.get('timestamp')
        words = (kind, 100 + ordinal if timestamp is None else timestamp,
                 actor, row['tid'], detail) + row['args']
        expected = {2: 13, 3: 10, 15: 13, 16: 6, 18: 8}.get(kind, 5)
        assert len(words) == expected, row
        leading = int(kind in (1, 4, 5, 7))
        records = [dict(action=1, size=0, offset=12, hex='')] if leading else []
        records += [dict(action=1, size=8, offset=16 + 8 * i,
                         hex=struct.pack('<Q', value).hex()) for i, value in enumerate(words)]
        record = dict(event=ordinal, cpu=0, epid=IDS[names], probe_id=IDS[names],
                      record_bytes=16 + 8 * expected,
                      header_record_indexes=list(range(leading, leading + 5)),
                      kind=kind, timestamp=words[1], pid=actor, tid=row['tid'], detail=detail,
                      **dict(zip(('provider', 'module', 'function', 'name'), names)), records=records)
        result.append(json.dumps(record, separators=(',', ':')).encode() + b'\n')
    return result


def evidence():
    original = recipe_vectors.evidence()
    return policy.RuntimeRecipeEvidence(
        original.request, original.catalog, original.launch_plan, original.status_stream,
        original.launcher_artifact, original.output_witness, original.gate_delivery,
        original.go_prefix)


def evaluate(rows=None, **kwargs):
    rows = stream() if rows is None else rows
    return policy.evaluate_runtime_fd_policy_raw(
        kwargs.pop('program', recipe_vectors.recipe._IMAGES.expected_images_program(TARGET)),
        kwargs.pop('probes', INVENTORY), kwargs.pop('errors', b''),
        kwargs.pop('event_lines', physical(rows)),
        owner_pid=kwargs.pop('owner_pid', OWNER), target_pid=kwargs.pop('target_pid', TARGET),
        contract_bytes=kwargs.pop('contract_bytes', base.CONTRACT),
        launch_evidence=kwargs.pop('launch_evidence', evidence()), **kwargs)


class RuntimeFDPolicyControls(unittest.TestCase):
    def runtime_attempts(self, result, name=None):
        return [a for a in result.attempts if a.context == 'runtime' and
                (name is None or a.source_name == name)]

    def finding(self, values, name):
        return [value for value in values if value.source_name == name]

    def accounted(self, result):
        rows = result.source.phases
        self.assertEqual([a.ordinal for a in result.phase_accounting], list(range(1, len(rows) + 1)))
        self.assertEqual(len({a.ordinal for a in result.phase_accounting}), len(rows))
        entries = [p.ordinal for p in rows if p.raw_scalars[0] in (2, 15)]
        self.assertEqual([a.entry.ordinal for a in result.attempts], entries)
        self.assertEqual(len({a.entry.ordinal for a in result.attempts}), len(entries))
        for index, a in enumerate(result.attempts):
            self.assertEqual(next(p for p in result.phase_accounting
                                  if p.ordinal == a.entry.ordinal).attempt_index, index)
            original = next(p for p in rows if p.ordinal == a.entry.ordinal)
            self.assertEqual(a.entry.raw_scalars, original.raw_scalars)
            self.assertEqual((a.entry.provider, a.entry.module, a.entry.function, a.entry.name),
                             (original.provider, original.module, original.function, original.name))
            if a.returned is not None:
                self.assertEqual(a.returned.raw_scalars[0], 3)
                self.assertEqual(a.returned.function, a.source_name)
        returns = {a.returned.ordinal for a in result.attempts if a.returned is not None}
        attachment = result.recipe.images.attachment_return if result.recipe is not None else None
        if attachment is not None:
            returns.add(attachment.phase.ordinal)
        if result.recipe is not None:
            self.assertEqual(returns, {p.ordinal for p in rows if p.raw_scalars[0] == 3})
        else:
            self.assertTrue(all(a.returned is None for a in result.attempts))

    def no_authority(self, result):
        self.assertEqual(result.output_exemptions, ())
        for name in ('native_admission', 'output_capabilities_authorized', 'state_feed_eligible',
                     'successful_effect_linearization', 'full_trace_acceptance'):
            self.assertIs(getattr(result, name), False)
        for binding in result.final_bindings:
            self.assertFalse(binding.kernel_generation_attested or binding.output_authorized)

    def test_closed_roster_baseline_accounts_every_original_phase_and_has_no_authority(self):
        result = evaluate()
        self.assertEqual(result.status, 'source-conditional-clean')
        self.assertEqual(self.runtime_attempts(result), [])
        self.assertEqual(result.violations, ())
        self.assertEqual(result.gaps, ())
        self.accounted(result)
        self.no_authority(result)

    def test_all_three_attachment_returns_are_retained_without_invented_entries(self):
        for attachment, route in (('read', 'GO-read-in-flight'), ('write', 'READY-write-tail'),
                                  ('poll', 'gate-poll-in-flight')):
            with self.subTest(attachment=attachment):
                result = evaluate(stream(attachment=attachment))
                self.assertEqual(result.status, 'source-conditional-clean')
                a = result.recipe.images.attachment_return
                self.assertEqual((a.phase.ordinal, a.source_route), (2, route))
                self.assertFalse(a.entry_observed or a.complete_interval)
                self.assertFalse(any(x.entry.ordinal == 2 for x in result.attempts))
                self.accounted(result)

    def test_validated_bootstrap_retries_are_context_not_runtime_write_exemptions(self):
        rows = stream()
        at = next(i for i, r in enumerate(rows) if r['kind'] == 2 and r['function'] == 'write')
        rows[at:at] = call('write', (STATUS, 0x2000, 512), tid=OLD, errno=4)
        result = evaluate(rows)
        self.assertEqual(result.status, 'source-conditional-clean')
        writes = [a for a in result.attempts if a.source_name == 'write']
        self.assertEqual(len(writes), 2)
        self.assertTrue(all(a.context == 'bootstrap' for a in writes))
        self.assertEqual(writes[0].returned.raw_scalars[-2:], (4, 4))
        self.accounted(result)
        self.no_authority(result)

    def test_postexec_stdout_never_inherits_the_ready_seed_even_after_success(self):
        result = evaluate(stream(call('write', (1, 0x6000, 4), 4)))
        a, = self.runtime_attempts(result, 'write')
        self.assertEqual((a.fd, a.requested_bytes), (1, 4))
        self.assertEqual(result.status, 'incomplete')
        self.assertTrue(self.finding(result.gaps, 'write'))
        self.assertTrue(any(t.fd in (1, 2) and t.state == 'unknown' for t in result.transitions))
        self.no_authority(result)
        self.accounted(result)

    def test_failed_write_keeps_full_request_and_hidden_partial_effect_uncertainty(self):
        result = evaluate(stream(call('write_nocancel', (2, 0x6000, 7), errno=32)))
        a, = self.runtime_attempts(result, 'write_nocancel')
        self.assertEqual((a.fd, a.requested_bytes), (2, 7))
        self.assertEqual(a.returned.raw_scalars[-2:], (32, 32))
        self.assertTrue(a.write_reasons)
        self.assertEqual(result.status, 'incomplete')
        self.accounted(result)

    def test_zero_byte_write_is_still_an_attempt_with_unresolved_target(self):
        result = evaluate(stream(call('write', (1, 0, 0), 0)))
        a, = self.runtime_attempts(result, 'write')
        self.assertEqual(a.requested_bytes, 0)
        self.assertTrue(a.write_reasons)
        self.assertEqual(result.status, 'incomplete')

    def test_write_success_domains_and_failed_oversize_request_are_distinct(self):
        for requested, reported in ((3, 4), (INT_MAX + 1, INT_MAX + 1)):
            with self.subTest(requested=requested, reported=reported):
                r = evaluate(stream(call('write', (1, 0x6000, requested), reported)))
                a, = self.runtime_attempts(r, 'write')
                self.assertTrue(a.unsupported_reasons)
                self.assertEqual(r.status, 'incomplete')
        result = evaluate(stream(call('write', (1, 0x6000, INT_MAX + 1), errno=22)))
        a, = self.runtime_attempts(result, 'write')
        self.assertEqual(a.requested_bytes, INT_MAX + 1)
        self.assertEqual(a.returned.raw_scalars[-1], 22)
        self.assertTrue(a.write_reasons)

    def test_pwrite_offsets_are_requests_and_only_minus_one_success_is_inconsistent(self):
        result = evaluate(stream(call('pwrite', (1, 0x6000, 4, U64 - 1), 4)))
        a, = self.runtime_attempts(result, 'pwrite')
        self.assertEqual((a.requested_offset, a.requested_bytes), (-2, 4))
        self.assertEqual(a.unsupported_reasons, ())
        rejected = evaluate(stream(call('pwrite_nocancel', (1, 0x6000, 4, U64), 4)))
        b, = self.runtime_attempts(rejected, 'pwrite_nocancel')
        self.assertEqual(b.requested_offset, -1)
        self.assertTrue(b.unsupported_reasons)

    def test_flush_and_truncate_preserve_attempts_without_observed_size_claim(self):
        body = call('fsync', (1,), errno=5) + call('fsync_nocancel', (2,), 0)
        body += call('ftruncate', (1, 8192), 0)
        result = evaluate(stream(body))
        self.assertEqual(len(self.runtime_attempts(result)), 3)
        trunc, = self.runtime_attempts(result, 'ftruncate')
        self.assertEqual(trunc.requested_length, 8192)
        self.assertTrue(all(a.write_reasons for a in self.runtime_attempts(result)))
        self.assertEqual(result.status, 'incomplete')
        self.no_authority(result)

    def test_each_open_variant_retains_writable_intent_on_error(self):
        for name in ('open', 'open_nocancel', 'openat', 'openat_nocancel'):
            args = (0x7000, 1, 0) if not name.startswith('openat') else (U64 - 1, 0x7000, 1, 0)
            with self.subTest(name=name):
                result = evaluate(stream(call(name, args, errno=13)))
                a, = self.runtime_attempts(result, name)
                self.assertEqual(a.flags_u32, 1)
                self.assertTrue(self.finding(result.violations, name))
                self.assertNotEqual(result.status, 'source-conditional-clean')
                self.accounted(result)

    def test_readonly_access_with_create_truncate_or_append_is_still_forbidden_intent(self):
        for flags in (0x200, 0x400, 0x8):
            with self.subTest(flags=flags):
                result = evaluate(stream(call('open', (0x7000, flags, 0), errno=2)))
                self.assertTrue(self.finding(result.violations, 'open'))

    def test_readonly_open_establishes_only_an_untrusted_new_slot(self):
        result = evaluate(stream(call('open', (0x7000, 0, 0), 3)))
        self.assertFalse(self.finding(result.violations, 'open'))
        binding = next(b for b in result.final_bindings if b.fd == 3)
        self.assertEqual(binding.state, 'untrusted-open')
        self.assertFalse(binding.output_authorized)
        self.no_authority(result)

    def test_known_path_mutation_failure_remains_intent_and_unknown_routes_block_whole(self):
        body = call('rename', (0x7000, 0x8000), errno=2) + call('mystery', (1, 2, 3), 0)
        result = evaluate(stream(body))
        self.assertTrue(self.finding(result.violations, 'rename'))
        self.assertTrue(self.finding(result.gaps, 'mystery'))
        self.assertNotEqual(result.status, 'source-conditional-clean')
        self.accounted(result)

    def test_unknown_query_fcntl_and_read_after_exec_are_not_bootstrap_exemptions(self):
        for name, args in (('getpid', ()), ('fcntl', (1, 3, 0)), ('read', (0, 0x7000, 1))):
            with self.subTest(name=name):
                result = evaluate(stream(call(name, args, 0)))
                self.assertEqual(result.status, 'incomplete')
                self.assertTrue(self.finding(result.gaps, name))
                self.assertEqual(len(self.runtime_attempts(result)), 1)

    def test_failed_close_and_failed_dup2_poison_without_claiming_unchanged(self):
        rows = stream(call('open', (0x7000, 0, 0), 3) + call('close', (3,), errno=5))
        result = evaluate(rows)
        self.assertEqual(next(b for b in result.final_bindings if b.fd == 3).state, 'unknown')
        other = evaluate(stream(call('open', (0x7000, 0, 0), 4) + call('dup2', (1, 4), errno=12)))
        self.assertEqual(next(b for b in other.final_bindings if b.fd == 4).state, 'unknown')

    def test_close_reuse_and_restore_advance_analysis_versions(self):
        body = call('open', (0x7000, 0, 0), 3) + call('close', (3,), 0)
        body += call('open', (0x7000, 0, 0), 3)
        result = evaluate(stream(body))
        changes = [t for t in result.transitions if t.fd == 3]
        self.assertGreaterEqual(len(changes), 3)
        self.assertEqual(len({t.version for t in changes}), len(changes))
        self.assertTrue(any(t.state == 'absent' for t in changes))
        self.assertEqual(next(b for b in result.final_bindings if b.fd == 3).state, 'untrusted-open')

    def test_dup2_self_preserves_version_while_distinct_dup_has_new_slot(self):
        body = call('open', (0x7000, 0, 0), 3) + call('dup2', (3, 3), 3)
        result = evaluate(stream(body))
        source = next(b for b in result.final_bindings if b.fd == 3)
        self.assertEqual(source.state, 'untrusted-open')
        history = [t for t in result.transitions if t.fd == 3]
        self.assertEqual(history[-1].prior_version, history[-1].version)
        self.assertEqual(source.version, history[0].version)
        self.assertEqual(source.analysis_binding_key, history[0].binding_key)
        self.assertEqual(source.cloexec, history[0].cloexec)
        index = next(i for i, a in enumerate(result.attempts)
                     if a.context == 'runtime' and a.source_name == 'dup2')
        self.assertEqual(next(w for w in result.windows if w.attempt_index == index).mutation_slots, ())
        other = evaluate(stream(call('open', (0x7000, 0, 0), 3) + call('dup', (3,), 4)))
        destination = next(b for b in other.final_bindings if b.fd == 4)
        self.assertEqual(destination.state, 'conditional-alias')
        self.assertEqual(destination.alias_source, 3)
        self.no_authority(other)

    def overlap(self, second='close', *, touching=False, allocation=False):
        start, finish = call('dup' if allocation else 'dup2', (3,) if allocation else (3, 4),
                             5 if allocation else 4)
        second_args = (0x7000, 0, 0) if allocation else ((3,) if second == 'close' else (1, 0x7000, 1))
        other_start, other_finish = call('open' if allocation else second, second_args,
                                        6 if allocation else 0, 303)
        body = [event(9, tid=NEW, detail=303), event(10, tid=303)]
        if touching:
            body += [start, finish, other_start, other_finish]
        else:
            body += [start, other_start, other_finish, finish]
        body += [event(11, tid=303)]
        rows = stream(call('open', (0x7100, 0, 0), 3) + body)
        if touching:
            # stream copied body objects, so locate the unique dup2 return.
            a = next(i for i, r in enumerate(rows) if r['kind'] == 3 and r['function'] == 'dup2')
            rows[a + 1]['timestamp'] = 100 + a + 1
        return rows

    def test_cross_thread_source_mutation_conflicts_despite_reversed_return_order(self):
        result = evaluate(self.overlap())
        self.assertTrue(result.conflicts)
        self.assertTrue(any(3 in conflict.slots for conflict in result.conflicts))
        self.assertFalse(result.successful_effect_linearization)

    def test_touching_cross_thread_endpoints_conflict_without_ordinal_linearization(self):
        result = evaluate(self.overlap(touching=True))
        self.assertTrue(result.conflicts)
        self.assertTrue(any(3 in conflict.slots for conflict in result.conflicts))

    def test_overlapping_allocators_conflict_even_with_distinct_returned_slots(self):
        result = evaluate(self.overlap(allocation=True))
        self.assertTrue(any(c.allocation_domain for c in result.conflicts))
        self.assertFalse(result.successful_effect_linearization)

    def test_disjoint_nonallocating_windows_do_not_create_false_slot_conflicts(self):
        first, last = call('close', (4,), 0)
        second, returned = call('close_nocancel', (5,), 0, 303)
        rows = stream([event(9, tid=NEW, detail=303), event(10, tid=303),
                       first, second, returned, last, event(11, tid=303)])
        result = evaluate(rows)
        self.assertEqual(result.conflicts, ())
        self.accounted(result)

    def test_late_exec_return_belongs_to_old_image_and_never_restores_seed(self):
        rows = stream(call('write', (1, 0x6000, 1), 1))
        rows = [r for r in rows if not (r['kind'] == 11 and r['tid'] == OLD)]
        at = next(i for i, r in enumerate(rows) if r['kind'] == 3 and
                  r['tid'] == NEW and r['function'] == 'write') + 1
        rows[at:at] = [event(3, 'execve', OLD, args=(0, 0, 0, U64 - 1, U64 - 1)), event(11, tid=OLD)]
        result = evaluate(rows)
        transition, = [a for a in result.attempts if a.context == 'exec']
        self.assertEqual(transition.returned.raw_scalars[3], OLD)
        written, = self.runtime_attempts(result, 'write')
        self.assertGreater(transition.returned.ordinal, written.returned.ordinal)
        self.assertFalse(any(a.context == 'runtime' and a.source_name == 'execve' for a in result.attempts))
        self.assertEqual(result.status, 'incomplete')
        self.accounted(result)
        self.no_authority(result)

    def test_nonreturning_exit_is_retained_once_without_successful_return(self):
        result = evaluate()
        terminal, = [a for a in result.attempts if a.context == 'termination']
        self.assertEqual(terminal.source_name, 'exit')
        self.assertIsNone(terminal.returned)
        self.assertEqual(terminal.entry.ordinal, result.recipe.images.terminating_call.entry.ordinal)
        self.assertFalse(result.recipe.images.terminating_call.successful_return_invented)
        self.accounted(result)

    def test_worker_declaration_subject_and_retirement_do_not_create_new_fd_tables(self):
        rows = stream([event(9, tid=NEW, detail=303), event(10, tid=303),
                       *call('close', (4,), 0, 303), event(11, tid=303)])
        result = evaluate(rows)
        worker = next(t for t in result.recipe.images.threads if t.tid == 303)
        binding = next(b for b in result.recipe.images.lifecycle_bindings
                       if b.thread_instance == worker.capture_instance and b.role == 'ordinary-lwp-declaration')
        self.assertNotEqual(binding.source_actor_instance, binding.thread_instance)
        self.accounted(result)
        self.no_authority(result)

    def test_late_image_failure_has_complete_raw_attempts_and_no_state_prefix(self):
        body = call('write', (1, 0x6000, 1), 1) + [event(15, tid=NEW, args=(0,) * 8),
                                                 event(16, tid=NEW, args=(0,))]
        result = evaluate(stream(body))
        self.assertEqual(result.status, 'incomplete')
        self.assertIsNone(result.recipe)
        self.assertEqual(result.transitions, ())
        self.assertEqual(result.final_bindings, ())
        self.assertTrue(any(a.source_name == 'write' and a.entry.provider == 'syscall'
                            for a in result.attempts))
        mach, = [a for a in result.attempts if a.entry.raw_scalars[0] == 15]
        self.assertEqual(mach.intent, 'opaque-mach-attempt')
        self.assertEqual(mach.context, 'unresolved-image')
        self.assertEqual(mach.arguments, ())
        self.assertIsNone(mach.returned)
        self.assertIsNone(mach.outcome)
        index = result.attempts.index(mach)
        self.assertEqual(next(p for p in result.phase_accounting
                              if p.ordinal == mach.entry.ordinal).attempt_index, index)
        self.accounted(result)
        self.no_authority(result)

    def test_mach_names_resembling_bsd_calls_never_acquire_bsd_intent_or_fd_semantics(self):
        for name in ('write', 'open'):
            with self.subTest(name=name):
                original = (1, 0x7000, 0x201, 0, 0, 0, 0, 0)
                body = [event(15, name, NEW, args=original), event(16, name, NEW, args=(0,))]
                result = evaluate(stream(body))
                mach, = [a for a in result.attempts if a.entry.provider == 'mach_trap']
                self.assertEqual((mach.source_name, mach.entry.name), (name, 'entry'))
                self.assertEqual(mach.entry.raw_scalars[5:], original)
                self.assertEqual((mach.context, mach.intent), ('unresolved-image', 'opaque-mach-attempt'))
                self.assertEqual((mach.arguments, mach.write_reasons), ((), ()))
                self.assertTrue(all(getattr(mach, field) is None for field in (
                    'returned', 'outcome', 'fd', 'source_fd', 'target_fd', 'requested_bytes',
                    'requested_offset', 'requested_length', 'flags_u32', 'image_epoch', 'thread_instance')))
                self.assertEqual(result.violations, ())
                self.assertEqual(result.status, 'incomplete')
                self.assertEqual((result.windows, result.conflicts, result.transitions,
                                  result.final_bindings, result.output_exemptions), ((), (), (), (), ()))
                self.accounted(result)
                self.no_authority(result)

    def test_late_unknown_route_blocks_whole_but_keeps_earlier_forbidden_attempt(self):
        body = call('open', (0x7000, 1, 0), errno=13) + call('mystery', (), 0)
        result = evaluate(stream(body))
        self.assertTrue(self.finding(result.violations, 'open'))
        self.assertTrue(self.finding(result.gaps, 'mystery'))
        self.assertEqual(result.source.raw.events, len(stream(body)))
        self.accounted(result)

    def test_bad_final_transport_and_wrong_or_missing_launch_evidence_never_return_a_policy(self):
        raw = physical(stream())
        with self.assertRaises(ValueError):
            evaluate(event_lines=raw + [b'{}\n'])
        with self.assertRaises(ValueError):
            evaluate(event_lines=raw[:-1])
        with self.assertRaises(ValueError):
            evaluate(errors=b'{"drop":1}\n')
        with self.assertRaises(ValueError):
            evaluate(launch_evidence=None)
        with self.assertRaisesRegex(ValueError, 'exact runtime recipe evidence type'):
            evaluate(launch_evidence=recipe_vectors.evidence())
        e = evidence()
        wrong = bytearray(e.output_witness); wrong[-1] ^= 1
        with self.assertRaises(ValueError):
            evaluate(launch_evidence=replace(e, output_witness=bytes(wrong)))

    def test_original_raw_iterable_is_consumed_once_and_late_exceptions_escape(self):
        raw = physical(stream(call('close', (3,), 0)))
        class Once:
            def __init__(self):
                self.iterations = self.yielded = 0
            def __iter__(self):
                self.iterations += 1
                if self.iterations != 1:
                    raise AssertionError('second raw iteration')
                for line in raw:
                    self.yielded += 1
                    yield line
        original = Once()
        result = evaluate(event_lines=original)
        self.assertEqual((original.iterations, original.yielded), (1, len(raw)))
        self.accounted(result)
        def broken():
            yield from raw
            raise RuntimeError('late input failure')
        with self.assertRaisesRegex(RuntimeError, 'late input failure'):
            evaluate(event_lines=broken())

    def test_noncanonical_fd_keeps_write_intent_without_masking_into_a_slot(self):
        # int32 -1 requires sign extension; raw0xffffffff is not canonical.
        result = evaluate(stream(call('write', (0xffffffff, 0x6000, 4), errno=9)))
        a, = self.runtime_attempts(result, 'write')
        self.assertIsNone(a.fd)
        self.assertTrue(a.unsupported_reasons)
        self.assertTrue(a.write_reasons)
        self.assertTrue(any(g.code == 'unsupported-frame' for g in self.finding(result.gaps, 'write')))
        self.assertEqual(result.status, 'incomplete')
        self.accounted(result)

    def test_impossible_dup_success_domains_do_not_install_aliases(self):
        for name, args, reported in (('dup', (3,), 3), ('dup2', (3, 4), 5)):
            with self.subTest(name=name):
                result = evaluate(stream(call(name, args, reported)))
                a, = self.runtime_attempts(result, name)
                self.assertTrue(a.unsupported_reasons)
                self.assertEqual(result.status, 'incomplete')
                self.assertFalse(any(b.state == 'conditional-alias' for b in result.final_bindings))

    def test_failed_allocator_reservation_still_conflicts_without_a_new_slot(self):
        rows = self.overlap(allocation=True)
        failed = next(r for r in rows if r['kind'] == 3 and r['function'] == 'open' and r['tid'] == 303)
        failed['args'] = (U64, U64, U64, 24, 24)
        result = evaluate(rows)
        self.assertTrue(any(c.allocation_domain for c in result.conflicts))
        self.assertFalse(any(b.fd == 6 for b in result.final_bindings))
        failure, = [a for a in self.runtime_attempts(result, 'open') if a.entry.raw_scalars[3] == 303]
        self.assertEqual(failure.returned.raw_scalars[-2:], (24, 24))
        self.accounted(result)

    def test_every_later_exec_retires_all_prior_slot_certainty(self):
        new_tid = 1002
        body = call('open', (0x7000, 0, 0), 3)
        body += [event(2, 'execve', NEW, args=(0x8000, 0x9000, 0xa000, 0, 0, 0, 0, 0)),
                 event(9, tid=NEW, detail=new_tid), event(11, tid=NEW),
                 event(18, tid=NEW, detail=TARGET, args=(0, 0x220000, 0x20)),
                 event(7, tid=new_tid), event(5, tid=new_tid), event(10, tid=new_tid)]
        body += call('write', (1, 0x6000, 1), 1, new_tid)
        result = evaluate(stream(body, terminal_tid=new_tid))
        self.assertEqual(len(result.recipe.images.transitions), 2)
        self.assertEqual(len([a for a in result.attempts if a.context == 'exec']), 2)
        self.assertEqual(next(b for b in result.final_bindings if b.fd == 3).state, 'unknown')
        self.assertGreaterEqual(len([t for t in result.transitions if t.fd == 1 and t.state == 'unknown']), 2)
        self.assertTrue(self.finding(result.gaps, 'write'))
        self.accounted(result)
        self.no_authority(result)

    def test_undeclared_raw_tail_words_are_retained_without_inventing_arguments(self):
        rows = stream(call('write', (1, 0x6000, 4), 4))
        row = next(r for r in rows if r['kind'] == 2 and r['function'] == 'write' and r['tid'] == NEW)
        row['args'] = (1, 0x6000, 4, U64, 0x1234, 7, U64 - 1, 0xfeed)
        result = evaluate(rows)
        a, = self.runtime_attempts(result, 'write')
        self.assertEqual(a.entry.raw_scalars[5:], row['args'])
        self.assertEqual(a.requested_bytes, 4)
        self.assertEqual(a.unsupported_reasons, ())
        self.accounted(result)

    def test_unknown_entry_starts_an_opaque_horizon_that_later_open_and_dup_cannot_repair(self):
        body = call('open', (0x7000, 0, 0), 3) + call('mystery', (), 0)
        body += call('open', (0x8000, 0, 0), 4) + call('dup', (4,), 5)
        result = evaluate(stream(body))
        opaque, = self.runtime_attempts(result, 'mystery')
        self.assertEqual(result.status, 'incomplete')
        self.assertEqual(len(self.runtime_attempts(result)), 4)
        self.assertTrue(any(g.code == 'unsupported-route' for g in self.finding(result.gaps, 'mystery')))
        self.assertTrue(result.final_bindings)
        self.assertTrue(all(b.state == 'unknown' and b.analysis_binding_key is None
                            for b in result.final_bindings))
        self.assertFalse(any(t.ordinal > opaque.entry.ordinal and
                             t.state in ('untrusted-open', 'conditional-alias')
                             for t in result.transitions))
        self.accounted(result)
        self.no_authority(result)

    def test_no_asset_io_after_import_and_detached_immutable_serialization(self):
        e, raw = evidence(), physical(stream(call('close', (3,), 0)))
        with patch('builtins.open', side_effect=AssertionError('late asset open')), \
             patch.object(Path, 'read_bytes', side_effect=AssertionError('late read_bytes')):
            result = evaluate(launch_evidence=e, event_lines=raw)
        with self.assertRaises(FrozenInstanceError):
            result.status = 'source-conditional-clean'
        first, second = result.to_dict(), result.to_dict()
        first['attempts'].clear()
        first['phase_accounting'].clear()
        self.assertTrue(second['attempts'])
        self.assertTrue(result.to_dict()['phase_accounting'])
        self.no_authority(result)


if __name__ == '__main__':
    unittest.main()
