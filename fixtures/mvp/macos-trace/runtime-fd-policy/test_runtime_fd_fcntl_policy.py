"""Original-byte controls for the separate fixed v2 fcntl interval profile."""
from dataclasses import FrozenInstanceError
from pathlib import Path
import unittest
from unittest.mock import patch
import test_runtime_fd_policy as vectors
import runtime_fd_policy as policy

call, event, stream, physical = vectors.call, vectors.event, vectors.stream, vectors.physical
U64, NEW, GATE = vectors.U64, vectors.NEW, vectors.GATE


def evaluate(rows=None, **kwargs):
    return policy.evaluate_runtime_fd_fcntl_policy_raw(
        vectors.recipe_vectors.recipe._IMAGES.expected_images_program(vectors.TARGET),
        vectors.INVENTORY, b'', kwargs.pop('event_lines', physical(stream() if rows is None else rows)),
        owner_pid=vectors.OWNER, target_pid=vectors.TARGET,
        contract_bytes=vectors.base.CONTRACT, launch_evidence=vectors.evidence(), **kwargs)


def opened(fd=5):
    return call('open', (0x7000, 0, 0), fd)


def binding(result, fd):
    return next(row for row in result.final_bindings if row.fd == fd)


class FcntlIntervalControls(unittest.TestCase):
    accounted = vectors.RuntimeFDPolicyControls.accounted
    no_authority = vectors.RuntimeFDPolicyControls.no_authority

    def test_both_forms_all_four_commands_and_descriptor_local_flags(self):
        for name in ('fcntl', 'fcntl_nocancel'):
            with self.subTest(name=name):
                body = opened()+call(name, (5, 2, U64), 0)+call(name, (5, 1, U64), 1)
                body += call(name, (5, 0, 10), 10)+call(name, (5, 67, 11), 11)
                result = evaluate(stream(body))
                self.assertEqual(result.protocol, 'darwin-runtime-fd-fcntl-policy-v2')
                self.assertEqual(result.status, 'source-conditional-clean')
                self.assertEqual([row.request.command for row in result.fcntl_attempts], [2, 1, 0, 67])
                self.assertTrue(binding(result, 5).cloexec)
                self.assertFalse(binding(result, 10).cloexec)
                self.assertTrue(binding(result, 11).cloexec)
                self.assertEqual(binding(result, 10).analysis_binding_key, binding(result, 5).analysis_binding_key)
                self.assertEqual(binding(result, 11).analysis_binding_key, binding(result, 5).analysis_binding_key)
                self.accounted(result); self.no_authority(result)

    def test_getfd_does_not_rewrite_binding_bit_or_version_at_return(self):
        result = evaluate(stream(opened()+call('fcntl', (5, 1, U64), 0)))
        changes = [row for row in result.transitions if row.fd == 5]
        self.assertEqual(len(changes), 1)
        self.assertEqual(binding(result, 5).version, changes[0].version)
        self.assertEqual(result.fcntl_attempts[0].request.argument, -1)
        unknown = evaluate(stream(call('fcntl', (1, 1, U64), 1)))
        self.assertIsNone(binding(unknown, 1).analysis_binding_key)
        self.assertIsNone(binding(unknown, 1).cloexec)
        self.no_authority(unknown)

    def test_setfd_is_descriptor_local_even_for_shared_analysis_keys(self):
        body = opened()+call('dup', (5,), 6)+call('fcntl', (5, 2, 1), 0)
        result = evaluate(stream(body))
        self.assertTrue(binding(result, 5).cloexec)
        self.assertFalse(binding(result, 6).cloexec)
        self.assertEqual(binding(result, 5).analysis_binding_key, binding(result, 6).analysis_binding_key)
        self.assertEqual(binding(result, 6).alias_source, 5)

    def test_full_signed64_argument_bits_are_retained_without_u32_projection(self):
        for raw, signed, requested in ((U64, -1, True), (1 << 63, -(1 << 63), False),
                                        ((1 << 63)+1, -(1 << 63)+1, True)):
            with self.subTest(raw=raw):
                result = evaluate(stream(opened()+call('fcntl', (5, 2, raw), 0)))
                row, = result.fcntl_attempts
                self.assertEqual(row.request.argument, signed)
                self.assertEqual(row.request.requested_cloexec, requested)
                self.assertEqual(binding(result, 5).cloexec, requested)
                attempt = result.attempts[row.attempt_index]
                self.assertIsNone(attempt.flags_u32)
                self.assertEqual(attempt.entry.raw_scalars[7], raw)

    def test_minimum_signed32_boundary_and_numeric_fd_is_not_storage_ceiling(self):
        result = evaluate(stream(opened()+call('fcntl', (5, 0, vectors.INT_MAX), vectors.INT_MAX)))
        self.assertEqual(binding(result, vectors.INT_MAX).analysis_binding_key,
                         binding(result, 5).analysis_binding_key)
        invalid = evaluate(stream(opened()+call('fcntl', (5, 0, 1 << 31), errno=22)+opened(6)))
        self.assertEqual(invalid.status, 'incomplete')
        self.assertIsNone(invalid.fcntl_attempts[0].request.minimum_descriptor)
        self.assertTrue(all(row.analysis_binding_key is None for row in invalid.final_bindings))

    def test_negative_minimum_error_is_retained_without_alias_or_global_poison(self):
        result = evaluate(stream(opened()+call('fcntl', (5, 0, U64), errno=22)))
        self.assertEqual(result.fcntl_attempts[0].request.minimum_descriptor, -1)
        self.assertEqual(result.status, 'incomplete')
        self.assertIsNotNone(binding(result, 5).analysis_binding_key)
        self.assertFalse(any(row.state == 'conditional-alias' for row in result.final_bindings))
        self.assertTrue(any(row.code == 'failed-scalar-operation' for row in result.gaps))

    def test_impossible_success_and_noncanonical_domains_cannot_install_alias(self):
        cases = [((5,0,10),9), ((5,0,5),5), ((U64,0,0),6),
                 ((0xffffffff,0,0),6), ((5,0,U64),6), ((5,1,0),2), ((5,2,1),1)]
        for args, result in cases:
            with self.subTest(args=args,result=result):
                value = evaluate(stream(opened()+call('fcntl', args, result)))
                self.assertTrue(value.attempts[value.fcntl_attempts[0].attempt_index].unsupported_reasons)
                self.assertEqual(value.status, 'incomplete')
                self.assertFalse(any(row.state == 'conditional-alias' for row in value.final_bindings))

    def test_nonzero_secondary_result_is_preserved_and_unsupported(self):
        rows=stream(opened()+call('fcntl', (5,0,6),6))
        returned=next(row for row in rows if row['kind']==3 and row['function']=='fcntl')
        returned['args']=(6,6,1,0,0)
        result=evaluate(rows)
        self.assertEqual(result.fcntl_attempts[0].operation.outcome.secondary_result,1)
        self.assertEqual(result.status,'incomplete')
        self.assertFalse(any(row.fd==6 for row in result.final_bindings))

    def test_failed_allocator_has_gap_and_preserves_isolated_prior_key(self):
        for name,args in (('dup',(5,)),('fcntl',(5,0,6)),('fcntl_nocancel',(5,67,6))):
            with self.subTest(name=name):
                result=evaluate(stream(opened()+call(name,args,errno=24)))
                self.assertIsNotNone(binding(result,5).analysis_binding_key)
                self.assertTrue(any(row.code=='failed-scalar-operation' for row in result.gaps))
                self.assertEqual(result.status,'incomplete')

    def test_failed_setfd_clears_only_local_bit_certainty(self):
        body=opened()+call('dup',(5,),6)+call('fcntl',(5,2,1),errno=1)
        result=evaluate(stream(body))
        self.assertIsNone(binding(result,5).cloexec)
        self.assertFalse(binding(result,6).cloexec)
        self.assertEqual(binding(result,5).analysis_binding_key,binding(result,6).analysis_binding_key)
        self.assertEqual(result.status,'incomplete')

    def test_contradictory_getfd_is_an_explicit_gap_not_a_new_binding(self):
        result=evaluate(stream(opened()+call('fcntl',(5,1,0),1)))
        self.assertTrue(any(row.code=='contradictory-cloexec-observation' for row in result.gaps))
        self.assertIsNone(binding(result,5).cloexec)
        self.assertIsNotNone(binding(result,5).analysis_binding_key)

    def test_unsupported_commands_stay_sticky_from_entry_through_later_known_calls(self):
        for command in (3,4,7,999):
            with self.subTest(command=command):
                body=opened()+call('fcntl',(5,command,0),errno=22)+opened(6)+call('dup',(6,),7)
                result=evaluate(stream(body))
                self.assertEqual(result.status,'incomplete')
                self.assertTrue(all(row.analysis_binding_key is None for row in result.final_bindings))
                self.assertTrue(result.fcntl_attempts[0].operation.unsupported_reasons)

    def test_touching_setfd_getfd_windows_conflict(self):
        a,b=call('fcntl',(5,2,1),0)
        c,d=call('fcntl_nocancel',(5,1,0),1,303)
        rows=stream(opened()+[event(9,tid=NEW,detail=303),event(10,tid=303),a,b,c,d,event(11,tid=303)])
        i=next(i for i,row in enumerate(rows) if row['kind']==3 and row['function']=='fcntl')
        rows[i+1]['timestamp']=100+i+1
        result=evaluate(rows)
        self.assertTrue(result.conflicts)
        self.assertIsNone(binding(result,5).analysis_binding_key)
        self.accounted(result)

    def test_failed_dupfd_reservation_conflicts_with_distinct_allocator(self):
        a,b=call('fcntl',(5,0,8),errno=24)
        c,d=call('open',(0x8000,0,0),9,303)
        body=opened()+[event(9,tid=NEW,detail=303),event(10,tid=303),a,c,d,b,event(11,tid=303)]
        result=evaluate(stream(body))
        self.assertTrue(any(row.allocation_domain for row in result.conflicts))
        self.assertTrue(all(row.analysis_binding_key is None for row in result.final_bindings))

    def test_source_close_inside_dupfd_blocks_alias_propagation(self):
        a,b=call('fcntl',(5,0,8),8)
        body=opened()+[event(9,tid=NEW,detail=303),event(10,tid=303),a,
                       *call('close',(5,),0,303),b,event(11,tid=303)]
        result=evaluate(stream(body))
        self.assertTrue(result.conflicts)
        self.assertIsNone(binding(result,8).analysis_binding_key)

    def test_distinct_alias_descriptor_flag_windows_are_independent(self):
        a,b=call('fcntl',(5,2,1),0)
        c,d=call('fcntl_nocancel',(6,2,1),0,303)
        body=opened()+call('dup',(5,),6)+[event(9,tid=NEW,detail=303),event(10,tid=303),a,c,d,b,event(11,tid=303)]
        result=evaluate(stream(body))
        self.assertEqual(result.conflicts,())
        self.assertTrue(binding(result,5).cloexec and binding(result,6).cloexec)
        self.assertEqual(binding(result,5).analysis_binding_key,binding(result,6).analysis_binding_key)

    def test_validated_bootstrap_getfl_is_not_a_runtime_permission(self):
        rows=stream()
        rows[2:2]=call('fcntl',(GATE,3,0),0x01000004,vectors.OLD)
        result=evaluate(rows)
        self.assertEqual(result.status,'source-conditional-clean')
        row,=result.fcntl_attempts
        self.assertEqual(result.attempts[row.attempt_index].context,'bootstrap')
        self.assertIsNone(row.operation)
        self.no_authority(result)

    def test_getfd_and_setfd_do_not_authorize_stdout(self):
        body=call('fcntl',(1,1,0),0)+call('fcntl',(1,2,0),0)+call('write',(1,0x7000,1),1)
        result=evaluate(stream(body))
        self.assertEqual(result.status,'incomplete')
        self.assertTrue(any(row.code=='unresolved-output-binding' for row in result.gaps))
        self.assertEqual(result.output_exemptions,())
        self.no_authority(result)

    def test_whole_image_failure_retains_fcntl_request_without_outcome_or_state_prefix(self):
        body=call('fcntl',(5,2,U64),0)+[event(15,'write',NEW,args=(0,)*8),event(16,'write',NEW,args=(0,))]
        result=evaluate(stream(body))
        row,=result.fcntl_attempts
        self.assertEqual(row.request.argument,-1)
        self.assertIsNone(row.operation)
        self.assertEqual((result.windows,result.transitions,result.final_bindings),((),(),()))
        self.assertTrue(any(row.intent=='opaque-mach-attempt' for row in result.attempts))
        self.accounted(result)

    def test_recipe_and_original_iterator_are_consumed_once_and_late_faults_raise(self):
        raw=physical(stream(opened()+call('fcntl',(5,0,6),6)))
        class Once:
            calls=0
            def __iter__(self):
                self.calls+=1
                if self.calls!=1: raise AssertionError('raw replay')
                yield from raw
        original=Once()
        with patch.object(policy._RECIPE,'pair_runtime_recipe_raw',wraps=policy._RECIPE.pair_runtime_recipe_raw) as reader, \
             patch.object(policy._FCNTL,'decode_owned_fcntl_semantics',side_effect=AssertionError('public reparse')):
            result=evaluate(event_lines=original)
        self.assertEqual((reader.call_count,original.calls),(1,1))
        self.accounted(result)
        def broken():
            yield from raw
            raise RuntimeError('late raw fault')
        with self.assertRaisesRegex(RuntimeError,'late raw fault'): evaluate(event_lines=broken())
        with self.assertRaises(ValueError): evaluate(event_lines=raw+[b'{}\n'])

    def test_later_exec_retires_fcntl_aliases_and_flags_without_rebuilding_outputs(self):
        tid=1002
        body=opened()+call('fcntl',(5,67,6),6)+call('fcntl',(5,2,1),0)
        body += [event(2,'execve',NEW,args=(0x8000,0x9000,0xa000,0,0,0,0,0)),
                 event(9,tid=NEW,detail=tid),event(11,tid=NEW),
                 event(18,tid=NEW,detail=vectors.TARGET,args=(0,0x220000,0x20)),
                 event(7,tid=tid),event(5,tid=tid),event(10,tid=tid)]
        body += call('fcntl',(5,1,0),0,tid)+call('write',(1,0x7000,1),1,tid)
        result=evaluate(stream(body,terminal_tid=tid))
        self.assertEqual(len(result.recipe.images.transitions),2)
        self.assertIsNone(binding(result,5).analysis_binding_key)
        self.assertIsNone(binding(result,6).analysis_binding_key)
        self.assertIsNone(binding(result,5).cloexec)
        self.no_authority(result);self.accounted(result)

    def test_failed_getfd_adds_no_bit_observation_or_new_table_revision(self):
        result=evaluate(stream(opened()+call('fcntl',(5,1,U64),errno=5)))
        row,=result.fcntl_attempts
        self.assertIsNone(row.operation.rule)
        self.assertEqual(len([row for row in result.transitions if row.fd==5]),1)
        self.assertFalse(binding(result,5).cloexec)
        self.assertIsNotNone(binding(result,5).analysis_binding_key)
        self.assertEqual(result.status,'incomplete')

    def test_original_undeclared_tail_and_command_word_are_conserved(self):
        rows=stream(call('fcntl',(1,1,U64),0))
        entered=next(row for row in rows if row['kind']==2 and row['function']=='fcntl')
        entered['args']=(1,1,U64,0x1234,U64,7,8,0xfeed)
        result=evaluate(rows)
        command,=result.fcntl_attempts
        attempt=result.attempts[command.attempt_index]
        self.assertEqual(attempt.entry.raw_scalars[5:],entered['args'])
        self.assertEqual(len(attempt.arguments),3)
        self.accounted(result)

    def test_successful_lookups_do_not_preserve_known_conditional_absence(self):
        cases=[('fcntl',(5,1,0),0),('fcntl',(5,2,1),0),
               ('fcntl',(5,0,6),6),('fcntl_nocancel',(5,67,6),6),('dup',(5,),6)]
        for name,args,result in cases:
            with self.subTest(name=name,args=args):
                value=evaluate(stream(opened()+call('close',(5,),0)+call(name,args,result)))
                self.assertTrue(any(row.code=='inconsistent-present-lookup' for row in value.gaps))
                self.assertEqual(value.status,'incomplete')
                self.assertEqual(binding(value,5).state,'unknown')
                self.assertIsNone(binding(value,5).cloexec)
                self.assertFalse(any(row.state=='conditional-alias' for row in value.final_bindings))
                self.accounted(value);self.no_authority(value)

    def test_allocator_success_does_not_replace_known_occupied_destination(self):
        cases=[('fcntl',(5,0,6),6),('fcntl_nocancel',(5,67,6),6),
               ('dup',(5,),6),('open',(0x8000,0,0),6)]
        for name,args,result in cases:
            with self.subTest(name=name,args=args):
                value=evaluate(stream(opened()+opened(6)+call(name,args,result)))
                self.assertTrue(any(row.code=='inconsistent-free-allocation' for row in value.gaps))
                self.assertEqual(binding(value,6).state,'unknown')
                self.assertIsNone(binding(value,6).analysis_binding_key)
                self.assertIsNone(binding(value,6).cloexec)
                self.assertIsNotNone(binding(value,5).analysis_binding_key)
                self.assertEqual(value.status,'incomplete')
        # dup2 explicitly replaces its destination, so occupation alone is legal.
        value=evaluate(stream(opened()+opened(6)+call('dup2',(5,6),6)))
        self.assertEqual(value.status,'source-conditional-clean')
        self.assertEqual(binding(value,5).analysis_binding_key,binding(value,6).analysis_binding_key)

    def test_v1_factory_shape_and_unsupported_scope_are_preserved(self):
        rows=stream(opened()+call('fcntl',(5,1,0),0))
        old=vectors.evaluate(rows)
        self.assertEqual(old.protocol,'darwin-runtime-fd-policy-v1')
        self.assertNotIn('fcntl_attempts',old.to_dict())
        self.assertEqual(old.status,'incomplete')
        self.assertEqual(len(policy.HANDLED_RUNTIME_NAMES),15)
        with self.assertRaises(TypeError): evaluate(rows,profile='v1')

    def test_result_is_immutable_detached_and_has_no_late_asset_io(self):
        original=vectors.evidence();raw=physical(stream(opened()+call('fcntl',(5,0,6),6)))
        # Construct evidence before blocking reads; the source API accepts only bytes.
        with patch('builtins.open',side_effect=AssertionError('lateopen')), \
             patch.object(Path,'read_bytes',side_effect=AssertionError('lateread')):
            result=policy.evaluate_runtime_fd_fcntl_policy_raw(
                vectors.recipe_vectors.recipe._IMAGES.expected_images_program(vectors.TARGET),
                vectors.INVENTORY,b'',raw,owner_pid=vectors.OWNER,target_pid=vectors.TARGET,
                contract_bytes=vectors.base.CONTRACT,launch_evidence=original)
        with self.assertRaises(FrozenInstanceError): result.status='clean'
        one=result.to_dict();one['fcntl_attempts'].clear()
        self.assertTrue(result.to_dict()['fcntl_attempts'])
        self.no_authority(result)


if __name__=='__main__': unittest.main()
