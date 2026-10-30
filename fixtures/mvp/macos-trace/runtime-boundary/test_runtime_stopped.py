"""Original physical-byte controls, no provider, signals or native admission."""
from dataclasses import FrozenInstanceError
import copy
import hashlib
import json
import struct
import unittest
from unittest.mock import patch

import runtime_stopped as stopped
import test_runtime_boundary as base
import test_runtime_recipe as recipe_vectors

OWNER, TARGET, OLD, NEW, CTID = base.OWNER, base.TARGET, base.OLD, base.NEW, 900
U64 = (1 << 64) - 1
EXTRA = [('syscall', '', name, phase) for name in ('proc_info', 'wait4', 'wait4_nocancel', 'kill')
         for phase in ('entry', 'return')]
NAMES = base.NAMES + [name for name in EXTRA if name not in base.NAMES]
IDS = {name: i + 1 for i, name in enumerate(NAMES)}
INVENTORY = ''.join(str(IDS[name])+'\t'+'\t'.join(name)+'\n' for name in NAMES).encode()


def evidence():
    e = recipe_vectors.evidence()
    return stopped.RuntimeRecipeEvidence(*(getattr(e, name) for name in (
        'request','catalog','launch_plan','status_stream','launcher_artifact',
        'output_witness','gate_delivery','go_prefix')))


def spec(kind, name='', tid=CTID, args=(), actor=None, detail=None, memory=b''):
    return dict(kind=kind,function=name,tid=tid,args=tuple(args),actor=actor,detail=detail,memory=memory)


def owner_call(name, args, result=0, errno=0, memory=b'', call_id=1, returned_kind=None):
    kind = returned_kind or (20 if name=='proc_info' else 21 if name.startswith('wait4') else 22)
    value = (U64,U64,U64,errno,errno) if errno else (result,result,0,0,0)
    return [spec(2,name,args=tuple(args)+(0,)*(8-len(args)),actor=OWNER,detail=call_id),
            spec(kind,name,args=value,actor=OWNER,detail=call_id,memory=memory)]


def native_fields(original, query):
    role=query%2;row=original[160+40*role:200+40*role]
    b=bytearray(176)
    def le(at,n,value): b[at:at+n]=value.to_bytes(n,'little')
    u=lambda at,n:int.from_bytes(row[at:at+n],'big')
    le(0,4,2 | (0x10000 if query%2 else 0));le(4,4,2 if query<2 or query>=6 else 0)
    le(8,8,100+query);le(16,4,1);le(24,4,u(16,8)&0xffffffff)
    le(28,2,u(12,4));le(30,2,u(32,8));le(32,8,u(24,8));le(160,4,1)
    return bytes(b)


def field_swap(b):
    # Independent fixed SDK-width table; no production codec is called.
    widths=(4,4,8,4,4,4,2,2,8,4,4,8,8,8,8,8,8,8,8,8,8,4,4,4,4,8,8,4,4,4,4)
    result=bytearray();offset=0
    for n in widths: result+=b[offset:offset+n][::-1];offset+=n
    assert offset==176
    return bytes(result)


def physical(rows):
    result=[]
    for ordinal,item in enumerate(rows,1):
        k=item['kind'];actor=item.get('actor')
        if actor is None: actor=OWNER if k in (1,17) else TARGET
        detail=item.get('detail')
        if detail is None: detail=OWNER if k in (2,3,5,7,15,16) else 0
        if k in (1,17): names=('dtrace','','','BEGIN' if k==1 else 'END')
        elif k in (2,3,20,21,22,23): names=('syscall','',item['function'],'entry' if k==2 else 'return')
        elif k in (15,16): names=('mach_trap','','mach_msg2_trap','entry' if k==15 else 'return')
        else: names=('proc','','','lwp-start' if k==19 else base.PROC_NAMES[k])
        words=(k,item.get('timestamp',100+ordinal),actor,item['tid'],detail)+item['args']
        count={2:13,3:10,15:13,16:6,18:8,19:7,20:10,21:10,22:10,23:10}.get(k,5)
        assert len(words)==count,(item,words)
        leading={1:1,2:8,4:1,5:1,7:4,8:1}.get(k,0)
        records=[dict(action=1,size=0,offset=12,hex='') for _ in range(leading)]
        records += [dict(action=1,size=8,offset=16+8*i,hex=struct.pack('<Q',x).hex()) for i,x in enumerate(words)]
        memory=item.get('memory',b'')
        if memory: records.append(dict(action=6,size=len(memory),offset=16+8*count,hex=memory.hex()))
        if k==19: records += [dict(action=514,size=0,offset=72,hex=''),dict(action=1,size=0,offset=72,hex='')]
        record=dict(event=ordinal,cpu=0,epid=IDS[names]*32+k,probe_id=IDS[names],
            record_bytes=16+8*count+len(memory),header_record_indexes=list(range(leading,leading+5)),
            kind=k,timestamp=words[1],pid=actor,tid=item['tid'],detail=detail,
            **dict(zip(('provider','module','function','name'),names)),records=records)
        result.append(json.dumps(record,separators=(',',':')).encode()+b'\n')
    return result


def fixture(*,prelude=False,marker_first=False):
    e=evidence();program=stopped.expected_stopped_program(OWNER,TARGET,
        hashlib.sha256(e.request).digest(),hashlib.sha256(e.catalog).digest())
    rows=copy.deepcopy(base.happy());cut=next(i for i,x in enumerate(rows) if x['kind']==10)
    prefix,tail=rows[:cut+1],rows[cut+1:]
    marker=spec(19,tid=NEW,detail=1,args=(NEW,17))
    prefix.insert(len(prefix)-1 if marker_first else len(prefix),marker)
    call_id=1
    if prelude:
        prefix[1:1]=owner_call('wait4',(TARGET,0x8000,1,0),memory=bytes(4),call_id=call_id)
        call_id+=1
    controls=owner_call('wait4',(TARGET,0x8010,3,0),TARGET,memory=(0x117f).to_bytes(4,'little'),call_id=call_id)
    call_id+=1
    for query in range(8):
        role=query%2;parent=query<2 or query>=6
        fd=int.from_bytes(e.output_witness[160+40*role:164+40*role],'big') if parent else 1+role
        controls+=owner_call('proc_info',(3,OWNER if parent else TARGET,1,fd,0x10000+256*query,176),
            176,memory=native_fields(e.output_witness,query),call_id=call_id)
        call_id+=1
    controls+=owner_call('kill',(TARGET,19,1),call_id=call_id);call_id+=1
    rows=prefix+controls+tail[:-1]+owner_call('wait4_nocancel',(TARGET,0x8020,1,0),TARGET,
        memory=bytes(4),call_id=call_id)+tail[-1:]
    packet=bytearray(4096);packet[:8]=b'GLUEPX01'
    put=base.put
    for at,n,value in ((8,2,1),(10,2,256),(12,4,4096),(16,4,OWNER),(20,4,TARGET),
        (24,8,1),(32,8,1000000),(40,8,next(i for i,x in enumerate(rows,1) if x['kind']==7)),
        (48,8,NEW),(56,2,8),(58,2,1),(60,2,2),(68,4,15),(72,8,5000),(80,2,1)):
        put(packet,at,n,value)
    for at,b in ((96,e.request),(128,e.catalog),(160,e.status_stream[:512]),(192,program),(224,e.output_witness)):
        packet[at:at+32]=hashlib.sha256(b).digest()
    for query in range(8):
        role=query%2;parent=query<2 or query>=6
        fd=int.from_bytes(e.output_witness[160+40*role:164+40*role],'big') if parent else 1+role
        at=256+224*query
        for offset,n,value in ((0,4,OWNER if parent else TARGET),(4,4,fd),(8,8,1100+20*query),
            (16,8,1110+20*query),(24,8,0x10000+256*query),(32,4,176),(40,2,11)):
            put(packet,at+offset,n,value)
        packet[at+42]=1+role;packet[at+43]=1 if query<4 else 2
        packet[at+48:at+224]=field_swap(native_fields(e.output_witness,query))
    for at,n,value in ((2048,8,1000),(2056,8,1010),(2064,4,TARGET),(2068,4,0x117f),(2076,4,51)):
        put(packet,at,n,value)
    return e,program,rows,bytes(packet)


def paired(data=None,**kwargs):
    e,program,rows,packet=fixture() if data is None else data
    return stopped.pair_runtime_stopped_raw(kwargs.pop('program',program),kwargs.pop('probes',INVENTORY),
        kwargs.pop('errors',b''),kwargs.pop('event_lines',physical(rows)),owner_pid=OWNER,target_pid=TARGET,
        contract_bytes=kwargs.pop('contract_bytes',base.CONTRACT),launch_evidence=kwargs.pop('launch_evidence',e),
        output_observation=kwargs.pop('output_observation',packet),**kwargs)


class StoppedRuntimeControls(unittest.TestCase):
    def test_original_outer_stream_and_all_query_wait_bytes_correlate(self):
        result=paired()
        self.assertEqual(result.status,'source-conditional-correlated',result.gaps)
        self.assertEqual((len(result.query_correlations),len(result.wait_correlations)),(8,1))
        self.assertEqual([p.source_ordinal for p in result.phase_accounting],list(range(1,len(result.source.phases)+1)))
        self.assertEqual(result.source.raw.events,len(result.source.phases))
        self.assertTrue(result.intended_continue_control is not None)
        for name in ('native_origin_authenticated','raw_origin_authenticated','quiescence_proved','ofd_identity_proved',
            'descriptor_generation_proved','state_feed_eligible','authorizes_sink_exemptions','full_flags_proved',
            'full_trace_acceptance','retention_before_continue_proved','c_and_trace_clock_origins_calibrated',
            'foreign_controller_excluded'):
            self.assertIs(getattr(result,name),False)
        self.assertFalse(result.wait_correlations[0].status_buffer_address_authenticated)

    def test_owner_prelude_keeps_actual_orphan_ordinal_and_child_logical_position(self):
        result=paired(fixture(prelude=True))
        self.assertEqual(result.status,'source-conditional-correlated',result.gaps)
        self.assertEqual(result.images.attachment_return.phase.ordinal,4)
        self.assertEqual(result.source.phases[1].raw_scalars[2],OWNER)

    def test_marker_ECB_order_and_distinct_timestamps_do_not_require_equality(self):
        result=paired(fixture(marker_first=True))
        self.assertEqual(result.status,'source-conditional-correlated',result.gaps)
        marker=result.source.phases[result.selected_marker_ordinal-1]
        self.assertNotEqual(marker.raw_scalars[1],result.images.transitions[0].lwp_start.raw_scalars[1])

    def test_marker_cannot_precede_selected_success_even_when_timestamps_tie(self):
        for delta in (0,1):
            e,p,rows,packet=fixture()
            marker=rows.pop(next(i for i,x in enumerate(rows) if x['kind']==19))
            success=next(i for i,x in enumerate(rows) if x['kind']==7)
            rows.insert(success,marker)
            success=next(i for i,x in enumerate(rows) if x['kind']==7)
            marker['timestamp']=100+success+1+delta
            b=bytearray(packet);base.put(b,40,8,success+1)
            with self.subTest(timestamp_delta=delta):
                result=paired((e,p,rows,bytes(b)))
                self.assertEqual(result.status,'incomplete')
                self.assertTrue(any(x.code=='stop-marker' for x in result.gaps))
                self.assertLess(result.selected_marker_ordinal,result.images.transitions[0].success.ordinal)
                self.assertEqual(len(result.phase_accounting),len(rows))
                self.assertEqual(result.source.phases[result.selected_marker_ordinal-1].raw_scalars[1],
                    result.images.transitions[0].success.raw_scalars[1]+delta)
                self.assertFalse(result.native_origin_authenticated)

    def test_exact_descriptor_memory_and_raise_shapes(self):
        e,p,rows,packet=fixture();raw=physical(rows)
        for kind in (2,7,8,19,20,21):
            selected=next((i for i,x in enumerate(rows) if x['kind']==kind),None)
            if selected is None:continue
            record=json.loads(raw[selected]);record['records'][-1]['action']^=1
            bad=list(raw);bad[selected]=json.dumps(record).encode()+b'\n'
            with self.subTest(kind=kind),self.assertRaises(stopped.RawValidationError):paired((e,p,rows,packet),event_lines=bad)

    def test_query_pointer_payload_subject_fd_and_library_outcome_cannot_drift(self):
        for mutation in ('pointer','bytes','subject','fd','result'):
            e,p,rows,packet=fixture();row=next(x for x in rows if x['kind']==2 and x['function']=='proc_info')
            if mutation in ('pointer','subject','fd'):
                values=list(row['args']);values[{'pointer':4,'subject':1,'fd':3}[mutation]]+=1;row['args']=tuple(values)
            else:
                returned=next(x for x in rows if x['kind']==20)
                if mutation=='bytes':returned['memory']=bytes([returned['memory'][0]^1])+returned['memory'][1:]
                else:returned['args']=(175,175,0,0,0)
            with self.subTest(mutation=mutation):self.assertEqual(paired((e,p,rows,packet)).status,'incomplete')

    def test_owner_call_id_pairing_and_clock_failures_are_not_normalized(self):
        for mutation in ('missing','duplicate','return','clock'):
            e,p,rows,packet=fixture()
            entries=[x for x in rows if x['kind']==2 and x.get('actor')==OWNER]
            returns=[x for x in rows if x['kind'] in (20,21,22,23)]
            if mutation=='missing':entries[0]['detail']=2
            elif mutation=='duplicate':entries[2]['detail']=entries[1]['detail']
            elif mutation=='return':returns[1]['detail']+=100
            else:entries[2]['timestamp']=1
            with self.subTest(mutation=mutation):
                result=paired((e,p,rows,packet))
                self.assertEqual(result.status,'incomplete')
                self.assertEqual(len(result.phase_accounting),len(rows))

    def test_failed_continue_keeps_actual_intent_and_false_retention(self):
        e,p,rows,packet=fixture()
        returned=next(x for x in rows if x['kind']==22)
        returned['args']=(U64,U64,U64,1,1)
        result=paired((e,p,rows,packet))
        self.assertEqual(result.status,'incomplete')
        self.assertTrue(any(x.code=='continue-failed' for x in result.gaps))
        self.assertIsNotNone(result.intended_continue_control)
        self.assertFalse(result.retention_before_continue_proved)

    def test_legacy_kill_posix_mode_does_not_become_a_continue(self):
        e,p,rows,packet=fixture()
        entry=next(x for x in rows if x['kind']==2 and x['function']=='kill')
        entry['args']=(TARGET,19,0,0,0,0,0,0)
        result=paired((e,p,rows,packet))
        self.assertEqual(result.status,'incomplete')
        self.assertIsNone(result.intended_continue_control)
        self.assertTrue(any(x.code=='unsupported-owner-signal' for x in result.gaps))

    def test_terminal_wait_retires_signalling_before_later_continue(self):
        e,p,rows,packet=fixture()
        at=next(i for i,x in enumerate(rows) if x['kind']==2 and x['function']=='kill')
        rows[at:at]=owner_call('wait4',(TARGET,0x9000,1,0),TARGET,memory=bytes(4))
        count=0
        for row in rows:
            if row['kind']==2 and row.get('actor')==OWNER:count+=1;row['detail']=count
            elif row['kind'] in (20,21,22,23):row['detail']=count
        result=paired((e,p,rows,packet))
        self.assertEqual(result.status,'incomplete')
        self.assertTrue(any(x.code=='signal-after-retirement' for x in result.gaps))

    def test_child_can_progress_during_continue_but_never_before_its_entry(self):
        e,p,rows,packet=fixture()
        at=next(i for i,x in enumerate(rows) if x['kind']==22)
        rows[at:at]=base.call('getpid',(),TARGET,NEW)
        result=paired((e,p,rows,packet))
        self.assertEqual(result.status,'source-conditional-correlated',result.gaps)
        e,p,rows,packet=fixture()
        at=next(i for i,x in enumerate(rows) if x['kind']==2 and x['function']=='kill')
        rows[at:at]=base.call('write',(1,0x7000,0),0,NEW)
        result=paired((e,p,rows,packet))
        self.assertEqual(result.status,'incomplete')
        self.assertTrue(any(x.code=='child-progress-before-continue' for x in result.gaps))
        self.assertFalse(result.authorizes_sink_exemptions)

    def test_closed_child_call_crossing_sampling_is_a_conflict(self):
        e,p,rows,packet=fixture()
        entered,returned=base.call('write',(1,0x7000,1),1,NEW)
        first=next(i for i,x in enumerate(rows) if x['kind']==2 and x['function']=='proc_info')
        rows[first:first]=[entered]
        last=next(i for i,x in enumerate(rows) if x['kind']==22)
        rows[last:last]=[returned]
        result=paired((e,p,rows,packet))
        self.assertEqual(result.status,'incomplete')
        self.assertTrue(any(x.code=='sampling-window-conflict' for x in result.gaps))

    def test_extra_marker_or_new_tid_binding_cannot_claim_selected_stop(self):
        for mutation in ('duplicate','PXtid','PXordinal'):
            e,p,rows,packet=fixture()
            if mutation=='duplicate':
                at=next(i for i,x in enumerate(rows) if x['kind']==19)
                rows[at:at]=[copy.deepcopy(rows[at])]
            else:
                b=bytearray(packet);base.put(b,48 if mutation=='PXtid' else 40,8,9999);packet=bytes(b)
            with self.subTest(mutation=mutation):self.assertEqual(paired((e,p,rows,packet)).status,'incomplete')

    def test_unsafe_scalar_fallback_retains_call_without_invented_memory(self):
        e,p,rows,packet=fixture()
        entry=next(x for x in rows if x['kind']==2 and x['function']=='proc_info')
        args=list(entry['args']);args[5]=175;entry['args']=tuple(args)
        returned=next(x for x in rows if x['kind']==20);returned['kind']=23;returned['memory']=b''
        result=paired((e,p,rows,packet))
        self.assertEqual(result.status,'incomplete')
        control=next(x for x in result.owner_controls if x.entry.function=='proc_info')
        self.assertEqual(control.memory,b'')
        self.assertEqual(control.returned.raw_scalars[0],23)
        self.assertTrue(control.unsupported_reasons)

    def test_late_Mach_failure_retains_whole_outer_without_image_prefix(self):
        e,p,rows,packet=fixture()
        at=next(i for i,x in enumerate(rows) if x['kind']==2 and x['function']=='exit')
        rows[at:at]=[spec(15,tid=NEW,args=(0,)*8),spec(16,tid=NEW,args=(0,))]
        result=paired((e,p,rows,packet))
        self.assertEqual(result.status,'incomplete')
        self.assertIsNone(result.images)
        self.assertEqual(result.query_correlations,())
        self.assertEqual(len(result.phase_accounting),len(rows))
        self.assertTrue(any(x.role=='opaque-mach-original' for x in result.phase_accounting))

    def test_coherently_forged_buffer_declaration_is_still_not_native_authentication(self):
        e,p,rows,packet=fixture();b=bytearray(packet)
        entry=next(x for x in rows if x['kind']==2 and x['function']=='proc_info')
        args=list(entry['args']);args[4]=0x700000;entry['args']=tuple(args)
        base.put(b,256+24,8,0x700000)
        result=paired((e,p,rows,bytes(b)))
        self.assertEqual(result.status,'source-conditional-correlated',result.gaps)
        self.assertFalse(result.native_origin_authenticated)
        self.assertFalse(result.query_correlations[0].native_origin_authenticated)

    def test_failed_query_prefix_correlates_original_opaque_bytes_without_success(self):
        e,p,rows,packet=fixture();b=bytearray(packet)
        base.put(b,56,2,3);base.put(b,60,2,3);base.put(b,62,2,12)
        base.put(b,64,4,5);base.put(b,68,4,7);base.put(b,72,8,1150);base.put(b,82,2,1)
        b[256+3*224:2048]=bytes(5*224)
        at=256+2*224;base.put(b,at+32,4,0);base.put(b,at+36,4,5);base.put(b,at+40,2,13)
        b[at+48:at+224]=native_fields(e.output_witness,2)
        removed=set();query=0
        for i,row in enumerate(rows):
            if row['kind']==2 and row['function']=='proc_info':
                if query>=3:removed.update((i,i+1))
                if query==2:rows[i+1]['args']=(U64,U64,U64,5,5)
                query+=1
        rows=[row for i,row in enumerate(rows) if i not in removed]
        for row in rows:
            if row['kind']==2 and row['function']=='kill':row['args']=(TARGET,9,1,0,0,0,0,0)
        count=0
        for row in rows:
            if row['kind']==2 and row.get('actor')==OWNER:count+=1;row['detail']=count
            elif row['kind'] in (20,21,22,23):row['detail']=count
        result=paired((e,p,rows,bytes(b)))
        self.assertEqual(result.status,'incomplete')
        self.assertEqual(len(result.query_correlations),3)
        self.assertEqual(result.observer.queries[-1].opaque_buffer,native_fields(e.output_witness,2))
        self.assertFalse(result.authorizes_sink_exemptions)

    def test_failed_after_clock_cannot_restore_reaped_or_ECHILD_signal_ownership(self):
        for state,flags,pid,errno,wflags in ((4,16,TARGET,0,37),(5,32,0xffffffff,10,9)):
            e,p,rows,packet=fixture();b=bytearray(packet)
            b[256:2048]=bytes(1792)
            for at,n,value in ((56,2,0),(60,2,state),(62,2,5),(64,4,5),(68,4,flags),
                               (72,8,1000),(80,2,0),(82,2,1),(2056,8,0),(2064,4,pid),
                               (2068,4,0),(2072,4,errno),(2076,4,wflags)):
                base.put(b,at,n,value)
            returned=next(row for row in rows if row['kind']==21)
            returned['args']=(U64,U64,U64,10,10) if errno else (TARGET,TARGET,0,0,0)
            returned['memory']=bytes(4)
            result=paired((e,p,rows,bytes(b)))
            with self.subTest(state=state):
                self.assertEqual(result.status,'incomplete')
                self.assertTrue(any(x.code=='signal-after-retirement' for x in result.gaps))
                self.assertEqual(result.query_correlations,())
                self.assertFalse(result.state_feed_eligible)

    def test_no_future_continue_sidecar_or_profile_input(self):
        for name in ('continue_record','profile','capture','stopped'):
            with self.subTest(name=name),self.assertRaises(TypeError):paired(**{name:b'future'})

    def test_raw_iterator_once_late_fault_and_late_malformed_never_return_prefix(self):
        e,p,rows,packet=fixture();raw=physical(rows)
        class Once:
            count=0
            def __iter__(self):
                self.count+=1
                if self.count!=1:raise AssertionError('second raw iteration')
                yield from raw
        once=Once();result=paired((e,p,rows,packet),event_lines=once)
        self.assertEqual(once.count,1);self.assertEqual(result.status,'source-conditional-correlated')
        def fault():
            yield from raw
            raise RuntimeError('late input failure')
        with self.assertRaisesRegex(RuntimeError,'late input failure'):paired((e,p,rows,packet),event_lines=fault())
        with self.assertRaises(stopped.RawValidationError):paired((e,p,rows,packet),event_lines=raw+[b'{}\n'])

    def test_program_PX_original_bindings_and_wrong_profile_refuse(self):
        e,p,rows,packet=fixture()
        for at in (96,128,160,192,224):
            b=bytearray(packet);b[at]^=1
            with self.subTest(at=at),self.assertRaises(stopped.RawValidationError):paired((e,p,rows,bytes(b)))
        with self.assertRaises(stopped.RawValidationError):paired((e,stopped._IMAGES.expected_images_program(TARGET),rows,packet))

    def test_immutable_fresh_serialization_and_no_asset_IO_after_import(self):
        data=fixture()
        with patch('builtins.open',side_effect=AssertionError('late asset IO')):
            result=paired(data)
        with self.assertRaises(FrozenInstanceError):result.status='native'
        one=result.to_dict();one['query_correlations'].clear()
        self.assertEqual(len(result.to_dict()['query_correlations']),8)


if __name__=='__main__':unittest.main()
