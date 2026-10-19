"""Pure metadata and standalone injected shell gates; no generated phase runs."""
import copy
from pathlib import Path
import re
import shlex
import subprocess
import unittest

import gates

REQUEST, CATALOG = '1' * 64, '2' * 64
EMPTY = 'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855'
FILES = ['program.d', 'probes.tsv', 'events.jsonl', 'errors.jsonl']


def error(native=False):
    return dict(stage=0, reason=0, system_errno=0, libdtrace_code=0,
                callback_error=0, message_hex='') if native else \
           dict(stage=0, reason=0, callback_error=0, detail=0)


def fixture():
    # Independently transcribed fixed native receipt/sidecar contract. Fixtures
    # never use the implementation's predicates/relation tables to make data.
    result = dict(schema='glue-owned-traced-bootstrap-diagnostic-v1', tracing=True,
        exec_proved=False, full_acceptance=False,
        identity_policy='request-declarations-compared-to-observations',
        consistent_owned_probe=True, controller_pid=100, child_pid=200,
        parent_error=dict(stage=0, reason=0, errno=0, detail=0),
        cleanup_error=dict(stage=0, reason=0, errno=0, detail=0),
        helpers=dict(admission=dict(stage=0, reason=0, errno=0, component=0, metadata_step=0),
            endpoints=dict(stage=0, reason=0, errno=0, role=5, fd=-1),
            signal_prepare=dict(stage=0, reason=0, errno=0)),
        child_error=dict(present=False, stage=0, reason=0, errno=0, flags=0, detail=0),
        protocol=dict(records=2, bytes=512, wire_fault=0, io_stage=0, io_reason=0, io_errno=0, eof_class=3),
        go=dict(action=1, attempted=True, possibly_released=True, bytes=64, stage=0, reason=0, errno=0, closed=True),
        ready_matched=True, probe_matched=True,
        wait=dict(forked=True, reaped=True, lost=False, kill_attempted=False, raw_status=0),
        signals=dict(prepared=True, restore_called=True, pipe_restored=True, mask_restored=True,
            restore_stage=0, restore_reason=0, restore_errno=0),
        identities=dict(request_sha256=REQUEST, catalog_sha256=CATALOG,
            signal_policy_sha256='3'*64, status_sha256='4'*64, stdout_sha256='5'*64,
            stderr_sha256=EMPTY, probe_sha256='6'*64,
            runner_static_sources_sha256='7'*64, build_recipe_sha256='8'*64),
        stdout_capture_valid=True, stderr_capture_valid=True, stdout_bytes=256, stderr_bytes=0,
        trace_sidecar='trace.json', trace_finalization_safe=True, trace_success_eligible=True)
    binding = dict(fixture=1, owner_pid=100, target_pid=200,
                   request_sha256=REQUEST, catalog_sha256=CATALOG)
    session = dict(binding=binding, attempt_deadline_ns=10000000000,
        cleanup_deadline_ns=12000000000, cleanup_ms=2000, cleanup_attempted=1, cleanup_bound=1,
        error=error(), cleanup_error=error(), configured=1, initialized=1,
        start_attempted=1, backend_touched=1, last_ns=11000000000, total_pumps=2,
        child=1, wait_status=0, kill_claimed=0, started=1, provider_ready=1,
        begin=1, terminal=1, end=1, pumps=[1,1,0], events=4, go_claim_attempted=1,
        go_possibly_released=1, go_result_seen=1, go_complete=1, go_bytes=64,
        bootstrap_seen=1, bootstrap_sealed=1, bootstrap_prefix_bytes=512,
        gate_close_seen=1, gate_closed=1, stop_attempted=1, stopped=1,
        drain_attempted=1, drained=1, close_attempted=1, closed=1,
        parent_close_seen=1, parent_closed=1)
    backend = dict(binding=copy.deepcopy(binding), original_attempt_deadline_ns=10000000000,
        cleanup_deadline_ns=12000000000, first_error=error(True), close_error=error(True),
        writer_close_error=error(True), writer_close_files=FILES[:],
        writer_close_attempted_mask=15, writer_close_failed_mask=0, writer_close_errno=[0]*4,
        events=3, raw_bytes=3000, diagnostic_bytes=0, inventory_bytes=1000,
        drops=0, faults=0, inventory_probes=17, expected_matches=17,
        enabled_matches=17, enablings=3, begin=1, terminal=1, end=1,
        start_attempted=1, started=1, stop_attempted=1, stopped=1,
        drain_attempted=1, drained=1, close_attempted=1, resources_closed=1)
    trace = dict(schema='glue-owned-trace-session-diagnostic-v1', tracing=True,
        exec_proved=False, full_acceptance=False, parent_cleanup_deadline_ns=12000000000,
        parent_cleanup_valid=1, create_attempted=1, session_present=1, snapshot_valid=1,
        backend_destroyed=1, finalization_safe=1, success_eligible=1, create_error=error(True),
        session=session, backend=backend)
    return result, trace


def zero(value, key=''):
    # An unstarted TS/OTB snapshot is native zero-initialized storage; serializer
    # alone emits the fixed writer-name array even without a backend instance.
    if type(value) is dict:
        return {k: zero(v,k) for k,v in value.items()}
    if type(value) is list:
        return [zero(x,key) for x in value]
    if type(value) is str:
        return '0'*64 if key.endswith('_sha256') else ''
    return 0


def denied_fixture():
    result, trace = fixture()
    result.update(consistent_owned_probe=False, ready_matched=False, probe_matched=False,
                  trace_success_eligible=False, stdout_bytes=0)
    result['identities']['stdout_sha256'] = EMPTY
    result['parent_error'] = dict(stage=10, reason=12, errno=0, detail=-1)
    result['child_error'] = dict(present=True, stage=6, reason=3, errno=13, flags=1, detail=-1)
    result['protocol'].update(records=1, bytes=256, eof_class=2)
    result['go'].update(attempted=False, possibly_released=False, bytes=0)
    result['wait']['raw_status'] = 30720
    trace.update(create_attempted=0, session_present=0, snapshot_valid=0,
                 backend_destroyed=0, success_eligible=0)
    trace['session'] = zero(trace['session'])
    trace['backend'] = zero(trace['backend'])
    trace['backend']['writer_close_files'] = FILES[:]
    return result, trace


def change(obj, path, value):
    parts = path.split('.')
    for part in parts[:-1]:
        obj = obj[int(part)] if type(obj) is list else obj[part]
    if type(obj) is list:
        obj[int(parts[-1])] = value
    else:
        obj[parts[-1]] = value


def check(case, result, trace, native=None, request=REQUEST, catalog=CATALOG):
    status = 0 if case == 'positive' else 1
    return gates.check_metadata(case, status if native is None else native,
        result, trace, request_sha256=request, catalog_sha256=catalog)


def shell_stub(objects, fault=None):
    values = []
    def walk(which, obj, path=''):
        if type(obj) in (dict, list):
            if type(obj) is list:
                values.append((which + ':' + path + ':array', str(len(obj))))
            items = enumerate(obj) if type(obj) is list else obj.items()
            for key, value in items:
                walk(which, value, path + ('.' if path else '') + str(key))
        else:
            kind = 'bool' if type(obj) is bool else 'integer' if type(obj) is int else 'string' if type(obj) is str else 'invalid'
            text = ('true' if obj else 'false') if type(obj) is bool else str(obj)
            values.append((which + ':' + path + ':' + kind, text))
    for which, obj in objects.items(): walk(which,obj)
    lines = ['meta_value() { case "$1:$2:$3" in']
    for key,value in values:
        failed = fault is not None and key == ':'.join(fault)
        lines.append('  '+shlex.quote(key)+') printf \'%s\\n\' '+shlex.quote(value)
                     + ('; return 7' if failed else '') + ' ;;')
    lines += ['  *) return 2 ;;','esac; }',
              'meta_expect() { mm=$(meta_value "$1" "$2" "$3") || return 2; [ "$mm" = "$4" ]; }']
    return '\n'.join(lines)


def shell_check(case, result, trace, *, native=None, request=REQUEST, catalog=CATALOG, fault=None):
    # Only module-emitted metadata functions and literal test stubs execute.
    # Never read/render/source a generated root/outer/launch phase.
    status = 0 if case == 'positive' else 1
    code = '\n'.join([shell_stub({'result':result, 'trace':trace}, fault=fault), gates.shell_checks(),
        'native='+shlex.quote(str(status if native is None else native)),
        'expected_request_sha256='+shlex.quote(request),
        'expected_catalog_sha256='+shlex.quote(catalog), 'gate_'+case])
    return subprocess.run(['/bin/sh','-c',code],capture_output=True,timeout=10)


class Gates(unittest.TestCase):
    def refusal(self, which, path, value, case='positive', shell=False):
        result, trace = fixture() if case=='positive' else denied_fixture()
        change(result if which=='result' else trace,path,value)
        before=copy.deepcopy((result,trace))
        with self.assertRaises(ValueError): check(case,result,trace)
        self.assertEqual(before,(result,trace))
        if shell:
            done=shell_check(case,result,trace)
            self.assertEqual(done.returncode,2,done.stderr)

    def test_complete_positive_and_denial_rosters(self):
        base={'request.bin','status.bin','probe.stdout','probe.stderr','result.json','trace.json'}
        self.assertEqual(set(check('positive',*fixture())),base|set(FILES))
        self.assertEqual(set(check('denied',*denied_fixture())),base)

    def test_unknown_native_status_case_and_types(self):
        for status in (True,False,-1,1,2,120,'0',None):
            with self.subTest(status=status):
                with self.assertRaises(ValueError):
                    gates.check_metadata('positive',status,*fixture(),request_sha256=REQUEST,catalog_sha256=CATALOG)
        with self.assertRaises(ValueError): check('trailing',*fixture())

    def test_cross_snapshot_pid_binding(self):
        for which,path,value in [('result','controller_pid',200),('result','child_pid',0),
            ('result','controller_pid',1<<31),('result','child_pid',True),
            ('trace','session.binding.fixture',2),('trace','backend.binding.fixture',0),
            ('trace','session.binding.owner_pid',101),('trace','backend.binding.target_pid',201),
            ('trace','backend.binding.owner_pid','100')]:
            with self.subTest(path=path): self.refusal(which,path,value,shell=True)

    def test_trusted_request_catalog_hashes(self):
        for path in ('identities.request_sha256','identities.catalog_sha256'):
            self.refusal('result',path,'f'*64,shell=True)
        for path in ('session.binding.request_sha256','session.binding.catalog_sha256',
                     'backend.binding.request_sha256','backend.binding.catalog_sha256'):
            self.refusal('trace',path,'f'*64,shell=True)
        for value in ('', '1'*63, 'A'*64, 'g'*64, None, True):
            with self.assertRaises(ValueError): check('positive',*fixture(),request=value)
        result,trace=fixture()
        for obj in (result['identities'],trace['session']['binding'],trace['backend']['binding']):
            obj['request_sha256']='f'*64
        with self.assertRaises(ValueError): check('positive',result,trace)
        self.assertEqual(shell_check('positive',result,trace).returncode,2)

    def test_deadline_binding_and_cleanup_source_consistency(self):
        for path,value in [('session.attempt_deadline_ns',10000000001),
            ('backend.cleanup_deadline_ns',12000000001),('parent_cleanup_deadline_ns',0),
            ('session.cleanup_ms',1999),('session.last_ns',12000000000),
            ('session.last_ns',9999999999),('session.last_ns',True),
            ('session.cleanup_deadline_ns',1<<64)]:
            with self.subTest(path=path,value=value): self.refusal('trace',path,value,shell=True)
        result,trace=fixture()
        for key in ('parent_cleanup_deadline_ns',): trace[key]=(1<<64)-1
        trace['session'].update(cleanup_deadline_ns=(1<<64)-1,last_ns=(1<<64)-2000000001)
        trace['backend']['cleanup_deadline_ns']=(1<<64)-1
        self.assertTrue(check('positive',result,trace))
        self.assertEqual(shell_check('positive',result,trace).returncode,0)
        trace['session']['last_ns']-=1
        with self.assertRaises(ValueError): check('positive',result,trace)
        self.assertEqual(shell_check('positive',result,trace).returncode,2)

    def test_inventory_counters_budgets_and_pumps(self):
        for path,value in [('backend.expected_matches',18),('backend.enabled_matches',16),
            ('backend.inventory_probes',8193),('backend.enablings',18),
            ('backend.events',1000001),('backend.raw_bytes',134217729),
            ('backend.inventory_bytes',1048577),('backend.diagnostic_bytes',1),
            ('backend.drops',1),('backend.faults',1),('session.total_pumps',1),('session.total_pumps',3),
            ('session.pumps.0',65537),('session.pumps.1',0),
            ('session.pumps.2',1),('session.events',5)]:
            with self.subTest(path=path): self.refusal('trace',path,value,shell=True)
        # Coherently update the total so a sum mismatch cannot mask a missing
        # per-phase success constraint. The complete baseline is accepted.
        for pumps,total,reason in (([2,0,0],2,'session.pumps.1'),
                                   ([1,1,1],3,'session.pumps.2'),
                                   ([0,2,0],2,'session.pumps.0'),
                                   ([1,0,0],1,'session.total_pumps')):
            result,trace=fixture()
            self.assertTrue(check('positive',result,trace))
            trace['session'].update(pumps=pumps,total_pumps=total)
            with self.subTest(pumps=pumps),self.assertRaisesRegex(ValueError,re.escape(reason)):
                check('positive',result,trace)
            self.assertEqual(shell_check('positive',result,trace).returncode,2)
        result,trace=fixture()
        trace['backend']['events']=10  # shadow/lwp cleanup do not all reach TS
        self.assertTrue(check('positive',result,trace))
        self.assertEqual(shell_check('positive',result,trace).returncode,0)

    def test_full_closure_and_error_provenance(self):
        mutations=[('result','wait.reaped',False),('result','wait.lost',True),
            ('result','go.closed',False),('result','signals.mask_restored',False),
            ('result','trace_finalization_safe',False),('result','cleanup_error.errno',4),
            ('result','protocol.eof_class',1),('result','go.bytes',63),
            ('result','child_error.present',True),('result','helpers.endpoints.errno',5),
            ('trace','backend.resources_closed',0),('trace','snapshot_valid',0),
            ('trace','backend_destroyed',0),('trace','session.parent_closed',0),
            ('trace','session.gate_closed',0),('trace','session.cleanup_bound',0),
            ('trace','backend.writer_close_failed_mask',8),('trace','backend.writer_close_errno.3',4),
            ('trace','backend.writer_close_attempted_mask',7),('trace','backend.close_error.callback_error',75),
            ('trace','backend.first_error.libdtrace_code',123),('trace','backend.writer_close_error.system_errno',4),
            ('trace','create_error.message_hex','ff'),('trace','session.cleanup_error.callback_error',110)]
        for which,path,value in mutations:
            with self.subTest(path=path): self.refusal(which,path,value)

    def test_native_endpoint_success_sentinels_not_old_zero_error_fixture(self):
        # Read-only primary source assertions ground the independently literal
        # fixture. No helper is compiled, imported, executed or used to generate
        # metadata; enum/serializer drift requires a new contract review.
        base=Path(__file__).resolve().parent.parent
        header=(base/'target-endpoints/target_endpoints.h').read_text()
        implementation=(base/'target-endpoints/target_endpoints.c').read_text()
        serializer=(base/'bootstrap-runner/runner_files.c').read_text()
        roles=re.search(r'enum te_role \{([^}]+)\}',header).group(1)
        self.assertEqual([x.strip() for x in roles.split(',')],
            ['TE_STDIN','TE_STDOUT','TE_STDERR','TE_GATE_READER','TE_STATUS_WRITER','TE_NO_ROLE'])
        self.assertIn('(struct te_error){TE_STAGE_NONE, TE_REASON_NONE, 0, TE_NO_ROLE, -1, 0, 0}',implementation)
        self.assertIn('a->endpoint_error.system_errno,a->endpoint_error.role,a->endpoint_error.fd',serializer)
        for case,make in [('positive',fixture),('denied',denied_fixture)]:
            result,trace=make()
            self.assertEqual(result['helpers']['endpoints'],dict(stage=0,reason=0,errno=0,role=5,fd=-1))
            self.assertTrue(check(case,result,trace))
            self.assertEqual(shell_check(case,result,trace).returncode,0)
            for role,fd in ((0,0),(5,0),(0,-1),(4,-1),(5,-2),(True,-1),(5,False)):
                result,trace=make()
                result['helpers']['endpoints'].update(role=role,fd=fd)
                with self.subTest(case=case,role=role,fd=fd):
                    with self.assertRaises(ValueError): check(case,result,trace)
                    self.assertEqual(shell_check(case,result,trace).returncode,2)

    def test_exact_arrays_not_numeric_key_objects_or_extra_elements(self):
        for path,bad in [('backend.writer_close_errno',{'0':0,'1':0,'2':0,'3':0}),
            ('backend.writer_close_errno',[0]*5),('backend.writer_close_errno',[0]*3),
            ('backend.writer_close_files',FILES+['extra']),('session.pumps',[1,0,0,0]),
            ('session.pumps',{'0':1,'1':0,'2':0})]:
            with self.subTest(path=path,bad=bad): self.refusal('trace',path,bad,shell=True)

    def test_denial_is_exact_no_session_no_backend(self):
        for path,value in [('create_attempted',1),('session_present',1),('snapshot_valid',1),
            ('backend_destroyed',1),('session.binding.owner_pid',100),('session.configured',1),
            ('session.cleanup_bound',1),('session.go_claim_attempted',1),('session.error.callback_error',5),
            ('backend.raw_bytes',1),('backend.inventory_probes',17),('backend.resources_closed',1),
            ('backend.first_error.libdtrace_code',123)]:
            with self.subTest(path=path): self.refusal('trace',path,value,case='denied',shell=True)
        self.refusal('result','parent_error.reason',11,case='denied',shell=True)

    def test_exact_denial_cleanup_race_matrix(self):
        for raw, killed in ((30720,False),(30720,True),(9,True)):
            result,trace=denied_fixture()
            result['wait'].update(raw_status=raw,kill_attempted=killed)
            before=copy.deepcopy((result,trace))
            self.assertTrue(check('denied',result,trace))
            self.assertEqual(shell_check('denied',result,trace).returncode,0)
            self.assertEqual((result,trace),before)
        for raw,killed in ((9,False),(0,False),(0,True),(30721,False),
                           (120,False),(30720,1),(True,False),('30720',False)):
            result,trace=denied_fixture()
            result['wait'].update(raw_status=raw,kill_attempted=killed)
            before=copy.deepcopy((result,trace))
            with self.assertRaises(ValueError): check('denied',result,trace)
            self.assertEqual(shell_check('denied',result,trace).returncode,2)
            self.assertEqual((result,trace),before)

    def test_sim_always_refuses_and_preserves_actual_facts(self):
        for raw,kill in ((30720,False),(9,True),(0,False),(255,True)):
            result,trace=fixture()
            result['wait'].update(raw_status=raw,kill_attempted=kill)
            trace['session'].update(wait_status=raw,kill_claimed=int(kill))
            trace['session']['error'].update(stage=3,reason=14,callback_error=5,detail=4)
            before=copy.deepcopy((result,trace))
            with self.assertRaisesRegex(ValueError,'uncalibrated'): check('simulated',result,trace)
            self.assertEqual((result,trace),before)
            self.assertEqual(shell_check('simulated',result,trace).returncode,2)
        class Untouched:
            def __getitem__(self,key): raise AssertionError('SIM metadata inspected')
        with self.assertRaisesRegex(ValueError,'uncalibrated'): check('simulated',Untouched(),Untouched())

    def test_standalone_shell_syntax_and_passing_gates(self):
        snippet=gates.shell_checks()
        done=subprocess.run(['/bin/sh','-n'],input=snippet.encode(),capture_output=True,timeout=5)
        self.assertEqual(done.returncode,0,done.stderr)
        self.assertNotIn('sudo',snippet)
        self.assertNotIn('chmod',snippet)
        for case,inputs in [('positive',fixture()),('denied',denied_fixture())]:
            done=shell_check(case,*inputs)
            self.assertEqual(done.returncode,0,done.stderr)
            self.assertEqual(done.stdout,b'')

    def test_missing_metadata_never_becomes_inequality_or_absence_success(self):
        result,trace=fixture();del result['child_pid']
        with self.assertRaises(ValueError): check('positive',result,trace)
        self.assertEqual(shell_check('positive',result,trace).returncode,2)
        result,trace=fixture();del trace['backend']['binding']['request_sha256']
        with self.assertRaises(ValueError): check('positive',result,trace)
        self.assertEqual(shell_check('positive',result,trace).returncode,2)

    def test_checked_array_count_refuses_expected_bytes_with_failed_read(self):
        for case,inputs in [('positive',fixture()),('denied',denied_fixture())]:
            for path in ('backend.writer_close_files','backend.writer_close_errno','session.pumps'):
                with self.subTest(case=case,path=path):
                    # The injected reader emits the correct typed array count,
                    # then fails. Equality alone must never authorize a gate.
                    done=shell_check(case,*inputs,fault=('trace',path,'array'))
                    self.assertEqual(done.returncode,2,done.stderr)
                    self.assertEqual(done.stdout,b'')
        snippet=gates.shell_checks()
        self.assertNotIn('meta_absent',snippet)
        self.assertNotIn('meta_type',snippet)
        self.assertIn('meta_expect trace backend.writer_close_errno array 4',snippet)

    def test_prior_negative_absence_inferred_success_from_read_failure(self):
        # Regression explanation only: the prior negative probe blessed an
        # operation failure as absence, even after an extra element was read.
        # This standalone synthetic helper is not a generated guest phase.
        old='''read_extra() { printf 'extra-element\\n'; return 7; }
old_absent() { if read_extra >/dev/null 2>&1; then return 2; fi; }
old_absent
'''
        done=subprocess.run(['/bin/sh','-c',old],capture_output=True,timeout=5)
        self.assertEqual(done.returncode,0)


if __name__=='__main__': unittest.main()
