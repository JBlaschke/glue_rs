"""Fixed stopped-runtime original-byte diagnostic; never native/sink authority.

One complete physical pass retains owner and child records. Call IDs and actual
buffer bytes correlate source observations, not native origin or an exclusive
stop lease. No controller/TS adoption or future continue sidecar is accepted.
"""
from dataclasses import dataclass
import hashlib
import importlib.util
from pathlib import Path
from typing import Iterable, Optional

_HERE = Path(__file__).resolve().parent
_BASE = _HERE.parent
DEPENDENCY_IDENTITIES = (
    ('runtime-boundary/runtime_recipe.py', '95ddd5a12362a7b8dc3e1803de7f45282478a6ca56e58a8cb7d924c450ba02ef'),
    ('post-exec-output/post_exec_output.py', '524ed88e617c495e58fcc031fe2c7422b5dabee257ce3a83d4008550ca1e8b7b'),
 )
for _relative, _digest in DEPENDENCY_IDENTITIES:
    with (_BASE / _relative).open('rb') as _stream:
        _source = _stream.read(65537)
    if len(_source) > 65536 or hashlib.sha256(_source).hexdigest() != _digest:
        raise ValueError('stopped-runtime fixed dependency identity: ' + _relative)
del _relative, _digest, _stream, _source


def _import(name, relative):
    spec = importlib.util.spec_from_file_location(name, _BASE / relative)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


_RECIPE = _import('_stopped_runtime_recipe', 'runtime-boundary/runtime_recipe.py')
_PX = _import('_stopped_runtime_observer', 'post-exec-output/post_exec_output.py')
_IMAGES = _RECIPE._IMAGES
_V1 = _IMAGES._V1
_RAW = _V1._RAW
_require = _V1._require
RawValidationError = _V1.RawValidationError
RuntimeRecipeEvidence = _RECIPE.RuntimeRecipeEvidence
INT_MAX, U64 = _V1.INT_MAX, _V1.U64
SOURCE_COMMIT = _V1.SOURCE_COMMIT
PROFILE_MARKER = b'/* glue-stopped-runtime-v1; first-selected-exec; owner-control-snapshots; no-process-creation */\n'
_PROGRAM_TEMPLATE = b'#pragma D option quiet\n/* glue-stopped-runtime-v1; first-selected-exec; owner-control-snapshots; no-process-creation */\n/* owner=@OWNER@ target=@TARGET@ request=@REQUEST_HEX@ catalog=@CATALOG_HEX@ */\nBEGIN {watched[@TARGET@]=1;trace((uint64_t)1);trace((uint64_t)timestamp);trace((uint64_t)pid);trace((uint64_t)tid);trace((uint64_t)(0));}\nEND {trace((uint64_t)17);trace((uint64_t)timestamp);trace((uint64_t)pid);trace((uint64_t)tid);trace((uint64_t)(0));}\nsyscall:::entry /watched[pid] || (pid==@OWNER@ && (probefunc=="proc_info" || probefunc=="wait4" || probefunc=="wait4_nocancel" || probefunc=="kill"))/ {self->call_id=self->call_id+1;self->s0=(uint64_t)arg0;self->s1=(uint64_t)arg1;self->s2=(uint64_t)arg2;self->s3=(uint64_t)arg3;self->s4=(uint64_t)arg4;self->s5=(uint64_t)arg5;selected_exec[pid]=probefunc=="execve"?tid:selected_exec[pid];trace((uint64_t)2);trace((uint64_t)timestamp);trace((uint64_t)pid);trace((uint64_t)tid);trace((uint64_t)(pid==@OWNER@?self->call_id:ppid));trace((uint64_t)arg0);trace((uint64_t)arg1);trace((uint64_t)arg2);trace((uint64_t)arg3);trace((uint64_t)arg4);trace((uint64_t)arg5);trace((uint64_t)arg6);trace((uint64_t)arg7);}\nsyscall:::return /watched[pid]/ {trace((uint64_t)3);trace((uint64_t)timestamp);trace((uint64_t)pid);trace((uint64_t)tid);trace((uint64_t)(ppid));trace((uint64_t)arg0);trace((uint64_t)arg1);trace((uint64_t)arg2);trace((uint64_t)arg3);trace((uint64_t)errno);}\nmach_trap:::entry /watched[pid]/ {trace((uint64_t)15);trace((uint64_t)timestamp);trace((uint64_t)pid);trace((uint64_t)tid);trace((uint64_t)(ppid));trace((uint64_t)arg0);trace((uint64_t)arg1);trace((uint64_t)arg2);trace((uint64_t)arg3);trace((uint64_t)arg4);trace((uint64_t)arg5);trace((uint64_t)arg6);trace((uint64_t)arg7);}\nmach_trap:::return /watched[pid]/ {trace((uint64_t)16);trace((uint64_t)timestamp);trace((uint64_t)pid);trace((uint64_t)tid);trace((uint64_t)(ppid));trace((uint64_t)arg0);}\nproc:::create /watched[pid]/ {watched[pid]=1;trace((uint64_t)4);trace((uint64_t)timestamp);trace((uint64_t)pid);trace((uint64_t)tid);trace((uint64_t)(args[0]->pr_pid));}\nproc:::start /watched[pid]/ {watched[pid]=1;trace((uint64_t)5);trace((uint64_t)timestamp);trace((uint64_t)pid);trace((uint64_t)tid);trace((uint64_t)(ppid));}\nproc:::exec-success /watched[pid]/ {watched[pid]=1;image_seq[pid]=image_seq[pid]+1;pending_tid[pid]=(selected_exec[pid]!=0 && image_seq[pid]==1)?tid:0;selected_exec[pid]=0;trace((uint64_t)7);trace((uint64_t)timestamp);trace((uint64_t)pid);trace((uint64_t)tid);trace((uint64_t)(ppid));}\nproc:::exit /watched[pid]/ {trace((uint64_t)6);trace((uint64_t)timestamp);trace((uint64_t)pid);trace((uint64_t)tid);trace((uint64_t)(arg0));}\nproc:::exec-failure /watched[pid]/ {selected_exec[pid]=0;trace((uint64_t)8);trace((uint64_t)timestamp);trace((uint64_t)pid);trace((uint64_t)tid);trace((uint64_t)(arg0));}\nproc:::lwp-create /watched[pid]/ {trace((uint64_t)9);trace((uint64_t)timestamp);trace((uint64_t)pid);trace((uint64_t)tid);trace((uint64_t)(args[0]->pr_lwpid));}\nproc:::lwp-start /watched[pid]/ {trace((uint64_t)10);trace((uint64_t)timestamp);trace((uint64_t)pid);trace((uint64_t)tid);trace((uint64_t)(0));}\nproc:::lwp-exit /watched[pid]/ {trace((uint64_t)11);trace((uint64_t)timestamp);trace((uint64_t)pid);trace((uint64_t)tid);trace((uint64_t)(0));}\nproc:::spawn-success /watched[pid]/ {trace((uint64_t)12);trace((uint64_t)timestamp);trace((uint64_t)pid);trace((uint64_t)tid);trace((uint64_t)(0));}\nproc:::spawn-failure /watched[pid]/ {trace((uint64_t)13);trace((uint64_t)timestamp);trace((uint64_t)pid);trace((uint64_t)tid);trace((uint64_t)(arg0));}\nproc:::exited /watched[args[0]->pr_pid]/ {trace((uint64_t)18);trace((uint64_t)timestamp);trace((uint64_t)pid);trace((uint64_t)tid);trace((uint64_t)(args[0]->pr_pid));trace((uint64_t)arg1);trace((uint64_t)args[0]->pr_addr);trace((uint64_t)((struct proc *)args[0]->pr_addr)->p_refcount);}\nproc:::lwp-start /watched[pid] && image_seq[pid]==1 && pending_tid[pid]!=0 && pending_tid[pid]==tid/ {trace((uint64_t)19);trace((uint64_t)timestamp);trace((uint64_t)pid);trace((uint64_t)tid);trace((uint64_t)(image_seq[pid]));trace((uint64_t)pending_tid[pid]);trace((uint64_t)17);raise(17);pending_tid[pid]=0;}\nsyscall::proc_info:return /pid==@OWNER@ && (self->s0==3 && (self->s1==@OWNER@ || self->s1==@TARGET@) && self->s2==1 && self->s4!=0 && self->s5==176 && ((self->s1==@TARGET@ && (self->s3==1 || self->s3==2)) || (self->s1==@OWNER@ && self->s3>=3 && self->s3<=2147483647)))/ {trace((uint64_t)20);trace((uint64_t)timestamp);trace((uint64_t)pid);trace((uint64_t)tid);trace((uint64_t)(self->call_id));trace((uint64_t)arg0);trace((uint64_t)arg1);trace((uint64_t)arg2);trace((uint64_t)arg3);trace((uint64_t)errno);tracemem(copyin(self->s4,176),176);}\nsyscall::wait4:return /pid==@OWNER@ && (self->s0==@TARGET@ && self->s1!=0 && (self->s2==3 || self->s2==1) && self->s3==0)/ {trace((uint64_t)21);trace((uint64_t)timestamp);trace((uint64_t)pid);trace((uint64_t)tid);trace((uint64_t)(self->call_id));trace((uint64_t)arg0);trace((uint64_t)arg1);trace((uint64_t)arg2);trace((uint64_t)arg3);trace((uint64_t)errno);tracemem(copyin(self->s1,4),4);}\nsyscall::wait4_nocancel:return /pid==@OWNER@ && (self->s0==@TARGET@ && self->s1!=0 && (self->s2==3 || self->s2==1) && self->s3==0)/ {trace((uint64_t)21);trace((uint64_t)timestamp);trace((uint64_t)pid);trace((uint64_t)tid);trace((uint64_t)(self->call_id));trace((uint64_t)arg0);trace((uint64_t)arg1);trace((uint64_t)arg2);trace((uint64_t)arg3);trace((uint64_t)errno);tracemem(copyin(self->s1,4),4);}\nsyscall::kill:return /pid==@OWNER@/ {trace((uint64_t)22);trace((uint64_t)timestamp);trace((uint64_t)pid);trace((uint64_t)tid);trace((uint64_t)(self->call_id));trace((uint64_t)arg0);trace((uint64_t)arg1);trace((uint64_t)arg2);trace((uint64_t)arg3);trace((uint64_t)errno);}\nsyscall:::return /pid==@OWNER@ && ((probefunc=="proc_info" && !(self->s0==3 && (self->s1==@OWNER@ || self->s1==@TARGET@) && self->s2==1 && self->s4!=0 && self->s5==176 && ((self->s1==@TARGET@ && (self->s3==1 || self->s3==2)) || (self->s1==@OWNER@ && self->s3>=3 && self->s3<=2147483647)))) || ((probefunc=="wait4" || probefunc=="wait4_nocancel") && !(self->s0==@TARGET@ && self->s1!=0 && (self->s2==3 || self->s2==1) && self->s3==0)))/ {trace((uint64_t)23);trace((uint64_t)timestamp);trace((uint64_t)pid);trace((uint64_t)tid);trace((uint64_t)(self->call_id));trace((uint64_t)arg0);trace((uint64_t)arg1);trace((uint64_t)arg2);trace((uint64_t)arg3);trace((uint64_t)errno);}\n'


def expected_stopped_program(owner_pid: int, target_pid: int,
                             request_sha256: bytes, catalog_sha256: bytes) -> bytes:
    """Pure fixed formatting; no producer import or caller-provided template."""
    _RAW._integer(owner_pid, 1, INT_MAX, 'stopped program owner PID')
    _RAW._integer(target_pid, 1, INT_MAX, 'stopped program target PID')
    _require(owner_pid != target_pid, 'stopped distinct program PIDs')
    for digest in (request_sha256, catalog_sha256):
        _require(type(digest) is bytes and len(digest) == 32 and any(digest),
                 'stopped nonzero exact program digest')
    return (_PROGRAM_TEMPLATE.replace(b'@OWNER@', str(owner_pid).encode('ascii'))
            .replace(b'@TARGET@', str(target_pid).encode('ascii'))
            .replace(b'@REQUEST_HEX@', request_sha256.hex().encode('ascii'))
            .replace(b'@CATALOG_HEX@', catalog_sha256.hex().encode('ascii')))


@dataclass(frozen=True)
class DiagnosticGap:
    code: str
    source_ordinal: Optional[int]
    message: str


@dataclass(frozen=True)
class OwnerControl:
    call_id: int
    entry: object
    returned: Optional[object]
    memory: bytes
    outcome: str
    primary_result: Optional[int]
    kernel_errno: Optional[int]
    unsupported_reasons: tuple[str, ...]


@dataclass(frozen=True)
class DiagnosticPhaseAccounting:
    source_ordinal: int
    role: str
    control_index: Optional[int] = None


@dataclass(frozen=True)
class QueryCorrelation:
    query_index: int
    control_index: int
    entry_ordinal: int
    return_ordinal: int
    next_owner_entry_ordinal: Optional[int]
    lookup_window: tuple[int, int]
    buffer_completion_window: Optional[tuple[int, int]]
    original_buffer_address: int
    original_payload_sha256: str
    native_origin_authenticated: bool = False
    exact_copy_time_observed: bool = False


@dataclass(frozen=True)
class WaitCorrelation:
    wait_index: int
    control_index: int
    entry_ordinal: int
    return_ordinal: int
    trace_window: tuple[int, int]
    original_status_bits: int
    status_semantically_valid: bool
    status_buffer_address_authenticated: bool = False
    native_origin_authenticated: bool = False


@dataclass(frozen=True)
class RuntimeStoppedDiagnostic:
    protocol: str
    status: str
    source: object
    launch: object
    original_outputs: object
    original_go_delivery: object
    observer: object
    images: Optional[object]
    owner_controls: tuple[OwnerControl, ...]
    phase_accounting: tuple[DiagnosticPhaseAccounting, ...]
    selected_marker_ordinal: Optional[int]
    query_correlations: tuple[QueryCorrelation, ...]
    wait_correlations: tuple[WaitCorrelation, ...]
    intended_continue_control: Optional[int]
    gaps: tuple[DiagnosticGap, ...]
    native_origin_authenticated: bool = False
    raw_origin_authenticated: bool = False
    quiescence_proved: bool = False
    ofd_identity_proved: bool = False
    descriptor_generation_proved: bool = False
    state_feed_eligible: bool = False
    authorizes_sink_exemptions: bool = False
    full_flags_proved: bool = False
    full_trace_acceptance: bool = False
    retention_before_continue_proved: bool = False
    c_and_trace_clock_origins_calibrated: bool = False
    foreign_controller_excluded: bool = False

    def to_dict(self):
        return _V1._plain(self)


def _gap(code, ordinal, message):
    return DiagnosticGap(code, ordinal, message)


def _qsafe(args, owner, target):
    return (args[0] == 3 and args[1] in (owner, target) and args[2] == 1 and
            args[4] != 0 and args[5] == 176 and
            (args[1] == target and args[3] in (1, 2) or
             args[1] == owner and 3 <= args[3] <= INT_MAX))


def _wsafe(args, target):
    return args[0] == target and args[1] != 0 and args[2] in (1, 3) and args[3] == 0


def _return_class(name, args, owner, target):
    if name == 'proc_info':
        return 20 if _qsafe(args, owner, target) else 23
    if name in ('wait4', 'wait4_nocancel'):
        return 21 if _wsafe(args, target) else 23
    return 22


def _outcome(returned):
    a, b, secondary, error, errno = returned.raw_scalars[5:]
    if a == b and secondary == error == errno == 0 and a <= INT_MAX:
        return 'kernel-success', a, None, ()
    if a == b == secondary == U64 and 1 <= error == errno <= INT_MAX:
        return 'kernel-error', None, error, ()
    return 'unsupported', None, None, ('noncanonical fixed scalar owner outcome',)


def _owner_controls(capture, owner, target):
    memory = {row.source_ordinal: row.payload for row in capture.memory}
    entries, pending, returned_rows, orphan_returns, gaps = [], {}, {}, [], []
    call_ids, controller_tid = {}, None
    roles = {}
    for phase in capture.phases:
        kind, timestamp, pid, tid, detail = phase.raw_scalars[:5]
        if kind == 2 and pid == owner:
            if controller_tid is None:
                controller_tid = tid
            elif controller_tid != tid:
                gaps.append(_gap('owner-thread', phase.ordinal, 'more than one owner control thread'))
            if detail != call_ids.get(tid, 0) + 1:
                gaps.append(_gap('owner-call-id', phase.ordinal, 'missing/duplicate/noninitial owner call ID'))
            call_ids[tid] = detail
            index = len(entries)
            entries.append(phase)
            key = (tid, detail)
            if any(key_tid == tid for key_tid, _ in pending):
                gaps.append(_gap('owner-overlap', phase.ordinal, 'owner entry before earlier return'))
            if key in pending:
                gaps.append(_gap('owner-call-id', phase.ordinal, 'duplicate pending owner call ID'))
            pending[key] = index
            roles[phase.ordinal] = DiagnosticPhaseAccounting(phase.ordinal, 'owner-control-entry', index)
        elif kind in (20, 21, 22, 23):
            key = (tid, detail)
            index = pending.get(key)
            if index is None:
                gaps.append(_gap('owner-orphan-return', phase.ordinal, 'owner return has no original pending entry'))
                orphan_returns.append(phase)
                roles[phase.ordinal] = DiagnosticPhaseAccounting(phase.ordinal, 'unpaired-owner-return')
                continue
            entered = entries[index]
            if (entered.provider, entered.module, entered.function) != (phase.provider, phase.module, phase.function):
                gaps.append(_gap('owner-return-identity', phase.ordinal, 'owner return differs from pending call'))
                orphan_returns.append(phase)
                roles[phase.ordinal] = DiagnosticPhaseAccounting(phase.ordinal, 'unpaired-owner-return')
                continue
            del pending[key]
            returned_rows[index] = phase
            roles[phase.ordinal] = DiagnosticPhaseAccounting(phase.ordinal, 'owner-control-return', index)
    controls, last_returns = [], {}
    for index, entered in enumerate(entries):
        returned = returned_rows.get(index)
        reasons = []
        tid = entered.raw_scalars[3]
        if entered.raw_scalars[1] < last_returns.get(tid, 0):
            reasons.append('owner entry precedes previous return on same thread')
        if returned is None:
            outcome, result, errno = 'unpaired', None, None
            reasons.append('owner entry has no uniquely associated return')
        else:
            if returned.raw_scalars[1] < entered.raw_scalars[1]:
                reasons.append('owner call clock runs backwards')
            expected = _return_class(entered.function, entered.raw_scalars[5:], owner, target)
            if returned.raw_scalars[0] != expected:
                reasons.append('owner return class differs from original argument shape')
            outcome, result, errno, invalid = _outcome(returned)
            reasons.extend(invalid)
            last_returns[tid] = returned.raw_scalars[1]
            if outcome == 'kernel-success':
                if entered.function == 'kill' and result != 0:
                    reasons.append('fixed kill success must return zero')
                elif entered.function in ('wait4', 'wait4_nocancel') and result not in (0, target):
                    reasons.append('wait for actual child returned another PID')
                elif entered.function == 'proc_info' and expected == 20 and result != 176:
                    reasons.append('fixed vnode handler success must return176')
            if expected == 23:
                reasons.append('unsafe/unexpected owner arguments retained without memory interpretation')
        for reason in reasons:
            gaps.append(_gap('owner-control', entered.ordinal, reason))
        controls.append(OwnerControl(entered.raw_scalars[4], entered, returned,
            b'' if returned is None else memory.get(returned.ordinal, b''),
            outcome, result, errno, tuple(reasons)))
    return tuple(controls), roles, gaps


def _native_query_bytes(query):
    if query.flags & 4:
        return query.payload
    result, offset = bytearray(), 0
    for _, width, _ in _PX._FIELDS:
        result += query.payload[offset:offset + width][::-1]
        offset += width
    _require(offset == 176, 'stopped fixed observer field size')
    return bytes(result)


def _matches_query(control, query, owner):
    args = control.entry.raw_scalars[5:]
    if (control.entry.function != 'proc_info' or control.returned is None or
            control.returned.raw_scalars[0] != 20 or control.unsupported_reasons or
            args[:6] != (3, query.pid, 1, query.fd, query.buffer_address, 176) or
            control.entry.raw_scalars[2] != owner or control.memory != _native_query_bytes(query)):
        return False
    if control.outcome == 'kernel-success':
        return control.primary_result == query.result == 176 and query.saved_errno == 0
    return (control.outcome == 'kernel-error' and query.result == 0 and
            query.saved_errno == control.kernel_errno)


def _matches_wait(control, wait, target):
    args = control.entry.raw_scalars[5:]
    if (control.entry.function not in ('wait4', 'wait4_nocancel') or
            control.returned is None or control.returned.raw_scalars[0] != 21 or
            control.unsupported_reasons or args[0] != target or args[1] == 0 or
            args[2:4] != (3, 0) or len(control.memory) != 4 or
            int.from_bytes(control.memory, 'little') != (wait.status & 0xffffffff)):
        return False
    if control.outcome == 'kernel-success':
        return control.primary_result == wait.returned_pid and wait.saved_errno == 0
    return (control.outcome == 'kernel-error' and wait.returned_pid == -1 and
            wait.saved_errno == control.kernel_errno)


def _accounting(capture, owner_roles, images):
    roles = dict(owner_roles)

    def note(phase, role):
        if phase is not None and phase.ordinal not in roles:
            roles[phase.ordinal] = DiagnosticPhaseAccounting(phase.ordinal, role)

    if images is not None:
        for pair in images.pairs:
            note(pair.entry, 'child-image-entry')
            note(pair.returned, 'child-image-return')
        if images.attachment_return is not None:
            note(images.attachment_return.phase, 'validated-child-attachment-return')
        for transition in images.transitions:
            for phase, role in ((transition.entry, 'selected-exec-entry'),
                                (transition.returned, 'selected-exec-return-context'),
                                (transition.success, 'selected-exec-success'),
                                (transition.proc_start, 'selected-proc-start'),
                                (transition.lwp_start, 'selected-lwp-start')):
                note(phase, role)
        for binding in images.lifecycle_bindings:
            if binding.source_ordinal not in roles:
                roles[binding.source_ordinal] = DiagnosticPhaseAccounting(binding.source_ordinal, binding.role)
        for shadow in images.unbound_shadows:
            note(shadow.source, 'unbound-nonlive-shadow-context')
        if images.terminating_call is not None:
            note(images.terminating_call.entry, 'nonreturning-child-exit-entry')
            note(images.terminating_call.exit_context, 'nonreturning-child-exit-context')
    for phase in capture.phases:
        kind = phase.raw_scalars[0]
        role = ('stop-action-request-marker' if kind == 19 else
                'opaque-mach-original' if kind in (15, 16) else
                'unresolved-child-entry' if kind == 2 else
                'unresolved-child-return' if kind == 3 else 'original-lifecycle-context')
        note(phase, role)
    _require(set(roles) == {phase.ordinal for phase in capture.phases}, 'stopped whole phase accounting')
    return tuple(roles[phase.ordinal] for phase in capture.phases)


def _correlate(capture, controls, observer, images, owner, target):
    gaps, queries, waits = [], [], []
    markers = [phase for phase in capture.phases if phase.raw_scalars[0] == 19]
    marker = markers[0] if len(markers) == 1 else None
    if marker is None:
        gaps.append(_gap('stop-marker', None, 'requires exactly one original stop-request marker'))
    if len(images.transitions) != 1:
        gaps.append(_gap('image-bound', None, 'first diagnostic accepts exactly one selected exec'))
    first = images.transitions[0]
    new_tid = first.success.raw_scalars[3]
    if observer.exec_ordinal != first.success.ordinal or observer.new_tid != new_tid:
        gaps.append(_gap('observer-image-binding', first.success.ordinal,
                         'observer declaration differs from original selected exec/new TID'))
    if marker is not None and (marker.ordinal <= first.success.ordinal or
            marker.raw_scalars[3] != new_tid or
            marker.raw_scalars[5:] != (new_tid, 17) or
            marker.probe_id != first.lwp_start.probe_id or
            marker.raw_scalars[1] < first.success.raw_scalars[1]):
        gaps.append(_gap('stop-marker', marker.ordinal, 'marker differs from exact selected new-image latch'))
    if observer.state != 2 or not observer.conditional_backing_match:
        gaps.append(_gap('observer-refused', None, 'original observer did not complete a conditional match'))
    candidates = [i for i, control in enumerate(controls)
                  if observer.queries and _matches_query(control, observer.queries[0], owner)]
    if len(candidates) != 1:
        gaps.append(_gap('query-prefix', None, 'first original query has no unique raw control association'))
        return marker, tuple(queries), tuple(waits), None, gaps
    start = candidates[0]
    matched = set()
    for qindex, query in enumerate(observer.queries):
        index = start + qindex
        if index >= len(controls) or not _matches_query(controls[index], query, owner):
            gaps.append(_gap('query-prefix', None, 'original query prefix differs from contiguous raw controls'))
            break
        control = controls[index]
        following = controls[index + 1].entry if index + 1 < len(controls) else None
        entry_time, return_time = control.entry.raw_scalars[1], control.returned.raw_scalars[1]
        completion = None
        if following is not None:
            next_time = following.raw_scalars[1]
            if following.raw_scalars[3] != control.entry.raw_scalars[3] or next_time < return_time:
                gaps.append(_gap('query-copy-bound', control.entry.ordinal,
                                 'next owner entry cannot bound original buffer-copy completion'))
            else:
                completion = (entry_time, next_time)
        else:
            gaps.append(_gap('query-copy-bound', control.entry.ordinal, 'no next owner entry bounds buffer copying'))
        queries.append(QueryCorrelation(qindex, index, control.entry.ordinal, control.returned.ordinal,
            None if following is None else following.ordinal, (entry_time, return_time), completion,
            query.buffer_address, hashlib.sha256(control.memory).hexdigest()))
        matched.add(index)
    wstart = start - len(observer.waits)
    if wstart < 0:
        gaps.append(_gap('wait-prefix', None, 'raw stream lacks the original wait journal prefix'))
    else:
        for windex, wait in enumerate(observer.waits):
            index = wstart + windex
            if not _matches_wait(controls[index], wait, target):
                gaps.append(_gap('wait-prefix', controls[index].entry.ordinal,
                                 'original wait journal differs from raw options/result/status prefix'))
                break
            control = controls[index]
            waits.append(WaitCorrelation(windex, index, control.entry.ordinal, control.returned.ordinal,
                (control.entry.raw_scalars[1], control.returned.raw_scalars[1]), wait.status & 0xffffffff,
                bool(wait.flags & 32)))
            matched.add(index)
        if waits:
            accepted = controls[wstart + len(waits) - 1]
            if marker is not None and accepted.returned.raw_scalars[1] < marker.raw_scalars[1]:
                gaps.append(_gap('stale-stop', accepted.returned.ordinal, 'accepted stop precedes selected marker'))
    continue_index = None
    after = start + len(observer.queries)
    if after < len(controls):
        control = controls[after]
        args = control.entry.raw_scalars[5:]
        if (control.entry.function == 'kill' and args[:3] == (target, 19, 1) and
                control.returned is not None and control.returned.raw_scalars[0] == 22):
            continue_index = after
            matched.add(after)
            if control.unsupported_reasons or control.outcome != 'kernel-success' or control.primary_result != 0:
                gaps.append(_gap('continue-failed', control.entry.ordinal, 'actual intended continue did not return success'))
    if continue_index is None:
        gaps.append(_gap('continue-absent', None, 'no immediately subsequent actual intended SIGCONT control'))
    # This is diagnostic correlation, not a finite runtime effect permission.
    # Any live new-image call before the prospective cut contradicts this first
    # episode's pre-user stop boundary; later operations grant no exemptions.
    cut = controls[continue_index].entry.raw_scalars[1] if continue_index is not None else None
    first_query_time = controls[start].entry.raw_scalars[1]
    last_copy_bound = queries[-1].buffer_completion_window if queries else None
    for phase in capture.phases:
        kind = phase.raw_scalars[0]
        live_exit = kind == 6 or kind == 18 and not phase.raw_scalars[7] & _RAW.SHADOW_BIT
        if live_exit and (cut is None or phase.raw_scalars[1] <= cut):
            gaps.append(_gap('child-exit-before-continue', phase.ordinal,
                             'live target exit precedes intended continue or sampling completion'))
    for thread in images.threads:
        if thread.image_epoch != 1 or thread.tid == new_tid:
            continue
        origin = thread.declaration if thread.declaration is not None else thread.start
        if origin is not None and (cut is None or origin.raw_scalars[1] <= cut):
            gaps.append(_gap('thread-progress-before-continue', origin.ordinal,
                             'additional new-image thread is declared before intended continue'))
    for pair in images.pairs:
        if pair.image_epoch == 0:
            continue
        lo, hi = pair.entry.raw_scalars[1], pair.returned.raw_scalars[1]
        if cut is None or lo <= cut:
            gaps.append(_gap('child-progress-before-continue', pair.entry.ordinal,
                             'new-image operation precedes/touches intended continue; no retroactive write grant'))
        if last_copy_bound is not None and not (hi < first_query_time or last_copy_bound[1] < lo):
            gaps.append(_gap('sampling-window-conflict', pair.entry.ordinal,
                             'closed live child call interval intersects original sampling/copy window'))
    for index, control in enumerate(controls):
        args = control.entry.raw_scalars[5:]
        if index in matched:
            continue
        if control.entry.function == 'kill':
            if args[:3] != (target, 9, 1):
                gaps.append(_gap('unmatched-owner-control', control.entry.ordinal, 'unexpected owner signal'))
        elif control.entry.function in ('wait4', 'wait4_nocancel'):
            if args[0] != target or args[2:4] != (1, 0):
                gaps.append(_gap('unmatched-owner-control', control.entry.ordinal,
                                 'unmatched wait is not fixed cleanup context'))
        else:
            gaps.append(_gap('unmatched-owner-control', control.entry.ordinal,
                             'owner query is not part of original observer prefix'))
    return marker, tuple(queries), tuple(waits), continue_index, gaps


def _owner_lifecycle(controls, target):
    # Conditional source bookkeeping only. Never turns a PID into signalling
    # authority, and remains checked even for failed/uncorrelated PX prefixes.
    owned, gaps = True, []
    for control in controls:
        name = control.entry.function
        args = control.entry.raw_scalars[5:]
        if name == 'kill':
            if not owned:
                gaps.append(_gap('signal-after-retirement', control.entry.ordinal,
                                 'owner signal follows terminal wait/ECHILD or unresolved wait state'))
            if args[0] != target or args[1] not in (9, 19) or args[2] != 1:
                gaps.append(_gap('unsupported-owner-signal', control.entry.ordinal,
                                 'signal is not fixed UNIX03 owned-child CONT/cleanup'))
        elif name in ('wait4', 'wait4_nocancel'):
            if control.outcome == 'kernel-error' and control.kernel_errno == 10:
                owned = False
            elif control.outcome == 'kernel-success' and control.primary_result == target:
                if len(control.memory) != 4:
                    owned = False
                else:
                    status = int.from_bytes(control.memory, 'little')
                    if status & 0x7f != 0x7f:
                        owned = False
                    elif args[2] == 1:
                        gaps.append(_gap('unexpected-cleanup-stop', control.entry.ordinal,
                                         'untraced cleanup wait without WUNTRACED returned a stop'))
    return gaps


def pair_runtime_stopped_raw(program: bytes, probes: bytes, errors: bytes,
                             event_lines: Iterable[bytes], *, owner_pid: int, target_pid: int,
                             contract_bytes: bytes, launch_evidence: RuntimeRecipeEvidence,
                             output_observation: bytes) -> RuntimeStoppedDiagnostic:
    """Consume one original outer capture and correlate one conditional episode.

    No future continue packet, profile, capture or stopped/match boolean input
    exists. Raw kill calls describe actual intended control only; no durable
    observation-before-CONT or native/state/output permission is established.
    """
    launch, outputs, delivery = _RECIPE._validated_recipe_assets(launch_evidence, owner_pid, target_pid)
    try:
        observer = _PX.decode_observation(output_observation, launch_evidence.output_witness)
    except (ValueError, TypeError) as error:
        raise RawValidationError('stopped original observer bytes: ' + str(error)) from error
    _require(observer.owner_pid == owner_pid and observer.child_pid == target_pid and
             observer.request_sha256 == hashlib.sha256(launch_evidence.request).hexdigest() and
             observer.catalog_sha256 == hashlib.sha256(launch_evidence.catalog).hexdigest() and
             observer.ready_sha256 == hashlib.sha256(launch_evidence.status_stream[:512]).hexdigest() and
             observer.program_sha256 == hashlib.sha256(program).hexdigest(),
             'stopped observer original asset/program bindings')
    _V1._bytes(contract_bytes, _RAW.CONTRACT_BYTES, _RAW.CONTRACT_BYTES, 'pinned contract bytes')
    _require(hashlib.sha256(contract_bytes).hexdigest() == _RAW.CONTRACT_SHA256, 'pinned contract digest')
    table = _RAW._CONTRACT_HELPERS.parse_table(contract_bytes)
    required = expected_stopped_program(owner_pid, target_pid,
        hashlib.sha256(launch_evidence.request).digest(), hashlib.sha256(launch_evidence.catalog).digest())
    capture = _V1._transport_stopped(program, probes, errors, event_lines, owner_pid, target_pid, required)
    controls, owner_roles, gaps = _owner_controls(capture, owner_pid, target_pid)
    gaps.extend(_owner_lifecycle(controls, target_pid))
    try:
        images = _IMAGES._pair_capture(capture, launch, table,
                                       skipped_ordinals=capture.image_skip_ordinals)
    except _IMAGES.ImageValidationError as error:
        images = None
        gaps.append(_gap('image-coverage', None, str(error)))
    marker, queries, waits, continued = None, (), (), None
    if images is not None:
        marker, queries, waits, continued, failures = _correlate(capture, controls, observer,
                                                               images, owner_pid, target_pid)
        gaps.extend(failures)
    accounting = _accounting(capture, owner_roles, images)
    status = 'incomplete' if gaps else 'source-conditional-correlated'
    return RuntimeStoppedDiagnostic('darwin-runtime-stopped-output-diagnostic-v1', status,
        capture, launch, outputs, delivery, observer, images, controls, accounting,
        None if marker is None else marker.ordinal, queries, waits, continued, tuple(gaps))
