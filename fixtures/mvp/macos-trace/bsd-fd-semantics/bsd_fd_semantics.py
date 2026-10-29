"""Executable source rules for eleven owned BSD descriptor operations.

Conditional postconditions require native/object/lifetime/ordering witnesses.
No numeric descriptor or successful result alone supplies those witnesses.
"""
from dataclasses import dataclass, fields, is_dataclass
import hashlib
import importlib.util
import json
from pathlib import Path
from types import MappingProxyType
from typing import Iterable, Optional


_BASE = Path(__file__).resolve().parent.parent
DEPENDENCY_IDENTITIES = (
    ('owned-trace-check/owned_trace_check.py',
     '1d8616b51002225c8b9abf4a18940c48f01d1ef97a3f7c54e120153ca8c978ec'),
    ('syscall-contract/syscall_contract.py',
     '35a4229894dd0373de1b312747e8acd1a23ae2074566391e8d28855ca0624dbf'),
    ('bsd-entry-abi/bsd_entry_abi.py',
     '1cd28940f18c5ca7d1d6af13e653cc985fc3afa9ce98e6516b11dbcbcf8dcf17'),
    ('bsd-outcomes/bsd_outcomes.py',
     'cf3f85d71d870ade4a8cb62441d4c856c036f65a574b0dce20b1d0d188ba36ef'),
)
# Verify every executable dependency before the first ordinary import. A stable
# trusted checkout is assumed; no caller path/profile or helper is accepted.
for _relative, _digest in DEPENDENCY_IDENTITIES:
    with (_BASE / _relative).open('rb') as _stream:
        _code = _stream.read(65537)
    if len(_code) > 65536 or hashlib.sha256(_code).hexdigest() != _digest:
        raise ValueError('BSD FD semantics dependency identity differs: ' + _relative)
del _relative, _digest, _stream, _code


def _import_fixed(name, relative):
    spec = importlib.util.spec_from_file_location(name, _BASE / relative)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


_RAW = _import_fixed('_fd_semantics_owned_raw', 'owned-trace-check/owned_trace_check.py')
_ENTRY = _import_fixed('_fd_semantics_entry_abi', 'bsd-entry-abi/bsd_entry_abi.py')
_OUTCOME = _import_fixed('_fd_semantics_outcomes', 'bsd-outcomes/bsd_outcomes.py')
RawValidationError = _RAW.RawValidationError
INT_MAX = (1 << 31) - 1
SOURCE_COMMIT = 'f6217f891ac0bb64f3d375211650a4c1ff8ca1ea'
SOURCE_IDENTITIES = (
    ('bsd/kern/kern_descrip.c',
     '480cfed4e987be874bd71fb6933c254adf9fb1f36de8496dee8f351b18da13b1'),
    ('bsd/kern/sys_generic.c',
     '6bf3e35160701519d433f5a2269f8220646459e2b131816de7408fb7d5505c2c'),
    ('bsd/kern/syscalls.master',
     '7e866891439ad5b3464777d2cacc3b82fc2e7f439fb5a8686c3e6f160d5aeab5'),
    ('bsd/dev/arm/systemcalls.c',
     '7eb44232e6da37c8e6f5d2317ed5cf1d55d02032410b0ddf7007e4ca7b495df4'),
    ('bsd/dev/i386/systemcalls.c',
     '7822b31e4f62fcd5f2baeb7fc41fde518b1f44b98fab3908594e18ee2c48426f'),
    ('bsd/vfs/vfs_syscalls.c',
     'b30d68fb85f34b864b5e71e3127541c2674e0fb52e59d6ee072c8b0ecbb46a4f'),
    ('bsd/kern/posix_shm.c',
     '68556983aade7abb1dd0159e6d5fcd1b00068cc0881eaf506c7454e2e6552fbe'),
)
INTERPRETATION_PROFILE = 'pinned-xnu-lp64-bsd-fd-semantics-v1'
OPERATION_NAMES = (
    ('close', 'fd-close', 'descriptor-state-attempt'),
    ('close_nocancel', 'fd-close', 'descriptor-state-attempt'),
    ('dup', 'fd-dup', 'descriptor-state-attempt'),
    ('dup2', 'fd-dup2', 'descriptor-state-attempt'),
    ('write', 'fd-write', 'payload-write-attempt'),
    ('write_nocancel', 'fd-write', 'payload-write-attempt'),
    ('pwrite', 'fd-pwrite', 'payload-write-attempt'),
    ('pwrite_nocancel', 'fd-pwrite', 'payload-write-attempt'),
    ('fsync', 'fd-flush', 'flush-attempt'),
    ('fsync_nocancel', 'fd-flush', 'flush-attempt'),
    ('ftruncate', 'fd-truncate', 'truncate-attempt'),
)
_OPERATIONS = MappingProxyType({name: (operation, attempt)
                              for name, operation, attempt in OPERATION_NAMES})
MISSING_CAPABILITIES = (
    'installed native ABI and provider/source coverage calibration',
    'descriptor generations and kernel lookup/chosen open-file-description binding',
    'initial objects, process/image lifetimes and concurrent mutation ordering',
    'filesystem/backing/namespace identities and application-output policy',
    'complete operation coverage and extraction policy resolution',
)
_CONDITIONAL_GAPS = (
    'conditional rule needs calibrated kernel lookup/object/lifetime witnesses',
    'call interval does not establish effect linearization or slot state at return',
    'application-output binding and extraction policy remain unresolved',
)


@dataclass(frozen=True)
class FdRequest:
    operation: Optional[str]
    attempt_kind: str
    fd: Optional[int] = None
    source_fd: Optional[int] = None
    target_fd: Optional[int] = None
    buffer_address: Optional[int] = None
    requested_bytes: Optional[int] = None
    requested_offset: Optional[int] = None
    requested_length: Optional[int] = None
    position_mode: Optional[str] = None
    entry_attempt_observed: bool = True


@dataclass(frozen=True)
class ConditionalPostcondition:
    kind: str
    subject_fd: Optional[int] = None
    source_fd: Optional[int] = None
    target_fd: Optional[int] = None
    ofd_relation: Optional[str] = None
    cloexec_rule: Optional[str] = None
    allocation_rule: Optional[str] = None
    reported_bytes: Optional[int] = None
    position_mode: Optional[str] = None
    requested_offset: Optional[int] = None
    requested_length: Optional[int] = None
    object_domain: Optional[str] = None
    required_witnesses: tuple[str, ...] = _CONDITIONAL_GAPS


@dataclass(frozen=True)
class FdOperation:
    source_pair_index: int
    correlation_id: tuple[int, int]
    source_name: str
    arguments: tuple[_ENTRY.ArgumentAbi, ...]
    request: FdRequest
    outcome: _OUTCOME.BsdOutcome
    status: str
    postcondition: Optional[ConditionalPostcondition]
    unsupported_reasons: tuple[str, ...]
    effect_uncertainties: tuple[str, ...]


@dataclass(frozen=True)
class SemanticsCounts:
    bsd_pairs: int
    recognized_operation_pairs: int
    unknown_bsd_pairs: int
    known_unhandled_pairs: int
    source_consistent_successes: int
    kernel_errors: int
    unsupported: int
    uninterpreted_mach_pairs: int


def _plain(value):
    if is_dataclass(value):
        return {field.name: _plain(getattr(value, field.name)) for field in fields(value)}
    if isinstance(value, tuple):
        return [_plain(item) for item in value]
    return value


@dataclass(frozen=True)
class OwnedFdSemantics:
    protocol: str
    status: str
    source: _RAW.OwnedCallPairs
    operations: tuple[FdOperation, ...]
    counts: SemanticsCounts
    interpretation_profile: str = INTERPRETATION_PROFILE
    source_commit: str = SOURCE_COMMIT
    source_identities: tuple[tuple[str, str], ...] = SOURCE_IDENTITIES
    dependency_identities: tuple[tuple[str, str], ...] = DEPENDENCY_IDENTITIES
    argument_interpretation_profile: str = _ENTRY.INTERPRETATION_PROFILE
    outcome_interpretation_profile: str = _OUTCOME.INTERPRETATION_PROFILE
    missing_capabilities: tuple[str, ...] = MISSING_CAPABILITIES
    native_abi_calibrated: bool = False
    successful_effect_ordering: bool = False
    state_feed_eligible: bool = False
    full_trace_acceptance: bool = False

    def to_dict(self):
        return _plain(self)


def _request(operation, attempt, arguments):
    values = tuple(argument.value for argument in arguments)
    if operation in ('fd-close', 'fd-flush'):
        return FdRequest(operation, attempt, fd=values[0])
    if operation == 'fd-dup':
        return FdRequest(operation, attempt, source_fd=values[0])
    if operation == 'fd-dup2':
        return FdRequest(operation, attempt, source_fd=values[0], target_fd=values[1])
    if operation in ('fd-write', 'fd-pwrite'):
        return FdRequest(operation, attempt, fd=values[0], buffer_address=values[1],
            requested_bytes=values[2], requested_offset=values[3] if operation == 'fd-pwrite' else None,
            position_mode='explicit' if operation == 'fd-pwrite' else 'implicit')
    if operation == 'fd-truncate':
        return FdRequest(operation, attempt, fd=values[0], requested_length=values[1])
    return FdRequest(None, 'unmodeled-bsd-attempt')


def _failure_uncertainties(operation):
    details = {
        'fd-close': 'descriptor slot may already be released before close reports an error',
        'fd-dup': 'descriptor/object lifetime and concurrent table effects remain unresolved',
        'fd-dup2': 'target may already be closed or reserved before duplication fails',
        'fd-write': 'partial written bytes may be hidden by provider failure results',
        'fd-pwrite': 'partial written bytes may be hidden by provider failure results',
        'fd-flush': 'partial durability or metadata effects remain unresolved',
        'fd-truncate': 'partial size, backing or metadata effects remain unresolved',
    }
    return ('kernel error does not establish absence of effects', details[operation])


def _success_rule(request, outcome):
    operation, primary = request.operation, outcome.primary_result
    reasons = []
    if operation in ('fd-close', 'fd-flush', 'fd-truncate'):
        if primary != 0:
            reasons.append('this operation requires zero primary success result')
        if request.fd < 0:
            reasons.append('claimed success has a negative signed descriptor')
    if operation in ('fd-close', 'fd-flush', 'fd-truncate', 'fd-dup', 'fd-dup2'):
        # Both LP64 dispatchers initialize rv[1]; these closed handlers modify
        # only rv[0] or leave the storage unused (including pshm_truncate).
        if outcome.secondary_result != 0:
            reasons.append('closed int operation has nonzero initialized secondary result')
    if operation == 'fd-dup':
        if primary < 0 or primary == request.source_fd:
            reasons.append('dup success requires a distinct nonnegative descriptor')
    if operation == 'fd-dup2' and primary != request.target_fd:
        reasons.append('dup2 success differs from its requested target descriptor')
    if operation in ('fd-write', 'fd-pwrite'):
        if request.fd < 0:
            reasons.append('claimed write success has a negative signed descriptor')
        if not 0 <= primary <= request.requested_bytes <= INT_MAX:
            reasons.append('write success requires 0 <= reported <= requested <= INT_MAX')
        if operation == 'fd-pwrite' and request.requested_offset == -1:
            reasons.append('pwrite wrapper rejects requested offset -1 before I/O')
    if operation == 'fd-truncate' and request.requested_length < 0:
        reasons.append('truncate wrapper rejects negative requested length')
    if reasons:
        return None, tuple(reasons)
    if operation == 'fd-close':
        return ConditionalPostcondition('release-descriptor-slot', subject_fd=request.fd), ()
    if operation == 'fd-dup':
        return ConditionalPostcondition('create-descriptor-alias', source_fd=request.source_fd,
            target_fd=primary, ofd_relation='kernel-chosen-shared-open-file-description',
            cloexec_rule='cleared', allocation_rule='lowest-free-at-allocation-point'), ()
    if operation == 'fd-dup2':
        same = request.source_fd == request.target_fd
        return ConditionalPostcondition('preserve-same-descriptor' if same else 'replace-target-with-alias',
            source_fd=request.source_fd, target_fd=request.target_fd,
            ofd_relation='same-descriptor' if same else 'kernel-chosen-shared-open-file-description',
            cloexec_rule='preserved' if same else 'cleared',
            allocation_rule='no-allocation' if same else 'requested-target'), ()
    if operation in ('fd-write', 'fd-pwrite'):
        return ConditionalPostcondition('reported-write-bytes', subject_fd=request.fd,
            reported_bytes=primary, position_mode=request.position_mode,
            requested_offset=request.requested_offset, object_domain='unresolved-fileops-target'), ()
    if operation == 'fd-flush':
        return ConditionalPostcondition('file-integrity-flush', subject_fd=request.fd,
                                         object_domain='vnode'), ()
    return ConditionalPostcondition('object-specific-truncate', subject_fd=request.fd,
        requested_length=request.requested_length, object_domain='vnode-or-posix-shared-memory',
        required_witnesses=_CONDITIONAL_GAPS + (
            'vnode-versus-POSIX-shm branch, page size, prior allocation and object lifetime semantics',)), ()


def _decode_operation(index, pair, calls, return_types):
    call = calls.get(pair.entry.function)
    arguments = () if call is None else tuple(_ENTRY._decode_argument(position, declaration,
        tuple(role for role, selected in call['selectors'].items() if selected == position),
        pair.entry.raw_scalars[5 + position])
        for position, declaration in enumerate(call['arguments']))
    operation, attempt = _OPERATIONS.get(pair.entry.function, (None, 'unmodeled-bsd-attempt'))
    request = _request(operation, attempt, arguments)
    outcome = _OUTCOME._decode_pair(index, pair, return_types)
    reasons = []
    if operation is None:
        reasons.append('unknown BSD declaration' if call is None else 'known BSD operation has no handled semantic rule')
    if any(argument.unsupported_reason is not None for argument in arguments):
        reasons.append('one or more arguments lack supported canonical typing')
    if outcome.disposition == 'unsupported':
        reasons.append(outcome.unsupported_reason or 'unsupported provider outcome')
    if operation in ('fd-dup', 'fd-dup2'):
        # Kernel implementations receive int descriptors; do not guess the
        # implementation-defined unsigned-to-int conversion for larger inputs.
        if (request.source_fd is not None and request.source_fd > INT_MAX
                or request.target_fd is not None and request.target_fd > INT_MAX):
            reasons.append('unsigned descriptor exceeds supported nonnegative signed domain')
    postcondition = None
    if not reasons and outcome.disposition == 'kernel-success':
        postcondition, invalid = _success_rule(request, outcome)
        reasons.extend(invalid)
    if reasons:
        status, uncertainties = 'unsupported', ('operation/effect interpretation unavailable',)
    elif outcome.disposition == 'kernel-error':
        status, uncertainties = 'kernel-error', _failure_uncertainties(operation)
    else:
        status, uncertainties = 'source-consistent', _CONDITIONAL_GAPS
    return FdOperation(index, pair.correlation_id, pair.entry.function, arguments,
        request, outcome, status, postcondition, tuple(reasons), uncertainties)


def decode_owned_fd_semantics(program: bytes, probes: bytes, errors: bytes,
                               event_lines: Iterable[bytes], *, owner_pid: int,
                               target_pid: int, contract_bytes: bytes) -> OwnedFdSemantics:
    """Interpret operation rules after one complete strict raw pairing pass.

    Failed paired attempts stay present. Unknown and known-unhandled BSD names
    get explicit unsupported rows, and all Mach/lifecycle data stays in source.
    Orphan/unpaired/ambiguous input refuses; no prefix or synthetic state is fed.
    After import only caller bytes and their event iterable are accessed.
    """
    source = _RAW.pair_raw_owned(program, probes, errors, event_lines,
        owner_pid=owner_pid, target_pid=target_pid, contract_bytes=contract_bytes)
    calls = {call['name']: call for call in json.loads(contract_bytes)['calls']}
    return_types = {name: call['return_type'] for name, call in calls.items()}
    operations = tuple(_decode_operation(index, pair, calls, return_types)
                       for index, pair in enumerate(source.pairs)
                       if pair.entry.raw_scalars[0] == 2)
    recognized = sum(row.request.operation is not None for row in operations)
    unknown = sum(row.source_name not in calls for row in operations)
    counts = SemanticsCounts(len(operations), recognized, unknown,
        len(operations) - recognized - unknown,
        sum(row.status == 'source-consistent' for row in operations),
        sum(row.status == 'kernel-error' for row in operations),
        sum(row.status == 'unsupported' for row in operations), source.counts.mach_pairs)
    return OwnedFdSemantics('darwin-owned-bsd-fd-semantics-v1', 'incomplete',
                            source, operations, counts)
