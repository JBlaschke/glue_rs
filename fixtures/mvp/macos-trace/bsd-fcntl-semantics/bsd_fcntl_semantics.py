"""Exact scalar fcntl descriptor rules over complete owned provider pairs.

Conditional rules need kernel lookup, descriptor lifetime and ordering evidence.
They neither identify objects nor admit a native state feed or extraction trace.
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
# Check every executable dependency before ordinary imports. A stable trusted
# checkout is assumed; callers supply no paths, helper choices or source profile.
for _relative, _digest in DEPENDENCY_IDENTITIES:
    with (_BASE / _relative).open('rb') as _stream:
        _code = _stream.read(65537)
    if len(_code) > 65536 or hashlib.sha256(_code).hexdigest() != _digest:
        raise ValueError('BSD fcntl semantics dependency identity differs: ' + _relative)
del _relative, _digest, _stream, _code


def _import_fixed(name, relative):
    spec = importlib.util.spec_from_file_location(name, _BASE / relative)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


_RAW = _import_fixed('_fcntl_semantics_owned_raw', 'owned-trace-check/owned_trace_check.py')
_ENTRY = _import_fixed('_fcntl_semantics_entry_abi', 'bsd-entry-abi/bsd_entry_abi.py')
_OUTCOME = _import_fixed('_fcntl_semantics_outcomes', 'bsd-outcomes/bsd_outcomes.py')
RawValidationError = _RAW.RawValidationError
INT_MIN, INT_MAX = -(1 << 31), (1 << 31) - 1
SOURCE_COMMIT = 'f6217f891ac0bb64f3d375211650a4c1ff8ca1ea'
SOURCE_IDENTITIES = (
    ('bsd/sys/fcntl.h',
     '0f93c8918a70ffafe20bfe9c72e671fde67438cbee9f9de8c2f87b5c704c9a9e'),
    ('bsd/sys/file_internal.h',
     'eecc3ac648ef62b90cefeeb9f13ab82fa166018abedc2a04b64ccf9dcef3fc09'),
    ('bsd/sys/file.h',
     '382bbfc44dcc94ca7122fc51f0d6b030bc54007ca0069e684217d988ed838c0c'),
    ('bsd/kern/kern_descrip.c',
     '480cfed4e987be874bd71fb6933c254adf9fb1f36de8496dee8f351b18da13b1'),
    ('bsd/dev/arm/systemcalls.c',
     '7eb44232e6da37c8e6f5d2317ed5cf1d55d02032410b0ddf7007e4ca7b495df4'),
    ('bsd/dev/i386/systemcalls.c',
     '7822b31e4f62fcd5f2baeb7fc41fde518b1f44b98fab3908594e18ee2c48426f'),
)
INTERPRETATION_PROFILE = 'pinned-xnu-lp64-bsd-fcntl-scalars-v1'
FCNTL_NAMES = ('fcntl', 'fcntl_nocancel')
FD_CLOEXEC = 1
COMMANDS = (
    (0, 'F_DUPFD', 'duplicate-minimum', 'descriptor-allocation-attempt'),
    (1, 'F_GETFD', 'query-cloexec', 'descriptor-flag-query-attempt'),
    (2, 'F_SETFD', 'set-cloexec', 'descriptor-flag-change-attempt'),
    (67, 'F_DUPFD_CLOEXEC', 'duplicate-minimum-cloexec', 'descriptor-allocation-attempt'),
)
_COMMANDS = MappingProxyType({value: (name, operation, attempt)
                             for value, name, operation, attempt in COMMANDS})
_WITNESSES = (
    'native ABI calibration and kernel-chosen fileproc descriptor generation/lifetime',
    'kernel lookup, allocation/flag access point and concurrent mutation ordering',
    'no slot-at-return or entry-time object binding follows from numeric descriptors',
    'filesystem/backing identity and application-output extraction policy unresolved',
)
MISSING_CAPABILITIES = (
    'installed native ABI and provider/source coverage calibration',
    'kernel lookup/fileproc generations and finishdup chosen-fileglob association',
    'initial descriptor/object/process/image state and successful-effect ordering',
    'pointer/lock commands, shared status flags and other command-specific effects',
    'complete operation coverage and application-output extraction policy',
)


@dataclass(frozen=True)
class FcntlRequest:
    is_fcntl: bool
    fd: Optional[int]
    command: Optional[int]
    command_name: Optional[str]
    operation: Optional[str]
    argument: Optional[int]
    argument_role: str
    minimum_descriptor: Optional[int]
    requested_cloexec: Optional[bool]
    attempt_kind: str
    entry_attempt_observed: bool = True


@dataclass(frozen=True)
class ConditionalFcntlRule:
    kind: str
    source_fd: int
    target_fd: Optional[int] = None
    minimum_descriptor: Optional[int] = None
    observed_cloexec: Optional[bool] = None
    requested_cloexec: Optional[bool] = None
    cloexec_rule: Optional[str] = None
    allocation_rule: Optional[str] = None
    ofd_relation: Optional[str] = None
    affected_scope: str = 'kernel-chosen-fileproc-descriptor-entry'
    required_witnesses: tuple[str, ...] = _WITNESSES


@dataclass(frozen=True)
class FcntlOperation:
    source_pair_index: int
    correlation_id: tuple[int, int]
    source_name: str
    arguments: tuple[_ENTRY.ArgumentAbi, ...]
    request: FcntlRequest
    outcome: _OUTCOME.BsdOutcome
    status: str
    rule: Optional[ConditionalFcntlRule]
    unsupported_reasons: tuple[str, ...]
    effect_uncertainties: tuple[str, ...]


@dataclass(frozen=True)
class FcntlCounts:
    bsd_pairs: int
    fcntl_pairs: int
    recognized_command_pairs: int
    unhandled_command_pairs: int
    non_fcntl_pairs: int
    source_consistent_successes: int
    interpreted_kernel_errors: int
    unsupported: int
    uninterpreted_mach_pairs: int


def _plain(value):
    if is_dataclass(value):
        return {field.name: _plain(getattr(value, field.name)) for field in fields(value)}
    if isinstance(value, tuple):
        return [_plain(item) for item in value]
    return value


@dataclass(frozen=True)
class OwnedFcntlSemantics:
    protocol: str
    status: str
    source: _RAW.OwnedCallPairs
    operations: tuple[FcntlOperation, ...]
    counts: FcntlCounts
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


def _request(name, arguments):
    if name not in FCNTL_NAMES:
        return FcntlRequest(False, None, None, None, None, None, 'unmodeled',
                            None, None, 'unmodeled-bsd-attempt')
    fd, command, argument = (item.value for item in arguments)
    command_name, operation, attempt = _COMMANDS.get(command,
        (None, None, 'unmodeled-fcntl-command'))
    if operation in ('duplicate-minimum', 'duplicate-minimum-cloexec'):
        minimum = argument if argument is not None and INT_MIN <= argument <= INT_MAX else None
        role, cloexec = 'minimum-descriptor-signed32-subset', None
    elif operation == 'query-cloexec':
        role, minimum, cloexec = 'ignored-by-command', None, None
    elif operation == 'set-cloexec':
        # Source-defined command semantics, not a repair of a noncanonical word:
        # F_SETFD tests only this bit of the full already-typed signed64 long.
        role, minimum = 'FD_CLOEXEC-bit-only', None
        cloexec = bool(argument & FD_CLOEXEC) if argument is not None else None
    else:
        role, minimum, cloexec = 'unmodeled', None, None
    return FcntlRequest(True, fd, command, command_name, operation, argument,
                        role, minimum, cloexec, attempt)


def _unsupported_uncertainties(request):
    gaps = ('command effects and target objects remain uninterpreted; no harmless-operation permission',)
    if request.is_fcntl and request.command == 4:
        gaps += ('F_SETFL can change shared flags before driver ioctl failure or partial rollback',)
    return gaps


def _failure_uncertainties(request):
    gaps = ('kernel error is not an absence-of-effects verdict',
            'descriptor lookup, guard/lifetime and concurrent state remain unresolved')
    if request.operation in ('duplicate-minimum', 'duplicate-minimum-cloexec'):
        gaps += ('allocation reservations and finishdup-chosen object association remain unresolved',)
    elif request.operation == 'set-cloexec':
        gaps += ('guarded clearing can fail; no resulting descriptor-bit state is inferred',)
    return gaps


def _success_rule(request, outcome):
    reasons = []
    if request.fd < 0:
        reasons.append('supported fcntl success requires a nonnegative descriptor')
    if outcome.secondary_result != 0:
        reasons.append('closed scalar fcntl branch has nonzero initialized secondary result')
    primary = outcome.primary_result
    if request.operation in ('duplicate-minimum', 'duplicate-minimum-cloexec'):
        minimum = request.minimum_descriptor
        if not (0 <= minimum <= primary and primary != request.fd):
            reasons.append('duplication success requires nonnegative minimum <= result, distinct from source fd')
    elif request.operation == 'query-cloexec':
        if primary not in (0, FD_CLOEXEC):
            reasons.append('F_GETFD success must be zero or FD_CLOEXEC')
    elif primary != 0:
        reasons.append('F_SETFD success must have zero primary result')
    if reasons:
        return None, tuple(reasons)
    if request.operation in ('duplicate-minimum', 'duplicate-minimum-cloexec'):
        return ConditionalFcntlRule('create-minimum-descriptor-alias', request.fd,
            target_fd=primary, minimum_descriptor=request.minimum_descriptor,
            cloexec_rule='set' if request.operation == 'duplicate-minimum-cloexec' else 'clear',
            allocation_rule='lowest-free-at-or-above-minimum-at-allocation-point',
            ofd_relation='finishdup-kernel-chosen-shared-fileglob'), ()
    if request.operation == 'query-cloexec':
        return ConditionalFcntlRule('observe-descriptor-cloexec-at-kernel-read', request.fd,
                                    observed_cloexec=bool(primary & FD_CLOEXEC)), ()
    return ConditionalFcntlRule('set-descriptor-cloexec-bit', request.fd,
                                requested_cloexec=request.requested_cloexec), ()


def _decode_operation(index, pair, calls, return_types):
    call = calls.get(pair.entry.function)
    arguments = () if call is None else tuple(_ENTRY._decode_argument(position, declaration,
        tuple(role for role, selected in call['selectors'].items() if selected == position),
        pair.entry.raw_scalars[5 + position])
        for position, declaration in enumerate(call['arguments']))
    request = _request(pair.entry.function, arguments)
    outcome = _OUTCOME._decode_pair(index, pair, return_types)
    reasons = []
    if not request.is_fcntl:
        reasons.append('BSD call has no fcntl command-specific semantic rule')
    elif request.operation is None:
        reasons.append('fcntl command has no handled scalar semantic rule')
    if any(argument.unsupported_reason is not None for argument in arguments):
        reasons.append('one or more arguments lack supported canonical typing')
    if (request.operation in ('duplicate-minimum', 'duplicate-minimum-cloexec')
            and request.minimum_descriptor is None):
        reasons.append('duplication minimum long is outside supported canonical signed32 range')
    if outcome.disposition == 'unsupported':
        reasons.append(outcome.unsupported_reason or 'unsupported provider outcome')
    rule = None
    if not reasons and outcome.disposition == 'kernel-success':
        rule, invalid = _success_rule(request, outcome)
        reasons.extend(invalid)
    if reasons:
        status, uncertainties = 'unsupported', _unsupported_uncertainties(request)
    elif outcome.disposition == 'kernel-error':
        status, uncertainties = 'kernel-error', _failure_uncertainties(request)
    else:
        status, uncertainties = 'source-consistent', _WITNESSES
    return FcntlOperation(index, pair.correlation_id, pair.entry.function, arguments,
        request, outcome, status, rule, tuple(reasons), uncertainties)


def decode_owned_fcntl_semantics(program: bytes, probes: bytes, errors: bytes,
                                  event_lines: Iterable[bytes], *, owner_pid: int,
                                  target_pid: int, contract_bytes: bytes) -> OwnedFcntlSemantics:
    """Apply four exact scalar rules after one complete strict raw pairing pass.

    Every BSD pair has a row; unsupported commands keep their full request and
    no-effect permission is never inferred. Mach pairs and lifecycle stay in the
    retained source. Orphan/unpaired/ambiguous input refuses with no prefix.
    After import only caller-provided bytes and their event iterable are used.
    """
    source = _RAW.pair_raw_owned(program, probes, errors, event_lines,
        owner_pid=owner_pid, target_pid=target_pid, contract_bytes=contract_bytes)
    calls = {call['name']: call for call in json.loads(contract_bytes)['calls']}
    return_types = {name: call['return_type'] for name, call in calls.items()}
    operations = tuple(_decode_operation(index, pair, calls, return_types)
                       for index, pair in enumerate(source.pairs)
                       if pair.entry.raw_scalars[0] == 2)
    fcntl_pairs = sum(row.request.is_fcntl for row in operations)
    recognized = sum(row.request.operation is not None for row in operations)
    counts = FcntlCounts(len(operations), fcntl_pairs, recognized, fcntl_pairs - recognized,
        len(operations) - fcntl_pairs,
        sum(row.status == 'source-consistent' for row in operations),
        sum(row.status == 'kernel-error' for row in operations),
        sum(row.status == 'unsupported' for row in operations), source.counts.mach_pairs)
    return OwnedFcntlSemantics('darwin-owned-bsd-fcntl-semantics-v1', 'incomplete',
                               source, operations, counts)
