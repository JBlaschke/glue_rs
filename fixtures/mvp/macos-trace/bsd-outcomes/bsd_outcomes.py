"""Source-defined LP64 BSD outcomes from complete owned provider call pairs.

These facts interpret the pinned provider's result words. They establish neither
an installed-kernel ABI calibration nor filesystem effects or state-feed safety.
"""
from dataclasses import dataclass, fields, is_dataclass
import hashlib
import importlib.util
import json
from pathlib import Path
from typing import Iterable, Optional


_BASE = Path(__file__).resolve().parent.parent
DEPENDENCY_IDENTITIES = (
    ('owned-trace-check/owned_trace_check.py',
     '1d8616b51002225c8b9abf4a18940c48f01d1ef97a3f7c54e120153ca8c978ec'),
    ('syscall-contract/syscall_contract.py',
     '35a4229894dd0373de1b312747e8acd1a23ae2074566391e8d28855ca0624dbf'),
)
# Check all executable dependencies before the first helper import. Normal code
# imports assume a stable trusted checkout; there are no caller-selected helpers.
for _relative, _digest in DEPENDENCY_IDENTITIES:
    with (_BASE / _relative).open('rb') as _stream:
        _code = _stream.read(65537)
    if len(_code) > 65536 or hashlib.sha256(_code).hexdigest() != _digest:
        raise ValueError('BSD outcome dependency identity differs: ' + _relative)
del _relative, _digest, _stream, _code
_spec = importlib.util.spec_from_file_location('_bsd_outcomes_owned_raw',
    _BASE / 'owned-trace-check/owned_trace_check.py')
_RAW = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(_RAW)
del _spec
RawValidationError = _RAW.RawValidationError

U64 = (1 << 64) - 1
INT_MAX = (1 << 31) - 1
SOURCE_COMMIT = 'f6217f891ac0bb64f3d375211650a4c1ff8ca1ea'
SOURCE_IDENTITIES = (
    ('bsd/dev/dtrace/systrace.c',
     'be8c6f8fca90cf95d97bd653056b2ad1c6b1c7a19ca36ba95eac5c848ac4efdd'),
    ('bsd/kern/makesyscalls.sh',
     'bd44c344880e121277d33c7539c05915a030a52c4ceab7c9f88e54f373293c67'),
    ('bsd/sys/errno.h',
     'b16e5eb195f153793b14c3826e6b04db945e9ed6a37c5a9046196555bded6906'),
)
INTERPRETATION_PROFILE = 'pinned-xnu-lp64-systrace-bsd-return-v1'
MISSING_CAPABILITIES = (
    'installed native ABI and provider/source coverage calibration',
    'operation-specific semantics and successful-effect ordering',
    'pathname, descriptor, backing-object, namespace and rights bindings',
    'process/image generations and complete lifecycle effects',
    'application-output object binding and extraction policy resolution',
)


@dataclass(frozen=True)
class BsdOutcome:
    # source.pairs[source_pair_index] retains the original phases and all words.
    source_pair_index: int
    correlation_id: tuple[int, int]
    source_name: str
    return_type: Optional[str]
    disposition: str
    primary_result: Optional[int]
    secondary_result: Optional[int]
    kernel_error: Optional[int]
    control_flow: Optional[str]
    unsupported_reason: Optional[str]


@dataclass(frozen=True)
class OutcomeCounts:
    bsd_pairs: int
    kernel_successes: int
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
class OwnedBsdOutcomes:
    protocol: str
    status: str
    source: _RAW.OwnedCallPairs
    outcomes: tuple[BsdOutcome, ...]
    counts: OutcomeCounts
    interpretation_profile: str = INTERPRETATION_PROFILE
    source_commit: str = SOURCE_COMMIT
    source_identities: tuple[tuple[str, str], ...] = SOURCE_IDENTITIES
    dependency_identities: tuple[tuple[str, str], ...] = DEPENDENCY_IDENTITIES
    missing_capabilities: tuple[str, ...] = MISSING_CAPABILITIES
    native_abi_calibrated: bool = False
    successful_effect_ordering: bool = False
    state_feed_eligible: bool = False
    full_trace_acceptance: bool = False

    def to_dict(self):
        """Return fresh JSON-compatible containers, retaining no mutable aliases."""
        return _plain(self)


def _signed32(word):
    """Validate the provider's int-to-uint64 conversion; never mask high bits."""
    value = word if word < (1 << 63) else word - (1 << 64)
    return value if -(1 << 31) <= value <= INT_MAX else None


def _decode_pair(index, pair, return_types):
    entry, returned = pair.entry, pair.returned
    return_type = return_types.get(entry.function)

    def unsupported(reason, control_flow=None):
        return BsdOutcome(index, pair.correlation_id, entry.function, return_type,
                          'unsupported', None, None, None, control_flow, reason)

    if return_type is None:
        return unsupported('no pinned BSD source return type')
    if return_type not in ('int', 'user_ssize_t', 'user_addr_t'):
        return unsupported('pinned BSD return type has no handled LP64 interpretation')
    if returned.returned is None:
        return unsupported(returned.unsupported_reason or 'unsupported provider return framing')
    # The strict reader checked the five uint64 words and the contract helper
    # checked primary duplication and equality of kernel error/builtin errno.
    primary, _, secondary, error, _ = returned.raw_scalars[5:]
    if error in (U64, U64 - 1):
        control = 'ERESTART' if error == U64 else 'EJUSTRETURN'
        expected = U64 if error == U64 else 0
        reason = (control + ' changes control flow; no completed ordinary outcome')
        if primary != expected or secondary != expected:
            reason = control + ' result words differ from pinned provider; control flow unresolved'
        return unsupported(reason, control)
    if error:
        if not 0 < error <= INT_MAX:
            return unsupported('unmodeled negative or noncanonical signed32 kernel return code')
        if primary != U64 or secondary != U64:
            return unsupported('kernel error lacks pinned all-ones provider failure results')
        # This is a kernel error, not a claim about libc wrappers or absence of
        # partial effects. Private positive codes must not be capped at ELAST.
        return BsdOutcome(index, pair.correlation_id, entry.function, return_type,
                          'kernel-error', None, None, error, None, None)
    if return_type == 'int':
        first, second = _signed32(primary), _signed32(secondary)
        if first is None or second is None:
            return unsupported('successful int result is not canonically sign-extended signed32')
    else:
        if secondary != 0:
            return unsupported('successful LP64 address/ssize result has nonzero secondary word')
        first = primary
        if return_type == 'user_ssize_t' and primary >= (1 << 63):
            first -= 1 << 64
        second = 0
    # A signed primary of -1 can be successful at the provider level. Its
    # operation-specific meaning is separate; error==0 decides this disposition.
    return BsdOutcome(index, pair.correlation_id, entry.function, return_type,
                      'kernel-success', first, second, 0, None, None)


def decode_owned_bsd_outcomes(program: bytes, probes: bytes, errors: bytes,
                              event_lines: Iterable[bytes], *, owner_pid: int,
                              target_pid: int, contract_bytes: bytes) -> OwnedBsdOutcomes:
    """Decode BSD outcomes only after strict raw transport and pairing finish.

    No public API accepts caller-created pairs, normalized results, calibration
    assertions or an alternate source profile. Unsupported outcomes retain their
    original pair and a reason. A transport/pairing/source failure returns no
    prefix. Every Mach pair and lifecycle record stays in the retained source.
    After import the only inputs accessed are caller bytes and their iterable.
    """
    source = _RAW.pair_raw_owned(program, probes, errors, event_lines,
        owner_pid=owner_pid, target_pid=target_pid, contract_bytes=contract_bytes)
    # pair_raw_owned already required the exact immutable asset identity and
    # parsed its complete bounded table. No second asset read or lookup occurs.
    return_types = {call['name']: call['return_type']
                    for call in json.loads(contract_bytes)['calls']}
    outcomes = tuple(_decode_pair(index, pair, return_types)
                     for index, pair in enumerate(source.pairs)
                     if pair.entry.raw_scalars[0] == 2)
    counts = OutcomeCounts(len(outcomes),
        sum(row.disposition == 'kernel-success' for row in outcomes),
        sum(row.disposition == 'kernel-error' for row in outcomes),
        sum(row.disposition == 'unsupported' for row in outcomes),
        source.counts.mach_pairs)
    return OwnedBsdOutcomes('darwin-owned-bsd-outcomes-v1', 'incomplete',
                            source, outcomes, counts)
