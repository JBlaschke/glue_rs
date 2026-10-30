"""Conditional F_GETFL conversion beside the unchanged four scalar rules.

Algebraic preimages are alternatives, never observed fileglob or process state.
Only a conservative source construction subset receives a conditional rule.
"""
from dataclasses import dataclass, replace
import hashlib
import importlib.util
import json
from pathlib import Path
from typing import Iterable, Optional


_BASE = Path(__file__).resolve().parent.parent
DEPENDENCY_IDENTITIES = (
    ('bsd-fcntl-semantics/bsd_fcntl_semantics.py',
     'da6ea5ae6887d47f1d2b9b2da616e9632d2c9f6ad4b32d7cb0981187030f3260'),
    ('owned-trace-check/owned_trace_check.py',
     '1d8616b51002225c8b9abf4a18940c48f01d1ef97a3f7c54e120153ca8c978ec'),
    ('syscall-contract/syscall_contract.py',
     '35a4229894dd0373de1b312747e8acd1a23ae2074566391e8d28855ca0624dbf'),
    ('bsd-entry-abi/bsd_entry_abi.py',
     '1cd28940f18c5ca7d1d6af13e653cc985fc3afa9ce98e6516b11dbcbcf8dcf17'),
    ('bsd-outcomes/bsd_outcomes.py',
     'cf3f85d71d870ade4a8cb62441d4c856c036f65a574b0dce20b1d0d188ba36ef'),
)
# Fixed identities are checked before any helper executes. This assumes a stable
# trusted checkout; it is not protection against concurrent checkout replacement.
for _relative, _digest in DEPENDENCY_IDENTITIES:
    with (_BASE / _relative).open('rb') as _stream:
        _code = _stream.read(65537)
    if len(_code) > 65536 or hashlib.sha256(_code).hexdigest() != _digest:
        raise ValueError('BSD F_GETFL dependency identity differs: ' + _relative)
del _relative, _digest, _stream, _code
_spec = importlib.util.spec_from_file_location('_fgetfl_fixed_scalar',
    _BASE / 'bsd-fcntl-semantics/bsd_fcntl_semantics.py')
_SCALAR = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(_SCALAR)
del _spec
RawValidationError = _SCALAR.RawValidationError
SOURCE_COMMIT = _SCALAR.SOURCE_COMMIT
SOURCE_IDENTITIES = _SCALAR.SOURCE_IDENTITIES
INTERPRETATION_PROFILE = 'pinned-xnu-lp64-bsd-fgetfl-conversion-v1'
F_GETFL = 3
U32 = (1 << 32) - 1
FREAD, FWRITE, FNONBLOCK, FAPPEND = 1, 2, 4, 8
O_EVTONLY, FWASWRITTEN, FEXEC = 0x8000, 0x10000, 0x40000000
# Names classify candidate bits only. They neither exhaust all writers nor prove
# that a named combination is reachable. O_NOCTTY has a private F_NOCACHE_EXT use.
NAMED_FILEGLOB_BITS = (
    (1, 'FREAD'), (2, 'FWRITE'), (4, 'FNONBLOCK'), (8, 'FAPPEND'),
    (0x40, 'FASYNC'), (0x1000, 'FMARK'),
    (0x2000, 'FDEFER'), (0x4000, 'FWASLOCKED'), (0x8000, 'O_EVTONLY'),
    (0x10000, 'FWASWRITTEN'), (0x20000, 'O_NOCTTY-private-F_NOCACHE_EXT'),
    (0x40000, 'FNOCACHE'), (0x80000, 'FNORDAHEAD'),
    (0x800000, 'FNODIRECT'), (0x2000000, 'FENCRYPTED'),
    (0x4000000, 'FSINGLE_WRITER'), (0x10000000, 'FUNENCRYPTED'),
    (0x40000000, 'FEXEC'),
)
_NAMED_MASK = sum(bit for bit, _ in NAMED_FILEGLOB_BITS)
CORE_PHYSICAL_ANCHORS = (
    ('bsd/sys/fcntl.h', 'OFLAGS/FFLAGS; FMASK; F_GETFL', '237-246;281'),
    ('bsd/sys/file_internal.h', 'fileproc/fileglob; uint32 fg_flag', '120-130;178-190'),
    ('bsd/kern/kern_descrip.c', 'f_flag alias; unsigned fflag; lookup/MAC; F_GETFL',
     '140;2784;2794-2823;2865-2877'),
    ('bsd/kern/kern_descrip.c', 'F_SETFL; private flag writers', '2879-2905;3588-3647;5852'),
    ('bsd/dev/arm/systemcalls.c', 'LP64 return storage initialization', '130;136'),
    ('bsd/dev/i386/systemcalls.c', 'LP64 return storage initialization', '365-366'),
)
# Supplemental pages are commit-pinned symbol evidence. Full original bytes were
# not retained, so their SHA256 and physical line numbers are explicitly unknown.
SUPPLEMENTAL_SOURCE_EVIDENCE = (
    ('bsd/vfs/vfs_syscalls.c', 'open1: access validation, FFLAGS, event-only policy, fg_flag retention/truncation',
     'full-file-sha256-unavailable; physical-lines-unverified'),
    ('bsd/kern/sys_generic.c', 'fp_writev: FWASWRITTEN after nonzero write result',
     'full-file-sha256-unavailable; physical-lines-unverified'),
    ('bsd/kern/uipc_usrreq.c', 'unp_gc/unp_mark: FMARK/FDEFER',
     'full-file-sha256-unavailable; physical-lines-unverified'),
    ('bsd/kern/kern_proc.c', 'proc_disallow_rw_for_o_evtonly: relaxed p_vfs_iopolicy read',
     'full-file-sha256-unavailable; physical-lines-unverified'),
)
_WITNESSES = (
    'native ABI/provider calibration and kernel-chosen descriptor/fileglob generation/lifetime',
    'actual fg_flag and event-only process-policy reads are not observed; preimages are alternatives',
    'some source construction does not prove actual object, state, policy or operation ordering',
    'shared flag writers, alias mutation and relaxed policy reads can race; no at-return snapshot',
    'backing identity, application-output authorization and extraction policy remain unresolved',
)
MISSING_CAPABILITIES = _SCALAR.MISSING_CAPABILITIES + (
    'actual F_GETFL flag preimage and process event-only policy, including policy changes since open',
    'complete flag-writer reachability and private/unknown flag combinations',
)


@dataclass(frozen=True)
class FlagPreimage:
    fileglob_flags_uint32: int
    adjusted_flags_uint32: int
    policy_condition: str
    named_flags: tuple[str, ...]
    unknown_bits_uint32: int
    source_feasibility: str


@dataclass(frozen=True)
class FgetflObservation:
    primary_signed32: int
    primary_uint32: int
    algebraic_preimages: tuple[FlagPreimage, ...]
    feasibility: str
    actual_fileglob_flags: str = 'unobserved'
    event_only_process_policy: str = 'unobserved; no branch selected'


@dataclass(frozen=True)
class ConditionalFgetflRule:
    kind: str
    source_fd: int
    observation: FgetflObservation
    affected_scope: str = 'kernel-chosen-shared-fileglob-at-flag-read'
    required_witnesses: tuple[str, ...] = _WITNESSES


@dataclass(frozen=True)
class FgetflOperation:
    source_pair_index: int
    correlation_id: tuple[int, int]
    source_name: str
    arguments: tuple[object, ...]
    request: _SCALAR.FcntlRequest
    outcome: object
    status: str
    observation: Optional[FgetflObservation]
    rule: Optional[ConditionalFgetflRule]
    unsupported_reasons: tuple[str, ...]
    effect_uncertainties: tuple[str, ...] = _WITNESSES


@dataclass(frozen=True)
class FgetflCounts:
    bsd_pairs: int
    fcntl_pairs: int
    fgetfl_pairs: int
    legacy_source_consistent_successes: int
    conditional_conversions: int
    interpreted_kernel_errors: int
    unresolved_conversions: int
    unsupported: int
    uninterpreted_mach_pairs: int


@dataclass(frozen=True)
class OwnedFgetflSemantics:
    protocol: str
    status: str
    source: object
    operations: tuple[object, ...]
    counts: FgetflCounts
    interpretation_profile: str = INTERPRETATION_PROFILE
    source_commit: str = SOURCE_COMMIT
    source_identities: tuple[tuple[str, str], ...] = SOURCE_IDENTITIES
    dependency_identities: tuple[tuple[str, str], ...] = DEPENDENCY_IDENTITIES
    core_physical_anchors: tuple[tuple[str, str, str], ...] = CORE_PHYSICAL_ANCHORS
    supplemental_source_evidence: tuple[tuple[str, str, str], ...] = SUPPLEMENTAL_SOURCE_EVIDENCE
    missing_capabilities: tuple[str, ...] = MISSING_CAPABILITIES
    native_abi_calibrated: bool = False
    successful_effect_ordering: bool = False
    state_feed_eligible: bool = False
    application_output_authorized: bool = False
    extraction_acceptance: bool = False
    full_trace_acceptance: bool = False

    def to_dict(self):
        return _SCALAR._plain(self)


def _source_subset(flags):
    """Some ordinary open/write construction exists; actual state is unproved.

    This intentionally proves no event-only, mixed FEXEC/access, other private
    combination or exhaustive flag domain. A small subset is preferable to an
    invented reachability claim for every integer or every named-bit subset.
    """
    if flags == FEXEC:
        return True
    allowed = FREAD | FWRITE | FNONBLOCK | FAPPEND | FWASWRITTEN
    return (not (flags & ~allowed) and flags & 3 in (1, 2, 3)
            and (not flags & FWASWRITTEN or bool(flags & FWRITE)))


def _preimage(flags, adjusted, policy):
    return FlagPreimage(flags, adjusted, policy,
        tuple(name for bit, name in NAMED_FILEGLOB_BITS if flags & bit),
        flags & (U32 ^ _NAMED_MASK),
        'some-source-feasible-ordinary-subset' if _source_subset(flags)
        else 'reachability-unproved')


def _observe(primary):
    bits = primary & U32  # canonical signed32 is already validated; a bit view only
    adjusted = []
    # Invert the two unsigned OFLAGS branches without dropping any private bits.
    incremented = (bits + 1) & U32
    if not incremented & FEXEC:
        adjusted.append(incremented)
    if bits & FEXEC and not bits & 3:
        adjusted.extend(bits | access for access in range(4))
    preimages = []
    for flags in adjusted:
        if not flags & O_EVTONLY:
            preimages.append(_preimage(flags, flags, 'not-event-only; policy-irrelevant'))
        else:
            preimages.append(_preimage(flags, flags, 'event-only; process-disallow-rw-clear'))
            if flags & FREAD:
                # FREAD may already have been set or may be inserted locally.
                for raw in (flags, flags & ~FREAD):
                    preimages.append(_preimage(raw, flags, 'event-only; process-disallow-rw-set'))
    feasible = any(item.source_feasibility == 'some-source-feasible-ordinary-subset'
                   for item in preimages)
    status = ('some-source-feasible-preimage; actual-state-unproved' if feasible
              else 'no-algebraic-preimage' if not preimages
              else 'algebraic-preimages-only; source-reachability-unproved')
    return FgetflObservation(primary, bits, tuple(preimages), status)


def _decode_operation(index, pair, calls, return_types):
    """Private recipe hook: use only after one complete fixed raw pairing pass."""
    legacy = _SCALAR._decode_operation(index, pair, calls, return_types)
    if not legacy.request.is_fcntl or legacy.request.command != F_GETFL:
        return legacy
    request = replace(legacy.request, command_name='F_GETFL', operation='query-status-flags',
        argument_role='ignored-by-command', attempt_kind='descriptor-status-flag-query-attempt')
    reasons = []
    if any(arg.unsupported_reason is not None for arg in legacy.arguments):
        reasons.append('one or more arguments lack supported canonical typing')
    outcome = legacy.outcome
    if outcome.disposition == 'unsupported':
        reasons.append(outcome.unsupported_reason or 'unsupported provider outcome')
    observation, rule = None, None
    if not reasons and outcome.disposition == 'kernel-success':
        if request.fd < 0:
            reasons.append('F_GETFL success requires a nonnegative descriptor')
        if outcome.secondary_result != 0:
            reasons.append('F_GETFL branch has nonzero initialized secondary result')
        # Retain canonical conversion facts even if fd/secondary relations fail.
        observation = _observe(outcome.primary_result)
        if not reasons:
            if observation.feasibility.startswith('some-source-feasible-preimage;'):
                rule = ConditionalFgetflRule('observe-conditional-OFLAGS-conversion',
                                             request.fd, observation)
            else:
                reasons.append(observation.feasibility)
    if reasons:
        status = 'unresolved-conversion' if observation is not None and not rule else 'unsupported'
    elif outcome.disposition == 'kernel-error':
        status = 'kernel-error'
    else:
        status = 'conditional-conversion'
    uncertainties = _WITNESSES
    if status == 'kernel-error':
        uncertainties += ('kernel error is not an absence-of-effects verdict; lookup/MAC paths unresolved',)
    return FgetflOperation(index, pair.correlation_id, pair.entry.function,
        legacy.arguments, request, outcome, status, observation, rule, tuple(reasons), uncertainties)


def decode_owned_fgetfl_semantics(program: bytes, probes: bytes, errors: bytes,
                                  event_lines: Iterable[bytes], *, owner_pid: int,
                                  target_pid: int, contract_bytes: bytes) -> OwnedFgetflSemantics:
    """Pair original bytes once; interpret F_GETFL beside four unchanged rules.

    No prefix survives transport/pairing refusal. Every BSD row remains explicit;
    all Mach/lifecycle phases remain in source. After import only caller bytes and
    the bounded original iterable are accessed, with no source/asset fallback.
    """
    source = _SCALAR._RAW.pair_raw_owned(program, probes, errors, event_lines,
        owner_pid=owner_pid, target_pid=target_pid, contract_bytes=contract_bytes)
    calls = {call['name']: call for call in json.loads(contract_bytes)['calls']}
    return_types = {name: call['return_type'] for name, call in calls.items()}
    operations = tuple(_decode_operation(index, pair, calls, return_types)
                       for index, pair in enumerate(source.pairs)
                       if pair.entry.raw_scalars[0] == 2)
    counts = FgetflCounts(len(operations), sum(row.request.is_fcntl for row in operations),
        sum(row.request.operation == 'query-status-flags' for row in operations),
        sum(row.status == 'source-consistent' for row in operations),
        sum(row.status == 'conditional-conversion' for row in operations),
        sum(row.status == 'kernel-error' for row in operations),
        sum(row.status == 'unresolved-conversion' for row in operations),
        sum(row.status == 'unsupported' for row in operations), source.counts.mach_pairs)
    return OwnedFgetflSemantics('darwin-owned-bsd-fgetfl-semantics-v1', 'incomplete',
                                source, operations, counts)
