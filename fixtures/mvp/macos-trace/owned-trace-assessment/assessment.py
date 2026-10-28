"""Pure request diagnostics over complete owned transport; never acceptance."""
from dataclasses import dataclass, fields, is_dataclass
import hashlib
import importlib.util
from pathlib import Path
from typing import Iterable, Optional


_BASE = Path(__file__).resolve().parent.parent
# Reviewed source identities are checked once before importing any helper code.
# A stable trusted checkout is assumed between preflight and ordinary imports.
# Code imports (including the classifier's ABI read) happen only at import time;
# the contract asset is supplied by the caller and is never opened here.
DEPENDENCY_IDENTITIES = (
    ('owned-trace-check/owned_trace_check.py',
     '1d8616b51002225c8b9abf4a18940c48f01d1ef97a3f7c54e120153ca8c978ec'),
    ('syscall-contract/syscall_contract.py',
     '35a4229894dd0373de1b312747e8acd1a23ae2074566391e8d28855ca0624dbf'),
    ('open-intent/open_intent.py',
     '104dd3e21a78264ae947033e133cd152dc43159cd91807c82569e1718905945a'),
    ('open-intent/abi.json',
     'a76cfb519805f5b45a196defb10d6a5185a5e861f41e8c75f66a653cb11d7b20'),
)
for _relative, _digest in DEPENDENCY_IDENTITIES:
    with (_BASE / _relative).open('rb') as _stream:
        _code = _stream.read(65537)
    if len(_code) > 65536 or hashlib.sha256(_code).hexdigest() != _digest:
        raise ValueError('assessment dependency identity differs: ' + _relative)
del _relative, _digest, _stream, _code


def _import_fixed(name, relative):
    spec = importlib.util.spec_from_file_location(name, _BASE / relative)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


_RAW = _import_fixed('_assessment_owned_raw', 'owned-trace-check/owned_trace_check.py')
_OPEN = _import_fixed('_assessment_open_flags', 'open-intent/open_intent.py')
RawValidationError = _RAW.RawValidationError

# Closed source-family dispatch, not an effects allowlist. Every route still
# carries all original source requirements through its linked entry facts.
_ROUTES = (
    ('asynchronous', 'asynchronous-request', 'indirect buffers, submission and completion effects unresolved'),
    ('cwd-state', 'cwd-state-request', 'cwd, root and thread scope transitions unresolved'),
    ('fd-mutation', 'fd-operation-request', 'payload, metadata, flush and transfer semantics and fd objects unresolved'),
    ('fd-state', 'descriptor-state-request', 'command semantics, descriptor lineage and initial fd state unresolved'),
    ('indirect-open', 'indirect-open-request', 'filehandle or object-ID binding and indirect open semantics unresolved'),
    ('mapping', 'mapping-request', 'backing objects, aliases, protections and write effects unresolved'),
    ('opaque-control', 'opaque-control-request', 'command-specific pointed structures and namespace effects unresolved'),
    ('open-request', 'open-request', 'pathname, dirfd, mode and variant-specific semantics unresolved'),
    ('path-mutation', 'path-mutation-request', 'source, destination, literal target and object bindings unresolved'),
    ('path-observation', 'path-observation-request', 'pathname binding and operation semantics unresolved; no harmless-read authorization'),
    ('rights-or-namespace', 'rights-or-namespace-request', 'rights transfer, socket, port and namespace identities unresolved'),
    ('spawn-or-exec', 'spawn-or-exec-request', 'executable, inherited state and image transitions unresolved'),
)
REQUEST_CATEGORIES = tuple(row[1] for row in _ROUTES) + ('unsupported-bsd-request',)
_ROUTE_BY_FAMILY = {family: (category, reason) for family, category, reason in _ROUTES}
_LIFECYCLE = ((4, 'create'), (5, 'start'), (6, 'exit'), (7, 'exec-success'),
              (8, 'exec-failure'), (9, 'lwp-create'), (10, 'lwp-start'),
              (11, 'lwp-exit'), (12, 'spawn-success'), (13, 'spawn-failure'),
              (18, 'exited'))
MISSING_CAPABILITIES = (
    'native ABI and provider/source coverage calibration',
    'completed-call pairing, canonical results and successful-effect ordering',
    'pathname bytes, cwd/dirfd resolution and filesystem object binding',
    'initial descriptor objects, descriptor generations and aliases',
    'Mach bodies, port rights and object identities',
    'lifecycle generations, image transitions and causal state',
    'mapping, asynchronous, control and namespace effect interpretation',
    'application-output object binding and extraction policy resolution',
)


@dataclass(frozen=True)
class OpenFlagAssessment:
    raw_word: int
    intent: str
    write_reasons: tuple[str, ...]
    unmodeled_bits: Optional[int]
    unknown_bits: Optional[int]
    unmodeled_sdk_flags: tuple[str, ...]
    unsupported_reason: Optional[str]


@dataclass(frozen=True)
class RequestAssessment:
    # The selected raw fields and every source requirement remain in exactly
    # source.observations[phase_index].entry. No copied raw frame/state is added.
    phase_index: int
    ordinal: int
    source_name: str
    family: Optional[str]
    category: str
    open_flags: Optional[OpenFlagAssessment]
    unresolved_reasons: tuple[str, ...]


@dataclass(frozen=True)
class AssessmentCoverage:
    bsd_entries: int
    bsd_returns: int
    known_entries: int
    unknown_entries: int
    supported_return_shapes: int
    unsupported_return_shapes: int
    control_flow_unmodeled_returns: int
    unknown_names: tuple[tuple[str, int], ...]
    source_family_entries: tuple[tuple[str, int], ...]
    request_category_entries: tuple[tuple[str, int], ...]
    mach_entries: int
    mach_returns: int
    lifecycle_kind_counts: tuple[tuple[int, str, int], ...]
    begin_records: int
    end_records: int


def _plain(value):
    """Fresh JSON-compatible containers; never expose internal mutable aliases."""
    if is_dataclass(value):
        return {field.name: _plain(getattr(value, field.name)) for field in fields(value)}
    if isinstance(value, tuple):
        return [_plain(item) for item in value]
    return value


@dataclass(frozen=True)
class OwnedRequestAssessment:
    protocol: str
    status: str
    source: _RAW.OwnedBsdObservations
    requests: tuple[RequestAssessment, ...]
    coverage: AssessmentCoverage
    dependency_identities: tuple[tuple[str, str], ...] = DEPENDENCY_IDENTITIES
    missing_capabilities: tuple[str, ...] = MISSING_CAPABILITIES
    full_trace_acceptance: bool = False
    state_feed_eligible: bool = False

    def to_dict(self):
        return _plain(self)


def _open_flags(entry):
    word = dict(entry.fields).get('flags')
    if word is None:
        return None
    if word > (1 << 32) - 1:
        return OpenFlagAssessment(word, 'unsupported', (), None, None, (),
                                  'raw flags are not canonical uint32; no truncation or signed reinterpretation')
    fact = _OPEN.classify_flags(word)
    # Its separate no-output policy is deliberately not applied here. Declared
    # application outputs require object binding before any product verdict.
    reason = ('common open flags unsupported' if fact['intent'] == 'unsupported' else None)
    return OpenFlagAssessment(word, fact['intent'], tuple(fact['write_reasons']),
                              fact['unmodeled_bits'], fact['unknown_bits'],
                              tuple(fact['unmodeled_sdk_flags']), reason)


def assess_owned_raw(program: bytes, probes: bytes, errors: bytes,
                     event_lines: Iterable[bytes], *, owner_pid: int,
                     target_pid: int, contract_bytes: bytes) -> OwnedRequestAssessment:
    """Assess entry requests only after complete strict transport exhaustion.

    No pairing, successful effects, FD objects, origins, output exemptions or
    clean extraction verdict are manufactured. Caller bytes are the only input
    access during this call; no code, ABI or contract asset is opened here.
    """
    source = _RAW.observe_raw_bsd(program, probes, errors, event_lines,
        owner_pid=owner_pid, target_pid=target_pid, contract_bytes=contract_bytes)
    requests = []
    families = {family: 0 for family, _, _ in _ROUTES}
    categories = {category: 0 for category in REQUEST_CATEGORIES}
    for index, phase in enumerate(source.observations):
        if phase.raw_scalars[0] != 2:
            continue
        entry = phase.entry
        family = entry.family if entry is not None else None
        category, reason = _ROUTE_BY_FAMILY.get(family,
            ('unsupported-bsd-request', 'no handled pinned BSD source-family route'))
        if family in families:
            families[family] += 1
        categories[category] += 1
        flags = _open_flags(entry) if family == 'open-request' else None
        reasons = [reason, 'source requirements remain unresolved',
                   'object binding and application-output policy unresolved']
        if family == 'open-request' and flags is None:
            reasons.append('source flags selector unavailable')
        requests.append(RequestAssessment(index, phase.ordinal, phase.function,
            family, category, flags, tuple(reasons)))
    bsd, kinds = source.coverage, source.raw.event_kind_counts
    coverage = AssessmentCoverage(bsd.entries, bsd.returns, bsd.known_entries,
        bsd.unknown_entries, bsd.supported_return_shapes,
        bsd.unsupported_return_shapes, bsd.control_flow_unmodeled_returns,
        bsd.unknown_names, tuple(families.items()), tuple(categories.items()),
        kinds[15], kinds[16], tuple((kind, name, kinds[kind]) for kind, name in _LIFECYCLE),
        kinds[1], kinds[17])
    return OwnedRequestAssessment('darwin-owned-request-assessment-v1',
                                  'incomplete', source, tuple(requests), coverage)
