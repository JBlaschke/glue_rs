"""Fixed raw runtime FD intent/interval policy; never native acceptance.

All execution input is original byte evidence. Closed windows describe possible
lookup/effect periods, not effect instants. READY provenance is retired at EVERY
exec; this first profile has no post-exec observation or output exemption.
"""
from dataclasses import dataclass
import hashlib
import importlib.util
import json
from pathlib import Path
from typing import Iterable, Optional

_BASE = Path(__file__).resolve().parent.parent
DEPENDENCY_IDENTITIES = (
    ('runtime-boundary/runtime_recipe.py', '0eec5212fe031a3c22e63f597faa587a01fd83804db3d1911b53ca3ba746cbd0'),
    ('bsd-fd-semantics/bsd_fd_semantics.py', '1d97f20c18fcc90ab5c467b0d44403aecd288d530394e32ad0d00b5ef5e1c7ba'),
    ('open-intent/open_intent.py', '104dd3e21a78264ae947033e133cd152dc43159cd91807c82569e1718905945a'),
    ('open-intent/abi.json', 'a76cfb519805f5b45a196defb10d6a5185a5e861f41e8c75f66a653cb11d7b20'),
)
for _relative, _digest in DEPENDENCY_IDENTITIES:
    with (_BASE / _relative).open('rb') as _stream:
        _code = _stream.read(65537)
    if len(_code) > 65536 or hashlib.sha256(_code).hexdigest() != _digest:
        raise ValueError('runtime FD policy fixed helper identity: ' + _relative)
del _relative, _digest, _stream, _code


def _import(name, relative):
    spec = importlib.util.spec_from_file_location(name, _BASE / relative)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


_RECIPE = _import('_runtime_fd_recipe', 'runtime-boundary/runtime_recipe.py')
_FD = _import('_runtime_fd_operations', 'bsd-fd-semantics/bsd_fd_semantics.py')
_OPEN = _import('_runtime_fd_open_intent', 'open-intent/open_intent.py')
_IMAGES = _RECIPE._IMAGES
_V1 = _IMAGES._V1
RawValidationError = _RECIPE.RawValidationError
RuntimeRecipeEvidence = _RECIPE.RuntimeRecipeEvidence
SOURCE_COMMIT = _FD.SOURCE_COMMIT
INT_MAX = (1 << 31) - 1
MAX_ATTEMPTS = 4096
MAX_CONFLICTS = 8192
MAX_TRANSITIONS = 32768
MAX_SLOTS = 4096  # Analysis storage bound, never RLIMIT or a numeric FD ceiling.
OPEN_NAMES = frozenset(('open', 'open_nocancel', 'openat', 'openat_nocancel'))
FD_NAMES = frozenset(name for name, _, _ in _FD.OPERATION_NAMES)
HANDLED_RUNTIME_NAMES = tuple(sorted(FD_NAMES | OPEN_NAMES))


@dataclass(frozen=True)
class PolicyFinding:
    code: str
    entry_ordinal: Optional[int]
    source_name: str
    message: str


@dataclass(frozen=True)
class PolicyAttempt:
    source_name: str
    entry: object
    returned: Optional[object]
    context: str
    image_epoch: Optional[int]
    thread_instance: Optional[int]
    intent: str
    arguments: tuple[object, ...]
    outcome: Optional[object]
    fd: Optional[int] = None
    source_fd: Optional[int] = None
    target_fd: Optional[int] = None
    requested_bytes: Optional[int] = None
    requested_offset: Optional[int] = None
    requested_length: Optional[int] = None
    flags_u32: Optional[int] = None
    unsupported_reasons: tuple[str, ...] = ()
    write_reasons: tuple[str, ...] = ()
    effect_uncertainties: tuple[str, ...] = ()
    output_exempt: bool = False

    @property
    def entry_ordinal(self):
        return self.entry.ordinal

    @property
    def return_ordinal(self):
        return None if self.returned is None else self.returned.ordinal


@dataclass(frozen=True)
class PhaseAccounting:
    ordinal: int
    role: str
    attempt_index: Optional[int] = None


@dataclass(frozen=True)
class EffectWindow:
    attempt_index: int
    entry_ordinal: int
    end_ordinal: int
    start_ns: int
    end_ns: int
    image_epoch: int
    thread_instance: int
    mutation_slots: tuple[int, ...]
    allocation: bool
    unknown_effects: bool
    lookup_slots: tuple[int, ...] = ()
    effect_instant: None = None
    native_clock_calibrated: bool = False


@dataclass(frozen=True)
class IntervalConflict:
    first_attempt: int
    second_attempt: int
    slots: tuple[int, ...]
    allocation_domain: bool


@dataclass(frozen=True)
class FdState:
    fd: int
    version: int
    state: str
    analysis_binding_key: Optional[str]
    cloexec: Optional[bool]
    origin_ordinal: int
    alias_source: Optional[int] = None
    kernel_generation_attested: bool = False
    output_authorized: bool = False


@dataclass(frozen=True)
class FdTransition:
    ordinal: int
    fd: int
    prior_version: int
    version: int
    state: str
    binding_key: Optional[str]
    source_fd: Optional[int]
    window: tuple[int, int]
    reason: str
    cloexec: Optional[bool]
    effect_instant: None = None
    native_identity_attested: bool = False


@dataclass(frozen=True)
class RuntimeFdPolicy:
    protocol: str
    status: str
    source: object
    recipe: Optional[object]
    attempts: tuple[PolicyAttempt, ...]
    phase_accounting: tuple[PhaseAccounting, ...]
    windows: tuple[EffectWindow, ...]
    conflicts: tuple[IntervalConflict, ...]
    transitions: tuple[FdTransition, ...]
    final_bindings: tuple[FdState, ...]
    violations: tuple[PolicyFinding, ...]
    gaps: tuple[PolicyFinding, ...]
    output_exemptions: tuple = ()
    native_admission: bool = False
    output_capabilities_authorized: bool = False
    state_feed_eligible: bool = False
    successful_effect_linearization: bool = False
    full_trace_acceptance: bool = False
    final_state_is_live: bool = False

    def to_dict(self):
        return _V1._plain(self)


def _finding(code, attempt, message):
    return PolicyFinding(code, None if attempt is None else attempt.entry.ordinal,
                         '' if attempt is None else attempt.source_name, message)


def _typed(index, entry, returned, calls, return_types, pair=None):
    arguments = _FD._ENTRY._decode_entry(index, entry, calls).arguments
    outcome = None if pair is None else _FD._OUTCOME._decode_pair(index, pair, return_types)
    reasons = []
    if entry.function not in calls:
        reasons.append('no pinned source declaration')
    if any(arg.unsupported_reason is not None for arg in arguments):
        reasons.append('noncanonical or unsupported source argument')
    if outcome is not None and outcome.disposition == 'unsupported':
        reasons.append(outcome.unsupported_reason or 'unsupported kernel outcome')
    return arguments, outcome, reasons


def _attempt(index, entry, returned, context, epoch, actor, calls, return_types, pair=None):
    arguments, outcome, reasons = _typed(index, entry, returned, calls, return_types, pair)
    name = entry.function
    # Intent is retained before checking argument/outcome support.
    if name in FD_NAMES:
        operation, intent = _FD._OPERATIONS[name]
        request = _FD._request(operation, intent, arguments)
        if context == 'runtime':
            decoded = _FD._decode_operation(index, pair, calls, return_types)
            reasons = list(decoded.unsupported_reasons)
            uncertainty = decoded.effect_uncertainties
        else:
            uncertainty = ('no ordinary completed outcome is invented for this context',)
        return PolicyAttempt(name, entry, returned, context, epoch, actor, intent,
            arguments, outcome, request.fd, request.source_fd, request.target_fd,
            request.requested_bytes, request.requested_offset, request.requested_length,
            unsupported_reasons=tuple(reasons),
            write_reasons=(intent,) if intent in ('payload-write-attempt', 'flush-attempt', 'truncate-attempt') else (),
            effect_uncertainties=uncertainty)
    if name in OPEN_NAMES:
        selected = calls[name]['selectors']['flags']
        signed = arguments[selected].value
        bits, writes = None, ()
        intent = 'open-request-attempt'
        if signed is not None:
            # A bit view of an ALREADY canonical signed32 int, not repair/masking
            # of an arbitrary raw word. The original signed argument stays kept.
            bits = signed if signed >= 0 else signed + (1 << 32)
            classification = _OPEN.classify_flags(bits)
            intent = classification['intent']
            writes = tuple(classification['write_reasons'])
            if classification['intent'] == 'unsupported':
                reasons.append('unsupported open flag intent')
        if outcome is not None and outcome.disposition == 'kernel-success' and (
                outcome.primary_result < 0 or outcome.secondary_result != 0):
            reasons.append('open success requires nonnegative descriptor and zero secondary')
        return PolicyAttempt(name, entry, returned, context, epoch, actor, intent,
            arguments, outcome, flags_u32=bits, unsupported_reasons=tuple(reasons),
            write_reasons=writes, effect_uncertainties=('open intent does not identify its returned object',))
    call = calls.get(name)
    intent = 'path-mutation-attempt' if call is not None and call['family'] == 'path-mutation' else 'unmodeled-bsd-attempt'
    return PolicyAttempt(name, entry, returned, context, epoch, actor, intent,
        arguments, outcome, unsupported_reasons=tuple(reasons),
        effect_uncertainties=('unhandled effects are never a harmless-operation permission',))


def _whole_incomplete(capture, contract_bytes, message):
    # The upstream exception contains a completely validated physical capture,
    # never a clean image prefix. Project EVERY original entry without pairing,
    # actor generation or a successful state/exemption result.
    calls = {call['name']: call for call in json.loads(contract_bytes)['calls']}
    types = {name: call['return_type'] for name, call in calls.items()}
    entries = [phase for phase in capture.phases if phase.raw_scalars[0] in (2, 15)]
    _V1._require(len(entries) <= MAX_ATTEMPTS, 'FD policy attempt bound')
    attempts = tuple(
        PolicyAttempt(phase.function, phase, None, 'unresolved-image', None, None,
            'opaque-mach-attempt', (), None,
            unsupported_reasons=('Mach trap arguments/outcomes have no BSD interpretation',),
            effect_uncertainties=('Mach/rights/effects remain opaque; no state or authority follows',))
        if phase.raw_scalars[0] == 15 else
        _attempt(i, phase, None, 'unresolved-image', None, None, calls, types)
        for i, phase in enumerate(entries))
    by_ordinal = {a.entry.ordinal: i for i, a in enumerate(attempts)}
    _V1._require(len(by_ordinal) == len(entries), 'FD policy all-entry conservation')
    accounting = tuple(PhaseAccounting(p.ordinal,
        'opaque-mach-entry' if p.raw_scalars[0] == 15 else 'unresolved-image-context',
        by_ordinal.get(p.ordinal)) for p in capture.phases)
    violations = tuple(_finding('forbidden-path-mutation' if a.intent == 'path-mutation-attempt' else
                                'forbidden-open-intent', a, 'forbidden requested intent is retained despite incomplete image context')
                       for a in attempts if a.intent == 'path-mutation-attempt' or
                       a.source_name in OPEN_NAMES and a.write_reasons)
    return RuntimeFdPolicy('darwin-runtime-fd-policy-v1', 'incomplete', capture, None,
        attempts, accounting, (), (), (), (), violations,
        (PolicyFinding('image-coverage', None, '', message),))


def _partition(recipe, contract_bytes):
    images, capture = recipe.images, recipe.source
    calls = {call['name']: call for call in json.loads(contract_bytes)['calls']}
    types = {name: call['return_type'] for name, call in calls.items()}
    contexts = {}
    for index, pair in enumerate(images.pairs):
        contexts[pair.entry.ordinal] = (pair.returned, 'bootstrap' if pair.image_epoch == 0 else 'runtime',
                                        pair.image_epoch, pair.thread_instance, pair, index)
    for transition in images.transitions:
        contexts[transition.entry.ordinal] = (transition.returned, 'exec', transition.old_image_epoch,
                                              transition.old_thread_instance, None, len(contexts))
    if images.terminating_call is not None:
        terminal = images.terminating_call
        contexts[terminal.entry.ordinal] = (None, 'termination', terminal.image_epoch,
                                            terminal.thread_instance, None, len(contexts))
    entries = [p for p in capture.phases if p.raw_scalars[0] == 2]
    _V1._require(len(entries) <= MAX_ATTEMPTS and set(contexts) == {p.ordinal for p in entries},
                 'FD policy complete entry partition')
    attempts, roles = [], {}
    for entry in entries:
        returned, context, epoch, actor, pair, source_index = contexts[entry.ordinal]
        attempt = _attempt(source_index, pair.entry if pair is not None else entry,
            returned, context, epoch, actor, calls, types, pair)
        index = len(attempts)
        attempts.append(attempt)
        roles[entry.ordinal] = PhaseAccounting(entry.ordinal, context + '-entry', index)
        if returned is not None:
            _V1._require(returned.ordinal not in roles, 'FD policy return accounted twice')
            roles[returned.ordinal] = PhaseAccounting(returned.ordinal, context + '-return', index)
    attachment = images.attachment_return
    if attachment is not None:
        ordinal = attachment.phase.ordinal
        _V1._require(ordinal not in roles, 'FD policy duplicate attachment return')
        roles[ordinal] = PhaseAccounting(ordinal, 'validated-attachment-return')
    lifecycle = {binding.source_ordinal: binding.role for binding in images.lifecycle_bindings}
    shadow = {row.source.ordinal for row in images.unbound_shadows}
    for phase in capture.phases:
        if phase.ordinal in roles:
            continue
        kind = phase.raw_scalars[0]
        _V1._require(kind not in (2, 3), 'FD policy unaccounted ordinary phase')
        role = 'unbound-nonlive-shadow' if phase.ordinal in shadow else lifecycle.get(phase.ordinal, 'validated-lifecycle-context')
        roles[phase.ordinal] = PhaseAccounting(phase.ordinal, role)
    return tuple(attempts), tuple(roles[p.ordinal] for p in capture.phases)


def _window(index, a):
    source, target, fd = a.source_fd, a.target_fd, a.fd
    lookups = tuple(sorted({v for v in (source, fd) if v is not None and 0 <= v <= INT_MAX}))
    slots, allocate, unknown = (), False, bool(a.unsupported_reasons)
    if a.source_name in ('close', 'close_nocancel'):
        slots = lookups
    elif a.source_name == 'dup':
        allocate = True
        if a.outcome is not None and a.outcome.disposition == 'kernel-success' and not a.unsupported_reasons:
            slots = (a.outcome.primary_result,)
    elif a.source_name == 'dup2':
        preserve = (a.source_fd == target and a.outcome is not None and
                    a.outcome.disposition == 'kernel-success' and not a.unsupported_reasons)
        slots = (target,) if not preserve and target is not None and 0 <= target <= INT_MAX else ()
    elif a.source_name in OPEN_NAMES:
        allocate = True
        if a.outcome is not None and a.outcome.disposition == 'kernel-success' and not a.unsupported_reasons:
            slots = (a.outcome.primary_result,)
    elif a.source_name not in FD_NAMES:
        unknown = True
    return EffectWindow(index, a.entry.ordinal, a.returned.ordinal,
        a.entry.raw_scalars[1], a.returned.raw_scalars[1], a.image_epoch,
        a.thread_instance, slots, allocate, unknown, lookups)


def _conflicts(windows):
    result = []
    for offset, first in enumerate(windows):
        for second in windows[offset + 1:]:
            if first.image_epoch != second.image_epoch or first.end_ns < second.start_ns or second.end_ns < first.start_ns:
                continue
            a = set(first.mutation_slots)
            b = set(second.mutation_slots)
            touches = (a & (b | set(second.lookup_slots))) | (b & (a | set(first.lookup_slots)))
            global_domain = (first.unknown_effects or second.unknown_effects or
                first.allocation and bool(second.allocation or second.mutation_slots or second.lookup_slots) or
                second.allocation and bool(first.allocation or first.mutation_slots or first.lookup_slots))
            if touches or global_domain:
                _V1._require(len(result) < MAX_CONFLICTS, 'FD policy conflict bound')
                result.append(IntervalConflict(first.attempt_index, second.attempt_index,
                    tuple(sorted(touches or a | b | set(first.lookup_slots) | set(second.lookup_slots))), bool(global_domain)))
    return tuple(result)


def _run(recipe, attempts, accounting):
    gaps, violations = [], []
    windows = tuple(_window(i, a) for i, a in enumerate(attempts) if a.context == 'runtime')
    conflicts = _conflicts(windows)
    conflicted = {i for row in conflicts for i in (row.first_attempt, row.second_attempt)}
    for row in conflicts:
        first, second = attempts[row.first_attempt], attempts[row.second_attempt]
        gaps.append(_finding('interval-conflict', first,
            'closed possible-effect window conflicts with entry ' + str(second.entry.ordinal)))
    for a in attempts:
        if a.context != 'runtime':
            continue
        if a.source_name in OPEN_NAMES and a.write_reasons:
            violations.append(_finding('forbidden-open-intent', a, ', '.join(a.write_reasons)))
        if a.intent == 'path-mutation-attempt':
            violations.append(_finding('forbidden-path-mutation', a, 'fixed output policy forbids namespace mutation intent'))
        if a.source_name not in FD_NAMES | OPEN_NAMES and a.intent != 'path-mutation-attempt':
            gaps.append(_finding('unsupported-route', a, 'no fixed rule for this runtime BSD route'))
        for reason in a.unsupported_reasons:
            gaps.append(_finding('unsupported-frame', a, reason))
        if a.source_name in ('write', 'write_nocancel', 'pwrite', 'pwrite_nocancel', 'fsync', 'fsync_nocancel', 'ftruncate'):
            gaps.append(_finding('unresolved-output-binding', a,
                'pre-exec READY provenance supplies no post-exec output exemption; failed calls may have partial effects'))
        if a.outcome is not None and a.outcome.disposition == 'kernel-error':
            if a.source_name in ('close', 'close_nocancel'):
                gaps.append(_finding('failed-close-state', a, 'slot may already be released before close error'))
            if a.source_name == 'dup2':
                gaps.append(_finding('failed-dup2-state', a, 'target may already be closed/reserved before error'))

    states, history, serial = {}, [], 0
    raw_digest = recipe.source.raw.raw_sha256

    def state(fd):
        return states.get(fd, FdState(fd, 0, 'unknown', None, None, 0))

    def change(fd, kind, key, cloexec, ordinal, window, reason, source=None):
        nonlocal serial
        if fd is None or not 0 <= fd <= INT_MAX:
            return
        _V1._require(fd in states or len(states) < MAX_SLOTS, 'FD policy slot storage bound')
        _V1._require(len(history) < MAX_TRANSITIONS, 'FD policy history bound')
        prior = state(fd)
        serial += 1
        value = FdState(fd, serial, kind, key, cloexec, ordinal, source)
        states[fd] = value
        history.append(FdTransition(ordinal, fd, prior.version, serial, kind, key, source, window, reason, cloexec))

    def invalidate(ordinal, window, reason):
        for fd in tuple(states):
            change(fd, 'unknown', None, None, ordinal, window, reason)

    seeds = {seed.child.fd: seed.capture_key for seed in recipe.conditional_output_seeds}
    for row in recipe.launch.objects:
        change(row.fd, 'ready-output' if row.fd in seeds else 'unknown', seeds.get(row.fd),
            bool(row.descriptor_flags & 1), 0, (0, 0), 'pre-exec READY provenance only')
    by_index = {w.attempt_index: w for w in windows}
    events = []
    opaque_horizon = False
    for transition in recipe.images.transitions:
        events.append((transition.success.raw_scalars[1], 0, transition.success.ordinal, 'exec', transition))
    for i, a in enumerate(attempts):
        if a.context == 'runtime':
            w = by_index[i]
            if w.unknown_effects:
                events.append((w.start_ns, -1, w.entry_ordinal, 'opaque', (a, w)))
            events.append((w.end_ns, 1, w.end_ordinal, 'post', (i, a, w)))
        elif a.context == 'bootstrap' and a.source_name in ('close', 'close_nocancel'):
            events.append((a.returned.raw_scalars[1], 1, a.returned.ordinal, 'bootstrap-close', a))
    for _, _, _, kind, value in sorted(events, key=lambda event: event[:3]):
        if kind == 'opaque':
            a, w = value
            if not opaque_horizon:
                opaque_horizon = True
                invalidate(w.entry_ordinal, (w.entry_ordinal, w.end_ordinal),
                    'opaque effects have no proved completion bound; certainty retired from ENTRY onward')
            continue
        if kind == 'exec':
            transition = value
            invalidate(transition.success.ordinal, (transition.entry.ordinal, transition.success.ordinal),
                       'exec retires ALL binding certainty including the initial image')
            continue
        if kind == 'bootstrap-close':
            a = value
            change(a.fd, 'absent', None, None, a.returned.ordinal,
                   (a.entry.ordinal, a.returned.ordinal), 'validated bootstrap endpoint close')
            continue
        index, a, w = value
        interval = (w.entry_ordinal, w.end_ordinal)
        # These are post-interval facts. Every possible lookup inside a touching
        # or intersecting mutation window is barred; no effect point is chosen.
        if opaque_horizon:
            # A return from an unhandled route does not close asynchronous or
            # unknown effects. Later known calls cannot rebuild precise lineage.
            for fd in set(w.mutation_slots) | set(w.lookup_slots):
                change(fd, 'unknown', None, None, w.end_ordinal, interval,
                       'sticky opaque-effect horizon forbids later precise state')
            continue
        if index in conflicted:
            if w.allocation:
                invalidate(w.end_ordinal, interval, 'conflicting allocation/reservation window')
            for fd in w.mutation_slots:
                change(fd, 'unknown', None, None, w.end_ordinal, interval, 'conflicting lookup/effect window')
            continue
        success = a.outcome is not None and a.outcome.disposition == 'kernel-success'
        if a.source_name in ('close', 'close_nocancel'):
            change(a.fd, 'absent' if success else 'unknown', None, None, w.end_ordinal, interval,
                   'conditional close postcondition after entire isolated window' if success else 'failed close poisons slot')
        elif a.source_name in OPEN_NAMES:
            if success:
                fd = a.outcome.primary_result
                key = hashlib.sha256((raw_digest + ':open:' + str(a.entry.ordinal)).encode()).hexdigest()
                change(fd, 'untrusted-open', key, bool(a.flags_u32 & _OPEN.FLAGS['O_CLOEXEC']),
                       w.end_ordinal, interval, 'read/open result has no output authority or resolved backing')
        elif a.source_name in ('dup', 'dup2'):
            target = a.outcome.primary_result if success else a.target_fd
            if not success:
                if a.source_name == 'dup2':
                    change(target, 'unknown', None, None, w.end_ordinal, interval, 'failed dup2 poisons target')
                continue
            previous = state(a.source_fd)
            if a.source_name == 'dup2' and a.source_fd == a.target_fd:
                # This source branch performs no slot or flag change. Preserve
                # its analysis version as well; the history is an observation,
                # not an invented replacement or kernel generation.
                _V1._require(len(history) < MAX_TRANSITIONS, 'FD policy history bound')
                history.append(FdTransition(w.end_ordinal, target, previous.version, previous.version,
                    previous.state, previous.analysis_binding_key, a.source_fd, interval,
                    'source-consistent same-fd dup2 preserves binding/flags', previous.cloexec))
            else:
                change(target, 'conditional-alias' if previous.analysis_binding_key is not None else 'unknown',
                       previous.analysis_binding_key, False, w.end_ordinal, interval,
                       'conditional chosen-source alias after entire stable window; no kernel/OFD identity', a.source_fd)
    status = 'incomplete' if gaps else 'forbidden-intent' if violations else 'source-conditional-clean'
    return RuntimeFdPolicy('darwin-runtime-fd-policy-v1', status, recipe.source, recipe, attempts,
        accounting, windows, conflicts, tuple(history), tuple(states[fd] for fd in sorted(states)),
        tuple(violations), tuple(gaps))


def evaluate_runtime_fd_policy_raw(program: bytes, probes: bytes, errors: bytes,
                                   event_lines: Iterable[bytes], *, owner_pid: int, target_pid: int,
                                   contract_bytes: bytes, launch_evidence: RuntimeRecipeEvidence) -> RuntimeFdPolicy:
    """Consume original runtime evidence once; emit finite conditional policy.

    Complete physical validation precedes facts. An image-unsupported capture
    retains every entry but emits no successful state prefix. Invalid byte
    evidence/transport raises. No caller-created capture or authority is accepted.
    """
    try:
        recipe = _RECIPE.pair_runtime_recipe_raw(program, probes, errors, event_lines,
            owner_pid=owner_pid, target_pid=target_pid, contract_bytes=contract_bytes,
            launch_evidence=launch_evidence)
    except _IMAGES.ImageValidationError as error:
        if error.capture is None:
            raise
        return _whole_incomplete(error.capture, contract_bytes, str(error))
    attempts, accounting = _partition(recipe, contract_bytes)
    return _run(recipe, attempts, accounting)
