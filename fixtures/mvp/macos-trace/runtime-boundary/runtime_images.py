"""Fixed v2 raw image/thread correlations; no native, FD or effect admission.

Only original physical streams are public inputs. Complete transport validation
precedes the private bootstrap stage and every later image/lifetime operation.
"""
from dataclasses import dataclass, replace
import hashlib
import importlib.util
from pathlib import Path
from typing import Iterable, Optional

_HERE = Path(__file__).resolve().parent
_V1_SHA256 = '118fe319f42e31d051e7fd5653576d8e9d643ea3029f4b778b4f7b97b3eb689a'
with (_HERE / 'runtime_boundary.py').open('rb') as _stream:
    _code = _stream.read(65537)
if len(_code) > 65536 or hashlib.sha256(_code).hexdigest() != _V1_SHA256:
    raise ValueError('runtime-images fixed boundary helper identity')
del _stream, _code
_spec = importlib.util.spec_from_file_location('_runtime_images_fixed_boundary', _HERE / 'runtime_boundary.py')
_V1 = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(_V1)
del _spec

RawValidationError = _V1.RawValidationError
LaunchEvidence = _V1.LaunchEvidence
_require = _V1._require
_RAW = _V1._RAW
MAX_EXECS = 16
MAX_THREAD_INSTANCES = 256
MAX_SHADOW_CONTEXT = 64
PROFILE_MARKER = b'/* glue-runtime-images-v2; quiescent-exec; no-process-creation */\n'
SOURCE_COMMIT = _V1.SOURCE_COMMIT


def expected_images_program(target_pid: int) -> bytes:
    """Independent fixed reader template; no native producer import/execution."""
    return _V1.expected_program(target_pid).replace(_V1.PROFILE_MARKER, PROFILE_MARKER, 1)


class ImageValidationError(RawValidationError):
    """No image result; optional capture is a completely validated raw stream."""
    def __init__(self, message, capture=None):
        super().__init__(message)
        self.capture = capture


@dataclass(frozen=True)
class ThreadInstance:
    capture_instance: int
    tid: int
    generation: int  # Capture-local count, never a kernel generation ID.
    image_epoch: int
    origin: str
    declaration: Optional[object]
    start: Optional[object]
    image_replaced_at: Optional[object]
    retirement: Optional[object]
    end_reason: str
    kernel_generation_attested: bool = False


@dataclass(frozen=True)
class ImagePair:
    image_epoch: int
    thread_instance: int
    correlation_id: tuple[int, int]
    entry: object
    returned: object


@dataclass(frozen=True)
class ImageTransition:
    old_image_epoch: int
    new_image_epoch: int
    old_thread_instance: int
    new_thread_instance: int
    entry: object
    returned: Optional[object]
    success: object
    proc_start: object
    lwp_start: object
    requested_path: Optional[bytes]
    artifact_sha256: Optional[str]
    identity_basis: str
    pathname_observed: bool = False
    native_identity_attested: bool = False
    successful_return_invented: bool = False


@dataclass(frozen=True)
class LifecycleBinding:
    source_ordinal: int
    thread_instance: int  # Subject: detail's declared TID for creation records.
    image_epoch: int
    role: str
    source_actor_instance: int


@dataclass(frozen=True)
class UnboundShadowContext:
    source: object
    image_epoch: None = None
    thread_instance: None = None
    live_pid_terminal: bool = False
    image_attribution_resolved: bool = False
    filesystem_effects_interpreted: bool = False


@dataclass(frozen=True)
class ProcessTerminalCall:
    image_epoch: int
    thread_instance: int
    entry: object
    exit_context: object
    successful_return_invented: bool = False


@dataclass(frozen=True)
class RuntimeImages:
    protocol: str
    source: object
    launch: object
    pairs: tuple[ImagePair, ...]
    attachment_return: Optional[object]
    transitions: tuple[ImageTransition, ...]
    threads: tuple[ThreadInstance, ...]
    lifecycle_bindings: tuple[LifecycleBinding, ...]
    unbound_shadows: tuple[UnboundShadowContext, ...]
    terminating_call: Optional[ProcessTerminalCall]
    unresolved_shadow_attribution: bool
    native_calibration: bool = False
    protected_target_attested: bool = False
    output_capabilities_seeded: bool = False
    successful_effect_ordering: bool = False
    state_feed_eligible: bool = False
    full_trace_acceptance: bool = False

    def to_dict(self):
        return _V1._plain(self)


def _walk(capture, launch, table):
    initial = _V1._initial_image(capture, launch, table)
    first = initial.selected_exec
    prefix = capture.phases[:initial.next_phase_index]
    threads, current, generations = [], {}, {}
    pending, pairs, transitions, bindings, shadows = {}, [], [], [], []

    def make_thread(tid, epoch, origin, declaration=None, start=None, state='active'):
        _require(0 < tid <= _V1.U64 and len(threads) < MAX_THREAD_INSTANCES,
                 'images thread instance bound/range')
        previous = current.get(tid)
        _require(previous is None or (threads[previous]['state'] == 'retired' and
                                     threads[previous]['retirement'] is not None),
                 'images numeric TID reused before observed retirement')
        generation = generations.get(tid, 0) + 1
        generations[tid] = generation
        index = len(threads)
        threads.append(dict(capture_instance=index, tid=tid, generation=generation,
            image_epoch=epoch, origin=origin, declaration=declaration, start=start,
            image_replaced_at=None, retirement=None, end_reason='unresolved', state=state))
        current[tid] = index
        return index

    def bind(raw, index, role, source_actor=None):
        bindings.append(LifecycleBinding(raw.ordinal, index, threads[index]['image_epoch'], role,
                                         index if source_actor is None else source_actor))

    old_exit = next((p for p in prefix if p.raw_scalars[0] == 11 and
                     p.raw_scalars[3] == first.old_tid), None)
    old_index = make_thread(first.old_tid, 0, 'bootstrap-first-observation')
    threads[old_index].update(image_replaced_at=first.success, retirement=old_exit,
        end_reason='image-replaced', state='retired' if old_exit is not None else 'image-replaced')
    declaration = next((p for p in prefix if p.raw_scalars[0] == 9 and
                        p.raw_scalars[4] == first.new_tid), None)
    new_index = make_thread(first.new_tid, 1, 'exec-success', declaration, first.lwp_start)
    if declaration is not None:
        bind(declaration, new_index, 'exec-thread-declaration', old_index)
    if old_exit is not None:
        bind(old_exit, old_index, 'old-image-lwp-exit')
    for raw, role in ((first.success, 'exec-success'), (first.proc_start, 'exec-proc-start'),
                      (first.lwp_start, 'exec-lwp-start')):
        bind(raw, new_index, role)
    transitions.append(ImageTransition(0, 1, old_index, new_index, first.entry,
        first.returned, first.success, first.proc_start, first.lwp_start,
        launch.executable, launch.target_sha256, 'supplied-initial-launch-byte-binding'))
    pairs.extend(ImagePair(pair.image_epoch, old_index, pair.correlation_id,
                            pair.entry, pair.returned) for pair in initial.pairs)
    shadows.extend(UnboundShadowContext(p) for p in prefix
                   if p.raw_scalars[0] == 18 and p.raw_scalars[7] & _RAW.SHADOW_BIT)
    exec_by_old = {old_index: 0}
    epoch, transition, terminal_call, closing = 1, None, None, False
    last_time = prefix[-1].raw_scalars[1]
    last_call = False

    def actor(tid, *, states=('active',)):
        index = current.get(tid)
        _require(index is not None and threads[index]['state'] in states,
                 'images inactive/undeclared actor')
        return index

    for raw in capture.phases[initial.next_phase_index:]:
        kind, timestamp, pid, tid, detail = raw.raw_scalars[:5]
        call = kind in (2, 3, 15, 16)
        _require(timestamp >= last_time and
                 (timestamp != last_time or (call and last_call)),
                 'images backward/ambiguous lifecycle timestamp')
        last_time, last_call = timestamp, call
        if kind == 17:
            continue
        _require(kind not in (1, 4, 12, 13), 'images unsupported begin/process creation/spawn')
        _require(kind not in (15, 16), 'images opaque Mach/rights route unsupported')
        _require(kind != 8, 'images exec-failure route unsupported')
        if kind == 18 and raw.raw_scalars[7] & _RAW.SHADOW_BIT:
            _require(len(shadows) < MAX_SHADOW_CONTEXT, 'images shadow context bound')
            # P_REF_SHADOW is the old, replaced proc, not the live PID-hash
            # process. Its address is never bound to an image or live actor.
            shadows.append(UnboundShadowContext(raw))
            continue
        if closing:
            _require(kind in (11, 18), 'images activity after process exit context')
        if kind == 3 and raw.function == 'execve':
            index = current.get(tid)
            active_transition = transition is not None and index == transition['old']
            previous_transition = exec_by_old.get(index)
            _require(active_transition or previous_transition is not None,
                     'images exec return without original transition')
            entered = transition['entry'] if active_transition else transitions[previous_transition].entry
            returned = transition['returned'] if active_transition else transitions[previous_transition].returned
            _require(returned is None and threads[index]['retirement'] is None and
                     (entered.provider, entered.module, entered.function) ==
                     (raw.provider, raw.module, raw.function) and
                     entered.raw_scalars[2:4] == (pid, tid) and
                     raw.raw_scalars[5:] == (0, 0, 0, _V1.U64 - 1, _V1.U64 - 1),
                     'images duplicate/noncanonical exec return or return after retirement')
            phase = _V1._phase(raw, table)
            if active_transition:
                transition['returned'] = phase
            else:
                transitions[previous_transition] = replace(transitions[previous_transition], returned=phase)
            pending.pop(index, None)
            continue
        if kind == 11:
            retired_image = current.get(tid)
            if retired_image is not None and threads[retired_image]['state'] == 'image-replaced':
                _require(threads[retired_image]['retirement'] is None and retired_image not in pending,
                         'images duplicate/pending replaced-image thread retirement')
                threads[retired_image].update(retirement=raw, state='retired')
                bind(raw, retired_image, 'old-image-lwp-exit')
                continue
        if transition is not None:
            old = transition['old']
            if kind == 11 and tid == threads[old]['tid']:
                _require(threads[old]['retirement'] is None and
                         (not pending or (set(pending) == {old} and
                                          pending[old] is transition['entry'])),
                         'images duplicate/ambiguous old-image thread retirement')
                threads[old].update(retirement=raw, state='retired')
                bind(raw, old, 'old-image-lwp-exit')
                continue
            if transition['success'] is not None:
                new = transition['new']
                _require(tid == threads[new]['tid'], 'images wrong new-image startup actor')
                if transition['start'] is None:
                    _require(kind == 5, 'images exec-success must precede proc:start')
                    transition['start'] = raw
                    threads[new]['state'] = 'exec-start'
                    bind(raw, new, 'exec-proc-start')
                    continue
                _require(kind == 10, 'images proc:start must precede lwp-start')
                threads[new].update(start=raw, state='active')
                bind(raw, new, 'exec-lwp-start')
                transitions.append(ImageTransition(epoch - 1, epoch, old, new,
                    transition['entry'], transition['returned'], transition['success'],
                    transition['start'], raw, None, None, 'opaque-execve-pointer-words-only'))
                exec_by_old[old] = len(transitions) - 1
                transition = None
                continue
        if kind in (2, 3):
            _require(len(pairs) < _V1.MAX_PAIRS, 'images pair bound')
            if kind == 2:
                _require(transition is None, 'images overlapping/concurrent exec activity')
                index = actor(tid)
                _require(threads[index]['image_epoch'] == epoch and index not in pending,
                         'images overlapping entry/image actor')
                _require(raw.function not in _V1.UNSUPPORTED_ENTRIES, 'images unsupported syscall route')
                phase = _V1._phase(raw, table)
                if raw.function == 'execve':
                    live = [i for i, thread in enumerate(threads)
                            if thread['state'] not in ('retired', 'image-replaced')]
                    _require(len(transitions) < MAX_EXECS and live == [index] and not pending,
                             'images nonquiescent exec or exec bound')
                    transition = dict(old=index, entry=phase, returned=None, success=None,
                                      start=None, new=None, declaration=None)
                pending[index] = phase
                continue
            index = current.get(tid)
            _require(index is not None and index in pending, 'images arbitrary orphan return')
            entered = pending[index]
            _require(entered.function == raw.function and entered.provider == raw.provider and
                     entered.module == raw.module and entered.raw_scalars[2:4] == (pid, tid),
                     'images return family/actor mismatch')
            phase = _V1._phase(raw, table)
            _require(transition is None, 'images ordinary return during exec transition')
            actor(tid)
            pairs.append(ImagePair(epoch, index, (entered.ordinal, raw.ordinal), entered, phase))
            del pending[index]
        elif kind == 7:
            _require(transition is not None and transition['success'] is None,
                     'images success without unique exec entry')
            old = transition['old']
            _require(tid != threads[old]['tid'] and
                     (not pending or (set(pending) == {old} and pending[old] is transition['entry'])),
                     'images exec-success identity/pending ambiguity')
            if transition['declaration'] is None:
                new = make_thread(tid, epoch + 1, 'exec-success', state='exec-success')
            else:
                new = transition['declaration']
                _require(threads[new]['tid'] == tid and threads[new]['state'] == 'reserved-exec',
                         'images exec-success differs from declared new actor')
                threads[new]['state'] = 'exec-success'
            threads[old].update(image_replaced_at=raw, end_reason='image-replaced',
                state='retired' if threads[old]['retirement'] is not None else 'image-replaced')
            pending.pop(old, None)
            transition.update(success=raw, new=new)
            epoch += 1
            bind(raw, new, 'exec-success')
        elif kind == 5:
            raise RawValidationError('images proc:start without exec-success boundary')
        elif kind == 9:
            if transition is not None:
                old = transition['old']
                _require(transition['success'] is None and transition['declaration'] is None and
                         tid == threads[old]['tid'] and threads[old]['state'] == 'active',
                         'images ambiguous exec thread declaration')
                new = make_thread(detail, epoch + 1, 'exec-thread-declared', raw, state='reserved-exec')
                transition['declaration'] = new
                bind(raw, new, 'exec-thread-declaration', old)
            else:
                creator = actor(tid)
                _require(threads[creator]['image_epoch'] == epoch, 'images declaration from old image')
                new = make_thread(detail, epoch, 'lwp-declared', raw, state='reserved')
                bind(raw, new, 'ordinary-lwp-declaration', creator)
        elif kind == 10:
            index = actor(tid, states=('reserved',))
            _require(transition is None and threads[index]['image_epoch'] == epoch,
                     'images ordinary start across image boundary')
            threads[index].update(start=raw, state='active')
            bind(raw, index, 'ordinary-lwp-start')
        elif kind == 11:
            index = actor(tid, states=('active', 'image-replaced'))
            _require(index not in pending, 'images unmodeled pending call at LWP exit')
            threads[index].update(retirement=raw, state='retired')
            if threads[index]['end_reason'] == 'unresolved':
                threads[index]['end_reason'] = 'lwp-exit-observed'
            bind(raw, index, 'ordinary-lwp-exit' if threads[index]['image_epoch'] == epoch else 'old-image-lwp-exit')
        elif kind == 6:
            _require(transition is None and not closing, 'images process exit during transition/duplicate')
            index = actor(tid)
            _require(threads[index]['image_epoch'] == epoch, 'images process exit from old image')
            if pending:
                entered = pending.get(index)
                _require(set(pending) == {index} and entered.function == 'exit',
                         'images unresolved ordinary call at process exit')
                terminal_call = ProcessTerminalCall(epoch, index, entered, raw)
                pending.clear()
            closing = True
            bind(raw, index, 'process-exit-context')
        elif kind == 18:
            _require(closing and transition is None and not pending,
                     'images terminal without completed image/exit context')
        else:
            raise RawValidationError('images unsupported lifecycle route')
    _require(transition is None and not pending and closing and
             all(thread['state'] in ('retired', 'image-replaced') for thread in threads),
             'images unresolved final transition/call/thread lifetime')
    result_threads = tuple(ThreadInstance(**{key: value for key, value in thread.items() if key != 'state'})
                           for thread in threads)
    return RuntimeImages('darwin-runtime-images-pairs-v2', capture, launch,
        tuple(sorted(pairs, key=lambda pair: pair.entry.ordinal)), initial.attachment_return,
        tuple(transitions), result_threads, tuple(bindings), tuple(shadows), terminal_call, bool(shadows))


def pair_runtime_images_raw(program: bytes, probes: bytes, errors: bytes,
                            event_lines: Iterable[bytes], *, owner_pid: int, target_pid: int,
                            contract_bytes: bytes, launch_evidence: LaunchEvidence) -> RuntimeImages:
    """Validate every original phase once before returning bounded image facts.

    This fixed entry point accepts only v2 bytes. The byte evidence is supplied
    by a trusted collector and is not authenticated native/protected deployment.
    Unknown Mach/creation/rights or ambiguous lifetimes refuse with no prefix.
    """
    launch = _V1.validate_launch_evidence(launch_evidence, owner_pid=owner_pid, target_pid=target_pid)
    _V1._bytes(contract_bytes, _RAW.CONTRACT_BYTES, _RAW.CONTRACT_BYTES, 'pinned contract bytes')
    _require(_V1._sha(contract_bytes) == _RAW.CONTRACT_SHA256, 'pinned contract digest')
    table = _RAW._CONTRACT_HELPERS.parse_table(contract_bytes)
    capture = _V1._transport_fixed(program, probes, errors, event_lines, owner_pid, target_pid,
                                   expected_images_program(target_pid))
    try:
        return _walk(capture, launch, table)
    except RawValidationError as error:
        raise ImageValidationError(str(error), capture) from error
