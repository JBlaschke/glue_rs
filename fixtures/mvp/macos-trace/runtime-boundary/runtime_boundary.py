"""Strict source-selected raw runtime boundary; never a native or write oracle.

Every public pairing call consumes the physical raw stream exactly once. The
complete transport is validated before image/interval facts are exposed. Launch
bytes come from the trusted collector; checking their consistency authenticates
neither their native origin nor the protected installation that supplied them.
"""
from dataclasses import dataclass, fields, is_dataclass
import hashlib
import importlib.util
from pathlib import Path
import re
from typing import Iterable, Optional

_BASE = Path(__file__).resolve().parent.parent
DEPENDENCY_IDENTITIES = (
    ('runtime-boundary/runtime_physical.py', '02a1955354af4ce385ba4c126159eb773377652175a55a54359a403aadd4ce4a'),
    ('owned-trace-check/owned_trace_check.py', '1d8616b51002225c8b9abf4a18940c48f01d1ef97a3f7c54e120153ca8c978ec'),
    ('syscall-contract/syscall_contract.py', '35a4229894dd0373de1b312747e8acd1a23ae2074566391e8d28855ca0624dbf'),
)
for _name, _sha in DEPENDENCY_IDENTITIES:
    with (_BASE / _name).open('rb') as _stream:
        _code = _stream.read(65537)
    if len(_code) > 65536 or hashlib.sha256(_code).hexdigest() != _sha:
        raise ValueError('runtime-boundary dependency identity: ' + _name)
del _name, _sha, _stream, _code
_spec = importlib.util.spec_from_file_location('_runtime_boundary_raw',
                                              _BASE / 'owned-trace-check/owned_trace_check.py')
_RAW = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(_RAW)
del _spec
_spec = importlib.util.spec_from_file_location('_runtime_boundary_physical',
                                              _BASE / 'runtime-boundary/runtime_physical.py')
_PHYSICAL = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(_PHYSICAL)
del _spec

RawValidationError = _RAW.RawValidationError
_require = _RAW._require
U64 = (1 << 64) - 1
INT_MAX = (1 << 31) - 1
MAX_PHASES = 8192
MAX_PAIRS = 2048
MAX_THREADS = 256
MAX_TARGET_BYTES = 4194304
PROFILE_MARKER = b'/* glue-runtime-boundary-v1; selected-exec; no-process-creation */\n'
SOURCE_COMMIT = 'f6217f891ac0bb64f3d375211650a4c1ff8ca1ea'
UNSUPPORTED_ENTRIES = frozenset((
    'fork', 'vfork', 'posix_spawn', '__mac_execve', 'sendmsg',
    'sendmsg_nocancel', 'recvmsg', 'recvmsg_nocancel', 'sendmsg_x',
    'recvmsg_x', 'fileport_makefd', 'fileport_makeport',
))
_READ = frozenset(('read', 'read_nocancel'))
_WRITE = frozenset(('write', 'write_nocancel'))
_POLL = frozenset(('poll', 'poll_nocancel'))
_CLOSE = frozenset(('close', 'close_nocancel'))
_PREFIX = _READ | _WRITE | _POLL | _CLOSE | frozenset((
    'fstat', 'fstat64', 'fcntl', 'fcntl_nocancel', 'getpid', 'getppid',
    'sigaction', 'sigaltstack', 'sigpending', 'sigprocmask', '__pthread_sigmask',
))


def _sha(value):
    return hashlib.sha256(value).hexdigest()


def _bytes(value, low, high, label):
    _require(type(value) is bytes and low <= len(value) <= high, label)
    return value


def _uint(value, width, at):
    return int.from_bytes(value[at:at + width], 'big')


def _zero(value):
    return not any(value)


def _path(value):
    _require(value.startswith(b'/') and len(value) <= 4095 and b'\0' not in value,
             'request absolute path')
    parts = value.split(b'/')[1:]
    _require(value == b'/' or all(0 < len(p) <= 255 and p not in (b'.', b'..')
                                 for p in parts), 'request path components')


@dataclass(frozen=True)
class ObjectRow:
    fd: int
    descriptor_flags: int
    status_flags: int
    mode: int
    device: int
    inode: int
    links: int


@dataclass(frozen=True)
class LaunchEvidence:
    """Exact original bytes, not caller-asserted native success fields."""
    request: bytes
    catalog: bytes
    ready: bytes
    go: bytes
    exec_attempt: bytes
    target_artifact: bytes


@dataclass(frozen=True)
class LaunchBinding:
    owner_pid: int
    target_pid: int
    request_sha256: str
    catalog_sha256: str
    target_sha256: str
    runner_sources_sha256: str
    target_sources_sha256: str
    recipe_sha256: str
    executable: bytes
    cwd: bytes
    kept_fds: tuple[int, ...]
    objects: tuple[ObjectRow, ...]
    signal_policy_sha256: str
    evidence_sha256: str
    native_origin_authenticated: bool = False
    protected_target_admitted: bool = False
    output_objects_matched: bool = False


def validate_launch_evidence(evidence: LaunchEvidence, *, owner_pid: int,
                             target_pid: int) -> LaunchBinding:
    """Validate canonical byte/binding consistency only; no filesystem I/O.

    PID/ownership and the native origin of these exact byte artifacts remain
    trusted collector obligations. No booleans can assert admission or a held
    output-handle match. The fixed catalog currently selects context-probe.
    """
    _require(type(evidence) is LaunchEvidence, 'exact launch evidence type')
    _RAW._integer(owner_pid, 1, INT_MAX, 'owner PID')
    _RAW._integer(target_pid, 1, INT_MAX, 'target PID')
    _require(owner_pid != target_pid, 'distinct launch PIDs')
    r = _bytes(evidence.request, 208, 16384, 'request bytes')
    c = _bytes(evidence.catalog, 194, 320, 'catalog bytes')
    target = _bytes(evidence.target_artifact, 1, MAX_TARGET_BYTES, 'target artifact bytes')
    _require(c[:8] == b'GLUENC01' and _uint(c, 2, 8) == 1 and
             _uint(c, 2, 10) == 192 and _uint(c, 4, 12) == len(c) and
             _zero(c[188:192]), 'canonical catalog header')
    a, b = _uint(c, 2, 184), _uint(c, 2, 186)
    _require(1 <= a <= 64 and b == 13 and 192 + a + b == len(c), 'catalog name lengths')
    build, leaf = c[192:192 + a], c[192 + a:]
    _require(re.fullmatch(rb'[A-Za-z0-9][A-Za-z0-9_.-]{0,63}', build) is not None and
             leaf == b'context-probe', 'fixed protected target catalog')
    root, data = c[24:40], c[40:56]
    _require(_uint(c, 8, 24) and _uint(c, 8, 40) and any(c[32:40]) and
             any(c[48:56]) and root != data, 'catalog mount profile')
    _require(_uint(c, 8, 16) == len(target) and c[56:88] == hashlib.sha256(target).digest(),
             'catalog target artifact identity')
    _require(all(any(c[i:i + 32]) for i in (88, 120, 152)), 'catalog source/recipe identities')
    _require(r[:8] == b'GLUENR01' and _uint(r, 2, 8) == 1 and
             _uint(r, 2, 10) == 208 and _uint(r, 4, 12) == len(r) and
             _zero(r[184:208]), 'canonical request header')
    get = lambda at: _uint(r, 4, at)
    _require(get(16) == 1 and all(get(i) == 1 for i in (96, 100, 104, 120)) and
             get(108) == 4096 and get(124) == 0 and 1 <= get(112) <= 10000 and
             1 <= get(116) <= 2000, 'request fixed selectors/bounds')
    uid, gid, count = get(20), get(24), get(28)
    groups = tuple(get(32 + 4 * i) for i in range(16))
    _require(1 <= uid <= INT_MAX and 1 <= gid <= INT_MAX and 1 <= count <= 16 and
             groups[0] == gid and all(0 <= n <= INT_MAX for n in groups[:count]) and
             len(set(groups[:count])) == count and not any(groups[count:]),
             'canonical request credentials')
    x, y = get(176), get(180)
    _require(1 <= x <= 4095 and 1 <= y <= 4095 and 208 + x + y == len(r),
             'request path lengths')
    executable, cwd = r[208:208 + x], r[208 + x:]
    _path(executable)
    _path(cwd)
    catalog_cwd = b'/System/Volumes/Data/Library/GlueMVPFixtures/' + build
    _require(cwd == catalog_cwd and executable == catalog_cwd + b'/context-probe' and
             r[128:160] == hashlib.sha256(c).digest(), 'request/catalog path and digest binding')
    digest = hashlib.sha256(r).digest()
    binding = owner_pid.to_bytes(4, 'big') + target_pid.to_bytes(4, 'big') + digest

    def status(raw, kind):
        raw = _bytes(raw, 512, 512, 'object status record length/type')
        _require(raw[:8] == b'GLUEFS02' and _uint(raw, 2, 8) == 2 and
                 _uint(raw, 2, 10) == kind and _uint(raw, 4, 12) == 512 and
                 _uint(raw, 4, 16) == (5 if kind == 1 else 0) and
                 _uint(raw, 4, 20) == 256 and _zero(raw[24:32]) and
                 _zero(raw[488:]), 'canonical object status header')
        p = raw[32:288]
        _require(p[:8] == b'GLUEBS01' and _uint(p, 2, 8) == 1 and
                 _uint(p, 2, 10) == kind and _uint(p, 4, 12) == 256 and
                 p[16:56] == binding and _uint(p, 4, 64) == 0 and
                 _uint(p, 4, 68) == 3 and _uint(p, 4, 224) == 0 and
                 _uint(p, 4, 228) == 0xffffffff and _zero(p[232:]),
                 'canonical bound inner status')
        if kind == 1:
            _require(_uint(p, 4, 56) == _uint(p, 4, 60) == 0 and
                     tuple(_uint(p, 4, i) for i in (72, 76, 80, 84, 88)) ==
                     (uid, uid, gid, gid, count) and
                     tuple(_uint(p, 4, 92 + 4 * i) for i in range(16)) == groups and
                     p[156:172] == r[160:176] and any(p[192:224]), 'READY requested observations')
        else:
            _require(_uint(p, 4, 56) == 1 and _uint(p, 4, 60) == 13 and
                     _zero(p[72:224]) and _zero(raw[288:488]), 'EXEC_ATTEMPT canonical observations')
        return p

    ready = status(evidence.ready, 1)
    status(evidence.exec_attempt, 2)
    keep = tuple(_uint(ready, 4, 172 + 4 * i) for i in range(5))
    _require(keep[:3] == (0, 1, 2) and 3 <= keep[3] <= INT_MAX and
             3 <= keep[4] <= INT_MAX and keep[3] != keep[4], 'READY kept descriptors')
    rows = []
    for i, fd in enumerate(keep):
        raw = evidence.ready[288 + i * 40:328 + i * 40]
        values = tuple(_uint(raw, 4, j) for j in (0, 4, 8, 12)) + tuple(
            _uint(raw, 8, j) for j in (16, 24, 32))
        row = ObjectRow(*values)
        _require(row.fd == fd and row.descriptor_flags <= INT_MAX and
                 row.status_flags <= INT_MAX and row.mode <= 0xffff, 'READY row canonical integer/FD')
        # This is only the closed Darwin bootstrap topology, not an object match.
        _require(row.descriptor_flags == (0 if i < 3 else 1) and
                 (row.status_flags & 3) == (1 if i in (1, 2, 4) else 0) and
                 (i < 3 or bool(row.status_flags & 4)) and
                 (row.mode & 0o170000) == (0o100000 if i in (1, 2) else 0o010000),
                 'READY fixed descriptor shape')
        _require(i not in (1, 2) or row.links > 0, 'READY regular output link count')
        rows.append(row)
    go = _bytes(evidence.go, 64, 64, 'GO bytes')
    _require(go[:8] == b'GLUEFG02' and _uint(go, 2, 8) == 2 and
             _uint(go, 2, 10) == 64 and go[12:52] == binding and _zero(go[52:]),
             'canonical bound object GO')
    components = (r, c, evidence.ready, go, evidence.exec_attempt, target)
    evidence_hash = hashlib.sha256()
    for value in components:
        evidence_hash.update(len(value).to_bytes(8, 'big'))
        evidence_hash.update(value)
    return LaunchBinding(owner_pid, target_pid, digest.hex(), _sha(c), _sha(target),
                         c[120:152].hex(), c[88:120].hex(), c[152:184].hex(),
                         executable, cwd, keep, tuple(rows), ready[192:224].hex(),
                         evidence_hash.hexdigest())


def expected_program(target_pid: int) -> bytes:
    """Independent reader template; never imports/executes the C producer."""
    _RAW._integer(target_pid, 1, INT_MAX, 'program target PID')
    legacy = _RAW._expected_program(target_pid)
    first, rest = legacy.split(b'\n', 1)
    return first + b'\n' + PROFILE_MARKER + rest


@dataclass(frozen=True)
class RuntimeCapture:
    raw: _RAW.RawFacts
    phases: tuple[_RAW.OwnedRawPhase, ...]


@dataclass(frozen=True)
class CapturedMemory:
    source_ordinal: int
    payload: bytes


@dataclass(frozen=True)
class RuntimeStoppedCapture(RuntimeCapture):
    memory: tuple[CapturedMemory, ...]
    image_skip_ordinals: tuple[int, ...]


class BoundaryValidationError(RawValidationError):
    """No pairing result; capture exists only after complete transport validation."""
    def __init__(self, message, capture=None):
        super().__init__(message)
        self.capture = capture


@dataclass(frozen=True)
class AttachmentReturn:
    phase: _RAW.OwnedRawPhase
    source_route: str
    result: int
    entry_observed: bool = False
    complete_interval: bool = False


@dataclass(frozen=True)
class RuntimePair:
    image_epoch: int
    correlation_id: tuple[int, int]
    entry: object
    returned: object


@dataclass(frozen=True)
class SelectedExec:
    entry: object
    returned: Optional[object]
    success: _RAW.OwnedRawPhase
    proc_start: _RAW.OwnedRawPhase
    lwp_start: _RAW.OwnedRawPhase
    old_tid: int
    new_tid: int
    old_image_epoch: int = 0
    new_image_epoch: int = 1
    pathname_observed: bool = False
    native_protected_target_attested: bool = False


@dataclass(frozen=True)
class TerminatingCall:
    entry: object
    exit_context: _RAW.OwnedRawPhase
    successful_return_invented: bool = False


def _plain(value):
    if is_dataclass(value):
        return {field.name: _plain(getattr(value, field.name)) for field in fields(value)}
    if isinstance(value, tuple):
        return [_plain(item) for item in value]
    if isinstance(value, bytes):
        return value.hex()
    return value


@dataclass(frozen=True)
class RuntimeBoundary:
    protocol: str
    source: RuntimeCapture
    launch: LaunchBinding
    pairs: tuple[RuntimePair, ...]
    attachment_return: Optional[AttachmentReturn]
    selected_exec: SelectedExec
    terminating_call: Optional[TerminatingCall]
    bootstrap_phase_ordinals: tuple[int, ...]
    runtime_phase_ordinals: tuple[int, ...]
    native_calibration: bool = False
    protected_target_attested: bool = False
    output_capabilities_seeded: bool = False
    state_feed_eligible: bool = False
    full_trace_acceptance: bool = False

    def to_dict(self):
        return _plain(self)


def _transport(program, probes, errors, lines, owner, target):
    # Fixed v1 factory. No public caller can select other expected bytes.
    return _transport_fixed(program, probes, errors, lines, owner, target,
                            expected_program(target))


def _transport_fixed(program, probes, errors, lines, owner, target, required_program):
    """Private legacy wrapper; existing fixed factories preserve their shape."""
    return _transport_common(program, probes, errors, lines, owner, target, required_program,
                             stopped=False)


def _transport_stopped(program, probes, errors, lines, owner, target, required_program):
    # Private fixed diagnostic entry; no public grammar/policy argument exists.
    return _transport_common(program, probes, errors, lines, owner, target, required_program,
                             stopped=True)


def _transport_common(program, probes, errors, lines, owner, target, required_program, *, stopped):
    """One bounded physical pass; internal factories select a closed grammar."""
    _RAW._bounded_bytes(program, _RAW.MAX_PROGRAM_BYTES, 'program bytes')
    _RAW._bounded_bytes(probes, _RAW.MAX_INVENTORY_BYTES, 'inventory bytes')
    _RAW._bounded_bytes(errors, _RAW.MAX_ERROR_BYTES, 'error bytes')
    _require(not errors, 'runtime profile nonempty errors')
    _require(program == required_program, 'fixed runtime profile program bytes')
    inventory, inventory_counts = _RAW._inventory(probes)
    epids, clauses, counts, phases = {}, {}, [0] * (24 if stopped else 19), []
    memory, skip = [], []
    if stopped:
        for function in ('proc_info', 'wait4', 'wait4_nocancel', 'kill'):
            for phase_name in ('entry', 'return'):
                _require(any(names[0] == 'syscall' and names[2:] == (function, phase_name)
                             for names, _ in inventory.values()),
                         'stopped required owner-control probe absent')
    raw_hash = hashlib.sha256()
    size = begin = terminal = end = shadow = cleanup = 0
    terminal_words = None
    for ordinal, line in enumerate(lines, 1):
        _RAW._bounded_bytes(line, _RAW.MAX_EVENT_BYTES, 'event line bytes')
        _require(line.endswith(b'\n') and b'\n' not in line[:-1] and b'\r' not in line,
                 'one complete LF event')
        _RAW._stream_budget(ordinal - 1, size, len(line))
        _require(ordinal <= MAX_PHASES and not end, 'runtime retained-event bound/after END')
        payload = b''
        if stopped:
            decoded = _PHYSICAL._stopped_event(_RAW, line, ordinal, inventory)
            kind, epid, probe, words, cpu = (decoded.kind, decoded.epid, decoded.probe,
                                            decoded.words, decoded.cpu)
            payload = decoded.memory
        else:
            kind, epid, probe, words, cpu = _PHYSICAL._legacy_event(_RAW, line, ordinal, inventory)
        clause = (probe, kind)
        _require(epid not in epids or epids[epid] == clause, 'runtime EPID rebound')
        _require(clause not in clauses or clauses[clause] == epid, 'runtime multiple clause EPIDs')
        _require(epid in epids or len(epids) < _RAW.MAX_ENABLINGS, 'runtime enabling bound')
        epids[epid], clauses[clause] = clause, epid
        actor, detail = words[2], words[4]
        if kind in (1, 17):
            _require(actor == owner and detail == 0, 'runtime controller identity')
        elif kind == 18:
            _require(detail == target and words[6] != 0 and words[7] <= _RAW.U32,
                     'runtime target exited identity')
        elif stopped and (kind in (20, 21, 22, 23) or kind == 2 and actor == owner):
            _require(actor == owner and 0 < detail <= _RAW.U64 and
                     inventory[probe][0][2] in ('proc_info', 'wait4', 'wait4_nocancel', 'kill'),
                     'stopped owner control identity')
            skip.append(ordinal)
        elif stopped and kind == 19:
            _require(actor == target and detail == 1 and words[5:] == (words[3], 17),
                     'stopped selected marker header')
            skip.append(ordinal)
        else:
            _require(actor == target, 'runtime target actor')
            if kind in (2, 3, 5, 7, 15, 16):
                _require(detail == owner, 'runtime target parent')
            if kind in (10, 11, 12):
                _require(detail == 0, 'runtime lifecycle zero detail')
            if kind == 4:
                _RAW._integer(detail, 1, INT_MAX, 'runtime created PID')
        if kind == 1:
            _require(not begin, 'runtime duplicate BEGIN')
            begin = ordinal
        else:
            _require(begin != 0, 'runtime event before BEGIN')
        if terminal:
            _require(kind in (11, 17) or stopped and actor == owner and
                     kind in (2, 20, 21, 22, 23), 'runtime activity after terminal')
        if kind == 18:
            if words[7] & _RAW.SHADOW_BIT:
                shadow += 1
            else:
                _require(not terminal, 'runtime duplicate terminal')
                terminal, terminal_words = ordinal, words
        if kind == 11 and terminal:
            cleanup += 1
        if kind == 17:
            _require(terminal, 'runtime END before terminal')
            end = ordinal
        phases.append(_RAW.OwnedRawPhase(ordinal, cpu, probe, epid,
                                         *inventory[probe][0], tuple(words)))
        if payload:
            memory.append(CapturedMemory(ordinal, payload))
        counts[kind] += 1
        size += len(line)
        raw_hash.update(line)
    _require(begin and terminal and end, 'runtime incomplete BEGIN/terminal/END')
    raw = _RAW.RawFacts(owner, target, len(program), _sha(program), len(probes), _sha(probes),
        len(inventory), inventory_counts, len(epids), len(phases), size, raw_hash.hexdigest(),
        0, _sha(errors), tuple(counts), begin, terminal, end, shadow, cleanup,
        terminal_words[2], terminal_words[5], terminal_words[6], terminal_words[7])
    if stopped:
        return RuntimeStoppedCapture(raw, tuple(phases), tuple(memory), tuple(skip))
    return RuntimeCapture(raw, tuple(phases))


def _success(phase):
    a, b, secondary, error, errno = phase.raw_scalars[5:]
    _require(a == b and secondary == 0 and error == errno == 0,
             'bootstrap canonical successful return')
    return a


def _phase(phase, table):
    if phase.raw_scalars[0] not in (2, 3):
        return phase
    return _RAW._bsd_phase(_RAW._CONTRACT_HELPERS, table, phase.ordinal,
                           phase.cpu, phase.epid, phase.probe_id,
                           (phase.provider, phase.module, phase.function, phase.name),
                           list(phase.raw_scalars))


@dataclass(frozen=True)
class _InitialImage:
    # Internal only, after complete physical transport validation. Original
    # ordinals/records are retained; no terminal or return record is synthesized.
    pairs: tuple[RuntimePair, ...]
    attachment_return: Optional[AttachmentReturn]
    selected_exec: SelectedExec
    thread_states: tuple[tuple[int, str], ...]
    next_phase_index: int


def _pair(capture, launch, table):
    # Preserve the fixed v1 whole-capture contract and public call signature.
    return _pair_walk(capture, launch, table, initial_only=False)


def _initial_image(capture, launch, table, *, skipped_ordinals=()):
    # Private fixed bootstrap stage for v2. It is never a public successful
    # prefix; v2 must validate every remaining original phase before returning.
    return _pair_walk(capture, launch, table, initial_only=True, skipped_ordinals=skipped_ordinals)


def _pair_walk(capture, launch, table, *, initial_only, skipped_ordinals=()):
    pairs, pending, threads = [], {}, {}
    attachment = exec_entry = exec_return = success = start = lwp = termination = None
    bootstrap_tid = None
    epoch = gate_bytes = attempt_bytes = 0
    gate_eof = gate_closed = closing = old_exit_seen = False
    last_time, last_call = -1, False
    prefix_shadows = 0
    bootstrap, runtime = [], []
    skipped = frozenset(skipped_ordinals)
    child_position = 0
    gate, status_fd = launch.kept_fds[3:]

    def active(tid):
        _require(threads.get(tid) == 'active', 'runtime call on inactive/undeclared thread')

    for raw in capture.phases:
        if raw.ordinal in skipped:
            continue
        child_position += 1
        kind, timestamp, pid, tid, detail = raw.raw_scalars[:5]
        call = kind in (2, 3, 15, 16)
        _require(timestamp >= last_time and
                 (timestamp != last_time or (call and last_call)),
                 'runtime backward/ambiguous lifecycle timestamp')
        last_time, last_call = timestamp, call
        (bootstrap if epoch == 0 else runtime).append(raw.ordinal)
        if kind in (1, 17):
            continue
        _require(kind not in (4, 12, 13), 'runtime process creation/spawn unsupported')
        _require(kind not in (15, 16), 'runtime opaque Mach/rights route unsupported')
        _require(kind != 8, 'runtime exec-failure route unsupported')
        if kind == 18 and raw.raw_scalars[7] & _RAW.SHADOW_BIT:
            prefix_shadows += 1
            _require(exec_entry is not None and prefix_shadows <= 1 and
                     (initial_only or capture.raw.shadow_exits <= 1),
                     'runtime shadow exit outside selected transition')
            continue
        if closing:
            _require(kind in (11, 18), 'runtime activity after exit context')
        if bootstrap_tid is None:
            _require(kind in (2, 3), 'runtime first bootstrap event is not BSD phase')
            bootstrap_tid = tid
            threads[tid] = 'active'
        if kind == 7:
            _require(success is None and exec_entry is not None and
                     set(pending) <= {bootstrap_tid} and tid != bootstrap_tid and
                     threads.get(tid) in (None, 'reserved') and gate_closed and
                     attempt_bytes == 512, 'runtime selected exec transition')
            _require(len(threads) < MAX_THREADS, 'runtime thread bound')
            success = raw
            pending.pop(bootstrap_tid, None)
            threads[bootstrap_tid] = 'retired' if old_exit_seen else 'exec-retired'
            threads[tid] = 'exec-success'
            epoch = 1
            continue
        if success is not None and lwp is None:
            if initial_only and kind == 3 and tid == bootstrap_tid and raw.function == 'execve':
                _require(exec_return is None and threads[tid] == 'exec-retired' and
                         (raw.provider, raw.module) == (exec_entry.provider, exec_entry.module) and
                         raw.raw_scalars[5:] == (0, 0, 0, U64 - 1, U64 - 1),
                         'runtime duplicate/noncanonical exec return after image replacement')
                exec_return = _phase(raw, table)
                continue
            if kind == 11 and tid == bootstrap_tid:
                _require(threads[tid] == 'exec-retired', 'runtime duplicate old exec thread exit')
                threads[tid] = 'retired'
                continue
            if start is None:
                _require(kind == 5 and tid == success.raw_scalars[3],
                         'runtime exec-success must precede proc:start')
                start = raw
                continue
            _require(kind == 10 and tid == success.raw_scalars[3],
                     'runtime proc:start must precede lwp-start')
            lwp = raw
            threads[tid] = 'active'
            if initial_only:
                _require(set(threads) == {bootstrap_tid, tid} and
                         threads[bootstrap_tid] in ('retired', 'exec-retired') and
                         threads[tid] == 'active',
                         'runtime unresolved initial exec thread declaration')
                transition = SelectedExec(exec_entry, exec_return, success, start, lwp,
                                          bootstrap_tid, success.raw_scalars[3])
                return _InitialImage(tuple(pairs), attachment, transition,
                                     tuple(threads.items()), raw.ordinal)
            continue
        if kind == 5:
            raise RawValidationError('runtime extra proc:start boundary')
        if call:
            _require(len(pairs) < MAX_PAIRS, 'runtime pair bound')
            if kind == 2:
                _require(exec_entry is None or epoch == 1, 'runtime activity after pending selected exec')
                _require(raw.function not in UNSUPPORTED_ENTRIES, 'runtime unsupported syscall route')
                _require(raw.function != 'execve' or (epoch == 0 and exec_entry is None),
                         'runtime later/duplicate exec unsupported')
            active(tid)
            phase = _phase(raw, table)
            if kind == 2:
                _require(tid not in pending, 'runtime overlapping entry')
                if epoch == 0:
                    _require(tid == bootstrap_tid and (raw.function in _PREFIX or raw.function == 'execve'),
                             'runtime unknown trusted bootstrap operation')
                    words = raw.raw_scalars[5:]
                    if raw.function in _READ:
                        _require(not gate_closed and not gate_eof and words[0] == gate and words[1] != 0 and
                                 words[2] == (64 - gate_bytes if gate_bytes < 64 else 1),
                                 'bootstrap exact remaining gate read arguments')
                    elif raw.function in _WRITE:
                        _require(gate_closed and words[0] == status_fd and words[1] != 0 and
                                 attempt_bytes < 512 and words[2] == 512 - attempt_bytes,
                                 'bootstrap exact remaining EXEC_ATTEMPT write arguments')
                    elif raw.function in _CLOSE:
                        _require(not gate_closed and words[0] == gate and gate_bytes == 64 and gate_eof,
                                 'bootstrap exact gate close prerequisite')
                    elif raw.function in _POLL:
                        _require(words[0] != 0 and words[1] == 1 and 1 <= words[2] <= 10000,
                                 'bootstrap bounded single-FD poll')
                    elif raw.function in ('fstat', 'fstat64', 'fcntl', 'fcntl_nocancel'):
                        _require(words[0] in (gate, status_fd), 'bootstrap endpoint observation FD')
                        if raw.function.startswith('fcntl'):
                            _require(words[1] == 3, 'bootstrap only F_GETFL')
                    elif raw.function == 'execve':
                        _require(gate_closed and attempt_bytes == 512 and not pending and all(words[i] for i in (0, 1, 2)),
                                 'bootstrap complete status before selected execve')
                        exec_entry = phase
                pending[tid] = phase
                continue
            if tid not in pending:
                _require(epoch == 0 and attachment is None and child_position == 2 and tid == bootstrap_tid,
                         'runtime arbitrary orphan return')
                value = _success(raw)
                name = raw.function
                _require((name in _WRITE and 1 <= value <= 512) or
                         (name in _READ and 1 <= value <= 64) or
                         (name in _POLL and 0 <= value <= 1), 'runtime unsupported attachment return')
                route = 'READY-write-tail' if name in _WRITE else ('GO-read-in-flight' if name in _READ else 'gate-poll-in-flight')
                if name in _READ:
                    gate_bytes = value
                attachment = AttachmentReturn(raw, route, value)
                continue
            entered = pending.pop(tid)
            _require(entered.function == raw.function and entered.provider == raw.provider and
                     entered.module == raw.module, 'runtime paired call identity')
            if epoch == 0 and entered.function == 'execve':
                _require(raw.raw_scalars[5:] == (0, 0, 0, U64 - 1, U64 - 1),
                         'selected exec return is not canonical EJUSTRETURN')
                exec_return = phase
                continue
            if epoch == 0:
                returned_words = raw.raw_scalars[5:]
                retry_errors = (4,) if raw.function in _POLL else (4, 35)
                retry = raw.function in (_READ | _WRITE | _POLL) and any(
                    returned_words == (U64, U64, U64, error, error) for error in retry_errors)
                if retry:
                    # The fixed BIO source retries these exact projections without
                    # changing its confirmed moved-byte count. This is not a
                    # general syscall no-effect assertion or an invented success.
                    pairs.append(RuntimePair(epoch, (entered.ordinal, raw.ordinal), entered, phase))
                    continue
                value = _success(raw)
                requested = entered.raw_scalars[7]
                if raw.function in _READ:
                    _require(value <= requested and gate_bytes + value <= 64 and
                             (value != 0 or gate_bytes == 64), 'bootstrap gate read result')
                    if value == 0:
                        gate_eof = True
                    gate_bytes += value
                elif raw.function in _WRITE:
                    _require(1 <= value <= requested, 'bootstrap status write result')
                    attempt_bytes += value
                elif raw.function in _POLL:
                    _require(value <= 1, 'bootstrap poll result')
                elif raw.function in _CLOSE:
                    _require(value == 0, 'bootstrap gate close failed')
                    gate_closed = True
                elif raw.function in ('fstat', 'fstat64'):
                    _require(value == 0, 'bootstrap fstat exact-zero success')
                elif raw.function in ('fcntl', 'fcntl_nocancel'):
                    fd = entered.raw_scalars[5]
                    _require(value <= INT_MAX and (value & 3) == (0 if fd == gate else 1) and
                             bool(value & 4), 'bootstrap F_GETFL access/nonblock observation')
                elif raw.function == 'getpid':
                    _require(value == launch.target_pid, 'bootstrap getpid observation')
                elif raw.function == 'getppid':
                    _require(value == launch.owner_pid, 'bootstrap getppid observation')
            pairs.append(RuntimePair(epoch, (entered.ordinal, raw.ordinal), entered, phase))
        elif kind == 9:
            active(tid)
            _require(detail not in threads and 0 < detail <= U64 and len(threads) < MAX_THREADS and
                     (epoch == 1 or (exec_entry is not None and tid == bootstrap_tid and
                                     not any(state == 'reserved' for state in threads.values()))),
                     'runtime thread declaration/reuse')
            threads[detail] = 'reserved'
        elif kind == 10:
            _require(epoch == 1 and threads.get(tid) == 'reserved', 'runtime thread start without declaration')
            threads[tid] = 'active'
        elif kind == 11:
            if epoch == 0 and tid == bootstrap_tid and exec_entry is not None:
                _require(not old_exit_seen and threads.get(tid) == 'active' and
                         (not pending or (set(pending) == {tid} and pending[tid] is exec_entry)),
                         'runtime old exec thread exit ambiguity')
                threads[tid] = 'exec-retired'
                old_exit_seen = True
            else:
                _require(threads.get(tid) in ('active', 'exec-retired') and tid not in pending,
                         'runtime thread exit/pending call')
                threads[tid] = 'retired'
        elif kind == 6:
            active(tid)
            _require(epoch == 1 and not closing, 'runtime exit before selected epoch/duplicate')
            if pending:
                entered = pending.get(tid)
                _require(len(pending) == 1 and entered is not None and entered.function == 'exit',
                         'runtime unresolved call at exit context')
                termination = TerminatingCall(entered, raw)
                pending.clear()
            closing = True
        elif kind == 18:
            _require(epoch == 1 and closing and not pending, 'runtime terminal without closed image')
        else:
            raise RawValidationError('runtime unsupported lifecycle')
    _require(success is not None and start is not None and lwp is not None and not pending and
             all(state in ('retired', 'exec-retired') for state in threads.values()),
             'runtime incomplete selected epoch or thread lifetime')
    transition = SelectedExec(exec_entry, exec_return, success, start, lwp,
                              bootstrap_tid, success.raw_scalars[3])
    return RuntimeBoundary('darwin-runtime-boundary-pairs-v1', capture, launch,
                           tuple(sorted(pairs, key=lambda pair: pair.entry.ordinal)),
                           attachment, transition, termination, tuple(bootstrap), tuple(runtime))


def pair_runtime_raw(program: bytes, probes: bytes, errors: bytes,
                     event_lines: Iterable[bytes], *, owner_pid: int, target_pid: int,
                     contract_bytes: bytes, launch_evidence: LaunchEvidence) -> RuntimeBoundary:
    """Pair the complete independently selected stream or refuse without a prefix.

    A semantic refusal carries only an immutable fully validated raw capture in
    BoundaryValidationError.capture. Transport/source/iterator failures expose
    no capture. Calls never open assets, run a provider or accept prebuilt pairs.
    """
    launch = validate_launch_evidence(launch_evidence, owner_pid=owner_pid, target_pid=target_pid)
    _bytes(contract_bytes, _RAW.CONTRACT_BYTES, _RAW.CONTRACT_BYTES, 'pinned contract bytes')
    _require(_sha(contract_bytes) == _RAW.CONTRACT_SHA256, 'pinned contract digest')
    table = _RAW._CONTRACT_HELPERS.parse_table(contract_bytes)
    capture = _transport(program, probes, errors, event_lines, owner_pid, target_pid)
    try:
        return _pair(capture, launch, table)
    except RawValidationError as error:
        raise BoundaryValidationError(str(error), capture) from error
