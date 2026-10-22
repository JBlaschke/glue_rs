"""Pure fixed owned-trace raw transport checks; no session acceptance or I/O."""
from dataclasses import dataclass
import hashlib
import json
import re
from typing import Iterable, Optional

MAX_PROGRAM_BYTES = 16384
MAX_INVENTORY_BYTES = 1048576
MAX_PROBES = 8192
MAX_ENABLINGS = 8192
MAX_ERROR_BYTES = 65536
MAX_RAW_BYTES = 134217728
MAX_EVENT_BYTES = 8191  # Backend char[8192] includes its terminating NUL.
MAX_EVENTS = 1000000
MAX_BSD_PHASES = 4096
CONTRACT_BYTES = 96972
CONTRACT_SHA256 = '31f96f93c2ca1bd58ae322a6d3c223dd764e5a763088cfed2dbf78a8a21104e2'
U32 = (1 << 32) - 1
U64 = (1 << 64) - 1
PID_MAX = (1 << 31) - 1
SHADOW_BIT = 0x20
_NAME = re.compile(r"[a-zA-Z0-9_.-]*", re.ASCII)
_HEX = re.compile(r"[0-9a-f]*", re.ASCII)
_PROC = {"create": 4, "start": 5, "exit": 6, "exec-success": 7,
         "exec-failure": 8, "lwp-create": 9, "lwp-start": 10, "lwp-exit": 11,
         "spawn-success": 12, "spawn-failure": 13, "exited": 18}
_REQUIRED = frozenset(range(1, 19)) - {14}
_EVENT_KEYS = frozenset(("event", "cpu", "epid", "probe_id", "record_bytes",
    "header_record_indexes", "kind", "timestamp", "pid", "tid", "detail",
    "provider", "module", "function", "name", "records"))
_RECORD_KEYS = frozenset(("action", "size", "offset", "hex"))


class RawValidationError(ValueError):
    """An input contract failed; no partial facts are returned."""


def _require(condition, message):
    if not condition:
        raise RawValidationError(message)


def _integer(value, low, high, label):
    _require(type(value) is int and low <= value <= high, label)
    return value


def _bounded_bytes(value, cap, label):
    _require(type(value) is bytes and len(value) <= cap, label)


@dataclass(frozen=True)
class RawFacts:
    """Bounded observations only, after complete raw validation and exhaustion."""
    owner_pid: int
    target_pid: int
    program_bytes: int
    program_sha256: str
    inventory_bytes: int
    inventory_sha256: str
    inventory_probes: int
    inventory_kind_counts: tuple[int, ...]  # indexes0..18;0/14 are always zero
    observed_enablings: int  # does not establish enabled/expected match counts
    events: int
    raw_bytes: int
    raw_sha256: str
    error_bytes: int  # zero
    error_sha256: str
    event_kind_counts: tuple[int, ...]
    begin_event: int
    terminal_event: int
    end_event: int
    shadow_exits: int
    post_terminal_lwp_exits: int
    terminal_actor_pid: int
    terminal_raw_exit: int  # not POSIX wait status
    terminal_address: int
    terminal_refcount: int


@dataclass(frozen=True)
class BsdEntryFacts:
    protocol: str
    name: str
    number: int
    family: str
    fields: tuple[tuple[str, int], ...]
    raw_words: tuple[int, ...]
    source_argument_count: int
    entry_attempt_observed: bool
    requirements: tuple[str, ...]
    contract_sha256: str
    full_trace_acceptance: bool
    scope: str


@dataclass(frozen=True)
class BsdReturnFacts:
    protocol: str
    primary_result_bits: int
    secondary_result_bits: int
    kernel_error_bits: int
    control_flow_unmodeled: bool
    full_trace_acceptance: bool
    scope: str


@dataclass(frozen=True)
class BsdPhase:
    """One raw phase, not a paired call, kernel generation or successful effect."""
    ordinal: int
    cpu: int
    probe_id: int
    epid: int
    provider: str
    module: str
    function: str
    name: str
    raw_scalars: tuple[int, ...]  # five header words, then all entry/return words
    source_contract_known: bool
    entry: Optional[BsdEntryFacts]
    returned: Optional[BsdReturnFacts]
    unsupported_reason: Optional[str]


@dataclass(frozen=True)
class BsdCoverage:
    entries: int
    returns: int
    known_entries: int
    unknown_entries: int
    supported_return_shapes: int
    unsupported_return_shapes: int
    control_flow_unmodeled_returns: int
    unknown_names: tuple[tuple[str, int], ...]  # counts phases, not calls


@dataclass(frozen=True)
class OwnedBsdObservations:
    protocol: str
    raw: RawFacts
    contract_sha256: str
    observations: tuple[BsdPhase, ...]
    coverage: BsdCoverage
    full_trace_acceptance: bool = False


def _contract_helpers():
    # Standard fixed helper-code import, separate from contract-asset access.
    # Neither this import nor the pure parser opens contracts.json. No sys.path/
    # sys.modules mutation, caller module selection or asset fallback is involved.
    import importlib.util
    from pathlib import Path
    path = Path(__file__).parent.parent / 'syscall-contract' / 'syscall_contract.py'
    spec = importlib.util.spec_from_file_location('_owned_bsd_source_contract', path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


_CONTRACT_HELPERS = _contract_helpers()


class _BsdProjection:
    def __init__(self, helpers, table):
        self.helpers, self.table, self.phases = helpers, table, []

    def take(self, ordinal, cpu, epid, probe, names, scalars):
        if scalars[0] not in (2, 3):
            return
        _require(len(self.phases) < MAX_BSD_PHASES, 'BSD phase projection bound')
        known = names[2] in self.table[1]
        entry = returned = reason = None
        words = scalars[5:]
        if scalars[0] == 2:
            if known:
                facts = self.helpers.entry_facts(names[2], words, self.table)
                entry = BsdEntryFacts(**(facts | {
                    'fields': tuple(facts['fields'].items()),
                    'raw_words': tuple(facts['raw_words']),
                    'requirements': tuple(facts['requirements']),
                }))
            else:
                reason = 'no pinned BSD source contract'
        else:
            try:
                returned = BsdReturnFacts(**self.helpers.return_facts(words))
            except self.helpers.UnsupportedContract as error:
                # Old transport accepts these raw shapes. Keep the phase and
                # explicitly unsupported projection, not a new transport rule.
                reason = str(error)
        self.phases.append(BsdPhase(ordinal, cpu, probe, epid, *names,
                                    tuple(scalars), known, entry, returned, reason))

    def finish(self, raw):
        observations = tuple(self.phases)
        entries = [p for p in observations if p.raw_scalars[0] == 2]
        returns = [p for p in observations if p.raw_scalars[0] == 3]
        unknown = {}
        for phase in observations:
            if not phase.source_contract_known:
                unknown[phase.function] = unknown.get(phase.function, 0) + 1
        known = sum(p.source_contract_known for p in entries)
        supported = sum(p.returned is not None for p in returns)
        coverage = BsdCoverage(len(entries), len(returns), known, len(entries) - known,
                               supported, len(returns) - supported,
                               sum(p.returned is not None and p.returned.control_flow_unmodeled
                                   for p in returns), tuple(sorted(unknown.items())))
        return OwnedBsdObservations('darwin-owned-bsd-observations-v1', raw,
                                    CONTRACT_SHA256, observations, coverage)


def _expected_program(target):
    # Independent fixed template. No producer import/execution or source parsing.
    # The spelling and order are byte-significant, including LF and no blank lines.
    def scalars(kind, detail, extra=""):
        return (f"trace((uint64_t){kind});trace((uint64_t)timestamp);"
                "trace((uint64_t)pid);trace((uint64_t)tid);"
                f"trace((uint64_t)({detail}));{extra}")

    lines = ["#pragma D option quiet",
             f"BEGIN {{ watched[{target}]=1;" + scalars(1, "0") + "}",
             "END {" + scalars(17, "0") + "}"]
    args8 = "".join(f"trace((uint64_t)arg{i});" for i in range(8))
    args4 = "".join(f"trace((uint64_t)arg{i});" for i in range(4))
    # Each tuple is one required fixed clause, including both Mach transports.
    for provider, name, kind, extra in (
        ("syscall", "entry", 2, args8),
        ("syscall", "return", 3, args4 + "trace((uint64_t)errno);"),
        ("mach_trap", "entry", 15, args8),
        ("mach_trap", "return", 16, "trace((uint64_t)arg0);"),
    ):
        lines.append(f"{provider}:::{name} /watched[pid]/ {{" + scalars(kind, "ppid", extra) + "}")
    for name, kind, detail, assignment in (
        ("create", 4, "args[0]->pr_pid", True),
        ("start", 5, "ppid", True),
        ("exec-success", 7, "ppid", True),
        ("exit", 6, "arg0", False),
        ("exec-failure", 8, "arg0", False),
        ("lwp-create", 9, "args[0]->pr_lwpid", False),
        ("lwp-start", 10, "0", False),
        ("lwp-exit", 11, "0", False),
        ("spawn-success", 12, "0", False),
        ("spawn-failure", 13, "arg0", False),
    ):
        lines.append(f"proc:::{name} /watched[pid]/ {{" +
                     ("watched[pid]=1;" if assignment else "") + scalars(kind, detail) + "}")
    lines.append("proc:::exited /watched[args[0]->pr_pid]/ {" +
                 scalars(18, "args[0]->pr_pid") +
                 "trace((uint64_t)arg1);trace((uint64_t)args[0]->pr_addr);"
                 "trace((uint64_t)((struct proc *)args[0]->pr_addr)->p_refcount);}")
    return ("\n".join(lines) + "\n").encode("ascii")


def _kind(names):
    provider, module, function, name = names
    for text, capacity in zip(names, (64, 64, 128, 64)):
        _require(type(text) is str and len(text) < capacity and _NAME.fullmatch(text),
                 "native probe name/capacity")
    if provider == "dtrace" and module == function == "":
        return {"BEGIN": 1, "END": 17}.get(name, 0)
    if provider in ("syscall", "mach_trap") and function:
        return {"entry": 2, "return": 3}.get(name, 0) + (13 if provider == "mach_trap" and name in ("entry", "return") else 0)
    if provider == "proc":
        return _PROC.get(name, 0)
    return 0


def _inventory(raw):
    _require(raw.endswith(b"\n"), "inventory missing final LF")
    _require(0 < raw.count(b"\n") <= MAX_PROBES, "inventory probe bound")
    try:
        rows = raw.decode("ascii").split("\n")[:-1]
    except UnicodeError as error:
        raise RawValidationError("non-ASCII inventory") from error
    _require(0 < len(rows) <= MAX_PROBES, "inventory probe bound")
    inventory, identities, counts = {}, set(), [0] * 19
    for row in rows:
        fields = row.split("\t")
        _require(len(fields) == 5, "inventory fields")
        text_id, *names = fields
        _require(re.fullmatch(r"[1-9][0-9]{0,9}", text_id), "inventory probe ID spelling")
        probe_id = _integer(int(text_id), 1, U32, "inventory probe ID range")
        names = tuple(names)
        kind = _kind(names)
        _require(kind in _REQUIRED, "inventory category")
        _require(probe_id not in inventory and names not in identities, "duplicate inventory identity")
        inventory[probe_id] = (names, kind)
        identities.add(names)
        counts[kind] += 1
    _require({k for k in _REQUIRED if counts[k]} == _REQUIRED, "missing required inventory category")
    return inventory, tuple(counts)


def _pairs(pairs):
    result = {}
    for key, value in pairs:
        _require(key not in result, "duplicate JSON key")
        result[key] = value
    return result


def _number(text):
    _require(len(text) <= 21, "JSON integer token bound")
    return int(text)


def _not_integer(_):
    raise RawValidationError("non-integer JSON number")


def _object(line):
    try:
        return json.loads(line.decode("ascii"), object_pairs_hook=_pairs,
                          parse_int=_number, parse_float=_not_integer,
                          parse_constant=_not_integer)
    except (UnicodeError, json.JSONDecodeError, RecursionError) as error:
        raise RawValidationError("malformed JSON event") from error


def _keys(value, expected, label):
    _require(type(value) is dict and value.keys() == expected, label)


def _event(line, ordinal, inventory):
    event = _object(line)
    _keys(event, _EVENT_KEYS, "event object keys")
    _integer(event["event"], ordinal, ordinal, "event ordinal")
    _integer(event["cpu"], 0, PID_MAX, "CPU range")
    epid = _integer(event["epid"], 1, U32, "EPID range")
    probe = _integer(event["probe_id"], 1, U32, "probe ID range")
    _require(probe in inventory, "unlisted probe ID")
    names, kind = inventory[probe]
    _require(tuple(event[key] for key in ("provider", "module", "function", "name")) == names,
             "event probe identity")
    _integer(event["kind"], kind, kind, "event kind differs from inventory")
    leading = int(kind in (1, 4, 5, 7))
    payloads = {2: 13, 3: 10, 15: 13, 16: 6, 18: 8}.get(kind, 5)
    _integer(event["record_bytes"], 16 + 8 * payloads, 16 + 8 * payloads, "record byte size")
    indexes = event["header_record_indexes"]
    _require(type(indexes) is list and len(indexes) == 5 and
             all(type(i) is int for i in indexes) and indexes == list(range(leading, leading + 5)),
             "header record indexes")
    records = event["records"]
    _require(type(records) is list and len(records) == payloads + leading, "record count")
    scalars = []
    for i, record in enumerate(records):
        _keys(record, _RECORD_KEYS, "record object keys")
        zero = leading and i == 0
        size = 0 if zero else 8
        offset = 12 if zero else 16 + 8 * (i - leading)
        _integer(record["action"], 1, 1, "record action")  # DTRACEACT_DIFEXPR
        _integer(record["size"], size, size, "record width")
        _integer(record["offset"], offset, offset, "record offset")
        raw = record["hex"]
        _require(type(raw) is str and len(raw) == size * 2 and _HEX.fullmatch(raw), "scalar hex")
        if not zero:
            scalars.append(int.from_bytes(bytes.fromhex(raw), "little", signed=False))
    for key, scalar in zip(("kind", "timestamp", "pid", "tid", "detail"), scalars):
        _integer(event[key], 0, U64, "header integer range")
        _require(event[key] == scalar, "raw/header disagreement")
    _integer(scalars[1], 1, U64, "timestamp range")
    _integer(scalars[2], 1, PID_MAX, "actor PID range")
    _integer(scalars[3], 1, U64, "thread ID range")
    return kind, epid, probe, scalars, event['cpu']


def _stream_budget(events, raw_bytes, line_bytes):
    _require(events < MAX_EVENTS, "event count bound")
    _require(line_bytes <= MAX_RAW_BYTES - raw_bytes, "raw byte bound")


def validate_raw(program: bytes, probes: bytes, errors: bytes,
                 event_lines: Iterable[bytes], *, owner_pid: int, target_pid: int) -> RawFacts:
    """Validate a complete fixed raw stream, or raise RawValidationError.

    PIDs are trusted actual identities supplied by the caller, not discovered or
    kernel-attested here. Each iterable item must be exactly one immutable LF-
    terminated physical event line. Memory is bounded by inventory/enablings and
    one line; the caller must itself bound each read (e.g. readline(8192)). The
    iterable must terminate and must not mutate inputs or concurrently reenter.
    Unexpected iterable/source exceptions propagate; they never return facts.
    """
    return _validate_raw(program, probes, errors, event_lines,
                         owner_pid=owner_pid, target_pid=target_pid)


def observe_raw_bsd(program: bytes, probes: bytes, errors: bytes,
                    event_lines: Iterable[bytes], *, owner_pid: int,
                    target_pid: int, contract_bytes: bytes) -> OwnedBsdObservations:
    """Validate the complete transport, then return bounded immutable BSD phases.

    contract_bytes must be the exact pinned asset supplied by the caller, not a
    path. No asset I/O, public prefix callback, call pairing, normalized result,
    native identity attestation or extraction acceptance occurs here.
    """
    _require(type(contract_bytes) is bytes and len(contract_bytes) == CONTRACT_BYTES,
             'pinned BSD contract byte type/size')
    _require(hashlib.sha256(contract_bytes).hexdigest() == CONTRACT_SHA256,
             'pinned BSD contract digest')
    helpers = _CONTRACT_HELPERS
    projection = _BsdProjection(helpers, helpers.parse_table(contract_bytes))
    raw = _validate_raw(program, probes, errors, event_lines,
                        owner_pid=owner_pid, target_pid=target_pid, projection=projection)
    return projection.finish(raw)


def require_full_trace_acceptance():
    raise RawValidationError('owned BSD observations cannot establish full Darwin R02 acceptance')


def _validate_raw(program, probes, errors, event_lines, *, owner_pid, target_pid,
                  projection=None):
    _integer(owner_pid, 1, PID_MAX, "owner PID")
    _integer(target_pid, 1, PID_MAX, "target PID")
    _require(owner_pid != target_pid, "owner equals target")
    _bounded_bytes(program, MAX_PROGRAM_BYTES, "program byte bound/type")
    _bounded_bytes(probes, MAX_INVENTORY_BYTES, "inventory byte bound/type")
    _bounded_bytes(errors, MAX_ERROR_BYTES, "error byte bound/type")
    _require(not errors, "nonempty error stream")
    _require(program == _expected_program(target_pid), "fixed program bytes")
    inventory, inventory_counts = _inventory(probes)
    epids, clauses, counts = {}, {}, [0] * 19
    raw_hash = hashlib.sha256()
    raw_bytes = events = begin = terminal = end = shadow = cleanup = 0
    terminal_scalars = None
    for line in event_lines:
        _bounded_bytes(line, MAX_EVENT_BYTES, "event line byte bound/type")
        _require(line.endswith(b"\n") and b"\n" not in line[:-1] and b"\r" not in line,
                 "one complete LF-terminated event required")
        _stream_budget(events, raw_bytes, len(line))
        _require(not end, "event after END")
        kind, epid, probe, scalars, cpu = _event(line, events + 1, inventory)
        clause = (probe, kind)
        _require(epid not in epids or epids[epid] == clause, "EPID rebound")
        _require(clause not in clauses or clauses[clause] == epid, "multiple EPIDs for clause")
        _require(epid in epids or len(epids) < MAX_ENABLINGS, "enabling bound")
        epids[epid], clauses[clause] = clause, epid
        actor, detail = scalars[2], scalars[4]
        if kind in (1, 17):
            _require(actor == owner_pid and detail == 0, "controller event identity")
        elif kind == 18:
            _require(detail == target_pid and scalars[6] != 0 and scalars[7] <= U32,
                     "exited target/address/refcount")
        else:
            _require(actor == target_pid, "target actor identity")
            if kind in (2, 3, 5, 7, 15, 16):
                _require(detail == owner_pid, "target parent identity")
            if kind in (10, 11, 12):
                _require(detail == 0, "zero lifecycle detail")
            if kind == 4:
                _integer(detail, 1, PID_MAX, "created PID range")
        _require(kind not in (4, 12, 13), "descendant/spawn outside fixed scope")
        if kind == 1:
            _require(not begin, "duplicate BEGIN")
            begin = events + 1
        else:
            _require(begin != 0, "event before BEGIN")
        if terminal:
            _require(kind in (18, 11, 17), "activity after terminal")
        if kind == 18:
            if scalars[7] & SHADOW_BIT:
                shadow += 1
            else:
                _require(not terminal, "duplicate nonshadow terminal")
                terminal = events + 1
                terminal_scalars = scalars
        if kind == 11 and terminal:
            cleanup += 1
        if kind == 17:
            _require(terminal != 0, "END before terminal")
            end = events + 1
        events += 1
        counts[kind] += 1
        raw_bytes += len(line)
        raw_hash.update(line)
        if projection is not None:
            projection.take(events, cpu, epid, probe, inventory[probe][0], scalars)
    _require(begin != 0 and terminal != 0 and end != 0, "incomplete BEGIN/terminal/END")
    return RawFacts(owner_pid, target_pid, len(program), hashlib.sha256(program).hexdigest(),
                    len(probes), hashlib.sha256(probes).hexdigest(), len(inventory),
                    inventory_counts, len(epids), events, raw_bytes, raw_hash.hexdigest(),
                    0, hashlib.sha256(errors).hexdigest(), tuple(counts), begin, terminal,
                    end, shadow, cleanup, terminal_scalars[2], terminal_scalars[5],
                    terminal_scalars[6], terminal_scalars[7])
