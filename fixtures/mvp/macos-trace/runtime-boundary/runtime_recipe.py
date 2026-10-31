"""Exact RR/RC/TL launch bytes and recomputed original held-output observations.

The sole public pairing entry consumes a complete fixed-v2 raw capture. Neither
sample consistency nor a supplied artifact's digest authenticates its native
origin, an OFD/generation, protected installation or authorized sink exemption.
"""
from dataclasses import dataclass
import hashlib
import importlib.util
from pathlib import Path
from typing import Iterable

_HERE = Path(__file__).resolve().parent
_IMAGES_SHA256 = '42a2000c54801856c923a749239a3f1cea3cc8ef4d37844181c51fd3e394f1c4'
with (_HERE / 'runtime_images.py').open('rb') as _stream:
    _code = _stream.read(65537)
if len(_code) > 65536 or hashlib.sha256(_code).hexdigest() != _IMAGES_SHA256:
    raise ValueError('runtime-recipe fixed image helper identity')
del _stream, _code
_spec = importlib.util.spec_from_file_location('_runtime_recipe_fixed_images', _HERE / 'runtime_images.py')
_IMAGES = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(_IMAGES)
del _spec
_V1 = _IMAGES._V1
RawValidationError = _IMAGES.RawValidationError
_require, _bytes, _u, _zero = _V1._require, _V1._bytes, _V1._uint, _V1._zero
INT_MAX = (1 << 31) - 1
MAX_LAUNCHER_BYTES = 16777216
MAX_CATALOG_BYTES = 8192
MAX_PLAN_BYTES = 4184
ObjectRow = _V1.ObjectRow


def _sha(raw):
    return hashlib.sha256(raw).hexdigest()


@dataclass(frozen=True)
class RuntimeRecipeEvidence:
    request: bytes
    catalog: bytes
    launch_plan: bytes
    status_stream: bytes  # Complete status.bin, never caller-selected slices.
    launcher_artifact: bytes
    output_witness: bytes
    gate_delivery: bytes
    go_prefix: bytes


@dataclass(frozen=True)
class RecipeLaunchBinding:
    owner_pid: int
    target_pid: int
    request_sha256: str
    catalog_sha256: str
    status_sha256: str
    ready_sha256: str
    launch_plan_sha256: str
    launcher_sha256: str
    sources_sha256: str
    recipe_sha256: str
    r01_lock_sha256: str
    executable: bytes
    cwd: bytes
    arguments: tuple[bytes, ...]
    kept_fds: tuple[int, ...]
    objects: tuple[ObjectRow, ...]
    signal_policy_sha256: str
    evidence_sha256: str
    native_origin_authenticated: bool = False
    protected_target_admitted: bool = False
    output_objects_authenticated: bool = False

    @property
    def target_sha256(self):
        # Private image-walker vocabulary: only the initial artifact has a hash.
        return self.launcher_sha256


@dataclass(frozen=True)
class OutputReferenceMatch:
    child: ObjectRow
    parent: ObjectRow
    role: str


@dataclass(frozen=True)
class RecomputedOutputWitness:
    sha256: str
    samples: tuple[ObjectRow, ...]
    matches: tuple[OutputReferenceMatch, ...]
    native_observations_authenticated: bool = False
    lineage_authenticated: bool = False
    atomic_snapshot_proved: bool = False
    authorizes_sink_exemptions: bool = False


@dataclass(frozen=True)
class GateDelivery:
    sha256: str
    go_sha256: str
    release_action: int
    attempted: int
    bytes_moved: int
    bio_error_bytes_moved: int
    write_result: int
    close_attempted: int
    close_result: int
    close_errno: int
    native_delivery_authenticated: bool = False


@dataclass(frozen=True)
class ConditionalOutputSeed:
    capture_key: str  # Capture-local provenance key, never an OFD/generation ID.
    role: str
    child: ObjectRow
    parent: ObjectRow
    observation_boundary: str = 'READY-before-GO'
    native_lineage_authenticated: bool = False
    authorized_exemption: bool = False
    state_admission: bool = False


@dataclass(frozen=True)
class RuntimeRecipeCapture:
    protocol: str
    images: object
    output_witness: RecomputedOutputWitness
    gate_delivery: GateDelivery
    conditional_output_seeds: tuple[ConditionalOutputSeed, ...]
    native_admission: bool = False
    output_capabilities_authorized: bool = False
    state_feed_eligible: bool = False
    full_trace_acceptance: bool = False

    @property
    def source(self):
        return self.images.source

    @property
    def launch(self):
        return self.images.launch

    def to_dict(self):
        return _V1._plain(self)


def _name(raw):
    import re
    _require(re.fullmatch(rb'[A-Za-z0-9][A-Za-z0-9_.-]{0,63}', raw) is not None,
             'runtime catalog closed name')


def _plan(raw, executable):
    _bytes(raw, 24, MAX_PLAN_BYTES, 'runtime TL plan bytes')
    _require(raw[:8] == b'GLUETL\0\1' and _u(raw, 8, 8) == 1 and
             1 <= _u(raw, 4, 16) <= 16 and _u(raw, 4, 20) == 0,
             'runtime TL target/count/environment')
    offset, arguments, total = 24, [], 0
    for _ in range(_u(raw, 4, 16)):
        _require(offset + 4 <= len(raw), 'runtime TL missing length')
        length = _u(raw, 4, offset)
        offset += 4
        _require(length < 4096 and offset + length <= len(raw), 'runtime TL span bound')
        value = raw[offset:offset + length]
        _require(b'\0' not in value, 'runtime TL embedded NUL')
        total += length + 1
        _require(total <= 4096, 'runtime TL copied storage bound')
        arguments.append(value)
        offset += length
    _require(offset == len(raw) and arguments[0] == executable and
             2 <= len(arguments[0]) <= 255, 'runtime TL executable/framing')
    _V1._path(arguments[0])
    return tuple(arguments)


def _row(raw):
    _require(len(raw) == 40, 'runtime observation row length')
    result = ObjectRow(*(tuple(_u(raw, 4, p) for p in (0, 4, 8, 12)) +
                         tuple(_u(raw, 8, p) for p in (16, 24, 32))))
    _require(result.fd <= INT_MAX and result.descriptor_flags <= INT_MAX and
             result.status_flags <= INT_MAX and result.mode <= 0xffff,
             'runtime observation native integer domain')
    return result


def _launch(e, owner, child):
    _require(type(e) is RuntimeRecipeEvidence, 'exact runtime recipe evidence type')
    _V1._RAW._integer(owner, 1, INT_MAX, 'runtime owner PID')
    _V1._RAW._integer(child, 1, INT_MAX, 'runtime child PID')
    _require(owner != child, 'runtime distinct PIDs')
    c = _bytes(e.catalog, 256, MAX_CATALOG_BYTES, 'runtime RC catalog bytes')
    r = _bytes(e.request, 208, 16384, 'runtime RR request bytes')
    artifact = _bytes(e.launcher_artifact, 1, MAX_LAUNCHER_BYTES, 'runtime launcher bytes')
    status = _bytes(e.status_stream, 1024, 1024, 'runtime complete status stream length')
    _bytes(e.output_witness, 320, 320, 'runtime output witness length')
    _bytes(e.gate_delivery, 240, 240, 'runtime gate delivery length')
    _bytes(e.go_prefix, 0, 64, 'runtime confirmed GO prefix bound')
    _require(c[:8] == b'GLUERC01' and _u(c, 4, 8) == 1 and _u(c, 4, 12) == len(c) and
             _zero(c[200:256]), 'runtime canonical RC header')
    a, b, d, n = (_u(c, 4, p) for p in (184, 188, 192, 196))
    _require(all(1 <= v <= 64 for v in (a, b, d)) and 24 <= n <= MAX_PLAN_BYTES and
             256 + a + b + d + n == len(c), 'runtime RC lengths')
    build, leaf, cwd_name = c[256:256 + a], c[256 + a:256 + a + b], c[256 + a + b:256 + a + b + d]
    for value in (build, leaf, cwd_name):
        _name(value)
    _require(build != cwd_name and _u(c, 8, 24) and _u(c, 8, 40) and any(c[32:40]) and
             any(c[48:56]) and c[24:40] != c[40:56], 'runtime RC sibling CWD/mount declarations')
    _require(_u(c, 8, 16) == len(artifact) and c[56:88] == hashlib.sha256(artifact).digest(),
             'runtime RC launcher size/hash binding')
    prefix = b'/System/Volumes/Data/Library/GlueMVPFixtures/'
    executable, cwd = prefix + build + b'/' + leaf, prefix + cwd_name
    embedded = c[256 + a + b + d:]
    _bytes(e.launch_plan, 24, MAX_PLAN_BYTES, 'runtime standalone TL bytes')
    _require(e.launch_plan == embedded, 'runtime standalone/embedded TL mismatch')
    arguments = _plan(embedded, executable)
    _require(r[:8] == b'GLUERR01' and _u(r, 2, 8) == 1 and _u(r, 2, 10) == 208 and
             _u(r, 4, 12) == len(r) and _zero(r[184:208]), 'runtime canonical RR header')
    get = lambda at: _u(r, 4, at)
    _require(get(16) == get(120) == 2 and all(get(p) == 1 for p in (96, 100, 104)) and
             get(108) == 4096 and get(124) == 0 and 1 <= get(112) <= 10000 and
             1 <= get(116) <= 2000, 'runtime RR fixed selectors/bounds')
    uid, gid, count = get(20), get(24), get(28)
    groups = tuple(get(32 + 4 * i) for i in range(16))
    _require(1 <= uid <= INT_MAX and 1 <= gid <= INT_MAX and 1 <= count <= 16 and
             groups[0] == gid and all(0 <= v <= INT_MAX for v in groups[:count]) and
             len(set(groups[:count])) == count and not any(groups[count:]),
             'runtime RR canonical credentials')
    x, y = get(176), get(180)
    _require(1 <= x <= 4095 and 1 <= y <= 4095 and 208 + x + y == len(r), 'runtime RR path lengths')
    _require(r[208:208 + x] == executable and r[208 + x:] == cwd and
             r[128:160] == hashlib.sha256(c).digest(), 'runtime RR/RC exact path/digest binding')
    request_sha = hashlib.sha256(r).digest()
    binding = owner.to_bytes(4, 'big') + child.to_bytes(4, 'big') + request_sha

    def decode_record(raw, kind):
        _require(raw[:8] == b'GLUEFS02' and _u(raw, 2, 8) == 2 and _u(raw, 2, 10) == kind and
                 _u(raw, 4, 12) == 512 and _u(raw, 4, 16) == (5 if kind == 1 else 0) and
                 _u(raw, 4, 20) == 256 and _zero(raw[24:32]) and _zero(raw[488:]),
                 'runtime canonical object status header')
        p = raw[32:288]
        _require(p[:8] == b'GLUEBS01' and _u(p, 2, 8) == 1 and _u(p, 2, 10) == kind and
                 _u(p, 4, 12) == 256 and p[16:56] == binding and _u(p, 4, 64) == 0 and
                 _u(p, 4, 68) == 3 and _u(p, 4, 224) == 0 and _u(p, 4, 228) == 0xffffffff and
                 _zero(p[232:]), 'runtime canonical bound inner status')
        if kind == 1:
            _require(_u(p, 4, 56) == _u(p, 4, 60) == 0 and
                     tuple(_u(p, 4, at) for at in (72, 76, 80, 84, 88)) == (uid, uid, gid, gid, count) and
                     tuple(_u(p, 4, 92 + 4 * i) for i in range(16)) == groups and
                     p[156:172] == r[160:176] and any(p[192:224]), 'runtime READY requested observations')
        else:
            _require(_u(p, 4, 56) == 1 and _u(p, 4, 60) == 13 and
                     _zero(p[72:224]) and _zero(raw[288:488]), 'runtime EXEC_ATTEMPT canonical observations')
        return p

    ready, attempt = status[:512], status[512:]
    p = decode_record(ready, 1)
    decode_record(attempt, 2)
    keep = tuple(_u(p, 4, 172 + 4 * i) for i in range(5))
    _require(keep[:3] == (0, 1, 2) and 3 <= keep[3] <= INT_MAX and 3 <= keep[4] <= INT_MAX and
             keep[3] != keep[4], 'runtime READY kept descriptors')
    rows = tuple(_row(ready[288 + 40 * i:328 + 40 * i]) for i in range(5))
    for i, row in enumerate(rows):
        _require(row.fd == keep[i] and (row.status_flags & 3) == (1 if i in (1, 2, 4) else 0) and
                 (row.descriptor_flags & 1) == int(i >= 3) and
                 (row.mode & 0o170000) == (0o020000 if i == 0 else 0o100000 if i in (1, 2) else 0o010000) and
                 (i < 3 or bool(row.status_flags & 4)), 'runtime READY closed descriptor topology')
    return RecipeLaunchBinding(owner, child, request_sha.hex(), _sha(c), _sha(status), _sha(ready),
        _sha(embedded), _sha(artifact), c[88:120].hex(), c[120:152].hex(), c[152:184].hex(),
        executable, cwd, arguments, keep, rows, p[192:224].hex(), _evidence_digest(e))


def _evidence_digest(e):
    digest = hashlib.sha256()
    for name in ('request', 'catalog', 'launch_plan', 'status_stream', 'launcher_artifact',
                 'output_witness', 'gate_delivery', 'go_prefix'):
        value = getattr(e, name)
        _require(type(value) is bytes, 'runtime exact evidence byte type')
        digest.update(len(value).to_bytes(8, 'big'))
        digest.update(value)
    return digest.hexdigest()


def _bound_record(raw, size, magic, launch):
    _bytes(raw, size, size, 'runtime witness/delivery exact length')
    _require(raw[:8] == magic and _u(raw, 4, 8) == 1 and _u(raw, 4, 12) == size and
             _u(raw, 4, 16) == launch.owner_pid and _u(raw, 4, 20) == launch.target_pid and
             raw[32:64].hex() == launch.request_sha256 and raw[64:96].hex() == launch.catalog_sha256 and
             raw[96:128].hex() == launch.ready_sha256, 'runtime witness/delivery exact binding')


def _backing(row):
    return row.mode, row.device, row.inode, row.links


def _outputs(raw, launch):
    _bound_record(raw, 320, b'GLUERW01', launch)
    _require(_u(raw, 4, 24) == 4 and _zero(raw[28:32]) and _zero(raw[148:160]) and
             all(_u(raw, 4, p) == 0 for p in (128, 132, 136)) and
             _u(raw, 4, 140) == _u(raw, 4, 144) == 0xffffffff,
             'runtime original output samples require complete successful observation')
    samples = tuple(_row(raw[160 + 40 * i:200 + 40 * i]) for i in range(4))
    _require(samples[0] == samples[2] and samples[1] == samples[3], 'runtime held samples changed')
    _require(samples[0].fd != samples[1].fd, 'runtime held descriptor alias')
    matches = []
    for i, parent in enumerate(samples[:2]):
        child = launch.objects[i + 1]
        _require(parent.fd >= 3 and bool(parent.descriptor_flags & 1) and
                 not (child.descriptor_flags & 1) and
                 (parent.mode & 0o170000) == (child.mode & 0o170000) == 0o100000 and
                 parent.links == child.links == 1 and
                 (parent.status_flags & 3) == (child.status_flags & 3) == 1,
                 'runtime regular single-link write-only held output shape')
        _require(_backing(parent) == _backing(child) and parent.status_flags == child.status_flags,
                 'runtime actual held/READY observation mismatch')
        matches.append(OutputReferenceMatch(child, parent, 'stdout' if i == 0 else 'stderr'))
    _require((samples[0].device, samples[0].inode) != (samples[1].device, samples[1].inode),
             'runtime stdout/stderr backing alias')
    return RecomputedOutputWitness(_sha(raw), samples, tuple(matches))


def _delivery(raw, go, launch):
    _bound_record(raw, 240, b'GLUERD01', launch)
    _bytes(go, 64, 64, 'runtime exact confirmed GO prefix')
    _require(_u(raw, 4, 24) == _u(raw, 4, 28) == 1 and _u(raw, 4, 128) == 64 and
             all(_u(raw, 4, p) == 0 for p in (132, 136, 140, 144, 148, 156, 160)) and
             _u(raw, 4, 152) == 1 and _zero(raw[164:176]) and raw[176:240] == go,
             'runtime GO requires actual complete write/close success')
    binding = (launch.owner_pid.to_bytes(4, 'big') + launch.target_pid.to_bytes(4, 'big') +
               bytes.fromhex(launch.request_sha256))
    _require(go[:8] == b'GLUEFG02' and _u(go, 2, 8) == 2 and _u(go, 2, 10) == 64 and
             go[12:52] == binding and _zero(go[52:]), 'runtime original GO wire binding')
    return GateDelivery(_sha(raw), _sha(go), 1, 1, 64, 0, 0, 1, 0, 0)


def pair_runtime_recipe_raw(program: bytes, probes: bytes, errors: bytes,
                            event_lines: Iterable[bytes], *, owner_pid: int, target_pid: int,
                            contract_bytes: bytes, launch_evidence: RuntimeRecipeEvidence) -> RuntimeRecipeCapture:
    """Consume the complete fixed-v2 capture and exact runtime assets or refuse.

    Matches are independently recomputed from original samples, never from a
    result.json boolean. Conditional seeds appear only after whole raw/image
    validation; all native/capability authority and state/full admission is false.
    """
    launch = _launch(launch_evidence, owner_pid, target_pid)
    output = _outputs(launch_evidence.output_witness, launch)
    delivery = _delivery(launch_evidence.gate_delivery, launch_evidence.go_prefix, launch)
    images = _IMAGES._pair_with_launch(program, probes, errors, event_lines, owner_pid=owner_pid,
        target_pid=target_pid, contract_bytes=contract_bytes, launch=launch)
    seeds = []
    for match in output.matches:
        raw = (b'GLUE-runtime-output-seed-v1\0' + bytes.fromhex(launch.evidence_sha256) +
               bytes.fromhex(images.source.raw.raw_sha256) + match.child.fd.to_bytes(4, 'big'))
        seeds.append(ConditionalOutputSeed(_sha(raw), match.role, match.child, match.parent))
    return RuntimeRecipeCapture('darwin-runtime-recipe-capture-v1', images, output, delivery, tuple(seeds))
