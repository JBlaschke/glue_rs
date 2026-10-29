"""Canonical source-defined LP64 BSD entry values; never native admission."""
from dataclasses import dataclass, fields, is_dataclass
import hashlib
import importlib.util
import json
from pathlib import Path
import re
from types import MappingProxyType
from typing import Iterable, Optional


_BASE = Path(__file__).resolve().parent.parent
DEPENDENCY_IDENTITIES = (
    ('owned-trace-check/owned_trace_check.py',
     '1d8616b51002225c8b9abf4a18940c48f01d1ef97a3f7c54e120153ca8c978ec'),
    ('syscall-contract/syscall_contract.py',
     '35a4229894dd0373de1b312747e8acd1a23ae2074566391e8d28855ca0624dbf'),
)
# Standard imports assume a stable trusted checkout. Check every executable
# dependency before importing the first one; callers cannot select helpers.
for _relative, _digest in DEPENDENCY_IDENTITIES:
    with (_BASE / _relative).open('rb') as _stream:
        _code = _stream.read(65537)
    if len(_code) > 65536 or hashlib.sha256(_code).hexdigest() != _digest:
        raise ValueError('BSD entry ABI dependency identity differs: ' + _relative)
del _relative, _digest, _stream, _code
_spec = importlib.util.spec_from_file_location('_bsd_entry_abi_owned_raw',
    _BASE / 'owned-trace-check/owned_trace_check.py')
_RAW = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(_RAW)
del _spec
RawValidationError = _RAW.RawValidationError

SOURCE_COMMIT = 'f6217f891ac0bb64f3d375211650a4c1ff8ca1ea'
INTERPRETATION_PROFILE = 'pinned-xnu-lp64-bsd-entry-abi-v1'
SOURCE_IDENTITIES = (
    ('bsd/sys/_types.h',
     '508393c2752392fb306f3f9540f848e766f9bb4b52a5f616739a9cc63006f9ec'),
    ('bsd/sys/types.h',
     'f8b136bb10d56bb604e7b253f1ec23858d0b4ae21fe85eaede0ccc66afdb554a'),
    ('bsd/arm/_types.h',
     'dea174bb0a2621285e0380e1044283d04d7911c0c0c7507ae370e154b5a2d963'),
    ('bsd/i386/_types.h',
     'd8addb5671aadb61a796d2b7cbaf11d5716b78371ae5f59ebe30e69b9bd5a4d1'),
    ('osfmk/mach/port.h',
     '0ec7d265d9d27ea8911506038edbf7e14498340661470157ea31913736c3473c'),
    ('bsd/sys/socket.h',
     '38e9e2b003df33b5cc924b57c20a85ec082c90a41efe21cfb07d9258db2451d4'),
    ('bsd/arm/types.h',
     '4b6d31fc15d19635ae7179647145130a86d0dff5ee9157e632e9bd3828ba3b73'),
    ('bsd/i386/types.h',
     '21f31aa149d5bad233fb244fbee08cf2928137064ad3aa4bf24f2a70d921f5c6'),
    ('osfmk/mach/arm/vm_types.h',
     'b2deb6cfadc2972a42f698b1822393d240f96c1f91426f4f087e0cffc367225d'),
    ('osfmk/mach/i386/vm_types.h',
     'fd08a1f8d73c50d02b568a85ec995937ffc0c1426c8b464d94b79c1ecfce2565'),
    ('bsd/sys/_types/_caddr_t.h',
     'ce35ab3f966e02483951de5c54de4ad3a4acc4a70bca3e97ef476738897706a0'),
    ('bsd/sys/_types/_gid_t.h',
     'e687ad58c03701c132a02ebf20699c8cacfd34c3a67271bd2a415a5a8e4a9ea7'),
    ('bsd/sys/_types/_uid_t.h',
     'd2140a65a17943a857381757c0b73a920f35ade41dc9809437c168be457c276a'),
    ('bsd/sys/_types/_off_t.h',
     '7b07626d71084f1b3220e045089f54fd30f4d736be9cd0449042c5fe411fc569'),
    ('bsd/sys/_types/_socklen_t.h',
     'a747e7fd8c243c7bbbd2f2cfa4b05f56f905e1f013fb2ff230f07a1954fdbf07'),
    ('bsd/sys/_types/_size_t.h',
     'db84f57e9d0992b42649957a58f530f25a8e4bf417bf85592dca602cc79ca6fc'),
    ('bsd/sys/_types/_u_int.h',
     '85e9858c13fdc4fb614948fbcadec5f5973dbf6874b97464044a3b4e23486978'),
    ('bsd/kern/makesyscalls.sh',
     'bd44c344880e121277d33c7539c05915a030a52c4ceab7c9f88e54f373293c67'),
    ('bsd/dev/dtrace/systrace.c',
     'be8c6f8fca90cf95d97bd653056b2ad1c6b1c7a19ca36ba95eac5c848ac4efdd'),
)
# Closed type spellings from the exact source contract. Neither an arbitrary '*'
# rule nor the generator's cast spelling alone determines the underlying type.
TYPE_CLASSES = (
    ('int', 'signed32'),
    ('u_int', 'unsigned32'),
    ('unsigned int', 'unsigned32'),
    ('uint32_t', 'unsigned32'),
    ('uid_t', 'unsigned32'),
    ('gid_t', 'unsigned32'),
    ('socklen_t', 'unsigned32'),
    ('mach_port_name_t', 'unsigned32'),
    ('sae_associd_t', 'unsigned32'),
    ('long', 'signed64'),
    ('off_t', 'signed64'),
    ('u_long', 'unsigned64'),
    ('size_t', 'unsigned64'),
    ('size_ut', 'unsigned64'),
    ('uint64_t', 'unsigned64'),
    ('user_size_t', 'unsigned64'),
    ('user_addr_t', 'opaque-address64'),
    ('caddr_t', 'opaque-address64'),
    ('caddr_ut', 'opaque-address64'),
    ('char *', 'opaque-address64'),
    ('char **', 'opaque-address64'),
    ('const char *', 'opaque-address64'),
    ('const guardid_t *', 'opaque-address64'),
    ('const sa_endpoints_t *', 'opaque-address64'),
    ('const struct _posix_spawn_args_desc *', 'opaque-address64'),
    ('const struct fhandle *', 'opaque-address64'),
    ('const struct iovec *', 'opaque-address64'),
    ('const struct kevent *', 'opaque-address64'),
    ('const struct kevent64_s *', 'opaque-address64'),
    ('const struct kevent_qos_s *', 'opaque-address64'),
    ('const struct timespec *', 'opaque-address64'),
    ('graftdmg_args_un *', 'opaque-address64'),
    ('int *', 'opaque-address64'),
    ('off_t *', 'opaque-address64'),
    ('pid_t *', 'opaque-address64'),
    ('sae_connid_t *', 'opaque-address64'),
    ('size_t *', 'opaque-address64'),
    ('struct attrlist *', 'opaque-address64'),
    ('struct iovec *', 'opaque-address64'),
    ('struct kevent *', 'opaque-address64'),
    ('struct kevent64_s *', 'opaque-address64'),
    ('struct kevent_qos_s *', 'opaque-address64'),
    ('struct mac *', 'opaque-address64'),
    ('struct msghdr *', 'opaque-address64'),
    ('struct msghdr_x *', 'opaque-address64'),
    ('struct sf_hdtr *', 'opaque-address64'),
    ('struct timeval *', 'opaque-address64'),
    ('user_addr_t *', 'opaque-address64'),
    ('void *', 'opaque-address64'),
)
_TYPE_MAP = MappingProxyType(dict(TYPE_CLASSES))
_CLASS_INFO = MappingProxyType({
    'signed32': (32, True), 'unsigned32': (32, False),
    'signed64': (64, True), 'unsigned64': (64, False),
    'opaque-address64': (64, False),
})
_DECLARATION = re.compile(r'(.+?)([A-Za-z_][A-Za-z0-9_]*)\Z')
MISSING_CAPABILITIES = (
    'installed native entry ABI and provider/source coverage calibration',
    'pointer snapshots and path/FD/backing/port object bindings',
    'process, cwd, image and descriptor-generation semantics',
    'operation/effect ordering and application-output policy',
)


@dataclass(frozen=True)
class ArgumentAbi:
    argument_index: int
    declaration: str
    parameter_name: Optional[str]
    source_type: Optional[str]
    roles: tuple[str, ...]
    abi_class: Optional[str]
    width_bits: Optional[int]
    signed: Optional[bool]
    value: Optional[int]
    unsupported_reason: Optional[str]


@dataclass(frozen=True)
class EntryAbi:
    # Original raw words/requirements stay in source.observations[phase_index].
    phase_index: int
    ordinal: int
    source_name: str
    status: str
    arguments: tuple[ArgumentAbi, ...]
    unsupported_reason: Optional[str]


@dataclass(frozen=True)
class EntryAbiCounts:
    bsd_entries: int
    known_entries: int
    unknown_entries: int
    fully_typed_entries: int
    unsupported_entries: int
    declared_arguments: int
    typed_arguments: int
    unsupported_arguments: int
    abi_class_arguments: tuple[tuple[str, int], ...]


def _plain(value):
    if is_dataclass(value):
        return {field.name: _plain(getattr(value, field.name)) for field in fields(value)}
    if isinstance(value, tuple):
        return [_plain(item) for item in value]
    return value


@dataclass(frozen=True)
class OwnedBsdEntryAbi:
    protocol: str
    status: str
    source: _RAW.OwnedBsdObservations
    entries: tuple[EntryAbi, ...]
    counts: EntryAbiCounts
    interpretation_profile: str = INTERPRETATION_PROFILE
    source_commit: str = SOURCE_COMMIT
    source_identities: tuple[tuple[str, str], ...] = SOURCE_IDENTITIES
    dependency_identities: tuple[tuple[str, str], ...] = DEPENDENCY_IDENTITIES
    missing_capabilities: tuple[str, ...] = MISSING_CAPABILITIES
    native_abi_calibrated: bool = False
    state_feed_eligible: bool = False
    full_trace_acceptance: bool = False

    def to_dict(self):
        """Serialize to fresh containers; opaque addresses remain numbers only."""
        return _plain(self)


def _decode_argument(index, declaration, roles, word):
    match = _DECLARATION.fullmatch(declaration)
    if match is None:
        return ArgumentAbi(index, declaration, None, None, roles, None, None,
                           None, None, 'source declaration has no handled type/name split')
    source_type, name = match[1].strip(), match[2]
    abi_class = _TYPE_MAP.get(source_type)
    if abi_class is None:
        return ArgumentAbi(index, declaration, name, source_type, roles, None,
                           None, None, None, 'no fixed LP64 alias for source type')
    bits, signed = _CLASS_INFO[abi_class]
    value = word - (1 << 64) if signed and word >= (1 << 63) else word
    reason = None
    if signed and not -(1 << (bits - 1)) <= value < (1 << (bits - 1)):
        reason = 'source signed32 argument is not canonically sign-extended to uint64'
    elif not signed and bits == 32 and word >= (1 << 32):
        reason = 'source unsigned32 argument is not canonically zero-extended to uint64'
    return ArgumentAbi(index, declaration, name, source_type, roles, abi_class,
                       bits, signed, None if reason else value, reason)


def _decode_entry(index, phase, calls):
    call = calls.get(phase.function)
    if call is None:
        return EntryAbi(index, phase.ordinal, phase.function, 'unsupported', (),
                        'no pinned BSD source argument declaration')
    arguments = tuple(_decode_argument(position, declaration,
        tuple(role for role, selected in call['selectors'].items() if selected == position),
        phase.raw_scalars[5 + position])
        for position, declaration in enumerate(call['arguments']))
    unsupported = any(argument.unsupported_reason is not None for argument in arguments)
    return EntryAbi(index, phase.ordinal, phase.function,
                    'unsupported' if unsupported else 'typed', arguments,
                    'one or more declared arguments lack supported canonical typing' if unsupported else None)


def decode_owned_bsd_entries(program: bytes, probes: bytes, errors: bytes,
                             event_lines: Iterable[bytes], *, owner_pid: int,
                             target_pid: int, contract_bytes: bytes) -> OwnedBsdEntryAbi:
    """Type entry values only after complete strict owned raw validation.

    Failed/unpaired requests and orphan/unsupported return phases stay visible in
    the retained source; no closed-call pairer is applied. Caller-created facts,
    profiles, ABI assertions and normalized state are not inputs. Unknown names
    and noncanonical arguments remain explicit; pointer words are not accessed.
    After import only caller bytes and their bounded iterable are consumed.
    """
    source = _RAW.observe_raw_bsd(program, probes, errors, event_lines,
        owner_pid=owner_pid, target_pid=target_pid, contract_bytes=contract_bytes)
    # Upstream has already verified exact immutable contract bytes and the full
    # bounded table. No asset load or alternate profile is needed here.
    calls = {call['name']: call for call in json.loads(contract_bytes)['calls']}
    entries = tuple(_decode_entry(index, phase, calls)
                    for index, phase in enumerate(source.observations)
                    if phase.raw_scalars[0] == 2)
    arguments = tuple(argument for entry in entries for argument in entry.arguments)
    typed_entries = sum(entry.status == 'typed' for entry in entries)
    typed_arguments = sum(argument.unsupported_reason is None for argument in arguments)
    classes = tuple((name, sum(argument.abi_class == name for argument in arguments))
                    for name in _CLASS_INFO)
    counts = EntryAbiCounts(len(entries), source.coverage.known_entries,
        source.coverage.unknown_entries, typed_entries, len(entries) - typed_entries,
        len(arguments), typed_arguments, len(arguments) - typed_arguments, classes)
    return OwnedBsdEntryAbi('darwin-owned-bsd-entry-abi-v1', 'incomplete',
                            source, entries, counts)
