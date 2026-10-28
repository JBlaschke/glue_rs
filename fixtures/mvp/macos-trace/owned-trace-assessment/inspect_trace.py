"""Bounded caller-supplied diagnostics; never native capture/export admission."""
import argparse
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import stat
import sys


MAX_PROGRAM_BYTES = 16384
MAX_INVENTORY_BYTES = 1048576
MAX_ERROR_BYTES = 65536
MAX_RAW_BYTES = 134217728
MAX_EVENT_BYTES = 8191
MAX_OUTPUT_BYTES = 16777216
EXPECTED_NAMES = ('program.d', 'probes.tsv', 'errors.jsonl', 'events.jsonl')
# Fixed reviewed code/assets, not caller-supplied hash or import-path overrides.
SOURCE_IDENTITIES = (
    ('owned-trace-assessment/assessment.py', 9672,
     '70230f0c995c47b26fabefb1ead592d792d37e527a739a9dbc6383e331186e0f'),
    ('owned-trace-check/owned_trace_check.py', 28676,
     '1d8616b51002225c8b9abf4a18940c48f01d1ef97a3f7c54e120153ca8c978ec'),
    ('syscall-contract/syscall_contract.py', 11687,
     '35a4229894dd0373de1b312747e8acd1a23ae2074566391e8d28855ca0624dbf'),
    ('open-intent/open_intent.py', 7227,
     '104dd3e21a78264ae947033e133cd152dc43159cd91807c82569e1718905945a'),
    ('open-intent/abi.json', 888,
     'a76cfb519805f5b45a196defb10d6a5185a5e861f41e8c75f66a653cb11d7b20'),
    ('syscall-contract/contracts.json', 96972,
     '31f96f93c2ca1bd58ae322a6d3c223dd764e5a763088cfed2dbf78a8a21104e2'),
)
_BASE = Path(__file__).resolve().parent.parent
_READ_FLAGS = os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC | os.O_NONBLOCK


class InspectorError(ValueError):
    """No diagnostic report is available for this input."""


def _require(condition, message):
    if not condition:
        raise InspectorError(message)


def _identity(info):
    # Reads may change atime. Namespace/content/permission mutations change these.
    return tuple(getattr(info, field) for field in (
        'st_dev', 'st_ino', 'st_mode', 'st_nlink', 'st_uid', 'st_gid',
        'st_size', 'st_mtime_ns', 'st_ctime_ns'))


def _check_process():
    credentials = (os.getuid(), os.geteuid(), os.getgid(), os.getegid())
    uid, euid, gid, egid = credentials
    _require(uid != 0 and euid != 0 and gid != 0 and egid != 0 and
             uid == euid and gid == egid, 'privileged or mismatched credentials')
    return credentials


def _check_root(path, root_fd):
    held = os.fstat(root_fd)
    anchored = os.stat(path, follow_symlinks=False)
    _require(stat.S_ISDIR(held.st_mode) and stat.S_IMODE(held.st_mode) == 0o700
             and held.st_uid == os.getuid(), 'input directory ownership or mode')
    _require(_identity(held) == _identity(anchored), 'input directory identity changed')
    return _identity(held)


def _check_leaf(root_fd, name, fd):
    held = os.fstat(fd)
    anchored = os.stat(name, dir_fd=root_fd, follow_symlinks=False)
    _require(stat.S_ISREG(held.st_mode) and stat.S_IMODE(held.st_mode) == 0o600
             and held.st_uid == os.getuid() and held.st_nlink == 1,
             'input file type, ownership, mode or link count')
    _require(_identity(held) == _identity(anchored), 'input file identity changed')
    return _identity(held)


def _check_roster(root_fd):
    names = []
    iterator = os.scandir(root_fd)
    try:
        for entry in iterator:
            names.append(entry.name)
            _require(len(names) <= 4, 'input directory has a fifth entry')
    finally:
        iterator.close()
    _require(set(names) == set(EXPECTED_NAMES), 'input directory roster differs')


def _close_all(fds):
    failed = False
    # Remove each descriptor before its one close attempt; never retry EINTR.
    while fds:
        fd = fds.pop()
        try:
            os.close(fd)
        except BaseException:
            failed = True
    _require(not failed, 'descriptor closure failed')


def _read_static(fd, cap):
    data = bytearray()
    while True:
        chunk = os.read(fd, min(65536, cap + 1 - len(data)))
        if not chunk:
            return bytes(data)
        data.extend(chunk)
        _require(len(data) <= cap, 'static input byte bound')


def _event_lines(fd):
    pending = b''
    total = 0
    while True:
        chunk = os.read(fd, min(MAX_EVENT_BYTES + 1 - len(pending),
                                MAX_RAW_BYTES + 1 - total))
        if not chunk:
            if pending:
                yield pending
            return
        total += len(chunk)
        _require(total <= MAX_RAW_BYTES, 'event transport byte bound')
        pending += chunk
        while b'\n' in pending:
            line, pending = pending.split(b'\n', 1)
            line += b'\n'
            _require(len(line) <= MAX_EVENT_BYTES, 'event line byte bound')
            yield line
        _require(len(pending) <= MAX_EVENT_BYTES, 'event line byte bound')


def _trusted_bytes(relative, size, digest):
    path = _BASE / relative
    fds = []
    try:
        fd = os.open(path, _READ_FLAGS)
        fds.append(fd)
        first = os.fstat(fd)
        _require(stat.S_ISREG(first.st_mode) and first.st_size == size and
                 _identity(first) == _identity(os.stat(path, follow_symlinks=False)),
                 'trusted source metadata differs')
        data = _read_static(fd, size)
        _require(len(data) == size and hashlib.sha256(data).hexdigest() == digest,
                 'trusted source identity differs')
        _require(_identity(first) == _identity(os.fstat(fd)) ==
                 _identity(os.stat(path, follow_symlinks=False)),
                 'trusted source changed during read')
        return data
    finally:
        _close_all(fds)


def _load_assessment():
    # Normal imports reread reviewed sources. A stable trusted source tree is a
    # workflow precondition; no native harness/export backend is loaded here.
    contract = None
    for relative, size, digest in SOURCE_IDENTITIES:
        data = _trusted_bytes(relative, size, digest)
        if relative == 'syscall-contract/contracts.json':
            contract = data
    spec = importlib.util.spec_from_file_location(
        '_standalone_owned_assessment', _BASE / 'owned-trace-assessment/assessment.py')
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module, contract


def _encode_report(report):
    encoded = (json.dumps(report, sort_keys=True, separators=(',', ':'),
                          ensure_ascii=True, allow_nan=False) + '\n').encode('utf-8')
    _require(len(encoded) <= MAX_OUTPUT_BYTES, 'encoded diagnostic byte bound')
    return encoded


def inspect_directory(path, *, owner_pid, target_pid):
    """Inspect four unverified diagnostic files; never authenticate a capture.

    Numeric modes do not attest ACL privacy. A stable owned input namespace and
    trusted source tree without a concurrent privileged mutator are required.
    """
    fds = []
    try:
        credentials = _check_process()
        _require(type(owner_pid) is int and type(target_pid) is int and
                 1 <= owner_pid <= (1 << 31) - 1 and
                 1 <= target_pid <= (1 << 31) - 1 and owner_pid != target_pid,
                 'declared PIDs differ or are out of range')
        path = os.fspath(path)
        _require(bool(path), 'empty input directory path')
        separator = b'/' if isinstance(path, bytes) else '/'
        # A trailing slash can make the kernel follow the last symlink despite
        # O_NOFOLLOW. Preserve the final component as the object being checked.
        path = path.rstrip(separator) or separator
        _require(path.rsplit(separator, 1)[-1] not in
                 ((b'.', b'..') if isinstance(path, bytes) else ('.', '..')),
                 'input directory ends in a dot component')
        assessor, contract = _load_assessment()
        root_fd = os.open(path, _READ_FLAGS | os.O_DIRECTORY)
        fds.append(root_fd)
        root_identity = _check_root(path, root_fd)
        _check_roster(root_fd)
        leaves = {}
        initial = {}
        caps = dict(zip(EXPECTED_NAMES, (MAX_PROGRAM_BYTES, MAX_INVENTORY_BYTES,
                                         MAX_ERROR_BYTES, MAX_RAW_BYTES)))
        # Admit every leaf's metadata before consuming any input file content.
        for name in EXPECTED_NAMES:
            fd = os.open(name, _READ_FLAGS, dir_fd=root_fd)
            fds.append(fd)
            leaves[name] = fd
            initial[name] = _check_leaf(root_fd, name, fd)
            _require(os.fstat(fd).st_size <= caps[name], 'input file byte bound')
        static = {name: _read_static(leaves[name], caps[name])
                  for name in EXPECTED_NAMES[:3]}
        event_hash = hashlib.sha256()
        event_count = 0

        def lines():
            nonlocal event_count
            for line in _event_lines(leaves['events.jsonl']):
                event_count += len(line)
                event_hash.update(line)
                yield line

        assessment = assessor.assess_owned_raw(
            static['program.d'], static['probes.tsv'], static['errors.jsonl'], lines(),
            owner_pid=owner_pid, target_pid=target_pid, contract_bytes=contract)
        input_files = {name: {'byte_count': len(data),
                             'sha256': hashlib.sha256(data).hexdigest()}
                       for name, data in static.items()}
        input_files['events.jsonl'] = {'byte_count': event_count,
                                      'sha256': event_hash.hexdigest()}
        for name in EXPECTED_NAMES:
            _require(_check_leaf(root_fd, name, leaves[name]) == initial[name],
                     'input file changed during inspection')
            _require(input_files[name]['byte_count'] == os.fstat(leaves[name]).st_size,
                     'input file was not completely consumed')
        _check_roster(root_fd)
        _require(_check_root(path, root_fd) == root_identity,
                 'input directory changed during inspection')
        _require(_check_process() == credentials, 'process credentials changed')
    except InspectorError:
        raise
    except Exception:
        raise InspectorError('input inspection failed') from None
    finally:
        _close_all(fds)
    # Publication, including serialization, starts only after every close.
    report = {
        'protocol': 'darwin-owned-trace-diagnostic-v1',
        'origin': 'caller-supplied/unverified', 'status': 'incomplete',
        'native_admission': False, 'export_admission': False,
        'full_trace_acceptance': False, 'state_feed_eligible': False,
        'declared_pids': {'owner_pid': owner_pid, 'target_pid': target_pid},
        'input_files': input_files,
        'source_identities': {relative: {'byte_count': size, 'sha256': digest}
                              for relative, size, digest in SOURCE_IDENTITIES},
        'assessment': assessment.to_dict(),
        'scope': 'Numeric ownership/modes do not attest ACL privacy; caller declarations do not authenticate native capture or export safety.',
    }
    _encode_report(report)
    return report


class _ArgumentParser(argparse.ArgumentParser):
    def error(self, message):
        self.exit(2, 'inspect_trace: invalid arguments\n')


def main(argv=None):
    argv = sys.argv[1:] if argv is None else list(argv)
    if '--acceptance' in argv:
        sys.stderr.write('inspect_trace: native acceptance is unavailable\n')
        return 1
    parser = _ArgumentParser(description='Inspect unverified standalone diagnostic files.')
    parser.add_argument('--input', required=True)
    parser.add_argument('--owner-pid', required=True, type=int)
    parser.add_argument('--target-pid', required=True, type=int)
    try:
        arguments = parser.parse_args(argv)
    except SystemExit as error:
        return error.code
    try:
        report = inspect_directory(arguments.input, owner_pid=arguments.owner_pid,
                                   target_pid=arguments.target_pid)
        encoded = _encode_report(report)
        _require(sys.stdout.buffer.write(encoded) == len(encoded), 'stdout write failed')
        sys.stdout.buffer.flush()
        return 0
    except (InspectorError, OSError, ValueError):
        sys.stderr.write('inspect_trace: diagnostic refused or output failed\n')
        return 1


if __name__ == '__main__':
    raise SystemExit(main())
