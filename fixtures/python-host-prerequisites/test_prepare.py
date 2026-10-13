#!/usr/bin/env python3
"""Independent audit of pinned host prerequisite publication and its controls.

This oracle imports no product API, extracts no archive, and never executes
Python from a prepared tree. It compares all output bytes to checked-in pins,
including mode/time transformations, and retains no large payload trees.
"""
from __future__ import annotations

import argparse
import gzip
import errno
import hashlib
import json
import os
from pathlib import Path
import posixpath
import re
import shutil
import stat
import subprocess
import sys

HERE = Path(__file__).resolve().parent
FIXTURES = HERE.parent
PROVIDERS = ('host-full', 'host-install')
LIBRARY_BYTES = 73563968
LIBRARY_SHA = '42be968275d5be2d9e632ec9ef6790dd2c10f1d4a710ad1028fc2b687242f219'
MTIME = 1704067200
FILE_MODE, DIRECTORY_MODE = 0o444, 0o555
SENTINEL = b'existing output must remain unchanged\n'
FACTS = {
    'host-full': {
        'filename': 'cpython-3.13.16+20261009-aarch64-unknown-linux-gnu-pgo+lto-full.tar.zst',
        'size': 95632430, 'sha256': '8907ec2f181f0fc5cd08b9d897d36159432405af78f68f8faca728f48940e0ca',
        'entries': 6574, 'regular_files': 5525, 'regular_bytes': 395119171,
        'source_inventory': 'python-imports/stdlib-pins.json', 'source_files': 2174,
        'source_bytes': 39158056, 'cache_inventory': None,
        'build': 'pbs-20261009-cpython-3.13.16-pgo-lto-host-metadata-apps-v1',
    },
    'host-install': {
        'filename': 'cpython-3.13.16+20261009-aarch64-unknown-linux-gnu-install_only.tar.gz',
        'size': 57626877, 'sha256': '397ca401f416c3c99330a6be16d735d0cbeaf53e82070b80395b2fb4a8891f34',
        'entries': 4526, 'regular_files': 3478, 'regular_bytes': 182155939,
        'source_inventory': 'python-install-host-source-apps/source-pins.json', 'source_files': 1037,
        'source_bytes': 15894268, 'cache_inventory': 'python-install-host-source-apps/cache-pins.json',
        'build': 'pbs-20261009-cpython-3.13.16-pgo-lto-host-install-metadata-apps-v1',
    },
}
# Complete artifact aggregate facts were independently retained by the pinned
# PBS inspection and install-only fixture before this product command existed.


def require(condition, message):
    if not condition:
        raise ValueError(message)


def identity(payload):
    return {'size': len(payload), 'sha256': hashlib.sha256(payload).hexdigest()}


def file_identity(path, maximum=None):
    before = path.lstat()
    require(stat.S_ISREG(before.st_mode), 'oracle input must be a regular file: ' + str(path))
    require(maximum is None or before.st_size <= maximum, 'oracle input exceeds bound: ' + str(path))
    digest, size = hashlib.sha256(), 0
    with path.open('rb') as stream:
        while block := stream.read(65536):
            size += len(block)
            require(maximum is None or size <= maximum, 'oracle input grew beyond bound: ' + str(path))
            digest.update(block)
    require(size == before.st_size, 'oracle input size changed: ' + str(path))
    return {'size': size, 'sha256': digest.hexdigest()}


def strict_json(payload):
    def pairs(items):
        result = {}
        for key, value in items:
            require(key not in result, 'duplicate JSON field: ' + key)
            result[key] = value
        return result

    def constant(value):
        raise ValueError('nonfinite JSON value: ' + value)

    return json.loads(payload, object_pairs_hook=pairs, parse_constant=constant)


def same_json(left, right):
    # Python's dictionary equality treats False and 0 as interchangeable; the
    # recorded schema distinguishes JSON booleans from numeric evidence facts.
    options = {'sort_keys': True, 'separators': (',', ':'), 'ensure_ascii': False, 'allow_nan': False}
    return json.dumps(left, **options) == json.dumps(right, **options)


def inventory(relative, files, size, artifact):
    payload = (FIXTURES / relative).read_bytes()
    pins = strict_json(payload)
    require(pins['schema_version'] == 0 and pins['artifact_sha256'] == artifact,
            'independent inventory schema/artifact differs: ' + relative)
    require(len(pins['files']) == files and sum(item['size'] for item in pins['files'].values()) == size,
            'independent inventory count/bytes differs: ' + relative)
    return pins['files'], {'identity': {'path': 'fixtures/' + relative} | identity(payload),
                           'files': files, 'uncompressed_bytes': size, 'artifact_sha256': artifact}


def expected_contract(provider):
    facts = FACTS[provider]
    sources, source_inventory = inventory(facts['source_inventory'], facts['source_files'],
                                          facts['source_bytes'], facts['sha256'])
    files = {'lib/python3.13/' + name: value for name, value in sources.items()}
    files['lib/libpython3.13.so.1.0'] = {'size': LIBRARY_BYTES, 'sha256': LIBRARY_SHA}
    cache_inventory = None
    if facts['cache_inventory']:
        caches, cache_inventory = inventory(facts['cache_inventory'], 3, 21157, facts['sha256'])
        files.update({'lib/python3.13/' + name: value for name, value in caches.items()})
    files = dict(sorted(files.items()))
    selected_bytes = sum(item['size'] for item in files.values())
    artifact = {key: facts[key] for key in ('filename', 'size', 'sha256')}
    artifact['url'] = 'https://github.com/astral-sh/python-build-standalone/releases/download/20261009/' + facts['filename'].replace('+', '%2B')
    return files, {
        'schema_version': 0, 'provider': provider, 'files': files, 'artifact': artifact,
        'artifact_entries': facts['entries'], 'artifact_payload_bytes': facts['regular_bytes'],
        'selected_files': len(files), 'selected_bytes': selected_bytes,
        'omitted_files': facts['regular_files'] - len(files),
        'omitted_bytes': facts['regular_bytes'] - selected_bytes,
        'source_inventory': source_inventory, 'cache_inventory': cache_inventory,
        'profile_build_id': facts['build'], 'python_version': '3.13.16',
        'target_triple': 'aarch64-unknown-linux-gnu', 'full_install_pairing_observed': False,
        'runtime_execution_observed': False, 'is_complete_python_installation': False,
        'stock_mtime_seconds': MTIME,
    }


def expected_directories(files):
    result = {'.'}
    for name in files:
        parent = posixpath.dirname(name)
        while parent:
            result.add(parent)
            parent = posixpath.dirname(parent)
    return result


def tree_inventory(root):
    require(stat.S_ISDIR(root.lstat().st_mode), 'host prefix must be an ordinary directory')
    files, directories = {}, {'.': root}
    for path in sorted(root.rglob('*')):
        mode = path.lstat().st_mode
        name = path.relative_to(root).as_posix()
        require(stat.S_ISDIR(mode) or stat.S_ISREG(mode), 'host prefix contains link/special file: ' + name)
        (directories if stat.S_ISDIR(mode) else files)[name] = path
    return files, directories


def audit_tree(prefix, provider, report):
    expected_files, expected_provenance = expected_contract(provider)
    files, directories = tree_inventory(prefix)
    require(set(files) == set(expected_files) | {'provenance.json'}, 'host prerequisite file inventory differs')
    require(set(directories) == expected_directories(expected_files), 'host prerequisite directory inventory differs')
    for name, path in files.items():
        metadata = path.lstat()
        require(stat.S_IMODE(metadata.st_mode) == FILE_MODE, 'host prerequisite file mode differs: ' + name)
        require(metadata.st_mtime_ns == MTIME * 1000000000, 'host prerequisite file mtime differs: ' + name)
        if name != 'provenance.json':
            require(file_identity(path, expected_files[name]['size']) == expected_files[name],
                    'host prerequisite payload identity differs: ' + name)
    for name, path in directories.items():
        metadata = path.lstat()
        require(stat.S_IMODE(metadata.st_mode) == DIRECTORY_MODE, 'host prerequisite directory mode differs: ' + name)
        require(metadata.st_mtime_ns == MTIME * 1000000000, 'host prerequisite directory mtime differs: ' + name)
    provenance_identity = file_identity(files['provenance.json'], 1024 * 1024)
    provenance_bytes = files['provenance.json'].read_bytes()
    require(identity(provenance_bytes) == provenance_identity, 'host prerequisite provenance changed during audit')
    provenance = strict_json(provenance_bytes)
    require(same_json(provenance, expected_provenance), 'host prerequisite provenance differs from independent pinned contract')
    require(same_json(report, {
        'provider': provider, 'prefix': str(prefix), 'provenance': provenance,
        'provenance_file': {'path': 'provenance.json'} | identity(provenance_bytes),
        'files': expected_files, 'file_count': len(expected_files),
        'payload_bytes': sum(value['size'] for value in expected_files.values()),
        'directory_count': len(directories), 'file_mode': FILE_MODE,
        'directory_mode': DIRECTORY_MODE, 'mtime_seconds': MTIME,
    }), 'host prerequisite stdout report differs from independently observed output')
    return {'provider': provider, 'prefix': str(prefix), 'files': expected_files,
            'file_count': len(expected_files), 'payload_bytes': sum(value['size'] for value in expected_files.values()),
            'directory_count': len(directories), 'file_mode': FILE_MODE, 'directory_mode': DIRECTORY_MODE,
            'mtime_seconds': MTIME, 'provenance_file': identity(provenance_bytes), 'provenance': provenance,
            'all_file_bytes_modes_times_verified': True, 'all_directory_modes_times_verified': True}


def remove_owned_tree(root):
    """Unfreeze only a new ordinary tree owned by this fixture, never follow links."""
    files, directories = tree_inventory(root)
    for path in directories.values():
        path.chmod(0o700)
    for path in files.values():
        path.chmod(0o600)
    shutil.rmtree(root)


def invoke(command, directory):
    (directory / 'command.json').write_text(json.dumps(command, indent=2) + '\n', encoding='utf-8')
    try:
        result = subprocess.run(command, capture_output=True, check=False, timeout=120)
    except subprocess.TimeoutExpired as error:
        (directory / 'stdout.txt').write_bytes(error.stdout or b'')
        (directory / 'stderr.txt').write_bytes(error.stderr or b'')
        (directory / 'exit-status.txt').write_text('124\n', encoding='utf-8')
        raise ValueError('product preparation timed out: ' + str(directory)) from error
    (directory / 'stdout.txt').write_bytes(result.stdout)
    (directory / 'stderr.txt').write_bytes(result.stderr)
    (directory / 'exit-status.txt').write_text(str(result.returncode) + '\n', encoding='utf-8')
    return result


def command(args, provider, prefix, artifact=None):
    if artifact is None:
        artifact = args.full if provider == 'host-full' else args.install
    flag = '--pbs-full' if provider == 'host-full' else '--pbs-install-only'
    return [str(args.glue), 'python-host', '--provider', provider, flag, str(artifact), '--output', str(prefix), '--json']


def capture_control(args, results, name, cmd, directory, prefix, protected=None):
    result = invoke(cmd, directory)
    if protected is None:
        protected = lambda: not prefix.exists() and not prefix.is_symlink()
    require(result.returncode == 1 and not result.stdout and bool(result.stderr) and protected(),
            'control did not reject with protected output: ' + name + '; see ' + str(directory))
    results[name] = {'exit_status': result.returncode, 'stderr': result.stderr.decode('utf-8'), 'output_protected': True}


def generation_controls(args):
    results = {}
    controls = args.output / 'controls'
    controls.mkdir()
    for provider in PROVIDERS:
        for label, prefix in (
                ('root', '/'), ('relative', 'relative/Python'), ('trailing-slash', '/missing/Python/'),
                ('empty-component', '/missing//Python'), ('dot-component', '/missing/./Python'),
                ('traversal', '/missing/../Python'), ('backslash', '/missing\\Python'),
                ('non-ascii', '/missing/Pythön'), ('control-character', '/missing/Python\n'),
                ('path-budget', '/' + 'a' * 4090), ('ownership-budget', '/' + '/'.join(['a'] * 100))):
            name = provider + '-' + label
            directory = controls / name
            directory.mkdir()
            def prefix_state():
                try:
                    before = os.lstat(prefix)
                    return (before.st_dev, before.st_ino, before.st_mode, before.st_size, before.st_mtime_ns)
                except OSError as error:
                    require(error.errno in (errno.ENOENT, errno.ENAMETOOLONG, errno.ENOTDIR), 'unexpected invalid-prefix lookup failure')
                    return None
            original_state = prefix_state()
            capture_control(args, results, name, command(args, provider, prefix), directory, Path(prefix),
                            lambda: prefix_state() == original_state)
        for label in ('existing-file', 'existing-directory', 'existing-symlink', 'existing-dangling-symlink', 'missing-parent', 'parent-file'):
            name = provider + '-' + label
            directory = controls / name
            directory.mkdir()
            prefix = directory / 'prefix'
            protected = None
            if label == 'existing-file':
                prefix.write_bytes(SENTINEL)
                protected = lambda prefix=prefix: prefix.is_file() and not prefix.is_symlink() and prefix.read_bytes() == SENTINEL
            elif label == 'existing-directory':
                prefix.mkdir()
                (prefix / 'sentinel').write_bytes(SENTINEL)
                protected = lambda prefix=prefix: {p.name for p in prefix.iterdir()} == {'sentinel'} and (prefix / 'sentinel').read_bytes() == SENTINEL
            elif label in ('existing-symlink', 'existing-dangling-symlink'):
                target = directory / 'protected-target'
                if label == 'existing-symlink':
                    target.mkdir()
                    (target / 'sentinel').write_bytes(SENTINEL)
                prefix.symlink_to(target, target_is_directory=True)
                protected = lambda prefix=prefix, target=target, label=label: prefix.is_symlink() and os.readlink(prefix) == str(target) and (
                    ({p.name for p in target.iterdir()} == {'sentinel'} and (target / 'sentinel').read_bytes() == SENTINEL)
                    if label == 'existing-symlink' else not target.exists())
            elif label == 'missing-parent':
                prefix = directory / 'absent/prefix'
                protected = lambda prefix=prefix: not prefix.parent.exists()
            else:
                parent = directory / 'parent'
                parent.write_bytes(SENTINEL)
                prefix = parent / 'prefix'
                protected = lambda parent=parent: parent.is_file() and parent.read_bytes() == SENTINEL
            capture_control(args, results, name, command(args, provider, prefix), directory, prefix, protected)
        for label in ('missing', 'empty', 'malformed', 'truncated', 'oversized', 'trailing', 'directory', 'symlink', 'fifo', 'corrupt'):
            name = provider + '-artifact-' + label
            directory = controls / name
            directory.mkdir()
            scratch = args.scratch / name
            scratch.mkdir()
            artifact = scratch / 'input'
            original = args.full if provider == 'host-full' else args.install
            if label == 'empty':
                artifact.touch()
            elif label == 'malformed':
                artifact.write_bytes(b'not the pinned PBS artifact\n')
            elif label in ('truncated', 'oversized'):
                with artifact.open('wb') as stream:
                    stream.truncate(FACTS[provider]['size'] + (-1 if label == 'truncated' else 1))
            elif label in ('trailing', 'corrupt'):
                shutil.copyfile(original, artifact)
                with artifact.open('r+b') as stream:
                    if label == 'trailing':
                        stream.seek(0, os.SEEK_END)
                        stream.write(b'trailing data')
                    else:
                        stream.seek(65536)
                        previous = stream.read(1)
                        require(len(previous) == 1, 'corruption source is truncated')
                        stream.seek(65536)
                        stream.write(bytes([previous[0] ^ 1]))
            elif label == 'directory':
                artifact.mkdir()
            elif label == 'symlink':
                artifact.symlink_to(original)
            elif label == 'fifo':
                os.mkfifo(artifact)
            prefix = scratch / 'prefix'
            capture_control(args, results, name, command(args, provider, prefix, artifact), directory, prefix)
            if artifact.exists() and stat.S_ISREG(artifact.lstat().st_mode):
                (directory / 'input.identity.json').write_text(json.dumps(file_identity(artifact), sort_keys=True) + '\n')
                artifact.unlink()
            elif artifact.is_symlink() or (artifact.exists() and stat.S_ISFIFO(artifact.lstat().st_mode)):
                artifact.unlink()
            elif artifact.exists():
                artifact.rmdir()
            scratch.rmdir()
    parser_cases = {
        'unknown-provider': ['--provider', 'future'],
        'missing-provider': [],
        'missing-artifact': ['--provider', 'host-full'],
        'full-with-install': ['--provider', 'host-full', '--pbs-install-only', str(args.install)],
        'install-with-full': ['--provider', 'host-install', '--pbs-full', str(args.full)],
        'both-artifacts': ['--provider', 'host-full', '--pbs-full', str(args.full), '--pbs-install-only', str(args.install)],
        'duplicate-provider': ['--provider', 'host-full', '--provider', 'host-install', '--pbs-full', str(args.full)],
        'duplicate-json': ['--provider', 'host-full', '--pbs-full', str(args.full), '--json'],
        'unknown-option': ['--provider', 'host-full', '--pbs-full', str(args.full), '--future'],
    }
    for name, flags in parser_cases.items():
        directory = controls / name
        directory.mkdir()
        prefix = directory / 'prefix'
        capture_control(args, results, name, [str(args.glue), 'python-host', *flags, '--output', str(prefix), '--json'], directory, prefix)
    return results


def audit(args):
    for provider, path in (('host-full', args.full), ('host-install', args.install)):
        facts = FACTS[provider]
        require(file_identity(path, facts['size']) == {key: facts[key] for key in ('size', 'sha256')}, 'audit artifact pin differs: ' + provider)
    args.output.mkdir(parents=True, exist_ok=False)
    if args.scratch is None:
        args.scratch = args.output / 'scratch'
    args.scratch.mkdir(parents=True, exist_ok=False)
    results = {}
    for provider in PROVIDERS:
        first = None
        for relative in (provider, 'repeated/' + provider):
            directory = args.output / relative
            directory.mkdir(parents=True)
            parent = args.scratch / relative
            parent.mkdir(parents=True)
            prefix = parent / 'prefix'
            outcome = invoke(command(args, provider, prefix), directory)
            require(outcome.returncode == 0 and not outcome.stderr, 'valid prerequisite preparation failed: ' + provider + '; see ' + str(directory))
            report = strict_json(outcome.stdout)
            observed = audit_tree(prefix, provider, report)
            shutil.copyfile(prefix / 'provenance.json', directory / 'provenance.json')
            (directory / 'oracle.json').write_text(json.dumps(observed, indent=2, sort_keys=True) + '\n')
            normalized = report.copy()
            normalized.pop('prefix')
            if first is None:
                first = normalized
                results[provider] = observed
            else:
                require(normalized == first, 'repeated prerequisite report differs beyond prefix: ' + provider)
                require((directory / 'provenance.json').read_bytes() == (args.output / provider / 'provenance.json').read_bytes(),
                        'repeated prerequisite provenance bytes differ: ' + provider)
                results[provider]['repeated_byte_identity'] = True
            remove_owned_tree(prefix)
    controls = generation_controls(args)
    summary = {'schema_version': 0, 'valid_generations': 4, 'hostile_controls': len(controls),
               'results': results, 'controls': controls,
               'large_payloads_retained': False, 'runtime_execution_observed': False}
    (args.output / 'audit.json').write_text(json.dumps(summary, indent=2, sort_keys=True) + '\n', encoding='utf-8')
    # Only empty fixture-owned parents remain; removing them never follows links.
    for directory in sorted(args.scratch.rglob('*'), key=lambda p: len(p.parts), reverse=True):
        require(directory.is_dir() and not directory.is_symlink(), 'unexpected scratch residue: ' + str(directory))
        directory.rmdir()
    args.scratch.rmdir()
    return summary


def decode_trace_string(value):
    result, position = [], 0
    escapes = {'a': '\a', 'b': '\b', 'f': '\f', 'n': '\n', 'r': '\r', 't': '\t',
               'v': '\v', '\\': '\\', '"': '"', "'": "'"}
    while position < len(value):
        character = value[position]
        position += 1
        if character != '\\':
            result.append(character)
            continue
        require(position < len(value), 'unterminated process trace string escape')
        escaped = value[position]
        position += 1
        if escaped in escapes:
            result.append(escapes[escaped])
        elif escaped in '01234567':
            digits = escaped
            while position < len(value) and len(digits) < 3 and value[position] in '01234567':
                digits += value[position]
                position += 1
            result.append(chr(int(digits, 8)))
        elif escaped == 'x':
            digits = value[position:position + 2]
            require(len(digits) == 2 and re.fullmatch('[0-9a-fA-F]{2}', digits), 'invalid process trace hexadecimal escape')
            result.append(chr(int(digits, 16)))
            position += 2
        else:
            raise ValueError('unknown process trace string escape: \\' + escaped)
    return ''.join(result)


def normalized_trace_path(value):
    require('\0' not in value, 'process trace path contains NUL')
    return '/' + posixpath.normpath(value).lstrip('/') if value.startswith('/') else value


def audit_process_trace(path, program):
    opener = gzip.open if str(path).endswith('.gz') else open
    with opener(path, 'rt', encoding='utf-8') as stream:
        lines = stream.readlines()
    require(lines, 'process trace is empty')
    pid, output, cwd, exits, execs = None, None, None, 0, 0
    descriptors_by_number, created_directories, created_files = {}, set(), set()
    stdio_live = {0, 1, 2}
    executable_system_files = {'/usr/lib/aarch64-linux-gnu/' + name
                               for name in ('libm.so.6', 'libgcc_s.so.1', 'libc.so.6')}
    forbidden = {'clone', 'clone3', 'fork', 'vfork', 'execveat', 'memfd_create', 'socket', 'socketpair',
                 'connect', 'accept', 'accept4', 'bind', 'listen', 'sendto', 'sendmsg', 'sendmmsg',
                 'recvfrom', 'recvmsg', 'recvmmsg', 'shutdown', 'getsockname', 'getpeername',
                 'setsockopt', 'getsockopt', 'socketcall', 'io_uring_setup', 'io_uring_register', 'io_uring_enter',
                 'dup', 'dup2', 'dup3', 'close_range', 'sendfile', 'sendfile64', 'copy_file_range', 'splice', 'tee', 'vmsplice'}
    quoted = re.compile(r'"((?:[^"\\]|\\.)*)"')
    annotated = re.compile(r'(AT_FDCWD|\d+)<([^<>]*)>')
    library = re.compile(r'libpython(?:\d+(?:\.\d+)*)?d?(?:\.so(?:\.\d+)*|\.dylib|\.dll|\.a|\.lib)\Z')
    interpreter = re.compile(r'python(?:\d+(?:\.\d+)*)?(?:\.exe)?\Z')
    opens = {'open', 'openat', 'openat2', 'creat'}
    writes = {'write', 'writev', 'pwrite64', 'pwritev', 'pwritev2'}
    path_mutations = {'mkdir', 'mkdirat', 'chmod', 'fchmodat', 'fchmodat2', 'chown', 'lchown', 'fchownat',
                      'utime', 'utimes', 'utimensat', 'futimesat', 'unlink', 'unlinkat', 'rmdir', 'rename', 'renameat',
                      'renameat2', 'symlink', 'symlinkat', 'link', 'linkat', 'truncate', 'truncate64',
                      'mknod', 'mknodat', 'setxattr', 'lsetxattr', 'removexattr', 'lremovexattr'}
    descriptor_mutations = {'fchmod', 'fchown', 'ftruncate', 'ftruncate64', 'fallocate',
                            'fsetxattr', 'fremovexattr', 'utimensat', 'futimesat'}
    path_calls = opens | path_mutations | {'stat', 'lstat', 'newfstatat', 'statx', 'access', 'faccessat',
                                         'faccessat2', 'readlink', 'readlinkat', 'chdir', 'execve', 'execveat'}
    publication_metadata = {'stat', 'lstat', 'newfstatat', 'statx', 'fstat', 'chmod', 'fchmod',
                            'fchmodat', 'fchmodat2', 'utime', 'utimes', 'utimensat', 'futimesat',
                            'close', 'fsync', 'fdatasync'}

    # This audit is bound to the recorded GNU arm64 producer cell. Unclassified
    # kernel operations cannot establish zero network/mutation/acquisition facts.
    allowed_syscalls = path_calls | descriptor_mutations | writes | publication_metadata | {
        'execve', 'read', 'readv', 'pread64', 'preadv', 'preadv2', 'getdents64', 'lseek',
        'fcntl', 'fcntl64', 'fchdir', 'brk', 'mmap', 'mmap2', 'munmap', 'mprotect', 'pkey_mprotect',
        'prlimit64', 'set_tid_address', 'set_robust_list', 'rseq', 'getrandom',
        'sched_getaffinity', 'rt_sigaction', 'sigaltstack', 'ppoll', 'exit_group'}

    def inside_prefix(value):
        return value == output or value.startswith(output + '/')

    for line in lines:
        record = re.fullmatch(r'(\d+)\s+(.+)\n?', line)
        require(record is not None, 'process trace record lacks numbered PID: ' + line.strip())
        if pid is None:
            pid = record.group(1)
        require(record.group(1) == pid, 'process trace contains another PID: ' + line.strip())
        require(exits == 0, 'process trace contains records after builder exit')
        body = record.group(2)
        require('<unfinished ...>' not in body and ' resumed>' not in body, 'process trace has unfinished/resumed syscall: ' + line.strip())
        match = re.match(r'([A-Za-z_][A-Za-z_0-9]*)\(', body)
        if match:
            name = match.group(1)
            require(name not in forbidden, 'preparation attempted child creation/network/acquisition/descriptor reassignment: ' + line.strip())
            require(name in allowed_syscalls, 'process trace contains unclassified syscall outside preparation audit: ' + line.strip())
            if name == 'execve':
                parsed = re.fullmatch(r'execve\(("(?:[^"\\]|\\.)*"), \[(.*)\], .*\)\s*=\s*0\s*', body)
                require(parsed is not None, 'builder execve is malformed/failed')
                executable = decode_trace_string(parsed.group(1)[1:-1])
                raw = parsed.group(2)
                arguments = [decode_trace_string(item.group(1)) for item in quoted.finditer(raw)]
                require(re.fullmatch(r'\s*(?:,\s*)*', quoted.sub('', raw)) is not None, 'builder execve arguments truncated/malformed')
                require(executable == program and arguments[:2] == [program, 'python-host'], 'preparation executed unexpected command')
                require(arguments.count('--output') == 1 and arguments.index('--output') + 1 < len(arguments), 'builder lacks one output prefix')
                output = normalized_trace_path(arguments[arguments.index('--output') + 1])
                require(output.startswith('/'), 'process audit requires absolute output prefix')
                execs += 1
                require(execs == 1, 'process trace contains additional execve')
                continue
            require(execs == 1, 'process syscall precedes builder execve')
            # Ignore descriptor-shaped text and NUL bytes inside binary buffers.
            # Preserve offsets so relative path arguments retain their real base.
            unquoted = quoted.sub(lambda item: ' ' * len(item.group(0)), body)
            syscall_arguments = annotated.sub(lambda item: item.group(1), unquoted)
            require(not (name in {'fcntl', 'fcntl64'} and re.search(r'\bF_DUPFD(?:_CLOEXEC)?\b', syscall_arguments)),
                    'preparation attempted descriptor reassignment')
            if name in {'mprotect', 'pkey_mprotect'}:
                require('PROT_EXEC' not in syscall_arguments, 'preparation attempted to grant executable memory protection')
            descriptors = [(item.start(), item.group(1), normalized_trace_path(decode_trace_string(item.group(2)).removesuffix(' (deleted)')))
                           for item in annotated.finditer(unquoted)]
            result_start = body.rfind(' = ')
            argument_descriptors = [(position, number, value) for position, number, value in descriptors
                                    if result_start < 0 or position < result_start]
            for _, number, value in argument_descriptors:
                if number != 'AT_FDCWD' and int(number) in descriptors_by_number:
                    require(value == descriptors_by_number[int(number)]['path'], 'descriptor annotation differs from remembered open owner')
            observed_cwd = re.search(r'AT_FDCWD<([^<>]*)>', unquoted)
            if observed_cwd is not None:
                cwd = normalized_trace_path(decode_trace_string(observed_cwd.group(1)))
            first = re.match(r'[A-Za-z_][A-Za-z_0-9]*\((\d+)(?:<[^<>]*>)?[,)]', body)
            first_number = int(first.group(1)) if first else None
            first_owner = descriptors_by_number.get(first_number)
            paths = [value for _, _, value in descriptors]
            if first_owner:
                paths.append(first_owner['path'])
            mapped_number, mapped_owner = None, None
            if name in {'mmap', 'mmap2'}:
                arguments = syscall_arguments[syscall_arguments.index('(') + 1:].split(',')
                require(len(arguments) >= 6 and re.fullmatch(r'\s*-?\d+\s*', arguments[4]), 'mapping descriptor arguments differ')
                mapped_number = int(arguments[4])
                mapped_owner = descriptors_by_number.get(mapped_number)
                shared_writable = ('PROT_WRITE' in syscall_arguments and
                                   re.search(r'\bMAP_SHARED(?:_VALIDATE)?\b', syscall_arguments) is not None and
                                   mapped_number >= 0 and 'MAP_ANONYMOUS' not in syscall_arguments)
                require(not shared_writable, 'preparation attempted shared writable file mapping')
                if mapped_owner:
                    paths.append(mapped_owner['path'])
                if 'PROT_EXEC' in syscall_arguments:
                    anonymous = 'MAP_ANONYMOUS' in syscall_arguments or mapped_number == -1
                    require(not anonymous, 'preparation attempted anonymous executable mapping')
                    require(mapped_owner is not None and not mapped_owner['publication'] and
                            mapped_owner['path'] in executable_system_files,
                            'preparation attempted executable mapping outside exact system loader inventory')
            strings = []
            if name in path_calls:
                require(re.search(r'"(?:[^"\\]|\\.)*"\s*\.\.\.', body) is None,
                        'process trace file path/string argument is truncated')
                for item in quoted.finditer(body):
                    value = normalized_trace_path(decode_trace_string(item.group(1)))
                    preceding = [value for position, _, value in argument_descriptors if position < item.start() and value.startswith('/')]
                    base = preceding[-1] if preceding else cwd
                    resolved = normalized_trace_path(posixpath.join(base, value)) if base and not value.startswith('/') else value
                    paths.append(resolved)
                    strings.append(resolved)
            flags = set(re.findall(r'\bO_[A-Z0-9_]+\b', syscall_arguments))
            write_open = name == 'creat' or bool(flags & {'O_WRONLY', 'O_RDWR', 'O_CREAT', 'O_TRUNC', 'O_APPEND', 'O_TMPFILE'})
            if name in opens:
                require(strings, 'open lacks complete path argument')
                if write_open:
                    require(inside_prefix(strings[0]), 'preparation write-capable open escapes declared output prefix')
                    require(flags == {'O_WRONLY', 'O_CREAT', 'O_EXCL', 'O_CLOEXEC'}, 'publication was not an exclusive write')
                elif inside_prefix(strings[0]):
                    require(strings[0] in created_directories and flags == {'O_RDONLY', 'O_CLOEXEC'},
                            'preparation read Python path without owned-directory evidence')
            if name in path_mutations:
                require(all(inside_prefix(value) for value in strings if value), 'preparation pathname mutation escapes declared output prefix')
                require(bool(strings) or (first_owner is not None and first_owner['publication']),
                        'preparation pathname mutation lacks owned output path/descriptor')
            if name in descriptor_mutations and first_number is not None:
                require(first_owner is not None and first_owner['publication'], 'preparation mutates an unowned descriptor')
            if name in writes:
                require(first_number is not None, 'write lacks explicit descriptor')
                require((first_number in {1, 2} and first_number in stdio_live) or
                        (first_owner is not None and first_owner['publication'] and first_owner['kind'] == 'file'),
                        'preparation writes through unowned or reassigned descriptor')
            for value in paths:
                basename = posixpath.basename(value).removeprefix('memfd:')
                if library.fullmatch(basename):
                    require(value == output + '/lib/libpython3.13.so.1.0', 'preparation looked up foreign Python library')
                if interpreter.fullmatch(basename):
                    require(value in {output, output + '/lib/python3.13'}, 'preparation looked up target Python interpreter')
                if inside_prefix(value) and name not in opens | {'mkdir', 'mkdirat'}:
                    permitted = name in publication_metadata or (name in writes and value in created_files)
                    require(permitted, 'preparation acquired/read/mapped owned publication output: ' + line.strip())
            if name in {'mkdir', 'mkdirat'} and re.search(r'=\s*0\s*$', body) and strings:
                created_directories.add(strings[0])
            if name in opens:
                result_fd = re.search(r'=\s*(\d+)(?:<[^<>]*>)?\s*$', body)
                if result_fd:
                    number = int(result_fd.group(1))
                    require(number > 2 and number not in descriptors_by_number, 'successful open reassigns an existing or original standard descriptor')
                    returned = [value for position, descriptor, value in descriptors if position > result_start and descriptor == str(number)]
                    opened = returned[-1] if returned else strings[0]
                    publication = inside_prefix(strings[0])
                    require(publication == inside_prefix(opened), 'read-only open aliases a publication output')
                    require(not publication or opened == strings[0], 'publication descriptor aliases its declared output path')
                    kind = 'file' if write_open else 'directory' if publication else 'input'
                    descriptors_by_number[number] = {'path': opened, 'publication': publication, 'kind': kind}
                    if publication and kind == 'file':
                        created_files.add(opened)
            if name == 'close' and first_number is not None and re.search(r'=\s*0\s*$', body):
                descriptors_by_number.pop(first_number, None)
                stdio_live.discard(first_number)
            if name == 'chdir' and re.search(r'=\s*0\s*$', body) and strings:
                cwd = strings[0]
            if name == 'fchdir' and re.search(r'=\s*0\s*$', body) and argument_descriptors:
                cwd = argument_descriptors[0][2]
        else:
            require(body == '+++ exited with 0 +++' or (body.startswith('--- ') and body.endswith(' ---')),
                    'unrecognized process trace record: ' + line.strip())
            if body == '+++ exited with 0 +++':
                exits += 1
    require(execs == 1 and exits == 1, 'process trace requires one successful execve and exit')
    return {'schema_version': 0, 'execve_count': execs, 'successful_exit_count': exits,
            'child_creation_count': 0, 'network_count': 0, 'runtime_acquisition_count': 0,
            'target_library_read_count': 0, 'target_library_mapping_count': 0,
            'publication_output_read_mapping_count': 0, 'outside_prefix_mutation_count': 0,
            'descriptor_reassignment_count': 0, 'unclassified_syscall_count': 0, 'executable_system_mapping_inventory': sorted(executable_system_files),
            'anonymous_executable_mapping_count': 0, 'executable_memory_protection_grant_count': 0,
            'trace_identity': file_identity(path), 'program': program, 'prefix': output}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ('glue', 'full', 'install', 'output', 'scratch', 'audit-tree', 'report', 'audit-process-trace'):
        parser.add_argument('--' + name, type=Path)
    parser.add_argument('--provider', choices=PROVIDERS)
    parser.add_argument('--program')
    args = parser.parse_args()
    # Do not normalize output/prefix inputs in controls: canonical-path rejection
    # is part of the actual command contract. Ordinary fixture roots are absolute.
    for name in ('glue', 'full', 'install', 'output', 'scratch', 'audit_tree', 'report', 'audit_process_trace'):
        value = getattr(args, name)
        if value is not None:
            setattr(args, name, value.absolute())
    try:
        if args.audit_process_trace is not None:
            require(args.program is not None, '--program is required for process trace audit')
            result = audit_process_trace(args.audit_process_trace, args.program)
        elif args.audit_tree is not None:
            require(args.provider is not None and args.report is not None, '--provider and --report are required for tree audit')
            result = audit_tree(args.audit_tree, args.provider, strict_json(args.report.read_bytes()))
            if args.output is not None:
                args.output.write_text(json.dumps(result, indent=2, sort_keys=True) + '\n', encoding='utf-8')
                result = {name: result[name] for name in ('provider', 'file_count', 'payload_bytes', 'directory_count',
                                                         'file_mode', 'directory_mode', 'mtime_seconds', 'provenance_file',
                                                         'all_file_bytes_modes_times_verified', 'all_directory_modes_times_verified')}
        else:
            require(all(getattr(args, name) is not None for name in ('glue', 'full', 'install', 'output')),
                    '--glue, --full, --install and --output are required for generation audit')
            full_result = audit(args)
            result = {name: full_result[name] for name in ('valid_generations', 'hostile_controls', 'large_payloads_retained', 'runtime_execution_observed')}
        print(json.dumps(result, sort_keys=True))
    except (OSError, ValueError, KeyError, TypeError) as error:
        print('host prerequisite audit failed: ' + str(error), file=sys.stderr)
        return 1
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
