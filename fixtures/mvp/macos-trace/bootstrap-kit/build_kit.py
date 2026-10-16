#!/usr/bin/env python3
"""Reviewed, host-only kit construction. Never runs a newly built executable."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import platform
import re
import stat
import struct
import subprocess
import sys

HERE = Path(__file__).resolve().parent
REGISTRY = HERE / 'reviewed-inputs.json'
MAX_FILE = 8 * 1024 * 1024
MAX_TOTAL = 64 * 1024 * 1024
MAX_FILES = 256
MAX_JSON = 256 * 1024
PREFIX = '/System/Volumes/Data/Library/GlueMVPFixtures/'
GUEST_KIT = '/Volumes/My Shared Files/glue-mvp-macos-vm-toolkit/bootstrap-inspector-v1-20261016'
GUEST_RESULTS = '/Volumes/My Shared Files/glue-mvp-macos-vm-results'
HEX = re.compile(r'[0-9a-f]{64}\Z')
SOURCE_NAME = re.compile(r'[A-Za-z0-9_./-]+\Z')
COMMANDS = ('binary-check', 'signature', 'sip', 'os', 'kernel', 'observation')


class Refusal(ValueError):
    pass


def require(value, message):
    if not value:
        raise Refusal(message)


def exact_keys(value, keys):
    require(type(value) is dict and set(value) == set(keys), 'unexpected object keys')
    return value


def integer(value, minimum=0, maximum=(1 << 64) - 1):
    require(type(value) is int and minimum <= value <= maximum, 'integer type/range')
    return value


def sha(value):
    require(type(value) is str and HEX.fullmatch(value), 'SHA-256 syntax')
    return value


def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(',', ':'), ensure_ascii=True).encode() + b'\n'


def digest(data):
    return hashlib.sha256(data).hexdigest()


def strict_json(data):
    require(type(data) is bytes and len(data) <= MAX_JSON, 'JSON bound')
    def pairs(items):
        result = {}
        for key, value in items:
            require(key not in result, 'duplicate JSON key')
            result[key] = value
        return result
    try:
        return json.loads(data.decode('utf-8'), object_pairs_hook=pairs,
                          parse_constant=lambda _: (_ for _ in ()).throw(Refusal('nonfinite JSON')))
    except (UnicodeError, json.JSONDecodeError, RecursionError) as exc:
        raise Refusal('invalid bounded JSON') from exc


def relative_name(name):
    require(type(name) is str and len(name) <= 512 and SOURCE_NAME.fullmatch(name), 'member name')
    require(all(part not in ('', '.', '..') for part in name.split('/')), 'member escape')
    return name


def open_directory(path):
    """Resolve an absolute physical chain without following any symlink."""
    path = Path(path)
    require(path.is_absolute(), 'absolute physical directory required')
    parts = path.parts[1:]
    require(all(p not in ('', '.', '..') for p in parts), 'directory escape')
    fd = os.open('/', os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC)
    try:
        for part in parts:
            child = os.open(part, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC, dir_fd=fd)
            os.close(fd)
            fd = child
        return fd
    except BaseException:
        os.close(fd)
        raise


def read_member(root_fd, name, maximum=MAX_FILE):
    relative_name(name)
    fd = os.dup(root_fd)
    try:
        parts = name.split('/')
        for part in parts[:-1]:
            child = os.open(part, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC, dir_fd=fd)
            os.close(fd)
            fd = child
        leaf = os.open(parts[-1], os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC, dir_fd=fd)
        try:
            before = os.fstat(leaf)
            require(stat.S_ISREG(before.st_mode) and before.st_nlink == 1 and before.st_size <= maximum, 'regular single-link bounded file required')
            chunks, count = [], 0
            while count <= maximum:
                chunk = os.read(leaf, min(65536, maximum + 1 - count))
                if not chunk:
                    break
                count += len(chunk)
                chunks.append(chunk)
            after = os.fstat(leaf)
            attributes = ('st_dev', 'st_ino', 'st_size', 'st_mtime_ns', 'st_ctime_ns')
            require(count == before.st_size and count <= maximum and
                    all(getattr(before, k) == getattr(after, k) for k in attributes), 'file changed or oversized')
            return b''.join(chunks)
        finally:
            os.close(leaf)
    finally:
        os.close(fd)


def tree_members(root_fd):
    names = []
    def visit(fd, prefix='', depth=0):
        require(depth <= 16, 'directory depth')
        entries = sorted(os.listdir(fd))
        require(len(entries) <= MAX_FILES, 'directory entry bound')
        for entry in entries:
            name = relative_name(prefix + entry)
            info = os.stat(entry, dir_fd=fd, follow_symlinks=False)
            if stat.S_ISDIR(info.st_mode):
                child = os.open(entry, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC, dir_fd=fd)
                try:
                    require(os.listdir(child), 'unexpected empty directory')
                    visit(child, name + '/', depth + 1)
                finally:
                    os.close(child)
            else:
                require(stat.S_ISREG(info.st_mode) and info.st_nlink == 1, 'link or special member')
                names.append(name)
                require(len(names) <= MAX_FILES, 'file count bound')
    visit(root_fd)
    return names


def parse_manifest(data):
    require(len(data) <= MAX_JSON, 'manifest bound')
    try:
        lines = data.decode('ascii').splitlines(keepends=True)
    except UnicodeError as exc:
        raise Refusal('manifest encoding') from exc
    require(lines and len(lines) < MAX_FILES, 'manifest count')
    result = {}
    for line in lines:
        require(line.endswith('\n') and len(line) > 67 and line[64:66] == '  ', 'manifest line')
        value, name = sha(line[:64]), relative_name(line[66:-1])
        require(name != 'SHA256SUMS' and name not in result, 'duplicate/self manifest')
        result[name] = value
    return result


def verified_tree(path, expected_manifest):
    sha(expected_manifest)
    fd = open_directory(path)
    try:
        manifest = read_member(fd, 'SHA256SUMS', MAX_JSON)
        require(digest(manifest) == expected_manifest, 'unregistered tree manifest')
        wanted = parse_manifest(manifest)
        require(set(tree_members(fd)) == set(wanted) | {'SHA256SUMS'}, 'unexpected or missing tree member')
        result, total = {}, 0
        for name, value in wanted.items():
            data = read_member(fd, name)
            total += len(data)
            require(total <= MAX_TOTAL and digest(data) == value, 'tree bytes/hash')
            result[name] = data
        return result
    finally:
        os.close(fd)


def observation(data):
    value = strict_json(data)
    exact_keys(value, ('schema', 'model', 'kernel_release', 'observed_unix_seconds', 'observed_nanoseconds',
                       'ids', 'groups', 'tc_compatible', 'components', 'settings_changed', 'executable_admission', 'full_acceptance'))
    require(value['schema'] == 'glue-bootstrap-deployment-observation-v1' and value['model'] == 'VirtualMac2,1', 'observation schema/model')
    require(type(value['kernel_release']) is str and re.fullmatch(r'[0-9]+\.[0-9]+\.[0-9]+', value['kernel_release']), 'kernel release')
    integer(value['observed_unix_seconds'], 1); integer(value['observed_nanoseconds'], 0, 999999999)
    require(value['tc_compatible'] is True and all(value[k] is False for k in ('settings_changed', 'executable_admission', 'full_acceptance')), 'observation scope/compatibility')
    ids, groups = value['ids'], value['groups']
    require(type(ids) is list and len(ids) == 4 and type(groups) is list and 1 <= len(groups) <= 16, 'identity/group counts')
    for item in ids: integer(item, 1, 2147483647)
    for item in groups: integer(item, 0, 2147483647)
    require(ids[0] == ids[1] and ids[2] == ids[3] == groups[0] and len(set(groups)) == len(groups), 'canonical actual credentials')
    components = value['components']
    require(type(components) is list and len(components) == 5, 'component count')
    keys = ('name', 'device', 'inode', 'uid', 'gid', 'mode', 'fsid', 'mount_flags', 'mount_policy',
            'mount_owner', 'descriptor_flags', 'status_flags', 'mountpoint', 'filesystem', 'filesec_population', 'acl_present')
    for i, item in enumerate(components):
        exact_keys(item, keys)
        require(item['name'] == ('/', 'System', 'Volumes', 'Data', 'Library')[i], 'component name')
        integer(item['device'], 1); integer(item['inode']); integer(item['mount_flags'])
        integer(item['uid'], 0, 0); integer(item['gid'], 0, 4294967295)
        mode = integer(item['mode'], 0, 65535)
        require(stat.S_ISDIR(mode) and not mode & 0o6022, 'component ownership/mode')
        require(type(item['fsid']) is list and len(item['fsid']) == 2, 'FSID count')
        for word in item['fsid']: integer(word, -(1 << 31), (1 << 31) - 1)
        require(any(item['fsid']), 'zero FSID')
        integer(item['mount_policy'], 3 if i < 3 else 1, 3 if i < 3 else 1)
        integer(item['mount_owner'], 0, 0)
        flags = integer(item['descriptor_flags'], 0, 2147483647)
        status = integer(item['status_flags'], 0, 2147483647)
        require(flags & 1 and status & (3 | 64 | 32768) == 0, 'Darwin descriptor/status flags')
        require(item['mountpoint'] == ('/' if i < 3 else '/System/Volumes/Data') and item['filesystem'] == 'apfs', 'mount text')
        integer(item['filesec_population'], 7, 7); integer(item['acl_present'], 0, 0)
    mount = lambda c: (c['device'], tuple(c['fsid']))
    require(all(mount(c) == mount(components[0]) for c in components[:3]) and
            mount(components[0]) != mount(components[3]) and mount(components[3]) == mount(components[4]), 'root/Data transition')
    return value


def registry(data):
    value = strict_json(data)
    exact_keys(value, ('schema', 'source_revision', 'sources', 'probe_sources', 'runner_sources', 'request_sources', 'proofs'))
    require(value['schema'] == 'glue-bootstrap-kit-inputs-v1', 'registry schema')
    require(type(value['sources']) is dict and len(value['sources']) <= 128, 'source closure bound')
    for name, identity in value['sources'].items():
        relative_name(name); sha(identity)
        require(name != 'fixtures/mvp/macos-trace/bootstrap-kit/reviewed-inputs.json', 'registry cannot enter its own source digest')
    for key in ('probe_sources', 'runner_sources', 'request_sources'):
        seq = value[key]
        require(type(seq) is list and len(seq) <= 32 and all(type(n) is str for n in seq) and len(set(seq)) == len(seq), 'compile source list')
        for name in seq:
            require(type(name) is str and name in value['sources'] and name.endswith('.c') and not name.endswith('/catalog_unconfigured.c'), 'unlocked/default compile source')
    require(type(value['proofs']) is list and len(value['proofs']) <= 8, 'proof registry bound')
    identities = set()
    for p in value['proofs']:
        exact_keys(p, ('manifest_sha256', 'review_manifest_sha256', 'inspector_manifest_sha256', 'wrapper_sha256',
                       'binary_sha256', 'inspector_source_commit', 'guest_output_name', 'kernel_release', 'os_version', 'os_build'))
        for key in ('manifest_sha256', 'review_manifest_sha256', 'inspector_manifest_sha256', 'wrapper_sha256', 'binary_sha256'): sha(p[key])
        require(p['manifest_sha256'] not in identities, 'duplicate admitted proof')
        identities.add(p['manifest_sha256'])
        require(type(p['inspector_source_commit']) is str and re.fullmatch(r'[0-9a-f]{7,40}', p['inspector_source_commit']), 'source commit syntax')
        require(type(p['guest_output_name']) is str and re.fullmatch(r'glue-bootstrap-deployment-v1-[A-Za-z0-9]{8}', p['guest_output_name']), 'guest result name')
        for key in ('kernel_release', 'os_version', 'os_build'):
            require(type(p[key]) is str and re.fullmatch(r'[A-Za-z0-9.]{1,32}', p[key]), 'registered OS text')
    if value['source_revision'] is not None:
        require(type(value['source_revision']) is str and re.fullmatch(r'[0-9a-f]{40}', value['source_revision']), 'source revision')
    return value


def admitted_proof(proof_path, kit_path, rules):
    # A registry entry is a reviewed workflow input, not an administrator-proof
    # trust root. Self-consistency or a caller-provided hash cannot add an entry.
    fd = open_directory(proof_path)
    try: identity = digest(read_member(fd, 'SHA256SUMS', MAX_JSON))
    finally: os.close(fd)
    entry = next((p for p in rules['proofs'] if p['manifest_sha256'] == identity), None)
    require(entry is not None, 'actual proof has not been independently reviewed/registered')
    proof = verified_tree(proof_path, identity)
    kit = verified_tree(kit_path, entry['inspector_manifest_sha256'])
    require('KIT.json' in kit and digest(kit.get('run-inspector.sh', b'')) == entry['wrapper_sha256'] and
            digest(kit.get('inspect-deployment', b'')) == entry['binary_sha256'], 'inspector kit identity')
    kd = strict_json(kit['KIT.json'])
    exact_keys(kd, ('binary_sha256', 'guest_execution_completed', 'minimum_macos', 'privilege_required', 'purpose',
                    'schema', 'settings_changed', 'signature', 'source_commit', 'source_manifest_sha256'))
    require(kd['schema'] == 'glue-bootstrap-inspector-vm-kit-v1' and kd['binary_sha256'] == entry['binary_sha256'] and
            kd['source_commit'] == entry['inspector_source_commit'] and kd['minimum_macos'] == '26.0' and
            kd['signature'] == 'strict-verified development ad-hoc' and all(kd[k] is False for k in
            ('guest_execution_completed', 'privilege_required', 'settings_changed')), 'inspector kit schema/scope')
    sha(kd['source_manifest_sha256'])
    wanted = {'wrapper-source.sh', 'binary-check.sha256', 'wrapper.json'} | {f'{c}.{suffix}' for c in COMMANDS for suffix in ('argv', 'status', 'stdout', 'stderr')}
    require(set(proof) == wanted and proof['wrapper-source.sh'] == kit['run-inspector.sh'], 'proof members/wrapper')
    wrapper = strict_json(proof['wrapper.json'])
    exact_keys(wrapper, ('schema', 'failed', 'settings_changed', 'full_acceptance'))
    require(wrapper['schema'] == 'glue-bootstrap-inspection-wrapper-v1' and integer(wrapper['failed'], 0, 0) == 0 and
            wrapper['settings_changed'] is False and wrapper['full_acceptance'] is False, 'wrapper did not complete')
    output = GUEST_RESULTS + '/' + entry['guest_output_name']
    commands = {
        'binary-check': ['/usr/bin/shasum', '-a', '256', '-c', output + '/binary-check.sha256'],
        'signature': ['/usr/bin/codesign', '--verify', '--strict', '--verbose=2', GUEST_KIT + '/inspect-deployment'],
        'sip': ['/usr/bin/csrutil', 'status'], 'os': ['/usr/bin/sw_vers'], 'kernel': ['/usr/bin/uname', '-mrs'],
        'observation': [GUEST_KIT + '/inspect-deployment']}
    for name, argv in commands.items():
        require(proof[name + '.status'] == b'0\n' and proof[name + '.argv'] == b''.join(a.encode() + b'\0' for a in argv), 'command argv/status mismatch')
    target = GUEST_KIT + '/inspect-deployment'
    require(proof['binary-check.sha256'] == (entry['binary_sha256'] + '  ' + target + '\n').encode() and
            proof['binary-check.stdout'] == (target + ': OK\n').encode(), 'guest binary hash check')
    require(proof['sip.stdout'] == b'System Integrity Protection status: enabled.\n', 'SIP is not exactly enabled')
    require(proof['kernel.stdout'] == ('Darwin ' + entry['kernel_release'] + ' arm64\n').encode(), 'guest kernel/architecture')
    try:
        os_lines = proof['os.stdout'].decode('ascii').splitlines()
        os_items = [line.split(':', 1) for line in os_lines]
        require(len(os_items) == 3 and all(len(x) == 2 for x in os_items), 'OS lines')
        require([(a, b.strip()) for a, b in os_items] == [('ProductName', 'macOS'), ('ProductVersion', entry['os_version']), ('BuildVersion', entry['os_build'])], 'OS version/build')
    except UnicodeError as exc:
        raise Refusal('OS output encoding') from exc
    result = observation(proof['observation.stdout'])
    require(result['kernel_release'] == entry['kernel_release'], 'observation kernel differs')
    return entry, result


def catalog_bytes(build_id, profile, probe_size, probe_sha, probe_sources, runner_sources, recipe_sha):
    sha(build_id)
    for value in (probe_sha, probe_sources, runner_sources, recipe_sha): sha(value)
    integer(probe_size, 1, 4194304)
    exact_keys(profile, ('root', 'data'))
    root, data = profile['root'], profile['data']
    for item in (root, data):
        exact_keys(item, ('device', 'fsid')); integer(item['device'], 1)
        require(type(item['fsid']) is list and len(item['fsid']) == 2, 'catalog FSID')
        for word in item['fsid']: integer(word, -(1 << 31), (1 << 31) - 1)
        require(any(item['fsid']), 'catalog zero FSID')
    require(root != data, 'catalog root equals Data')
    out = bytearray(192)
    struct.pack_into('>8sHHIQQiiQii', out, 0, b'GLUENC01', 1, 192, 269, probe_size,
                     root['device'], *root['fsid'], data['device'], *data['fsid'])
    out[56:184] = b''.join(bytes.fromhex(x) for x in (probe_sha, probe_sources, runner_sources, recipe_sha))
    struct.pack_into('>HH', out, 184, 64, 13)
    return bytes(out) + build_id.encode() + b'context-probe'


def generated_catalog(build_id, profile, size, identities, raw):
    # Only validated hex/integers enter generated C, never caller C source text.
    require(type(identities) in (tuple, list) and len(identities) == 4, 'catalog digest count')
    require(raw == catalog_bytes(build_id, profile, size, *identities), 'generated catalog bytes differ')
    def array(data): return '{' + ','.join(str(x) for x in data) + '}'
    def mount(m): return '{UINT64_C(' + str(m['device']) + '),{' + ','.join(str(x) for x in m['fsid']) + '}}'
    hashes = ','.join(array(bytes.fromhex(sha(s))) for s in identities)
    return ('#include "fixtures/mvp/macos-trace/bootstrap-runner/runner_catalog.h"\n'
            '#include "fixtures/mvp/macos-trace/bootstrap-kit/request_catalog.h"\n'
            'static const struct nr_catalog c={UINT64_C(' + str(integer(size, 1, 4194304)) + '),{' +
            mount(profile['root']) + ',' + mount(profile['data']) + '},' + hashes + ',"' + build_id + '","context-probe"};\n'
            'static const struct bk_request_catalog v={' + array(raw + bytes(320-len(raw))) + ',' + str(len(raw)) + '};\n'
            'const struct nr_catalog *nr_compiled_catalog(void){return &c;}\n'
            'const struct bk_request_catalog *bk_compiled_request_catalog(void){return &v;}\n').encode()


def macho(data):
    """Bounded load-command provenance check; not a general Mach-O verifier."""
    require(type(data) is bytes and len(data) <= 4194304 and len(data) >= 32, 'executable bytes bound')
    magic, cpu, subtype, kind, count, size, flags, reserved = struct.unpack_from('<8I', data)
    require(magic == 0xfeedfacf and cpu == 0x100000c and subtype == 0 and kind == 2 and reserved == 0 and 1 <= count <= 128 and
            size <= 65536 and 32 + size <= len(data), 'native arm64 executable header')
    allowed = {0x19, 2, 0xb, 0xe, 0x32, 0x80000028, 0x26, 0x29, 0x1d, 0x2a, 0x80000022, 0x80000033, 0x80000034, 0xc, 0x2e, 0x1b}
    loads, dylinkers, builds, signatures, uuids = [], [], [], 0, []
    at = 32
    for _ in range(count):
        require(at + 8 <= 32 + size, 'truncated load command')
        cmd, length = struct.unpack_from('<II', data, at)
        require(cmd in allowed and length >= 8 and length % 8 == 0 and at + length <= 32 + size, 'unsupported/invalid load command')
        raw = data[at:at+length]
        if cmd in (0xc, 0xe):
            require(length >= (24 if cmd == 0xc else 12), 'dynamic command size')
            offset = struct.unpack_from('<I', raw, 8)[0]
            require((24 if cmd == 0xc else 12) <= offset < length and b'\0' in raw[offset:], 'dynamic name bounds')
            name, tail = raw[offset:].split(b'\0', 1)
            require(not any(tail), 'dynamic command padding')
            (loads if cmd == 0xc else dylinkers).append(name)
        elif cmd == 0x32:
            require(length >= 24, 'build-version size')
            plat, minimum, sdk, tools = struct.unpack_from('<4I', raw, 8)
            require(length == 24 + tools * 8 and plat == 1 and minimum == 0x1a0000, 'macOS minimum/build-version')
            builds.append((minimum, sdk))
        elif cmd == 0x1d:
            require(length == 16, 'signature command size')
            offset, amount = struct.unpack_from('<II', raw, 8)
            require(amount and offset + amount <= len(data), 'signature range')
            signatures += 1
        elif cmd == 0x1b:
            require(length == 24 and any(raw[8:24]), 'UUID command size/value')
            uuids.append(raw[8:24].hex())
        at += length
    require(at == 32 + size and loads == [b'/usr/lib/libSystem.B.dylib'] and dylinkers == [b'/usr/lib/dyld'] and
            len(builds) == 1 and signatures == 1 and len(uuids) == 1, 'dyld/libSystem/minimum/signature/UUID provenance')
    return {'architecture': 'arm64', 'minimum_macos': '26.0', 'sdk_word': builds[0][1],
            'dependencies': ['/usr/lib/libSystem.B.dylib'], 'dylinker': '/usr/lib/dyld', 'uuid': uuids[0]}


def git(repo, *args):
    done = subprocess.run(['/usr/bin/git', '-C', str(repo), *args], capture_output=True, timeout=30, env={'PATH': '/usr/bin:/bin', 'LC_ALL': 'C'})
    require(done.returncode == 0 and len(done.stdout) <= MAX_FILE and len(done.stderr) <= MAX_JSON, 'git source check failed')
    return done.stdout


def locked_sources(repo, rules):
    require(rules['source_revision'] is not None and rules['sources'] and all(rules[k] for k in ('probe_sources', 'runner_sources', 'request_sources')), 'runner/source closure is not configured/frozen')
    require(not git(repo, 'status', '--porcelain=v1', '--untracked-files=all'), 'dirty/untracked checkout refused')
    require(git(repo, 'merge-base', '--is-ancestor', rules['source_revision'], 'HEAD') == b'', 'unrelated source revision')
    root = open_directory(repo)
    try:
        result = {}
        for name, identity in rules['sources'].items():
            data = read_member(root, name)
            require(digest(data) == identity and git(repo, 'show', rules['source_revision'] + ':' + name) == data, 'source lock mismatch')
            result[name] = data
        for name in ('build_kit.py', 'reviewed-inputs.json'):
            path = 'fixtures/mvp/macos-trace/bootstrap-kit/' + name
            require(git(repo, 'show', 'HEAD:' + path) == read_member(root, path), 'uncommitted builder/registry')
        require('fixtures/mvp/macos-trace/bootstrap-kit/build_kit.py' in result, 'builder absent from closure')
        return result
    finally:
        os.close(root)


def outside_repository(output, repository):
    """Reject lexical links/.. and physical descendants, including mount aliases.
    No directory is created. Stable namespace is an explicit build precondition.
    """
    output = Path(output)
    require(output.is_absolute(), 'absolute new output required')
    root = open_directory(repository)
    parent = open_directory(output.parent)
    try:
        r = os.fstat(root)
        identity = (r.st_dev, r.st_ino)
        for _ in range(512):
            current = os.fstat(parent)
            here = (current.st_dev, current.st_ino)
            require(here != identity, 'output must be outside the repository')
            above = os.open('..', os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC, dir_fd=parent)
            a = os.fstat(above)
            if (a.st_dev, a.st_ino) == here:
                os.close(above)
                return
            os.close(parent)
            parent = above
        raise Refusal('output ancestor bound')
    finally:
        os.close(parent)
        os.close(root)


class Build:
    def __init__(self, output, repository):
        # No existing output, overwrite, cleanup or recursive deletion.
        self.output = Path(output)
        outside_repository(self.output, repository)
        parent = open_directory(self.output.parent)
        try:
            require(re.fullmatch(r'[A-Za-z0-9][A-Za-z0-9._-]{0,127}', self.output.name), 'output leaf')
            os.mkdir(self.output.name, 0o700, dir_fd=parent)
        finally:
            os.close(parent)
        self.commands = []
        self.env = {'PATH': '/usr/bin:/bin:/usr/sbin:/sbin', 'LC_ALL': 'C', 'TZ': 'UTC',
                    'MACOSX_DEPLOYMENT_TARGET': '26.0', 'SOURCE_DATE_EPOCH': '0'}

    def put(self, name, data):
        relative_name(name)
        path = self.output / name
        path.parent.mkdir(parents=True, exist_ok=True)
        with path.open('xb') as stream:
            stream.write(data)

    def run(self, label, argv):
        require(re.fullmatch(r'[a-z0-9-]+', label), 'command label')
        self.put('logs/' + label + '.argv.json', canonical(argv))
        out = self.output / ('logs/' + label + '.stdout')
        err = self.output / ('logs/' + label + '.stderr')
        code, timed_out = None, False
        try:
            with out.open('xb') as stdout, err.open('xb') as stderr:
                done = subprocess.run(argv, stdout=stdout, stderr=stderr, timeout=60, env=self.env, cwd=self.output)
                code = done.returncode
        except subprocess.TimeoutExpired:
            timed_out = True
        record = {'argv': argv, 'returncode': code, 'timed_out': timed_out}
        self.commands.append(record)
        self.put('logs/' + label + '.status.json', canonical(record))
        require(not timed_out and code == 0 and out.stat().st_size <= MAX_JSON and err.stat().st_size <= MAX_JSON, 'build command failed: ' + label)
        return out.read_bytes()

    def finish(self, result):
        result_bytes = canonical(result)
        lines = []
        fd = open_directory(self.output)
        try:
            total = 0
            for name in sorted(tree_members(fd)):
                data = read_member(fd, name)
                total += len(data)
                require(total <= MAX_TOTAL, 'generated tree byte bound')
                lines.append(digest(data) + '  ' + name + '\n')
        finally:
            os.close(fd)
        # A complete success record is last. An interrupted inventory leaves no
        # success record; a normal zero builder exit is still required.
        lines.append(digest(result_bytes) + '  result.json\n')
        self.put('SHA256SUMS', ''.join(lines).encode())
        self.put('result.json', result_bytes)


def construct(proof_path, kit_path, output):
    # Do not add test injection/trust options to this native entry point.
    rules = registry(REGISTRY.read_bytes())
    require(rules['proofs'], 'no independently reviewed actual guest proof is configured')
    repo = HERE.parents[3]
    sources = locked_sources(repo, rules)
    entry, observed = admitted_proof(proof_path, kit_path, rules)
    require(platform.system() == 'Darwin' and platform.machine() == 'arm64' and os.getuid() != 0 and os.geteuid() != 0, 'ordinary native Darwin arm64 build host required')
    build = Build(output, repo)
    try:
        for name, data in sources.items(): build.put('sources/' + name, data)
        build.put('source-lock.json', canonical(rules))
        build.put('admitted-proof.json', canonical({'registry_entry': entry, 'observation': observed, 'full_acceptance': False}))
        version = build.run('compiler-version', ['/usr/bin/xcrun', '--sdk', 'macosx', 'clang', '--version'])
        sdk = build.run('sdk-path', ['/usr/bin/xcrun', '--sdk', 'macosx', '--show-sdk-path']).decode().strip()
        sdk_version = build.run('sdk-version', ['/usr/bin/xcrun', '--sdk', 'macosx', '--show-sdk-version']).decode().strip()
        require(sdk.startswith('/Applications/') or sdk.startswith('/Library/Developer/'), 'unexpected SDK root')
        require('\n' not in sdk and '\0' not in sdk and re.fullmatch(r'[0-9.]+', sdk_version), 'SDK identity')
        flags = ['-arch', 'arm64', '-mmacosx-version-min=26.0', '-std=c11', '-O2', '-g0', '-Wall', '-Wextra', '-Werror']
        recipe = {'schema': 'glue-bootstrap-kit-recipe-v1', 'compiler': digest(version), 'sdk': sdk, 'sdk_version': sdk_version,
                  'compiler_tool': '/usr/bin/xcrun --sdk macosx clang', 'flags': flags, 'sign_tool': '/usr/bin/codesign',
                  'sign_flags': ['--force', '--sign', '-', '--timestamp=none', '--identifier', 'glue.mvp.bootstrap.{name}.{build_id}'],
                  'source_root_mapping': '/glue-sources', 'generated_catalog': '{generated_catalog}',
                  'probe_sources': rules['probe_sources'], 'runner_sources': rules['runner_sources'], 'request_sources': rules['request_sources'],
                  'full_acceptance': False}
        recipe_sha = digest(canonical(recipe))
        static_sha = digest(canonical(rules['sources']))
        probe_sha = digest(canonical({n: rules['sources'][n] for n in rules['sources'] if '/bootstrap-probe/' in n}))
        runner_sha = digest(canonical({n: s for n, s in rules['sources'].items() if '/bootstrap-kit/' not in n and '/bootstrap-probe/' not in n}))
        identity = digest(canonical({'schema': 'glue-bootstrap-kit-build-id-v1', 'sources': static_sha,
                                    'recipe': recipe_sha, 'guest_manifest': entry['manifest_sha256']}))
        build.put('recipe.json', canonical(recipe))
        profile = {name: {'device': observed['components'][i]['device'], 'fsid': observed['components'][i]['fsid']}
                   for name, i in (('root', 0), ('data', 3))}
        artifacts, catalog = {}, None
        source_root = build.output / 'sources'
        for trial in ('first', 'second'):
            directory = build.output / 'builds' / trial
            directory.mkdir(parents=True)
            generated = directory / 'catalog.generated.c'
            common = ['/usr/bin/xcrun', '--sdk', 'macosx', 'clang', *flags, '-isysroot', sdk, '-I', str(source_root),
                      '-ffile-prefix-map=' + str(source_root) + '=/glue-sources', '-fmacro-prefix-map=' + str(source_root) + '=/glue-sources']
            for name, key in (('context-probe', 'probe_sources'), ('bootstrap-runner', 'runner_sources'), ('make-request', 'request_sources')):
                path = directory / name
                command = common + [str(source_root / n) for n in rules[key]]
                if key != 'probe_sources': command += [str(generated)]
                command += ['-lproc', '-o', str(path)]
                build.run(trial + '-' + name + '-compile', command)
                build.run(trial + '-' + name + '-sign', ['/usr/bin/codesign', '--force', '--sign', '-', '--timestamp=none', '--identifier', 'glue.mvp.bootstrap.' + name + '.' + identity, str(path)])
                build.run(trial + '-' + name + '-verify', ['/usr/bin/codesign', '--verify', '--strict', '--verbose=2', str(path)])
                fd = open_directory(build.output)
                try: data = read_member(fd, 'builds/' + trial + '/' + name, 4194304)
                finally: os.close(fd)
                provenance = macho(data)
                if name == 'context-probe':
                    raw = catalog_bytes(identity, profile, len(data), digest(data), probe_sha, runner_sha, recipe_sha)
                    require(catalog is None or raw == catalog, 'probe/catalog builds differ')
                    catalog = raw
                    generated.write_bytes(generated_catalog(identity, profile, len(data), (digest(data), probe_sha, runner_sha, recipe_sha), raw))
                if trial == 'first': artifacts[name] = {'sha256': digest(data), 'size': len(data), 'provenance': provenance}
                else: require(digest(data) == artifacts[name]['sha256'] and len(data) == artifacts[name]['size'], 'signed builds are not byte-reproducible')
        build.put('catalog.bin', catalog)
        build.put('catalog.generated.c', (build.output / 'builds/first/catalog.generated.c').read_bytes())
        for name in artifacts:
            build.put('kit/' + name, (build.output / 'builds/first' / name).read_bytes())
            os.chmod(build.output / 'kit' / name, 0o555)
        build.finish({'schema': 'glue-bootstrap-kit-result-v1', 'status': 'built-reproducibly', 'build_id': identity,
                      'catalog_sha256': digest(catalog), 'artifacts': artifacts, 'new_binaries_executed': False,
                      'installed': False, 'kernel_exec_proof': False, 'full_acceptance': False})
        return 0
    except BaseException as exc:
        failed = {'schema': 'glue-bootstrap-kit-result-v1', 'status': 'failed', 'error': str(exc)[:512],
                  'new_binaries_executed': False, 'installed': False, 'kernel_exec_proof': False, 'full_acceptance': False}
        if not (build.output / 'failure.json').exists(): build.put('failure.json', canonical(failed))
        if not (build.output / 'result.json').exists() and not (build.output / 'SHA256SUMS').exists(): build.finish(failed)
        raise


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--guest-proof', required=True, type=Path)
    parser.add_argument('--inspector-kit', required=True, type=Path)
    parser.add_argument('--output', required=True, type=Path)
    args = parser.parse_args()
    try:
        return construct(args.guest_proof, args.inspector_kit, args.output)
    except (Refusal, OSError, subprocess.SubprocessError, UnicodeError) as exc:
        print('bootstrap-kit: ' + str(exc)[:512], file=sys.stderr)
        return 1


if __name__ == '__main__':
    sys.exit(main())
