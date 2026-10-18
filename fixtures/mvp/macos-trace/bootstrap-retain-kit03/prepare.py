#!/usr/bin/env python3
"""Render fixed owned-VM inventory/retention packets; never invoke guest tools."""
import argparse
import hashlib
import importlib.util
import json
import os
from pathlib import Path, PurePosixPath
import re
import secrets
import shlex
import sys

HERE = Path(__file__).resolve().parent
CORE = HERE.parent / 'bootstrap-kit/build_kit.py'
CORE_SHA = '440cdc2cadf5d86acae91e313c266b815d1c40130b4ce53d58a77e36b13fff48'
INVENTORY_SHA = '02e02538a71b2829bb684611d91d8f40bdbc7fa10bb6dd08bbaefa2c37e7a070'
COMPLETED_SHA = '28ce38d54156cb2c20121448ed539dd91db7da8f79dd682fa742af137661ef2f'
INSPECTOR = '/Volumes/My Shared Files/glue-mvp-macos-vm-toolkit/bootstrap-inspector-v1-20261016/inspect-deployment'
INSPECTOR_SHA = 'c78b9ddab7bb9feb15d8575847018b88d3dc6c8c520037867fa7ed82b2b2b77a'
# Separate gates. Neither a CLI flag nor a caller-supplied approval can enable them.
INSPECTION_APPROVAL = {'proof_manifest_sha256': 'cd57a36af2a9db11f7d24105485137f7afb2ad9743161db190d7ed6c7ca361fd',
 'proof_review_manifest_sha256': '2b3c60fc811ed292cd3e33a33851ba751a1de8c3667c5c2df8f4062000d80dfb',
 'observation': {'schema': 'glue-bootstrap-deployment-observation-v1',
                 'model': 'VirtualMac2,1',
                 'kernel_release': '25.6.0',
                 'observed_unix_seconds': 1792320840,
                 'observed_nanoseconds': 765135000,
                 'ids': [501, 501, 20, 20],
                 'groups': [20, 12, 61, 79, 80, 81, 701, 33, 98, 100, 204, 250, 395, 398, 399, 400],
                 'tc_compatible': True,
                 'components': [{'name': '/',
                                 'device': 16777234,
                                 'inode': 2,
                                 'uid': 0,
                                 'gid': 0,
                                 'mode': 16877,
                                 'fsid': [16777236, 26],
                                 'mount_flags': 1149292545,
                                 'mount_policy': 3,
                                 'mount_owner': 0,
                                 'descriptor_flags': 1,
                                 'status_flags': 0,
                                 'mountpoint': '/',
                                 'filesystem': 'apfs',
                                 'filesec_population': 7,
                                 'acl_present': 0},
                                {'name': 'System',
                                 'device': 16777234,
                                 'inode': 1152921500311879703,
                                 'uid': 0,
                                 'gid': 0,
                                 'mode': 16877,
                                 'fsid': [16777236, 26],
                                 'mount_flags': 1149292545,
                                 'mount_policy': 3,
                                 'mount_owner': 0,
                                 'descriptor_flags': 1,
                                 'status_flags': 0,
                                 'mountpoint': '/',
                                 'filesystem': 'apfs',
                                 'filesec_population': 7,
                                 'acl_present': 0},
                                {'name': 'Volumes',
                                 'device': 16777234,
                                 'inode': 1152921500312543581,
                                 'uid': 0,
                                 'gid': 0,
                                 'mode': 16877,
                                 'fsid': [16777236, 26],
                                 'mount_flags': 1149292545,
                                 'mount_policy': 3,
                                 'mount_owner': 0,
                                 'descriptor_flags': 1,
                                 'status_flags': 0,
                                 'mountpoint': '/',
                                 'filesystem': 'apfs',
                                 'filesec_population': 7,
                                 'acl_present': 0},
                                {'name': 'Data',
                                 'device': 16777234,
                                 'inode': 1152921500311879682,
                                 'uid': 0,
                                 'gid': 0,
                                 'mode': 16877,
                                 'fsid': [16777234, 26],
                                 'mount_flags': 76582912,
                                 'mount_policy': 1,
                                 'mount_owner': 0,
                                 'descriptor_flags': 1,
                                 'status_flags': 0,
                                 'mountpoint': '/System/Volumes/Data',
                                 'filesystem': 'apfs',
                                 'filesec_population': 7,
                                 'acl_present': 0},
                                {'name': 'Library',
                                 'device': 16777234,
                                 'inode': 471,
                                 'uid': 0,
                                 'gid': 0,
                                 'mode': 16877,
                                 'fsid': [16777234, 26],
                                 'mount_flags': 76582912,
                                 'mount_policy': 1,
                                 'mount_owner': 0,
                                 'descriptor_flags': 1,
                                 'status_flags': 0,
                                 'mountpoint': '/System/Volumes/Data',
                                 'filesystem': 'apfs',
                                 'filesec_population': 7,
                                 'acl_present': 0}],
                 'settings_changed': False,
                 'executable_admission': False,
                 'full_acceptance': False}}
APPROVED = None
RETENTION_ENABLED = False
PREFIX = '/System/Volumes/Data/Library/GlueMVPFixtures'
ARCHIVE = '/System/Volumes/Data/Library/GlueMVPFixtures-retained-1b85f0ac-da1aaf9a'
BUILD = '1b85f0ac3d3ec2de7df50004ee2732d8d5c049adb44193383245050f800fa11d'
TMP = '/System/Volumes/Data/private/tmp/'
NONCES = ('c10ed2e4ce0404bd', '6ae386cc044ff2a1', '1ee4bbe2b443c268', 'da1aaf9a396020b3')
CASES = ('positive', 'simulated', 'denied', 'trailing')
ROOTS = (PREFIX, '/System/Volumes/Data/Library/GlueMVPFixtures-retained-a75d54bb-1ee4bbe2') + tuple(
    path for nonce in NONCES for path in (
        *(TMP + stem + nonce for stem in ('glue-bs-stage-', 'glue-bs-user-', 'glue-bs-launch-')),
        *(TMP + 'glue-bs-' + nonce + '-' + case for case in CASES))) + tuple(
    TMP + stem + '1ee4bbe2b443c268-03' for stem in ('glue-bs-retain-stage-', 'glue-bs-retain-launch-'))
PARENTS = ('/', '/System', '/System/Volumes', '/System/Volumes/Data',
           '/System/Volumes/Data/Library', '/System/Volumes/Data/private', TMP[:-1])
ARTIFACTS = {
    'bootstrap-runner': (110768, '2e3714e8d6503a21a76947ad93f3328419dcf0b2bf21909145d819e437ffcceb'),
    'context-probe': (52912, 'b15f974ed14129d738b8963d8d8d865502e73e9be11436105468e071ee8cbf67'),
    'make-request': (72240, '28dea7f9bc8aaabb0ce1421e55522b8cf4a9f7efa6e3b79aa8a4ae6f92c164b8'),
}


def require(value, message):
    if not value:
        raise ValueError(message)


def sha(data):
    return hashlib.sha256(data).hexdigest()


def canonical(value):
    return (json.dumps(value, sort_keys=True, separators=(',', ':'), ensure_ascii=True) + '\n').encode()


def enabled(mode):
    require(mode in ('inspect', 'retain'), 'fixed operation')
    require(INSPECTION_APPROVAL is not None, 'fresh inspection approval is not configured')
    if mode == 'retain':
        require(APPROVED is not None and RETENTION_ENABLED is True,
                'retention approval/execution is not configured')


def primitives():
    require(sha(CORE.read_bytes()) == CORE_SHA, 'reviewed host parser differs')
    spec = importlib.util.spec_from_file_location('kit03_retention_primitives', CORE)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def inspection_approval():
    p = primitives()
    a = INSPECTION_APPROVAL
    p.exact_keys(a, ('proof_manifest_sha256', 'proof_review_manifest_sha256', 'observation'))
    p.sha(a['proof_manifest_sha256']); p.sha(a['proof_review_manifest_sha256'])
    observed = p.observation(p.canonical(a['observation']))
    require(observed['model'] == 'VirtualMac2,1' and observed['kernel_release'] == '25.6.0' and
            observed['ids'] == [501, 501, 20, 20], 'fixed guest profile')
    return a


def completed_pins():
    data = (HERE / 'completed-files.json').read_bytes()
    require(sha(data) == COMPLETED_SHA, 'completed byte pins differ')
    return json.loads(data)['files']


def validate_snapshot(snapshot, device):
    """Admit only a complete physically inspected fixed forest, never an override."""
    p = primitives()
    p.exact_keys(snapshot, ('parents', 'roots'))
    p.exact_keys(snapshot['parents'], PARENTS)
    p.exact_keys(snapshot['roots'], ROOTS)
    for path, m in snapshot['parents'].items():
        p.exact_keys(m, ('device', 'inode', 'mode', 'uid', 'gid'))
        require(m['device'] == device and m['uid'] == m['gid'] == 0 and
                m['mode'] == (0o41777 if path == TMP[:-1] else 0o40755), 'protected parent')
        p.integer(m['inode'], 1)
    count = total = 0
    for root, entries in snapshot['roots'].items():
        if entries is None:
            continue
        require(type(entries) is list and entries and len(entries) <= 2048, 'tree roster')
        by_name = {}
        for m in entries:
            require(type(m) is dict, 'entry object')
            directory = m.get('mode', 0) & 0o170000 == 0o040000
            p.exact_keys(m, ('device', 'inode', 'mode', 'links', 'uid', 'gid', 'size', 'relative',
                            'names' if directory else 'sha256'))
            r = m['relative']
            require(type(r) is str and (r == '.' or (len(PurePosixPath(r).parts) <= 5 and
                    all(re.fullmatch('[A-Za-z0-9._-]{1,128}', x) and x not in ('.', '..')
                        for x in r.split('/')))), 'relative path')
            require(r not in by_name and m['device'] == device, 'duplicate or foreign device')
            for k in ('device', 'inode', 'links'):
                p.integer(m[k], 1)
            p.integer(m['size'], 0, 4194304)
            p.integer(m['mode'], 1, 0o177777)
            p.integer(m['uid'], 0); p.integer(m['gid'], 0)
            require(m['uid'] in (0, 501) and m['gid'] in (0, 20) and not m['mode'] & 0o22,
                    'entry ownership/mode')
            if directory:
                require(type(m['names']) is list and len(m['names']) <= 128 and
                        m['names'] == sorted(set(m['names'])) and all(type(x) is str and
                        re.fullmatch('[A-Za-z0-9._-]{1,128}', x) and x not in ('.', '..')
                        for x in m['names']), 'directory names')
            else:
                require(m['mode'] & 0o170000 == 0o100000 and m['links'] == 1, 'regular single link')
                p.sha(m['sha256']); total += m['size']
            by_name[r] = m
            count += 1
        require('.' in by_name and 'names' in by_name['.'], 'root directory')
        actual_children = {r: [] for r, m in by_name.items() if 'names' in m}
        for r in by_name:
            if r == '.':
                continue
            parent, _, leaf = r.rpartition('/')
            require((parent or '.') in actual_children, 'missing directory')
            actual_children[parent or '.'].append(leaf)
        for r, children in actual_children.items():
            require(sorted(children) == by_name[r]['names'], 'incomplete directory roster')
        require([m['relative'] for m in entries] == sorted(by_name, key=lambda r: r.split('/')),
                'canonical depth-first roster')
    require(count <= 2048 and total <= 67108864, 'forest bound')
    live = {m['relative']: m for m in snapshot['roots'][PREFIX] or []}
    require(set(live) == {'.', BUILD, *(BUILD + '/' + n for n in ARTIFACTS)}, 'kit03 roster')
    for r in ('.', BUILD):
        require(live[r]['mode'] == 0o40755 and live[r]['uid'] == live[r]['gid'] == 0, 'kit directory')
    for name, (size, digest) in ARTIFACTS.items():
        m = live[BUILD + '/' + name]
        require(m['mode'] == 0o100555 and m['uid'] == m['gid'] == 0 and
                m['size'] == size and m['sha256'] == digest, 'kit payload')
    # Preserve failed old checkpoints as observed, but admit only the completed
    # packet04 byte contract for the installation being moved.
    nonce = NONCES[-1]
    stage = {m['relative']: m for m in snapshot['roots'][TMP + 'glue-bs-stage-' + nonce] or []}
    pins = completed_pins()
    require(all(m['uid'] == m['gid'] == 0 and m['mode'] ==
                (0o40700 if m['relative'] == '.' else 0o100500 if m['relative'] == 'root-stage.sh' else 0o100600)
                for m in stage.values()), 'private stage permissions')
    expected = {'root-stage.sh', 'installed'}
    for case in CASES:
        expected.update(case + '.' + role for role in ('started', 'request.bin', 'input.sha256',
            'native.stdout', 'native.stderr', 'native.status', 'closed'))
    expected.add('trailing.output.absent')
    require(set(stage) == {'.', *expected}, 'completed private stage roster')
    def pinned(m, size, sha256, mode=0o100600):
        require(m['uid'] == m['gid'] == 0 and m['mode'] == mode and m['links'] == 1 and
                m['size'] == size and m['sha256'] == sha256, 'completed bytes differ')
    def literal(name, value):
        b = value.encode(); pinned(stage[name], len(b), sha(b))
    pinned(stage['root-stage.sh'], **pins['root-stage.sh'], mode=0o100500)
    literal('installed', 'ea67cfba1dab8dc51c44e514ca6ff8a00f703e665cbc89c17f996b3e02f4efae\n')
    for case, status in zip(CASES, (0, 1, 1, 2)):
        literal(case + '.started', 'started\n')
        literal(case + '.native.status', str(status) + '\n')
        literal(case + '.closed', 'no-output\n' if case == 'trailing' else 'closed\n')
        pin = pins['evidence/requests/' + case + '.bin']
        pinned(stage[case + '.request.bin'], **pin)
        literal(case + '.input.sha256', pin['sha256'] + '\n')
        if case != 'trailing':
            entries = snapshot['roots'][TMP + 'glue-bs-' + nonce + '-' + case]
            require(entries is not None, 'completed native output absent')
            output = {m['relative']: m for m in entries}
            roles = ('request.bin', 'status.bin', 'probe.stdout', 'probe.stderr', 'result.json')
            require(set(output) == {'.', *roles}, 'completed native output roster')
            require(output['.']['mode'] == 0o40700 and output['.']['uid'] == output['.']['gid'] == 0,
                    'private native output')
            for role in roles:
                pinned(output[role], **pins[case + '/' + role])
    literal('trailing.output.absent', 'true\n')
    require(snapshot['roots'][TMP + 'glue-bs-' + nonce + '-trailing'] is None, 'trailing output exists')
    require(stage['.']['mode'] == 0o40700 and stage['.']['uid'] == stage['.']['gid'] == 0,
            'private completed stage')
    for stem, prefix in (('glue-bs-user-', 'evidence/'), ('glue-bs-launch-', 'launch/')):
        entries = snapshot['roots'][TMP + stem + nonce]
        require(entries is not None, 'completed ordinary checkpoint absent')
        entries = {m['relative']: m for m in entries}
        require(entries['.']['uid'] == 501 and entries['.']['gid'] == 20 and
                entries['.']['mode'] == 0o40700, 'private ordinary checkpoint')
        require(all(m['uid'] == 501 and m['gid'] == 20 and m['mode'] ==
                    (0o40700 if 'names' in m else 0o100600) for m in entries.values()),
                'ordinary checkpoint permissions')
        expected_files = {name[len(prefix):]: pin for name, pin in pins.items() if name.startswith(prefix)}
        for name, pin in expected_files.items():
            r = prefix + name if prefix == 'evidence/' else name
            require(r in entries, 'completed ordinary bytes absent')
            m = entries[r]
            require(m['uid'] == 501 and m['gid'] == 20 and m['mode'] == 0o100600 and
                    m['size'] == pin['size'] and m['sha256'] == pin['sha256'], 'completed ordinary bytes differ')
        subtree = {r for r, m in entries.items() if 'sha256' in m and
                   (prefix != 'evidence/' or r.startswith(prefix))}
        require(subtree == {(prefix + name if prefix == 'evidence/' else name) for name in expected_files},
                'completed ordinary byte roster')
    require(snapshot['roots'][ROOTS[1]] is not None, 'retained kit02 checkpoint absent')
    return snapshot


def root_program(mode):
    enabled(mode)
    a = inspection_approval()
    common = (HERE / 'inventory.pl').read_bytes()
    require(sha(common) == INVENTORY_SHA, 'reviewed inventory source differs')
    device = a['observation']['components'][3]['device']
    head = b'#!/usr/bin/perl\n' + common + b'\n'
    head += ('fail("arguments or root identity") if @ARGV || $< != 0 || $> != 0;\n' +
             'my $DATA_DEVICE = ' + str(device) + ';\n').encode()
    if mode == 'inspect':
        main = '''my $before = snapshot(0, $DATA_DEVICE);
verify_kit03($before);
my $signatures = signatures(0);
my $after = snapshot(0, $DATA_DEVICE);
fail('inspection changed') unless canonical($before) eq canonical($after);
report({schema=>'glue-kit03-physical-inspection-v1', snapshot=>$after,
    signatures=>$signatures, native_payload_executed=>JSON::PP::false,
    security_settings_changed=>JSON::PP::false, retained=>JSON::PP::false,
    tracing=>JSON::PP::false, exec_proved=>JSON::PP::false, full_acceptance=>JSON::PP::false});
'''
    else:
        p = primitives()
        p.exact_keys(APPROVED, ('inspection_approval', 'inspection_manifest_sha256',
            'inspection_review_manifest_sha256', 'coordination_receipt_sha256', 'snapshot'))
        require(APPROVED['inspection_approval'] == a, 'retention deployment differs')
        for k in ('inspection_manifest_sha256', 'inspection_review_manifest_sha256', 'coordination_receipt_sha256'):
            p.sha(APPROVED[k])
        validate_snapshot(APPROVED['snapshot'], device)
        data = canonical(APPROVED).decode().strip()
        # Canonical JSON has no apostrophes from accepted keys/paths/hex values.
        require("'" not in data, 'approval quoting')
        main = "my $approval = $JSON->decode('" + data + "');\n" + '''
fail('archive already exists') if status_of($ARCHIVE);
my $before = snapshot(0, $DATA_DEVICE);
verify_kit03($before);
fail('fresh physical state differs') unless canonical($before) eq canonical($approval->{snapshot});
my $before_signatures = signatures(0);
# A fixed, exclusive attempt marker prevents a later packet retry after any
# uncertain move. It is a new receipt, never an alteration of old evidence.
fail('retention already attempted') if status_of($ATTEMPT);
mkdir($ATTEMPT, 0700) or fail('exclusive attempt directory');
no_acl($ATTEMPT);
my $attempt_stat = status_of($ATTEMPT) // fail('attempt disappeared');
fail('attempt identity') unless $attempt_stat->[0] == $DATA_DEVICE && $attempt_stat->[2] == 040700 &&
    $attempt_stat->[4] == 0 && $attempt_stat->[5] == 0;
my $attempt_bytes = canonical({schema=>'glue-kit03-retention-attempt-v1',
    snapshot_sha256=>sha256_hex(canonical($before)), source=>$PREFIX, archive=>$ARCHIVE});
sysopen(my $attempt_file, "$ATTEMPT/attempt.json", O_WRONLY|O_CREAT|O_EXCL|O_NOFOLLOW, 0600)
    or fail('exclusive attempt record');
print $attempt_file $attempt_bytes or fail('attempt write');
close($attempt_file) or fail('attempt close');
# Protected stable parent and coordinated exclusion of concurrent fixture
# mutation are required. This is not a hostile-mutator containment primitive.
my @move = ('/bin/mv', '-n', $PREFIX, $ARCHIVE);
my $move_status = system {$move[0]} @move;
fail('uncertain rename status') unless $move_status == 0;
fail('source still exists') if status_of($PREFIX);
my $after = snapshot(1, $DATA_DEVICE);
verify_kit03($after);
fail('relocated tree or preserved checkpoint changed') unless canonical($before) eq canonical($after);
my $after_signatures = signatures(1);
report({schema=>'glue-kit03-retained-install-v1', source=>$PREFIX, archive=>$ARCHIVE,
    move_argv=>\\@move, move_raw_status=>$move_status, snapshot=>$after,
    attempt_path=>$ATTEMPT, attempt_record_sha256=>sha256_hex($attempt_bytes),
    before_signatures=>$before_signatures, after_signatures=>$after_signatures,
    native_payload_executed=>JSON::PP::false, security_settings_changed=>JSON::PP::false,
    retained=>JSON::PP::true, tracing=>JSON::PP::false, exec_proved=>JSON::PP::false,
    full_acceptance=>JSON::PP::false});
'''
    return head + main.encode()


def current_checks(observed):
    lines = []
    def walk(path, value):
        key = shlex.quote(path)
        if isinstance(value, dict):
            lines.append('typed_dictionary "$WORK/current.stdout" ' + key + ' || exit 2')
            for k, v in value.items():
                if k not in ('observed_unix_seconds', 'observed_nanoseconds'):
                    walk(path + '.' + k if path else k, v)
        elif isinstance(value, list):
            lines.append('typed ' + key + ' array ' + str(len(value)) + ' || exit 2')
            for i, v in enumerate(value):
                walk(path + '.' + str(i), v)
        else:
            kind = 'bool' if type(value) is bool else 'integer' if type(value) is int else 'string'
            expected = str(value).lower() if type(value) is bool else str(value)
            lines.append('typed ' + key + ' ' + kind + ' ' + shlex.quote(expected) + ' || exit 2')
    # The fixed inspector always emits this exact dictionary schema. Checking
    # every member preserves full FSIDs/ancestors rather than just stat device.
    for k, v in observed.items():
        if k not in ('observed_unix_seconds', 'observed_nanoseconds'):
            walk(k, v)
    return '\n'.join(lines)


def render(mode, nonce):
    enabled(mode)
    require(type(nonce) is str and re.fullmatch('[0-9a-f]{16}', nonce), 'fresh nonce')
    a = inspection_approval()
    root = root_program(mode)
    packet = '/Volumes/My Shared Files/glue-mvp-macos-vm-toolkit/kit03-' + mode + '-' + nonce
    work = TMP + 'glue-kit03-' + mode + '-' + nonce
    stage = TMP + 'glue-kit03-root-' + mode + '-' + nonce
    export = '/Volumes/My Shared Files/glue-mvp-macos-vm-results/glue-kit03-' + mode + '-' + nonce
    q = shlex.quote
    guard = lambda s: s + ' || exit 2; '
    code = 'set -eu; umask 077; set -C; '
    code += guard('[ "$(/usr/bin/id -ru)" = 0 ]') + guard('[ "$(/usr/bin/id -u)" = 0 ]')
    code += guard('[ -d ' + q(TMP[:-1]) + ' ] && [ ! -L ' + q(TMP[:-1]) + ' ]')
    code += guard('[ "$(/usr/bin/stat -f %u:%g:%p:%d ' + q(TMP[:-1]) + ')" = ' +
                  q('0:0:41777:' + str(a['observation']['components'][3]['device'])) + ' ]')
    code += guard('[ ! -e ' + q(stage) + ' ] && [ ! -L ' + q(stage) + ' ]')
    code += '/bin/mkdir -m 0700 ' + q(stage) + '; /bin/chmod -N ' + q(stage) + '; '
    code += guard('[ -f ' + q(packet + '/root.pl') + ' ] && [ ! -L ' + q(packet + '/root.pl') + ' ]')
    code += '/usr/bin/head -c ' + str(len(root)+1) + ' ' + q(packet + '/root.pl') + ' > ' + q(stage + '/root.pl') + '; '
    code += guard('[ "$(/usr/bin/stat -f %z ' + q(stage + '/root.pl') + ')" = ' + str(len(root)) + ' ]')
    code += '/bin/chmod -N ' + q(stage + '/root.pl') + '; /bin/chmod 0500 ' + q(stage + '/root.pl') + '; '
    code += guard('[ "$(/usr/bin/stat -f %u:%g:%p:%l ' + q(stage + '/root.pl') + ')" = 0:0:100500:1 ]')
    code += guard('[ "$(/usr/bin/shasum -a 256 ' + q(stage + '/root.pl') + ')" = ' + q(sha(root) + '  ' + stage + '/root.pl') + ' ]')
    code += 'exec /usr/bin/perl ' + q(stage + '/root.pl')
    argv = ['/usr/bin/sudo', '-n', '/usr/bin/env', '-i', 'PATH=/usr/bin:/bin:/usr/sbin:/sbin',
            'LC_ALL=C', 'TZ=UTC', '/bin/sh', '-c', code]
    values = {'WORK': q(work), 'PACKET': q(packet), 'EXPORT': q(export),
        'INSPECTOR': q(INSPECTOR), 'INSPECTOR_SHA': q(INSPECTOR_SHA),
        'PHASE': ' '.join(q(x) for x in argv), 'CURRENT_CHECKS': current_checks(a['observation'])}
    launch = (HERE / 'launch.sh.in').read_text()
    for k, v in values.items():
        launch = launch.replace('@@' + k + '@@', v)
    require(not re.search('@@[A-Z_]+@@', launch), 'unfilled template')
    plan = {'schema': 'glue-kit03-preservation-plan-v1', 'operation': mode,
        'inspection_approval': a, 'retention_approval': APPROVED if mode == 'retain' else None,
        'guest_packet': packet, 'guest_work': work, 'root_stage': stage, 'guest_export': export,
        'root_phase_argv': argv, 'root_sha256': sha(root), 'root_size': len(root),
        'source_sha256': {'inventory.pl': INVENTORY_SHA, 'completed-files.json': COMPLETED_SHA,
                          'host_parser': CORE_SHA},
        'roots': list(ROOTS), 'archive': ARCHIVE, 'interpreter': '/usr/bin/perl',
        'core_modules': ['Digest::SHA', 'JSON::PP', 'Fcntl', 'Errno'],
        'exclusive_fixture_slot_required': True, 'atomic_hostile_mutator_exclusion_claimed': False,
        'native_payload_executed': False, 'security_settings_changed': False,
        'tracing': False, 'exec_proved': False, 'full_acceptance': False}
    return {'root.pl': root, 'launch.sh': launch.encode(), 'plan.json': canonical(plan)}


def prepare(mode, output):
    enabled(mode)  # Before path resolution, reads, helper imports or writes.
    files = render(mode, secrets.token_hex(8))
    require(output.is_absolute() and not output.exists() and not output.is_symlink(), 'fresh absolute output')
    output.mkdir(mode=0o700)
    for name, data in files.items():
        with (output / name).open('xb') as f:
            f.write(data)
        (output / name).chmod(0o444)
    index = ''.join(sha(data) + '  ' + name + '\n' for name, data in sorted(files.items())).encode()
    with (output / 'SHA256SUMS').open('xb') as f:
        f.write(index)
    (output / 'SHA256SUMS').chmod(0o444)
    return {'packet': str(output), 'manifest_sha256': sha(index), 'operation': mode,
            'prepared_only': True, 'staged': False, 'retained': False, 'full_acceptance': False}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('operation', choices=('inspect', 'retain'))
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    try:
        print(json.dumps(prepare(args.operation, args.output), sort_keys=True))
    except (ValueError, OSError) as exc:
        print(str(exc), file=sys.stderr)
        return 2
    return 0


if __name__ == '__main__':
    sys.exit(main())
