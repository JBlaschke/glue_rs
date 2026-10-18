#!/usr/bin/env python3
"""Contract-boundary controls; no guest/root/native payload is executed."""
import copy
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

HERE = Path(__file__).resolve().parent
spec = importlib.util.spec_from_file_location('kit03_prepare', HERE / 'prepare.py')
p = importlib.util.module_from_spec(spec)
spec.loader.exec_module(p)


def unconfigured_module():
    """Private module copy; production approval/gates are never changed."""
    fixture = json.loads((HERE / 'unconfigured-inputs.fixture.json').read_bytes())
    spec = importlib.util.spec_from_file_location('kit03_unconfigured_fixture', HERE / 'prepare.py')
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    assert set(fixture) == {'APPROVED', 'RETENTION_ENABLED'}
    for key, value in fixture.items():
        setattr(module, key, value)
    return module


def actual_baseline():
    # Independent exact snapshot fixture, copied from the read-only phase
    # receipt rather than constructed by the approval loader or validator.
    data = (HERE / 'actual-snapshot.fixture.json').read_bytes()
    assert hashlib.sha256(data).hexdigest() == '18e3a2d7d69cb1a25affab756329d7dab396d48e51275fa032da4ca62e5f0346'
    return json.loads(data)


def tree(files, uid=0, gid=0, mode=0o40700):
    rows = {'.': {'names': [], 'mode': mode}}
    for path, (size, digest, file_mode) in files.items():
        parts = path.split('/')
        for i in range(1, len(parts)):
            rows.setdefault('/'.join(parts[:i]), {'names': [], 'mode': mode})
        rows[path] = {'size': size, 'sha256': digest, 'mode': file_mode}
    for path in rows:
        if path == '.':
            continue
        parent, _, leaf = path.rpartition('/')
        rows[parent or '.']['names'].append(leaf)
    result = []
    for i, (path, row) in enumerate(sorted(rows.items(), key=lambda pair: pair[0].split('/'))):
        row = dict(row)
        if 'names' in row:
            row['names'] = sorted(row['names'])
        result.append({'relative': path, 'device': 16777234, 'inode': 1000+i, 'uid': uid,
                       'gid': gid, 'links': 1, 'size': 64, **row})
    return result


def literal(value):
    b = value.encode()
    return len(b), p.sha(b), 0o100600


def baseline():
    d = 16777234
    snapshot = {'parents': {path: {'device': d, 'inode': i+1, 'uid': 0, 'gid': 0,
        'mode': 0o41777 if path == p.TMP[:-1] else 0o40755} for i, path in enumerate(p.PARENTS)},
        'roots': dict.fromkeys(p.ROOTS)}
    roots = snapshot['roots']
    roots[p.PREFIX] = tree({p.BUILD+'/'+name: (size, digest, 0o100555)
                           for name, (size, digest) in p.ARTIFACTS.items()}, mode=0o40755)
    roots[p.ROOTS[1]] = tree({}, mode=0o40755)
    nonce = p.NONCES[-1]
    pins = p.completed_pins()
    stage = {'root-stage.sh': (pins['root-stage.sh']['size'], pins['root-stage.sh']['sha256'], 0o100500),
             'installed': literal('ea67cfba1dab8dc51c44e514ca6ff8a00f703e665cbc89c17f996b3e02f4efae\n')}
    for case, status in zip(p.CASES, (0, 1, 1, 2)):
        stage[case+'.started'] = literal('started\n')
        stage[case+'.native.status'] = literal(str(status)+'\n')
        stage[case+'.native.stdout'] = literal('')
        stage[case+'.native.stderr'] = literal('')
        stage[case+'.closed'] = literal('no-output\n' if case == 'trailing' else 'closed\n')
        pin = pins['evidence/requests/'+case+'.bin']
        stage[case+'.request.bin'] = (pin['size'], pin['sha256'], 0o100600)
        stage[case+'.input.sha256'] = literal(pin['sha256']+'\n')
        if case != 'trailing':
            roots[p.TMP+'glue-bs-'+nonce+'-'+case] = tree({name: (pins[case+'/'+name]['size'],
                pins[case+'/'+name]['sha256'], 0o100600) for name in (
                'request.bin', 'status.bin', 'probe.stdout', 'probe.stderr', 'result.json')})
    stage['trailing.output.absent'] = literal('true\n')
    roots[p.TMP+'glue-bs-stage-'+nonce] = tree(stage)
    for stem, prefix in (('glue-bs-user-', 'evidence/'), ('glue-bs-launch-', 'launch/')):
        files = {(name if prefix == 'evidence/' else name[len(prefix):]):
                 (pin['size'], pin['sha256'], 0o100600) for name, pin in pins.items() if name.startswith(prefix)}
        roots[p.TMP+stem+nonce] = tree(files, uid=501, gid=20)
    return snapshot


class PreparationTests(unittest.TestCase):
    def test_current_inspection_renders_only_fixed_read_only_operation(self):
        files = p.render('inspect', '0123456789abcdef')
        plan = json.loads(files['plan.json'])
        self.assertEqual(set(files), {'root.pl', 'launch.sh', 'plan.json'})
        self.assertEqual(plan['roots'], list(p.ROOTS))
        self.assertIsNone(plan['retention_approval'])
        self.assertNotIn(b'/bin/mv', files['root.pl'])
        self.assertNotIn(b'/bin/chmod', files['root.pl'])
        self.assertNotIn(b'/bin/chown', files['root.pl'])
        self.assertIn(b'proof_manifest_sha256', files['plan.json'])
        self.assertIn(b'16777234', files['launch.sh'])
        self.assertIn(b'components.0.fsid.1 integer 26', files['launch.sh'])
        self.assertLess(files['launch.sh'].index(b'components.4.filesystem'),
                        files['launch.sh'].index(b'/usr/bin/sudo -v'))

    def test_unconfigured_fixture_retention_refuses_before_io(self):
        fixture = unconfigured_module()
        with patch.object(Path, 'read_bytes', side_effect=AssertionError('I/O before guard')):
            with self.assertRaisesRegex(ValueError, 'retention approval'):
                fixture.prepare('retain', Path('/not-created'))
        fixture.INSPECTION_APPROVAL = None
        with patch.object(Path, 'read_bytes', side_effect=AssertionError):
            with self.assertRaisesRegex(ValueError, 'fresh inspection approval'):
                fixture.prepare('inspect', Path('/not-created'))

    def test_actual_profile_accepts_exact_inspection_and_rejects_each_changed_root(self):
        original = actual_baseline()
        self.assertIs(p.validate_actual_snapshot(original, 16777234), original)
        self.assertEqual((len(original['parents']), len(original['roots'])), (7, 32))
        self.assertEqual(sum(x is None for x in original['roots'].values()), 30)
        self.assertEqual([len(original['roots'][r]) for r in p.ROOTS[:2]], [5, 5])
        # The complete checkpoint contract and actual observed-absence contract
        # have distinct positive baselines and refuse one another.
        with self.assertRaises(ValueError):
            p.validate_snapshot(original, 16777234)
        with self.assertRaises(ValueError):
            p.validate_actual_snapshot(baseline(), 16777234)
        for root in p.ROOTS[2:]:
            changed = copy.deepcopy(original)
            changed['roots'][root] = tree({})
            with self.subTest(root=root), self.assertRaisesRegex(ValueError, 'temporary root'):
                p.validate_actual_snapshot(changed, 16777234)
        mutations = []
        changed = copy.deepcopy(original); changed['roots'][p.ROOTS[1]] = None; mutations.append(changed)
        changed = copy.deepcopy(original); changed['roots'][p.ROOTS[1]].pop(); mutations.append(changed)
        changed = copy.deepcopy(original); changed['roots']['/unreviewed'] = None; mutations.append(changed)
        for root in p.ROOTS[:2]:
            for field, value in (('device', 1), ('inode', True), ('inode', 999), ('uid', 501),
                                 ('gid', 20), ('mode', 0o104555), ('links', 2), ('sha256', '0'*64),
                                 ('size', 42)):
                changed = copy.deepcopy(original); changed['roots'][root][2][field] = value
                mutations.append(changed)
        for parent in p.PARENTS:
            for field, value in (('device', 1), ('inode', 999), ('uid', True), ('gid', 20), ('mode', 0o44755)):
                changed = copy.deepcopy(original); changed['parents'][parent][field] = value
                mutations.append(changed)
        for i, changed in enumerate(mutations):
            with self.subTest(i=i), self.assertRaises(ValueError):
                p.validate_actual_snapshot(changed, 16777234)

    def test_literal_approval_historical_and_coordination_bindings(self):
        a = p.retention_approval()
        self.assertEqual(a['snapshot'], actual_baseline())
        self.assertEqual(a['inspection_manifest_sha256'], '563731431c81c3ee0790f5451cfad108bacd3b09f1a0c54667615659f0d03724')
        self.assertEqual(a['inspection_review']['manifest_sha256'], 'bd56990e6ddc6a067b52d780c2706d96d1e275425f129737108ac499ff2869d1')
        self.assertEqual(a['coordination']['receipt_sha256'], '39b44c8b675d9b3429c0ed899a33de2af618d7831bde10c4f3e1b03fd2e09012')
        self.assertEqual(a['coordination']['manifest_sha256'], '5257549ebf1eb5f803b503861530f02883eb7e78badafa211cb043993aa8a397')
        expected = {
            'historical_kit03': 'ea67cfba1dab8dc51c44e514ca6ff8a00f703e665cbc89c17f996b3e02f4efae',
            'historical_packet04': '3464a9b713df68fe0b58a6f1a47a950af6158baae961ca067f2f626b252d661a',
            'historical_batch': 'b2654ce96a03860c41a17b26effd411f0da1b6955dd99c43237b8b8eef739cfb',
            'historical_outer': 'c688fdcb146e49bcb6450460b6edd9dc0ee3bc89879f30a50bc401c551cf8029',
            'historical_review': 'c0fb82f1237f50e235a9991784f641b71c3dc1df35578a46d9d62f08e1ea4962'}
        self.assertEqual({k: v['manifest_sha256'] for k, v in a['historical_host'].items()}, expected)
        originals = [a]
        for key in ('inspection_manifest_sha256', 'snapshot_sha256', 'profile', 'attempt_path'):
            changed = copy.deepcopy(a); changed[key] = 'unreviewed'; originals.append(changed)
        for key, field in (('coordination', 'receipt_sha256'), ('coordination', 'manifest_sha256'),
                           ('inspection_review', 'manifest_sha256')):
            changed = copy.deepcopy(a); changed[key][field] = '0'*64; originals.append(changed)
        for name in expected:
            changed = copy.deepcopy(a); changed['historical_host'][name]['manifest_sha256'] = '0'*64
            originals.append(changed)
        read_bytes = Path.read_bytes
        for i, changed in enumerate(originals):
            # Even equivalent whitespace is a changed source approval file.
            data = json.dumps(changed, indent=2).encode()
            def read(path):
                return data if path == HERE / 'actual-retention-approval.json' else read_bytes(path)
            with self.subTest(i=i), patch.object(Path, 'read_bytes', read), self.assertRaisesRegex(ValueError, 'literal retention approval'):
                p.retention_approval()

    def test_closed_cli_rejects_overrides_before_output(self):
        with tempfile.TemporaryDirectory() as td:
            output = Path(td) / 'must-not-exist'
            for flag in ('--approval', '--profile', '--snapshot', '--source', '--archive',
                         '--attempt', '--coordination', '--enable'):
                done = subprocess.run([sys.executable, str(HERE/'prepare.py'), 'retain',
                    '--output', str(output), flag, 'unreviewed'], capture_output=True, timeout=5)
                self.assertEqual(done.returncode, 2, done.stderr)
                self.assertEqual(done.stdout, b'')
                self.assertFalse(output.exists())

    def test_complete_synthetic_state_and_contract_mutations(self):
        original = baseline()
        self.assertIs(p.validate_snapshot(original, 16777234), original)
        mutations = []
        changed = copy.deepcopy(original); changed['parents'][p.PARENTS[4]]['mode'] = 0o40777; mutations.append(changed)
        changed = copy.deepcopy(original); changed['roots']['/unreviewed'] = None; mutations.append(changed)
        changed = copy.deepcopy(original); changed['roots'][p.PREFIX][2]['links'] = 2; mutations.append(changed)
        changed = copy.deepcopy(original); changed['roots'][p.PREFIX][2]['device'] = 1; mutations.append(changed)
        changed = copy.deepcopy(original); changed['roots'][p.PREFIX][2]['inode'] = True; mutations.append(changed)
        changed = copy.deepcopy(original); changed['roots'][p.PREFIX][2]['sha256'] = '0'*64; mutations.append(changed)
        changed = copy.deepcopy(original); changed['roots'][p.TMP+'glue-bs-stage-'+p.NONCES[-1]] = None; mutations.append(changed)
        changed = copy.deepcopy(original); changed['roots'][p.TMP+'glue-bs-'+p.NONCES[-1]+'-trailing'] = tree({}); mutations.append(changed)
        changed = copy.deepcopy(original); changed['roots'][p.TMP+'glue-bs-'+p.NONCES[-1]+'-positive'][1]['sha256'] = '0'*64; mutations.append(changed)
        changed = copy.deepcopy(original); changed['roots'][p.TMP+'glue-bs-user-'+p.NONCES[-1]] = None; mutations.append(changed)
        changed = copy.deepcopy(original); changed['roots'][p.TMP+'glue-bs-launch-'+p.NONCES[-1]][1]['size'] += 1; mutations.append(changed)
        changed = copy.deepcopy(original); changed['roots'][p.ROOTS[1]] = None; mutations.append(changed)
        for i, changed in enumerate(mutations):
            with self.subTest(i=i), self.assertRaises(ValueError):
                p.validate_snapshot(changed, 16777234)

    def test_prepared_packet_is_fresh_and_inventory_exact(self):
        with tempfile.TemporaryDirectory() as td:
            out = Path(td) / 'packet'
            result = p.prepare('inspect', out)
            index = (out/'SHA256SUMS').read_bytes()
            self.assertEqual(p.sha(index), result['manifest_sha256'])
            members = {}
            for line in index.decode().splitlines():
                digest, name = line.split('  ', 1)
                self.assertEqual(p.sha((out/name).read_bytes()), digest)
                members[name] = digest
            self.assertEqual(set(members), {'root.pl', 'launch.sh', 'plan.json'})
            with self.assertRaisesRegex(ValueError, 'fresh absolute'):
                p.prepare('inspect', out)

    def rendered_programs(self):
        return {mode: p.render(mode, '0123456789abcdef') for mode in ('inspect', 'retain')}

    def test_inspection_rendering_unchanged_from_actual_inspection_source(self):
        expected = {'root.pl': '43fc1e43eea4d265d27054e93217a6d09809b2689143fbc7597f64da844e6fd7',
                    'launch.sh': '000379fb15146670b18bb3384148977da495419c43e3373475f1e7a06a70428d',
                    'plan.json': '13144d288ed6ccd061f44aa03b24cf88e45063532c2f2a212389026bbe90181b'}
        self.assertEqual({n: p.sha(b) for n, b in p.render('inspect', '0123456789abcdef').items()}, expected)

    def test_durable_attempt_and_single_move_ordering(self):
        files = p.render('retain', '0123456789abcdef')
        plan = json.loads(files['plan.json'])
        source = files['root.pl']
        marker = b"$ATTEMPT = '/System/Volumes/Data/Library/GlueMVPFixtures-retain-attempt-1b85f0ac-da1aaf9a';"
        ordered = [marker, b"fail('archive already exists')", b"fail('retention already attempted')",
            b'my $before = snapshot(0', b"fail('fresh physical state differs')", b'my $before_signatures = signatures(0)',
            b"mkdir($ATTEMPT, 0700)", b"no_acl($ATTEMPT)", b"fail('attempt identity')", b'sysopen(my $attempt_file,',
            b"close($attempt_file) or fail('attempt close')", b"my @move = ('/bin/mv', '-n', $PREFIX, $ARCHIVE)",
            b"fail('uncertain rename status')", b"fail('source still exists')", b'my $after = snapshot(1',
            b"fail('relocated tree or preserved checkpoint changed')", b'my $after_signatures = signatures(1)',
            b"report({schema=>'glue-kit03-retained-install-v1'"]
        positions = [source.index(x) for x in ordered]
        self.assertEqual(positions, sorted(positions))
        self.assertEqual(source.count(b"'/bin/mv'"), 1)
        self.assertIn(b'O_WRONLY|O_CREAT|O_EXCL|O_NOFOLLOW, 0600', source)
        self.assertEqual(source.count(b'$ATTEMPT = '), 2)  # old unused common value, then durable override
        self.assertEqual(plan['attempt_path'], p.ATTEMPT)
        self.assertEqual(plan['retention_approval'], p.retention_approval())
        self.assertEqual(plan['source_sha256']['actual-retention-approval.json'], p.ACTUAL_APPROVAL_SHA)
        for command in (b'/bin/rm', b'/bin/chown', b'/bin/chmod'):
            self.assertNotIn(command, source)

    def test_retain_checked_command_outputs_preserve_failure_status(self):
        # Run only the pure checked-output helper against harmless text stubs.
        # Expected bytes from a failed operation must never authorize mutation.
        for stub, success in (("printf '%s' expected", True),
                              ("printf '%s' expected; exit 7", False),
                              ("printf '%s' wrong", False),
                              ("exit 7", False)):
            done = subprocess.run(['/bin/sh', '-c', p.CHECKED_EQUAL +
                '\nchecked_equal expected /bin/sh -c "$1" || exit 2\n', 'control', stub],
                capture_output=True, timeout=5)
            self.assertEqual(done.returncode, 0 if success else 2, done.stderr)
            self.assertEqual((done.stdout, done.stderr), (b'', b''))
        files = p.render('retain', '0123456789abcdef')
        launch = files['launch.sh'].decode()
        plan = json.loads(files['plan.json'])
        bootstrap = plan['root_phase_argv'][-1]
        self.assertNotIn('[ "$(' , launch)
        self.assertNotIn('[ "$(' , bootstrap)
        for command in ('/usr/bin/id -ru', '/usr/bin/id -u', '/usr/sbin/sysctl -n hw.model',
                        '/usr/bin/sw_vers -productVersion', '/usr/bin/sw_vers -buildVersion',
                        '/usr/bin/uname -mrs', '/usr/bin/csrutil status'):
            line = next(line for line in launch.splitlines() if command in line)
            self.assertIn('checked_equal ', line)
        self.assertEqual(bootstrap.count('checked_equal '), 6)
        with self.assertRaisesRegex(ValueError, 'reviewed launcher source'):
            p.retain_launcher((HERE/'launch.sh.in').read_text() + '\n')

    def test_extracted_read_only_marker_guard_refuses_any_existing_entry(self):
        common = (HERE/'inventory.pl').read_text()
        status = common[common.index('sub status_of {'):common.index('# Perl stat timestamps')]
        root = p.root_program('retain').decode()
        start = root.index("fail('archive already exists')")
        checks = root[start:root.index('my $before = snapshot(0', start)]
        self.assertNotIn('mkdir', checks)
        self.assertNotIn('system', checks)
        self.assertNotIn('/bin/mv', checks)
        # Execute only two extracted read-only existence guards and status_of,
        # never a generated phase/root main or any mutation/guest command.
        source = 'use strict; use warnings; use Errno qw(ENOENT); sub fail {die $_[0]}\n' + status
        source += 'my ($ARCHIVE,$ATTEMPT)=@ARGV;\n' + checks + 'print "ready\\n";\n'
        with tempfile.TemporaryDirectory() as td:
            archive, attempt = Path(td)/'archive', Path(td)/'attempt'
            def check(expected):
                done = subprocess.run(['/usr/bin/perl', '-e', source, str(archive), str(attempt)],
                                      capture_output=True, timeout=5)
                self.assertEqual(done.returncode == 0, expected, done.stderr)
                self.assertEqual(done.stdout, b'ready\n' if expected else b'')
            check(True)
            attempt.mkdir(); check(False); attempt.rmdir()
            attempt.write_bytes(b'partial'); check(False); attempt.unlink()
            attempt.symlink_to(Path(td)/'absent'); check(False); attempt.unlink()
            os.mkfifo(attempt, 0o600); check(False); attempt.unlink()
            archive.mkdir(); check(False)

    def test_both_shell_programs_parse_without_running_them(self):
        for mode, files in self.rendered_programs().items():
            done = subprocess.run(['/bin/sh', '-n'], input=files['launch.sh'], capture_output=True)
            self.assertEqual(done.returncode, 0, done.stderr)
            if mode == 'retain':
                self.assertEqual(files['root.pl'].count(b"'/bin/mv'"), 1)
                self.assertIn(b'fresh physical state differs', files['root.pl'])
                self.assertIn(b'source still exists', files['root.pl'])
                self.assertNotIn(b'/bin/chmod', files['root.pl'])
                self.assertNotIn(b'/bin/chown', files['root.pl'])
                self.assertNotIn(b'/bin/rm', files['root.pl'])

    def test_both_perl_programs_compile_without_running_them(self):
        env = {'PATH': '/usr/bin:/bin', 'LC_ALL': 'C', 'TZ': 'UTC'}
        missing = []
        for module in ('Digest::SHA', 'JSON::PP', 'Fcntl', 'Errno'):
            probe = subprocess.run(['/usr/bin/perl', '-M' + module, '-e', 'exit 0'],
                                   capture_output=True, timeout=5, env=env)
            if probe.returncode == 0:
                self.assertEqual((probe.stdout, probe.stderr), (b'', b''))
                continue
            expected = ("Can't locate " + module.replace('::', '/') + '.pm in @INC').encode()
            if probe.returncode == 2 and probe.stdout == b'' and probe.stderr.startswith(expected):
                missing.append(module)
            else:
                self.fail('unexpected system Perl dependency probe failure: ' +
                          repr((module, probe.returncode, probe.stdout, probe.stderr)))
        if missing:
            self.skipTest('system Perl modules unavailable: ' + ', '.join(missing))
        for files in self.rendered_programs().values():
            done = subprocess.run(['/usr/bin/perl', '-c'], input=files['root.pl'],
                                  capture_output=True, timeout=5, env=env)
            self.assertEqual(done.returncode, 0, done.stderr)


@unittest.skipUnless(__import__('sys').platform == 'darwin',
                     'native macOS owned-file policy')
class PhysicalBoundaryTests(unittest.TestCase):
    def invoke(self, root, race_fifo=False):
        common = (HERE/'inventory.pl').read_bytes()
        # Adapt only this unit fixture's owner to the host account; production
        # roots and the guest-only 0/501 ownership policy remain unchanged.
        common = common.replace(b'($s->[4] == 0 || $s->[4] == 501)',
                                ('($s->[4] == 0 || $s->[4] == '+str(os.getuid())+')').encode())
        if race_fifo:
            common = common.replace(b'        sysopen(my $file, $path,',
                b'        unlink($path) or die; require POSIX; POSIX::mkfifo($path,0600) == 0 or die;\n        sysopen(my $file, $path,')
        source = common + b'\n($entry_count,$byte_count)=(0,0); $entry_device=(lstat($ARGV[0]))[0]; my @rows; entry($ARGV[0],".",0,\\@rows); print canonical(\\@rows);\n'
        return subprocess.run(['/usr/bin/perl', '-e', source.decode(), str(root)], capture_output=True, timeout=5)

    def test_closed_regular_bytes_and_missing_are_distinct(self):
        with tempfile.TemporaryDirectory() as td:
            root = Path(td); os.chmod(root, 0o700)
            (root/'closed').write_bytes(b'owned fixture\n'); os.chmod(root/'closed', 0o600)
            done = self.invoke(root)
            self.assertEqual(done.returncode, 0, done.stderr)
            rows = json.loads(done.stdout)
            self.assertEqual(rows[1]['sha256'], hashlib.sha256(b'owned fixture\n').hexdigest())
            self.assertNotEqual(self.invoke(root/'missing').returncode, 0)

    def test_raced_fifo_open_is_nonblocking_and_refuses(self):
        with tempfile.TemporaryDirectory() as td:
            root = Path(td); os.chmod(root, 0o700)
            (root/'file').write_bytes(b'x'); os.chmod(root/'file', 0o600)
            done = self.invoke(root, race_fifo=True)
            self.assertNotEqual(done.returncode, 0)
            self.assertIn(b'entry changed', done.stderr)

    @unittest.skipIf(os.geteuid() == 0, 'permission refusal requires ordinary account')
    def test_permission_error_is_not_absence(self):
        with tempfile.TemporaryDirectory() as td:
            root = Path(td); (root/'closed').write_bytes(b'x')
            os.chmod(root, 0)
            try:
                done = self.invoke(root/'closed')
                self.assertNotEqual(done.returncode, 0)
                self.assertIn(b'lstat failed', done.stderr)
            finally:
                os.chmod(root, 0o700)

    def test_symlink_hardlink_special_and_oversize_refuse(self):
        with tempfile.TemporaryDirectory() as td:
            root = Path(td); os.chmod(root, 0o700)
            file = root/'file'; file.write_bytes(b'x'); os.chmod(file, 0o600)
            link = root/'link'; link.symlink_to(file)
            self.assertNotEqual(self.invoke(root).returncode, 0); link.unlink()
            os.link(file, link)
            self.assertNotEqual(self.invoke(root).returncode, 0); link.unlink()
            os.mkfifo(link, 0o600)
            self.assertNotEqual(self.invoke(root).returncode, 0); link.unlink()
            with file.open('r+b') as f: f.truncate(4194305)
            self.assertNotEqual(self.invoke(root).returncode, 0)


if __name__ == '__main__':
    unittest.main()
