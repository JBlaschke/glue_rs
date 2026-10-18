#!/usr/bin/env python3
"""Contract-boundary controls; no guest/root/native payload is executed."""
import copy
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import subprocess
import tempfile
import unittest
from unittest.mock import patch

HERE = Path(__file__).resolve().parent
spec = importlib.util.spec_from_file_location('kit03_prepare', HERE / 'prepare.py')
p = importlib.util.module_from_spec(spec)
spec.loader.exec_module(p)


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

    def test_disabled_retention_refuses_before_io(self):
        with patch.object(Path, 'read_bytes', side_effect=AssertionError('I/O before guard')):
            with self.assertRaisesRegex(ValueError, 'retention approval'):
                p.prepare('retain', Path('/not-created'))
        with patch.object(p, 'INSPECTION_APPROVAL', None), patch.object(Path, 'read_bytes', side_effect=AssertionError):
            with self.assertRaisesRegex(ValueError, 'fresh inspection approval'):
                p.prepare('inspect', Path('/not-created'))

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
        approved = {'inspection_approval': p.INSPECTION_APPROVAL,
            'inspection_manifest_sha256': '1'*64, 'inspection_review_manifest_sha256': '2'*64,
            'coordination_receipt_sha256': '3'*64, 'snapshot': baseline()}
        with patch.object(p, 'APPROVED', approved), patch.object(p, 'RETENTION_ENABLED', True):
            return {mode: p.render(mode, '0123456789abcdef') for mode in ('inspect', 'retain')}

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
