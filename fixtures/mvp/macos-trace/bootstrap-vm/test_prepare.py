import copy
import hashlib
import importlib.util
import os
from pathlib import Path
import re
import shlex
import stat
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

HERE = Path(__file__).resolve().parent
spec = importlib.util.spec_from_file_location('vm_prepare', HERE / 'prepare.py')
vm = importlib.util.module_from_spec(spec)
spec.loader.exec_module(vm)


def observation():
    components = []
    for i, name in enumerate(('/', 'System', 'Volumes', 'Data', 'Library')):
        data = i >= 3
        components.append({'name': name, 'device': 16777230, 'inode': i+1, 'uid': 0, 'gid': 0,
                           'mode': stat.S_IFDIR | 0o755, 'fsid': [16777230 if data else 16777236, 26],
                           'mount_flags': 0, 'mount_policy': 1 if data else 3, 'mount_owner': 0,
                           'descriptor_flags': 1, 'status_flags': 0, 'mountpoint': '/System/Volumes/Data' if data else '/',
                           'filesystem': 'apfs', 'filesec_population': 7, 'acl_present': 0})
    return {'schema': 'glue-bootstrap-deployment-observation-v1', 'model': 'VirtualMac2,1', 'kernel_release': '25.6.0',
            'observed_unix_seconds': 1, 'observed_nanoseconds': 0, 'ids': [501, 501, 20, 20], 'groups': [20, 12, 0],
            'tc_compatible': True, 'components': components, 'settings_changed': False, 'executable_admission': False, 'full_acceptance': False}


def fixture():
    binaries = {n: b'not-an-executable synthetic host-output fixture: ' + n.encode() for n in vm.PROGRAMS}
    result = {'build_id': vm.APPROVED['build_id'], 'catalog_sha256': vm.APPROVED['catalog_sha256'],
              'artifacts': {n: {'sha256': vm.sha(b), 'size': len(b)} for n, b in binaries.items()}}
    data = {'kit/' + n: b for n, b in binaries.items()}
    for original in vm.METADATA.values():
        if original != 'SHA256SUMS':
            data[original] = b'synthetic detached metadata; never a reviewed kit\n'
    return data, b'synthetic original inventory\n', result, observation()


def mode_helpers():
    # Only the two read-only predicates, never a generated root phase.
    template = (HERE / 'root-stage.sh.in').read_text()
    return '\n'.join(re.search(r'^' + name + r'\(\) \{\n.*?^\}', template,
                               re.M | re.S).group() for name in ('directory', 'regular'))


def inline_mode_predicates():
    _, _, result, observed = fixture()
    outer = vm.render(vm.make_plan(result, observed, '0123456789abcdef'))['outer.sh'].decode()
    predicates = []
    for line in outer.splitlines():
        if '/bin/sh -c ' not in line:
            continue
        shim = shlex.split(line.split('/bin/sh -c ', 1)[1])[0]
        for match in re.finditer(r'\[ "\$\((/usr/bin/stat -f ([^)]*))\)" = ([^ ]+) \]', shim):
            fmt = shlex.split(match[2])[0]
            if fmt.startswith('%u:'):
                predicates.append((match.group(), fmt, match[3]))
    return predicates


# Model BSD stat's documented formats rather than assuming every format returns
# the same value. Thus the old %Lp predicates fail these behavior controls.
MODE_STAT = '''mode_stat() {
    case "$2" in
        %u:%p) printf '%s:%s\\n' "$MODEL_UID" "$MODEL_FULL" ;;
        %u:%p:%l) printf '%s:%s:%s\\n' "$MODEL_UID" "$MODEL_FULL" "$MODEL_LINKS" ;;
        %u:%Lp) printf '%s:%s\\n' "$MODEL_UID" "$MODEL_LOW" ;;
        %u:%Lp:%l) printf '%s:%s:%s\\n' "$MODEL_UID" "$MODEL_LOW" "$MODEL_LINKS" ;;
        *) return 2 ;;
    esac
}
'''


def modeled_predicate(source, argv, mode, uid=0, links=1):
    script = ('set -eu; ' + MODE_STAT + source.replace('/usr/bin/stat', 'mode_stat'))
    env = {'MODEL_UID': str(uid), 'MODEL_FULL': format(mode, 'o'),
           'MODEL_LOW': format(mode & 0o777, 'o'), 'MODEL_LINKS': str(links)}
    return subprocess.run(['/bin/sh', '-c', script, 'mode-control', *argv],
                          env=env, capture_output=True, timeout=5)


def current_helpers(plan=None):
    if plan is None:
        _, _, result, observed = fixture()
        plan = vm.make_plan(result, observed, '0123456789abcdef')
    outer = vm.render(plan)['outer.sh'].decode()
    return outer.split('# GLUE_CURRENT_PREFLIGHT_BEGIN\n', 1)[1].split('# GLUE_CURRENT_PREFLIGHT_END', 1)[0]


def modeled_current_preflight(observed=None, failure=None, *, native_plutil=False):
    """Only extracted helpers with controlled read-tool/inspector models."""
    observed = observation() if observed is None else observed
    raw = vm.primitives().canonical(observed) if failure != 'invalid-json' else b'not JSON\n'
    with tempfile.TemporaryDirectory(prefix='glue-current-preflight-model-') as name:
        root = Path(name).resolve();work = root/'work';work.mkdir()
        inspector = root/'inspector';inspector.write_bytes(b'nonexecutable synthetic inspector data\n')
        calls = root/'calls'
        rows = []
        def visit(key, value):
            kind = {bool: 'bool', int: 'integer', str: 'string', list: 'array', dict: 'dictionary'}.get(type(value))
            if kind == 'dictionary':
                rows.append((key+'|json|dictionary', '', 0))
            elif kind:
                text = ('true' if value else 'false') if kind == 'bool' else str(len(value) if kind == 'array' else value)
                status = 1 if failure == 'plutil-status' and key == 'schema' else 0
                rows.append((key+'|raw|'+kind, text+'\n', status))
            if type(value) is dict:
                for child, item in value.items():visit(key+'.'+child if key else child, item)
            elif type(value) is list:
                for index, item in enumerate(value):visit(key+'.'+str(index), item)
        if failure != 'invalid-json':
            for key, value in observed.items():visit(key, value)
        plist = 'plutil_model() { printf "plutil\\n" >> "$CALLS"; case "$2|$3|$5" in\n'
        for key, text, status in rows:
            plist += shlex.quote(key)+') printf %s '+shlex.quote(text)+'; return '+str(status)+' ;;\n'
        plist += '*) return 1 ;; esac; }\n'
        digest = ('0'*64 if failure == 'hash-value' else vm.INSPECTOR_SHA) + '  ' + str(inspector) + '\n'
        functions = plist
        functions += 'hash_model() { printf "hash\\n" >> "$CALLS"; printf %s '+shlex.quote(digest)+'; return '+('1' if failure == 'hash-status' else '0')+'; }\n'
        functions += 'signature_model() { printf "signature\\n" >> "$CALLS"; return '+('1' if failure == 'signature' else '0')+'; }\n'
        functions += 'inspector_model() { printf "inspector\\n" >> "$CALLS"; printf %s '+shlex.quote(raw.decode())+'; '
        if failure == 'stderr':functions += 'printf unexpected >&2; '
        if failure == 'symlink':functions += '/bin/rm "$WORK/current-observation.json"; /bin/ln -s "$INSPECTOR" "$WORK/current-observation.json"; '
        if failure == 'directory':functions += '/bin/rm "$WORK/current-observation.json"; /bin/mkdir "$WORK/current-observation.json"; '
        functions += 'return '+('1' if failure == 'inspector-status' else '0')+'; }\n'
        mode = {'owner': '0:100600:1', 'mode': '501:100644:1', 'links': '501:100600:2'}.get(failure, '501:100600:1')
        size = '262145' if failure == 'oversized' else ('0' if failure == 'empty' else str(len(raw)))
        functions += ('stat_model() { printf "stat\\n" >> "$CALLS"; case "$2" in '
                      '%u:%p:%l) printf %s '+shlex.quote(mode)+' ;; %z) printf %s '+shlex.quote(size)+' ;; *) return 1 ;; esac; '
                      'return '+('1' if failure == 'stat-status' else '0')+'; }\n')
        helper = current_helpers().replace('INSPECTOR='+shlex.quote(vm.INSPECTOR_PATH), 'INSPECTOR='+shlex.quote(str(inspector)))
        for original, replacement in [('/usr/bin/shasum', 'hash_model'), ('/usr/bin/codesign', 'signature_model'),
                                      ('/usr/bin/plutil', 'plutil_model'), ('/usr/bin/stat', 'stat_model')]:
            if native_plutil and original == '/usr/bin/plutil':continue
            helper = helper.replace(original, replacement)
        helper = helper.replace('/usr/bin/env -i PATH=/usr/bin:/bin:/usr/sbin:/sbin LC_ALL=C TZ=UTC "$INSPECTOR"', 'inspector_model')
        script = ('set -eu; umask 077; set -C; WORK='+shlex.quote(str(work))+'; CALLS='+shlex.quote(str(calls))+';\n'+
                  functions+helper+'\ncurrent_deployment_matches || exit 2; printf authenticated; printf installed')
        done = subprocess.run(['/bin/sh', '-c', script], capture_output=True, timeout=30 if native_plutil else 5)
        return done, calls.read_text().splitlines() if calls.exists() else []


class PreparationTests(unittest.TestCase):
    def test_no_runtime_override_and_no_output_on_invalid_kit(self):
        with tempfile.TemporaryDirectory() as name:
            root = Path(name).resolve()
            for flag in ('--hash', '--profile', '--uid', '--execute', '--trust'):
                done = subprocess.run([sys.executable, '-B', str(HERE/'prepare.py'), '--kit', str(root), '--output', str(root/'out'), flag, 'x'], capture_output=True, timeout=5)
                self.assertEqual(done.returncode, 2)
                self.assertFalse((root/'out').exists())
            with self.assertRaises((ValueError, OSError)):
                vm.prepare(root, root/'out')
            self.assertFalse((root/'out').exists())

    def test_unconfigured_approval_refuses_before_snapshot_or_output(self):
        with tempfile.TemporaryDirectory() as name, patch.object(vm, 'APPROVED', None):
            root = Path(name).resolve()
            with self.assertRaisesRegex(ValueError, 'not configured'):
                vm.prepare(root, root/'out')
            self.assertFalse((root/'out').exists())

    def test_plan_same_device_distinct_fsid_ordered_groups_and_short_outputs(self):
        _, _, result, observed = fixture()
        plan = vm.make_plan(result, observed, '0123456789abcdef')
        self.assertEqual(plan['root_mount']['device'], plan['data_mount']['device'])
        self.assertNotEqual(plan['root_mount'], plan['data_mount'])
        self.assertEqual(plan['expected_groups'], [20, 12, 0])
        self.assertIs(plan['execution_enabled'], vm.EXECUTION_ENABLED)
        self.assertTrue(plan['build_dir'].endswith(vm.APPROVED['build_id']))
        for path in plan['outputs'].values():
            self.assertLessEqual(len(Path(path).name), 64)
        for nonce in ('../x', 'a'*15, 'A'*16, 'a'*17, '$(id)', 123):
            with self.assertRaises(ValueError):
                vm.make_plan(result, observed, nonce)

    def test_render_hash_dag_closed_phases_policy_and_shell_syntax_only(self):
        _, _, result, observed = fixture()
        plan = vm.make_plan(result, observed, '0123456789abcdef')
        scripts = vm.render(plan)
        self.assertEqual(scripts, vm.render(copy.deepcopy(plan)))
        self.assertEqual(set(scripts), {'launch.sh', 'outer.sh', 'root-stage.sh'})
        self.assertIn(vm.sha(scripts['root-stage.sh']).encode(), scripts['outer.sh'])
        self.assertIn(vm.sha(scripts['outer.sh']).encode(), scripts['launch.sh'])
        self.assertNotIn(vm.sha(scripts['outer.sh']).encode(), scripts['root-stage.sh'])
        for source in scripts.values():
            self.assertIn(f'[ {int(vm.EXECUTION_ENABLED)} = 1 ]'.encode(), source)
            self.assertNotIn(b'@@', source)
            self.assertNotIn(b'eval ', source)
            self.assertNotIn(b'SUDO_UID', source)
        outer = scripts['outer.sh'].decode()
        self.assertLess(outer.index('plutil -extract b'), outer.index('/usr/bin/sudo -v'))
        self.assertIn('case "$rc" in 0|1)', outer)
        root = scripts['root-stage.sh'].decode()
        self.assertLess(root.index('closed || return 2'), root.index('/bin/chmod 0755 "$BUILD"', root.index('closed || return 2')))
        self.assertNotRegex(root, r'(?m)^\s*trap\s')
        with tempfile.TemporaryDirectory() as name:
            for label, source in scripts.items():
                path = Path(name)/label
                path.write_bytes(source)
                done = subprocess.run(['/bin/sh', '-n', str(path)], capture_output=True, timeout=5)
                self.assertEqual(done.returncode, 0, done.stderr)

    def test_render_refuses_changed_privileged_paths_ids_or_export_roles(self):
        _, _, result, observed = fixture()
        original = vm.make_plan(result, observed, '0123456789abcdef')
        for key, value in [('root_stage', '/tmp/other'), ('guest_work', '/tmp/other'),
                           ('build_dir', '/arbitrary/program'), ('expected_ids', ['501; false',501,20,20]),
                           ('expected_ids', [True,True,20,20]), ('evidence_files', ['../../private']),
                           ('execution_enabled', not vm.EXECUTION_ENABLED), ('full_acceptance', 0)]:
            plan = copy.deepcopy(original);plan[key] = value
            with self.subTest(key=key), self.assertRaises(ValueError):
                vm.render(plan)
        for kind in ('extra', 'unknown-case'):
            plan = copy.deepcopy(original)
            if kind == 'extra':plan['extra'] = 'x'
            else:plan['outputs']['other'] = '/arbitrary'
            with self.assertRaises(ValueError):vm.render(plan)

    def test_render_current_preflight_rejects_tuple_and_group_coercion(self):
        _, _, result, observed = fixture()
        original = vm.make_plan(result, observed, '0123456789abcdef')
        for mount in ('root_mount', 'data_mount'):
            for field, value in [('device', True), ('device', '16777230'), ('device', 0),
                                 ('fsid', [True,26]), ('fsid', [16777230,'26']),
                                 ('fsid', {'0':16777230,'1':26}), ('fsid', [1]), ('fsid', [0,0])]:
                plan = copy.deepcopy(original);plan[mount][field] = value
                with self.subTest(mount=mount, field=field, value=value), self.assertRaises(ValueError):vm.render(plan)
        for value in ({'0':20,'1':12}, [20,True], [20,12,12], [12,20], []):
            plan = copy.deepcopy(original);plan['expected_groups'] = value
            with self.subTest(groups=value), self.assertRaises(ValueError):vm.render(plan)
        plan = copy.deepcopy(original);plan['root_mount'] = copy.deepcopy(plan['data_mount'])
        with self.assertRaises(ValueError):vm.render(plan)

    def test_current_native_preflight_checks_all_five_complete_tuples_before_authentication(self):
        done, calls = modeled_current_preflight()
        self.assertEqual(done.returncode, 0, done.stderr)
        self.assertEqual(done.stdout, b'authenticatedinstalled')
        self.assertEqual(calls[:3], ['hash','signature','inspector'])
        for index in range(5):
            for field in ('device','fsid.0','fsid.1'):
                trial = observation()
                if field == 'device':trial['components'][index]['device'] += 1
                else:trial['components'][index]['fsid'][int(field[-1])] += 1
                with self.subTest(index=index, field=field):
                    done,_ = modeled_current_preflight(trial)
                    self.assertEqual(done.returncode, 2, done.stderr);self.assertEqual(done.stdout,b'')
        outer = vm.render(vm.make_plan(fixture()[2], observation(), '0123456789abcdef'))['outer.sh'].decode()
        self.assertLess(outer.index('\nplutil_capabilities || exit 2'), outer.index('/usr/bin/sudo -v'))
        self.assertLess(outer.index('\ncurrent_deployment_matches || exit 2'), outer.index('/usr/bin/sudo -v'))
        self.assertLess(outer.index('/usr/bin/sudo -v'), outer.index('install_status=0'))
        self.assertIn(shlex.quote(vm.INSPECTOR_PATH), outer);self.assertIn(vm.INSPECTOR_SHA, outer)

    def test_current_native_preflight_rejects_scope_identity_and_container_lookalikes(self):
        changes = [('tc_compatible',False), ('tc_compatible','true'), ('model','OtherMac'),
                   ('kernel_release','25.6.1'), ('settings_changed',True), ('full_acceptance',True),
                   ('executable_admission',True), ('schema','other'), ('ids',[501,501,20,'20']),
                   ('ids',{'0':501,'1':501,'2':20,'3':20}), ('groups',[20,0,12]),
                   ('groups',{'0':20,'1':12,'2':0})]
        for key,value in changes:
            trial = observation();trial[key] = value
            with self.subTest(key=key, value=value):
                done,_ = modeled_current_preflight(trial)
                self.assertEqual(done.returncode,2,done.stderr);self.assertEqual(done.stdout,b'')
        for field,value in [('device',True), ('device','16777230'), ('fsid',['16777236',26]),
                            ('fsid',[16777236,True]), ('fsid',{'0':16777236,'1':26})]:
            trial = observation();trial['components'][0][field] = value
            with self.subTest(field=field, value=value):
                done,_ = modeled_current_preflight(trial)
                self.assertEqual(done.returncode,2,done.stderr);self.assertEqual(done.stdout,b'')
        trial = observation();trial['components'] = {str(i):c for i,c in enumerate(trial['components'])}
        done,_ = modeled_current_preflight(trial)
        self.assertEqual(done.returncode,2,done.stderr);self.assertEqual(done.stdout,b'')

    def test_current_native_preflight_tool_and_file_failures_cannot_reach_authentication(self):
        for failure in ('hash-value','hash-status','signature','inspector-status','stderr','stat-status',
                        'owner','mode','links','symlink','directory','empty','oversized','invalid-json','plutil-status'):
            with self.subTest(failure=failure):
                done,calls = modeled_current_preflight(failure=failure)
                self.assertEqual(done.returncode,2,done.stderr);self.assertEqual(done.stdout,b'')
                if failure.startswith('hash-'):self.assertEqual(calls,['hash'])
                elif failure == 'signature':self.assertEqual(calls,['hash','signature'])
                elif failure not in ('invalid-json','plutil-status'):self.assertNotIn('plutil',calls)

    @unittest.skipUnless(sys.platform == 'darwin', 'requires native typed plutil')
    def test_native_plutil_capabilities_and_current_integer_container_type_refusals(self):
        with tempfile.TemporaryDirectory(prefix='glue-plutil-capability-') as name:
            script = ('set -eu; umask 077; set -C; WORK='+shlex.quote(str(Path(name).resolve()))+';\n'+
                      current_helpers()+'\nplutil_capabilities || exit 2; printf reached')
            done = subprocess.run(['/bin/sh','-c',script],capture_output=True,timeout=5)
            self.assertEqual(done.returncode,0,done.stderr);self.assertEqual(done.stdout,b'reached')
        done,_ = modeled_current_preflight(native_plutil=True)
        self.assertEqual(done.returncode,0,done.stderr);self.assertEqual(done.stdout,b'authenticatedinstalled')
        for field,value in [('device',True), ('device','16777230'), ('fsid',{'0':16777236,'1':26})]:
            trial = observation();trial['components'][0][field] = value
            done,_ = modeled_current_preflight(trial,native_plutil=True)
            self.assertEqual(done.returncode,2,done.stderr);self.assertEqual(done.stdout,b'')
        trial = observation();trial['groups'] = {'0':20,'1':12,'2':0}
        done,_ = modeled_current_preflight(trial,native_plutil=True)
        self.assertEqual(done.returncode,2,done.stderr);self.assertEqual(done.stdout,b'')

    def test_inline_guard_first_false_AND_operand_cannot_reach_later_command(self):
        # Only shell builtins in an isolated ordinary process. Never invokes
        # root tools, a rendered phase, authentication or filesystem operations.
        for predicate, expected in [('false && true', 2), ('true && false', 2), ('false', 2), ('true', 0)]:
            script = 'set -eu; ' + vm.inline_guard(predicate) + 'printf reached'
            done = subprocess.run(['/bin/sh', '-c', script], capture_output=True, timeout=5)
            self.assertEqual(done.returncode, expected)
            self.assertEqual(done.stdout, b'reached' if expected == 0 else b'')
        _, _, result, observed = fixture()
        outer = vm.render(vm.make_plan(result, observed, '0123456789abcdef'))['outer.sh'].decode()
        # Both independently rendered inline shims guard every predicate. A
        # source FIFO cannot slip past the nonlast -f predicate into head.
        self.assertNotIn(' ] && [ ', outer.split('root_phase()')[0].split('/bin/sh -c ')[1])
        self.assertIn('|| exit 2;', outer)

    def test_request_digest_failures_cannot_compare_equal_empty_outputs(self):
        # Extract the actual narrow helper; substitute only digest with shell
        # builtins. No rendered phase, hashing tool, root tool or file I/O runs.
        template = (HERE / 'root-stage.sh.in').read_text()
        helper = template.split('request_digests_match() {', 1)[1].split('\n}\n', 1)[0]
        helper = 'request_digests_match() {' + helper + '\n}\n'
        digest = ('digest() { case "$1" in fail) return 1 ;; empty) return 0 ;; '
                  'invalid) printf "%064d" 0; printf z ;; '
                  'other) printf "%064d" 1 ;; *) printf "%064d" 0 ;; esac; }\n')
        for left, right, wanted in [('fail','fail',2), ('fail','ok',2), ('ok','fail',2),
                                    ('empty','empty',2), ('invalid','invalid',2),
                                    ('ok','other',2), ('ok','ok',0)]:
            script = ('set -eu; ' + digest + helper +
                      'request_digests_match "$1" "$2" || exit $?; printf reached')
            done = subprocess.run(['/bin/sh', '-c', script, 'control', left, right],
                                  capture_output=True, timeout=5)
            self.assertEqual(done.returncode, wanted, (left, right, done.stderr))
            self.assertEqual(done.stdout, b'reached' if wanted == 0 else b'')
        self.assertIn('request_digests_match "$STAGE/$C.request.bin" "$source" || return 2', template)
        self.assertIn("printf '%s\\n' \"$staged_hash\" > \"$STAGE/$C.input.sha256\"", template)

    def test_inline_full_mode_predicates_preserve_sticky_type_and_failure_edges(self):
        predicates = inline_mode_predicates()
        self.assertEqual(len(predicates), 5)  # Bootstrap tmp, then both copies of the two script guards.
        self.assertEqual({(fmt, expected) for _, fmt, expected in predicates},
                         {('%u:%p', '0:41777'), ('%u:%p', '0:40700'),
                          ('%u:%p:%l', '0:100500:1')})
        for predicate, _, expected in predicates:
            mode = int(expected.split(':')[1], 8)
            variants = [(mode, 0, 1, True), (mode, 1, 1, False),
                        (mode ^ 0o1000, 0, 1, False), (mode ^ 0o2000, 0, 1, False),
                        (mode ^ 0o4000, 0, 1, False), (mode ^ 0o010, 0, 1, False),
                        ((mode & 0o7777) | (stat.S_IFDIR if stat.S_ISREG(mode) else stat.S_IFREG), 0, 1, False)]
            if stat.S_ISREG(mode):
                variants.append((mode, 0, 2, False))
            for actual, uid, links, wanted in variants:
                with self.subTest(expected=expected, actual=oct(actual), uid=uid, links=links):
                    done = modeled_predicate(predicate + ' || exit 2; printf reached', [], actual, uid, links)
                    self.assertEqual(done.returncode, 0 if wanted else 2, done.stderr)
                    self.assertEqual(done.stdout, b'reached' if wanted else b'')

    def test_root_mode_helpers_reject_mode_type_owner_link_and_symlink_models(self):
        helpers = mode_helpers()
        with tempfile.TemporaryDirectory() as name:
            root = Path(name).resolve();directory = root/'directory';directory.mkdir()
            regular = root/'regular';regular.write_bytes(b'not executable\n')
            link = root/'link';link.symlink_to(directory, target_is_directory=True)
            for kind, path, modes in [('directory', directory, (0o40700, 0o40755)),
                                      ('regular', regular, (0o100500, 0o100555, 0o100600))]:
                for mode in modes:
                    expected = '0:' + format(mode, 'o') + (':1' if kind == 'regular' else '')
                    command = helpers + '\n' + kind + ' "$1" "$2" || exit 2; printf reached'
                    for actual, uid, links, wanted in [(mode,0,1,True), (mode,1,1,False),
                            (mode | 0o1000,0,1,False), (mode | 0o2000,0,1,False),
                            (mode | 0o4000,0,1,False), (mode ^ 0o010,0,1,False),
                            ((mode & 0o7777) | (stat.S_IFREG if kind == 'directory' else stat.S_IFDIR),0,1,False)]:
                        with self.subTest(kind=kind, mode=oct(mode), actual=oct(actual), uid=uid):
                            done = modeled_predicate(command, [str(path), expected], actual, uid, links)
                            self.assertEqual(done.returncode, 0 if wanted else 2, done.stderr)
                            self.assertEqual(done.stdout, b'reached' if wanted else b'')
                    if kind == 'regular':
                        self.assertEqual(modeled_predicate(command, [str(path), expected], mode, links=2).returncode, 2)
            for kind, path, expected in [('directory', link, '0:40755'),
                                         ('regular', directory, '0:100600:1'),
                                         ('directory', regular, '0:40755')]:
                done = modeled_predicate(helpers + '\n' + kind + ' "$1" "$2" || exit 2',
                                         [str(path), expected], int(expected.split(':')[1], 8))
                self.assertEqual(done.returncode, 2, done.stderr)

    @unittest.skipUnless(sys.platform == 'darwin', 'requires native BSD stat')
    def test_native_bsd_mode_helpers_discriminate_sticky_setid_and_regular_modes(self):
        helpers = mode_helpers()
        with tempfile.TemporaryDirectory() as name:
            root = Path(name).resolve();directory = root/'directory';directory.mkdir()
            regular = root/'regular';regular.write_bytes(b'not executable\n')
            for kind, path, modes, accepted in [
                    ('directory', directory, (0o700,0o755,0o777,0o1777), (0o700,0o755)),
                    ('regular', regular, (0o500,0o555,0o600,0o1500), (0o500,0o555,0o600))]:
                for mode in modes:
                    os.chmod(path, mode)
                    self.assertEqual(stat.S_IMODE(path.stat().st_mode), mode)
                    native = subprocess.run(['/usr/bin/stat', '-f', '%u:%p:%Lp', str(path)],
                                            capture_output=True, timeout=5, check=True).stdout
                    full = (stat.S_IFDIR if kind == 'directory' else stat.S_IFREG) | mode
                    self.assertEqual(native, f'{os.getuid()}:{full:o}:{mode & 0o777:o}\n'.encode())
                    for wanted in accepted:
                        expected = f'{os.getuid()}:{(full & ~0o7777) | wanted:o}' + (':1' if kind == 'regular' else '')
                        command = helpers + '\n' + kind + ' "$1" "$2" || exit 2; printf reached'
                        done = subprocess.run(['/bin/sh', '-c', command, 'native-mode', str(path), expected],
                                              capture_output=True, timeout=5)
                        with self.subTest(kind=kind, actual=oct(mode), wanted=oct(wanted)):
                            self.assertEqual(done.returncode, 0 if mode == wanted else 2, done.stderr)
                            self.assertEqual(done.stdout, b'reached' if mode == wanted else b'')
            os.chmod(regular, 0o600);os.link(regular, root/'alias')
            done = subprocess.run(['/bin/sh', '-c', helpers + '\nregular "$1" "$2" || exit 2',
                                   'native-links', str(regular), f'{os.getuid()}:100600:1'],
                                  capture_output=True, timeout=5)
            self.assertEqual(done.returncode, 2, done.stderr)
        # Darwin can clear set-ID bits on ordinary-user chmod. Observe the
        # existing OS-owned set-ID control instead; never execute or modify it.
        special = Path('/usr/bin/newgrp')
        info = special.lstat()
        self.assertTrue(stat.S_ISREG(info.st_mode))
        self.assertEqual((info.st_uid, stat.S_IMODE(info.st_mode), info.st_nlink), (0, 0o4555, 1))
        native = subprocess.run(['/usr/bin/stat', '-f', '%u:%p:%Lp', str(special)],
                                capture_output=True, timeout=5, check=True)
        self.assertEqual(native.stdout, b'0:104555:555\n')
        done = subprocess.run(['/bin/sh', '-c', helpers + '\nregular "$1" "$2" || exit 2',
                               'native-setid', str(special), '0:100555:1'],
                              capture_output=True, timeout=5)
        self.assertEqual(done.returncode, 2, done.stderr)

    @unittest.skipUnless(sys.platform == 'darwin', 'requires native BSD stat and physical Data private/tmp')
    def test_native_private_tmp_exact_rendered_guard_accepts_full_sticky_mode(self):
        predicates = [predicate for predicate, _, _ in inline_mode_predicates()
                      if '/System/Volumes/Data/private/tmp)' in predicate]
        self.assertEqual(len(predicates), 1)
        done = subprocess.run(['/bin/sh', '-c', predicates[0] + ' || exit 2; printf reached'],
                              capture_output=True, timeout=5)
        self.assertEqual(done.returncode, 0, done.stderr)
        self.assertEqual(done.stdout, b'reached')
        # Demonstrate the actual historical bug, without running the old phase.
        low = subprocess.run(['/usr/bin/stat', '-f', '%u:%Lp', '/System/Volumes/Data/private/tmp'],
                             capture_output=True, timeout=5, check=True)
        self.assertEqual(low.stdout, b'0:777\n')

    def test_derived_packet_exact_inventory_and_existing_output_untouched(self):
        values = fixture()
        with tempfile.TemporaryDirectory() as name:
            root = Path(name).resolve();out = root/'packet'
            with patch.object(vm, 'load_kit', return_value=values):
                plan = vm.prepare(root/'unused', out)
                old = {p.relative_to(out).as_posix(): p.read_bytes() for p in out.rglob('*') if p.is_file()}
                with self.assertRaises(FileExistsError):
                    vm.prepare(root/'unused', out)
            self.assertEqual(old, {p.relative_to(out).as_posix(): p.read_bytes() for p in out.rglob('*') if p.is_file()})
            p = vm.primitives();members = p.verified_tree(out, vm.sha((out/'SHA256SUMS').read_bytes()))
            self.assertEqual(set(members), {'payload/'+n for n in vm.PROGRAMS} | {'metadata/'+n for n in vm.METADATA} |
                             {'plan.json', 'derived-subset.json', 'launch.sh', 'outer.sh', 'root-stage.sh'})
            subset = p.strict_json(members['derived-subset.json'])
            self.assertIs(subset['original_inventory_is_detached_metadata'], True)
            self.assertEqual(len(subset['selected']), 9)
            self.assertEqual(p.strict_json(members['plan.json']), plan)
            self.assertNotEqual(members['metadata/build-SHA256SUMS'], (out/'SHA256SUMS').read_bytes())

    def test_inside_repo_and_linked_output_parent_refuse(self):
        with tempfile.TemporaryDirectory() as name:
            root = Path(name).resolve();real = root/'real';real.mkdir();(root/'link').symlink_to(real, target_is_directory=True)
            with patch.object(vm, 'load_kit', return_value=fixture()):
                with self.assertRaises((ValueError, OSError)):
                    vm.prepare(root/'unused', root/'link'/'new')
                with self.assertRaisesRegex(ValueError, 'outside'):
                    vm.prepare(root/'unused', HERE/'must-not-create')
            self.assertFalse((real/'new').exists());self.assertFalse((HERE/'must-not-create').exists())

    def test_partial_prepare_keeps_directory_without_final_inventory(self):
        with tempfile.TemporaryDirectory() as name:
            root = Path(name).resolve();out = root/'packet'
            original = os.chmod
            def fail(path, mode):
                if Path(path).name == 'outer.sh':
                    raise OSError('injected final script chmod failure')
                return original(path, mode)
            with patch.object(vm, 'load_kit', return_value=fixture()), patch.object(vm.os, 'chmod', side_effect=fail):
                with self.assertRaises(OSError):
                    vm.prepare(root/'unused', out)
            self.assertTrue(out.is_dir());self.assertFalse((out/'SHA256SUMS').exists())
            self.assertTrue((out/'payload/context-probe').is_file())


if __name__ == '__main__':
    unittest.main()
