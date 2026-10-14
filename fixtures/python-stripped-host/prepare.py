#!/usr/bin/env python3
"""Independent selected stripped prerequisite preparation/publication oracle.

The input tree is a selected projection of authenticated upstream tar bytes,
not an installed uv runtime. No interpreter is extracted or executed.
"""
from __future__ import annotations

import argparse
import importlib.util
import json
import os
from pathlib import Path
import shutil
import stat
import subprocess
import sys
import tarfile
import tempfile

HERE = Path(__file__).resolve().parent
FIXTURES = HERE.parent
_inspection_spec = importlib.util.spec_from_file_location('stripped_independent_inspection', HERE / 'inspection.py')
inspection = importlib.util.module_from_spec(_inspection_spec)
_inspection_spec.loader.exec_module(inspection)
LIBRARY = 'lib/libpython3.13.so.1.0'
SYSCONFIG = 'lib/python3.13/_sysconfigdata__linux_aarch64-linux-gnu.py'
PROVIDER = 'host-install-stripped'
MTIME = 1704067200
require = inspection.require
identity = inspection.identity


def previous(name, relative):
    specification = importlib.util.spec_from_file_location(name, FIXTURES / relative)
    module = importlib.util.module_from_spec(specification)
    specification.loader.exec_module(module)
    return module


OLD = previous('stripped_independent_host', 'python-host-prerequisites/test_prepare.py')
TREE = previous('stripped_independent_tree', 'python-runtime-trees/prepare.py')
same_json = TREE.same_json
strict_json = TREE.strict_json
regular_identity = TREE.regular_identity
write_json = TREE.write_json


def selected_contract():
    files = TREE.selected_contract()
    files[LIBRARY] = inspection.pins()['stripped_library']
    require(len(files) == 1041 and sum(row['size'] for row in files.values()) == 38093257,
            'independent stripped selected cell differs')
    return files


def audit_input(root):
    TREE.ordinary_root(root)
    files, prefixes = {}, {}
    for name, expected in selected_contract().items():
        actual, prefix = regular_identity(root / name, expected['size'])
        require(same_json(actual, expected), 'selected stripped input identity differs: ' + name)
        files[name], prefixes[name] = actual, prefix.hex()
    return {'schema_version': 0, 'input_root': str(root), 'input_layout': 'stock-install-only-stripped',
            'selected_files': files, 'selected_file_prefixes': prefixes,
            'selected_file_count': len(files), 'selected_input_bytes': 38093257,
            'input_python_execution_observed': False, 'complete_input_inventory_observed': False}


def extract_tree(artifact, root):
    require(not root.exists() and not root.is_symlink(), 'selected input output already exists')
    TREE.ordinary_root(root.parent)
    expected = inspection.pins()['stripped_artifact']
    actual, _ = regular_identity(artifact, expected['size'])
    require(same_json(actual, {k: expected[k] for k in ('size', 'sha256')}),
            'stripped artifact pin differs')
    selected = selected_contract()
    root.mkdir()
    seen = set()
    try:
        with tarfile.open(artifact, 'r:gz') as archive:
            for member in archive:
                relative = member.name.removeprefix('python/')
                if relative not in selected:
                    continue
                require(member.isfile() and relative not in seen, 'selected tar type/uniqueness differs')
                payload = archive.extractfile(member).read()
                require(same_json(identity(payload), selected[relative]), 'selected tar payload pin differs')
                destination = root / relative
                destination.parent.mkdir(parents=True, exist_ok=True)
                with destination.open('xb') as stream:
                    stream.write(payload)
                destination.chmod(0o644)
                os.utime(destination, ns=(MTIME * 1000000000,) * 2)
                seen.add(relative)
        require(seen == set(selected), 'selected tar files absent')
        result = audit_input(root)
        require(not (root / 'bin').exists(), 'input interpreter unexpectedly extracted')
        return result | {'artifact': expected, 'source_kind': 'authenticated-selected-tar-projection'}
    except Exception:
        shutil.rmtree(root)
        raise


def expected_provenance(root=None):
    files, provenance = OLD.expected_contract('host-install')
    files[LIBRARY] = inspection.pins()['stripped_library']
    require(same_json(files, selected_contract()), 'independent source inventories disagree')
    provenance['files'] = files
    provenance['provider'] = PROVIDER
    provenance['profile_build_id'] = inspection.pins()['profile_build_id']
    provenance['selected_bytes'] = 38093257
    artifact = inspection.pins()['stripped_artifact']
    if root is None:
        provenance.update(artifact=artifact, artifact_entries=4526, artifact_payload_bytes=79291731,
                          omitted_files=2437, omitted_bytes=41198474)
    else:
        source = audit_input(root)
        for name in ('artifact', 'artifact_entries', 'artifact_payload_bytes', 'omitted_files', 'omitted_bytes'):
            provenance[name] = None
        provenance['installed_tree'] = {
            'input_root': str(root), 'input_layout': 'stock-install-only-stripped',
            'inspection_scope': 'selected-prerequisites-only', 'expected_artifact': artifact,
            'sysconfig_input': source['selected_files'][SYSCONFIG],
            'sysconfig_output': files[SYSCONFIG], 'sysconfig_normalized': False,
            'sysconfig_template': None,
        }
    return files, provenance


def audit_output(prefix, report, root=None):
    expected, provenance = expected_provenance(root)
    files, directories = OLD.tree_inventory(prefix)
    require(set(files) == set(expected) | {'provenance.json'}, 'stripped output file inventory differs')
    require(set(directories) == OLD.expected_directories(expected), 'stripped output directory inventory differs')
    for name, path in files.items():
        metadata = path.lstat()
        require(stat.S_IMODE(metadata.st_mode) == 0o444 and metadata.st_mtime_ns == MTIME * 1000000000,
                'stripped output file mode/time differs: ' + name)
        if name != 'provenance.json':
            require(same_json(regular_identity(path, expected[name]['size'])[0], expected[name]),
                    'stripped output payload identity differs: ' + name)
    for name, path in directories.items():
        metadata = path.lstat()
        require(stat.S_IMODE(metadata.st_mode) == 0o555 and metadata.st_mtime_ns == MTIME * 1000000000,
                'stripped output directory mode/time differs: ' + name)
    provenance_identity, payload = regular_identity(files['provenance.json'], 1024 * 1024, True)
    actual = strict_json(payload)
    require(same_json(actual, provenance), 'stripped output provenance differs from independent contract')
    expected_report = {
        'provider': PROVIDER, 'prefix': str(prefix), 'provenance': provenance,
        'provenance_file': {'path': 'provenance.json'} | provenance_identity,
        'files': expected, 'file_count': 1041, 'payload_bytes': 38093257,
        'directory_count': len(directories), 'file_mode': 0o444, 'directory_mode': 0o555,
        'mtime_seconds': MTIME,
    }
    require(same_json(report, expected_report), 'stripped stdout report differs from independent observation')
    return expected_report | {
        'schema_version': 0, 'all_file_bytes_modes_times_verified': True,
        'all_directory_modes_times_verified': True, 'input_python_execution_observed': False,
        'complete_input_installation_certified': False,
    }


def invoke(command, directory):
    directory.mkdir()
    write_json(directory / 'command.json', command)
    result = subprocess.run(command, capture_output=True, timeout=120, check=False)
    require(len(result.stdout) <= 1024 * 1024 and len(result.stderr) <= 65536,
            'product preparation diagnostics exceed fixture bound')
    (directory / 'stdout.txt').write_bytes(result.stdout)
    (directory / 'stderr.txt').write_bytes(result.stderr)
    (directory / 'exit-status.txt').write_text(str(result.returncode) + '\n')
    return result


def controls(args):
    require(not args.output.exists(), 'controls output already exists')
    args.output.mkdir()
    original = audit_input(args.runtime_tree)
    protected = {name: (path.stat().st_ino, path.stat().st_nlink, path.stat().st_mode,
                       path.stat().st_mtime_ns) for name in selected_contract()
                 for path in [args.runtime_tree / name]}
    successes, rejections = {}, {}
    with tempfile.TemporaryDirectory(prefix='glue-stripped-controls-', dir=args.scratch_parent) as temporary:
        scratch = Path(temporary)
        base = scratch / 'base'
        TREE.clone_selected(args.runtime_tree, base, copy_files=True)

        def command(prefix, source, artifact=False, provider=PROVIDER):
            return [str(args.glue), 'python-host', '--provider', provider,
                    '--pbs-install-only' if artifact else '--runtime-tree', str(source),
                    '--output', str(prefix), '--json']

        repeated = None
        for label, source, artifact in [('artifact', args.pbs_install_only, True),
                                        ('tree', base, False), ('tree-repeat', base, False)]:
            prefix = scratch / (label + '-output')
            result = invoke(command(prefix, source, artifact), args.output / label)
            require(result.returncode == 0 and not result.stderr, 'valid stripped preparation failed: ' + label)
            report = strict_json(result.stdout)
            comparable = {key: value for key, value in report.items() if key != 'prefix'}
            if label == 'tree':
                repeated = comparable
            elif label == 'tree-repeat':
                require(same_json(comparable, repeated), 'repeated tree preparation reports/payload identities differ')
            audit = audit_output(prefix, report, None if artifact else source)
            write_json(args.output / label / 'oracle.json', audit)
            successes[label] = {'file_count': 1041, 'payload_bytes': 38093257,
                                'provenance_file': audit['provenance_file']}
            OLD.remove_owned_tree(prefix)

        ignored = scratch / 'ignored-unselected'
        TREE.clone_selected(base, ignored)
        (ignored / 'bin').mkdir()
        (ignored / 'bin/python3.13').write_bytes(b'not an executable interpreter\n')
        (ignored / 'lib/python3.13/ignored-native.so').write_bytes(b'not a native image\n')
        os.mkfifo(ignored / 'lib/python3.13/ignored.fifo')
        prefix = scratch / 'ignored-output'
        result = invoke(command(prefix, ignored), args.output / 'ignored-unselected')
        require(result.returncode == 0 and not result.stderr, 'unselected lure changed selected preparation')
        audit = audit_output(prefix, strict_json(result.stdout), ignored)
        write_json(args.output / 'ignored-unselected/oracle.json', audit)
        successes['ignored-unselected'] = {'file_count': 1041, 'payload_bytes': 38093257,
                                          'provenance_file': audit['provenance_file']}
        OLD.remove_owned_tree(prefix)
        TREE.remove_owned_tree(ignored)

        def reject(label, source, prefix=None, artifact=False, extra=(), provider=PROVIDER, check=None):
            prefix = prefix or scratch / (label + '-output')
            result = invoke(command(prefix, source, artifact, provider) + list(extra), args.output / label)
            require(result.returncode == 1 and not result.stdout and result.stderr,
                    'hostile stripped preparation was accepted: ' + label)
            require(check() if check else not prefix.exists() and not prefix.is_symlink(),
                    'rejected preparation modified output: ' + label)
            rejections[label] = {'exit_status': 1, 'output_protected': True,
                                 'stderr': result.stderr.decode('utf-8')}

        for label, relative, mutation in [
                ('missing-library', LIBRARY, 'missing'), ('corrupt-library', LIBRARY, 'corrupt'),
                ('library-symlink', LIBRARY, 'symlink'), ('library-fifo', LIBRARY, 'fifo'),
                ('source-symlink', 'lib/python3.13/json/__init__.py', 'symlink'),
                ('missing-cache', 'lib/python3.13/encodings/__pycache__/utf_8.cpython-313.pyc', 'missing'),
                ('corrupt-cache', 'lib/python3.13/encodings/__pycache__/aliases.cpython-313.pyc', 'corrupt'),
                ('modified-sysconfig', SYSCONFIG, 'corrupt')]:
            tree = scratch / label
            TREE.clone_selected(base, tree)
            path = tree / relative
            payload = path.read_bytes() if mutation == 'corrupt' else None
            path.unlink()
            if mutation == 'corrupt':
                path.write_bytes(bytes([payload[0] ^ 1]) + payload[1:])
            elif mutation == 'symlink':
                path.symlink_to(base / relative)
            elif mutation == 'fifo':
                os.mkfifo(path)
            reject(label, tree)
            TREE.remove_owned_tree(tree)
        ancestor = scratch / 'ancestor-symlink'
        TREE.clone_selected(base, ancestor)
        TREE.remove_owned_tree(ancestor / 'lib/python3.13')
        (ancestor / 'lib/python3.13').symlink_to(base / 'lib/python3.13', target_is_directory=True)
        reject('ancestor-symlink', ancestor)
        TREE.remove_owned_tree(ancestor)
        oversized = scratch / 'oversized-library'
        TREE.clone_selected(base, oversized)
        oversized_library = oversized / LIBRARY
        oversized_library.unlink()
        with oversized_library.open('xb') as stream:
            stream.truncate(inspection.pins()['stripped_library']['size'] + 1)
        reject('oversized-library', oversized)
        TREE.remove_owned_tree(oversized)
        reject('wrong-provider-tree', base, provider='host-install')
        reject('wrong-provider-artifact', args.pbs_install_only, artifact=True, provider='host-install')
        if args.unstripped_artifact:
            reject('opposite-artifact', args.unstripped_artifact, artifact=True)
        reject('duplicate-tree-option', base, extra=('--runtime-tree', str(base)))
        reject('mixed-artifact-tree', base, extra=('--pbs-install-only', str(args.pbs_install_only)))
        reject('relative-root', Path('relative-root'))
        reject('overlap-child', base, base / 'child-output')
        for kind in ('file', 'directory', 'symlink'):
            prefix = scratch / ('existing-' + kind)
            if kind == 'file':
                prefix.write_bytes(b'preserved stripped sentinel\n')
                check = lambda: prefix.read_bytes() == b'preserved stripped sentinel\n'
            elif kind == 'directory':
                prefix.mkdir()
                (prefix / 'sentinel').write_bytes(b'preserved stripped sentinel\n')
                check = lambda: (prefix / 'sentinel').read_bytes() == b'preserved stripped sentinel\n' and len(list(prefix.iterdir())) == 1
            else:
                prefix.symlink_to(base, target_is_directory=True)
                check = lambda: prefix.is_symlink() and prefix.readlink() == base
            reject('existing-' + kind, base, prefix, check=check)
    require(same_json(audit_input(args.runtime_tree), original), 'controls modified original selected bytes')
    require(all((path.stat().st_ino, path.stat().st_nlink, path.stat().st_mode, path.stat().st_mtime_ns) == protected[name]
                for name in selected_contract() for path in [args.runtime_tree / name]),
            'controls modified original selected ownership/mode/time')
    summary = {'schema_version': 0, 'success_count': len(successes), 'rejection_count': len(rejections),
               'successes': successes, 'rejections': rejections,
               'original_selected_bytes_inodes_links_modes_times_unchanged': True,
               'repeated_tree_payload_and_provenance_identical': True,
               'input_interpreter_extracted_or_executed': False}
    write_json(args.output / 'summary.json', summary)
    return summary


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest='command', required=True)
    extract = commands.add_parser('extract-tree')
    extract.add_argument('--pbs-install-only', type=Path, required=True)
    extract.add_argument('--output', type=Path, required=True)
    extract.add_argument('--audit', type=Path)
    audit = commands.add_parser('audit-input')
    audit.add_argument('--runtime-tree', type=Path, required=True)
    audit.add_argument('--output', type=Path, required=True)
    output = commands.add_parser('audit-output')
    output.add_argument('--runtime-tree', type=Path)
    output.add_argument('--prefix', type=Path, required=True)
    output.add_argument('--report', type=Path, required=True)
    output.add_argument('--output', type=Path, required=True)
    control = commands.add_parser('controls')
    control.add_argument('--glue', type=Path, required=True)
    control.add_argument('--pbs-install-only', type=Path, required=True)
    control.add_argument('--unstripped-artifact', type=Path)
    control.add_argument('--runtime-tree', type=Path, required=True)
    control.add_argument('--output', type=Path, required=True)
    control.add_argument('--scratch-parent', type=Path,
                         default=Path('/private/tmp' if sys.platform == 'darwin' else '/tmp'))
    args = parser.parse_args()
    if args.command == 'extract-tree':
        result = extract_tree(args.pbs_install_only, args.output)
        if args.audit:
            write_json(args.audit, result)
    elif args.command == 'audit-input':
        result = audit_input(args.runtime_tree)
        write_json(args.output, result)
    elif args.command == 'audit-output':
        result = audit_output(args.prefix, strict_json(args.report.read_bytes()), args.runtime_tree)
        write_json(args.output, result)
    else:
        result = controls(args)
    print(json.dumps({key: result[key] for key in ('schema_version', 'selected_file_count',
                                                  'selected_input_bytes', 'file_count', 'payload_bytes',
                                                  'success_count', 'rejection_count') if key in result}, sort_keys=True))


if __name__ == '__main__':
    try:
        main()
    except (OSError, ValueError, subprocess.TimeoutExpired) as error:
        raise SystemExit('stripped fixture: ' + str(error))
