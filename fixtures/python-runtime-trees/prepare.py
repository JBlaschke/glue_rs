#!/usr/bin/env python3
"""Independent selected-runtime-tree fixture and offline genuine uv installer.

The oracle reads pinned selected bytes without executing the input Python.  Its
uv expectation is reconstructed from the independently recorded dictionary
changes to the original stock source, rather than from the product's template.
"""
from __future__ import annotations

import argparse
import ast
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import shutil
import stat
import subprocess
import sys
import tempfile

HERE = Path(__file__).resolve().parent
FIXTURES = HERE.parent
KEY = 'cpython-3.13.16-linux-aarch64-gnu'
SYSCONFIG = 'lib/python3.13/_sysconfigdata__linux_aarch64-linux-gnu.py'
LIBRARY = 'lib/libpython3.13.so.1.0'
LIBRARY_IDENTITY = {'size': 73563968, 'sha256': '42be968275d5be2d9e632ec9ef6790dd2c10f1d4a710ad1028fc2b687242f219'}
STOCK_IDENTITY = {'size': 51570, 'sha256': '2f1efec1bde90579ce80b849b755f7347a83705e73bfedeb25e947b617d25347'}
ADJUSTMENTS_IDENTITY = {'size': 14907, 'sha256': 'e5e220295f6a3fe9522f91487be90729cd4c52fccd19c38593a22f85f579fb09'}
TEMPLATE_IDENTITY = {'size': 51552, 'sha256': 'ac2bdd1c0d98d36a508b19006c7485e0100585ff3703f090dab6b075017f11fb'}
ARTIFACT = {
    'filename': 'cpython-3.13.16+20261009-aarch64-unknown-linux-gnu-install_only.tar.gz',
    'size': 57626877, 'sha256': '397ca401f416c3c99330a6be16d735d0cbeaf53e82070b80395b2fb4a8891f34',
    'url': 'https://github.com/astral-sh/python-build-standalone/releases/download/20261009/cpython-3.13.16%2B20261009-aarch64-unknown-linux-gnu-install_only.tar.gz',
}
HEADER = b'# system configuration generated and used by the sysconfig module\nbuild_time_vars = '
PLACEHOLDER = '@PYTHON_ROOT@'


def require(condition, message):
    if not condition:
        raise ValueError(message)


def identity(payload):
    return {'size': len(payload), 'sha256': hashlib.sha256(payload).hexdigest()}


def same_json(left, right):
    options = {'sort_keys': True, 'separators': (',', ':'), 'ensure_ascii': False, 'allow_nan': False}
    return json.dumps(left, **options) == json.dumps(right, **options)


def strict_json(payload):
    def pairs(items):
        result = {}
        for name, value in items:
            require(name not in result, 'duplicate JSON field: ' + name)
            result[name] = value
        return result
    return json.loads(payload, object_pairs_hook=pairs, parse_constant=lambda value: (_ for _ in ()).throw(ValueError(value)))


def write_json(path, value):
    with path.open('x', encoding='utf-8') as stream:
        json.dump(value, stream, sort_keys=True, indent=2, ensure_ascii=False, allow_nan=False)
        stream.write('\n')


def ordinary_root(root):
    text = str(root)
    require(root.is_absolute() and text.isascii() and '\\' not in text and '\x00' not in text,
            'selected runtime root must be an absolute ASCII path')
    require(all(part not in ('.', '..') for part in root.parts), 'selected runtime root is not canonical')
    for parent in [*reversed(root.parents), root]:
        require(stat.S_ISDIR(parent.lstat().st_mode), 'selected runtime ancestor is not an ordinary directory: ' + str(parent))


def regular_identity(path, maximum, retain=False):
    """Bound and hash an ordinary file, rejecting aliases and special files."""
    for parent in reversed(path.parents):
        require(stat.S_ISDIR(parent.lstat().st_mode), 'selected input ancestor is not an ordinary directory: ' + str(parent))
    mode = path.lstat()
    require(stat.S_ISREG(mode.st_mode) and mode.st_size <= maximum, 'selected input is not a bounded regular file: ' + str(path))
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    try:
        opened = os.fstat(fd)
        require(stat.S_ISREG(opened.st_mode) and (opened.st_dev, opened.st_ino, opened.st_size) ==
                (mode.st_dev, mode.st_ino, mode.st_size), 'selected input identity changed before read')
        digest, size, payload = hashlib.sha256(), 0, bytearray()
        while block := os.read(fd, 65536):
            size += len(block)
            require(size <= maximum, 'selected input grew beyond its bound')
            digest.update(block)
            if retain:
                payload.extend(block)
            elif len(payload) < 512:
                payload.extend(block[:512 - len(payload)])
        require(size == mode.st_size, 'selected input size changed during read')
        return {'size': size, 'sha256': digest.hexdigest()}, bytes(payload)
    finally:
        os.close(fd)


def selected_contract():
    files = {LIBRARY: dict(LIBRARY_IDENTITY)}
    for name, count, total in [('source-pins.json', 1037, 15894268), ('cache-pins.json', 3, 21157)]:
        pins = strict_json((FIXTURES / 'python-install-host-source-apps' / name).read_bytes())
        require(type(pins['schema_version']) is int and pins['schema_version'] == 0 and
                pins['artifact_sha256'] == ARTIFACT['sha256'], 'selected oracle producer pin differs')
        require(len(pins['files']) == count and sum(item['size'] for item in pins['files'].values()) == total,
                'selected oracle inventory totals differ')
        for path, declared in pins['files'].items():
            require(set(declared) == {'size', 'sha256'} and type(declared['size']) is int and
                    0 <= declared['size'] <= 16 * 1024 * 1024 and type(declared['sha256']) is str and
                    len(declared['sha256']) == 64 and all(c in '0123456789abcdef' for c in declared['sha256']),
                    'selected oracle file schema differs')
            require(path and not path.startswith('/') and all(part not in ('', '.', '..') for part in path.split('/')),
                    'selected oracle path is unsafe')
            files['lib/python3.13/' + path] = declared
    require(len(files) == 1041 and sum(item['size'] for item in files.values()) == 89479393 and
            same_json(files[SYSCONFIG], STOCK_IDENTITY), 'selected oracle fixed cell differs')
    return dict(sorted(files.items()))


def stock_variables():
    payload = (HERE / 'stock-sysconfig.py').read_bytes()
    require(same_json(identity(payload), STOCK_IDENTITY), 'independent original stock source identity differs')
    module = ast.parse(payload)
    require(len(module.body) == 1 and isinstance(module.body[0], ast.Assign) and
            len(module.body[0].targets) == 1 and isinstance(module.body[0].targets[0], ast.Name) and
            module.body[0].targets[0].id == 'build_time_vars', 'original stock source is not one literal dictionary')
    variables = ast.literal_eval(module.body[0].value)
    require(type(variables) is dict and all(type(k) is str and type(v) in (str, int) for k, v in variables.items()),
            'original stock scalar schema differs')
    return variables


def uv_sysconfig(root):
    """Reconstruct exact uv bytes independently using original stock scalars."""
    text = str(root)
    require(root.is_absolute() and text.isascii() and '\x00' not in text, 'uv source root is not absolute ASCII')
    payload = (HERE / 'uv-0.12.23-adjustments.json').read_bytes()
    require(same_json(identity(payload), ADJUSTMENTS_IDENTITY), 'independent uv adjustment identity differs')
    changes = strict_json(payload)
    require(len(changes) == 72 and changes.get('PYTHON_BUILD_STANDALONE') == 1 and
            sum(value.count(PLACEHOLDER) for value in changes.values() if type(value) is str) == 27,
            'independent uv scalar adjustment closure differs')
    variables = stock_variables()
    require(set(changes) - set(variables) == {'PYTHON_BUILD_STANDALONE'} and
            sum(name in variables and not same_json(variables[name], value) for name, value in changes.items()) == 71,
            'independent uv changed-key set differs')
    variables.update({name: value.replace(PLACEHOLDER, text) if type(value) is str else value
                      for name, value in changes.items()})
    return HEADER + json.dumps(variables, sort_keys=True, indent=4, ensure_ascii=False).encode('utf-8') + b'\n'


def audit_input(root):
    ordinary_root(root)
    stock = selected_contract()
    uv = uv_sysconfig(root)
    observed, prefixes = {}, {}
    for relative, expected in stock.items():
        bound = max(STOCK_IDENTITY['size'], len(uv)) if relative == SYSCONFIG else expected['size']
        actual, payload = regular_identity(root / relative, bound, relative == SYSCONFIG)
        if relative == SYSCONFIG:
            if same_json(actual, STOCK_IDENTITY):
                layout = 'stock'
            else:
                require(payload == uv, 'selected uv sysconfig differs from all independently expected bytes')
                layout = 'uv-0.12.23'
        else:
            require(same_json(actual, expected), 'selected runtime bytes differ: ' + relative)
        observed[relative] = actual
        prefixes[relative] = payload[:512].hex()
    return {'schema_version': 0, 'root': str(root), 'input_layout': layout, 'selected_files': observed,
            'selected_file_prefixes': prefixes,
            'selected_file_count': len(observed), 'selected_input_bytes': sum(item['size'] for item in observed.values()),
            'selected_output_bytes': sum(item['size'] for item in stock.values()),
            'sysconfig_input': observed[SYSCONFIG], 'sysconfig_output': STOCK_IDENTITY,
            'sysconfig_normalized': layout != 'stock', 'input_python_execution_observed': False,
            'complete_input_inventory_observed': False}


def previous_oracle():
    specification = importlib.util.spec_from_file_location('independent_host_prerequisites',
        FIXTURES / 'python-host-prerequisites/test_prepare.py')
    module = importlib.util.module_from_spec(specification)
    specification.loader.exec_module(module)
    return module


def expected_provenance(source):
    old = previous_oracle()
    files, provenance = old.expected_contract('host-install')
    require(same_json(files, selected_contract()), 'independent source/output pin inventories disagree')
    for name in ('artifact', 'artifact_entries', 'artifact_payload_bytes', 'omitted_files', 'omitted_bytes'):
        provenance[name] = None
    normalized = source['sysconfig_normalized']
    require(type(normalized) is bool and same_json(source['sysconfig_output'], STOCK_IDENTITY), 'input audit normalization schema differs')
    template = (HERE / 'uv-0.12.23-sysconfig.py.in').read_bytes()
    require(same_json(identity(template), TEMPLATE_IDENTITY) and template.count(b'__GLUE_RUNTIME_TREE_ROOT__') == 27,
            'product uv template fixed identity differs from its observed binding')
    provenance['installed_tree'] = {
        'input_root': source['root'],
        'input_layout': 'uv-0.12.23-sysconfig' if normalized else 'stock-install-only',
        'inspection_scope': 'selected-prerequisites-only', 'expected_artifact': ARTIFACT,
        'sysconfig_input': source['sysconfig_input'], 'sysconfig_output': STOCK_IDENTITY,
        'sysconfig_normalized': normalized,
        'sysconfig_template': ({'path': 'fixtures/python-runtime-trees/uv-0.12.23-sysconfig.py.in'} |
                              TEMPLATE_IDENTITY) if normalized else None,
    }
    return files, provenance


def audit_output(prefix, report, source):
    """Observe every output file, byte identity, directory, permission and time."""
    old = previous_oracle()
    expected, provenance = expected_provenance(source)
    files, directories = old.tree_inventory(prefix)
    require(set(files) == set(expected) | {'provenance.json'}, 'published output file inventory differs')
    require(set(directories) == old.expected_directories(expected), 'published output directory inventory differs')
    for name, path in files.items():
        metadata = path.lstat()
        require(stat.S_IMODE(metadata.st_mode) == 0o444 and metadata.st_mtime_ns == 1704067200 * 1000000000,
                'published output file mode/time differs: ' + name)
        if name != 'provenance.json':
            require(same_json(regular_identity(path, expected[name]['size'])[0], expected[name]),
                    'published output bytes differ: ' + name)
    for name, path in directories.items():
        metadata = path.lstat()
        require(stat.S_IMODE(metadata.st_mode) == 0o555 and metadata.st_mtime_ns == 1704067200 * 1000000000,
                'published output directory mode/time differs: ' + name)
    provenance_path = files['provenance.json']
    actual_identity, payload = regular_identity(provenance_path, 1024 * 1024, True)
    actual = strict_json(payload)
    require(same_json(actual, provenance), 'published tree provenance differs from independent input/pins')
    wanted = {'provider': 'host-install', 'prefix': str(prefix), 'provenance': provenance,
              'provenance_file': {'path': 'provenance.json'} | actual_identity,
              'files': expected, 'file_count': 1041, 'payload_bytes': 89479393,
              'directory_count': len(directories), 'file_mode': 0o444, 'directory_mode': 0o555,
              'mtime_seconds': 1704067200}
    require(same_json(report, wanted), 'product stdout report differs from independently observed publication')
    return {'schema_version': 0, 'input_root': source['root'], 'input_layout': source['input_layout'],
            'prefix': str(prefix), 'files': expected, 'file_count': 1041, 'payload_bytes': 89479393,
            'directory_count': len(directories), 'provenance': actual,
            'provenance_file': actual_identity, 'all_file_bytes_modes_times_verified': True,
            'all_directory_modes_times_verified': True, 'complete_input_installation_certified': False}


def remove_owned_tree(root):
    """Remove only this fixture's new tree; never chmod linked input files."""
    require(stat.S_ISDIR(root.lstat().st_mode), 'owned scratch root is not an ordinary directory')
    for directory, names, files in os.walk(root, topdown=True, followlinks=False):
        path = Path(directory)
        require(stat.S_ISDIR(path.lstat().st_mode), 'owned scratch directory changed to an alias')
        path.chmod(0o700)
        for name in list(names):
            child = path / name
            if stat.S_ISLNK(child.lstat().st_mode):
                child.unlink()
                names.remove(name)
    shutil.rmtree(root)


def clone_selected(source, destination, uv=False):
    destination.mkdir()
    for relative in selected_contract():
        target = destination / relative
        target.parent.mkdir(parents=True, exist_ok=True)
        if relative == SYSCONFIG:
            target.write_bytes(uv_sysconfig(destination) if uv else (HERE / 'stock-sysconfig.py').read_bytes())
        else:
            os.link(source / relative, target)
    return destination


def replacement(path, payload):
    """Detach a fixture alias before mutation, preserving the genuine input."""
    path.unlink()
    with path.open('xb') as stream:
        stream.write(payload)


def invoke(command, directory):
    write_json(directory / 'command.json', command)
    result = subprocess.run(command, capture_output=True, check=False, timeout=120)
    require(len(result.stdout) <= 1024 * 1024 and len(result.stderr) <= 65536, 'product control output exceeds its bound')
    (directory / 'stdout.txt').write_bytes(result.stdout)
    (directory / 'stderr.txt').write_bytes(result.stderr)
    (directory / 'exit-status.txt').write_text(str(result.returncode) + '\n', encoding='ascii')
    return result


def controls(args):
    root, glue, output = args.runtime_tree.absolute(), args.glue.absolute(), args.output.absolute()
    source = audit_input(root)
    source_metadata = {name: (stat.S_IMODE((root / name).lstat().st_mode), (root / name).lstat().st_mtime_ns)
                       for name in source['selected_files']}
    require(not (root / 'bin').exists() and not (root / 'bin').is_symlink(), 'controls require the input interpreter directory absent')
    require(not output.exists() and not output.is_symlink() and output.parent.is_dir(), 'control evidence must be new')
    output.mkdir()
    write_json(output / 'selected-input-audit.json', source)
    binary = regular_identity(glue, 256 * 1024 * 1024)[0]
    # Selected clones use hardlinks, so scratch must share the installed input's
    # filesystem. It is a fresh sibling, outside the selected installation root.
    scratch = Path(tempfile.mkdtemp(prefix='grt-', dir=root.parent))
    results, successes = {}, {}
    sentinel = b'existing runtime-tree output must remain unchanged\n'

    def command(tree, prefix, provider='host-install'):
        return [str(glue), 'python-host', '--provider', provider, '--runtime-tree', str(tree),
                '--output', str(prefix), '--json']

    try:
        ignored = clone_selected(root, scratch / 'ignored-unselected')
        (ignored / 'unselected-native.so').symlink_to(scratch / 'never-read-native-image')
        os.mkfifo(ignored / 'unselected-fifo')
        (ignored / 'lib/python3.13/unselected-extra.pyc').write_bytes(b'not an admitted bytecode cache')
        for name, tree in [('genuine-uv', root), ('genuine-uv-repeat', root),
                           ('stock-selected', clone_selected(root, scratch / 'stock')),
                           ('relocated-uv-quotes', clone_selected(root, scratch / 'uv \'"root', True)),
                           ('ignored-unselected', ignored)]:
            evidence = output / name
            evidence.mkdir()
            prefix = scratch / (name + '-prefix')
            input_audit = source if tree == root else audit_input(tree)
            result = invoke(command(tree, prefix), evidence)
            require(result.returncode == 0 and not result.stderr, 'valid tree preparation failed: ' + name)
            report = strict_json(result.stdout)
            observed = audit_output(prefix, report, input_audit)
            write_json(evidence / 'publication-audit.json', observed)
            (evidence / 'provenance.json').write_bytes((prefix / 'provenance.json').read_bytes())
            successes[name] = {'input_layout': input_audit['input_layout'], 'file_count': 1041,
                               'payload_bytes': 89479393, 'provenance': identity((prefix / 'provenance.json').read_bytes()),
                               'report': identity(result.stdout), 'interpreter_absent': not (tree / 'bin').exists()}
            remove_owned_tree(prefix)
        require((output / 'genuine-uv/provenance.json').read_bytes() ==
                (output / 'genuine-uv-repeat/provenance.json').read_bytes(), 'repeated tree provenance bytes differ')
        first = strict_json((output / 'genuine-uv/stdout.txt').read_bytes())
        repeated = strict_json((output / 'genuine-uv-repeat/stdout.txt').read_bytes())
        del first['prefix'], repeated['prefix']
        require(same_json(first, repeated), 'repeated report differs beyond its output prefix')

        cases = ['missing-library', 'oversized-library', 'corrupt-library', 'missing-cache', 'corrupt-cache',
                 'source-symlink', 'ancestor-symlink', 'source-fifo', 'modified-uv-source', 'wrong-uv-root',
                 'overlap-child', 'overlap-parent-alias', 'existing-file', 'existing-directory', 'existing-symlink',
                 'wrong-provider', 'mixed-artifact-input', 'relative-root', 'duplicate-tree-option']
        case_probe = scratch / 'CaseProbe'
        case_probe.mkdir()
        alias_probe = scratch / 'caseprobe'
        case_alias_supported = alias_probe.exists() and case_probe.samefile(alias_probe)
        skipped = {}
        if case_alias_supported:
            cases.append('case-alias-overlap')
        else:
            skipped['case-alias-overlap'] = {'status': 'skipped', 'reason': 'fixture filesystem is case-sensitive'}
        case_probe.rmdir()
        for name in cases:
            evidence = output / name
            evidence.mkdir()
            tree = clone_selected(root, scratch / name, name in ('modified-uv-source', 'wrong-uv-root'))
            prefix = scratch / (name + '-prefix')
            arguments = command(tree, prefix)
            before = None
            if name == 'missing-library':
                (tree / LIBRARY).unlink()
            elif name == 'oversized-library':
                (tree / LIBRARY).unlink()
                with (tree / LIBRARY).open('xb') as stream:
                    stream.truncate(LIBRARY_IDENTITY['size'] + 1)
            elif name == 'corrupt-library':
                b = bytearray((tree / LIBRARY).read_bytes()); b[0] ^= 1
                replacement(tree / LIBRARY, b)
            elif name in ('missing-cache', 'corrupt-cache'):
                cache = next(path for path in selected_contract() if path.endswith('.pyc'))
                path = tree / cache
                if name == 'missing-cache':
                    path.unlink()
                else:
                    b = bytearray(path.read_bytes()); b[-1] ^= 1
                    replacement(path, b)
            elif name == 'source-symlink':
                path = tree / 'lib/python3.13/abc.py'; path.unlink(); path.symlink_to(root / 'lib/python3.13/abc.py')
            elif name == 'ancestor-symlink':
                path = tree / 'lib/python3.13/encodings'; shutil.rmtree(path); path.symlink_to(root / 'lib/python3.13/encodings', target_is_directory=True)
            elif name == 'source-fifo':
                path = tree / 'lib/python3.13/abc.py'; path.unlink(); os.mkfifo(path)
            elif name == 'modified-uv-source':
                replacement(tree / SYSCONFIG, (tree / SYSCONFIG).read_bytes() + b'# not the observed uv source\n')
            elif name == 'wrong-uv-root':
                replacement(tree / SYSCONFIG, uv_sysconfig(scratch / 'another-root'))
            elif name == 'overlap-child':
                prefix = tree / 'publication'; arguments = command(tree, prefix)
                (tree / LIBRARY).unlink()  # overlap must reject before opening this missing selected input
            elif name == 'overlap-parent-alias':
                alias = scratch / 'parent-alias'; alias.symlink_to(tree, target_is_directory=True)
                prefix = alias / 'publication'; arguments = command(tree, prefix)
                (tree / LIBRARY).unlink()
            elif name == 'case-alias-overlap':
                alias = tree.with_name(tree.name.upper())
                require(alias.samefile(tree), 'case alias no longer identifies the owned selected tree')
                prefix = tree / 'publication'
                arguments = command(alias, prefix)
            elif name == 'existing-file':
                prefix.write_bytes(sentinel); before = identity(sentinel)
            elif name == 'existing-directory':
                prefix.mkdir(); (prefix / 'sentinel.txt').write_bytes(sentinel); before = identity(sentinel)
            elif name == 'existing-symlink':
                protected = scratch / 'protected-file'; protected.write_bytes(sentinel); prefix.symlink_to(protected); before = identity(sentinel)
            elif name == 'wrong-provider':
                arguments = command(tree, prefix, 'host-full')
            elif name == 'mixed-artifact-input':
                arguments.extend(['--pbs-install-only', str(scratch / 'not-consulted.tar.gz')])
            elif name == 'relative-root':
                arguments[arguments.index('--runtime-tree') + 1] = 'relative-runtime-root'
            elif name == 'duplicate-tree-option':
                arguments.extend(['--runtime-tree', str(tree)])
            result = invoke(arguments, evidence)
            require(result.returncode != 0 and not result.stdout and result.stderr, 'hostile tree control was accepted: ' + name)
            if before:
                protected = prefix / 'sentinel.txt' if name == 'existing-directory' else (
                    scratch / 'protected-file' if name == 'existing-symlink' else prefix)
                require(same_json(regular_identity(protected, len(sentinel))[0], before), 'existing output changed: ' + name)
                require(prefix.is_symlink() if name == 'existing-symlink' else not prefix.is_symlink(), 'existing output kind changed')
                (evidence / 'sentinel.txt').write_bytes(protected.read_bytes())
            else:
                require(not prefix.exists() and not prefix.is_symlink(), 'hostile input created an output: ' + name)
            if name.startswith('overlap-') or name == 'case-alias-overlap':
                require(b'overlap' in result.stderr.lower(), 'physical input/output overlap was not rejected')
            results[name] = {'exit_status': result.returncode, 'diagnostic': result.stderr.decode('utf-8'),
                             'output_protected': True, 'output_before': before, 'output_after': before,
                             'input_interpreters_absent': not (tree / 'bin').exists()}
            remove_owned_tree(tree)
        require(same_json(source, audit_input(root)), 'hostile controls changed the original selected input')
        require(source_metadata == {name: (stat.S_IMODE((root / name).lstat().st_mode), (root / name).lstat().st_mtime_ns)
                                    for name in source['selected_files']},
                'hostile controls changed original selected input permissions or mtimes')
        report = {'schema_version': 0, 'glue': binary, 'input_audit': identity((output / 'selected-input-audit.json').read_bytes()),
                  'valid_preparations': len(successes), 'hostile_controls': len(results), 'successes': successes,
                  'results': results, 'source_selected_files_unchanged': True,
                  'skipped_controls': skipped, 'case_alias_control_executed': case_alias_supported,
                  'source_selected_file_modes_times_unchanged': True,
                  'large_payload_trees_retained': False, 'input_interpreter_executions': 0}
        write_json(output / 'audit.json', report)
        return {key: report[key] for key in ('valid_preparations', 'hostile_controls', 'source_selected_files_unchanged')}
    finally:
        remove_owned_tree(scratch)


def install(args):
    output = args.output.absolute()
    artifact, uv = args.pbs_install_only.absolute(), args.uv.absolute()
    require(not output.exists() and not output.is_symlink() and output.parent.is_dir(), 'installer output must be a new directory with an existing parent')
    require(same_json(regular_identity(artifact, ARTIFACT['size'])[0], {key: ARTIFACT[key] for key in ('size', 'sha256')}),
            'installer artifact differs from the exact unstripped producer pin')
    uv_identity = regular_identity(uv, 256 * 1024 * 1024)[0]
    if sys.platform == 'linux':
        uv_pin = strict_json((HERE / 'uv-pins.json').read_bytes())
        require(uv_pin['version'] == '0.12.23' and uv_pin['target'] == 'aarch64-unknown-linux-gnu' and
                same_json(uv_identity, {key: uv_pin['binary'][key] for key in ('size', 'sha256')}),
                'Linux uv binary differs from the authenticated pinned release')
    environment = {key: value for key, value in os.environ.items() if not key.startswith('UV_')}
    version = subprocess.run([str(uv), '--version'], capture_output=True, env=environment, check=True, timeout=30)
    require(version.stdout.startswith(b'uv 0.12.23 ') or version.stdout == b'uv 0.12.23\n', 'installer uv version must be pinned 0.12.23')
    output.mkdir()
    catalog = {KEY: {'name': 'cpython', 'arch': {'family': 'aarch64', 'variant': None}, 'os': 'linux', 'libc': 'gnu',
                     'major': 3, 'minor': 13, 'patch': 16, 'prerelease': None, 'url': artifact.as_uri(),
                     'sha256': ARTIFACT['sha256'], 'variant': None, 'build': '20261009'}}
    catalog_path = output / 'download-metadata.json'
    write_json(catalog_path, catalog)
    command = [str(uv), 'python', 'install', KEY, '--install-dir', str(output / 'install'),
               '--cache-dir', str(output / 'cache'), '--python-downloads-json-url', str(catalog_path),
               '--no-bin', '--no-registry', '--offline', '--no-config', '--no-progress']
    write_json(output / 'command.json', command)
    result = subprocess.run(command, capture_output=True, env=environment, check=False, timeout=120)
    (output / 'stdout.txt').write_bytes(result.stdout)
    (output / 'stderr.txt').write_bytes(result.stderr)
    (output / 'exit-status.txt').write_text(str(result.returncode) + '\n', encoding='ascii')
    (output / 'uv-version.stdout.txt').write_bytes(version.stdout)
    require(result.returncode == 0, 'genuine uv installation failed; see ' + str(output / 'stderr.txt'))
    root = output / 'install' / KEY
    source = audit_input(root)
    require(source['input_layout'] == 'uv-0.12.23', 'genuine uv installation did not create the expected selected layout')
    require((root / 'BUILD').read_bytes() == b'20261009' and
            (root / 'lib/python3.13/EXTERNALLY-MANAGED').read_bytes() ==
            b'[externally-managed]\nError=This Python installation is managed by uv and should not be modified.\n',
            'genuine uv producer markers differ')
    interpreter_identity = regular_identity(root / 'bin/python3.13', 128 * 1024 * 1024)[0]
    if args.remove_bin:
        require(stat.S_ISDIR((root / 'bin').lstat().st_mode), 'owned uv interpreter directory is not ordinary')
        shutil.rmtree(root / 'bin')
        require(not (root / 'bin').exists() and not (root / 'bin').is_symlink(), 'owned uv interpreter directory remains')
        require(same_json(source, audit_input(root)), 'selected uv bytes changed when removing interpreter aliases')
    report = {'schema_version': 0, 'uv': uv_identity, 'uv_version': version.stdout.decode('ascii').strip(),
              'reference_artifact': ARTIFACT, 'catalog': identity(catalog_path.read_bytes()), 'command': command,
              'installation_exit_status': result.returncode, 'selected_input_audit': source,
              'interpreter_identity_before_removal': interpreter_identity, 'input_interpreters_removed': args.remove_bin,
              'sysconfig_adjustments': ADJUSTMENTS_IDENTITY, 'expected_stock_sysconfig': STOCK_IDENTITY,
              'runtime_execution_observed': False, 'default_uv_stripped_runtime_accepted': False}
    write_json(output / 'installation-provenance.json', report)
    return {'root': str(root), 'input_layout': source['input_layout'], 'selected_files': 1041,
            'selected_input_bytes': source['selected_input_bytes'], 'input_interpreters_removed': args.remove_bin,
            'provenance': str(output / 'installation-provenance.json')}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    subparsers = parser.add_subparsers(dest='mode', required=True)
    installer = subparsers.add_parser('install')
    installer.add_argument('--uv', required=True, type=Path)
    installer.add_argument('--pbs-install-only', required=True, type=Path)
    installer.add_argument('--output', required=True, type=Path)
    installer.add_argument('--remove-bin', action='store_true')
    auditor = subparsers.add_parser('audit-input')
    auditor.add_argument('--runtime-tree', required=True, type=Path)
    auditor.add_argument('--output', required=True, type=Path)
    publisher = subparsers.add_parser('audit-output')
    publisher.add_argument('--runtime-tree', required=True, type=Path)
    publisher.add_argument('--prefix', required=True, type=Path)
    publisher.add_argument('--report', required=True, type=Path)
    publisher.add_argument('--output', required=True, type=Path)
    control = subparsers.add_parser('controls')
    control.add_argument('--runtime-tree', required=True, type=Path)
    control.add_argument('--glue', required=True, type=Path)
    control.add_argument('--output', required=True, type=Path)
    args = parser.parse_args()
    try:
        if args.mode == 'install':
            result = install(args)
        elif args.mode == 'audit-input':
            result = audit_input(args.runtime_tree)
            write_json(args.output, result)
            result = {key: result[key] for key in ('root', 'input_layout', 'selected_file_count', 'selected_input_bytes', 'sysconfig_normalized')}
        elif args.mode == 'audit-output':
            source = audit_input(args.runtime_tree)
            result = audit_output(args.prefix, strict_json(args.report.read_bytes()), source)
            write_json(args.output, result)
            result = {key: result[key] for key in ('input_layout', 'file_count', 'payload_bytes', 'directory_count',
                      'all_file_bytes_modes_times_verified', 'all_directory_modes_times_verified')}
        else:
            result = controls(args)
        print(json.dumps(result, sort_keys=True))
        return 0
    except (ValueError, OSError, subprocess.SubprocessError) as error:
        print('runtime tree fixture: ' + str(error), file=sys.stderr)
        return 1


if __name__ == '__main__':
    raise SystemExit(main())
