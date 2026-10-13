#!/usr/bin/env python3
"""Independently audit product runtime templates and their publication controls.

The oracle reads checked-in upstream resource identities and helper sources.
It does not import a product API, run Python application code, discover a host
installation, or extract an upstream archive. Optional installed-input builds
use the genuinely installed fixture prepared by python-venv-ingestion.
"""
from __future__ import annotations

import argparse
import gzip
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import stat
import struct
import subprocess
import sys
import zipfile

HERE = Path(__file__).resolve().parent
FIXTURES = HERE.parent
PROVIDERS = ('bundled', 'host-full', 'host-install')
OLD_NAMES = {'bundled': 'bundled', 'host-full': 'host', 'host-install': 'install-host'}
BUILDS = {
    'bundled': 'pbs-20261009-cpython-3.13.16-pgo-lto-bundled-metadata-apps-v1',
    'host-full': 'pbs-20261009-cpython-3.13.16-pgo-lto-host-metadata-apps-v1',
    'host-install': 'pbs-20261009-cpython-3.13.16-pgo-lto-host-install-metadata-apps-v1',
}
FULL_BYTES = 95632430
FULL_SHA = '8907ec2f181f0fc5cd08b9d897d36159432405af78f68f8faca728f48940e0ca'
FROZEN_BYTES = 139523
FROZEN_SHA = '6a41fc38141d45c5197adfc1b0ee740c6244ea681742c205b8aa7b8449d865d7'
LIBRARY_BYTES = 73563968
LIBRARY_SHA = '42be968275d5be2d9e632ec9ef6790dd2c10f1d4a710ad1028fc2b687242f219'
TARGET = {'abi': {'family': 'glibc', 'minimum_version': '2.36'},
          'arch': 'aarch64', 'cpu_features': [], 'minimum_os_version': '7.1.4',
          'os': 'linux', 'page_sizes': [4096]}
SENTINEL = b'existing output must remain unchanged\n'
PLACEHOLDER = b"raise RuntimeError('This is a Python runtime template; use glue build-python with its manifest.json and root directory to package an application.')\n"


def require(condition, message):
    if not condition:
        raise ValueError(message)


def sha(payload):
    return hashlib.sha256(payload).hexdigest()


def identity(payload):
    return {'size': len(payload), 'sha256': sha(payload)}


def file_identity(path, maximum=None):
    before = path.lstat()
    require(stat.S_ISREG(before.st_mode), 'oracle input must be a regular file: ' + str(path))
    require(maximum is None or before.st_size <= maximum, 'oracle input exceeds its bound: ' + str(path))
    digest, size = hashlib.sha256(), 0
    with path.open('rb') as stream:
        while block := stream.read(65536):
            size += len(block)
            require(maximum is None or size <= maximum, 'oracle input grew beyond its bound: ' + str(path))
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


def source_pins():
    raw = (FIXTURES / 'python-imports/stdlib-pins.json').read_bytes()
    pins = strict_json(raw)
    require(pins['schema_version'] == 0 and pins['artifact_sha256'] == FULL_SHA,
            'independent source inventory artifact identity differs')
    require(len(pins['files']) == 2174 and sum(value['size'] for value in pins['files'].values()) == 39158056,
            'independent source inventory count/bytes differ')
    return pins['files']


def helper_specs():
    return {name: identity((FIXTURES / relative).read_bytes()) | {'compression': 'deflate'}
            for name, relative in (
                ('python/archive-importer.py', 'python-imports/bootstrap.py'),
                ('python/archive-metadata.py', 'python-metadata/bootstrap.py'))}


def provider_specs(provider):
    specs = helper_specs()
    if provider == 'bundled':
        specs.update({'stdlib/' + name: value | {'compression': 'deflate'}
                      for name, value in source_pins().items()})
        specs['python/libpython3.13.so.1.0'] = {
            'size': LIBRARY_BYTES, 'sha256': LIBRARY_SHA, 'compression': 'stored'}
        specs['python/frozen.json'] = {
            'size': FROZEN_BYTES, 'sha256': FROZEN_SHA, 'compression': 'stored'}
    return dict(sorted(specs.items()))


def expected_runtime(provider, prefix):
    if provider == 'bundled':
        provisioning = {
            'mode': 'bundled', 'provider': 'python_build_standalone',
            'runtime_library': 'python/libpython3.13.so.1.0', 'stdlib': 'python/frozen.json',
            'source': {'release': '20261009', 'revision': 'ccc07c40c2731bfb459c119f2388f65a5a470de6',
                       'artifact': 'cpython-3.13.16+20261009-aarch64-unknown-linux-gnu-pgo+lto-full.tar.zst',
                       'sha256': FULL_SHA, 'variant': 'pgo+lto-full/bundled-metadata-apps-v1'},
        }
    else:
        provisioning = {'mode': 'host', 'discovery': 'explicit_paths',
                        'runtime_library': prefix + '/lib/libpython3.13.so.1.0',
                        'stdlib': prefix + '/lib/python3.13'}
    return {'abi': {'debug': False, 'gil': 'conventional', 'language': 'python',
                    'version': {'major': 3, 'minor': 13, 'patch': 16}},
            'build_id': BUILDS[provider], 'provisioning': provisioning,
            'required_features': [], 'target': 'linux-arm64'}


def expected_manifest(provider, prefix, specs, app_id='python.runtime.template'):
    return {'schema_version': 0, 'app_id': app_id, 'entrypoint': 'launch',
            'components': {'launch': {'entry_point': 'app/main.py', 'native_modules': [], 'runtime': 'python'}},
            'targets': {'linux-arm64': TARGET}, 'runtimes': {'python': expected_runtime(provider, prefix)},
            'native_modules': {}, 'host_imports': {}, 'resources': specs}


def tree_files(root):
    require(root.is_dir() and not root.is_symlink(), 'template root must be an ordinary directory')
    result = {}
    for path in sorted(root.rglob('*')):
        mode = path.lstat().st_mode
        require(stat.S_ISDIR(mode) or stat.S_ISREG(mode), 'template root contains a link/special file: ' + str(path))
        if stat.S_ISREG(mode):
            result[path.relative_to(root).as_posix()] = path
    return result


def audit_template(directory, provider, prefix, report):
    require(directory.is_dir() and not directory.is_symlink(), 'template output is not an ordinary directory')
    require({path.name for path in directory.iterdir()} == {'manifest.json', 'provenance.json', 'root'},
            'template top-level inventory differs')
    manifest_bytes = (directory / 'manifest.json').read_bytes()
    manifest = strict_json(manifest_bytes)
    specs = provider_specs(provider)
    entry = (directory / 'root/app/main.py').read_bytes()
    require(entry == PLACEHOLDER, 'fixed placeholder source differs')
    specs['app/main.py'] = identity(entry) | {'compression': 'stored'}
    require(manifest == expected_manifest(provider, prefix, specs), 'template manifest differs from independent exact provider contract')
    resources = tree_files(directory / 'root')
    require(set(resources) == set(specs), 'template resource inventory differs')
    for name, path in resources.items():
        require(file_identity(path, specs[name]['size']) == {key: specs[name][key] for key in ('size', 'sha256')},
                'template resource identity differs: ' + name)
    for name, relative in (
            ('python/archive-importer.py', 'python-imports/bootstrap.py'),
            ('python/archive-metadata.py', 'python-metadata/bootstrap.py')):
        require(resources[name].read_bytes() == (FIXTURES / relative).read_bytes(), 'compiled helper source differs: ' + name)
    provenance_bytes = (directory / 'provenance.json').read_bytes()
    provenance = strict_json(provenance_bytes)
    require(report['provider'] == provider and report['provenance'] == provenance,
            'stdout provider/provenance differs from retained provenance')
    require(report['manifest'] == {'path': 'manifest.json'} | identity(manifest_bytes),
            'stdout manifest file identity differs')
    require(report['provenance_file'] == {'path': 'provenance.json'} | identity(provenance_bytes),
            'stdout provenance file identity differs')
    require(report['resources'] == specs and report['resource_count'] == len(specs) and
            report['uncompressed_bytes'] == sum(value['size'] for value in specs.values()),
            'stdout resource inventory/count/bytes differ')
    audit_provenance(provenance, provider, prefix, manifest, specs)
    return {'manifest_file': identity(manifest_bytes), 'provenance_file': identity(provenance_bytes),
            'resource_count': len(specs), 'uncompressed_bytes': sum(value['size'] for value in specs.values()),
            'resources': specs, 'provenance': provenance}


def audit_provenance(provenance, provider, prefix, manifest, specs):
    def inventory(relative, count, total, artifact):
        payload = (FIXTURES / relative).read_bytes()
        files = strict_json(payload)['files']
        require(len(files) == count and sum(value['size'] for value in files.values()) == total,
                'independent inventory count/bytes differ: ' + relative)
        return {'identity': {'path': 'fixtures/' + relative} | identity(payload),
                'files': count, 'uncompressed_bytes': total, 'artifact_sha256': artifact}

    install_sha = '397ca401f416c3c99330a6be16d735d0cbeaf53e82070b80395b2fb4a8891f34'
    install = provider == 'host-install'
    expected = {
        'schema_version': 0, 'provider': provider, 'host_prefix': prefix,
        'host_prerequisites_verified': False, 'runtime_execution_observed': False,
        'inspected_artifact': None, 'inspected_artifact_entries': None, 'frozen_bootstrap': None,
        'producer': {
            'release': '20261009', 'revision': 'ccc07c40c2731bfb459c119f2388f65a5a470de6',
            'python_version': '3.13.16', 'target_triple': 'aarch64-unknown-linux-gnu',
            'build_options': 'pgo+lto', 'gil': 'conventional', 'debug': False,
            'runtime_library_sha256': LIBRARY_SHA,
            'metadata_sha256': '2be93f8346d647c46a9c5133cddb403d757a564ce1ec4039239ce9008fd763dc',
            'executable_sha256': '1abe8738dd82558ba7884a0dd00bb8e9561ad0b85a3ddd3d755999c2dd878d45',
            'bytecode_magic': 'f30d0d0a', 'cache_tag': 'cpython-313',
        },
        'source_inventory': inventory('python-install-host-source-apps/source-pins.json', 1037, 15894268, install_sha)
        if install else inventory('python-imports/stdlib-pins.json', 2174, 39158056, FULL_SHA),
        'cache_inventory': inventory('python-install-host-source-apps/cache-pins.json', 3, 21157, install_sha) if install else None,
        'selected_stdlib_sources': 2174 if provider == 'bundled' else 0,
        'manifest_sha256': sha(json.dumps(manifest, sort_keys=True, separators=(',', ':'), ensure_ascii=False).encode('utf-8')),
        'resources': specs,
    }
    if provider == 'bundled':
        expected.update({
            'inspected_artifact': {
                'filename': 'cpython-3.13.16+20261009-aarch64-unknown-linux-gnu-pgo+lto-full.tar.zst',
                'size': FULL_BYTES, 'sha256': FULL_SHA,
                'url': 'https://github.com/astral-sh/python-build-standalone/releases/download/20261009/cpython-3.13.16%2B20261009-aarch64-unknown-linux-gnu-pgo%2Blto-full.tar.zst'},
            'inspected_artifact_entries': 6574,
            'frozen_bootstrap': {'path': 'python/frozen.json', 'size': FROZEN_BYTES, 'sha256': FROZEN_SHA},
        })
    require(provenance == expected, 'constructor provenance differs from independent pinned input/declaration facts')


def read_archive(path):
    with path.open('rb') as stream:
        locator = stream.read(64)
        require(len(locator) == 64 and locator[:8] == b'GLUERS00' and locator[8:16] == b'\0' * 8,
                'generated application locator differs')
        length, payload = struct.unpack_from('<QQ', locator, 16)
        require(0 < length <= 2 * 1024 * 1024 and 64 + length + payload == path.stat().st_size,
                'generated application regions differ')
        manifest_bytes = stream.read(length)
        require(hashlib.sha256(manifest_bytes).digest() == locator[32:64], 'generated application manifest digest differs')
    return strict_json(manifest_bytes)


def audit_application(path, provider, prefix):
    application = strict_json((FIXTURES / 'python-venv-ingestion/expected-inventory.json').read_bytes())['files']
    specs = provider_specs(provider)
    specs.update({name: value | {'compression': 'stored'} for name, value in application.items()})
    manifest = read_archive(path)
    require(manifest == expected_manifest(provider, prefix, specs, 'distribution.metadata'),
            'product application differs from independent normalized provider/application contract')
    with zipfile.ZipFile(path) as archive:
        require(len(archive.infolist()) == len(specs) and set(archive.namelist()) == set(specs),
                'product application ZIP inventory differs')
        for name, spec in specs.items():
            member = archive.getinfo(name)
            require(member.file_size == spec['size'] and member.compress_type == (
                zipfile.ZIP_STORED if spec['compression'] == 'stored' else zipfile.ZIP_DEFLATED),
                'product application ZIP declaration differs: ' + name)
            digest, size = hashlib.sha256(), 0
            with archive.open(name) as stream:
                while block := stream.read(65536):
                    size += len(block)
                    require(size <= spec['size'], 'generated application resource exceeds bound: ' + name)
                    digest.update(block)
            require(size == spec['size'] and digest.hexdigest() == spec['sha256'],
                    'generated application resource differs: ' + name)
            if name in application:
                require(archive.read(name) == (FIXTURES / 'python-venv-ingestion/expected-input' / name).read_bytes(),
                        'normalized application bytes differ: ' + name)
    return file_identity(path, 128 * 1024 * 1024)


def invoke(command, directory):
    result = subprocess.run(command, capture_output=True, check=False)
    (directory / 'command.json').write_text(json.dumps(command, indent=2) + '\n', encoding='utf-8')
    (directory / 'stdout.txt').write_bytes(result.stdout)
    (directory / 'stderr.txt').write_bytes(result.stderr)
    (directory / 'exit-status.txt').write_text(str(result.returncode) + '\n', encoding='utf-8')
    return result


def template_command(args, provider, output, prefix=None, full=None, frozen=None):
    command = [str(args.glue), 'python-template', '--provider', provider]
    if provider == 'bundled':
        command += ['--pbs-full', str(args.full if full is None else full),
                    '--frozen-bootstrap', str(args.frozen if frozen is None else frozen)]
    else:
        command += ['--host-prefix', prefix if prefix is not None else getattr(args, provider.replace('-', '_') + '_prefix')]
    return command + ['--output', str(output), '--json']


def build_command(args, stage, output):
    return [str(args.glue), 'build-python', '--provider-template', str(stage / 'manifest.json'),
            '--provider-root', str(stage / 'root'), '--app', str(args.prepared / 'application'),
            '--venv', str(args.prepared / 'venv'), '--app-id', 'distribution.metadata',
            '--entry', 'app/main.py', '--output', str(output), '--json']


def generated_stage(args, relative, directory):
    if args.scratch is None:
        return directory / 'template'
    result = args.scratch / relative / 'template'
    result.parent.mkdir(parents=True, exist_ok=False)
    return result


def retain_template(stage, directory):
    retained = directory / 'template'
    if stage != retained:
        retained.mkdir()
        for name in ('manifest.json', 'provenance.json'):
            shutil.copyfile(stage / name, retained / name)
        shutil.rmtree(stage)
    else:
        shutil.rmtree(stage / 'root')


def capture_control(args, results, name, command, directory, output, protected=None):
    result = invoke(command, directory)
    if protected is None:
        protected = lambda: not output.exists() and not output.is_symlink()
    require(result.returncode == 1 and not result.stdout and bool(result.stderr) and protected(),
            'control did not reject with protected output: ' + name + '; see ' + str(directory))
    results[name] = {'exit_status': result.returncode, 'stderr': result.stderr.decode('utf-8'), 'output_protected': True}


def generation_controls(args):
    results = {}
    controls = args.output / 'controls'
    controls.mkdir()
    for provider in PROVIDERS[1:]:
        for name, prefix in (
                ('root', '/'), ('relative', 'relative/Python'), ('trailing-slash', '/missing/Python/'),
                ('empty-component', '/missing//Python'), ('dot-component', '/missing/./Python'),
                ('traversal', '/missing/../Python'), ('backslash', '/missing\\Python'),
                ('non-ascii', '/missing/Pythön'), ('control-character', '/missing/Python\n'),
                ('path-budget', '/' + 'a' * 4090), ('ownership-budget', '/' + '/'.join(['a'] * 100))):
            case = provider + '-' + name
            directory = controls / case
            directory.mkdir()
            output = directory / 'template'
            capture_control(args, results, case, template_command(args, provider, output, prefix), directory, output)
    for name in ('existing-file', 'existing-directory', 'existing-symlink', 'existing-dangling-symlink', 'missing-parent', 'parent-file'):
        directory = controls / name
        directory.mkdir()
        output = directory / 'template'
        protected = None
        if name == 'existing-file':
            output.write_bytes(SENTINEL)
            protected = lambda output=output: output.is_file() and not output.is_symlink() and output.read_bytes() == SENTINEL
        elif name == 'existing-directory':
            output.mkdir()
            (output / 'sentinel').write_bytes(SENTINEL)
            protected = lambda output=output: {path.name for path in output.iterdir()} == {'sentinel'} and (output / 'sentinel').read_bytes() == SENTINEL
        elif name in ('existing-symlink', 'existing-dangling-symlink'):
            target = directory / 'protected-target'
            if name == 'existing-symlink':
                target.mkdir()
                (target / 'sentinel').write_bytes(SENTINEL)
            output.symlink_to(target, target_is_directory=True)
            protected = lambda output=output, target=target, name=name: output.is_symlink() and os.readlink(output) == str(target) and (
                ({path.name for path in target.iterdir()} == {'sentinel'} and (target / 'sentinel').read_bytes() == SENTINEL)
                if name == 'existing-symlink' else not target.exists())
        elif name == 'missing-parent':
            output = directory / 'absent/template'
            protected = lambda output=output: not output.parent.exists()
        else:
            parent = directory / 'parent'
            parent.write_bytes(SENTINEL)
            output = parent / 'template'
            protected = lambda parent=parent: parent.is_file() and parent.read_bytes() == SENTINEL
        capture_control(args, results, name, template_command(args, 'host-full', output), directory, output, protected)
    for name in ('full-missing', 'full-too-small', 'full-directory', 'full-symlink', 'full-corrupt',
                 'frozen-missing', 'frozen-empty', 'frozen-directory', 'frozen-symlink', 'frozen-too-large', 'frozen-corrupt'):
        directory = controls / name
        directory.mkdir()
        full, frozen = args.full, args.frozen
        input_directory = directory
        if args.scratch is not None:
            input_directory = args.scratch / 'controls' / name
            input_directory.mkdir(parents=True)
        if name.startswith('full-'):
            full = input_directory / 'input.tar.zst'
            if name == 'full-too-small':
                full.write_bytes(b'not the pinned full artifact\n')
            elif name == 'full-directory':
                full.mkdir()
            elif name == 'full-symlink':
                full.symlink_to(args.full)
            elif name == 'full-corrupt':
                shutil.copyfile(args.full, full)
                with full.open('r+b') as stream:
                    stream.seek(65536)
                    original = stream.read(1)
                    require(len(original) == 1, 'full corruption control source is truncated')
                    stream.seek(65536)
                    stream.write(bytes([original[0] ^ 1]))
        else:
            frozen = input_directory / 'frozen.json'
            if name == 'frozen-empty':
                frozen.write_bytes(b'')
            elif name == 'frozen-directory':
                frozen.mkdir()
            elif name == 'frozen-symlink':
                frozen.symlink_to(args.frozen)
            elif name == 'frozen-too-large':
                frozen.write_bytes(args.frozen.read_bytes() + b' ')
            elif name == 'frozen-corrupt':
                payload = bytearray(args.frozen.read_bytes())
                payload[0] ^= 1
                frozen.write_bytes(payload)
        output = directory / 'template'
        capture_control(args, results, name, template_command(args, 'bundled', output, full=full, frozen=frozen), directory, output)
        # Retain command/error/identity, not an unnecessary second 96 MiB input.
        for path in (full, frozen):
            if path.parent == input_directory and path.is_file() and not path.is_symlink():
                (directory / (path.name + '.identity.json')).write_text(json.dumps(file_identity(path), sort_keys=True) + '\n')
                path.unlink()
    parser_cases = {
        'unknown-provider': ['--provider', 'future', '--output'],
        'missing-provider': ['--output'],
        'missing-host-prefix': ['--provider', 'host-full', '--output'],
        'host-with-pbs-input': ['--provider', 'host-full', '--host-prefix', '/unavailable/Python', '--pbs-full', str(args.full), '--output'],
        'bundled-with-host-prefix': ['--provider', 'bundled', '--pbs-full', str(args.full), '--frozen-bootstrap', str(args.frozen), '--host-prefix', '/unavailable/Python', '--output'],
        'duplicate-provider': ['--provider', 'host-full', '--provider', 'host-install', '--host-prefix', '/unavailable/Python', '--output'],
    }
    for name, flags in parser_cases.items():
        directory = controls / name
        directory.mkdir()
        output = directory / 'template'
        capture_control(args, results, name, [str(args.glue), 'python-template', *flags, str(output), '--json'], directory, output)
    return results


def audit(args):
    require(file_identity(args.full, FULL_BYTES) == {'size': FULL_BYTES, 'sha256': FULL_SHA}, 'audit full input pin differs')
    require(file_identity(args.frozen, FROZEN_BYTES) == {'size': FROZEN_BYTES, 'sha256': FROZEN_SHA}, 'audit frozen input pin differs')
    args.output.mkdir(parents=True, exist_ok=False)
    if args.scratch is not None:
        args.scratch.mkdir(parents=True, exist_ok=False)
    results = {}
    for provider in PROVIDERS:
        directory = args.output / provider
        directory.mkdir()
        stage = generated_stage(args, provider, directory)
        result = invoke(template_command(args, provider, stage), directory)
        require(result.returncode == 0 and not result.stderr, 'valid template failed: ' + provider + '; see ' + str(directory))
        prefix = None if provider == 'bundled' else getattr(args, provider.replace('-', '_') + '_prefix')
        report = strict_json(result.stdout)
        results[provider] = audit_template(stage, provider, prefix, report)
        repeated = args.output / 'repeated' / provider
        repeated.mkdir(parents=True)
        repeated_stage = generated_stage(args, 'repeated/' + provider, repeated)
        repeated_result = invoke(template_command(args, provider, repeated_stage), repeated)
        require(repeated_result.returncode == 0 and not repeated_result.stderr, 'repeated template failed: ' + provider)
        require(strict_json(repeated_result.stdout) == report and repeated_result.stdout == result.stdout,
                'repeated stdout report differs: ' + provider)
        repeated_audit = audit_template(repeated_stage, provider, prefix, strict_json(repeated_result.stdout))
        require(repeated_audit == results[provider], 'repeated staged provider differs: ' + provider)
        retain_template(repeated_stage, repeated)
        results[provider]['repeated_byte_identity'] = True
        if args.prepared is not None:
            build_directory = directory / 'build'
            build_directory.mkdir()
            application = (directory if args.scratch is None else stage.parent) / 'application.glue'
            built = invoke(build_command(args, stage, application), build_directory)
            require(built.returncode == 0 and not built.stderr, 'installed-input build failed: ' + provider)
            results[provider]['application'] = audit_application(application, provider, prefix)
            results[provider]['build_report'] = strict_json(built.stdout)
            (directory / 'application.manifest.json').write_text(json.dumps(read_archive(application), sort_keys=True, separators=(',', ':')) + '\n')
            if args.legacy_templates is not None:
                legacy = args.legacy_templates / OLD_NAMES[provider]
                legacy_directory = directory / 'legacy-build'
                legacy_directory.mkdir()
                legacy_archive = (legacy_directory if args.scratch is None else stage.parent) / 'legacy-application.glue'
                legacy_built = invoke(build_command(args, legacy, legacy_archive), legacy_directory)
                require(legacy_built.returncode == 0 and not legacy_built.stderr, 'legacy installed-input build failed: ' + provider)
                require(audit_application(legacy_archive, provider, prefix) == results[provider]['application'],
                        'legacy/product application archive identities differ: ' + provider)
                results[provider]['legacy_archive_byte_identity'] = True
                legacy_archive.unlink()
            application.unlink()
        retain_template(stage, directory)
    # Explicitly declare a missing target installation. Successful construction
    # is required even though runtime prerequisites cannot possibly be verified.
    for provider in PROVIDERS[1:]:
        directory = args.output / (provider + '-missing-target')
        directory.mkdir()
        prefix = '/unavailable/Python runtime template target'
        stage = generated_stage(args, provider + '-missing-target', directory)
        result = invoke(template_command(args, provider, stage, prefix), directory)
        require(result.returncode == 0 and not result.stderr, 'missing target declaration failed: ' + provider)
        results[provider + '-missing-target'] = audit_template(stage, provider, prefix, strict_json(result.stdout))
        retain_template(stage, directory)
    controls = generation_controls(args)
    summary = {'schema_version': 0, 'valid_generations': 8, 'hostile_controls': len(controls),
               'application_builds': 3 if args.prepared else 0,
               'legacy_comparisons': 3 if args.legacy_templates and args.prepared else 0,
               'inputs': {'pbs_full': file_identity(args.full, FULL_BYTES), 'frozen_bootstrap': file_identity(args.frozen, FROZEN_BYTES)},
               'results': results, 'controls': controls}
    (args.output / 'audit.json').write_text(json.dumps(summary, indent=2, sort_keys=True) + '\n', encoding='utf-8')
    return summary


def audit_process_trace(path, program, host_prefix=None):
    opener = gzip.open if str(path).endswith('.gz') else open
    with opener(path, 'rt', encoding='utf-8') as stream:
        lines = stream.readlines()
    require(lines, 'process trace is empty')
    execs, exits = [], 0
    forbidden = {'clone', 'clone3', 'fork', 'vfork', 'execveat', 'socket', 'socketpair', 'connect', 'accept', 'accept4', 'bind', 'listen', 'sendto', 'sendmsg', 'recvfrom', 'recvmsg'}
    file_calls = {'open', 'openat', 'openat2', 'stat', 'lstat', 'newfstatat', 'statx', 'access', 'faccessat', 'faccessat2', 'readlink', 'readlinkat'}
    for line in lines:
        match = re.search(r'(?<![A-Za-z_])([A-Za-z_][A-Za-z_0-9]*)\(', line)
        if match:
            name = match.group(1)
            require(name not in forbidden, 'build process attempted child creation/network: ' + line.strip())
            if name == 'execve':
                match_exec = re.search(r'execve\(("(?:[^"\\]|\\.)*"), \[(.*)\], .*\)\s*=\s*0\s*$', line)
                require(match_exec is not None, 'build process execve is malformed/failed: ' + line.strip())
                executable = json.loads(match_exec.group(1))
                arguments = match_exec.group(2)
                require(executable == program and '"python-template"' in arguments,
                        'build process executed an unexpected command: ' + line.strip())
                execs.append(executable)
            if name in file_calls:
                paths = re.findall(r'"((?:[^"\\]|\\.)*)"', line)
                for value in paths:
                    decoded = json.loads('"' + value + '"')
                    require(not (host_prefix is not None and (decoded == host_prefix or decoded.startswith(host_prefix + '/'))),
                            'template generation looked up target provider: ' + line.strip())
        if '+++ exited with 0 +++' in line:
            exits += 1
        require('+++ killed by ' not in line, 'build process was killed')
    require(len(execs) == 1 and exits == 1, 'build process trace must contain exactly one successful execve and exit')
    return {'schema_version': 0, 'execve_count': len(execs), 'successful_exit_count': exits,
            'child_creation_count': 0, 'network_count': 0, 'target_provider_lookup_count': 0,
            'trace_identity': file_identity(path), 'program': program, 'host_prefix': host_prefix}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ('glue', 'full', 'frozen', 'output', 'prepared', 'legacy-templates', 'scratch'):
        parser.add_argument('--' + name, type=Path)
    parser.add_argument('--host-full-prefix', default='/build-target/host Python metadata')
    parser.add_argument('--host-install-prefix', default='/build-target/install Python metadata')
    parser.add_argument('--audit-process-trace', type=Path)
    parser.add_argument('--program')
    parser.add_argument('--host-prefix')
    args = parser.parse_args()
    for name in ('glue', 'full', 'frozen', 'output', 'prepared', 'legacy_templates', 'scratch', 'audit_process_trace'):
        value = getattr(args, name)
        if value is not None:
            setattr(args, name, value.absolute())
    try:
        if args.audit_process_trace is not None:
            require(args.program is not None, '--program is required for the process trace audit')
            print(json.dumps(audit_process_trace(args.audit_process_trace, args.program, args.host_prefix), sort_keys=True))
        else:
            require(all(getattr(args, name) is not None for name in ('glue', 'full', 'frozen', 'output')),
                    '--glue, --full, --frozen and --output are required for the generation audit')
            report = audit(args)
            print(json.dumps({name: report[name] for name in ('valid_generations', 'hostile_controls', 'application_builds', 'legacy_comparisons')}, sort_keys=True))
    except (OSError, ValueError, KeyError, TypeError, zipfile.BadZipFile) as error:
        print('runtime template audit failed: ' + str(error), file=sys.stderr)
        return 1
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
