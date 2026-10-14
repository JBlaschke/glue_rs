#!/usr/bin/env python3
"""Install and independently audit three unmodified pure Python wheels offline.

The product never invokes this fixture installer. Its independent oracle derives
all retained bytes from pinned upstream wheel payloads and deterministic RECORD
rewriting, then checks genuine pip installation, omissions and product archives.
"""
from __future__ import annotations

import argparse
import base64
import csv
import hashlib
import io
import json
import os
import re
from pathlib import Path, PurePosixPath
import shutil
import stat
import struct
import subprocess
import sys
import zipfile

HERE = Path(__file__).resolve().parent
APPLICATION = HERE / 'application/app/main.py'
PIN_FILE = HERE / 'wheel-pins.json'
PROJECTS = (('markdown-it-py', '4.2.0', 'markdown_it_py-4.2.0.dist-info'),
            ('mdit-py-plugins', '0.6.1', 'mdit_py_plugins-0.6.1.dist-info'),
            ('mdurl', '0.1.2', 'mdurl-0.1.2.dist-info'))
OUTPUT = b'glue python real packages ok: markdown-it-py=4.2.0 mdit-py-plugins=0.6.1 mdurl=0.1.2 render=tokens=metadata=resources=entrypoint\n'


def require(condition, message):
    if not condition:
        raise ValueError(message)


def identity(payload):
    return {'size': len(payload), 'sha256': hashlib.sha256(payload).hexdigest()}


def strict_json(payload):
    def pairs(items):
        result = {}
        for key, value in items:
            require(key not in result, 'duplicate JSON field: ' + key)
            result[key] = value
        return result

    return json.loads(payload, object_pairs_hook=pairs,
                      parse_constant=lambda value: (_ for _ in ()).throw(ValueError('nonfinite JSON: ' + value)))


def typed_equal(left, right):
    """Keep JSON booleans, integers and floats distinct at every nesting level."""
    if type(left) is not type(right):
        return False
    if type(left) is dict:
        return set(left) == set(right) and all(typed_equal(left[key], right[key]) for key in left)
    if type(left) is list:
        return len(left) == len(right) and all(typed_equal(a, b) for a, b in zip(left, right))
    return left == right


def object_keys(value, keys, label):
    require(type(value) is dict and set(value) == set(keys), label + ' exact object fields differ')


def unsigned(value, label, minimum=0, maximum=(1 << 64) - 1):
    require(type(value) is int and minimum <= value <= maximum, label + ' must be a bounded integer')


def digest_string(value, label):
    require(type(value) is str and re.fullmatch('[0-9a-f]{64}', value) is not None, label + ' must be canonical SHA256')


def validate_report_schema(report):
    object_keys(report, {'build', 'package_input', 'distributions', 'inputs', 'omissions'}, 'build report')
    require(type(report['package_input']) is str and report['package_input'] == 'venv', 'report package input differs')
    build = report['build']
    object_keys(build, {'archive_bytes', 'resource_count', 'uncompressed_bytes', 'manifest_sha256', 'archive_sha256'}, 'archive report')
    for name in ('archive_bytes', 'resource_count', 'uncompressed_bytes'):
        unsigned(build[name], 'archive report ' + name)
    for name in ('manifest_sha256', 'archive_sha256'):
        digest_string(build[name], 'archive report ' + name)
    require(type(report['distributions']) is list and len(report['distributions']) == 3, 'report distribution array differs')
    for item in report['distributions']:
        object_keys(item, {'name', 'version', 'directory', 'original_record_sha256', 'original_record_bytes', 'retained_files'}, 'distribution report')
        require(all(type(item[name]) is str for name in ('name', 'version', 'directory')), 'distribution report strings differ')
        digest_string(item['original_record_sha256'], 'distribution original RECORD')
        unsigned(item['original_record_bytes'], 'distribution original RECORD bytes', 1, 256 * 1024)
        unsigned(item['retained_files'], 'distribution retained file count', 1, 1024)
    require(type(report['inputs']) is list and len(report['inputs']) <= 8192, 'report input array differs')
    for item in report['inputs']:
        object_keys(item, {'source', 'path', 'size', 'sha256'}, 'input report')
        require(type(item['source']) is str and item['source'] in {'application', 'packages', 'provider', 'template', 'venv'}, 'input source is unknown')
        require(type(item['path']) is str and canonical_member(item['path']), 'input path is not canonical')
        unsigned(item['size'], 'input size')
        digest_string(item['sha256'], 'input identity')
    require(type(report['omissions']) is list and len(report['omissions']) == 111, 'report omission array differs')
    for item in report['omissions']:
        object_keys(item, {'path', 'reason'}, 'omission report')
        require(type(item['path']) is str and type(item['reason']) is str, 'omission report strings differ')


def validate_manifest_schema(manifest):
    object_keys(manifest, {'schema_version', 'app_id', 'entrypoint', 'components', 'runtimes', 'targets',
                          'native_modules', 'host_imports', 'resources'}, 'archive manifest')
    require(type(manifest['resources']) is dict and 0 < len(manifest['resources']) <= 8192, 'manifest resource inventory differs')
    for name, spec in manifest['resources'].items():
        require(type(name) is str and canonical_member(name), 'manifest resource path is not canonical')
        object_keys(spec, {'size', 'sha256', 'compression'}, 'resource specification')
        unsigned(spec['size'], 'resource specification size')
        digest_string(spec['sha256'], 'resource specification identity')
        require(type(spec['compression']) is str and spec['compression'] in {'stored', 'deflate'}, 'resource compression differs')
    object_keys(manifest['runtimes'], {'python'}, 'runtime inventory')
    provider = manifest['runtimes']['python']
    object_keys(provider, {'abi', 'build_id', 'provisioning', 'required_features', 'target'}, 'runtime declaration')
    ids = {kind: 'pbs-20261009-cpython-3.13.16-pgo-lto-' + suffix + '-metadata-apps-v1'
           for kind, suffix in (('bundled', 'bundled'), ('host', 'host'), ('install-host', 'host-install'))}
    require(type(provider['build_id']) is str and provider['build_id'] in ids.values(), 'runtime profile differs')
    if provider['build_id'] == ids['bundled']:
        provisioning = {'mode': 'bundled', 'provider': 'python_build_standalone',
                        'runtime_library': 'python/libpython3.13.so.1.0', 'stdlib': 'python/frozen.json',
                        'source': {'release': '20261009', 'revision': 'ccc07c40c2731bfb459c119f2388f65a5a470de6',
                                   'artifact': 'cpython-3.13.16+20261009-aarch64-unknown-linux-gnu-pgo+lto-full.tar.zst',
                                   'sha256': '8907ec2f181f0fc5cd08b9d897d36159432405af78f68f8faca728f48940e0ca',
                                   'variant': 'pgo+lto-full/bundled-metadata-apps-v1'}}
    else:
        declaration = provider['provisioning']
        require(type(declaration) is dict and type(declaration.get('stdlib')) is str and
                declaration['stdlib'].endswith('/lib/python3.13'), 'host standard library declaration differs')
        prefix = declaration['stdlib'].removesuffix('/lib/python3.13')
        require(prefix.startswith('/') and prefix.isascii() and '\\' not in prefix and
                all(part and part not in ('.', '..') for part in prefix[1:].split('/')) and
                all(32 <= ord(character) < 127 for character in prefix), 'host prefix declaration is not canonical')
        provisioning = {'mode': 'host', 'discovery': 'explicit_paths', 'stdlib': prefix + '/lib/python3.13',
                        'runtime_library': prefix + '/lib/libpython3.13.so.1.0'}
    expected_provider = {'abi': {'language': 'python', 'version': {'major': 3, 'minor': 13, 'patch': 16},
                                 'debug': False, 'gil': 'conventional'}, 'build_id': provider['build_id'],
                         'provisioning': provisioning, 'required_features': [], 'target': 'linux-arm64'}
    require(typed_equal(provider, expected_provider), 'runtime declaration fields/types differ from pinned profile')
    target = {'os': 'linux', 'arch': 'aarch64', 'abi': {'family': 'glibc', 'minimum_version': '2.36'},
              'minimum_os_version': '7.1.4', 'page_sizes': [4096], 'cpu_features': []}
    expected = {'schema_version': 0, 'app_id': 'python.real-packages', 'entrypoint': 'launch',
                'components': {'launch': {'entry_point': 'app/main.py', 'runtime': 'python', 'native_modules': []}},
                'runtimes': {'python': expected_provider}, 'targets': {'linux-arm64': target},
                'native_modules': {}, 'host_imports': {}, 'resources': manifest['resources']}
    require(typed_equal(manifest, expected), 'manifest fields/types differ from exact corpus/profile')


def factory_template_identity(manifest, provider_resources):
    # This fixture consumes only product-generated runtime templates. Rebuild
    # their canonical manifest, including the fixed placeholder and JSON LF,
    # independently from the final unchanged provider declaration/resources.
    placeholder = b"raise RuntimeError('This is a Python runtime template; use glue build-python with its manifest.json and root directory to package an application.')\n"
    template = dict(manifest)
    template['app_id'] = 'python.runtime.template'
    template['resources'] = provider_resources | {'app/main.py': identity(placeholder) | {'compression': 'stored'}}
    payload = (json.dumps(template, sort_keys=True, separators=(',', ':'), ensure_ascii=False) + '\n').encode('utf-8')
    return identity(payload)


def regular_bytes(path, maximum=2 * 1024 * 1024):
    metadata = path.lstat()
    require(stat.S_ISREG(metadata.st_mode) and metadata.st_size <= maximum, 'nonregular/oversized oracle input: ' + str(path))
    payload = path.read_bytes()
    require(len(payload) == metadata.st_size, 'oracle input changed: ' + str(path))
    return payload


def record_hash(payload):
    return 'sha256=' + base64.urlsafe_b64encode(hashlib.sha256(payload).digest()).rstrip(b'=').decode('ascii')


def record_bytes(files, record):
    stream = io.StringIO(newline='')
    writer = csv.writer(stream, lineterminator='\n')
    for name in sorted(set(files) | {record}):
        writer.writerow([name, '', ''] if name == record else [name, record_hash(files[name]), str(len(files[name]))])
    return stream.getvalue().encode('utf-8')


def canonical_member(name):
    parts = name.split('/')
    return (name and not name.startswith('/') and '\\' not in name and
            all(part and part not in ('.', '..') for part in parts) and
            not any(ord(character) < 32 or ord(character) == 127 for character in name))


def wheel_corpus():
    pin_bytes = regular_bytes(PIN_FILE)
    require(identity(pin_bytes) == {'size': 1418, 'sha256': '485b1c442c958a71d33a16dad40008ca33bfb77dbfdaa9a8e1731000303147dd'}, 'upstream wheel pin file identity differs')
    pins = strict_json(pin_bytes)
    require(pins['schema_version'] == 0 and len(pins['wheels']) == 3, 'wheel pin inventory differs')
    owners, all_files, facts = {}, {}, {}
    expected_projects = {(name, version) for name, version, _ in PROJECTS}
    require({(pin['project'], pin['version']) for pin in pins['wheels']} == expected_projects, 'wheel project/version pins differ')
    for pin in pins['wheels']:
        payload = regular_bytes(HERE / 'wheels' / pin['filename'])
        require(identity(payload) == {key: pin[key] for key in ('size', 'sha256')}, 'wheel compressed identity differs: ' + pin['filename'])
        with zipfile.ZipFile(io.BytesIO(payload)) as archive:
            names = archive.namelist()
            require(len(names) == len(set(names)) and all(canonical_member(name) for name in names), 'wheel has duplicate/unsafe members')
            files = {name: archive.read(name) for name in names}
            require(all(not member.is_dir() and stat.S_IFMT(member.external_attr >> 16) in (0, stat.S_IFREG)
                        for member in archive.infolist()), 'wheel contains a nonregular member')
        dist = next(dist for project, _, dist in PROJECTS if project == pin['project'])
        record = dist + '/RECORD'
        require(record in files, 'wheel lacks RECORD')
        rows = list(csv.reader(io.StringIO(files[record].decode('utf-8'), newline='')))
        seen = set()
        for row in rows:
            require(len(row) == 3, 'wheel RECORD columns differ')
            name, digest, size = row
            require(name in files and name not in seen, 'wheel RECORD ownership differs: ' + name)
            seen.add(name)
            require((digest, size) == (('', '') if name == record else (record_hash(files[name]), str(len(files[name])))),
                    'wheel RECORD identity differs: ' + name)
        require(seen == set(files), 'wheel RECORD omits payloads')
        wheel = files[dist + '/WHEEL']
        require(b'Root-Is-Purelib: true\n' in wheel and b'Tag: py3-none-any\n' in wheel, 'wheel pure tag differs')
        require(not set(files) & set(all_files), 'upstream wheel owners overlap')
        all_files.update(files)
        owners[dist] = files
        facts[dist] = {'wheel': pin, 'members': {name: identity(data) for name, data in sorted(files.items())},
                       'record_identity': identity(files[record])}
    require(len(all_files) == 145 and sum(name.endswith('.py') for name in all_files) == 110,
            'upstream corpus member/source count differs')
    return owners, facts


def expected_projection():
    owners, _ = wheel_corpus()
    result = {'app/main.py': regular_bytes(APPLICATION)}
    for dist, wheel in owners.items():
        files = wheel | {dist + '/INSTALLER': b'pip\n', dist + '/REQUESTED': b''}
        record = dist + '/RECORD'
        files[record] = record_bytes(files, record)
        result.update({'app/python/' + name: data for name, data in files.items()})
    require(min(result) == 'app/main.py' and len(result) == 152, 'normalized application inventory differs')
    return dict(sorted(result.items()))


def expected_inventory():
    return {'schema_version': 0, 'files': {name: identity(data) for name, data in expected_projection().items()}}


def installed_projection(venv):
    owners, wheel_facts = wheel_corpus()
    site = venv / 'lib/python3.13/site-packages'
    normalized, installed, ownership, omissions, original_records = {}, {}, {}, [], {}
    for dist, wheel in owners.items():
        record = dist + '/RECORD'
        raw_record = regular_bytes(site / record)
        rows = list(csv.reader(io.StringIO(raw_record.decode('utf-8'), newline='')))
        owned, caches = {}, set()
        expected_caches = {str(PurePosixPath(name).parent / '__pycache__' / (PurePosixPath(name).stem + '.cpython-313.pyc'))
                           for name in wheel if name.endswith('.py')}
        expected = set(wheel) | {dist + '/INSTALLER', dist + '/REQUESTED'}
        seen, wrappers = set(), set()
        for row in rows:
            require(len(row) == 3, 'installed RECORD columns differ')
            name, digest, size = row
            require(name not in seen, 'installed RECORD duplicate owner: ' + name)
            seen.add(name)
            if name == '../../../bin/markdown-it':
                require(dist == 'markdown_it_py-4.2.0.dist-info', 'unexpected console wrapper owner')
                payload = regular_bytes(venv / 'bin/markdown-it')
                require((digest, size) == (record_hash(payload), str(len(payload))), 'generated wrapper identity differs')
                require(payload.startswith(b'#!') and b'markdown_it.cli.parse' in payload, 'generated wrapper is not upstream console launcher')
                wrappers.add(name)
                omissions.append({'owner': dist, 'path': name, 'kind': 'console-wrapper', 'identity': identity(payload)})
                continue
            require(canonical_member(name), 'installed RECORD unsafe path: ' + name)
            payload = regular_bytes(site / name)
            require(name not in ownership, 'installed RECORD cross-owner overlap: ' + name)
            ownership[name] = dist
            installed[name] = identity(payload)
            if name in expected_caches:
                source_name = next(source for source in wheel if source.endswith('.py') and
                                   str(PurePosixPath(source).parent / '__pycache__' / (PurePosixPath(source).stem + '.cpython-313.pyc')) == name)
                source = site / source_name
                require((digest, size) == ('', '') and len(payload) >= 16 and payload[:4] == b'\xf3\r\r\n', 'default pip cache header/RECORD differs')
                require(struct.unpack_from('<III', payload, 4) == (0, int(source.stat().st_mtime) & 0xffffffff, len(wheel[source_name])),
                        'default pip cache source mtime/size header differs')
                caches.add(name)
                omissions.append({'owner': dist, 'path': name, 'kind': 'bytecode', 'identity': identity(payload)})
                continue
            require(name in expected, 'unexpected pip-installed retained member: ' + name)
            if name == record:
                require((digest, size) == ('', ''), 'installed RECORD self row differs')
            else:
                require((digest, size) == (record_hash(payload), str(len(payload))), 'installed RECORD identity differs: ' + name)
                expected_payload = b'pip\n' if name == dist + '/INSTALLER' else b'' if name == dist + '/REQUESTED' else wheel[name]
                require(payload == expected_payload, 'pip changed upstream/generated metadata payload: ' + name)
            owned[name] = payload
        require(set(owned) == expected and caches == expected_caches, 'pip retained/cache ownership inventory differs: ' + dist)
        require(wrappers == ({'../../../bin/markdown-it'} if dist.startswith('markdown_it_py-') else set()), 'console wrapper inventory differs')
        normalized[dist] = record_bytes(owned, record)
        original_records[dist] = {'identity': identity(raw_record), 'rows': rows,
                                  'normalized_identity': identity(normalized[dist])}
    actual = {}
    for path in sorted(site.rglob('*')):
        mode = path.lstat().st_mode
        require(stat.S_ISDIR(mode) or stat.S_ISREG(mode), 'installed site contains link/special object')
        if stat.S_ISREG(mode):
            actual[path.relative_to(site).as_posix()] = identity(regular_bytes(path))
    require(actual == installed and len(actual) == 261, 'installed site inventory differs from RECORD ownership')
    require(len(omissions) == 111 and sum(item['kind'] == 'bytecode' for item in omissions) == 110,
            'genuine default pip cache/wrapper omission inventory differs')
    expected = expected_projection()
    require({'schema_version': 0, 'files': {name: identity(data) for name, data in expected.items()}} ==
            strict_json((HERE / 'expected-inventory.json').read_bytes()), 'committed normalized inventory differs')
    for dist, normalized_record in normalized.items():
        require(expected['app/python/' + dist + '/RECORD'] == normalized_record, 'deterministic independent RECORD rewrite differs')
    return expected, {'wheel_facts': wheel_facts, 'installed_files': installed, 'installed_file_count': len(actual),
                      'original_records': original_records, 'omissions': sorted(omissions, key=lambda item: item['path']),
                      'omission_count': len(omissions)}


def publish_expected(venv, output):
    files, facts = installed_projection(venv)
    output.mkdir(parents=True, exist_ok=False)
    for name, payload in files.items():
        path = output / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(payload)
    return files, facts


def run(command, output, label, environment):
    (output / (label + '.command.json')).write_text(json.dumps(command, indent=2) + '\n')
    result = subprocess.run(command, capture_output=True, env=environment, check=False, timeout=180)
    for kind, payload in (('stdout', result.stdout), ('stderr', result.stderr)):
        (output / (label + '.' + kind + '.txt')).write_bytes(payload)
    (output / (label + '.exit-status.txt')).write_text(str(result.returncode) + '\n')
    require(result.returncode == 0, 'offline fixture command failed: ' + label + '; see ' + str(output))
    return result


def install(producer, output):
    require(sys.version_info[:3] == (3, 13, 16), 'installation evidence requires exact stock Python 3.13.16')
    producer, output = producer.absolute(), output.absolute()
    require(not output.exists() and not output.is_symlink(), 'installation output already exists')
    wheel_corpus()
    require(expected_inventory() == strict_json((HERE / 'expected-inventory.json').read_bytes()), 'committed normalized inventory differs')
    output.mkdir(parents=True, exist_ok=False)
    python = producer / 'bin/python3.13'
    environment = dict(os.environ)
    for name in ('PYTHONPATH', 'PYTHONHOME', 'PYTHONDONTWRITEBYTECODE', 'PIP_TARGET', 'PIP_PREFIX', 'PIP_USER'):
        environment.pop(name, None)
    environment.update({'PIP_CONFIG_FILE': '/dev/null', 'LD_LIBRARY_PATH': str(producer / 'lib'), 'LC_ALL': 'C'})
    commands = [
        [str(python), '-I', '-m', 'venv', '--without-pip', str(output / 'venv')],
        [str(python), '-I', '-m', 'pip', '--isolated', '--disable-pip-version-check', '--python', str(output / 'venv/bin/python'),
         'install', '--no-index', '--find-links', str(HERE / 'wheels'), '--no-deps', '--no-cache-dir',
         *[project + '==' + version for project, version, _ in PROJECTS]],
    ]
    for index, command in enumerate(commands):
        run(command, output, 'install-' + str(index), environment)
    files, facts = publish_expected(output / 'venv', output / 'expected-input')
    application = output / 'application/app'
    application.mkdir(parents=True)
    shutil.copyfile(APPLICATION, application / 'main.py')
    inventory = expected_inventory()
    (output / 'expected-inventory.json').write_text(json.dumps(inventory, indent=2, sort_keys=True) + '\n')
    pip_text = (producer / 'lib/python3.13/site-packages/pip/__init__.py').read_text()
    pip_version = re.search(r'^__version__ = "([0-9.]+)"$', pip_text, re.MULTILINE)
    require(pip_version is not None, 'stock producer pip version is not declared')
    provenance = {'schema_version': 0, 'python_version': list(sys.version_info[:3]), 'pip_version': pip_version[1],
                  'bytecode_cache_tag': sys.implementation.cache_tag, 'commands': commands,
                  'venv_configuration': (output / 'venv/pyvenv.cfg').read_text(),
                  'venv_has_pip': any(path.name == 'pip' or path.name.startswith('pip-')
                                      for path in (output / 'venv/lib/python3.13/site-packages').iterdir()),
                  'expected_application': inventory['files'], 'application_bytes': sum(len(data) for data in files.values()),
                  'baseline_stdout_identity': identity(OUTPUT), **facts}
    require(not provenance['venv_has_pip'], 'pip was installed into the unseeded venv')
    (output / 'installation-provenance.json').write_text(json.dumps(provenance, indent=2, sort_keys=True) + '\n')
    environment['GLUE_REAL_PACKAGE_BASELINE'] = '1'
    baseline = run([str(output / 'venv/bin/python'), '-I', str(application / 'main.py')], output, 'baseline', environment)
    require(baseline.stdout == OUTPUT and not baseline.stderr, 'stock baseline output differs')
    return provenance


def audit_build(report_path, archive_path, provenance_path=None):
    report = strict_json(regular_bytes(report_path))
    validate_report_schema(report)
    expected = expected_projection()
    require(report['package_input'] == 'venv' and len(report['distributions']) == 3, 'product package input/distribution count differs')
    owners, _ = wheel_corpus()
    by_dist = {item['directory']: item for item in report['distributions']}
    require(len(by_dist) == 3 and set(by_dist) == set(owners), 'product distribution directory inventory differs')
    for project, version, dist in PROJECTS:
        declaration = by_dist[dist]
        require(declaration['name'] == project and declaration['version'] == version and
                declaration['retained_files'] == len(owners[dist]) + 2 and
                re.fullmatch('[0-9a-f]{64}', declaration['original_record_sha256']) is not None,
                'product distribution identity/retained count differs: ' + dist)
    expected_omissions = [{'path': str(PurePosixPath(name).parent / '__pycache__' /
                                (PurePosixPath(name).stem + '.cpython-313.pyc')), 'reason': 'bytecode_or_cache'}
                          for wheel in owners.values() for name in wheel if name.endswith('.py')]
    expected_omissions.append({'path': '../../../bin/markdown-it', 'reason': 'generated_entry_point_wrapper'})
    expected_omissions.sort(key=lambda item: (item['path'], item['reason']))
    require(typed_equal(report['omissions'], expected_omissions), 'product exact cache/wrapper omission inventory differs')
    inputs = {(item['source'], item['path']): {'size': item['size'], 'sha256': item['sha256']} for item in report['inputs']}
    require(len(inputs) == len(report['inputs']), 'product input identity repeats')
    require({('application', 'app/main.py'), ('venv', 'pyvenv.cfg'), ('template', 'manifest.json')} <= set(inputs),
            'product required application/venv/template input identity is missing')
    require(typed_equal(inputs['application', 'app/main.py'], identity(expected['app/main.py'])), 'product original app identity differs')
    package_inputs = {name: item for (source, name), item in inputs.items() if source == 'packages'}
    expected_inputs = {name.removeprefix('app/python/'): identity(data) for name, data in expected.items() if name.startswith('app/python/')}
    provenance = strict_json(regular_bytes(provenance_path)) if provenance_path else None
    if provenance:
        require(typed_equal(provenance['expected_application'], expected_inventory()['files']) and type(provenance['omission_count']) is int and provenance['omission_count'] == 111,
                'retained installation provenance corpus differs')
    for _, _, dist in PROJECTS:
        declaration = by_dist[dist]
        original = {'size': declaration['original_record_bytes'], 'sha256': declaration['original_record_sha256']}
        if provenance:
            require(typed_equal(original, provenance['original_records'][dist]['identity']), 'product original RECORD differs from independent installation audit')
        expected_inputs[dist + '/RECORD'] = original
    require(typed_equal(package_inputs, expected_inputs), 'product selected original package input identities differ')
    if provenance:
        require(typed_equal(inputs['venv', 'pyvenv.cfg'], identity(provenance['venv_configuration'].encode('utf-8'))),
                'product venv declaration differs from original conventional installation')
    with archive_path.open('rb') as stream:
        locator = stream.read(64)
        require(len(locator) == 64 and locator[:8] == b'GLUERS00' and locator[8:16] == b'\0' * 8, 'archive locator differs')
        manifest_size, zip_size = struct.unpack_from('<QQ', locator, 16)
        require(0 < manifest_size <= 4 * 1024 * 1024 and zip_size <= 128 * 1024 * 1024, 'archive framing exceeds independent bound')
        manifest_bytes = stream.read(manifest_size)
        require(hashlib.sha256(manifest_bytes).digest() == locator[32:64], 'archive manifest identity differs')
        require(archive_path.stat().st_size == 64 + manifest_size + zip_size, 'archive framing differs')
    manifest = strict_json(manifest_bytes)
    validate_manifest_schema(manifest)
    require(manifest['app_id'] == 'python.real-packages' and manifest['components']['launch']['entry_point'] == 'app/main.py', 'archive app identity differs')
    resources = manifest['resources']
    provider_resources = {name: item for name, item in resources.items() if not name.startswith('app/')}
    helper_specs = {'python/archive-importer.py': identity((HERE.parent / 'python-imports/bootstrap.py').read_bytes()) | {'compression': 'deflate'},
                    'python/archive-metadata.py': identity((HERE.parent / 'python-metadata/bootstrap.py').read_bytes()) | {'compression': 'deflate'}}
    provider = manifest['runtimes']['python']
    if provider['provisioning']['mode'] == 'bundled':
        source_pins = strict_json((HERE.parent / 'python-imports/stdlib-pins.json').read_bytes())['files']
        helper_specs.update({'stdlib/' + name: item | {'compression': 'deflate'} for name, item in source_pins.items()})
        helper_specs['python/libpython3.13.so.1.0'] = {'size': 73563968, 'sha256': '42be968275d5be2d9e632ec9ef6790dd2c10f1d4a710ad1028fc2b687242f219', 'compression': 'stored'}
        helper_specs['python/frozen.json'] = {'size': 139523, 'sha256': '6a41fc38141d45c5197adfc1b0ee740c6244ea681742c205b8aa7b8449d865d7', 'compression': 'stored'}
    require(typed_equal(provider_resources, helper_specs), 'complete provider resource inventory differs from independent pins/helpers')
    expected_provider_inputs = {name: {key: item[key] for key in ('size', 'sha256')} for name, item in provider_resources.items()}
    require(typed_equal({name: item for (source, name), item in inputs.items() if source == 'provider'}, expected_provider_inputs),
            'product provider input identities differ')
    expected_input_keys = ({('application', 'app/main.py'), ('template', 'manifest.json'), ('venv', 'pyvenv.cfg')} |
                           {('packages', name) for name in expected_inputs} | {('provider', name) for name in provider_resources})
    require(set(inputs) == expected_input_keys, 'product exact input source/path inventory differs')
    require(typed_equal(inputs['template', 'manifest.json'], factory_template_identity(manifest, provider_resources)),
            'product factory-template input identity differs')
    require(report['build']['archive_bytes'] == archive_path.stat().st_size and
            report['build']['resource_count'] == len(resources) and
            report['build']['uncompressed_bytes'] == sum(item['size'] for item in resources.values()) and
            report['build']['manifest_sha256'] == hashlib.sha256(manifest_bytes).hexdigest(),
            'product archive report sizes/counts/manifest identity differ')
    application_specs = {name: spec for name, spec in resources.items() if name.startswith('app/')}
    require(typed_equal(application_specs, {name: identity(data) | {'compression': 'stored'} for name, data in expected.items()}), 'product app resource identities differ')
    with zipfile.ZipFile(archive_path) as archive:
        require(set(archive.namelist()) == set(resources) and len(archive.namelist()) == len(resources), 'complete archive member inventory differs')
        for name, spec in resources.items():
            member = archive.getinfo(name)
            require(member.file_size == spec['size'] and member.compress_type ==
                    {'stored': zipfile.ZIP_STORED, 'deflate': zipfile.ZIP_DEFLATED}[spec['compression']],
                    'archive member size/compression differs: ' + name)
            require(not member.is_dir() and stat.S_IFMT(member.external_attr >> 16) in (0, stat.S_IFREG),
                    'archive member is not a regular payload: ' + name)
            payload = archive.read(name)
            require(typed_equal(identity(payload), {key: spec[key] for key in ('size', 'sha256')}), 'archive member identity differs: ' + name)
            if name in expected:
                require(payload == expected[name], 'archive normalized member differs from wheel/pip oracle: ' + name)
    archive_identity = identity(archive_path.read_bytes())
    require(report['build']['archive_sha256'] == archive_identity['sha256'], 'product archive reported digest differs')
    return {'schema_version': 0, 'application_file_count': len(expected), 'distribution_count': 3,
            'omitted_bytecode_files': 110, 'omitted_console_scripts': 1,
            'application_bytes': sum(map(len, expected.values())), 'archive_identity': archive_identity,
            'complete_archive_resource_count': len(resources), 'all_resource_bytes_verified': True}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    sub = parser.add_subparsers(dest='operation', required=True)
    installation = sub.add_parser('install'); installation.add_argument('producer', type=Path); installation.add_argument('output', type=Path)
    projection = sub.add_parser('project'); projection.add_argument('venv', type=Path); projection.add_argument('output', type=Path)
    inventory = sub.add_parser('inventory'); inventory.add_argument('output', type=Path)
    build = sub.add_parser('audit-build'); build.add_argument('report', type=Path); build.add_argument('archive', type=Path); build.add_argument('--provenance', type=Path)
    args = parser.parse_args()
    try:
        if args.operation == 'install':
            result = install(args.producer, args.output)
            summary = {'installed_file_count': result['installed_file_count'], 'omission_count': result['omission_count'],
                       'application_file_count': len(result['expected_application']), 'baseline_stdout_identity': result['baseline_stdout_identity']}
        elif args.operation == 'project':
            files, facts = publish_expected(args.venv, args.output)
            summary = {'files': {name: identity(data) for name, data in files.items()}, **facts}
        elif args.operation == 'inventory':
            result = expected_inventory()
            with args.output.open('x', encoding='utf-8') as stream:
                stream.write(json.dumps(result, indent=2, sort_keys=True) + '\n')
            summary = {'identity': identity(args.output.read_bytes()), 'files': len(result['files']),
                       'bytes': sum(value['size'] for value in result['files'].values())}
        else:
            summary = audit_build(args.report, args.archive, args.provenance)
        print(json.dumps(summary, sort_keys=True))
    except (OSError, ValueError, KeyError, TypeError, csv.Error, zipfile.BadZipFile, subprocess.TimeoutExpired) as error:
        print('real package fixture rejected: ' + str(error), file=sys.stderr)
        return 1
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
