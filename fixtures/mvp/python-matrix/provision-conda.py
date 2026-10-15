#!/usr/bin/env python3
"""Explicit independent CI input preparation, never called by glue.

Resolve once, retain the complete HTTPS URL/SHA256 lock, verify every package,
then install the prebuilt closure offline. --lock replays that exact closure.
The selected non-PBS CPython/libffi input remains subject to the shared oracle.
"""
import argparse
import hashlib
import json
import os
from pathlib import Path
import platform
import re
import subprocess
import sys
import tarfile
from urllib.parse import urlparse
from urllib.request import urlopen

CHANNEL = 'https://conda.anaconda.org/conda-forge'
MICROMAMBA = {
    'url': CHANNEL + '/linux-64/micromamba-2.3.3-0.tar.bz2',
    'sha256': 'e7274528ceb9c20d048a428d6c22d7e02e268f8ffb762c4c365422347c8b8ba2',
}
PINS = {
    'python': {'version': '3.14.8', 'build': 'hcd007b5_102_cp314',
               'sha256': '32a39d6b85fd55d9949ea48d63887bef0dc61dca46d9844d4b409eb993460617'},
    'libffi': {'version': '3.7.0', 'build': 'h81df57d_1',
               'sha256': 'c8c7583ef063bc3c430f1d48298e5ad24f796a35c22ed5b14183325825a61106'},
    'libstdcxx': {'version': '16.2.0', 'build': 'h934c35e_7',
                  'sha256': 'fa7018298629fc429971fffd6ecba3d27a7b02e4e890d6a93ea01ffebe8cb745'},
}


def write_json(path, value):
    path.write_text(json.dumps(value, indent=2, sort_keys=True) + '\n')


def digest(path):
    with path.open('rb') as stream:
        return hashlib.file_digest(stream, 'sha256').hexdigest()


def fetch(url, destination, expected, maximum=256 * 1024 * 1024):
    if not re.fullmatch('[0-9a-f]{64}', expected):
        raise ValueError('invalid SHA256')
    with urlopen(url, timeout=120) as response, destination.open('xb') as output:
        if urlparse(response.url).scheme != 'https':
            raise ValueError('download redirected away from HTTPS')
        size = 0
        while block := response.read(1024 * 1024):
            size += len(block)
            if size > maximum:
                raise ValueError('package exceeds explicit download bound')
            output.write(block)
    if digest(destination) != expected:
        raise ValueError('SHA256 mismatch: ' + url)


def validate_lock(lock):
    if lock.get('schema') != 1 or lock.get('platform') != 'linux-64' or lock.get('micromamba') != MICROMAMBA:
        raise ValueError('unexpected provisioning lock identity')
    packages = lock['packages']
    if not 1 <= len(packages) <= 100:
        raise ValueError('invalid package count')
    names, filenames = set(), set()
    for package in packages:
        parsed = urlparse(package['url'])
        parts = parsed.path.split('/')
        if (parsed.scheme != 'https' or parsed.netloc != 'conda.anaconda.org'
                or parsed.query or parsed.fragment or len(parts) != 4
                or parts[1] != 'conda-forge' or parts[2] not in {'linux-64', 'noarch'}
                or parts[3] != package['filename'] or not parts[3].endswith(('.conda', '.tar.bz2'))):
            raise ValueError('unexpected package source: ' + package['url'])
        if (not re.fullmatch('[0-9a-f]{64}', package['sha256'])
                or not re.fullmatch('[0-9a-f]{32}', package['md5'])
                or package['name'] in names or package['filename'] in filenames):
            raise ValueError('invalid or duplicate package identity')
        names.add(package['name'])
        filenames.add(package['filename'])
    for name, pin in PINS.items():
        candidates = [p for p in packages if p['name'] == name]
        if len(candidates) != 1 or any(candidates[0][key] != value for key, value in pin.items()):
            raise ValueError('selected input does not match pinned ' + name)
    return packages


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--work', type=Path, required=True, help='new preparation directory')
    parser.add_argument('--output', type=Path, required=True, help='new staged runtime directory')
    parser.add_argument('--evidence', type=Path, required=True, help='new small provenance directory')
    parser.add_argument('--lock', type=Path, help='replay a previously retained complete lock')
    args = parser.parse_args()
    if platform.system() != 'Linux' or platform.machine() != 'x86_64':
        raise ValueError('requires a native GNU Linux x86_64 preparation host')
    for path in [args.work, args.output, args.evidence]:
        if path.exists() or path.is_symlink():
            raise ValueError('preparation destination already exists: ' + str(path))
    work, output, evidence = (path.absolute() for path in [args.work, args.output, args.evidence])
    work.mkdir(parents=True)
    evidence.mkdir(parents=True)
    home = work / 'home'
    home.mkdir()
    environment = {'PATH': os.environ['PATH'], 'HOME': str(home), 'LANG': 'C.UTF-8',
                   'MAMBA_ROOT_PREFIX': str(work / 'mamba-root'), 'MAMBA_NO_BANNER': '1'}
    archive = work / 'micromamba.tar.bz2'
    fetch(MICROMAMBA['url'], archive, MICROMAMBA['sha256'], 16 * 1024 * 1024)
    tool = work / 'micromamba'
    with tarfile.open(archive) as bundle:
        member = bundle.getmember('bin/micromamba')
        if not member.isfile() or member.size > 32 * 1024 * 1024:
            raise ValueError('unexpected micromamba archive member')
        tool.write_bytes(bundle.extractfile(member).read())
        tool.chmod(0o755)
    base = [str(tool), '--no-rc', '--no-env', '--root-prefix', str(work / 'mamba-root')]
    commands = []

    def run(argv, log):
        commands.append(argv)
        result = subprocess.run(argv, env=environment, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        (evidence / (log + '.stdout')).write_bytes(result.stdout)
        (evidence / (log + '.stderr')).write_bytes(result.stderr)
        write_json(evidence / 'commands.json', commands)
        result.check_returncode()
        return result.stdout

    raw = work / 'runtime'
    if args.lock:
        lock = json.loads(args.lock.read_text())
    else:
        transaction = json.loads(run(base + ['create', '--yes', '--json', '--dry-run', '--override-channels',
            '--channel', CHANNEL, '--platform', 'linux-64', '--strict-channel-priority', '--prefix', str(raw)]
            + [name + '=' + pin['version'] + '=' + pin['build'] for name, pin in PINS.items()], 'resolve'))
        if transaction.get('success') is not True:
            raise ValueError('micromamba resolution did not succeed')
        packages = []
        for package in transaction['actions']['LINK']:
            packages.append({key: package[source] for key, source in {
                'name': 'name', 'version': 'version', 'build': 'build_string', 'filename': 'fn',
                'url': 'url', 'sha256': 'sha256', 'md5': 'md5'}.items()})
        lock = {'schema': 1, 'platform': 'linux-64', 'micromamba': MICROMAMBA,
                'requested': PINS, 'packages': sorted(packages, key=lambda p: p['name'])}
    packages = validate_lock(lock)
    write_json(evidence / 'explicit-lock.json', lock)
    (evidence / 'upstream-explicit.txt').write_text('@EXPLICIT\n' + ''.join(p['url'] + '#' + p['md5'] + '\n' for p in packages))
    downloads = work / 'packages'
    downloads.mkdir()
    local = []
    for package in packages:
        destination = downloads / package['filename']
        fetch(package['url'], destination, package['sha256'])
        local.append(destination.as_uri() + '#' + package['md5'])
    explicit = work / 'local-explicit.txt'
    explicit.write_text('@EXPLICIT\n' + '\n'.join(local) + '\n')
    run(base + ['create', '--yes', '--offline', '--json', '--prefix', str(raw), '--file', str(explicit)], 'install-offline')
    # CPython's own ensurepip is needed by the existing ordinary-venv recipe.
    # Probe it here; no dependency installation occurs in glue build or run.
    code = ('import ctypes,ensurepip,json,sys,sysconfig;'
            'assert tuple(sys.version_info[:3])==(3,14,8);'
            'assert not sysconfig.get_config_var("Py_GIL_DISABLED");'
            'assert not sysconfig.get_config_var("Py_DEBUG");'
            'print(json.dumps({"version":sys.version,"executable":sys.executable,"ensurepip":ensurepip.version()}))')
    run([str(raw / 'bin/python3.14'), '-I', '-S', '-B', '-c', code], 'runtime-probe')
    run([sys.executable, str(Path(__file__).with_name('stage-runtime.py')), str(raw), str(output)], 'stage')
    stage_receipt = output.parent / (output.name + '-stage.json')
    (evidence / 'stage.json').write_bytes(stage_receipt.read_bytes())
    write_json(evidence / 'provisioning.json', {'schema': 1, 'status': 'prepared',
        'kind': 'independent-prebuilt-conda-forge-input', 'platform': 'linux-64',
        'lock_sha256': digest(evidence / 'explicit-lock.json'), 'micromamba_sha256': digest(tool),
        'package_count': len(packages), 'runtime': str(output),
        'native_images_recompiled': False, 'product_execution_checked': False,
        'scope': 'Explicit test prerequisite only; shared V02/R02 trace still required.'})
    print(output)


if __name__ == '__main__':
    main()
