#!/usr/bin/env python3
"""Read-only identity-bound audit of the sixteen clean stock install-only host source-app captures/60 controls."""
import argparse
import hashlib
import importlib.util
import json
from pathlib import Path
import re
import struct
import subprocess
import sys
import zipfile

ROOT = next(path for path in Path(__file__).resolve().parents if (path / 'scripts/check-linux-python-install-host-source-app-trace.py').is_file())


def sha(path):
    with path.open('rb') as stream:
        return hashlib.file_digest(stream, 'sha256').hexdigest()


def identity(path):
    return {'bytes': path.stat().st_size, 'sha256': sha(path)}


def require(condition, message):
    if not condition:
        raise ValueError(message)


def doctor(app_id, full=False):
    return ('Launcher: glue 0.1.0 on linux/aarch64\n'
            'Linked Lua: 5.4.9 (int64, float64)\n'
            'Available: archive packaging, inspection, verification, read-only resources, linked Lua source profile\n'
            'Pending: general runtime/package compatibility, Node adapters, workers, standalone signing\n'
            'Python: controlled CPython 3.13.16 / PBS 20261009 profiles; GNU Linux arm64 execution only\n'
            f'Validated metadata for {app_id}\n'
            f'Ready: pinned {"explicit-host" if full else "install-only host"} Python source application build/target prerequisites, CPython 3.13.16 / PBS 20261009\n'
            'Run checks profile archive limits, contents and explicit host prerequisites before loading Python\n').encode()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--capture', type=Path, required=True)
    parser.add_argument('--build', type=Path, required=True)
    parser.add_argument('--source-revision', required=True)
    parser.add_argument('--output', type=Path, required=True)
    parser.add_argument('--allow-development', action='store_true')
    args = parser.parse_args()
    capture, build = args.capture.resolve(), args.build.resolve()
    spec = importlib.util.spec_from_file_location('source_control_audit', ROOT / 'scripts/check-linux-python-install-host-source-app-trace.py')
    policy = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(policy)
    require((capture / 'source-revision.txt').read_text().strip() == args.source_revision, 'capture revision differs')
    clean = (capture / 'source-status.txt').read_bytes() == (capture / 'source-diff.patch').read_bytes() == b''
    if not args.allow_development:
        require(clean, 'capture source was dirty')
        require((capture / 'development-opt-in.txt').read_bytes() == b'false\n', 'clean capture opted into development')
        require((capture / 'commands.sh').read_bytes() == subprocess.check_output(['git', 'show', args.source_revision + ':fixtures/python-install-host-source-apps/run-linux.sh'], cwd=ROOT), 'capture commands differ from checkpoint')
    else:
        require((capture / 'development-opt-in.txt').read_bytes() == b'true\n', 'development audit lacks explicit capture opt-in')
        require((capture / 'commands.sh').read_bytes() == (ROOT / 'fixtures/python-install-host-source-apps/run-linux.sh').read_bytes(), 'development commands changed after capture')
    metadata = capture / 'source-metadata.json'
    archives = build / 'relocated Python install host source apps'
    report = {'schema_version': 0, 'command': sys.argv, 'source_revision': args.source_revision, 'source_clean': clean, 'development_audit': args.allow_development,
              'source_branch': (capture / 'source-branch.txt').read_text().strip(), 'script': identity(Path(__file__)),
              'capture_commands': identity(capture / 'commands.sh'), 'metadata': identity(metadata),
              'runtime': [], 'controls': [], 'provenance': [], 'findings': []}
    for mode in policy.MODES:
        archive = archives / (mode + '.glue')
        actual = policy.archive_record(archive, mode)
        require(actual == policy.retained_metadata(metadata, mode, archive.stat().st_size), mode + ': archive metadata drift')
        status = 0 if mode in policy.SUCCESS else 1
        require((capture / (mode + '.exit-status.txt')).read_bytes() == f'{status}\n'.encode(), mode + ': runtime status')
        for path, expected in zip((capture / (mode + '.stdout.txt'), capture / (mode + '.stderr.txt')), policy.expected_output(mode)):
            require(path.read_bytes() == expected, mode + ': runtime diagnostics')
        require((capture / (mode + '.trace-check.txt')).read_text().startswith('Trace checks passed:'), mode + ': strict live replay')
        with archive.open('rb') as stream:
            locator = stream.read(64)
            raw = stream.read(struct.unpack_from('<Q', locator, 16)[0])
        manifest = json.loads(raw)
        for operation in (('build', 'doctor') if mode in policy.CONTROLS else ('build', 'inspect', 'verify', 'doctor', 'cat')):
            if operation == 'build' and mode == 'corrupt-source':
                continue
            stem = capture / 'cli-controls' / (mode + '.' + operation)
            out_path, err_path = Path(str(stem) + '.stdout.txt'), Path(str(stem) + '.stderr.txt')
            out, err = out_path.read_bytes(), err_path.read_bytes()
            expected_status = 1 if operation == 'verify' and mode == 'corrupt-source' else 0
            require(Path(str(stem) + '.exit-status.txt').read_bytes() == f'{expected_status}\n'.encode(), mode + ': control status')
            require(err == (policy.expected_output(mode)[1] if expected_status else b''), mode + ': control stderr')
            command = [policy.PROGRAM, operation, policy.archive_for(mode)]
            if operation == 'build':
                expected = f'Built {policy.archive_for(mode)}: {len(manifest["resources"])} resources, {archive.stat().st_size} archive bytes, {sum(item["size"] for item in manifest["resources"].values())} uncompressed bytes\nArchive SHA-256: {sha(archive)}\n'.encode()
                command = ['/build-target/release/glue', 'build', '--manifest', f'/build-target/staging/{mode}/manifest.json', '--root', f'/build-target/staging/{mode}/root', '--output', policy.archive_for(mode)]
                comparison = 'actual archive size/hash plus manifest inventory count/bytes'
            elif operation == 'inspect':
                expected = raw + b'\n'
                command.append('--json')
                comparison = 'exact actual canonical manifest bytes'
            elif operation == 'cat':
                with zipfile.ZipFile(archive) as source:
                    expected = source.read(policy.identity_for(mode)[1])
                command.append(policy.identity_for(mode)[1])
                comparison = 'exact archive declared entry bytes, including quoting and embedded NUL'
            elif operation == 'verify':
                expected = (f'Verified {len(manifest["resources"])} resources ({sum(item["size"] for item in manifest["resources"].values())} uncompressed bytes)\n'.encode() if not expected_status else b'')
                comparison = 'exact complete manifest count/bytes or stored source CRC rejection'
            else:
                expected = doctor(manifest['app_id'])
                comparison = 'exact declared build/target readiness text without executing source'
            require(out == expected, mode + ': control stdout')
            report['controls'].append({'mode': mode, 'operation': operation, 'command': command, 'status': expected_status, 'comparison': comparison, 'stdout': identity(out_path), 'stderr': identity(err_path)})
        report['runtime'].append({'mode': mode, 'status': status, 'stdout': identity(capture / (mode + '.stdout.txt')), 'stderr': identity(capture / (mode + '.stderr.txt')), 'trace': identity(capture / (mode + '.trace.txt')), 'archive': actual})
    for mode, operation in [('protected-module', 'build'), ('bytecode', 'build'), ('helper-drift', 'build'), ('helper-drift', 'doctor'), ('outside-entry', 'doctor')]:
        stem = capture / 'cli-controls' / (mode + '.' + operation)
        out_path, err_path = Path(str(stem) + '.stdout.txt'), Path(str(stem) + '.stderr.txt')
        require(Path(str(stem) + '.exit-status.txt').read_bytes() == b'1\n' and err_path.stat().st_size > 0, mode + ': structural rejection')
        if operation == 'build':
            require(out_path.read_bytes() == b'' and not (build / (mode + '-should-not-exist.glue')).exists(), mode + ': output opened before declaration rejection')
        else:
            require(b'Ready:' not in out_path.read_bytes(), mode + ': readiness advertised for invalid declarations')
        report['controls'].append({'mode': mode, 'operation': operation, 'status': 1, 'comparison': 'declaration rejection and preserved/absent build output; doctor advertises no readiness', 'stdout': identity(out_path), 'stderr': identity(err_path)})
    full_archive = archives / 'full-profile-on-stock.glue'
    with full_archive.open('rb') as stream:
        locator = stream.read(64)
        full_raw = stream.read(struct.unpack_from('<Q', locator, 16)[0])
    full_manifest = json.loads(full_raw)
    minimal_manifest = json.loads((capture / 'minimal.manifest.json').read_text())
    expected_full = json.loads(json.dumps(minimal_manifest))
    expected_full['runtimes']['python']['build_id'] = 'pbs-20261009-cpython-3.13.16-pgo-lto-host-source-apps-v1'
    require(full_manifest == expected_full and full_manifest == json.loads((capture / 'full-profile-on-stock.manifest.json').read_text()), 'full profile control changes another declaration')
    with zipfile.ZipFile(full_archive) as full_zip, zipfile.ZipFile(archives / 'minimal.glue') as minimal_zip:
        require(full_zip.namelist() == minimal_zip.namelist() and all(full_zip.read(key) == minimal_zip.read(key) for key in full_zip.namelist()), 'full profile changes archived app/helper contents')
    for operation in ('build', 'doctor', 'run'):
        stem = capture / 'cli-controls' / ('full-profile-on-stock.' + operation)
        out_path, err_path = Path(str(stem) + '.stdout.txt'), Path(str(stem) + '.stderr.txt')
        status = 1 if operation == 'run' else 0
        require(Path(str(stem) + '.exit-status.txt').read_bytes() == f'{status}\n'.encode(), 'full profile control status differs')
        if operation == 'build':
            expected_out = (f'Built {policy.DIRECTORY}/full-profile-on-stock.glue: {len(full_manifest["resources"])} resources, {full_archive.stat().st_size} archive bytes, {sum(spec["size"] for spec in full_manifest["resources"].values())} uncompressed bytes\nArchive SHA-256: {sha(full_archive)}\n').encode()
            expected_err = b''
        elif operation == 'doctor':
            expected_out, expected_err = doctor(full_manifest['app_id'], full=True), b''
        else:
            expected_out = b''
            expected_err = ('glue: host path ' + policy.PREFIX + '/lib/python3.13/idlelib/idle_test: No such file or directory (os error 2)\n').encode()
        require(out_path.read_bytes() == expected_out and err_path.read_bytes() == expected_err, 'full profile control outcome differs: ' + operation)
        report['controls'].append({'mode': 'full-profile-on-stock', 'operation': operation, 'status': status, 'comparison': 'exact full profile identity without automatic install-only subset/provider selection', 'stdout': identity(out_path), 'stderr': identity(err_path), 'archive': identity(full_archive)})
    require(len(report['controls']) == len(list((capture / 'cli-controls').glob('*.exit-status.txt'))) == 60, 'control inventory differs')
    provider_audit = json.loads((capture / 'post-runtime-provider-audit.json').read_text())
    require(provider_audit['all_ten_provider_trees_passed'] is True and provider_audit['independent_post_runtime_audit'] is True and provider_audit['complete_stock_files'] == 3478 and provider_audit['complete_stock_symlinks'] == 1048 and len(provider_audit['trees']) == 10, 'post-runtime complete stock tree audit differs')
    require((capture / 'post-runtime-provider-audit.exit-status.txt').read_bytes() == b'0\n' and (capture / 'post-runtime-provider-audit.stderr.txt').read_bytes() == b'', 'post-runtime provider audit failed')
    require((capture / 'runtime-volume-removal.stderr.txt').read_bytes() == b'' and (capture / 'runtime-volume-removal.stdout.txt').read_bytes() == (capture / 'runtime-volume-name.txt').read_bytes(), 'ephemeral Linux provider volume cleanup differs')
    report['provider_audit'] = identity(capture / 'post-runtime-provider-audit.json')
    report['volume_cleanup'] = identity(capture / 'runtime-volume-removal.stdout.txt')

    elf = (capture / 'launcher.elf.txt').read_text()
    require('[...]' not in elf, 'ELF listing is abbreviated')
    needed = re.findall(r'Shared library: \[([^]]+)\]', elf)
    require(needed == ['libm.so.6', 'libgcc_s.so.1', 'libc.so.6'] and not re.search(r'\bUND[ \t]+(?:Py|_Py)', elf), 'launcher directly links Python or another dependency')
    report['launcher'] = {'binary': identity(archives / 'glue'), 'complete_elf': identity(capture / 'launcher.elf.txt'), 'needed': needed, 'python_undefined_symbols': []}
    for path in sorted((capture / 'build-provenance').glob('*.txt')):
        text = path.read_text()
        require(path.name.startswith('glue-runtime-python-'), 'another C provenance owner')
        if path.name.endswith('.undefined.txt'):
            require(not re.search(r'\bU[ \t]+(?:Py|_Py)', text), 'boundary links Python directly')
        else:
            require('api_revision=4\n' in text and 'python_api_export_count=29\n' in text and 'boundary_compiled=true\n' in text and 'verified_installed_header_count=264\n' in text, 'C provenance differs')
        report['provenance'].append({'name': path.name, **identity(path)})
    require(len(report['provenance']) == 8, 'C provenance file inventory differs')
    report['counts'] = {'runtime_cases': 16, 'controls': 60, 'provenance_receipts': 4, 'provenance_files': 8}
    args.output.write_text(json.dumps(report, indent=2, sort_keys=True) + '\n')
    print('Control audit passed: ' + ('development capture with explicit opt-in' if args.allow_development else 'clean checkpoint') + ', sixteen exact outcomes, 60 controls bound to actual archives, four C receipts and complete launcher symbols')


if __name__ == '__main__':
    main()
