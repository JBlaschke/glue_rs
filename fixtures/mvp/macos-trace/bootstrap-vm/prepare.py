#!/usr/bin/env python3
"""Prepare a closed, reviewed NONTRACING VM packet. Never runs tools."""
import argparse
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import re
import secrets
import shlex
import sys

HERE = Path(__file__).resolve().parent
PARSER = HERE.parent / 'bootstrap-kit/build_kit.py'
PARSER_SHA = '5b9332b7d426037f7443eb61cdca0097116dee9610c35260d683f846709c04a9'
# A reviewed literal binding, not caller-provided authentication or a registry API.
APPROVED = {
    'kit_manifest_sha256': '098b758fe740d61efccd2ef34d3fe8cf00caba82e281dbc752e419e7a973995c',
    'build_id': 'a75d54bba97103ec8b15dd7be7beb5b8eb23de5bfdda624ad2fcd9f224ab84d5',
    'catalog_sha256': '95c943c36e36b7ccab9e20d3540260e61fa41eb38d880411cb7b865713cc58ab',
    'kit_review_manifest_sha256': 'af1034b7bf2d4d70f3db9c361f1fd44ef2262e8e156f30910a66e7c6bec0d591',
    'catalog_review_manifest_sha256': '44da57195e8d6b0687f9921d71695cc507a909a1a1ec300db00d7b604a540b90',
    'builder_receipt_manifest_sha256': '42ea3e6d47faf97def1cda88cd3e413bf76935d8b22688fb8db6a94962678497',
}
EXECUTION_ENABLED = True  # Reviewed fixed kit/orchestration/checker; no runtime override.
PROGRAMS = ('context-probe', 'bootstrap-runner', 'make-request')
CASES = ('positive', 'simulated', 'denied', 'trailing')
METADATA = {'catalog.bin': 'catalog.bin', 'recipe.json': 'recipe.json',
            'source-lock.json': 'source-lock.json', 'admitted-proof.json': 'admitted-proof.json',
            'build-result.json': 'result.json', 'build-SHA256SUMS': 'SHA256SUMS'}


def sha(data):
    return hashlib.sha256(data).hexdigest()


def primitives():
    if sha(PARSER.read_bytes()) != PARSER_SHA:
        raise ValueError('reviewed host parser source differs')
    spec = importlib.util.spec_from_file_location('reviewed_kit_primitives', PARSER)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def evidence_names():
    names = ['plan.json', 'batch.tsv', 'install.stdout', 'install.stderr', 'install.status']
    for case in CASES:
        names += ['case-' + case + '.' + suffix for suffix in ('stdout', 'stderr', 'status')]
        if case != 'trailing':
            names += ['requests/' + case + '.' + suffix for suffix in ('bin', 'status', 'stderr')]
        else:
            names.append('requests/trailing.bin')
        roles = ('input.sha256', 'native.status', 'output.absent') if case == 'trailing' else (
            'input.sha256', 'native.status', 'request.bin', 'status.bin', 'probe.stdout', 'probe.stderr', 'result.json')
        names += ['cases/' + case + '/' + role for role in roles]
    return sorted(names)


def load_kit(path):
    p = primitives()
    p.require(APPROVED is not None, 'actual kit approval is not configured')
    data = p.verified_tree(path, APPROVED['kit_manifest_sha256'])
    fd = p.open_directory(path)
    try:
        manifest = p.read_member(fd, 'SHA256SUMS', p.MAX_JSON)
    finally:
        os.close(fd)
    p.require(sha(manifest) == APPROVED['kit_manifest_sha256'], 'kit manifest changed')
    result = p.strict_json(data['result.json'])
    p.require(result['schema'] == 'glue-bootstrap-kit-result-v1' and result['status'] == 'built-reproducibly' and
              result['build_id'] == APPROVED['build_id'] and result['catalog_sha256'] == APPROVED['catalog_sha256'], 'kit result binding')
    p.require(all(result[k] is False for k in ('new_binaries_executed', 'installed', 'kernel_exec_proof', 'full_acceptance')), 'kit scope')
    p.require(set(result['artifacts']) == set(PROGRAMS) and sha(data['catalog.bin']) == APPROVED['catalog_sha256'], 'catalog/artifact roster')
    for name in PROGRAMS:
        artifact = result['artifacts'][name]
        binary = data['kit/' + name]
        p.require(sha(binary) == artifact['sha256'] and len(binary) == artifact['size'] and
                  binary == data['builds/first/' + name] == data['builds/second/' + name], 'artifact bytes differ')
        p.macho(binary)
    proof = p.strict_json(data['admitted-proof.json'])
    observed = p.observation(p.canonical(proof['observation']))
    p.require(proof['full_acceptance'] is False and proof['registry_entry']['manifest_sha256'] ==
              'ec28e38b3066112d874a54b0dfb4bb9c20fae3f39dc90697bf7d4ea684a84c8a', 'deployment binding')
    return data, manifest, result, observed


def make_plan(result, observed, nonce):
    p = primitives()
    p.require(type(nonce) is str and re.fullmatch('[0-9a-f]{16}', nonce), 'batch nonce')
    p.require(result['build_id'] == APPROVED['build_id'] and result['catalog_sha256'] == APPROVED['catalog_sha256'], 'closed build')
    p.require(set(result['artifacts']) == set(PROGRAMS), 'program roster')
    p.observation(p.canonical(observed))
    build = '/System/Volumes/Data/Library/GlueMVPFixtures/' + APPROVED['build_id']
    tmp = '/System/Volumes/Data/private/tmp/'
    return {
        'schema': 'glue-bootstrap-vm-plan-v1', 'approval': APPROVED.copy(),
        'build_id': result['build_id'], 'catalog_sha256': result['catalog_sha256'],
        'artifacts': {n: {'sha256': result['artifacts'][n]['sha256'], 'size': result['artifacts'][n]['size']} for n in PROGRAMS},
        'expected_ids': observed['ids'], 'expected_groups': observed['groups'],
        'root_mount': {k: observed['components'][0][k] for k in ('device', 'fsid')},
        'data_mount': {k: observed['components'][3][k] for k in ('device', 'fsid')},
        'guest_os': {'model': observed['model'], 'kernel': observed['kernel_release'], 'version': '26.6.2', 'build': '25G83'},
        'nonce': nonce, 'guest_packet': '/Volumes/My Shared Files/glue-mvp-macos-vm-toolkit/bootstrap-vm-' + nonce,
        'guest_work': tmp + 'glue-bs-user-' + nonce, 'root_stage': tmp + 'glue-bs-stage-' + nonce,
        'guest_export': '/Volumes/My Shared Files/glue-mvp-macos-vm-results/glue-bootstrap-batch-' + nonce,
        'guest_run_receipt': tmp + 'glue-bs-launch-' + nonce,
        'guest_receipt_export': '/Volumes/My Shared Files/glue-mvp-macos-vm-results/glue-bootstrap-run-receipt-' + nonce,
        'build_dir': build, 'outputs': {c: tmp + 'glue-bs-' + nonce + '-' + c for c in CASES},
        'execution_enabled': EXECUTION_ENABLED, 'full_acceptance': False,
        'evidence_files': evidence_names(),
    }


def substitute(template, values):
    for key, value in values.items():
        template = template.replace('@@' + key + '@@', value)
    if re.search('@@[A-Z_]+@@', template):
        raise ValueError('unfilled template')
    return template.encode()


def inline_guard(command):
    # POSIX set -e exempts nonlast AND-list operands. Every closed predicate
    # needs its own explicit failure edge before a later privileged operation.
    return command + ' || exit 2; '


def render(plan):
    p = primitives()
    p.exact_keys(plan, ('schema', 'approval', 'build_id', 'catalog_sha256', 'artifacts', 'expected_ids', 'expected_groups',
                        'root_mount', 'data_mount', 'guest_os', 'nonce', 'guest_packet', 'guest_work', 'root_stage',
                        'guest_export', 'guest_run_receipt', 'guest_receipt_export', 'build_dir', 'outputs',
                        'execution_enabled', 'full_acceptance', 'evidence_files'))
    p.require(plan['schema'] == 'glue-bootstrap-vm-plan-v1' and plan['approval'] == APPROVED and
              plan['build_id'] == APPROVED['build_id'] and plan['catalog_sha256'] == APPROVED['catalog_sha256'] and
              plan['execution_enabled'] is EXECUTION_ENABLED and plan['full_acceptance'] is False, 'unreviewed plan')
    nonce = plan['nonce']
    p.require(type(nonce) is str and re.fullmatch('[0-9a-f]{16}', nonce), 'batch nonce')
    tmp = '/System/Volumes/Data/private/tmp/'
    for key, value in {'guest_packet': '/Volumes/My Shared Files/glue-mvp-macos-vm-toolkit/bootstrap-vm-' + nonce,
                       'guest_work': tmp + 'glue-bs-user-' + nonce, 'root_stage': tmp + 'glue-bs-stage-' + nonce,
                       'guest_export': '/Volumes/My Shared Files/glue-mvp-macos-vm-results/glue-bootstrap-batch-' + nonce,
                       'guest_run_receipt': tmp + 'glue-bs-launch-' + nonce,
                       'guest_receipt_export': '/Volumes/My Shared Files/glue-mvp-macos-vm-results/glue-bootstrap-run-receipt-' + nonce,
                       'build_dir': '/System/Volumes/Data/Library/GlueMVPFixtures/' + APPROVED['build_id']}.items():
        p.require(plan[key] == value, 'unreviewed path')
    p.exact_keys(plan['artifacts'], PROGRAMS)
    p.exact_keys(plan['outputs'], CASES)
    p.require(plan['evidence_files'] == evidence_names(), 'export allowlist')
    p.require(type(plan['expected_ids']) is list and len(plan['expected_ids']) == 4, 'actual IDs')
    for value in plan['expected_ids']:
        p.integer(value, 1, 2147483647)
    for case in CASES:
        p.require(plan['outputs'][case] == tmp + 'glue-bs-' + nonce + '-' + case, 'native output path')
        p.require(len(Path(plan['outputs'][case]).name) <= 64 and re.fullmatch('[A-Za-z0-9._-]+', Path(plan['outputs'][case]).name), 'native output leaf')
    values = {k: shlex.quote(plan[k]) for k in ('guest_packet', 'guest_work', 'root_stage', 'build_dir', 'guest_export', 'guest_run_receipt', 'guest_receipt_export')}
    values = {k.upper(): v for k, v in values.items()}
    values['ENABLED'] = '1' if EXECUTION_ENABLED else '0'
    values['UID'] = str(plan['expected_ids'][0])
    values['KIT_SHA'] = shlex.quote(APPROVED['kit_manifest_sha256'])
    for case in CASES:
        values['OUT_' + case.upper()] = shlex.quote(plan['outputs'][case])
    installs = []
    for name in PROGRAMS:
        a = plan['artifacts'][name]
        p.exact_keys(a, ('sha256', 'size'))
        p.sha(a['sha256']); p.integer(a['size'], 1, 4194304)
        installs.append('install_file ' + shlex.quote(name) + ' ' + str(a['size']) + ' ' + shlex.quote(a['sha256']))
    values['INSTALL_FILES'] = '\n'.join(installs)
    root = substitute((HERE / 'root-stage.sh.in').read_text(), values)
    values['ROOT_SHA'] = shlex.quote(sha(root))
    values['ROOT_SIZE'] = str(len(root))
    values['ROOT_LIMIT'] = str(len(root) + 1)
    stage = plan['root_stage']
    script = stage + '/root-stage.sh'
    identities = inline_guard('[ "$(/usr/bin/id -ru)" = 0 ]') + inline_guard('[ "$(/usr/bin/id -u)" = 0 ]')
    check = 'set -eu; ' + identities
    check += inline_guard('[ -d ' + shlex.quote(stage) + ' ]') + inline_guard('[ ! -L ' + shlex.quote(stage) + ' ]')
    # BSD %p retains the file type and special bits; %Lp silently drops both.
    check += inline_guard('[ "$(/usr/bin/stat -f %u:%p ' + shlex.quote(stage) + ')" = 0:40700 ]')
    check += inline_guard('[ -f ' + shlex.quote(script) + ' ]') + inline_guard('[ ! -L ' + shlex.quote(script) + ' ]')
    check += inline_guard('[ "$(/usr/bin/stat -f %u:%p:%l ' + shlex.quote(script) + ')" = 0:100500:1 ]')
    check += inline_guard('[ "$(/usr/bin/shasum -a 256 ' + shlex.quote(script) + ')" = ' + shlex.quote(sha(root) + '  ' + script) + ' ]')
    values['ROOT_CHECK'] = shlex.quote(check + 'exec /bin/sh ' + shlex.quote(script) + ' "$1"')
    bootstrap = 'set -eu; umask 077; set -C; ' + identities
    bootstrap += inline_guard('[ "$(/usr/bin/stat -f %u:%p /System/Volumes/Data/private/tmp)" = 0:41777 ]')
    bootstrap += inline_guard('[ ! -e ' + shlex.quote(stage) + ' ]') + inline_guard('[ ! -L ' + shlex.quote(stage) + ' ]')
    bootstrap += '/bin/mkdir -m 0700 ' + shlex.quote(stage) + '; /bin/chmod -N ' + shlex.quote(stage) + '; '
    source = plan['guest_packet'] + '/root-stage.sh'
    bootstrap += inline_guard('[ -f ' + shlex.quote(source) + ' ]') + inline_guard('[ ! -L ' + shlex.quote(source) + ' ]')
    bootstrap += '/usr/bin/head -c ' + str(len(root) + 1) + ' ' + shlex.quote(source) + ' > ' + shlex.quote(script) + '; '
    bootstrap += inline_guard('[ "$(/usr/bin/stat -f %z ' + shlex.quote(script) + ')" = ' + str(len(root)) + ' ]')
    bootstrap += '/bin/chmod -N ' + shlex.quote(script) + '; /bin/chmod 0500 ' + shlex.quote(script) + '; '
    values['ROOT_BOOTSTRAP'] = shlex.quote(bootstrap + check + 'exec /bin/sh ' + shlex.quote(script) + ' install')
    values['EVIDENCE_LIST'] = '\n'.join(plan['evidence_files'])
    outer = substitute((HERE / 'outer.sh.in').read_text(), values)
    values['OUTER_SHA'] = shlex.quote(sha(outer))
    values['OUTER_SHA_RAW'] = sha(outer)
    launch = substitute((HERE / 'launch.sh.in').read_text(), values)
    return {'root-stage.sh': root, 'outer.sh': outer, 'launch.sh': launch}


def prepare(kit, output):
    p = primitives()
    data, manifest, result, observed = load_kit(kit)
    plan = make_plan(result, observed, secrets.token_hex(8))
    scripts = render(plan)
    # Parent exists, each component is physical, output exclusive/outside repo.
    output = Path(output)
    p.outside_repository(output, HERE.parents[3])
    parent = p.open_directory(output.parent)
    try:
        p.require(re.fullmatch('[A-Za-z0-9][A-Za-z0-9._-]{0,127}', output.name), 'output leaf')
        os.mkdir(output.name, 0o700, dir_fd=parent)
    finally:
        os.close(parent)
    def put(name, value, mode=0o444):
        p.relative_name(name)
        path = output / name
        path.parent.mkdir(parents=True, exist_ok=True)
        with path.open('xb') as f:
            f.write(value)
        os.chmod(path, mode)
    try:
        selected = []
        for name in PROGRAMS:
            original = 'kit/' + name
            put('payload/' + name, data[original], 0o555)
            selected.append({'member': 'payload/' + name, 'original': original, 'sha256': sha(data[original])})
        for name, original in METADATA.items():
            value = manifest if original == 'SHA256SUMS' else data[original]
            put('metadata/' + name, value)
            selected.append({'member': 'metadata/' + name, 'original': original, 'sha256': sha(value)})
        put('plan.json', p.canonical(plan))
        for name, value in scripts.items():
            put(name, value, 0o555)
        put('derived-subset.json', p.canonical({'schema': 'glue-bootstrap-vm-subset-v1', 'approval': APPROVED, 'selected': selected,
                                              'original_inventory_is_detached_metadata': True, 'full_acceptance': False}))
        fd = p.open_directory(output)
        try:
            lines = ''.join(sha(p.read_member(fd, n)) + '  ' + n + '\n' for n in sorted(p.tree_members(fd)))
        finally:
            os.close(fd)
        put('SHA256SUMS', lines.encode())
    except BaseException:
        # No cleanup or success inventory synthesis over partial preparation.
        raise
    return plan


def main():
    cli = argparse.ArgumentParser(description=__doc__)
    cli.add_argument('--kit', required=True, type=Path)
    cli.add_argument('--output', required=True, type=Path)
    args = cli.parse_args()
    try:
        prepare(args.kit, args.output)
    except (ValueError, OSError, KeyError) as exc:
        print('bootstrap-vm: ' + str(exc)[:512], file=sys.stderr)
        return 1
    return 0


if __name__ == '__main__':
    sys.exit(main())
