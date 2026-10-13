#!/usr/bin/env python3
"""Stage metadata-aware app inputs against an explicitly selected pinned provider.

This fixture adapter reuses the verified legacy preparers. It does not execute
application packages or discover/install dependencies. The normal product
builder packages its output; execution separately validates metadata contents.
"""
from __future__ import annotations

import argparse
import csv
import hashlib
import importlib.util
import io
import json
from pathlib import Path
import sys

HERE = Path(__file__).resolve().parent
HELPER = 'python/archive-metadata.py'
BUILDS = {
    'bundled': 'pbs-20261009-cpython-3.13.16-pgo-lto-bundled-metadata-apps-v1',
    'host': 'pbs-20261009-cpython-3.13.16-pgo-lto-host-metadata-apps-v1',
    'install-host': 'pbs-20261009-cpython-3.13.16-pgo-lto-host-install-metadata-apps-v1',
}


def load(name, directory):
    spec = importlib.util.spec_from_file_location(name, HERE.parent / directory / 'prepare.py')
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def prepare(provider, application, output, base, prefix, app_id, entry, component, bad_record=False):
    if provider == 'bundled':
        if base is None or prefix is not None:
            raise ValueError('bundled metadata requires --base and no --prefix')
        load('metadata_bundled_stage', 'python-source-apps').prepare(base, application, output, app_id, entry, component)
    elif provider == 'host':
        if base is None or prefix is None:
            raise ValueError('full-host metadata requires --base and --prefix')
        load('metadata_host_stage', 'python-host-source-apps').stage(base, application, output, prefix, app_id, entry, component)
    else:
        if base is not None or prefix is None:
            raise ValueError('install-host metadata requires --prefix and no --base')
        load('metadata_install_stage', 'python-install-host-source-apps').stage(application, output, prefix, app_id, entry, component)
    manifest_path = output / 'manifest.json'
    manifest = json.loads(manifest_path.read_text())
    if bad_record:
        records = sorted(key for key in manifest['resources'] if key.startswith('app/python/') and key.endswith('.dist-info/RECORD'))
        if not records:
            raise ValueError('RECORD control requires a distribution')
        key = records[0]
        source = output / 'root' / key
        rows = list(csv.reader(io.StringIO(source.read_text())))
        if not rows:
            raise ValueError('RECORD control requires a file row')
        rows[0][0] = '../escape.py'
        stream = io.StringIO(newline='')
        csv.writer(stream, lineterminator='\n').writerows(rows)
        payload = stream.getvalue().encode()
        source.write_bytes(payload)
        manifest['resources'][key] = {'size': len(payload), 'sha256': hashlib.sha256(payload).hexdigest(), 'compression': 'stored'}
    helper = (HERE / 'bootstrap.py').read_bytes()
    if not helper or len(helper) > 64 * 1024 or b'\0' in helper:
        raise ValueError('metadata helper exceeds the fixed source boundary')
    target = output / 'root' / HELPER
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_bytes(helper)
    manifest['resources'][HELPER] = {'size': len(helper), 'sha256': hashlib.sha256(helper).hexdigest(), 'compression': 'deflate'}
    runtime = manifest['runtimes']['python']
    runtime['build_id'] = BUILDS[provider]
    if provider == 'bundled':
        runtime['provisioning']['source']['variant'] = 'pgo+lto-full/bundled-metadata-apps-v1'
    manifest_path.write_text(json.dumps(manifest, sort_keys=True, separators=(',', ':')) + '\n')
    (output / 'metadata-prepare-summary.json').write_text(json.dumps({
        'schema_version': 0, 'provider': provider, 'app_id': app_id, 'entry': entry,
        'bad_record_control': bad_record, 'helper': manifest['resources'][HELPER],
        'application': {key: value for key, value in manifest['resources'].items() if key.startswith('app/')},
    }, indent=2, sort_keys=True) + '\n')


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('provider', choices=BUILDS)
    parser.add_argument('application', type=Path)
    parser.add_argument('output', type=Path)
    parser.add_argument('--base', type=Path)
    parser.add_argument('--prefix')
    parser.add_argument('--app-id', default='distribution.metadata')
    parser.add_argument('--entry', default='app/main.py')
    parser.add_argument('--component', default='launch')
    parser.add_argument('--bad-record', action='store_true')
    args = parser.parse_args()
    try:
        prepare(args.provider, args.application, args.output, args.base, args.prefix,
                args.app_id, args.entry, args.component, args.bad_record)
    except (OSError, ValueError, KeyError, TypeError, csv.Error) as error:
        print('metadata preparation rejected: ' + str(error), file=sys.stderr)
        return 1
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
