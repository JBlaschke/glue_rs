"""Check exact build, verify and doctor reports against retained identities."""
from pathlib import Path
import hashlib
import json
import sys

root = Path(sys.argv[1])
records = json.loads((root / 'source-metadata.json').read_text())['archives']
builds = {}
reports = {}
metadata_key = 'app/python/glue_meta_demo-1.2.3.dist-info/METADATA'
labels = {'bundled': 'bundled', 'host': 'explicit-host', 'install-host': 'install-only host'}
doctor_prefix = (
    'Launcher: glue 0.1.0 on linux/aarch64\n'
    'Linked Lua: 5.4.9 (int64, float64)\n'
    'Available: archive packaging, inspection, verification, read-only resources, linked Lua source profile\n'
    'Pending: general runtime/package compatibility, Node adapters, workers, standalone signing\n'
    'Python: controlled CPython 3.13.16 / PBS 20261009 profiles; GNU Linux arm64 execution only\n'
    'Validated metadata for distribution.metadata\n'
)


def check(mode, operation, stdout, stderr=b'', status=0):
    prefix = root / 'cli-controls' / (mode + '.' + operation)
    assert Path(str(prefix) + '.stdout.txt').read_bytes() == stdout
    assert Path(str(prefix) + '.stderr.txt').read_bytes() == stderr
    assert int(Path(str(prefix) + '.exit-status.txt').read_text()) == status
    return {'stdout_sha256': hashlib.sha256(stdout).hexdigest(),
            'stderr_sha256': hashlib.sha256(stderr).hexdigest(), 'exit_status': status}


for mode, record in records.items():
    provider = mode.removesuffix('-bad-record').removesuffix('-corrupt-metadata')
    manifest = json.loads((root / (provider + ('-bad-record' if mode.endswith('-bad-record') else '') + '.manifest.json')).read_text())
    count = len(manifest['resources'])
    total = sum(item['size'] for item in manifest['resources'].values())
    if not mode.endswith('-corrupt-metadata'):
        stdout = (
            f'Built /build-target/relocated Python metadata/{mode}.glue: {count} resources, '
            f'{record["bytes"]} archive bytes, {total} uncompressed bytes\n'
            f'Archive SHA-256: {record["sha256"]}\n'
        ).encode()
        builds[mode] = check(mode, 'build', stdout)
        builds[mode].update(resources=count, archive_bytes=record['bytes'], uncompressed_bytes=total)
    stdout = (doctor_prefix + f'Ready: pinned {labels[provider]} Python distribution metadata application '
              'build/target prerequisites, CPython 3.13.16 / PBS 20261009\n'
              'Run checks profile archive limits, contents and explicit host prerequisites before loading Python\n').encode()
    reports[mode + '.doctor'] = check(mode, 'doctor', stdout)
    if mode.endswith('-corrupt-metadata'):
        stderr = f'glue: resource "{metadata_key}" failed CRC32 verification\n'.encode()
        reports[mode + '.verify'] = check(mode, 'verify', b'', stderr, 1)
    else:
        stdout = f'Verified {count} resources ({total} uncompressed bytes)\n'.encode()
        reports[mode + '.verify'] = check(mode, 'verify', stdout)

result = {'schema_version': 0, 'checked_build_controls': len(builds), 'builds': builds,
          'checked_exact_read_only_reports': len(reports), 'read_only_reports': reports}
assert len(builds) == 6 and len(reports) == 18
(root / 'independent-build-control-audit.json').write_text(json.dumps(result, indent=2, sort_keys=True) + '\n')
print('All six exact build controls and eighteen verify/doctor reports agree')
