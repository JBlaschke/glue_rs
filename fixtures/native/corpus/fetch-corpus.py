"""Download and unpack the pinned native wheel corpus as build-time input.

Usage: python3 -I fixtures/native/corpus/fetch-corpus.py [--pins PINS] [--output DIR]

The default output directory is target/native-corpus/. Every wheel is verified
against the pinned size and SHA-256 before it is unpacked into its own
directory; a wheel that is already present and verified is not downloaded
again. Downloads use the system curl. The unpacked trees are untrusted data:
nothing in this repository imports or executes them, and the survey only
reads their bytes.
"""

import argparse
import hashlib
import json
import subprocess
import sys
import zipfile
from pathlib import Path

HERE = Path(__file__).resolve().parent
ROOT = HERE.parent.parent.parent


def fail(message):
    print('fetch-corpus: ' + message, file=sys.stderr)
    sys.exit(1)


def sha256(path):
    digest = hashlib.sha256()
    with path.open('rb') as handle:
        for block in iter(lambda: handle.read(1 << 20), b''):
            digest.update(block)
    return digest.hexdigest()


def verified(path, pin):
    return path.is_file() and path.stat().st_size == pin['size'] and sha256(path) == pin['sha256']


def download(pin, path):
    # curl uses the operating system's certificate store; the framework Python
    # on the development Mac ships without one. The pinned hash decides
    # acceptance either way.
    print('downloading ' + pin['filename'])
    partial = path.with_name(path.name + '.partial')
    command = ['curl', '--fail', '--location', '--silent', '--show-error', '--max-time', '600',
               '--max-filesize', str(pin['size']), '--output', str(partial), pin['url']]
    completed = subprocess.run(command, check=False)
    if completed.returncode != 0:
        fail('curl exited with status ' + str(completed.returncode) + ' for ' + pin['filename'])
    if not verified(partial, pin):
        partial.unlink(missing_ok=True)
        fail('downloaded ' + pin['filename'] + ' does not match its pinned size/SHA-256')
    partial.rename(path)


def unpack(path, directory):
    with zipfile.ZipFile(path) as wheel:
        for member in wheel.infolist():
            name = member.filename
            if name.startswith('/') or '..' in Path(name).parts or '\\' in name:
                fail('refusing wheel member path ' + repr(name))
        wheel.extractall(directory)


def main():
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument('--pins', type=Path, default=HERE / 'wheel-pins.json')
    parser.add_argument('--output', type=Path, default=ROOT / 'target' / 'native-corpus')
    arguments = parser.parse_args()
    pins = json.loads(arguments.pins.read_bytes())
    if pins.get('schema_version') != 0:
        fail('unsupported pins schema')
    wheels = arguments.output / 'wheels'
    unpacked = arguments.output / 'unpacked'
    wheels.mkdir(parents=True, exist_ok=True)
    unpacked.mkdir(parents=True, exist_ok=True)
    for pin in pins['wheels']:
        path = wheels / pin['filename']
        if not verified(path, pin):
            download(pin, path)
        if not verified(path, pin):
            fail(path.name + ' failed verification after download')
        directory = unpacked / (pin['project'] + '-' + pin['version'])
        if directory.exists():
            print('already unpacked ' + directory.name)
            continue
        staging = unpacked / (directory.name + '.partial')
        if staging.exists():
            fail('remove stale ' + str(staging))
        unpack(path, staging)
        staging.rename(directory)
        print('unpacked ' + directory.name)
    print('corpus ready in ' + str(arguments.output))


if __name__ == '__main__':
    main()
