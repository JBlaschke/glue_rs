#!/usr/bin/env python3
"""Strict six-workload traces for source-only installed-package ingestion.

The runtime, provider, loader and syscall policy remains the privately imported
metadata policy. Only the independently checked-in normalized application and
the workload inventory change. This does not trace package installation.
"""
from __future__ import annotations

import hashlib
import importlib.util
import json
from pathlib import Path
import re
import struct
import sys
import zipfile
import zlib


spec = importlib.util.spec_from_file_location(
    'venv_private_metadata_policy', Path(__file__).with_name('check-linux-python-metadata-trace.py'))
METADATA = importlib.util.module_from_spec(spec)
spec.loader.exec_module(METADATA)
ROOT = Path(__file__).resolve().parents[1]
INPUT = ROOT / 'fixtures/python-venv-ingestion/expected-input'
INVENTORY = ROOT / 'fixtures/python-venv-ingestion/expected-inventory.json'
TraceError = METADATA.TraceError
MODES = ('bundled', 'host', 'install-host', 'bundled-corrupt-metadata',
         'host-corrupt-metadata', 'install-host-corrupt-metadata')
CRC_PREFIX = ('app/main.py', METADATA.DIST_INFO + '/INSTALLER', METADATA.CORRUPT_KEY)


def application_bytes(mode):
    METADATA.profile_for(mode)
    data = json.loads(INVENTORY.read_text())
    if (not isinstance(data, dict) or set(data) != {'schema_version', 'files'} or
            type(data['schema_version']) is not int or data['schema_version'] != 0 or
            not isinstance(data['files'], dict) or len(data['files']) != 11):
        raise TraceError('installed-package expected inventory differs from eleven normalized app files')
    files = {path.relative_to(INPUT).as_posix(): path.read_bytes()
             for path in sorted(INPUT.rglob('*')) if path.is_file()}
    if set(files) != set(data['files']):
        raise TraceError('installed-package expected input paths differ from independent inventory')
    for key, payload in files.items():
        value = data['files'][key]
        if (not isinstance(value, dict) or set(value) != {'size', 'sha256'} or
                type(value['size']) is not int or value['size'] != len(payload) or
                not isinstance(value['sha256'], str) or re.fullmatch('[0-9a-f]{64}', value['sha256']) is None or
                value['sha256'] != hashlib.sha256(payload).hexdigest()):
            raise TraceError('installed-package expected bytes differ from independent inventory: ' + key)
    return files


def corrupt_bytes():
    raw = application_bytes('host')[METADATA.CORRUPT_KEY]
    return bytes([raw[0] ^ 1]) + raw[1:]


# Mutate only this fresh private module, preserving every historical policy.
METADATA.MODES = MODES
METADATA.application_bytes = application_bytes
METADATA.corrupt_bytes = corrupt_bytes

_archive_record = METADATA.archive_record
_retained_metadata = METADATA.retained_metadata
_checker = METADATA.Checker


def archive_record(path, mode):
    record = _archive_record(path, mode)
    if mode.endswith('-corrupt-metadata'):
        offsets = {}
        with zipfile.ZipFile(path) as archive, path.open('rb') as stream:
            for key in CRC_PREFIX:
                info = archive.getinfo(key)
                stream.seek(info.header_offset)
                header = stream.read(30)
                names, extra = struct.unpack_from('<HH', header, 26)
                offsets[key] = info.header_offset + 30 + names + extra
        record['crc_read_offsets'] = offsets
    return record


def retained_metadata(path, mode, size):
    if not mode.endswith('-corrupt-metadata'):
        return _retained_metadata(path, mode, size)
    profile = METADATA.profile_for(mode)
    if path.stat().st_size > 256 * 1024:
        raise TraceError('retained ingestion metadata exceeds bounded profile')
    data = json.loads(path.read_text())
    if (not isinstance(data, dict) or set(data) != {'schema_version', 'archives'} or
            type(data.get('schema_version')) is not int or data['schema_version'] != 0 or
            not isinstance(data.get('archives'), dict) or set(data['archives']) != set(MODES)):
        raise TraceError('retained ingestion metadata schema/workload inventory differs')
    record = data['archives'][mode]
    keys = {'bytes', 'sha256', 'manifest_sha256', 'manifest_bytes', 'zip_directory_offset',
            'app_id', 'entry', 'component', 'application', 'provider', 'target', 'readiness',
            'corrupt_offset', 'crc_read_offsets'}
    lower, upper = (73563968, 128 * 1024 * 1024) if profile == 'bundled' else (64, 16 * 1024 * 1024)
    if (not isinstance(record, dict) or set(record) != keys or
            type(record.get('bytes')) is not int or record['bytes'] != size or
            not lower < size <= upper or
            (record.get('app_id'), record.get('entry'), record.get('component')) != METADATA.IDENTITY):
        raise TraceError('retained ingestion metadata archive identity differs')
    if (not METADATA.SOURCE.typed_equal(record['application'], METADATA.expected_application(mode)) or
            not METADATA.SOURCE.typed_equal(record['provider'], METADATA.provider_contract(mode)) or
            not METADATA.SOURCE.typed_equal(record['target'], METADATA.TARGET)):
        raise TraceError('retained ingestion application/provider/target differs')
    if any(not isinstance(record.get(key), str) or re.fullmatch('[0-9a-f]{64}', record[key]) is None
           for key in ('sha256', 'manifest_sha256')):
        raise TraceError('retained ingestion metadata digest is noncanonical')
    METADATA.PRODUCT.validate_readiness(record['readiness'], size,
                                        (record['manifest_bytes'], record['zip_directory_offset']))
    manifest_bound = (2 if profile == 'bundled' else 1) * 1024 * 1024
    directory_bound = 2 * 1024 * 1024 if profile == 'bundled' else 256 * 1024
    if record['manifest_bytes'] > manifest_bound or size - record['zip_directory_offset'] > directory_bound:
        raise TraceError('retained ingestion manifest/directory exceeds selected profile bounds')
    offsets = record['crc_read_offsets']
    payloads = application_bytes(mode)
    if (not isinstance(offsets, dict) or set(offsets) != set(CRC_PREFIX) or
            any(type(offsets[key]) is not int or
                not 64 + record['manifest_bytes'] <= offsets[key] <= record['zip_directory_offset'] - len(payloads[key])
                for key in CRC_PREFIX) or
            type(record['corrupt_offset']) is not int or record['corrupt_offset'] != offsets[METADATA.CORRUPT_KEY] or
            any(offsets[before] + len(payloads[before]) > offsets[after]
                for before, after in zip(CRC_PREFIX, CRC_PREFIX[1:]))):
        raise TraceError('retained ingestion CRC read offsets differ from ordered admitted payloads')
    return record


class Checker(_checker):
    """Pin the three stored payload reads before the metadata CRC rejection."""

    def line(self, line):
        if self.mode.endswith('-corrupt-metadata'):
            match = METADATA.BASE.LINE.fullmatch(line)
            if match is not None and match[2] == 'read':
                args = METADATA.BASE.split_arguments(match[3])
                runtime = getattr(self.checker, 'runtime', self.checker)
                if (len(args) == 3 and METADATA.PBS.descriptor(args[0])[1] == METADATA.archive_for(self.mode)
                        and self.checker.uname_queries):
                    if self.crc_payload_reads >= len(CRC_PREFIX):
                        raise TraceError('ingestion CRC control contains an extra payload read')
                    key = CRC_PREFIX[self.crc_payload_reads]
                    data = corrupt_bytes() if key == METADATA.CORRUPT_KEY else application_bytes(self.mode)[key]
                    visible = re.fullmatch(r'"((?:[^"\\]|\\.)*)"(\.\.\.)?', args[1])
                    if visible is None or args[2] != str(len(data)) or match[4] != str(len(data)):
                        raise TraceError('ingestion CRC control payload length/order differs')
                    try:
                        prefix = bytes(visible[1], 'ascii').decode('unicode_escape').encode('latin1')
                    except (ValueError, UnicodeError) as error:
                        raise TraceError('ingestion CRC visible bytes are not a complete byte encoding') from error
                    if (prefix != data[:256] or bool(visible[2]) != (len(data) > 256) or
                            runtime.archive_cursor != self.record['crc_read_offsets'][key]):
                        raise TraceError('ingestion CRC entry/INSTALLER/metadata bytes or exact offsets differ')
                    self.crc_payload_reads += 1
        return self.checker.line(line)

    def finish(self):
        self.checker.finish()
        if self.mode.endswith('-corrupt-metadata'):
            runtime = getattr(self.checker, 'runtime', self.checker)
            payloads = application_bytes(self.mode)
            expected_read = self.record['readiness']['archive_read_bytes'] + sum(len(payloads[key]) for key in CRC_PREFIX)
            if (self.crc_payload_reads != len(CRC_PREFIX) or runtime.archive_read != expected_read or
                    runtime.archive_cursor != self.record['corrupt_offset'] + len(corrupt_bytes())):
                raise TraceError('ingestion CRC rejection lacks its exact complete three-read phase')
            for lower, upper in ((0, 64 + self.record['manifest_bytes']),
                                 (self.record['zip_directory_offset'], runtime.archive_bytes)):
                if not any(start <= lower and end >= upper
                           for start, end in METADATA.PRODUCT.merged_ranges(runtime.archive_ranges)):
                    raise TraceError('ingestion CRC rejection lacks complete manifest/ZIP admission')


METADATA.archive_record = archive_record
METADATA.retained_metadata = retained_metadata
METADATA.Checker = Checker


def __getattr__(name):
    return getattr(METADATA, name)


if __name__ == '__main__':
    try:
        raise SystemExit(METADATA.main())
    except (OSError, EOFError, ValueError, KeyError, TypeError, UnicodeError,
            struct.error, zipfile.BadZipFile, zlib.error, TraceError) as error:
        print('Python installed-package trace rejected: ' + str(error), file=sys.stderr)
        raise SystemExit(1)
