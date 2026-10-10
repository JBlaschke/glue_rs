#!/usr/bin/env python3
"""Independent hostile edits against all eleven captured registered-extension traces.

Run: python3 target/python-extensions-design-trace-audit.py CAPTURE_DIRECTORY OUTPUT.json
Raw MODE.trace.txt or gzip MODE.trace.txt.gz inputs are accepted. The output uses
capture-relative names and includes exact edits, source/checker/input identities,
all eleven baseline results, and the original 35 controls plus two archive
coverage controls. Only the output JSON is written; no runtime is executed.
"""
import argparse
import datetime
import gzip
import hashlib
import importlib.util
import json
from pathlib import Path
import re
import subprocess


ROOT = next(parent for parent in Path(__file__).resolve().parents
            if (parent / 'scripts/check-linux-python-extension-trace.py').is_file())


def sha256(payload):
    return hashlib.sha256(payload).hexdigest()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('capture_directory', type=Path)
    parser.add_argument('output', type=Path)
    parser.add_argument('--require-clean', action='store_true',
                        help='fail unless the current source and capture are the same clean revision')
    args = parser.parse_args()
    checker_path = ROOT / 'scripts/check-linux-python-extension-trace.py'
    checker_hash = sha256(checker_path.read_bytes())
    spec = importlib.util.spec_from_file_location('independent_actual_trace_audit', checker_path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    capture = args.capture_directory.resolve()
    retained = json.loads((capture / 'native-metadata.json').read_text())
    traces, baselines, mutants = {}, [], []

    for mode in module.MODES:
        path = capture / (mode + '.trace.txt')
        if not path.exists():
            path = capture / (mode + '.trace.txt.gz')
        stored = path.read_bytes()
        raw = gzip.decompress(stored) if path.suffix == '.gz' else stored
        lines = raw.decode('utf-8', errors='strict').splitlines(True)
        record = retained['archives'][mode if mode in module.NEGATIVE else module.cell_for(mode)]
        size = record['bytes']
        offset = record.get('corrupt_native_offset') if mode == 'corrupt-native' else None
        admission = (record['manifest_bytes'], record['zip_directory_offset'])
        traces[mode] = (lines, size, offset, admission)
        try:
            module.retained_metadata(capture / 'native-metadata.json', mode, size, offset)
            module.check_lines(lines, mode, size, offset, admission)
            status, reason = 'accepted', None
        except Exception as error:
            status, reason = 'rejected', type(error).__name__ + ': ' + str(error)
        baselines.append({'mode': mode, 'trace': path.name, 'trace_sha256': sha256(raw),
                          'stored_trace_sha256': sha256(stored), 'archive_bytes': size,
                          'corrupt_native_offset': offset, 'admission': list(admission),
                          'status': status, 'reason': reason})

    def add(name, mode, edits):
        original, size, offset, admission = traces[mode]
        changed = original.copy()
        for edit in sorted(edits, key=lambda item: item['index'], reverse=True):
            index = edit['index']
            if edit['op'] == 'insert':
                changed.insert(index, edit['after'])
            elif edit['op'] == 'delete':
                edit['before'] = changed[index]
                changed.pop(index)
            elif edit['op'] == 'replace':
                edit['before'] = changed[index]
                changed[index] = edit['after']
            else:
                raise ValueError('unknown hostile-edit operation')
        try:
            module.check_lines(changed, mode, size, offset, admission)
            status, reason = 'accepted', None
        except Exception as error:
            status, reason = 'rejected', type(error).__name__ + ': ' + str(error)
        mutants.append({'name': name, 'mode': mode, 'edits': edits,
                        'mutant_sha256': sha256(''.join(changed).encode()),
                        'status': status, 'reason': reason})

    def insert(name, mode, index, call):
        pid = re.match(r'([0-9]+)', traces[mode][0][0])[1]
        add(name, mode, [{'op': 'insert', 'index': index, 'after': f'{pid}    {call}\n'}])

    def replace(name, mode, index, old, new):
        line = traces[mode][0][index]
        if old not in line:
            raise ValueError(f'{name}: expected text is absent from selected record')
        add(name, mode, [{'op': 'replace', 'index': index, 'after': line.replace(old, new)}])

    def delete(name, mode, indices):
        add(name, mode, [{'op': 'delete', 'index': index} for index in indices])

    mode = 'host-host'
    lines = traces[mode][0]
    publication = next(i for i, line in enumerate(lines) if 'write(1</evidence/' in line)
    base = next(re.search(r'mmap\((0x[0-9a-f]+), 131072, PROT_READ\|PROT_EXEC', line)[1]
                for line in lines if '131072, PROT_READ|PROT_EXEC' in line and 'libglue_python_dependency.so>' in line)
    runtime = next(hex(int(re.search(r' = (0x[0-9a-f]+)', line)[1], 16) + 8192)
                   for line in lines if 'mmap(' in line and 'PROT_READ|PROT_EXEC' in line and '/lib/libpython3.13.so.1.0>' in line)
    for name, call in (
        ('native_fixed_anonymous_replacement', f'mmap({base}, 4096, PROT_READ|PROT_WRITE, MAP_PRIVATE|MAP_FIXED|MAP_ANONYMOUS, -1, 0) = {base}'),
        ('native_null_mapping_result_collision', f'mmap(NULL, 4096, PROT_READ|PROT_WRITE, MAP_PRIVATE|MAP_ANONYMOUS, -1, 0) = {base}'),
        ('native_guard_permissions_changed', f'mprotect({hex(int(base, 16) + 8192)}, 4096, PROT_READ|PROT_WRITE) = 0'),
        ('native_mapped_pages_unmapped', f'munmap({base}, 4096) = 0'),
        ('selected_runtime_unmapped', f'munmap({runtime}, 4096) = 0'),
        ('selected_runtime_rx_made_writable', f'mprotect({runtime}, 4096, PROT_READ|PROT_WRITE) = 0'),
        ('selected_runtime_null_result_collision', f'mmap(NULL, 4096, PROT_READ|PROT_WRITE, MAP_PRIVATE|MAP_ANONYMOUS, -1, 0) = {runtime}'),
        ('unknown_failed_process_creation', 'clone3({}, 64) = -1 ENOSYS (Function not implemented)'),
        ('failed_virtual_source_fallback', f'openat({module.BUNDLED.CWD}, "glue://stock-pbs-registered-extensions/app/missing.py", O_RDONLY) = -1 ENOENT (No such file or directory)'),
        ('failed_materialization_attempt', f'openat({module.BUNDLED.CWD}, "/tmp/native.so", O_WRONLY|O_CREAT, 0600) = -1 EACCES (Permission denied)'),
        ('empty_diagnostic_write', 'write(1</evidence/host-host.stdout.txt>, "", 0) = 0'),
    ):
        insert(name, mode, publication, call)
    replace('wrong_exec_command', mode, 0, 'run-extensions', 'run-imports')
    replace('wrong_stdout_identity', mode, publication, 'host-host.stdout', 'other.stdout')
    read = next(i for i, line in enumerate(lines) if 'read(' in line and 'host Python extensions/libglue_python_dependency.so>' in line and '", 1) = 0' in line)
    replace('zero_count_false_eof', mode, read, '", 1) = 0', '", 0) = 0')
    metadata = next(i for i, line in enumerate(lines) if 'statx(' in line and 'host Python extensions/libglue_python_dependency.so' in line and 'stx_size=67152,' in line)
    replace('native_size_prefix_confusion', mode, metadata, 'stx_size=67152,', 'stx_size=671520,')
    replace('native_symlink_kind', mode, metadata, 'S_IFREG', 'S_IFLNK')
    replace('native_path_missing_nofollow', mode, metadata, 'AT_SYMLINK_NOFOLLOW', '0')
    loader = next(i for i, line in enumerate(lines) if 'mmap(' in line and '131072, PROT_READ|PROT_EXEC' in line and 'libglue_python_dependency.so>' in line)
    replace('native_wrong_segment_length', mode, loader, '131072', '131073')
    replace('native_fixed_result_differs', mode, loader, ' = ' + base, ' = ' + hex(int(base, 16) + 4096))
    relro = next(i for i, line in enumerate(lines) if f'mprotect({hex(int(base, 16) + 0x1f000)}, 4096, PROT_READ)' in line)
    add('duplicate_native_relro', mode, [{'op': 'insert', 'index': relro, 'after': lines[relro]}])
    guard = next(i for i, line in enumerate(lines) if f'mprotect({hex(int(base, 16) + 4096)}, 122880, PROT_NONE)' in line)
    delete('missing_native_gap_guard', mode, [guard])
    reservation = next(i for i, line in enumerate(lines) if 'mmap(NULL, 196848, PROT_NONE' in line)
    old = re.search(r' = (0x[0-9a-f]+)', lines[reservation])[1]
    replace('native_reservation_overlaps_first_image', mode, reservation, ' = ' + old, ' = ' + base)
    remap = next(i for i, line in enumerate(lines) if 'mremap(' in line and i > guard)
    old = re.search(r' = (0x[0-9a-f]+)', lines[remap])[1]
    replace('moved_buffer_destination_overlaps_native', mode, remap, ' = ' + old, ' = ' + base)
    source_open = next(line for line in lines if 'openat(' in line and '"/build-target/host Python extensions/libglue_python_dependency.so"' in line)
    source_fd = re.search(r' = ([0-9]+)<', source_open)[1]
    insert('early_native_source_close', mode, publication, f'close({source_fd}</build-target/host Python extensions/libglue_python_dependency.so>) = 0')
    pid = lines[0].split()[0]
    insert('delegated_reader_fd_collides_native', mode, publication, f'openat({module.BUNDLED.CWD}, "/proc/self/maps", O_RDONLY|O_CLOEXEC) = {source_fd}</proc/{pid}/maps>')
    checker = module.Checker(mode, traces[mode][1])
    seen, omitted = set(), []
    for index, line in enumerate(lines):
        match = module.BASE.LINE.fullmatch(line[:-1])
        if match:
            name, call_args = match[2], module.BASE.split_arguments(match[3])
            if name in {'fstat', 'statx', 'newfstatat'}:
                try:
                    number = module.descriptor(call_args[0])[0]
                except module.TraceError:
                    number = None
                if number in checker.directory_fds:
                    path = checker.directory_fds[number]
                    if path in seen:
                        omitted.append(index)
                    else:
                        seen.add(path)
        checker.line(line[:-1])
    delete('fresh_ancestor_fd_metadata_omitted', mode, omitted)

    mode = 'host-archived'
    lines = traces[mode][0]
    for name, operation in (('native_seal_verification_omitted', 'F_GET_SEALS'), ('native_seal_installation_omitted', 'F_ADD_SEALS')):
        index = next(i for i, line in enumerate(lines) if operation in line and 'glue-python-native-libglue_python_dependency.so' in line)
        delete(name, mode, [index])

    mode = 'host-host-app-error'
    index = next(i for i, line in enumerate(traces[mode][0]) if 'GLUE_PYTHON_EXTENSIONS_PASS' in line)
    delete('app_error_before_native_pass', mode, [index])

    mode = 'missing-host-image'
    lines = traces[mode][0]
    start = next(i for i, line in enumerate(lines) if 'close(' in line and '</build-target/relocated Python extensions/missing-host-image.glue>)' in line) + 1
    failure = next(i for i, line in enumerate(lines) if 'libglue_python_dependency.so"' in line and 'ENOENT' in line)
    end = failure + 1
    while 'close(' in lines[end]:
        end += 1
    delete('missing_image_without_ancestor_admission', mode, list(range(start, failure)) + list(range(failure + 1, end)))
    diagnostic = next(i for i, line in enumerate(lines) if 'write(2</evidence/' in line)
    replace('negative_wrong_stream_number', mode, diagnostic, 'write(2<', 'write(0<')
    replace('negative_wrong_stderr_identity', mode, diagnostic, 'missing-host-image.stderr', 'other.stderr')
    insert('negative_acquisition_after_diagnostic', mode, diagnostic + 1, f'openat({module.BUNDLED.CWD}, "/etc/ld.so.cache", O_RDONLY|O_CLOEXEC) = 9</etc/ld.so.cache>')

    mode = 'corrupt-native'
    lines = traces[mode][0]
    corrupt = next(i for i, line in enumerate(lines) if 'read(' in line and '"~ELF' in line)
    replace('corrupt_selected_payload_marker_missing', mode, corrupt, '"~ELF', '"\\177ELF')
    last = next(i for i, line in enumerate(lines) if i > corrupt and 'read(' in line and ', 1616) = 1616' in line)
    delete('corrupt_selected_payload_truncated', mode, [last])
    manifest = next(i for i, line in enumerate(lines) if 'read(' in line and '"{\\"app_id\\"' in line)
    delete('corrupt_manifest_coverage_omitted', mode, [manifest])
    central = next(i for i, line in enumerate(lines) if 'read(' in line and '"PK\\1\\2' in line)
    delete('corrupt_zip_directory_coverage_omitted', mode, [central])

    parent_policies = [
        'scripts/check-linux-python-import-trace.py',
        'scripts/check-linux-python-host-import-trace.py',
        'scripts/check-linux-python-bootstrap-trace.py',
        'scripts/check-linux-pbs-trace.py',
        'scripts/check-linux-memfd-trace.py',
    ]
    capture_revision = (capture / 'source-revision.txt').read_text().strip()
    capture_status = (capture / 'source-status.txt').read_text()
    source_revision = subprocess.check_output(['git', 'rev-parse', 'HEAD'], cwd=ROOT, text=True).strip()
    source_status = subprocess.check_output(['git', 'status', '--porcelain'], cwd=ROOT, text=True)
    log = {
        'schema_version': 0,
        'scope': 'Independent complete captured-trace and retained-metadata replay plus hostile trace edits; no new runtime executions.',
        'created_utc': datetime.datetime.now(datetime.timezone.utc).isoformat(),
        'source_revision': source_revision, 'source_status': source_status,
        'capture_source_revision': capture_revision, 'capture_source_status': capture_status,
        'source_and_capture_match': source_revision == capture_revision and source_status == capture_status,
        'audit_script_sha256': sha256(Path(__file__).read_bytes()),
        'checker': str(checker_path.relative_to(ROOT)), 'checker_sha256': checker_hash,
        'parent_policy_sha256': {name: sha256((ROOT / name).read_bytes()) for name in parent_policies},
        'native_metadata_sha256': sha256((capture / 'native-metadata.json').read_bytes()),
        'baselines': baselines, 'mutants': mutants,
        'summary': {'baselines_accepted': sum(item['status'] == 'accepted' for item in baselines),
                    'baselines_total': len(baselines),
                    'mutants_rejected': sum(item['status'] == 'rejected' for item in mutants),
                    'mutants_total': len(mutants)},
        'checker_changed_during_audit': sha256(checker_path.read_bytes()) != checker_hash,
    }
    args.output.write_text(json.dumps(log, indent=2, sort_keys=True) + '\n')
    print(json.dumps({'output': str(args.output), 'summary': log['summary'],
                      'source_and_capture_match': log['source_and_capture_match'],
                      'checker_changed_during_audit': log['checker_changed_during_audit'],
                      'accepted_mutants': [item['name'] for item in mutants if item['status'] == 'accepted']}))
    return int(bool(log['checker_changed_during_audit'] or log['summary']['baselines_accepted'] != len(baselines) or
               log['summary']['mutants_rejected'] != len(mutants) or
               args.require_clean and (not log['source_and_capture_match'] or source_status or capture_status)))


if __name__ == '__main__':
    raise SystemExit(main())
