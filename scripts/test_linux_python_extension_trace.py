"""Hostile controls for the registered-extension complete-trace policy."""
import copy
import gzip
import importlib.util
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest


def load(filename, name):
    spec = importlib.util.spec_from_file_location(name, Path(__file__).with_name(filename))
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


C = load('check-linux-python-extension-trace.py', 'extension_checker_test')
B = load('test_linux_python_import_trace.py', 'extension_bundled_fixture')
H = load('test_linux_python_host_import_trace.py', 'extension_host_fixture')
CWD = C.BUNDLED.CWD
SIZE = B.CHECKER.ARCHIVE_BYTES
OFFSET = 4096
SCRIPT = Path(__file__).with_name('check-linux-python-extension-trace.py')


def metadata(path, kind, size, fd=None):
    location = CWD if fd is None else f'{fd}<{path}>'
    argument = json.dumps(path) if fd is None else '""'
    flags = 'AT_STATX_SYNC_AS_STAT|' + ('AT_SYMLINK_NOFOLLOW' if fd is None else 'AT_EMPTY_PATH')
    return f'statx({location}, {argument}, {flags}, STATX_ALL, {{stx_mask=STATX_ALL|STATX_MNT_ID, stx_attributes=0, stx_mode={kind}|0555, stx_size={size}, ...}}) = 0'


def native_sources(mode):
    lines, directories, sources = [], {}, {}
    for index, image in enumerate(C.NAMES):
        if mode == 'missing-host-image' and index > 0 or mode == 'wrong-host-image' and index > 1:
            break
        prefix = C.prefix_for(mode)
        for offset, path in enumerate(('/', '/build-target', prefix)):
            fd = 1000 + index * 4 + offset
            directories[fd] = path
            lines.extend([metadata(path, 'S_IFDIR', 4096),
                          f'openat({CWD}, {json.dumps(path)}, O_RDONLY|O_NONBLOCK|O_NOFOLLOW|O_CLOEXEC|O_DIRECTORY) = {fd}<{path}>',
                          metadata(path, 'S_IFDIR', 4096, fd), metadata(path, 'S_IFDIR', 4096)])
        path, size = prefix + '/' + image, C.SIZES[image]
        if mode == 'missing-host-image':
            lines.append(f'statx({CWD}, {json.dumps(path)}, AT_STATX_SYNC_AS_STAT|AT_SYMLINK_NOFOLLOW, STATX_ALL, 0x1234) = -1 ENOENT (No such file or directory)')
            break
        fd = 1003 + index * 4
        sources[fd] = path
        lines.extend([metadata(path, 'S_IFREG', size),
                      f'openat({CWD}, {json.dumps(path)}, O_RDONLY|O_NONBLOCK|O_NOFOLLOW|O_CLOEXEC) = {fd}<{path}>',
                      metadata(path, 'S_IFREG', size, fd), metadata(path, 'S_IFREG', size)])
        for phase in range(2):
            prefix = '~ELF' if mode == 'wrong-host-image' and index == 1 else r'\177ELF'
            lines.extend([f'read({fd}<{path}>, "{prefix}"..., 65536) = 65536',
                          f'read({fd}<{path}>, "remainder"..., 65536) = {size - 65536}',
                          f'read({fd}<{path}>, "", 1) = 0'])
            if mode == 'wrong-host-image' and index == 1:
                break
            lines.append(f'lseek({fd}<{path}>, 0, SEEK_SET) = 0')
    return lines, directories, sources


def native_loading(mode):
    lines = []
    archived = C.cell_for(mode).endswith('-archived')
    for index, image in enumerate(C.NAMES):
        if archived:
            fd = 1000 + index
            token = f'{fd}</memfd:glue-python-native-{image}>(deleted)'
            lines.extend([f'memfd_create("glue-python-native-{image}", MFD_CLOEXEC|MFD_ALLOW_SEALING|0x10) = {token}',
                          f'write({token}, "verified native image"..., {C.SIZES[image]}) = {C.SIZES[image]}',
                          f'fcntl({token}, F_ADD_SEALS, F_SEAL_SEAL|F_SEAL_SHRINK|F_SEAL_GROW|F_SEAL_WRITE) = 0',
                          f'fcntl({token}, F_GET_SEALS) = 0xf (seals F_SEAL_SEAL|F_SEAL_SHRINK|F_SEAL_GROW|F_SEAL_WRITE)'])
    for index, image in enumerate(C.NAMES):
        fd = 1000 + index if archived else 1003 + index * 4
        alias = f'2000</memfd:glue-python-native-{image}>(deleted)' if archived else f'2000<{C.prefix_for(mode)}/{image}>'
        span = next(count for count, offset in C.SEGMENTS[image] if offset == 0)
        rw = next(count for count, offset in C.SEGMENTS[image] if offset != 0)
        base = 0x5000000 + index * 0x100000
        end = base + ((span + 4095) & ~4095)
        lines.extend([f'openat({CWD}, "/proc/self/fd/{fd}", O_RDONLY|O_CLOEXEC) = {alias}',
                      f'read({alias}, "\\177ELF"..., 832) = 832',
                      f'newfstatat({alias}, "", {{st_mode=S_IFREG|0777, st_size={C.SIZES[image]}, ...}}, AT_EMPTY_PATH) = 0',
                      f'mmap(NULL, {span + 65536}, PROT_NONE, MAP_PRIVATE|MAP_ANONYMOUS, -1, 0) = {hex(base)}',
                      f'mmap({hex(base)}, {span}, PROT_READ|PROT_EXEC, MAP_PRIVATE|MAP_FIXED|MAP_DENYWRITE, {alias}, 0) = {hex(base)}',
                      f'munmap({hex(end)}, {base + span + 65536 - end}) = 0',
                      f'mprotect({hex(base + 4096)}, 122880, PROT_NONE) = 0',
                      f'mmap({hex(base + 0x1f000)}, {rw}, PROT_READ|PROT_WRITE, MAP_PRIVATE|MAP_FIXED|MAP_DENYWRITE, {alias}, 0xf000) = {hex(base + 0x1f000)}',
                      f'close({alias}) = 0',
                      f'mprotect({hex(base + 0x1f000)}, 4096, PROT_READ) = 0'])
    return lines


def fixture(mode='bundled-archived'):
    host_runtime = C.cell_for(mode).startswith('host-')
    parent = H if host_runtime else B
    lines = parent.fixture_lines()
    old = parent.CHECKER.archive_for('success')
    lines = [line.replace(old, C.archive_for(mode)) for line in lines]
    lines[0] = f'execve({json.dumps(C.PROGRAM)}, {json.dumps(C.command_for(mode))}, 0x1234 /* 18 vars */) = 0'
    lines = [line.replace('/evidence/success.', f'/evidence/{mode}.') for line in lines]
    lines = [line for line in lines if not line.startswith(('write(1<', 'write(2<'))]
    runtime_closes = []
    if host_runtime:
        while len(lines) > 2 and lines[-3].startswith('close('):
            runtime_closes.insert(0, lines.pop(-3))
    if not host_runtime:
        if C.cell_for(mode).endswith('-archived'):
            lines = [line.replace('299008', '176128').replace('593920', '348160') for line in lines]
        else:
            lines = [line for line in lines if not line.startswith(('mmap(NULL, 299008', 'mremap('))]
    directories = {}
    if mode in C.NEGATIVE:
        lines = lines[:next(index for index, line in enumerate(lines) if line.startswith('memfd_create'))]
        if mode == 'corrupt-native':
            complete = next(i for i, line in enumerate(lines) if '"complete archive"' in line)
            archive = '3<' + C.archive_for(mode) + '>'
            lines[complete] = f'read({archive}, "complete manifest"..., 64) = 64'
            lines[-3:-1] = [f'lseek({archive}, {SIZE - 22}, SEEK_SET) = {SIZE - 22}',
                            f'read({archive}, "complete ZIP directory"..., 22) = 22']
            lines.pop()
            lines.extend([f'lseek({archive}, {OFFSET}, SEEK_SET) = {OFFSET}',
                          f'read({archive}, "~ELF"..., 32768) = 32768',
                          f'read({archive}, "native bytes"..., 32768) = 32768',
                          f'read({archive}, "remainder"..., 1616) = 1616',
                          f'close({archive}) = 0'])
        else:
            native, directories, sources = native_sources(mode)
            lines += native
            lines += [f'close({fd}<{path}>) = 0' for fd, path in {**sources, **directories}.items()]
    else:
        if C.cell_for(mode).endswith('-host'):
            native, directories, _ = native_sources(mode)
            insertion = next(index for index, line in enumerate(lines) if line.startswith('close(3<') and C.archive_for(mode) in line) + 1
            lines[insertion:insertion] = native
        insertion = next(index for index, line in enumerate(lines) if line.startswith('gettid'))
        lines[insertion:insertion] = native_loading(mode)
        lines = lines[:-2]
    for number, output in enumerate(C.expected_output(mode), 1):
        if output:
            lines.append(f'write({number}</evidence/{mode}.{"stdout" if number == 1 else "stderr"}.txt>, {json.dumps(output.decode())}, {len(output)}) = {len(output)}')
    if mode not in C.NEGATIVE:
        lines += [f'close({fd}<{path}>) = 0' for fd, path in directories.items()]
        lines += runtime_closes
    status = 0 if mode in C.CELLS else 1
    lines.extend([f'exit_group({status}) = ?', f'+++ exited with {status} +++'])
    return lines, H.CHECKER.ARCHIVE_BYTES if host_runtime else SIZE


def check(lines, mode='bundled-archived', size=None):
    if size is None:
        size = H.CHECKER.ARCHIVE_BYTES if C.cell_for(mode).startswith('host-') else SIZE
    C.check_lines((f'1234  {line}\n' for line in lines), mode, size,
                  OFFSET if mode == 'corrupt-native' else None,
                  (64, size - 22) if mode == 'corrupt-native' else None)


def retained_metadata_fixture():
    files = {name: {'size': C.SIZES[name], 'sha256': C.HASHES[name],
                    'loads': copy.deepcopy(C.EXPECTED_LOADS[name])} for name in C.NAMES}
    archives = {}
    for mode in C.CELLS + C.NEGATIVE:
        runtime, native = C.cell_for(mode).split('-')
        declarations = {}
        for name in C.NAMES:
            spec = {'sha256': C.HASHES[name]}
            if native == 'host':
                spec['path'] = C.prefix_for(mode) + '/' + name
            else:
                spec.update(size=C.SIZES[name], compression='stored')
            declarations[name] = spec
        archives[mode] = {'bytes': H.CHECKER.ARCHIVE_BYTES if runtime == 'host' else SIZE,
                          'sha256': '1' * 64, 'manifest_sha256': '2' * 64,
                          'runtime': runtime, 'native': native, 'declarations': declarations}
        archives[mode].update(manifest_bytes=64, zip_directory_offset=archives[mode]['bytes'] - 22)
        if mode == 'corrupt-native':
            archives[mode]['corrupt_native_offset'] = OFFSET
    return {'schema_version': 0, 'files': files, 'archives': archives}


def cli(directory, mode='bundled-archived', metadata=None, compressed=False,
        include_metadata=True):
    lines, size = fixture(mode)
    trace = directory / ('trace.txt.gz' if compressed else 'trace.txt')
    payload = ''.join(f'1234  {line}\n' for line in lines).encode()
    trace.write_bytes(gzip.compress(payload, mtime=0) if compressed else payload)
    stdout, stderr = directory / 'stdout.txt', directory / 'stderr.txt'
    expected = C.expected_output(mode)
    stdout.write_bytes(expected[0]); stderr.write_bytes(expected[1])
    metadata_file = directory / 'native-metadata.json'
    metadata_file.write_text(json.dumps(retained_metadata_fixture() if metadata is None else metadata))
    command = [sys.executable, str(SCRIPT), str(trace), '--mode', mode,
               '--archive-bytes', str(size), '--stdout-file', str(stdout),
               '--stderr-file', str(stderr)]
    if include_metadata:
        command.extend(['--native-metadata-file', str(metadata_file)])
    if mode == 'corrupt-native':
        command.extend(['--corrupt-native-offset', str(OFFSET)])
    return subprocess.run(command, capture_output=True, text=True, check=False)


class ExtensionTraceTests(unittest.TestCase):
    def reject(self, lines, mode='bundled-archived'):
        with self.assertRaises(C.TraceError):
            check(lines, mode)

    def test_all_eleven_modes_are_admitted(self):
        for mode in C.MODES:
            with self.subTest(mode=mode):
                lines, size = fixture(mode)
                check(lines, mode, size)

    def test_exact_command_stream_and_pid_identities(self):
        lines, _ = fixture()
        for old, new in [(C.PROGRAM, '/tmp/launcher'), ('run-extensions', 'run-imports'), ('/evidence/bundled-archived.stdout', '/evidence/success.stdout')]:
            self.reject([line.replace(old, new) for line in lines])
        with self.assertRaises(C.TraceError):
            C.check_lines([f'{1235 if index == 2 else 1234}  {line}\n' for index, line in enumerate(lines)], 'bundled-archived', SIZE)

    def test_every_seal_and_full_population_are_required(self):
        lines, _ = fixture()
        for text in ['F_GET_SEALS', 'F_ADD_SEALS', 'verified native image']:
            mutant = lines.copy()
            mutant.pop(next(i for i, line in enumerate(mutant) if text in line and 'glue-python-native' in line))
            self.reject(mutant)

    def test_all_five_images_must_be_prepared_before_first_alias(self):
        lines, _ = fixture()
        start = next(i for i, line in enumerate(lines) if line.startswith('memfd_create("glue-python-native-glue_native_exec_error'))
        block = lines[start:start + 4]
        del lines[start:start + 4]
        insertion = next(i for i, line in enumerate(lines) if '/proc/self/fd/1001' in line)
        lines[insertion:insertion] = block
        self.reject(lines)

    def test_loader_alias_must_name_original_fd_and_order(self):
        lines, _ = fixture()
        self.reject([line.replace('/proc/self/fd/1000', '/proc/self/fd/1001') for line in lines])
        self.reject([line.replace('O_RDONLY|O_CLOEXEC) = 2000', 'O_RDONLY) = 2000') for line in lines])

    def test_exact_segment_length_flags_address_and_return(self):
        lines, _ = fixture()
        index = next(i for i, line in enumerate(lines) if 'MAP_DENYWRITE, 2000' in line)
        for old, new in [('131072', '131073'), ('MAP_PRIVATE|MAP_FIXED', 'MAP_PRIVATE'), ('mmap(0x5000000', 'mmap(NULL'), (' = 0x5000000', ' = 0x6000000')]:
            mutant = lines.copy(); mutant[index] = mutant[index].replace(old, new)
            self.reject(mutant)

    def test_reservation_guard_trim_and_relro_are_once_only(self):
        lines, _ = fixture()
        for text in ['mmap(NULL, 196608', 'munmap(0x5020000', 'mprotect(0x5001000', 'mprotect(0x501f000']:
            index = next(i for i, line in enumerate(lines) if text in line)
            mutant = lines.copy(); mutant.pop(index); self.reject(mutant)
            mutant = lines.copy(); mutant.insert(index, mutant[index]); self.reject(mutant)

    def test_live_native_and_runtime_pages_cannot_be_replaced(self):
        lines, _ = fixture()
        for address in ('0x5000000', '0x501f000', '0x102000'):
            for call in [f'munmap({address}, 4096) = 0', f'mprotect({address}, 4096, PROT_READ|PROT_WRITE) = 0', f'mmap({address}, 4096, PROT_READ|PROT_WRITE, MAP_PRIVATE|MAP_FIXED|MAP_ANONYMOUS, -1, 0) = {address}', f'mmap(NULL, 4096, PROT_READ|PROT_WRITE, MAP_PRIVATE|MAP_ANONYMOUS, -1, 0) = {address}']:
                mutant = lines.copy(); mutant.insert(-3, call); self.reject(mutant)

    def test_native_reservation_cannot_overlap_another_image(self):
        lines, _ = fixture()
        index = next(i for i, line in enumerate(lines) if line.startswith('mmap(NULL, 196848'))
        lines[index] = lines[index].replace(' = 0x5100000', ' = 0x5000000')
        self.reject(lines)

    def test_host_images_require_two_full_passes_eofs_and_rewinds(self):
        lines, _ = fixture('bundled-host')
        for text in ['read(1003<', 'lseek(1003<']:
            mutant = lines.copy(); mutant.pop(next(i for i, line in enumerate(mutant) if text in line)); self.reject(mutant, 'bundled-host')
        self.reject([line.replace('"", 1) = 0', '"", 0) = 0') if 'host Python extensions' in line else line for line in lines], 'bundled-host')

    def test_host_ancestors_nofollow_metadata_and_size_are_required(self):
        lines, _ = fixture('bundled-host')
        for old, new in [('AT_SYMLINK_NOFOLLOW', '0'), ('O_NOFOLLOW|', ''), ('stx_size=67152,', 'stx_size=671520,'), ('S_IFREG|0555', 'S_IFLNK|0555')]:
            self.reject([line.replace(old, new) if 'host Python extensions' in line else line for line in lines], 'bundled-host')

    def test_fresh_host_ancestor_requires_its_own_descriptor_metadata(self):
        lines, _ = fixture('bundled-host')
        # The first image retains a verified root descriptor. Reopening that
        # ancestor for the second image must inspect the fresh descriptor too.
        index = next(i for i, line in enumerate(lines) if line.startswith('statx(1004</>, "",'))
        lines.pop(index)
        with self.assertRaisesRegex(C.TraceError, 'directory ancestors'):
            check(lines, 'bundled-host')

    def test_each_host_verification_pass_requires_selected_elf_magic(self):
        lines, _ = fixture('bundled-host')
        indices = [i for i, line in enumerate(lines) if line.startswith('read(1003<') and r'\177ELF' in line]
        self.assertEqual(len(indices), 2)
        for index in indices:
            with self.subTest(pass_index=index):
                mutant = lines.copy(); mutant[index] = mutant[index].replace(r'\177ELF', '~ELF')
                with self.assertRaisesRegex(C.TraceError, 'selected ELF/control prefix'):
                    check(mutant, 'bundled-host')

    def test_host_parser_remap_result_cannot_overlap_native_image(self):
        lines, _ = fixture('host-host')
        index = next(i for i, line in enumerate(lines) if line.startswith('mremap('))
        self.assertTrue(lines[index].endswith(' = 0x3000000'))
        lines[index] = lines[index].removesuffix('0x3000000') + '0x5000000'
        with self.assertRaisesRegex(C.TraceError, 'overlaps a retained native'):
            check(lines, 'host-host')

    def test_manifest_backing_must_remain_live_until_remap(self):
        lines, _ = fixture()
        index = next(i for i, line in enumerate(lines) if line.startswith('mremap('))
        lines.insert(index, 'munmap(0x3000000, 176128) = 0')
        with self.assertRaisesRegex(C.TraceError, 'manifest growth'):
            check(lines)

    def test_missing_host_control_requires_live_verified_ancestors(self):
        lines, _ = fixture('missing-host-image')
        lines = [line for line in lines if not ('S_IFDIR' in line or 'O_DIRECTORY' in line or line.startswith('close(100'))]
        self.reject(lines, 'missing-host-image')

    def test_failed_source_fallbacks_and_materialization_attempts_reject(self):
        lines, _ = fixture()
        for call in [f'openat({CWD}, "glue://stock-pbs-registered-extensions/app/missing.py", O_RDONLY) = -1 ENOENT (No such file or directory)', f'openat({CWD}, "/tmp/native.so", O_WRONLY|O_CREAT, 0600) = -1 EACCES (Permission denied)', 'unlink("/tmp/native.so") = -1 ENOENT (No such file or directory)', 'clone3({},64) = -1 ENOSYS (Function not implemented)']:
            mutant = lines.copy(); mutant.insert(-3, call); self.reject(mutant)

    def test_python_initialization_and_publication_follow_native_closure(self):
        lines, _ = fixture()
        for start in ('gettid()', 'write(1<'):
            index = next(i for i, line in enumerate(lines) if line.startswith(start))
            mutant = lines.copy(); call = mutant.pop(index)
            mutant.insert(next(i for i, line in enumerate(mutant) if line.startswith('memfd_create("glue-python-native')), call)
            self.reject(mutant)

    def test_corrupt_native_requires_complete_selected_payload_and_locator(self):
        lines, _ = fixture('corrupt-native')
        for text in ['~ELF', 'remainder', 'GLUERS00 locator']:
            mutant = lines.copy(); mutant.pop(next(i for i, line in enumerate(mutant) if text in line)); self.reject(mutant, 'corrupt-native')
        with self.assertRaises(C.TraceError):
            C.Checker('corrupt-native', SIZE)

    def test_corrupt_native_requires_independent_complete_manifest_and_zip_coverage(self):
        lines, _ = fixture('corrupt-native')
        for text in ('complete manifest', 'complete ZIP directory'):
            index = next(i for i, line in enumerate(lines) if text in line)
            with self.subTest(omitted=text):
                mutant = lines.copy(); mutant.pop(index)
                self.reject(mutant, 'corrupt-native')
            with self.subTest(shortened=text):
                mutant = lines.copy()
                if text == 'complete manifest':
                    mutant[index] = mutant[index].replace('64) = 64', '63) = 63')
                else:
                    mutant[index] = mutant[index].replace('22) = 22', '21) = 21')
                self.reject(mutant, 'corrupt-native')

    def test_retained_manifest_zip_and_member_bounds_are_typed_and_disjoint(self):
        for admission in (None, (True, SIZE - 22), (64, True), (0, SIZE - 22),
                          (1024 * 1024 + 1, SIZE - 22), (64, 128),
                          (64, SIZE - 21), (64, OFFSET + C.SIZES[C.NAMES[0]] - 1)):
            with self.subTest(admission=admission):
                with self.assertRaises(C.TraceError):
                    C.Checker('corrupt-native', SIZE, OFFSET, admission)
        with self.assertRaises(C.TraceError):
            C.Checker('corrupt-native', SIZE, 127, (64, SIZE - 22))

    def test_validation_diagnostic_uses_exact_stderr_and_freezes_inputs(self):
        for mode in C.NEGATIVE:
            lines, _ = fixture(mode)
            self.reject([line.replace('2</evidence/', '0</evidence/') for line in lines], mode)
            self.reject([line.replace('.stderr.txt>', '.stderr.txt>(deleted)') for line in lines], mode)
            mutant = lines.copy(); mutant.insert(-2, f'openat({CWD}, "/etc/ld.so.cache", O_RDONLY|O_CLOEXEC) = 5</etc/ld.so.cache>'); self.reject(mutant, mode)

    def test_runtime_and_native_live_fds_cannot_collide(self):
        lines, _ = fixture()
        mutant = lines.copy(); mutant.insert(-3, f'openat({CWD}, "/proc/self/maps", O_RDONLY|O_CLOEXEC) = 1000</proc/1234/maps>'); self.reject(mutant)

    def test_truncated_native_calls_and_completion_are_rejected_cleanly(self):
        lines, _ = fixture()
        for call in ['execve()', 'read(1000)', 'write(1000)', 'statx(1000, "")', 'fcntl(1000)']:
            mutant = lines.copy(); mutant.insert(-3, call + ' = 0'); self.reject(mutant)
        self.reject(lines[:-1])

    def test_cli_admits_plain_and_gzip_for_all_eleven_modes(self):
        with tempfile.TemporaryDirectory() as temporary:
            directory = Path(temporary)
            for mode in C.MODES:
                for compressed in (False, True):
                    with self.subTest(mode=mode, compressed=compressed):
                        result = cli(directory, mode, compressed=compressed)
                        self.assertEqual(result.returncode, 0, result.stderr)
                        self.assertTrue(result.stdout.startswith('Trace checks passed:'))
                        self.assertEqual(result.stderr, '')

    def test_cli_requires_native_metadata_and_rejects_truncated_gzip(self):
        with tempfile.TemporaryDirectory() as temporary:
            directory = Path(temporary)
            missing = cli(directory, include_metadata=False)
            self.assertEqual(missing.returncode, 2)
            self.assertIn('--native-metadata-file', missing.stderr)
            admitted = cli(directory, compressed=True)
            self.assertEqual(admitted.returncode, 0, admitted.stderr)
            trace = directory / 'trace.txt.gz'
            trace.write_bytes(trace.read_bytes()[:-8])
            truncated = subprocess.run(admitted.args, capture_output=True, text=True, check=False)
            self.assertEqual(truncated.returncode, 1)
            self.assertIn('trace rejected:', truncated.stderr)
            self.assertNotIn('Traceback', truncated.stderr)

    def test_cli_rejects_native_identity_inventory_and_layout_mutants(self):
        with tempfile.TemporaryDirectory() as temporary:
            directory = Path(temporary)
            for kind in ('schema', 'missing-image', 'extra-image', 'size', 'hash',
                         'rx-offset', 'rw-vaddr', 'rw-filesz', 'rw-memsz', 'align'):
                metadata = retained_metadata_fixture()
                image = metadata['files'][C.NAMES[0]]
                if kind == 'schema': metadata['schema_version'] = 1
                elif kind == 'missing-image': del metadata['files'][C.NAMES[1]]
                elif kind == 'extra-image': metadata['files']['unreviewed.so'] = copy.deepcopy(image)
                elif kind == 'size': image['size'] += 1
                elif kind == 'hash': image['sha256'] = '0' * 64
                elif kind == 'rx-offset': image['loads'][0]['offset'] = 4096
                elif kind == 'rw-vaddr': image['loads'][1]['vaddr'] += 4096
                elif kind == 'rw-filesz': image['loads'][1]['filesz'] += 1
                elif kind == 'rw-memsz': image['loads'][1]['memsz'] += 1
                else: image['loads'][1]['align'] = 4096
                with self.subTest(kind=kind):
                    result = cli(directory, metadata=metadata)
                    self.assertEqual(result.returncode, 1)
                    self.assertIn('trace rejected:', result.stderr)
                    self.assertNotIn('Traceback', result.stderr)

    def test_cli_rejects_wrong_native_host_declarations_and_provider(self):
        with tempfile.TemporaryDirectory() as temporary:
            directory = Path(temporary)
            for kind in ('path', 'hash', 'missing-declaration', 'runtime', 'native', 'bytes'):
                metadata = retained_metadata_fixture()
                record = metadata['archives']['host-host']
                declaration = record['declarations'][C.NAMES[0]]
                if kind == 'path': declaration['path'] = '/tmp/' + C.NAMES[0]
                elif kind == 'hash': declaration['sha256'] = '0' * 64
                elif kind == 'missing-declaration': del record['declarations'][C.NAMES[1]]
                elif kind == 'runtime': record['runtime'] = 'bundled'
                elif kind == 'native': record['native'] = 'archived'
                else: record['bytes'] += 1
                with self.subTest(kind=kind):
                    result = cli(directory, 'host-host', metadata)
                    self.assertEqual(result.returncode, 1)
                    self.assertIn('trace rejected:', result.stderr)
                    self.assertNotIn('Traceback', result.stderr)

    def test_cli_rejects_archive_identity_storage_and_corrupt_offset_mutants(self):
        with tempfile.TemporaryDirectory() as temporary:
            directory = Path(temporary)
            for kind in ('missing-archive', 'extra-archive', 'archive-hash', 'manifest-hash',
                         'storage', 'size', 'wrong-offset', 'missing-offset'):
                metadata = retained_metadata_fixture()
                record = metadata['archives']['corrupt-native']
                if kind == 'missing-archive': del metadata['archives']['host-host']
                elif kind == 'extra-archive': metadata['archives']['unexpected'] = copy.deepcopy(record)
                elif kind == 'archive-hash': record['sha256'] = '1' * 63
                elif kind == 'manifest-hash': record['manifest_sha256'] = 'z' * 64
                elif kind == 'storage': record['declarations'][C.NAMES[0]]['compression'] = 'deflated'
                elif kind == 'size': record['declarations'][C.NAMES[0]]['size'] += 1
                elif kind == 'wrong-offset': record['corrupt_native_offset'] += 1
                else: del record['corrupt_native_offset']
                with self.subTest(kind=kind):
                    result = cli(directory, 'corrupt-native', metadata)
                    self.assertEqual(result.returncode, 1)
                    self.assertIn('trace rejected:', result.stderr)
                    self.assertNotIn('Traceback', result.stderr)

    def test_cli_rejects_malformed_native_metadata_shapes_cleanly(self):
        with tempfile.TemporaryDirectory() as temporary:
            directory = Path(temporary)
            for kind in ('root', 'files', 'archives', 'image', 'hash', 'declarations'):
                metadata = retained_metadata_fixture()
                if kind == 'root': metadata = []
                elif kind == 'files': metadata['files'] = None
                elif kind == 'archives': metadata['archives'] = []
                elif kind == 'image': metadata['files'][C.NAMES[0]] = None
                elif kind == 'hash': metadata['archives']['bundled-archived']['sha256'] = 123
                else: metadata['archives']['bundled-archived']['declarations'] = None
                with self.subTest(kind=kind):
                    result = cli(directory, metadata=metadata)
                    self.assertEqual(result.returncode, 1)
                    self.assertIn('trace rejected:', result.stderr)
                    self.assertNotIn('Traceback', result.stderr)


if __name__ == '__main__':
    unittest.main()
