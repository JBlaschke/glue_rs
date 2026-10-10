"""Adversarial checks for the independent bounded host archive-import profile."""

import gzip
import importlib.util
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest


SCRIPT = Path(__file__).with_name("check-linux-python-host-import-trace.py")
SPEC = importlib.util.spec_from_file_location("host_import_trace_checker", SCRIPT)
assert SPEC is not None and SPEC.loader is not None
CHECKER = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(CHECKER)
CWD = CHECKER.CWD


def fixture_lines(mode="success"):
    c = CHECKER.Checker(mode)
    archive, stdlib, library = c.archive, c.stdlib, c.library
    command = [CHECKER.PROGRAM, "run-host-imports", archive] if mode != "app-error" else [CHECKER.PROGRAM, "run-host-imports-negative", archive, "app-error"]
    archive_fd = "3<" + archive + ">"
    lines = [
        f"execve({json.dumps(CHECKER.PROGRAM)}, {json.dumps(command)}, 0x1234 /* 18 vars */) = 0",
        f"openat({CWD}, {json.dumps(archive)}, O_RDONLY|O_CLOEXEC) = {archive_fd}",
        f"lseek({archive_fd}, 0, SEEK_END) = {CHECKER.ARCHIVE_BYTES}",
        f"lseek({archive_fd}, 0, SEEK_SET) = 0",
        f'read({archive_fd}, "GLUERS00 locator"..., 64) = 64',
    ]
    if mode == "corrupt-source":
        lines += [
            f"lseek({archive_fd}, {CHECKER.CORRUPT_SOURCE_OFFSET}, SEEK_SET) = {CHECKER.CORRUPT_SOURCE_OFFSET}",
            f'read({archive_fd}, {json.dumps(CHECKER.CORRUPT_SOURCE.decode("ascii"))}, {len(CHECKER.CORRUPT_SOURCE)}) = {len(CHECKER.CORRUPT_SOURCE)}',
        ]
    else:
        lines += [
            f'read({archive_fd}, "complete archive"..., {CHECKER.ARCHIVE_BYTES - 64}) = {CHECKER.ARCHIVE_BYTES - 64}',
            f"lseek({archive_fd}, {CHECKER.ARCHIVE_BYTES - 20}, SEEK_SET) = {CHECKER.ARCHIVE_BYTES - 20}",
            f'read({archive_fd}, "ZIP bytes"..., 20) = 20',
        ]
    lines.append(f"close({archive_fd}) = 0")
    fds = {}
    next_fd = 3

    def metadata(path, kind, size, fd=None):
        location = CWD if fd is None else str(fd) + "<" + path + ">"
        argument = json.dumps(path) if fd is None else '\"\"'
        flags = "AT_STATX_SYNC_AS_STAT|AT_SYMLINK_NOFOLLOW" if fd is None else "AT_STATX_SYNC_AS_STAT|AT_EMPTY_PATH"
        lines.append(f"statx({location}, {argument}, {flags}, STATX_ALL, {{stx_mask=STATX_ALL|STATX_MNT_ID, stx_attributes=0, stx_mode={kind}|0555, stx_size={size}, ...}}) = 0")

    def missing(path):
        lines.append(f"statx({CWD}, {json.dumps(path)}, AT_STATX_SYNC_AS_STAT|AT_SYMLINK_NOFOLLOW, STATX_ALL, 0x1234) = -1 ENOENT (No such file or directory)")

    def cache(path):
        if mode == "cached-import-bytecode" and path.endswith("/importlib/resources/__pycache__"):
            metadata(path, "S_IFDIR", 4096)
        else:
            missing(path)

    if mode != "corrupt-source":
        for path in sorted(c.directories, key=lambda p: (len(Path(p).parts), p)):
            metadata(path, "S_IFDIR", 4096)
            fd = next_fd
            next_fd += 1
            lines.append(f"openat({CWD}, {json.dumps(path)}, O_RDONLY|O_NONBLOCK|O_NOFOLLOW|O_CLOEXEC|O_DIRECTORY) = {fd}<{path}>")
            fds[fd] = path
            metadata(path, "S_IFDIR", 4096, fd)
            metadata(path, "S_IFDIR", 4096)
        initial_caches = {stdlib + "/__pycache__", stdlib + "/encodings/__pycache__"}
        for path in sorted(initial_caches):
            cache(path)
        files = [(library, CHECKER.LIBRARY_BYTES)] + [(stdlib + "/" + path, size) for path, size in CHECKER.STARTUP_SOURCES.items()]
        if mode != "wrong-library":
            for path in sorted(c.cache_paths() - initial_caches):
                cache(path)
                if mode == "cached-import-bytecode" and path.endswith("/importlib/resources/__pycache__"):
                    break
            if mode != "cached-import-bytecode":
                files += [(stdlib + "/" + path, CHECKER.SOURCES[path]) for path in sorted(set(CHECKER.SOURCES) - set(CHECKER.STARTUP_SOURCES))]
        for path, size in files:
            if mode == "missing-import-source" and path.endswith("/contextlib.py"):
                missing(path)
                break
            metadata(path, "S_IFREG", size)
            fd = next_fd
            next_fd += 1
            fds[fd] = path
            lines.append(f"openat({CWD}, {json.dumps(path)}, O_RDONLY|O_NONBLOCK|O_NOFOLLOW|O_CLOEXEC) = {fd}<{path}>")
            metadata(path, "S_IFREG", size, fd)
            metadata(path, "S_IFREG", size)
            remaining = size
            while remaining:
                count = min(remaining, 65536)
                lines.append(f'read({fd}<{path}>, "verified input"..., 65536) = {count}')
                remaining -= count
            lines.append(f'read({fd}<{path}>, "", 1) = 0')
            if (mode == "wrong-library" and path == library) or (mode == "wrong-import-source" and path.endswith("/contextlib.py")):
                break
            lines.append(f"lseek({fd}<{path}>, 0, SEEK_SET) = 0")
    if mode in CHECKER.INITIALIZED:
        library_fd = next(fd for fd, path in fds.items() if path == library)
        alias = next_fd
        lines += [
            f'openat({CWD}, "/proc/self/fd/{library_fd}", O_RDONLY|O_CLOEXEC) = {alias}<{library}>',
            f'read({alias}<{library}>, "ELF header"..., 832) = 832',
            f'newfstatat({alias}<{library}>, "", {{st_mode=S_IFREG|0444, st_size={CHECKER.LIBRARY_BYTES}, ...}}, AT_EMPTY_PATH) = 0',
            f"mmap(0x100000, 20423824, PROT_READ|PROT_EXEC, MAP_PRIVATE|MAP_FIXED|MAP_DENYWRITE, {alias}<{library}>, 0) = 0x100000",
            f"mmap(0x2000000, 1695744, PROT_READ|PROT_WRITE, MAP_PRIVATE|MAP_FIXED|MAP_DENYWRITE, {alias}<{library}>, 0x115a000) = 0x2000000",
            f"close({alias}<{library}>) = 0",
            f'openat({CWD}, "{CHECKER.COMMON.OVERCOMMIT}", O_RDONLY) = {alias}<{CHECKER.COMMON.OVERCOMMIT}>',
            f'read({alias}<{CHECKER.COMMON.OVERCOMMIT}>, "0\\n", 32) = 2',
            f"close({alias}<{CHECKER.COMMON.OVERCOMMIT}>) = 0",
            "gettid() = 1234",
            f'readlinkat({CWD}, "/__glue_archive__/launcher", 0x1234, 4096) = -1 ENOENT (No such file or directory)',
            f'openat({CWD}, "/usr/share/zoneinfo/UTC0", O_RDONLY|O_CLOEXEC) = -1 ENOENT (No such file or directory)',
        ]
        for relative, count in CHECKER.ENUM_ENTRIES.items():
            directory = stdlib + ("/" + relative if relative else "")
            for _ in range(CHECKER.ENUM_PASSES[relative]):
                lines += [
                f"openat({CWD}, {json.dumps(directory)}, O_RDONLY|O_NONBLOCK|O_CLOEXEC|O_DIRECTORY) = {alias}<{directory}>",
                f"getdents64({alias}<{directory}>, 0x1234 /* {count} entries */, 32768) = 2048",
                f"getdents64({alias}<{directory}>, 0x1234 /* 0 entries */, 32768) = 0",
                f"close({alias}<{directory}>) = 0",
            ]
        for suffix in sorted(CHECKER.IMPORT_SOURCES):
            path = stdlib + "/" + suffix
            size = CHECKER.SOURCES[suffix]
            cached = str(Path(path).parent / "__pycache__" / (Path(path).stem + ".cpython-313.pyc"))
            lines += [
                f"openat({CWD}, {json.dumps(cached)}, O_RDONLY|O_CLOEXEC) = -1 ENOENT (No such file or directory)",
                f"openat({CWD}, {json.dumps(path)}, O_RDONLY|O_CLOEXEC) = {alias}<{path}>",
                f"fcntl({alias}<{path}>, F_GETFD) = 0x1 (flags FD_CLOEXEC)",
                f"fstat({alias}<{path}>, {{st_mode=S_IFREG|0444, st_size={size}, ...}}) = 0",
                f"ioctl({alias}<{path}>, TCGETS, 0x1234) = -1 ENOTTY (Inappropriate ioctl for device)",
                f"lseek({alias}<{path}>, 0, SEEK_CUR) = 0",
                f'read({alias}<{path}>, "installed source"..., {size + 1}) = {size}',
                f'read({alias}<{path}>, "", 1) = 0',
                f"close({alias}<{path}>) = 0",
            ]
        for index, (old, new) in enumerate(CHECKER.REMAPS):
            if index == 3:
                lines.append('getrandom("seed"..., 2496, GRND_NONBLOCK) = 2496')
            if index != 2:
                lines.append(f"mmap(NULL, {old}, PROT_READ|PROT_WRITE, MAP_PRIVATE|MAP_ANONYMOUS, -1, 0) = 0x3000000")
            lines.append(f"mremap(0x3000000, {old}, {new}, MREMAP_MAYMOVE) = 0x3000000")
        lines.append("gettid() = 1234")
    if mode not in CHECKER.INITIALIZED:
        for fd, path in fds.items():
            lines.append(f"close({fd}<{path}>) = 0")
    for index, diagnostic in enumerate(CHECKER.expected_output(mode), 1):
        if diagnostic:
            fd = f'{index}</evidence/{mode}.{"stdout" if index == 1 else "stderr"}.txt>'
            lines.append(f"write({fd}, {json.dumps(diagnostic.decode('ascii'))}, {len(diagnostic)}) = {len(diagnostic)}")
    for fd, path in fds.items() if mode in CHECKER.INITIALIZED else []:
        if path != library:
            lines.append(f"close({fd}<{path}>) = 0")
    status = 0 if mode == "success" else 1
    lines += [f"exit_group({status}) = ?", f"+++ exited with {status} +++"]
    return lines


def trace(lines=None, mode="success"):
    return "".join("1234  " + line + "\n" for line in (fixture_lines(mode) if lines is None else lines))


class HostImportTracePolicyTests(unittest.TestCase):
    def reject(self, text, mode="success", fragment=None):
        with self.assertRaises(CHECKER.TraceError) as caught:
            CHECKER.check_trace(text, mode)
        if fragment:
            self.assertIn(fragment, str(caught.exception))

    def extra(self, call, mode="success"):
        lines = fixture_lines(mode)
        lines.insert(-2, call)
        self.reject(trace(lines, mode), mode)

    def test_complete_success_and_all_six_controls(self):
        for mode in CHECKER.MODES:
            with self.subTest(mode=mode):
                CHECKER.check_trace(trace(mode=mode), mode)

    def test_exact_program_command_archive_exit_and_streams(self):
        for old, new in [(CHECKER.PROGRAM, "/tmp/launcher"), ('"run-host-imports"', '"run-host"'), (CHECKER.archive_for("success"), "/tmp/app.glue"), ('exit_group(0)', 'exit_group(1)'), ('1</evidence/success.stdout.txt>', '1</tmp/output>')]:
            self.reject(trace().replace(old, new, 1))
        self.extra(fixture_lines()[0])
        self.reject(trace(mode="app-error"), "success")

    def test_failed_mutations_processes_network_memfd_and_async_calls(self):
        for call in ['unknown_call(0) = 0', 'clone3({}, 64) = -1 ENOSYS (Function not implemented)', 'socket(AF_INET, SOCK_STREAM, 0) = -1 EPERM (Operation not permitted)', 'io_uring_setup(8, {}) = -1 EPERM (Operation not permitted)', f'openat({CWD}, "/tmp/x", O_WRONLY|O_CREAT, 0600) = -1 EACCES (Permission denied)', 'unlink("/tmp/x") = -1 ENOENT (No such file or directory)', 'mkdir("/tmp/x", 0700) = -1 EACCES (Permission denied)', 'memfd_create("fallback", MFD_CLOEXEC) = -1 EPERM (Operation not permitted)', 'pwrite64(9, "x", 1, 0) = -1 EPERM (Operation not permitted)', 'dup2(9, 1) = 1']:
            self.extra(call)
        self.reject(trace().replace('1234  gettid', '1235  gettid'), fragment="additional process")

    def test_no_host_lures_unknown_sources_or_virtual_source_attempts(self):
        for path in [CHECKER.PREFIX + '/lib/python3.13/glue_demo/missing.py', CHECKER.PREFIX + '/lib/python3.13/glue_ns/part.py', CHECKER.PREFIX + '/lib/python3.13/standalone.py', CHECKER.PREFIX + '/lib/python3.13/site.py', '/usr/lib/python3.13/contextlib.py', 'glue://stock-pbs-host-archive-imports/app/python/glue_demo/syntax_error.py', '/forbidden/python-path/a.py', '/tmp/resource']:
            self.extra(f'openat({CWD}, {json.dumps(path)}, O_RDONLY|O_CLOEXEC) = -1 ENOENT (No such file or directory)')

    def test_nofollow_ancestors_metadata_and_cache_prerequisites(self):
        for old, new in [('O_NONBLOCK|O_NOFOLLOW', 'O_NONBLOCK'), ('AT_STATX_SYNC_AS_STAT|AT_SYMLINK_NOFOLLOW', 'AT_STATX_SYNC_AS_STAT'), ('STATX_ALL|STATX_MNT_ID', 'STATX_BASIC_STATS'), ('S_IFREG|0555', 'S_IFLNK|0555')]:
            self.reject(trace().replace(old, new, 1))
        lines = fixture_lines()
        self.reject(trace([l for l in lines if not ('__pycache__", AT_STATX' in l)]))
        self.reject(trace([l for l in lines if not l.startswith('statx(3</>')]))

    def test_complete_archive_locator_size_coverage_and_close_before_host(self):
        for predicate in [lambda l: 'GLUERS00' in l, lambda l: l.startswith('lseek') and 'SEEK_END' in l, lambda l: l.startswith('close') and '.glue>' in l]:
            self.reject(trace([l for l in fixture_lines() if not predicate(l)]))
        self.reject(trace().replace('"complete archive"..., 4032) = 4032', '"complete archive"..., 4032) = 4031'))

    def test_all_pinned_hashes_eof_and_once_rewind_before_library_alias(self):
        for suffix in ('contextlib.py', 'importlib/resources/_common.py', 'encodings/__init__.py'):
            lines = fixture_lines()
            self.reject(trace([l for l in lines if not (suffix in l and l.startswith('read') and 'verified input' in l)]))
            self.reject(trace([l for l in lines if not (suffix in l and l.startswith('read') and '\"\", 1) = 0' in l)]))
            self.reject(trace([l for l in lines if not (suffix in l and l.startswith('lseek') and 'SEEK_SET' in l)]))
        lines = fixture_lines()
        i = next(i for i,l in enumerate(lines) if '/proc/self/fd/' in l)
        alias = lines.pop(i)
        lines.insert(next(i for i,l in enumerate(lines) if 'verified input' in l), alias)
        self.reject(trace(lines), fragment="verification")

    def test_alias_must_use_pinned_library_fd_once_and_exact_map_fixed_return(self):
        lines = fixture_lines()
        i = next(i for i,l in enumerate(lines) if '/proc/self/fd/' in l)
        self.reject(trace(lines[:i]+[lines[i]]+lines[i:]))
        self.reject(trace().replace('/proc/self/fd/19', '/proc/self/fd/20', 1))
        self.reject(trace().replace('mmap(0x100000, 20423824', 'mmap(NULL, 20423824'))
        self.reject(trace().replace('0) = 0x100000', '0) = 0x200000', 1))

    def test_startup_queries_are_after_both_maps_and_alias_close(self):
        lines = fixture_lines()
        first = next(i for i,l in enumerate(lines) if CHECKER.COMMON.OVERCOMMIT in l)
        last = next(i for i,l in enumerate(lines[first:],first) if '/usr/share/zoneinfo/UTC0' in l)
        startup = lines[first:last+1]
        remainder = lines[:first]+lines[last+1:]
        self.reject(trace(remainder[:1]+startup+remainder[1:]))
        self.reject(trace([l for l in lines if not (l.startswith('close') and 'libpython' in l)]))

    def test_exact_import_source_coverage_eof_and_directory_counts(self):
        lines = fixture_lines()
        for predicate in [lambda l: 'installed source' in l and 'contextlib.py' in l, lambda l: l.startswith('getdents64'), lambda l: 'getrandom' in l, lambda l: l == 'gettid() = 1234']:
            self.reject(trace([l for l in lines if not predicate(l)]))
        self.reject(trace().replace('entries */, 32768) = 2048', 'entries */, 32767) = 2048',1))

    def test_runtime_source_and_probe_metadata_require_closed_loader_alias(self):
        lines = fixture_lines()
        start = next(i for i,l in enumerate(lines) if l.startswith("openat") and '"' + CHECKER.PREFIX + '/lib/python3.13/contextlib.py"' in l and "O_NOFOLLOW" not in l)
        end = next(i for i,l in enumerate(lines[start:],start) if l.startswith("close"))
        block = [l.replace(str(CHECKER.descriptor(lines[start].split(" = ")[1])[0]) + "<", "9999<") for l in lines[start:end+1]]
        remainder = lines[:start]+lines[end+1:]
        alias_close = next(i for i,l in enumerate(remainder) if l.startswith("close") and "libpython" in l)
        self.reject(trace(remainder[:alias_close]+block+remainder[alias_close:]))
        probe = CHECKER.PREFIX + "/lib/python3.13/importlib/resources/__pycache__/__init__.cpython-313.pyc"
        call = f"statx({CWD}, {json.dumps(probe)}, AT_STATX_SYNC_AS_STAT|AT_SYMLINK_NOFOLLOW, STATX_ALL, 0x1234) = -1 ENOENT (No such file or directory)"
        archive_close = next(i for i,l in enumerate(lines) if l.startswith("close") and ".glue>" in l)
        self.reject(trace(lines[:archive_close+1]+[call]+lines[archive_close+1:]))

    def test_only_exact_parser_remaps_with_live_anonymous_backings(self):
        for old,new in [("139264, 155648", "139264, 155649"), ("MREMAP_MAYMOVE", "MREMAP_FIXED|MREMAP_MAYMOVE"), ("mremap(0x3000000,", "mremap(0x4000000,"), ("155648, MREMAP_MAYMOVE) = 0x3000000", "155648, MREMAP_MAYMOVE) = -1 ENOMEM (Cannot allocate memory)")]:
            self.reject(trace().replace(old,new,1))
        lines=fixture_lines()
        self.reject(trace([l for l in lines if not l.startswith("mremap")]))
        i=next(i for i,l in enumerate(lines) if l.startswith("mremap"))
        self.reject(trace(lines[:i]+["munmap(0x3000000, 139264) = 0"]+lines[i:]))
        self.extra("mremap(0x3000000, 249856, 278528, MREMAP_MAYMOVE) = 0x3000000")

    def test_loader_header_is_once_exact_and_before_selected_mapping(self):
        lines=fixture_lines()
        i=next(i for i,l in enumerate(lines) if '"ELF header"' in l)
        self.reject(trace(lines[:i]+lines[i+1:]))
        self.reject(trace(lines[:i]+[lines[i]]+lines[i:]))
        self.reject(trace().replace('"ELF header"..., 832) = 832','"ELF header"..., 831) = 831'))

    def test_unobserved_bytecode_and_successful_extension_probes_reject(self):
        for suffix in ('codecs.cpython-313.pyc', 'encodings/ascii.cpython-313.pyc'):
            self.extra(f'openat({CWD}, {json.dumps(CHECKER.PREFIX + "/lib/python3.13/__pycache__/" + suffix)}, O_RDONLY|O_CLOEXEC) = -1 ENOENT (No such file or directory)')
        path=CHECKER.PREFIX+'/lib/python3.13/importlib/__init__.so'
        self.extra(f'openat({CWD}, {json.dumps(path)}, O_RDONLY|O_CLOEXEC) = 9000<{path}>')

    def test_publication_requires_runtime_closure_and_app_error_order(self):
        lines = fixture_lines()
        output = lines.pop(next(i for i,l in enumerate(lines) if l.startswith('write')))
        lines.insert(1, output)
        self.reject(trace(lines))
        lines = fixture_lines('app-error')
        i = next(i for i,l in enumerate(lines) if l.startswith('write'))
        lines[i], lines[i+1] = lines[i+1],lines[i]
        self.reject(trace(lines,'app-error'),'app-error')
        self.reject(trace().replace('answer=42\\n', 'answer=41\\n'))

    def test_retained_source_and_ancestor_descriptors_outlive_app(self):
        lines = fixture_lines()
        i = next(i for i,l in enumerate(lines) if l.startswith('close(3</>'))
        close = lines.pop(i)
        lines.insert(next(i for i,l in enumerate(lines) if '/proc/self/fd/' in l), close)
        self.reject(trace(lines))

    def test_negative_controls_require_complete_selected_failure(self):
        for mode in CHECKER.MODES:
            if mode in CHECKER.INITIALIZED or mode=='corrupt-source':
                continue
            lines=fixture_lines(mode)
            self.reject(trace([l for l in lines if not ('verified input' in l)],mode), mode)
            self.extra(f'openat({CWD}, "/proc/self/fd/9", O_RDONLY|O_CLOEXEC) = -1 ENOENT (No such file or directory)',mode)

    def test_corrupt_source_needs_locator_size_exact_full_payload_and_closure(self):
        lines=fixture_lines('corrupt-source')
        for predicate in [lambda l:'GLUERS00' in l, lambda l:'SEEK_END' in l, lambda l:'grom' in l, lambda l:l.startswith('close')]:
            self.reject(trace([l for l in lines if not predicate(l)],'corrupt-source'),'corrupt-source')
        self.reject(trace(lines,'corrupt-source').replace('104) = 104','104) = 103'), 'corrupt-source')
        self.reject(trace(lines,'corrupt-source').replace('grom','from'), 'corrupt-source')
        self.reject(trace(lines,'corrupt-source').replace('1024, SEEK_SET) = 1024','1025, SEEK_SET) = 1025'), 'corrupt-source')

    def test_raw_gzip_truncation_extra_records_and_trace_bounds(self):
        with tempfile.TemporaryDirectory() as directory:
            path=Path(directory)/'trace.gz'
            path.write_bytes(gzip.compress(trace().encode(),mtime=0))
            CHECKER.check_file(path)
            path.write_bytes(path.read_bytes()[:-5])
            with self.assertRaises((EOFError,CHECKER.TraceError)):
                CHECKER.check_file(path)
        self.reject(trace()[:-1])
        self.reject(trace()+'1234  gettid() = 1234\n')
        self.reject(trace().replace('1234  ', '', 1))
        self.reject(trace().replace(' = 0\n', ' = ?\n', 1))

    def test_cli_retained_outputs_and_corrupt_offset_required(self):
        with tempfile.TemporaryDirectory() as directory:
            root=Path(directory)
            raw=root/'trace.txt'; out=root/'out'; err=root/'err'
            raw.write_text(trace(mode='corrupt-source'))
            out.write_bytes(b''); err.write_bytes(CHECKER.CORRUPT_ERROR)
            argv=[sys.executable,str(SCRIPT),str(raw),'--mode','corrupt-source','--archive-bytes',str(CHECKER.ARCHIVE_BYTES),'--stdout-file',str(out),'--stderr-file',str(err)]
            result=subprocess.run(argv,capture_output=True)
            self.assertEqual(result.returncode,1)
            self.assertIn(b'requires retained',result.stderr)
            result=subprocess.run(argv+['--corrupt-source-offset',str(CHECKER.CORRUPT_SOURCE_OFFSET)],capture_output=True)
            self.assertEqual(result.returncode,0,result.stderr)
            err.write_bytes(CHECKER.CORRUPT_ERROR+b'extra')
            self.assertEqual(subprocess.run(argv+['--corrupt-source-offset',str(CHECKER.CORRUPT_SOURCE_OFFSET)],capture_output=True).returncode,1)


if __name__ == '__main__':
    unittest.main()
