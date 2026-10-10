"""Adversarial checks for the complete installed-Python trace policy."""

import gzip
import importlib.util
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch


SCRIPT = Path(__file__).with_name("check-linux-python-host-trace.py")
SPEC = importlib.util.spec_from_file_location("host_trace_checker", SCRIPT)
assert SPEC is not None and SPEC.loader is not None
CHECKER = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(CHECKER)
CWD = CHECKER.CWD


def fixture_lines(mode="success"):
    archive = CHECKER.archive_for(mode)
    prefix = CHECKER.prefix_for(mode)
    stdlib = prefix + "/lib/python3.13"
    library = prefix + "/lib/libpython3.13.so.1.0"
    command = [CHECKER.PROGRAM, "run-host", archive] if mode != "app-error" else [CHECKER.PROGRAM, "run-host-negative", archive, "app-error"]
    archive_fd = "3<" + archive + ">"
    lines = [
        f"execve({json.dumps(CHECKER.PROGRAM)}, {json.dumps(command)}, 0x1234 /* 18 vars */) = 0",
        f"openat({CWD}, {json.dumps(archive)}, O_RDONLY|O_CLOEXEC) = {archive_fd}",
        f"lseek({archive_fd}, 0, SEEK_END) = {CHECKER.ARCHIVE_BYTES}",
        f"lseek({archive_fd}, 0, SEEK_SET) = 0",
        f'read({archive_fd}, "complete archive"..., {CHECKER.ARCHIVE_BYTES}) = {CHECKER.ARCHIVE_BYTES}',
        f"lseek({archive_fd}, {CHECKER.ARCHIVE_BYTES - 20}, SEEK_SET) = {CHECKER.ARCHIVE_BYTES - 20}",
        f'read({archive_fd}, "ZIP bytes"..., 20) = 20',
        f"close({archive_fd}) = 0",
    ]
    fds = {}
    next_fd = 3

    def metadata(path, kind, size, fd=None):
        location = CWD if fd is None else str(fd) + "<" + path + ">"
        argument = json.dumps(path) if fd is None else '""'
        flags = "AT_STATX_SYNC_AS_STAT|AT_SYMLINK_NOFOLLOW" if fd is None else "AT_STATX_SYNC_AS_STAT|AT_EMPTY_PATH"
        lines.append(f"statx({location}, {argument}, {flags}, STATX_ALL, {{stx_mask=STATX_ALL|STATX_MNT_ID, stx_attributes=0, stx_mode={kind}|0555, stx_size={size}, ...}}) = 0")

    def missing(path):
        lines.append(f"statx({CWD}, {json.dumps(path)}, AT_STATX_SYNC_AS_STAT|AT_SYMLINK_NOFOLLOW, STATX_ALL, 0x1234) = -1 ENOENT (No such file or directory)")

    for path in ["/", "/build-target", prefix, prefix + "/lib", stdlib, stdlib + "/encodings"]:
        if mode == "symlink-stdlib" and path == stdlib:
            metadata(path, "S_IFLNK", 45)
            break
        metadata(path, "S_IFDIR", 4096)
        fd = next_fd
        next_fd += 1
        lines.append(f"openat({CWD}, {json.dumps(path)}, O_RDONLY|O_NONBLOCK|O_NOFOLLOW|O_CLOEXEC|O_DIRECTORY) = {fd}<{path}>")
        fds[fd] = path
        metadata(path, "S_IFDIR", 4096, fd)
        metadata(path, "S_IFDIR", 4096)
    if mode != "symlink-stdlib":
        missing(stdlib + "/__pycache__")
        if mode == "cached-bytecode":
            metadata(stdlib + "/encodings/__pycache__", "S_IFDIR", 4096)
        else:
            missing(stdlib + "/encodings/__pycache__")
            files = [(library, CHECKER.LIBRARY_BYTES)] + [(stdlib + "/" + path, size) for path, size in CHECKER.SOURCES.items()]
            for path, size in files:
                if (mode == "missing-library" and path == library) or (mode == "missing-encodings" and path.endswith("encodings/__init__.py")):
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
                if (mode == "wrong-library" and path == library) or (mode == "wrong-stdlib" and path.endswith("encodings/__init__.py")):
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
        for directory, count in [(stdlib, 193), (stdlib + "/encodings", 124)]:
            lines += [
                f"openat({CWD}, {json.dumps(directory)}, O_RDONLY|O_NONBLOCK|O_CLOEXEC|O_DIRECTORY) = {alias}<{directory}>",
                f"getdents64({alias}<{directory}>, 0x1234 /* {count} entries */, 32768) = 8192",
                f"getdents64({alias}<{directory}>, 0x1234 /* 0 entries */, 32768) = 0",
                f"close({alias}<{directory}>) = 0",
            ]
        for suffix in ["encodings/__init__.py", "encodings/aliases.py", "encodings/utf_8.py"]:
            path = stdlib + "/" + suffix
            size = CHECKER.SOURCES[suffix]
            cache = str(Path(path).parent / "__pycache__" / (Path(path).stem + ".cpython-313.pyc"))
            lines += [
                f"openat({CWD}, {json.dumps(cache)}, O_RDONLY|O_CLOEXEC) = -1 ENOENT (No such file or directory)",
                f"openat({CWD}, {json.dumps(path)}, O_RDONLY|O_CLOEXEC) = {alias}<{path}>",
                f"fcntl({alias}<{path}>, F_GETFD) = 0x1 (flags FD_CLOEXEC)",
                f"fstat({alias}<{path}>, {{st_mode=S_IFREG|0444, st_size={size}, ...}}) = 0",
                f"ioctl({alias}<{path}>, TCGETS, 0x1234) = -1 ENOTTY (Inappropriate ioctl for device)",
                f"lseek({alias}<{path}>, 0, SEEK_CUR) = 0",
                f'read({alias}<{path}>, "installed source"..., {size + 1}) = {size}',
                f'read({alias}<{path}>, "", 1) = 0',
                f"close({alias}<{path}>) = 0",
            ]
    if mode not in CHECKER.INITIALIZED:
        for fd, path in fds.items():
            lines.append(f"close({fd}<{path}>) = 0")
    for index, diagnostic in enumerate(CHECKER.expected_output(mode), 1):
        for offset in range(0, len(diagnostic), 128):
            chunk = diagnostic[offset:offset + 128]
            fd = f'{index}</evidence/{mode}.{"stdout" if index == 1 else "stderr"}.txt>'
            lines.append(f"write({fd}, {json.dumps(chunk.decode('ascii'))}, {len(chunk)}) = {len(chunk)}")
    for fd, path in fds.items() if mode in CHECKER.INITIALIZED else []:
        if mode in CHECKER.INITIALIZED and path == library:
            continue
        lines.append(f"close({fd}<{path}>) = 0")
    status = 0 if mode == "success" else 1
    lines += [f"exit_group({status}) = ?", f"+++ exited with {status} +++"]
    return lines


def trace(lines=None, mode="success"):
    return "".join("1234  " + line + "\n" for line in (fixture_lines(mode) if lines is None else lines))


def extra(call, mode="success"):
    lines = fixture_lines(mode)
    lines.insert(-2, call)
    return trace(lines, mode)


class HostTracePolicyTests(unittest.TestCase):
    def reject(self, text, mode="success", fragment=None):
        with self.assertRaises(CHECKER.TraceError) as caught:
            CHECKER.check_trace(text, mode)
        if fragment:
            self.assertIn(fragment, str(caught.exception))

    def test_complete_success_and_all_seven_controls(self):
        for mode in CHECKER.MODES:
            with self.subTest(mode=mode):
                CHECKER.check_trace(trace(mode=mode), mode)

    def test_exact_exec_program_command_archive_and_exit(self):
        for old, new in [(CHECKER.PROGRAM, "/tmp/launcher"), ('"run-host"', '"run"'), (CHECKER.archive_for("success"), "/tmp/app.glue"), (" = 0\n", " = -1 EACCES (Permission denied)\n")]:
            self.reject(trace().replace(old, new, 1))
        self.reject(extra(fixture_lines()[0]))
        self.reject(trace(mode="app-error"), "success")

    def test_unknown_process_thread_network_and_async_calls(self):
        for call in ["unknown_future_syscall(0) = 0", "clone3({}, 64) = -1 ENOSYS (Function not implemented)", "clone(CLONE_VM|CLONE_THREAD, NULL) = -1 EPERM (Operation not permitted)", "socket(AF_INET, SOCK_STREAM, 0) = -1 EPERM (Operation not permitted)", "io_uring_setup(8, {}) = -1 EPERM (Operation not permitted)", 'execve("/bin/sh", ["sh"], NULL) = -1 EACCES (Permission denied)', "getpid() = 1234"]:
            self.reject(extra(call))
        self.reject(trace().replace("1234  gettid", "1235  gettid"), fragment="additional process")

    def test_mutation_attempts_and_memfd_fallback_even_when_failed(self):
        for call in [f'openat({CWD}, "/tmp/hidden", O_WRONLY|O_CREAT|O_EXCL, 0600) = -1 EACCES (Permission denied)', 'unlink("/tmp/hidden") = -1 ENOENT (No such file or directory)', 'mkdir("/tmp/a", 0700) = -1 EACCES (Permission denied)', "ftruncate(9, 0) = -1 EPERM (Operation not permitted)", 'memfd_create("glue-python-libpython3.13.so.1.0", MFD_CLOEXEC|MFD_ALLOW_SEALING|0x10) = -1 EPERM (Operation not permitted)', 'pwrite64(9, "x", 1, 0) = -1 EPERM (Operation not permitted)', "dup2(9, 1) = 1"]:
            self.reject(extra(call))

    def test_host_paths_flags_symlinks_and_fallback_probes_are_exact(self):
        for path in ["/usr/lib/python3.13/encodings/__init__.py", "/workspace/app.py", "/etc/passwd", CHECKER.PREFIX + "/lib/python3.13/site.py", "/proc/4321/fd/9"]:
            self.reject(extra(f"openat({CWD}, {json.dumps(path)}, O_RDONLY|O_CLOEXEC) = -1 ENOENT (No such file or directory)"))
        for old, new in [("O_NONBLOCK|O_NOFOLLOW", "O_NONBLOCK"), ("O_RDONLY|O_NONBLOCK|O_NOFOLLOW", "O_RDWR|O_NONBLOCK|O_NOFOLLOW"), (CWD, "AT_FDCWD</tmp>"), ("S_IFREG|0555, stx_size=73563968", "S_IFLNK|0555, stx_size=73563968")]:
            self.reject(trace().replace(old, new, 1))

    def test_ancestors_and_metadata_checks_precede_no_follow_opens(self):
        for predicate in [lambda line: line.startswith("statx"), lambda line: 'statx(9<' in line, lambda line: 'statx(3</>' in line]:
            self.reject(trace([line for line in fixture_lines() if not predicate(line)]))
        self.reject(trace().replace("STATX_ALL|STATX_MNT_ID", "STATX_BASIC_STATS", 1))
        self.reject(trace().replace("AT_STATX_SYNC_AS_STAT|AT_SYMLINK_NOFOLLOW", "AT_STATX_SYNC_AS_STAT", 1))

    def test_cache_absence_and_cached_control_fail_before_library_reads(self):
        for old, new in [('"' + CHECKER.PREFIX + '/lib/python3.13/__pycache__"', '"/tmp/cache"'), (" = -1 ENOENT (No such file or directory)", " = -1 EACCES (Permission denied)")]:
            self.reject(trace().replace(old, new, 1))
        self.reject(trace([line for line in fixture_lines() if '__pycache__", AT_STATX' not in line]))
        self.reject(extra('memfd_create("fallback", MFD_CLOEXEC) = -1 EPERM (Operation not permitted)', "cached-bytecode"), "cached-bytecode")

    def test_verified_host_hashing_is_complete_sequential_and_before_alias(self):
        library = CHECKER.PREFIX + "/lib/libpython3.13.so.1.0"
        old = f'read(9<{library}>, "verified input"..., 65536) = 65536'
        self.reject(trace().replace(old, old.removesuffix("65536") + "65535", 1))
        self.reject(trace().replace('"verified input"..., 65536)', '"verified input"..., 65537)', 1))
        lines = fixture_lines()
        alias = lines.pop(next(i for i, line in enumerate(lines) if '"/proc/self/fd/9"' in line))
        lines.insert(next(i for i, line in enumerate(lines) if '"verified input"' in line), alias)
        self.reject(trace(lines), fragment="verification")
        self.reject(trace().replace('"/proc/self/fd/9"', '"/proc/self/fd/10"', 1))

    def test_complete_hash_eof_and_exactly_one_rewind_are_required_before_loading(self):
        lines = fixture_lines()
        self.reject(trace([line for line in lines if not (line.startswith("lseek") and "host Python/" in line and "SEEK_SET" in line)]))
        self.reject(trace([line for line in lines if not (line.startswith("read") and '"", 1) = 0' in line)]))
        index = next(i for i, line in enumerate(lines) if line.startswith("lseek(9<"))
        self.reject(trace(lines[:index] + [lines[index]] + lines[index:]))
        eof = next(i for i, line in enumerate(lines) if line.startswith("read(9<") and '"", 1) = 0' in line)
        self.reject(trace(lines[:eof] + [lines[eof]] + lines[eof:]))
        early = lines.pop(eof)
        lines.insert(next(i for i, line in enumerate(lines) if line.startswith("read(9<")), early)
        self.reject(trace(lines), fragment="EOF")
        for mode in ["wrong-library", "wrong-stdlib"]:
            self.reject(trace([line for line in fixture_lines(mode) if not (line.startswith("read") and '"", 1) = 0' in line)], mode), mode)

    def test_archive_coverage_seek_and_descriptor_lifetime(self):
        archive = CHECKER.archive_for("success")
        self.reject(trace().replace(f"SEEK_END) = {CHECKER.ARCHIVE_BYTES}", f"SEEK_END) = {CHECKER.ARCHIVE_BYTES + 1}", 1))
        lines = fixture_lines()
        index = next(i for i, line in enumerate(lines) if '"complete archive"' in line)
        lines[index:index + 1] = [f'read(3<{archive}>, "first"..., 10) = 10', f'lseek(3<{archive}>, 11, SEEK_SET) = 11', f'read(3<{archive}>, "remaining"..., {CHECKER.ARCHIVE_BYTES - 10}) = {CHECKER.ARCHIVE_BYTES - 11}', f'lseek(3<{archive}>, 0, SEEK_SET) = 0', f'read(3<{archive}>, "duplicate", 1) = 1']
        self.reject(trace(lines), fragment="archive admission")
        self.reject(extra(f'read(3<{archive}>, "closed", 6) = 6'))

    def test_complete_archive_admission_precedes_host_validation_and_image_load(self):
        lines = fixture_lines()
        block = lines[1:8]
        delayed = lines[:1] + lines[8:-2] + block + lines[-2:]
        self.reject(trace(delayed), fragment="archive admission")
        # Keep a source descriptor number independent of later host FDs so the
        # late tail cannot be rejected merely because its FD was reused.
        lines = [line.replace("3<" + CHECKER.archive_for("success") + ">", "99<" + CHECKER.archive_for("success") + ">") for line in fixture_lines()]
        tail = lines[5:8]
        delayed = lines[:5] + lines[8:-2] + tail + lines[-2:]
        self.reject(trace(delayed), fragment="archive admission")

    def test_only_two_private_exact_stock_segments_are_admitted(self):
        for old, new in [("MAP_PRIVATE|MAP_FIXED|MAP_DENYWRITE", "MAP_SHARED|MAP_FIXED"), ("PROT_READ|PROT_EXEC", "PROT_READ|PROT_WRITE|PROT_EXEC"), ("20423824", "20423825"), ("0x115a000", "0x115b000")]:
            self.reject(trace().replace(old, new, 1))
        self.reject(extra("mmap(NULL, 4096, PROT_READ|PROT_EXEC, MAP_PRIVATE|MAP_ANONYMOUS, -1, 0) = 0x1234"))
        self.reject(extra("mprotect(0x1234, 4096, PROT_READ|PROT_EXEC) = 0"))

    def test_host_validation_controls_cannot_map_or_initialize_python(self):
        for mode in CHECKER.MODES:
            if mode in CHECKER.INITIALIZED:
                continue
            for call in ['openat(' + CWD + ', "/proc/self/fd/9", O_RDONLY|O_CLOEXEC) = -1 ENOENT (No such file or directory)', "gettid() = 1234", 'readlinkat(' + CWD + ', "/__glue_archive__/launcher", 0x1234, 4096) = -1 ENOENT (No such file or directory)']:
                self.reject(extra(call, mode), mode)

    def test_verified_descriptors_stay_pinned_until_app_has_completed(self):
        self.reject(extra(f"close(9<{CHECKER.PREFIX}/lib/libpython3.13.so.1.0>) = 0"))
        lines = fixture_lines()
        close = lines.pop(next(i for i, line in enumerate(lines) if line.startswith("close(10<")))
        lines.insert(next(i for i, line in enumerate(lines) if '"/proc/self/fd/9"' in line), close)
        self.reject(trace(lines), fragment="outlive app")

    def test_source_reads_must_be_installed_complete_and_bound_to_exact_fds(self):
        for old, new in [('"installed source"..., 6021) = 6020', '"installed source"..., 6021) = 6019'), ("F_GETFD) = 0x1 (flags FD_CLOEXEC)", "F_SETFD, 0) = 0"), ("TCGETS, 0x1234) = -1 ENOTTY", "TCGETS, 0x1234) = -1 EACCES")]:
            self.reject(trace().replace(old, new, 1))
        path = CHECKER.PREFIX + "/lib/python3.13/encodings/__pycache__/__init__.cpython-313.pyc"
        self.reject(trace().replace(json.dumps(path), json.dumps(path.replace("313", "314")), 1))
        self.reject(trace().replace('"installed source"..., 6021) = 6020', '"installed source"..., 6021) = 6021', 1))
        lines = fixture_lines()
        first_import = next(i for i, line in enumerate(lines) if '"installed source"' in line)
        self.reject(trace(lines[:first_import] + [line for line in lines[first_import:] if not (line.startswith("read") and '"", 1) = 0' in line)]))

    def test_startup_and_app_diagnostics_follow_image_mapping_and_imports(self):
        for predicate in [lambda line: line.startswith("gettid"), lambda line: line.startswith("write(1<")]:
            lines = fixture_lines()
            index = next(i for i, line in enumerate(lines) if predicate(line))
            early = lines.pop(index)
            lines.insert(next(i for i, line in enumerate(lines) if line.startswith("mmap")), early)
            self.reject(trace(lines))
        lines = fixture_lines("app-error")
        diagnostics = [line for line in lines if line.startswith("write(2<")]
        lines = [line for line in lines if not line.startswith("write(2<")]
        before_pass = next(i for i, line in enumerate(lines) if line.startswith("write(1<"))
        self.reject(trace(lines[:before_pass] + diagnostics + lines[before_pass:], "app-error"), "app-error")
        for mode in CHECKER.MODES:
            if mode in CHECKER.INITIALIZED:
                continue
            lines = fixture_lines(mode)
            diagnostics = [line for line in lines if line.startswith("write(2<")]
            rest = [line for line in lines if not line.startswith("write(2<")]
            self.reject(trace(rest[:1] + diagnostics + rest[1:], mode), mode)

    def test_cache_absence_lookups_must_reject_dangling_symlinks(self):
        lines = fixture_lines()
        for index, line in enumerate(lines):
            if '__pycache__", AT_STATX' in line:
                path = line.split('statx(' + CWD + ', ', 1)[1].split(', AT_STATX', 1)[0]
                lines[index] = f"newfstatat({CWD}, {path}, 0x1234, 0) = -1 ENOENT (No such file or directory)"
        self.reject(trace(lines), fragment="reject symlinks")
        mode = "missing-library"
        path = CHECKER.prefix_for(mode) + "/lib/libpython3.13.so.1.0"
        lines = fixture_lines(mode)
        index = next(i for i, line in enumerate(lines) if json.dumps(path) in line and " = -1 ENOENT" in line)
        lines[index] = f"newfstatat({CWD}, {json.dumps(path)}, 0x1234, 0) = -1 ENOENT (No such file or directory)"
        self.reject(trace(lines, mode), mode, fragment="reject symlinks")

    def test_directory_enumeration_requires_declared_path_full_inventory_and_eof(self):
        for old, new in [("/* 193 entries */", "/* 194 entries */"), ("/* 0 entries */, 32768) = 0", "/* 0 entries */, 32768) = 1"), ("32768) = 8192", "32769) = 8192")]:
            self.reject(trace().replace(old, new, 1))
        self.reject(trace([line for line in fixture_lines() if not line.startswith("getdents64")]))

    def test_exact_complete_diagnostics_and_standard_descriptor_identity(self):
        for old, new in [('"PASS Python', '"FAIL Python'), ("1</evidence/success.stdout.txt>", "2</evidence/success.stderr.txt>"), (", 111) = 111", ", 111) = 110"), (" = 111", " = -1 EPIPE (Broken pipe)")]:
            self.reject(trace().replace(old, new, 1))
        self.reject(extra('write(2</evidence/success.stderr.txt>, "extra", 5) = 5'))
        for mode in CHECKER.MODES:
            self.reject(trace([line for line in fixture_lines(mode) if not line.startswith("write")], mode), mode)

    def test_exact_os_probes_and_no_real_timezone_fallback(self):
        for old, new in [('"/usr/share/zoneinfo/UTC0"', '"/etc/localtime"'), ('"/__glue_archive__/launcher"', '"/usr/bin/python3"'), ('"0\\n", 32) = 2', '"1\\n", 32) = 2')]:
            self.reject(trace().replace(old, new, 1))
        self.reject(extra(f'openat({CWD}, "/usr/share/zoneinfo/UTC0", O_RDONLY|O_CLOEXEC) = 17</usr/share/zoneinfo/UTC0>'))

    def test_exit_records_and_no_activity_after_exit(self):
        for mode in CHECKER.MODES:
            lines = fixture_lines(mode)
            self.reject(trace(lines[:-1], mode), mode)
            self.reject(trace([line for line in lines if not line.startswith("exit_group")], mode), mode)
            self.reject(trace(lines, mode) + "1234  gettid() = 1234\n", mode)
            self.reject(trace(lines, mode).replace("+++ exited with", "--- interrupted with"), mode)
        self.reject(trace()[:-1])
        self.reject(trace() + "\n")

    def test_byte_line_record_numeric_and_utf8_bounds(self):
        with patch.object(CHECKER, "MAX_TRACE_BYTES", 20):
            self.reject(trace(), fragment="oversized")
        with patch.object(CHECKER, "MAX_RECORDS", 1):
            self.reject(trace(), fragment="record bound")
        with patch.object(CHECKER, "MAX_LINE_CHARACTERS", 20):
            self.reject(trace(), fragment="oversized")
        self.reject(trace().replace("1234  ", "12345678901  ", 1))
        self.reject(trace().replace("65536) = 65536", "18446744073709551616) = 65536", 1))
        self.reject(trace().replace("execve", "\ud800execve", 1), fragment="UTF-8")
        for size in [0, -1, True, 96 * 1024 + 1]:
            with self.assertRaises(CHECKER.TraceError):
                CHECKER.Checker(archive_bytes=size)

    def test_cli_raw_gzip_and_separate_diagnostics(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            stdout, stderr = root / "stdout", root / "stderr"
            stdout.write_bytes(CHECKER.SUCCESS)
            stderr.write_bytes(b"")
            for name in ["trace.txt", "trace.txt.gz"]:
                path = root / name
                data = trace().encode()
                path.write_bytes(gzip.compress(data) if name.endswith(".gz") else data)
                command = [sys.executable, str(SCRIPT), str(path), "--stdout-file", str(stdout), "--stderr-file", str(stderr), "--archive-bytes", str(CHECKER.ARCHIVE_BYTES)]
                self.assertEqual(subprocess.run(command, capture_output=True).returncode, 0)
                stderr.write_bytes(b"unexpected\n")
                self.assertEqual(subprocess.run(command, capture_output=True).returncode, 1)
                stderr.write_bytes(b"")
            (root / "broken.gz").write_bytes(b"not gzip")
            with self.assertRaises((OSError, EOFError)):
                CHECKER.check_file(root / "broken.gz")


if __name__ == "__main__":
    unittest.main()
