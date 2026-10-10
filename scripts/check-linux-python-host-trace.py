#!/usr/bin/env python3
"""Fail-closed complete-trace policy for the exact installed-Python fixture.

This evidence policy admits only the selected host library, its six pinned
startup sources, isolated import probes and observed OS startup reads. Artifact
identities are retained separately. It rejects attempted filesystem mutation,
unknown calls, unverified Python mappings and additional processes, including
failed attempts. It is not a runtime sandbox or a general Python import policy.
"""

from __future__ import annotations

import argparse
import gzip
import importlib.util
import json
from pathlib import Path
import re
import sys


SPEC = importlib.util.spec_from_file_location(
    "glue_host_common_trace", Path(__file__).with_name("check-linux-python-bootstrap-trace.py")
)
assert SPEC is not None and SPEC.loader is not None
COMMON = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(COMMON)
PBS, BASE, TraceError = COMMON.PBS, COMMON.BASE, COMMON.TraceError
quoted, unsigned, pointer, result_number, descriptor = (
    COMMON.quoted, COMMON.unsigned, COMMON.pointer, COMMON.result_number, COMMON.descriptor
)
DIRECTORY = "/build-target/relocated Python host"
PROGRAM = DIRECTORY + "/glue-python-bootstrap-probe"
PREFIX = "/build-target/host Python"
CWD = COMMON.CWD
LIBRARY_BYTES = COMMON.LIBRARY_BYTES
ARCHIVE_BYTES = 4096  # Synthetic test size; real captures pass their retained size.
SOURCES = {
    "codecs.py": 36978,
    "encodings/__init__.py": 6020,
    "encodings/aliases.py": 16011,
    "encodings/ascii.py": 1248,
    "encodings/latin_1.py": 1264,
    "encodings/utf_8.py": 1005,
}
MODES = ("success", "wrong-library", "wrong-stdlib", "missing-encodings", "symlink-stdlib", "missing-library", "cached-bytecode", "app-error")
INITIALIZED = {"success", "app-error"}
MAX_TRACE_BYTES, MAX_LINE_CHARACTERS, MAX_RECORDS = (
    COMMON.MAX_TRACE_BYTES, COMMON.MAX_LINE_CHARACTERS, COMMON.MAX_RECORDS
)
SUCCESS = COMMON.SUCCESS.replace(b"encodings=frozen", b"encodings=installed")
APP_ERROR = b"glue-python-bootstrap-probe: intentional Python host app error\n"
READ_FLAGS = {"O_RDONLY", "O_NOFOLLOW", "O_NONBLOCK", "O_CLOEXEC"}
DIRECTORY_FLAGS = READ_FLAGS | {"O_DIRECTORY"}
IMAGE_SEGMENTS = {(20_423_824, 0): "PROT_READ|PROT_EXEC", (1_695_744, 0x115a000): "PROT_READ|PROT_WRITE"}


def prefix_for(mode):
    return PREFIX if mode in INITIALIZED else PREFIX + " " + mode


def archive_for(mode):
    return DIRECTORY + "/" + ("success" if mode == "app-error" else mode) + ".glue"


def expected_output(mode):
    if mode not in MODES:
        raise TraceError("unknown installed-Python fixture mode")
    prefix = prefix_for(mode)
    messages = {
        "wrong-library": f"host file identity mismatch: {prefix}/lib/libpython3.13.so.1.0",
        "wrong-stdlib": f"host file identity mismatch: {prefix}/lib/python3.13/encodings/__init__.py",
        "missing-encodings": f"host path {prefix}/lib/python3.13/encodings/__init__.py: No such file or directory (os error 2)",
        "symlink-stdlib": f"host path {prefix}/lib/python3.13 must be a directory without symlinks",
        "missing-library": f"host path {prefix}/lib/libpython3.13.so.1.0: No such file or directory (os error 2)",
        "cached-bytecode": f"host startup bytecode cache is unsupported: {prefix}/lib/python3.13/encodings/__pycache__",
    }
    return (SUCCESS if mode in INITIALIZED else b"",
            b"" if mode == "success" else APP_ERROR if mode == "app-error"
            else ("glue-python-bootstrap-probe: " + messages[mode] + "\n").encode("ascii"))


class Checker(COMMON.Checker):
    def __init__(self, mode="success", archive_bytes=ARCHIVE_BYTES):
        # Reuse strict parsing and OS/std-stream rules without changing the
        # archived-runtime policy's large archive or memfd requirements.
        super().__init__("success")
        self.mode = mode
        self.expected = expected_output(mode)
        if type(archive_bytes) is not int or not 0 < archive_bytes <= 96 * 1024:
            raise TraceError("archive size is outside the bounded host fixture profile")
        self.archive_bytes = archive_bytes
        self.archive = archive_for(mode)
        self.prefix = prefix_for(mode)
        self.stdlib = self.prefix + "/lib/python3.13"
        self.library = self.prefix + "/lib/libpython3.13.so.1.0"
        self.sources = {self.stdlib + "/" + suffix: size for suffix, size in SOURCES.items()}
        self.import_sources = {self.stdlib + "/encodings/" + name for name in ("__init__.py", "aliases.py", "utf_8.py")}
        self.host_sizes = {self.library: LIBRARY_BYTES, **self.sources}
        self.directories = {"/", "/build-target", self.prefix, self.prefix + "/lib", self.stdlib, self.stdlib + "/encodings"}
        self.directory_fds = set()
        self.pinned_dirs = set()
        self.verified_fds = set()
        self.verified_bytes = {path: 0 for path in self.host_sizes}
        self.cursors = {}
        self.library_fd = None
        self.alias_fd = None
        self.alias_opens = 0
        self.source_opens = {path: 0 for path in self.sources}
        self.import_reads = {path: 0 for path in self.sources}
        self.control_failure = False
        self.getdents_queries = 0
        self.metadata_queries = 0
        self.cache_checks = set()
        self.path_metadata = {}
        self.fd_metadata = set()
        self.enumerated = set()
        self.directory_entries = {self.stdlib: 0, self.stdlib + "/encodings": 0}
        self.load_verified = False
        self.hash_eof = set()
        self.hash_eof_paths = set()
        self.rewound = set()
        self.import_eof = set()

    def cache_paths(self):
        return {self.stdlib + "/__pycache__", self.stdlib + "/encodings/__pycache__"}

    def archive_complete(self):
        if self.archive_opened != 1 or self.archive_read != self.archive_bytes + 20 or self.archive in self.readers.values():
            return False
        covered = 0
        for start, end in sorted(self.archive_ranges):
            if start > covered:
                return False
            covered = max(covered, end)
        return covered == self.archive_bytes

    def host_complete(self):
        return (all(self.verified_bytes[path] == size for path, size in self.host_sizes.items()) and
                all(self.path_metadata.get(path, 0) >= 2 for path in self.host_sizes) and
                all(number in self.fd_metadata for number in self.verified_fds) and
                all(number in self.hash_eof and number in self.rewound and self.cursors[number] == 0 for number in self.verified_fds) and
                len(self.verified_fds) == len(self.host_sizes))

    def imports_complete(self):
        return (self.import_eof == self.import_sources and
                all(self.import_reads[path] == self.sources[path] and self.source_opens[path] == 1 for path in self.import_sources) and
                self.enumerated == {self.stdlib, self.stdlib + "/encodings"})

    def control_complete(self):
        if self.mode in INITIALIZED or not self.archive_complete() or self.alias_opens or self.image_mappings or self.readers:
            return False
        if self.mode == "symlink-stdlib":
            return self.control_failure and not self.cache_checks and not any(self.verified_bytes.values())
        if self.cache_checks != self.cache_paths():
            return False
        required = {self.library} if self.mode == "wrong-library" else {self.library, self.stdlib + "/codecs.py"} if self.mode == "missing-encodings" else {self.library, self.stdlib + "/codecs.py", self.stdlib + "/encodings/__init__.py"} if self.mode == "wrong-stdlib" else set()
        return (all(self.verified_bytes[path] == size if path in required else self.verified_bytes[path] == 0 for path, size in self.host_sizes.items()) and
                required <= self.hash_eof_paths and
                (self.mode in {"wrong-library", "wrong-stdlib"} or self.control_failure))

    def reader(self, argument):
        return PBS.Checker.reader(self, argument)

    def metadata(self, name, args, result):
        value = result_number(result)
        if name == "fstat":
            self.arity(name, args, (2,))
            number, _, _ = descriptor(args[0])
            if number < 3:
                return super().call(name, args, result)
            number, path = self.reader(args[0])
            body = args[1]
        else:
            self.arity(name, args, (4,))
            body = args[2]
            if args[0] == CWD:
                path = quoted(args[1])
                number = None
                if args[3] not in {"0", "AT_SYMLINK_NOFOLLOW"}:
                    raise TraceError("unapproved host path metadata flags")
            else:
                number, path = self.reader(args[0])
                if args[1] != '""' or args[3] != "AT_EMPTY_PATH":
                    raise TraceError("descriptor metadata must inspect its exact open object")
        if path in self.cache_paths() | self.directories | set(self.host_sizes) and not self.archive_complete():
            raise TraceError("complete archive admission must precede all host runtime validation")
        if path in self.cache_paths() | self.directories | set(self.host_sizes) and not self.alias_opens and number is None and args[3] != "AT_SYMLINK_NOFOLLOW":
            raise TraceError("every host prerequisite lookup must reject symlinks even on failed queries")
        if path in self.cache_paths():
            if self.alias_opens or path in self.cache_checks:
                raise TraceError("cache prerequisite must be checked once before Python image loading")
            if self.mode == "cached-bytecode" and path.endswith("/encodings/__pycache__"):
                if value != 0 or re.fullmatch(r"\{st_mode=S_IFDIR\|[0-7]{4}, st_size=[0-9]{1,20}, \.\.\.\}", body) is None:
                    raise TraceError("cached-bytecode control requires its exact present cache directory")
                self.control_failure = True
            else:
                if result != "-1 ENOENT (No such file or directory)":
                    raise TraceError("both installed startup cache directories must be absent")
                pointer(body)
            self.cache_checks.add(path)
        elif path in self.directories:
            if self.mode == "symlink-stdlib" and path == self.stdlib:
                expected = "S_IFLNK"
                self.control_failure = True
            else:
                expected = "S_IFDIR"
            if value != 0 or re.fullmatch(r"\{st_mode=" + expected + r"\|[0-7]{4}, st_size=[0-9]{1,20}, \.\.\.\}", body) is None:
                raise TraceError("host directory metadata differs from the selected path kind")
            unsigned(re.search(r"st_size=([0-9]+)", body)[1])
        elif path in self.host_sizes:
            if ((self.mode == "missing-encodings" and path == self.stdlib + "/encodings/__init__.py") or
                    (self.mode == "missing-library" and path == self.library)):
                if result != "-1 ENOENT (No such file or directory)":
                    raise TraceError("missing source must fail its exact metadata lookup")
                pointer(body)
                self.control_failure = True
            elif value != 0 or re.fullmatch(r"\{st_mode=S_IFREG\|[0-7]{4}, st_size=" + str(self.host_sizes[path]) + r", \.\.\.\}", body) is None:
                raise TraceError("host regular-file metadata has the wrong kind or pinned size")
        elif self.mode in INITIALIZED and path in self.import_probes():
            if result != "-1 ENOENT (No such file or directory)":
                raise TraceError("isolated import probe must fail without reading a fallback")
            pointer(body)
        else:
            # Common rules admit metadata only through known open OS files.
            if number is None or path not in COMMON.LIBRARIES | {COMMON.CACHE, COMMON.OVERCOMMIT, f"/proc/{self.pid}/maps"}:
                raise TraceError("unapproved metadata or host fallback path")
            return super().call(name, args, result)
        self.metadata_queries += 1
        if value == 0 and path not in self.cache_paths() and not self.alias_opens:
            if number is None:
                if args[3] != "AT_SYMLINK_NOFOLLOW":
                    raise TraceError("host pre-load path metadata must reject symlinks")
                self.path_metadata[path] = self.path_metadata.get(path, 0) + 1
            else:
                self.fd_metadata.add(number)
        if self.metadata_queries > 512:
            raise TraceError("host metadata query bound exceeded")

    def import_probes(self):
        probes = set()
        for source in self.sources:
            path = Path(source)
            probes.add(str(path.parent / "__pycache__" / (path.stem + ".cpython-313.pyc")))
        for suffix in (".cpython-313-aarch64-linux-gnu.so", ".abi3.so", ".so", ".pyc"):
            probes.add(self.stdlib + "/encodings/__init__" + suffix)
        return probes

    def call(self, name, args, result):
        value = result_number(result)
        if self.exit_group or (value is None and name != "exit_group"):
            raise TraceError("incomplete syscall or operation after exit_group")
        if name != "execve" and self.execs != 1:
            raise TraceError("trace must begin with its sole successful execve")
        if self.mode not in INITIALIZED and self.output[1] and name in {"openat", "read", "lseek", "statx", "newfstatat", "fstat", "getdents64", "mmap"}:
            raise TraceError("rejected host runtime may not resume validation or loading after its diagnostic")
        if name == "execve":
            self.arity(name, args, (3,))
            command = [PROGRAM, "run-host", self.archive] if self.mode != "app-error" else [PROGRAM, "run-host-negative", self.archive, "app-error"]
            if args[:2] != [json.dumps(PROGRAM), json.dumps(command)] or re.fullmatch(r"0x[0-9a-f]{1,16} /\* [0-9]{1,6} vars \*/", args[2]) is None:
                raise TraceError("execve differs from the exact relocated host fixture command")
            self.execs += 1
            if self.execs != 1 or value != 0:
                raise TraceError("require exactly one successful execve")
        elif name == "openat":
            self.arity(name, args, (3,))
            if args[0] != CWD:
                raise TraceError("unapproved filesystem directory descriptor or working directory")
            path = quoted(args[1])
            actual = BASE.flags(args[2], DIRECTORY_FLAGS | {"O_RDONLY", "O_CLOEXEC"})
            alias = re.fullmatch(r"/proc/self/fd/([0-9]{1,10})", path)
            target = path
            is_directory = path in self.directories
            is_verified = False
            if alias:
                if self.mode not in INITIALIZED or not self.archive_complete() or not self.host_complete() or self.alias_opens or int(alias[1]) != self.library_fd or actual != {"O_RDONLY", "O_CLOEXEC"}:
                    raise TraceError("host library alias load precedes complete pinned input verification")
                target = self.library
                self.alias_opens += 1
                self.load_verified = True
            elif path == self.archive:
                if actual != {"O_RDONLY", "O_CLOEXEC"} or self.archive_opened:
                    raise TraceError("archive must be opened exactly once, read-only and close-on-exec")
                self.archive_opened += 1
            elif path in self.host_sizes or is_directory:
                if not self.archive_complete():
                    raise TraceError("complete archive admission must precede host no-follow opens")
                if not self.alias_opens:
                    if actual != (DIRECTORY_FLAGS if is_directory else READ_FLAGS):
                        raise TraceError("host verification opens require no-follow read-only flags")
                    if path == self.stdlib and self.mode == "symlink-stdlib":
                        raise TraceError("symlinked stdlib must fail before an open or image load")
                    is_verified = not is_directory
                    if not self.path_metadata.get(path):
                        raise TraceError("host no-follow open must follow selected path metadata")
                    ancestors = [str(parent) for parent in Path(path).parents]
                    retained = {self.readers[number] for number in self.directory_fds if number in self.fd_metadata}
                    if any(parent not in retained or self.path_metadata.get(parent, 0) < 2 for parent in ancestors):
                        raise TraceError("host open requires verified retained ancestor directories")
                    if is_verified and self.cache_checks != self.cache_paths():
                        raise TraceError("host file hashing must follow both startup cache absence checks")
                    if is_verified and self.verified_bytes[path]:
                        raise TraceError("host verification may open each pinned file only once")
                elif self.mode not in INITIALIZED or self.image_mappings != set(IMAGE_SEGMENTS) or (is_directory and path not in {self.stdlib, self.stdlib + "/encodings"}) or (not is_directory and path not in self.import_sources) or actual != ({"O_RDONLY", "O_NONBLOCK", "O_CLOEXEC", "O_DIRECTORY"} if is_directory else {"O_RDONLY", "O_CLOEXEC"}):
                    raise TraceError("isolated imports must read only selected source files or directories")
                if self.mode == "missing-encodings" and path == self.stdlib + "/encodings/__init__.py":
                    raise TraceError("missing source must fail before it can be opened")
            elif path in self.import_probes():
                if self.mode not in INITIALIZED or not self.alias_opens or actual != {"O_RDONLY", "O_CLOEXEC"} or result != "-1 ENOENT (No such file or directory)":
                    raise TraceError("only exact absent bytecode probes are admitted")
                return
            else:
                # Adapt only the archive path for common OS opens; their exact
                # flags/identity/error checks remain unchanged.
                return super().call(name, args, result)
            number, annotation, deleted = descriptor(result)
            if value is None or value < 3 or number in self.readers or deleted or annotation != target:
                raise TraceError("open did not return a distinct exact annotated host descriptor")
            self.readers[number] = target
            self.cursors[number] = 0
            if is_directory:
                self.directory_fds.add(number)
                if not self.alias_opens:
                    self.pinned_dirs.add(number)
            elif is_verified:
                self.verified_fds.add(number)
                if path == self.library:
                    if self.library_fd is not None:
                        raise TraceError("host library must have exactly one pinned verification descriptor")
                    self.library_fd = number
            elif alias:
                self.alias_fd = number
            elif path in self.sources:
                self.source_opens[path] += 1
                if self.source_opens[path] != 1:
                    raise TraceError("installed source may be imported at most once")
        elif name == "read":
            self.arity(name, args, (3,))
            number, path = self.reader(args[0])
            count = unsigned(args[2])
            if PBS.BUFFER.fullmatch(args[1]) is None or value is None or not 0 <= value <= count or count > 96 * 1024 * 1024:
                raise TraceError("read requires a successful bounded count and parsed payload")
            if path == self.archive:
                if value:
                    self.archive_ranges.append((self.archive_cursor, self.archive_cursor + value))
                self.archive_cursor += value
                self.archive_read += value
                if self.archive_cursor > self.archive_bytes or self.archive_read > 3 * self.archive_bytes:
                    raise TraceError("archive read exceeds its retained size or pass bound")
            elif number in self.verified_fds:
                if self.alias_opens or count == 0 or count > 65536 or number in self.hash_eof or number in self.rewound or self.cursors[number] != self.verified_bytes[path]:
                    raise TraceError("host verification requires one sequential bounded read before alias loading")
                self.verified_bytes[path] += value
                self.cursors[number] += value
                if self.verified_bytes[path] > self.host_sizes[path]:
                    raise TraceError("host verified bytes exceed their exact pinned source size")
                if value == 0:
                    if count != 1 or args[1] != '""' or self.verified_bytes[path] != self.host_sizes[path]:
                        raise TraceError("host verification EOF must follow every pinned file byte")
                    self.hash_eof.add(number)
                    self.hash_eof_paths.add(path)
            elif path in self.sources:
                self.import_reads[path] += value
                if not self.alias_opens or path in self.import_eof or self.import_reads[path] > self.sources[path]:
                    raise TraceError("installed source reads exceed their pinned size or precede verification")
                if value == 0:
                    if count != 1 or args[1] != '""' or self.import_reads[path] != self.sources[path]:
                        raise TraceError("installed source EOF must follow every pinned imported byte")
                    self.import_eof.add(path)
            elif number == self.alias_fd:
                if not self.host_complete() or count > 832:
                    raise TraceError("loader header read must follow complete host identity verification")
            elif number in self.directory_fds:
                raise TraceError("directories may not be read as files")
            else:
                return super().call(name, args, result)
        elif name == "lseek":
            self.arity(name, args, (3,))
            number, _, _ = descriptor(args[0])
            if number < 3:
                return super().call(name, args, result)
            number, path = self.reader(args[0])
            if path == self.archive:
                offset = unsigned(args[1])
                expected = self.archive_bytes if args[2] == "SEEK_END" and offset == 0 else offset if args[2] == "SEEK_SET" and offset <= self.archive_bytes else None
                if expected is None or value != expected:
                    raise TraceError("archive seek result disagrees with a bounded requested offset")
                self.archive_cursor = expected
            elif number in self.verified_fds:
                if args[1:] != ["0", "SEEK_SET"] or value != 0 or self.verified_bytes[path] != self.host_sizes[path] or self.alias_opens or number not in self.hash_eof or number in self.rewound:
                    raise TraceError("host file rewind must follow its complete verification read")
                self.cursors[number] = 0
                self.rewound.add(number)
            elif path in self.sources and self.alias_opens:
                if args[1:] != ["0", "SEEK_CUR"] or value != self.import_reads[path]:
                    raise TraceError("source seek may only query the current import offset")
            else:
                raise TraceError("unapproved host descriptor seek")
        elif name == "statx":
            self.arity(name, args, (5,))
            expected_flag = "AT_STATX_SYNC_AS_STAT|AT_SYMLINK_NOFOLLOW" if args[0] == CWD else "AT_STATX_SYNC_AS_STAT|AT_EMPTY_PATH"
            if args[2:4] != [expected_flag, "STATX_ALL"]:
                raise TraceError("host statx must use exact no-follow or descriptor metadata flags")
            body = args[4]
            if value == 0:
                match = re.fullmatch(r"\{stx_mask=STATX_ALL\|STATX_MNT_ID, stx_attributes=(?:0|STATX_ATTR_MOUNT_ROOT), stx_mode=(S_IFDIR|S_IFREG|S_IFLNK)\|([0-7]{4}), stx_size=([0-9]{1,20}), \.\.\.\}", body)
                if match is None:
                    raise TraceError("unparsed host statx object kind or size")
                unsigned(match[3])
                body = "{st_mode=" + match[1] + "|" + match[2] + ", st_size=" + match[3] + ", ...}"
            else:
                pointer(body)
            flag = "AT_SYMLINK_NOFOLLOW" if args[0] == CWD else "AT_EMPTY_PATH"
            return self.metadata("newfstatat", [args[0], args[1], body, flag], result)
        elif name in {"newfstatat", "fstat"}:
            return self.metadata(name, args, result)
        elif name in {"fcntl", "ioctl"}:
            self.arity(name, args, (2,) if name == "fcntl" else (3,))
            number, _, _ = descriptor(args[0])
            if number < 3:
                return super().call(name, args, result)
            number, path = self.reader(args[0])
            if self.mode not in INITIALIZED or not self.alias_opens or path not in self.sources or number in self.verified_fds:
                raise TraceError("source descriptor query requires an isolated imported source")
            if name == "fcntl":
                if args[1] != "F_GETFD" or result != "0x1 (flags FD_CLOEXEC)":
                    raise TraceError("import source descriptor must retain close-on-exec")
            else:
                pointer(args[2])
                if args[1] != "TCGETS" or result != "-1 ENOTTY (Inappropriate ioctl for device)":
                    raise TraceError("only the failed imported-source terminal query is admitted")
        elif name == "getdents64":
            self.arity(name, args, (3,))
            number, path = self.reader(args[0])
            if self.mode not in INITIALIZED or not self.alias_opens or number not in self.directory_fds or path not in {self.stdlib, self.stdlib + "/encodings"} or args[2] != "32768" or value is None or not 0 <= value <= 32768:
                raise TraceError("directory enumeration requires an isolated selected stdlib directory")
            match = re.fullmatch(r"(0x[0-9a-f]{1,16}) /\* ([0-9]{1,3}) entries \*/", args[1])
            if match is None or not 0 <= int(match[2]) <= 200 or (value == 0) != (int(match[2]) == 0):
                raise TraceError("unparsed stdlib directory enumeration buffer")
            self.getdents_queries += 1
            if path in self.enumerated:
                raise TraceError("directory enumeration may not continue after its complete EOF")
            self.directory_entries[path] += int(match[2])
            if value == 0:
                if self.directory_entries[path] != (193 if path == self.stdlib else 124):
                    raise TraceError("installed stdlib directory enumeration differs from retained source inventory")
                self.enumerated.add(path)
            if self.getdents_queries > 6:
                raise TraceError("stdlib directory enumeration bound exceeded")
        elif name == "close":
            self.arity(name, args, (1,))
            number, path = self.reader(args[0])
            self.succeeds(value)
            if number == self.library_fd and self.mode in INITIALIZED:
                raise TraceError("loaded host library descriptor must remain pinned until process exit")
            if self.mode in INITIALIZED and (number in self.verified_fds or number in self.pinned_dirs) and bytes(self.output[0]) != self.expected[0]:
                raise TraceError("verified host file and ancestor descriptors must outlive app execution")
            del self.readers[number]
            self.directory_fds.discard(number)
            self.pinned_dirs.discard(number)
            self.verified_fds.discard(number)
            self.cursors.pop(number, None)
            self.fd_metadata.discard(number)
            if number == self.alias_fd:
                self.alias_fd = None
        elif name == "mmap":
            self.arity(name, args, (6,))
            flags = BASE.flags(args[3], {"MAP_PRIVATE", "MAP_ANONYMOUS", "MAP_FIXED", "MAP_DENYWRITE", "MAP_STACK"})
            if "MAP_ANONYMOUS" not in flags:
                number, path = self.reader(args[4])
                if path in self.host_sizes:
                    pointer(args[0])
                    count = unsigned(args[1])
                    offset = int(args[5], 16) if re.fullmatch(r"0x[0-9a-f]{1,16}", args[5]) else unsigned(args[5])
                    if self.mode not in INITIALIZED or not self.host_complete() or number != self.alias_fd or flags != {"MAP_PRIVATE", "MAP_FIXED", "MAP_DENYWRITE"} or args[2] != IMAGE_SEGMENTS.get((count, offset)) or (count, offset) in self.image_mappings or value is None or value <= 0:
                        raise TraceError("host image mapping must be one verified private stock segment")
                    self.image_mappings.add((count, offset))
                    return
                if path == self.archive:
                    raise TraceError("host archive payload may not be mapped")
            return super().call(name, args, result)
        elif name == "memfd_create":
            raise TraceError("installed Python must not create a memfd or fall back to bundled loading")
        elif name == "write":
            if self.mode in INITIALIZED and (self.image_mappings != set(IMAGE_SEGMENTS) or not self.imports_complete()):
                raise TraceError("app diagnostics must follow verified image mappings and complete installed source imports")
            if self.mode == "app-error" and descriptor(args[0])[0] == 2 and bytes(self.output[0]) != self.expected[0]:
                raise TraceError("app-error diagnostic must follow the complete app success output")
            if self.mode not in INITIALIZED and not self.control_complete():
                raise TraceError("validation diagnostic must follow exact failed prerequisites and closed descriptors")
            return super().call(name, args, result)
        elif name in {"gettid", "readlinkat"}:
            if self.mode in INITIALIZED and self.image_mappings != set(IMAGE_SEGMENTS):
                raise TraceError("Python startup probes must follow both verified private image segments")
            return super().call(name, args, result)
        else:
            return super().call(name, args, result)

    def finish(self):
        if self.execs != 1 or not self.exit_group or not self.completed:
            raise TraceError("incomplete trace: require one exec and completed expected exit")
        if self.archive_opened != 1 or self.archive_read != self.archive_bytes + 20:
            raise TraceError("require complete archive reads and the checked ZIP directory")
        covered = 0
        for start, end in sorted(self.archive_ranges):
            if start > covered:
                raise TraceError("archive read coverage contains an unread byte range")
            covered = max(covered, end)
        if covered != self.archive_bytes:
            raise TraceError("archive reads do not cover every retained byte")
        if self.mode in INITIALIZED:
            if not self.load_verified or self.alias_opens != 1 or self.image_mappings != set(IMAGE_SEGMENTS):
                raise TraceError("require all pinned host input bytes before the two private library mappings")
            if self.readers != {self.library_fd: self.library} or self.alias_fd is not None:
                raise TraceError("require one pinned host library and a closed loader alias descriptor")
            if self.virtual_queries != 1 or self.overcommit_reads != 1 or self.tid_queries != 1 or self.timezone_queries != 1:
                raise TraceError("required controlled stock startup observations are missing")
            if not self.imports_complete():
                raise TraceError("require complete installed encodings source imports and isolated directory enumeration")
        elif self.alias_opens or self.image_mappings or self.virtual_queries or self.overcommit_reads or self.tid_queries or self.timezone_queries:
            raise TraceError("invalid host runtime must fail before any Python image load or initialization")
        elif self.mode == "wrong-library" and (self.verified_bytes[self.library] != LIBRARY_BYTES or self.library not in self.hash_eof_paths):
            raise TraceError("wrong-library control must hash the complete selected library")
        elif self.mode == "wrong-stdlib" and (self.verified_bytes[self.library] != LIBRARY_BYTES or self.library not in self.hash_eof_paths or self.verified_bytes[self.stdlib + "/encodings/__init__.py"] != SOURCES["encodings/__init__.py"] or self.stdlib + "/encodings/__init__.py" not in self.hash_eof_paths):
            raise TraceError("wrong-stdlib control must hash the selected library and corrupt source")
        elif self.mode in {"missing-encodings", "symlink-stdlib", "missing-library", "cached-bytecode"} and not self.control_failure:
            raise TraceError("missing/symlink source control requires its exact failed validation lookup")
        if self.mode != "symlink-stdlib" and self.cache_checks != self.cache_paths():
            raise TraceError("require both selected startup cache prerequisite checks")
        if self.mode in {"symlink-stdlib", "missing-library", "cached-bytecode"} and any(self.verified_bytes.values()):
            raise TraceError("absent/unsupported prerequisite must fail before hashing host file bytes")
        if any(path not in self.host_sizes and path not in self.directories for path in self.readers.values()):
            raise TraceError("ordinary read descriptors must be closed before exit")
        if tuple(bytes(data) for data in self.output) != self.expected:
            raise TraceError("trace diagnostics differ from complete expected stdout/stderr")


def check_lines(lines, mode="success", archive_bytes=ARCHIVE_BYTES):
    checker = Checker(mode, archive_bytes)
    total = 0
    for number, line in enumerate(lines, 1):
        if number > MAX_RECORDS:
            raise TraceError("trace exceeds the record bound")
        try:
            total += len(line.encode("utf-8"))
        except UnicodeError as error:
            raise TraceError("trace is not strict UTF-8") from error
        if total > MAX_TRACE_BYTES or len(line) > MAX_LINE_CHARACTERS + 1 or not line.endswith("\n") or "\r" in line:
            raise TraceError("trace is oversized, noncanonical or has a truncated line")
        try:
            checker.line(line[:-1])
        except TraceError as error:
            raise TraceError(f"line {number}: {error}") from error
    checker.finish()


def check_trace(text, mode="success", archive_bytes=ARCHIVE_BYTES):
    check_lines(text.splitlines(keepends=True), mode, archive_bytes)


def check_file(path, mode="success", archive_bytes=ARCHIVE_BYTES):
    if path.stat().st_size > MAX_TRACE_BYTES:
        raise TraceError("trace input exceeds the compressed/raw byte bound")
    with (gzip.open if path.suffix == ".gz" else open)(path, "rb") as stream:
        def lines():
            while True:
                raw = stream.readline(MAX_LINE_CHARACTERS + 2)
                if not raw:
                    return
                if len(raw) > MAX_LINE_CHARACTERS + 1:
                    raise TraceError("trace exceeds the line bound")
                yield raw.decode("utf-8", errors="strict")
        check_lines(lines(), mode, archive_bytes)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("trace", type=Path)
    parser.add_argument("--mode", choices=MODES, default="success")
    parser.add_argument("--stdout-file", type=Path, required=True)
    parser.add_argument("--stderr-file", type=Path, required=True)
    archive = parser.add_mutually_exclusive_group(required=True)
    archive.add_argument("--archive-file", type=Path)
    archive.add_argument("--archive-bytes", type=int)
    args = parser.parse_args()
    try:
        for path, expected in zip((args.stdout_file, args.stderr_file), expected_output(args.mode)):
            with path.open("rb") as stream:
                if stream.read(len(expected) + 1) != expected:
                    raise TraceError("retained stdout/stderr differs from the exact fixture diagnostic")
        size = args.archive_file.stat().st_size if args.archive_file else args.archive_bytes
        check_file(args.trace, args.mode, size)
    except (OSError, UnicodeError, EOFError, TraceError) as error:
        print(f"stock host Python trace rejected: {error}", file=sys.stderr)
        return 1
    print("Trace checks passed: complete archive reads, pinned installed inputs before private library mappings or exact pre-init rejection, isolated source imports, exact diagnostics and exit, no mutation, bundled fallback or extra process")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
