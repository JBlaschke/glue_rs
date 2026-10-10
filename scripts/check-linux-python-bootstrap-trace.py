#!/usr/bin/env python3
"""Fail-closed complete-trace policy for one pinned stock-PBS bootstrap cell.

The archive and launcher identities are retained separately. This evidence
checker admits the observed OS runtime reads and one fully populated, sealed
libpython memfd, followed by private stock-image mappings. It rejects mutation
attempts even when the kernel rejected them. It is not a runtime sandbox.
"""

from __future__ import annotations

import argparse
import gzip
import importlib.util
import json
import re
import sys
from pathlib import Path


SPEC = importlib.util.spec_from_file_location(
    "glue_python_trace_parser", Path(__file__).with_name("check-linux-pbs-trace.py")
)
assert SPEC is not None and SPEC.loader is not None
PBS = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(PBS)
BASE = PBS.BASE
TraceError = PBS.TraceError
quoted, unsigned, pointer, result_number = PBS.quoted, PBS.unsigned, PBS.pointer, PBS.result_number

DIRECTORY = "/build-target/relocated Python bootstrap"
PROGRAM = DIRECTORY + "/glue-python-bootstrap-probe"
ARCHIVE = DIRECTORY + "/app.glue"
CWD = "AT_FDCWD</build-target/runtime-empty>"
MEMFD = "glue-python-libpython3.13.so.1.0"
MEMFD_PATH = "/memfd:" + MEMFD
LIBRARY_BYTES = 73_563_968
ARCHIVE_BYTES = 73_705_257
CACHE = "/etc/ld.so.cache"
OVERCOMMIT = "/proc/sys/vm/overcommit_memory"
LIBRARIES = {
    f"/{prefix}/aarch64-linux-gnu/{name}"
    for prefix in ("lib", "usr/lib")
    for name in ("libc.so.6", "libgcc_s.so.1", "libm.so.6", "libpthread.so.0", "librt.so.1", "libdl.so.2", "libutil.so.1")
}
MAX_TRACE_BYTES = PBS.MAX_TRACE_BYTES
MAX_LINE_CHARACTERS = PBS.MAX_LINE_CHARACTERS
MAX_RECORDS = PBS.MAX_RECORDS
MODES = ("success", "missing-encodings", "bad-bytecode", "app-error")
SUCCESS = b"PASS Python=3.13.16 encodings=frozen math=built-in ssl=built-in answer=42 openssl=OpenSSL 3.5.9 29 Sep 2026\n"
STARTUP_ERROR = b"""Python path configuration:
  PYTHONHOME = '/__glue_archive__/python'
  PYTHONPATH = (not set)
  program name = 'glue-python-bootstrap'
  isolated = 1
  environment = 0
  user site = 0
  safe_path = 1
  import site = 0
  is in build tree = 0
  stdlib dir = '/__glue_archive__/python/stdlib'
  sys.path[0] = (not set)
  sys._base_executable = '/__glue_archive__/launcher'
  sys.base_prefix = '/__glue_archive__/python'
  sys.base_exec_prefix = '/__glue_archive__/python'
  sys.platlibdir = 'lib'
  sys.executable = '/__glue_archive__/launcher'
  sys.prefix = '/__glue_archive__/python'
  sys.exec_prefix = '/__glue_archive__/python'
  sys.path = [
  ]
glue-python-bootstrap-probe: Failed to import encodings module
"""
APP_ERROR = b"glue-python-bootstrap-probe: intentional Python bootstrap app error\n"


def expected_output(mode: str) -> tuple[bytes, bytes]:
    if mode not in MODES:
        raise TraceError("unknown bootstrap fixture mode")
    return (
        SUCCESS if mode in {"success", "app-error"} else b"",
        b"" if mode == "success" else APP_ERROR if mode == "app-error" else STARTUP_ERROR,
    )


def descriptor(value: str) -> tuple[int, str | None, bool]:
    if value == "0</dev/null<char 1:3>>":
        return 0, "/dev/null", False
    return PBS.descriptor(value)


class Checker(PBS.Checker):
    def __init__(self, mode: str = "success", archive_bytes: int = ARCHIVE_BYTES) -> None:
        super().__init__(1)  # The inherited ordinary-runtime checks use no output size.
        self.mode = mode
        self.expected = expected_output(mode)
        self.output = [bytearray(), bytearray()]
        if type(archive_bytes) is not int or not LIBRARY_BYTES < archive_bytes <= 84 * 1024 * 1024:
            raise TraceError("archive size is outside the bounded fixture profile")
        self.archive_bytes = archive_bytes
        self.archive_opened = 0
        self.archive_read = 0
        self.archive_cursor = 0
        self.archive_ranges: list[tuple[int, int]] = []
        self.populated = 0
        self.seal_requested = False
        self.seal_verified = False
        self.image_mappings: set[tuple[int, int]] = set()
        self.overcommit_reads = 0
        self.virtual_queries = 0
        self.tid_queries = 0
        self.timezone_queries = 0

    def line(self, line: str) -> None:
        if self.completed:
            raise TraceError("record after completed process exit")
        exit_match = re.fullmatch(r"([1-9][0-9]{0,9})\s+\+\+\+ exited with ([01]) \+\+\+", line)
        if exit_match is not None:
            self.process(exit_match[1])
            if not self.exit_group or int(exit_match[2]) != (0 if self.mode == "success" else 1):
                raise TraceError("completion disagrees with expected fixture exit")
            self.completed = True
            return
        match = BASE.LINE.fullmatch(line)
        if match is None:
            raise TraceError("unparsed, abbreviated or incomplete trace record")
        self.process(match[1])
        self.call(match[2], BASE.split_arguments(match[3]), match[4])

    def inherited(self, argument: str) -> int:
        number, path, deleted = descriptor(argument)
        allowed = {0: "/dev/null", 1: f"/evidence/{self.mode}.stdout.txt", 2: f"/evidence/{self.mode}.stderr.txt"}
        if deleted or number not in allowed or path != allowed[number]:
            raise TraceError("inherited standard descriptor identity changed")
        return number

    def reader(self, argument: str) -> tuple[int, str]:
        number, path, deleted = descriptor(argument)
        if number in self.memfds:
            if path != MEMFD_PATH or not deleted:
                raise TraceError("created memfd annotation differs from its identity")
            return number, path
        return super().reader(argument)

    def call(self, name: str, args: list[str], result: str) -> None:
        value = result_number(result)
        if self.exit_group or (value is None and name != "exit_group"):
            raise TraceError("incomplete syscall or operation after exit_group")
        if name != "execve" and self.execs != 1:
            raise TraceError("trace must begin with its sole successful execve")
        if name == "execve":
            self.arity(name, args, (3,))
            command = [PROGRAM, "run", ARCHIVE] if self.mode == "success" else [PROGRAM, "run-negative", ARCHIVE, self.mode]
            if args[:2] != [json.dumps(PROGRAM), json.dumps(command)] or re.fullmatch(r"0x[0-9a-f]{1,16} /\* [0-9]{1,6} vars \*/", args[2]) is None:
                raise TraceError("execve differs from the exact relocated fixture command")
            self.execs += 1
            if self.execs != 1 or value != 0:
                raise TraceError("require exactly one successful execve")
        elif name == "openat":
            self.arity(name, args, (3,))
            path = quoted(args[1])
            if args[0] != CWD:
                raise TraceError("unexpected filesystem directory descriptor or working directory")
            flags = BASE.flags(args[2], {"O_RDONLY", "O_CLOEXEC"})
            if "O_RDONLY" not in flags:
                raise TraceError("all filesystem opens must be read-only")
            if path == "/usr/share/zoneinfo/UTC0":
                if flags != {"O_RDONLY", "O_CLOEXEC"} or result != "-1 ENOENT (No such file or directory)" or self.timezone_queries:
                    raise TraceError("only one absent POSIX-timezone lookup is admitted")
                self.timezone_queries += 1
                return
            alias = re.fullmatch(r"/proc/self/fd/([0-9]{1,10})", path)
            if alias is not None:
                if int(alias[1]) not in self.created or not self.seal_verified:
                    raise TraceError("libpython alias load precedes verified sealing")
                expected_target, expected_deleted = MEMFD_PATH, True
            else:
                allowed = LIBRARIES | {CACHE, ARCHIVE, OVERCOMMIT, "/proc/self/maps"}
                if path not in allowed:
                    raise TraceError("unapproved OS, Python-source or filesystem read path")
                expected_target = path.replace("/lib/", "/usr/lib/", 1) if path.startswith("/lib/") else path
                if path == "/proc/self/maps":
                    expected_target = f"/proc/{self.pid}/maps"
                expected_deleted = False
                if path not in {OVERCOMMIT, "/proc/self/maps"} and flags != {"O_RDONLY", "O_CLOEXEC"}:
                    raise TraceError("ordinary file opens require close-on-exec")
            number, target, deleted = descriptor(result)
            if value is None or value < 3 or number in self.readers or number in self.memfds or target != expected_target or deleted != expected_deleted:
                raise TraceError("open did not return a distinct approved annotated descriptor")
            if alias is not None:
                self.memfds[number] = MEMFD
            else:
                self.readers[number] = target
                if path == ARCHIVE:
                    self.archive_opened += 1
                    if self.archive_opened != 1:
                        raise TraceError("archive must be opened exactly once")
        elif name == "read":
            self.arity(name, args, (3,))
            _, path = self.reader(args[0])
            count = unsigned(args[2])
            if PBS.BUFFER.fullmatch(args[1]) is None or value is None or not 0 <= value <= count or count > 84 * 1024 * 1024:
                raise TraceError("read requires a successful bounded payload count")
            if path == ARCHIVE:
                if value:
                    self.archive_ranges.append((self.archive_cursor, self.archive_cursor + value))
                self.archive_cursor += value
                self.archive_read += value
                if self.archive_cursor > self.archive_bytes or self.archive_read > 3 * self.archive_bytes:
                    raise TraceError("archive read exceeds its retained size or pass bound")
            elif path == OVERCOMMIT:
                if args[1:] != ['"0\\n"', "32"] or value != 2 or self.overcommit_reads:
                    raise TraceError("overcommit query differs from the observed OS cell")
                self.overcommit_reads += 1
            elif path == MEMFD_PATH and not self.seal_verified:
                raise TraceError("loader memfd read precedes verified sealing")
        elif name == "lseek":
            self.arity(name, args, (3,))
            number, _, _ = descriptor(args[0])
            if number < 3:
                self.inherited(args[0])
                position = len(self.output[number - 1]) if number in {1, 2} else 0
                if args[1:] != ["0", "SEEK_CUR"] or value != position:
                    raise TraceError("standard-stream seek must only query its current position")
            else:
                _, path = self.reader(args[0])
                if path != ARCHIVE:
                    raise TraceError("only archive offsets and inherited stream queries are admitted")
                offset = unsigned(args[1])
                if args[2] == "SEEK_END" and offset == 0:
                    expected = self.archive_bytes
                elif args[2] == "SEEK_SET" and offset <= self.archive_bytes:
                    expected = offset
                else:
                    raise TraceError("unapproved archive seek")
                if value != expected:
                    raise TraceError("archive seek result disagrees with the requested offset")
                self.archive_cursor = expected
        elif name == "memfd_create":
            self.arity(name, args, (2,))
            flags = BASE.flags(args[1], {"MFD_CLOEXEC", "MFD_ALLOW_SEALING", "MFD_EXEC", "0x10"})
            if quoted(args[0]) != MEMFD or not {"MFD_CLOEXEC", "MFD_ALLOW_SEALING"} <= flags or len(flags & {"MFD_EXEC", "0x10"}) != 1:
                raise TraceError("require the one explicitly executable, sealable fixture memfd")
            number, path, deleted = descriptor(result)
            if self.created or value is None or value < 3 or number in self.readers or path != MEMFD_PATH or not deleted:
                raise TraceError("memfd creation must return one distinct annotated anonymous descriptor")
            self.created[number] = MEMFD
            self.memfds[number] = MEMFD
        elif name == "write":
            self.arity(name, args, (3,))
            number, _, _ = descriptor(args[0])
            count = unsigned(args[2])
            if count == 0 or value != count:
                raise TraceError("fixture writes must succeed with their full requested count")
            if number in self.created:
                self.reader(args[0])
                if self.seal_requested or self.seal_verified or PBS.BUFFER.fullmatch(args[1]) is None or count > LIBRARY_BYTES - self.populated:
                    raise TraceError("memfd mutation exceeds exact image bytes or follows sealing")
                self.populated += count
            else:
                number = self.inherited(args[0])
                if number == 0:
                    raise TraceError("stdin writes are forbidden")
                try:
                    payload = json.loads(args[1]).encode("ascii")
                except (ValueError, AttributeError, UnicodeError) as error:
                    raise TraceError("stdio data must be the complete controlled ASCII diagnostic") from error
                if len(payload) != count:
                    raise TraceError("diagnostic bytes disagree with the write count")
                stream = number - 1
                self.output[stream].extend(payload)
                if not self.expected[stream].startswith(self.output[stream]):
                    raise TraceError("stdout or stderr differs from the expected fixture diagnostic")
        elif name == "fcntl":
            self.arity(name, args, (2, 3))
            if args[1] == "F_GETFD":
                self.arity(name, args, (2,))
                self.inherited(args[0])
                self.succeeds(value)
            else:
                number, _ = self.reader(args[0])
                if number not in self.created:
                    raise TraceError("only the original created memfd may receive seal operations")
                if args[1] == "F_ADD_SEALS":
                    self.arity(name, args, (3,))
                    if self.seal_requested or self.populated != LIBRARY_BYTES or BASE.flags(args[2], BASE.SEALS) != BASE.SEALS:
                        raise TraceError("all exact image bytes must precede the one complete seal request")
                    self.succeeds(value)
                    self.seal_requested = True
                elif args[1] == "F_GET_SEALS":
                    self.arity(name, args, (2,))
                    if not self.seal_requested or self.seal_verified or value != 0xf:
                        raise TraceError("seals must be requested then successfully verified as 0xf")
                    self.seal_verified = True
                else:
                    raise TraceError("unapproved fcntl operation")
        elif name == "newfstatat":
            self.arity(name, args, (4,))
            _, path = self.reader(args[0])
            if args[1] != '""' or args[3] != "AT_EMPTY_PATH" or re.fullmatch(r"\{st_mode=S_IFREG\|[0-7]{4}, st_size=[0-9]{1,20}, \.\.\.\}", args[2]) is None:
                raise TraceError("metadata queries require a known open regular-file descriptor")
            if path == MEMFD_PATH and f"st_size={LIBRARY_BYTES}," not in args[2]:
                raise TraceError("libpython memfd metadata has the wrong size")
            self.succeeds(value)
        elif name == "fstat":
            self.arity(name, args, (2,))
            number = self.inherited(args[0])
            expected = "{st_mode=S_IFCHR|0666, st_rdev=makedev(0x1, 0x3), ...}" if number == 0 else "{st_mode=S_IFREG|0644, st_size=0, ...}"
            if args[1] != expected:
                raise TraceError("standard-stream metadata differs from the fixture")
            self.succeeds(value)
        elif name == "close":
            self.arity(name, args, (1,))
            number, _ = self.reader(args[0])
            self.succeeds(value)
            if number in self.created:
                raise TraceError("loaded stock image descriptor must remain pinned until process exit")
            if number in self.memfds:
                del self.memfds[number]
            else:
                del self.readers[number]
        elif name == "mmap":
            self.arity(name, args, (6,))
            flags = BASE.flags(args[3], {"MAP_PRIVATE", "MAP_ANONYMOUS", "MAP_FIXED", "MAP_DENYWRITE", "MAP_STACK"})
            if "MAP_ANONYMOUS" not in flags:
                _, path = self.reader(args[4])
                if path == MEMFD_PATH:
                    pointer(args[0])
                    count = unsigned(args[1])
                    offset = int(args[5], 16) if re.fullmatch(r"0x[0-9a-f]{1,16}", args[5]) else unsigned(args[5])
                    profile = {(20_423_824, 0): "PROT_READ|PROT_EXEC", (1_695_744, 0x115a000): "PROT_READ|PROT_WRITE"}
                    if not self.seal_verified or flags != {"MAP_PRIVATE", "MAP_FIXED", "MAP_DENYWRITE"} or args[2] != profile.get((count, offset)) or (count, offset) in self.image_mappings or value is None or value <= 0:
                        raise TraceError("stock image mapping must match a once-only sealed private segment")
                    self.image_mappings.add((count, offset))
                    return
                if path not in LIBRARIES | {CACHE}:
                    raise TraceError("only OS libraries/cache and the verified sealed stock image may map")
                pointer(args[0])
                if unsigned(args[1]) == 0 or value is None or value <= 0:
                    raise TraceError("OS file mapping must succeed with positive length")
                protection = BASE.flags(args[2], {"PROT_NONE", "PROT_READ", "PROT_WRITE", "PROT_EXEC"})
                if "MAP_PRIVATE" not in flags or "MAP_STACK" in flags or {"PROT_WRITE", "PROT_EXEC"} <= protection:
                    raise TraceError("OS file mappings must be private and never writable executable")
                if path == CACHE and (protection != {"PROT_READ"} or flags != {"MAP_PRIVATE"}):
                    raise TraceError("startup cache mapping must be private and read-only")
                if re.fullmatch(r"(?:[0-9]{1,20}|0x[0-9a-f]{1,16})", args[5]) is None:
                    raise TraceError("unparsed OS file mapping offset")
                return
            super().call(name, args, result)
        elif name == "ppoll":
            expected = "[{fd=0</dev/null<char 1:3>>, events=0}, " + f"{{fd=1</evidence/{self.mode}.stdout.txt>, events=0}}, {{fd=2</evidence/{self.mode}.stderr.txt>, events=0}}]"
            if args != [expected, "3", "{tv_sec=0, tv_nsec=0}", "NULL", "0"] or result != "0 (Timeout)":
                raise TraceError("unapproved inherited-stream readiness query")
        elif name == "faccessat":
            if args != [CWD, '"/etc/ld.so.preload"', "R_OK"] or result != "-1 ENOENT (No such file or directory)":
                raise TraceError("only the observed absent preload read query is admitted")
        elif name == "readlinkat":
            self.arity(name, args, (4,))
            pointer(args[2])
            if args[:2] != [CWD, '"/__glue_archive__/launcher"'] or args[3] != "4096" or result != "-1 ENOENT (No such file or directory)" or self.virtual_queries:
                raise TraceError("only the once-only absent virtual executable lookup is admitted")
            self.virtual_queries += 1
        elif name == "gettid":
            self.arity(name, args, (0,))
            self.succeeds(value, int(self.pid))
            self.tid_queries += 1
            if self.tid_queries != 1:
                raise TraceError("unexpected additional thread query")
        elif name == "ioctl":
            self.arity(name, args, (3,))
            self.inherited(args[0])
            pointer(args[2])
            if args[1] != "TCGETS" or result != "-1 ENOTTY (Inappropriate ioctl for device)":
                raise TraceError("only an observed failed inherited-stream terminal query is admitted")
        elif name == "exit_group":
            if args != ["0" if self.mode == "success" else "1"] or result != "?":
                raise TraceError("require the expected nonreturning fixture exit")
            self.exit_group = True
        else:
            super().call(name, args, result)

    def finish(self) -> None:
        if self.execs != 1 or not self.exit_group or not self.completed:
            raise TraceError("incomplete trace: require one exec and completed expected exit")
        if self.archive_opened != 1 or self.archive_read != self.archive_bytes + 20:
            raise TraceError("require all observed archive reads, including its checked ZIP directory")
        covered = 0
        for start, end in sorted(self.archive_ranges):
            if start > covered:
                raise TraceError("archive read coverage contains an unread byte range")
            covered = max(covered, end)
        if covered != self.archive_bytes:
            raise TraceError("archive reads do not cover every retained byte")
        if len(self.created) != 1 or self.populated != LIBRARY_BYTES or not self.seal_verified:
            raise TraceError("require exactly one fully populated, verified sealed stock image")
        if self.image_mappings != {(20_423_824, 0), (1_695_744, 0x115a000)} or self.readers or set(self.memfds) != set(self.created):
            raise TraceError("require both private stock segments, closed read descriptors and one pinned image")
        if self.virtual_queries != 1 or self.overcommit_reads != 1 or self.tid_queries != 1 or self.timezone_queries != 1:
            raise TraceError("required controlled stock startup observations are missing")
        if tuple(bytes(data) for data in self.output) != self.expected:
            raise TraceError("trace diagnostics differ from complete expected stdout/stderr")


def check_lines(lines, mode: str = "success", archive_bytes: int = ARCHIVE_BYTES) -> None:
    checker = Checker(mode, archive_bytes)
    total = 0
    for number, line in enumerate(lines, start=1):
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


def check_trace(text: str, mode: str = "success", archive_bytes: int = ARCHIVE_BYTES) -> None:
    check_lines(text.splitlines(keepends=True), mode, archive_bytes)


def check_file(path: Path, mode: str = "success", archive_bytes: int = ARCHIVE_BYTES) -> None:
    if path.stat().st_size > MAX_TRACE_BYTES:
        raise TraceError("trace input exceeds the compressed/raw byte bound")
    opener = gzip.open if path.suffix == ".gz" else open
    with opener(path, "rb") as stream:
        def lines():
            while True:
                raw = stream.readline(MAX_LINE_CHARACTERS + 2)
                if not raw:
                    return
                if len(raw) > MAX_LINE_CHARACTERS + 1:
                    raise TraceError("trace exceeds the line bound")
                yield raw.decode("utf-8", errors="strict")
        check_lines(lines(), mode, archive_bytes)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("trace", type=Path)
    parser.add_argument("--mode", choices=MODES, default="success")
    parser.add_argument("--stdout-file", type=Path, required=True)
    parser.add_argument("--stderr-file", type=Path, required=True)
    archive = parser.add_mutually_exclusive_group()
    archive.add_argument("--archive-file", type=Path, help="derive the retained archive size; its hash is verified separately")
    archive.add_argument("--archive-bytes", type=int, help="replay with the bounded archive size from retained artifact metadata")
    args = parser.parse_args()
    try:
        expected = expected_output(args.mode)
        for path, diagnostic in zip((args.stdout_file, args.stderr_file), expected):
            with path.open("rb") as stream:
                if stream.read(len(diagnostic) + 1) != diagnostic:
                    raise TraceError("retained stdout/stderr differs from the controlled diagnostic")
        size = args.archive_file.stat().st_size if args.archive_file else args.archive_bytes if args.archive_bytes is not None else ARCHIVE_BYTES
        check_file(args.trace, args.mode, size)
    except (OSError, UnicodeError, EOFError, TraceError) as error:
        print(f"stock Python bootstrap trace rejected: {error}", file=sys.stderr)
        return 1
    print("Trace checks passed: complete archive reads, one sealed private stock image, exact diagnostics and expected exit, no filesystem mutation, source fallback or extra process")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
