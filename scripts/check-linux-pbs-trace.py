#!/usr/bin/env python3
"""Check complete syscall evidence for the pinned Linux PBS inspection.

This checks one build-time fixture, not a sandbox or Python execution. Only the
three declared input files and observed Rust/OS startup reads are admitted.
Attempted mutations fail even when the kernel rejected them. Stdout payloads
are abbreviated by strace; their returned byte total is checked against the
separately retained report, whose contents and hash require separate validation.
Raw UTF-8 traces and gzip-compressed copies are both read with strict bounds.
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
    "glue_pbs_trace_parser", Path(__file__).with_name("check-linux-memfd-trace.py")
)
assert SPEC is not None and SPEC.loader is not None
BASE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(BASE)
TraceError = BASE.TraceError

PROGRAM = "/build-target/release/glue-pbs-inspect"
PINS = "/workspace/fixtures/python-pbs/pins.json"
FULL = "/workspace/target/pbs-inspection/cpython-3.13.16+20261009-aarch64-unknown-linux-gnu-pgo+lto-full.tar.zst"
INSTALL = "/workspace/target/pbs-inspection/cpython-3.13.16+20261009-aarch64-unknown-linux-gnu-install_only.tar.gz"
INPUTS = {PINS, FULL, INSTALL}
ARTIFACT_SIZES = {FULL: 95_632_430, INSTALL: 57_626_877}
STDOUT = "/evidence/linux/inspection.json"
STDERR = "/evidence/linux/inspection.stderr.txt"
CACHE = "/etc/ld.so.cache"
LIBRARIES = {
    f"/{prefix}/aarch64-linux-gnu/{name}"
    for prefix in ("lib", "usr/lib")
    for name in ("libc.so.6", "libgcc_s.so.1")
}
MAX_TRACE_BYTES = 32 * 1024 * 1024
MAX_LINE_CHARACTERS = 8192
MAX_RECORDS = 100_000
MAX_STDOUT_BYTES = 64 * 1024 * 1024
BUFFER = re.compile(r'^"(?:[^"\\\n]|\\.)*"(?:\.\.\.)?$')
ADDRESS = re.compile(r"(?:NULL|0x[0-9a-f]{1,16})")


def quoted(value: str) -> str:
    try:
        decoded = json.loads(value)
    except (ValueError, UnicodeError) as error:
        raise TraceError("unparsed or abbreviated quoted path") from error
    if not isinstance(decoded, str) or any(ord(char) < 32 for char in decoded):
        raise TraceError("expected a complete quoted path without controls")
    return decoded


def unsigned(value: str) -> int:
    if re.fullmatch(r"[0-9]{1,20}", value) is None:
        raise TraceError("expected a bounded unsigned decimal number")
    number = int(value)
    if number > (1 << 64) - 1:
        raise TraceError("unsigned number exceeds u64")
    return number


def pointer(value: str) -> None:
    if ADDRESS.fullmatch(value) is None:
        raise TraceError("unparsed address")


def descriptor(value: str) -> tuple[int, str | None, bool]:
    token = value.split("<", 1)[0]
    if re.fullmatch(r"-?[0-9]{1,10}", token) is None:
        raise TraceError("unparsed or oversized file descriptor")
    result = BASE.descriptor(value)
    if not -(1 << 31) <= result[0] < (1 << 31):
        raise TraceError("file descriptor exceeds the signed int range")
    return result


def result_number(value: str) -> int | None:
    token = value.split(" ", 1)[0].split("<", 1)[0]
    if token != "?" and re.fullmatch(r"-?(?:0x[0-9a-fA-F]{1,16}|[0-9]{1,20})", token) is None:
        raise TraceError("unparsed or oversized syscall result")
    try:
        return BASE.return_value(value)
    except ValueError as error:
        raise TraceError("invalid syscall result") from error


class Checker(BASE.Checker):
    def __init__(self, stdout_bytes: int) -> None:
        super().__init__()
        if type(stdout_bytes) is not int or not 0 < stdout_bytes <= MAX_STDOUT_BYTES:
            raise TraceError("expected report size must be positive and at most 64 MiB")
        self.expected_stdout = stdout_bytes
        self.stdout_bytes = 0
        self.readers: dict[int, str] = {}
        self.opens = {path: 0 for path in INPUTS}
        self.reads = {path: 0 for path in INPUTS}
        self.rewinds = {path: 0 for path in ARTIFACT_SIZES}

    def process(self, pid: str | None) -> None:
        if pid is None or re.fullmatch(r"[1-9][0-9]{0,9}", pid) is None:
            raise TraceError("require a bounded positive PID on every strace -f record")
        super().process(pid)

    def readable(self, path: str | None) -> bool:
        return path in INPUTS | LIBRARIES | {CACHE, "/proc/self/maps"} or (
            self.pid is not None and path == f"/proc/{self.pid}/maps"
        )

    def reader(self, argument: str) -> tuple[int, str]:
        number, path, deleted = descriptor(argument)
        if deleted or number < 3 or self.readers.get(number) != path or path is None:
            raise TraceError("unknown, closed, deleted or unannotated read descriptor")
        return number, path

    @staticmethod
    def succeeds(value: int | None, expected: int = 0) -> None:
        if value != expected:
            raise TraceError("fixture operation must return its expected successful result")

    def call(self, name: str, args: list[str], result: str) -> None:
        value = result_number(result)
        if value is None and name != "exit_group":
            raise TraceError("incomplete non-exit syscall result")
        if self.exit_group:
            raise TraceError("syscall after exit_group")
        if name != "execve" and self.execs != 1:
            raise TraceError("trace must begin with its sole successful execve")

        if name == "execve":
            self.arity(name, args, (3,))
            expected = "[" + ", ".join(json.dumps(path) for path in [PROGRAM, PINS, FULL, INSTALL]) + "]"
            if args[0] != json.dumps(PROGRAM) or args[1] != expected or re.fullmatch(r"0x[0-9a-f]{1,16} /\* [0-9]{1,6} vars \*/", args[2]) is None:
                raise TraceError("execve must name the exact pinned inspection command")
            self.execs += 1
            if self.execs != 1 or value != 0:
                raise TraceError("require exactly one successful execve")
        elif name == "openat":
            self.arity(name, args, (3,))
            path = quoted(args[1])
            if args[0] != "AT_FDCWD</workspace>" or not self.readable(path):
                raise TraceError("unapproved filesystem read path or directory descriptor")
            if BASE.flags(args[2], {"O_RDONLY", "O_CLOEXEC"}) != {"O_RDONLY", "O_CLOEXEC"}:
                raise TraceError("all opens must be explicitly read-only and close-on-exec")
            number, target, deleted = descriptor(result)
            allowed_target = path
            if path in LIBRARIES:
                allowed_target = path.replace("/lib/", "/usr/lib/", 1) if path.startswith("/lib/") else path
            elif path == "/proc/self/maps":
                allowed_target = f"/proc/{self.pid}/maps"
            if value is None or value < 3 or number in self.readers or deleted or target != allowed_target:
                raise TraceError("open did not return a distinct approved annotated descriptor")
            self.readers[number] = target
            if path in INPUTS:
                self.opens[path] += 1
                if self.opens[path] != 1:
                    raise TraceError("each declared input must be opened exactly once")
        elif name == "read":
            self.arity(name, args, (3,))
            _, path = self.reader(args[0])
            count = unsigned(args[2])
            if BUFFER.fullmatch(args[1]) is None or value is None or not 0 <= value <= count:
                raise TraceError("read must contain a parsed buffer and successful bounded count")
            if path in INPUTS:
                self.reads[path] += value
                limit = 2 * ARTIFACT_SIZES[path] if path in ARTIFACT_SIZES else 16 * 1024 + 1
                if self.reads[path] > limit:
                    raise TraceError("declared input read total exceeds the fixture bound")
        elif name == "lseek":
            self.arity(name, args, (3,))
            _, path = self.reader(args[0])
            if path not in ARTIFACT_SIZES or args[1:] != ["0", "SEEK_SET"]:
                raise TraceError("only exact artifact rewinds are admitted")
            self.succeeds(value)
            self.rewinds[path] += 1
            if self.rewinds[path] > 2:
                raise TraceError("unexpected additional artifact rewind")
        elif name == "newfstatat":
            self.arity(name, args, (4,))
            self.reader(args[0])
            if args[1] != '""' or args[3] != "AT_EMPTY_PATH" or not args[2].startswith("{st_mode=S_IFREG|") or not args[2].endswith("}"):
                raise TraceError("metadata queries require an approved open regular-file descriptor")
            self.succeeds(value)
        elif name == "faccessat":
            self.arity(name, args, (3,))
            if args != ["AT_FDCWD</workspace>", '"/etc/ld.so.preload"', "R_OK"] or result != "-1 ENOENT (No such file or directory)":
                raise TraceError("only the observed absent preload read query is admitted")
        elif name == "close":
            self.arity(name, args, (1,))
            number, _ = self.reader(args[0])
            self.succeeds(value)
            del self.readers[number]
        elif name == "write":
            self.arity(name, args, (3,))
            if descriptor(args[0]) != (1, STDOUT, False):
                raise TraceError("writes require the unchanged inherited evidence stdout descriptor")
            count = unsigned(args[2])
            if BUFFER.fullmatch(args[1]) is None or count == 0 or value != count:
                raise TraceError("stdout write must succeed with its complete requested byte count")
            self.stdout_bytes += value
            if self.stdout_bytes > self.expected_stdout:
                raise TraceError("stdout write total exceeds the retained report size")
        elif name == "mmap":
            self.arity(name, args, (6,))
            pointer(args[0])
            if unsigned(args[1]) == 0:
                raise TraceError("mapping length must be positive")
            protection = BASE.flags(args[2], {"PROT_NONE", "PROT_READ", "PROT_WRITE", "PROT_EXEC"})
            actual = BASE.flags(args[3], {"MAP_PRIVATE", "MAP_ANONYMOUS", "MAP_FIXED", "MAP_DENYWRITE", "MAP_STACK"})
            if "MAP_PRIVATE" not in actual or {"PROT_WRITE", "PROT_EXEC"} <= protection:
                raise TraceError("shared or writable executable mappings are forbidden")
            if "MAP_ANONYMOUS" in actual:
                if args[4] != "-1" or args[5] != "0" or "PROT_EXEC" in protection or "MAP_DENYWRITE" in actual:
                    raise TraceError("anonymous mappings must be private non-executable memory")
            else:
                _, path = self.reader(args[4])
                if path not in LIBRARIES | {CACHE} or "MAP_STACK" in actual:
                    raise TraceError("file mappings require observed OS startup libraries or cache")
                if path == CACHE and (protection != {"PROT_READ"} or actual != {"MAP_PRIVATE"}):
                    raise TraceError("startup cache mapping must be private and read-only")
                if re.fullmatch(r"(?:[0-9]{1,20}|0x[0-9a-f]{1,16})", args[5]) is None:
                    raise TraceError("unparsed file mapping offset")
            if value is None or value <= 0:
                raise TraceError("fixture mappings must succeed")
        elif name == "mprotect":
            self.arity(name, args, (3,))
            pointer(args[0])
            if unsigned(args[1]) == 0:
                raise TraceError("protection length must be positive")
            BASE.flags(args[2], {"PROT_NONE", "PROT_READ", "PROT_WRITE"})
            self.succeeds(value)
        elif name == "munmap":
            self.arity(name, args, (2,))
            pointer(args[0])
            if unsigned(args[1]) == 0:
                raise TraceError("unmap length must be positive")
            self.succeeds(value)
        elif name == "brk":
            self.arity(name, args, (1,))
            pointer(args[0])
            if value is None or value <= 0:
                raise TraceError("fixture heap query or growth must succeed")
        elif name == "set_tid_address":
            self.arity(name, args, (1,))
            pointer(args[0])
            self.succeeds(value, int(self.pid))
        elif name == "set_robust_list":
            self.arity(name, args, (2,))
            pointer(args[0])
            if args[1] != "24":
                raise TraceError("unexpected robust-list size")
            self.succeeds(value)
        elif name == "rseq":
            self.arity(name, args, (4,))
            pointer(args[0])
            if args[1:] != ["0x20", "0", "0xd428bc00"]:
                raise TraceError("unapproved rseq registration")
            self.succeeds(value)
        elif name == "prlimit64":
            self.arity(name, args, (4,))
            if args[0] not in {"0", self.pid} or args[1] != "RLIMIT_STACK" or args[2] != "NULL" or not args[3].startswith("{rlim_cur="):
                raise TraceError("only this process's stack-limit query is admitted")
            self.succeeds(value)
        elif name == "sched_getaffinity":
            self.arity(name, args, (3,))
            if args[0] not in {"0", self.pid} or unsigned(args[1]) > 4096 or not args[2].startswith("[") or not args[2].endswith("]") or value is None or value < 0:
                raise TraceError("unapproved self affinity query")
        elif name == "getrandom":
            self.arity(name, args, (3,))
            count = unsigned(args[1])
            if BUFFER.fullmatch(args[0]) is None or not 0 < count <= 256 or args[2] != "GRND_NONBLOCK" or value != count:
                raise TraceError("unapproved runtime random query")
        elif name == "ppoll":
            expected = "[{fd=0</dev/null<char 1:3>>, events=0}, " + f"{{fd=1<{STDOUT}>, events=0}}, {{fd=2<{STDERR}>, events=0}}]"
            if args != [expected, "3", "{tv_sec=0, tv_nsec=0}", "NULL", "0"] or result != "0 (Timeout)":
                raise TraceError("unapproved inherited-descriptor readiness query")
        elif name == "rt_sigaction":
            self.arity(name, args, (4,))
            if args[0] not in {"SIGPIPE", "SIGSEGV", "SIGBUS"} or args[3] != "8" or any(arg != "NULL" and not (arg.startswith("{sa_handler=") and arg.endswith("}")) for arg in args[1:3]):
                raise TraceError("unapproved runtime signal action")
            self.succeeds(value)
        elif name == "sigaltstack":
            self.arity(name, args, (2,))
            if any(arg != "NULL" and not (arg.startswith("{ss_sp=") and arg.endswith("}")) for arg in args):
                raise TraceError("unapproved runtime alternate-stack operation")
            self.succeeds(value)
        elif name == "exit_group":
            self.arity(name, args, (1,))
            if args != ["0"] or result != "?":
                raise TraceError("require a nonreturning successful exit_group(0)")
            self.exit_group = True
        else:
            raise TraceError(f"unapproved syscall {name}")

    def finish(self) -> None:
        if self.execs != 1 or not self.exit_group or not self.completed:
            raise TraceError("trace is incomplete: require one exec and completed zero exit")
        if any(count != 1 for count in self.opens.values()) or self.reads[PINS] == 0:
            raise TraceError("require all three declared inputs opened and read")
        if any(self.reads[path] != 2 * size or self.rewinds[path] != 2 for path, size in ARTIFACT_SIZES.items()):
            raise TraceError("require both complete compressed-input verification and decoding passes")
        if self.stdout_bytes != self.expected_stdout:
            raise TraceError("stdout returned-byte total differs from the retained report size")


def check_lines(lines, stdout_bytes: int) -> None:
    checker = Checker(stdout_bytes)
    total = 0
    for number, line in enumerate(lines, start=1):
        if number > MAX_RECORDS:
            raise TraceError("trace exceeds the record bound")
        try:
            total += len(line.encode("utf-8"))
        except UnicodeError as error:
            raise TraceError("trace is not strict UTF-8") from error
        if total > MAX_TRACE_BYTES or len(line) > MAX_LINE_CHARACTERS + 1:
            raise TraceError("trace exceeds the byte or line bound")
        if not line.endswith("\n") or "\r" in line:
            raise TraceError("trace contains a truncated or noncanonical line")
        try:
            checker.line(line[:-1])
        except TraceError as error:
            raise TraceError(f"line {number}: {error}") from error
    checker.finish()


def check_trace(text: str, stdout_bytes: int) -> None:
    check_lines(text.splitlines(keepends=True), stdout_bytes)


def check_file(path: Path, stdout_bytes: int) -> None:
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
                try:
                    yield raw.decode("utf-8", errors="strict")
                except UnicodeError as error:
                    raise TraceError("trace is not strict UTF-8") from error
        check_lines(lines(), stdout_bytes)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("trace", type=Path)
    size = parser.add_mutually_exclusive_group(required=True)
    size.add_argument("--stdout-file", type=Path, help="derive expected byte count from the retained report")
    size.add_argument("--stdout-bytes", type=int, help="explicit retained report byte count")
    args = parser.parse_args()
    try:
        expected = args.stdout_file.stat().st_size if args.stdout_file is not None else args.stdout_bytes
        check_file(args.trace, expected)
    except (OSError, UnicodeError, EOFError, TraceError) as error:
        print(f"PBS inspection trace rejected: {error}", file=sys.stderr)
        return 1
    print("Trace checks passed: complete pinned input reads, exact stdout byte total, no payload mappings, mutation attempts or extra processes, completed zero exit")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
