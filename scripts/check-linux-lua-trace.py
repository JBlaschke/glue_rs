#!/usr/bin/env python3
"""Check the complete relocated, source-only linked Lua fixture trace.

This is evidence checking for one Linux/aarch64 fixture, not a syscall sandbox.
Unknown/incomplete records and attempted mutations fail, including unsuccessful
attempts. Only the exact fixture stdout is admitted. Filesystem reads are limited
to the relocated archive and the pinned image's observed OS/Rust startup files.
No memfd, shared mapping, native payload mapping, or other process is admitted.
"""

from __future__ import annotations

import argparse
import importlib.util
import json
import sys
from pathlib import Path


SPEC = importlib.util.spec_from_file_location(
    "glue_memfd_trace_parser", Path(__file__).with_name("check-linux-memfd-trace.py")
)
assert SPEC is not None and SPEC.loader is not None
BASE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(BASE)
TraceError = BASE.TraceError

PROGRAM = "/build-target/debug/glue"
ARCHIVE = "/build-target/relocated Lua fixture/app.glue"
STDOUT = "/evidence/lua.stdout.txt"
STDERR = "/evidence/lua.stderr.txt"
SYSTEM_LIBRARIES = {
    f"/{prefix}/aarch64-linux-gnu/{name}"
    for prefix in ("lib", "usr/lib")
    for name in ("libc.so.6", "libm.so.6", "libgcc_s.so.1", "ld-linux-aarch64.so.1")
} | {"/lib/ld-linux-aarch64.so.1"}
STARTUP_FILES = {"/etc/ld.so.cache", "/etc/ld.so.preload", "/proc/self/maps"}


def expected_stdout(version: str = "5.4") -> str:
    if version not in {"5.4", "5.5"}:
        raise TraceError("unsupported fixture Lua version")
    return f"Lua {version} answer=42 asset=Hello from archived resources!\n"


def quoted(value: str) -> str:
    try:
        decoded = json.loads(value)
    except (ValueError, UnicodeError) as error:
        raise TraceError(f"unparsed or abbreviated quoted string {value!r}") from error
    if not isinstance(decoded, str):
        raise TraceError("expected a quoted string")
    return decoded


def descriptor(value: str) -> tuple[int, str | None, bool]:
    if value == "0</dev/null<char 1:3>>":
        return 0, "/dev/null", False
    return BASE.descriptor(value)


class Checker(BASE.Checker):
    def __init__(self, version: str = "5.4") -> None:
        super().__init__()
        self.expected = expected_stdout(version)
        self.stdout = ""
        self.readers: dict[int, str] = {}
        self.archive_opens = 0
        self.archive_bytes_read = 0

    def allowed_read(self, path: str | None) -> bool:
        return path in SYSTEM_LIBRARIES | STARTUP_FILES | {ARCHIVE} or (
            self.pid is not None and path == f"/proc/{self.pid}/maps"
        )

    def known_descriptor(self, argument: str, standard: bool = False) -> tuple[int, str]:
        number, path, deleted = descriptor(argument)
        expected = {0: "/dev/null", 1: STDOUT, 2: STDERR}.get(number) if standard else None
        expected = self.readers.get(number, expected)
        if deleted or path is None or expected is None or path != expected:
            raise TraceError(f"unapproved or unannotated descriptor {argument}")
        return number, path

    def call(self, name: str, args: list[str], result: str) -> None:
        value = BASE.return_value(result)
        if value is None and name != "exit_group":
            raise TraceError("non-exit syscall has an incomplete result")
        if self.exit_group:
            raise TraceError("syscall after exit_group")
        if name != "execve" and self.execs != 1:
            raise TraceError("trace must begin with its sole successful execve")
        if name == "execve":
            self.arity(name, args, (3,))
            argv = f'[{json.dumps(PROGRAM)}, "run", {json.dumps(ARCHIVE)}]'
            if args[0] != json.dumps(PROGRAM) or args[1] != argv:
                raise TraceError("execve is not the exact relocated glue run command")
        elif name in {"open", "openat"}:
            self.arity(name, args, (2, 3) if name == "open" else (3, 4))
            index = 0 if name == "open" else 1
            path = quoted(args[index])
            if not self.allowed_read(path):
                raise TraceError(f"unapproved filesystem read path {path!r}")
            actual = BASE.flags(args[index + 1], BASE.READ_ONLY_OPEN_FLAGS)
            if "O_RDONLY" not in actual and "O_PATH" not in actual:
                raise TraceError("open is not explicitly read-only")
            if value is not None and value >= 0:
                number, target, deleted = descriptor(result)
                if number < 3 or deleted or not self.allowed_read(target):
                    raise TraceError("open returned an unapproved file descriptor")
                self.readers[number] = target
                if path == ARCHIVE:
                    if target != ARCHIVE:
                        raise TraceError("archive open resolved to another file")
                    self.archive_opens += 1
            return
        elif name in {"read", "readv", "pread64", "preadv", "lseek", "fstat", "fstatfs", "getdents64"}:
            self.arity(name, args, BASE.READ_ONLY_CALLS[name])
            _, path = self.known_descriptor(args[0], standard=name in {"fstat", "fstatfs"})
            if path == ARCHIVE and name in {"read", "readv", "pread64", "preadv"} and value is not None and value > 0:
                self.archive_bytes_read += value
            return
        elif name in BASE.READ_ONLY_CALLS:
            self.arity(name, args, BASE.READ_ONLY_CALLS[name])
            if name in {"newfstatat", "statx"}:
                path = quoted(args[1])
                if path == "":
                    self.known_descriptor(args[0], standard=True)
                elif not self.allowed_read(path):
                    raise TraceError("unapproved filesystem metadata path")
            elif name in {"readlinkat", "faccessat", "faccessat2"}:
                if not self.allowed_read(quoted(args[1])):
                    raise TraceError("unapproved filesystem query path")
            elif name == "getcwd":
                pass
            elif not self.allowed_read(quoted(args[0])):
                raise TraceError("unapproved filesystem query path")
            return
        elif name == "close":
            self.arity(name, args, (1,))
            number, _ = self.known_descriptor(args[0], standard=True)
            if value == 0:
                self.readers.pop(number, None)
            return
        elif name == "write":
            self.arity(name, args, (3,))
            if descriptor(args[0]) != (1, STDOUT, False):
                raise TraceError("writes may only target the exact evidence stdout descriptor")
            data = quoted(args[1])
            try:
                count = len(data.encode("ascii"))
            except UnicodeError as error:
                raise TraceError("stdout contains unexpected non-ASCII bytes") from error
            if count == 0 or args[2] != str(count) or result != str(count):
                raise TraceError("stdout write is incomplete or has inconsistent lengths")
            self.stdout += data
            if not self.expected.startswith(self.stdout):
                raise TraceError("stdout is not the exact expected Lua fixture output")
            return
        elif name == "fcntl":
            self.arity(name, args, (2,))
            self.known_descriptor(args[0], standard=True)
            if args[1] not in {"F_GETFD", "F_GETFL"}:
                raise TraceError("only descriptor flag queries are allowed")
            return
        elif name == "ioctl":
            self.arity(name, args, (3,))
            number, _ = self.known_descriptor(args[0], standard=True)
            if number not in {0, 1, 2} or args[1] not in {"TCGETS", "TIOCGWINSZ"}:
                raise TraceError("unapproved terminal query")
            return
        elif name == "ppoll":
            expected = "[{fd=0</dev/null<char 1:3>>, events=0}, " + f"{{fd=1<{STDOUT}>, events=0}}, {{fd=2<{STDERR}>, events=0}}]"
            if args != [expected, "3", "{tv_sec=0, tv_nsec=0}", "NULL", "0"]:
                raise TraceError("unapproved ppoll readiness query")
            return
        elif name == "mmap":
            self.arity(name, args, (6,))
            BASE.flags(args[2], {"PROT_NONE", "PROT_READ", "PROT_WRITE", "PROT_EXEC"})
            actual = BASE.flags(args[3], {"MAP_PRIVATE", "MAP_ANONYMOUS", "MAP_FIXED", "MAP_DENYWRITE", "MAP_STACK", "MAP_NORESERVE", "MAP_FIXED_NOREPLACE"})
            if "MAP_PRIVATE" not in actual:
                raise TraceError("only private mappings are allowed")
            if "MAP_ANONYMOUS" in actual:
                if args[4] != "-1" or "PROT_EXEC" in args[2].split("|"):
                    raise TraceError("anonymous mapping must have no file descriptor or executable protection")
            else:
                _, path = self.known_descriptor(args[4])
                if path not in SYSTEM_LIBRARIES | {"/etc/ld.so.cache"}:
                    raise TraceError("file mappings are limited to OS startup libraries/cache")
            return
        elif name == "mprotect":
            self.arity(name, args, (3,))
            BASE.flags(args[2], {"PROT_NONE", "PROT_READ", "PROT_WRITE"})
        elif name == "memfd_create":
            raise TraceError("memfd creation is outside this source-only fixture")
        super().call(name, args, result)

    def finish(self) -> None:
        if self.execs != 1 or not self.exit_group or not self.completed:
            raise TraceError("trace is incomplete: require one execve and a completed zero exit")
        if self.archive_opens < 1 or self.archive_bytes_read < 64:
            raise TraceError("require a successful relocated archive open and archive reads")
        if self.stdout != self.expected:
            raise TraceError("require the exact complete Lua fixture stdout")


def check_trace(text: str, version: str = "5.4") -> None:
    checker = Checker(version)
    for number, line in enumerate(text.splitlines(), start=1):
        try:
            checker.line(line)
        except TraceError as error:
            raise TraceError(f"line {number}: {error}: {line}") from error
    checker.finish()


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("trace", type=Path)
    parser.add_argument("--lua-version", choices=("5.4", "5.5"), default="5.4")
    args = parser.parse_args()
    try:
        check_trace(args.trace.read_text(encoding="utf-8"), args.lua_version)
    except (OSError, UnicodeError, TraceError) as error:
        print(f"Lua trace rejected: {error}", file=sys.stderr)
        return 1
    print(f"Trace checks passed: Lua {args.lua_version}, exact stdout, relocated archive reads, no payload/file mutations, memfds or shared mappings, completed zero exit")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
