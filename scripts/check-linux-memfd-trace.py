#!/usr/bin/env python3
"""Check one complete `strace -f -yy -s 256 -e trace=all` memfd probe.

This is a narrow fixture policy, not a general syscall sandbox. Unrecognized
operations, incomplete records, and attempted mutations fail even if the kernel
rejected them. Writes may target the two created fixture memfds. The annotated
evidence stdout descriptor may receive its one exact success diagnostic. Stderr
writes are outside this successful fixture's policy.
"""

from __future__ import annotations

import argparse
import re
import sys
from pathlib import Path


class TraceError(ValueError):
    """A trace is incomplete or outside the fixture's allowed operations."""


MEMFD_NAMES = {"glue-probe-dependency", "glue-probe-module"}
SINKS = {1: "/evidence/probe.stdout.txt", 2: "/evidence/probe.stderr.txt"}
SUCCESS_MESSAGES = {
    machine: (
        f"PASS answer=42 data=7 constructors=1 machine={machine} "
        "dependency_seals=0xf module_seals=0xf mechanism=sealed-memfd+/proc/self/fd "
        "runtime=unacquired-fixture-scaffold\n"
    )
    for machine in ("aarch64", "x86_64")
}
READ_ONLY_OPEN_FLAGS = {
    "O_RDONLY", "O_CLOEXEC", "O_NOFOLLOW", "O_DIRECTORY", "O_NONBLOCK",
    "O_LARGEFILE", "O_NOCTTY", "O_PATH",
}
SEALS = {"F_SEAL_SEAL", "F_SEAL_SHRINK", "F_SEAL_GROW", "F_SEAL_WRITE"}
READ_ONLY_CALLS = {
    "read": (3,), "readv": (3,), "pread64": (4,), "preadv": (4,),
    "lseek": (3,), "stat": (2,), "lstat": (2,), "fstat": (2,),
    "newfstatat": (4,), "statx": (5,), "statfs": (2,), "fstatfs": (2,),
    "access": (2,), "faccessat": (3,), "faccessat2": (4,),
    "readlink": (3,), "readlinkat": (4,), "getdents64": (3,), "getcwd": (2,),
}
SELF_CALLS = {
    "brk": (1,), "mprotect": (3,), "munmap": (2,), "mremap": (4, 5),
    "set_tid_address": (1,), "set_robust_list": (2,), "rseq": (4,),
    "getpid": (0,), "gettid": (0,), "getuid": (0,), "geteuid": (0,),
    "getgid": (0,), "getegid": (0,), "uname": (1,),
    "clock_gettime": (2,), "clock_getres": (2,), "gettimeofday": (2,),
    "rt_sigaction": (4,), "rt_sigprocmask": (4,), "sigaltstack": (2,),
    "getrlimit": (2,),
}
LINE = re.compile(r"^(?:(\d+)\s+)?([a-z][a-z0-9_]*)\((.*)\)\s+=\s+(.+)$")
EXIT = re.compile(r"^(?:(\d+)\s+)?\+\+\+ exited with 0 \+\+\+$")
FD = re.compile(r"^(-?\d+)(?:<([^<>]+)>)?(\(deleted\))?$")
RETURN = re.compile(
    r"^(-?(?:0x[0-9a-fA-F]+|\d+))"
    r"(?:<[^<>]+>(?:\(deleted\))?)?"
    r"(?: [A-Z][A-Z0-9_]* \([^\n]*\)| \([^\n]*\))?$"
)


def split_arguments(text: str) -> list[str]:
    """Split strace arguments without confusing quoted data or nested structs."""
    if not text:
        return []
    parts: list[str] = []
    stack: list[str] = []
    pairs = {"(": ")", "[": "]", "{": "}", "<": ">"}
    quote = False
    escaped = False
    start = 0
    index = 0
    while index < len(text):
        character = text[index]
        if quote:
            if escaped:
                escaped = False
            elif character == "\\":
                escaped = True
            elif character == '"':
                quote = False
        elif text.startswith("/*", index):
            end = text.find("*/", index + 2)
            if end == -1:
                raise TraceError("unterminated syscall comment")
            index = end + 1
        elif character == '"':
            quote = True
        elif character in pairs:
            stack.append(pairs[character])
        elif character in ")]}>":
            if not stack or stack.pop() != character:
                raise TraceError("unbalanced syscall arguments")
        elif character == "," and not stack:
            parts.append(text[start:index].strip())
            start = index + 1
        index += 1
    if quote or stack:
        raise TraceError("incomplete syscall arguments")
    parts.append(text[start:].strip())
    if any(not part for part in parts):
        raise TraceError("empty syscall argument")
    return parts


def flags(value: str, allowed: set[str]) -> set[str]:
    actual = set(value.split("|"))
    if not actual or not actual <= allowed:
        raise TraceError(f"unapproved flags {value}")
    return actual


def descriptor(value: str) -> tuple[int, str | None, bool]:
    match = FD.fullmatch(value)
    if not match:
        raise TraceError(f"unparsed file descriptor {value!r}")
    return int(match[1]), match[2], bool(match[3])


def return_value(value: str) -> int | None:
    if value == "?":
        return None
    match = RETURN.fullmatch(value)
    if not match:
        raise TraceError(f"unparsed syscall result {value!r}")
    token = match[1]
    return int(token, 16 if "0x" in token else 10)


class Checker:
    def __init__(self) -> None:
        self.pid: str | None = None
        self.created: dict[int, str] = {}
        self.memfds: dict[int, str] = {}
        self.sealed: set[int] = set()
        self.execs = 0
        self.diagnostics = 0
        self.exit_group = False
        self.completed = False

    def process(self, pid: str | None) -> None:
        if pid is not None:
            if self.pid is not None and pid != self.pid:
                raise TraceError("unexpected additional process or thread")
            self.pid = pid

    def memfd(self, value: str) -> int:
        number, path, _ = descriptor(value)
        name = self.memfds.get(number)
        if name is None or path != f"/memfd:{name}":
            raise TraceError(f"descriptor is not a created fixture memfd: {value}")
        return number

    @staticmethod
    def arity(name: str, args: list[str], counts: tuple[int, ...]) -> None:
        if len(args) not in counts:
            raise TraceError(f"unexpected {name} argument count")

    def call(self, name: str, args: list[str], result: str) -> None:
        value = return_value(result)
        if self.exit_group:
            raise TraceError("syscall after exit_group")
        if name != "execve" and self.execs != 1:
            raise TraceError("trace must begin with its sole successful execve")
        if name == "execve":
            self.arity(name, args, (3,))
            self.execs += 1
            if self.execs != 1 or value != 0:
                raise TraceError("expected exactly one successful execve")
        elif name in READ_ONLY_CALLS:
            self.arity(name, args, READ_ONLY_CALLS[name])
        elif name in SELF_CALLS:
            self.arity(name, args, SELF_CALLS[name])
        elif name in {"open", "openat"}:
            self.arity(name, args, (2, 3) if name == "open" else (3, 4))
            path_index = 0 if name == "open" else 1
            open_flags = flags(args[path_index + 1], READ_ONLY_OPEN_FLAGS)
            if "O_RDONLY" not in open_flags and "O_PATH" not in open_flags:
                raise TraceError("open is not explicitly read-only")
            if value is not None and value >= 0:
                number, target, _ = descriptor(result)
                self.memfds.pop(number, None)
                if target and target.startswith("/memfd:"):
                    path = args[path_index]
                    alias = re.fullmatch(r'"/proc/(?:self|\d+)/fd/(\d+)"', path)
                    source = int(alias[1]) if alias else -1
                    if alias and "/proc/self/" not in path:
                        if self.pid is None or not path.startswith(f'"/proc/{self.pid}/'):
                            raise TraceError("memfd alias belongs to another process")
                    name_from_source = self.memfds.get(source)
                    if name_from_source is None or target != f"/memfd:{name_from_source}":
                        raise TraceError("read-only open returned an unknown memfd alias")
                    self.memfds[number] = name_from_source
        elif name == "close":
            self.arity(name, args, (1,))
            number, _, _ = descriptor(args[0])
            if value == 0:
                self.memfds.pop(number, None)
        elif name == "memfd_create":
            self.arity(name, args, (2,))
            fixture_name = args[0].removeprefix('"').removesuffix('"')
            if args[0] != f'"{fixture_name}"' or fixture_name not in MEMFD_NAMES:
                raise TraceError("unexpected memfd name")
            actual = flags(args[1], {"MFD_CLOEXEC", "MFD_ALLOW_SEALING", "MFD_EXEC", "0x10"})
            if not {"MFD_CLOEXEC", "MFD_ALLOW_SEALING"} <= actual:
                raise TraceError("fixture memfd must be close-on-exec and sealable")
            if len(actual & {"MFD_EXEC", "0x10"}) != 1:
                raise TraceError("fixture memfd must request exactly one explicit executable flag")
            if value is not None and value >= 0:
                number, target, _ = descriptor(result)
                if number < 3:
                    raise TraceError("fixture memfd cannot replace a standard descriptor")
                if number in self.created or fixture_name in self.created.values():
                    raise TraceError("fixture memfds must be two distinct creations and descriptors")
                if target != f"/memfd:{fixture_name}":
                    raise TraceError("memfd creation is missing its expected descriptor annotation")
                self.created[number] = fixture_name
                self.memfds[number] = fixture_name
        elif name in {"write", "writev", "pwrite64", "pwritev", "pwritev2", "ftruncate"}:
            self.arity(name, args, {
                "write": (3,), "writev": (3,), "pwrite64": (4,),
                "pwritev": (4,), "pwritev2": (5,), "ftruncate": (2,),
            }[name])
            number, path, deleted = descriptor(args[0])
            if number == 1 and path == SINKS[1] and not deleted:
                if name != "write" or self.diagnostics != 0:
                    raise TraceError("stdout requires exactly one success diagnostic write")
                for message in SUCCESS_MESSAGES.values():
                    # strace's ordinary ASCII string rendering, without data
                    # abbreviation, alternative escapes, or extra payload bytes.
                    rendered = '"' + message[:-1] + '\\n"'
                    count = len(message.encode("ascii"))
                    if args[1] == rendered and args[2] == str(count) and result == str(count):
                        self.diagnostics += 1
                        return
                raise TraceError("stdout write is not the complete expected success diagnostic")
            self.memfd(args[0])
        elif name == "fcntl":
            self.arity(name, args, (2, 3))
            operation = args[1]
            if operation in {"F_GETFD", "F_GETFL"}:
                self.arity(name, args, (2,))
                descriptor(args[0])
            elif operation == "F_GET_SEALS":
                self.arity(name, args, (2,))
                number = self.memfd(args[0])
                if value == 0xF and number in self.created:
                    self.sealed.add(number)
            elif operation == "F_ADD_SEALS":
                self.arity(name, args, (3,))
                self.memfd(args[0])
                if flags(args[2], SEALS) != SEALS:
                    raise TraceError("fixture must request all four required seals")
            else:
                raise TraceError(f"unapproved fcntl operation {operation}")
        elif name == "ioctl":
            self.arity(name, args, (3,))
            descriptor(args[0])
            if args[1] not in {"TCGETS", "TIOCGWINSZ"}:
                raise TraceError(f"unapproved ioctl operation {args[1]}")
        elif name == "ppoll":
            # Rust startup queries these inherited descriptors without waiting
            # or requesting events. Keep the observed exception this narrow.
            self.arity(name, args, (5,))
            expected = (
                "[{fd=0</dev/null<char 1:3>>, events=0}, "
                "{fd=1</evidence/probe.stdout.txt>, events=0}, "
                "{fd=2</evidence/probe.stderr.txt>, events=0}]"
            )
            if args != [expected, "3", "{tv_sec=0, tv_nsec=0}", "NULL", "0"]:
                raise TraceError("unapproved ppoll readiness query")
        elif name == "mmap":
            self.arity(name, args, (6,))
            actual = flags(args[3], {
                "MAP_PRIVATE", "MAP_SHARED", "MAP_ANONYMOUS", "MAP_FIXED",
                "MAP_DENYWRITE", "MAP_STACK", "MAP_NORESERVE", "MAP_FIXED_NOREPLACE",
            })
            if ("MAP_PRIVATE" in actual) == ("MAP_SHARED" in actual):
                raise TraceError("mapping must have exactly one private/shared mode")
            if "MAP_SHARED" in actual:
                self.memfd(args[4])
            if "MAP_ANONYMOUS" in actual and args[4] != "-1":
                raise TraceError("anonymous mapping has an unexpected descriptor")
        elif name == "prlimit64":
            self.arity(name, args, (4,))
            if args[0] not in {"0", self.pid} or args[2] != "NULL":
                raise TraceError("prlimit64 may only query this process")
        elif name == "sched_getaffinity":
            self.arity(name, args, (3,))
            if args[0] not in {"0", self.pid}:
                raise TraceError("sched_getaffinity may only query this process")
        elif name == "arch_prctl":
            self.arity(name, args, (2,))
            if args[0] not in {"ARCH_SET_FS", "ARCH_GET_FS", "ARCH_SET_GS", "ARCH_GET_GS"}:
                raise TraceError("unapproved arch_prctl operation")
        elif name == "getrandom":
            self.arity(name, args, (3,))
            flags(args[2], {"0", "GRND_NONBLOCK", "GRND_RANDOM"})
        elif name == "madvise":
            self.arity(name, args, (3,))
            if args[2] not in {"MADV_DONTNEED", "MADV_FREE", "MADV_HUGEPAGE", "MADV_NOHUGEPAGE"}:
                raise TraceError("unapproved madvise operation")
        elif name == "futex":
            self.arity(name, args, (4, 5, 6))
            flags(args[1], {"FUTEX_WAIT_PRIVATE", "FUTEX_WAKE_PRIVATE", "FUTEX_WAIT_BITSET_PRIVATE", "FUTEX_CLOCK_REALTIME"})
        elif name == "exit_group":
            self.arity(name, args, (1,))
            if args[0] != "0" or result != "?":
                raise TraceError("expected exit_group(0) with a nonreturning result")
            self.exit_group = True
        else:
            raise TraceError(f"unapproved syscall {name}")

    def line(self, text: str) -> None:
        if self.completed:
            raise TraceError("records after completed process exit")
        if "<unfinished ...>" in text or "resumed>" in text:
            raise TraceError("unfinished or resumed syscall record")
        completion = EXIT.fullmatch(text)
        if completion:
            self.process(completion[1])
            if not self.exit_group:
                raise TraceError("exit marker without exit_group(0)")
            self.completed = True
            return
        match = LINE.fullmatch(text)
        if not match:
            raise TraceError("unparsed trace record")
        self.process(match[1])
        self.call(match[2], split_arguments(match[3]), match[4])

    def finish(self) -> None:
        if self.execs != 1 or not self.exit_group or not self.completed:
            raise TraceError("trace is incomplete: require one execve and a completed zero exit")
        if len(self.created) != 2 or set(self.created.values()) != MEMFD_NAMES:
            raise TraceError("require two successful distinct fixture memfd creations")
        if self.sealed != set(self.created):
            raise TraceError("both created memfds require successful F_GET_SEALS = 0xf")
        if self.diagnostics != 1:
            raise TraceError("require exactly one complete success diagnostic write")


def check_trace(text: str) -> None:
    checker = Checker()
    for number, line in enumerate(text.splitlines(), start=1):
        try:
            checker.line(line)
        except TraceError as error:
            raise TraceError(f"line {number}: {error}: {line}") from error
    checker.finish()


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("trace", type=Path)
    args = parser.parse_args()
    try:
        check_trace(args.trace.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, TraceError) as error:
        print(f"memfd trace rejected: {error}", file=sys.stderr)
        return 1
    print("Trace checks passed: two sealed fixture memfds, allowed operations, completed zero exit")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
