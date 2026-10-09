#!/usr/bin/env python3
"""Fail-closed evidence policy for the two-image native Lua Linux fixture.

Extends the source fixture's approved OS startup/archive reads with exactly two
named, sealed memfds. No filesystem mutation attempt, shared mapping, host Lua
library/source fallback, extra process or incomplete trace is admitted. This is
one controlled Linux/aarch64 fixture's evidence checker, not a runtime sandbox.
"""

from __future__ import annotations

import argparse
import importlib.util
import json
import re
import sys
from pathlib import Path


SPEC = importlib.util.spec_from_file_location(
    "glue_native_lua_source_policy", Path(__file__).with_name("check-linux-lua-trace.py")
)
assert SPEC is not None and SPEC.loader is not None
SOURCE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(SOURCE)
BASE = SOURCE.BASE
TraceError = BASE.TraceError

PROGRAM = "/build-target/debug/glue"
ARCHIVE = "/build-target/relocated native Lua fixture/app.glue"
STDOUT = "/evidence/native-lua.stdout.txt"
STDERR = "/evidence/native-lua.stderr.txt"
MEMFD_NAMES = {"glue-lua-native-libglue_lua_dep.so", "glue-lua-native-libglue_lua_native.so"}
MAX_TRACE_BYTES = 32 * 1024 * 1024
MAX_LINE_CHARACTERS = 8192
MAX_RECORDS = 100_000
SOURCE.PROGRAM, SOURCE.ARCHIVE = PROGRAM, ARCHIVE
SOURCE.STDOUT, SOURCE.STDERR = STDOUT, STDERR


def expected_stdout(version: str, pid: str | int) -> str:
    if version not in {"5.4", "5.5"} or re.fullmatch(r"[1-9][0-9]{0,9}", str(pid)) is None:
        raise TraceError("expected an explicit Lua version and positive traced PID")
    return f"Lua {version} native answer=42 data=7 constructors=1 state=124 pid={pid} errors=2\n"


class Checker(SOURCE.Checker):
    def __init__(self, version: str = "5.4") -> None:
        super().__init__(version)
        self.version = version
        self.expected = ""
        self.seal_requests: set[str] = set()
        self.seal_verified: set[str] = set()
        self.mapped: set[str] = set()
        self.written: dict[str, int] = {}
        self.os_calls = 0

    def process(self, pid: str | None) -> None:
        super().process(pid)
        if self.pid is not None:
            self.expected = expected_stdout(self.version, self.pid)

    def known_descriptor(self, argument: str, standard: bool = False) -> tuple[int, str]:
        number, path, _ = SOURCE.descriptor(argument)
        if number in self.memfds:
            name = self.memfds[number]
            if path != f"/memfd:{name}":
                raise TraceError("fixture memfd annotation disagrees with its identity")
            return number, path
        return super().known_descriptor(argument, standard)

    def image_name(self, argument: str) -> str:
        number, path = self.known_descriptor(argument)
        name = self.memfds.get(number)
        if name is None or path != f"/memfd:{name}":
            raise TraceError("operation requires a created fixture memfd")
        return name

    def call(self, name: str, args: list[str], result: str) -> None:
        value = BASE.return_value(result)
        if value is None and name != "exit_group":
            raise TraceError("non-exit syscall has an incomplete result")
        if self.exit_group:
            raise TraceError("syscall after exit_group")
        if name != "execve" and self.execs != 1:
            raise TraceError("trace must begin with its sole successful execve")
        if name == "memfd_create":
            self.arity(name, args, (2,))
            image = SOURCE.quoted(args[0])
            if image not in MEMFD_NAMES:
                raise TraceError("unexpected native fixture memfd name")
            flags = BASE.flags(args[1], {"MFD_CLOEXEC", "MFD_ALLOW_SEALING", "MFD_EXEC", "0x10"})
            if not {"MFD_CLOEXEC", "MFD_ALLOW_SEALING"} <= flags or len(flags & {"MFD_EXEC", "0x10"}) != 1:
                raise TraceError("memfd requires explicit executable, sealable, close-on-exec flags")
            number, path, _ = SOURCE.descriptor(result)
            if value is None or value < 3 or number in self.created or number in self.readers or number in self.memfds or image in self.created.values() or path != f"/memfd:{image}":
                raise TraceError("require two successful distinct annotated memfd creations")
            self.created[number] = image
            self.memfds[number] = image
            self.written[image] = 0
            return
        if name in {"write", "writev", "pwrite64", "pwritev", "pwritev2", "ftruncate"}:
            number, _, _ = SOURCE.descriptor(args[0]) if args else (-1, None, False)
            if number in self.memfds:
                self.arity(name, args, {"write": (3,), "writev": (3,), "pwrite64": (4,), "pwritev": (4,), "pwritev2": (5,), "ftruncate": (2,)}[name])
                image = self.image_name(args[0])
                if image in self.seal_requests or image in self.seal_verified:
                    raise TraceError("attempted mutation after image sealing")
                if value is None or value < 0:
                    raise TraceError("fixture memfd population must succeed")
                if name == "ftruncate":
                    if not args[1].isdigit() or int(args[1]) <= 0 or value != 0:
                        raise TraceError("unexpected memfd sizing operation")
                elif value <= 0:
                    raise TraceError("memfd population requires positive writes")
                else:
                    self.written[image] += value
                return
        if name == "fcntl":
            self.arity(name, args, (2, 3))
            if args[1] in {"F_ADD_SEALS", "F_GET_SEALS"}:
                image = self.image_name(args[0])
                if args[1] == "F_ADD_SEALS":
                    self.arity(name, args, (3,))
                    if BASE.flags(args[2], BASE.SEALS) != BASE.SEALS or value != 0 or self.written[image] <= 0:
                        raise TraceError("populated fixture images require all four successful seals")
                    self.seal_requests.add(image)
                else:
                    self.arity(name, args, (2,))
                    if value != 0xF or image not in self.seal_requests:
                        raise TraceError("image seals must be requested and verified as 0xf")
                    self.seal_verified.add(image)
                return
        if name in {"open", "openat"}:
            self.arity(name, args, (2, 3) if name == "open" else (3, 4))
            index = 0 if name == "open" else 1
            path = SOURCE.quoted(args[index])
            alias = re.fullmatch(r"/proc/(self|[0-9]+)/fd/([0-9]+)", path)
            if alias is not None:
                source = int(alias[2])
                image = self.memfds.get(source)
                if alias[1] not in {"self", self.pid} or image is None or self.seal_verified != MEMFD_NAMES:
                    raise TraceError("memfd alias requires the complete closure's verified seals")
                flags = BASE.flags(args[index + 1], BASE.READ_ONLY_OPEN_FLAGS)
                if "O_RDONLY" not in flags:
                    raise TraceError("loader memfd aliases must be read-only")
                number, target, _ = SOURCE.descriptor(result)
                if value is None or value < 3 or target != f"/memfd:{image}" or number in self.readers or number in self.memfds:
                    raise TraceError("memfd alias open did not return a distinct known image descriptor")
                self.memfds[number] = image
                return
        if name == "mmap":
            self.arity(name, args, (6,))
            flags = BASE.flags(args[3], {"MAP_PRIVATE", "MAP_ANONYMOUS", "MAP_FIXED", "MAP_DENYWRITE", "MAP_STACK", "MAP_NORESERVE", "MAP_FIXED_NOREPLACE"})
            if "MAP_PRIVATE" not in flags:
                raise TraceError("only private mappings are allowed")
            if "MAP_ANONYMOUS" not in flags:
                number, _, _ = SOURCE.descriptor(args[4])
                if number in self.memfds:
                    image = self.image_name(args[4])
                    BASE.flags(args[2], {"PROT_NONE", "PROT_READ", "PROT_WRITE", "PROT_EXEC"})
                    if self.seal_verified != MEMFD_NAMES:
                        raise TraceError("image mapping precedes the complete closure's verified sealing")
                    if "PROT_WRITE" in args[2].split("|") and "PROT_EXEC" in args[2].split("|"):
                        raise TraceError("fixture image cannot map writable executable pages")
                    if value is None or value < 0:
                        raise TraceError("fixture image mapping must succeed")
                    self.mapped.add(image)
                    return
        if name == "close":
            self.arity(name, args, (1,))
            number, _, _ = SOURCE.descriptor(args[0])
            if number in self.memfds:
                self.image_name(args[0])
                if value != 0:
                    raise TraceError("fixture memfd close must succeed")
                self.memfds.pop(number)
                return
        if name == "getpid":
            self.arity(name, args, (0,))
            if self.pid is None or value != int(self.pid):
                raise TraceError("OS PID observation differs from the traced process")
            self.os_calls += 1
        super().call(name, args, result)

    def finish(self) -> None:
        super().finish()
        if self.pid is None or len(self.created) != 2 or set(self.created.values()) != MEMFD_NAMES:
            raise TraceError("require a PID and exactly two native fixture memfd creations")
        if self.seal_verified != MEMFD_NAMES or self.mapped != MEMFD_NAMES:
            raise TraceError("both fixture images must be verified sealed before private mapping")
        if self.os_calls == 0:
            raise TraceError("require a successful actual getpid OS call")


def check_trace(text: str, version: str = "5.4") -> None:
    # The CLI bounds bytes before decoding. Keep the callable checker bounded as
    # well; reject character length before creating an encoded copy.
    if len(text) > MAX_TRACE_BYTES or len(text.encode("utf-8")) > MAX_TRACE_BYTES:
        raise TraceError("trace exceeds the byte limit")
    checker = Checker(version)
    for number, line in enumerate(text.splitlines(), start=1):
        if number > MAX_RECORDS:
            raise TraceError("trace exceeds the record limit")
        if len(line) > MAX_LINE_CHARACTERS:
            raise TraceError(f"line {number}: trace record exceeds the line limit")
        try:
            checker.line(line)
        except (ValueError, OverflowError, RecursionError) as error:
            raise TraceError(f"line {number}: {error}: {line}") from error
    checker.finish()


def read_trace(path: Path) -> str:
    with path.open("rb") as source:
        data = source.read(MAX_TRACE_BYTES + 1)
    if len(data) > MAX_TRACE_BYTES:
        raise TraceError("trace exceeds the byte limit")
    return data.decode("utf-8")


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("trace", type=Path)
    parser.add_argument("--lua-version", choices=("5.4", "5.5"), default="5.4")
    args = parser.parse_args()
    try:
        check_trace(read_trace(args.trace), args.lua_version)
    except (OSError, UnicodeError, TraceError) as error:
        print(f"native Lua trace rejected: {error}", file=sys.stderr)
        return 1
    print("Trace checks passed: exact native Lua output/PID, two sealed private memfd images, no payload file mutations")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
