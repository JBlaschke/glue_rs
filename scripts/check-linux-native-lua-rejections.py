#!/usr/bin/env python3
"""Check six native-Lua ELF rejection traces before any native loader work.

Reuse the source-only fixture's startup/read policy. Each case must read only
its exact archive, emit only its exact diagnostic to its own evidence stderr,
create no memfd, and complete with the case's exact status: unsupported ELF
capabilities use 2 and invalid closure declarations use 1. This is fixture
evidence, not a sandbox.
"""

from __future__ import annotations

import argparse
import importlib.util
import json
import re
import sys
from pathlib import Path


SPEC = importlib.util.spec_from_file_location(
    "glue_native_rejection_shared_policy", Path(__file__).with_name("check-linux-native-lua-trace.py")
)
assert SPEC is not None and SPEC.loader is not None
SHARED = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(SHARED)
SOURCE = SHARED.SOURCE
BASE = SOURCE.BASE
TraceError = BASE.TraceError
MAX_TRACE_BYTES = SHARED.MAX_TRACE_BYTES
MAX_LINE_CHARACTERS = SHARED.MAX_LINE_CHARACTERS
MAX_RECORDS = SHARED.MAX_RECORDS
PROGRAM = "/build-target/debug/glue"
DIAGNOSTICS = {
    "wrong-architecture": "native Lua closure is unsupported: native_probe: require ET_DYN AArch64",
    "soname-mismatch": 'invalid native Lua closure: native_probe: SONAME "libwrong_native.so" does not match "libglue_lua_native.so"',
    "executable-stack": "native Lua closure is unsupported: native_probe: unknown segment permissions or writable executable segment",
    "undeclared-needed": "invalid native Lua closure: native_probe: ELF NEEDED differs from declared direct dependencies",
    "undeclared-import": 'invalid native Lua closure: native_probe: undeclared undefined symbol "glue_forbidden_constructor"',
    "wrong-initializer": "invalid native Lua closure: native_probe: payload defines Lua runtime symbol luaopen_other",
}
CASES = tuple(DIAGNOSTICS)
STATUSES = {case: 2 if case in {"wrong-architecture", "executable-stack"} else 1 for case in CASES}
REJECTION_EXIT = re.compile(r"^(?:(\d+)\s+)?\+\+\+ exited with ([12]) \+\+\+$")


def expected_stderr(case: str) -> str:
    if case not in DIAGNOSTICS:
        raise TraceError("unknown native rejection case")
    return f"glue: {DIAGNOSTICS[case]}\n"


class Checker(SOURCE.Checker):
    def __init__(self, case: str) -> None:
        super().__init__()
        self.case = case
        self.archive = f"/build-target/native-rejections/{case}.glue"
        self.stdout_path = f"/evidence/native-rejections/{case}.stdout.txt"
        self.stderr_path = f"/evidence/native-rejections/{case}.stderr.txt"
        self.required_stderr = expected_stderr(case)
        self.required_status = STATUSES[case]
        if len(self.required_stderr.encode("ascii")) > 4096:
            raise TraceError("fixture diagnostic exceeds the bound")
        self.expected = ""  # No source/native program output may occur.
        self.stderr = ""
        self.actual_rejection_exit = False
        self.completed_rejection_exit = False

    def process(self, pid: str | None) -> None:
        if pid is not None and re.fullmatch(r"[1-9][0-9]{0,9}", pid) is None:
            raise TraceError("expected a canonical bounded positive PID")
        super().process(pid)

    def allowed_read(self, path: str | None) -> bool:
        return path in SOURCE.SYSTEM_LIBRARIES | SOURCE.STARTUP_FILES | {self.archive} or (
            self.pid is not None and path == f"/proc/{self.pid}/maps"
        )

    def known_descriptor(self, argument: str, standard: bool = False) -> tuple[int, str]:
        number, path, deleted = SOURCE.descriptor(argument)
        expected = {0: "/dev/null", 1: self.stdout_path, 2: self.stderr_path}.get(number) if standard else None
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
            argv = f'[{json.dumps(PROGRAM)}, "run", {json.dumps(self.archive)}]'
            if args[0] != json.dumps(PROGRAM) or args[1] != argv:
                raise TraceError("execve is not the exact rejection launcher/archive command")
            BASE.Checker.call(self, name, args, result)
            return
        if name == "memfd_create":
            raise TraceError("rejection must precede every memfd creation attempt")
        if name in {"open", "openat"}:
            self.arity(name, args, (2, 3) if name == "open" else (3, 4))
            index = 0 if name == "open" else 1
            path = SOURCE.quoted(args[index])
            if not self.allowed_read(path):
                raise TraceError(f"unapproved filesystem read path {path!r}")
            flags = BASE.flags(args[index + 1], BASE.READ_ONLY_OPEN_FLAGS)
            if "O_RDONLY" not in flags and "O_PATH" not in flags:
                raise TraceError("open is not explicitly read-only")
            if value is not None and value >= 0:
                number, target, deleted = SOURCE.descriptor(result)
                if number < 3 or deleted or not self.allowed_read(target):
                    raise TraceError("open returned an unapproved descriptor")
                self.readers[number] = target
                if path == self.archive:
                    if target != self.archive:
                        raise TraceError("archive open resolved to another file")
                    self.archive_opens += 1
            return
        if name in {"read", "readv", "pread64", "preadv"}:
            super().call(name, args, result)
            _, path = self.known_descriptor(args[0])
            if path == self.archive and value is not None and value > 0:
                self.archive_bytes_read += value
            return
        if name == "write":
            self.arity(name, args, (3,))
            if SOURCE.descriptor(args[0]) != (2, self.stderr_path, False):
                raise TraceError("only the exact rejection evidence stderr may receive writes")
            data = SOURCE.quoted(args[1])
            try:
                count = len(data.encode("ascii"))
            except UnicodeError as error:
                raise TraceError("rejection diagnostic contains unexpected bytes") from error
            if count == 0 or args[2] != str(count) or result != str(count):
                raise TraceError("stderr write is incomplete or has inconsistent lengths")
            self.stderr += data
            if not self.required_stderr.startswith(self.stderr):
                raise TraceError("stderr is not the exact expected case diagnostic")
            return
        if name == "ppoll":
            self.arity(name, args, (5,))
            expected = "[{fd=0</dev/null<char 1:3>>, events=0}, " + f"{{fd=1<{self.stdout_path}>, events=0}}, {{fd=2<{self.stderr_path}>, events=0}}]"
            if args != [expected, "3", "{tv_sec=0, tv_nsec=0}", "NULL", "0"]:
                raise TraceError("unapproved ppoll readiness query")
            return
        if name == "exit_group":
            self.arity(name, args, (1,))
            if args != [str(self.required_status)] or result != "?":
                raise TraceError(f"expected exit_group({self.required_status}) with a nonreturning result")
            # Only the internal completion flag uses the base zero-exit policy;
            # both actual records must independently match the case's status.
            super().call(name, ["0"], result)
            self.actual_rejection_exit = True
            return
        super().call(name, args, result)

    def line(self, text: str) -> None:
        completed = REJECTION_EXIT.fullmatch(text)
        if completed:
            if self.completed or not self.actual_rejection_exit or int(completed[2]) != self.required_status:
                raise TraceError("unexpected, mismatched or duplicate completed rejection marker")
            super().line(text.replace(f"exited with {self.required_status}", "exited with 0"))
            self.completed_rejection_exit = True
            return
        if BASE.EXIT.fullmatch(text):
            raise TraceError("rejection must complete with its case's exact status")
        super().line(text)

    def finish(self) -> None:
        super().finish()
        if self.pid is None or not self.actual_rejection_exit or not self.completed_rejection_exit:
            raise TraceError("require a PID and complete matching rejection exit records")
        if self.stderr != self.required_stderr:
            raise TraceError("require the exact complete case diagnostic")


def check_trace(text: str, case: str) -> None:
    if len(text) > MAX_TRACE_BYTES or len(text.encode("utf-8")) > MAX_TRACE_BYTES:
        raise TraceError("trace exceeds the byte limit")
    checker = Checker(case)
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


def check_records(directory: Path, cases: tuple[str, ...] = CASES) -> None:
    for case in cases:
        expected = expected_stderr(case).encode("ascii")
        if read_small(directory / f"{case}.exit-status.txt", 16) != f"{STATUSES[case]}\n".encode("ascii"):
            raise TraceError(f"{case}: recorded status must be exactly {STATUSES[case]}")
        if read_small(directory / f"{case}.stdout.txt", 0) != b"":
            raise TraceError(f"{case}: stdout must be empty")
        for suffix in ("stderr.txt", "expected.stderr.txt"):
            if read_small(directory / f"{case}.{suffix}", 4096) != expected:
                raise TraceError(f"{case}: {suffix} differs from the exact diagnostic")
        check_trace(SHARED.read_trace(directory / f"{case}.trace.txt"), case)


def read_small(path: Path, limit: int) -> bytes:
    with path.open("rb") as source:
        data = source.read(limit + 1)
    if len(data) > limit:
        raise TraceError(f"{path.name}: record exceeds its byte limit")
    return data


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("records", type=Path, help="native-rejections evidence directory")
    parser.add_argument("--case", choices=CASES, help="check one case for diagnostics; default checks all six")
    args = parser.parse_args()
    cases = (args.case,) if args.case else CASES
    try:
        check_records(args.records, cases)
    except (OSError, UnicodeError, TraceError) as error:
        print(f"native Lua rejection evidence rejected: {error}", file=sys.stderr)
        return 1
    print(f"Trace checks passed: {len(cases)} exact ELF rejection diagnostic(s), empty stdout, exact case-specific statuses 1/2, no memfd or payload mutations")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
