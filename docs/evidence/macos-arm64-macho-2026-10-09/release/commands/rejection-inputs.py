#!/usr/bin/env python3
"""Build-time mutations; archive length/hash checks still succeed afterwards."""
import pathlib
import shutil
import struct
import sys


def load_commands(image):
    count, size = struct.unpack_from("<II", image, 16)
    offset = 32
    end = offset + size
    if end > len(image):
        raise SystemExit("fixture has truncated load commands")
    for _ in range(count):
        command, length = struct.unpack_from("<II", image, offset)
        if length < 8 or offset + length > end:
            raise SystemExit("fixture has invalid load command length")
        yield command, offset, length
        offset += length
    if offset != end:
        raise SystemExit("fixture load commands have trailing bytes")


def replace_once(image, before, after):
    if len(before) != len(after) or image.count(before) != 1:
        raise SystemExit("mutation must preserve one uniquely identified string")
    return image.replace(before, after)


def main():
    if len(sys.argv) != 3:
        raise SystemExit("Usage: rejection-inputs.py VALID_INPUT_ROOT OUTPUT_ROOT")
    original = pathlib.Path(sys.argv[1])
    output = pathlib.Path(sys.argv[2])
    if output.exists():
        raise SystemExit("rejection output already exists")
    module = (original / "native/libglue_probe_module.dylib").read_bytes()
    cases = {}
    wrong_arch = bytearray(module)
    struct.pack_into("<II", wrong_arch, 4, 0x01000007, 3)
    cases["wrong_architecture"] = wrong_arch
    cases["install_name"] = replace_once(
        module,
        b"@loader_path/libglue_probe_module.dylib\0",
        b"@loader_path/libglue_probe_bodule.dylib\0",
    )
    cases["undeclared_dependency"] = replace_once(
        module,
        b"@loader_path/libglue_probe_dep.dylib\0",
        b"@loader_path/libglue_probe_xep.dylib\0",
    )
    writable_executable = bytearray(module)
    changed = False
    for command, offset, _ in load_commands(module):
        if command == 0x19 and module[offset + 8 : offset + 24].rstrip(b"\0") == b"__TEXT":
            struct.pack_into("<II", writable_executable, offset + 56, 7, 7)
            changed = True
            break
    if not changed:
        raise SystemExit("fixture has no __TEXT segment to mutate")
    cases["writable_executable"] = writable_executable
    future_minimum = bytearray(module)
    changed = False
    for command, offset, length in load_commands(module):
        if command == 0x32 and length >= 24:  # LC_BUILD_VERSION
            struct.pack_into("<II", future_minimum, offset + 12, 99 << 16, 99 << 16)
            changed = True
            break
    if not changed:
        raise SystemExit("fixture has no LC_BUILD_VERSION to mutate")
    cases["future_minimum"] = future_minimum
    for name, data in cases.items():
        destination = output / name
        shutil.copytree(original, destination, ignore=shutil.ignore_patterns("baseline"))
        (destination / "native/libglue_probe_module.dylib").write_bytes(data)


if __name__ == "__main__":
    main()
