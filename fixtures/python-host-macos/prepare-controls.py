"""Derive rejected host installations from the valid read-only prefix.

usage: python3 -I fixtures/python-host-macos/prepare-controls.py VALID_PREFIX CONTROL_ROOT

Each control copies the complete valid installation and applies exactly one
change. The copies are left read-only like the valid prefix. This is a
build-time fixture step; it never runs the installed interpreter.
"""

import os
import shutil
import stat
import sys

LIBRARY = "lib/libpython3.13.dylib"
STDLIB = "lib/python3.13"
MODES = (
    "wrong-library",
    "wrong-stdlib",
    "missing-encodings",
    "symlink-stdlib",
    "missing-library",
    "cached-bytecode",
)


def writable(path):
    os.chmod(path, os.stat(path).st_mode | stat.S_IWUSR)


def writable_tree(path):
    for current, _directories, names in os.walk(path):
        writable(current)
        for name in names:
            entry = os.path.join(current, name)
            if not os.path.islink(entry):
                writable(entry)


def flip_last_byte(path):
    writable(os.path.dirname(path))
    writable(path)
    with open(path, "r+b") as handle:
        handle.seek(-1, os.SEEK_END)
        byte = handle.read(1)
        handle.seek(-1, os.SEEK_END)
        handle.write(bytes([byte[0] ^ 0x01]))


def main(argv):
    if len(argv) != 3:
        raise SystemExit(__doc__)
    valid, root = argv[1:]
    if not os.path.isabs(valid) or not os.path.isabs(root):
        raise SystemExit("prefixes must be absolute")
    for required in (LIBRARY, STDLIB + "/codecs.py", STDLIB + "/encodings/utf_8.py"):
        if not os.path.isfile(os.path.join(valid, required)):
            raise SystemExit(f"valid prefix lacks {required}")
    os.mkdir(root)
    for mode in MODES:
        prefix = os.path.join(root, f"host Python {mode}", "python")
        shutil.copytree(valid, prefix, symlinks=True)
        stdlib = os.path.join(prefix, STDLIB)
        if mode == "wrong-library":
            flip_last_byte(os.path.join(prefix, LIBRARY))
        elif mode == "wrong-stdlib":
            flip_last_byte(os.path.join(stdlib, "encodings", "utf_8.py"))
        elif mode == "missing-encodings":
            writable(os.path.join(stdlib, "encodings"))
            os.unlink(os.path.join(stdlib, "encodings", "utf_8.py"))
        elif mode == "symlink-stdlib":
            writable(os.path.join(prefix, "lib"))
            writable_tree(stdlib)
            shutil.rmtree(stdlib)
            os.symlink(os.path.join(valid, STDLIB), stdlib)
        elif mode == "missing-library":
            writable(os.path.join(prefix, "lib"))
            os.unlink(os.path.join(prefix, LIBRARY))
        elif mode == "cached-bytecode":
            cache = os.path.join(stdlib, "encodings", "__pycache__")
            writable(os.path.join(stdlib, "encodings"))
            os.mkdir(cache)
            with open(os.path.join(cache, "utf_8.cpython-313.pyc"), "wb") as handle:
                handle.write(b"\xcb\r\r\nstale")
        for current, directories, names in os.walk(os.path.join(root, f"host Python {mode}"), topdown=False):
            for name in names:
                path = os.path.join(current, name)
                if not os.path.islink(path):
                    os.chmod(path, os.stat(path).st_mode & ~(stat.S_IWUSR | stat.S_IWGRP | stat.S_IWOTH))
            os.chmod(current, os.stat(current).st_mode & ~(stat.S_IWUSR | stat.S_IWGRP | stat.S_IWOTH))
        print(f"prepared control {mode}")


if __name__ == "__main__":
    main(sys.argv)
