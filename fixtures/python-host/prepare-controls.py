#!/usr/bin/env python3
"""Build-time controls for the exact installed-Python bootstrap fixture.

Execute with the pinned producer, before deleting that producer executable.
This helper is never mounted or executed by a traced runtime.
"""

import hashlib
import json
import os
from pathlib import Path
import shutil
import sys


LIBRARY = "lib/libpython3.13.so.1.0"
LIBRARY_IDENTITY = (73_563_968, "42be968275d5be2d9e632ec9ef6790dd2c10f1d4a710ad1028fc2b687242f219")
STDLIB = "lib/python3.13"
MODES = ("wrong-library", "wrong-stdlib", "missing-encodings", "symlink-stdlib", "missing-library", "cached-bytecode")


def identity(path):
    total = 0
    hasher = hashlib.sha256()
    with path.open("rb") as source:
        for block in iter(lambda: source.read(1024 * 1024), b""):
            total += len(block)
            hasher.update(block)
    return total, hasher.hexdigest()


def main():
    if len(sys.argv) != 5 or sys.version_info[:3] != (3, 13, 16):
        raise ValueError("requires the pinned stock Python and PRODUCER PREFIX BUNDLE PROVENANCE")
    producer, prefix, bundle_path, provenance = map(Path, sys.argv[1:])
    bundle = json.loads(bundle_path.read_text())
    if prefix.exists() or identity(producer / LIBRARY) != LIBRARY_IDENTITY:
        raise ValueError("host fixture output already exists or producer library differs")
    sources = {}
    for entry in bundle["modules"]:
        relative = entry["source_path"].removeprefix("install/")
        if not relative.startswith(STDLIB + "/") or identity(producer / relative)[1] != entry["source_sha256"]:
            raise ValueError("producer startup source differs from verified bundle")
        sources[relative] = entry["source_sha256"]
    if len(sources) != 6:
        raise ValueError("requires exactly six startup source pins")
    producer.rename(prefix)
    # The stock interpreter and freeze requests are build inputs only. Retain
    # the actual installed stdlib sources and unchanged shared library.
    shutil.rmtree(prefix / "bin")
    for path in prefix.glob("freeze-*"):
        path.unlink()
    alias = prefix / "lib/libpython3.13.so"
    if alias.exists() or alias.is_symlink():
        alias.unlink()
    for directory, names, files in os.walk(prefix / STDLIB):
        for name in list(names):
            if name == "__pycache__":
                shutil.rmtree(Path(directory) / name)
                names.remove(name)
        for name in files:
            if name.endswith((".pyc", ".pyo")):
                (Path(directory) / name).unlink()
    for mode in MODES:
        control = prefix.with_name(prefix.name + " " + mode)
        if control.exists():
            raise ValueError("control output must not already exist")
        (control / "lib").mkdir(parents=True)
        library = control / LIBRARY
        if mode == "missing-library":
            pass
        elif mode == "wrong-library":
            shutil.copyfile(prefix / LIBRARY, library)
            with library.open("r+b") as target:
                original = target.read(1)
                target.seek(0)
                target.write(bytes([original[0] ^ 1]))
        else:
            os.link(prefix / LIBRARY, library)
        if mode == "symlink-stdlib":
            os.symlink(str(prefix / STDLIB), control / STDLIB)
        else:
            for relative in sources:
                if mode == "missing-encodings" and relative == STDLIB + "/encodings/__init__.py":
                    continue
                destination = control / relative
                destination.parent.mkdir(parents=True, exist_ok=True)
                shutil.copyfile(prefix / relative, destination)
            if mode == "wrong-stdlib":
                source = control / STDLIB / "encodings/__init__.py"
                content = source.read_bytes()
                source.write_bytes(bytes([content[0] ^ 1]) + content[1:])
            if mode == "cached-bytecode":
                cache = control / STDLIB / "encodings/__pycache__"
                cache.mkdir()
                (cache / "__init__.cpython-313.pyc").write_bytes(b"deliberately unsupported fixture cache\n")
    records = {}
    for tree in [prefix, *[prefix.with_name(prefix.name + " " + mode) for mode in MODES]]:
        files = {}
        for path in sorted(tree.rglob("*")):
            if path.is_symlink():
                files[str(path.relative_to(tree))] = {"symlink": os.readlink(path)}
            elif path.is_file():
                size, sha256 = identity(path)
                files[str(path.relative_to(tree))] = {"size": size, "sha256": sha256}
                path.chmod(0o444)
        for path in sorted(tree.rglob("*"), reverse=True):
            if path.is_dir() and not path.is_symlink():
                path.chmod(0o555)
        tree.chmod(0o555)
        records[str(tree)] = files
    provenance.write_text(json.dumps({"schema_version": 0, "build_time_materialization": True,
                                     "removed": ["bin/python3.13", "freeze-*", "lib/libpython3.13.so", "**/__pycache__", "**/*.pyc", "**/*.pyo"],
                                     "runtime_trees": records}, sort_keys=True, indent=2) + "\n")
    print("Prepared unchanged installed host runtime and six pre-initialization controls")


if __name__ == "__main__":
    main()
