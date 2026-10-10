#!/usr/bin/env python3
"""Build-time bounded host source trees and negative controls; never traced."""

import hashlib
import json
import os
from pathlib import Path
import shutil
import sys


LIBRARY = "lib/libpython3.13.so.1.0"
LIBRARY_IDENTITY = (73_563_968, "42be968275d5be2d9e632ec9ef6790dd2c10f1d4a710ad1028fc2b687242f219")
STDLIB = "lib/python3.13"
MODES = ("wrong-library", "wrong-import-source", "missing-import-source", "cached-import-bytecode")
LURES = {
    "glue_demo/missing.py": b'raise RuntimeError("host package fallback executed")\n',
    "glue_demo/bytecode_only.pyc": b"unsupported host bytecode lure\n",
    "glue_ns/missing.py": b'raise RuntimeError("host namespace fallback executed")\n',
    "glue_ns/part.py": b"answer = -1\n",
    "standalone.py": b"answer = -1\n",
}


def identity(path):
    digest = hashlib.sha256()
    size = 0
    with path.open("rb") as stream:
        for block in iter(lambda: stream.read(65536), b""):
            digest.update(block)
            size += len(block)
    return size, digest.hexdigest()


def main():
    if len(sys.argv) != 6 or sys.version_info[:3] != (3, 13, 16):
        raise ValueError("requires pinned stock Python and PRODUCER PREFIX BUNDLE IMPORT_PINS PROVENANCE")
    producer, prefix, bundle_path, pin_path, provenance = map(Path, sys.argv[1:])
    if prefix.exists() or identity(producer / LIBRARY) != LIBRARY_IDENTITY:
        raise ValueError("host output exists or producer library differs")
    bundle = json.loads(bundle_path.read_text())
    pins = json.loads(pin_path.read_text())
    inventory_path = pin_path.parent.parent / "python-imports/stdlib-pins.json"
    inventory_bytes = inventory_path.read_bytes()
    inventory = json.loads(inventory_bytes)
    if pins["schema_version"] != 0 or pins["source_inventory_sha256"] != hashlib.sha256(inventory_bytes).hexdigest():
        raise ValueError("supplemental source inventory differs")
    sources = {}
    for entry in bundle["modules"]:
        relative = entry["source_path"].removeprefix("install/")
        if not relative.startswith(STDLIB + "/") or identity(producer / relative) != (inventory["files"][relative.removeprefix(STDLIB + "/")]["size"], entry["source_sha256"]):
            raise ValueError("producer startup source differs")
        sources[relative] = (inventory["files"][relative.removeprefix(STDLIB + "/")]["size"], entry["source_sha256"])
    if len(sources) != 6 or len(pins["files"]) != 63:
        raise ValueError("requires six startup and 63 supplemental sources")
    for relative, spec in pins["files"].items():
        if spec["compression"] != "stored" or {key: spec[key] for key in ("size", "sha256")} != inventory["files"][relative] or STDLIB + "/" + relative in sources:
            raise ValueError("supplemental pin differs from inventory or duplicates startup")
        key = STDLIB + "/" + relative
        expected = (spec["size"], spec["sha256"])
        if identity(producer / key) != expected:
            raise ValueError("producer supplemental source differs")
        sources[key] = expected
    (prefix / "lib").mkdir(parents=True)
    shutil.copyfile(producer / LIBRARY, prefix / LIBRARY)
    for relative in sources:
        target = prefix / relative
        target.parent.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(producer / relative, target)
    for relative, payload in LURES.items():
        target = prefix / STDLIB / relative
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_bytes(payload)
    for mode in MODES:
        control = prefix.with_name(prefix.name + " " + mode)
        if control.exists():
            raise ValueError("control output already exists")
        (control / "lib").mkdir(parents=True)
        if mode == "wrong-library":
            shutil.copyfile(prefix / LIBRARY, control / LIBRARY)
            with (control / LIBRARY).open("r+b") as stream:
                byte = stream.read(1)
                stream.seek(0)
                stream.write(bytes([byte[0] ^ 1]))
        else:
            os.link(prefix / LIBRARY, control / LIBRARY)
        for relative in sources:
            if mode == "missing-import-source" and relative == STDLIB + "/contextlib.py":
                continue
            target = control / relative
            target.parent.mkdir(parents=True, exist_ok=True)
            shutil.copyfile(prefix / relative, target)
        if mode == "wrong-import-source":
            target = control / STDLIB / "contextlib.py"
            payload = target.read_bytes()
            target.write_bytes(bytes([payload[0] ^ 1]) + payload[1:])
        if mode == "cached-import-bytecode":
            cache = control / STDLIB / "importlib/resources/__pycache__"
            cache.mkdir()
            (cache / "__init__.cpython-313.pyc").write_bytes(b"unsupported nested installed cache\n")
    records = {}
    for tree in (prefix, *(prefix.with_name(prefix.name + " " + mode) for mode in MODES)):
        files = {}
        for path in sorted(tree.rglob("*")):
            if path.is_symlink():
                raise ValueError("prepared host tree must not contain symlinks")
            if path.is_file():
                size, sha256 = identity(path)
                files[str(path.relative_to(tree))] = {"size": size, "sha256": sha256}
                path.chmod(0o444)
        for path in sorted(tree.rglob("*"), reverse=True):
            if path.is_dir():
                path.chmod(0o555)
        tree.chmod(0o555)
        records[str(tree)] = files
    provenance.write_text(json.dumps({"schema_version": 0, "build_time_materialization": True,
                                     "startup_sources": 6, "supplemental_sources": 63,
                                     "supplemental_bytes": sum(s["size"] for s in pins["files"].values()),
                                     "source_inventory_sha256": pins["source_inventory_sha256"],
                                     "lures": sorted(LURES), "runtime_trees": records}, indent=2, sort_keys=True) + "\n")
    print("Prepared bounded installed sources, host lures and four pre-initialization controls")


if __name__ == "__main__":
    main()
