#!/usr/bin/env python3
"""Produce the bounded startup bundle using the exact stock PBS compiler.

This is an explicitly build-time tool. It verifies the two cached upstream
archives, materializes the selected producer installation and matching headers,
and invokes that installation's interpreter to compile the startup modules.
Runtime execution uses the resulting archive and removes these build inputs.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path, PurePosixPath
import platform
import shutil
import subprocess
import sys
import tarfile


HERE = Path(__file__).resolve().parent
PIN_FILE = HERE.parent / "python-pbs" / "pins.json"
HEADER_PINS = HERE / "header-pins.json"
MODULES = {
    "codecs": ("codecs.py", False),
    "encodings": ("encodings/__init__.py", True),
    "encodings.aliases": ("encodings/aliases.py", False),
    "encodings.ascii": ("encodings/ascii.py", False),
    "encodings.latin_1": ("encodings/latin_1.py", False),
    "encodings.utf_8": ("encodings/utf_8.py", False),
}
LIBRARY = "install/lib/libpython3.13.so.1.0"
EXECUTABLE = "install/bin/python3.13"
INCLUDE = "python/install/include/python3.13/"
MAX_ENTRIES = 10_000
MAX_MEMBER_BYTES = 256 * 1024 * 1024
MAX_INSTALL_BYTES = 256 * 1024 * 1024
MAX_BUNDLE_BYTES = 4 * 1024 * 1024
MAX_BYTECODE_BYTES = 2 * 1024 * 1024


def digest(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def file_digest(path: Path) -> tuple[int, str]:
    count = 0
    hasher = hashlib.sha256()
    with path.open("rb") as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b""):
            count += len(block)
            hasher.update(block)
    return count, hasher.hexdigest()


def verify_artifact(path: Path, pin: dict) -> None:
    if file_digest(path) != (pin["size"], pin["sha256"]):
        raise ValueError(f"cached artifact does not match its upstream pin: {path}")


def canonical(path: str) -> str:
    if not path or len(path) > 4096 or "\\" in path or "\0" in path or any(part in {"", ".", ".."} for part in path.split("/")):
        raise ValueError(f"noncanonical build-time archive path: {path!r}")
    if not path.startswith("python/"):
        raise ValueError("archive member is outside python/")
    return path


def link_target(path: str, target: str) -> str:
    if not target or target.startswith("/") or len(target) > 4096 or "\\" in target or "\0" in target:
        raise ValueError("unsafe build-time archive symlink")
    parts = path.split("/")[:-1]
    for part in target.split("/"):
        if part in {"", "."}:
            if not part:
                raise ValueError("empty symlink path component")
            continue
        if part == "..":
            if len(parts) <= 1:
                raise ValueError("build-time archive symlink escapes python/")
            parts.pop()
        else:
            parts.append(part)
    return "/".join(parts)


def provision_install(path: Path, destination: Path) -> dict:
    if destination.exists():
        raise ValueError("producer destination must not already exist")
    with tarfile.open(path, "r:gz") as archive:
        members = archive.getmembers()
        if len(members) > MAX_ENTRIES:
            raise ValueError("producer installation exceeds the entry bound")
        inventory = {}
        total = 0
        links = {}
        for member in members:
            name = canonical(member.name.rstrip("/") if member.isdir() else member.name)
            if name in inventory or not (member.isfile() or member.issym() or member.isdir()):
                raise ValueError("duplicate or unsupported producer installation member")
            if member.size < 0 or member.size > MAX_MEMBER_BYTES or (not member.isfile() and member.size):
                raise ValueError("producer installation member size exceeds the bound")
            total += member.size
            if total > MAX_INSTALL_BYTES:
                raise ValueError("producer installation exceeds the payload byte bound")
            inventory[name] = member
            if member.issym():
                links[name] = link_target(name, member.linkname)
        for name in inventory:
            parts = name.split("/")
            for count in range(1, len(parts)):
                ancestor = inventory.get("/".join(parts[:count]))
                if ancestor is not None and not ancestor.isdir():
                    raise ValueError("producer archive traverses a non-directory ancestor")
        for source, target in links.items():
            visited = {source}
            while target in links:
                if target in visited:
                    raise ValueError("producer archive contains a symlink cycle")
                visited.add(target)
                target = links[target]
            if target not in inventory or not inventory[target].isfile():
                raise ValueError("producer archive has a dangling or non-file symlink")
        # Materialize only the stock compiler, its exact shared library and its
        # stdlib. The unrelated terminfo tree contains case-distinct filenames
        # that cannot coexist on a usual macOS build-input filesystem.
        def selected(name: str) -> bool:
            return name in {"python/bin/python3.13", "python/lib/libpython3.13.so.1.0", "python/lib/libpython3.13.so"} or name.startswith("python/lib/python3.13/")

        selected_names = {name for name in inventory if selected(name)}
        if any(target not in selected_names for source, target in links.items() if source in selected_names):
            raise ValueError("selected producer symlink leaves the materialized subset")
        destination.mkdir(parents=True)
        records = {}
        for member in members:
            if member.name not in selected_names:
                continue
            relative = PurePosixPath(member.name).relative_to("python")
            output = destination.joinpath(*relative.parts)
            if member.isdir():
                output.mkdir(parents=True, exist_ok=True)
            elif member.isfile():
                output.parent.mkdir(parents=True, exist_ok=True)
                with archive.extractfile(member) as source, output.open("xb") as sink:
                    shutil.copyfileobj(source, sink, length=1024 * 1024)
                output.chmod(member.mode & 0o777)
                size, sha256 = file_digest(output)
                if size != member.size:
                    raise ValueError("producer extraction was incomplete")
                records[str(relative)] = {"size": size, "sha256": sha256}
        for member in members:
            if member.name in selected_names and member.issym():
                output = destination.joinpath(*PurePosixPath(member.name).relative_to("python").parts)
                output.parent.mkdir(parents=True, exist_ok=True)
                os.symlink(member.linkname, output)
    return records


def inspect_full(path: Path, include_destination: Path) -> tuple[dict, dict, dict]:
    if include_destination.exists():
        raise ValueError("header destination must not already exist")
    header_pins = json.loads(HEADER_PINS.read_text())
    expected_headers = header_pins["files"]
    selected = {f"python/{LIBRARY}", f"python/{EXECUTABLE}", "python/PYTHON.json"}
    selected.update(f"python/install/lib/python3.13/{suffix}" for suffix, _ in MODULES.values())
    identities = {}
    sources = {}
    headers = {}
    include_destination.mkdir(parents=True)
    process = subprocess.Popen(["zstd", "-dc", str(path)], stdout=subprocess.PIPE)
    try:
        with tarfile.open(fileobj=process.stdout, mode="r|") as archive:
            count = 0
            for member in archive:
                count += 1
                if count > MAX_ENTRIES:
                    raise ValueError("full archive exceeds the member bound")
                canonical(member.name)
                if not member.isfile() or (member.name not in selected and not member.name.startswith(INCLUDE)):
                    continue
                if not 0 < member.size <= MAX_MEMBER_BYTES:
                    raise ValueError("selected full archive member exceeds the byte bound")
                hasher = hashlib.sha256()
                data = bytearray() if member.name != f"python/{LIBRARY}" and member.name != f"python/{EXECUTABLE}" else None
                with archive.extractfile(member) as source:
                    for block in iter(lambda: source.read(1024 * 1024), b""):
                        hasher.update(block)
                        if data is not None:
                            if len(data) + len(block) > 1024 * 1024:
                                raise ValueError("selected source/header exceeds 1MiB")
                            data.extend(block)
                identity = {"size": member.size, "sha256": hasher.hexdigest()}
                if member.name.startswith(INCLUDE):
                    relative = member.name.removeprefix(INCLUDE)
                    if relative in headers or expected_headers.get(relative) != identity:
                        raise ValueError("full archive installed header differs from checked-in pin")
                    output = include_destination.joinpath(*PurePosixPath(relative).parts)
                    output.parent.mkdir(parents=True, exist_ok=True)
                    output.write_bytes(data)
                    headers[relative] = identity
                elif member.name in identities:
                    raise ValueError("duplicate selected full archive resource")
                else:
                    identities[member.name] = identity
                    if data is not None:
                        sources[member.name] = bytes(data)
        if process.wait() != 0:
            raise ValueError("full archive zstd decompression failed")
    finally:
        if process.poll() is None:
            process.kill()
            process.wait()
    if headers != expected_headers or set(identities) != selected:
        raise ValueError("full archive is missing pinned headers or selected resources")
    return identities, sources, headers


COMPILER = r'''
import hashlib, importlib.util, json, marshal, sys, _ssl
request = json.loads(open(sys.argv[1], encoding="utf-8").read())
assert sys.version_info[:3] == (3, 13, 16)
assert sys.implementation.name == "cpython"
assert sys.implementation.cache_tag == "cpython-313"
assert sys._is_gil_enabled()
assert importlib.util.MAGIC_NUMBER.hex() == "f30d0d0a"
assert sys.flags.isolated and sys.flags.no_site and sys.flags.dont_write_bytecode
modules = []
for entry in request["modules"]:
    source = bytes.fromhex(entry.pop("source_hex"))
    assert hashlib.sha256(source).hexdigest() == entry["source_sha256"]
    code = compile(source, "glue://python/stdlib/" + entry["name"], "exec", dont_inherit=True, optimize=0)
    bytecode = marshal.dumps(code)
    entry["bytecode_hex"] = bytecode.hex()
    entry["bytecode_sha256"] = hashlib.sha256(bytecode).hexdigest()
    modules.append(entry)
request["modules"] = modules
assert len(modules) <= 32
assert sum(len(bytes.fromhex(entry["bytecode_hex"])) for entry in modules) <= 2 * 1024 * 1024
output = (json.dumps(request,sort_keys=True,separators=(",",":")) + "\n").encode()
assert len(output) <= 4 * 1024 * 1024
provenance = json.loads(open(sys.argv[2],encoding="utf-8").read())
provenance["compiler"] = {"version":sys.version,"executable":sys.executable,"openssl_version":_ssl.OPENSSL_VERSION,"flags":{"isolated":sys.flags.isolated,"no_site":sys.flags.no_site,"dont_write_bytecode":sys.flags.dont_write_bytecode}}
provenance["bundle"] = {"size":len(output),"sha256":hashlib.sha256(output).hexdigest()}
provenance["command"] = [sys.executable,"-I","-S","-B",*sys.argv]
with open(sys.argv[3],"xb") as stream: stream.write(output)
with open(sys.argv[4],"x",encoding="utf-8") as stream: stream.write(json.dumps(provenance,sort_keys=True,indent=2)+"\n")
print(f"Frozen six startup modules with stock CPython 3.13.16; bundle bytes={len(output)} sha256={hashlib.sha256(output).hexdigest()}")
'''


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("full", type=Path)
    parser.add_argument("install_only", type=Path)
    parser.add_argument("producer", type=Path)
    parser.add_argument("include", type=Path, help="exact matching Python include directory")
    parser.add_argument("output", type=Path)
    parser.add_argument("--provenance", type=Path, required=True)
    parser.add_argument("--provision-only", action="store_true", help="prepare cross-target build inputs without executing their compiler")
    args = parser.parse_args()
    if not args.provision_only and (platform.system() != "Linux" or platform.machine() != "aarch64"):
        raise ValueError("the selected stock compiler must execute on GNU Linux arm64")
    pins = json.loads(PIN_FILE.read_text())
    if pins["python_version"] != "3.13.16" or pins["target_triple"] != "aarch64-unknown-linux-gnu" or pins["build_options"] != "pgo+lto":
        raise ValueError("unexpected stock-PBS fixture profile")
    if json.loads(HEADER_PINS.read_text())["artifact_sha256"] != pins["full"]["sha256"]:
        raise ValueError("installed header pins refer to a different full artifact")
    verify_artifact(args.full, pins["full"])
    verify_artifact(args.install_only, pins["install_only"])
    identities, sources, headers = inspect_full(args.full, args.include)
    installed = provision_install(args.install_only, args.producer)
    for path, identity in identities.items():
        if path.startswith("python/install/") and installed.get(path.removeprefix("python/install/")) != identity:
            raise ValueError("producer resource differs from the matching full distribution")
    producer = {
        "python_version": pins["python_version"],
        "target_triple": pins["target_triple"],
        "full_sha256": pins["full"]["sha256"],
        "install_only_sha256": pins["install_only"]["sha256"],
        "metadata_sha256": identities["python/PYTHON.json"]["sha256"],
        "runtime_library_sha256": identities[f"python/{LIBRARY}"]["sha256"],
        "executable_sha256": identities[f"python/{EXECUTABLE}"]["sha256"],
        "bytecode_magic": "f30d0d0a",
        "cache_tag": "cpython-313",
    }
    app = (HERE / "app.py").read_bytes()
    modules = []
    for name, (suffix, is_package) in sorted(MODULES.items()):
        source_path = f"install/lib/python3.13/{suffix}"
        source = sources[f"python/{source_path}"]
        modules.append({"name": name, "is_package": is_package, "source_path": source_path, "source_sha256": digest(source), "source_hex": source.hex()})
    request = {"schema_version": 0, "producer": producer, "modules": modules, "app": {"source_path": "fixtures/python-bootstrap/app.py", "source_sha256": digest(app), "source_hex": app.hex()}}
    request_path = args.producer / "freeze-input.json"
    compiler_path = args.producer / "freeze-compiler.py"
    request_path.write_text(json.dumps(request, sort_keys=True, separators=(",", ":")))
    compiler_path.write_text(COMPILER)
    # Recheck immutable cached artifacts before publishing the build output.
    verify_artifact(args.full, pins["full"])
    verify_artifact(args.install_only, pins["install_only"])
    template = {"schema_version": 0, "build_time_materialization": True, "producer_selection": ["bin/python3.13", "lib/libpython3.13.so.1.0", "lib/libpython3.13.so", "lib/python3.13/**"], "pins": pins, "full_selected_resources": identities, "installed_headers": headers, "provision_command": sys.argv}
    template_path = args.producer / "freeze-provenance.json"
    template_path.write_text(json.dumps(template, sort_keys=True, indent=2) + "\n")
    if args.provision_only:
        print("Verified and materialized stock producer plus matching headers; target compiler has not executed")
        return
    args.output.parent.mkdir(parents=True, exist_ok=True)
    environment = {key: value for key, value in os.environ.items() if key not in {"LD_PRELOAD", "LD_LIBRARY_PATH"} and not key.startswith("PYTHON")}
    result = subprocess.run([str(args.producer / "bin/python3.13"), "-I", "-S", "-B", str(compiler_path), str(request_path), str(template_path), str(args.output), str(args.provenance)], check=True, capture_output=True, env=environment)
    if result.stderr or len(result.stdout) > 1024:
        raise ValueError("stock compiler emitted stderr or exceeded the diagnostic bound")
    print(result.stdout.decode("utf-8"), end="")


if __name__ == "__main__":
    main()
