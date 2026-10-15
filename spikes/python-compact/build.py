#!/usr/bin/env python3
"""Build-time stock-CPython ZIP-stdlib relocation experiment (no downloads).

This executable spike intentionally accepts installed Unix trees only. Product
discovery, safe archive ingestion and native closure resolution have other owners.
"""
import argparse
import hashlib
import json
import os
from pathlib import Path
import platform
import re
import selectors
import shutil
import signal
import subprocess
import tempfile
import time
import zipfile

PROBE = r'''
import importlib.machinery, json, platform, sys, sysconfig
print(json.dumps({
 "executable":sys.executable,"prefix":sys.base_prefix,
 "stdlib":sysconfig.get_path("stdlib"),"version":list(sys.version_info[:3]),
 "version_text":sys.version,"implementation":sys.implementation.name,
 "machine":platform.machine(),"system":platform.system(),
 "soabi":sysconfig.get_config_var("SOABI"),
 "gil_disabled":bool(sysconfig.get_config_var("Py_GIL_DISABLED")),
 "debug":bool(sysconfig.get_config_var("Py_DEBUG")),
 "framework":sysconfig.get_config_var("PYTHONFRAMEWORK"),
 "extension_suffixes":importlib.machinery.EXTENSION_SUFFIXES,
}))
'''
MAX_PROBE_BYTES = 65536
MAX_FILES = 50000
MAX_INPUT_BYTES = 2 * 1024 ** 3


def bounded_command(argv, timeout=15, limit=MAX_PROBE_BYTES):
    """Drain both pipes with an aggregate bound; kill descendants on failure."""
    child = subprocess.Popen(argv, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                             start_new_session=True)
    deadline = time.monotonic() + timeout
    output = {"stdout": bytearray(), "stderr": bytearray()}
    try:
        with selectors.DefaultSelector() as selector:
            for name in output:
                selector.register(getattr(child, name), selectors.EVENT_READ, name)
            while selector.get_map():
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    raise ValueError("metadata command exceeded timeout")
                for key, _ in selector.select(min(remaining, 0.25)):
                    chunk = os.read(key.fd, 4096)
                    if not chunk:
                        selector.unregister(key.fileobj)
                    else:
                        output[key.data].extend(chunk)
                        if sum(map(len, output.values())) > limit:
                            raise ValueError("metadata command exceeded output bound")
            status = child.wait(timeout=max(0.01, deadline - time.monotonic()))
        if status:
            raise ValueError("metadata command failed: " + output["stderr"].decode(errors="replace"))
        return output["stdout"].decode("utf-8")
    finally:
        if child.poll() is None:
            os.killpg(child.pid, signal.SIGKILL)
            child.wait()
        child.stdout.close()
        child.stderr.close()


def discover(executable):
    selected = Path(executable).resolve(strict=True)
    metadata = json.loads(bounded_command([str(selected), "-I", "-S", "-B", "-c", PROBE]))
    if metadata["implementation"] != "cpython" or metadata["version"][:2] < [3, 11]:
        raise ValueError("requires modern CPython 3.11+")
    if metadata["gil_disabled"] or metadata["debug"]:
        raise ValueError("free-threaded/debug runtime needs a separately tested adapter")
    if metadata["system"] != platform.system() or metadata["machine"] != platform.machine():
        raise ValueError("foreign runtime cannot be executed by this native spike")
    if metadata["framework"]:
        raise ValueError("framework runtime requires explicit Mach-O path normalization; "
                         "select Resources/Python.app/Contents/MacOS/Python (bin/python may exec an original-prefix app), "
                         "rewrite its Python dependency to @executable_path/../../../../Python, collect/rewrite every non-system edge, "
                         "then re-sign all modified images; unchanged bytes cannot relocate")
    metadata["executable"] = str(selected)
    root = Path(metadata["prefix"]).resolve(strict=True)
    Path(metadata["stdlib"]).resolve(strict=True).relative_to(root)
    return metadata


def is_native(path):
    return bool(re.search(r"\.(?:so(?:\.\d+)*|dylib)$", path.name))


def input_files(root):
    count = total = 0
    for path in sorted(root.rglob("*")):
        if any(part in {"__pycache__", "site-packages"} for part in path.relative_to(root).parts):
            continue
        if path.is_symlink():
            path.resolve(strict=True).relative_to(root)
        if path.is_file():
            count += 1
            total += path.stat().st_size
            if count > MAX_FILES or total > MAX_INPUT_BYTES:
                raise ValueError("runtime inventory exceeds spike bounds")
            yield path


def digest(path):
    value = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            value.update(chunk)
    return value.hexdigest()


def write_zip(path, entries):
    with zipfile.ZipFile(path, "w", compression=zipfile.ZIP_DEFLATED) as archive:
        for name, source in sorted(entries):
            info = zipfile.ZipInfo(name, date_time=(1980, 1, 1, 0, 0, 0))
            info.compress_type = zipfile.ZIP_DEFLATED
            info.external_attr = 0o100444 << 16
            archive.writestr(info, source.read_bytes() if isinstance(source, Path) else source)


def assemble(executable, output):
    metadata = discover(executable)
    output = Path(output).absolute()
    if output.exists():
        raise ValueError("output already exists")
    root = Path(metadata["prefix"]).resolve(strict=True)
    stdlib = Path(metadata["stdlib"]).resolve(strict=True)
    if output.is_relative_to(root) or root.is_relative_to(output):
        raise ValueError("output overlaps runtime input")
    version = ".".join(map(str, metadata["version"][:2]))
    output.parent.mkdir(parents=True, exist_ok=True)
    stage = Path(tempfile.mkdtemp(prefix=".python-compact-", dir=output.parent))
    try:
        runtime = stage / "runtime"
        target_executable = runtime / "bin" / ("python" + version)
        target_executable.parent.mkdir(parents=True)
        shutil.copyfile(metadata["executable"], target_executable)
        target_executable.chmod(0o555)
        entries = []
        native_inputs = []
        for source in input_files(root):
            relative = source.relative_to(root)
            if is_native(source) and relative.parts[0] == "lib":
                target = runtime / relative
                target.parent.mkdir(parents=True, exist_ok=True)
                shutil.copyfile(source, target)
                target.chmod(0o444)
                native_inputs.append({"path":str(relative), "sha256":digest(source)})
            elif source.is_relative_to(stdlib):
                entries.append((source.relative_to(stdlib).as_posix(), source))
        archive = runtime / "lib" / ("python" + version.replace(".", "") + ".zip")
        archive.parent.mkdir(parents=True, exist_ok=True)
        write_zip(archive, entries)
        (runtime / "lib" / ("python" + version) / "lib-dynload").mkdir(parents=True, exist_ok=True)
        support = stage / "support"
        support.mkdir()
        shutil.copyfile(Path(__file__).with_name("bootstrap.py"), support / "python-bootstrap.py")
        fixture = Path(__file__).with_name("fixture")
        write_zip(stage / "app.zip", [(p.relative_to(fixture).as_posix(), p)
                                     for p in fixture.rglob("*") if p.is_file()])
        spec = {
            "schema":1, "runtime":metadata,
            "executable":str(target_executable.relative_to(stage)),
            "argv":["-I", "-S", "-B", "support/python-bootstrap.py", "app.zip", "compact_probe"],
            "environment":{}, "cwd":"unrelated empty directory", "stdio":"inherit",
            "signals":"forward; launcher must wait for child", "native_inputs":native_inputs,
            "stdlib_entries":len(entries), "loose_bootstrap_files":1,
            "limitations":["native closure must be checked by C03/C04 before product use",
                            "Tcl/Tk external data is not assembled by this spike"],
        }
        (stage / "launch.json").write_text(json.dumps(spec, indent=2) + "\n")
        # Probe the staged interpreter before publication. A broken ZIP prefix
        # never creates a seemingly usable distribution.
        result = json.loads(bounded_command([str(target_executable), "-I", "-S", "-B", "-c",
                                             "import json,sys;print(json.dumps(sys.path))"]))
        if any(not Path(p).resolve().is_relative_to(runtime.resolve()) for p in result):
            raise ValueError("runtime prefix discovery fell back outside staged runtime: " + repr(result))
        stage.rename(output)
        return spec
    finally:
        if stage.exists():
            shutil.rmtree(stage)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--python", required=True)
    parser.add_argument("--output", required=True)
    args = parser.parse_args()
    try:
        print(json.dumps(assemble(args.python, args.output), indent=2))
    except (ValueError, OSError, subprocess.SubprocessError) as error:
        parser.exit(1, "python-compact: " + str(error) + "\n")
