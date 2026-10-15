#!/usr/bin/env python3
"""Independent test environment preparation; glue never invokes this helper."""
from pathlib import Path
import argparse
import json
import os
import shutil
import subprocess
import sys


def run(argv):
    subprocess.run([str(arg) for arg in argv], check=True, env={**os.environ, "PYTHONDONTWRITEBYTECODE": "1", "UV_PYTHON_DOWNLOADS": "never"})


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("inputs", type=Path)
    parser.add_argument("executable", help="relative existing executable under copied runtime")
    parser.add_argument("kind", choices=["ordinary", "uv", "descriptor"])
    parser.add_argument("--native", action="store_true")
    parser.add_argument("--framework", action="store_true")
    args = parser.parse_args()
    root = args.inputs.resolve()
    runtime = root / "runtime"
    python = runtime / args.executable
    if not python.resolve().is_relative_to(runtime):
        raise ValueError("runtime executable escapes copied runtime")
    if args.framework:
        # The stock framework's small bin stub executes its original app path.
        # The explicitly selected real app image is independently made probeable
        # in this copied fixture before product input identities are recorded.
        core = runtime / "Python"
        dependencies = subprocess.check_output(["/usr/bin/otool", "-L", str(python)], text=True).splitlines()[1:]
        original = [line.strip().split(" (", 1)[0] for line in dependencies if "/Python.framework/" in line and line.strip().split(" (", 1)[0].endswith("/Python")]
        if len(original) != 1 or not core.is_file():
            raise ValueError("expected one existing framework core dependency")
        run(["/usr/bin/install_name_tool", "-change", original[0], "@executable_path/../../../../Python", python])
        run(["/usr/bin/codesign", "--force", "--sign", "-", "--timestamp=none", python])
    version = json.loads(subprocess.check_output([str(python), "-I", "-S", "-B", "-c", "import json,sys;print(json.dumps(list(sys.version_info[:2])))"], text=True))
    environment = root / "environment"
    if args.kind == "ordinary":
        run([python, "-I", "-B", "-m", "venv", "--copies", environment])
    elif args.kind == "uv":
        uv = os.environ["GLUE_MVP_UV"]
        os.environ["UV_CACHE_DIR"] = str(root.parent / "uv-test-cache")
        run([uv, "venv", "--offline", "--no-project", "--no-managed-python", "--no-python-downloads", "--python", python, environment])
    else:
        (environment / "bin").mkdir(parents=True)
        (environment / "bin/python").symlink_to(os.path.relpath(python, environment / "bin"))
        (environment / "pyvenv.cfg").write_text("home = " + str(python.parent) + "\ninclude-system-site-packages = false\n")
    # Preserve actual venv/uv layout while converting only internal interpreter
    # aliases to relative links so the harness can prove copied-prefix removal.
    for path in environment.rglob("*"):
        if path.is_symlink() and Path(os.readlink(path)).is_absolute():
            target = path.resolve()
            if not target.is_relative_to(root):
                raise ValueError("prepared environment alias escapes copied inputs")
            path.unlink()
            path.symlink_to(os.path.relpath(target, path.parent))
    site = environment / f"lib/python{version[0]}.{version[1]}/site-packages"
    site.mkdir(parents=True, exist_ok=True)
    supplied = root / "installed"
    for item in supplied.iterdir():
        destination = site / item.name
        if destination.exists():
            raise ValueError("supplied package collides with environment seed: " + item.name)
        if item.is_dir():
            shutil.copytree(item, destination, symlinks=True)
        else:
            shutil.copy2(item, destination)
    if args.native:
        package = site / "native_probe"
        package.mkdir()
        (package / "__init__.py").write_text("\n")
        shutil.copy2(root / "secondary", package / ("libsecondary.dylib" if sys.platform == "darwin" else "libsecondary.so"))
    (root / "environment-receipt.json").write_text(json.dumps({"kind": args.kind, "runtime": str(python), "version": version, "pip_present": any(site.glob("pip-*.dist-info")), "framework_input_prepared": args.framework}, indent=2) + "\n")


if __name__ == "__main__":
    main()
