#!/usr/bin/env python3
"""Check one prepared example after copying its complete distribution elsewhere."""

import argparse
from pathlib import Path
import shutil
import subprocess
import tempfile


EXAMPLES = {
    "lua": "lua-native",
    "python": "python-venv",
    "node": "node-npm",
}


def run(command, cwd, environment):
    result = subprocess.run(
        [str(part) for part in command],
        cwd=cwd,
        env=environment,
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        timeout=120,
        check=False,
    )
    if result.returncode:
        raise RuntimeError(
            f"{command[1]} exited {result.returncode}\n{result.stdout}{result.stderr}"
        )
    return result.stdout


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("example", choices=EXAMPLES)
    parser.add_argument("distribution", type=Path)
    args = parser.parse_args()
    source = args.distribution.resolve(strict=True)
    for name in ("glue", "app.glue", "glue.lock.json"):
        if not (source / name).is_file():
            parser.error(f"missing {source / name}; pass a complete Glue distribution")
    expected = (
        Path(__file__).resolve().parent / EXAMPLES[args.example] / "expected.txt"
    ).read_text(encoding="utf-8")

    with tempfile.TemporaryDirectory(prefix="glue example check ") as temporary:
        root = Path(temporary)
        home = root / "empty home"
        scratch = root / "scratch"
        cwd = root / "unrelated working directory"
        for directory in (home, scratch, cwd):
            directory.mkdir()
        environment = {
            "PATH": "/usr/bin:/bin",
            "HOME": str(home),
            "TMPDIR": str(scratch),
            "LANG": "C",
        }
        run([source / "glue", "doctor", source / "app.glue", "--json"], cwd, environment)
        relocated = root / "relocated app"
        shutil.copytree(source, relocated, symlinks=True)
        run(
            [relocated / "glue", "doctor", relocated / "app.glue", "--json"],
            cwd,
            environment,
        )
        actual = run(
            [relocated / "glue", "run", relocated / "app.glue", "--", "hello from relocated app"],
            cwd,
            environment,
        )
        if actual != expected:
            raise RuntimeError(f"output differs\nexpected: {expected!r}\nactual:   {actual!r}")
    print(f"{args.example}: doctor, relocation, calculation, and quoted argv passed")


if __name__ == "__main__":
    main()
