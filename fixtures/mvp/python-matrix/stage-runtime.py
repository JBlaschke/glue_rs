#!/usr/bin/env python3
"""Explicit independent test input copy; preserve native bytes and internal links.

Drops installation site-packages and development metadata for an execution fixture.
Absolute links within the selected installation become equivalent relative links;
external aliases reject. This helper is never invoked by glue build or run.
"""
from pathlib import Path
import argparse
import json
import os
import shutil

parser = argparse.ArgumentParser(description=__doc__)
parser.add_argument("source", type=Path)
parser.add_argument("output", type=Path)
args = parser.parse_args()
source = args.source.resolve()
shutil.copytree(source, args.output, symlinks=True, ignore=shutil.ignore_patterns("site-packages", "__pycache__", "*.pyc", "include", "pkgconfig", "share"))
output = args.output.resolve()
changes = []
for path in output.rglob("*"):
    if not path.is_symlink():
        continue
    target = Path(os.readlink(path))
    if target.is_absolute():
        original = target.resolve()
        if not original.is_relative_to(source):
            raise ValueError("copied test runtime contains external absolute alias: " + str(path))
        path.unlink()
        new_target = os.path.relpath(output / original.relative_to(source), path.parent)
        path.symlink_to(new_target)
        changes.append({"path": path.relative_to(output).as_posix(), "original": str(target), "relative": new_target})
    if not path.resolve().is_relative_to(output):
        raise ValueError("copied test runtime alias escapes input: " + str(path))
receipt = {"source": str(source), "output": str(output), "native_bytes_edited": False, "omitted": ["installation site-packages", "__pycache__", "*.pyc", "include", "pkgconfig", "share"], "internalized_aliases": changes}
(output.parent / (output.name + "-stage.json")).write_text(json.dumps(receipt, indent=2) + "\n")
print(output)
