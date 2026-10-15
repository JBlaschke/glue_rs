"""Stock reference startup with the same explicit project/site import roots."""
from pathlib import Path
import importlib.metadata
import json
import runpy
import sys

inputs, kind, entry, *arguments = sys.argv[1:]
inputs = Path(inputs)
site = inputs / f"environment/lib/python{sys.version_info.major}.{sys.version_info.minor}/site-packages"
sys.path[:0] = [str(inputs / "project"), str(site)]
sys.argv = [entry, *arguments]
if kind == "file":
    runpy.run_path(str(inputs / "project" / entry), run_name="__main__")
elif kind == "module":
    runpy.run_module(entry, run_name="__main__", alter_sys=True)
elif kind == "console":
    matches = [p for p in importlib.metadata.entry_points(group="console_scripts") if p.name == entry]
    if len(matches) != 1:
        raise ValueError("console entry is missing or ambiguous")
    raise SystemExit(matches[0].load()())
else:
    raise ValueError("invalid entry kind")
