"""One bounded loose file: isolate paths before importing archived application."""
import sys
import os

if not (sys.flags.isolated and sys.flags.no_site and sys.flags.dont_write_bytecode):
    raise RuntimeError("Python compact bootstrap requires -I -S -B")
if len(sys.argv) < 3:
    raise RuntimeError("expected application ZIP and module")
distribution = os.path.dirname(os.path.dirname(os.path.realpath(__file__)))
runtime = os.path.join(distribution, "runtime")
for candidate in sys.path:
    if os.path.commonpath([runtime, os.path.realpath(candidate)]) != runtime:
        raise RuntimeError("runtime prefix fallback outside distribution: " + candidate)
# Some stock builds freeze the encodings package but leave its additional codec
# modules as source. Frozen package paths point at the omitted loose stdlib.
# Keep that package's native implementation and route its children to the ZIP.
import encodings
if encodings.__spec__.origin == "frozen":
    stdlib_zip = next((path for path in sys.path if path.endswith(".zip")), None)
    if stdlib_zip is None:
        raise RuntimeError("frozen encodings package requires archived stdlib")
    encodings.__path__ = [stdlib_zip + "/encodings"]
    encodings.__spec__.submodule_search_locations = encodings.__path__
app = os.path.realpath(sys.argv[1])
if os.path.commonpath([distribution, app]) != distribution:
    raise RuntimeError("application ZIP must be inside distribution")
sys.path.insert(0, app)
module = sys.argv[2]
sys.argv = [module, *sys.argv[3:]]
import runpy
runpy.run_module(module, run_name="__main__", alter_sys=True)
