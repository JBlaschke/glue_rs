import example_ns.alpha
import example_ns.beta
import importlib.metadata
import importlib.resources
import samplepkg
import sys

assert example_ns.alpha.VALUE == "project namespace"
assert example_ns.beta.VALUE == "installed namespace"
assert {path.name for path in importlib.resources.files(__import__("example_ns")).iterdir()} == {"alpha.py", "beta.py"}
assert importlib.metadata.version("samplepkg") == "1.0"
assert importlib.resources.files(samplepkg).joinpath("resource.txt").read_text().strip() == "resource café"
try:
    with importlib.resources.as_file(importlib.resources.files(samplepkg).joinpath("resource.txt")):
        raise AssertionError("archive resource extracted")
except OSError as error:
    assert "as_file" in str(error)
assert samplepkg is __import__("samplepkg")
print("python-env-ok", *sys.argv[1:])
