import codecs
import example_ns.alpha
import example_ns.beta
import importlib.metadata
import importlib.resources
import json
import math
import samplepkg
import ssl
import sys

assert example_ns.alpha.VALUE == "project namespace"
assert example_ns.beta.VALUE == "installed namespace"
assert {p.name for p in importlib.resources.files(__import__("example_ns")).iterdir()} == {"alpha.py", "beta.py"}
assert importlib.metadata.version("samplepkg") == "1.0"
assert importlib.resources.files(samplepkg).joinpath("resource.txt").read_text().strip() == "resource café"
assert samplepkg is __import__("samplepkg")
assert codecs.lookup("cp437") and math.sqrt(81) == 9 and ssl.OPENSSL_VERSION
plugins = importlib.metadata.entry_points(group="console_scripts")
assert any(p.name == "sample" and p.value == "samplepkg:main" for p in plugins)
print(json.dumps({"status": "python-source-ok", "version": list(sys.version_info[:3]), "arguments": sys.argv[1:]}))
