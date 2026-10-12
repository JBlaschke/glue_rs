import atexit
from fractions import Fraction
import importlib.resources as resources
import statistics
import sys
import xml.etree.ElementTree as tree
import xml

assert __name__ == "__main__"
assert __file__ == "glue://stdlib.source/app/tasks/stdlib.py"
assert sys.argv == [__file__]
assert __package__ is __spec__ is __cached__ is __loader__ is None
assert "_glue_run_source_entry" not in globals()
assert sys.path == [] and sys.flags.isolated == 1
assert Fraction(1, 3) + Fraction(1, 6) == Fraction(1, 2)
assert statistics.mean([40, 42, 44]) == 42
assert tree.fromstring("<answer>42</answer>").text == "42"
source = resources.files(xml).joinpath("etree/ElementTree.py")
assert b"XML" in source.read_bytes()
assert tree.__file__.startswith("glue://stdlib.source/stdlib/")
for name in ("glue_host_extra", "xml.etree.absent"):
    try:
        __import__(name)
    except ModuleNotFoundError as error:
        assert error.name == name
    else:
        raise AssertionError("unverified installed source imported")

def finish():
    assert b"XML" in source.read_bytes()
    assert statistics.mean([41, 43]) == 42

atexit.register(finish)
print("PASS source-app=stdlib fractions=1/2 statistics=42 xml=42 resources=streams", flush=True)
