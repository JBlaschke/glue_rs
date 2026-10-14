import atexit
from decimal import Decimal
import hashlib
import importlib.metadata as metadata
import importlib.resources as resources
import json
import sys

import stripped_demo

assert __name__ == "__main__"
assert __file__ == "glue://python.stripped-host/app/main.py"
assert sys.argv == [__file__]
assert sys.path == []
assert sys.version_info[:3] == (3, 13, 16)
assert sys.flags.isolated == sys.flags.ignore_environment == 1
assert sys.flags.no_site == sys.flags.dont_write_bytecode == 1
assert hashlib.sha256(b"fixture").hexdigest() == "f16d05ec6b29248d2c61adb1e9263f78e4f7bace1b955014a2d17872cfe4064d"
assert Decimal("0.1") + Decimal("0.2") == Decimal("0.3")
assert json.loads(json.dumps({"answer": stripped_demo.answer})) == {"answer": 42}
assert json.__file__.startswith("glue://python.stripped-host/stdlib/")
assert metadata.version("glue-stripped-demo") == "1.0"
assert metadata.distribution("glue-stripped-demo").read_text("METADATA").startswith("Metadata-Version: 2.1\n")
data = resources.files(stripped_demo).joinpath("data/value.txt")
assert data.read_bytes() == b"42\n"


def finish():
    assert data.read_bytes() == b"42\n"
    assert Decimal("0.1") + Decimal("0.2") == Decimal("0.3")


atexit.register(finish)
print("PASS python-host stdlib=hashlib,decimal,json metadata=1.0 resource=42", flush=True)
