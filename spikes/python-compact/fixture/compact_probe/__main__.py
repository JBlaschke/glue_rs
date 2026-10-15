import _dbm
import codecs
import importlib.metadata
import importlib.resources
import json
import math
import os
import ssl
import sys

assert codecs.lookup("utf-8").encode("café")[0] == b"caf\xc3\xa9"
assert math.sqrt(81) == 9
assert ssl.OPENSSL_VERSION
assert importlib.metadata.version("compact-probe") == "1.0"
assert importlib.resources.files("compact_probe").joinpath("message.txt").read_text().strip() == "archived resource café"
assert _dbm.__file__ and "runtime" in _dbm.__file__
assert sys.flags.isolated and sys.flags.no_site and sys.flags.dont_write_bytecode
print(json.dumps({"version":list(sys.version_info[:3]),"prefix":sys.prefix,
                  "path":sys.path,"native":_dbm.__file__,"openssl":ssl.OPENSSL_VERSION,
                  "argv":sys.argv[1:],"cwd":os.getcwd(),"status":"ok"}, ensure_ascii=False))
