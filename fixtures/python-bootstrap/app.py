"""Controlled stock-PBS startup proof; this is not a general archive importer."""

import sys
import encodings
import math
import _ssl

assert sys.version_info[:3] == (3, 13, 16)
assert sys.implementation.name == "cpython"
assert sys.implementation.cache_tag == "cpython-313"
assert sys.flags.isolated == 1
assert sys.flags.ignore_environment == 1
assert sys.flags.no_site == 1
assert sys.flags.no_user_site == 1
assert sys.flags.dont_write_bytecode == 1
assert sys.flags.utf8_mode == 1
assert sys.getfilesystemencoding() == "utf-8"
assert sys.stdout.encoding == "utf-8"
assert sys.path == []
assert "site" not in sys.modules
assert encodings.__spec__.origin == "frozen"
assert math.__spec__.origin == "built-in"
assert _ssl.__spec__.origin == "built-in"
assert sys._is_gil_enabled()
assert math.isqrt(1764) == 42
assert "archive".encode("utf-8").decode("utf-8") == "archive"
assert "λ".encode("utf-8").decode("utf-8") == "λ"
assert _ssl.OPENSSL_VERSION.startswith("OpenSSL 3.5.")
print(
    "PASS Python=3.13.16 encodings=frozen math=built-in ssl=built-in "
    f"answer=42 openssl={_ssl.OPENSSL_VERSION}",
    flush=True,
)
