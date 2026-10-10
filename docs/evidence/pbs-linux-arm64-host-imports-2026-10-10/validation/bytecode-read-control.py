import importlib.util
import marshal
from pathlib import Path
import sys

root = Path('/control')
source = root / 'contextlib.py'
source.write_text("raise RuntimeError('source executed instead of the unchecked cache')\n")
cache = root / '__pycache__'
cache.mkdir()
code = compile("print('PASS -B executes unchecked installed cache')", str(source), 'exec')
(cache / ('contextlib.' + sys.implementation.cache_tag + '.pyc')).write_bytes(
    importlib.util.MAGIC_NUMBER + (1).to_bytes(4, 'little') + bytes(8) + marshal.dumps(code))
