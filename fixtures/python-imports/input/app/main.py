"""Conformance checks executed by the real pinned stock CPython adapter."""

import sys
import io
import encodings
import math
import _ssl
import importlib
import importlib.resources as resources
import glue_demo
import glue_demo.answer as answer_module
import glue_demo.nested
import glue_demo.cycle_a
import glue_demo.encoded
import glue_ns
import glue_ns.part
import standalone
import atexit


def raises(exception, function, contains=None):
    try:
        function()
    except exception as error:
        if contains is not None:
            assert contains in str(error), str(error)
        return error
    raise AssertionError("expected " + exception.__name__)


assert sys.version_info[:3] == (3, 13, 16)
assert sys.implementation.name == "cpython"
assert sys.implementation.cache_tag == "cpython-313"
assert sys.flags.isolated == sys.flags.ignore_environment == 1
assert sys.flags.no_site == sys.flags.no_user_site == sys.flags.dont_write_bytecode == 1
assert sys.flags.utf8_mode == 1
assert sys.getfilesystemencoding() == "utf-8"
assert sys.getfilesystemencodeerrors() == "surrogateescape"
assert sys.stdout.encoding == sys.stderr.encoding == "utf-8"
assert sys.stdout.errors == "strict"
assert sys.stderr.errors == "backslashreplace"
assert sys.base_prefix == sys.prefix == sys.exec_prefix == sys.base_exec_prefix
assert sys.executable == sys._base_executable == "/__glue_archive__/launcher"
assert "site" not in sys.modules
if sys.path == []:
    assert sys.prefix == "/__glue_archive__/python"
    assert encodings.__spec__.origin == "frozen"
    assert resources.__spec__.origin.startswith("glue://")
    assert resources.__spec__.origin.endswith("/stdlib/importlib/resources/__init__.py")
    assert resources.__loader__.__class__.__name__ == "_ArchiveLoader"
else:
    assert sys.path == [sys.base_prefix + "/lib/python3.13"]
    assert encodings.__spec__.origin == sys.path[0] + "/encodings/__init__.py"
    assert encodings.__file__ == encodings.__spec__.origin
    assert encodings.__loader__.__class__.__name__ == "SourceFileLoader"
    assert resources.__spec__.origin == sys.path[0] + "/importlib/resources/__init__.py"
    assert resources.__loader__.__class__.__name__ == "SourceFileLoader"
assert resources.__file__ == resources.__spec__.origin
assert math.__spec__.origin == _ssl.__spec__.origin == "built-in"
assert sys._is_gil_enabled()
assert math.isqrt(1764) == glue_demo.package_answer == answer_module.answer == 42
assert glue_demo.nested.value == glue_demo.cycle_a.answer == glue_ns.part.answer == standalone.answer == 42
assert glue_demo.encoded.text == "café"
assert sys.modules["glue_demo.answer"] is answer_module
assert importlib.import_module("glue_demo.answer") is answer_module
assert answer_module.runs == 1
assert glue_demo.initializations == 1
assert importlib.reload(answer_module) is answer_module
assert answer_module.runs == 2
assert importlib.reload(glue_demo) is glue_demo
assert glue_demo.initializations == 2
importlib.invalidate_caches()
assert importlib.import_module("glue_demo.answer") is answer_module

for module in (glue_demo, answer_module, glue_demo.nested, glue_ns.part, standalone):
    assert module.__spec__.origin.startswith("glue://")
    assert module.__file__ == module.__spec__.origin
    assert module.__cached__ is None and module.__spec__.cached is None
    assert module.__loader__.get_filename(module.__name__) == module.__file__
    assert module.__loader__.get_code(module.__name__).co_filename == module.__file__
assert answer_module.result.__code__.co_filename == answer_module.__file__
assert glue_demo.__package__ == "glue_demo"
assert answer_module.__package__ == "glue_demo"
assert glue_demo.nested.__package__ == "glue_demo.nested"
assert all(path.startswith("glue://") for path in glue_demo.__path__)
assert glue_ns.__spec__.origin is None
assert glue_ns.__file__ is None
assert len(glue_ns.__path__) == 1 and glue_ns.__path__[0].startswith("glue://")
assert glue_ns.__loader__.get_code("glue_ns") is None
assert glue_ns.__loader__.get_source("glue_ns") is None
assert "def result" in answer_module.__loader__.get_source("glue_demo.answer")
assert "café" in glue_demo.encoded.__loader__.get_source("glue_demo.encoded")
assert "\r" not in glue_demo.encoded.__loader__.get_source("glue_demo.encoded")

error = raises(ModuleNotFoundError, lambda: importlib.import_module("glue_demo.missing"), "declared archive")
assert error.name == "glue_demo.missing"
error = raises(ModuleNotFoundError, lambda: importlib.import_module("glue_ns.missing"), "declared archive")
assert error.name == "glue_ns.missing"
raises(RuntimeError, lambda: importlib.import_module("glue_demo.broken"), "intentional archive module error")
assert "glue_demo.broken" not in sys.modules
assert sys.modules["glue_demo.dependency"].retained
error = raises(SyntaxError, lambda: importlib.import_module("glue_demo.syntax_error"))
assert error.filename.startswith("glue://")
assert error.args[1][0] == error.filename
assert error.text == 'if True print("this deliberately fails to compile")\n'
assert (error.lineno, error.offset, error.end_lineno, error.end_offset) == (1, 9, 1, 14)
assert "glue_demo.syntax_error" not in sys.modules
raises(ModuleNotFoundError, lambda: importlib.import_module("glue_demo.bytecode_only"), "declared archive")
assert "glue_demo.bytecode_only" not in sys.modules

files = resources.files(glue_demo)
assert files.is_dir() and not files.is_file()
assert files.name == "glue_demo"
children = [child.name for child in files.iterdir()]
assert children == sorted(children) and "data" in children and "__init__.py" in children
data = files.joinpath("data")
binary = data / "binary.bin"
text = files.joinpath("data", "text.txt")
assert binary.is_file() and not binary.is_dir()
assert binary.read_bytes() == b"\x00\xffarchive\x00\x2a"
assert text.read_text(encoding="utf-8") == "λ café\nsecond line\n"
assert resources.read_binary(glue_demo, "data", "binary.bin") == binary.read_bytes()
assert resources.read_text(glue_demo, "data", "text.txt", encoding="utf-8") == text.read_text()
assert resources.files(glue_ns).joinpath("data/info.txt").read_text() == "namespace resource\n"
assert resources.files(answer_module).joinpath("data/text.txt").read_text() == text.read_text()
assert not (data / "missing.bin").is_file()
assert not (data / "missing.bin").is_dir()
raises(FileNotFoundError, lambda: (data / "missing.bin").read_bytes())
raises(IsADirectoryError, data.read_bytes)
raises(NotADirectoryError, lambda: list(binary.iterdir()))
for child in ("..", "../answer.py", "/tmp/payload", "data//text.txt", "data/./text.txt", "data\\text.txt", "C:payload", "a\x00b", "", "é", "NUL.txt"):
    raises(ValueError, lambda child=child: files.joinpath(child))
raises(TypeError, lambda: files.joinpath(7))
assert files.joinpath() is files

first = binary.open("rb")
second = binary.open("rb")
assert first.readable() and first.seekable() and not first.writable()
assert first.read(2) == b"\x00\xff" and second.tell() == 0
assert second.read(1) == b"\x00"
assert first.seek(-1, 2) == len(binary.read_bytes()) - 1
assert first.read() == b"\x2a"
assert first.seek(100) == 100 and first.read() == b""
assert first.seek(0) == 0
target = bytearray(3)
assert first.readinto(target) == 3 and target == b"\x00\xffa"
raises(io.UnsupportedOperation, lambda: first.write(b"mutation"))
raises(io.UnsupportedOperation, first.fileno)
raises(io.UnsupportedOperation, lambda: first.truncate(0))
first.close()
raises(ValueError, first.read)
second.close()
with binary.open("rb", buffering=0) as raw:
    assert raw.seek(0) == 0
    assert raw.read(1) == b"\x00"
    before = raw.tell()
    raises(ValueError, lambda: raw.seek(-2))
    assert raw.tell() == before
    raises(ValueError, lambda: raw.seek(1 << 64))
    assert raw.tell() == before
    raises(TypeError, lambda: raw.readinto(b"readonly"))
with text.open("r", encoding="utf-8") as stream:
    assert stream.readline() == "λ café\n"
    assert stream.read() == "second line\n"
raises(io.UnsupportedOperation, lambda: binary.open("wb"))
raises(ValueError, lambda: binary.open("rb", encoding="utf-8"))
raises(ValueError, lambda: text.open("r", buffering=0))
raises(TypeError, lambda: __import__("os").fspath(binary))
raises(RuntimeError, lambda: resources.as_file(binary), "use read_bytes(), read_text(), or open()")
raises(RuntimeError, lambda: resources.as_file(data), "cannot be materialized")
raises(RuntimeError, lambda: resources.path(glue_demo, "data", "binary.bin"), "cannot be materialized")
raises(FileNotFoundError, lambda: glue_demo.__loader__.get_resource_reader("glue_demo").resource_path("data"), "no filesystem path")


def _check_exit_resources():
    # C finalization must keep the Rust callback context and archive alive.
    tree = resources.files(glue_demo)
    assert tree.joinpath("data/binary.bin").read_bytes() == b"\x00\xffarchive\x00\x2a"
    assert tree.joinpath("data/text.txt").read_text() == "λ café\nsecond line\n"


atexit.register(_check_exit_resources)

print("PASS Python=3.13.16 imports=archive packages=archive namespaces=archive resources=streams answer=42", flush=True)
