import atexit
import importlib
import importlib.resources as resources
import sys
import report_data
import report_data.answer
import report_parts
import report_parts.extra

assert __name__ == "__main__"
assert __file__ == "glue://daily.report/app/tasks/report%27s%20%5Bdaily%5D.py"
assert sys.argv == [__file__]
assert __package__ is __spec__ is __cached__ is __loader__ is None
assert "_glue_run_source_entry" not in globals()
assert sys.path == [] and sys.flags.isolated == 1
assert report_data.answer.value == report_parts.extra.value == 42
assert report_data.answer.label == "café"
module = report_data.answer
assert importlib.import_module("report_data.answer") is module
assert importlib.reload(module) is module and module.loads == 2
assert module.__file__.startswith("glue://daily.report/")
assert module.__cached__ is None
assert report_parts.__spec__.origin is None
assert len(report_parts.__path__) == 1
files = resources.files(report_data)
text = files.joinpath("assets/message.txt")
binary = files.joinpath("assets/binary.bin")
assert text.read_text(encoding="utf-8") == "λ café\nreport\n"
assert binary.read_bytes() == b"\x00\xff\x2a\x00"
assert resources.files(report_parts).joinpath("assets/part.txt").read_text() == "namespace report\n"
with binary.open("rb") as stream:
    assert stream.read(1) == b"\x00"
    assert stream.seek(-2, 2) == 2 and stream.read() == b"\x2a\x00"
try:
    with resources.as_file(text):
        raise AssertionError("materialization was admitted")
except RuntimeError as error:
    assert "materializ" in str(error)
try:
    importlib.import_module("report_data.absent")
except ModuleNotFoundError as error:
    assert error.name == "report_data.absent"
else:
    raise AssertionError("missing owned child imported")

def finish():
    assert text.read_text() == "λ café\nreport\n"
    assert binary.read_bytes() == b"\x00\xff\x2a\x00"

atexit.register(finish)
print("PASS source-app=resources packages=archive namespaces=archive resources=streams answer=42", flush=True)
