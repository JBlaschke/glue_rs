#!/usr/bin/env python3
"""Portable adapter checks; the Linux fixture separately runs actual CPython.

The fake callback implements the declared wire protocol over fixture bytes.
It leaves the test interpreter's stdlib available so these tests exercise the
adapter without pretending to prove the pinned provider or syscall boundary.
"""

from contextlib import contextmanager
import importlib
import importlib.resources as resources
import io
from pathlib import Path
import sys
import types
import unittest
from urllib.parse import quote


HERE = Path(__file__).resolve().parent
BOOTSTRAP = (HERE / "bootstrap.py").read_bytes()
INPUT = HERE / "input"
FILES = {path.relative_to(INPUT).as_posix(): path.read_bytes() for path in INPUT.rglob("*") if path.is_file()}
PREFIX = "app/python/"
ROOT_NAMES = {key[len(PREFIX):].split("/", 1)[0].removesuffix(".py") for key in FILES if key.startswith(PREFIX)}
NODES = {""}
for key in FILES:
    parts = key.split("/")
    NODES.update("/".join(parts[:count]) for count in range(1, len(parts)))


def origin(key):
    return "glue://adapter-unit-fixture/" + quote(key, safe="/-._~")


class FakeArchive:
    def __init__(self, files=None):
        self.files = dict(FILES if files is None else files)
        self.calls = []
        self.nodes = {""}
        for key in self.files:
            parts = key.split("/")
            self.nodes.update("/".join(parts[:count]) for count in range(1, len(parts)))

    def request(self, query):
        self.calls.append(query)
        operation, key = query.split("\t", 1)
        if operation == "origin":
            return origin(key).encode()
        if operation == "read":
            try:
                return self.files[key]
            except KeyError:
                raise RuntimeError("native resource missing") from None
        if operation == "stat":
            if key in self.files:
                return ("file\n" + str(len(self.files[key]))).encode()
            return b"directory\n0" if key in self.nodes else b"missing\n0"
        if operation == "list":
            prefix = key + "/" if key else ""
            names = {node[len(prefix):].split("/", 1)[0] for node in self.nodes | self.files.keys() if node.startswith(prefix) and node != key}
            return "\n".join(sorted(names)).encode()
        if operation == "resolve":
            if not key.isascii() or not all(part.isidentifier() for part in key.split(".")):
                raise RuntimeError("invalid module name")
            candidate = PREFIX + key.replace(".", "/")
            package = candidate + "/__init__.py"
            module = candidate + ".py"
            if package in self.files and module in self.files:
                raise RuntimeError("ambiguous package and module")
            if package in self.files:
                return "\n".join(("package", package, origin(package), candidate)).encode()
            if module in self.files:
                return "\n".join(("module", module, origin(module), "")).encode()
            if candidate in self.nodes:
                return "\n".join(("namespace", candidate, "", candidate)).encode()
            return ("blocked\n\n\n" if key.split(".", 1)[0] in ROOT_NAMES else "missing\n\n\n").encode()
        raise RuntimeError("unknown archive operation")


@contextmanager
def adapter(archive=None):
    archive = archive or FakeArchive()
    previous_finders = list(sys.meta_path)
    previous_native = sys.modules.get("_glue_archive")
    previous_modules = {name: module for name, module in sys.modules.items() if name.split(".", 1)[0] in ROOT_NAMES}
    for name in previous_modules:
        del sys.modules[name]
    native = types.ModuleType("_glue_archive")
    native.request = archive.request
    sys.modules["_glue_archive"] = native
    namespace = {"__name__": "_glue_archive_bootstrap_test"}
    try:
        exec(compile(BOOTSTRAP, "glue://adapter/bootstrap.py", "exec"), namespace)
        yield namespace, archive
    finally:
        sys.meta_path[:] = previous_finders
        for name in list(sys.modules):
            if name.split(".", 1)[0] in ROOT_NAMES:
                del sys.modules[name]
        sys.modules.update(previous_modules)
        if previous_native is None:
            sys.modules.pop("_glue_archive", None)
        else:
            sys.modules["_glue_archive"] = previous_native


class ImporterTests(unittest.TestCase):
    def test_module_package_relative_and_circular_imports(self):
        with adapter():
            package = importlib.import_module("glue_demo")
            answer = importlib.import_module("glue_demo.answer")
            self.assertEqual(package.package_answer, 42)
            self.assertEqual(answer.answer, 42)
            self.assertEqual(importlib.import_module("glue_demo.nested").value, 42)
            self.assertEqual(importlib.import_module("glue_demo.cycle_a").answer, 42)
            self.assertEqual(importlib.import_module("standalone").answer, 42)
            self.assertEqual(package.__package__, "glue_demo")
            self.assertEqual(answer.__package__, "glue_demo")

    def test_normal_module_cache_and_explicit_reload(self):
        with adapter() as (_, archive):
            module = importlib.import_module("glue_demo.answer")
            reads = archive.calls.count("read\tapp/python/glue_demo/answer.py")
            self.assertIs(importlib.import_module("glue_demo.answer"), module)
            self.assertEqual(module.runs, 1)
            self.assertEqual(archive.calls.count("read\tapp/python/glue_demo/answer.py"), reads)
            self.assertIs(importlib.reload(module), module)
            self.assertEqual(module.runs, 2)
            self.assertEqual(archive.calls.count("read\tapp/python/glue_demo/answer.py"), reads + 1)

    def test_virtual_origins_and_source_code_metadata(self):
        with adapter():
            module = importlib.import_module("glue_demo.answer")
            expected = origin("app/python/glue_demo/answer.py")
            self.assertEqual(module.__file__, expected)
            self.assertEqual(module.__spec__.origin, expected)
            self.assertIsNone(module.__spec__.cached)
            self.assertIsNone(module.__cached__)
            self.assertEqual(module.result.__code__.co_filename, expected)
            self.assertEqual(module.__loader__.get_code(module.__name__).co_filename, expected)
            self.assertIn("def result", module.__loader__.get_source(module.__name__))
            with self.assertRaises(ImportError):
                module.__loader__.get_source("another_module")

    def test_namespace_has_one_virtual_portion_and_resources(self):
        with adapter():
            namespace = importlib.import_module("glue_ns")
            self.assertEqual(namespace.__path__, [origin("app/python/glue_ns")])
            self.assertIsNone(namespace.__spec__.origin)
            self.assertIsNone(namespace.__file__)
            self.assertIsNone(namespace.__loader__.get_code("glue_ns"))
            self.assertEqual(importlib.import_module("glue_ns.part").answer, 42)
            self.assertEqual(resources.files(namespace).joinpath("data/info.txt").read_text(), "namespace resource\n")

    def test_reserved_missing_descendant_cannot_reach_later_finder(self):
        class DecoyFinder:
            called = False

            def find_spec(self, fullname, path=None, target=None):
                if fullname == "glue_demo.host_only":
                    self.called = True
                    raise AssertionError("reserved archive miss escaped to another finder")
                return None

        with adapter() as (namespace, _):
            decoy = DecoyFinder()
            index = sys.meta_path.index(namespace["_archive_finder"])
            sys.meta_path.insert(index + 1, decoy)
            with self.assertRaises(ModuleNotFoundError) as failure:
                importlib.import_module("glue_demo.host_only")
            self.assertEqual(failure.exception.name, "glue_demo.host_only")
            self.assertFalse(decoy.called)
            self.assertIsNone(namespace["_archive_finder"].find_spec("unreserved_external_name"))

    def test_import_failure_cleans_only_failing_module(self):
        with adapter():
            with self.assertRaisesRegex(RuntimeError, "intentional archive module error"):
                importlib.import_module("glue_demo.broken")
            self.assertNotIn("glue_demo.broken", sys.modules)
            self.assertTrue(sys.modules["glue_demo.dependency"].retained)
            with self.assertRaises(SyntaxError) as error:
                importlib.import_module("glue_demo.syntax_error")
            self.assertEqual(error.exception.filename, origin("app/python/glue_demo/syntax_error.py"))
            self.assertEqual(error.exception.args[1][0], error.exception.filename)
            self.assertEqual(error.exception.text, 'if True print("this deliberately fails to compile")\n')
            self.assertEqual((error.exception.lineno, error.exception.offset, error.exception.end_lineno, error.exception.end_offset), (1, 9, 1, 14))
            self.assertNotIn("glue_demo.syntax_error", sys.modules)

    def test_nested_code_objects_restore_virtual_origin_recursively(self):
        with adapter() as (namespace, _):
            source = b"def outer():\n def inner():\n  return [x for x in range(2)]\n return inner\n"
            expected = origin("app/python/glue_demo/nested_code.py")
            code = namespace["_compile_source"](source, expected)
            pending = [code]
            count = 0
            while pending:
                current = pending.pop()
                count += 1
                self.assertEqual(current.co_filename, expected)
                pending.extend(value for value in current.co_consts if isinstance(value, type(code)))
            self.assertGreaterEqual(count, 3)
            globals = {}
            exec(code, globals)
            self.assertEqual(globals["outer"]()(), [0, 1])

    def test_syntax_error_subclasses_and_diagnostic_offsets_survive_rewrite(self):
        with adapter() as (namespace, _):
            expected = origin("app/python/glue_demo/error.py")
            for source, exception, text, locations in (
                (b"x = (\n", SyntaxError, "x = (\n", (1, 5, 1, 0)),
                (b"if True:\n", IndentationError, "if True:\n", (1, 9, 1, -1)),
            ):
                with self.subTest(source=source), self.assertRaises(exception) as failure:
                    namespace["_compile_source"](source, expected)
                error = failure.exception
                self.assertEqual(error.filename, expected)
                self.assertEqual(error.args[1][0], expected)
                self.assertEqual(error.text, text)
                self.assertEqual((error.lineno, error.offset, error.end_lineno, error.end_offset), locations)

    def test_source_only_never_reads_bytecode_lure(self):
        with adapter() as (_, archive):
            with self.assertRaises(ModuleNotFoundError):
                importlib.import_module("glue_demo.bytecode_only")
            self.assertNotIn("read\tapp/python/glue_demo/bytecode_only.pyc", archive.calls)

    def test_source_bytes_honor_encoding_cookie_and_normalize_get_source(self):
        files = dict(FILES)
        files["app/python/glue_demo/encoded.py"] = b"# coding: latin-1\r\ntext = 'caf\xe9'\r\n"
        with adapter(FakeArchive(files)):
            module = importlib.import_module("glue_demo.encoded")
            self.assertEqual(module.text, "caf\u00e9")
            source = module.__loader__.get_source(module.__name__)
            self.assertIn("caf\u00e9", source)
            self.assertNotIn("\r", source)

    def test_resource_tree_binary_text_and_module_anchor(self):
        with adapter():
            package = importlib.import_module("glue_demo")
            module = importlib.import_module("glue_demo.answer")
            tree = resources.files(package)
            children = [child.name for child in tree.iterdir()]
            self.assertEqual(children, sorted(children))
            self.assertIn("data", children)
            self.assertEqual(tree.joinpath("data", "binary.bin").read_bytes(), b"\x00\xffarchive\x00\x2a")
            self.assertEqual(tree.joinpath("data/text.txt").read_text(), "λ café\nsecond line\n")
            self.assertEqual(resources.files(module).joinpath("data/text.txt").read_text(), "λ café\nsecond line\n")
            missing = tree / "missing"
            self.assertFalse(missing.is_file())
            self.assertFalse(missing.is_dir())
            with self.assertRaises(FileNotFoundError):
                missing.read_bytes()
            with self.assertRaises(IsADirectoryError):
                tree.read_bytes()
            with self.assertRaises(NotADirectoryError):
                list((tree / "answer.py").iterdir())

    def test_join_rejects_path_escape_and_os_coercion(self):
        with adapter():
            tree = resources.files(importlib.import_module("glue_demo"))
            for child in ("..", "a/../b", "/tmp/x", "a//b", "a/./b", "a\\b", "C:x", "a\x00b", "", "é", "NUL.txt"):
                with self.subTest(child=child), self.assertRaises(ValueError):
                    tree.joinpath(child)
            with self.assertRaises(TypeError):
                tree.joinpath(1)
            with self.assertRaises(TypeError):
                __import__("os").fspath(tree)
            self.assertIs(tree.joinpath(), tree)

    def test_seekable_read_only_streams_have_independent_lifetimes(self):
        with adapter():
            resource = resources.files(importlib.import_module("glue_demo")) / "data/binary.bin"
            first = resource.open("rb")
            second = resource.open("rb")
            self.assertEqual(first.read(2), b"\x00\xff")
            self.assertEqual(second.tell(), 0)
            first.seek(-1, 2)
            self.assertEqual(first.read(), b"\x2a")
            first.seek(100)
            self.assertEqual(first.read(), b"")
            first.seek(0)
            output = bytearray(2)
            self.assertEqual(first.readinto(output), 2)
            self.assertEqual(output, b"\x00\xff")
            for operation in (lambda: first.write(b"x"), first.fileno, lambda: first.truncate(0)):
                with self.assertRaises(io.UnsupportedOperation):
                    operation()
            first.close()
            with self.assertRaises(ValueError):
                first.read()
            self.assertEqual(second.read(1), b"\x00")
            second.close()
            with resource.open("rb", buffering=0) as raw:
                before = raw.tell()
                for offset in (-1, 1 << 64):
                    with self.assertRaises(ValueError):
                        raw.seek(offset)
                    self.assertEqual(raw.tell(), before)
                with self.assertRaises(TypeError):
                    raw.readinto(b"readonly")

    def test_text_stream_options_and_write_modes(self):
        with adapter():
            resource = resources.files(importlib.import_module("glue_demo")) / "data/text.txt"
            with resource.open("r", encoding="utf-8") as stream:
                self.assertEqual(stream.readline(), "λ café\n")
                self.assertEqual(stream.read(), "second line\n")
            with self.assertRaises(io.UnsupportedOperation):
                resource.open("wb")
            with self.assertRaises(ValueError):
                resource.open("rb", encoding="utf-8")
            with self.assertRaises(ValueError):
                resource.open("r", buffering=0)

    def test_materialization_entry_points_reject_before_tempfile_creation(self):
        import tempfile
        from unittest.mock import patch

        with adapter():
            package = importlib.import_module("glue_demo")
            tree = resources.files(package)
            with patch.object(tempfile, "mkstemp", side_effect=AssertionError("tempfile attempt")), patch.object(tempfile, "TemporaryDirectory", side_effect=AssertionError("directory attempt")):
                for target in (tree, tree / "data/binary.bin"):
                    with self.assertRaisesRegex(RuntimeError, r"use read_bytes\(\), read_text\(\), or open\(\)"):
                        resources.as_file(target)
                with self.assertRaisesRegex(RuntimeError, "cannot be materialized"):
                    resources.path(package, "data", "binary.bin")
            reader = package.__loader__.get_resource_reader(package.__name__)
            with self.assertRaisesRegex(FileNotFoundError, "no filesystem path"):
                reader.resource_path("answer.py")

    def test_callback_protocol_rejects_malformed_resolution_and_metadata(self):
        class MalformedArchive(FakeArchive):
            def request(self, query):
                if query == "resolve\tbad_module":
                    return b"module\nonly-two-fields"
                if query == "stat\tapp/python/glue_demo/answer.py":
                    return b"directory\n17"
                return super().request(query)

        with adapter(MalformedArchive()) as (namespace, _):
            with self.assertRaisesRegex(RuntimeError, "module resolution"):
                namespace["_archive_finder"].find_spec("bad_module")
            with self.assertRaisesRegex(RuntimeError, "resource metadata"):
                namespace["_ArchivePath"]("app/python/glue_demo/answer.py").is_file()


if __name__ == "__main__":
    unittest.main()
