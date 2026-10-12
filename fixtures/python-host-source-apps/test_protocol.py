#!/usr/bin/env python3
"""Check the actual host prelude plus unchanged archive bootstrap.

The callback below is a portable immutable byte-protocol fake, not the Rust
host verifier. Two stock-only checks additionally read available pinned sources
from the cached install-only producer. They do not assert that this producer
contains the complete 2,174-source host projection required for execution.
"""

from contextlib import contextmanager
import hashlib
import importlib
import importlib.machinery
import importlib.resources
import json
from pathlib import Path
import py_compile
import sys
import tempfile
import types
import unittest
from urllib.parse import quote


ROOT = Path(__file__).resolve().parents[2]
PRELUDE = (ROOT / "fixtures/python-host-source-apps/prelude.py").read_bytes()
BOOTSTRAP = (ROOT / "fixtures/python-imports/bootstrap.py").read_bytes()
APP_ID = "host-source-protocol"
STOCK = sys.platform == "linux" and sys.version_info[:3] == (3, 13, 16)
# Portable cases use their test interpreter's already-loaded resource adapter;
# the stock source test removes that entire subtree and imports its real pins.
importlib.resources.files("importlib.resources")


def origin(key):
    return "glue://" + APP_ID + "/" + quote(key, safe="/-._~")


class Snapshot:
    def __init__(self, files):
        self.files = dict(files)
        self.calls = []
        self.directories = set()
        self.owners = {}
        for key in self.files:
            parts = key.split("/")
            self.directories.update("/".join(parts[:end]) for end in range(1, len(parts)))
            for root in ("app/python", "stdlib"):
                prefix = root + "/"
                if key.startswith(prefix):
                    name = key[len(prefix):].split("/", 1)[0].removesuffix(".py")
                    if name.isascii() and name.isidentifier() and name != "__init__":
                        previous = self.owners.setdefault(name, root)
                        if previous != root:
                            raise ValueError("overlapping fake module roots")

    def request(self, query):
        self.calls.append(query)
        operation, key = query.split("\t", 1)
        if operation == "origin":
            return origin(key).encode()
        if operation == "read":
            try:
                return self.files[key]
            except KeyError:
                raise RuntimeError("snapshot resource is missing") from None
        if operation == "stat":
            if key in self.files:
                return ("file\n" + str(len(self.files[key]))).encode()
            return b"directory\n0" if key in self.directories else b"missing\n0"
        if operation == "list":
            prefix = key + "/"
            names = {node[len(prefix):].split("/", 1)[0] for node in self.directories | self.files.keys() if node.startswith(prefix)}
            return "\n".join(sorted(names)).encode()
        if operation != "resolve":
            raise RuntimeError("unknown snapshot operation")
        if not key.isascii() or not all(part.isidentifier() for part in key.split(".")):
            raise RuntimeError("invalid snapshot module name")
        root = self.owners.get(key.split(".", 1)[0])
        if root is None:
            return b"missing\n\n\n"
        directory = root + "/" + key.replace(".", "/")
        parent = directory
        while "/" in parent:
            parent = parent.rsplit("/", 1)[0]
            if parent == root:
                break
            if parent not in self.directories or parent + ".py" in self.files and parent + "/__init__.py" not in self.files:
                return b"blocked\n\n\n"
        package, module = directory + "/__init__.py", directory + ".py"
        if package in self.files:
            return "\n".join(("package", package, origin(package), directory)).encode()
        if module in self.files:
            return "\n".join(("module", module, origin(module), "")).encode()
        if directory in self.directories:
            return "\n".join(("namespace", directory, "", directory)).encode()
        return b"blocked\n\n\n"


@contextmanager
def closed_imports(snapshot, fresh_roots=()):
    state = (sys.meta_path[:], sys.path[:], sys.path_hooks[:], sys.path_importer_cache.copy())
    modules = sys.modules.copy()
    def fresh(name):
        return any(name == root or name.startswith(root + ".") for root in fresh_roots)
    parent_attributes = []
    for root in fresh_roots:
        if "." in root:
            parent, attribute = root.rsplit(".", 1)
            if parent in modules and hasattr(modules[parent], attribute):
                parent_attributes.append((modules[parent], attribute, getattr(modules[parent], attribute)))
    for name in list(sys.modules):
        if fresh(name):
            del sys.modules[name]
    native = types.ModuleType("_glue_archive")
    native.request = snapshot.request
    sys.modules["_glue_archive"] = native
    namespace = {"__name__": "_glue_archive_bootstrap_protocol"}
    try:
        exec(compile(PRELUDE, "trusted-host-source-prelude", "exec"), namespace)
        exec(compile(BOOTSTRAP, "trusted-shared-importer", "exec"), namespace)
        yield namespace
    finally:
        sys.meta_path[:], sys.path[:], sys.path_hooks[:] = state[:3]
        sys.path_importer_cache.clear()
        sys.path_importer_cache.update(state[3])
        for name in list(sys.modules):
            if name not in modules or fresh(name):
                del sys.modules[name]
        sys.modules.update(modules)
        for parent, attribute, value in parent_attributes:
            setattr(parent, attribute, value)


def installed_stock_snapshot():
    pins = json.loads((ROOT / "fixtures/python-imports/stdlib-pins.json").read_text())["files"]
    stdlib = Path(sys.base_prefix) / "lib/python3.13"
    files = {}
    for relative, spec in pins.items():
        path = stdlib / relative
        if not path.is_file():
            continue
        data = path.read_bytes()
        if len(data) != spec["size"] or hashlib.sha256(data).hexdigest() != spec["sha256"]:
            raise AssertionError("present producer source differs from stock pin: " + relative)
        files["stdlib/" + relative] = data
    if len(files) < 1000:
        raise AssertionError("stock protocol producer has fewer than 1,000 pinned source files")
    return Snapshot(files)


class HostProtocolTests(unittest.TestCase):
    def test_prelude_closes_paths_before_shared_bootstrap_without_leaking_helpers(self):
        path_finder = importlib.machinery.PathFinder
        sys.path_importer_cache["protocol-decoy"] = object()
        with closed_imports(Snapshot({})) as namespace:
            self.assertNotIn(path_finder, sys.meta_path)
            self.assertEqual(sys.path, [])
            self.assertEqual(sys.path_hooks, [])
            self.assertEqual(sys.path_importer_cache, {})
            self.assertNotIn("_glue_close_host_imports", namespace)
            self.assertNotIn("_sys", namespace)
            self.assertNotIn("_external", namespace)
            self.assertLess(sys.meta_path.index(importlib.machinery.BuiltinImporter), sys.meta_path.index(namespace["_archive_finder"]))
            self.assertLess(sys.meta_path.index(importlib.machinery.FrozenImporter), sys.meta_path.index(namespace["_archive_finder"]))
        sys.path_importer_cache.pop("protocol-decoy", None)

    def test_available_source_bytecode_and_native_path_lures_all_become_missing(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory)
            (path / "outside_source.py").write_text("raise AssertionError('source lure executed')\n")
            source = path / "outside_bytecode.py"
            source.write_text("raise AssertionError('bytecode lure executed')\n")
            py_compile.compile(str(source), cfile=str(path / "outside_bytecode.pyc"), doraise=True)
            source.unlink()
            (path / ("outside_native" + importlib.machinery.EXTENSION_SUFFIXES[0])).write_bytes(b"invalid native lure")
            for name in ("outside_source", "outside_bytecode", "outside_native"):
                self.assertIsNotNone(importlib.machinery.PathFinder.find_spec(name, [directory]))
            snapshot = Snapshot({})
            with closed_imports(snapshot):
                # Even changing sys.path after the prelude cannot restore the
                # default path-based finder. This is an import policy, not a
                # restriction on explicit user-created loaders or ordinary I/O.
                sys.path.append(directory)
                for name in ("outside_source", "outside_bytecode", "outside_native"):
                    with self.assertRaises(ModuleNotFoundError) as error:
                        importlib.import_module(name)
                    self.assertEqual(error.exception.name, name)
                    self.assertNotIn(name, sys.modules)
                    self.assertIn("resolve\t" + name, snapshot.calls)

    def test_missing_owned_child_does_not_consult_a_later_finder(self):
        class Lure:
            def find_spec(self, fullname, path=None, target=None):
                if fullname == "owned.missing":
                    raise AssertionError("owned child reached later finder")
                return None

        snapshot = Snapshot({"app/python/owned/__init__.py": b"answer = 42\n"})
        with closed_imports(snapshot, ("owned",)):
            sys.meta_path.append(Lure())
            with self.assertRaises(ModuleNotFoundError) as error:
                importlib.import_module("owned.missing")
            self.assertEqual(error.exception.name, "owned.missing")
            self.assertEqual(sys.modules["owned"].answer, 42)

    def test_immutable_source_snapshot_keeps_reload_and_virtual_metadata(self):
        snapshot = Snapshot({"stdlib/snapshot_value.py": b"loads = globals().get('loads', 0) + 1\nanswer = 42\ndef value(): return answer\n"})
        with closed_imports(snapshot, ("snapshot_value",)):
            module = importlib.import_module("snapshot_value")
            self.assertIs(importlib.import_module("snapshot_value"), module)
            self.assertEqual(module.loads, 1)
            self.assertIs(importlib.reload(module), module)
            self.assertEqual(module.loads, 2)
            self.assertEqual(module.value(), 42)
            self.assertEqual(module.__file__, origin("stdlib/snapshot_value.py"))
            self.assertEqual(module.__spec__.origin, module.__file__)
            self.assertEqual(module.value.__code__.co_filename, module.__file__)
            self.assertIsNone(module.__cached__)
            self.assertIsNone(module.__spec__.cached)

    def test_snapshot_resources_use_streams_and_reject_materialization(self):
        snapshot = Snapshot({"stdlib/snapshot_package/__init__.py": b"", "stdlib/snapshot_package/asset.txt": "λ café\n".encode()})
        with closed_imports(snapshot, ("snapshot_package",)):
            package = importlib.import_module("snapshot_package")
            asset = importlib.resources.files(package).joinpath("asset.txt")
            self.assertEqual(asset.read_text(), "λ café\n")
            with asset.open("rb") as stream:
                self.assertEqual(stream.read(), "λ café\n".encode())
            with self.assertRaisesRegex(RuntimeError, "cannot be materialized"):
                with importlib.resources.as_file(asset):
                    self.fail("snapshot materialized")

    def test_initialized_builtin_frozen_and_startup_module_metadata_stay_unchanged(self):
        import encodings
        import io
        before = (encodings, encodings.__spec__.origin, encodings.__file__, hasattr(encodings, "__cached__"), getattr(encodings, "__cached__", None), sys.prefix, sys.base_prefix, io, io.__spec__.origin)
        with closed_imports(Snapshot({})):
            self.assertIs(importlib.import_module("sys"), sys)
            self.assertEqual(sys.__spec__.origin, "built-in")
            self.assertEqual((encodings, encodings.__spec__.origin, encodings.__file__, hasattr(encodings, "__cached__"), getattr(encodings, "__cached__", None), sys.prefix, sys.base_prefix, importlib.import_module("io"), io.__spec__.origin), before)

    def test_compiler_failure_keeps_virtual_identity_and_cleans_module_cache(self):
        key = "stdlib/snapshot_invalid.py"
        with closed_imports(Snapshot({key: b"value = (\n"}), ("snapshot_invalid",)):
            with self.assertRaises(SyntaxError) as error:
                importlib.import_module("snapshot_invalid")
            self.assertEqual(error.exception.filename, origin(key))
            self.assertEqual(error.exception.args[1][0], origin(key))
            self.assertNotIn("snapshot_invalid", sys.modules)

    def test_native_package_initializer_would_shadow_startup_source_without_guard(self):
        # The real C boundary imports encodings before running this prelude.
        # Its source hash alone cannot exclude an alternate native initializer.
        with tempfile.TemporaryDirectory() as directory:
            package = Path(directory) / "encodings"
            package.mkdir()
            (package / "__init__.py").write_text("value = 'pinned source'\n")
            source_spec = importlib.machinery.PathFinder.find_spec("encodings", [directory])
            self.assertIsInstance(source_spec.loader, importlib.machinery.SourceFileLoader)
            native = package / ("__init__" + importlib.machinery.EXTENSION_SUFFIXES[0])
            native.write_bytes(b"invalid native initializer lure")
            importlib.invalidate_caches()
            shadow_spec = importlib.machinery.PathFinder.find_spec("encodings", [directory])
            self.assertIsInstance(shadow_spec.loader, importlib.machinery.ExtensionFileLoader)
            self.assertEqual(shadow_spec.origin, str(native))

    def test_disabled_bytecode_writes_still_allow_unchecked_cache_reads_before_prelude(self):
        previous_prefix = sys.pycache_prefix
        previous_writes = sys.dont_write_bytecode
        try:
            sys.pycache_prefix = None
            sys.dont_write_bytecode = True
            with tempfile.TemporaryDirectory() as directory:
                source = Path(directory) / "startup_cache_lure.py"
                source.write_text("raise RuntimeError('unchecked startup cache executed')\n")
                py_compile.compile(str(source), doraise=True, invalidation_mode=py_compile.PycInvalidationMode.UNCHECKED_HASH)
                source.write_text("value = 'verified source'\n")
                loader = importlib.machinery.SourceFileLoader("startup_cache_lure", str(source))
                with self.assertRaisesRegex(RuntimeError, "^unchecked startup cache executed$"):
                    exec(loader.get_code("startup_cache_lure"), {})
        finally:
            sys.pycache_prefix = previous_prefix
            sys.dont_write_bytecode = previous_writes

    @unittest.skipUnless(STOCK, "requires the pinned Linux stock 3.13.16 producer")
    def test_stock_sources_beyond_old_closure_resolve_from_verified_bytes(self):
        snapshot = installed_stock_snapshot()
        events, active = [], [True]
        def audit(event, args):
            if active[0] and event in {"open", "os.listdir", "os.scandir"}:
                events.append((event, args))
        sys.addaudithook(audit)
        try:
            with closed_imports(snapshot, ("decimal", "_pydecimal", "numbers", "email", "xml", "json", "importlib.resources")) as namespace:
                decimal = importlib.import_module("decimal")
                message = importlib.import_module("email.message")
                etree = importlib.import_module("xml.etree.ElementTree")
                json_module = importlib.import_module("json")
                self.assertEqual(decimal.Decimal("0.1") + decimal.Decimal("0.2"), decimal.Decimal("0.3"))
                self.assertEqual(message.EmailMessage()["Subject"], None)
                self.assertEqual(etree.fromstring("<answer>42</answer>").text, "42")
                self.assertEqual(json_module.loads('{"answer":42}'), {"answer": 42})
                for module in (decimal, message, etree, json_module, namespace["_resources"]):
                    self.assertTrue(module.__file__.startswith("glue://" + APP_ID + "/stdlib/"))
                    self.assertIsNone(module.__cached__)
                self.assertIn("read\tstdlib/decimal.py", snapshot.calls)
                self.assertIn("read\tstdlib/email/message.py", snapshot.calls)
                self.assertIn("read\tstdlib/xml/etree/ElementTree.py", snapshot.calls)
        finally:
            active[0] = False
        self.assertEqual(events, [])

    @unittest.skipUnless(STOCK, "requires the pinned Linux stock 3.13.16 producer")
    def test_stock_frozen_modules_keep_runtime_precedence_over_snapshot_sources(self):
        snapshot = installed_stock_snapshot()
        with closed_imports(snapshot, ("abc", "os", "io")):
            for name in ("abc", "os", "io"):
                module = importlib.import_module(name)
                self.assertEqual(module.__spec__.origin, "frozen")
                self.assertIs(module.__loader__, importlib.machinery.FrozenImporter)
                self.assertNotIn("read\tstdlib/" + name + ".py", snapshot.calls)


if __name__ == "__main__":
    unittest.main()
