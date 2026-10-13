#!/usr/bin/env python3
"""Portable checks for the metadata adapter, independent of provider evidence.

Stdlib modules are deliberately imported from the test interpreter before the
callback-only checks. The Linux harness separately proves the pinned CPython
runtime and syscall boundary; these tests prove the helper's public API usage.
"""

from contextlib import contextmanager, ExitStack
import base64
import csv
import email.parser
import email.policy
import importlib
import importlib.metadata as metadata
import importlib.metadata._adapters
import importlib.resources as resources
import importlib.resources._adapters
import importlib.util
import hashlib
import io
import json
import os
from pathlib import Path
import sys
import unittest
from unittest.mock import patch


HERE = Path(__file__).resolve().parent
HELPER = (HERE / "bootstrap.py").read_bytes()
ENTRY = (HERE / "input/app/main.py").read_bytes()
FILES = {path.relative_to(HERE / "input").as_posix(): path.read_bytes()
         for path in (HERE / "input").rglob("*") if path.is_file()}
DIST_DIR = "app/python/glue_meta_demo-1.2.3.dist-info"
SPEC = importlib.util.spec_from_file_location("metadata_test_importer_adapter", HERE.parent / "python-imports/test_importer.py")
BASE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(BASE)
ROOT_NAMES = {"glue_meta_demo", "glue_meta_namespace"}


@contextmanager
def metadata_adapter(files=None, install_helper=True):
    previous_path = list(sys.path)
    previous_hooks = list(sys.path_hooks)
    previous_cache = dict(sys.path_importer_cache)
    previous_modules = {name: value for name, value in sys.modules.items()
                        if name.split(".", 1)[0] in ROOT_NAMES}
    for name in previous_modules:
        del sys.modules[name]
    try:
        with BASE.adapter(BASE.FakeArchive(FILES if files is None else files)) as (namespace, archive):
            if install_helper:
                exec(compile(HELPER, "glue://metadata/bootstrap.py", "exec"), namespace)
            yield namespace, archive
    finally:
        sys.path[:] = previous_path
        sys.path_hooks[:] = previous_hooks
        sys.path_importer_cache.clear()
        sys.path_importer_cache.update(previous_cache)
        for name in list(sys.modules):
            if name.split(".", 1)[0] in ROOT_NAMES:
                del sys.modules[name]
        sys.modules.update(previous_modules)


@contextmanager
def prohibit_os_reads():
    def forbidden(*args, **kwargs):
        raise AssertionError("metadata query attempted a host filesystem operation")
    with ExitStack() as stack:
        for owner, name in (("builtins", "open"), (io, "open"), (os, "stat"), (os, "lstat"),
                            (os, "scandir"), (os, "listdir"), (os, "readlink")):
            if isinstance(owner, str):
                stack.enter_context(patch(owner + "." + name, forbidden))
            else:
                stack.enter_context(patch.object(owner, name, forbidden))
        yield


class MetadataTests(unittest.TestCase):
    def test_fixture_record_covers_and_hashes_every_selected_package_file(self):
        root = "app/python/"
        record = DIST_DIR + "/RECORD"
        rows = list(csv.reader(io.StringIO(FILES[record].decode("utf-8"))))
        self.assertEqual(len(rows), 7)
        self.assertEqual({root + row[0] for row in rows}, {key for key in FILES if key.startswith(root)})
        for name, digest, size in rows:
            key = root + name
            if key == record:
                self.assertEqual((digest, size), ("", ""))
            else:
                expected = base64.urlsafe_b64encode(hashlib.sha256(FILES[key]).digest()).decode("ascii").rstrip("=")
                self.assertEqual(digest, "sha256=" + expected)
                self.assertEqual(int(size), len(FILES[key]))

    def test_helper_execution_does_not_import_metadata_or_read_archive(self):
        with metadata_adapter(install_helper=False) as (namespace, archive):
            calls = len(archive.calls)
            with patch("builtins.__import__", side_effect=AssertionError("helper imported before query")):
                exec(compile(HELPER, "glue://metadata/bootstrap.py", "exec"), namespace)
            self.assertIsNone(namespace["_MetadataDistributionType"])
            self.assertEqual(len(archive.calls), calls)
            self.assertTrue(callable(namespace["_archive_finder"].find_distributions))

    def test_helper_closes_stock_path_finder_before_explicit_physical_metadata_query(self):
        with metadata_adapter(install_helper=False) as (namespace, archive):
            self.assertIn(namespace["_path_finder"], sys.meta_path)
            sys.path.append("/physical/distribution/lure")
            sys.path_importer_cache["/physical/distribution/lure"] = object()
            calls = len(archive.calls)
            with prohibit_os_reads(), patch("builtins.__import__", side_effect=AssertionError("helper imported before query")):
                exec(compile(HELPER, "glue://metadata/bootstrap.py", "exec"), namespace)
            self.assertNotIn(namespace["_path_finder"], sys.meta_path)
            self.assertEqual(sys.path, [])
            self.assertEqual(sys.path_hooks, [])
            self.assertEqual(sys.path_importer_cache, {})
            self.assertEqual(len(archive.calls), calls)
            with prohibit_os_reads():
                self.assertEqual(list(metadata.distributions(path=["/physical/distribution/lure"])), [])

    def test_public_functions_are_preserved(self):
        functions = {name: getattr(metadata, name) for name in
                     ("version", "metadata", "requires", "entry_points", "files", "packages_distributions", "distribution", "distributions")}
        with metadata_adapter():
            for name, function in functions.items():
                self.assertIs(getattr(metadata, name), function)

    def test_distribution_subclasses_public_distribution(self):
        with metadata_adapter() as (namespace, _):
            distribution = metadata.distribution("glue-meta-demo")
            self.assertIsInstance(distribution, metadata.Distribution)
            self.assertNotIsInstance(distribution, metadata.PathDistribution)
            self.assertIsInstance(distribution, namespace["_MetadataDistributionType"])

    def test_name_normalization_and_version(self):
        with metadata_adapter(), prohibit_os_reads():
            for name in ("Glue.Meta-Demo", "glue_meta_demo", "GLUE--META___DEMO", "glue...meta-demo"):
                self.assertEqual(metadata.version(name), "1.2.3")

    def test_metadata_and_requirements_are_stock_parsed(self):
        with metadata_adapter(), prohibit_os_reads():
            message = metadata.metadata("glue-meta-demo")
            self.assertEqual(message["Name"], "Glue.Meta-Demo")
            self.assertEqual(message["Version"], "1.2.3")
            self.assertEqual(message["Provides-Extra"], "test")
            self.assertEqual(metadata.requires("glue-meta-demo"), ['Glue-Optional>=1; extra == "test"'])

    def test_missing_distribution_has_normal_package_not_found(self):
        with metadata_adapter(), prohibit_os_reads():
            for name in ("absent", "glue/invalid", "glue méta", "-glue", "glue-", "glue\tmeta"):
                with self.subTest(name=name), self.assertRaises(metadata.PackageNotFoundError):
                    metadata.version(name)

    def test_finder_rejects_non_string_search_names(self):
        with metadata_adapter() as (namespace, _), prohibit_os_reads():
            finder = namespace["_archive_finder"]
            for name in (42, b"glue-meta-demo", [], object()):
                with self.subTest(name=name), self.assertRaises(TypeError):
                    list(finder.find_distributions(metadata.DistributionFinder.Context(name=name)))

    def test_empty_search_name_direct_finder_returns_no_distribution(self):
        with metadata_adapter() as (namespace, _):
            self.assertEqual(list(namespace["_archive_finder"].find_distributions(metadata.DistributionFinder.Context(name=""))), [])

    def test_default_context_discovers_archive_with_empty_sys_path(self):
        with metadata_adapter(), prohibit_os_reads():
            self.assertEqual(sys.path, [])
            self.assertEqual([distribution.name for distribution in metadata.distributions()], ["Glue.Meta-Demo"])

    def test_explicit_empty_path_excludes_archive(self):
        with metadata_adapter(), prohibit_os_reads():
            self.assertEqual(list(metadata.distributions(path=[])), [])

    def test_unrelated_paths_are_never_coerced_or_scanned(self):
        class HostPath:
            def __fspath__(self):
                raise AssertionError("an unrelated OS path was coerced")
        with metadata_adapter(), prohibit_os_reads():
            self.assertEqual(list(metadata.distributions(path=["/physical/lure", "app/python", HostPath()])), [])

    def test_explicit_virtual_root_selects_archive(self):
        with metadata_adapter() as (namespace, _), prohibit_os_reads():
            origin = namespace["_origin"]("app/python")
            distributions = list(metadata.distributions(path=["/physical/lure", origin], name="GLUE_META_DEMO"))
            self.assertEqual([distribution.name for distribution in distributions], ["Glue.Meta-Demo"])

    def test_entry_point_selection_and_load_use_archive_importer(self):
        with metadata_adapter(), prohibit_os_reads():
            entries = metadata.entry_points(group="glue.archive.plugins", name="answer")
            self.assertEqual(len(entries), 1)
            entry = next(iter(entries))
            self.assertEqual(entry.value, "glue_meta_demo:plugin")
            self.assertEqual(entry.load()(), 42)
            self.assertEqual(entry.dist.name, "Glue.Meta-Demo")
            self.assertTrue(sys.modules["glue_meta_demo"].__file__.startswith("glue://"))

    def test_top_level_mapping_includes_namespace(self):
        with metadata_adapter(), prohibit_os_reads():
            mapping = metadata.packages_distributions()
            self.assertEqual(mapping["glue_meta_demo"], ["Glue.Meta-Demo"])
            self.assertEqual(mapping["glue_meta_namespace"], ["Glue.Meta-Demo"])
            self.assertEqual(importlib.import_module("glue_meta_namespace.part").answer, 42)

    def test_missing_optional_metadata_is_none(self):
        with metadata_adapter(), prohibit_os_reads():
            distribution = metadata.distribution("glue-meta-demo")
            self.assertIsNone(distribution.read_text("missing.txt"))
            self.assertIsNone(distribution.read_text("direct_url.json"))
            self.assertIsNone(distribution.origin)

    def test_metadata_text_reads_are_strict_utf8(self):
        files = dict(FILES)
        files[DIST_DIR + "/optional.txt"] = b"invalid \xff utf8"
        with metadata_adapter(files), prohibit_os_reads():
            with self.assertRaises(UnicodeDecodeError):
                metadata.distribution("glue-meta-demo").read_text("optional.txt")

    def test_missing_entry_points_and_top_level_have_stock_fallback(self):
        files = dict(FILES)
        del files[DIST_DIR + "/entry_points.txt"]
        del files[DIST_DIR + "/top_level.txt"]
        with metadata_adapter(files), prohibit_os_reads():
            self.assertEqual(list(metadata.entry_points(group="glue.archive.plugins")), [])
            self.assertEqual(metadata.packages_distributions()["glue_meta_demo"], ["Glue.Meta-Demo"])

    def test_record_uses_public_package_paths_with_hash_and_size(self):
        with metadata_adapter(), prohibit_os_reads():
            paths = {str(path): path for path in metadata.files("glue-meta-demo")}
            resource = paths["glue_meta_demo/data/message,one.txt"]
            self.assertIsInstance(resource, metadata.PackagePath)
            self.assertEqual(resource.hash.mode, "sha256")
            self.assertEqual(resource.size, 26)
            self.assertEqual(resource.read_binary(), b"archive metadata resource\n")
            self.assertEqual(resource.read_text(), "archive metadata resource\n")

    def test_record_self_entry_has_no_hash_or_size(self):
        with metadata_adapter(), prohibit_os_reads():
            record = next(path for path in metadata.files("glue-meta-demo") if str(path).endswith(".dist-info/RECORD"))
            self.assertIsNone(record.hash)
            self.assertIsNone(record.size)
            self.assertIn('"glue_meta_demo/data/message,one.txt",sha256=', record.read_text())

    def test_located_files_have_virtual_streams_and_exists(self):
        with metadata_adapter() as (namespace, _), prohibit_os_reads():
            distribution = metadata.distribution("glue-meta-demo")
            path = distribution.locate_file("glue_meta_demo/data/message,one.txt")
            self.assertIsInstance(path, namespace["_ArchivePath"])
            self.assertTrue(path.exists())
            self.assertEqual(str(path), namespace["_origin"](path._key))
            with path.open("rb") as stream:
                self.assertEqual(stream.read(), b"archive metadata resource\n")
            self.assertFalse(distribution.locate_file("missing.txt").exists())

    def test_locate_empty_relative_path_is_virtual_package_root(self):
        with metadata_adapter(), prohibit_os_reads():
            path = metadata.distribution("glue-meta-demo").locate_file("")
            self.assertEqual(path._key, "app/python")
            self.assertTrue(path.is_dir())
            self.assertTrue(path.exists())

    def test_located_path_attributes_are_immutable(self):
        with metadata_adapter():
            path = metadata.distribution("glue-meta-demo").locate_file("")
            with self.assertRaises(AttributeError):
                path._key = "/host/lure"
            with self.assertRaises(AttributeError):
                del path._key

    def test_metadata_path_materialization_and_os_coercion_are_rejected(self):
        with metadata_adapter(), prohibit_os_reads():
            path = metadata.distribution("glue-meta-demo").locate_file("glue_meta_demo/data/message,one.txt")
            with self.assertRaises(TypeError):
                os.fspath(path)
            with self.assertRaisesRegex(RuntimeError, "cannot be materialized"):
                resources.as_file(path)

    def test_metadata_path_streams_are_read_only(self):
        with metadata_adapter(), prohibit_os_reads():
            path = metadata.distribution("glue-meta-demo").locate_file("glue_meta_demo/data/message,one.txt")
            with self.assertRaises(io.UnsupportedOperation):
                path.open("wb")

    def test_metadata_filename_and_locate_paths_reject_escape(self):
        with metadata_adapter(), prohibit_os_reads():
            distribution = metadata.distribution("glue-meta-demo")
            for name in ("../METADATA", "/tmp/METADATA", "a/../../METADATA", "a\\METADATA", "glue://physical/METADATA"):
                with self.subTest(name=name), self.assertRaises(ValueError):
                    distribution.read_text(name)
                with self.subTest(name=name), self.assertRaises(ValueError):
                    distribution.locate_file(name)

    def test_locate_does_not_coerce_host_path_objects(self):
        class HostPath:
            def __fspath__(self):
                raise AssertionError("host path coercion")
        with metadata_adapter(), prohibit_os_reads():
            with self.assertRaises(TypeError):
                metadata.distribution("glue-meta-demo").locate_file(HostPath())

    def test_only_top_level_dist_info_directories_are_discovered(self):
        files = dict(FILES)
        files["app/python/glue_meta_demo/nested-9.dist-info/METADATA"] = b"Name: Nested\nVersion: 9\n"
        files["app/python/unclaimed.egg-info/PKG-INFO"] = b"Name: Egg-Lure\nVersion: 9\n"
        files["app/python/lure-9.dist-info"] = b"not a directory"
        files["outside/physical-9.dist-info/METADATA"] = b"Name: Physical\nVersion: 9\n"
        with metadata_adapter(files), prohibit_os_reads():
            self.assertEqual([distribution.name for distribution in metadata.distributions()], ["Glue.Meta-Demo"])

    def test_absent_archive_package_root_has_no_distributions(self):
        with metadata_adapter({"app/main.py": b"pass\n"}), prohibit_os_reads():
            self.assertEqual(list(metadata.distributions()), [])

    def test_unrelated_metadata_finders_are_preserved(self):
        class OtherFinder:
            def find_distributions(self, context):
                return iter(())
        with metadata_adapter(install_helper=False) as (namespace, _):
            other = OtherFinder()
            sys.meta_path.append(other)
            finders = list(sys.meta_path)
            exec(compile(HELPER, "glue://metadata/bootstrap.py", "exec"), namespace)
            self.assertEqual(sys.meta_path, [finder for finder in finders if finder is not namespace["_path_finder"]])
            self.assertIs(sys.meta_path[-1], other)

    def test_runtime_assertion_application(self):
        with metadata_adapter(), prohibit_os_reads(), patch("sys.stdout", new_callable=io.StringIO) as output:
            exec(compile(ENTRY, "glue://metadata/app/main.py", "exec"), {"__name__": "__main__"})
            self.assertEqual(output.getvalue(), "glue python distribution metadata ok: version=1.2.3 plugin=42 files=7\n")


if __name__ == "__main__":
    unittest.main()
