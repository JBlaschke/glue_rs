#!/usr/bin/env python3
"""Contract tests for external evidence preparation and safe restoration."""
import argparse
import gzip
import hashlib
import importlib.util
import io
import json
import os
from pathlib import Path
import shutil
import shlex
import stat
import subprocess
import sys
import tarfile
import tempfile
import unittest
from types import SimpleNamespace
from unittest import mock

SPEC = importlib.util.spec_from_file_location("evidence_bundle", Path(__file__).with_name("evidence-bundle.py"))
B = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(B)


class BundleTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name)
        self.source = self.root / "source"
        self.source.mkdir()
        self.index = self.root / "source.sha256"
        self.output = self.root / "prepared"
        self.files = {"ordinary.txt": b"exact bytes\x00\xff\n", "owned inputs ü/sub/δ.txt": b"unicode\n"}
        for path, data in self.files.items():
            target = self.source / path
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_bytes(data)
        os.chmod(self.source / "ordinary.txt", 0o751)
        self.write_index()

    def tearDown(self):
        self.temp.cleanup()

    def write_index(self, rows=None):
        rows = rows or {p: hashlib.sha256(data).hexdigest() for p, data in self.files.items()}
        self.index.write_bytes(B.index_bytes(rows))

    def prepare(self, output=None):
        return B.prepare(argparse.Namespace(source_root=str(self.source), inventory=str(self.index),
                output=str(output or self.output), max_files=100, max_bytes=1024 * 1024))

    def restore(self, output=None):
        return B.restore(argparse.Namespace(archive=str(self.output / "evidence.tar.gz"),
                metadata=str(self.output / "prepared.json"), inventory=str(self.output / "bundle-payload.sha256"),
                output=str(output or self.root / "restored"), max_files=100, max_bytes=1024 * 1024))

    def rewrite_archive(self, mutate):
        archive_path = self.output / "evidence.tar.gz"
        with tarfile.open(archive_path, "r:gz") as archive:
            members = [(member, archive.extractfile(member).read()) for member in archive]
        members = mutate(members)
        with open(archive_path, "wb") as raw:
            with gzip.GzipFile(filename="", mode="wb", fileobj=raw, mtime=0) as zipped:
                with tarfile.open(fileobj=zipped, mode="w|", format=tarfile.PAX_FORMAT) as archive:
                    for member, data in members:
                        archive.addfile(member, io.BytesIO(data) if member.isreg() else None)
        metadata_path = self.output / "prepared.json"
        metadata = json.loads(metadata_path.read_text())
        metadata.update(size=archive_path.stat().st_size, sha256=B.digest(archive_path))
        metadata_path.write_bytes(B.canonical(metadata))

    def test_roundtrip_unicode_permissions_and_determinism(self):
        metadata = self.prepare()
        other = self.root / "second"
        self.assertEqual(metadata, self.prepare(other))
        self.assertEqual((self.output / "evidence.tar.gz").read_bytes(), (other / "evidence.tar.gz").read_bytes())
        self.restore()
        for path, expected in self.files.items():
            actual = self.root / "restored" / "payload" / path
            self.assertEqual(actual.read_bytes(), expected)
        self.assertEqual(stat.S_IMODE((self.root / "restored/payload/ordinary.txt").stat().st_mode), 0o751)
        self.assertEqual(self.index.read_bytes(), (self.root / "restored/source-inventory.sha256").read_bytes())
        self.assertFalse((self.output / "bundle.json").exists())

    def test_contained_parent_alias_preserves_logical_names(self):
        (self.source / "alias").symlink_to("owned inputs ü", target_is_directory=True)
        self.files["alias/sub/δ.txt"] = self.files["owned inputs ü/sub/δ.txt"]
        self.write_index()
        self.prepare()
        self.restore()
        alias_copy = self.root / "restored/payload/alias/sub/δ.txt"
        self.assertEqual(alias_copy.read_bytes(), b"unicode\n")
        self.assertFalse(alias_copy.parent.parent.is_symlink())

    def test_parent_components_follow_symlink_semantics(self):
        (self.source / "deep/inner").mkdir(parents=True)
        (self.source / "deep/value").write_bytes(b"correct")
        (self.source / "value").write_bytes(b"incorrect")
        (self.source / "first").symlink_to("deep/inner", target_is_directory=True)
        (self.source / "alias").symlink_to("first/..", target_is_directory=True)
        self.write_index({"alias/value": hashlib.sha256(b"correct").hexdigest()})
        self.prepare()
        self.restore()
        self.assertEqual((self.root / "restored/payload/alias/value").read_bytes(), b"correct")

    def test_escaping_parent_alias_rejected(self):
        external = self.root / "external"
        external.mkdir()
        (external / "file").write_bytes(b"outside")
        (self.source / "escape").symlink_to(external, target_is_directory=True)
        self.write_index({"escape/file": hashlib.sha256(b"outside").hexdigest()})
        with self.assertRaises(B.Invalid):
            self.prepare()
        self.assertFalse(self.output.exists())

    def test_final_symlink_hardlink_special_mode_and_fifo_rejected(self):
        for kind in ("symlink", "hardlink", "fifo"):
            with self.subTest(kind=kind):
                special = self.source / "special"
                if kind == "symlink":
                    special.symlink_to("ordinary.txt")
                elif kind == "hardlink":
                    os.link(self.source / "ordinary.txt", special)
                else:
                    os.mkfifo(special)
                self.write_index({"special": hashlib.sha256(b"x").hexdigest()})
                with self.assertRaises(B.Invalid):
                    self.prepare()
                special.unlink()
        with self.assertRaises(B.Invalid):
            B.ordinary(SimpleNamespace(st_mode=stat.S_IFREG | 0o4755, st_nlink=1))

    def test_inventory_malformed_traversal_duplicates_and_parent_file(self):
        sha = "0" * 64
        for raw in (f"{sha}  ../escape\n", f"{sha}  /absolute\n", f"{sha}  a\\b\n",
                    f"{sha}  a\n{sha}  a\n", f"{sha}  a\n{sha}  a/b\n", "invalid\n"):
            with self.subTest(raw=raw):
                with self.assertRaises(B.Invalid):
                    B.parse_index(raw.encode(), 100)

    def test_changed_source_fails_and_preserves_existing_output(self):
        (self.source / "ordinary.txt").write_bytes(b"changed")
        with self.assertRaises(B.Invalid):
            self.prepare()
        self.assertFalse(self.output.exists())
        self.output.mkdir()
        marker = self.output / "keep"
        marker.write_bytes(b"original")
        with self.assertRaises(B.Invalid):
            self.prepare()
        self.assertEqual(marker.read_bytes(), b"original")

    def test_concurrent_source_replacement_detected(self):
        fd = os.open(self.source, os.O_RDONLY | os.O_DIRECTORY)
        try:
            with self.assertRaises(B.Invalid):
                with B.source_file(fd, self.source, "ordinary.txt") as (handle, info):
                    replacement = self.source / "replacement"
                    replacement.write_bytes(handle.read())
                    os.replace(replacement, self.source / "ordinary.txt")
        finally:
            os.close(fd)

    def test_fifo_replacement_open_is_nonblocking_and_rejected(self):
        real_open = os.open
        def replace_before_open(path, flags, *args, **kwargs):
            if path == "ordinary.txt":
                self.assertTrue(flags & os.O_NONBLOCK)
                (self.source / "ordinary.txt").unlink()
                os.mkfifo(self.source / "ordinary.txt")
            return real_open(path, flags, *args, **kwargs)
        fd = real_open(self.source, os.O_RDONLY | os.O_DIRECTORY)
        try:
            with mock.patch.object(B.os, "open", side_effect=replace_before_open):
                with self.assertRaises(B.Invalid):
                    with B.source_file(fd, self.source, "ordinary.txt"):
                        self.fail("replacement FIFO accepted")
        finally:
            os.close(fd)

    def test_payload_hash_checked_after_valid_compressed_identity(self):
        self.prepare()
        def mutate(members):
            for index, (member, data) in enumerate(members):
                if member.name.startswith("payload/"):
                    members[index] = (member, b"!" * len(data))
                    break
            return members
        self.rewrite_archive(mutate)
        with self.assertRaises(B.Invalid):
            self.restore()
        self.assertFalse((self.root / "restored").exists())

    def test_corruption_and_truncation_fail_without_output(self):
        self.prepare()
        path = self.output / "evidence.tar.gz"
        original = path.read_bytes()
        for content in (original[:-4], original[:20] + b"bad" + original[23:]):
            path.write_bytes(content)
            with self.assertRaises(B.Invalid):
                self.restore()
            self.assertFalse((self.root / "restored").exists())
        path.write_bytes(original)

    def test_unexpected_duplicate_missing_traversal_link_device_mode_rejected(self):
        self.prepare()
        original = self.root / "original"
        shutil.copytree(self.output, original)
        for kind in ("unexpected", "duplicate", "missing", "traversal", "symlink", "hardlink", "device", "mode", "oversize"):
            with self.subTest(kind=kind):
                shutil.rmtree(self.output)
                shutil.copytree(original, self.output)
                def mutate(members):
                    member, data = members[-1]
                    if kind == "unexpected":
                        member.name = "payload/unlisted"
                    elif kind == "duplicate":
                        return members + [members[-1]]
                    elif kind == "missing":
                        return members[:-1]
                    elif kind == "traversal":
                        member.name = "../escape"
                        member.pax_headers = {}
                    elif kind in ("symlink", "hardlink", "device"):
                        member.type = {"symlink": tarfile.SYMTYPE, "hardlink": tarfile.LNKTYPE, "device": tarfile.CHRTYPE}[kind]
                        member.linkname = "/outside"
                        member.size = 0
                    elif kind == "mode":
                        member.mode = 0o4755
                    else:
                        member.size = 2 * 1024 * 1024
                        data = b"x" * member.size
                    return members[:-1] + [(member, data)]
                self.rewrite_archive(mutate)
                with self.assertRaises((B.Invalid, tarfile.TarError)):
                    self.restore()
                self.assertFalse((self.root / "restored").exists())
                self.assertFalse((self.root / "escape").exists())

    def test_oversized_extension_and_hidden_archive_tail_rejected(self):
        self.prepare()
        path = self.output / "evidence.tar.gz"
        original = path.read_bytes()
        metadata_path = self.output / "prepared.json"
        metadata = json.loads(metadata_path.read_text())
        for kind in ("pax", "gnu", "tail"):
            with self.subTest(kind=kind):
                info = tarfile.TarInfo("extension")
                info.size = 1024 ** 3
                info.type = tarfile.XHDTYPE if kind == "pax" else tarfile.GNUTYPE_LONGNAME
                raw = info.tobuf() if kind != "tail" else gzip.decompress(original) + tarfile.TarInfo("hidden").tobuf()
                path.write_bytes(gzip.compress(raw, mtime=0))
                metadata.update(size=path.stat().st_size, sha256=B.digest(path))
                metadata_path.write_bytes(B.canonical(metadata))
                with self.assertRaises(B.Invalid):
                    self.restore()
                self.assertFalse((self.root / "restored").exists())

    def test_sparse_pax_rejected_before_builtin_processing(self):
        self.prepare()
        def mutate(members):
            member, data = members[-1]
            member.pax_headers = {"GNU.sparse.major": "1", "GNU.sparse.minor": "0"}
            return members
        self.rewrite_archive(mutate)
        with mock.patch.object(tarfile.TarInfo, "_proc_gnusparse_10", side_effect=AssertionError("unsafe sparse parser entered")):
            with self.assertRaises(B.Invalid):
                self.restore()
        self.assertFalse((self.root / "restored").exists())

    def test_metadata_types_and_duplicate_json_fail(self):
        self.prepare()
        path = self.output / "prepared.json"
        original = path.read_bytes()
        for raw in (b"[]", b'{"schema":1,"schema":2}', B.canonical({**json.loads(original), "file_count": True})):
            with self.subTest(raw=raw):
                path.write_bytes(raw)
                with self.assertRaises(B.Invalid):
                    self.restore()
        path.write_bytes(original)

    def test_versioned_fetch_dispatch_with_offline_release_stub(self):
        self.prepare()
        pointer = json.loads((self.output / "prepared.json").read_text())
        pointer.update(repository="owner/repository", tag="evidence/test")
        (self.output / "bundle.json").write_bytes(B.canonical(pointer))
        tools = self.root / "tools"
        tools.mkdir()
        stub = tools / "gh"
        stub.write_text("#!" + sys.executable + "\nimport shutil,sys\nfrom pathlib import Path\n"
                        + "shutil.copyfile(" + repr(str(self.output / "evidence.tar.gz"))
                        + ",Path(sys.argv[sys.argv.index('--dir')+1])/'evidence.tar.gz')\n")
        stub.chmod(0o755)
        script = Path(__file__).with_name("fetch-evidence.sh")
        env = {**os.environ, "PATH": str(tools) + os.pathsep + os.environ["PATH"]}
        result = subprocess.run(["sh", str(script), str(self.output), "--output", str(self.root / "fetched")],
                                env=env, capture_output=True, text=True)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual((self.root / "fetched/payload/ordinary.txt").read_bytes(), self.files["ordinary.txt"])
        missing = subprocess.run(["sh", str(script), str(self.output)], env=env, capture_output=True)
        self.assertNotEqual(missing.returncode, 0)

    def test_legacy_fetch_remains_shell_only(self):
        legacy = self.root / "legacy"
        legacy.mkdir()
        data = b"legacy bytes\n"
        archive_path = self.root / "legacy.tar.gz"
        with tarfile.open(archive_path, "w:gz") as archive:
            member = tarfile.TarInfo("artifact.txt")
            member.size = len(data)
            archive.addfile(member, io.BytesIO(data))
        (legacy / "bundle-payload.sha256").write_bytes(B.index_bytes({"artifact.txt": hashlib.sha256(data).hexdigest()}))
        (legacy / "bundle.json").write_bytes(B.canonical({"schema": "glue-evidence-bundle-1", "repository": "owner/repository",
                "tag": "evidence/test", "asset": archive_path.name, "size": archive_path.stat().st_size, "sha256": B.digest(archive_path)}))
        tools = self.root / "shell-tools"
        tools.mkdir()
        for tool in ("wc", "tr", "sed", "head", "mktemp", "rm", "tar", "gzip", "cut", "grep", "sha256sum", "shasum"):
            executable = shutil.which(tool)
            if executable:
                (tools / tool).symlink_to(executable)
        stub = tools / "gh"
        stub.write_text("#!/bin/sh\nwhile [ \"$#\" -gt 0 ]; do\n"
                        "  if [ \"$1\" = --dir ]; then shift; destination=$1; fi\n  shift\ndone\n"
                        + "/bin/cp " + shlex.quote(str(archive_path)) + " \"$destination/legacy.tar.gz\"\n")
        stub.chmod(0o755)
        self.assertIsNone(shutil.which("python3", path=str(tools)))
        script = Path(__file__).with_name("fetch-evidence.sh")
        result = subprocess.run(["/bin/sh", str(script), str(legacy)], env={**os.environ, "PATH": str(tools)},
                                capture_output=True, text=True)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual((legacy / "artifact.txt").read_bytes(), data)

    def test_limits_and_existing_restore_output_preserved(self):
        self.prepare()
        output = self.root / "restored"
        output.mkdir()
        (output / "keep").write_bytes(b"keep")
        with self.assertRaises(B.Invalid):
            self.restore()
        self.assertEqual((output / "keep").read_bytes(), b"keep")
        with self.assertRaises(B.Invalid):
            B.parse_index(self.index.read_bytes(), 1)


if __name__ == "__main__":
    unittest.main()
