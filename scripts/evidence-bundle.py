#!/usr/bin/env python3
"""Prepare and safely restore explicitly indexed external evidence; never publish."""
import argparse
import contextlib
import gzip
import hashlib
import json
import os
from pathlib import Path, PurePosixPath
import re
import shutil
import stat
import subprocess
import sys
import tarfile
import tempfile

SCHEMA = "glue-evidence-bundle-2"
PROFILE = "external-root-v1"
META_LIMIT = 64 * 1024
INDEX_LIMIT = 32 * 1024 * 1024
MANIFEST_LIMIT = 32 * 1024 * 1024
DEFAULT_FILES = 100000
DEFAULT_BYTES = 32 * 1024 ** 3
CHUNK = 1024 * 1024


class Invalid(ValueError):
    pass


def require(condition, message):
    if not condition:
        raise Invalid(message)


def name(value):
    require(isinstance(value, str) and value and "\\" not in value,
            "invalid relative name")
    require(not any(ord(c) < 32 or ord(c) == 127 for c in value), "control in name")
    require(not value.startswith("/") and all(p not in ("", ".", "..")
            for p in value.split("/")), "escaping or noncanonical name")
    require(len(value.encode("utf-8", "strict")) <= 4096, "relative name exceeds bound")
    return value


def bounded(path, limit):
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    with os.fdopen(fd, "rb") as handle:
        before = os.fstat(handle.fileno())
        require(stat.S_ISREG(before.st_mode) and before.st_size <= limit, "metadata type/size exceeds bound")
        result = handle.read(limit + 1)
        require(identity(before) == identity(os.fstat(handle.fileno())), "metadata changed while reading")
    require(len(result) <= limit, "metadata exceeds bound")
    return result


def decode_json(raw):
    def pairs(items):
        result = {}
        for key, value in items:
            require(key not in result, "duplicate JSON key")
            result[key] = value
        return result
    return json.loads(raw, object_pairs_hook=pairs,
                      parse_constant=lambda value: (_ for _ in ()).throw(Invalid("invalid JSON constant")))


def canonical(value):
    return (json.dumps(value, ensure_ascii=False, sort_keys=True, indent=2) + "\n").encode("utf-8")


def digest(path):
    result = hashlib.sha256()
    with open(path, "rb") as handle:
        for chunk in iter(lambda: handle.read(CHUNK), b""):
            result.update(chunk)
    return result.hexdigest()


def parse_index(raw, max_files):
    require(raw.endswith(b"\n"), "inventory must end with newline")
    rows = {}
    for line in raw.decode("utf-8", "strict").split("\n")[:-1]:
        require(re.fullmatch(r"[0-9a-f]{64}  .+", line) is not None, "malformed inventory")
        path = name(line[66:])
        require(path not in rows, "duplicate inventory path")
        rows[path] = line[:64]
        require(len(rows) <= max_files, "inventory file count exceeds bound")
    require(rows, "empty inventory")
    for path in rows:
        parent = PurePosixPath(path).parent
        while str(parent) != ".":
            require(str(parent) not in rows, "inventory file is also a parent")
            parent = parent.parent
    return rows


def index_bytes(rows):
    return "".join(f"{rows[path]}  {path}\n" for path in sorted(rows)).encode("utf-8")


def identity(info):
    return (info.st_dev, info.st_ino, info.st_size, info.st_mtime_ns,
            info.st_ctime_ns, info.st_mode, info.st_nlink)


def ordinary(info):
    require(stat.S_ISREG(info.st_mode), "source/member is not an ordinary file")
    require(info.st_nlink == 1, "source hard links are not allowed")
    require(not info.st_mode & 0o7000, "special permissions are not allowed")


@contextlib.contextmanager
def source_file(root_fd, root_path, logical):
    """Resolve parent aliases only, opening every component relative to held FDs."""
    remaining = logical.split("/")
    resolved = []
    aliases = 0
    current = os.dup(root_fd)
    try:
        while len(remaining) > 1:
            part = remaining.pop(0)
            if part == ".":
                continue
            if part == "..":
                require(resolved, "source alias escapes source root")
                resolved.pop()
                os.close(current)
                current = os.dup(root_fd)
                for component in resolved:
                    opened = os.open(component, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=current)
                    os.close(current)
                    current = opened
                continue
            before = os.stat(part, dir_fd=current, follow_symlinks=False)
            if stat.S_ISLNK(before.st_mode):
                aliases += 1
                require(aliases <= 40, "too many source parent aliases")
                target = os.readlink(part, dir_fd=current)
                after = os.stat(part, dir_fd=current, follow_symlinks=False)
                require(identity(before) == identity(after), "source alias changed")
                if target.startswith("/"):
                    try:
                        target = str(Path(target).relative_to(root_path))
                    except ValueError as error:
                        raise Invalid("source alias escapes source root") from error
                    resolved = []
                    os.close(current)
                    current = os.dup(root_fd)
                parts = [component for component in target.split("/") if component and component != "."]
                for component in parts:
                    if component != "..":
                        name(component)
                # Resolve .. only after preceding symlinks, preserving filesystem semantics.
                remaining = parts + remaining
                continue
            require(stat.S_ISDIR(before.st_mode), "source parent is not a directory")
            opened = os.open(part, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=current)
            if identity(before) != identity(os.fstat(opened)):
                os.close(opened)
                raise Invalid("source parent changed")
            os.close(current)
            current = opened
            resolved.append(part)
        leaf = remaining[0]
        before = os.stat(leaf, dir_fd=current, follow_symlinks=False)
        ordinary(before)
        fd = os.open(leaf, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=current)
        with os.fdopen(fd, "rb") as handle:
            require(identity(before) == identity(os.fstat(handle.fileno())), "source file changed")
            yield handle, before
            require(identity(before) == identity(os.fstat(handle.fileno())), "source changed while copying")
            require(identity(before) == identity(os.stat(leaf, dir_fd=current, follow_symlinks=False)),
                    "source was replaced while copying")
    finally:
        os.close(current)


def copy_hash(source, destination, expected, max_size):
    total = 0
    result = hashlib.sha256()
    with open(destination, "xb") as output:
        while True:
            chunk = source.read(CHUNK)
            if not chunk:
                break
            total += len(chunk)
            require(total <= max_size, "file exceeds declared size or byte bound")
            result.update(chunk)
            output.write(chunk)
    require(result.hexdigest() == expected, "file SHA-256 mismatch")
    return total


@contextlib.contextmanager
def staging(output):
    output = Path(output).absolute()
    parent = output.parent.resolve(strict=True)
    leaf = name(output.name)
    parent_fd = os.open(parent, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    stage = None
    try:
        try:
            os.stat(leaf, dir_fd=parent_fd, follow_symlinks=False)
        except FileNotFoundError:
            pass
        else:
            raise Invalid("output must be a new path")
        stage = Path(tempfile.mkdtemp(prefix=".glue-evidence-stage-", dir=parent))
        yield stage
        # Exclusive creation never replaces an existing path, even in a race.
        os.mkdir(leaf, 0o700, dir_fd=parent_fd)
        output_fd = os.open(leaf, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=parent_fd)
        owned = os.fstat(output_fd)
        stage_fd = os.open(stage.name, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=parent_fd)
        try:
            for child in os.listdir(stage_fd):
                require(identity(owned)[:2] == identity(os.stat(leaf, dir_fd=parent_fd, follow_symlinks=False))[:2],
                        "output directory was replaced")
                os.rename(child, child, src_dir_fd=stage_fd, dst_dir_fd=output_fd)
            os.fchmod(output_fd, 0o755)
            require(identity(owned)[:2] == identity(os.stat(leaf, dir_fd=parent_fd, follow_symlinks=False))[:2],
                    "output directory was replaced")
        except BaseException:
            now = os.stat(leaf, dir_fd=parent_fd, follow_symlinks=False)
            if (now.st_dev, now.st_ino) == (owned.st_dev, owned.st_ino):
                shutil.rmtree(parent / leaf)
            raise
        finally:
            os.close(stage_fd)
            os.close(output_fd)
    finally:
        if stage is not None:
            shutil.rmtree(stage)
        os.close(parent_fd)


def make_archive(stage, rows, destination, modes):
    with open(destination, "xb") as raw:
        with gzip.GzipFile(filename="", mode="wb", fileobj=raw, mtime=0, compresslevel=9) as zipped:
            with tarfile.open(fileobj=zipped, mode="w|", format=tarfile.USTAR_FORMAT) as archive:
                for path in sorted(rows):
                    # PAX handles long and Unicode names deterministically; no directory entries needed.
                    info = tarfile.TarInfo(path)
                    info.size = (stage / path).stat().st_size
                    info.mode = modes.get(path, 0o644)
                    info.uid = info.gid = info.mtime = 0
                    info.uname = info.gname = ""
                    with open(stage / path, "rb") as handle:
                        # A fresh per-member PAX header has only the necessary path metadata.
                        if not path.isascii() or len(path.encode("utf-8")) > 100:
                            archive.format = tarfile.PAX_FORMAT
                        archive.addfile(info, handle)


def prepare(args):
    raw_index = bounded(args.inventory, INDEX_LIMIT)
    sources = parse_index(raw_index, args.max_files)
    root = Path(args.source_root).resolve(strict=True)
    root_fd = os.open(root, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try:
        with staging(args.output) as stage:
            entries = []
            rows = {}
            modes = {}
            total = 0
            for logical, expected in sorted(sources.items()):
                target = "payload/" + logical
                destination = stage / target
                destination.parent.mkdir(parents=True, exist_ok=True)
                with source_file(root_fd, root, logical) as (source, info):
                    require(info.st_size <= args.max_bytes - total, "source byte total exceeds bound")
                    size = copy_hash(source, destination, expected, info.st_size)
                    require(size == info.st_size, "source size changed")
                    mode = stat.S_IMODE(info.st_mode)
                    os.chmod(destination, mode)
                total += size
                entries.append({"path": logical, "size": size, "sha256": expected, "mode": mode})
                rows[target] = expected
                modes[target] = mode
            manifest = canonical({"schema": PROFILE, "files": entries, "total_bytes": total})
            require(len(manifest) <= MANIFEST_LIMIT, "manifest exceeds bound")
            (stage / "manifest.json").write_bytes(manifest)
            (stage / "source-inventory.sha256").write_bytes(raw_index)
            rows["manifest.json"] = hashlib.sha256(manifest).hexdigest()
            rows["source-inventory.sha256"] = hashlib.sha256(raw_index).hexdigest()
            complete = index_bytes(rows)
            require(len(complete) <= INDEX_LIMIT, "complete inventory exceeds bound")
            (stage / "bundle-payload.sha256").write_bytes(complete)
            archive = stage / "evidence.tar.gz"
            make_archive(stage, rows, archive, modes)
            metadata = {"schema": SCHEMA, "profile": PROFILE, "asset": archive.name,
                        "size": archive.stat().st_size, "sha256": digest(archive),
                        "inventory_sha256": hashlib.sha256(complete).hexdigest(),
                        "file_count": len(rows), "payload_bytes": total,
                        "source_inventory_sha256": rows["source-inventory.sha256"]}
            (stage / "prepared.json").write_bytes(canonical(metadata))
    finally:
        os.close(root_fd)
    return metadata


def metadata_and_inventory(args):
    metadata = decode_json(bounded(args.metadata, META_LIMIT))
    require(isinstance(metadata, dict), "metadata must be an object")
    require(metadata.get("schema") == SCHEMA and metadata.get("profile") == PROFILE,
            "unsupported bundle profile")
    raw = bounded(args.inventory, INDEX_LIMIT)
    require(hashlib.sha256(raw).hexdigest() == metadata.get("inventory_sha256"),
            "complete inventory identity mismatch")
    rows = parse_index(raw, args.max_files + 2)
    require(set(p for p in rows if not p.startswith("payload/")) ==
            {"manifest.json", "source-inventory.sha256"}, "unexpected inventory member")
    require(type(metadata.get("file_count")) is int and len(rows) == metadata["file_count"], "inventory count mismatch")
    require(type(metadata.get("payload_bytes")) is int and
            0 <= metadata["payload_bytes"] <= args.max_bytes, "payload byte bound exceeded")
    return metadata, raw, rows


def validate_manifest(stage, metadata, rows, actual):
    raw = bounded(stage / "source-inventory.sha256", INDEX_LIMIT)
    require(hashlib.sha256(raw).hexdigest() == metadata.get("source_inventory_sha256"),
            "source inventory identity mismatch")
    sources = parse_index(raw, len(rows) - 2)
    require({"payload/" + p: sha for p, sha in sources.items()} ==
            {p: sha for p, sha in rows.items() if p.startswith("payload/")},
            "source and complete inventories differ")
    manifest = decode_json(bounded(stage / "manifest.json", MANIFEST_LIMIT))
    require(isinstance(manifest, dict), "manifest must be an object")
    require(manifest.get("schema") == PROFILE and isinstance(manifest.get("files"), list),
            "invalid manifest")
    expected = {}
    for entry in manifest["files"]:
        require(isinstance(entry, dict) and set(entry) == {"path", "size", "sha256", "mode"},
                "invalid manifest entry")
        require(type(entry["size"]) is int and entry["size"] >= 0 and
                type(entry["mode"]) is int and 0 <= entry["mode"] <= 0o777 and
                isinstance(entry["sha256"], str) and re.fullmatch(r"[0-9a-f]{64}", entry["sha256"]),
                "invalid manifest identity types")
        path = "payload/" + name(entry["path"])
        require(path not in expected, "duplicate manifest path")
        expected[path] = (entry["size"], entry["sha256"], entry["mode"])
    require(set(expected) == set(actual) - {"manifest.json", "source-inventory.sha256"},
            "manifest member set mismatch")
    require(all(expected[p] == actual[p] for p in expected), "manifest member identity mismatch")
    total = sum(actual[p][0] for p in expected)
    require(type(manifest.get("total_bytes")) is int and total == manifest["total_bytes"] == metadata["payload_bytes"],
            "manifest total mismatch")



class BoundedTarInfo(tarfile.TarInfo):
    """Check extension lengths before tarfile reads or allocates their contents."""
    def _proc_pax(self, archive):
        require(self.type == tarfile.XHDTYPE and 0 <= self.size <= 16384,
                "unsupported or oversized tar extension")
        return super()._proc_pax(archive)

    def _proc_gnulong(self, archive):
        raise Invalid("GNU tar name extensions are not supported")

    def _proc_sparse(self, archive):
        raise Invalid("sparse archive members are not supported")


class LimitedReader:
    def __init__(self, reader, limit):
        self.reader = reader
        self.remaining = limit

    def read(self, size):
        require(0 <= size <= self.remaining + 1, "decompressed archive exceeds bound")
        data = self.reader.read(min(size, self.remaining + 1))
        self.remaining -= len(data)
        require(self.remaining >= 0, "decompressed archive exceeds bound")
        return data


def restore(args):
    metadata, raw_index, rows = metadata_and_inventory(args)
    archive_path = Path(args.archive)
    require(type(metadata.get("size")) is int and 0 <= metadata["size"] <= args.max_bytes + MANIFEST_LIMIT + INDEX_LIMIT + 8192 * (args.max_files + 2) + 10240,
            "archive size exceeds bound")
    actual = {}
    total = 0
    payload_total = 0
    archive_fd = os.open(archive_path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    with os.fdopen(archive_fd, "rb") as raw_archive, staging(args.output) as stage:
        before = os.fstat(raw_archive.fileno())
        require(stat.S_ISREG(before.st_mode) and before.st_size == metadata["size"], "archive size/type mismatch")
        hashed = hashlib.sha256()
        for chunk in iter(lambda: raw_archive.read(CHUNK), b""):
            hashed.update(chunk)
        require(hashed.hexdigest() == metadata.get("sha256"), "archive SHA-256 mismatch")
        raw_archive.seek(0)
        with gzip.GzipFile(fileobj=raw_archive, mode="rb") as uncompressed:
            limited = LimitedReader(uncompressed, metadata["payload_bytes"] + MANIFEST_LIMIT + INDEX_LIMIT + 8192 * len(rows) + 10240)
            archive = tarfile.open(fileobj=limited, mode="r|", tarinfo=BoundedTarInfo)
            try:
                for member in archive:
                    path = name(member.name)
                    require(path in rows and path not in actual, "unexpected or duplicate archive member")
                    require(set(member.pax_headers) <= {"path"}, "unsupported archive extension metadata")
                    require(member.type == tarfile.REGTYPE and not member.linkname, "archive links and special files are forbidden")
                    require(0 <= member.mode <= 0o777 and member.uid == member.gid == member.mtime == 0,
                            "unsupported archive metadata")
                    bound = MANIFEST_LIMIT if path == "manifest.json" else INDEX_LIMIT if path == "source-inventory.sha256" else args.max_bytes
                    require(0 <= member.size <= bound, "archive member exceeds bound")
                    if path.startswith("payload/"):
                        payload_total += member.size
                        require(payload_total <= metadata["payload_bytes"], "payload exceeds committed byte total")
                    total += member.size
                    require(total <= args.max_bytes + MANIFEST_LIMIT + INDEX_LIMIT, "archive total exceeds bound")
                    destination = stage / path
                    destination.parent.mkdir(parents=True, exist_ok=True)
                    source = archive.extractfile(member)
                    require(source is not None, "missing member bytes")
                    with source:
                        size = copy_hash(source, destination, rows[path], member.size)
                    require(size == member.size, "truncated archive member")
                    os.chmod(destination, member.mode)
                    actual[path] = (size, rows[path], member.mode)
                padding = 0
                while True:
                    trailing = archive.fileobj.read(10240)
                    if not trailing:
                        break
                    padding += len(trailing)
                    require(padding <= 10240 and not trailing.strip(b"\0"),
                            "unexpected data after tar terminator")
            finally:
                archive.close()
        require(identity(before) == identity(os.fstat(raw_archive.fileno())), "archive changed during verification")
        require(set(actual) == set(rows), "archive is missing inventory members")
        validate_manifest(stage, metadata, rows, actual)
        (stage / "bundle-payload.sha256").write_bytes(raw_index)
        (stage / "prepared.json").write_bytes(canonical(metadata))
    return {"status": "verified", "file_count": len(rows), "payload_bytes": metadata["payload_bytes"],
            "archive_sha256": metadata["sha256"]}


def fetch(args):
    args.metadata = str(Path(args.directory) / "bundle.json")
    args.inventory = str(Path(args.directory) / "bundle-payload.sha256")
    metadata, _, _ = metadata_and_inventory(args)
    require(isinstance(metadata.get("repository"), str) and re.fullmatch(r"[A-Za-z0-9_-]+/[A-Za-z0-9_.-]+", metadata["repository"]),
            "invalid release repository")
    require(isinstance(metadata.get("tag"), str) and metadata["tag"] and not metadata["tag"].startswith("-"),
            "invalid release tag")
    require(isinstance(metadata.get("asset"), str) and re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._-]*", metadata["asset"]),
            "invalid release asset")
    with tempfile.TemporaryDirectory(prefix="glue-evidence-download-") as temporary:
        subprocess.run(["gh", "release", "download", metadata["tag"], "--repo", metadata["repository"],
                        "--pattern", metadata["asset"], "--dir", temporary], check=True)
        args.archive = str(Path(temporary) / metadata["asset"])
        return restore(args)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest="command", required=True)
    for command in ("prepare", "restore", "fetch"):
        sub = commands.add_parser(command)
        sub.add_argument("--output", required=True)
        sub.add_argument("--max-files", type=int, default=DEFAULT_FILES)
        sub.add_argument("--max-bytes", type=int, default=DEFAULT_BYTES)
        if command == "prepare":
            sub.add_argument("--source-root", required=True)
            sub.add_argument("--inventory", required=True)
        elif command == "restore":
            sub.add_argument("--archive", required=True)
            sub.add_argument("--metadata", required=True)
            sub.add_argument("--inventory", required=True)
        else:
            sub.add_argument("--directory", required=True)
    args = parser.parse_args()
    try:
        require(0 < args.max_files <= DEFAULT_FILES and 0 < args.max_bytes <= DEFAULT_BYTES,
                "configured limits must be positive and cannot increase defaults")
        print(json.dumps(globals()[args.command](args), sort_keys=True))
    except (Invalid, OSError, EOFError, ValueError, TypeError, tarfile.TarError, subprocess.CalledProcessError) as error:
        print(f"evidence-bundle: {error}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
