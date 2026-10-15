#!/usr/bin/env python3
"""Explicit test-only prebuilt wheel provisioning; never called by glue build.

Fetch exact named releases from PyPI only with --fetch. Verify upstream SHA-256
and retain a receipt. No package-manager, wheel hook, compiler or application runs.
"""
import argparse
import hashlib
import json
from pathlib import Path, PurePosixPath
import re
import urllib.parse
import urllib.request
import zipfile


def fetch(url, limit):
    with urllib.request.urlopen(url, timeout=30) as response:
        data = response.read(limit + 1)
    if len(data) > limit:
        raise ValueError("test input exceeds download bound")
    return data


def compatible(filename, python, target):
    if not filename.endswith(".whl"):
        return False
    _, python_tags, abi, platforms = filename[:-4].rsplit("-", 3)
    for tag in python_tags.split("."):
        if not (tag == python or tag == "py3" or
                (abi == "abi3" and tag.startswith("cp3") and int(tag[3:]) <= int(python[3:]))):
            continue
        if abi not in ("none", "abi3", python):
            continue
        if platforms == "any":
            return True
        for platform in platforms.split("."):
            if target == "macos-arm64" and platform.startswith("macosx_") and platform.endswith(("_arm64", "_universal2")):
                return True
            if target == "linux-arm64" and platform.startswith("manylinux") and platform.endswith("_aarch64"):
                return True
    return False


def unpack(wheel, output):
    with zipfile.ZipFile(wheel) as archive:
        members = archive.infolist()
        if len(members) > 100000 or sum(member.file_size for member in members) > 1024 ** 3:
            raise ValueError("test wheel inventory exceeds bounds")
        for member in members:
            name = PurePosixPath(member.filename)
            if name.is_absolute() or ".." in name.parts or "\\" in member.filename or "\0" in member.filename:
                raise ValueError("unsafe wheel member path")
            if (member.external_attr >> 16) & 0o170000 == 0o120000:
                raise ValueError("test wheel symlink is unsupported")
            destination = output.joinpath(*name.parts)
            if member.is_dir():
                destination.mkdir(parents=True, exist_ok=True)
                continue
            if destination.exists():
                raise ValueError("wheel input collision: " + str(destination))
            if member.file_size > 256 * 1024 ** 2:
                raise ValueError("test wheel member exceeds bound")
            destination.parent.mkdir(parents=True, exist_ok=True)
            with archive.open(member) as source:
                data = source.read(member.file_size + 1)
            if len(data) != member.file_size:
                raise ValueError("test wheel member size differs")
            destination.write_bytes(data)
            destination.chmod((member.external_attr >> 16) & 0o777 or 0o644)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--python", required=True, choices=["cp312", "cp313", "cp314", "cp315"])
    parser.add_argument("--target", required=True, choices=["linux-arm64", "macos-arm64"])
    parser.add_argument("--output", required=True, type=Path)
    parser.add_argument("--fetch", action="store_true", required=True)
    parser.add_argument("packages", nargs="+", help="exact name==version inputs")
    args = parser.parse_args()
    args.output.mkdir(parents=True, exist_ok=False)
    site = args.output / "site"
    site.mkdir()
    receipts = []
    for requested in args.packages:
        name, version = requested.split("==", 1)
        if not re.fullmatch(r"[A-Za-z0-9_.-]+", name + version):
            raise ValueError("invalid exact release input")
        metadata_url = "https://pypi.org/pypi/" + urllib.parse.quote(name) + "/" + urllib.parse.quote(version) + "/json"
        metadata = json.loads(fetch(metadata_url, 16 * 1024 ** 2))
        choices = sorted((item for item in metadata["urls"] if compatible(item["filename"], args.python, args.target)), key=lambda item: item["filename"])
        if not choices:
            raise ValueError("no prebuilt wheel for " + requested)
        chosen = choices[-1]
        if urllib.parse.urlparse(chosen["url"]).hostname != "files.pythonhosted.org":
            raise ValueError("unexpected wheel download host")
        data = fetch(chosen["url"], 256 * 1024 ** 2)
        if len(data) != chosen["size"] or hashlib.sha256(data).hexdigest() != chosen["digests"]["sha256"]:
            raise ValueError("wheel bytes differ from upstream identity")
        wheel = args.output / chosen["filename"]
        wheel.write_bytes(data)
        unpack(wheel, site)
        receipts.append({"release": requested, "metadata": metadata_url, "filename": chosen["filename"], "url": chosen["url"], "size": len(data), "sha256": hashlib.sha256(data).hexdigest()})
        print(requested + " " + chosen["filename"], flush=True)
    (args.output / "inputs.json").write_text(json.dumps({"test_only": True, "python": args.python, "target": args.target, "wheels": receipts}, indent=2) + "\n")


if __name__ == "__main__":
    main()
