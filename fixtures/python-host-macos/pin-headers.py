"""Record the exact installed header tree of a pinned PBS artifact.

usage: python3 -I fixtures/python-host-macos/pin-headers.py INCLUDE_DIR ARTIFACT_SHA256 OUTPUT.json

Every regular file below INCLUDE_DIR is hashed; the result mirrors the shape of
fixtures/python-bootstrap/header-pins.json and is consumed by the build script.
"""

import hashlib
import json
import os
import sys


def main(argv):
    if len(argv) != 4:
        raise SystemExit(__doc__)
    include_dir, artifact_sha256, output = argv[1:]
    if len(artifact_sha256) != 64 or any(c not in "0123456789abcdef" for c in artifact_sha256):
        raise SystemExit("artifact SHA-256 must be 64 lowercase hex digits")
    files = {}
    for root, directories, names in os.walk(include_dir):
        directories.sort()
        for name in sorted(names):
            path = os.path.join(root, name)
            if os.path.islink(path) or not os.path.isfile(path):
                raise SystemExit(f"unexpected non-regular header entry: {path}")
            relative = os.path.relpath(path, include_dir).replace(os.sep, "/")
            with open(path, "rb") as handle:
                data = handle.read()
            files[relative] = {"sha256": hashlib.sha256(data).hexdigest(), "size": len(data)}
    if not files:
        raise SystemExit("no header files found")
    with open(output, "w", encoding="ascii") as handle:
        json.dump({"artifact_sha256": artifact_sha256, "files": dict(sorted(files.items()))}, handle, indent=2, sort_keys=False)
        handle.write("\n")
    print(f"pinned {len(files)} headers, {sum(f['size'] for f in files.values())} bytes")


if __name__ == "__main__":
    main(sys.argv)
