#!/bin/sh
# Build only with the reviewed stock PBS headers and selected library.
set -eu
if test "$#" -ne 3; then
    echo 'Usage: build-fixture.sh OUTPUT_DIRECTORY HEADERS LIBPYTHON' >&2
    exit 1
fi
output=$1
headers=$2
library=$3
fixture=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
test "$(uname -m)" = aarch64
"${PYTHON:-python3}" -I -S -B - "$headers" "$library" "$fixture/../python-bootstrap/header-pins.json" <<'PY'
import hashlib
import json
from pathlib import Path
import sys

headers, library, pins = map(Path, sys.argv[1:])
inventory = json.loads(pins.read_text())
actual = {p.relative_to(headers).as_posix() for p in headers.rglob('*') if p.is_file()}
assert actual == set(inventory['files']), 'header inventory differs from pinned stock PBS'
for name, pin in inventory['files'].items():
    source = headers / name
    assert not source.is_symlink(), f'symlink header: {name}'
    data = source.read_bytes()
    assert len(data) == pin['size'] and hashlib.sha256(data).hexdigest() == pin['sha256'], name
data = library.read_bytes()
assert len(data) == 73563968
assert hashlib.sha256(data).hexdigest() == '42be968275d5be2d9e632ec9ef6790dd2c10f1d4a710ad1028fc2b687242f219'
PY
mkdir -p "$output"
flags='-O2 -g0 -Wall -Wextra -Werror -fPIC -fvisibility=hidden -shared -nostdlib -Wl,--hash-style=sysv,-z,now,-z,relro,-z,noexecstack'
cc $flags -Wl,-z,defs,-soname,libglue_python_dependency.so \
    "$fixture/dependency.c" -o "$output/libglue_python_dependency.so"
for module in single multi init_error exec_error; do
    source=$(printf '%s' "$module" | tr _ -)
    cc $flags -I"$headers" -Wl,-soname,"glue_native_$module.so" \
        "$fixture/$source.c" -L"$output" -lglue_python_dependency "$library" \
        -o "$output/glue_native_$module.so"
done
cc -O2 -g0 -Wall -Wextra -Werror -I"$headers" \
    "$fixture/baseline-driver.c" -ldl -o "$output/baseline-driver"
: > "$output/artifacts.sha256"
sha256sum "$output/baseline-driver" >> "$output/artifacts.sha256"
readelf -d -r -Ws -l "$output/baseline-driver" > "$output/baseline-driver.elf.txt"
nm -u "$output/baseline-driver" > "$output/baseline-driver.imports.txt"
for image in "$output/"*.so; do
    readelf -d -r -Ws -l "$image" > "$image.elf.txt"
    nm -D --undefined-only "$image" > "$image.imports.txt"
    sha256sum "$image" >> "$output/artifacts.sha256"
done
cc --version > "$output/compiler.txt"
