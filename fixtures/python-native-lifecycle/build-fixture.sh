#!/bin/sh
# Reviewed fixtures only; ordinary stock loading precedes adapter capture.
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
actual = {path.relative_to(headers).as_posix() for path in headers.rglob('*') if path.is_file()}
assert actual == set(inventory['files']), 'header inventory differs from pinned stock PBS'
for name, pin in inventory['files'].items():
    path = headers / name
    assert not path.is_symlink(), 'symlink header: ' + name
    data = path.read_bytes()
    assert len(data) == pin['size'] and hashlib.sha256(data).hexdigest() == pin['sha256'], name
assert not library.is_symlink(), 'selected stock library must be regular'
data = library.read_bytes()
assert len(data) == 73563968
assert hashlib.sha256(data).hexdigest() == '42be968275d5be2d9e632ec9ef6790dd2c10f1d4a710ad1028fc2b687242f219'
PY
mkdir -p "$output"
flags='-O2 -g0 -Wall -Wextra -Werror -fPIC -fvisibility=hidden -fno-builtin -shared -nostdlib -Wl,--hash-style=sysv,-z,now,-z,relro,-z,noexecstack'
cc $flags -Wl,-z,defs,-soname,libglue_python_lifecycle.so \
    "$fixture/ledger.c" -o "$output/libglue_python_lifecycle.so"
for specification in 'lifecycle:glue_native_lifecycle' 'create-error:glue_native_create_error' 'exec-error:glue_native_lifecycle_exec_error'; do
    source=${specification%%:*}
    module=${specification#*:}
    cc $flags -I"$headers" -Wl,-soname,"$module.so" \
        "$fixture/$source.c" -L"$output" -lglue_python_lifecycle "$library" \
        -o "$output/$module.so"
done
cc -O2 -g0 -Wall -Wextra -Werror -I"$headers" \
    "$fixture/baseline-driver.c" -ldl -o "$output/baseline-driver"
cc -O2 -g0 -Wall -Wextra -Werror "$fixture/ledger.c" "$fixture/test-ledger.c" \
    -o "$output/test-ledger"
for scenario in complete incomplete owned-free duplicate-free wrong-root duplicate-own capacity; do
    "$output/test-ledger" "$scenario"
done
: > "$output/artifacts.sha256"
sha256sum "$output/baseline-driver" "$output/test-ledger" >> "$output/artifacts.sha256"
readelf -d -r -Ws -l "$output/baseline-driver" > "$output/baseline-driver.elf.txt"
nm -u "$output/baseline-driver" > "$output/baseline-driver.imports.txt"
for image in "$output/"*.so; do
    readelf -d -r -Ws -l "$image" > "$image.elf.txt"
    nm -D --undefined-only "$image" > "$image.imports.txt"
    sha256sum "$image" >> "$output/artifacts.sha256"
done
cc --version > "$output/compiler.txt"
