#!/bin/sh
set -eu
if [ "$(uname -s)" != Darwin ] || [ "$(uname -m)" != arm64 ] || [ "$#" -ne 1 ]; then
  echo 'usage on macOS arm64: prepare-controls.sh NEW_ABSOLUTE_TOOLKIT' >&2
  exit 2
fi
case "$1" in /*) ;; *) echo 'toolkit path must be absolute' >&2; exit 2 ;; esac
script_dir=$(CDPATH='' cd -- "$(dirname -- "$0")" && pwd -P)
toolkit_dir=$1
mkdir "$toolkit_dir"
sdk_dir=$(xcrun --sdk macosx26.5 --show-sdk-path)
cp "$script_dir/open-control.c" "$script_dir/open_intent.py" "$script_dir/abi.json" "$script_dir/prepare-controls.sh" "$script_dir/README.md" "$toolkit_dir/"
printf '%s\n' "$sdk_dir" > "$toolkit_dir/sdk-path.txt"
/usr/bin/cc --version > "$toolkit_dir/compiler.txt"
python3 - "$sdk_dir" "$toolkit_dir" <<'PY'
import json, pathlib, subprocess, sys
sdk, output=map(pathlib.Path,sys.argv[1:])
argv=['/usr/bin/cc','-isysroot',str(sdk),'-arch','arm64','-mmacosx-version-min=11.0','-O2','-std=c11','-D_DARWIN_C_SOURCE','-Wall','-Wextra','-Werror','-Wno-deprecated-declarations',str(output/'open-control.c'),'-o',str(output/'open-control')]
(output/'build.argv').write_bytes(b'\0'.join(a.encode() for a in argv)+b'\0')
result=subprocess.run(argv,capture_output=True)
(output/'compile.stdout').write_bytes(result.stdout); (output/'compile.stderr').write_bytes(result.stderr)
result.check_returncode()
result=subprocess.run([str(output/'open-control'),'--describe'],check=True,capture_output=True)
(output/'abi-observed.json').write_bytes(result.stdout)
if json.loads(result.stdout)!=json.loads((output/'abi.json').read_bytes()):
 raise SystemExit('compiled SDK constants differ from reviewed normalized unit ABI')
PY
codesign --force --sign - "$toolkit_dir/open-control" > "$toolkit_dir/sign.stdout" 2> "$toolkit_dir/sign.stderr"
codesign --verify --strict "$toolkit_dir/open-control" > "$toolkit_dir/verify.stdout" 2> "$toolkit_dir/verify.stderr"
codesign --display --verbose=4 "$toolkit_dir/open-control" > "$toolkit_dir/signature.stdout" 2> "$toolkit_dir/signature.stderr"
otool -l "$toolkit_dir/open-control" > "$toolkit_dir/load-commands.txt"
otool -L "$toolkit_dir/open-control" > "$toolkit_dir/libraries.txt"
shasum -a 256 "$sdk_dir/usr/include/sys/fcntl.h" "$sdk_dir/usr/include/sys/syscall.h" "$sdk_dir/usr/include/sys/_types/_o_sync.h" "$sdk_dir/usr/include/sys/_types/_o_dsync.h" "$sdk_dir/usr/include/sys/_types.h" "$sdk_dir/usr/include/sys/syslimits.h" > "$toolkit_dir/sdk-header-sha256.txt"
(cd "$toolkit_dir" && shasum -a 256 open-control open-control.c open_intent.py abi.json abi-observed.json build.argv prepare-controls.sh README.md sdk-header-sha256.txt > SHA256SUMS)
