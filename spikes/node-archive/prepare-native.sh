#!/bin/sh
# Independent fixture preparation. The packager never runs this script.
set -eu
if [ "$#" -ne 2 ]; then echo 'usage: prepare-native.sh NODE_INCLUDE NEW_DIRECTORY' >&2; exit 2; fi
headers=$1
output=$2
mkdir "$output"
case $(uname -s) in
Darwin)
  cc -dynamiclib -Wl,-install_name,@rpath/libprobe.dylib "$(dirname "$0")/fixtures/native/dependency.c" -o "$output/libprobe.dylib"
  cc -bundle -undefined dynamic_lookup -I"$headers" "$(dirname "$0")/fixtures/native/addon.c" -L"$output" -lprobe -Wl,-rpath,@loader_path -o "$output/addon.node"
  ;;
Linux)
  cc -shared -fPIC -Wl,-soname,libprobe.so "$(dirname "$0")/fixtures/native/dependency.c" -o "$output/libprobe.so"
  cc -shared -fPIC -I"$headers" "$(dirname "$0")/fixtures/native/addon.c" -L"$output" -lprobe '-Wl,-rpath,$ORIGIN' -o "$output/addon.node"
  ;;
*) echo 'unsupported fixture preparation platform' >&2; exit 1;;
esac
