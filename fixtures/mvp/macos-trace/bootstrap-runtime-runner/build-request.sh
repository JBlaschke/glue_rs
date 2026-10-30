#!/bin/sh
set -eu
[ "$#" -eq 1 ] || [ "$#" -eq 2 ] || exit 2
out=$1
here=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
base=$(dirname "$here")
catalog=${2:-$here/catalog_unconfigured.c}
[ ! -e "$out" ] && [ ! -L "$out" ] || exit 2
"${CC:-cc}" -std=c11 -D_DEFAULT_SOURCE -D_DARWIN_C_SOURCE -Wall -Wextra -Werror -O2 \
 "$here/make_runtime_request.c" "$here/runtime_catalog.c" "$here/runtime_request.c" "$catalog" \
 "$base/target-launch/target_launch.c" "$base/bootstrap-kit/request_catalog.c" \
 "$base/bootstrap-request/bootstrap_request.c" "$base/bootstrap-wire/bootstrap_wire.c" \
 "$base/target-credentials/target_credentials.c" "$base/bootstrap-admission/bootstrap_admission.c" -o "$out"
