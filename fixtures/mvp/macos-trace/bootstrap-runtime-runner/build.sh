#!/bin/sh
set -eu
[ "$#" -eq 1 ] || [ "$#" -eq 2 ] || exit 2
out=$1
here=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
base=$(dirname "$here")
runner=$base/bootstrap-runner
profile=$base/bootstrap-runtime-runner
catalog=${2:-$profile/catalog_unconfigured.c}
[ ! -e "$out" ] && [ ! -L "$out" ] || exit 2
case $(uname -s) in Darwin) native_libs=-lproc ;; *) native_libs= ;; esac
"${CC:-cc}" -std=c11 -D_DEFAULT_SOURCE -D_DARWIN_C_SOURCE -Wall -Wextra -Werror -O2 -I "$runner" \
 "$runner/owned_bootstrap_main.c" "$runner/runner_catalog.c" "$catalog" \
 "$here/runtime_protocol.c" "$here/runtime_support.c" "$here/runtime_files.c" \
 "$here/runtime_child.c" "$here/runtime_parent.c" \
 "$base/bootstrap-request/bootstrap_request.c" "$base/bootstrap-wire/bootstrap_wire.c" \
 "$base/bootstrap-object-wire/bootstrap_object_wire.c" "$base/target-fd-objects/target_fd_objects.c" \
 "$base/target-cwd/target_cwd.c" "$base/target-launch/target_launch.c" \
 "$profile/runtime_catalog.c" "$profile/runtime_request.c" "$profile/runtime_admission.c" \
 "$base/bootstrap-kit/request_catalog.c" \
 "$base/bootstrap-probe/probe_report.c" "$base/bootstrap-io/bootstrap_io.c" \
 "$base/bootstrap-signals/bootstrap_signals.c" "$base/bootstrap-admission/bootstrap_admission.c" \
 "$base/target-credentials/target_credentials.c" "$base/target-descriptors/target_descriptors.c" \
 "$base/target-endpoints/target_endpoints.c" $native_libs -o "$out"
