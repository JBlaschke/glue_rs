#!/bin/sh
set -eu
# Explicit new output path; generated catalog replaces the fail-closed default.
[ "$#" -eq 1 ] || [ "$#" -eq 2 ] || exit 2
out=$1
catalog=${2:-$(dirname "$0")/catalog_unconfigured.c}
[ ! -e "$out" ] && [ ! -L "$out" ] || exit 2
here=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
base=$(dirname "$here")
case $(uname -s) in Darwin) native_libs=-lproc ;; *) native_libs= ;; esac
# A reviewed generated source is a BUILD input, never a runtime selector.
"${CC:-cc}" -std=c11 -D_DEFAULT_SOURCE -D_DARWIN_C_SOURCE -Wall -Wextra -Werror -O2 -I "$here" \
 "$here/owned_bootstrap_main.c" "$here/runner_catalog.c" "$catalog" \
 "$here/runner_protocol.c" "$here/runner_support.c" "$here/runner_files.c" \
 "$here/runner_child.c" "$here/runner_parent.c" \
 "$base/bootstrap-request/bootstrap_request.c" "$base/bootstrap-wire/bootstrap_wire.c" \
 "$base/bootstrap-probe/probe_report.c" "$base/bootstrap-io/bootstrap_io.c" \
 "$base/bootstrap-signals/bootstrap_signals.c" "$base/bootstrap-admission/bootstrap_admission.c" \
 "$base/target-credentials/target_credentials.c" "$base/target-descriptors/target_descriptors.c" \
 "$base/target-endpoints/target_endpoints.c" $native_libs -o "$out"
