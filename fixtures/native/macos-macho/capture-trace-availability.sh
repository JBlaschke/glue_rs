#!/bin/sh
set -eu

if test "$#" -ne 1; then
    echo 'Usage: capture-trace-availability.sh RECORD_DIRECTORY' >&2
    exit 1
fi
record_dir=$1
mkdir -p "$record_dir"

# These are read-only, unprivileged capability checks. A failure is evidence of
# an unavailable tracing capability, never evidence of no filesystem activity.
set +e
/usr/sbin/dtrace -l -n 'syscall:::entry' \
    > "$record_dir/dtrace.stdout.txt" 2> "$record_dir/dtrace.stderr.txt"
dtrace_status=$?
/usr/bin/fs_usage -w -f filesys -t 1 \
    > "$record_dir/fs-usage.stdout.txt" 2> "$record_dir/fs-usage.stderr.txt"
fs_usage_status=$?
/usr/bin/xctrace list templates \
    > "$record_dir/xctrace.stdout.txt" 2> "$record_dir/xctrace.stderr.txt"
xctrace_status=$?
set -e
printf '%s\n' "$dtrace_status" > "$record_dir/dtrace.exit-status.txt"
printf '%s\n' "$fs_usage_status" > "$record_dir/fs-usage.exit-status.txt"
printf '%s\n' "$xctrace_status" > "$record_dir/xctrace.exit-status.txt"
printf '%s\n' \
    'Commands were run without sudo and without changing security settings.' \
    'No directory listing or loader event log substitutes for a complete filesystem trace.' \
    > "$record_dir/scope.txt"
