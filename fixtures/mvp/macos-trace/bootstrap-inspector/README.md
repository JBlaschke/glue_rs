# Read-only deployment observation

This ordinary-user Darwin tool opens the fixed physical root/System/Volumes/
Data/Library chain, reads checked metadata and records actual numeric IDs/groups,
model, kernel release and time. It accepts no arguments, changes no settings,
creates no files and performs no target execution. Its result is an observation,
not executable admission, authenticated host identity or provisioning evidence.
See the [decision](../../../../docs/decisions/mvp-r02-bootstrap-inspector.md).

The admission adapter's read-only callback can return zero with incomplete
semantic metadata. The inspector independently requires all three populated
typed scalar properties, exact stat equality, no ACL and the closed root/Data
APFS/type/ownership/mode/flags policy before emitting a result. It closes every
new FD once, including on failure; close/EINTR is not retried. All output strings
are fixed or bounded ASCII, groups are unsorted and bounded at 256, and stream
errors return nonzero. Consumers require exit zero and complete exact-schema JSON.
The tc-compatible boolean describes whether the actual vector meets that
helper's bounds; it never normalizes groups or silently selects a launch identity.

Build and test without privilege:

```sh
cc -std=c11 -O2 -Wall -Wextra -Werror -mmacosx-version-min=26.0 \
  fixtures/mvp/macos-trace/bootstrap-inspector/inspect_deployment.c \
  fixtures/mvp/macos-trace/bootstrap-admission/bootstrap_admission.c \
  -o /new/private/directory/inspect-deployment
python3 fixtures/mvp/macos-trace/bootstrap-inspector/test_inspect_deployment.py -v
```

Three controls collect two passes on each native host and one explicit platform
skip: Darwin checks the complete observation against direct read-only stat/ID/
group results and unchanged enclosing-parent state; Linux checks unsupported
native mode. Both reject arbitrary arguments. A developer-host run supplies no
guest values. Guest output must be separately retained/reviewed before the
controller catalog is generated. Protected fixture provisioning, root-to-nonroot
execution, tracing and full R02/M2 remain separate work; SIP stays enabled.
