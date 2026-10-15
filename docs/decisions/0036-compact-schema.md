# Revision-one compact distribution metadata

Schema zero keeps its original linked/archived/host semantics. Schema one adds a
required `distribution` descriptor and uses the existing verified resource table;
legacy target/runtime/component/native maps must be empty to avoid two authorities.
`entrypoint` is the adapter's archived entry resource. Relative payload records
identify deployed files or internal symlinks (the link text has its own identity).
Runtime descriptors use capabilities and supplied input hashes, never fixture IDs.
Launch argv/environment contain literal values with bounded `{root}`/`{archive}`
substitution; they are never shell commands. Compact mode does not implement
memory delivery. The external report hashes the archive, avoiding circular hashes.

Public APIs live in `glue_format::distribution`. Stable diagnostic codes are
serialized snake_case. Reader bounds and duplicate-key rejection apply to both
schema revisions. The immutable deployment assumption still leaves a check/exec
race on mutable storage; these digests do not establish publisher trust.
