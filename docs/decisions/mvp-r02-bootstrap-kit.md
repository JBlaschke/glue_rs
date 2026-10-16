# R02: reviewed native bootstrap kit construction

The bootstrap primitives and the ordinary-user context probe do not yet form an
approved privileged launch. This component prepares reproducible inputs for a
later, separately reviewed installation and attempt. It neither installs nor
executes the resulting binaries and grants no tracing or extraction acceptance.

`bootstrap-kit/build_kit.py` accepts only `--guest-proof`, `--inspector-kit` and
an exclusive new `--output`. Its checked-in registry starts unconfigured. A
reviewed follow-up must pin the actual guest proof manifest and independent
audit, the inspector kit, and the frozen complete runner/probe/helper closure.
The registry is a review workflow guard, not cryptographic authorization or a
defence against an administrator who can replace source and tools. There are no
runtime profile, identity, target, hash, compiler or trust overrides.

The builder bounds all data and rejects duplicate JSON keys, coerced integers,
symlinks, path escapes, unexpected members, missing or failed command receipts,
non-enabled SIP, a different guest model/architecture, incompatible actual
ordered groups and incomplete root/Data metadata. Hash consistency alone does
not admit a proof: its exact manifest and independent review must be registered.
It also requires clean, committed sources matching the reviewed closure. Missing
or mutable inputs cause failure before output creation or compilation.

Static source identities and a normalized fixed recipe/toolchain identity, plus
the admitted guest proof identity, determine a build ID. The probe is built
first. Its actual size and SHA enter the canonical `GLUENC01` catalog together
with the source/recipe digests and observed guest device/FSID tuples. The
generated constant catalog, its own digest and resulting runner/utility binaries
are excluded from those input digests. Exactly one generated translation unit
defines `nr_compiled_catalog`; `catalog_unconfigured.c` is never linked with it.
The final external inventory identifies the catalog and all resulting binaries.

Only the fixed native arm64/minimum macOS 26.0 recipe is admitted. Read-only load
command checks require the ordinary dyld loader and libSystem-only dependencies;
strict ad-hoc signature verification follows signing. Two fresh builds must have
identical signed executable bytes. This checks the selected local toolchain and
recipe, not reproducibility across arbitrary SDK/compiler versions. Commands,
tools, source snapshots and failed partial output are retained in the new output;
the builder never runs a newly built executable, downloads, installs or elevates.

Failed, timed-out or spawn-error external tools do not establish descendant
cleanup: reaping a direct compiler does not prove its linker children stopped.
Those attempts retain only explicitly partial raw output/marker, with possible
live writers, and suppress a final inventory or closed result. The successful
path is unchanged. Consumers require normal builder exit zero and the complete
exact verified inventory/result tree, never presence of one partial file.

The separately linked `make-request` utility accepts no arguments for SEND_GO or
exactly `--simulate-provider-failure`. It observes real nonzero equal real and
effective IDs and the actual kernel group vector, rejecting incompatible values
without normalization. It has no identity/path/profile/hash override or root
mode. Its compiled catalog fixes the protected build directory and executable.
A no-follow read-only walk independently checks complete admission metadata
(including populated scalar properties, equality to stat fields, ACL absence and
the root/Data mount profile); inspect callback success alone is insufficient.
It closes every owned descriptor before output. It then encodes one canonical
BR request using that directory's device/inode, catalog SHA and implicit
digest-derived target argv policy. A single stdout write may leave a prefix on
failure; it is never replayed. Only an exact record plus normal utility exit may
be consumed. Generating a request proves neither protected installation nor
target execution, credential transition, kernel object identity or full R02/M2.

Pure codec, bounded parser, source/proof refusal and malformed data controls may
run before guest proof and runner freeze. Native kit construction remains
unavailable until those reviewed inputs are registered. No synthetic fixture or
unit registry substitution is a native guest acceptance result.
