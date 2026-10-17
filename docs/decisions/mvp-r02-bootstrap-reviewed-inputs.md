# R02: register the owned guest deployment observation

The ordinary-user inspector ran in the owned `glue-mvp-macos-trace` VM on
17 October 2026. Its exact output manifest is
`ec28e38b3066112d874a54b0dfb4bb9c20fae3f39dc90697bf7d4ea684a84c8a`.
The six recorded commands succeeded, including strict signature verification and
the exact SIP-enabled status. Raw observations stay local. Registration requires
an independent audit of those bytes and its manifest identity in the registry;
self-consistent synthetic input cannot register itself.
The independent audit manifest is
`d5a899e5659dde3f5ac02b6d7dad754204a85fafcfa906fd339e4935fb58e279`.

The source lock uses reviewed production/build-controller bytes from `3d500d4`.
It includes every quoted header needed by the probe, runner, request writer and
generated catalog bridge. Separate compile lists exclude the unconfigured
catalog, registry, generated files and resulting binaries. Tests and reference
documents retain separate provenance rather than entering a production closure
under a misleading label. The overall static map/build ID covers all registered
source bytes; the existing individual probe/runner digest fields retain their
literal directory-filtered subset semantics.

The actual root and Data observations have the same `st_dev` and distinct FSIDs.
Admission compares the complete device/FSID tuple, with the existing explicit
mount/ownership/ACL policy. Registration does not normalize these facts or invent
different device numbers. The kit's older `source_manifest_sha256` field names the
whole frozen inspector producer inventory, including build/signature records and
source copies; direct source-byte checks establish its six-file Git provenance.

Portable refusal controls use a separate explicit empty registry fixture. They
must continue to prove rejection before source/proof/build/output work when the
checked-in production registry contains reviewed inputs. Production CLI arguments
gain no registry or trust override. A separate CLI control rejects unreviewed
paths without creating output, under either configured or unconfigured state.

Registration enables only the existing host build workflow. It does not install
or execute the resulting binaries, change guest security settings, establish
privileged credential transitions or prove kernel exec/tracing effects. A later
protected guest attempt still requires a concrete reviewed kit and orchestration.

## Ubuntu compiler follow-up — 17 October

The next hosted checkpoint (`78f4072`, run 39020970722) reaches the context-probe
compile and exposes Ubuntu GCC 13's `warn_unused_result` diagnostic on the
best-effort error write. Consuming the result in a local `ssize_t` and then
explicitly ignoring that local preserves the single write, no-retry behavior.
The test now includes compiler stdout/stderr when compilation fails. The native
Ubuntu GCC 13 reproduction rejects the old source and accepts the fixed source;
focused native Mac controls also pass. No warning is disabled.

The production source lock must deliberately advance to the integrated fix
`863e3279cb701676cc90d32507f7513742abd695`. Exactly one of its 34 source hashes,
`bootstrap-probe/context_probe.c`, changes. The deployment proof and other 33
source bytes remain unchanged. Registration does not rebuild or reinterpret the
already frozen kit02: that kit and its separate approved VM packet continue to
identify their original `3d500d4` inputs, binaries and audits. A future builder run
uses the new source lock and must produce its own new output and inventory.
