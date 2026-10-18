# R02: admit the fixed tracing sources only with fresh deployment proof

Use the existing `glue-owned-trace-kit-inputs-v1` registry without changing its
API/schema, builder policy or CLI. This decision precedes any registry mutation;
the registry remains null/empty while fresh post-reboot disabled-SIP proof and
its independent review are missing. A later admission commit is one separate
bounded step; root coordinates admission review and the subsequent host build.

Freeze `source_revision` to `e2c728bcdb25ceb151f8f434859c668faf0abcd0` and the
reviewed 41 native/core/wrapper pins, whose canonical source-map SHA256 is
`75fce31776344598d92f8705e5a831a2451687e99b423fc200e89c35e053f997`.
The closed external candidate has manifest
`e909d5af8f142f95800d26119cb582517428c93474ab6de35c5da55a03e883bf`.
Preserve the wrapper's exact ordered 2 probe/19 runner/6 request compile lists:
39 C/header files in the recursive local include closure plus the two builder
helpers. The registry excludes itself. Recheck all pins against the fixed
revision and the clean related checkout; both builders and registry must equal
committed HEAD guards. Changed source/helper bytes require separate review and
an explicit source decision. Raw/case/packet/SIM Python code is outside this
native build closure and gains no admission here.

Register only a freshly collected, independently reviewed post-reboot proof
whose SIP stdout is exactly `System Integrity Protection status: disabled.\n`.
Recheck the unchanged inspector manifest/wrapper/binary/source provenance and
all six exact command argv/status/stream receipts, full inventories, model,
kernel/OS, credentials and every literal component/device/FSID observation.
Never rewrite or reuse an enabled-SIP proof, guess a hash/observation, normalize
the actual tuples or substitute a previous boot's catalog values. The new catalog
must derive its root/Data tuples directly from the fresh observation.

Populate the registry's ten proof fields with reviewed literals:
`manifest_sha256`, `review_manifest_sha256`, `inspector_manifest_sha256`,
`wrapper_sha256`, `binary_sha256`, `inspector_source_commit`, `guest_output_name`,
`kernel_release`, `os_version`, `os_build`. Independently establish post-reboot
collection chronology and bind the complete review record to the actual proof
manifest: the parser neither establishes boot freshness nor opens the review
tree. Syntax or source-lock success cannot replace that independent review.

Preserve the default registry and both historical proofs, legacy preparer/checker
and approvals, and packet/SIM refusal policies. Retain ordinary-user host build,
exclusive output, fixed compiler flags, strict ad-hoc signing, two identical
signed builds and checked tool cleanup. Only `owned-trace-runner` defines
`GLUE_OWNED_TRACING` and adds `-ldtrace`; its exact ordered dependencies remain
libSystem then libdtrace, while probe/request remain libSystem-only. Generated
catalog, recipe/build/artifact identities are derived from actual reviewed
proof/toolchain/build bytes later. No build, artifact/provider execution, guest
operation, packet activation, proof publication or R02/M2 acceptance occurs in
this decision-only step.
