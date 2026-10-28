# V02/R02/R03: reproduce native Linux arm64 acceptance

Status: accepted for target-matched CI automation. Fresh native results remain
required; source controls do not replace them.

The shared harness, tracer policy, wheel preparation and five budget profiles
support both GNU Linux architectures. The hosted native runner currently fixes
x86_64. Missing historical arm64 evidence requires a reproducible fresh run,
without changing guest SIP or accepting incomplete target cells.

## Closed native target profiles

Support exactly `x86_64-unknown-linux-gnu` and `aarch64-unknown-linux-gnu` through
closed source-defined profiles. Bind Linux machine architecture, Rust target,
Node archive suffix, PBS triple/checksums, wheel platform, Node fixture config,
multiarch library roots, conda lock and accepted budget directory together.
Reject an unsupported host or requested/expected target mismatch before creating
the CI root or starting provisioning. Preserve the existing default x86_64
runtime versions, exact package inputs and acceptance semantics.

Propagate the selected target through trace-environment proof, every case and
benchmark invocation, retained receipts, completeness checks and final summary.
Retain exactly 24 cases: both Lua families with project/native inputs, two Node
majors with four corpora each, and three Python minors with four corpora each.
Retain all five 10,000-added-entry benchmark profiles and first/warm 1/32-rank
series. No missing or duplicate case/benchmark can yield a passed summary.

## Independent runtime input profiles

Keep the exact existing x86_64 conda lock and pins. Add a separate reviewed
linux-aarch64 CPython3.14.8/libffi/compiler-runtime lock and native micromamba
identity, resolved from official metadata. It must include all required
dependencies with HTTPS URLs and SHA256 identities. Cross-platform metadata
resolution is allowed but is not Linux runtime execution.

Generalize `provision-conda.py` through closed exact profiles, with native-host
checks before filesystem/network/process side effects. Wrong-platform packages,
tool identity, duplicate/incomplete locks and changed selected pins refuse.
There are no caller-provided package channels, URLs or expected-hash overrides.
Actual installation/probing stays on the matching Linux host and preserves
independent native input bytes; glue build/run never installs or rebuilds them.

Use verified target-specific PBS3.12.15/3.13.16 and Node24.22.0/26.10.0 archives,
not architecture substitutions or version reductions. Missing official inputs
must leave the new cell unimplemented rather than silently shrinking the matrix.

## Execution and evidence

Add a native Ubuntu arm64 job with a distinct artifact name while retaining the
x86_64 job and explicit traceable-native-syscalls-v1 policy. Preserve root-owned
offline namespaces, full process-tree strace and independent receipt/control
replay. Workflow dispatch can select a target without making foreign execution
valid. CI can proceed independently of later feature work.

Enforce the existing target-specific structural/I/O/FD/scaling limits. Keep
time/RSS scoped to the recorded budget fingerprint; never automatically refreeze
limits after a failed run. Record new runtime inputs, toolchain and native host
identity. Actual native execution and complete independently replayed retained
output are required before declaring the new arm64 cell passed.

Portable controls cover both complete profiles, unchanged x86 defaults,
pre-side-effect host refusal, lock/platform/pin tampering, target propagation and
exact case/benchmark summary closure. Shell/workflow syntax and appropriate
existing controls are checked before publication. Full Darwin oracle/corpus,
Mac budgets, external retention and final M2 remain separate open gates.
