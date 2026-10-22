# Unconfigured tracing match-repair kit profile

This thin host wrapper imports the unchanged `bootstrap-trace-kit` wrapper and
reuses its shared builder. It preserves the historical tracing registry, source
pins, proofs, kits and packet bindings. The new production registry has a null
source revision, empty source and compile lists, and no admitted proof.
Construction refuses before source locking, proof traversal, output creation or
tool execution.

The closed CLI accepts only the inherited three arguments:

```sh
python3 -B fixtures/mvp/macos-trace/bootstrap-trace-match-kit/build_kit.py \
  --guest-proof /absolute/proof --inspector-kit /absolute/inspector --output /absolute/new
```

The invocation currently exits 1 with no output tree. There are no trust, hash,
SIP, profile, registry, source, target, library or environment overrides. Synthetic
configured test records never populate the production registry.

The frozen policy differs from its parent only in the fixed registry path,
guarded helper/registry paths, required helper closure and runner filter exclusion
for this directory. Source locking must include the core builder, parent tracing
wrapper and new wrapper, and compare all three plus the new registry with
committed HEAD. Imported policies and module globals remain unchanged.

Artifact names, schemas, exact ordered 2/19/6 compile lists, strict ad-hoc signing
and dependency rules are inherited. Only `owned-trace-runner` receives
`GLUE_OWNED_TRACING` and libdtrace. Its exact dependencies remain libSystem then
libdtrace; probe/request remain libSystem-only. The proof policy still requires
literal disabled-SIP stdout and all existing inspector, command, OS/model and
mount observations. An enabled proof cannot admit this profile.

Run the focused source/synthetic controls with:

```sh
python3 -B fixtures/mvp/macos-trace/bootstrap-trace-match-kit/test_build_kit.py -v
```

These controls use isolated synthetic trees and raw Mach-O parser fixtures.
They perform no SDK build, native fixture/provider execution, VM operation or
actual proof/capture access. The existing tracing suite remains separate and
unchanged. Passing these tests does not demonstrate a built kit or tracing
readiness.

A later step must freeze reviewed committed repaired sources and the complete
wrapper closure, then register a fresh independently reviewed post-reboot
disabled-SIP proof. Normal enabled-SIP verification belongs to security
restoration and cannot substitute for that admission. Ordinary-user reproducible
kit construction, independent artifact/packet admission, installation retention
and native calibration follow separately. See the
[decision](../../../../docs/decisions/mvp-r02-trace-match-kit.md). R02/M2 and the
complete Darwin extraction oracle remain open.
