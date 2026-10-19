# Guarded owned tracing kit profile

This host-only builder has one source-defined profile for `context-probe`,
`owned-trace-runner` and `make-request`. Its registry is deliberately unconfigured:
null source revision, empty source/compile lists and no admitted deployment proof.
Every construction attempt refuses before inspecting source/proof inputs,
creating output or invoking a build tool. No admitted native kit is produced here.

The closed CLI accepts only:

```
python3 -B build_kit.py --guest-proof ABS --inspector-kit ABS --output NEW
```

There are no trust, hash, SIP, profile, library, source, target or environment
overrides. The wrapper passes a frozen internal policy to the existing bounded
tree/proof/source-lock/build helpers and does not mutate their module globals.
Fixed compile-unit paths anticipate the independently reviewed tracing parent,
coordinator and backend. They register no source bytes, revision or guest facts.

The eventual tracing proof must independently register fresh exact disabled-SIP
command bytes, unchanged inspector provenance, exact model/kernel/OS and full
literal device/FSID observations. Enabled-SIP proof is accepted only by the
legacy nontracing profile. Proof bytes and mount tuples are never normalized or
selected from an older boot. No actual proof/export is accessed by these controls.

Only `owned-trace-runner` receives `GLUE_OWNED_TRACING` and `-ldtrace`. Its strict
Mach-O policy requires exactly `/usr/lib/libSystem.B.dylib` followed by
`/usr/lib/libdtrace.dylib`; probe/request remain libSystem-only. Unknown artifacts,
missing/additional/weak/reexport dependencies and existing architecture/OS/UUID/
signature/load-command failures refuse. SDK metadata calibration compiles/links
only and never executes the resulting binary or tracing provider.

Trace registry/recipe/build-identity/result/failure schemas, signing identity and
runner artifact name are distinct. Catalog bytes and BA_PREFIX remain unchanged.
The same exclusive output, two identical signed builds, exact source closure,
tool cleanup and final inventory rules apply. Installation, retention and an
independent tracing receipt checker remain separate work.

The profile feature preserves the legacy CLI, default helper policy, enabled-SIP
admission and recipe bytes. Its shared-helper refactor initially leaves the
legacy source registry and VM parser literal stale, which correctly refuses
construction/checking. The separate
[source registration](../../../../docs/decisions/mvp-r02-owned-trace-inputs.md)
updates six of the existing 34 default source pins and that exact parser literal,
preserving both proofs, compile lists and kit03's fixed approval. The historical
nontracing checker replay then passes with identical native results and unchanged
input bytes/metadata. Historical kits keep their exact locks. This tracing
registry remains empty; no tracing deployment is admitted by the default repin.

Run `python3 -B test_build_kit.py -v` and the legacy
`../bootstrap-kit/test_build_kit.py` controls. New checks use synthetic proof trees,
raw load-command parser data, refusal paths and compile/link-only SDK metadata.
No provider, admitted kit executable, guest, sudo, SIP, network or
publication action occurs. Native calibration and R02/M2 remain open.
