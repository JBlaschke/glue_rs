# Guarded owned tracing kit profile

This host-only builder has one source-defined profile for `context-probe`,
`owned-trace-runner` and `make-request`. Its registry freezes 41 reviewed source
pins at `e2c728bcdb25ceb151f8f434859c668faf0abcd0` and the exact ordered 2/19/6
compile lists. It admits the fresh post-reboot `Ap5KkPYA` disabled-SIP deployment
proof, manifest `cd57a36af2a9db11f7d24105485137f7afb2ad9743161db190d7ed6c7ca361fd`,
independently reviewed under manifest
`2b3c60fc811ed292cd3e33a33851ba751a1de8c3667c5c2df8f4062000d80dfb`.
The [admission decision](../../../../docs/decisions/mvp-r02-trace-registry-admission.md)
precedes this registration. No native kit is built by this source-admission step.

The closed CLI accepts only:

```
python3 -B build_kit.py --guest-proof ABS --inspector-kit ABS --output NEW
```

There are no trust, hash, SIP, profile, library, source, target or environment
overrides. The wrapper passes a frozen internal policy to the existing bounded
tree/proof/source-lock/build helpers and does not mutate their module globals.
Fixed compile-unit paths select the independently reviewed tracing parent,
coordinator and backend. The separate explicit unconfigured fixture retains the
null/empty registry and refusal-before-source/proof/output/build controls.

Each tracing proof must independently register fresh exact disabled-SIP
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
input bytes/metadata. Historical kits keep their exact locks. The later tracing
admission uses its own fresh disabled proof and source map; no tracing deployment
is admitted by the default repin.

Run `python3 -B test_build_kit.py -v` and the legacy
`../bootstrap-kit/test_build_kit.py` controls. New checks use synthetic proof trees,
raw load-command parser data, refusal paths and compile/link-only SDK metadata.
Empty/refusal controls use a test-only fixture profile whose sole policy
difference is its explicit empty registry path; production registry and closed
CLI checks remain distinct. Synthetic configured data never enters production
construction. Actual registered proof/source-lock checking is a separately
retained read-only admission control, without invoking kit construction.
No provider, admitted kit executable, guest, sudo, SIP, network or
publication action occurs. Native calibration and R02/M2 remain open.
