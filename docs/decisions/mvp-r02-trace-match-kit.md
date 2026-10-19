# R02: preserve tracing history with a separate match-repair kit profile

Status: accepted for an unconfigured source profile; native admission pending.

The compiled-selector repair changes the native backend while the existing
tracing registry freezes one historical source revision and its proof. Preserve
that registry, every existing builder, kit and packet byte. Add a thin
`bootstrap-trace-match-kit` wrapper that imports the unchanged tracing wrapper
and reuses its shared core. Do not copy the builder implementation or introduce
a runtime profile selector.

Derive a frozen policy with `dataclasses.replace`. Change only the fixed registry
path, the guarded helper/registry paths, the required helper closure and the
runner source-discovery exclusion for the new directory. Include the core
builder, original tracing wrapper and new wrapper as required helpers; guard
all three plus the new registry against committed HEAD. Preserve the exact
ordered 2/19/6 compile units, artifact names, schemas, signing policy, runner-only
tracing flags and link/dependency rules, and literal disabled-SIP requirement.
Never mutate imported module globals or the parent policy.

The new production registry starts with null source revision, empty sources,
empty compile lists and no proofs under the existing tracing registry schema.
Construction must refuse before source locking, proof traversal, output creation
or tools. Keep public entry points closed over the new constant policy; CLI
trust, hash, SIP, registry, target, source and library overrides remain invalid.
Synthetic configured parser/proof controls are explicitly test-only and cannot
populate the production registry.

Controls cover early refusal/no output, closed CLI, frozen policy isolation,
exact ordered compile/link rules, strict Mach-O dependencies, disabled versus
enabled proof requirements and mandatory helper/guard closure. Preserve the
historical production registry/source/test bytes and compare their identities.
Run no native kit or provider, SDK build, VM operation or actual capture.

A later source admission must freeze the committed repaired backend and wrapper
closure, receive separate independent review, and register a fresh post-reboot
disabled-SIP proof for a separately authorized tracing window. An enabled proof
is never admission for this profile. Fresh ordinary-user reproducible kit builds,
artifact/packet admission and inspection/preservation of the installed kit remain
later steps. This unconfigured profile grants no tracing readiness or R02/M2
acceptance and does not change any extraction interpretation.
