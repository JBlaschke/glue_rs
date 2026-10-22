# R02: admit repaired tracing sources with a fresh guest proof

Status: decision accepted; production match registry remains unconfigured.

Freeze the separate match profile's eventual source revision to
`7daa90268432d74bf44d14df7b344602b810485f`. Its external candidate has 42 sources:
the historical 39 C/header files, unchanged core and tracing helpers, and the new
match wrapper. The canonical map SHA256 is
`1d9c56bdd00bd711cfec0c09979cf427e98a2b56b62e5da7d848b3de59d3b02d`.
The closed candidate record has manifest
`630a3ebf730246be90c83710577b421184c40643b8d670967a5b346432b5e054`.
Among the old 41 keys, only the reviewed native backend C file changes; the new
wrapper is the sole addition. Preserve the exact ordered 2/19/6 compile lists and
all three mandatory helpers. The literal local-include graph is a source check,
not SDK compilation or native execution.

Do not populate the production registry until independent source review and a
fresh, independently reviewed normal-boot disabled-SIP proof are available for
a separately approved guest tracing window. Use actual proof literals for all
ten existing proof-entry fields. Preserve exact command argv, statuses, streams,
complete inventories and unchanged inspector source/binary/wrapper provenance.
Establish post-reboot chronology separately; parsing cannot prove freshness.
The enabled proof from the closed 18–19 October window cannot admit this kit.
Do not reuse old mount/device tuples; derive the eventual catalog from the new
observation. No placeholder, guessed or synthetic proof enters production.

Before the eventual registration, preserve this profile's original null/empty
registry in an explicitly named test-only fixture. Route empty-registry refusal
controls to that fixed fixture policy and keep actual production checks separate.
Synthetic configured parser/proof controls remain test-only. After registration,
verify the clean committed source lock and actual proof without building a kit,
and retain the affected focused-suite receipt and independent review.

Keep both historical production registries, builders, proofs, kits, packet
bindings and failed attempt outputs unchanged. Do not change shared APIs, schemas,
the disabled-SIP requirement, compiler/link/signing policy or no-extraction
interpretation. The match wrapper's own registry remains excluded from its source
digest and is checked against committed HEAD along with all three helpers.

This decision performs no registration, proof collection, VM/security change,
SDK build or provider execution. A fresh reproducible ordinary-user kit, artifact
and packet admission, inspection/preservation of the installed tracing kit, and
native calibration remain subsequent steps. Full Darwin R02/M2 remains open.
