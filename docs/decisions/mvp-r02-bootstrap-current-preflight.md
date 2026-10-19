# R02: check the current native deployment before authentication

The VM reboot changed APFS device/FSID tuples. The old kit installed into its
fresh protected prefix, then its ordinary request writer refused before the
first case. Preserve that evidence and prefix. Add an ordinary preflight that
rejects a changed deployment before sudo or any protected installation, while
retaining the later native request/controller admission checks.

Use the already reviewed no-argument `inspect-deployment` executable at the
literal shared `bootstrap-inspector-v1-20261016` path. Pin binary SHA
`c78b9ddab7bb9feb15d8575847018b88d3dc6c8c520037867fa7ed82b2b2b77a`,
verify its strict ad-hoc signature, and run it in a clean ordinary-user
environment. Its toolkit manifest is
`d5f5519e2f59eff40114297e6c4bdef952f40968352bfe2154e1e4efd96e6505`;
direct six-file source provenance is `d2bd45d`. The toolkit producer inventory
field is not that narrower source closure. There is no runtime path/hash/profile
override. Stable reviewed shared inputs and no concurrent mutation remain
preconditions, rather than a claim of atomic hash-to-exec binding.

Require inspector normal zero, empty stderr and a bounded ordinary-owned
single-link regular JSON observation in the fresh private work directory. The
fixed inspector itself validates its held five-component native filesec scalar
equality, ACL/mount/FD policy, physical traversal and checked closes. Typed
`plutil` checks must additionally require the closed schema/model/kernel/scope,
compatible exact ordered IDs/groups, five components, and every component's
complete device plus both FSID words against the plan's root/Data tuples.
Component/FSID/identity/group container types and lengths must be explicit;
dictionary keys resembling array indices cannot stand in for arrays. Preserve
both FSID words even where root and Data device numbers coincide.

Extend the actual typed capability fixture before authentication for array and
dictionary operations used by the preflight, with positive and mismatched-type
checks. Every parser/tool status has an explicit failure edge, including a tool
that fails after writing an expected-looking value. No regex/coercion fallback,
native policy weakening or normalization is introduced.

The packet plan and exported evidence schemas stay unchanged. Current-inspection
files remain ordinary private preflight diagnostics; a failed preflight neither
authenticates nor installs nor starts a request/case. The approved kit constants
do not change. A fresh packet still needs independent source/packet review.
Focused tests execute only extracted ordinary preflight helpers with controlled
tool/inspector models and owned temporary files, plus native typed-plutil
capability checks; they never run generated phases, sudo, the native inspector
or a configured kit. This change does not establish bootstrap, kernel exec,
tracing, no extraction or full R02/M2 acceptance.
