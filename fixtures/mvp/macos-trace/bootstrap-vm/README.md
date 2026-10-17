# Closed NONTRACING VM packet preparation

`prepare.py --kit ABS --output NEW` verifies the one literal reviewed kit and
creates an exclusive derived packet outside the repository. It copies three
unchanged native executables, selected detached metadata and fixed shell scripts;
it does not run any tool, build, authenticate, stage a share or execute scripts.
`APPROVED` records the actual kit02 audit bindings. The independent reviews and
normal builder-zero receipt are review-workflow inputs, not administrator-proof
authentication. Source/proof hashes do not themselves authorize root execution.

The source policy is enabled for the one reviewed kit after independent preparer
and checker reviews. There is no runtime flag/environment fallback. Inspect each
freshly rendered packet before staging or launching it in the owned VM; successful
preparation alone is insufficient. The earlier disabled packet remains unchanged.
See [the reviewed-run decision](../../../../docs/decisions/mvp-r02-bootstrap-vm-reviewed-run.md).

The packet is an explicit subset, not the complete builder output. Its own exact
`SHA256SUMS` inventories `payload/{context-probe,bootstrap-runner,make-request}`,
`metadata/{catalog.bin,recipe.json,source-lock.json,admitted-proof.json,
build-result.json,build-SHA256SUMS}`, `derived-subset.json`, `plan.json` and the
three scripts. `derived-subset.json` maps each selected member to its original
path/hash. The original complete inventory is detached provenance only.

`plan.json` fixes a 16-hex batch nonce, physical private/tmp work/stager/output
paths, the full64-hex protected build cwd, actual guest mount tuples and actual
ID/group observations. Root and Data legitimately share device16777230 while
their FSIDs differ; tuple comparison preserves both fields. It also lists the
complete allowed evidence names. Stable caller-owned namespaces and no concurrent
source/metadata/FD/privileged mutation are explicit preconditions. The ordinary
packet writer uses physical input traversal/exclusive output but is not a
hostile-concurrent-mutator sandbox.

Reviewed execution has exactly one no-argument entry, `launch.sh`, from
the literal shared packet path. Launch uses a clean environment for the ordinary
outer script and records its exact NUL argv, stdout/stderr and actual exitstatus.
Failed launches retain private partial receipts, without inventory/export.
Normal-zero launches export only that closed four-file receipt plus its inventory.
The outer script performs an actual typed `plutil` fixture check before sudo,
including array counts and dictionary checks with mismatched-type refusals.
Before authentication it also verifies the literal SHA and strict signature of
the unchanged ordinary `bootstrap-inspector-v1-20261016/inspect-deployment`
executable at its fixed shared toolkit path. It runs that no-argument inspector
in a clean environment and requires normal zero, empty stderr and a bounded
single-link ordinary-owned regular JSON observation in fresh private work.
Typed checks require the exact scope/model/kernel, compatible ordered IDs/groups,
and all five complete component device/FSID tuples against the packet plan.
Container types and lengths are explicit. A changed boot tuple refuses before
authentication or protected installation. The fixed inspector performs native
filesec/ACL/FD/mount checks on its held five-component walk; these shell checks
do not replace the later request/controller admission. No inspector/path/profile
override is available. See [the current-preflight decision](../../../../docs/decisions/mvp-r02-bootstrap-current-preflight.md).
Current-inspection diagnostics remain private and do not change the plan or
exported evidence schema. Stable reviewed shared inputs without concurrent
mutation remain required; hash/signature checking is not an atomic hash-to-exec
binding. Only after preflight does the outer script use one private `sudo -v`
and then fixed `sudo -n` phases. It never reads a password or uses `SUDO_*` to
select target credentials.

The OS bootstrap copies the root script into a fresh root0700 stager, closes its
writer and checks its literal destination SHA before `/bin/sh`. Each later phase
rechecks that protected script. Fresh fixture prefix/build paths are mandatory;
no existing unreviewed prefix is repaired. Only fresh owned objects have ACLs
removed/modes set. All three destination payloads are closed, hashed and strict
signature-verified before their directories become0755. The ordinary request
writer then validates native typed admission metadata; the native controller
rechecks the exact mount/ACL/profile and probe before its child attempt. The
pre-authentication inspector covers the five existing directory ancestors; it
does not admit a future installed payload or replace those later checks.

Every numeric shell mode guard uses BSD `stat -f '%p'`, the full octal value
including file type and special bits. Exact directory modes are `40700`,
`40755`, or sticky private/tmp `41777`; regular modes are `100500`, `100555`,
or `100600`, with their required owner and single-link count. `%Lp` would omit
the sticky/set-ID bits and cannot validate these contracts. Physical/no-symlink
checks remain separate. See [the mode-guard decision](../../../../docs/decisions/mvp-r02-bootstrap-vm-mode-guards.md).

The four fixed cases are positive, simulated provider failure, denied cwd and
trailing request LAST. Denied mode restoration is behind the known-closure gate;
there is no EXIT trap that restores on uncertainty. Result presence alone or CLI2
never establishes closure. Native CLI0/1 plus exact reaped/resource/signal fields
allow fixed file export; expected ERROR/control matching is separate. Raw wait120
is not required for expected failures because cleanup may kill/reap first.
Unexpected CLI2 stops without inspecting/copying possibly live outputs. Root
pending files are not exported; fixed literal pointers and raw partial artifacts
remain for separate investigation. A failed export is partial and never reused.

Complete evidence contains the fixed names returned by `evidence_names()` and a
new exact inventory. `batch.tsv` is the closed sequence `schema` then preflight,
install, positive, simulated, denied, trailing, complete, each status0. Per-case
native statuses are0/1/1/2. `input.sha256` is64lowercasehex plus LF; trailing has
only input hash/native status/output.absent (`true\n`), no native output payload.
The separate normal-zero outer run receipt is mandatory for later host checking.
The checker must reject incomplete/failed gates before reading case payloads.

Focused controls run with `python3 -B test_prepare.py -v`. They exercise only
host parser/renderer/output boundaries, `sh -n`, extracted read-only mode
predicates, and the narrow ordinary preflight helpers with controlled
tool/inspector models. Native macOS controls also exercise typed `plutil` on
owned temporary fixtures, rejecting boolean/string integer coercion and
dictionary/array lookalikes. These controls never execute the actual inspector.
Portable stat-format models retain type/special bits, owner and
link count. Native macOS controls observe BSD stat on temporary ordinary-user
objects, the existing OS-owned set-ID `newgrp` metadata, and physical Data
private/tmp; they discriminate sticky1777 from777 and complete regular modes.
They never execute generated phases, sudo, native payloads or VM operations.
No privileged transition,
kernel exec, tracing, extraction verdict or full R02/M2 acceptance is claimed.
Syscall stalls/arbitrary descendants remain outside the native deadlines; no
watchdog, retry or fabricated closure is introduced here.
