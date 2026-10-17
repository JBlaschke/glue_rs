# Closed NONTRACING VM packet preparation

`prepare.py --kit ABS --output NEW` verifies the one literal reviewed kit and
creates an exclusive derived packet outside the repository. It copies three
unchanged native executables, selected detached metadata and fixed shell scripts;
it does not run any tool, build, authenticate, stage a share or execute scripts.
`APPROVED` records the actual kit02 audit bindings. The independent reviews and
normal builder-zero receipt are review-workflow inputs, not administrator-proof
authentication. Source/proof hashes do not themselves authorize root execution.

**Execution is disabled in every rendered script.** `EXECUTION_ENABLED=False`
must remain until the offline checker and exact orchestration bytes receive
independent review and a separately authorized source follow-up enables them.
There is no runtime flag/environment fallback. Do not copy/run a packet in a VM
merely because preparation succeeded.

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

Future reviewed execution has exactly one no-argument entry, `launch.sh`, from
the literal shared packet path. Launch uses a clean environment for the ordinary
outer script and records its exact NUL argv, stdout/stderr and actual exitstatus.
Failed launches retain private partial receipts, without inventory/export.
Normal-zero launches export only that closed four-file receipt plus its inventory.
The outer script performs an actual typed `plutil` fixture check before sudo,
uses one private `sudo -v` and then only fixed `sudo -n` phases. It never reads a
password or uses `SUDO_*` to select target credentials.

The OS bootstrap copies the root script into a fresh root0700 stager, closes its
writer and checks its literal destination SHA before `/bin/sh`. Each later phase
rechecks that protected script. Fresh fixture prefix/build paths are mandatory;
no existing unreviewed prefix is repaired. Only fresh owned objects have ACLs
removed/modes set. All three destination payloads are closed, hashed and strict
signature-verified before their directories become0755. The ordinary request
writer then validates native typed admission metadata; the native controller
rechecks the exact mount/ACL/profile and probe before its child attempt. The shell
does not claim to reproduce that native filesec API before installation.

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
host parser/renderer/output boundaries and `sh -n`, never generated script
execution, sudo, native payloads or VM operations. No privileged transition,
kernel exec, tracing, extraction verdict or full R02/M2 acceptance is claimed.
Syscall stalls/arbitrary descendants remain outside the native deadlines; no
watchdog, retry or fabricated closure is introduced here.
