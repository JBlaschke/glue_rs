# Fixed raw runtime FD interval policies

`runtime_fd_policy.py` applies a fixed, finite request policy to original runtime capture bytes. It calls the strict recipe reader once, retains every original phase and entry attempt, and reasons about closed possible lookup/effect windows. It never accepts a caller-created capture, normalized operation, object token, authority boolean or selectable policy.

```python
from runtime_fd_policy import RuntimeRecipeEvidence, evaluate_runtime_fd_policy_raw

# Construct the factory's exact frozen evidence type from the eight original
# request/catalog/plan/status/artifact/output/delivery/GO byte assets.
evidence = RuntimeRecipeEvidence(request, catalog, launch_plan, status_stream,
    launcher_artifact, output_witness, gate_delivery, go_prefix)
result = evaluate_runtime_fd_policy_raw(program, probes, errors, raw_event_lines,
    owner_pid=owner_pid, target_pid=target_pid, contract_bytes=contract_bytes,
    launch_evidence=evidence)
```

The evidence type is re-exported from the identity-checked private recipe reader. As with the existing fixed image profile, an otherwise similarly named class loaded through another module is not a fallback input type. After module import, this API consumes only caller bytes and the bounded iterable; it opens no assets, runs no subprocess and performs no native query or tracing.

## Exact finite scope

The handled runtime names are `close`, `close_nocancel`, `dup`, `dup2`, `write`, `write_nocancel`, `pwrite`, `pwrite_nocancel`, `fsync`, `fsync_nocancel`, `ftruncate`, `open`, `open_nocancel`, `openat` and `openat_nocancel`. The existing pinned entry/outcome and eleven-operation FD helpers supply canonical scalar rules. The existing pinned open-intent classifier supplies request-bit intent. A canonical signed32 flag is converted to its unsigned32 bit view only after typing; arbitrary/noncanonical raw words are never masked into permission.

Writable/create/truncate/append requests through those four opens are forbidden intent even when the kernel returned an error. Known `path-mutation` declarations also retain forbidden attempted intent independently of success. No path string, numeric fd or final metadata comparison grants an exemption. Other open variants, fcntl commands, reads/queries, vectors, mapping, asynchronous, cwd and opaque routes remain explicit unsupported coverage. This feature expands no161-call source table and imports no synthetic state/mapping engine.

`source-conditional-clean` means this finite request policy closed without a forbidden intent or required unresolved fact. `forbidden-intent` retains observed forbidden requests. `incomplete` means coverage, typing, outcome, interval or output binding is unresolved; it can still retain violations alongside gaps. None is a native no-extraction verdict, and an attempted violation is not a claim that extraction completed.

## Every exec retires output certainty

The recipe's conditional output seeds are constructed after capture validation, but their observations came from READY **before exec**. The policy installs their provenance only in bootstrap epoch0. Every selected exec, including the first, retires ALL tracked binding certainty. This stronger conservative first rule also discards non-output FD certainty at exec.

Clear CLOEXEC does not exclude MAC inheritance closure or internal missing-stdio repair. Therefore a successful, failed or zero-byte post-exec write to fd1/fd2 remains `unresolved-output-binding`. This module has no post-exec observation and returns an empty `output_exemptions` tuple. No output exemption can be fabricated by reusing the initial seed, artifact hash, pathname or descriptor number.

A future reviewed post-exec witness can supply a new prospective backing observation. It must not revive old generations or authorize earlier write windows. Native, output-authority, state-feed, effect-linearization and full-trace-acceptance flags remain false in every result, including a source-conditional-clean result.

## Closed windows and analysis versions

Entry and return provide a **closed possible lookup/effect window**. They do not locate the operation's kernel lookup or mutation point. Pairwise relevant overlap, including touching timestamp endpoints, creates a conflict. Cross-thread consumer order and reversed return order are never used to linearize effects. Allocation/reservation windows can conflict even with distinct or absent returned fds. The first model conservatively treats overlapping allocators and affected lookup domains as unresolved.

A postcondition is recorded only after an entire nonconflicting interval. Within that interval a relevant slot is unavailable for stable-binding propagation. A source-changing interval nested inside duplication, even if it restores the same numeric/object-looking value, conflicts. The implementation first computes all window conflicts, then applies only isolated post-interval facts; bookkeeping at an interval's end is not an assertion that the effect occurred at return.

An unhandled or unsupported effect has no proved completion bound. Its ENTRY installs a sticky opaque-effect horizon: every tracked binding becomes unknown, and later handled opens/duplications cannot rebuild precise lineage merely because that opaque call returned. Earlier source facts remain historical; the whole result stays incomplete (or retains an already-forbidden intent).

Versions and binding keys are capture-local analysis history, never kernel descriptor generations, OFD identity or native object attestation. A read-only open creates an `untrusted-open` analysis origin without output authority or resolved backing. A distinct duplication can propagate only a stable existing analysis origin; an unresolved source stays unresolved. Successful self-dup2 preserves its version, flags and key and records a preserving observation. A successful isolated close records conditional absence. Failed close poisons its slot; failed dup2 poisons its target. Reuse/change-and-restore creates new versions. The4096-slot limit bounds analysis storage, not RLIMIT or permissible numeric fd values.

Final bindings are historical analysis facts before the terminal process context, not live resources after capture (`final_state_is_live` is false). Thread instances share the process table; a worker declaration/exit does not manufacture another FD table. Subsequent exec resets the table's certainty independently of late old-image EJUSTRETURN context.

## Attempts, failures and complete accounting

Every entry retains its original source fields, all raw words, canonical argument facts where available, attempted intent, source-associated return and uncertainty. Scalar successful writes require `0 <= reported <= requested <= INT_MAX`. The pwrite wrapper's `-1` offset success is inconsistent; other negative signed offsets remain requests. Failed writes may hide partial effects. Zero-byte writes remain attempts. Flush and truncate errors preserve uncertainty, and requested truncate length is not an observed resulting size.

Bootstrap pairs are treated only as the exact upstream-validated bootstrap context: gate reads/poll/flags and status-pipe writes are not arbitrary runtime permissions. Moving the same function after exec triggers runtime coverage rules. The one validated attachment return has no invented entry or complete call interval. Exec/EJUSTRETURN and nonreturning process exit are accounted separately from ordinary completed calls; late old-image returns cannot restore output state.

`phase_accounting` covers every original phase exactly once. Malformed/incomplete transport or invalid evidence raises without a policy result. If strict image interpretation fails after full physical validation, the result retains every original BSD **and Mach** entry and phase in `unresolved-image` context, with `recipe=None` and no windows, transitions, final bindings or exemption prefix. Mach rows remain explicitly opaque: no BSD typing, outcome, pairing or FD intent is inferred, even when a Mach function name resembles a BSD name. Forbidden open/path intent is still projected from original BSD entries. Mach, rights, process creation and ambiguous lifetimes never become a clean prefix.

## Validation and source limits

Run `python3 fixtures/mvp/macos-trace/runtime-fd-policy/test_runtime_fd_policy.py` from the repository root. The36 independent physical-byte controls cover phase conservation, all three attachment routes, bootstrap retries, first/later exec retirement, typed success/failure domains, zero requests, open/path intent, failed close/dup2, reuse/alias history, source-slot/touching/allocation conflicts, late EJUSTRETURN, unresolved image routes, late transport, exact evidence, single iterator consumption and immutable detached serialization. They execute no target or provider.

Executable helpers and the open ABI asset are identity checked before ordinary imports. Their source grounding remains Apple XNU commit `f6217f891ac0bb64f3d375211650a4c1ff8ca1ea` and the existing fixed Darwin open ABI. See the FD helper's exact handler/dispatcher sources, open-intent ABI and [the policy decision](../../../../docs/decisions/mvp-r02-runtime-fd-policy.md). Installed provider/ABI/clock calibration, authoritative post-exec backing, complete runtime/Mach/mapping/process coverage and actual native corpus/budgets remain required. This source engine neither changes SIP nor closes those gates.


## Separate scalar fcntl profile v2

`evaluate_runtime_fd_fcntl_policy_raw` takes the same original-byte arguments,
but adds F_DUPFD, F_GETFD, F_SETFD and F_DUPFD_CLOEXEC through both fcntl forms.
The v1 factory keeps its fifteen-name scope and original result shape. The v2
result adds immutable `fcntl_attempts`, linked by original attempt index and
retaining the full signed64 argument plus the existing source semantic row. No
caller policy selector, normalized input or second capture pass is accepted.

GETFD retains a point observation within its closed window; it does not rewrite
a binding, version or return-time flag snapshot. A contradictory prior bit
creates a gap and removes bit certainty. SETFD changes only the selected
descriptor's conditional bit after an isolated interval, preserving its backing
key and alias provenance. Duplication requires a stable source throughout the
closed lookup/reservation window; the minimum is never narrowed and returned
numbers grant no backing identity. Descriptor flag changes do not spread across
aliases. Relevant touching/overlapping windows remain conservative conflicts.

Canonical failed scalar operations and existing dup get explicit uncertainty
gaps in v2. Failed SETFD clears only bit certainty under otherwise complete
conditional mutation coverage; isolated failed allocators infer no destination
while preserving earlier conditional keys. Unknown or unsupported commands,
including F_GETFL/F_SETFL, still establish the entry-onward opaque horizon.
Validated bootstrap observations remain upstream context only. Every exec still
retires all binding certainty. Successful lookups from a conditionally absent
source, or allocator returns into a conditionally occupied destination, create
explicit source-state gaps and retire incompatible certainty; they grant no
alias/flag replacement. The explicitly replacing dup2 route remains distinct.
No output exemption, state authority, native calibration or full acceptance is
granted.

Run the separate controls from the repository root:

```sh
python3 fixtures/mvp/macos-trace/runtime-fd-policy/test_runtime_fd_fcntl_policy.py
```

The original v1 control suite remains unchanged. This candidate is staged during
the approval-service outage; its feature decision/publication is pending.

## Separate fixed status-query profile v3

`evaluate_runtime_fd_status_policy_raw` uses the same original immutable byte
inputs and exact `RuntimeRecipeEvidence` type, with protocol
`darwin-runtime-fd-status-policy-v3`. It adds only the approved bounded F_GETFL
command3 semantics through `fcntl` and `fcntl_nocancel` to v2's finite scope.
Both old public factories retain their scopes, result classes and fields;
F_GETFL stays unsupported through v1/v2. V3 uses the same immutable
`RuntimeFdFcntlPolicy` result class and `RuntimeFcntlAttempt` rows with its distinct
protocol. Caller profiles, captures, policy constants and authority booleans
remain unsupported inputs.

```python
from runtime_fd_policy import evaluate_runtime_fd_status_policy_raw

result = evaluate_runtime_fd_status_policy_raw(
    program, probes, errors, raw_event_lines, owner_pid=owner_pid,
    target_pid=target_pid, contract_bytes=contract_bytes,
    launch_evidence=evidence)
```

The approved F_GETFL helper source is identity-checked as SHA256
`0358db16192afe9442348ca446a89a4478e137f3b376da7072b13485367ef54f` before any
helper import. V3 performs exactly one complete generic `pair_runtime_recipe_raw`
pass. Only after validation does its private fixed dispatch call the approved
F_GETFL `_decode_operation` on already-associated ordinary runtime pairs, using
their original source-pair index. The command row separately retains its policy
attempt index. Existing four-command rows use their unchanged scalar decoder.
No public helper or raw reader reparses the capture.

Each F_GETFL command row retains the full typed request, ignored signed64 long,
original tail words, outcome, `FgetflOperation`, signed32/uint32 result view,
all exact algebraic preimages and source/policy uncertainty. Its approved
21-construction ordinary subset includes FWASWRITTEN on writable states and
FEXEC alone. A `conditional-conversion` plus conditional rule admits only a
closed numeric-descriptor lookup/query window: lookup slot present, no table
mutation slot or allocation, no chosen effect instant. It supplies no flag,
binding, generation, backing, version or at-return snapshot. Its converted
result is not an open request and is never passed to the open-intent classifier.
No preimage or event-only process-policy branch is selected.

The query's successful return does not update state, including when an earlier
opaque horizon or conflict exists. The existing successful-lookup consistency
guard still applies: a successful lookup contradicting known conditional absence
produces an incomplete gap and retires incompatible certainty to unknown, never
a present binding or flag postcondition. Touching mutation/allocation windows
retain existing conflicts. Shared-flag writers through aliases can still race;
an isolated descriptor-table window does not certify stable fileglob flags.

A canonically typed kernel-error query has a `failed-status-query` gap and no
observation, rule or table/version rewrite. Unsupported or unresolved conversions
install the sticky opaque horizon at ENTRY. Event-only, private/unknown bit
combinations, source-inconsistent results, unsupported signed result framing
and noncanonical requests remain explicit and cannot be repaired by later
supported queries. F_SETFL retains pre-ioctl shared updates, errors and partial
rollback uncertainty; unknown commands acquire no family-wide permission.

Outside ordinary runtime pairs, v3 projects typed F_GETFL request intent only.
The whole-capture image-error fallback retains every original BSD/Mach entry and
phase with no invented outcome, operation, window or successful state prefix.
Bootstrap flags stay upstream context. Every exec retires all binding certainty;
point queries never restore READY seeds or authorize writes to fd0/1/2.

The runtime finite-policy status keeps its existing meaning. A supported query
may occur in a `source-conditional-clean` v3 result because this policy consumes
no flag value as authority or state; the unobserved preimage alone adds no gap.
Failed/unresolved queries, conflicts, prior unknown horizons and output-binding
gaps remain incomplete. This differs from the standalone source helper's
always-incomplete diagnostic status. All operation witnesses remain retained,
and native admission, state-feed, successful linearization, live final state,
output authority and full acceptance remain false for every runtime status.

Run all three source suites from the repository root:

```sh
python3 -B fixtures/mvp/macos-trace/runtime-fd-policy/test_runtime_fd_policy.py -v
python3 -B fixtures/mvp/macos-trace/runtime-fd-policy/test_runtime_fd_fcntl_policy.py -v
python3 -B fixtures/mvp/macos-trace/runtime-fd-policy/test_runtime_fd_status_policy.py -v
```

The original36/v1 and27/v2 test methods remain byte-for-byte unchanged. The new
focused suite adds16 methods, including42 ordinary-subset query vectors across
both syscall names, actual associated-pair/private-only single-pass checking,
unknown/private/event-only/signed/error/control-flow cases, request/tail/index
retention, touch/alias conflicts, cross-exec retirement, fixed old scopes and
immutable authority-free output. These are modeled original physical-byte
controls, not captured kernel evidence. Stage evidence retains pilot faults,
exact interpreter/count logs, prior-stage/HEAD identities and source hashes.
Only staged engine/README/new controls/decision change; no configured native
closure, observer adoption, CI, provider, target, VM or native action occurs.
