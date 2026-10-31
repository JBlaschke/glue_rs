# R02: separate fixed runtime status-query profile

Status: staged source implementation, 29 October 2026. This decision draft was
written before engine changes. Native tracing/admission, observer adoption and full R02 remain
open. The generic reviewed recipe profile is the only source recipe used here.

Add `evaluate_runtime_fd_status_policy_raw` with protocol
`darwin-runtime-fd-status-policy-v3`. It consumes original immutable byte evidence
through exactly one fixed `pair_runtime_recipe_raw` call. After complete raw,
image and recipe validation, use the fixed private F_GETFL decoder only on
already-associated ordinary runtime pairs, preserving original pair indices and
policy attempt indices separately. No public helper or raw-pairing reparse runs.

The v1 and v2 public scopes, result classes and fields remain unchanged. The new
v3 result uses the existing immutable command-row subclass with a distinct
protocol. Only a private fixed source selector enables command3; no caller
allowlist, constants, normalized captures, process-policy booleans or authority
assertions are accepted. Pin the approved helper SHA256
`0358db16192afe9442348ca446a89a4478e137f3b376da7072b13485367ef54f` before import.
Keep the existing four scalar command rows exact through their old decoder.

F_GETFL's full request, ignored signed64 long/tail words, outcome, observation,
algebraic preimages, source-feasibility limits and original pair remain retained.
A conditional-conversion rule permits only a closed lookup/query window; it
updates no table, flag, binding, version, backing identity or output authority.
Conflicts or an existing opaque horizon cannot turn the query's return into a
state rewrite. The existing successful-lookup consistency guard still records
known-absence contradictions and retires incompatible certainty to unknown;
that is uncertainty retirement, not a query state postcondition.
Canonical failed queries have an explicit gap and no observation/state update.

Unresolved or unsupported conversions install the existing sticky opaque horizon
at ENTRY. No private bit is masked away, no event-only policy branch selected,
and no later successful query repairs unknown certainty. F_SETFL/unknown commands
remain unsupported. Exec retires every conditional binding, including initial
READY provenance. Numeric fd0/1/2 never acquire an output grant.

The whole-capture image-failure path retains all BSD/Mach entries and phases,
with a typed command3 request projection where possible, no invented outcome,
window, successful state prefix or observation. A late malformed byte record or
iterator failure returns no policy prefix. The runtime finite-policy status
remains `source-conditional-clean` when all requested intents have fixed rules
and there are no other gaps/violations; the unobserved flag preimage alone adds
no gap because no flag value is consumed as authority or state. The standalone
helper remains always incomplete. All runtime native/state/linearization/output/
full-acceptance fields remain false for every status.

Work is isolated in PRIMARY `runtime-fgetfl-policy-20261029` staging. Frozen v2
module `c7bf68725ba6d814642fe8b97cd1c25895fd168af21ff6cc2f897f4350ee39b0`
and frozen leaf helpers remain read only. Keep base36/v1 and27/v2 controls exact,
then add focused independent physical-byte v3 controls for both command names,
ordinary21-state subset, FWASWRITTEN, event-only/private/unknown flags, signed
typing, failures/control flow, conflicts, cross-exec retirement, unchanged old
factories, one-pass/refusal behavior and immutable authority-free output.

Run those source controls under Python3.15 and3.9; retain actual counts, logs,
pilot faults, source/HEAD identities and modeled/native limits. No configured
native closure, CI, Git action, provider/target/native run or protected operation
belongs to this change. ROOT owns integration review, future CI and publication.

Final source validation passed unchanged36/v1, unchanged27/v2 and new16/v3
methods on Python3.15.2 and3.9.6, zero skips:79 per interpreter,158 total method
executions. The new ordinary-subset method includes42 command vectors, which
are not additional test methods. The first v3 pilot retained45 assertion failures
from cross-capture key-spelling comparisons; expected keys bind the entire raw
capture, so the controls now compare local key-equality structure and actual
in-capture key/version preservation. No engine semantics were weakened for that
test correction. All47 original regular files in both frozen stages, their file
sets, old test bytes, six pinned core source hashes and HEAD/ref identities were
reverified unchanged. Detailed logs, hashes, limits and pilot evidence remain
under this new staging directory; root peer review is pending.
