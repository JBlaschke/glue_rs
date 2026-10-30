# Fixed runtime recipe in the owned object child

This separate, untraced profile really reaches `execve` through the existing
owned child sequence. Its compiled catalog supplies a general bounded argument
vector, copied before fork. The tested vector is `glue run /absolute/app.glue --
"argument with spaces"`; the first environment is exactly empty. It accepts no
shell text, expansion, PATH lookup, inherited environment, runtime CLI selector,
caller trust flag or app-ID allowlist. The existing R01 launcher remains
responsible for distribution/integrity/runtime dependency checks.

The compiled getter returns NULL by default. `reviewed-inputs.json` records the
exact empty source/proof state; no native catalog/recipe or proof is admitted.
The runtime controller and request utility refuse before filesystem or signal
work when unconfigured. Build scripts accept an optional **source translation
unit at build time**, as development tooling; the resulting native CLI still has
only `--request` and `--output`. A future admitted kit generator requires a
separate review and may not reuse the probe catalog generator as a runtime one.

The new RR request has distinct magic and closed fixture2/template2 selectors.
Its explicit canonical adapter retains common BR credential/path/bounds rules,
while both legacy and runtime decoders refuse the other wire profile. Exact
consumed request bytes are hashed and READY/GO binding stays unchanged. The new
runtime catalog binds target, full copied argv, empty environment, protected
launcher size/hash, source/recipe and R01 lock identities. The launcher limit is
16 MiB; the existing probe remains limited to 4 MiB.

The launcher is admitted under the existing protected root/build/leaf path.
An independent compiled fixed sibling CWD is opened relative to the admitted
GlueMVPFixtures parent, checked by the existing directory policy and bound to the
request. Its borrowed descriptor is selected after credential drop, omitted from
the five keeps and closed in the child by TD. The parent's separate descriptor
is closed once during cleanup. Actual output backing references, blocked setup
signals, full object READY, one GO/EOF/gate close, empty final mask, original
absolute deadlines and owned-child cleanup are retained.

The runtime result captures opaque stdout/stderr separately, each capped at
64 KiB for retained reads; the cap is not a filesystem quota. Oversize observations
retain measured size and failure without decoding or hashing unavailable bytes.
Raw wait status and actual exit/signal are recorded. Passing also requires
complete setup/gate/status state, normal reaped exit 0, valid bounded captures and
safe cleanup. Result/catalog/launch-plan schemas and output names are distinct
from probe data; no NP report or post-exec root-regain claim is invented.

The actual parent now retains `output-witness.bin` before any tracing or GO.
It contains both original held-reference sampling rounds and binds them to the
owner, actual child and exact request/catalog/first READY bytes. Completed
sample prefixes survive helper refusal; unread rows stay zero. An additive
observed helper shares the original match engine and keeps match publication
all-or-none. The new strict reader recomputes the comparison from these rows;
`objects_matched` in the result is advisory metadata.

After the actual gate write and close, `go-prefix.bin` retains only confirmed
original BIO bytes. `gate-delivery.bin` independently records their count,
write/error details and close outcome. A failed write can have delivered all
64 bytes; it remains failed. Retention attempts are claimed before fallible
operations and cannot be replayed. Successful finalization also requires both
witnesses to have been written. Complete `status.bin` and `launch-plan.bin`
remain separate original inputs. These bytes authenticate neither the collector
nor protected installation and grant no sink exemption or extraction verdict.

Run `python3 fixtures/mvp/macos-trace/bootstrap-runtime-runner/test_runtime_witness.py -v`
for independent byte/adapter controls and
`python3 fixtures/mvp/macos-trace/bootstrap-runtime-runner/test_runtime_runner.py -v`.
The controls separate pure request/catalog checks, production-child models,
ordinary file IO with explicitly modeled root metadata/protocol state, actual
wait/cleanup operations and an ordinary real child/gate/CWD/FD/exec fixture with
**modeled admission and credential mutation**. The fixture is not glue, and no
configured root bootstrap or compact runtime application runs. The unchanged
held-CWD and object controls remain separate evidence.

Actual glue later execs stock Python/Node, which creates its own declared
runtime environment. Later exec epochs/CLOEXEC/mapping transfer and quiescent
process/thread joins remain separate dependencies. A host-query implementation
may create helpers/threads; optimizing that query does not establish general
process-tree support. This profile rejects traced builds, keeps exec proof and
full acceptance false and leaves native runtime admission, full Mac oracle and
MVP acceptance open. No privileged action, provider, VM, sudo or SIP change is
performed by these controls.
