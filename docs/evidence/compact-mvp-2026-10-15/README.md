# Compact MVP integration evidence

15 October 2026. This record covers the combined `codex/mvp-r04-docs` feature
stack. The [implementation ledger](../../plans/mvp-implementation.md) records all
26 task branches and separates implemented behavior from remaining acceptance.
Main has not been merged. No binary or evidence release has been published.

## Local observations

`local-evidence.sha256` inventories retained local files relative to
`/private/tmp`, including 40 checked passing shared V02 receipts: sixteen Node,
sixteen Python and eight Lua cases. The corresponding command streams,
input/deployment inventories, Linux process-tree traces and extraction controls
are retained alongside the receipts. Mac signature checks are separate records;
an offline/signature pass does not imply complete macOS filesystem tracing.
The inventory also includes the five accepted Linux arm64 performance profiles,
their first/warm 1/32-rank measurements, and the macOS tracing capability failure.

The local receipt indexes are:

- `/private/tmp/glue-mvp-indexed-passing-receipts.json` — exact 40 selected receipts;
- `/private/tmp/glue-node-final-summary.json` — Node 24.22.0/26.10.0 covering cases;
- `/private/tmp/glue-python-matrix-final/matrix.json` — Python provider/version cases;
- `/private/tmp/glue-r03-linux-release-evidence/` — five complete cost profiles.

Verify the actual local bytes with:

```sh
cd /private/tmp
shasum -a 256 -c /Users/johannes.blaschke/Developer/glue_rs/docs/evidence/compact-mvp-2026-10-15/local-evidence.sha256
```

Replay a selected acceptance record and the accepted arm64 budget set with:

```sh
cd /Users/johannes.blaschke/Developer/glue_rs
python3 scripts/check-mvp-results.py /absolute/path/to/receipt.json
python3 scripts/check-mvp-budgets.py \
  --target aarch64-unknown-linux-gnu \
  --reports /private/tmp/glue-r03-linux-release-evidence
```

Receipts retain original artifact/runtime identities. Follow-up implementation
commits do not retroactively change those identities. Failed preparatory runs
are retained separately and are excluded from the selected passing set.

## Hosted checks and macOS capability

Portable run [38794420717](https://github.com/JBlaschke/glue_rs/actions/runs/38794420717)
passed all nine baseline/Lua55/packaging jobs across macOS arm64, Linux arm64
and Linux x86_64, on source `13ca6db64839aa5fb2a3b9fccec272db74d522ff`.
The complete job log and final status snapshot are included in the local
inventory. These portable results do not replace native runtime/trace cases.

The owner authorized publishing the combined feature branch and running hosted
acceptance. The first native x86_64 run, `38791248353`, built and ran all 24
applications successfully but failed validation: inherited sysfs caused the
offline detector to report host interfaces, and newer strace `clone3` formatting
exposed a parser rejection. Those original failed receipts remain unchanged at
`/private/tmp/glue-native-x86-evidence-38791248353`. This run supplies diagnostic
evidence, not a passed target cell or accepted performance budgets.

Subsequent strict replay exposed successful libuv io_uring operations and a PBS
Python 3.14.8 libffi temporary executable trampoline. The trace environment and
independent runtime candidate are described in the implementation ledger. Original
traces, replay classifications and failure identities are retained unchanged;
the candidate has no acceptance pass until the new hosted execution completes.

The [original Actions artifact](https://github.com/JBlaschke/glue_rs/actions/runs/38791248353/artifacts/12000323207)
has GitHub digest
`sha256:6bbac15911723824ef2d8da0f3f82dff4d3e40e2b2fd5ae5169121bcbd7ba8d5`
and expires on 29 October. Its source commit is
`08e778841055804fa79da93a819747e5c1b87e3f`. Actions retention is temporary.
Subsequent execution results are recorded in the implementation ledger after
completion.

Native administrator authentication succeeded on the current Mac. Both the
wildcard syscall preflight and an exact `syscall::open:entry` probe of an owned,
ad-hoc-signed fixture failed because System Integrity Protection blocks the
provider. The exact probe recorded zero events and never started its fixture
body. The [diagnostic fixture](../../../fixtures/mvp/macos-trace/README.md)
records commands, hashes and the requirements for a future complete Darwin
backend. No OS security policy was changed. Full macOS extraction acceptance
remains open.

## Retention

Following [decision 0030](../../decisions/0030-evidence-retention.md), this directory
commits narrative and SHA-256 inventories only. Bulk receipts, traces and logs
remain outside Git. There is no `bundle.json` because no evidence archive has
been published. A clone alone cannot retrieve the local files; the selected
evidence must be packaged, explicitly published and fetched/verified before
claiming durable shared retention or release closure.
