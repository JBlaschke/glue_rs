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
their first/warm 1/32-rank measurements, all 24 native x86 acceptance cases and
five enforced x86 profiles from run 38800548172, earlier diagnostic runs,
and the physical Mac's and test VM's tracing capability failures. Failed native input builds
remain retained separately and do not count as passing cases.

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
Subsequent portable run
[38796670079](https://github.com/JBlaschke/glue_rs/actions/runs/38796670079)
also passed all nine jobs on source `26bc25446cf257794947394e8075267a43ae3029`.

The owner authorized publishing the combined feature branch and running hosted
acceptance. The first native x86_64 run, `38791248353`, built and ran all 24
applications successfully but failed validation: inherited sysfs caused the
offline detector to report host interfaces, and newer strace `clone3` formatting
exposed a parser rejection. Those original failed receipts remain unchanged at
`/private/tmp/glue-native-x86-evidence-38791248353`. This run supplies diagnostic
evidence, not a passed target cell or accepted performance budgets.

Subsequent strict replay exposed successful libuv io_uring operations and a PBS
Python 3.14.8 libffi temporary executable trampoline. The trace environment and
independent runtime input are described in the implementation ledger. Original
traces, replay classifications and failure identities are retained unchanged;
the original failed receipts are not promoted to acceptance.

Native run
[38796669924](https://github.com/JBlaschke/glue_rs/actions/runs/38796669924)
on source `26bc25446cf257794947394e8075267a43ae3029` subsequently passed 23 of
24 acceptance cases, including the independent Python 3.14 source/module/console
inputs. The remaining native build rejected conflicting conda/host libgcc
identities before publication or execution. All five R03 profiles passed;
independent Linux replay checked 15 receipts, 60 oracle controls and 990 rank
results before freezing their numeric budgets. Retained raw files, metadata and
review records are under `/private/tmp/glue-native-x86-evidence-38796669924`.
Its [Actions artifact](https://github.com/JBlaschke/glue_rs/actions/runs/38796669924/artifacts/12003666300)
has ZIP SHA-256
`9dea9422cefedf9d938164883cb088a82fb3757f6dbc9ed4bfe422ba104d68a8`.
This execution uses the explicit `traceable-native-syscalls-v1` environment;
it does not establish unrestricted-host acceptance. This historical run did not
close the target; the corrected rerun below supplies that evidence.

Native run
[38800548172](https://github.com/JBlaschke/glue_rs/actions/runs/38800548172)
on source `e3962701f558c287515508c97df4679e08d64ed2` passed all 24 acceptance
cases and all five frozen, reviewed R03 budgets in `enforce` mode. Independent
replay checked all 24 receipts, 15 benchmark variant receipts and traces, the
complete rank-result sets and the five accepted budget identities. A separate
Python 3.14 native review confirmed its unchanged runtime inputs, matching
conda C++ dependency closure and strict filesystem oracle result. This closes
the native Linux x86_64 target for the recorded `traceable-native-syscalls-v1`
CI environment. Timing and RSS limits remain scoped to the recorded host boot
fingerprint; structural byte/file/I/O/FD/scaling checks apply across hosts.

The retained artifact and replay are under
`/private/tmp/glue-native-x86-evidence-38800548172`. Its
[Actions artifact](https://github.com/JBlaschke/glue_rs/actions/runs/38800548172/artifacts/12005186009)
contains a 160,039,296-byte ZIP with SHA-256
`c1cc519d76e73888ed0339714deec1e97eea816c1f8861ab551da4579644e7a4`.
The independent replay SHA-256 is
`08a3f0b9c314d244539250b508f9bd01b828afef9b7103e813deee80cc7bbaec`.
GitHub retains this artifact until 29 October 2026. The immutable summary's
scope sentence still calls generated budgets proposed; its `budget_mode`,
copied accepted-budget hashes and successful independent enforcement establish
the actual mode. A subsequent wording fix does not rewrite that evidence.

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
backend. No physical host security policy was changed. The owner approved a
local UTM test VM, finished its Setup Assistant and supplied internal storage.
The guest identifies as arm64 VirtualMac2,1 with SIP enabled. Its authenticated
exact-name probe also returned the explicit SIP provider rejection, zero events
and no fixture execution. The result is retained under
`/private/tmp/glue-mvp-macos-vm-results/glue-mvp-guest-preflight-20261015T212252`.
Two earlier guest attempts failed at `dtrace -c` argument quoting and remain
diagnostic records rather than SIP evidence. Toolkit files are shared read-only;
only the dedicated test-results folder is writable. VM disk images and guest
credentials are excluded from evidence. After read-only Recovery inspection,
the owner chose to keep the guest's SIP enabled. `csrutil status` still reported
enabled immediately before its clean shutdown; no guest or host SIP change was
executed. The native diagnostic collector and strict raw reader are implemented
but always reject full-trace acceptance; a complete Darwin decoder/oracle and
actual macOS extraction acceptance remain open.

The integrated diagnostic reader passes 21 focused controls. The separately
reviewed normalized open-intent slice passes 11 controls, including ten actual
owned host fixture modes and comparison with compiled SDK constants. Those
self-reports are not kernel traces, and its acceptance API also rejects. The
host-only report is `/private/tmp/glue-darwin-open-intent-evidence/report.json`.
The retained guest toolkit includes a prepared nine-case native capture script;
that script was reviewed but not executed. VM trace acceptance is not inferred
from these host tests or the prepared script.

## Retention

Following [decision 0030](../../decisions/0030-evidence-retention.md), this directory
commits narrative and SHA-256 inventories only. Bulk receipts, traces and logs
remain outside Git. There is no `bundle.json` because no evidence archive has
been published. A clone alone cannot retrieve the local files; the selected
evidence must be packaged, explicitly published and fetched/verified before
claiming durable shared retention or release closure.
