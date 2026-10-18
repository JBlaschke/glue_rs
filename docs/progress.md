# Implementation progress

## Tracing kit checkpoint — 18 October 2026

The fresh normal-boot guest proof reports exactly disabled SIP and passes an
independent complete source/command/observation review. Registration `9a294d4`
freezes the 41 tracing sources at `e2c728b`, preserving the legacy policy and a
separate explicit empty-registry fixture. The two affected kit suites pass all
23/12 controls. Actual committed source-lock/proof admission also passes.

The ordinary-user native host build now succeeds: all 21 compiler/signature/tool
commands return0, and all three signed programs are byte-identical across two
builds. The catalog derives its root/Data tuples from the new guest observation.
The binaries remain unexecuted and uninstalled; independent kit and catalog
reviews both pass. Earlier failed preflight/compiler attempts remain separate;
the failed native directory is explicitly partial and has no final inventory.

The separately reviewed two-case calibration source `d733783` and completed-kit
preservation source `6d3884f` are integrated with their original feature commits
preserved. Test portability repairs `e35987a` and `9cea001` are integrated through
`283a94e`. The affected five suites compose to 77 Mac passes and Linux 70 passes
with seven explicit skips, using the unchanged prior suites and repaired pair.
This is composed coverage across runs. Both new calibration CLIs still refuse activation; the
old four-case/SIM policy remains disabled. A concrete reviewed read-only kit03
inspection packet completed successfully. Both Library installations and exact
kit03 signatures survive; all 30 historical temporary roots are observed absent.
Its independent review is pending. Mutating retention remains disabled.
CI `7fdf01f` adds exactly two invocations (37 configured suites). The first five
affected Linux suites collect76 controls:68 pass,6 skip and2 test-portability
failures. Those receipts remain preserved; the repaired pair passes with its
declared skips. No complete37-suite or newer hosted result
is claimed.

The temporary guest-only SIP window remains OPEN, with restoration after the
tracing session still required. The physical Mac's SIP is unchanged. Full Darwin extraction
oracle/corpus/budgets, R02/M2 and durable evidence publication remain open.
The latest approved public checkpoint is still `e2c728b` with nine green jobs;
newer local source has not been published. Details and exact evidence identities
are in the [18 October checkpoint](plans/mvp-implementation.md#18-october-fresh-guest-only-tracing-window).
Documentation continues on `codex/mvp-r04-trace-build-status`.

## Compact MVP implementation — 17 October 2026

The 26 cards have separate `codex/mvp-*` feature branches. The owner merged the
integrated `codex/mvp-r04-docs` stack into `main` at `96e6958` (PR #34).
[The task/compatibility ledger](plans/mvp-implementation.md) records all branches,
executed target/runtime cells, commands and open evidence. Follow-up work uses
new feature branches; no release asset has been published.

The CI failures are repaired. The latest approved public source `e2c728b` on
`codex/mvp-r04-owned-trace-source-status` passes all nine jobs in
[run 39074320935](https://github.com/JBlaschke/glue_rs/actions/runs/39074320935).
It contains every earlier published MVP follow-up branch and is the next merge
point into `main`; merging its ancestors individually is unnecessary. Prefer a
merge commit to preserve ancestry. Newer local reader/packet/case/SIM work follows
in a separate reviewed checkpoint after publication and hosted CI.
Earlier approved source `162f91a` on the public deployment branch also passes
all nine jobs in [run12](https://github.com/JBlaschke/glue_rs/actions/runs/39021989631).
The two earlier failed runs remain unchanged. Native Ubuntu GCC13 additionally
passes all22 Python suites (334 passes,25 explicit skips); its one changed
production source and updated lock were independently reviewed.

The SIP-enabled VM completed the reviewed same-parent preservation of kit02,
then installed kit03 and ran its four-case nontracing bootstrap diagnostic.
The positive probe passed, simulated and denied execution returned their exact
expected errors, and a request with one trailing byte refused before output.
The raw exports and earlier failed packets remain unchanged. A stale duplicate
proof literal initially stopped the host checker before case reads; the reviewed
repair at `476b081` permits the independently replayed batch. SIM records a kill
attempt and a normal exit 120; it does not prove signal-caused termination.
Bootstrap messages and probe context remain producer observations, with
`tracing=false`, `exec_proved=false` and `full_acceptance=false`.

The reviewed coordinator and cooperative pipe-I/O observer now connect to a
separately compiled owned tracing parent (`d08dd5f`) and fixed libdtrace backend
(`6c75976`). Independent source/model reviews pass, including the repaired
transient cleanup-clock failure: tracing work cannot borrow the longer attempt
budget after cleanup binding fails. The native SDK binaries compile/link but
remain unexecuted; no provider or new guest diagnostic has run.

The separate tracing kit profile (`a395ead`) preserves the legacy policy and
requires exact disabled-SIP proof plus runner-only libdtrace linkage. Its registry
remains null/empty and refuses construction. Registration `7f15c40` updates six
of the existing 34 default source pins and the legacy host-parser literal,
preserving both enabled-SIP proofs and kit03's fixed approval. Replaying the
actual nontracing batch succeeds with identical native results and unchanged
input bytes/metadata; only the two host source identities change in its report.

CI at `9f281f1` invokes 30 Python suites collecting 454 controls: Mac 448 pass/six
skip; native offline Linux arm64 GCC 14 passes 413 with 41 explicit skips. All 214
tracing/script source pins match before/after/committed bytes in the repeated run.
The first run omitted the executed fetch shell helper from its source inventory;
it remains retained, and the corrected inventory covers every tracked script.
Exact outer command
argv/status/streams are retained. These are local Python/C receipts; the later
public `e2c728b` matrix separately covers this 30-suite checkpoint.

The independent fixed raw reader is now integrated at `ac7e27a`. Its 16 controls
pass on both Mac and native offline Linux arm64 without skips, including complete
valid mutation baselines and the 128 MiB streaming boundary. CI at `a1f0e88` now
configures 31 suites: coverage combines the preceding 30-suite aggregate and this
focused new suite. The new record pins all 217 tracing/script sources. An
independent passive audit verifies its complete inventory, source identities,
actual command receipts and the stated composition with the earlier aggregate.
The reader supplies raw transport facts, with no native capture,
GO/session/closure verdict, clock-domain equivalence, exec or extraction claim.
The separate complete positive/denied case checker is integrated at `e1db60e`;
its 11 synthetic groups pass. The separate packet at `5f96d29` remains
hard-disabled before input/output access. The repairs require successful command
and array reads, the actual endpoint sentinel and clean positive pump counts.
A fresh deployment proof, admitted tracing kit and reviewed packet activation
remain required before native calibration. SIM still refuses as uncalibrated.
CI `e40d33e` adds the three packet/gate/case suites. Their 43 controls pass on
each Mac and native offline Linux arm64 host without skips. All 229 selected source
pins match before/after/committed bytes. Coverage combines these focused results
with the earlier 30-suite aggregate and raw-reader suite; no single 34-suite run
or newer hosted result is claimed. An independent passive audit verifies the
complete inventories, source closure and actual command/completion receipts.
The separate SIM metadata predicate at `036d76f` retains literal unknown errors
and wait/kill observations only after declared cleanup. It returns no SIM pass
or calibration approval and performs no collection or file/VM operation. Its
20 focused controls pass on both hosts at CI `783ff41`, with all 233 source pins
matching before/after/committed bytes. Coverage for 35 configured suites combines
the retained runs; no single 35-suite run is claimed. Separate passive source and
CI/composition audits pass, with unchanged original inputs.
The full Darwin extraction oracle, macOS corpus/budgets, M2 and durable evidence
publication remain open. SIP stays enabled in the VM and on the physical host.
Exact source branches, commands and frozen records are in the
[17 October checkpoint](plans/mvp-implementation.md#17-october-deployment-configured-kit-and-hosted-follow-up).
Documentation continues on `codex/mvp-r04-trace-sim-status`.
The approved push of `e2c728b` replaced the earlier `ae48aee` request and completed
the nine-job matrix on its first attempt. It excludes the newer raw reader,
packet/case and SIM metadata follow-ups. A fresh ordinary-user guest inspection
also passed all six commands and again reports SIP enabled. Its literal current
device/FSID observations are a pre-Recovery baseline, not tracing admission.
The external 41-source tracing registry candidate matches `e2c728b` exactly;
the production registry remains empty until a fresh independently reviewed
post-reboot disabled-SIP proof exists. No new tracing diagnostic has run.

Implemented: schema-one compact distributions, deterministic atomic builder,
ELF/Mach-O closure and optional normalization, Lua54/55 helpers/projects/native
modules, stock Python discovery/environment/provider/native paths, stock Node
CJS/ESM/resources/Node-API, common CLI/config/rebuild, pinned portable CI, shared
relocated/offline execution, complete Linux extraction oracle and performance harness.
Historical schema-zero commands and memory experiments remain separate.

The owner chose ad-hoc signing for macOS development acceptance; Developer ID and
notarization are prerequisites for public binary releases. Current development
execution covers macOS arm64 and native Linux arm64. Hosted native Linux x86_64
passed all 24 acceptance cases and five enforced performance budgets, including
independent replay. The merged `main` also passed all nine portable CI jobs in
[run 38810513172](https://github.com/JBlaschke/glue_rs/actions/runs/38810513172).
Complete macOS process-tree tracing is blocked by SIP on the physical host.
The owner subsequently authorized temporarily disabling SIP only in the owned
UTM test VM, with restoration after tracing; guest authentication and actual
capture validation were initially pending. Capture metadata records SIP disabled.
V3/v4 preserve rejected callback layouts; v5 completes eight owned cases and
exposes lost parent coverage after failed spawn. V6's explicit target-PID exit
candidate completes the two open-only cases but fails all seven tree cases:
macOS also cleans up an old exec image carrying the live PID. Four of those
failed streams additionally reject stdout identities after unobserved children
append beyond the premature footer. Those failures remain unchanged while
process identity calibration continues. V7/v8 retain the exec-shadow flag and
correct the separate open-only drain ordering. All nine v8 diagnostics now pass
independent source-matched transport checks (2,647 events, no drops/errors,
consistent hashes). After restoration in Recovery and normal reboot, the
running guest reports SIP enabled; its read-only proof is independently verified.
A complete Darwin decoder/oracle and M2 remain
open: no missing execution is replaced with a cross-build, snapshot or skipped
test.

User instructions and installed tools are in [README](../README.md) and
[the compact CLI guide](compact-cli.md). Test results, exact runtime versions,
local evidence locations and host-scoped numeric performance budgets are linked
from the acceptance ledger. Raw logs/binaries/traces stay outside Git under
[decision 0030](decisions/0030-evidence-retention.md); publication remains pending.

Follow-up source branches include `codex/mvp-r02-darwin-state` (`6ce6ae2`,
26 independently reviewed synthetic state controls),
`codex/mvp-r04-evidence-retention` (`1dd9b90`, strict external-root bundles and
18 controls) and `codex/mvp-v01-evidence-ci` (`45e375f`, automated portable
evidence controls). The 18,588-file checkpoint round-trips unchanged and replays
94 receipts, ten budget profiles and 1,980 rank results from a new root.
Current documentation continues on `codex/mvp-r04-acceptance-followup`.

The subsequent R02 branches and their integrated commits are listed in the
[follow-up ledger](plans/mvp-implementation.md#task-branches). The strict reader
has 55 controls and rejects changes to enabled-probe descriptors within a
session. The owned-open observer has 13 controls and replays all 15 calls in two
completed v5 streams, retaining raw paths and flags without claiming resolved
kernel paths or file objects. The source-contract table records 161 pinned
syscall declarations and has 18 controls. None is a complete extraction oracle.
Status documentation continues on `codex/mvp-r04-darwin-calibration-status`.

`codex/mvp-r02-shadow-exit` (`a401d49`, integrated `aa570d8`),
`codex/mvp-r02-darwin-shadow-reader` (`729bfea`, integrated `ad6ff3f`) and
`codex/mvp-r02-open-drain-order` (`d4e9e93`, integrated `748a309`) implement the
calibrated diagnostic fixes. The six portable suites at that point collect 138 controls:
all pass on the Mac; Linux arm64 passes 136 with the two Darwin compiler checks
skipped. Fourteen separate native SDK/signature/collector controls also pass.
Final logs use `/private/tmp/glue-portable-darwin-final-*-20261016.log` and
`/private/tmp/glue-darwin-open-drain-native-root-20261016.log`. This establishes
owned capability transport, with full R02/M2 still open. Documentation continues
on `codex/mvp-r04-darwin-calibration-final`.

`codex/mvp-r02-raw-call-pairing` (`7a98e78`, integrated `12159ec`) adds an
independently reviewed capture/toolkit API that invokes the strict reader and
pairs opaque BSD/Mach frames by observed thread and exec epoch. Seven actual
v8 tree captures replay 1,083 BSD and 110 Mach returned pairs, plus 12 `exit`
and one `bsdthread_terminate` entry with explicit termination boundaries and
null return fields. All raw frames and original capture identities remain
unchanged. Seventeen rebuilt-hash controls and three independent adversarial
checks pass, including live Mach calls spanning exec-shadow cleanup. The API
provides no attested kernel generation, FD/path, mutation or Mach effects verdict.
`codex/mvp-v01-darwin-pairing-ci` adds its controls to the portable baseline:
seven suites collect 155 tests, all pass on macOS/Python 3.15; offline Linux
arm64/Python 3.11 passes 153 with two Darwin compiler checks skipped. Logs are
`/private/tmp/glue-portable-darwin-pairing-*-20261016.log`; raw pairing evidence
and independent review remain outside Git under the retention policy. Full
Darwin R02/M2 acceptance remains open.

`codex/mvp-r02-tree-open` (`ace2f55`, integrated `6b5b0ad`) observes named opens
through the strict pairing API without changing the historical open-only API.
Thirteen new controls pass. Independent replay of seven v8 tree captures yields
68 whole-stream opens: 52 calibrated nonnegative result tuples and 16 ENOENT
tuples, retaining every copied path byte, flag bit and observed identity.
These differ from the 17 selected controlled pairs across all nine diagnostics.
Evidence remains at `/private/tmp/glue-darwin-tree-open-evidence-20261016` and
`/private/tmp/glue-tree-open-independent-review-20261016`.
`codex/mvp-r02-mach-msg2-scalars` (`dcb1c5c`, integrated `8fc437a`) preserves
all paired/raw provenance and decodes only source-grounded packed scalar fields.
Six profiles explicitly report Mach tracing not enabled; the enabled capture
has 18 selected message pairs. Sixteen controls and independent actual replay
pass. Message bodies, consumed bytes, port objects, RPC results and completed
effects remain unresolved, including the SIP-off KOBJECT_CALL caveat. Evidence
remains at `/private/tmp/glue-mach-msg2-v8-replay-20261016`.
`codex/mvp-v01-darwin-scalar-ci` adds both suites to portable CI. All nine suites
collect 184 tests: all pass on macOS/Python 3.15, while offline Linux arm64/Python
3.11 passes 182 with two Darwin compiler checks skipped. Logs are
`/private/tmp/glue-portable-darwin-scalar-*-20261016.log`. Both observation APIs
and CLIs reject full extraction acceptance.

After owner approval, `codex/mvp-r04-darwin-followup-status` at
`8567d387f41862883de4ea830042d7408c8412ed` was pushed unchanged. All nine native
portable jobs passed in [run 38895660723](https://github.com/JBlaschke/glue_rs/actions/runs/38895660723):
baseline, Lua55 and packaging on Linux x86_64, Linux arm64 and macOS arm64.
Exact run/jobs metadata, source workflow/script and a hash manifest remain at
`/private/tmp/glue-portable-darwin-followup-38895660723-20261016`; the review
summary SHA256 is `b39c5caa9af6003cda46b2effe94e39d8851be6fc2ba3fb6a20138d8b829efc8`.
This is portable CI evidence for that exact source, with no new full macOS
product, signing, filesystem-trace or budget acceptance.
`codex/mvp-r04-darwin-hosted-ci` (`b824afb`) records this result locally; it is
not included in the approved `8567d38` push.

The owner completed guest-only restoration in Recovery, selected full boot
security, and unlocked the VM after normal reboot. The read-only running-guest
status observation at 2026-10-16T12:14:43Z reports exactly
`System Integrity Protection status: enabled.` All ten metadata commands exit
zero; the 35 indexed payload files and their manifest verify unchanged. The
script identifies `VirtualMac2,1`, arm64, macOS 26.6.2 / 25G83 and UID 501. It
changes no settings and makes no full R02 claim. Its manifest SHA256 is
`73c4f5abfd66ac9fdf61d7251b7d7a69cdceb02dc476b796fc790bda042512eb`.
The independent review remains at
`/private/tmp/glue-sip-restoration-independent-review-20261016`; retained status
bytes establish SIP enabled, with Recovery/normal-boot context observed
separately by the operator. They do not independently attest every boot-policy
setting. The physical Mac's SIP settings remain unchanged.

`codex/mvp-r04-darwin-restoration-evidence` (`439bb46`) retains a separate
[restoration and hosted-CI checkpoint](evidence/compact-mvp-darwin-restoration-2026-10-16/README.md):
57 selected files / 160,140 bytes, restored as 59 exact archive members with
matching hashes, sizes and modes. Earlier checkpoints remain unchanged. The
independent fresh restore confirms the same exact members and source/CI proof;
its review remains at
`/private/tmp/glue-restoration-checkpoint-independent-review-20261016`.
The 22,316-byte archive stays local; durable publication remains open.
`codex/mvp-r04-sip-restoration-status` records the current restoration status.

`codex/mvp-r04-macos-calibration-evidence` (`d44dd33`, integrated `aded39b`)
commits the [preliminary Darwin checkpoint](evidence/compact-mvp-darwin-calibration-2026-10-15/README.md)
README and hash inventories. Its 1,372 selected files restore as 1,374 archive
members; all 46 historical outcomes, 25 exports and seven pairing outputs
replay with exact hashes/modes under independent restoration. The separate candidate01 also restores and
replays on macOS and offline Linux arm64 tmpfs. No raw evidence or VM files
enter Git, and no archive has been published. This finite checkpoint covers
v3–v8 calibration and reviewed pairing; later tree-open/Mach scalar snapshots
remain separate. At preparation, guest SIP restoration awaited private owner
authentication in Recovery. The checkpoint contains no restored-SIP proof.
The physical Mac's policy remains unchanged. Full Darwin R02, macOS
product/budget acceptance and M2 remain open. Checkpoint status was recorded on
`codex/mvp-r04-darwin-followup-status`.

The next native boundary must run the target with an explicit non-root identity
after a verified bootstrap and before observed application exec; the current
calibration runs the target as root. The read-only source proposal at
`/private/tmp/glue-darwin-collector-identity-assessment-20261016/ASSESSMENT.md`
(SHA256 `7f9e472e1a915e7b5216a08a02a70a98baf0ad05fc3a6a3dedd30f8d73bea23e`)
records Darwin group-list, inherited-FD, signal, gate and login-context limits.
That assessment itself changes no code or credentials.
`codex/mvp-r02-target-credentials` (`ecc35f2`, integrated `6eae79b`) implements
the separate [owned-child credential primitive](../fixtures/mvp/macos-trace/target-credentials/README.md).
It validates explicit nonzero numeric IDs and a bounded nonempty primary-first
group list, checks the declared controller/calling parent, applies groups then
GID then UID, and verifies exact real/effective IDs and the ordered group vector.
Failures stop at their precise stage and preserve syscall errno; after any
mutation attempt the caller must exit the child on failure. No target launch,
collector integration or saved-ID/login/Mach/FD/gate assurance is supplied.
Fourteen native unprivileged controls and independent review pass, including
five additional injected-only ASan/UBSan controls. A separate offline Linux
container control succeeds only in its forked child with UID/GID 65534 and
groups `[65534]`, leaving the parent unchanged; privileged Darwin transition
calibration remains unavailable. Evidence and review remain at
`/private/tmp/glue-target-credentials-native-20261016` and
`/private/tmp/glue-target-credentials-independent-review-20261016`.

`codex/mvp-v01-darwin-credential-ci` adds that suite to the portable baseline.
Ten suites collect 198 controls: all pass on macOS/Python 3.15, and the offline
Linux arm64 root-run container passes 195 with two Darwin compiler checks and
one nonprivileged-only credential control explicitly skipped. Logs are
`/private/tmp/glue-portable-darwin-credentials-*-20261016.log`; the exact driver is
`/private/tmp/glue-portable-darwin-credentials-tests-20261016.sh`.
The five-file portable control record at
`/private/tmp/glue-target-credentials-portable-20261016` retains those exact logs,
driver and counts; its manifest SHA256 is
`846eb333185dcae2a20c7b1b86b627e70422e9dfad9f81f6d153966729d66656`.
The owner subsequently approved pushing exact
`64a4dd2d59e23820553521c5e21484dc81d421f4` on
`codex/mvp-v01-darwin-credential-ci`. The public branch matches that commit.
All nine portable jobs pass in
[run 38903379520](https://github.com/JBlaschke/glue_rs/actions/runs/38903379520):
baseline, Lua55 and packaging on native Linux x86_64, Linux arm64 and macOS
arm64. Each required pinned-tool native check step also succeeds. The run is
event `push`, attempt one, and checks that exact source. Its 13-file frozen
metadata root is
`/private/tmp/glue-portable-darwin-credential-38903379520-20261016`;
the summary SHA256 is
`9e8de1a631bad5fe87d462622ad3ab1b3983e886a2e2eaee194261f556bfabe5`
and manifest SHA256 is
`6fa02c86daa6203a5729299fad1000ce4ed8441abfbf855ba46450f154022072`.
Independent raw run/jobs and Git-object review confirms nine exact unique jobs,
native runner labels, required successful steps and byte-identical workflow/script
sources; its separate review root is
`/private/tmp/glue-portable-darwin-credential-38903379520-root-review-20261016`.
No raw captures, archives or VM files were published. This portable CI result
does not calibrate a privileged Darwin target transition, complete bootstrap,
filesystem/Mach extraction oracle, new macOS product corpus or budgets.
`codex/mvp-r04-credential-hosted-ci` records these results locally, outside the
approved `64a4dd2` push. Full Darwin R02/M2 is still open.
Kernel file/port object identity, consumed Mach messages and the full extraction
oracle remain separate implementation work before the product corpus can pass.

`codex/mvp-r02-target-descriptors` (`7ca6005`, integrated `27baa08`) adds the
[owned-child numeric descriptor helper](../fixtures/mvp/macos-trace/target-descriptors/README.md).
It uses a preallocated bounded Darwin self-inventory with spare capacity,
validates all five kept numbers before closing anything, closes each nonkeep
descriptor once and requires an exact rescan. It checks the declared original
controller and current blocked signals; reviewed single-threaded setup and no
endpoint rebinding remain caller preconditions. Errors preserve stage/errno;
ambiguous close/EINTR never retries or authorizes launch. No soft-limit loop,
endpoint-object authorization, stdio remapping, cwd, gate or collector integration
is supplied. Fifteen controls collect 14 native Mac passes and one Linux-only
skip; offline Linux passes ten injected/unsupported controls with five native
Mac controls skipped. Native Mac tests close sparse FD 4096 above the child's
lowered soft/hard limit 64 and verify parent handles/limits unchanged.
Independent source review and six extra injected-only ASan/UBSan control groups
pass. Evidence/reviews remain at `/private/tmp/glue-target-descriptors-native-20261016`,
`/private/tmp/glue-target-descriptors-source-review-7ca6005-20261016` and
`/private/tmp/glue-target-descriptors-independent-review-20261016`.

`codex/mvp-v01-darwin-descriptor-ci` adds its controls to portable baseline CI.
Eleven suites collect 213 controls: Mac/Python 3.15 passes 212 with the Linux-only
adapter check skipped; the offline Linux arm64 root-run container passes 205
with eight explicit skips. Exact logs/driver/counts are frozen in the five-file
`/private/tmp/glue-target-descriptors-portable-20261016` record, manifest SHA256
`fb44812df31148df74b4cf6a49a7e26600ea45463167bd455a3e8eccd2208ed5`.
This follow-up remains local, beyond the approved `64a4dd2` push and hosted run.
Privileged guest bootstrap and full Darwin R02/M2 remain open; SIP stays enabled.

The separate read-only bootstrap assessment at
`/private/tmp/glue-darwin-nonroot-bootstrap-assessment-20261016/ASSESSMENT.md`
(SHA256 `2822a0b1d64d92877760b868d2ab25e274bca037e18158d5bc30ca781fdb00bd`)
defines remaining endpoint, signal/cwd, fixed protocol, watchdog and versioned
reader work. It is a proposal, not an implemented target launcher or new capture.

`codex/mvp-r02-bootstrap-wire` (`f7ecb27`, `5a48e25`, integrated as `2d93b0d`,
`e6d9587`) adds pure fixed-record codecs, request/PID binding and a poisonable
sequence validator. Eleven controls and an independent review with two extra
ASan/UBSan boundary groups pass. `codex/mvp-r02-target-endpoints` (`d25ccf4`,
integrated `04fea27`) validates all five source roles before copying, keeps
stdio blocking and private FIFO controls nonblocking, and maps only inside the
owned child. Seventeen native controls pass on both Mac and unprivileged Linux;
the independent source/cross-component review passes. Neither helper authorizes
endpoint objects or integrates the collector.

`codex/mvp-r02-bootstrap-io` (`135acc5`, `07b6a29`, `2279299`, integrated as
`4362220`, `cfe0c81`, `4e59295`) adds bounded nonblocking record/EOF transport.
The first implementation's later clock check could hide an earlier fatal poll
error; the separate fix and regression control preserve its original errno.
All 18 controls pass on Mac, Mac ASan/UBSan and offline unprivileged Linux.
Independent review adds two sanitizer controls after partial transfers. Previous
logs remain unchanged. The root review at
`/private/tmp/glue-bootstrap-primitives-root-review-20261016` (manifest SHA256
`10c784ddb20d285828bc4293708911ac80339039b2e67744dd3bde44a3285d32`)
also records the corrected sanitizer invocation after an unused environment
variable made an earlier run ordinary C execution. Prefixes survive failure;
a failed GO write may already have released the child and must never be replayed.
EOF alone supplies no exec-success proof.

`codex/mvp-v01-bootstrap-primitives-ci` adds these three suites to the portable
baseline. Fourteen suites collect 259 controls: Mac passes 258 with one Linux-only
skip; offline Linux arm64, now explicitly running as UID/GID 65534, passes 252
with two Darwin compiler and five Darwin descriptor controls skipped. The exact
driver, logs and 53 source/data pins are retained in
`/private/tmp/glue-bootstrap-primitives-portable-v2-20261016`, manifest SHA256
`b832ed22c95a4cb2e7be2833261f5c6b3bdd255239463251be7b2d2e6b4e579c`.
Independent audit verifies all five files, both counts, exact suite argv and
all 53 code/data identities against the tested base and current checkout:
`/private/tmp/glue-bootstrap-portable-independent-review-20261016`, manifest
`8a2c81368fdf60d69c2a9b5b066aaf2cf32c36d679d04ce1428468ea0d9acb7e`.
Shell syntax and diff checks pass. These local follow-ups remain outside the
approved public `64a4dd2` push and its hosted run. The complete nonroot controller,
privileged Darwin calibration and full R02/M2 remain open; guest SIP stays enabled.

`codex/mvp-r02-bootstrap-signals` records its decision in `89997da`, implements
the lifecycle in `83148d9` and clarifies fresh-state ownership in `12fff2f`.
The parent snapshots its mask/SIGPIPE policy, rejects caught handlers and unsafe
SIGCHLD/autoreaping, then verifies blocked setup signals and temporary ignored
SIGPIPE. Only the known direct child can reset/check/release the declared
default-action/no-altstack policy; pending signals prevent release. Parent
restoration attempts both steps once, preserving the first failure and separate
verified outcomes. The caller must use fresh state and one attempt.
Fifteen groups collect 14 native Mac passes plus one Linux-only skip; offline
unprivileged Linux passes 11 with four Darwin-native skips. Mac ASan/UBSan passes
ten injected/data groups, with native controls explicitly skipped because the
instrumentation installs caught handlers. Initial native ENOMEM exposed the
Darwin libc zero-size alternate-stack-disable behavior; SIGSTKSZ fixes the
disable request without installing storage. Earlier failed logs are preserved.
Evidence is `/private/tmp/glue-bootstrap-signals-native-20261016`, manifest
`8cdfbc4cf251eb740dd478096f28edd1b3c8bbdfd633f0529c9b41918b1b1298`.
Independent review adds five injected fault scenarios under ASan/UBSan and checks
all canonical policy bytes:
`/private/tmp/glue-bootstrap-signals-independent-review-20261016`, manifest
`0ca7f14f811c6704a96a713e3f02474f284e6ec257303b0e516b023d012ba775`.
The helper performs no fork, credential change, exec, tracing or VM action.

`codex/mvp-r02-bootstrap-request` (`9f30258`, `49b44cf`, integrated `50f52d5`,
`d702927`) adds the canonical bounded request and complete READY comparison.
Eleven controls pass on Mac, Mac ASan/UBSan and unprivileged Linux; independent
review adds guard-page and wide-scalar rejection groups. Request hashing and
native admission remain outer-controller duties. The implicit closed argv
template derives its digest argument after hashing, avoiding self-reference.
Root review is `/private/tmp/glue-bootstrap-request-root-review-20261016`;
independent review is `/private/tmp/glue-bootstrap-request-independent-review-20261016`.

`codex/mvp-r02-bootstrap-probe` (`aed1a3a` through `ac36669`, integrated through
`885660b`) supplies a separate fixed 256-byte post-exec self-report. Twelve pure
controls pass on both hosts and Mac sanitizers. Thirteen native controls collect
11 Mac passes plus two explicit skips; offline Linux passes the argument/native-
unsupported checks with eleven Darwin skips. The genuine ordinary-user Mac
positive checks actual IDs/groups/cwd/stdio/signal/FD context and observes
`setuid(0)` fail with EPERM and unchanged IDs. This does not prove a root-to-
nonroot transition or kernel exec. Separate test-only fixes supply the Darwin
altstack wrapper size and deliberately open exact read-only stdin; the first
DEVNULL O_RDWR failure is preserved. Evidence is
`/private/tmp/glue-bootstrap-probe-native-20261016`, manifest
`8aedd2eb2fe4cbae5fd4a23c769a9807762969228e36442231716f921fc8b673`.
Independent review validates the actual report and six strict rejection controls
at `/private/tmp/glue-bootstrap-probe-independent-review-20261016`.

`codex/mvp-r02-bootstrap-admission` (`41b75ec`, `3f6d388`, integrated `e5e4b93`,
`ead94f0`) walks eight held components in the closed physical root/Data fixture
path and returns only checked ownership/type/mode/ACL/mount metadata. A source
review found that fresh filesec storage alone cannot rule out an ACL-allocation
false success; typed OWNER/GROUP/MODE presence and stat equality are mandatory
before interpreting ACL absence. All 15 Mac and sanitizer controls pass;
unprivileged Linux passes 14 with the Darwin read-only API control skipped.
Native root admission remains unexecuted. Evidence and independent injected
review are `/private/tmp/glue-bootstrap-admission-native-20261016` and
`/private/tmp/glue-bootstrap-admission-independent-review-20261016`.

`codex/mvp-r02-bootstrap-inspector` (`a16feac`, `d2bd45d`) adds a no-argument,
ordinary-user read-only deployment observation. Three controls pass two and skip
one platform case on each host. The strict-verified ad-hoc arm64 binary targets
macOS 26.0 and links libSystem only. Host facts, source/build hashes and logs are
at `/private/tmp/glue-bootstrap-inspector-native-20261016`, manifest
`e839a35474a4e5641bdf9e6f4bf973563f8ebc154853d534dc3c514493495120`.
Its independently reviewed kit is staged under
`/private/tmp/glue-mvp-macos-vm-toolkit/bootstrap-inspector-v1-20261016`; the VM
is locked and its read-only run awaits the owner unlocking it. No guest facts
or privileged transition are inferred from host results. Guest SIP stays enabled.

`codex/mvp-v01-bootstrap-context-ci` adds all six new suites. Twenty suites collect
328 controls: Mac passes 323 with five explicit skips; unprivileged offline Linux
passes 304 with 24 native/platform skips. Exact driver/logs/76 code-data identities
are frozen at `/private/tmp/glue-bootstrap-context-portable-20261016`, manifest
`e7c9a2dc64043ccef133e27632c98686b6da6880e3e2c5a7cd3cb8ff6571e4f2`.
Independent review checks all five retained files, 76 source/data pins, exact
twenty-suite driver/CI correspondence and every status/count/skip at
`/private/tmp/glue-bootstrap-context-independent-review-20261016`, manifest
`46a4d8246916fa24e6ce226cd4ef31ece5b15fb777ac88a645b7d981d85eb474`.
Shell syntax and diff checks pass. This checkpoint extends the approved public
`64a4dd2` run and the earlier unpublished `2f087d5` push candidate; the latest
controller CI follow-up is documented below.
The nontracing controller has separate follow-up commits below; privileged Darwin
calibration, collector integration and full R02/M2 stay open.

`codex/mvp-r02-bootstrap-runner` (`093629b` through `7c50621`, integrated through
`6cc8a7d` on `codex/mvp-r02-bootstrap-runner-integration`) now combines the reviewed
helpers into a standalone, nontracing controller for the closed context probe.
Only a compiled catalog can select the protected executable; default builds
refuse. Canonical requests explicitly declare numeric target credentials, and
READY/report comparisons do not authenticate a caller's authorization. One GO,
strict same-deadline status EOF, known direct-child reap, signal restoration and
checked resource closure precede exclusive final-result promotion. Any parent close
failure suppresses promotion, including capture-reader failures found in review.
Capture-valid flags distinguish unavailable counts/hashes from measured empty
output. CLI1 is a finalized failed diagnostic; CLI2 requires halting without
reading potentially live probe outputs. Final JSON also requires independent CLI
exit-status validation. All scope fields retain `tracing=false`,
`exec_proved=false` and `full_acceptance=false`.

Seven focused controls pass on Mac and unprivileged offline Linux; Mac ASan/UBSan
passes five with two explicit native-CLI exclusions. Source-isolated child,
parent and finalization models exercise ordering, error framing, partial/late
GO, ownership, close failures and promotion boundaries. Native execution covers
only argument/nonroot/unsupported refusal, before output creation. Root integration
review and reruns retain 61 source pins at
`/private/tmp/glue-bootstrap-runner-root-review-v2-20261016`, manifest
`992337ccad06a6ed0eaeebf4e8f7198daa3f880919e599ac078eab631e68ea6e`.
Producer evidence is `/private/tmp/glue-bootstrap-runner-native-v2-20261016`,
manifest `8c72230164f942cc64bfe4368321f7b8aa36ba3ff9816cd11dbacef891e47e0d`.
Independent parent/output/finalization review verifies the final source and
producer inventory and adds two injected ASan/UBSan cleanup controls at
`/private/tmp/glue-bootstrap-runner-independent-review-20261016`, manifest
`96fe0f3272a1fb59ec1c1d7229a1ccc7274c0e178e585c5638d14cbf3448252e`.
The initial GCC test-stub warning is preserved separately; its test-only fix
initializes injected helper error outputs without weakening compiler warnings.
Protected guest admission, actual root-to-user transition and collector adoption
remain unexecuted. The next read-only guest inspection still awaits VM unlock;
guest SIP remains enabled.

`codex/mvp-r02-bootstrap-kit` (`d62964c` through `bbd82ca`, integrated through
`02495ac`) adds a host-only guarded kit builder and a separate ordinary-user
request writer. The empty reviewed-input registry prevents configured builds;
actual guest inspection and complete reviewed source registration are still
required. The source/recipe/probe/catalog digest graph excludes its own outputs.
The request writer uses actual equal IDs and ordered kernel groups, complete
read-only directory metadata, checked closes and one canonical output write.
Unconfigured native refusal runs use the host OS target; exact min26 compilation
and Mach-O inspection do not execute that binary. An earlier dyld rejection of
`-no_uuid` is retained, and the recipe now requires the UUID load command.

Review found that failed compiler descendants could leave live writers. Failed,
timed-out, spawn, read or growth outcomes now retain explicitly partial metadata
without claiming a closed tree or final inventory. No retry is permitted while
cleanup is unresolved. Consumers require normal builder exit0 and a complete
verified inventory/result. Twenty-one controls pass on Mac; unprivileged offline
Linux passes 20 with one Darwin SDK skip. Two previously passed pure C sanitizer
controls retain identical C/header bytes and harness AST; no new sanitizer run is
claimed for the Python-only failure-record fixes. Final integration record:
`/private/tmp/glue-bootstrap-kit-root-review-v2-20261016`, manifest
`cd44a9c7093cce9830ee33fa9f23b107d37b101e7900b1176c3f090af5e1e803`.
Independent catalog/native-writer review and two additional sanitizer groups are
at `/private/tmp/glue-bootstrap-kit-independent-review-20261016`, manifest
`74bcac9e8e16b5f68bfb6419546ead1ad1692681b375d933a19d61a77ba8a7c8`.
Independent builder/parser/workflow review, four pure groups and the six-outcome
injected failure check are at
`/private/tmp/glue-bootstrap-kit-workflow-independent-review-20261016`, manifest
`58d1584c3689f847ec3963600c30248df28985737b47b5fd311d53199a3931e2`.
No configured kit, protected installation or privileged guest launch has run.

`codex/mvp-v01-bootstrap-controller-ci` adds the runner and kit suites to CI.
Twenty-two suites collect 356 controls. Local coverage composes the unchanged
earlier 20-suite source with the final 7-control runner and 21-control kit runs;
it records 351 Mac passes/five skips and 331 Linux passes/25 skips, not a single
22-suite driver execution. All 104 source/data/decision pins and exact CI argv
are checked at `/private/tmp/glue-bootstrap-controller-ci-coverage-20261016`,
manifest `c9ca1da93293f11b1dd2616ff71b6e85e4f44a7fd1423f2858ec96b452d398e5`.
Independent pin/argv/log/count review is retained at
`/private/tmp/glue-bootstrap-controller-ci-independent-review-20261016`, manifest
`01a5fdb968606b43330be837fffc7c6f0c673fbcc966a05941c6b57db70d0289`.
Shell syntax and diff checks pass; no complete portable job or hosted run for
this latest source is claimed. The older approved `64a4dd2` nine-job hosted
result remains separate; Rust/Cargo/toolchain files are unchanged since that run.
Full R02, Darwin corpus/budgets and M2 remain open.

`codex/mvp-v01-darwin-observation-ci` adds the owned-open observation and
pinned syscall-contract suites to the portable baseline. All six Python suites
collect 126 controls: 126 pass on macOS arm64/Python 3.15 and 124 pass with two
Darwin C compiler controls skipped on offline Linux arm64/Python 3.11.17. The
reader now rejects changed EPID bindings before the observation layer; its
malformed-capture tests accept that precise earlier rejection. These controls
do not establish native Darwin extraction acceptance. Logs remain at
`/private/tmp/glue-portable-darwin-followup-{macos,linux-arm64}-20261016.log`;
the implementation result is this feature branch's tip.

## Historical implementation record

The earlier feature work and evidence were merged into `main` at `6afed9a`.
Further implementation continues on separate feature branches.

| Step | Branch | State | Evidence |
| --- | --- | --- | --- |
| A0 experimental contracts and Rust workspace | `codex/a0-contracts` / `96e188b` | Implemented | 20 contract tests on macOS and Linux arm64 / Rust 1.88.0; format and Clippy clean on macOS |
| A4 archive/resource foundation | `codex/a4-archive-resources` / `c4b307f` (stacked on A0) | Implemented | 56 tests on macOS and Linux arm64; deterministic ZIP64, corrupt/unsupported input rejection and bounded resources |
| Packaging/inspection CLI scaffold | `codex/packaging-cli` / `4581386` (stacked on A4) | Implemented | 76 tests on macOS and Linux arm64; explicit-inventory builder and read-only CLI commands; format/Clippy clean |
| A3 Linux memfd fixture | `codex/a3-linux-memfd-probe` / `447a339` (stacked on CLI) | Controlled spike | 80 Rust tests on macOS/Linux arm64, 15 trace-policy tests; Clippy clean on both; native ordinary-loader comparison and full syscall checks pass |
| A6 linked Lua 5.4 source slice | `codex/a6-lua-linked-execution` / `03303d7` | Experimental implementation | macOS arm64 CLI fixture builds, reports readiness and prints the expected result; 111 Rust tests and workspace Clippy pass; Linux execution/trace evidence pending at this baseline |
| A6 Lua 5.5 compiled profile | `codex/a6-lua55-profile` / `cb88d7d` (stacked on `03303d7`) | Experimental implementation | Separate exact Lua 5.4.9/5.5.1 compiled profiles; macOS arm64 CLI execution and opposite-version rejection pass |
| A6 linked Lua Linux validation | `codex/a6-lua-linux-validation` / `8b6eb1f` (stacked on `cb88d7d`; evidence bundle follows) | Controlled observation | macOS/Linux arm64: 118/119 Rust tests for `lua54`/`lua55`, all-target Clippy clean for both; both relocated Linux profiles exit 0 with exact output and full trace checks; 27 Python policy tests pass |
| A6 C-owned Lua error boundary | `codex/a6-lua-c-boundary` / `ee7c9d3` (from merged `db2c271`) | Experimental implementation | macOS/Linux arm64: 142/143 Rust tests for `lua54`/`lua55`, Clippy clean for both; 50/51 optimized macOS boundary tests; both relocated Linux fixtures pass exact output and full no-extraction trace checks |
| A5/A6 Linux native Lua closure | `codex/a6-linux-native-lua` / `3a24833`, fixture cleanup `fb61e5e` (from merged `7853282`) | Experimental implementation; controlled observation | Mac/Linux source workspaces: 181/182 tests; GNU Linux native workspaces: 178/179; 37 portable native tests and 54 Python policy tests; Clippy clean for all profiles; both Lua versions match ordinary loading and pass complete two-memfd/no-payload-write traces; twelve ELF rejection traces pass before any memfd attempt |
| A1 signed macOS arm64 Mach-O probe | `codex/a1-macos-macho-probe` / `346b2f0` (from merged `a596305`) | Controlled signed observation; acceptance evidence incomplete | 31 portable/optimized parser tests; 212/213 source workspace tests for Lua 5.4/5.5 and Clippy on Mac/Linux; ad-hoc hardened-runtime/allow-jit debug and optimized launchers match ordinary loading; fourteen native rejections, four signing controls and two memory-policy controls pass; full trace and distribution signing remain open |
| A7/A10 pinned stock PBS inputs | `codex/a7-pbs-artifact-inspection` / `886a415` (from merged `1425d6d`) | Experimental build-time inspection; controlled observation | Mac/Linux: 268/269 source workspace tests, Clippy, 56 optimized inspector tests; 71 Python policy tests; byte-identical inventories of independently pinned stock PBS inputs and exact 4,526-entry install-only projection; full inspector trace passes |
| A7 stock PBS frozen startup | `codex/a7-linux-pbs-bootstrap` / `30a1526` (from merged `8b56f7c`; evidence bundle follows) | Experimental bootstrap fixture; controlled GNU Linux arm64 observation | Mac/Linux: 291/292 source workspace tests and Clippy; 64 inspector tests, 15 portable bundle/profile tests and 16 GNU opt-in release tests; 89 Python policy tests; unchanged stock libpython starts with frozen encodings and built-in math/_ssl; baseline output agrees and all four complete traces pass |
| A7 explicit host Python startup | `codex/a7-linux-host-python` / `a50ae86` (from merged `06b92ea`; evidence bundle follows) | Experimental host fixture; controlled GNU Linux arm64 observation | Mac/Linux: 308/309 source workspace tests and Clippy; 32 portable bootstrap/host tests and 34 GNU opt-in release tests; 112 Python policy tests; all eight clean host traces and four frozen-bootstrap regression traces pass |
| A7 Python archive source/resources | `codex/a7-python-archive-imports` / `94da8de` (from merged `29b3f76`; evidence bundle follows) | Experimental bundled source/resource adapter; controlled GNU Linux arm64 observation | Mac/Linux: 316/317 source workspace tests and Clippy; 40 portable Python tests and 45 GNU opt-in release tests; 141 Python policy tests and 16 importer protocol tests; all three clean import traces plus four frozen/eight installed-host startup regressions pass |
| A7 host Python archive source/resources | `codex/a7-host-python-archive-imports` / `9aababa` (from merged `f99bb51`; evidence bundle follows) | Experimental host source/resource adapter; controlled GNU Linux arm64 observation | Mac/Linux 327/328 workspace tests, Clippy, 51 portable/56 GNU Python tests; 161 trace-policy and 16 importer protocol tests; seven host-import and fifteen prior regression traces pass |
| A7 registered Python native initializers | `codex/a7-python-extension-init-bridge` / `b784c99` (from merged `a50b654`; evidence bundle follows) | Experimental registered-initializer profile; controlled GNU Linux arm64 observation | Mac/Linux 338/339 workspace tests and Clippy for Lua 5.4/5.5; 59 portable/65 GNU Python tests; 191 policy and 16 importer protocol tests; all eleven native and twenty-two prior regression traces pass; 37 hostile trace edits reject |
| A7 controlled Python product route | `codex/a7-python-runner-profile` / `32a9562` (from merged `f92ac34`; evidence bundle follows) | Experimental launcher integration; controlled GNU Linux arm64 observation | Mac/Linux 350/351 workspace tests and Clippy; 68 portable/73 GNU Python tests, 14 GNU runner CLI tests, 209 policy and 16 importer tests; all nine product and 33 earlier traces pass; 30 CLI controls match and 185 hostile trace edits reject |
| A7 bundled Python source applications | `codex/a7-python-source-apps` / `d3ddac3` (from merged `90c4a10`; evidence bundle follows) | Experimental bounded source applications; controlled GNU Linux arm64 observation | Mac/Linux 366/367 workspace tests and Clippy; 87 GNU Python/probe and 14 runner tests; 238 policy, 16 importer and 7 byte-entry tests; all six new and 42 regression traces pass/replay; 34 new and 30 existing CLI controls match; 198 hostile source-app edits reject |
| A7 explicit-host Python source applications | `codex/a7-host-source-apps` / `dd6274f` (from merged `cb3cae4`) | Experimental bounded host source applications; controlled GNU Linux arm64 observation | Full pinned snapshot and startup guards; Mac/Linux 381/382 tests and Clippy; 102 GNU Python/probe and 14 runner tests; 261 policy and 11 host protocol tests (2 Mac skips); all 13 new and 48 regression traces pass/replay; 51 new/34 bundled/30 original controls match; all 567 hostile edits reject |
| A7 install-only host Python source applications | `codex/a7-install-only-host-source-apps` / `7a8e32c` (from merged `442d9eb`) | Experimental stock install-only host applications; controlled GNU Linux arm64 observation | Exact 1,037-source/three-cache prerequisites; complete provider audit; Mac/Linux 395/396 tests and Clippy; 116 GNU Python/probe and 14 runner tests; 288 policies; all 16 new/61 regression traces pass/replay; 60/51/34/30 product controls match; all 894 hostile edits reject |
| A9 worker-message foundation | `codex/a9-worker-protocol` / `42197bb` (from merged `aae69ef`) | Experimental codec and controller ledger; synthetic workers | Mac/Linux source workspaces pass 432/433 tests for Lua 5.4/5.5 and Clippy; 37 optimized IPC/ledger/real-pipe tests per platform; complete Linux trace confirms 18 anonymous pipes, six synthetic child launches and exact crash/truncation controls; [evidence](evidence/worker-protocol-2026-10-12/README.md) |
| A7 Python distribution metadata | `codex/a7-python-distribution-metadata` / `80c4b33` (from merged `6cd8f96`) | Experimental bounded `.dist-info` applications through all three providers | Mac/Linux 441/442 workspace tests and Clippy; 125 optimized GNU Python/probe and 14 runner tests; 32 adapter and 227 Python policy tests; all nine new/35 source-profile regression traces pass/replay; 42 new CLI controls agree; all 189 hostile edits reject |
| A7/A10 Python installed-package ingestion | `codex/a7-python-venv-ingestion` / `35dae52` (from merged `6afed9a`) | Experimental source-only build adapter with explicit provider template | Mac/Linux source workspaces 452/453 tests and Clippy; Mac packaging workspace 465; 33 pack/129 GNU Python/16 runner tests; 235 Python policies; real offline pip installation; Mac/GNU both input modes and all 30 hostile build controls pass; all six new/nine metadata regression traces pass/replay; 27 product controls and 126 hostile trace mutations pass/reject |
| A7/A10 Python runtime templates | `codex/a7-python-runtime-templates` / `3d15bf9`, checker strengthening `525da19` (from merged `c0ddaa4`) | Experimental portable preparation of the three pinned metadata providers | Mac/GNU source workspaces 460/461 tests and Clippy; Mac packaging workspace 482; optimized GNU 135 Python/41 pack/19 CLI tests; both builders pass eight template generations, 45 hostile controls and three installed-package builds; all six runtime traces replay under unchanged policy and retain prior archive hashes; 27 product controls and 126 hostile mutations pass/reject; strengthened oracle passes 21 tests on Mac/stock GNU |
| A7/A10 Python host prerequisites | `codex/a7-python-host-prerequisites` / `42c5abe`, strict evidence checks `3f3f31a` (from merged `c4a901e`) | Experimental product preparation of both admitted host prerequisite trees | Mac/GNU source workspaces 476/477 tests and Clippy; Mac packaging workspace 506; optimized GNU 142 Python/49 pack/21 CLI tests; both builders pass four generations and 63 hostile controls; two complete preparation/six runtime traces pass/replay; 46 oracle/241 policy tests; 27 product checks and 149 hostile trace mutations pass/reject; [evidence](evidence/pbs-linux-arm64-python-host-prerequisites-2026-10-13/README.md) |
| A7/A10 Real Python package compatibility | `codex/a7-python-real-packages` / `e525db8` (from merged `fce3dad`) | Experimental Requires-Python admission and three unmodified upstream pure-Python wheels | Mac/GNU source workspaces 484/485 and Clippy; Mac packaging workspace 518; optimized GNU 150 Python/53 pack/21 CLI; clean matrix passes three providers and three first-entry CRC rejections; both builders pass 32 requirement controls/two compatible builds; 21 oracle/253 policy tests and 229 hostile mutations; 27 product commands/5,273 valid members; [evidence](evidence/pbs-linux-arm64-python-real-packages-2026-10-14/README.md) |
| A7/A10 Pinned installed Python runtime trees | `codex/a7-python-installed-runtime-trees` / `b8fdbd1`, identity fix `801cbf6`, fixture staging `6b4499c` (merged `a52424c`) | Experimental selected-tree admission; controlled GNU Linux arm64 observation | Mac/GNU source 489/490 and Clippy; Mac packaging 533; GNU 154 Python/63 packaging/22 CLI; five valid preparations per builder, Mac20/GNU19 hostile controls; 24 tree/15 process-oracle/253 policy tests; all six raw/compressed runtime traces pass and archives retain previous hashes; 69 actual preparation mutations reject; [evidence](evidence/pbs-linux-arm64-python-runtime-trees-2026-10-14/README.md) |
| A7/A10 Pinned stripped host Python | `codex/a7-python-stripped-host` / `aef2f71` (stacked on runtime-tree evidence `421b24f`) | Experimental separate host-install metadata image; controlled GNU Linux arm64 observation | Mac packaging workspace 541 and source workspaces 496/497, Clippy clean; GNU optimized Python160/pack63/CLI23 and Clippy; four valid/twenty hostile preparations per builder; 20 preparation/23 process/5 runtime/11 trace units; seven native runtime traces pass; all 350 runtime/69 tree/21 artifact trace mutations reject; independent paired tar/ELF inspection and identical 1,037 sources/three caches; 38,093,257-byte prerequisites; [evidence](evidence/pbs-linux-arm64-python-stripped-host-2026-10-14/README.md) |
| A7 Registered Python native lifecycle | `codex/a7-python-native-lifecycle` / `9b1c386` (from merged `3f6bf8f`) | Experimental separate custom-create/owned-state profile; controlled GNU Linux arm64 observation | GNU source 501/502, Mac source Lua5.5 502/Mac packaging Lua5.4 546 and Clippy; GNU optimized Python165 and Clippy; independent stock baseline/seven ledger controls; all eleven new and eleven historical native traces pass; 22 Mac/stock-Python units and 264 historical units; all 33 hostile trace edits reject; five states freed/five references released after finalization on success and app error; [evidence](evidence/pbs-linux-arm64-python-native-lifecycle-2026-10-14/README.md) |
| A7 Python native package members | `codex/a7-python-native-package-imports` / `dd8cdd3` (from merged `478ebcd`) | Experimental stock dynamic-loader route for three dotted native children of an archive source package | Mac packaging Lua5.4 550/source Lua5.5 506 and GNU source 505/506, Clippy clean; GNU optimized Python170; independent stock descriptor-loader proof; eleven new and 22 historical native cases pass/replay; 300 policy units and all 20 hostile edits reject; exact unchanged native images and API4 boundary; five states freed/five references released after finalization; [evidence](evidence/pbs-linux-arm64-python-native-packages-2026-10-15/README.md) |
| Review hygiene and evidence retention | `claude/hygiene-and-evidence-policy` (from merged `a4e6ec1`) | Implemented | CONTRIBUTING toolchain guidance verified to select Rust 1.88.0 on the development Mac; 31 merged local branches pruned; [decision 0030](decisions/0030-evidence-retention.md) moves new evidence payloads to verified release assets; dry run packs the 2026-10-15 native-package bundle and verifies its inventory |
| A7/A1 macOS host Python product harness | `claude/relaxed-torvalds-a9df39` (from `108b4d0` on `claude/distracted-wozniak-c2a76a`) | Checked-in product harness and exact checker for the macOS arm64 cell; controlled observation on one cell | `run-product-macos.sh` runs the default-feature checks, the feature-enabled build, tests and lints, the no-boundary build, the six control installations, the seven macOS archives and a portably staged GNU Linux declaration, then records doctor, inspect, verify and run receipts from the poisoned environment; `check-product-results.py` matches every status and stream exactly; doctor Ready and run PASS, six installation rejections and the loader override at status 1, the GNU Linux declaration and the no-boundary build at status 2; workspace 514, runtime 177 and runner 23 tests and Clippy clean; installation snapshot unchanged; [decision 0034](decisions/0034-macos-python-product-harness.md); [evidence](evidence/macos-arm64-python-product-harness-2026-10-15/README.md) |
| A7/A1 macOS host Python product route | `claude/distracted-wozniak-c2a76a` (from merged `28b0cab`) | Product `glue doctor`/`glue run` route for the explicit macOS arm64 host startup profile; controlled observation on one cell | Portable admission of `stock-pbs-host-startup-macos`; macOS readiness from the declared Darwin arm64 target, observed `kern.osproductversion` and 16 KiB page size; archive-backed payload read with re-applied bounds; doctor Ready and run PASS on the cell; six installation rejections, loader override, GNU Linux declarations and the no-boundary Mac build report their expected statuses; GNU Linux readiness unchanged; [decision 0032](decisions/0032-macos-python-product-route.md) |
| A7/A1 Explicit macOS host Python startup | `claude/macos-python-host` (from merged `0c9b522`) | Experimental macOS arm64 host provider for the pinned startup subset; controlled observation without a tracer | Pinned PBS 20261009 macOS install-only artifact and 264 verified headers; C boundary compiled with Apple clang; dyld path loading with LC_UUID binding; one success, one app error, six installation rejections, one loader-override rejection and one unsupported-mode status match exactly; 173 feature tests and Clippy clean; read-only installation snapshot unchanged; bundled macOS requirements measured in [decision 0031](decisions/0031-macos-python-host-startup.md) |
| A5 native capability survey and proposed contract | `claude/competent-keller-668fef` (from merged `0c9b522`) | Static survey; proposed contract; no loader change | 24 shared objects from four pinned cp313 manylinux aarch64 wheels (markupsafe 3.0.4, numpy 2.5.4, pydantic-core 2.50.1, cryptography 50.0.2) read statically and cross-checked against llvm-readelf with zero disagreements; all 444 distinct Python API imports exported by the pinned runtime; the current inspector rejects all 24 images before any import policy; Mac workspace 505 tests and Clippy clean on Rust 1.88.0; [decision 0033](decisions/0033-native-capability-contract.md) |

## Legacy gate status before the plan revision

G0, G1 and G2 are open. Linked official Lua 5.4.9 and 5.5.1 have explicit,
version-specific source-only profiles and optional GNU Linux arm64 native
profiles. This is partial A5/A6/G2 work; four-OS acceptance remains open.
The original Linux memfd spike remains a separate historical observation.
The product now integrates a controlled native Lua closure. General native
backends, general runtime/package compatibility, Node adapters, workers,
approved system-library profiles and signed deployment remain pending.
The archive and manifest are version 0. Lua is pinned to `lua-src` 551.0.2
with int64/float64 configuration. Stock conventional-GIL CPython 3.13.16 / PBS
`20261009` full, unstripped install-only and separately identified stripped
install-only inputs are pinned for the GNU Linux
arm64 inspection and separate frozen/installed-host startup experiments; other runtime pins and Python execution profiles still
depend on platform experiments. The logical Lua build ID is not a compiler
configuration or artifact hash. See [the base profile decision](decisions/0005-linked-lua-source-profile.md)
and [version selection](decisions/0006-versioned-linked-lua-profiles.md).

The profile branch added mutually exclusive compiled `lua54` (default) and
`lua55` profiles with exact manifest identities. Supporting both versions through
separate launchers does not provide simultaneous multi-runtime acquisition or
worker execution.

The new C boundary replaces `mlua` in the source adapter. C owns the Lua state,
allocator, protected execution and result construction. Rust only serves archive
requests and catches callback panics; it never receives a Lua state. Replies are
released before C propagates an error, including allocation failures. Logical build
IDs now select source-v2/c-boundary-1, so v1 archives require rebuilding.
See [the boundary decision](decisions/0007-lua-c-error-boundary.md).

## Local test environments

The initial host is macOS arm64. Rust 1.88.0 is installed through Rustup; its
toolchain directory was placed first in PATH to avoid the Homebrew Rust 1.99
executables. `scripts/test-linux.sh` vendors the locked dependencies and runs
tests offline in a read-only Podman container with build outputs in memory.
Its default Linux arm64 image is Rust 1.88.0 / Debian bookworm, pinned by digest
`sha256:93717e495a1029ba94b9b4a5768cf14d5376077d26cfad3354cbe70be27c2b1d`.
This cell does not supply Linux x86_64 execution evidence.

The native fixture ran from clean commit `447a339` on Linux
`7.1.4-200.fc44.aarch64`, glibc `2.36-9+deb12u10`, GCC 12.2.0, 4 KiB pages and
`vm.memfd_noexec=0`. It returned 42/7/1 for function/data/constructor observations
with ordinary loading and archive memfds, and passed the full trace checker.
The [evidence record](evidence/linux-arm64-memfd-2026-10-08/README.md) retains the
commands, image identity, source and artifact hashes, test logs and raw trace.
The [probe decision](decisions/0004-linux-memfd-probe.md) lists its limits.

The synthetic resource fixture produces 1,469 archive bytes for 57 uncompressed
resource bytes, with SHA-256
`e2fa199105c8cffde55ec2dd403f27d3e1dc334c399aa334afba133c64be7d85`.
It is a packaging/resource fixture and contains no actual Lua runtime.
Its selected `host` provider still returns status 2; the linked runtime is never
used as a fallback. Separate [linked fixtures](../fixtures/lua-linked/README.md)
declare the exact source/build/ABI and macOS arm64 or GNU Linux arm64 target.
At the Lua 5.4 baseline, the macOS arm64 fixture was built through the CLI, reported ready through
`doctor`, and printed its expected nested-import/asset result. The complete
workspace passed 111 Rust tests and Clippy with warnings denied on this host.
The final validation branch passed 118 Rust tests with `lua54` and 119 with
`lua55` on macOS and GNU Linux arm64, and all-target Clippy with warnings denied
for both. Lua 5.5 built
through the CLI, reported ready for 5.5.1, and printed the expected `Lua 5.5`
result. Its fixture archive SHA-256 is
`4c0d21b1e8b2bec3bd146280958f0ddf958c03f7177451eb2049b9e3570a0094`.
Opposite-version archives return 1 without executing source; 27 Python
trace-policy tests pass.

The final Linux captures used clean commit `8b6eb1f` on
`codex/a6-lua-linux-validation`, stacked on source profiles `cb88d7d`. Both
relocated Lua fixtures exited 0 with exactly the expected stdout and empty
stderr, and passed full `strace` checks. The observed arm64 cell used Linux
`7.1.4-200.fc44.aarch64`, glibc `2.36-9+deb12u10`, Rust 1.88.0, GCC 12.2.0,
strace 6.1 and 4 KiB pages. Direct Podman commands were used because the
sandboxed wrapper could not access its socket. The
[retained evidence](evidence/linux-arm64-lua-2026-10-08/README.md) contains
commands, source/fixture/artifact identities, all build-provenance instances,
feature trees, test/Clippy logs and raw traces. These debug source-only
observations remain separate from the native probe and do not establish the
declared minimum kernel/glibc versions or other platforms/architectures.

The C-owned source adapter was captured from clean implementation `ee7c9d3` on
2026-10-09 using the same pinned Linux image and observed arm64 environment.
Both workspace profiles pass 142/143 Rust tests and all-target Clippy on macOS
and GNU Linux; the optimized macOS boundary suites pass 50/51 tests. Both new
relocated, read-only Linux fixtures produce exactly 55 stdout bytes, empty stderr,
exit 0 and pass the full trace checker. The
[boundary evidence](evidence/linux-arm64-lua-c-boundary-2026-10-09/README.md)
retains the fresh source/artifact identities, all provenance records, raw traces
and Mac/Linux test logs. The strict C-only error boundary is implemented for
this source profile; general native and platform/release acceptance remain pending.

The native Lua closure was captured from clean `fb61e5e` on 2026-10-09 using
the same immutable image and observed GNU Linux arm64 environment. Both source
workspace profiles pass 181/182 tests on Mac and Linux; native-feature profiles
pass 178/179 on GNU Linux and 177/178 on Mac, where the loader is unsupported.
All four profiles pass all-target Clippy with warnings denied on both systems.
Optimized Mac native C-boundary suites pass 53/54 tests. Both relocated native
fixtures match ordinary loading of the same compiled Lua core, exit 0 with
exact output and empty stderr, and pass full traces proving two completely
sealed memfds before loading and no payload filesystem mutation. All six
adversarial ELF cases per version reject with exact diagnostics and statuses
before any memfd attempt. The
[native evidence](evidence/linux-arm64-native-lua-2026-10-09/README.md)
retains all fourteen traces, source/artifact hashes, build provenance and
Mac/Linux validation logs. This completes the controlled Linux native Lua
slice, with the platform, release and general compatibility gates still open.

The signed macOS arm64 probe was captured from clean `346b2f0` on 2026-10-09.
Debug and optimized launchers use only the allow-jit entitlement under hardened
runtime and match ordinary dyld loading after PID normalization. All seven
native rejections per launcher and signing/memory-policy controls pass with
exact results. Source workspaces pass 212/213 tests and Clippy on Mac/Linux;
the parser has 31 tests, also passing in optimized Mac builds. The
[macOS evidence](evidence/macos-arm64-macho-2026-10-09/README.md)
retains source/artifact identities, signatures, inspections and tool denials.
This is a native-only fixture with an unacquired Lua scaffold. Full independent
filesystem/VM tracing is unavailable under current rights and no Developer ID
identity is available; A1 release acceptance and G0/G1 remain open.

The PBS inspector was captured from clean `886a415` on 2026-10-09. It pins stock
conventional-GIL CPython 3.13.16 / PBS `20261009` for GNU Linux arm64 and verifies
full and unstripped install-only inputs without extraction. All 6,574 full and
4,526 retained install-only member identities agree with independent inventories;
Mac/Linux optimized reports are byte-identical. Both source workspaces pass
268/269 tests and Clippy; both optimized inspector suites pass 56 tests and
all 71 Python policy tests pass. The complete Linux inspector trace passes
read-only input, no-payload-mapping/no-mutation and sole-process checks.
[The evidence](evidence/pbs-linux-arm64-inspection-2026-10-09/README.md) retains
pins, upstream records, complete compressed reports/trace, source/artifact
identities, candidate metadata, independent file research and validation logs.
The actual libpython registers `math`/`_ssl` in its file table, but its size and
ABS64/TLSDESC relocations exceed the current Lua loader profile. This is A7/A10
build-time input work; that inspection did not acquire or execute Python and
G0/G1 remain open. See [the decision](decisions/0010-pinned-pbs-inspection.md).

The separate stock PBS bootstrap uses the exact unchanged shared library and
public `PyImport_FrozenModules` before isolated public-API initialization. Six
pinned startup sources are compiled by the matching stock producer at build time;
the C bridge owns configuration, Python references, error buffers and finalization.
Actual GNU Linux arm64 execution imports frozen `encodings` and built-in `math`
and `_ssl`, returns 42, and agrees with ordinary loading of the same library and
bundle. This is a startup subset, rather than a complete Python stdlib/importer
or a host provider. The generic Lua loader limits remain unchanged; the probe
admits one exact larger stock runtime image through the system loader and sealed
memfd. The clean optimized capture from `30a1526` on 2026-10-10 passes success,
missing-encodings, corrupt-bytecode and app-error traces after removing the stock
producer/stdlib/headers. The unprivileged runtime container has read-only inputs,
no workspace mount and unavailable temporary paths. All four complete traces
prove archive byte coverage, one fully sealed private image, exact diagnostics
and exits, and no payload filesystem mutation or extra process. The
[bootstrap evidence](evidence/pbs-linux-arm64-bootstrap-2026-10-10/README.md)
retains the compiled bundle, commands, source/artifact/provenance identities,
complete compressed traces, controls and validation logs. See
[the bootstrap decision](decisions/0011-stock-pbs-frozen-bootstrap.md).

The explicit host startup fixture selects that exact stock library with its own
installed stdlib, and the archive contains only the shared app. Rust verifies
the library and all six startup sources before loading and rejects symlinks,
missing/altered inputs and existing startup bytecode caches. C uses the installed
prefixes and one stdlib search path without inserting a custom frozen table.
The library/stdlib mount is immutable and read-only; the verified source subset
does not certify arbitrary mutable installations or the complete stdlib. The
shared app proves version/ABI mode, isolation, UTF-8 and installed encodings with
built-in math/_ssl. Product host discovery, application imports and native
extension integration remain open. See
[the host startup decision](decisions/0012-explicit-host-python-startup.md).

The clean optimized host capture from `a50ae86` passes all eight complete traces,
including six prerequisite rejections before Python loading and a controlled
application error. The 2,741-byte successful archive contains only the app.
The same clean source also passes four fresh frozen-bootstrap regression traces.
The [host evidence](evidence/pbs-linux-arm64-host-python-2026-10-10/README.md)
retains both captures, installed input/archive identities, commands, C provenance,
test logs and independently replayed compressed traces.

The archive source/resource fixture extends bundled frozen startup with a
Rust-owned immutable source index and a small C request boundary. The unchanged
stock runtime imports modules, packages and one-portion namespaces from source,
with virtual origins and normal import-cache/reload/failure behavior. Actual
`importlib.resources` supplies read-only streams; archive Traversables reject
`as_file` and legacy `path` before temporary-file attempts. All 2,174 pinned
stdlib `.py` members are retained as a source-only projection, without claiming
complete stdlib/package compatibility. This remains a controlled bundled adapter;
host-provider archive imports and product integration still need evidence. See
[the source/resource decision](decisions/0013-python-archive-source-resources.md).

The clean optimized capture from `94da8de` matches ordinary loading and passes
all three complete import traces after removing producer/stdlib/library/headers.
Its 83,092,207-byte archive declares 2,194 resources. Syntax errors retain virtual
origins without compiler diagnostic source lookups in the observed UTF-8 cell;
an `atexit` callback reads resources during finalization. Corrupt stored source
rejects before memfd creation. The same implementation also passes four fresh
frozen and eight installed-host startup regression traces. The
[import evidence](evidence/pbs-linux-arm64-python-imports-2026-10-10/README.md)
retains all fifteen independently replayed compressed traces, exact manifests,
input/source/artifact identities, C provenance and validation logs. Host-provider
archive imports, general diagnostic source consumers and product integration
remain pending.

The next A7 implementation, on `codex/a7-host-python-archive-imports` from merged
`f99bb51`, shares the source/resource adapter with an explicit installed host
runtime. Its exact 18-resource archive holds only application/helper/assets;
the host owns the stdlib. Six startup plus 63 supplemental sources are pinned,
and all relevant bytecode caches must be absent before loading. Reserved names
cover stock built-ins, frozen aliases, bridge modules and stdlib roots. Host
module/namespace lures exercise fallback blocking. The unchanged C API revision 3
and shared invocation retain all owners through finalization. See
[the host archive-import decision](decisions/0014-host-python-archive-imports.md).

The clean optimized host-import capture from `9aababa` passes all seven complete
traces and agrees with ordinary loading. Its 13,932-byte archive contains only
18 app/helper/resource entries. All 69 installed sources are verified before
loading; Python subsequently reopens 67 for this workload. Corrupt archive
source rejects before host lookup; altered/missing supplemental sources and a
nested cache reject before Python mapping. The same clean implementation passes
three bundled-import, four frozen-startup and eight installed-host startup
regressions. All 22 retained compressed traces independently replay, and 29
hostile actual-trace mutations reject. Mac/Linux source assemblies pass 327/328
tests and Clippy for Lua 5.4/5.5; every fresh GNU opt-in build passes 56 tests and
Clippy. All 161 Python policy tests and both 16-test importer protocol cells pass.
The [host-import evidence](evidence/pbs-linux-arm64-host-imports-2026-10-10/README.md)
retains exact source/artifact/input identities, manifests, C provenance,
commands, validation logs and complete traces. At that checkpoint, product
Python integration, native extension initialization and general diagnostic
consumers remained open.

The registered native A7 slice, implemented as `b784c99` on
`codex/a7-python-extension-init-bridge` from merged `a50b654`, registers reviewed `PyInit_*` addresses through public
`PyImport_AppendInittab` before initialization. Stock `BuiltinImporter` owns
single-phase (`m_size=-1`) and multi-phase protocols, cache/reload/removal and
failure cleanup. Runtime and native providers vary independently over four
bundled/explicit-host and archived/explicit-host cells. The runtime stays
`RTLD_LOCAL`; every function/data relocation and initializer address is checked
against its admitted image owner before Python starts. C boundary API4 has 29
public exports/240 bytes and pins copied registration names through process exit.
The source/resource conformance app and its finalization callback are reused.
See [the registered initializer decision](decisions/0015-python-registered-extensions.md).
The [clean native evidence](evidence/pbs-linux-arm64-python-extensions-2026-10-10/README.md)
retains all eleven native cases and twenty-two earlier Python regressions from
the same implementation commit, plus exact native files, manifests, source/input
identities, commands and validation logs. All 37 independent hostile trace edits
reject. This profile does not implement generic extension-file discovery or
close the platform/product gates.

The controlled Python route moves the existing provider/import/registration
mechanisms into `glue-runtime-python`, with the historical preparer/probe as a
thin experimental wrapper. `glue run` dispatches by the selected component ABI
and transfers the same opened archive into the opaque, synchronous executor.
Python remains optional through `python-pbs`; the build verifies the matching
stock headers only on the exact supported GNU Linux arm64 target. `doctor`
checks admitted declarations and build/target readiness; execution checks the
selected archive bounds, content and explicit host prerequisites. Default Lua
execution retains its original 64 MiB member bound while inspection can admit
the pinned 73,563,968-byte Python runtime. See
[the integration decision](decisions/0016-controlled-python-runner.md).
The [clean runner evidence](evidence/pbs-linux-arm64-python-runner-2026-10-11/README.md)
retains all nine actual product traces and 33 earlier regression traces from
`32a9562`. Every compressed trace replays, all 30 CLI controls match exact
archive contents/statuses, and an independent audit rejects all 185 hostile
actual-trace edits. Mac/Linux source profiles pass 350/351 tests and Clippy;
Mac Python-enabled workspace checks also pass, while GNU execution remains
opt-in and limited to the controlled registry. General application/host-stdlib
admission, runtime version selection and other platforms remained later steps
at that checkpoint.

The next bundled source profile accepts application-owned source and assets,
with a declared script entry below `app/` and imports below `app/python/`.
Runtime, all 2,174 stdlib sources, importer and frozen-startup identities stay
pinned. Portable admission checks bounded inventories, runtime-name collisions,
module layout and source-only payload paths before acquisition. A trusted entry
launcher compiles verified bytes through the existing importer and runs them
as `__main__` with virtual metadata. The C bridge and loader remain unchanged.
`glue build` selects the larger pinned-runtime policy from its same parsed
manifest before looking up input resources. See
[the source application decision](decisions/0017-bundled-python-source-apps.md).

The [clean source-app evidence](evidence/pbs-linux-arm64-python-source-apps-2026-10-12/README.md)
retains six actual application invocations and 42 fresh prior-route regressions
from `d3ddac3`. All 48 compressed traces replay. Independent controls agree with
the actual build/inventory/entry bytes and expected statuses; all 198 hostile
actual-source-app trace edits reject. Source workspaces pass 366/367 tests and
Clippy on Mac/Linux, the Mac Python-enabled workspace passes 366, and optimized
GNU Python/probe builds pass 87. Policy/importer/entry suites pass 238/16/7 on
both Mac and the pinned stock Linux interpreter. The C bridge, API4 table and
Linux loader mechanisms remain byte-identical to the merged parent. This expands
bundled application source admission while preserving the exact runtime/stdlib
pins; general host-stdlib admission, version selection and other platforms remain
open.

The paired explicit-host source profile uses the same admitted applications
with a full verified host source snapshot. All 2,174 sources (39,158,056 bytes)
and the selected library verify before loading; derived caches and startup
shadows reject. Snapshot sources close promptly into owned bytes, while startup
and directory owners remain live through finalization. A trusted prelude removes
ordinary filesystem import fallback before the unchanged importer runs. Host
startup still requires immutable read-only installed paths, and the mapped
library requires immutable backing for process life. See
[decision 0018](decisions/0018-host-python-source-apps.md).

The [clean host source-app evidence](evidence/pbs-linux-arm64-python-host-source-apps-2026-10-12/README.md)
retains 13 new and 48 fresh regression traces from `dd6274f`, all replayed.
All 51 new, 34 bundled-app and 30 original product controls match; all 567
hostile actual-trace edits reject. Mac/Linux source workspaces pass 381/382
tests and Clippy, the Mac Python-enabled workspace passes 381, and optimized
GNU Python/probe builds pass 102. Policy/importer/entry protocols pass 261/16/7
on both interpreters; host source protocol tests pass all 11 on stock Linux
and run 11 with two stock-only skips on Mac. The C bridge, API4 table and
selected GNU library mapping implementation remain unchanged. This supports the
exact full projection; broader installation/package compatibility and version
selection remain open.

The separate install-only host identity uses all 1,037 source files and the
three exact encoding caches shipped by the independently pinned distribution.
Closed cache admission and byte/hash verification precede runtime loading;
all other derived caches and startup shadows reject. Source bytes are owned
before initialization, while cache/startup/directory owners remain live through
finalization. A separate total-descriptor cap prevents the smaller inventory
from implicitly widening prefix depth. The full-source host identity retains
its own inventory and cache rejection; no provider subset is selected silently.
See [decision 0019](decisions/0019-install-only-host-python-source-apps.md).

The [clean install-only host evidence](evidence/pbs-linux-arm64-python-install-host-source-apps-2026-10-12/README.md)
retains 16 new and 61 fresh regression traces from `7a8e32c`, all replayed.
Stock normalized mtimes make the three observed caches stale; traces read each
cache completely, close it and read its matching source. Runtime admission
checks bytes/path identity without imposing those exact mtimes on every host.
An independent post-runtime audit verifies all ten complete stock/control trees
on a case-sensitive Linux volume before cleanup. Mac/Linux workspaces pass
395/396 tests and Clippy; optimized GNU builds pass 116 Python/probe and 14 CLI
tests. Policy/importer/entry protocols pass 288/16/7; host protocol runs 11 with
two Mac skips and passes all 11 on stock Linux. All 60 new and 51/34/30 prior
product controls agree; all 894 hostile actual-trace edits reject. The C bridge
and selected GNU library mapping implementation remain unchanged. Broader host
installations, runtime versions and package/platform compatibility remain open.

The A9 foundation captured from clean `42197bb` freezes bounded version-0
messages, integer tags and controller ordering. Independent byte vectors and
real anonymous-pipe tests cover values, errors, cancellation/draining and
crash-versus-framing EOF. Mac/Linux source workspaces pass 432/433 tests and
Clippy for both Lua profiles; both optimized IPC suites pass all 37 tests.
The [retained evidence](evidence/worker-protocol-2026-10-12/README.md) includes
the full Linux pipe-test trace, source/artifact identities and validation logs.
No product/runtime worker or cross-language invocation is implemented; G4
remains open. See [decision 0020](decisions/0020-worker-message-protocol.md).

The [clean metadata evidence](evidence/pbs-linux-arm64-python-metadata-2026-10-13/README.md)
retains nine new and 35 fresh source-profile regression traces from `80c4b33`,
all replayed. Three metadata-aware build identities expose bounded `.dist-info`
through stock public metadata APIs, including plugin loading and virtual RECORD
files. Malformed RECORD paths and CRC damage reject before provider acquisition;
actual physical host metadata lures remain invisible. All 42 new product controls
agree, 6,615 valid archive members verify independently, and all 189 hostile
trace edits reject. Mac/Linux workspaces pass 441/442 tests and Clippy; optimized
GNU builds pass 125 Python/probe and 14 runner tests. Metadata/importer/entry
protocols pass 32/16/7; the Python policy suite passes 227 on both interpreters.
The legacy importer, C boundary and selected GNU library mapping files remain
unchanged. Generic wheel/venv ingestion and wider package/provider/platform
compatibility remain open. See [decision 0021](decisions/0021-python-distribution-metadata.md).

The [clean installed-package evidence](evidence/pbs-linux-arm64-python-venv-2026-10-13/README.md)
retains six new and nine fresh metadata-profile regression traces from `35dae52`,
all replayed. `glue build-python` normalizes a complete source-only package tree
or conventional Python 3.13 venv against an explicit admitted provider template.
It verifies original RECORD ownership/integrity, preserves retained bytes and
reports omitted caches/generated wrappers and deterministic RECORD rewriting.
A genuine offline pip installation exercises all three providers. Mac/GNU
controls pass both input modes and all 30 hostile cases; the Mac venv interpreter
target is absent, and three GNU build process traces show no child/interpreter
execution. Independent checks verify 4,427 valid members, three CRC controls,
27 product commands and all transformation reports; all 126 hostile trace
mutations reject. Workspaces pass 452/453 tests and Clippy, the Mac packaging
workspace passes 465, optimized GNU suites pass 129 Python/33 pack/16 runner,
and Python policies pass 235 on both interpreters. Runtime/helper/loader bodies
are unchanged. General runtime-template provisioning, package compatibility,
dependency solving and native/platform support remain open. See
[decision 0022](decisions/0022-python-installed-package-ingestion.md).

The [clean runtime-template evidence](evidence/pbs-linux-arm64-python-runtime-templates-2026-10-13/README.md)
retains portable Mac preparation and six GNU runtime traces from `3d15bf9`.
`glue python-template` now supplies `build-python` directly with the pinned
bundled library/source/frozen inputs or explicit unverified full/install-only
host declarations. Eight successful generations, 45 hostile controls and three
genuine installed-package builds pass on both builders. Every resulting archive
retains its previous byte identity, and runtime/helper/loader bodies and the
six-mode trace policy are unchanged. The strengthened preparation-process oracle
from `525da19` passes all 21 tests and actual/compressed trace replays. Product
runtime installation, uv discovery, version selection and broader package/native
compatibility remain open; preparation does not close runtime/platform gates.

The [clean host-prerequisite evidence](evidence/pbs-linux-arm64-python-host-prerequisites-2026-10-13/README.md)
adds `glue python-host` for both pinned PBS host projections on Unix builders.
Complete artifact inspection and selected payload identities precede exclusive
publication; all files/directories receive fixed permissions and mtimes, and
provenance records complete/selected/omitted inventory facts. Mac/GNU each pass
four preparations and 63 hostile controls, while a closed 46-test process oracle
checks two complete native preparation traces. Six runtime traces and all 149
hostile mutations pass/reject; all archive hashes retain their previous identity.
An isolated strict adapter derives the install-only root's 191 entries from the
exact source/cache pins, replacing the prior complete stock tree's 193 for this
workload only. Historical policies, product runtime/loader/helper bodies and
template bodies remain unchanged. The 241-test policy suite and independent
27-command/4,427-member product audit pass. Complete installation/discovery,
version selection and broader package/native/platform compatibility remain open.
See [decision 0024](decisions/0024-python-host-prerequisites.md).

The [clean real-package evidence](evidence/pbs-linux-arm64-python-real-packages-2026-10-14/README.md)
uses unmodified markdown-it-py 4.2.0, mdit-py-plugins 0.6.1 and mdurl 0.1.2 wheels.
Stock offline pip installs 261 files; the independently verified projection
retains 152 application resources, omits 110 caches/one generated wrapper and
rewrites only RECORD. Ordinary stock Python and all three archive providers agree
on rendering/tokens, real metadata, resources/licenses and a loaded console
callable. Mac/GNU each pass 32 requirement rejection commands and two compatible
builds, with provider files/input interpreters absent and existing outputs
protected. Shared Requires-Python admission rejects incompatible/unsupported
release constraints before provider reads/publication; explicit application
metadata receives the same early check. Six complete runtime traces replay;
all 229 hostile mutations reject. Historical policies/C/helper/loader bodies
remain unchanged; narrowly scoped new predicates cover five failed terminal
queries and one install-only anonymous growth/release. See
[decision 0025](decisions/0025-python-real-package-compatibility.md).

## Next critical-path assignments

Use [the MVP queue](plans/mvp-tasks.md), whose dependencies and acceptance checks
replace the former platform-first and Python-before-Node assignments:

1. C01: translate compact/runtime contracts into versioned shared types.
2. V01: automate existing portable checks; V02 then establishes target receipts.
3. L01: expose both existing Lua families as selectable helpers.
4. P00: prove stock multi-version Python bootstrap with archived stdlib.
5. N00: prove stock Node archive hooks and an existing native addon now.

Then implement compact distribution writing, Linux/macOS native collection and
the three independent input adapters. The exact pinned Python/native profiles
remain regression evidence, not the admission model for new project inputs.
No native-capable MVP is complete without all three languages. Node can proceed
alongside Python; Windows, BSD and general mixed-language workers are deferred.

The macOS native memory loader remains substantial work: actual runtime TLS,
unwinding, image identity and signed deployment are not established by the small
spike or host-startup route. Follow the [separate roadmap](plans/memory-roadmap.md)
instead of blocking compact packaging on general dyld replacement. Decision 0033
remains useful static-corpus evidence, not a completed dynamic loader contract.

## MVP implementation — C01 (15 October 2026)

- Branch `codex/mvp-c01-contracts`, based on `6b49cc5`; result: branch tip.
- Added explicit schema one distribution/runtime/native/launch/report/lock and
  stable diagnostic APIs; schema zero fixtures retain their interpretation.
- `cargo test -p glue-format --locked`: 55 tests passed on macOS arm64,
  Rust 1.88.0. `cargo clippy -p glue-format --all-targets --locked -- -D warnings`
  passed. Examples round-trip all three language descriptors, reject ambiguous
  modes, path collisions, escapes, cycles and runtime mismatches.
- Decision 0036 describes the schema change. Runtime execution is subsequent work.

## MVP implementation — C02 (15 October 2026)

- Branch `codex/mvp-c02-distribution`, based on C01 `c599587`; result: branch tip.
- Added bounded shared staging/build API, deterministic archive/lock/report,
  launcher and notices, payload modes/internal links, exclusive atomic directory
  publication and output/staging traversal exclusion. Native bytes stay deployed.
- Product bounds: 100,000 archive entries, 1 GiB archived input, 8 GiB deployed
  payload and 100,000 deployed files (configurable); original archive decode,
  per-entry and central-directory bounds remain enforced.
- `cargo test -p glue-pack --locked`: 24 tests passed on macOS arm64/Rust 1.88.0,
  including deterministic distinct roots, overlap, collisions, missing/escaped
  input, output preservation, safe links, modes and complete size accounting.
- The exclusive rename boundary uses the platform's no-replace primitive.
  Linux native execution remains a target-cell check; no release gate is claimed.

## MVP implementation — C03 (15 October 2026)

- Branch `codex/mvp-c03-linux-native`, based on C02 `74308df`; result: branch tip.
- Added ELF64 dynamic inspection and deterministic explicit-root native closure
  collection. Preserves relative paths, records SONAME/dependency/version/feature
  facts, rejects missing edges, target mismatch, path escape and identity conflicts.
  TLS, unwind and GNU hash facts do not inherit memory-mapper restrictions.
- macOS arm64 parser/closure tests and pinned Clippy passed. A separate Linux-only
  test compiles independent fixture inputs, compares readelf and executes the
  relocated module plus secondary library through dlopen with TLS state.
- Absolute/cwd-dependent load paths produce transformation-required diagnostics;
  optional normalization tooling and x86_64 native execution remain pending.
  This card is implemented partially until those acceptance requirements pass.

## MVP implementation — C04 (15 October 2026)

- Branch `codex/mvp-c04-macos-native`, based on C03 `bdc186e`; result: branch tip.
- Added bounded thin/universal Mach-O inspection, actual loader-chain rpath
  resolution, native target/OS-floor checks, preserved relative closure paths,
  explicit metadata normalization with input/output hashes and verified ad-hoc
  re-signing. Host-prefix paths reject without explicit normalization.
- `cargo test -p glue-pack --test native_macos --locked`: 3 passed on macOS arm64,
  including ordinary independently compiled bundle + secondary dylib, copied to
  Unicode/space path, original input deleted, native dlopen execution and final
  codesign verification for unchanged and normalized paths. otool independently
  confirms the dependency. Missing edges, slice mismatch and OS floor reject.
- Pinned Clippy passed. C03's separate offline Linux arm64 run passed all 3 tests,
  including real relocation/TLS execution and readelf comparison. x86_64 native
  execution remains unexecuted. Public Developer ID/notarization is R02 evidence.

## MVP implementation — V01 (15 October 2026)

- Branch `codex/mvp-v01-portable-ci`, based on C04 `25eb646`; result: branch tip.
- Added native Linux x86_64/Linux arm64/macOS arm64 GitHub jobs for baseline,
  Lua55 and packaging suites. Rust/Clippy 1.88.0, expected native host and locked
  dependencies are checked explicitly. Lua features run separately.
- `scripts/ci-portable.sh baseline` passed locally on macOS arm64 (workspace
  tests, formatting and all-target Clippy); raw log is local at
  `/private/tmp/glue-mvp-v01-baseline.log`. `sh -n` passed.
- Hosted jobs are configured, not yet executed. No signing/evidence assets are
  required; portable checks do not substitute for target product receipts.

## MVP implementation — C05 (15 October 2026)

- Branch `codex/mvp-c05-builder-cli`, based on V01 `dc8e659` plus reviewed task
  handoffs L01 `f78cdd5`, L02 `8ee9e76`, L03 `9f00c96`; result: branch tip.
- Added high-level language dispatch slots and working Lua compact build/run,
  TOML defaults with CLI precedence, compact inspection/size/doctor, sibling
  integrity verification, literal placeholder expansion and direct Unix exec.
  Payload write bits may be removed for immutable deployment; required read/exec
  bits and hashes remain checked. No shell or missing-payload recovery exists.
- Pinned runner tests passed (21 legacy + 3 new CLI tests); new tests execute a
  relocated read-only distribution with deleted project, unrelated cwd, Unicode,
  spaces and placeholder-looking path; stdin/out/err, literal argv, exit 7,
  SIGINT/SIGTERM, config errors and missing sibling rejection pass. Clippy passed.
- Reproduce: build/install the glue-owned Lua helpers, then
  `glue build lua fixtures/mvp/lua-projects/first --lua 5.4 --output /tmp/lua-app`;
  `/tmp/lua-app/glue run /tmp/lua-app/app.glue -- argument`.
- Python and Node slots are intentionally integrated in R01 after their provider
  handoffs. This is source/native Lua functionality, not M2 closure.

## MVP native acceptance update (15 October 2026)

Native Linux x86_64 [run 38800548172](https://github.com/JBlaschke/glue_rs/actions/runs/38800548172)
tested [source e3962701](https://github.com/JBlaschke/glue_rs/commit/e3962701f558c287515508c97df4679e08d64ed2)
and passed all 24 acceptance cases: both Lua families, twelve Python
3.12.15/3.13.16/3.14.8 cases and eight Node 24.22.0/26.10.0 cases. The supplied
3.14 conda runtime includes a compatible prebuilt compiler-runtime closure;
packaging neither rebuilt native inputs nor relaxed conflicting-identity checks.
All five reviewed R03 budgets, measured with 10,000 added entries at 1 and 32
ranks, passed in enforcement mode. Independent replay verified all receipts,
fifteen benchmark-variant traces, negative controls and 990 rank results.

The run explicitly inherits
[`traceable-native-syscalls-v1`](decisions/mvp-v02-ci-trace-environment.md),
which returns ENOSYS for asynchronous kernel I/O in the complete stock/reference,
packaged, control and rank trees. Fixed structure/I/O/scaling limits apply across
hosts; time/RSS remain scoped to the recorded host fingerprint. No controlled
cold-cache result or unrestricted ring-enabled-host acceptance is claimed.

[Artifact 12005186009](https://github.com/JBlaschke/glue_rs/actions/runs/38800548172/artifacts/12005186009)
retains the raw evidence, ZIP SHA256
`c1cc519d76e73888ed0339714deec1e97eea816c1f8861ab551da4579644e7a4`.
Local replay is
`/private/tmp/glue-native-x86-evidence-38800548172/independent-replay.json`.
The artifact currently expires on 29 October; durable evidence publication
remains open. The complete Darwin decoder/oracle is still unimplemented and
unvalidated, so Mac R02 corpus/controls/budgets and M2 remain open. Developer ID
and notarization are later public-release gates. Current task refs, commands and
remaining work are recorded in the [implementation ledger](plans/mvp-implementation.md).
