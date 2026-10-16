# MVP implementation and acceptance ledger

16 October 2026. Product authority remains [the plan](../../PLAN.md),
[the contract](mvp-contract.md) and [the 26 task cards](mvp-tasks.md).
Each card has its own local feature branch, with prerequisite commits stacked or
cherry-picked for integration. The owner merged the combined
`codex/mvp-r04-docs` stack into `main` at `96e6958` through
[PR #34](https://github.com/JBlaschke/glue_rs/pull/34). Task branches retain their
own implementation commits. Follow-up work continues on feature branches;
no release asset has been published.

Implementation and acceptance are separate. Shared contracts, the three compact
builders, ordinary-loader native routes, runtime/version discovery, integrity and
host checks, relocated/offline harness, Linux extraction oracle and benchmarks are
implemented. Native Linux x86_64 run
[38800548172](https://github.com/JBlaschke/glue_rs/actions/runs/38800548172)
passed all 24 acceptance cases and all five independently reviewed, enforced
performance budgets under the explicit CI trace policy. Its receipts, complete
traces, controls and rank streams also passed independent replay. The complete
Darwin process-tree decoder and extraction oracle remain unimplemented and
unvalidated. M2 therefore remains open.
Cross-compilation/emulation, snapshots,
ad-hoc signatures and skipped tests do not replace those observations.

The owner selected ad-hoc signing for development acceptance. Strict-valid
existing Developer ID signatures are retained and accepted by this development
policy; every image's actual signature class is recorded. Developer ID plus
notarization is required before publishing macOS binaries; it is a later release
check, not a claim established by the development signatures.

## Task branches

| Task | Feature branch | Current task commit | Implementation / remaining acceptance |
| --- | --- | --- | --- |
| C01 | `codex/mvp-c01-contracts` | `c599587` | Schema 1, descriptors, locks/reports, diagnostics; schema 0 preserved |
| C02 | `codex/mvp-c02-distribution` | `74308df` | Deterministic complete tree, atomic publication, integrity/accounting |
| C03 | `codex/mvp-c03-linux-native` | `d80eb32` | ELF closure, version/property checks, optional normalization; native x86 cases observed |
| C04 | `codex/mvp-c04-macos-native` | `ced7287` | Mach-O closure, unchanged/normalized relocation and strict signature checks |
| C05 | `codex/mvp-c05-builder-cli` | `e091fab` | CLI/config/process dispatch; initial Lua workflow and launch semantics |
| L01 | `codex/mvp-l01-lua-helpers` | `b5762a3` | Separate exact 5.4/5.5 helpers, bounded descriptor queries, one installation |
| L02 | `codex/mvp-l02-lua-projects` | `8ee9e76` | Directory/rocks ingestion, source/resources/native handoff |
| L03 | `codex/mvp-l03-lua-native` | `9f00c96` | OS-loaded modules/secondary deps, protected C boundary; both Linux architectures observed |
| P00 | `codex/mvp-p00-python-bootstrap` | `45e69db` | Stock multi-minor bootstrap proof and provider recipe |
| P01 | `codex/mvp-p01-python-discovery` | `56e8df4` | Existing environments/PBS/uv, bounded safe probes, foreign inspection |
| P02 | `codex/mvp-p02-python-provider` | `7dab743` | Bundled/explicit-host stock subprocess and archived stdlib |
| P03 | `codex/mvp-p03-python-inventory` | `8d422c0` | Installed source/data/metadata/namespace and entry inventory |
| P04 | `codex/mvp-p04-python-native` | `2abc06d` | Stock extension lifecycle, C/C++/Rust/scientific/FFI corpus; x86 3.12/3.13/3.14 native cases passed |
| P05 | `codex/mvp-p05-python-matrix` | `4555f45` | Version/provider/copy-venv matrix, runtime closure locks and pinned independent conda input with matching C++ runtime; all four x86 3.14 cases passed |
| N00 | `codex/mvp-n00-node-probe` | `e98ecc1` | Public stock-hook/bridge/addon proof |
| N01 | `codex/mvp-n01-node-provider` | `40f439c` | Bounded capability probes, native-header preflight, bundled/host provider |
| N02 | `codex/mvp-n02-node-resolution` | `10ca7f5` | Indexed CJS/ESM resolution and stock cache semantics |
| N03 | `codex/mvp-n03-node-project` | `119f7b0` | npm/pnpm installed graph and lock provenance, no package manager |
| N04 | `codex/mvp-n04-node-resources` | `44e7ca9` | Bounded read-only fs subset, streams and safe aliases |
| N05 | `codex/mvp-n05-node-addons` | `dae41af` | Existing Node-API addon/secondary closure across two majors; runtime closure locks and all eight hosted x86 cases |
| V01 | `codex/mvp-v01-portable-ci` | `d342e74` | Pinned native-host CI matrix; all nine hosted suites passed after helper fix |
| V02 | `codex/mvp-v02-relocated-harness` | `f6e7482` | Shared offline/relocation/reference protocol; current namespace proof and explicit traceable syscall policy |
| R01 | `codex/mvp-r01-workflows` | `448df87` | Three CLI adapters, inspect/doctor/size/rebuild, installer and end-to-end cases; accurate enforced-budget CI summary |
| R02 | `codex/mvp-r02-extraction-signing` | `d03b56f` | Complete Linux process-tree oracle and signing checks; bounded Darwin capability transport/diagnostic reader and normalized open-intent controls; full Darwin decoder/oracle unimplemented |
| R03 | `codex/mvp-r03-hpc-costs` | `05bd056` | Bounded buffered reader, measured 10,000-entry/32-rank harness and five reviewed budgets on each Linux architecture |
| R04 | `codex/mvp-r04-docs` | `d44ccb5` | User docs and compatibility/evidence ledger, merged through PR #34; M2 and durable evidence publication remain open |

Use `git log BRANCH` for each original task commit and
`git log codex/mvp-r04-docs` for the integrated stack. Follow-up fixes stay on their
owning card branch before integration. The table records implementation, not 26
completed acceptance gates. All nine portable jobs passed on merged `main`
`96e6958` in [run 38810513172](https://github.com/JBlaschke/glue_rs/actions/runs/38810513172).

Follow-up branches preserve the original task commits:

| Task | Follow-up branch | Commit | Verified scope |
| --- | --- | --- | --- |
| R02 | `codex/mvp-r02-darwin-capture-docs` | `695dd32` | Correct `proc:::exit` lifecycle-code documentation; integrated as `409f51c` |
| R02 | `codex/mvp-r02-darwin-state` | `6ce6ae2` | Synthetic process/thread generations, call pairing, FD/cwd inheritance and conservative race rejection; 26 controls, no native acceptance |
| R04 | `codex/mvp-r04-evidence-retention` | `1dd9b90` | Indexed external-root prepare/restore/fetch, 18 controls and unchanged full-bundle round trip; remote publication pending |
| V01 | `codex/mvp-v01-evidence-ci` | `45e375f` | Baseline runs evidence/reader/open-intent/state controls; Linux GNU tar fixture includes gzip |
| R02 | `codex/mvp-r02-native-diagnostics` | `3b44dce` | Bounded rejected-layout/libdtrace diagnostics preserve the first failure; integrated as `7ad6fce` |
| R02 | `codex/mvp-r02-native-layout-v2` | `281f1dd` | Exact assignment/scalar/path layouts, calibrated by v5; integrated as `cd9112c` |
| R02 | `codex/mvp-r02-target-exit` | `971fd7b` | Raw-v3 explicit target exit candidate; v6 rejects its incomplete exec-shadow handling; integrated as `17a6436` |
| R02 | `codex/mvp-r02-darwin-diagnostic-reader` | `e3274dd` | Strict source-matched diagnostics and raw-v2/v3 readers; v3 integrated as `2b7dc42` |
| R02 | `codex/mvp-r02-darwin-enabling-bindings` | `7135bca` | Session-stable EPID/probe/clause descriptors; 43 controls and all 2,592 retained v5 events replay; integrated as `b52b2f8` |
| R02 | `codex/mvp-r02-owned-open-observer` | `1408f3a` | Calibrated single-thread named-open observations, 13 controls and 15 whole-stream calls from two actual v5 captures; no kernel path/object or extraction claim |
| R02 | `codex/mvp-r02-darwin-syscall-coverage` | `9be06a1` | 161 pinned syscall declarations, argument/return facts and 18 controls; unresolved routes stay incomplete; integrated as `252b8a1` |
| V01 | `codex/mvp-v01-darwin-observation-ci` | `4177ab9` | Portable baseline adds owned-open and source-contract suites; 126 collected controls |
| R02 | `codex/mvp-r02-shadow-exit` | `a401d49` | Explicit target object/refcount distinguishes exec-shadow cleanup; integrated as `aa570d8` |
| R02 | `codex/mvp-r02-darwin-shadow-reader` | `729bfea` | Exact raw-v4 layout, shadow and terminal checks; 55 controls; integrated as `ad6ff3f` |
| R02 | `codex/mvp-r02-open-drain-order` | `d4e9e93` | Preserve queued open-only records after root wait; 14 native controls; integrated as `748a309` |
| R02 | `codex/mvp-r02-raw-call-pairing` | `7a98e78` | Strict-reader-backed opaque call pairing, 17 controls and seven actual tree replays; integrated as `12159ec` |
| V01 | `codex/mvp-v01-darwin-pairing-ci` | `1959c23` | Add pairing controls to the portable baseline; 155 collected controls |
| R02 | `codex/mvp-r02-tree-open` | `ace2f55` | Preserve calibrated named-open observations across process/thread lifetimes; 13 controls; integrated as `6b5b0ad` |
| R02 | `codex/mvp-r02-mach-msg2-scalars` | `dcb1c5c` | Observe packed scalar fields while keeping message effects unresolved; 16 controls; integrated as `8fc437a` |
| R02 | `codex/mvp-r02-target-credentials` | `ecc35f2` | Owned-child credential primitive and 14 controls; independently reviewed; integrated as `6eae79b`; collector integration/native privileged Darwin transition remain open |
| R02 | `codex/mvp-r02-target-descriptors` | `7ca6005` | Numeric owned-child FD closure with strict bounded self-inventory/rescan; 15 controls and two independent reviews; integrated as `27baa08`; no endpoint-object or collector integration claim |
| R02 | `codex/mvp-r02-bootstrap-wire` | `f7ecb27`, `5a48e25` | Fixed pure codecs and poisonable sequence validator; 11 controls and independent review; integrated as `2d93b0d`, `e6d9587` |
| R02 | `codex/mvp-r02-target-endpoints` | `d25ccf4` | Validate/copy five owned sources before child stdio mapping; 17 native controls on Mac and unprivileged Linux; independently reviewed; integrated as `04fea27` |
| R02 | `codex/mvp-r02-bootstrap-io` | `135acc5`, `07b6a29`, `2279299` | Nonblocking fixed-record/EOF transport, original poll-error precedence and documentation clarification; 18 controls plus independent sanitizer review; integrated as `4362220`, `cfe0c81`, `4e59295` |
| R02 | `codex/mvp-r02-bootstrap-signals` | `89997da`, `83148d9`, `12fff2f` | Single-attempt parent signal snapshot/restoration and owned-child reset/release; 15 controls and five extra independent sanitizer scenarios; privileged transition unexecuted |
| R02 | `codex/mvp-r02-bootstrap-request` | `9f30258`, `49b44cf` | Pure canonical request and complete READY comparison; 11 controls and two extra independent sanitizer groups; integrated as `50f52d5`, `d702927` |
| R02 | `codex/mvp-r02-bootstrap-probe` | `aed1a3a`, `df062f1`, `53e9a1a`, `ac36669` | Fixed ordinary-user context self-report; 12 pure/13 native controls, actual failed root-regain check and independent raw report review; integrated through `885660b` |
| R02 | `codex/mvp-r02-bootstrap-admission` | `41b75ec`, `3f6d388` | Parent-only protected physical path/ACL/root–Data profile, 15 controls and independent injected review; integrated as `e5e4b93`, `ead94f0`; native root positive unexecuted |
| R02 | `codex/mvp-r02-bootstrap-inspector` | `a16feac`, `d2bd45d` | Ordinary-user read-only root/Data and kernel-identity observation; three controls and independent source/kit reviews; guest run pending unlock |
| R02 | `codex/mvp-r02-bootstrap-runner` | `093629b` through `7c50621` | Fixed compiled-catalog nontracing owned-probe controller; seven Mac/Linux controls, five sanitizer controls plus two exclusions; integrated through `6cc8a7d`; protected guest/root transition unexecuted |
| R02 | `codex/mvp-r02-bootstrap-kit` | `d62964c` through `bbd82ca` | Guarded host-only kit builder and ordinary-user canonical request writer; 21 Mac/20 Linux passes plus one skip, independent codec/workflow reviews; integrated through `02495ac`; registry empty, configured build unexecuted |
| V01 | `codex/mvp-v01-darwin-scalar-ci` | `ceaf3fc` | Add both observation suites to portable CI; 184 collected controls |
| V01 | `codex/mvp-v01-darwin-credential-ci` | `64a4dd2` | Add credential controls to portable CI; 198 collected controls; approved public push and all nine jobs pass in run `38903379520` |
| V01 | `codex/mvp-v01-darwin-descriptor-ci` | `a3edd97` | Add descriptor controls to portable CI; 213 collected controls; local follow-up, no hosted run yet |
| V01 | `codex/mvp-v01-bootstrap-primitives-ci` | `2f087d5` | Add wire, endpoint and pipe-I/O controls to portable CI; 259 collected controls; unpublished earlier checkpoint, see latest controller CI follow-up |
| V01 | `codex/mvp-v01-bootstrap-context-ci` | `7156e80` | Add signal/request/probe/admission/inspector controls; 328 collected controls; local follow-up, no hosted run |
| V01 | `codex/mvp-v01-bootstrap-controller-ci` | `this branch` | Add runner/guarded-kit controls; 22 suites/356 controls; composed local coverage, no single full-driver or hosted run for this source |
| R04 | `codex/mvp-r04-acceptance-followup` | `c703309` | Merged-main and first guest-calibration status |
| R04 | `codex/mvp-r04-darwin-calibration-status` | `2ac8038` | Preserved rejected lifecycle candidates and calibration scope |
| R04 | `codex/mvp-r04-darwin-calibration-final` | `d9bf81b` | Nine validated owned diagnostics; full extraction corpus remains open |
| R04 | `codex/mvp-r04-macos-calibration-evidence` | `d44dd33` | Preliminary 1,372-file checkpoint restores and replays; SIP proof/publication pending; integrated as `aded39b` |
| R04 | `codex/mvp-r04-darwin-followup-status` | `8567d38` | Approved public push; all nine native portable CI jobs passed in run `38895660723` |
| R04 | `codex/mvp-r04-darwin-hosted-ci` | `b824afb` | Record exact hosted CI metadata; running-guest SIP proof was pending at this checkpoint |
| R04 | `codex/mvp-r04-darwin-restoration-evidence` | `439bb46` | Separate 57-file SIP-enabled proof and exact approved CI checkpoint; 59-member restore verifies |
| R04 | `codex/mvp-r04-sip-restoration-status` | `b1c462c` | Record independently verified running-guest SIP restoration and checkpoint restore; no full Darwin acceptance |
| R04 | `codex/mvp-r04-credential-hosted-ci` | `5567bcd` | Record exact approved credential CI run and independent metadata/source review; no new product acceptance |

Portable CI now invokes 22 Python suites collecting 356 controls. Local coverage
joins the frozen 20-suite run with separately executed final runner (7) and kit
(21) suites, verifying 104 source/data/decision pins and exact current CI argv.
This is composed coverage, not a single 22-suite driver run or a complete portable
baseline job. Together the recorded Mac/Python 3.15.0 results account for 351
passes and five explicit skips: four Linux-only refusal checks and the
inapplicable noncanonical-group negative (the actual vector is canonical).
Linux arm64/Python 3.11.17/glibc 2.28 accounts for 331 passes and 25 skips:
two Darwin compiler, five descriptor, four signal, eleven probe, one admission,
one inspector and one exact-min26 SDK control. Linux uses UID/GID 65534; applicable
nonprivileged credential and endpoint controls execute. Older root runs and skips
remain frozen. These unit/format/model checks do not prove full Darwin acceptance.
The six logs, CI snapshot, exact source pins and coverage method are retained at
`/private/tmp/glue-bootstrap-controller-ci-coverage-20261016`, manifest SHA256
`c9ca1da93293f11b1dd2616ff71b6e85e4f44a7fd1423f2858ec96b452d398e5`.
Independent pin/argv/log/count review is retained at
`/private/tmp/glue-bootstrap-controller-ci-independent-review-20261016`, manifest
`01a5fdb968606b43330be837fffc7c6f0c673fbcc966a05941c6b57db70d0289`.
The descriptor helper additionally passes six injected-only ASan/UBSan control
groups. Its native Mac controls close FD 4096 even after only the child's soft
and hard limits become 64; parent limits and sentinel FDs remain unchanged.
This proves bounded numeric closure on that host, not endpoint provenance,
privileged guest bootstrap, cwd/Mach/fileport closure or tracing acceptance.
The wire and pipe-I/O helpers additionally pass Mac ASan/UBSan suites and
independent boundary controls; the endpoint helper passes all 17 controls on
both native hosts. Root review is retained at
`/private/tmp/glue-bootstrap-primitives-root-review-20261016`. Deadline and
confirmed-prefix checks never turn pipe EOF into exec-success proof, and a
failed GO write must be treated as possibly delivered. Protected native controller
execution and collector integration remain open.
The hosted nine-job run above covers the earlier `64a4dd2` source; these
follow-ups have not been pushed or checked on hosted runners.
The credential primitive independently passes 14 native unprivileged controls
and five additional injected-only ASan/UBSan controls. Its isolated Linux
forked-child transition to UID/GID 65534 and groups `[65534]` preserves parent
credentials; it does not calibrate a privileged Darwin transition or integrate
the helper into the collector. That collector still runs root-target diagnostics.
The pairing adapter separately replays all seven v8 process-tree captures as
1,193 returned pairs and 13 explicit entries terminated without return. It
retains raw frames and observed thread/exec lifetimes; it supplies no resolved
file objects, path authorization, Mach effects or full extraction verdict.
The observation bridges replay 68 whole-tree named opens and 18 scalar
`mach_msg2_trap` pairs. The six profiles without Mach tracing explicitly report
that the provider was not enabled; they make no absence claim. Numeric results,
copied paths, message IDs, ports and options grant no filesystem authorization.
The Linux image was `83284f80eba5a876e1441d216f0e1d0143659b05642a75b34cc213270d83c9b9`,
with network disabled and this checkout mounted read-only. Native SDK/signature
open controls retain their separate target receipts.

## Executed development cells

| Cell | Lua | Python | Node | Release observations |
| --- | --- | --- | --- | --- |
| macOS arm64 | 5.4.9/5.5.1 source/native/secondary/TLS/errors | PBS/uv 3.13.16, 3.14.5, 3.15.0b1; non-PBS 3.12.14 and framework 3.14.8 (3.12.12 also focused provider test) | Official 24.22.0/26.10.0 CJS/ESM/resources/Node-API | Offline sandbox and relocated read-only execution; strict ad-hoc verification; complete Darwin oracle remains unimplemented |
| GNU Linux arm64 | Both families source/native and extraction traces | PBS 3.13.16 file/module/console/native/abi3; non-PBS 3.14.8 source; local PBS archive routes | Official 24.22.0/26.10.0 CJS/ESM/resources/Node-API | Native Podman VM, network none, controlled uid/read-only tree, complete strace where receipted |
| GNU Linux x86_64 | Both families source/native passed full acceptance | PBS 3.12.15/3.13.16 and independent conda-forge 3.14.8 source/module/console/native all passed | 24.22.0/26.10.0 all eight cases passed full acceptance | All 24 acceptance cases and all five reviewed R03 budgets passed under the explicit trace environment; independently replayed |
| macOS x86_64 | Unperformed | Unperformed | Unperformed | Later separate cell |

Versions are observations, not production pins. Node 24.10.0 failed mixed ESM/CJS
public-hook behavior and diagnoses unsupported capability; no promise is made
for every patch of a major. Python conventional-GIL 3.11+ has no hardcoded upper
minor ceiling; debug/free-threaded are diagnosed. New runtimes still need matching
ABI/features and a complete native closure. Inspect exact manifests/build reports
for each distribution's minimum OS/kernel, libc symbol versions, CPU properties,
external system dependencies and normalized image hashes.

## Commands and verification

[The CLI guide](../compact-cli.md) and README show the actual builder/installer
interfaces. The checked-in fixtures supply unrelated Lua project layouts, Python
file/module/console entries and namespace/metadata/resources, and npm/pnpm
CJS/ESM/native graphs. Independently provisioned native inputs are never rebuilt
by the packager. Input hashes are compared before/after packaging.

The Mac operator installed the release tools with:

```sh
scripts/install-glue.sh /private/tmp/glue-mvp-installed
```

The pinned portable baseline passed locally on macOS arm64 with actual compact CLI
execution required (`GLUE_REQUIRE_COMPACT_CLI=1`). Harness tests passed 22 checks,
including deliberate extraction violations and invalid/foreign receipt controls.
The Lua55 suite passed 90 tests and packaging passed 130, both with pinned
Clippy. Four additional CLI regressions passed after the final review fixes.
Hosted portable run [38794420717](https://github.com/JBlaschke/glue_rs/actions/runs/38794420717)
passed all nine suites: baseline, Lua55 and packaging on each of macOS arm64,
Linux arm64 and Linux x86_64. Its source is `13ca6db64839aa5fb2a3b9fccec272db74d522ff`.
The previous run's two transient Linux helper-spawn `ETXTBSY` failures are
retained; the bounded helper query fix passed this complete rerun.
Ignored runtime tests are not counted as target evidence; supplied-runtime
receipts exercise those routes separately. An initial extra suite run hit
ENOSPC and is not counted; disposable incremental build outputs were cleared.

Linux release/test commands use Rust 1.88.0, vendored locked dependencies and a
native arm64 container with network disabled. Normalization uses an independently
provisioned explicit patchelf; the product never installs it. The Mac native paths
were independently compared with otool/codesign and Linux metadata with readelf.
No public macOS signing or release publication is inferred.

## Measured costs and current receipts

Five frozen native Linux arm64 profiles cover Lua source/native, Node CommonJS,
Python source and Python NumPy/native. At 1 and 32 ranks, adding 10,000 source
entries added zero deployed files or native bytes. Metadata calls stayed
15/31/68/351/504 respectively. The Python native closure retained 40 files,
50,689,322 native bytes and 86,219,627 runtime bytes. These are observed
host-specific costs; [the method and numeric budgets](../decisions/mvp-r03-hpc-cost-budgets.md)
explain margins, memory/FD measurements, artifact identities and the absence
of a controlled cold-cache claim. Mac timing was measured but cannot freeze a
complete syscall budget without a tracer.

Node has 24 checked V02 receipts: four cases per major on macOS arm64,
Linux arm64 and native Linux x86_64. All sixteen Linux cases include full
descendant traces and injected extraction controls. Mac cases have offline
execution and strict final signature checks under the selected development policy;
complete Mac tracing remains unavailable. The local ARM index is
`/private/tmp/glue-node-final-summary.json`; the eight hosted x86 receipts are
under `/private/tmp/glue-native-x86-evidence-38800548172/cases/node-*`.

Python's final covering matrix includes Mac 3.12.14 source, 3.13.16 console,
3.14.5 uv source/native, 3.15.0b1 source and 3.14.8 non-PBS framework source.
Linux 3.13.16 ordinary copied-venv file/module/console, scientific/native and
cp311-abi3 cryptography runs pass complete V02/R02 traces; non-PBS 3.14.8 source
and local PBS archive variants are separately receipted. The raw locations are
`/private/tmp/glue-python-v02-*` and
`/private/tmp/glue-python-v02-linux-evidence/`. Failed preparatory runs remain
retained and do not count as acceptance. Acceptance summaries select checked
passing receipts and label signing/tracing checks separately; the evidence
inventory also preserves failed runs and preparatory diagnostics.

Native hosted x86_64 acceptance and performance enforcement are configured in
`.github/workflows/mvp-native.yml` using `scripts/ci-mvp-linux.sh`. It requires
24 exact acceptance cases, five 10,000-entry performance profiles at 1/32
ranks, enforced offline execution, full traces and negative controls.
Run [38796669924](https://github.com/JBlaschke/glue_rs/actions/runs/38796669924)
passed 23 acceptance cases and all five complete R03 profiles; independent
review reconciled 15 profile receipts, 60 controls and 990 rank results before
freezing numeric limits. Structure, size, I/O, FD and scaling limits are enforced
across hosts; time/RSS apply only to the recorded full host boot fingerprint.
The overall run failed the separate Python 3.14 native build and does not count
as complete target acceptance. Run
[38800548172](https://github.com/JBlaschke/glue_rs/actions/runs/38800548172)
on source `e3962701f558c287515508c97df4679e08d64ed2` reran all cases with
matching conda libstdc++/libgcc inputs and passed all 24 acceptance cases and all
five reviewed budgets in enforcement mode. Independent replay passed every
acceptance receipt, all 15 benchmark-variant receipts/traces, the retained
controls and all 990 rank results. The included launcher, Lua helpers and Node
bridge retain the preceding run's binary identities. Full evidence is retained in
[artifact 12005186009](https://github.com/JBlaschke/glue_rs/actions/runs/38800548172/artifacts/12005186009),
ZIP SHA256 `c1cc519d76e73888ed0339714deec1e97eea816c1f8861ab551da4579644e7a4`.
Local replay is
`/private/tmp/glue-native-x86-evidence-38800548172/independent-replay.json`.

Replaying the original hosted traces after the tokenizer correction revealed
successful libuv io_uring operations and a Python 3.14.8/libffi temporary
executable trampoline. The [explicit Linux trace environment](../decisions/mvp-v02-ci-trace-environment.md)
denies asynchronous kernel I/O for the entire reference/package/control/rank
process tree, retaining independent denial and inheritance proofs. This is a
declared test environment, not unrestricted-host acceptance or a product sandbox.
The [libffi compatibility decision](../decisions/mvp-p05-libffi-static-trampolines.md)
records the selected PBS input's path-with-spaces bug and the unchanged independent
conda runtime. The earlier native build correctly rejected a mismatched
host/conda compiler-runtime closure. Supplying the pinned matching C++ runtime
resolved that input conflict without relaxing the identity check; the final
3.14 native case passed the strict ten-process trace and all negative controls.
The oracle continues rejecting temporary code writes. Failed original receipts
remain retained separately and do not count as acceptance.

## Evidence retention and open gates

Raw outputs, binaries and traces remain outside Git. Hash inventories and local
locations are recorded in the [integration evidence README](../evidence/compact-mvp-2026-10-15/README.md), following
[decision 0030](../decisions/0030-evidence-retention.md). Evidence release assets
have not been published; there is no fabricated `bundle.json` or remote durable
retention claim. Local files alone will not survive transfer of this repository.
The indexed checkpoint now prepares and restores 18,588 captured files without
rewriting them; replay from a new root passes 94 receipts, ten budget profiles
and 1,980 rank results. The archive is 619,802,268 bytes with SHA-256
`aa8b2291a670791f8a50626c1098eb2281b8b616cff260163c9aa895ddc8879f`.
Independent review of its final native x86 subtree also passes 24 acceptance
receipts, 15 benchmark variants, 156 controls and 990 rank results, with the
4,804-file subtree unchanged. Review artifacts created after preparation are
separate from that frozen checkpoint; exact identities and commands are in the
evidence README.

Remaining M2 work includes a complete, validated Darwin extraction backend and
the required macOS corpus, negative controls and budgets. Native
administrator authentication succeeded on the current Mac, but both wildcard
and exact owned-fixture syscall probes failed under SIP. The password does not
override that provider restriction; no OS security setting was changed. See the
[capability diagnostic](../../fixtures/mvp/macos-trace/README.md). The owner
approved a local UTM VM after freeing internal storage, and completed the guest
Setup Assistant. The exact owned-fixture syscall probe also failed under SIP
in the arm64 VirtualMac2,1 guest. The owner initially chose to keep guest SIP
enabled, then explicitly corrected that choice and authorized temporarily
disabling it only in this owned test VM, with restoration after tracing.
Recovery owner authentication succeeded and post-reboot guest metadata confirms
SIP disabled. Native v3/v4 captures reject the first callback's layout. The exact
v2 layout candidate in guest run v5 completes eight of nine owned cases; failed
spawn exposes a genuine current-context/target exit mismatch and lost parent
syscalls. V6 adds explicit target exit records, completes the two open-only
cases and fails all seven tree cases: old-image cleanup after exec shares the
live PID and prematurely clears its watch. Four failed captures also reject
their stdout identities because unobserved descendants append after the
premature footer. Preserve all original bytes and failed gates. A target PID
alone cannot prove termination of the active process image. V7/v8 retain the
target object and raw shadow flag; all seven tree cases then complete, including
failed-spawn parent continuation and explicit child termination. V7's two
open-only failures expose queued events arriving after root wait. The focused
drain fix produces v8 with all nine cases captured, 2,647 events, no drops/errors
and consistent file identities under independent replay. Original failed
streams remain unchanged. Guest-only restoration in Recovery and normal reboot
are complete. The running guest's read-only status proof reports SIP enabled at
2026-10-16T12:14:43Z; all ten commands exit zero, and all 35 indexed payload
files plus their manifest verify unchanged. The separate
[restoration checkpoint](../evidence/compact-mvp-darwin-restoration-2026-10-16/README.md)
retains this observation and the exact approved nine-job portable CI result;
older captures and checkpoints remain unchanged. These are owned
diagnostics, with guest networking enabled,
and do not satisfy the offline product corpus.
The physical host policy remains unchanged. No approved trace-capable hosted
macOS runner is available. The capability transport and diagnostic reader do not supply the
missing Darwin decoder/oracle. Full Mac R02 implementation and its corpus,
negative controls and budgets remain open until actual capture and replay pass.
Public release additionally needs Developer ID/notarization under
the chosen policy, and publication/verification of retained evidence assets.
Memory mode and later platform/language expansion remain in
[their separate roadmap](memory-roadmap.md).
