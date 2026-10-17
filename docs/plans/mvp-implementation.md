# MVP implementation and acceptance ledger

17 October 2026. Product authority remains [the plan](../../PLAN.md),
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
| R02 | `codex/mvp-r02-bootstrap-inspector` | `a16feac`, `d2bd45d` | Ordinary-user read-only root/Data and kernel-identity observation; actual guest run and independent source/proof review passed on 17 October; SIP enabled |
| R02 | `codex/mvp-r02-bootstrap-runner` | `093629b` through `7c50621` | Fixed compiled-catalog nontracing owned-probe controller; seven Mac/Linux controls, five sanitizer controls plus two exclusions; integrated through `6cc8a7d`; protected guest/root transition unexecuted |
| R02 | `codex/mvp-r02-bootstrap-kit` | `d62964c` through `bbd82ca` | Guarded host-only kit builder and ordinary-user canonical request writer; original controls and independent reviews; integrated through `02495ac`; configured build now completed in the reviewed-input follow-up below |
| V01 | `codex/mvp-v01-darwin-scalar-ci` | `ceaf3fc` | Add both observation suites to portable CI; 184 collected controls |
| V01 | `codex/mvp-v01-darwin-credential-ci` | `64a4dd2` | Add credential controls to portable CI; 198 collected controls; approved public push and all nine jobs pass in run `38903379520` |
| V01 | `codex/mvp-v01-darwin-descriptor-ci` | `a3edd97` | Add descriptor controls to portable CI; 213 collected controls; local follow-up, no hosted run yet |
| V01 | `codex/mvp-v01-bootstrap-primitives-ci` | `2f087d5` | Add wire, endpoint and pipe-I/O controls to portable CI; 259 collected controls; unpublished earlier checkpoint, see latest controller CI follow-up |
| V01 | `codex/mvp-v01-bootstrap-context-ci` | `7156e80` | Add signal/request/probe/admission/inspector controls; 328 collected controls; local follow-up, no hosted run |
| V01 | `codex/mvp-v01-bootstrap-controller-ci` | `3d500d4` | Approved public push; run `39019048941` passed seven of nine jobs; both Linux baselines failed on the same test-only compiler warning |
| V01 | `codex/mvp-v01-bootstrap-hosted-fix` | `4eb0354`, integrated `7cfbac1` | Brace the signal test loop for modern GCC; native Linux arm64 GCC 14 runs all 22 suites: 331 passes/25 skips; patched hosted run pending |
| R02 | `codex/mvp-r02-bootstrap-reviewed-inputs` | `37856ca`, `5200be9` | Register independently reviewed actual guest proof and 34 production/build sources; separate explicit empty-registry controls; kit suite passes 22 Mac/21 Linux plus one skip |
| R04 | `codex/mvp-r04-bootstrap-deployment-status` | `78f4072` | Record actual deployment inspection, configured reproducible kit and exact hosted failure; no protected guest execution or full Darwin acceptance |
| V01 | `codex/mvp-v01-bootstrap-probe-gcc13` | `a805834`, integrated `863e327` | Consume best-effort diagnostic write result without retry; expose compiler failures; native Ubuntu GCC13 reproduction and focused Mac checks pass |
| R02 | `codex/mvp-r02-bootstrap-ubuntu-inputs` | `df5fb63`, `d2d0d0a` | Deliberately advance one of 34 source hashes to `863e327`; actual proof and earlier kit unchanged; kit suite22 Mac passes and committed source/proof admission passes |
| R04 | `codex/mvp-r04-bootstrap-ubuntu-ci-status` | `162f91a` | Approved repair push to the deployment-status branch; run12 passes all nine portable jobs |
| R02 | `codex/mvp-r02-bootstrap-vm` | `b956dd4`, `c460fd4`, `02a4247`, `fba154e` | Closed host packet/guest scripts; explicit inline guards and checked request digests; ten host controls and independent source review |
| R02 | `codex/mvp-r02-bootstrap-vm-checker` | `97d2be4`, `8012e98` | Strict offline canonical request/status/probe/result/terminal checks;18 controls on both native hosts and two independent reviews; no kernel exec/full acceptance |
| R02 | `codex/mvp-r02-bootstrap-vm-integration` | `ad9ea78` through `75c565e` | Integrate the separate decisions/implementation/guard/checker commits locally;10 preparer and18 checker controls pass |
| R02 | `codex/mvp-r02-bootstrap-vm-reviewed-run` | `a17f82b`, `0affe28` | Enable only the reviewed source policy, retain closed kit binding and no runtime override; freshly rendered packet still requires inspection/private guest authentication |
| R04 | `codex/mvp-r04-bootstrap-vm-handoff` | `448a86a` | Record green hosted CI and the reviewed local guest handoff; guest execution and complete Darwin acceptance remain open |
| V01 | `codex/mvp-v01-bootstrap-vm-ci` | `926ca82`, integrated `9f95855` | Two new baseline invocations;28/28 affected controls pass on Mac and native offline unprivileged Linux arm64; newer local source has no hosted run |
| R04 | `codex/mvp-r04-bootstrap-restart-status` | `c36b711`, based on `ad59dfa` | Independently verified all24 Mac Python suites; interrupted launch/reboot, second failed install and actual guest mode observations preserved |
| R02 | `codex/mvp-r02-bootstrap-mode-guards` | `46d61f3` | Exact full BSD mode/type guards,14 preparer/18 checker controls; integrated as `dec2488` after decision `fabae45` |
| R02 | `codex/mvp-r02-bootstrap-mode-integration` | `409dc4b`, based on `c36b711` | Reviewed mode repair and fresh packet03 preparation/review/staging; launch reached private guest authentication |
| R04 | `codex/mvp-r04-bootstrap-request-stop-status` | branch tip, based on `409dc4b` | Packet03 installation/signatures pass; ordinary positive request refuses before output/cases; bounded metadata retained, current deployment reobservation pending |
| R04 | `codex/mvp-r04-acceptance-followup` | `c703309` | Merged-main and first guest-calibration status |
| R04 | `codex/mvp-r04-darwin-calibration-status` | `2ac8038` | Preserved rejected lifecycle candidates and calibration scope |
| R04 | `codex/mvp-r04-darwin-calibration-final` | `d9bf81b` | Nine validated owned diagnostics; full extraction corpus remains open |
| R04 | `codex/mvp-r04-macos-calibration-evidence` | `d44dd33` | Preliminary 1,372-file checkpoint restores and replays; SIP proof/publication pending; integrated as `aded39b` |
| R04 | `codex/mvp-r04-darwin-followup-status` | `8567d38` | Approved public push; all nine native portable CI jobs passed in run `38895660723` |
| R04 | `codex/mvp-r04-darwin-hosted-ci` | `b824afb` | Record exact hosted CI metadata; running-guest SIP proof was pending at this checkpoint |
| R04 | `codex/mvp-r04-darwin-restoration-evidence` | `439bb46` | Separate 57-file SIP-enabled proof and exact approved CI checkpoint; 59-member restore verifies |
| R04 | `codex/mvp-r04-sip-restoration-status` | `b1c462c` | Record independently verified running-guest SIP restoration and checkpoint restore; no full Darwin acceptance |
| R04 | `codex/mvp-r04-credential-hosted-ci` | `5567bcd` | Record exact approved credential CI run and independent metadata/source review; no new product acceptance |

At the `3d500d4` checkpoint, portable CI invokes 22 Python suites collecting
356 controls. Its earlier local coverage
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
The earlier successful nine-job run covers `64a4dd2`. The subsequent approved
`3d500d4` run and its two Linux failures are recorded separately below.

## 17 October: deployment, configured kit and hosted follow-up

The owner-approved `3d500d4a607ef5c5ed5cc907f2a12cacd2c658e8` was pushed unchanged to
`codex/mvp-v01-bootstrap-controller-ci`. The superseded `2f087d5` request did not
produce a duplicate push/run. [Run 39019048941](https://github.com/JBlaschke/glue_rs/actions/runs/39019048941)
passed macOS baseline and all six Lua55/packaging jobs. Both Linux baselines
failed at the same signal test loop because GCC treats its indentation as an
error. The retained run remains failed; the formatting-only fix changes no
production source. Native arm64 GCC 14.2.1 reproduces the warning before the fix
and then passes all 22 suites (331 passes, 25 skips). This is local fix evidence,
not a successful patched hosted run. Exact failed CI metadata/logs are retained at
`/private/tmp/glue-portable-bootstrap-controller-39019048941-20261017`, manifest
`69083e6ea605e3f5b45c5167563c2c68484ee8223e907af8357748cc7f42e0ac`.
Fix evidence is `/private/tmp/glue-bootstrap-hosted-fix-native-20261017`, manifest
`ba7e4474d2fd0d4400c08099175a0b2679c688d28f59721a5a2d565414009d48`.

The read-only ordinary-user inspector completed all six commands in the owned
VM: binary hash, strict signature, SIP, OS, kernel and actual observation.
SIP remains enabled. Its 27 indexed payloads are retained at
`/private/tmp/glue-mvp-macos-vm-results/glue-bootstrap-deployment-v1-A8mkN4hy`,
manifest `ec28e38b3066112d874a54b0dfb4bb9c20fae3f39dc90697bf7d4ea684a84c8a`.
Independent review verifies the original bytes, six-source provenance and full
typed mount/ACL/identity observations; review manifest
`d5a899e5659dde3f5ac02b6d7dad754204a85fafcfa906fd339e4935fb58e279`.
The actual root/Data `st_dev` values match while their FSIDs differ. The policy
compares the complete tuple; no observation was normalized to fit an assumption.
The first registration at `5200be9` locks 34 production/build sources at
`3d500d4` and this exact proof.
Its independent registration-review manifest is
`92d13cf6714249e5e42b62c7f3531f59ae6fc4505fb49e809294121b42f1d47e`.
The updated kit suite passes 22 tests on Mac and 21 with one Darwin SDK skip on
native Linux arm64. No aggregate full-driver count is claimed for that update.

The first configured build stopped when the sandbox denied Clang temporary-file
access. Its directory remains an explicitly incomplete failure without a final
inventory. A fresh build with local tool access completed with CLI exit zero:
`/private/tmp/glue-bootstrap-native-kit-20261017-02`, manifest
`098b758fe740d61efccd2ef34d3fe8cf00caba82e281dbc752e419e7a973995c`.
All 21 recorded tool commands succeeded. Two separate builds of each of the three
ad-hoc-signed programs have identical bytes. Build ID is
`a75d54bba97103ec8b15dd7be7beb5b8eb23de5bfdda624ad2fcd9f224ab84d5`.
The catalog binds the actual observed root/Data tuples and signed probe identity.
Independent kit/tooling/signature review passes, manifest
`af1034b7bf2d4d70f3db9c361f1fd44ef2262e8e156f30910a66e7c6bec0d591`.
Separate catalog/source/modern-GCC evidence review passes, manifest
`44da57195e8d6b0687f9921d71695cc507a909a1a1ec300db00d7b604a540b90`.
The root-observed normal builder exit and final registration test logs are retained
at `/private/tmp/glue-bootstrap-configured-root-checkpoint-20261017`, manifest
`42ea3e6d47faf97def1cda88cd3e413bf76935d8b22688fb8db6a94962678497`.
The programs have not been executed or installed by the builder or reviewers.
This checkpoint does not establish a privileged Darwin transition, kernel exec, extraction
oracle, product corpus, performance budgets or M2. These newer source changes
remain local pending separate publication approval.

### Ubuntu GCC 13 follow-up

The owner-approved deployment checkpoint `78f4072` was pushed unchanged and
started [run 39020970722 (#11)](https://github.com/JBlaschke/glue_rs/actions/runs/39020970722).
All seven macOS-baseline/Lua55/packaging jobs passed again. The two Linux
baselines pass the earlier signal-test loop and then fail in context-probe
compilation. The old test hid compiler stderr; the retained hosted record does
not invent a diagnostic that was absent from its logs. Exact run metadata and
all nine logs are `/private/tmp/glue-portable-bootstrap-deployment-39020970722-20261017`,
manifest `f2f30d5facb0714731a59f8a24e692f1831c699c4fe5263a6e1f55cee2d7675a`.

A separate native arm64 reproduction with cached Ubuntu GCC13.3.0 identifies
`-Werror=unused-result` on the probe's best-effort error `write()`. The minimal
fix consumes that return in a local `ssize_t`, preserving exactly one write and
no retry or signal change. Compilation errors now include their captured
stdout/stderr, with two focused diagnostic controls. Mac probe controls collect
15:13 passes and two explicit skips. The current kit suite passes22 on Mac.
The fixed-source native Ubuntu GCC13 run completes all22 portable Python suites:
359 collected,334 passes and25 explicit skips. Exact logs/toolchain/commands,
source-before/after and the patch are retained at
`/private/tmp/glue-context-probe-hosted-repro-20261017`, manifest
`dd98b1b37709d9626f7a5939744621004cdd57a6d6272eda29d1776c3f6c1dd6`.
This covers the original fix commit `a805834`, byte-identical in the integrated
`863e327`; the later one-source registry update has separate focused checks.
The source registry advances exactly one hash, retaining the other33 and actual
deployment proof; clean committed `locked_sources` and actual proof admission
both pass. The independent one-source lock review has manifest
`7497befbbe6651c465dbd1fe6903c8aac0f245aa4e098562938ad4e23ad094e4`.
The earlier kit02 remains its original `3d500d4` artifact. Neither
failed hosted run is relabeled successful. The corrected run passes all nine jobs as recorded below.

### Corrected hosted CI and local VM preparation

After explicit approval of `162f91ad63394a149feb584861397d7089d4fa2f`, the repair
was pushed to the same `codex/mvp-r04-bootstrap-deployment-status` branch.
[Run 39021989631 (#12)](https://github.com/JBlaschke/glue_rs/actions/runs/39021989631)
passes all nine native baseline/Lua55/packaging jobs. Exact checkout SHA, native
labels, six required steps, Rust/Clippy1.88 and final markers were checked in
all nine logs. The43-file frozen run is
`/private/tmp/glue-portable-bootstrap-ubuntu-39021989631-20261017`, manifest
`e6dadfb21a25ba2dcad2c6a2f14d33c6e42ff3ddc670da19b7976f790509ebba`.
Its offline verifier reproduces the exact successful summary. An initial attempt
to push this newer source was rejected by automatic approval review because the
prior approval covered only `78f4072`; no rejected action executed. The subsequent
exact162 approval and successful push/read-back are retained separately.
This is portable CI evidence, not privileged guest or complete Darwin acceptance.

The new local-only `bootstrap-vm` component prepares a fixed derived subset of
kit02, three source-rendered scripts and a bounded plan. The separate checker
validates terminal gates before reading case payloads, then decodes canonical
request/status/probe bytes and strict result JSON with all cross-case bindings.
Independent preparer review has manifest
`7c6166f6bcf3bf5ba6b3237b8cc851953774da398094f8e58a4013ad04a162a4`.
Independent checker reviews have manifests
`15f531d3b848c5fb252c6ced490d15efab5d41bd05c6fffdb7cee5dc030201ac`
and `c6cf77d3983631b6d01c4390354662ad627ae7b39e1f4a4c1815880c05fdcca8`.
The source enablement retains every closed guard and changes no production kit
input. The enabled-source host controls pass10 preparer/18 checker tests on Mac;
the earlier checker also passes18 on offline unprivileged Linux arm64. These are
format/model/syntax checks and execute no generated script, root phase or kit
binary. The old disabled packet remains immutable. A fresh enabled packet has been independently reviewed and copied unchanged to
the existing read-only VM toolkit share, manifest
`e6e0f15937e6c9cead7fbc6dcfd589a7dee91d526ca7d434ec3a65d5ce377aed`.
Its independent packet review has manifest
`2049dc2bf5c133a98a40892a670e287e94660b368b41f9800815bf905bf6e79a`.
The staged folder is `bootstrap-vm-c10ed2e4ce0404bd`; source remains local-only.
At that staging checkpoint the VM was at its lock screen and no guest script or
payload had started. The script checks SIP enabled and changes no security
settings; the subsequent interrupted launch is recorded below.

The staging/root-exit/test-log checkpoint is
`/private/tmp/glue-bootstrap-vm-stage-root-checkpoint-20261017`, manifest
`37a518f2ba31a73ac0a2078b3fa7174a38c545233f2c39e58b035f115fa2ca60`.
The V01 follow-up adds only the preparer/checker invocations immediately after
kit controls. Both affected suites pass28/28 with no skips on Mac and native
unprivileged offline Linux arm64. Exact command/toolchain/logs/source pins are
`/private/tmp/glue-bootstrap-vm-ci-native-20261017`, manifest
`6c62e983d8ac6f728985c4557e7bb91e46031d5a8cf1a41920a5b7c86e2f00ef`.
The local baseline now invokes24 Python suites collecting387 controls. Green hosted run12 covers the
separate earlier `162f91a` source, before the new local VM component/CI additions.

All24 direct Python suite invocations at `ad59dfa` subsequently completed on the
local Mac:387 collected,382 passes, five expected skips and zero failures. Four
skips are Linux-only unsupported-adapter checks; one negative group-order branch
skips because the actual groups are canonical, while its positive native control
passes. No Rust/Lua CI driver or new hosted run is inferred. The77-file closed
record at `/private/tmp/glue-portable-python24-mac-v2-20261017` has manifest
`40163357625e96bcf09212eab91d4ccc9ab8137bee108d8d808a31653c6a0c67`.
Independent review reconciled all24 argv vectors, raw test lines, counts, exits,
stream hashes and105 unchanged Git/source pins without rerunning the tests:
`/private/tmp/glue-python24-mac-independent-review-20261017`, manifest
`3fbe63809e29f041f323b0365246f03be78df82e8b6957148dd8fffc752fa1a2`.

The first enabled packet `c10ed2e4ce0404bd` was launched and visibly reached its
private sudo password prompt. Before authentication completion was observed,
the owner reported that host memory exhaustion crashed the VM. UTM was observed
stopped, then running again at its restored guest desktop after host unlock.
At the first restart checkpoint, automated keyboard input was not reaching guest
Terminal and the fixed read-only interruption inspection had not executed. No completed-run receipt,
closure, protected installation or case success is inferred. The old packet and
private partial directories are not edited, retried, inventoried or repaired.

One fresh host-only packet was prepared normally from the unchanged reviewed
kit02 at `ad59dfa`: `/private/tmp/glue-bootstrap-vm-packet-reviewed-20261017-02`,
nonce `6ae386cc044ff2a1`, manifest
`50a5801a75101d585e8f4d800a3371c82b0b5751f991404ba180d4fce30f2181`.
Its15 files retain the same nine kit members and three source-rendered scripts;
syntax checks exit zero. The separate host preparation receipt is
`/private/tmp/glue-bootstrap-vm-packet-host-receipt-20261017-02`, manifest
`4b180f3466662254247cb4aecc809519d55c1bcd0408c3aad3f8acdbe0d81dbf`.
Independent packet/receipt review passed without execution:
`/private/tmp/glue-bootstrap-vm-packet02-independent-review-20261017`, manifest
`7666ef69283914849dc22cb17de488c6d92c66845abd9808c12788d5871568fa`.
Root rechecked exact source rendering, canonical plan and both complete trees,
then copied all15 files unchanged into read-only toolkit share folder
`bootstrap-vm-6ae386cc044ff2a1`. The separate restaging checkpoint is
`/private/tmp/glue-bootstrap-vm-restage-root-checkpoint-20261017`, manifest
`7a56018bb4bdfca5a4eff0404d51c4a5a63cbe7210a5b2ec6b0332ed913778b5`.
At that restaging checkpoint no fresh guest script or payload had executed.
Guest interruption inspection and private authentication remained prerequisites;
full Darwin R02/M2 remains open.

The subsequent read-only interruption inspection completed to its final marker
and returned to the guest shell. Its exact six-file record is
`/private/tmp/glue-mvp-macos-vm-results/glue-bootstrap-interruption-c10ed2e4-20261017-01`,
manifest `cee18554af18d4801de250b8cc8a283ca0b4aeb18504c8cd35df83f30434acb0`.
It records boot sec1792247668, SIP enabled, the same501/20 identity and16 ordered
groups, all eight old fixed paths absent (including the protected fixture prefix)
and all seven old metadata files absent. The OS reboot removed the temporary
workspace; the agent did not delete or repair it. Independent review is
`/private/tmp/glue-interruption-independent-review-4y3kqnqx`, manifest
`793bab3c0d87b7b0727057f51b8e2583cecc214e7752c30a226a317bea1cd2bb`.
A later UI status-print command lost shifted characters and did not capture an
actual shell status; final-marker/inventory observations are recorded separately.

Fresh packet `6ae386cc044ff2a1` then passed preflight/private authentication and
returned without exporting a normal-zero run receipt. Only fixed ordinary-user
wrapper metadata was inspected, with no native case payload read. The13-file
inspection at
`/private/tmp/glue-mvp-macos-vm-results/glue-bootstrap-launch-stop-6ae386cc-20261017-01`
has manifest `11ba2d99a9c5b34a2852a77d452c63ade4c2377a67cfb08aa27657f448006ca7`:
outer status1, preflight0/install2, empty wrapper streams, no case statuses and
no root stage, fixture prefix or native output directories. Its `paths.tsv`
retains literal `\\t` separators on present rows; absent rows/metadata use tabs.
It is not silently normalized or relabeled as a successful batch.

An ordinary-user guest mode observation completed separately:
`/private/tmp/glue-mvp-macos-vm-results/glue-bootstrap-mode-observation-6ae386cc-20261017-01`,
manifest `a3082f87cb8bfab5513750b94336acbee44708c2a5fc89df930b0c6a1db2a7ad`.
All five existing root/Library ancestors have full mode40755. Private/tmp has
full mode41777, while BSD `stat %Lp` prints only777; the bootstrap's expected
`0:1777` comparison therefore refuses before creating the stager. A bounded
mode/type guard repair was implemented on
`codex/mvp-r02-bootstrap-mode-guards`; no failed packet is edited or rerun, and
no protected directory/security setting is repaired to fit the check.
Joint independent source/metadata review is
`/private/tmp/glue-launch-stop-independent-review-o0p34cb4`, manifest
`dd7649b1cd9ca3b81e35a5249de8296c3d9bb4a2e78afb037ad20a5850eca8b1`.
The exact failing branch remains an inference from the closed metadata and
source; no branch trace or native closure is claimed. The separate root
checkpoint binds both independent reviews, all three inspection inventories
and their unchanged source scripts:
`/private/tmp/glue-bootstrap-vm-early-stop-root-checkpoint-20261017`, manifest
`8ae8259cac2dc997d90dec78b5f463e50fc6f8e84c2a0535826871d5786a8a5f`.

Decision `d3956a9` and implementation `46d61f3` are integrated as `fabae45`
and `dec2488` on `codex/mvp-r02-bootstrap-mode-integration`. Every numeric shell
guard now uses full BSD `stat %p`, retaining file type and all special bits:
directories40700/40755, private/tmp41777 and regular files100500/100555/100600,
with the existing owner/link/content/signature/physical/freshness checks.
Fourteen preparer and18 checker controls pass without skips. The old-source
sticky-mode regression fails as intended. Independent review additionally passes
48 combined-special-bit controls and12 native owned-temp controls; no generated
phase, native kit or privileged operation runs in these tests. Its closed record
is `/private/tmp/glue-bootstrap-mode-guards-independent-review-20261017-02`,
manifest `f33417b46f64a0305e05de30b6332fc637c769a9dc1a1b2c83570d62d3c225b4`.
An earlier optional socket-fixture attempt was sandbox-denied and remains a
separate incomplete review harness; no socket control result is claimed.

Fresh packet03, nonce `1ee4bbe2b443c268`, was prepared from the unchanged literal
kit02 at `dec2488`. Its15-file packet manifest is
`e00fb4a1d634c52dcdd59a7872e460b59babb0fc6f6f082dfd3916a61202c390`.
The host preparation receipt is
`/private/tmp/glue-bootstrap-vm-packet-host-receipt-20261017-03`, manifest
`f3d23282cffc78af0c396d83b2ec70196f12aaed90a2616987104bd5285c0e05`.
Preparation returned0, preserved all nine selected kit members and passed
syntax-only checks for all three rendered scripts. Independent actual-packet
review passes exact trees/modes, selected kit bytes, canonical plan, passive
template reconstruction and the script SHA/size dependency chain. Its27-file
closed record is `/private/tmp/glue-packet03-independent-review-q617wqtk`,
manifest `1154d4ec1db84f29d45139867eba8ad2eda800feddc28e6e291cd125823f437c`.
The new packet is staged byte/mode-identically at its literal shared path.
The separate root checkpoint is
`/private/tmp/glue-bootstrap-vm-mode-stage-root-checkpoint-20261017`, manifest
`ad2db2714e0f68ec20151626350d12d9016b6572df96ab55151de55d93c35057`.
An initial host staging check refused the fractional elapsed-time field when
using the strict native-plan JSON parser; that read-only failure preceded all
copying. Host receipt parsing was corrected separately; packet/native parsing
and all source remain unchanged. The reviewed no-argument launch reached its
private guest authentication prompt in the SIP-enabled VM. Authentication and
the four-case results remain pending. No new native success, tracing, extraction
verdict, hosted run or public source publication is claimed.

After the owner completed private authentication, packet03 returned to the guest
shell without a normal-zero receipt or complete batch export. A separate
ordinary-user metadata inspection completed to its final marker and preserved
13 files at
`/private/tmp/glue-mvp-macos-vm-results/glue-bootstrap-launch-stop-1ee4bbe2-20261017-01`,
manifest `95b5168bf41425ea2d97db3f2dad94d25ccd731588c83a5c0fb32efd5c40bd88`.
The batch records preflight0/install0, installation status0 and outer status1.
Strict signature verification succeeds for all three payloads. The root0700
stager and root0755 fixture prefix exist; all four native output directories
and all case wrapper statuses/stderr are absent. SIP remains enabled with the
same boot and ordinary ID/group observations. This proves progress past the
repaired shell guards, without proving a native case or protected child closure.

A second bounded ordinary-user inspection records only request-helper status,
stderr and output metadata. Its8 files are at
`/private/tmp/glue-mvp-macos-vm-results/glue-bootstrap-request-stop-1ee4bbe2-20261017-01`,
manifest `e2067625d92dda64f37cb2f25b2b6034259a0e12001378e929e4a480c1517c16`.
The positive helper returns1 with exact stderr
`make-request: protected cwd observation or close failed`; its single-link
ordinary0600 output is empty. Later request files/statuses/stderr are absent.
The existing source therefore stops at the positive request's status guard,
before size validation or any case. That diagnostic combines open, callback,
metadata-policy and close failures; the exact underlying cause is not yet known.
No request is regenerated, packet retried or native case payload read.
The wrapper record's independent review is
`/private/tmp/glue-packet03-stop-evidence-independent-review-v6qwuozt`, manifest
`b3fa18f71422714f8f36f7e909e9df03a7f7a5632cb7fd017e0b66a15a042865`.
The request record's independent review is
`/private/tmp/glue-packet03-request-evidence-independent-review-ad7j6z_s`,
manifest `665064e86767239936bd3b6059e4bf628fb7408c64bb59661642aa65af287c3a`.
Their exact source and raw captures remain unchanged; all retained review hashes
also verify independently at the integration root.
The unchanged read-only deployment inspector then completed all six commands
with status0 and returned `inspection_failed=0` to the guest shell. Its new
28-file observation is
`/private/tmp/glue-mvp-macos-vm-results/glue-bootstrap-deployment-v1-Pf78Qtnu`,
manifest `ca2e111c6f6abcdb94ca8b6851b464a95f7cea0792990aec7d60b995ab1be09f`.
The complete semantic metadata/IDs/groups remain valid, but current root/Data
device is16777231, root FSID `[16777236,27]` and Data FSID `[16777231,27]`.
The old catalog binds device16777230, root `[16777236,26]` and Data
`[16777230,26]`. These current tuples necessarily reject that compiled catalog;
the precise branch taken in the earlier helper remains a source-grounded
inference rather than an instruction trace. Independent current-proof review
and a separate append-only registration are in progress. A fresh build must
bind the reviewed current tuples; no observation is normalized, old kit relabeled
or runtime override introduced. The existing completed installation must be
preserved separately before any future fresh-prefix installation.


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
