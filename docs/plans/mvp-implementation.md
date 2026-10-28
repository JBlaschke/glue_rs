# MVP implementation and acceptance ledger

28 October 2026. Product authority remains [the plan](../../PLAN.md),
[the contract](mvp-contract.md) and [the 26 task cards](mvp-tasks.md).
Each card has its own local feature branch, with prerequisite commits stacked or
cherry-picked for integration. The owner merged the combined
`codex/mvp-r04-docs` stack into `main` at `96e6958` through
[PR #34](https://github.com/JBlaschke/glue_rs/pull/34). Task branches retain their
own implementation commits. Follow-up work continues on feature branches;
no release asset has been published.
The owner subsequently merged the follow-up checkpoints through PRs #35/#36,
putting the reviewed match-accounting repair on `main` at `08da274`.
PR #37 subsequently merged the baseline timeout repair at `9f787e9`; both
repair runs passed all nine jobs. The tree-open intent follow-up below starts
from that merged baseline.
The owner has now merged PRs #38, #39 and #40 through `dfc7747`.
[Merged-main run 39780832572](https://github.com/JBlaschke/glue_rs/actions/runs/39780832572)
completed successfully. The owned BSD observation work below starts from that
merged baseline; its new commits have not been published or tested by hosted CI.

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

## 28 October: source-grounded paired BSD outcomes

The independent `codex/mvp-r02-owned-bsd-outcomes` branch starts at merged main
`d1f0e3f`. Decision `ab8f7fe` precedes implementation `29f8881`.
`decode_owned_bsd_outcomes` directly invokes fixed `pair_raw_owned` on original
static bytes and the bounded event iterable. Exact contract identity, complete
transport and unambiguous pairing finish before decoding; caller-created pairs,
profiles and calibration assertions are not accepted inputs.

Pinned XNU LP64 rules interpret 143 signed32 `int`, sixteen signed64
`user_ssize_t` and two unsigned64 `user_addr_t` declarations. Canonical widening,
secondary-zero and provider failure tuples are checked without masking. Private
positive kernel codes remain supported without an ELAST cap; successful signed
minus-one differs from failure. ERESTART/EJUSTRETURN, malformed and unknown
outcomes remain unsupported with original pairs/reasons. Immutable source
retains all BSD/Mach phases, entry requirements and lifecycle data. All results
remain incomplete with native ABI, successful-effect ordering, object binding,
state feed and acceptance unresolved. Existing readers, collector, assessment,
inspector, state engines and native kits are unchanged.

All 27 controls pass on Python 3.15.2 and 3.9.6. Frozen receipt
`.evidence-local/controls/owned-bsd-outcomes-20261028/attempt-02` indexes fourteen
payloads; manifest SHA256 is
`e26db71d665fdda97226522a08d30c4a70b589ea51ed87334b8010601c3f1e1f`.
Six watched identities remain unchanged. Initial development reused a mutable
Mach fixture frame; only test serialization changed and that failure is retained.
Provider/generator/errno bytes and normal TLS-verified fetch records are in
`.evidence-local/bsd-outcomes-source-20261028`; a local urllib CA failure is
retained separately, and no TLS check was disabled.

Independent review at `.evidence-local/peer/bsd-outcomes-semantic-review-20261028`
finds no open issues; report SHA256 is
`dc90c10cf4a5f78ca26bbcc0d21bddc50585d93d8287244678ef011cdcb6a0a5`.
Root verifies the inventory, helper/public-source hashes and complete report.
Physical source-line references were corrected in README/decision only, with a
separate addendum; no behavioral rerun was needed. CI adds one invocation for
45 Python scripts here (48 with independent arm repair PR #91). Shell syntax and
staged diff checks pass. Hosted CI proceeds independently; no native capture,
VM/SIP change, full Darwin acceptance or M2 closure is claimed.

## 28 October: standalone owned-trace inspector

The separate `codex/mvp-r02-owned-trace-inspector` branch stacks on assessment
PR #87 at `a42cdff`. Decision `68444b6` precedes implementation `baa6508`.
`inspect_directory` and the operator CLI validate exactly four caller-supplied
diagnostic files. Bounded fifth-entry scanning, ordinary unprivileged identity,
numeric directory/file modes, no-follow/nonblocking held descriptors, anchored
before/after identity and exact roster checks precede publication. Static bytes
are bounded and the event stream is consumed once. Every acquired descriptor
gets one close attempt; any closure failure suppresses the report. Root aliases
ending in dot/parent components refuse before input opening.

Output is a distinct caller-unverified diagnostic protocol binding all file
hashes/counts and fixed assessor/core identities. It retains incomplete status
and false native/export admission, full acceptance and state eligibility.
`--acceptance` alone refuses before required args, helper import or input access.
Encoded JSON including its LF must fit16MiB before stdout; broken-pipe atomicity
is not claimed. Numeric modes do not attest ACL privacy, and stable trusted
source/owned namespaces without concurrent privileged mutation remain assumed.
The command neither invokes nor replaces native packet/metadata/closure/export
gates, creates no export and grants no permission to access protected failures.

Final focused commands both pass on macOS arm64/Python 3.15.2:
`python3 fixtures/mvp/macos-trace/owned-trace-assessment/test_inspect_trace.py -v`
(25 controls) and the unchanged `test_assessment.py -v` (16 controls).
`.evidence-local/controls/owned-inspector-20261028-final` has 39 files including
manifest `29c915d1f4d128d8376c39f977d95c0652971c02c1b12d763a45257aa67ba198`;
13 source/context snapshots remain identical before/after both runs.
Independent review at `.evidence-local/peer/owned-inspector-20261028` has seven
files, manifest `23fbb1e1d9d4a0b1e3e6d867863fd956da88d7b202d66d560045dc97a90325b6`,
and no remaining actionable findings. Root verifies both exact inventories and
reads the complete report. Initial environment-cleared setgid test assumptions
were corrected in development; the failed attempt and subsequent passing attempt
remain separate. Review's terminal-dot root-alias concern was fixed and covered
before the final receipt. No repeated peer suite or extra probe was needed.

Tests exercise real synthetic directory/file/FIFO/symlink/hardlink boundaries,
roster/file/line/output caps, anchored opens, identity changes, read/close/stdout
failures, static refusal before event consumption and early acceptance refusal.
All seven protected core/upstream hashes remain unchanged. README gains CLI
documentation and CI adds one invocation for 44 Python scripts. New-file/staged
diff and shell syntax checks pass. No full local Rust rerun or native capture,
admission, VM/SIP change, state feed or M2 closure is claimed.

At the background snapshot, PR #86 at `d4cd4dc` and PR #87 at `a42cdff` each have
18 successful push/PR checks. Their completion was not a prerequisite for starting
the next feature. Merge order is #86, #87, then this dependent inspector PR;
the new PR's CI is tracked independently without holding subsequent work.

## 28 October: owned request assessment

`codex/mvp-r02-owned-request-assessment` is stacked on retention PR #86 at
`d4cd4dc`. Decision `724955e` precedes implementation `84634eb`. The pure
`assess_owned_raw` API accepts original bytes and event lines, invokes the strict
BSD observer itself and returns no prefix before complete transport exhaustion.
It retains the whole immutable observation result once and links each request
to its original phase. The explicit twelve-family dispatch covers all 161 pinned
declarations; common flags for all nine open variants are classified only when
already uint32. Wider words are retained as unsupported without narrowing.

Source requirements, unknown names, unsupported return shapes, and all BSD/Mach/
lifecycle counts remain explicit. No family authorizes a harmless read or actual
write effect. Failed/unpaired requests are retained without requiring the
stricter pairer. Output exemptions require missing object bindings, so every
report has incomplete status, false full acceptance and false state-feed
eligibility. Upstream readers, contracts, ABI/classifier, state engines and all
native kit/registry/packet bytes remain unchanged.

The owner-reported crash leaves those source bytes unchanged but removes the
temporary initial 16-pass receipt and review. They are not reconstructed. A fresh
`python3 fixtures/mvp/macos-trace/owned-trace-assessment/test_assessment.py -v`
passes all 16 controls on macOS arm64/Python 3.15.2. Receipt
`.evidence-local/controls/owned-assessment-20261028-postcrash` has 30 files
including `manifest.json`, SHA-256
`2afadcdbb50c0bb4e496758d2512aa7dd08cbb530f0187affa534de1105149a9`.
Ten source/context before/after identities agree. Independent review at
`.evidence-local/peer/owned-assessment-20261028-postcrash` has seven files,
manifest `900f3161674af4e3cf3d010ffdc6e1b8cbd0ff38e8890877fecd86b9140cd430`,
and no actionable findings. Root verifies both exact inventories and reads the
review. These records are read-only and outside temporary/Cargo storage.

Final tracked diff review removes one extra terminal LF from the test script in
`1fa75f4`; its AST including positions is identical. The final exact focused argv
again passes 16/16 at `.evidence-local/controls/owned-assessment-20261028-final`,
30-file manifest `c50a323c3fb1f56b6ba33d6b573e0d04423c0d9785258845c53e5aa74c79ee59`.
The separate five-file independent addendum has manifest
`55b397cfb326394772f7c2dfbdd19c7ab983f3ccb3ef443047a02e88f086d048`.
Root verifies those inventories and reads the addendum; earlier frozen records
remain unchanged.

Controls cover independent selector vectors for every declaration, all nine flag
positions, unsupported high bits, failed/unpaired/orphan/exec/shadow requests,
Mach/lifecycle/zero activity, exact/over bounds, immutable serialization,
dependency preflight, runtime no-I/O and late stream failure. CI adds exactly one
invocation for 43 Python scripts; shell syntax and diff checks pass. Hosted CI
can run while the next feature proceeds, per the owner's instruction. No full
local Rust rerun, native calibration, state adoption or M2 completion is inferred.

After the crash, a separate persistent audit at
`.evidence-local/peer/x86-retention-20261028-postcrash` verifies all 4,820 archive
members, both physical prepared/restored rosters and the original 18 review
payloads. Its four-payload manifest hashes to
`45e8f0af77c1976a3fde53de5da1cb830c9c8e5e4daf23349557ba03e0d6da25`.
The archive and all committed bindings remain unchanged; the missing older
temporary peer record is not reconstructed. Local retention remains the scope.

## 28 October: recovered x86 local retention

The owner merged the prior reader work through PR #41 and examples through PR
#76, placing `main` at `8097be0` with successful portable run
[40078316223](https://github.com/JBlaschke/glue_rs/actions/runs/40078316223).
The owner now authorizes new feature/milestone branches with PRs and overlapping
CI. Earlier local-only directions below describe their dated checkpoints; guest
SIP stays enabled.

The independent `codex/mvp-r04-x86-local-retention` branch starts from `8097be0`;
commit `39e5390` adds only an ignore rule, two inventories and offline metadata.
Using the unchanged `scripts/evidence-bundle.py` at SHA-256
`54bca4d7d2a6ba4d8ea93290eaa47760c1d916d5f43c1c4bb35ae84cc10f9828`,
4,818 explicitly indexed source files prepare and restore with statuses zero.
All 4,820 indexed members and the exact expected sidecars independently verify
all hashes, payload sizes, modes and absence of aliases/special files; source identities remain stable.
No raw test log, capture or archive enters Git. The local archive is 318,451,457 bytes,
SHA-256 `77b5a9565145b23c492c7c08cecbce4cda29577186d44d68d97637f4d2e9f7df`.
Local command/review records are under
`.evidence-local/x86-38800548172/review-20261028-01`; its 18-payload index hashes to
`4bae520ab650a70d716bf6890ce5803b85f6ff1cdadcf0839475ef0e2d24dd82`.
Independent review at `/private/tmp/glue-x86-roundtrip-peer-20261028-x8t3iw66`
has five payloads and manifest
`10dd2dd463bab025cfece2989e62fff0325491c343fb227deee698228c133175`.
It also streams the archive without extraction and verifies the complete
4,823-file prepared / 4,822-file restored rosters, including expected sidecars.
Root verifies both review inventories and reads both reports.
The prepared/restored copies are outside `target`. The
[evidence README](../evidence/compact-mvp-2026-10-15/README.md) records exact
indices and a restore command. No archived replay/native application executes,
and local same-host retention does not close external publication, missing
arm64/current-checkpoint recovery or R04/M2. Existing runtime code is unchanged;
new portable CI is tracked in the PR independently of this actual round-trip.

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
| R04 | `codex/mvp-r04-bootstrap-request-stop-status` | `bd0e49d`, based on `409dc4b` | Packet03 installation/signatures pass; ordinary positive request refuses before output/cases; bounded metadata and fresh deployment observation retained |
| R02 | `codex/mvp-r02-bootstrap-retain-install` | `2de4103` decision | Fixed reversible same-parent retention of the completed kit02 installation; actual packet03 and owned controls reviewed, guest move pending |
| R02 | `codex/mvp-r02-reboot-proof-registration` | `28fe9b5`, `41c3f5c`; integrated `8b329f4`, `c24ddb4` | Append-only actual reboot-proof registration,34 source pins unchanged,23 kit controls and independent review pass |
| R02 | `codex/mvp-r02-bootstrap-current-preflight` | `65fc322`, `5f90c48`; integrated `a61225d`, `c9e845b` | Actual native observation and typed identity/mount checks before sudo;19 preparer/18 checker controls pass independently |
| R04 | `codex/mvp-r04-bootstrap-current-status` | `14c1839`, based on `c9e845b` | Fresh proof, rebuilt kit03, preflight and retention-packet checkpoint; no fresh guest run or full Darwin acceptance |
| R02 | `codex/mvp-r02-bootstrap-kit03-binding` | `58fbff0`, `8b068b1`; integrated `f1b4106`, `d295691` | Single literal actual kit03/new-proof binding, combined artifact/catalog audit;19/18 focused controls pass, kit02 refuses unchanged |
| R04 | `codex/mvp-r04-bootstrap-kit03-handoff` | branch tip, based on `d295691` | Reviewed actual packet04 and retention03 staged unchanged; preservation launcher at private guest authentication, no new native outcome |
| R02 | `codex/mvp-r02-bootstrap-checker-proof-binding` | `45627d1`, `476b081` | Share the existing admitted-proof constant; reject old/unknown packet proof before evidence reads;19 preparer/19 checker controls and independent review pass |
| R02 | `codex/mvp-r02-trace-session-integration` | `4520e73` through `68d22d1` | Integrate reviewed owned-child tracing lifecycle models, once-only GO/closure and fixed deadlines; no native backend/runner adoption |
| R02 | `codex/mvp-r02-bootstrap-observed-io` | `ab1f3a2`, `fbcc2cf` | Cooperative observer variants retain legacy ABI, original deadline, bounded waits, confirmed prefixes and error precedence;27 strict/27 sanitizer controls pass |
| R02 | `codex/mvp-r02-bootstrap-observer-inputs` | `b25d51a`, `cb19a8c` | Advance only BIO C/H pins among 34 sources to reviewed `fbcc2cf`; both actual proofs and historical kit03 unchanged |
| V01 | `codex/mvp-v01-trace-session-ci` | `cb26b09` | Add two model suites; all 26 Python suites pass locally on Mac and native offline Linux arm64 with explicit platform skips; no newer hosted run |
| R04 | `codex/mvp-r04-bootstrap-nontracing-status` | `ae48aee`, based on `cb26b09` | Record successful actual retention03/packet04 and independent nontracing replay; exact public push remains pending approval |
| R02 | `codex/mvp-r02-observed-status-protocol` | `c27f06c`, `b778bc3`; integrated `a002720`, `cfe24fb` | Explicit observed status/EOF entry, opaque failed prefixes and unchanged legacy path;11 strict/11 sanitizer groups |
| R02 | `codex/mvp-r02-trace-parent-completion` | `fd53af1`, `6ee2f85`; integrated `f97e9a0`, `463bb9d` | Clarify lifecycle versus final metadata resource closure; no token/layout/predicate change |
| R02 | `codex/mvp-r02-owned-trace-backend` | `6a23ac2` through `a2d8119`; integrated through `6c75976` | Fixed BSD/Mach/proc adapter, exact inventory/EPID/raw layouts and separate native/close errors; source-isolated controls and SDK link only |
| R02 | `codex/mvp-r02-owned-trace-parent` | `79d5fd4`, `21ab4c0`; integrated `e96d0bb`, `d08dd5f` | Separate tracing parent, once-only GO/cleanup/closure/promotion; transient cleanup-clock bug fixed;10 strict/10 sanitizer groups |
| R02 | `codex/mvp-r02-owned-trace-runner` | `5240b05` through `d08dd5f` | Integrate reviewed protocol/coordinator/backend/parent; default build remains nontracing; no native calibration |
| V01 | `codex/mvp-v01-owned-trace-ci` | `abecae2` | Add exactly three protocol/backend/parent control suites; Darwin-only skips remain explicit |
| R02 | `codex/mvp-r02-owned-trace-kit` | `5a1d2b9`, `24ba156`; integrated `f3f0ad1`, `a395ead` | Frozen tracing policy with empty registry, exact disabled SIP and runner-only libdtrace;23 legacy/12 new controls |
| R02 | `codex/mvp-r02-owned-trace-inputs` | `b356590`, `7f15c40` | Update six of 34 default source pins plus host-parser literal; both proofs/kit03 approval preserved; actual historical checker replay0 |
| V01 | `codex/mvp-v01-owned-trace-kit-ci` | `9f281f1` | Add one kit suite; all 30 Python suites pass locally on Mac/native offline Linux arm64; no new hosted or Rust run |
| R04 | `codex/mvp-r04-owned-trace-source-status` | `e2c728b`, based on `9f281f1` | Approved public source push; all nine portable jobs pass in run `39074320935`; native tracing remains unexecuted |
| R02 | `codex/mvp-r02-owned-trace-check` | `634efaf`, `3dc12ce`, `fb1d76a`; integrated `1b89364`, `47cc16f`, `ac7e27a` | Independent fixed raw program/inventory/event validator; repaired valid-baseline mutation controls, 16 portable passes; no case/session/native verdict |
| V01 | `codex/mvp-v01-owned-trace-check-ci` | `a1f0e88` | Add one raw-reader invocation (31 configured); focused 16 controls pass on both native development hosts, separately composed with prior 30 aggregate |
| R04 | `codex/mvp-r04-owned-trace-reader-status` | `519e2ff`, `e9f3d80`, based on `a1f0e88` | Record raw-reader source/controls and independent composed-coverage audit; preserve the fixed older public checkpoint |
| R02 | `codex/mvp-r02-owned-trace-cases` | `7ee2d0f`, `983b9e4`; integrated `fb790b7`, `e1db60e` | Pure complete positive/denied case consistency; 11 synthetic control groups; trusted caller provenance and SIM refusal |
| R02 | `codex/mvp-r02-bootstrap-trace-vm` | `5bf1d81`, `db3ff37`, `5622f9e`, `be85b24`; integrated through `5f96d29` | Separate hard-disabled packet, checked operation status and exact closure gates; endpoint/pump/array regressions repaired |
| V01 | `codex/mvp-v01-trace-packet-cases-ci` | `e40d33e` | Add exactly three packet/gate/case suites; 34 configured; focused 43 controls pass on each Mac/native offline Linux arm64 host |
| R04 | `codex/mvp-r04-trace-packet-cases-status` | `d00dda7`, `424a071`, based on `e40d33e` | Record integrated packet/case sources, focused controls and independent audit; remaining native admission/calibration |
| R02 | `codex/mvp-r02-trace-sim-metadata` | `af74a56`, `8609046`; integrated `66d1b46`, `036d76f` | Pure metadata collection predicate; preserve unknown errors/wait/kill without SIM acceptance; no collector or activation |
| V01 | `codex/mvp-v01-trace-sim-ci` | `783ff41` | Add one pure SIM suite; 35 configured; focused 20 controls pass on both native development hosts |
| R04 | `codex/mvp-r04-trace-sim-status` | branch tip, based on `783ff41` | Record SIM source/controls and remaining native admission/calibration |
| R02 | `codex/mvp-r02-trace-registry-admission` | `f8e50d1`, `e365c53`, `9a294d4` | Fresh disabled proof/41 fixed sources admitted; explicit empty fixture;23/12 kit controls and actual committed admission pass |
| R02 | `codex/mvp-r02-trace-calibration-vm` | `bdd4e41`, `62dd8b1`, `d733783`; merged `ded13fb` | Separate fixed two-case packet/physical checker, initially hard-disabled;16 new/16 original controls and independent review pass |
| R02 | `codex/mvp-r02-kit03-retention` | `66ff4ea`, `6d3884f`; merged `44e78a6` | Fixed bounded read-only inspection and initially disabled preservation; actual inspection and independent review pass, rename pending |
| V01 | `codex/mvp-v01-trace-calibration-retention-ci` | `7fdf01f` | Exactly two new invocations (37 configured); first Linux run preserves two test portability failures, no newer hosted run |
| R02 | `codex/mvp-r02-trace-calibration-portable-controls` | `e35987a`; integrated before `283a94e` | Remove Python-version-dependent test digest; production source unchanged;16 Mac/Linux passes |
| R02 | `codex/mvp-r02-kit03-portable-controls` | `9cea001`; integrated `283a94e` | Exact Perl dependency probe and separate shell syntax control;10 Mac passes, Linux5 passes/5 declared skips |
| R04 | `codex/mvp-r04-trace-build-status` | branch tip, based on `283a94e` | Fresh tracing proof/admission, reproducible unexecuted native kit and successful read-only inventory; guest window and acceptance remain open |
| R02 | `codex/mvp-r02-trace-calibration-admission` | `ecb37f0`, `0ea577a`; merged `d821900` | Admit only actual kit02 and exact 14-payload packet; 16 existing/15 new Mac controls pass; actual packet independently reviewed |
| R02 | `codex/mvp-r02-kit03-retention-admission` | `1e74198`, `d04d91a`, `f75aae6`; merged `9b638cd` | Exact observed two-Library/30-absence profile, durable marker, status-aware retain guards and aligned receipt hash; 17 Mac controls pass |
| V01 | `codex/mvp-v01-trace-admission-ci` | `d73fceb` | Add one packet-admission invocation; 38 configured suites; focused three-suite Linux run passes with five explicit skips |
| R04 | `codex/mvp-r04-trace-packet-status` | `161de67`, based on `9b638cd` | Record reviewed packets/target checks and actual kit03 preservation; tracing first-case wrapper refusal stays private |
| R02 | `codex/mvp-r02-trace-match-accounting` | decision `476c350`, implementation `490a8c3` | Derive bounded inventory from compiled selectors; independent review and normal/sanitized SDK/model controls pass; fresh native calibration and SIP restoration pending |
| V01 | `codex/mvp-v01-macos-cli-refusal-timeout` | `e939d7c` | Increase one configured CLI test's outer deadline; clean local23-test suite and source review pass, hosted repair pending |
| R02 | `codex/mvp-r02-tree-open-intent` | decision `8e01b37`, implementation `b9ef538` | Strict historical tree-open provenance plus pure flag classification; 38 focused controls and 32,841 compatibility inputs pass; full extraction acceptance always refuses |
| R02 | `codex/mvp-r02-trace-match-kit` | decision `9f9fc3a`, implementation `7daa902` | Thin unconfigured match-repair profile; 13 source/synthetic controls and independent review pass; old registrations preserved; actual admission/build/calibration pending |
| R02 | `codex/mvp-r02-trace-match-admission` | decision `c787755`, fixture split `4255819` | Reviewed 42-source candidate frozen at `7daa902`; separate empty fixture and 14 controls pass; production remains empty pending fresh disabled proof |
| R02 | `codex/mvp-r02-darwin-mapping-state` | decision `866a222`, implementation `e831200` | Bounded synthetic mapping/backing intervals and shared-write requests; 38 focused controls and independent review pass; native integration remains open |
| R02 | `codex/mvp-r02-owned-bsd-observations` | decision `49aac44`, implementation `a9f95e4` | Complete-transport-backed immutable BSD scalar observations, exact supplied contract bytes and 4,096-phase cap; 45 focused controls pass; native integration remains open |
| R02 | `codex/mvp-r02-owned-call-pairing` | decision `f2a4214`, implementation `0f2051e` | Closed BSD/Mach interval pairing with strict observed-thread/lifecycle rules; 42 focused controls pass; no native calibration or state-feed permission |
| V02 | `codex/mvp-v02-linux-proof-portability` | decision `724089d`, implementation `95a2799` | Explicit captured Linux errno values for both supported ABIs; seven portable controls pass and seven native controls skip on Mac; public original-proof replay passes; subsequent R02 dependency repair passes the full local baseline |
| R02 | `codex/mvp-r02-owned-reader-dependencies` | decisions `ebe00fc`/`33aa0c2`, implementation `13388ea` | Bind all eager code dependencies before library imports and separate reviewed host pin from historical native inputs; 58 focused controls and full 42-suite/Rust local baseline pass; no native acceptance or publication |
| R02 | `codex/mvp-r02-owned-request-assessment` | decision `724955e`, implementation `84634eb` | Integrated immutable raw request/coverage assessment across 161 declarations; 16 fresh focused controls and independent review pass; portable CI configures 43 scripts; full native oracle remains open |
| R02 | `codex/mvp-r02-owned-trace-inspector` | decision `68444b6`, implementation `baa6508` | Bounded standalone diagnostic directory/CLI, 25 controls plus 16 unchanged core controls and independent review pass; CI configures 44 scripts; native/export admission remains false |
| R04 | `codex/mvp-r04-x86-local-retention` | `39e5390`, based on `8097be0` | Actual prepare/restore of 4,818 recovered files, all 4,820 archive members verified; local backup survives cargo clean; external durability and missing arm64 evidence remain open |
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

## 22 October: owned reader source integration

The separate local `codex/mvp-r02-owned-reader-dependencies` branch stacks on
`caf0b12`. Decisions `ebe00fc` and amendment `33aa0c2` precede implementation
`13388ea`. Case metadata advances coherently to the reviewed owned reader, while
the selected codec definitions, RawFacts and case implementation remain
unchanged. Calibration `libraries()` verifies the fixed syscall helper plus all
three libraries before any import, including cached modules; existing per-load
hash/path checks and module order remain. Aggregate validation needs no contract
asset and does not run the new projections. Loading assumes a stable trusted
source tree. All native builders, registries, preparers, packet/admission pins and
42 candidate source files remain unchanged.

The first focused run passes 11 case, 18 calibration and 15 admission controls,
with no skips. `/private/tmp/glue-owned-reader-dependency-controls-q0_3atsu` has
32 payloads and manifest
`8363ea899a61a441e1c229d16441f41dc74d2609d7b378c3adce1569db770cc8`.
Independent review `/private/tmp/glue-owned-reader-dependencies-peer-20261022-zul09dkk`
has manifest `93d1d1973c06ac4ec27315ded83f8c324ce24969d96d5a5f150655a75a142bf9`.
It verifies unchanged legacy API/validator semantics, the complete code closure,
missing/modified dependencies with cold/warm imports and aggregate validation
without the asset or runtime file I/O. Those six implementation files remain
unchanged through the subsequent decision amendment and final baseline.

The integration baseline then exposes the old whole-file calibration-checker pin
in the match-kit controls. Amendment `33aa0c2` separates only that reviewed
current host checker from eight unchanged historical inputs; exact checks remain
for both sets. The 14 focused kit controls pass without skips at
`/private/tmp/glue-match-kit-reader-pin-controls-yia224ii`, manifest
`89e3ac268bf371807e3dabc691c370c68aefbd9961e96487359181b4ce73f3be`.
Separate independent review `/private/tmp/glue-match-reader-pin-peer-20261022-x397ax7r`
has manifest `bd58664958fd9b928649f914fe39b05b7af519fdc4f6ed1922019503b533ba4a`.
Both reviews find no actionable issue. Root verifies all four inventories and
reads both reports. A reference scan finds no other live consumers of the eight
changed files' superseded hashes.

The final frozen `sh scripts/ci-portable.sh baseline` passes on the development
Mac with Rust/Clippy 1.88.0 and Python 3.15.0. All 42 Python invocations pass:
693 collected, 680 passed and 13 explicit skips. Workspace Rust tests report
628 passed and five ignored; formatting and all-target Clippy with `-D warnings`
pass. The before/after patches, status and HEAD agree. Receipt
`target/mvp-validation/20261022-baseline-reader-closure-final` has eight payloads
and manifest `87139a13d034d78199e05448b53ffd219f4426fdd77691e6798961dc737b6e6c`.
It binds `33aa0c2` plus the frozen working tree: all eight fixture changes later
committed as `13388ea` and the availability README clarification recorded with
this ledger.
The original stale-raw-pin failure remains at `20261022-baseline` (manifest
`5656a9a4117447e871427bb80b0a02fabd8e7fe6fdfd2c187e19c0bd629b18fa`);
the stale-host-pin failure remains at `20261022-baseline-reader-dependencies`
(manifest `fdf91695868c8319dd897e22f4a8a5d719b8428f30e3d223fad253e2ed6136f4`).
Root verifies all three exact inventories. No hosted run or native acceptance is
inferred. All four follow-up branches remain local, guest SIP stays enabled and
full Darwin implementation/corpus, Mac budgets and final retention/M2 remain open.

## 22 October: Linux proof portability and evidence recovery

The separate local `codex/mvp-v02-linux-proof-portability` branch stacks on
`c7e59e9`. Decision `724089d` precedes implementation `95a2799`. The checker now
uses the captured Linux ABI's errno value rather than the importing host's value;
unknown architecture selectors refuse. Native C/filter policy, recorded proof,
helper identities and all other proof/manifest checks remain unchanged.

`python3 -B fixtures/mvp/test_trace_environment.py -v` passes seven portable
controls and explicitly skips seven native Linux controls on the development
Mac/Python 3.15.0. Receipt `/private/tmp/glue-linux-proof-portable-controls-3ysgz_ag`
has 12 payloads and manifest
`5482fcd7ff5736846ca0ef048788f2d209fc82eed1ac99a58a5a948598c4d0c3`.
Independent review at
`/private/tmp/glue-linux-proof-portability-peer-20261022-_igvgk6e`, manifest
`135e65724192d524e54c145cc5db15b879ace878187ebf2f8c7c6ba9522680c3`,
finds no actionable issue and verifies the unchanged native suite/filter.
It also runs `python3 -B fixtures/mvp/trace_environment.py
target/mvp-retention/recovered-x86-38800548172/raw-artifact/provisioning/trace-environment
--architecture x86_64` successfully, without `--record`, native execution or
input changes. Root verifies both inventories and reads the review.

CI adds that test script for 42 configured Python invocations. The first frozen
`sh scripts/ci-portable.sh baseline` attempt returns 1 at the owned-case test's
old raw-reader hash, before Rust tests/Clippy. Its before/after patches agree.
The receipt is `target/mvp-validation/20261022-baseline`, manifest
`5656a9a4117447e871427bb80b0a02fabd8e7fe6fdfd2c187e19c0bd629b18fa`.
This is an integration failure requiring a separate reader/helper dependency
closure repair, not a passing baseline. No hosted run or publication occurs.
The [subsequent integration checkpoint](#22-october-owned-reader-source-integration)
records the repair and successful full local baseline.

The old `/private/tmp` checkpoint, its 18,588 indexed files and all identified
prepared/restored archive copies are absent. Committed inventories remain
historical records; present retention cannot be inferred from their hashes.
The exact original x86_64 artifact ZIP from run `38800548172`, artifact
`12005186009`, is recovered under ignored
`target/mvp-retention/recovered-x86-38800548172`. Its 160,039,296 bytes hash to
`c1cc519d76e73888ed0339714deec1e97eea816c1f8861ab551da4579644e7a4`.
All 4,802 extracted regular files match the original committed inventory; the
two old host-added reports remain absent and are not reconstructed. Safe member
validation precedes extraction. Newly fetched metadata and replay reports have
their own names and provenance.

Fresh offline replay verifies 24 acceptance receipts, 15 benchmark variants,
156 oracle controls, five applicable structural/I/O/FD/scaling profiles and 990
rank results. All five time/RSS checks skip because the recorded host fingerprint
differs from the budget fingerprint. No cold-cache or universal timing claim is
made. The initial errno failure and its diagnostic rerun remain separate; no
stored command or native helper executes. That replay binds 14 original
helper/budget sources to `e3962701`; rerunning its archived driver requires
matching frozen sources or a separately recorded source revision after the
portability repair. The passing report has SHA-256
`945a2185dbb3a106e0e4eb4ae8c6f165cd2b6e3d1f68fd7bdf9384bd6ddc86d9`;
the 15-member `offline-replay-20261022.sha256` index hashes to
`77f03e5eb8c623b27ec375dfb3aa54947e93b350450bb40cacc30a8ef6ff8e56`.
Root verifies that inventory and reads the independent report. These files need
durable backup: `cargo clean` removes `target`. No complete checkpoint or current
arm64 backup is recovered, and no evidence asset is published.

## 22 October: closed owned call pairing

The separate local `codex/mvp-r02-owned-call-pairing` branch stacks on `ded2a4d`.
Decision `f2a4214` precedes implementation `0f2051e`. `pair_raw_owned` validates
the entire original transport and pairs only closed, matching BSD/Mach intervals
within established numeric TIDs. Orphans, overlaps, unresolved entries at exit,
exec/shadow transitions, numeric reuse and ambiguous lifecycle timestamp ties
refuse. Source words, unsupported return shapes and lifecycle context stay raw
and immutable. Limits are 4,096 call phases, 2,048 pairs, 256 TIDs and 1,024
noncall records; the valid closed subset can reach at most 770 noncall records.
Existing public APIs/types and streaming behavior remain unchanged. The strict
subset may deliberately refuse current bootstrap captures; native calibration,
state-feed eligibility, path/FD/backing semantics and full R02 remain open.

`python3 -B fixtures/mvp/macos-trace/owned-trace-check/test_owned_trace_check.py -v`
passes all 42 controls with no skips on the development Mac/Python 3.15.0,
including the unchanged 128 MiB memory control and no runtime I/O across all three
APIs. Final receipt `/private/tmp/glue-owned-pair-controls-llmzdoob` has 15 payloads
and manifest `13cc6123461ee29b5d87da8b3c8a1aca4c895ec05279ed821076c2fe9210f4e5`;
the earlier 41-test success remains separate. Independent review at
`/private/tmp/glue-owned-pairing-peer-20261022-5ptrubbo`, manifest
`fa6f4cac5d9a36d7f9c2252f3b5baad3c116b5704cc674c6340a22ed4b23a9a8`,
finds no actionable issue and checks exact legacy API/private-refactor
equivalence. Root verifies both inventories and reads the review. No CI
invocation, C/wire/contract/registry/state-engine change or publication occurs.

## 22 October: owned BSD observations and restored inspection toolkit

Decision `49aac44` precedes implementation `a9f95e4` on
`codex/mvp-r02-owned-bsd-observations`, based on merged `dfc7747`.
`observe_raw_bsd` retains immutable entry/return scalars and exact record
provenance after the same complete strict transport walk used by `validate_raw`.
Known entries use the pinned source contract; unknown names and unsupported
return shapes remain explicit. The caller supplies the exact 96,972-byte contract
asset. Neither API opens code or assets after normal module import. A prospective
4,096-phase projection cap leaves the old streaming API and bounds unchanged.
There is no call pairing, normalized state conversion or extraction verdict.

Both focused commands pass on the development Mac with Python 3.15.0:
`python3 -B fixtures/mvp/macos-trace/owned-trace-check/test_owned_trace_check.py -v`
(26 tests, including the existing 128 MiB memory control) and
`python3 -B fixtures/mvp/macos-trace/syscall-contract/test_syscall_contract.py -v`
(19 tests). No skips or failed test runs occurred. The final 21-payload receipt is
`/private/tmp/glue-owned-bsd-controls-_g_rqhtj`, manifest
`6ba4a2651c10d9f0c0bf0179d06a75bcc7d84b59b197a56fdc17809467eea882`.
It preserves the separate successful pre-review receipt. Independent review at
`/private/tmp/glue-owned-bsd-implementation-peer-20261022-b70vfn2c`, manifest
`07183632c64ff51b69a87ab73817cabee8fbdc73faa3ae00910d53a357ba8a6f`,
finds no actionable issue and independently compares the old validator body,
signatures, bounds and parser semantics. Root verifies both complete inventories
and reads the review. The existing CI suites already cover both scripts; the
configured invocation count stays 41. Shell syntax and diff checks pass.

The fixed VM inspection toolkit was missing all files. Two fresh builds from
the six unchanged `d2bd45d` sources reproduce the original 53,600-byte signed
executable exactly. Build record
`/private/tmp/glue-inspector-rebuild-20261022-4cy1udig` has manifest
`7fce9af57aaeeef987fd584df0911d84a38bb89c1cc3ae706c8d43e03d1bd2e0`;
independent source/tool/Mach-O/signature review has manifest
`d77f70a74ad5a25ad226a9549ec1db10b8f17a9ac33f6ac8479622d03da35016`.
The empty old skeleton is preserved. All nine restored payloads match the
original toolkit manifest `d5f5519e2f59eff40114297e6c4bdef952f40968352bfe2154e1e4efd96e6505`;
no pin, registry or preflight constant changes. Historical producer provenance
is retained as historical, rather than reconstructed.

A fresh ordinary-user guest inspection completes all six commands with zero
status and exact enabled-SIP output at 13:09:48 UTC on 22 October. Its 27-payload
record is
`/private/tmp/glue-mvp-macos-vm-results/glue-bootstrap-deployment-v1-1xvViCac`,
manifest `a28bcc1604215fec403cf073e0e7424bea288f0a74df83ca91abb3185d157b34`.
Independent review has manifest
`a509870c23d308380ada8f6e59936021e58580cbce55266a9a01242eb4081fc0`.
Actual devices/FSIDs are retained without normalizing to older boots. Root
verifies both inventories and reads the review. This is enabled preflight only;
no tracing proof or boot-security-policy attestation follows from it.
The 20 October coordination window closes before any agent security weakening,
with manifest `2d36f8401533dad6ba6c8040672e19868c3e87dbad6942926d7c6ebf3d61246c`.
The guest shuts down cleanly and reaches Recovery Terminal. Capturing input in
UTM restores menu interaction. The owner then chooses to keep guest SIP enabled
and keep `ded2a4d` local. No SIP change or publication occurs. Recovery shuts down
cleanly with input capture released. The closed no-change chronology is
`/private/tmp/glue-owned-trace-sip-window-20261022-01`, manifest
`72f672abce406947220a3daa127e8d425b5ea252fc278708826f99af6618752c`.
Native tracing remains on hold under that setting. No new native capture,
source admission, full Darwin oracle, macOS budgets or M2 completion is claimed.

## 20 October: mapping write-intent state

Decision `866a222` precedes implementation `e831200` on the separate
`codex/mvp-r02-darwin-mapping-state` branch. The engine preserves declared mapping
and backing generations across partial protect/unmap, address reuse and process
epochs. Shared-file write-capability requests survive failed calls; failed
protect/unmap poisons replay while retaining incomplete diagnostics. Strict
JSONL, cumulative fragment/history/output budgets and exact input-metadata
boundaries are enforced. Full acceptance always refuses before input access.
Existing state/readers, registries and kits remain unchanged.

The final focused command is `python3 -B
fixtures/mvp/macos-trace/mapping-units/test_mapping_state.py -v`, using recorded
Python 3.15.0 on the development Mac. All 38 controls pass without skips in
0.139 seconds; the outer process returns zero in 0.316760125 seconds. Independent
page-grid and disjoint-range controls check interval effects. The 21-payload
receipt at `/private/tmp/glue-mapping-unit-controls-jh28sx1u` has manifest
`d7df39f863e9cc76ea9ed8c2ad3d2f267610eb2700c52ae88f2a4940b094c3f0`.
Its two immutable prior links preserve the first 37-test run's two failures and
one error from cleanup-interfering metadata mocks, then a passing 37-test run
before the final metadata-boundary group. No earlier result is overwritten.

Independent source/receipt review at `/private/tmp/glue-mapping-unit-peer-fanqehtt`
has 37 payloads plus manifest
`52ff6ff4779560af24213d5d12e0a37f6c5fc825fd85465be74e846de9cdf3c1`.
Root verifies both complete final inventories and reads the report. All nine
test source/context identities and copies match; the single CI addition brings
configured Python invocations to 41. Shell syntax and diff checks pass. No
hosted result or publication approval covers this newer branch.

These controls establish declared synthetic consistency. The SDK 27.0 source
pins do not establish equivalence to the macOS 26.6.2 guest; raw ABI, seeded
identity, effect ordering, inheritance/Mach aliases and complete extraction
corpus validation remain open. Ordinary test completion does not attest native
or descendant cleanup. No native kit/provider/capture or security change occurs
in this source step. The guest is in Recovery Terminal with fresh enabled
preflight verified; a new guest-only SIP confirmation remains pending.
Full Darwin R02, macOS R03, R04/M2 and durable evidence publication remain open.

## 20 October: match source candidate and refusal fixture

Decision `c787755` fixes the eventual repaired source revision at
`7daa90268432d74bf44d14df7b344602b810485f`. The external candidate retains the
39 C/header sources and three mandatory helpers, exact ordered 2/19/6 compile
lists and the unchanged literal local-include graph. Only backend C changes
among the historical 41 keys; the new wrapper is the sole addition. Its canonical
42-source map SHA256 is
`1d9c56bdd00bd711cfec0c09979cf427e98a2b56b62e5da7d848b3de59d3b02d`.
The 96-payload candidate record is
`/private/tmp/glue-trace-match-source-candidate-9ulrkuoo`, manifest
`630a3ebf730246be90c83710577b421184c40643b8d670967a5b346432b5e054`.
Independent review at `/private/tmp/glue-trace-match-source-peer-men39guz`
has 10 payloads plus manifest
`1eef8dc00b0a5ffb56819382228d03e3e7b1b727bc75cdbc52b6359b790cb0a7`.
This is source preparation, not admission or native calibration.

Fixture split `4255819` preserves the original 181-byte null/empty registry,
SHA256 `218255f76dcb5da45760c0c84a1e7b17098063055452f752c8eef7850109685d`,
as `unconfigured-inputs.fixture.json`. Its immutable test-only policy differs
only in the fixed registry path. Empty parsing/construction/CLI refusal controls
use that fixture; separate production registry/CLI checks explicitly require
the still-empty production registry. No adaptive acceptance or skip is added.
All 14 focused controls pass without skips, with 58 source/context identities
unchanged before/after. The 68-payload receipt is
`/private/tmp/glue-trace-match-fixture-controls-idjbqho1`, manifest
`75f558b0857eca07eee53f0c3c3474536839dd86e689745b0a471349ae898c7b`.
Independent review finds no actionable issue at
`/private/tmp/glue-trace-match-fixture-peer-dirvq6n_`: 14 payloads plus manifest
`2735b09c25fea58952d0bd420f668bf549758a6bd1e5905402279a8f6d637cbe`.
The existing 42 candidate source pins remain unchanged.

The approved `27d39c3` profile checkpoint is published in
[PR #39](https://github.com/JBlaschke/glue_rs/pull/39), stacked on
[PR #38](https://github.com/JBlaschke/glue_rs/pull/38); merge #38 first.
Both exact-head runs
[39379506210](https://github.com/JBlaschke/glue_rs/actions/runs/39379506210) and
[39379517486](https://github.com/JBlaschke/glue_rs/actions/runs/39379517486)
pass all nine jobs. CI configures 40 Python suites. The 25-payload hosted record
is `/private/tmp/glue-trace-match-kit-hosted-ci-20261020-16ndknuw`, manifest
`c5a8f1cfc7e2979e303e2f5934b89c2441d28f1c3b4b2afb111e1d4fac5b0833`.
Three initial network-preflight failures remain retained before the successful
authorized query; they are not CI job failures. No hosted result or publication
approval covers current `4255819`.

The fresh normal-boot enabled preflight is
`/private/tmp/glue-mvp-macos-vm-results/glue-bootstrap-deployment-v1-aK6rBHWQ`:
27 payloads plus manifest
`cafa6e64fbce51fc05566b2ec1e1e0681c9672df761934d62f38a60347fccd99`.
All six commands return zero and SIP stdout is exactly enabled with its LF.
The independent review at `/private/tmp/glue-enabled-preflight-peer-c5zn5b03`
retains 42 payloads plus manifest
`83cdea6e54be36e29efa7dcf44e41de09dda38e396be2c2d3f2f34843dd93e71`.
Root verifies both complete inventories and reads the report. Inspector toolkit
and six direct source files remain unchanged. This is enabled preflight only,
not source admission or post-disable proof. The VM shuts down cleanly and UTM's
Run Recovery starts the guest boot selector. No fresh weakening approval or
security change is recorded. The new UI coordination record is in progress at
`/private/tmp/glue-owned-trace-sip-window-20261020-01`; the earlier closed window
remains unchanged. UI chronology does not supply command exit statuses.

The production match registry remains null/empty. A fresh independently reviewed
normal-boot disabled-SIP proof and separate actual registration are still
required before a reproducible native kit build and new packet/calibration.
The existing builders, registrations, proof/kit/packet bytes and failed attempts
remain unchanged. These source/test/status steps run no SDK build, native kit,
provider or actual capture. Full Darwin R02, macOS corpus/budgets, R04/M2 and
durable evidence publication remain open.

## 19 October: match-repair kit and restoration

The separate `codex/mvp-r02-trace-match-kit` branch follows decision `9f9fc3a`
with implementation `7daa902`.
It adds only a thin wrapper, empty registry, focused controls and README under
`bootstrap-trace-match-kit`, with one new CI invocation. The wrapper derives four
frozen routing/closure fields from the existing tracing policy. All schemas,
artifact names, exact ordered 2/19/6 compile units, runner-only tracing flags,
strict signing/dependency rules and literal disabled-SIP policy are inherited.
The original builders, registrations and packet bindings remain unchanged.
The new production registry refuses before source locking, proof traversal,
output creation or tools. Synthetic configured parser/proof records remain
test-only; no actual proof is admitted by this step.

All 13 focused controls pass with no skips. The 56 source/context identities
remain unchanged before/after, including the historical 41-source closure and
nine historical builder/registry/packet/test pins. The complete record is
`/private/tmp/glue-trace-match-kit-controls-eaekkllv`, 66 payloads plus manifest
`f94f453af33b777773c1a69419126e076bf4a5200e59e8c3b1f4779479a6d2ae`.
It retains exact outer command/status/streams, source copies and non-atime
identity observations. Inner CLI argv lives in the copied test source, and
normal exit is not independent descendant cleanup evidence. Root verifies all
payload hashes/membership and reads the report. Independent source/receipt review
finds no actionable issue at `/private/tmp/glue-trace-match-kit-peer-h92vt2eu`:
21 payloads plus manifest
`2b985e9a232027461993c3c755c41b6fca6f131d47889a24d62f641bf5e3c1d5`.
It verifies the full control receipt and current source without rerunning tests;
root verifies every peer payload and reads the complete report.
CI now configures 40 Python suites; no full local baseline or hosted
result for this newer feature is claimed. No native/SDK build, actual proof or
capture, guest operation, source admission or kit construction occurs in this
source-only implementation.

The separate guest restoration completes. After the owner's force-stop/4 GB
approval, Recovery runs `csrutil enable`, confirms full boot security and reports
SIP on after private authentication. The VM reboots normally and the owner
unlocks it. The unchanged ordinary-user inspector then runs without sudo and
exports `/private/tmp/glue-mvp-macos-vm-results/glue-bootstrap-deployment-v1-YdIDmdfZ`.
Its 27 payloads plus manifest have SHA256
`9776e6e51941462528c502fe41d36316ea4f0aef4bb57dedbb8986e5ad11700e`.
All six exact command statuses are zero; saved SIP stdout is precisely
`System Integrity Protection status: enabled.` plus LF. The complete observation
at Unix1792440808.238162000 reports VirtualMac2,1, macOS26.6.2/25G83,
Darwin25.6.0 arm64, ordinary501/20 credentials and the current root/Data tuples.
Device16777235 and Data FSID[16777235,26] are fresh observations, not permission
to reuse or rewrite the old catalog. The outer typed wrapper path lost capitals
through UTM and resolved through the guest's case-insensitive filesystem;
captured internal command argv retains the canonical paths.

Independent proof/source review at `/private/tmp/glue-sip-restoration-peer-9pekm_91`
verifies all six command receipts, all proof/toolkit members, wrapper/binary pins
and all six source files at `d2bd45d30c7c3888cb1ba5d3cad4448933c5f126` and current
source. Its 40 payloads plus manifest have SHA256
`09bcad8780f16255d8104bbbf23f4e3a481957ea2bb7b10eaad089eeb1a0dbe9`.
Root verifies complete hashes/membership and reads the full report. The fixed
inspector records enabled SIP; full boot security remains Recovery UI confirmation
without a separate machine-read policy attestation. The closed chronology
`/private/tmp/glue-owned-trace-sip-window-20261018-01` preserves every earlier
OPEN event and ends with the proof/review references: three payloads plus
manifest `93742bbc9b46478f9035db3b054221bf21f303670c9a4ca49a9eb350df081559`.
No physical-host security changes or failed native capture access/rerun occurs.
This closes the temporary guest security window, without granting tracing or
R02/M2 acceptance. A later tracing window requires its own authorization and
fresh disabled proof; this enabled proof cannot admit a tracing kit.

The earlier classifier branch is now published as
[PR #38](https://github.com/JBlaschke/glue_rs/pull/38) at exact source
`e4239b4a644918bc0acfb7887126c0ac5d13fdc0`. Its
[push run 39317343089](https://github.com/JBlaschke/glue_rs/actions/runs/39317343089)
passes all nine portable jobs. The
[PR run 39317456291](https://github.com/JBlaschke/glue_rs/actions/runs/39317456291)
also passes all nine jobs. The 20-payload hosted record is
`/private/tmp/glue-tree-open-intent-hosted-ci-20261019-jsuc1y3q`, plus manifest
`a7f9ae7f17340f406178584faac76e07103f4cdfa2964784bc1f87e2a47705e0`.
All four read-only commands complete0. Its outer collector ends1 on a local
count assertion that excluded the evidence script; the failure/source remain
preserved. Finalization verifies the retained responses and corrected39-script
count without repeating queries or tests. This is not a CI failure. These are
hosted portable results for the classifier checkpoint, not native tracing
calibration or full Darwin extraction acceptance.

## 19 October: tree-open intent bridge

This bounded follow-up starts at merged `main` `9f787e9`, after PR #37.
Both [push run 39313081797](https://github.com/JBlaschke/glue_rs/actions/runs/39313081797)
and [PR run 39313157211](https://github.com/JBlaschke/glue_rs/actions/runs/39313157211)
pass all nine jobs at exact source `e8048665b795c3b74eecb084914634356e6f0fe0`.
The preserved 21-file hosted record is
`/private/tmp/glue-cli-refusal-hosted-ci-20261019-axr6dnzc`, manifest SHA256
`95418c5084f1ab3c8b5a421c13257e5f06edb574cf1e64dd329c47f44b8ec79f`.
These results supersede the earlier pending repair checkpoint below.

Decision `8e01b37` precedes implementation `b9ef538` on
`codex/mvp-r02-tree-open-intent`. The existing normalized decoder delegates only
flag semantics to a pure unsigned32 helper. Its result schema, validation order,
reason order and errors stay compatible. The new path-only bridge invokes the
strict historical raw-v4 tree-open observer itself, retains its complete report,
non-open calls and raw frames, and links classifications to observation/pair/
consumer indexes and observed PID/TID/exec epochs. It neither forges normalized
origins nor infers resolved filesystem objects, successful effects or exemptions.
Failed requests retain write intent. Unknown/unmodeled bits remain unsupported.
CLI success means classification completed, including writes; it is not an
extraction verdict. Full-acceptance requests always refuse before input access.

Focused controls pass with no skips: 12 pure helper, 13 bridge and 13 unchanged
upstream observer tests. Complete rehashed synthetic captures exercise source
validation, non-open poisoning, failed writes, actors/interleaving, bounds,
unsupported flags and unconditional acceptance refusal. The inherited-open-bound
control lowers the limit to zero; it does not build a new 4,096-open corpus.
A separate source-only differential compares baseline `9f787e9` and current
normalized decoder behavior over 32,768 flag combinations, 13 other valid records
and 60 malformed inputs. All 32,841 exact serialized outputs or exception names/
messages agree, with no input mutation. All 15 compatibility input identities
remain unchanged. Native open-intent classes were not executed in these checks.

Receipts remain outside Git:

- `/private/tmp/glue-open-intent-pure-controls-l_qamvt2`: nine payloads plus
  manifest `b08dbea6b022762d36b0b0dbc237d5750be4958246f0f070541f3c7333d8e845`.
- `/private/tmp/glue-tree-open-intent-controls-o26o9o2z`: 25 payloads plus
  manifest `8bcf255ebaf7287c002c6e82f8453f6838319e2fbd4249eabb4ec0d7c6bc5ab5`.
- `/private/tmp/glue-tree-open-compatibility-fyk7l3ak`: 73 payloads plus
  manifest `15d3ed9b3332b60e2b78b26dfb700287f6916738ca22cdb3b9076394aa6e9cc0`.
- `/private/tmp/glue-tree-open-intent-final-review-goqwn8rn`: 91 payloads plus
  manifest `45156fbafa69ea487977ebb3576cba62c4ebdf7f81c83386e39cb1a90c567f65`.
  Independent review finds no actionable issue and verifies both focused receipts
  against current source without rerunning them. Root verifies every payload's
  hash/membership, reads the reports and checks reviewed source identity.

The records retain exact outer commands, statuses and streams with source pins;
the bridge/compatibility/review records also retain source copies. The helper's
small receipt has pins but no copies, supplied separately by review. Normal
command completion is not independent descendant cleanup evidence. CI adds one
new invocation, for 39 configured Python suites; existing observer/unit calls stay
enabled. Shell syntax and diff checks pass. Hosted feature results remain pending.
No actual capture, native provider, SDK build, kit/proof/source registry or
full-acceptance backend is involved in this implementation. The current owned
backend still lacks copied paths and authoritative object observations. Native
calibration, FD/cwd/object causality, other mutation routes, the complete Darwin
oracle/corpus, macOS budgets and R02/M2 remain open.

The separate security restoration proceeds with the owner's approved force-stop
and reduction from 8 GB to 4 GB RAM. Recovery runs `csrutil enable`, confirms full
boot security and reports SIP on after private owner authentication. A normal
reboot reaches the login screen. Normal-boot verification is still pending, so
the guest SIP window remains open in its chronology. This does not rerun the
failed native attempt, inspect its raw capture or change physical-host security.

## 19 October: merged preview and baseline timeout

The three compact language workflows, installer and diagnostics are available
for a development trial with the documented installed dependencies/runtimes.
All26 original cards have implementation commits; this is not a count of26
completed acceptance gates. No additional product feature task is needed before
a first trial. Remaining original task areas are R02 (complete macOS extraction
oracle and corpus/negative controls), R03 (macOS measured costs/budgets), and R04
(durable evidence plus final M2 acceptance/documentation). R02 is substantial and
may expose further fixes. Developer ID/notarization is a public macOS binary
release prerequisite under the chosen policy. Guest SIP restoration is still
unresolved from the last tracing session; this status inspection operates no VM.

Merged-main `08da274` run
[39311833729](https://github.com/JBlaschke/glue_rs/actions/runs/39311833729)
finishes with eight successful jobs and one failed
[macOS baseline job](https://github.com/JBlaschke/glue_rs/actions/runs/39311833729/job/118263122431).
Its only reported error is `subprocess.TimeoutExpired` in
`test_production_cli_rejects_unreviewed_inputs_without_output`: the outer
five-second deadline expires during the configured CLI's source audit. A full
clean source audit can use38 sequential Git calls for34 registered sources,
each already bounded at30 seconds. Shallow/inadmissible checkouts can stop
earlier; the particular slow hosted command is unknown. No application failure
or specific Git deadlock is established by this timeout.

Repair `e939d7c` raises only this test's outer deadline to60 seconds and explains
the ordering. Return1, empty stdout and absent output assertions remain intact;
the neighboring argparse-only deadline remains5 seconds. Production builder,
registries, source pins, historical proofs and kits are unchanged. No shared API
or extraction interpretation changes. The raw public failure capture is
`/private/tmp/glue-ci-macos-baseline-20261019-ex885a7n`:14 files, manifest
`b5baa062bf979e8f963f8c2e16409a7aa4feaaf5941b8b29e44094834fe9b524`.

Clean-checkout local verification at `e939d7c` passes all23 kit tests without
skips, including compile-only minimum26 SDK validation. A separate physical-path
CLI invocation reaches missing `SHA256SUMS`, returns1 with empty stdout and
creates no output. The original extra CLI invocation used macOS's `/var` alias
and correctly refused that path earlier; an over-specific collector assertion
stopped collection, and the separate resolved-path retry is retained alongside
the original results. No suite is repeated or original receipt overwritten.
The completed record `/private/tmp/glue-cli-refusal-controls-20261019-knaa62bt`
has83 files, manifest
`4ce373dfa61ff0e534c0b6d4f594b3b6c77e38a72b7dda42e616b011c6c8bd15`.
It retains exact outer argv/cwd/status/streams/completion, clean Git status
before/after and41 unchanged source/context copies. Inner compiler commands are
defined in copied test source, not separate raw receipts. Normal exits do not
prove independent descendant cleanup, and local timing does not reproduce the
hosted latency. Root verifies every record member and complete reports.

Independent source-only review finds no actionable issue. Its seven-file record
is `/private/tmp/glue-cli-refusal-repair-peer-u5gwfifo`, manifest
`df1de422a779bdf0e58d1acb85665ed64c313a9d8d77db6eae48ee360952267d`;
root verifies all six payloads and reads the complete report. Hosted verification
of this repair remains pending; the failed run is preserved. Product acceptance,
native tracing and guest security restoration are separate from this CI repair.

## 18 October: fresh guest-only tracing window

The owner approved a temporary SIP change only in `glue-mvp-macos-trace`, with
restoration afterward. Recovery displayed the disabled setting after private
owner authentication; the VM rebooted normally. The physical Mac's SIP remains
outside this change. The fresh ordinary-user inspector completed all six fixed
commands with literal status0 and reports exactly disabled SIP. No tracing
provider has run in this window yet; security restoration remains open.

The28-file proof is
`/private/tmp/glue-mvp-macos-vm-results/glue-bootstrap-deployment-v1-Ap5KkPYA`,
manifest `cd57a36af2a9db11f7d24105485137f7afb2ad9743161db190d7ed6c7ca361fd`.
The72-file independent review is
`/private/tmp/glue-disabled-proof-peer-ppxvxcea`, manifest
`2b3c60fc811ed292cd3e33a33851ba751a1de8c3667c5c2df8f4062000d80dfb`.
Root independently verifies its complete membership and hashes. The review binds
all27 proof payloads, unchanged nine-payload inspector, historical/current source
provenance, exact NUL command argv/status/streams and every literal deployment
field. Actual observation time is 2026-10-18T10:54:00.765135000Z, model
VirtualMac2,1, Darwin25.6.0 arm64, macOS26.6.2/25G83. Credentials remain
IDs[501,501,20,20] and the full16-group vector. Every component now has
device16777234, rootFSID[16777236,26] and DataFSID[16777234,26]. These changed
post-reboot tuples replace no historical catalog and are not normalized.

The open security chronology is
`/private/tmp/glue-owned-trace-sip-window-20261018-01`. Its UI observations are
explicitly labeled transcription, with no independent Recovery/wrapper exit or
authenticated boot-ID claim. The independent review retains an exact earlier
OPEN snapshot. The actual six child command receipts are retained separately.
Stable owned namespaces and original writable input permissions remain explicit;
complete hash inventories do not establish immutable or administrator-proof data.

Admission decision `f8e50d1` and test-separation addendum `e365c53` precede registry
commit `9a294d4`. Exact 41 source pins match the closed candidate and frozen
`e2c728b`, with ordered2/19/6 translation units. The one ten-field proof entry
binds the exact fresh proof and independent review above. Both builders, all
native sources, default registry and legacy preparer/checker/templates remain
unchanged. Explicit unconfigured tracing data retains empty/refusal controls;
production CLI override rejection remains direct. The52-file admission record is
`/private/tmp/glue-trace-registry-admission-controls-9_icse7o`, manifest
`2de83cbfd2645c2ead4b1e56f079f6834430e6bf35b7c09897da51a58eaa8967`.
Legacy23 and tracing12 controls pass, no skips. The clean committed lock loads
41/41 sources and actual admitted_proof returns every reviewed literal field.

The successful native build is
`/private/tmp/glue-owned-trace-native-kit-20261018-02`:143 files, manifest
`825d99567feb42bce9915e46e590436291ebffaa2dd1b28ed5c2bb9db124ffde`.
Its33-file actual builder-command record is
`/private/tmp/glue-owned-trace-host-build-receipt-20261018-03`, manifest
`34640346684b2e7332f6ee7dbde715b8b366c88940d3f35b698fa0d5e0eba73d`.
All21 SDK/compiler/sign/verify commands return0, with no timeout or unresolved
cleanup flag. All three signed programs match across first/second/kit copies:
probe52912 SHA`5aed421f11750b0d49c83300f2b8e818309b1fc886e8c535ab9e31f3b40b38e5`,
runner164528 SHA`ddd14bbe29b38e0f02427dad92fa16c74c63fc2bc04eda1980681475a6b9c1bc`,
request72240 SHA`236e78b2f38a79b5711e5d152526b9cfaf3d8735b8ecb0a8287bce81dd376818`.
BuildID is `69de4c44aa5d083c2cba64b1ee83b1978577ee61f46221ca64f620d3413d155f`,
catalog `65f3b9ed3d72f7ce79fdf314be0a40ba249bcb4d4d1c1263d281c328c3e47904`,
recipe `3a55ff7ff82f5673d68b92ef9fc4230eaf656f8a31208daed8e687c15d839689`
and source-lock `f2943d170c27c3ee5eb3c8b151efc2986d840c92c867505f7aa6b669f167d5af`.
Only the runner links libdtrace after libSystem; probe/request remain libSystem-only.
ARM64/min26 and exact fresh root/Data tuples pass root checks. No generated
program runs or installation occurs. The36-file independent kit review is
`/private/tmp/glue-owned-trace-kit-peer-ncx_2oeb`, manifest
`0162fb433e3490b53a4cf13fd26591abb5107118732f29261aa3d0d759428273`;
the34-file distinct catalog review is
`/private/tmp/glue-trace-kit-catalog-peer-74x0yl88`, manifest
`8a120aa2be0dcc52b72a36261aa5b25c5deca0d86d8411561b84cfce0c3b196a`.
Both pass; root independently verifies exact membership/hashes. Reviews bind all
source/tool/artifact/proof/catalog fields and independently parse native Mach-O,
CodeDirectory/page hashes and generated catalog/accessor data. Logical request
vectors use explicitly synthetic inodes and run no utility. An initial reviewer
assumption that unused signature allocation bytes must be zero is retained as a
superseded reviewer-only control failure; exact signed artifact bytes, embedded
signature/page hashes and actual strict signature receipts pass the fixed policy.
All successful input bytes/metadata remain unchanged; failed native01 is untouched.

Wrapper01 initially treated a zero-status Git environment warning as failure and
stopped before builder invocation. Wrapper02 reached the first compile but the
sandbox denied compiler temporary files. Both remain separate. Failed native
output01 stays PARTIAL/unresolved, with no final inventory, repair or reuse;
only bounded partial diagnostic metadata/stderr was read. Wrapper02's outer
possible_live_descendants=false described only its own timeout/error check and
does not override the builder's partial/unresolved marker; its interpretation
record explains this limitation. Wrapper03 records bounded Git warnings and
conservatively marks nonzero builder completion unresolved. It succeeds with
host compiler temporary-file access and a fresh native output02.

The fixed two-case source is `d733783` after decision `bdd4e41`, integrated through
merge `ded13fb`. Its64-file producer record is
`/private/tmp/glue-trace-calibration-validation-alncxz9s`, manifest
`e5dc1b4f462bae54969da2122d44a80cc55b3146d24363eabc23ad855bbe0bb9`;
the56-file independent peer is `/private/tmp/glue-trace-calibration-peer-4l1hv7pq`,
manifest `5b851a165869ce24c10dad9636cb5c6f7e426d2669fa4f3f412f67e05d8b4bd6`.
New16/original16 controls pass with complete independent synthetic pairs,
metadata-before-raw, exact receipts/context/rosters, exhausted128MiB streaming,
FIFO refusal, bounded enumeration and physical read/close failure controls.
The tiny shared kit-loader extraction preserves the original guarded behavior;
old four-case templates/gates/raw/case/native/build inputs stay unchanged.
Both new CLIs remain hard-disabled pending actual kit/packet admission and
reviewed activation; caller-trusted check_export consistency is not packet
provenance or native calibration. SIM remains refused.

Completed-kit preservation source `6d3884f`, after decision `66ff4ea`, integrates
through merge `44e78a6`. Its22-file source/control record is
`/private/tmp/glue-kit03-retention-controls-yed710e_`, manifest
`9138a13d8a96240dcb72cdf38b94ec87310f889a2ef54543fc73b86908fbe2ec`.
Nine Mac controls pass; both generated Perl programs compile without executing
root mains. The actual read-only inspection packet has four files, manifest
`48b56da4c14377d07cf133cf21e97a106eff798d082604910d493c364eaa3a13`.
Root verifies its sources, controls and exact staged bytes under the actual
shared toolkit; the3-file root review is
`/private/tmp/glue-kit03-inspection-root-review-20261018-01`, manifest
`952bc5bb72a700736c56f88173b28a2bc7ca43c69ee780cebc9f9f4e4ce973d4`.
It inspects only the fixed kit/32 historical roots/seven parents with bounded
core Perl reads, exact types/owners/modes/links/ACLs/hash/identity/signature checks.
Source metadata has seconds-resolution limits; coordinated stable namespace
is required, with no assertion that a lock excludes another root process.
Retention remains null/false until an actual physical inventory and independent
review bind every observed tree. The fixed attempt record prevents a new packet
from retrying an uncertain future move. No rename has occurred.

The actual read-only inventory completed after private human authentication.
Its 23-file export is
`/private/tmp/glue-mvp-macos-vm-results/glue-kit03-inspect-2d0913f96f54a01b`,
manifest `563731431c81c3ee0790f5451cfad108bacd3b09f1a0c54667615659f0d03724`.
Root verifies every 22 payload hash and exact roster, zero root-phase status,
the expected receipt path and restored empty shell prompt. Both Library
installations remain present with exact kit03 hashes and strict signature checks;
all 30 inspected historical temporary roots report absent. No cause is inferred,
and missing guest checkpoints will not be recreated. The independent seven-file
review is `/private/tmp/glue-kit03-inventory-peer-hwuddezi`, manifest
`bd56990e6ddc6a067b52d780c2706d96d1e275425f129737108ac499ff2869d1`.
It verifies all command receipts, exact source/packet/context bindings and all 71
historical completed-file pins against unchanged durable host exports. Existing
retention validation requires completed temporary trees, so a
separate reviewed decision/admission is needed before a move. The workflow
coordination receipt is
`/private/tmp/glue-kit03-exclusive-coordination-20261018-01/coordination.json`,
SHA256 `39b44c8b675d9b3429c0ed899a33de2af618d7831bde10c4f3e1b03fd2e09012`.
It records the root-controlled owned fixture slot and delegated exclusions,
without claiming an OS-wide process census or exclusion of arbitrary root writers.

CI `7fdf01f` adds only two baseline invocations for37 configured suites. The
first five-suite native offline Linux run collects76 controls:68 pass,6 skip,
2 fail. All three earlier suites pass; new calibration's Python-version-specific
AST dump hash differs between3.12/3.15, and the cached image's Perl is present
without Digest::SHA. The294-file
failure record is `/private/tmp/glue-trace-calibration-retention-linux-zp2q4aa3`,
manifest `5c88f2a1711bdd5432fffb3bf1c6aa73bd51118523dde73fa350900309d1a326`.
All251 tracked tracing/script/workflow pins match copied/committed/before/after
bytes and metadata. Actual raw receipts stay unchanged. The provisional driver
only parsed skip totals for an OK terminal line, undercounting failed-suite
skips; the record retains it plus a separate corrected76/68/6/2 interpretation.

Test-only repairs `e35987a` and `9cea001` change only the two new test modules and
their READMEs. Production source and the other 247 captured source paths remain
unchanged. Calibration removes the Python-version-dependent AST dump digest,
preserving functional guard/shared-loader controls. Retention probes fixed system
Perl modules, skips only recognized missing-module outcomes, fails unexpected
probe errors, and checks shell syntax independently. Their Mac 16/10-control
receipts are `/private/tmp/glue-trace-calibration-portable-controls-ahic2sg9`
(25 files, manifest `92c8f98aced71f35bc9265056ec3bcdd19bc9028c6d15d1570860835db4fea30`)
and `/private/tmp/glue-kit03-portable-controls-macos-u2ia577r`
(12 files, manifest `b1c139a95879a4d485109961d2df9569ee91b58383a194480b4e752333207fd5`).

At integrated source `283a94e`, the actual two-suite offline native Linux retry
collects 26 controls:21 pass and five skip. Four skips require native macOS; one
requires the missing declared Perl modules. Shell syntax passes separately.
Both suite commands and outer container return 0. The 279-file retry record is
`/private/tmp/glue-trace-calibration-retention-linux-repair-azsot_am`, manifest
`3e70af83af21a501c02da89dbcd957b64d35103ce8334233114cfe547ecb58f0`.
All 251 source pins match copied/committed/before/after identities. The corrected
driver parses skips in both OK and FAILED terminal summaries; earlier raw
receipts remain unchanged.

An independent passive audit verifies both full Linux records, both Mac repair
records, exact CI/container argv and completion facts, 502 Git source comparisons
and unchanged dependencies of the prior passing suites. Its 15-file record is
`/private/tmp/glue-affected-ci-composition-peer-osz49tv9`, manifest
`bc7011973b1eeceb60f6eccfc684700565fb41ccbf40cf63a32c1880686b65e7`.
The affected five suites compose to 77 Mac passes/zero skips and Linux 70 passes/
seven skips across separate runs. The Mac retention producer asserts its source
metadata interval without retaining a separate full before/after metadata pair;
current committed byte pins and actual receipts support the composition.
This does not establish a single combined current-HEAD run or a full 37-suite run.
No newer hosted run is claimed. All source branches and merged commits remain
local beyond the explicitly approved public `e2c728b` checkpoint. Native tracing,
full Darwin oracle/corpus/budgets, R02/M2, security restoration and durable
publication remain open.

### Concrete two-case admission and preservation packets

Decision `ecb37f0` precedes the fixed-kit admission at `0ea577a`. Production binds
the successful tracing kit02, all three artifacts, six metadata byte identities
and the prior kit/catalog/builder/proof reviews. Its checker admits an exact
bounded fourteen-payload packet before evidence checks; regenerated manifests
cannot grant trust to changed payloads or scripts. Synthetic configured policies
exist only at explicit private test boundaries. All old four-case, shared loader,
metadata gates, raw/case/codec, native, builder, registry and template bytes stay
unchanged. The 59-file Mac control record is
`/private/tmp/glue-trace-calibration-admission-controls-e29p63ge`, manifest
`8910445f85543acfb6cde93df28ebbddf5f96e66a4fffdcb60c1952fa598f491`.
Actual 16/15-test commands both return zero with no skips; 27 source pins and nine
actual kit input identities remain unchanged through that capture.

Decision `1e74198` precedes the separately named observed-state retention
contract. It preserves the old completed-tree predicate and unchanged inspection
rendering. The actual profile binds the exact two Library trees, all 30 observed
temporary-root absences and historical host references. No missing guest file is
recreated or represented as freshly observed. Retain-only command-output checks
also require successful command status. The attempt marker moves to a protected
Library sibling, outside the source/archive trees, before the sole `mv -n`.
Normal temporary-directory loss cannot clear that marker; power-loss/fsync and
hostile-writer exclusion are not claimed. A preexisting marker or changed fresh
snapshot refuses.

The original 33-file control record at `d04d91a` is
`/private/tmp/glue-kit03-retention-admission-controls-x8e2s6v5`, manifest
`08974985679688f4b68a21614b3af417ba0e4bc9e2b16d23f21910ad1c9e15ed`.
Its 17 controls pass; the original capture's later full-stat assertion fails only
on a manifest access-time update. The exact before/after facts and assertion are
preserved. Peer review then caught different LF conventions for a same-named
snapshot digest. Final `f75aae6` aligns both snapshot fields to canonical JSON
plus LF; the attempt file itself remains canonical JSON without LF. The successor
20-file record is `/private/tmp/glue-kit03-retention-hash-controls-apeskzai`,
manifest `22cc8bcfba7af52d046f79a676bbf9f565f1041c7e7a20d5f620a080e6853fff`.
All 17 focused controls pass, including the extracted independent Perl/Python
hash comparison. Eleven tested source pins equal the clean committed source;
input bytes and non-atime metadata are unchanged. Root and passive source peers
find no remaining blocker. Actual rename remains separate.

At integrated source `d821900`, the actual host preparer and read-only packet
admission both return zero. The tracing packet is
`/private/tmp/glue-trace-calibration-packet-20261018-01`, 15 files with manifest
`bbfbccd152ed5bf76d3350826c2775e940dc5db2b650c3a5b99533a8f7d4a61c`.
Its 43-file actual command receipt is
`/private/tmp/glue-trace-calibration-host-prepare-20261018-01`, manifest
`1feff1c8d30f17cf93332111037d6bcc88061c62d4f7f68adf5c75c96ae9dcd2`.
All 252 source and 143 kit input identities match before/after, excluding atime.
The independent 55-file actual packet review is
`/private/tmp/glue-trace-actual-packet-peer-9ja4_1qa`, manifest
`72837314733d00766f25a8e5d5cd34a5a2287b2b6e0171162a83b720b218e3f8`.
It checks every member/mode, all nine copied kit identities and separately
regenerated canonical plan/subset/scripts. Later CI and retention source changes
are explicitly qualified; preparation/render/admission dependencies stay fixed.
Root stages exact bytes/modes as
`/private/tmp/glue-mvp-macos-vm-toolkit/bootstrap-trace-calibration-269bf09070bc81f8`;
the staging receipt is `/private/tmp/glue-trace-calibration-stage-20261018-01`.
At this preparation/staging checkpoint, no packet script or native payload had
run in the guest; the actual later attempt is recorded below.

At integrated `9b638cd`, actual retention preparation and deterministic
packet/render/manifest comparison also return zero. The four-file packet is
`/private/tmp/glue-kit03-retention-packet-20261018-01`, manifest
`acb3e552ac38453398c9ee13032db065cc3b21fef463c78044b9a8855c614d25`.
Its 43-file receipt is `/private/tmp/glue-kit03-retention-host-prepare-20261018-01`,
manifest `b41e59dd518b98bc9b9ae7c9c4e30ca394283125ad41e6b5c603b79255b4e32f`.
All 255 source and 136 historical kit input identities remain equal across
preparation, excluding atime. Its fixed nonce is `0d1560914528a4f1`.
The independent 73-file actual packet peer is
`/private/tmp/glue-kit03-actual-retention-packet-peer-kck5j3wd`, manifest
`8d4de46b76405b9353e431725999303752aa8d15c88046762c55084f099aefb8`.
Physical membership, actual command receipts, source bindings, canonical payloads/
plan/root argv, marker/hash conventions and source-enforced move checks pass.
Root verifies every peer inventory member and stages all four exact files/modes as
`/private/tmp/glue-mvp-macos-vm-toolkit/kit03-retain-0d1560914528a4f1`;
the staging receipt is `/private/tmp/glue-kit03-retention-stage-20261018-01`.
After human wake/focus, root visually verifies the complete launcher command
before Return. Fresh UI observation then shows the guest at its private sudo
password prompt after preflight. This preparation review does not itself
establish the later rename outcome.

After human authentication, the actual preservation export is
`/private/tmp/glue-mvp-macos-vm-results/glue-kit03-retain-0d1560914528a4f1`: 23 files,
manifest `22f67bec1c0e1d364d204f845ac6c995e1f140c703c326e63db9a7e7e45cc550`.
All five captured commands return zero. The complete canonical root result
reports retained true and raw move status0 for the one `/bin/mv -n` from
`/System/Volumes/Data/Library/GlueMVPFixtures` to
`/System/Volumes/Data/Library/GlueMVPFixtures-retained-1b85f0ac-da1aaf9a`.
The approved snapshot and all six before/after strict signature records match.
Source-enforced checks require source absence, inode/byte/roster preservation,
the unchanged earlier Library archive and all 30 named temporary-root absences.
The exact no-LF durable attempt bytes independently regenerate to
`c7eee3e5262447186045f1de4b22aad12ce42163afe2a334355c10d9167935eb`, matching
the report; the guest attempt file is not independently opened. Root checks all
22 export payload hashes and the full report. Independent result review
`/private/tmp/glue-kit03-actual-retention-result-peer-q0n21oyu` has 41 files,
manifest `5d2b2eef6279ca42be12a7994e992784fb3ae8cdbf9e7baaffd09ac5e9f191d1`;
root verifies all 40 payload hashes and exact recursive membership. Runtime
source matches prepared `9b638cd`; documentation checkpoint `161de67` differs
only in status docs.

Root next visually verifies and submits the exact staged tracing launcher once.
The immediate screenshot fails with ScreenCaptureKit -3811; a later fresh
screenshot shows the submitted command and restored empty prompt. No relaunch
is performed. Neither expected completed host export exists. Bounded read-only
UI heads of the fixed private receipt show outer status1 and no visible outer
stderr; the batch checkpoint reports preflight0, install0 and positive2, with
empty visible first-case wrapper streams. These are UI transcriptions of private
receipts, not an independently retained command export. Positive2 is a wrapper
refusal and does not establish native status2. The denied case is not reached.
At that point native status and the exact generated gate are unknown. After
human private authentication, bounded read-only UI inspection of the exact
saved native status and metadata reports native1. The files are private regular
root-owned single-link0600 files, with status2 bytes, result2,128 bytes and trace
2,780 bytes; `result.pending` is absent. No raw output is opened or enumerated.
The result reports READY matched, GO attempted/possibly released false and
bytes0, gate closed, child3142 reaped with raw wait status9 by controller3141,
and trace finalization safe with success eligibility false. Parent error is
17/9/0/detail6 and cleanup error12/9/0/detail6. The trace reports started0,
provider-ready0, zero event/pump/BEGIN/terminal/END counts, and resources closed
with all four writer closes attempted and none failed. Its first backend error
is stage2/reason7/callback100, with the literal message
`enabled match count differs from exact selected inventory`: inventory and
expected matches1,051, enabled matches1,257, inventory bytes35,552 and raw
bytes0. These are bounded UI transcriptions, not a retained native result or
independent cleanup attestation. The positive wrapper rejects native1 before
its generated raw roster/export. No manual raw hash, inventory or export is
performed, and the failed attempt is not rerun or promoted.

Decision `476c350` on `codex/mvp-r02-trace-match-accounting` requires compilation
before bounded public-SDK statement/selector inventory, exact fixed selector
coverage and unique physical probe identities, followed by exact enabled-count
equality before `dtrace_go`. The earlier inventory assumes equivalence between
precompile physical probes and compiled ECB match counts. Compilation/probe
lookup may provision probes, but the particular guest count difference has no
established mechanism. Existing kits, source registrations and packets remain
immutable; repaired source needs separate admission and a fresh kit/packet.
No successful calibration or full Darwin acceptance follows from this attempt.

Implementation `490a8c3` changes only the backend C, its source-isolated C
controls and README. Public SDK statement iteration retains at most 512 action
statements and 17 distinct ECB pointers; exact selectors include bare BEGIN/END's
empty provider fields while their physical matches must belong to `dtrace`.
Each selector must have nonempty valid physical matches, with globally unique
IDs/name tuples, at most 8,192 probes and the original byte/deadline bounds.
The expected selector sum must equal the unique inventory count and then the
actual enabled count before GO. The fixed generated program, header/API,
metadata schemas, provider/event/readiness/cleanup contracts and old source
registrations/kits/packets remain unchanged. No count relaxation or retry is added.

The focused controls record is
`/private/tmp/glue-compiled-match-controls-20261018-01`: 59 files, manifest
`51b8aff92819169856b68ab0e158863907bb6d1457e4c9a47ab30a3ceae816c0`.
Final normal and ASan/UBSan attempt02 each return0 with two Darwin groups passing
and one portable-only skip. The isolated model defines all DTrace functions;
real SDK adapter binaries compile/link but are never executed. Exact outer NUL
argv/cwd/status/streams/completion and eight before/after source pins are retained;
inner compiler commands are defined in copied source, not separate raw receipts.
No timeout/output bound is hit, and normal exit is not independent descendant
cleanup proof. Initial passing attempt01 remains separate; attempt02 follows
the final static table-size assertion. Root verifies all 58 payload hashes,
exact recursive membership, final raw receipts and current source copies.

Independent final source/diff/receipt review finds no actionable issue. Its
record `/private/tmp/glue-compiled-selector-final-review-zrb37kyt` has 84 files,
manifest `d10a651f699aa5b577b64870d18bc04c888f60b87891862bee0c25803b8d6dfc`;
root reads the complete report and verifies all 83 payload hashes and membership.
The preceding public-SDK/Apple-source design review is separately retained at
`/private/tmp/glue-compiled-selector-design-review-a9449thm`: 15 files, manifest
`6b498a51607e1ab73067f1f27826d406e18b17f29812b51f7ed5b121c24a3a5f`.
Root verifies every member and the report. Cached Apple source is not established
as identical to the guest binary. These records establish model/SDK and source
verification, not repaired native calibration or the particular mismatch cause.

A new source registration must bind the committed repair while preserving the
historical registry/proof inputs. A subsequent restored/re-disabled boot needs
fresh literal deployment observations and independent review before deriving
the next catalog and kit. Mechanical acceptance of an old registered proof is
not current-boot readiness. Fresh build/signing/kit identities cannot reuse the
old artifact hashes. Before installing another kit, the current tracing
installation `69de4c44...155f` needs its own bounded inspection/preservation;
kit03's nontracing retention approval does not cover it or failed trace outputs.

The guest cleanly shuts down for security restoration; fresh UTM state shows
Start enabled and Stop disabled. Subsequent UTM control/observation calls time
out, so the human is asked to open this VM's Recovery Terminal. A later recovered
observation shows the running VM's normal login screen, without reading a new
SIP status. Closing its console returns noWindowsAvailable, and reconnect times
out; no credentials are entered. The temporary
SIP window remains open pending restoration and normal-boot verification;
physical host security settings are unchanged.

CI `d73fceb` adds exactly one invocation, for 38 configured suites. A focused
native offline Linux arm64 run of the three affected exact CI commands at clean
`9b638cd` returns zero: 48 collected, 43 pass and five explicit skips (four native
macOS groups and one missing declared Perl dependency group). All 255 copied/
committed/current source pins and before/after non-atime identities agree. The
310-file record is `/private/tmp/glue-trace-admission-linux-9d86vdpd`, manifest
`7b9aeb54a253afe41211582d6cdf69cb406ceb290dd380c45dbb087996b62f4e`.
Its complete inner inventory, actual per-suite and outer receipts are bound by
that manifest; root verifies every member hash and exact named membership.
Normal exits do not establish independent descendant-cleanup proof. The
initial sandbox denial reaches no container/test; a separate authorized local
service invocation uses only the cached image with pull-never/network-none,
UID 65534, read-only source/root/control and the prior resource/capability limits.
No complete 38-suite or newer hosted run is claimed. The temporary guest-only SIP
window remains open, and full Darwin oracle/corpus/budgets, R02/M2 and durable
publication remain open.

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
kit02 at `dec2488`. Its 15-file packet manifest is
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
inference rather than an instruction trace. The closed independent current-proof
review is `/private/tmp/glue-deployment-fresh-independent-review-vt3qcmj0`,
manifest `ac654ed36717a52fdbeadd3fcd09853265b0bcdc117befc2efe4836156bb1cc8`.
Append-only registration preserves the earlier proof and all34 production source
pins. Its23 controls pass; the separate source review is
`/private/tmp/glue-bootstrap-reboot-registration-independent-review-20261017-01`,
manifest `8dcd6dd7c21844c8d0b8bef0a29d54d3a7ffeff4d1e1083d6ba8cdfb040c97fb`.
No observation is normalized, old kit relabeled or runtime override introduced.

Actual fresh kit03 is `/private/tmp/glue-bootstrap-native-kit-20261017-03`,
136 files, manifest
`ea67cfba1dab8dc51c44e514ca6ff8a00f703e665cbc89c17f996b3e02f4efae`.
Build ID `1b85f0ac3d3ec2de7df50004ee2732d8d5c049adb44193383245050f800fa11d`
binds the current registered source map and fresh proof. Catalog SHA256 is
`c566af88348f4823aa93c67fa11ce851f210742c1b0b79ab792b3cb192e39e69`.
The actual builder returns0 and all21 recorded tool commands pass; both signed
trials have identical bytes. Its closed receipt is
`/private/tmp/glue-bootstrap-kit03-builder-receipt-20261017`, manifest
`5f9556fe22aa4e9764bf2184163ec704c4324e580624550a9eab1dbca04cb030`.
The combined artifact/catalog independent review is
`/private/tmp/glue-bootstrap-kit03-independent-review-20261017-04`, manifest
`1910f6a1a1274fb41b32030e1a62dff2bf6a218b6d2db1788c3ebb50d6db0e22`.
It passively verifies source/TU closure, exact command records, full hashes,
Mach-O/CodeDirectory structure and both compiled catalogs/current mount tuples.
Recorded strict codesign success remains distinct from passive signature checks;
unused signature-allocation tails are retained and fully hashed, with no invented
zero-tail requirement. No new kit binary executes during build or review.

The reviewed preflight uses the unchanged literal native inspector and exact
binary hash. Before sudo it requires a normal successful, bounded ordinary-user
observation, typed JSON extraction, exact IDs/ordered groups, scope, OS and all
five current component device/FSID bindings. Tool failure cannot pass by emitting
expected text. It does not alter the packet/evidence schemas or native admission.
Independent focused19 preparer/18 checker tests pass without skips at source
`5f90c48`: `/private/tmp/glue-bootstrap-current-preflight-root-review-20261017-01`,
manifest `8f845c59bb4ac4decdc7ff09bc1b6ccbb463f96fcab96b40c217e7edadb2de89`.
These focused runs do not claim a new aggregate run of all24 portable suites.

The completed kit02 installation must be preserved before fresh installation.
[The retention decision](../decisions/mvp-r02-bootstrap-retain-install.md) requires
the exact old stage/closed tree/signatures, absent old outputs and a fresh fixed
same-parent archive. It verifies full five-entry identities before/after one
`mv -n`, with no deletion, repair, retry or automatic restoration. This assumes
a stable protected parent and no concurrent privileged mutator; it is not an
atomic hostile-mutator exclusion primitive. Actual host packet03 is
`/private/tmp/glue-bootstrap-retain-packet-reviewed-20261017-03`, manifest
`6d92594dee41b9dc908f6be4f3cadc2c1e9b1d56ad83a4903bcfe8a118c53557`.
Its independent26-file source/control review is
`/private/tmp/glue-retain03-independent-review-pkz4o9y1`, manifest
`f2a4a881b941db657cfc87e94b9cf0b20fcc8d9033020500082639e0a18a8185`.
An earlier draft's omitted regular-device checks are preserved as a finding;
the fresh packet rejects wrong devices before mutation. Three owned native move
boundaries,21 existing read-only guards and10 focused field/inode controls pass.
The reviewed literal kit03 binding preserves all policy/templates/schemas and
changes only its six approval hashes/IDs plus admitted-proof identity. The same
combined audit supplies both artifact and catalog review fields explicitly.
Actual kit03 passes pure loading and kit02 refuses as an unregistered manifest;
both kits, the combined audit and builder receipt retain identical before/after
physical inventories. Focused19 preparer/18 checker controls pass without skips:
`/private/tmp/glue-bootstrap-kit03-binding-controls-20261017-01`, manifest
`0c83951ed599d05447a151266e9b489000300ac0429ba17f262e9a660d455f27`.

Fresh actual packet04, nonce `da1aaf9a396020b3`, is prepared from committed
`d295691` at `/private/tmp/glue-bootstrap-vm-packet-reviewed-20261017-04`,
15 files, manifest
`3464a9b713df68fe0b58a6f1a47a950af6158baae961ca067f2f626b252d661a`.
Its actual normal-zero host preparation receipt is
`/private/tmp/glue-bootstrap-vm-packet-host-receipt-20261017-04`, manifest
`d86b12b020c33ef9a568dd372172322a6ed7999ebae1c2d08def7bf9294070b2`.
All nine selected members equal kit03; scripts render from exact saved committed
source and pass syntax checks. The independent42-file actual-packet review is
`/private/tmp/glue-packet04-independent-review-awwpfdgd`, manifest
`7bb4d6fce8f1b491b8b33b943848d390d14d4b47a23e142235b9b84d2f1f84eb`.
It independently verifies plan/proof/current tuples, the root/outer/launch hash
DAG, guards, preflight before authentication, closure and export gates.

The separate copy driver's source-only review is
`/private/tmp/glue-packet04-stage-driver-source-review-7p7em49t`, manifest
`9827ba31974232b44c82c2bc5c79068916fe75efa8ab4655d9b2dc862c9be631`.
The driver returns0 and stages retention03's5 files and packet04's15 files into
exclusive fresh toolkit directories, with source inventories unchanged and
destination bytes/modes equal. The closed staging checkpoint is
`/private/tmp/glue-bootstrap-kit03-stage-root-checkpoint-20261017`, manifest
`cb46016403c09ae7f7fa06e8db48937534dcc950df821fcf5b87090a43901854`.
Guest paths end in `bootstrap-retain-kit02-packet03-20261017-03` and
`bootstrap-vm-da1aaf9a396020b3`. The preservation launcher's exact no-argument
command was visually checked before Return. Private guest authentication then
completed; the actual retention and fresh nontracing outcomes follow. None of
the failed packets is edited or rerun. SIP stays enabled.

### Completed kit03 nontracing diagnostic and tracing prerequisites

Retention03 returns0. Its five-file actual export is
`/private/tmp/glue-mvp-macos-vm-results/glue-bootstrap-retained-install-1ee4bbe2b443c268-03`,
manifest `5227e705f2b760c308f335da232eade4b14b6a1046b03919f068a0fdf0699490`.
The old protected installation is preserved at
`/System/Volumes/Data/Library/GlueMVPFixtures-retained-a75d54bb-1ee4bbe2`.
Exact argv, 12 strict signature lines and the five-entry final identity vector
verify. The reviewed source enforces equality before/after the single move;
separate raw before-vectors were not emitted. The stable-parent/no-concurrent-
privileged-mutator assumption remains explicit.

Packet04 then returns0 through its normal outer receipt. The actual 52-file batch
is `/private/tmp/glue-mvp-macos-vm-results/glue-bootstrap-batch-da1aaf9a396020b3`,
manifest `b2654ce96a03860c41a17b26effd411f0da1b6955dd99c43237b8b8eef739cfb`.
Its five-file outer receipt is
`/private/tmp/glue-mvp-macos-vm-results/glue-bootstrap-run-receipt-da1aaf9a396020b3`,
manifest `c688fdcb146e49bcb6450460b6edd9dc0ee3bc89879f30a50bc401c551cf8029`.
Preflight/install/all four case wrappers/complete return0; native statuses are
0/1/1/2 as declared. Positive has READY+ATTEMPT, a 256-byte context report,
strict EOF class 3 and wait 0. SIM has READY+ERROR, no GO, empty captures,
EOF class 2 and raw wait 30720 (normal exit 120); `kill_attempted=true` remains
recorded and is not reinterpreted as signal-caused termination. Denied has one
ERROR before READY/GO, errno 13, empty captures, EOF class 2 and normal exit 120.
Positive/denied request bytes match; SIM changes only release action. The 441-byte
trailing request is the canonical 440 bytes plus one NUL and refuses before output.

The original host checker stops before evidence/case reads because it repeats
the old proof literal. Its failed checkpoint remains unchanged at
`/private/tmp/glue-bootstrap-kit03-run-root-checkpoint-20261017`, manifest
`5fefe9d5315118c8b56486eb65ea81e59b47d83c152ee1fff93f0efa2f34ca9e`.
Decision `45627d1` and repair `476b081` share the preparer's existing admitted
proof constant, retaining policy/templates/schemas. Rebuilt-inventory old and
unknown proof controls refuse before renamed evidence is read. Focused 19/19
controls pass, with independent source review at
`/private/tmp/glue-checker-proof-source-review-Wn0xDe`, manifest
`e70dd5d8867e98325c7bf4afaf9a3699b42f40191ee2d0491b99fc15bdf76c9e`.

The repaired actual checker returns0 without rerunning native cases or changing
exports. Its21-file root checkpoint is
`/private/tmp/glue-bootstrap-kit03-run-root-checkpoint-20261017-02`, manifest
`6c1913ca6fef3b2ecbbfb82382d8dd8f684086750b8fc27ac6de541eaf6c2025`.
The independent140-file review is
`/private/tmp/glue-kit03-actual-result-review-wDKNY4`, manifest
`c0fb82f1237f50e235a9991784f641b71c3dc1df35578a46d9d62f08e1ea4962`.
It checks 14 terminal gates before case payloads, independently decodes BR/BW/NP
and catalog relationships, replays the actual checker byte-for-byte and verifies
all input inventories unchanged. These are strict owned nontracing diagnostics:
producer reports do not establish kernel exec or extraction proof.

The [trace-session decision](../decisions/mvp-r02-trace-session-coordinator.md)
defines the fixed owned-child coordinator. Original feature commits `0cddfdc`
through `cacb5a8` integrate as `4520e73` through `68d22d1`. Readiness and actual
BEGIN precede once-only GO; pumping, reap/ECHILD ownership, cleanup, queued terminal
drain and all closure reports preserve original deadlines and first errors.
Eleven strict/eleven sanitizer model groups pass; independent review adds 14
strict/14 sanitizer groups. Its44-file review is
`/private/tmp/glue-trace-session-independent-review-mpnnvzwy`, manifest
`2be89890d5ad9f22adccd369a0f847ba55d20112b7ab8795c3a43a5311081d21`.
The models supply no native provider or kernel event validation.

The [observed-I/O decision](../decisions/mvp-r02-bootstrap-observed-io.md)
and `fbcc2cf` add explicit cooperative variants without changing legacy APIs or
their operation table. Polls cap at min(remaining ceiling timeout,20ms), keep the
original deadline/retry bound and retain confirmed prefixes on failure, even a
fully written failedGO. Fatal poll/I/O and confirmed trailing-byte errors retain
their original precedence. Nine new and 18 legacy groups pass strict and ASan/UBSan
(27+27, no skips). The initial trailing-error ordering bug is preserved as a
failing reconstructed regression and fixed in committed source. The51-file peer
source review is `/private/tmp/glue-bio-observer-source-review-dGeMdp`, manifest
`4718ca0ad470988ffea370ab3a53067886d40f1f2a46cc8b79cebc16aadb76e2`.
Callbacks remain trusted/cooperative and cannot interrupt kernel stalls.

Registration `cb19a8c` advances exactly BIO C/H among the 34 source pins and
`source_revision` to committed `fbcc2cf`; all 32 other pins, both proofs, compile
unit lists and parser stay unchanged. Clean committed source loading passes 34/34.
Its eight-file independent review is
`/private/tmp/glue-bio-source-registration-review-pCuCrN`, manifest
`464a2613891e719d952ce74a7e6dec397836e46ba043ffb89454d7cb8e8b8eb6`.
No new kit is built; historical kit03/export identities remain unchanged.

CI `cb26b09` adds exactly two baseline Python test invocations. Its seven-file
source review is `/private/tmp/glue-trace-session-ci-source-review-m4wbWV`,
manifest `9621d455db0922e167ca557940a77d3f9df20526373357aac29137d0c0cc71c3`.
All 26 suites collect 418 controls locally: Mac 413 pass/five skip; native offline
Linux arm64 GCC 14 passes 390 with28 explicit skips. The cached image is
`83284f80eba5a876e1441d216f0e1d0143659b05642a75b34cc213270d83c9b9`,
with network none, read-only checkout/root, UID 65534, 256 MB memory and 64-PID bound.
The421-file checkpoint is `/private/tmp/glue-trace-portable-controls-20261017-01`,
manifest `a9628a65d2dd6b602094f71c45b1f42090f2b08bf18e370dfcbc06a13d30d47a`.
All 198 source pins equal before/after/committed bytes. An initial local driver's
assertion counted the informational version probe as a suite and stopped before
any test; its source and empty output directory remain preserved. The corrected
driver runs the 26 exact suite argv. These are local Python/C controls, with no
new Rust, hosted CI, provider or guest execution. The separate 23-file independent
aggregate review is `/private/tmp/glue-trace-portable-controls-review-5qie5L`,
manifest `0e338a1d9a03c7bb65aea1ca5ab8e72488d1dad724e4a876405e9d8d6e15b17f`.
All 420 payloads, both nested manifests, 52 command statuses and verbose case
counts pass; input metadata/bytes stay unchanged. The aggregate has writable
permissions: a complete named inventory is not an immutable-permission claim.
Container policy/outer status are root-witnessed transcription; child logs and
native platform/UID are direct captures, with no embedded outer-container receipt.
At that26-suite checkpoint native backend/runner adoption remained open. The
subsequent source integration follows below; native calibration and the complete
Darwin oracle/corpus/budgets and M2 remain open.

### Owned tracing source integration and 30-suite checkpoint

The [separate-parent decision](../decisions/mvp-r02-owned-trace-runner.md)
preserves the ordinary build/CLI/receipt and selects tracing only through the
fixed compile recipe. Observed protocol `cfe24fb` preserves failed status/GO
prefixes without decoding or replay; eleven strict/eleven sanitizer groups pass.
Its 49-file peer record is `/private/tmp/glue-observed-status-peer-review-NkHFbx`,
manifest `8496e647d9b5c6919eeac3b9a641c778869728b1de335303cadc01cc352a999a`.

The backend integrated through `6c75976` requires the complete fixed
BSD/Mach/proc inventory and exact enabled count. It validates native layouts,
probe/EPID identities and raw writes before coordinator delivery; actual consumed
BEGIN supplies readiness. Target nonshadow exit and queued END are distinct from
current-context/shadow cleanup. Actual POSIX/libdtrace errors, callback statuses
and every writer-close outcome remain separate. Its final validation is
`/private/tmp/glue-owned-trace-backend-closed-9okh8wbf`, manifest
`5af4d0b5258a6132a64957b530941cbc8414377f482d54795d60724a689ad68e`;
the 62-file peer record is `/private/tmp/glue-owned-trace-backend-peer-review-a7fnqrg3`,
manifest `0afbb1bd2643a15220035e96680d74a8a880995719e39917bf7cb21baac80923`.

Parent `d08dd5f` enters only after actual fork/full READY comparison, consumes
readiness/BEGIN before once-only GO, pumps observed status/wait/cleanup, and
retires kill ownership on reap/ECHILD before later fallible observations. The
initial parent allowed cleanup work against the longer attempt deadline after
a transient cleanup-clock failure. The repaired source requires valid shared
cleanup binding; the new control fails against original source and passes the
repair. Ten strict/ten sanitizer groups pass. Backend context remains alive
through parent reporting, and all sidecar/pending/held-directory closure gates
precede the final exclusive rename. The 50-file validation record are at
`/private/tmp/glue-owned-trace-parent-repair-validation-nxj4d4bs`, manifest
`a074cc5fd2d5e78bf2a03150345367021cb96907f08c3005830ded1494d20a5b`;
the 90-file peer record is `/private/tmp/glue-owned-trace-parent-peer-review-s3zqo5jp`,
manifest `a963ae1f07f2661c8f16270f86593a3fa0c71b6337af4cf7436eaef540bfadd2`.
Legacy controls remain separately retained. Linked SDK tracing binaries were
never executed; injected models supply no native provider/exec evidence.

The [tracing kit policy](../decisions/mvp-r02-owned-trace-kit.md), integrated as
`a395ead`, uses frozen internal policies without changing default schemas/CLI,
enabled-SIP admission or legacy recipe bytes. Only `owned-trace-runner` defines
tracing and links exactly libSystem plus libdtrace. Its registry remains null
revision with empty source/compile/proof lists; construction refuses before
source/proof/output/tool access. All 23 legacy and 12 new controls pass. Validation
is `/private/tmp/glue-owned-trace-kit-validation-7va390eo`, manifest
`130b5097b2909824f436908ebebd4ed9d2bcf814563f6189872129c7006b0795`;
the 37-file peer record is `/private/tmp/glue-owned-trace-kit-peer-review-wdlie6bs`,
manifest `0b35edb1eeb6a306954274d738ce8b3f0d535b85114d6570d1fb49c5c89de7bc`.

Separate [registration](../decisions/mvp-r02-owned-trace-inputs.md) `7f15c40`
updates exactly six of 34 default hashes, preserves 28 others, both actual proofs
and all compile lists, and pins source revision `a395ead`. Only the existing
legacy preparer's parser hash changes. Clean committed source loading passes
34/34. The actual historical checker replay returns0 with identical native
results; only parser/preparer source identities differ. All four input trees'
bytes and file/directory metadata remain unchanged. Its record is
`/private/tmp/glue-owned-trace-input-registration-20261017-01`, manifest
`4ccf8f8e10bd3b4a85d95e3b975e9f50892b3b37b0e501a34dcdf0cc5fed6cfa`.
The 73-file independent review is
`/private/tmp/glue-owned-trace-registration-peer-review-you9emkw`, manifest
`f1e34366a980d389c07ffd1074dccbd562d1185964c8140aee79d6fb369c4cf3`.
It verifies all source pins, both report identities and all four actual input
trees twice, without rerunning the checker or loader. The root record remains
writable; the separate peer record has read-only permissions.
No new kit or guest run follows from this registration; tracing admission stays
empty and kit03 retains its historical lock.

CI `abecae2` adds three invocations and `9f281f1` adds one. The complete local
run of all 30 Python suites collects 454 controls per host: Mac 448 pass/six skip;
native Linux arm64 GCC 14 passes 413 with 41 explicit skips. Parent promotion models
are Darwin-only (all 10 skip elsewhere); Linux runs the backend refusal and skips
its two SDK models, while the kit adds one Linux SDK skip. The first 481-file
record at `/private/tmp/glue-owned-trace-portable-controls-20261017-01`, manifest
`f34e22e8fdc31b70e53580d3ef2dd36d949b36012f6a8f45752d77fb45c2b40f`,
passes all controls but omits executed `scripts/fetch-evidence.sh` from its 157
selected source pins. It remains unchanged with that source-closure limitation.
The repaired driver inventories every tracked macos-trace file and script and
repeats all 30 exact suites. Its 538-file record is
`/private/tmp/glue-owned-trace-portable-controls-20261017-02`, manifest
`302bb2f8e1316a35fec00dd3856d5d6956f5abee90836674e0cf63000797d8f7`.
Both hosts again pass the same 454 controls. All 214 source pins equal
before/after/committed `35c0abd` bytes; that commit changes only progress/ledger
documentation from `9f281f1`, outside the selected runtime/script sources.
Actual outer Mac/container argv, completion status and streams are captured,
alongside 60 suite receipts. The cached native image and offline/read-only/
UID 65534/capability-drop/256MiB/64-PID policy remain fixed. Record permissions
remain writable, with no hostile-actor immutability or rootless-engine claim.
No Rust, hosted CI, provider or new guest execution is included.
The separate 1,046-file independent CI/aggregate review is
`/private/tmp/glue-owned-trace-aggregate-peer-review-5klfrdes`, manifest
`448943bbf2a41f198913ab9200e8f248654c8f5b29489c14ddbcaf2a92776b0a`.
It verifies both complete records and nested inventories, all source identities,
all command/count/skip receipts and the source-selection repair. Both inputs'
bytes and physical metadata stay unchanged. No suites are rerun by the reviewer.

An independent streaming raw reader, separate tracing packet/checker, fresh
post-SIP-reboot proof, reviewed trace source admission, actual kit construction
and protected-install retention still precede guest calibration. SIM has no GO
and must retain its actual failed-trace/normal-exit-or-kill facts; it cannot borrow
positive success eligibility. Absolute monotonic/DTrace timestamp domains have
not been equated. The VM and physical host remain SIP enabled. Full native
process-tree effects, extraction verdicts, Mac corpus/budgets and R02/M2 remain
open; no raw exports or newer source have been published.

### Independent owned raw reader

The [raw-reader decision](../decisions/mvp-r02-owned-trace-check.md) introduces
only pure byte/stream validation. Final source `fb1d76a`, integrated as
`ac7e27a`, independently reconstructs the exact target-bound fixed program,
requires all 17 inventory categories, checks stable probe/EPID bindings and
reconstructs each arm64 little-endian scalar from its exact native descriptor.
One BEGIN, actual target nonshadow terminal and END are required; shadow exits
and allowed post-terminal thread cleanup remain distinct. Error bytes refuse
before event iteration. Facts are returned only after complete exhaustion.
Observed EPIDs do not prove enabled inventory counts. Caller-supplied PIDs/read
bounds remain trusted; GO, stop/drain/DONE, reap, parent/resource closure,
deadline derivation and timestamp-domain equivalence remain separate checks.

Root review found that several initial mutation fixtures were standalone records
that would also fail without mutation because their lifecycle was incomplete.
The repair changes tests/docs only: complete valid baselines now precede each
mutation, intended rejection reasons are checked, and terminal mutation contexts
avoid duplicate-terminal masking. Final 16 controls pass, including 8,192-probe
capacity and exact 134,217,728-byte generated streaming input with a measured
Python allocation peak below 8 MiB for that fixture. This is not a general RSS
budget. The original 15-control record remains unchanged and superseded.
Final validation is `/private/tmp/glue-owned-trace-check-validation-u2zig128`,
manifest `9fe84987bac90f5714f5b5b7d1d2d09ec7220fa35e41878c1ea2b68b1ead585f`.
The 49-file independent review is
`/private/tmp/glue-owned-trace-check-peer-review-9cjaz4mc`, manifest
`48ec52fcba0fd29ee29f6f54a670e59228e17eee4495c69a6199648873724f57`.
It verifies both records, source/SDK contracts, repaired controls and unchanged
input bytes/metadata without executing the parser, tests or any native program.

CI `a1f0e88` adds exactly one invocation; removing that line restores the prior
30-suite script byte-for-byte. A focused run executes this new suite on Mac and
native offline Linux arm64, each collecting/passing 16 with no skips. The
251-file record is `/private/tmp/glue-owned-trace-check-portable-controls-20261017-01`,
manifest `f49318094e02b2cf0d338d4591282ee32675c56b6710ca2db470f0bcd31a0b9c`.
All 217 selected tracing/script sources equal before/after/committed `a1f0e88`
bytes. Relative to the preceding aggregate, only three component READMEs and
the new CI line change existing selected files; three new reader files are added.
The previous 30 suites are referenced, not rerun: composed coverage accounts for
470 controls per host (Mac 464 pass/six skip, Linux 429 pass/41 skip). No single
31-suite run, hosted result, new Rust suite or native provider execution is
claimed. The fixed `e2c728b` public checkpoint excludes this reader; its pending
push request replaces the earlier `ae48aee` request.

The 271-file focused-control peer audit is
`/private/tmp/glue-owned-trace-check-portable-peer-5m08d0xj`, manifest
`a082258cddb746e3ac2188f93fe021d366ef6d857c6967a625298c308f0a5b1a`.
It independently verifies all focused and basis inventories, 217 source pins,
exact CI/driver deltas, both native command receipts and the 30-plus-one coverage
composition without executing tests or reviewed tools. Both original input
trees retain identical bytes and physical metadata before/after the audit.

### Disabled tracing packet and complete case checks

The [complete-case decision](../decisions/mvp-r02-owned-trace-cases.md) and source
`983b9e4`, integrated as `e1db60e`, add a separate pure positive/denied consistency
layer. It links catalog/request/BW/NP bytes to every traced result/sidecar field,
including PID/context/digests, exact GO/status/reap/resource closure, native versus
callback errors, inventory/observed EPID counts and the exact raw-to-session event
projection. Twenty vendored pure codec definitions are AST-identical to the
pinned legacy reader, with an exact dependency closure; the legacy full checker,
packet loader and producer are never imported or relabeled. Caller identities,
roster and RawFacts provenance remain trusted. Declared clocks are checked only
where recorded; original budget derivation and timestamp-domain equivalence are
not inferred. SIM/unknown selectors refuse before inspecting payloads.

Eleven complete synthetic control groups pass, with valid positive/denied
baselines before single-field corruption and explicit baselines for all three
denied wait/kill race pairs. The 14-file component record is
`/private/tmp/glue-owned-trace-cases-validation-2rckv9n5`, manifest
`ab910974d01f3ff7cf003ce66f7f6dd9147c7ab4dc4f4d977a5ea8bac3236e52`.
Root's independent passive 27-file audit is
`/var/folders/_1/4wfvp9l93ln8l9rfqbv8qm_w0000gp/T/glue-owned-trace-cases-root-peer-bjm4lf69`,
manifest `f87f709accdf6139d1991b00118810bc41a479cc5d350d481b0cae2bfb94e622`.
All five snapshots equal committed/current source; the original input tree's
bytes and physical metadata remain unchanged. No tests or native tool ran during
that passive audit.

The [separate packet decision](../decisions/mvp-r02-bootstrap-trace-vm.md), source
`be85b24` integrated as `5f96d29`, adds eight new host/template files. Public CLI
approval/execution/SIM constants remain null/false and refuse before helper or
supplied input/output access. Synthetic rendering emits literal disabled guards
and an unapproved marker; changing constants alone cannot activate it. Legacy
preparer/checker/templates, kit03 approval, registries and limits are unchanged.
The fixed new profile has three artifacts, fresh paths, exact current deployment
checks, physical/full-mode/signature guards and distinct bounded export limits.
Promoted small metadata must resolve child, signals, gate, session, backend,
writers, snapshot and destroy before raw roster/read/export or denied-mode
restoration. Full raw/case validation remains a later layer. SIM always refuses,
so this revision cannot complete the four-case batch, even after a successful
individual positive case.

Review corrected shell status loss, ambiguous negative array-index lookup and
two source/fixture contradictions. Expected stdout from a failed read never
passes; array counts require successful typed reads. Successful endpoints retain
role 5/fd -1; a clean positive has bootstrap and waiting pumps, no cleanup pumps,
and a coherent total. The denied matrix remains exactly `(30720,false)`,
`(30720,true)` or `(9,true)`, with no widening of SIM. Final component controls
comprise 16 preparation and 16 gate groups plus separate syntax-only and
activation-refusal captures. Generated privileged phases were never executed.
The earlier passing models are preserved as superseded, not native compatibility
evidence. Final 120-file record:
`/private/tmp/glue-bootstrap-trace-vm-final-controls-8x8fhex3`, manifest
`9b9be055d96c055406f6b36d7d78ecf866575e8557fb65a4048f57fb4b22ebb0`.
All 30 retained source pins equal integrated committed/current bytes.

The independent six-file preparer/template review is
`/private/tmp/glue-bootstrap-trace-prepare-peer-s7llvbk3`, manifest
`a0b06bee5de33e9fec2fbd2d28caca135b7c0432242b2ff8070001309e3ed063`.
Its author explicitly excludes the two gates they implemented. Their final
18-file gate control record is
`/private/tmp/glue-bootstrap-trace-gates-final-rsy8285s`, manifest
`7fce4d218b538e787ab7c7569244425dcf6d1ceb3047126d1fe26830751332a5`.
The separate independent C-versus-original-gate audit is
`/private/tmp/glue-trace-gate-c-audit-lq3ens7_`, manifest
`373913ca1fab6d54663b368045ea0984068e8253879cee9585f01421db12c59e`.
Root separately verifies final source adoption and all named inventories/hashes.

CI `e40d33e` adds exactly three invocations; deleting them restores `a1f0e88`'s
31-suite script byte-for-byte. The focused 283-file record is
`/private/tmp/glue-owned-trace-packet-case-portable-controls-20261017-01`, manifest
`85547276ed099da8480fc3839aca45734ba4c15b89e873f117248834c51cbc7a`.
Both actual outer receipts complete zero, with exact NUL argv/status/streams;
each Mac/native offline Linux arm64 child collects and passes 43 controls with
no skips. All 229 selected tracing/script sources match before/after snapshots,
copied bytes and committed `e40d33e`. Relative to `a1f0e88`, only CI changes
existing selected bytes; twelve packet/case files are added. Composing the prior
30-suite 454-control aggregate, focused raw-reader 16 and these three suites
accounts for 513 controls per host: Mac 507 pass/six skip; Linux 472 pass/41 skip.
There is no single 34-suite run, newer hosted/Rust result or native provider run.

The independent 312-file focused-control peer audit is
`/private/tmp/glue-trace-packet-case-portable-peer-7mm2o57f`, manifest
`fe0ce78de3f1be9303bb8c4b11cf1bf97f09ef38378ddd50e709cf11dab64fd0`.
It verifies all current/basis inventories, 229 source identities, the exact CI
and driver changes, six suite and two outer completion receipts, repository
import/source-read closure and the stated composition without rerunning tools.
All three original input trees retain identical bytes and physical metadata.

SIP remains enabled in the VM. Fresh exact post-reboot proof, tracing source/proof
admission, a reproducible signed kit, separate current-kit retention, reviewed
packet activation and narrow SIM calibration remain prerequisites for native
work. No actual kit/proof/export, guest, staging, sudo/SIP, publication or network
operation belongs to these source changes. Kernel exec, full extraction/effect
oracle, Darwin corpus/budgets, R02, M2 and durable evidence publication remain open.

### Pure SIM diagnostic metadata

The [SIM metadata decision](../decisions/mvp-r02-trace-sim-metadata.md) precedes
source `8609046`, integrated as `036d76f`. This is a pure bounded bytes/status
predicate, with no collector, CLI, renderer, file/raw/VM operation or activation.
Exact schemas, types, array shapes, error namespaces and source-defined resource
shapes must describe known reap/gate/signals/parent/backend closure. Failed
create, allocated-but-unstarted and started/failed-start remain distinct; a
configured-but-uninitialized session and backend-started/session-not-started
clock failure are represented without inventing successful resource closure.
Writer masks are fixed creation prefixes; any failed close refuses eligibility.
Original bytes and all parsed fields are retained in frozen slotted structures.
Actual wait/kill and unknown tracing/end/drain errors remain literal observations.
Every returned SIM pass/calibration/exec/full-acceptance flag is false. Promotion,
pending absence, invocation/outer status and physical copying remain future
caller duties; producer declarations are not authenticated kernel evidence.

The final 89-file component record is
`/private/tmp/glue-trace-sim-metadata-controls-heuedd1h`, manifest
`8198f197a4af0ed32b09007d3ad256d91596197bd439fa96f2315a5c759f2411`.
All 34 source pins match integrated committed/current bytes. It retains the
direct 20-group passing source-bound capture, with independently literal
complete baselines before focused corruption. Earlier unbound draft streams
remain explicitly superseded. Fixture review corrected empty-capture hashes,
cleanup error propagation, init/start state, observer counts and native error
messages; those passing drafts are not native compatibility evidence. The direct
10-file test handoff is `/private/tmp/glue-trace-sim-tests-final-sgwga86y`, manifest
`e8ca80091ecf4d3ebef6264965bbd1cb98f436eab93a870f39e0741db40f18f0`.
All existing packet/checker/kit/legacy sources remain unchanged.

The independent 45-file functional source/control peer review is
`/private/tmp/glue-trace-sim-peer-review-mxjo1zzb`, manifest
`494fd5fcc17748dac5c9e702463ffcdd338955888e3d6ac9799ca405560a4cc0`.
It verifies every producer/direct-test payload, all 34 source identities and 17
unchanged native contracts, exact resource shapes, source-grounded complete
fixtures, 20 controls and the all-false/deep-freeze boundary. No test or reviewed
module is imported/rerun. Original producer and source bytes/metadata remain
unchanged. Root separately verifies the component, direct and peer inventories.

CI `783ff41` adds one invocation; removing it restores `e40d33e` byte-for-byte.
The focused 267-file record is
`/private/tmp/glue-owned-trace-sim-portable-controls-20261017-01`, manifest
`244dd431a0efb9dd6679bcea21eb7bd632f2b2121e27ed73ab8f8ca5083dc2a2`.
Both actual outer commands and the two suite commands complete zero. Each Mac
and native offline Linux arm64 host collects/passes 20 with no skips; all 233
selected source pins match before/after snapshots, retained copies and committed
`783ff41`. Only CI changes existing selected bytes relative to `e40d33e`, and four
SIM files are added. Coverage composes the prior 454-control aggregate, raw16,
packet/case43 and SIM20: 533 controls per host, Mac 527 pass/six skip and Linux
492 pass/41 skip. No single 35-suite run, hosted/Rust result, provider/guest run,
actual collection, proof/kit admission or R02/M2 closure follows.

The compact 53-file independent CI/receipt/source-composition audit is
`/private/tmp/glue-trace-sim-ci-peer-final-krtom3gd`, manifest
`68663cc9e8363a68a081ee4dab304e55b8c72cb55081ce4d9af070a554c7b48a`.
It verifies all 266 current payloads, both nested runs, 233 source identities,
driver/CI deltas, exact method/command/completion receipts and all three basis
references without rerunning tests. Its author excludes an independent
functional verdict on the tests they wrote. Original input bytes and physical
metadata remain unchanged. Partial source/basis manifests in this compact audit
are clearly named references rather than incomplete nested evidence trees.

### Approved public source checkpoint and current VM preflight

The owner approved and root pushed exactly `e2c728bcdb25ceb151f8f434859c668faf0abcd0`
to `codex/mvp-r04-owned-trace-source-status`. Public
[run 39074320935](https://github.com/JBlaschke/glue_rs/actions/runs/39074320935)
completed all nine declared jobs successfully, on push attempt 1, at
2026-10-17T22:18:53Z. The 104-file local retention record is
`/private/tmp/glue-public-e2c-ci-monitor-20lgn127`, manifest
`d6c9c6d65938597d7be955bdca05256b9cf6101ff0abd8634d2e0e4fc17f9d07`.
It retains actual metadata/log GET argv, statuses and streams, all nine completed
job logs (835,267 bytes), exact checkout SHA, matrix/runner identities and final
completion metadata. Initial network and ANSI-log read failures are preserved;
the read-only log retrieval adjustment did not rerun the workflow. This public
checkpoint configures 30 Python suites. The later local 35-suite stack and its
composed controls are not attributed to this hosted run.

Every earlier published `origin/codex/mvp-*` tip is an ancestor of `e2c728b`.
The preferred next merge is that one branch into `main`, preserving ancestry
with a merge commit. The original 26-card stack is already merged through
PR #34. The newer local stack ending at `adc5fbc` contains the reader, packet,
case and SIM follow-ups and belongs in a later separately validated public
checkpoint. Alternate local development branches are not extra merge inputs.
No merge, branch deletion or new PR was performed during this check.

The unchanged read-only inspector ran again in the current guest before
Recovery. All six commands returned zero; the 28-file proof is
`/private/tmp/glue-mvp-macos-vm-results/glue-bootstrap-deployment-v1-UpQXf3Yc`,
manifest `069b98a8ce2a1917ff8d9ad440f20f1e140595ebcc78e77f5cd68ef8e9ddf2aa`.
It reports SIP enabled at 2026-10-17T22:23:13.747047000Z, VirtualMac2,1,
Darwin 25.6.0 arm64/macOS 26.6.2 (25G83), IDs 501/501/20/20, root device
16777231/FSID `[16777236,27]` and Data device 16777231/FSID `[16777231,27]`.
These remain pre-Recovery observations, not disabled-SIP admission. The distinct
77-file proof/toolkit/CI peer review is
`/private/tmp/glue-fresh-proof-ci-peer-t979xc3g`, manifest
`a300f005529f6a68e6075b3772c2698c43316deabc4e6b1117d5811f239b7641`.
It verifies complete inventories, original inspector provenance, literal command
receipts and all nine CI logs, with unchanged input bytes and physical metadata.

The external source-only registry candidate is
`/private/tmp/glue-trace-registry-candidate-8x9wjgbm`, 83 files, manifest
`e909d5af8f142f95800d26119cb582517428c93474ab6de35c5da55a03e883bf`.
Its 41 native/core/wrapper pins match current, committed and public `e2c728b`
bytes, including the recursive 39-file C/header closure and ordered 2/19/6 TU
lists. Source parsing and locking pass; the external candidate has no proofs.
The production registry remains null/empty. A fresh exact post-reboot disabled
proof, independent review, committed admission, signed reproducible kit,
current-kit retention and reviewed packet activation still precede tracing.
No native provider run, SIM calibration, full Darwin oracle, R02/M2 closure or
durable evidence publication follows from these source and preflight records.


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
The historical indexed checkpoint prepared and restored 18,588 captured files without
rewriting them; replay from a new root passes 94 receipts, ten budget profiles
and 1,980 rank results. The archive is 619,802,268 bytes with SHA-256
`aa8b2291a670791f8a50626c1098eb2281b8b616cff260163c9aa895ddc8879f`.
Independent review of its final native x86 subtree also passes 24 acceptance
receipts, 15 benchmark variants, 156 controls and 990 rank results, with the
4,804-file subtree unchanged. Review artifacts created after preparation are
separate from that frozen checkpoint; exact identities and commands are in the
evidence README.

The 22 October availability audit finds that original temporary checkpoint and
its archive copies missing. Only the exact 4,802-file x86_64 artifact subtree has
been recovered so far, with new independent replay and separately named reports.
See the [current recovery checkpoint](#22-october-linux-proof-portability-and-evidence-recovery)
and the evidence README before relying on historical locations below. Complete
arm64/current-checkpoint recovery or fresh native runs and durable retention
remain required.

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
