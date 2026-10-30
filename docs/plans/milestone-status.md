# Current milestone status

29 October 2026. The [project plan](../../PLAN.md#milestones) defines five
milestones. The [26 task cards](mvp-tasks.md) are implementation assignments,
not 26 release gates. The [execution ledger](mvp-implementation.md) records exact
commits, tests, target scope and evidence limits.

| Milestone | Status | Delivered or remaining |
| --- | --- | --- |
| M0 — Foundations | Delivered | Distribution contracts/layout, inventory, native-host CI and executable Python/Node provider proofs. |
| M1 — Source preview | Delivered development preview | Lua 5.4/5.5, Python and Node build/run workflows, runtime selection, relocation/offline checks and runnable examples. Historical evidence recovery is still part of M2 closure. |
| M2 — Native compact MVP | In progress | Native packaging works across all three languages. Both Linux targets pass 49 same-source receipts and five applicable structural budgets, plus actual wrong-ABI refusal. Mac controller/oracle integration, native corpus, budgets and final sign-off remain open. |
| M3 — Memory mode | Planned | Earlier narrow experiments exist. General runtime/native dependency acquisition, Linux memory execution and macOS mapping/TLS/unwind/runtime/signing gates remain. |
| M4 — Expansion | Deferred | Broader compatibility, Julia bundles, combined executable, HPC sharing and optional mixed-language calls. Windows/BSD follow Linux/macOS completion. |

## Current work

The compact implementation spans all 26 original task cards. R02, R03 and R04
remain open, including source integration and oracle work in R02. Implementation
commits are not accepted release gates. `main` and PR merges remain under your control;
feature work continues while CI runs.

1. **Linux native corpus:** both architectures pass the same-source
   [cohort 40863475232](https://github.com/JBlaschke/glue_rs/actions/runs/40863475232)
   at 8532d509. Each has 49 independently replayed V02 receipts: 24 base, 7 archive/uv,
   3 patch/abi3 and 15 benchmark variants, 196 oracle controls and 990 rank results.
   Each also retains a separate actual prepublication wrong-ABI refusal. The five
   structural/I/O/FD/scaling budgets pass unchanged; time/RSS limits were
   inapplicable because the recorded host fingerprints differ. Older arm evidence
   is publicly retained; this newer 421.6 MB two-target set is prepared and verified
   locally, with separate public-asset approval pending. No new native run is
   implied by replay or archive preparation.
2. **Mac source integration:** the actual READY/gate/witness runner is in
   [PR110](https://github.com/JBlaschke/glue_rs/pull/110). The stopped-child output
   observer is in [PR113](https://github.com/JBlaschke/glue_rs/pull/113). Fixed FD,
   scalar fcntl and F_GETFL interval profiles are in PRs #112/#114/#115/#116. The stopped
   collector/reader is in [PR117](https://github.com/JBlaschke/glue_rs/pull/117),
   typed lifecycle status in [PR118](https://github.com/JBlaschke/glue_rs/pull/118),
   and file-synced observation retention in
   [PR119](https://github.com/JBlaschke/glue_rs/pull/119). These are source/model
   milestones with independent review, not complete native oracle acceptance.
3. **Active implementation:** connect the fixed controller to actual fork-minted
   ownership, exclusive stop observation, file sync before continuation, bounded
   cleanup and final lifecycle receipts. The reviewed stopped-stream FD-policy
   feature is
   `codex/mvp-r02-runtime-stopped-fd-policy`; it supplies no output seed or grant.
   In parallel, implement a small hosted native enablement diagnostic. Raw
   correlated samples or intended CONT calls do not authorize output exemptions.
4. **Hosted Mac evidence:** the corrected read-only inventory
   [run 40915997467](https://github.com/JBlaschke/glue_rs/actions/runs/40915997467)
   at c869536 passed. It reports an arm64 Mac, existing disabled SIP and a successful
   syscall-provider listing. It enabled no probes and traced no target; actual
   enablement/calibration remain unmeasured. Guest SIP stays enabled. This is a
   possible native test route without changing the guest's security setting.

The new source merge order is #112 → #114 → #115 → #116, #113 after #110, then #117 → #118 → #119;
#111's host inventory is independent. All PRs target `main`. Merge dependencies
first to reduce stacked diffs. Exact decisions, sources, tests and limits remain
in the [execution ledger](mvp-implementation.md) and [progress record](../progress.md).

## Remaining M2 delivery

- **R02 — complete the Mac oracle and native corpus.** Finish controller and
  runtime-policy integration, source-grounded filesystem/object/process/thread/
  mapping coverage, then calibrate original native observations. Run the full
  relocated/offline corpus and positive/negative extraction controls under the
  selected final development signing policy. Current helpers grant no native
  state, output exemption or full-trace authority. A scalar enablement diagnostic
  alone cannot close this work.
- **R03 — measure Mac deployment costs.** Use complete native observations for
  deployment/startup/I/O/FD/memory and multi-rank measurements, then freeze numeric
  budgets. Existing Linux structural budgets remain; newer timing/RSS values
  cannot silently replace host-scoped limits.
- **R04 — retain and sign off actual supported cells.** Finish durable retention
  of the latest approved Linux/Mac evidence, exact compatibility records and fresh
  operator documentation. Verify each M2 requirement against its receipt and keep
  unexecuted or unsupported cells explicit.

The first complete native Mac corpus run remains the next major readiness
checkpoint. Source control counts do not provide a reliable completion date.
M1 is a usable development preview while M2 remains open. Ad-hoc signing is the
selected development policy; Developer ID/notarization is additionally required
before public macOS product-binary publication.

## What M3 still needs

The seven [memory roadmap cards](memory-roadmap.md) are separate from the 26
compact-MVP assignments. None is recorded complete. Existing Linux arm64
sealed-memfd Lua and selected Python experiments, and a controlled two-image
Mac mapper, provide reusable groundwork with narrower compatibility boundaries.

| Card | Remaining delivery |
| --- | --- |
| ML01 | General sealed-memfd native acquisition on Linux x86_64 and arm64, including real runtime images, TLS/thread lifetime and C++/Rust unwinding. |
| ML02 | Complete archive dependency graphs, symbol versions/scopes, conflicts/cycles, introspection and declared nested loading without undeclared host lookup. |
| ML03 | Lua, Python import/ctypes/CFFI and Node addon integration; run the compact corpus with all non-system native payloads archived. |
| MM01 | Production Mach-O mapping/binding, required fixups and dependency/image semantics, compared with dyld on unchanged signed inputs. |
| MM02 | Actual compiler TLS/TLV initialization, access, concurrency, destruction and lifetime across existing, new and library-created threads. |
| MM03 | C++/Rust unwind behavior, loader identity/introspection, TLS interactions and secondary/nested loading. |
| MM04 | Actual archived Python/Node workloads, suitable memory providers, V8 JIT/W^X policy and signed final deployment with version-specific evidence. |

All paths need relocated/offline positive and negative native controls proving
zero payload-file creation and no extraction fallback. Unsupported capabilities
must reject explicitly. M3 permits a launcher plus archive; the combined single
executable is the later X01 expansion task. Compact-mode native success alone
does not satisfy memory-mode acceptance.


## Original runtime output and gate evidence — 29 October

Feature `codex/mvp-r02-runtime-witness`, implementation `34c5a8d`, retains both original parent-held output sampling rounds before tracing or GO. It binds those rows to actual owner/child and exact request/catalog/READY bytes. The actual parent separately records confirmed GO bytes and write/error/close outcomes, including failed full delivery; retention attempts are once-only and successful finalization requires both witnesses. The strict generic RR/RC/TL reader checks the complete original 1024-byte status stream, launcher up to 16 MiB, separate sibling CWD, actual character-device stdin topology, both sample rounds and gate delivery. It validates the entire raw capture before returning conditional output lineage values. Existing public probe profiles and empty runtime admission remain unchanged.

Validation: 40 final runtime/object/legacy/traced-parent controls passed, including an actual ordinary child/gate/CWD/FD/exec and retained witnesses with explicitly modeled protected admission/credentials. The observed helper passed 26 controls on both Python versions normally and under ASan/UBSan; independent wire/adapter controls passed 13 in each cell. Existing v1(35), v2(34) and new recipe(24) reader controls passed on both versions, including actual C codec comparison. A test-only portability define repair passed its two affected controls on each version. Strict GCC checks and independent C/Python reviews passed. Source registration preserves historical proof entries and rosters; genuine 34/41-file loaders and all 26 active registration controls pass after a retained test-pin repair. Historical metadata bytes are separate non-executable fixtures, not reclassified native proof.

Ignored final evidence: integration `e0864dec56dc70875361cd31893677897ebe619d4703938e58529e5442b8900f`; C peer `13661a4d40a822ab5d7145088a67b95d74d05ca04dd27f538120eaa7dc8b8b17`; reader peer `bd6c3db8ae95b81ceacc3bc526eb05c89fc9b0fd88b0e3469697f022f49ea076`; clean post-registration receipt `064fea40aaf6bfd5d10a3fbbd9f00c57d777460fbe08ab8e306251025b0c1bb6`.

M0/M1 remain delivered; M2 is active. The next implementation connects the fixed runtime trace session/backend to the actual runner, followed by conservative sink-capability state and complete syscall/process/mapping coverage. Native Mac calibration/corpus, offline/environment integration, budgets and final retention/sign-off remain. These consistency facts authenticate neither native origin nor OFD/generation identity and authorize no sink exemption, state feed or full extraction verdict. M3 memory mode remains planned and separate from the first compact MVP; M4 stays deferred.


## Owned traced runtime runner — 29 October

Feature `codex/mvp-r02-runtime-trace-runner`, implementation `9b5af34`, joins the fixed runtime launch and original witnesses to the fixture2/v2 trace session/backend. Eight fixed wrappers share the traced attempt layout, including admission and witness units. The untraced profile header remains unchanged and direct tracing markers still refuse. Actual READY comparison and original output witness retention precede attach; provider readiness and BEGIN precede GO. The traced path retains actual confirmed GO bytes, write/error and close outcomes, including failed full delivery. Early unresolved CWD/output references report failed parent closure, and no result can promote before complete cleanup, final snapshot and destruction. Runtime result and sidecar schemas are distinct and keep all native/exemption/full-acceptance flags false.

All 116 source-isolated controls pass on both Python versions, normal and ASan/UBSan. A narrow four-run addendum strengthens the positive promotion assertion; original receipts remain intact. Forty existing runtime/object/legacy/traced-parent controls pass without skips, including an ordinary real child fixture with explicitly modeled protected admission and credentials. Four retained old probe JSON examples remain byte-identical. The SDK build links the unconfigured runner without running a provider, and all eight GCC non-Apple wrapper syntax checks pass on Mac. Independent peer review verifies 1434 retained base/additive payloads and reports no open findings.

The approved import of main preserves every reviewed production/test byte; its documentation conflict retains both chronological records and its four CI additions remain. Registration `609118f` carries only two legacy and six trace source hashes, with rosters/proofs/historical snapshots unchanged. Genuine clean loaders pass 34/41 files, and 26 registration plus 30 imported fcntl controls pass without skips. Final registration receipt `ecba855352765d054b2d28a57da87a0a4ca04c45e5de1b336ff5a6df35d38032`; independent peer `735dda30ea7deb09a8d4b56a1107dfcb8f2b6ef243d55bfce8f415040e38c2f1`; author report `fa541aa70999810c6f7e8d4078085820f04dfe3879d4366e2b2a1d12a715a1bc`. All raw controls stay local.

M2 remains active. The raw FD interval policy is now the next implementation, with a separate post-exec backing witness required before output exemptions: clear CLOEXEC does not establish retained output backing because exec can implicitly close/replace stdio. Full BSD/Mach/VM/process/thread coverage, offline/environment integration, native Mac calibration/corpus, budgets and final retention/sign-off remain. M0/M1 are delivered; M3 memory mode is separately planned and M4 deferred. No provider, VM, sudo, ptrace or SIP action occurs in this source feature.
