# Current milestone status

1 November 2026. The [project plan](../../PLAN.md#milestones) defines five
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
2. **Mac source integration:** merged on `main` on 31 October. Held-CWD selection
   ([PR103](https://github.com/JBlaschke/glue_rs/pull/103)), fixed runtime launch
   recipes ([PR106](https://github.com/JBlaschke/glue_rs/pull/106)) and original
   output/gate witnesses ([PR108](https://github.com/JBlaschke/glue_rs/pull/108))
   came first. The actual READY/gate/witness runner is in
   [PR110](https://github.com/JBlaschke/glue_rs/pull/110). The stopped-child output
   observer is in [PR113](https://github.com/JBlaschke/glue_rs/pull/113). Fixed FD,
   scalar fcntl and F_GETFL interval profiles are in PRs #112/#114/#115/#116. The stopped
   collector/reader is in [PR117](https://github.com/JBlaschke/glue_rs/pull/117),
   typed lifecycle status in [PR118](https://github.com/JBlaschke/glue_rs/pull/118),
   file-synced observation retention in
   [PR119](https://github.com/JBlaschke/glue_rs/pull/119) and stopped-stream FD-policy
   integration in [PR120](https://github.com/JBlaschke/glue_rs/pull/120). The runtime
   image boundary and repeated-image pairing of the closed PRs #104/#107 arrived
   through PR108, and the fixed trace session/backend of the closed PR #109 through
   PR110. These are source/model milestones with independent review, not complete
   native oracle acceptance.
3. **Active implementation:** connect the fixed controller to actual fork-minted
   ownership, exclusive stop observation, file sync before continuation, bounded
   cleanup and final lifecycle receipts. The merged stopped-stream FD policy
   supplies no output seed or grant.
   In parallel, implement a small hosted native enablement diagnostic. Raw
   correlated samples or intended CONT calls do not authorize output exemptions.
4. **Hosted Mac evidence:** the corrected read-only inventory
   [run 40915997467](https://github.com/JBlaschke/glue_rs/actions/runs/40915997467)
   at c869536 passed. It reports an arm64 Mac, existing disabled SIP and a successful
   syscall-provider listing. It enabled no probes and traced no target; actual
   enablement/calibration remain unmeasured. Guest SIP stays enabled. This is a
   possible native test route without changing the guest's security setting. The
   inventory job merged in [PR111](https://github.com/JBlaschke/glue_rs/pull/111)
   on 1 November.

The compact host query ([PR105](https://github.com/JBlaschke/glue_rs/pull/105)) merged
on 1 November as well. PRs #104, #107 and #109 were closed without merging because
their features were already on `main`; their validation records are carried into
the ledger and progress record. Exact decisions, sources, tests and limits remain
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

The compact Mac host check now reuses the existing bounded native product-version
query, removing a helper subprocess and reader thread while preserving OS-floor
checks. Forty scoped Rust tests, formatting, Clippy and independent review pass.
Runtime launch recipes and the source-selected runtime boundary are on `main`
through PR106 and PR108; native admission of the runtime catalog is still not
configured.

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
