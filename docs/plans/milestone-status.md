# Current milestone status

28 October 2026. The [project plan](../../PLAN.md#milestones) defines five
milestones. The [26 task cards](mvp-tasks.md) are implementation assignments,
not 26 release gates. The [execution ledger](mvp-implementation.md) records exact
commits, tests, target scope and evidence limits.

| Milestone | Status | Delivered or remaining |
| --- | --- | --- |
| M0 — Foundations | Delivered | Distribution contracts/layout, inventory, native-host CI and executable Python/Node provider proofs. |
| M1 — Source preview | Delivered development preview | Lua 5.4/5.5, Python and Node build/run workflows, runtime selection, relocation/offline checks and runnable examples. Historical evidence recovery is still part of M2 closure. |
| M2 — Native compact MVP | In progress | Native packaging and ordinary-loader integration work across all three languages. Linux x86_64 recorded 24 acceptance cases and five reviewed budgets. Full Darwin oracle/corpus, Mac budgets and final retained evidence remain open. |
| M3 — Memory mode | Planned | Earlier narrow experiments exist. General runtime/native dependency acquisition, Linux memory execution and macOS mapping/TLS/unwind/runtime/signing gates remain. |
| M4 — Expansion | Deferred | Broader compatibility, Julia bundles, combined executable, HPC sharing and optional mixed-language calls. Windows/BSD follow Linux/macOS completion. |

## Current work

1. Consolidate the reviewed owned request assessment and standalone inspector
   into `main`. PRs #87/#88 merged into their stacked feature bases; the milestone
   integration targets `main` explicitly. Their exact implementation head passed
   all eighteen push/PR portable checks.
2. Run the new native Linux arm64 acceptance automation, replacing missing
   evidence with a reproducible fresh run. Implementation `3698ae4` adds exact
   target-matched inputs, the complete 24-case corpus and all five budgets.
   Portable controls, full local baseline and independent source reviews pass;
   fresh native execution and separately retained replay remain pending.

The diagnostic assessment covers 161 BSD declarations, and its operator command
adds bounded file handling. Every diagnostic stays incomplete with native/export
admission and extraction/state-feed eligibility false. These tools do not supply
the missing Darwin oracle.

## Remaining M2 gates

- **R02:** implement source-grounded Darwin result/state/object semantics and a
  complete process-tree filesystem oracle, then run positive/negative controls
  and the relocated/offline product corpus. The current owned collector lacks
  authoritative path/FD/backing/port bindings. Guest SIP remains enabled; native
  tracing cannot proceed under the current approved setting.
- **R03:** measure and freeze Mac deployment/startup/I/O/FD/memory and multi-rank
  budgets against complete native observations. Existing Linux limits retain
  their recorded host scope; newer measurements must not silently replace them.
- **R04:** recover or regenerate missing arm64/current evidence, establish
  external durable retention, and finish the exact compatibility/sign-off record.
  The recovered x86 archive has a verified backup outside `target`, on the same
  host. That is local integrity protection, not external durability.

The 26 cards all have implementation commits; remaining original acceptance
work is concentrated in R02/R03/R04. M1 remains a preview until M2 closes.
Ad-hoc signing is the selected development policy. Developer ID/notarization is
an additional requirement before public macOS binary publication.

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
