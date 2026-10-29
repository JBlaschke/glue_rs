# Current milestone status

29 October 2026. The [project plan](../../PLAN.md#milestones) defines five
milestones. The [26 task cards](mvp-tasks.md) are implementation assignments,
not 26 release gates. The [execution ledger](mvp-implementation.md) records exact
commits, tests, target scope and evidence limits.

| Milestone | Status | Delivered or remaining |
| --- | --- | --- |
| M0 — Foundations | Delivered | Distribution contracts/layout, inventory, native-host CI and executable Python/Node provider proofs. |
| M1 — Source preview | Delivered development preview | Lua 5.4/5.5, Python and Node build/run workflows, runtime selection, relocation/offline checks and runnable examples. Historical evidence recovery is still part of M2 closure. |
| M2 — Native compact MVP | In progress | Native packaging works across all three languages. Recorded x86_64 and fresh arm64 Linux cells pass 24 cases/five budgets; arm proof is externally retained and replayed. Full Darwin oracle/corpus, Mac budgets and final sign-off remain open. |
| M3 — Memory mode | Planned | Earlier narrow experiments exist. General runtime/native dependency acquisition, Linux memory execution and macOS mapping/TLS/unwind/runtime/signing gates remain. |
| M4 — Expansion | Deferred | Broader compatibility, Julia bundles, combined executable, HPC sharing and optional mixed-language calls. Windows/BSD follow Linux/macOS completion. |

## Current work

1. Diagnostic PR #89 and arm acceptance repair PR #91 reached `main` at
   `43bf806`. The repair's eighteen portable checks pass. New PRs target `main`
   explicitly, and status/evidence changes stay on their own milestone branch.
2. Native arm run `40754980497` at `30e8d08` and its complete independent replay
   pass all 24 cases and five unchanged budgets. The explicit benchmark-input
   repair preserves seeded application cases. All raw identities and a prepared/
   restored local bundle verify. Approved arm evidence is published and remotely
   replayed. Same-source x86 refresh `40758958354` also passes all 24 cases/five
   budgets and independent replay. Its local archive restores successfully; the
   prepared x86 release set awaits separate publication approval. See the
   [arm record](../evidence/native-linux-arm64-2026-10-28/README.md) and
   [x86 record](../evidence/native-linux-x86_64-2026-10-28/README.md).
3. Independent [paired-result PR #92](https://github.com/JBlaschke/glue_rs/pull/92)
   and [entry-ABI PR #93](https://github.com/JBlaschke/glue_rs/pull/93) add real
   source-grounded Darwin semantics, with 27 and 25 focused controls passing on
   each tested Python version. [Operation milestone #95](https://github.com/JBlaschke/glue_rs/pull/95)
   builds on them with eleven descriptor/write/flush/truncate forms and 37
   passing controls per tested interpreter. These are conditional source rules;
   native calibration, object binding and effect ordering remain open.

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
- **R04:** finish remaining target retention and the exact current compatibility/
  sign-off record. Arm64 evidence is regenerated, replayed, publicly retained and
  independently downloaded/replayed. Same-source x86 refresh and replay pass;
  its fresh backup verifies locally and the prepared publication set awaits
  separate owner approval. The older recovered archive also remains retained.

The 26 cards all have implementation commits; remaining original acceptance
work is concentrated in R02/R03/R04. M1 remains a preview until M2 closes.
Ad-hoc signing is the selected development policy. Developer ID/notarization is
an additional requirement before public macOS binary publication.

## Recent functional delivery — 29 October

The real Mac bootstrap object profile now captures its initial five descriptors
and matches regular output backing against the parent's held references before
tracing or GO. Its 120 local integration controls and separate wire checks pass;
after source registration the genuine 34/41-source loaders and 31 targeted
controls pass. This supplies initial backing association while preserving all
full-oracle gates. The next branch selects initial CWD from the admitted
directory handle, including a real renamed/replaced-path control.

[Linux compatibility PR #100](https://github.com/JBlaschke/glue_rs/pull/100)
runs additional-patch, abi3 and genuine wrong-ABI refusal checks independently on
both native Linux targets. M0/M1 are delivered, M2 remains active, M3 is planned
and M4 deferred. M3 memory mode is separate from the first compact MVP.

The source-selected runtime producer and first-image reader are now implemented
and independently reviewed, with 13 C-transport and 35 reader/wire controls per
tested Python version. They retain bootstrap and changed-thread exec boundaries
without granting native provenance or output/state acceptance. Generic runtime
launch recipes and a native macOS host-version query are active separate features.
Later execs/process-tree handling, sink state policy, native corpus and budgets
remain before M2 closure.

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
