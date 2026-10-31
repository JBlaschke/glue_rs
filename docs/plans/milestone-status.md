# Current milestone status

29 October 2026. The [project plan](../../PLAN.md#milestones) defines five
milestones. The [26 task cards](mvp-tasks.md) are implementation assignments,
not 26 release gates. The [execution ledger](mvp-implementation.md) records exact
commits, tests, target scope and evidence limits.

| Milestone | Status | Delivered or remaining |
| --- | --- | --- |
| M0 — Foundations | Delivered | Distribution contracts/layout, inventory, native-host CI and executable Python/Node provider proofs. |
| M1 — Source preview | Delivered development preview | Lua 5.4/5.5, Python and Node build/run workflows, runtime selection, relocation/offline checks and runnable examples. Historical evidence recovery is still part of M2 closure. |
| M2 — Native compact MVP | In progress | Native packaging works across all three languages. Both Linux targets pass 34 application cases and five structural budget profiles at the same source, with complete independent replay; time/RSS gates are host-scoped and inapplicable on the fresh hosts. Arm base proof is externally retained and replayed. Full Darwin oracle/corpus, Mac budgets and final sign-off remain open. |
| M3 — Memory mode | Planned | Earlier narrow experiments exist. General runtime/native dependency acquisition, Linux memory execution and macOS mapping/TLS/unwind/runtime/signing gates remain. |
| M4 — Expansion | Deferred | Broader compatibility, Julia bundles, combined executable, HPC sharing and optional mixed-language calls. Windows/BSD follow Linux/macOS completion. |

## Current work

1. PRs #92–#95 reached `main` at `cb24720`, including the BSD entry, outcome and
   descriptor/write semantics and both Linux acceptance records. PR #95's
   eighteen portable checks pass. New PRs target `main`
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
4. [Scalar fcntl PR #96](https://github.com/JBlaschke/glue_rs/pull/96) adds four
   descriptor duplication/flag commands through both syscall forms; thirty
   controls pass on each tested Python version. The independent Linux
   compatibility feature adds seven traced archive/uv cases. All seven pass native
   arm execution/replay; [PR #99](https://github.com/JBlaschke/glue_rs/pull/99)'s
   bounded streaming repair makes all seven pass on x86 too, with 46 receipts,
   184 controls and 990 ranks independently verified. Time/RSS gates are
   inapplicable on the repaired x86 host; accepted structural limits remain.
5. Patch-version/abi3 and a genuine wrong-ABI refusal extension is implemented,
   with 30 pure controls, 18 collector controls and 21 shared runner controls
   passing on each tested interpreter. Both-target native execution/replay is
   complete: native run `40863475232` at `8532d509` and independent replay pass on
   both targets, with 49 receipts, 196 controls, 990 ranks and the separate genuine
   refusal each. All five structural budgets pass; time/RSS are inapplicable.
6. [Mac READY PR #101](https://github.com/JBlaschke/glue_rs/pull/101) completes
   initial output-backing adoption with 120 integration controls and clean genuine
   source-loader validation. Held-directory CWD selection is being implemented.
   Full runtime capture boundaries/tree pairing, filesystem state policy and
   native Mac trace/oracle acceptance remain open.

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
  sign-off record, including externally retained current compatibility evidence and fresh Mac
  cells. Linux archive/uv, additional-patch, abi3 and genuine wrong-ABI refusal
  execution/replay now pass on both targets at `8532d509`. Arm64 evidence is regenerated,
  replayed, publicly retained and
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
full-oracle gates. Initial CWD selection now uses the admitted directory handle;
37 focused controls pass, including real renamed/replaced-path, permission and
parent-CWD checks. Independent review and clean source registration pass.

[Linux compatibility PR #100](https://github.com/JBlaschke/glue_rs/pull/100)
passes additional-patch, abi3 and genuine wrong-ABI refusal checks independently
on both native Linux targets, with complete replay recorded in PR #102. M0/M1 are delivered, M2 remains active, M3 is planned
and M4 deferred. M3 memory mode is separate from the first compact MVP.

The active next Mac feature establishes an explicit runtime capture/image
boundary, preserving the complete bootstrap prefix and accounting for exec
thread changes. A raw sink-capability state policy follows it; unknown or
ambiguous effects must fail closed. Generic runtime launch adoption, native
calibration/corpus, Mac budgets and final sign-off remain open.

The fixed generic runtime launch profile now has copied argv, protected launcher
hashing, independent held CWD and opaque output/wait capture, with 53 integration
executions, 22 planner controls and clean source registration passing. It remains
unconfigured and untraced. Repeated image/thread handling is separately reviewed.
The next source integration connects the actual trace profile and matching
runtime/output evidence before the sink policy and native Mac corpus.

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
