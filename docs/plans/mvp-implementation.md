# MVP implementation and acceptance ledger

15 October 2026. Product authority remains [the plan](../../PLAN.md),
[the contract](mvp-contract.md) and [the 26 task cards](mvp-tasks.md).
Each card has its own local feature branch, with prerequisite commits stacked or
cherry-picked for integration. No branch was merged to main and no release asset
was published. `codex/mvp-r04-docs` is the combined review branch; task branches
retain their own implementation commits.

Implementation and acceptance are separate. Shared contracts, the three compact
builders, ordinary-loader native routes, runtime/version discovery, integrity and
host checks, relocated/offline harness, extraction oracle and benchmarks are
implemented. Native Linux x86_64 and complete macOS process-tree tracing remain
unperformed. M1/M2 therefore remain open. Cross-compilation/emulation, snapshots,
ad-hoc signatures and skipped tests do not replace those observations.

The owner selected ad-hoc signing for development acceptance. Strict-valid
existing Developer ID signatures are retained and accepted by this development
policy; every image's actual signature class is recorded. Developer ID plus
notarization is required before publishing macOS binaries; it is a later release
check, not a claim established by the development signatures.

## Task branches

| Task | Feature branch | Current task commit | Implementation / remaining acceptance |
| --- | --- | --- | --- | --- |
| C01 | `codex/mvp-c01-contracts` | `c599587` | Schema 1, descriptors, locks/reports, diagnostics; schema 0 preserved |
| C02 | `codex/mvp-c02-distribution` | `74308df` | Deterministic complete tree, atomic publication, integrity/accounting |
| C03 | `codex/mvp-c03-linux-native` | `d80eb32` | ELF closure, version/property checks, optional normalization; native x86_64 pending |
| C04 | `codex/mvp-c04-macos-native` | `ced7287` | Mach-O closure, unchanged/normalized relocation and strict signature checks |
| C05 | `codex/mvp-c05-builder-cli` | `e091fab` | CLI/config/process dispatch; initial Lua workflow and launch semantics |
| L01 | `codex/mvp-l01-lua-helpers` | `f78cdd5` | Separate exact 5.4/5.5 helpers, one installation |
| L02 | `codex/mvp-l02-lua-projects` | `8ee9e76` | Directory/rocks ingestion, source/resources/native handoff |
| L03 | `codex/mvp-l03-lua-native` | `9f00c96` | OS-loaded modules/secondary deps, protected C boundary; x86_64 pending |
| P00 | `codex/mvp-p00-python-bootstrap` | `45e69db` | Stock multi-minor bootstrap proof and provider recipe |
| P01 | `codex/mvp-p01-python-discovery` | `56e8df4` | Existing environments/PBS/uv, bounded safe probes, foreign inspection |
| P02 | `codex/mvp-p02-python-provider` | `7dab743` | Bundled/explicit-host stock subprocess and archived stdlib |
| P03 | `codex/mvp-p03-python-inventory` | `8d422c0` | Installed source/data/metadata/namespace and entry inventory |
| P04 | `codex/mvp-p04-python-native` | `2abc06d` | Stock extension lifecycle, C/C++/Rust/scientific/FFI corpus; x86_64 pending |
| P05 | `codex/mvp-p05-python-matrix` | `1b6bdc5` | Version/provider/copy-venv matrix; see receipts below |
| N00 | `codex/mvp-n00-node-probe` | `e98ecc1` | Public stock-hook/bridge/addon proof |
| N01 | `codex/mvp-n01-node-provider` | `40f439c` | Bounded capability probes, native-header preflight, bundled/host provider |
| N02 | `codex/mvp-n02-node-resolution` | `10ca7f5` | Indexed CJS/ESM resolution and stock cache semantics |
| N03 | `codex/mvp-n03-node-project` | `119f7b0` | npm/pnpm installed graph and lock provenance, no package manager |
| N04 | `codex/mvp-n04-node-resources` | `44e7ca9` | Bounded read-only fs subset, streams and safe aliases |
| N05 | `codex/mvp-n05-node-addons` | `112a062` | Existing Node-API addon/secondary closure across two majors |
| V01 | `codex/mvp-v01-portable-ci` | `dc8e659` | Pinned native-host CI matrix; hosted jobs configured, not run here |
| V02 | `codex/mvp-v02-relocated-harness` | `894ab21` | Shared offline/relocation/reference receipt protocol; x86_64 pending |
| R01 | `codex/mvp-r01-workflows` | `ddd8468` | Three CLI adapters, inspect/doctor/size/rebuild, installer and end-to-end cases |
| R02 | `codex/mvp-r02-extraction-signing` | `a2bff19` | Complete process-tree oracle and signing checks; Mac tracer/x86_64 pending |
| R03 | `codex/mvp-r03-hpc-costs` | `b725309` | Bounded buffered reader, measured 10,000-entry/32-rank harness and budgets |
| R04 | `codex/mvp-r04-docs` | `this branch` | Current user docs, compatibility/evidence ledger; M2 closure blocked by missing cells |

Use `git log BRANCH` for each original task commit and
`git log codex/mvp-r04-docs` for the integrated stack. Follow-up fixes stay on their
owning card branch before integration. The table records implementation, not 26
completed acceptance gates.

## Executed development cells

| Cell | Lua | Python | Node | Release observations |
| --- | --- | --- | --- | --- |
| macOS arm64 | 5.4.9/5.5.1 source/native/secondary/TLS/errors | PBS/uv 3.13.16, 3.14.5, 3.15.0b1; non-PBS 3.12.14 and framework 3.14.8 (3.12.12 also focused provider test) | Official 24.22.0/26.10.0 CJS/ESM/resources/Node-API | Offline sandbox and relocated read-only execution; strict ad-hoc verification; full tracer unavailable |
| GNU Linux arm64 | Both families source/native and extraction traces | PBS 3.13.16 file/module/console/native/abi3; non-PBS 3.14.8 source; local PBS archive routes | Official 24.22.0/26.10.0 CJS/ESM/resources/Node-API | Native Podman VM, network none, controlled uid/read-only tree, complete strace where receipted |
| GNU Linux x86_64 | Unperformed | Unperformed | Unperformed | Required native runner missing; CI jobs are not execution evidence |
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

The pinned portable baseline passed on macOS arm64 with actual compact CLI
execution required (`GLUE_REQUIRE_COMPACT_CLI=1`). Harness tests passed 22 checks,
including deliberate extraction violations and invalid/foreign receipt controls.
The Lua55 suite passed 90 tests and packaging passed 130, both with pinned
Clippy. Four additional CLI regressions passed after the final review fixes.
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

Node has sixteen final release V02 receipts: four cases per major per OS. All
eight Linux cases include full descendant traces and injected extraction
controls. Mac cases have offline execution and strict final signature checks under the selected development policy;
complete Mac tracing remains unavailable. The local index is
`/private/tmp/glue-node-final-summary.json`.

Python's final covering matrix includes Mac 3.12.14 source, 3.13.16 console,
3.14.5 uv source/native, 3.15.0b1 source and 3.14.8 non-PBS framework source.
Linux 3.13.16 ordinary copied-venv file/module/console, scientific/native and
cp311-abi3 cryptography runs pass complete V02/R02 traces; non-PBS 3.14.8 source
and local PBS archive variants are separately receipted. The raw locations are
`/private/tmp/glue-python-v02-*` and
`/private/tmp/glue-python-v02-linux-evidence/`. Failed preparatory runs remain
retained and do not count as acceptance. The final integration evidence
inventory selects only checked passing receipts and labels signing/tracing
checks separately.

Native hosted x86_64 acceptance and first performance observations are configured in
`.github/workflows/mvp-native.yml` using `scripts/ci-mvp-linux.sh`. It requires
24 exact acceptance cases, five 10,000-entry performance profiles at 1/32
ranks, enforced offline execution, full traces and negative controls. First
x86_64 budgets remain proposed until measured reports are reviewed and frozen. A configured job is not a passed cell; actual runner results will be
recorded after completion.

## Evidence retention and open gates

Raw outputs, binaries and traces remain outside Git. Hash inventories and local
locations will be recorded in the integration evidence README, following
[decision 0030](../decisions/0030-evidence-retention.md). Evidence release assets
have not been published; there is no fabricated `bundle.json` or remote durable
retention claim. Local files alone will not survive transfer of this repository.

Remaining M2 work requires a native Linux x86_64 runner and an approved macOS
process-tree tracer. Re-run the shared corpus, negative controls and budgets on
those hosts. Public release additionally needs Developer ID/notarization under
the chosen policy, and publication/verification of retained evidence assets.
Memory mode and later platform/language expansion remain in
[their separate roadmap](memory-roadmap.md).
