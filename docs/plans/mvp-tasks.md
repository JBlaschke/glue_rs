# MVP implementation queue

All tasks below are **pending**, planned against `5bb1ac4` on 15 October 2026.
This is a dispatchable backlog, not evidence of implementation. Product authority:
[PLAN.md](../../PLAN.md), [MVP contract](mvp-contract.md),
[decision 0035](../decisions/0035-mvp-delivery-and-runtime-scope.md).

## How to assign work to a simpler model

Give one task card at a time, the three documents above, and the exact upstream
commit. Do not ask an agent to “finish Python” or “implement the loader.” Tasks
with multiple checks may be split at the listed step boundary without changing
the contract. A missing dependency means wait for its interface, not invent it.

Use this assignment text:

> Implement TASK-ID from docs/plans/mvp-tasks.md on BASE-COMMIT. Read its
> prerequisites and the MVP contract first. Work only in the assigned area;
> propose shared-file changes to the integration owner. Preserve the existing
> fixture routes. Implement the specified product behavior, run the task's
> acceptance checks and relevant existing tests, and hand back the commit,
> exact commands/results and remaining limitations. Do not replace failing
> acceptance with an allowlist, rebuild a supplied module, extract at runtime,
> or claim an unexecuted OS/version passed. If blocked, return a minimal failing
> input and the exact missing capability; continue independent assigned work.

Each handoff contains: task ID/status, base/result commits, changed files, public
interface changes, tests actually run with target/runtime versions, one reproducible
CLI example, evidence location and blockers. Keep raw logs out of Git under
decision 0030. Do not claim completion from parser tests or synthetic worker output
when the card requires execution. No automatic merge or release publishing.

The integration owner alone edits root Cargo files, shared manifest types,
`glue-pack/src/lib.rs`, `glue-runner/src/main.rs`, README and current progress
summary during parallel work. Owners provide small integration patches when
necessary. Use feature branches/worktrees according to CONTRIBUTING. Avoid a
repository-wide refactor inside a language card. If these cards reveal a genuine
design gap, add a bounded decision with executable evidence rather than asking
another small model to redesign all providers.

## Dispatch order

| Wave | Tasks | Why these can run together |
| --- | --- | --- |
| 0 | C01, V01, L01, P00, N00 | Contract translation, existing CI, independent Lua helper/probe work |
| 1 | C02, C03, C04, P01, N01, V02 | After C01; honor extra P00/N00/L01 dependencies below |
| 2 | C05, L02, P02, P03, N02, N03 | Separate language modules; P02 also needs native scanners |
| 3 | L03, P04, P05, N04, N05, R01 | Integrate native and resource behavior; R01 starts with source paths |
| 4 | R02, R03, R04 | Release gates after integrated product tests |

Dependencies on each card override the wave summary. Small teams take the next
ready card. Start Node now alongside Python; do not keep extending Python-only
fixture profiles. Memory tasks are in [their own roadmap](memory-roadmap.md).

## Shared foundation

### C01 — Freeze implementable distribution contracts

- **Needs:** this plan. **Owns:** `crates/glue-format/src/manifest.rs`, its tests;
  integration owner coordinates all public type/export changes.
- **Do:** add explicit manifest revision/delivery mode and relative deployed
  payload records. Define runtime descriptor, dependency provider classes, launch
  spec, report/lock shapes and stable diagnostic codes from the contract. Separate
  runtime identity from fixture admission. Decide backward parsing explicitly.
- **Check:** old fixture manifests retain their semantics; new compact examples
  validate; absolute/escaping/duplicate payload paths, unsupported revisions,
  inconsistent runtime/target and memory/compact ambiguity reject. Round-trip
  one Lua, Python and Node descriptor without fixture IDs.
- **Done:** committed schema/examples and Rust APIs consumed by later cards.
  No runtime implementation or schema redesign in dependent cards.

### C02 — Write and inspect a complete compact distribution

- **Needs:** C01. **Owns:** new `crates/glue-pack/src/distribution.rs`, focused
  pack tests; format/resource changes only through C01 owner.
- **Do:** take a resolved inventory, stage archive plus sibling binaries, preserve
  required modes/internal symlinks, generate lock/report/notices and publish
  atomically. Exclude output/staging from input traversal. Do not duplicate native
  bytes in ZIP. Add size and deployed-file accounting. Replace fixture-sized
  application caps with documented bounded product limits/configuration; support
  R03's 10,000-entry input without removing decompression/allocation safeguards.
- **Check:** deterministic unsigned outputs, input/output overlap, interrupted
  build cleanup, existing-output refusal, path collisions, missing input, escaped
  symlink, relocatable manifest paths and accurate totals. Test two distinct
  source roots with identical relative content.
- **Done:** reusable builder callable by all adapters; no language-specific
  template preparation required.

### C03 — Collect Linux native dependencies for compact mode

- **Needs:** C01. **Owns:** new `crates/glue-pack/src/native/linux.rs` and scanner
  fixtures; coordinate reusable parser access with `glue-native` owner.
- **Do:** inspect ELF class/arch, DT_NEEDED, SONAME, search paths, symbol-version
  requirements and CPU/libc properties. Resolve supplied runtime/package roots
  and explicit host requirements. Preserve dependency-relative layout. Preview
  optional load-path normalization with original/output identities.
- **Check:** an ordinary prebuilt extension with a secondary library loads with
  the OS loader after relocation; missing edge, conflicting SONAME, wrong arch,
  absent glibc requirement and escaped search root diagnose. Compare metadata
  with readelf. Admit OS-supported TLS/unwind/GNU hash features without inheriting
  memory-parser restrictions. Do not execute images merely to inspect them.
- **Done:** deterministic closure API, normalization off by default. Test x86_64
  natively and arm64 in its cell; label any missing execution explicitly.

### C04 — Collect and relocate macOS native dependencies

- **Needs:** C01. **Owns:** new `crates/glue-pack/src/native/macos.rs` and tests.
- **Do:** inspect supported Mach-O slices, dylib/bundle types, load commands,
  deployment target, IDs, rpaths and system dependencies. Resolve loader-relative
  edges using the actual dependency chain. Preserve structure; preview required
  metadata edits and signing consequences. Do not add a custom mapper here.
- **Check:** prebuilt `.so`/dylib plus secondary dependency survives relocation
  using dyld. Missing/ambiguous dependency, wrong slice/OS floor and host-prefix
  leakage reject. Independently compare otool output; demonstrate unchanged-byte
  route and explicit normalized/re-signed route, with normalization denied by
  default. Verify final signatures rather than assuming edits preserved them.
- **Done:** macOS closure provider matching C03's contract. Public distribution
  identity/notarization verification remains R02, not silently ad-hoc success.

### C05 — Expose language builders and launch one runtime

- **Needs:** C01, C02 and a launch spec from L01/P00/N00. **Owns:** integration
  edits to `glue-runner/src/main.rs`, new dispatch/process modules, CLI tests.
- **Do:** implement proposed `build python|lua|node`, optional config and entry
  semantics while retaining low-level commands. Add compact `run`/`doctor`,
  executable-relative payload resolution, argv/stdin/out/err/exit/signal handling.
  Export adapter slots; do not reimplement ingestion inside the CLI.
- **Check:** spaces/non-ASCII paths, arbitrary cwd, missing sibling, incompatible
  runtime, unsupported memory mode, app exit failure, SIGINT/SIGTERM and streamed
  stdio. Demonstrate no shell interpolation and no payload recovery on run.
- **Done:** first one-command Lua build/run; Python/Node adapters plug in later.
  General IPC and mixed-language calls remain out of scope.

## Lua

### L01 — Package both Lua families as selectable helpers

- **Needs:** none. **Owns:**
  `glue-runtime-lua` provider/helper modules and fixtures; root build integration
  through its owner.
- **Do:** reuse current 5.4/5.5 builds and C error boundary. Produce separate
  helper executables with runtime/ABI descriptors and exact patch identities.
  A packaging installation must find either helper without requiring user Cargo
  feature switches. Only the chosen helper enters a distribution.
  Preserve the current manifest while C01 runs; hand descriptor integration to
  its owner after the helper mechanism is tested.
- **Check:** run existing source/resource fixture with each helper; wrong-version
  declaration rejects. Verify int64/float64 configuration and protected Lua errors.
  Do not claim one helper can host both runtimes simultaneously.
- **Done:** helper launch contract handed to C05; existing direct Lua routes pass.

### L02 — Build archives from Lua project directories

- **Needs:** C01, C02, L01. **Owns:** new `glue-pack/src/lua.rs`, fixture inputs,
  pack tests; integration patch for C05.
- **Do:** source/assets discovery, main.lua/config/explicit entry selection,
  installed rocks-tree mapping, safe path handling and native inventory handoff.
  Preserve module layout; do not run LuaRocks or compiler commands.
- **Check:** two unrelated project layouts, nested requires, dynamic declared
  imports, asset reads, exclusions reported, symlink escape and ambiguous entry.
  Test both families with identical source where compatible. Native input is
  inventoried rather than rejected as “source-only”; execution follows L03.
- **Done:** project-to-distribution command without hand-authored manifest/template.

### L03 — Run existing Lua native modules in compact mode

- **Needs:** C03, C04, L01, L02, C05. **Owns:** Lua native searcher/helper integration
  and `fixtures/mvp/lua-native` (new).
- **Do:** ordinary OS loader route, matching Lua API exports/runtime identity,
  native `require` and declared `package.loadlib`, dependency handles and lifetime.
  Keep longjmp/error containment inside C-owned protected calls.
- **Check:** existing module plus secondary library for each Lua family, repeated
  imports, constructor once, failed initialization, missing export, callback/error
  and 5.4/5.5 mismatch. Execute on Linux x86_64, Linux arm64 and macOS arm64.
  Independently prepared fixture libraries are allowed; the packager never builds
  or substitutes them. Hash input native files before/after packaging.
- **Done:** same build/run UX for native and source-only Lua projects.

## Python

### P00 — Prove stock multi-version Python bootstrap

- **Needs:** none; spike only. **Owns:** new `spikes/python-compact` and its notes.
- **Do:** assemble at build time a selected interpreter, required binaries,
  archived stdlib and bounded glue bootstrap. Run isolated without the original
  installation. First test 3.13 and a newer minor, on Mac and Linux. Exercise PBS
  and identify a feasible non-PBS layout. Prefer subprocess startup, not a new
  version-specific C boundary.
- **Check:** encodings, imports, metadata, math/ssl, source resource and one native
  stdlib module from relocated read-only output. Original runtime inaccessible,
  empty cwd, no Python on PATH, no PYTHONHOME fallback or cache writes. Record any
  unavoidable loose bootstrap files and their count. Observe Python version
  differences in prefix discovery rather than assuming zipimport solves startup.
- **Done:** executable recipe/launch descriptor and evidence for P02. If a supplied
  installation cannot relocate unchanged, report exact metadata edits needed;
  do not quietly replace it with a catalog runtime.

### P01 — Discover an environment and arbitrary compatible runtime

- **Needs:** C01. **Owns:** new `glue-pack/src/python/discovery.rs` (or equivalent
  submodule without replacing the legacy python.rs route) and focused fixtures.
- **Do:** contract's safe metadata probe, pyvenv.cfg/base-runtime resolution,
  version/ABI/stdlib/site inventory, local PBS input inspection, uv tree support,
  entry-point metadata and explicit overrides. Reuse PBS parsing, separate pins
  used in regression tests from production admission.
- **Check:** ordinary venv and uv env; stock/PBS full/install-only/stripped/tree;
  spaces and symlinks; no application import or `.pth` execution; missing base
  runtime; mismatch/free-threaded/debug diagnostics; at least three minor versions.
  Inspect foreign-target metadata without executing it. New runtime hashes work
  without source edits. Bound probe output/time and malformed metadata handling.
- **Done:** resolved descriptor/inventory, no templates or python3.13 path constant
  in the general route. No environment creation or package installation.

### P02 — Assemble the compact Python provider

- **Needs:** P00, P01, C02, C03, C04. **Owns:** new Python compact provider module,
  bootstrap files and provider tests; reuse legacy runtime code where appropriate.
- **Do:** turn discovered runtime into the verified layout established by P00.
  Archive stdlib sources, retain necessary native stdlib/dependencies, stage
  bounded bootstrap, disable caches and launch isolated. Support explicit host
  provider separately without using it to pass bundled acceptance.
- **Check:** startup/stdlib corpus with chosen runtime on each cell, no original
  prefix or user-site access, missing library/version mismatch before app execution,
  no per-startup scan of thousands of source files. No embedding-header requirement
  for the executable-provider route. Input/output hashes cover transformations.
- **Done:** bundled Python launches from its distribution, with exact version
  retained; no application package specialization yet.

### P03 — Package installed Python sources, data and metadata

- **Needs:** C02, P01; execution tests additionally P02. **Owns:** Python inventory/
  import/resource modules and `fixtures/mvp/python-env` (new).
- **Do:** generalize existing source/metadata importer and installed-package
  adapter to resolved environments, entries/modules/console scripts, namespace
  packages, resources and RECORD provenance. Preserve pip-containing normal envs.
  Implement declared path-only `.pth`; diagnose editables/executable hooks.
- **Check:** two ordinary envs including uv, pure-Python package + plugin metadata,
  namespace packages, console script, archive resource stream, cache-disabled
  execution and no `as_file` extraction. Native files hand off to P04, not silent
  exclusion. Explicit pruning reports omissions; ordinary package data survives.
- **Done:** no manual provider-template/app-subtree work for source packages.

### P04 — Package and load existing Python native extensions

- **Needs:** C03, C04, P02, P03. **Owns:** compact native import/FFI mapping and
  native environment fixtures; preserve legacy extension-profile tests.
- **Do:** collect installed extension suffixes and wheel support libraries;
  load via stock ExtensionFileLoader preserving module spec, caching and PEP 489
  behavior. Map declared ctypes paths and one tested CFFI loading route. Keep
  runtime identity consistent and do not fabricate PyInit-only lifecycle handling.
- **Check:** prebuilt C extension, C++ binding with a translated exception, Rust
  extension, secondary library, TLS/threads, initialization error and repeat
  imports. Include a dependency-heavy scientific package. Compare operations to
  the source env, rename the project and change native bytes without product
  allowlist edits. Wrong Python ABI/arch and missing library reject. No recompiles.
- **Done:** same env command works for native wheels on all MVP cells; limitations
  identify actual ABI/path capabilities rather than fixture membership.

### P05 — Establish Python version/provider compatibility evidence

- **Needs:** P02, P03, P04 and V02. **Owns:** matrix fixture/configuration and receipts.
- **Do:** run 3.12, 3.13 and at least one newer minor across chosen providers;
  include PBS and non-PBS, uv/ordinary env, full/install-only/stripped input routes.
  Use a covering matrix, not every Cartesian combination. Record exact versions.
- **Check:** source corpus on each version; native corpus using independently
  compatible binaries for at least 3.13 and a newer minor; abi3 admission where
  valid; incompatible version/ABI cannot be overridden by a flag. Demonstrate an
  additional patch runtime with a new digest works without recompiling glue.
- **Done:** compatibility table derived from actual runs, and specific gaps for
  untested variants. No claim that all future CPython ABIs are proven.

## Node

### N00 — Prove stock Node archive hooks and choose the provider

- **Needs:** none; spike only. **Owns:** new `spikes/node-archive` and short decision.
- **Do:** on two modern major lines, feed archived CJS/ESM source through public
  synchronous hooks, read one resource, and load a pre-existing deployed Node-API
  addon with a secondary dependency. Prototype glue's Rust resource bridge; reuse
  the archive parser. Run on Linux and Mac, with caches disabled.
- **Check:** package exports, relative import, dynamic import, CJS cache identity,
  JSON and native addon; source tree inaccessible after build. Record hooks/ABI
  availability. A small manually assembled archive is sufficient for the probe.
- **Done:** executable Node route plus capabilities handed to N01/N02. If blocked,
  provide the specific hook limitation. Evaluate Deno only against this same
  corpus, including existing native modules and zero extraction; no assumption
  that compilation or a new runtime makes the limitation disappear.
  Publish the small logical module-index schema here for both N02 and N03, so
  those tasks can implement against the same contract independently.

### N01 — Bundle stock Node and the archive-reader bridge

- **Needs:** C01, C02, C03, C04, N00. **Owns:** new
  `crates/glue-runtime-node` provider/bridge/bootstrap; root Cargo via integrator.
- **Do:** discover executable/root, exact version/target/addon capabilities,
  collect runtime closure, ship Node-API bridge exposing bounded verified resource
  operations, bootstrap before app loading and disable compile caches. Keep
  archive/resource handles alive for the process lifetime.
- **Check:** bridge byte/error/ownership boundaries, repeated opens, malformed
  archive, wrong bridge/runtime ABI, no source-tree/runtime-prefix fallback.
  Same bridge API on two runtime majors; no libnode installation required.
- **Done:** stock runtime launch provider for C05; no embedding rewrite.

### N02 — Implement archive module resolution

- **Needs:** C01, N00, N01. **Owns:** Node resolver/bootstrap and module fixtures.
- **Do:** CJS/ESM hooks, package type, exports/imports/conditions, relative/bare
  imports, JSON, dynamic imports, distinct dependency versions and module caches.
  Generate/use a logical dependency index; use stock runtime for built-ins.
- **Check:** compare the same fixture graph under ordinary Node and glue:
  cycles, repeated imports, dual-mode packages, wildcard/conditional exports,
  missing/blocked exports and duplicate versions. Test both selected majors.
  Do not resolve missing modules from cwd/global node_modules.
- **Done:** general archive imports independent of fixture names. fs resources
  are N04; native execution is N05, not faked by returning stub exports.

### N03 — Ingest a Node project without an installation step

- **Needs:** C01, C02, N00. **Owns:** new `glue-pack/src/node.rs`, input tests;
  integrate with N02's agreed index schema.
- **Do:** package.json/entry/config discovery, installed npm/pnpm graph and safe
  internal links, runtime override, assets and lock provenance. Preserve names
  and multiple dependency versions. Inventory native addons/dependencies for N05.
- **Check:** one npm and one pnpm project; CJS and ESM entry; prebuilt TS output;
  package asset; missing deps, escaped symlink, ambiguous entry and unsupported
  PnP diagnosis. Install/postinstall/build scripts must not execute. Existing
  dependency bytes are inputs, not a trigger to invoke npm/node-gyp.
- **Done:** high-level build adapter; standalone low-level manifests unnecessary.

### N04 — Support archive resources through Node APIs

- **Needs:** N01, N02. **Owns:** resource facade and resource-specific tests.
- **Do:** implement the fs subset in the contract for virtual paths plus explicit
  glue resource APIs. Keep ordinary host-file behavior outside the virtual tree.
- **Check:** sync/callback/promises reads, buffers/encodings, stat/readdir/exists,
  streaming backpressure/close/errors, path traversal and attempted writes/fd-only
  operations. Test imports using node:fs and fs/promises. No temporary materialized
  resource even for unsupported requests.
- **Done:** documented working subset with real-package asset tests, not a promise
  that arbitrary native filesystem calls see the archive.

### N05 — Load existing Node-API addons

- **Needs:** C03, C04, N01, N02, N03. **Owns:** addon routing and native fixtures.
- **Do:** resolve archived logical addon names to declared deployed images;
  use stock Node loading, retain dependency layout and check addon/runtime ABI.
  No recompilation, temporary .node file or package postinstall invocation.
- **Check:** real Node-API addon plus secondary lib, normal resolver paths,
  repeated load, callback/error/thread use and wrong ABI/target. Prove same
  compatible Node-API binary across selected Node majors; diagnose V8/NAN inputs
  separately. Run Linux/Mac; use original Node as behavior reference.
- **Done:** native project works through the same CLI as source-only projects.

## Validation and release integration

### V01 — Add portable CI without widening implementation scope

- **Needs:** none. **Owns:** new CI configuration and scripts for existing tests.
- **Do:** use pinned Rust/toolchain/dependencies; run formatting, existing workspace
  tests and Clippy, plus packaging-feature tests where supported. Add explicit
  Lua54/Lua55 jobs rather than incompatible all-features combinations.
- **Check:** jobs invoke actual pinned tools; target-only skips are visible.
  Do not download huge evidence assets or require signing secrets for portable
  tests. No PR marked green solely because every runtime test was skipped.
- **Done:** automated baseline checks and documented runner gaps.

### V02 — Build the relocated/offline target harness

- **Needs:** C01, V01. **Owns:** new `fixtures/mvp` harness and target scripts.
- **Do:** establish real Linux x86_64, Linux arm64 and macOS arm64 execution cells.
  Provide one shared run/receipt protocol, reference-runtime comparison, relocated
  immutable payload, inaccessible input prefix, unrelated cwd and controlled env.
  No language tools on execution PATH. Record target/kernel/libc/runtime versions.
- **Check:** harness deliberately detects input-prefix fallback, cache write,
  missing native dependency, wrong exit status and skipped target execution.
  Cross-compilation is not a passing native run. Reuse existing trace policy
  machinery when applicable, without inheriting fixture-specific output hashes.
- **Done:** language tasks can supply cases without designing their own harness.

### R01 — Integrate the three user workflows

- **Needs:** C05, L02, P02/P03, N01/N02/N03; native completion also L03/P04/N04/N05.
  **Owns:** integration-only CLI exports/config and end-to-end product cases.
- **Do:** exercise every example in PLAN with ordinary project inputs. Add
  `inspect`, `doctor` and `explain-size` output, stable JSON errors, one-command
  rebuild using recorded config/lock and runtime selection. Publish M1 preview
  status separately while native tasks finish.
- **Check:** build with no hand-written inventory/template, copy output to a
  different machine/cell of matching target, run with its included launcher.
  Broken deps/version/entry/config fail before publication. Neither build nor run
  automatically installs or compiles user dependencies. Missing memory support
  errors rather than changing delivery mode.
- **Done:** Lua54/Lua55, Python env and Node project workflows pass together.

### R02 — Prove no extraction and final macOS deployment

- **Needs:** R01 native completion, P05, V02. **Owns:** trace/signing harness and
  evidence receipts; no loader feature expansion.
- **Do:** trace complete executions and descendants on each MVP cell, observing
  successful and failed payload writes and create/unlink pairs. Separate legitimate
  app output. Test final macOS layout under the intended signed distribution policy
  after all modifications; record ad-hoc vs Developer ID/notarization accurately.
- **Check:** caches disabled, unusable TMPDIR/HOME, read-only tree, offline network,
  modified/missing payload rejection, app error and denied-write paths. Inject
  synthetic extraction violations to test the trace oracle. A directory snapshot
  or unavailable tracer is not a pass. Use approved test hosts for signing/tracing.
- **Done:** exact supported cells and deployment policy with evidence. Missing
  signing identity/tracer is an external evidence gap, not permission to claim it.

### R03 — Measure and bound HPC deployment costs

- **Needs:** R01 native completion, V02. **Owns:** benchmark harness, size budgets
  and reports; coordinate performance fixes with owning cards.
- **Do:** measure empty runtime, source-heavy Lua/Python/Node, and native-heavy
  app. Record deployed file count, bytes, metadata/read calls, cold/warm startup,
  RSS/PSS where available and FDs, at 1 and 32 ranks on a recorded host. Select
  explicit numeric regression budgets from results and check them into CI config.
- **Check:** adding 10,000 source/resource entries does not add 10,000 deployment
  files or startup OS metadata calls; reads remain archive-based. Binaries scale
  with the declared native closure, not source count. Trace cost of hashing and
  dependency search too. Default pruning must not remove required packages.
- **Done:** frozen budgets and honest compact-mode limitations; no fabricated
  universal startup time or “zero linker storm” claim. Shared memfd optimization
  belongs to the later memory roadmap.

### R04 — Close M2 and write actual user documentation

- **Needs:** R01, R02, R03 and all required language cards. **Owns:** README,
  progress summary and release compatibility table via integration owner.
- **Do:** replace proposed commands with executed examples; document inputs,
  exact tested versions/targets, distribution unit, host requirements, resource
  API limits, unsupported cases and extending versions without catalog pins.
- **Check:** a fresh checkout/operator follows all three workflows with only
  documented build prerequisites. Compare each M2 requirement with a receipt;
  mark unexecuted cells blocked. Do not equate source preview with native MVP.
- **Done:** all required cells/corpus pass, finite known limitations, next work
  selected from memory/expansion roadmap. No Windows/BSD or Julia release claim.

## Acceptance command contract

V02 implements the following **planned** harness interface. These commands do
not exist at the planning baseline. Keep a single interface rather than letting
each agent invent an incompatible script. Earlier probes provide their own
checked-in run script until V02 is available.

```sh
scripts/run-mvp.sh --case CASE --target TARGET --output NEW_DIRECTORY
scripts/check-mvp-results.py NEW_DIRECTORY/receipt.json
```

Targets are explicit `x86_64-unknown-linux-gnu`, `aarch64-unknown-linux-gnu` and
`aarch64-apple-darwin`. Refuse a foreign execution target. The receipt includes
case, commit, target, runtime/artifact identities, exact commands, exit/stdout/
stderr, checks performed and evidence paths; skipped checks are not successful.
The checker compares observable semantics and required checks, not a single
known application/archive hash. Native inputs are prepared independently of the
packager; their byte identities prove that packaging did not recompile them.

| Case | Owner | Required observation |
| --- | --- | --- |
| `lua54-project`, `lua55-project` | L02 | nested import + resource + argv/exit from relocated archive |
| `lua54-native`, `lua55-native` | L03 | existing native module + secondary library + mismatch rejection |
| `python-runtime` | P02 | selected version, encodings/math/ssl with original runtime absent |
| `python-env`, `python-uv-env` | P03 | module/console entry, namespaces, metadata and resources |
| `python-native` | P04 | C/C++/Rust corpus, secondary deps and FFI without module rebuild |
| `python-versions` | P05 | required minor/provider matrix, additional digest without glue edit |
| `node-cjs`, `node-esm` | N02/N03 | same dependency resolution/results as selected stock runtime |
| `node-resources` | N04 | advertised fs subset, streaming and unsupported-operation errors |
| `node-native` | N05 | prebuilt Node-API addon/dependency across two runtime majors |
| `product-cli` | R01 | proposed commands, self-contained deployment unit, predictable errors |
| `no-extraction` | R02 | full process-tree trace and failing injected-violation controls |
| `hpc-cost` | R03 | measured baseline, 10,000-entry scaling check and frozen numeric budgets |

For each implementation change run the focused crate/feature tests and the
CONTRIBUTING checks required for integration. Retest affected native cells when
loader/bootstrap behavior changes. Do not rerun every large historical evidence
bundle after an unrelated documentation edit.
