# glue_rs project plan

Revised 15 October 2026 after the project-owner review. This is the current
product direction, not a claim that the proposed commands already work.
Implementation baseline: `5bb1ac4`. This supersedes the 8 October plan's
four-platform first release, mandatory mixed-language workers, and exact-runtime
fixture admission as a route to general packaging. Historical G0–G6/A0–A10
references describe that earlier plan; preserve their evidence.

## Outcome and constraints

Given an existing Python environment, a Lua project directory, or an installed
Node project, build a relocatable distribution containing a glue archive. Copy
it to another machine with the same OS/architecture and compatible OS/CPU ABI,
then run offline without an installed language toolchain. Application code,
ordinary resources and Python's source stdlib stay archived. Existing compiled
modules and their dependencies travel with the application without recompilation.

- “Static” means self-contained language distribution. A compact tree of shared
  libraries is acceptable; fully static OS linkage is not required. Apple system
  libraries/frameworks may remain system dependencies.
- No runtime payload extraction: no temporary files later unlinked, cache
  extraction, RAM-disk mounts or FUSE substitutes. Build-time layout creation and
  deployment before execution are allowed. Application output is separate.
- Accept bring-your-own runtimes and compiled libraries. Input hashes identify
  supplied bytes; they are not a catalog of approved packages or versions.
- Preserve input bytes by default. Necessary load-path normalization is an
  explicit build option, reported with original/result identities and signing
  consequences. Never automatically recompile user modules.
- No runtime installation, compilation, downloading or silent host fallback.
  Host-runtime provisioning is a separately selected mode.
- Native compatibility depends on interfaces, binary features and dependencies,
  not source language. C, C++, Rust/PyO3, pybind11 and nanobind are in scope.
  C interfaces do not eliminate TLS, unwinding or runtime requirements.
- Archived Objective-C/Swift runtime registration is excluded from the initial
  custom memory loader. Ordinary OS-loaded Apple frameworks remain usable.
- Later Julia support accepts complete prebuilt PackageCompiler `create_library`
  bundles with C-callable exports, matching Julia runtime, system image and
  artifacts. General Julia project compilation is out of scope.

Linux and macOS come first. Establish GNU Linux x86_64 and macOS arm64 product
acceptance while retaining GNU Linux arm64 coverage. macOS x86_64 follows as a
separate cell. Windows and BSD wait until Linux/macOS feature completion. Same
architecture alone does not guarantee compatible libc, OS or CPU requirements.

## Delivery modes

| Mode | Builder output | Execution | Priority |
| --- | --- | --- | --- |
| `compact` | Launcher, app archive, selected runtime/helpers and native closure | Normal OS loader for deployed binaries; archive import/resource adapters | Native-capable MVP |
| `memory` | Launcher plus archive; later an optional combined executable | Archived native bytes loaded without filesystem payload creation | Subsequent platform gates |

Both modes prohibit runtime extraction. In compact mode the archive references
adjacent immutable files: copying the archive alone is insufficient. The builder
creates the complete deployment unit; the launcher never restores missing files.
A transport tarball may be unpacked by deployment tooling before execution.

Compact mode is the shortest useful product path under the user's allowance for
a small native tree. It avoids making a custom dyld-compatible loader a
prerequisite for every packaging improvement. It still performs native-library
I/O and does not solve fully filesystem-free execution. Memory mode remains a
real deliverable for that requirement; it must never silently fall back to files.

## Target workflow

These are proposed commands, not instructions for the current executable.
The [MVP contract](docs/plans/mvp-contract.md) specifies their semantics.

```sh
glue build python --env .venv --entry main.py --output dist/my-python-app

# uv-created environments use the same interface; uv is not needed at runtime.
glue build python --env /work/project/.venv --project /work/project \
  --module my_app --output dist/my-python-app

# Supplied runtime must match the environment's package/native ABI.
glue build python --env .venv --runtime /downloads/python-install_only.tar.gz \
  --entry main.py --output dist/my-python-app

glue build lua ./lua-project --lua 5.4 --entry main.lua --output dist/my-lua-app
glue build lua ./lua-project --lua 5.5 --entry main.lua --output dist/my-lua55-app

glue build node ./node-project --node /opt/node/bin/node \
  --entry dist/main.js --output dist/my-node-app

glue inspect dist/my-python-app/app.glue
glue doctor dist/my-python-app/app.glue
glue run dist/my-python-app/app.glue -- argument
./dist/my-python-app/glue run ./dist/my-python-app/app.glue -- argument
```

Normal inputs need neither a hand-written inventory nor manually generated
provider templates. Optional `glue.toml` stores overrides. Existing dependencies
are consumed as supplied. Missing environments or `node_modules` cause useful
build errors, not implicit package-manager execution. Installation convenience
can be added explicitly later.

## Runtime/version policy

| Language | Product policy | First acceptance matrix |
| --- | --- | --- |
| Lua | Official 5.4 and 5.5; extensible to later versions. No 5.1–5.3/LuaJIT work. Numeric ABI remains explicit. | Both families, native module and secondary library, all MVP cells |
| Python | User-selectable modern CPython, including PBS full/install-only/stripped and uv-managed trees. Initial design range 3.11+, no hardcoded upper-version ceiling. | 3.13, an older modern minor (3.12), and a newer minor (3.14 or 3.15); PBS plus a non-PBS installation; conventional GIL first |
| Node | User-selectable stock Node with required loading capabilities, starting with maintained 22.x/24.x/26.x lines. | At least two major lines including LTS and a newer line; CJS, ESM and Node-API |

The matrix records evidence, not a runtime catalog. Additional compatible
versions must pass capability/ABI checks without adding a hash to Rust code.
A new ABI may require adapter work; do not promise unknown future versions work
untested. Free-threaded/debug Python and legacy V8/NAN addons initially report
specific unsupported capabilities. Changing the runtime cannot retarget existing
binary wheels; no automatic rebuilds.

Use stock interpreter subprocesses for compact Python and Node, bundling their
executables/dependencies and bootstrapping archive imports. This avoids coupling
the generic launcher to CPython structure layouts or Node embedding ABI changes.
Retain the existing embedded Python work for memory mode. Lua uses version-specific
linked helpers shipped with glue; package only the selected helper. These internal
runtime processes are not the deferred cross-language RPC feature.

Node is the first JavaScript route. N00 must prove stock Node module hooks and an
archive reader before product implementation. Deno is an allowed substitution
only if the same Node-project/native-addon corpus passes and a measured spike
shows less work. Do not implement both or assume `deno compile` solves native
loading. Public synchronous Node hooks begin at 22.15.0/23.5.0; probe the selected
runtime rather than assuming all modern releases behave identically.
[Node module hooks](https://nodejs.org/api/module.html#moduleregisterhooksoptions)

## Baseline: reuse rather than restart

| Area | Existing work | Remaining product work |
| --- | --- | --- |
| Archive/resources | Verified bounded ZIP, deterministic explicit builder, resource APIs | Distribution-relative payloads, runtime descriptors, high-level adapters |
| Lua | Linked 5.4.9/5.5.1 source execution on Mac/Linux arm64; controlled Linux native closure | Folder ingestion, convenient version choice, ordinary-loader native modules on Mac/Linux, x86_64 |
| Python | Pinned 3.13.16/PBS experiments; source/metadata packaging; Linux native fixtures; macOS host startup | Env discovery, multiple versions, compact full startup, arbitrary compatible native inputs |
| Native | Linux memfd, tiny signed Mach-O spike, real-wheel static survey (0033) | Build-time closure collection and compact OS loading; memory features separately |
| Node | Manifest concepts; no adapter | Runtime provider, source/resources/native integration and CLI |
| IPC | Synthetic codec/ledger | Preserve; not an MVP gate |

`build-python` still needs templates, assumes 3.13 layouts and rejects native
files. Several native profiles admit exact fixtures. The macOS route proves
controlled startup, not general packaging. Historical host startup also reads
thousands of stdlib files per process. None of these limitations should be
replicated in the general product path.

## Milestones

| Gate | Deliverable | Completion requirement |
| --- | --- | --- |
| M0 | Shared contracts, inventory/layout support, platform CI, Python/Node bootstrap proofs | Executable probes settle provider choices; no user-library rebuild |
| M1 | Source preview for Lua, Python and Node through simple build commands | Relocated offline runs on Linux x86_64/macOS arm64, both Lua families and version diversity |
| M2 | Native-capable compact MVP | M1 plus existing native modules/deps, all MVP cells, no-extraction traces, diagnostics and fixed cost budgets |
| M3 | Memory mode | Separate Linux and macOS gates for real runtime/native closure, TLS/unwind and signing |
| M4 | Expansion | Broader compatibility, Julia bundles, single executable, optional mixed-language calls; Windows/BSD after Linux/macOS completion |

M1 is a preview, not the requested MVP. M2 requires Lua, Python **and Node**;
there is no indefinite “Python before Node” gate. Keep Linux arm64 regressions
while establishing Linux x86_64 early. Verify final macOS layouts under the
intended signing policy; ad-hoc signing is not Developer ID/notarization evidence.

## Assignment and acceptance

[The task queue](docs/plans/mvp-tasks.md) supplies IDs, dependencies, ownership,
concrete edits and tests for small-model assignments. First dispatch: C01, V01,
L01, P00 and N00. Serialize shared-file changes through the integration owner.
This document plans the work; it does not start agents or create chats.

After contracts land, Lua, Python and Node proceed independently. Every task
must add reusable behavior and executable checks, not another exact app-ID
registry. Keep input bounds and integrity checks while replacing fixture
membership with capability checks. A blocked task returns a minimal reproduction
and the precise missing contract/platform capability; it does not relax the gate.

Measure deployed files/directories, archive/runtime/native bytes, startup
open/stat/read counts, time, memory and descriptors. Source-file count must not
produce equivalent filesystem metadata work. Freeze numeric budgets from measured
baselines before M2. Test multi-rank startup as well as one process; per-rank
memory and I/O can matter more than archive size.

Run the final distribution after build inputs become inaccessible, under a new
path with spaces/non-ASCII, offline, with no language tools on PATH, unrelated
cwd, read-only payloads and unusable temp/cache directories. Trace descendants,
failed write attempts and create/unlink pairs. Snapshot equality is insufficient.
Follow decision 0030 for large evidence; do not replay/publish every historical
trace for unrelated localized changes.

## Working documents

- [MVP contract and input semantics](docs/plans/mvp-contract.md)
- [Task queue and model handoff protocol](docs/plans/mvp-tasks.md)
- [Memory loading and later features](docs/plans/memory-roadmap.md)
- [Decision 0035](docs/decisions/0035-mvp-delivery-and-runtime-scope.md)
- [Implementation history](docs/progress.md) and [existing fixtures](docs/fixtures.md)
