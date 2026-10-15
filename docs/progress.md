# Implementation progress

## Compact MVP implementation — 15 October 2026

The 26 cards now have separate `codex/mvp-*` feature branches. The integrated
review stack is `codex/mvp-r04-docs`; `main` remains unchanged at `6b49cc5`.
[The task/compatibility ledger](plans/mvp-implementation.md) records all branches,
executed target/runtime cells, commands and open evidence. No milestone merge or
release publication was performed.

Implemented: schema-one compact distributions, deterministic atomic builder,
ELF/Mach-O closure and optional normalization, Lua54/55 helpers/projects/native
modules, stock Python discovery/environment/provider/native paths, stock Node
CJS/ESM/resources/Node-API, common CLI/config/rebuild, pinned portable CI, shared
relocated/offline execution, complete Linux extraction oracle and performance harness.
Historical schema-zero commands and memory experiments remain separate.

The owner chose ad-hoc signing for macOS development acceptance; Developer ID and
notarization are prerequisites for public binary releases. Current development
execution covers macOS arm64 and native Linux arm64. Hosted native Linux x86_64
ran all 24 applications successfully but awaits acceptance rerun after harness
fixes. Complete macOS process-tree tracing is blocked by SIP on the current host,
including after native administrator authentication. M1/M2 remain open: no
missing execution is replaced with a cross-build, snapshot or skipped test.

User instructions and installed tools are in [README](../README.md) and
[the compact CLI guide](compact-cli.md). Test results, exact runtime versions,
local evidence locations and host-scoped numeric performance budgets are linked
from the acceptance ledger. Raw logs/binaries/traces stay outside Git under
[decision 0030](decisions/0030-evidence-retention.md); publication remains pending.

## Historical implementation record

The earlier feature work and evidence were merged into `main` at `6afed9a`.
Further implementation continues on separate feature branches.

| Step | Branch | State | Evidence |
| --- | --- | --- | --- |
| A0 experimental contracts and Rust workspace | `codex/a0-contracts` / `96e188b` | Implemented | 20 contract tests on macOS and Linux arm64 / Rust 1.88.0; format and Clippy clean on macOS |
| A4 archive/resource foundation | `codex/a4-archive-resources` / `c4b307f` (stacked on A0) | Implemented | 56 tests on macOS and Linux arm64; deterministic ZIP64, corrupt/unsupported input rejection and bounded resources |
| Packaging/inspection CLI scaffold | `codex/packaging-cli` / `4581386` (stacked on A4) | Implemented | 76 tests on macOS and Linux arm64; explicit-inventory builder and read-only CLI commands; format/Clippy clean |
| A3 Linux memfd fixture | `codex/a3-linux-memfd-probe` / `447a339` (stacked on CLI) | Controlled spike | 80 Rust tests on macOS/Linux arm64, 15 trace-policy tests; Clippy clean on both; native ordinary-loader comparison and full syscall checks pass |
| A6 linked Lua 5.4 source slice | `codex/a6-lua-linked-execution` / `03303d7` | Experimental implementation | macOS arm64 CLI fixture builds, reports readiness and prints the expected result; 111 Rust tests and workspace Clippy pass; Linux execution/trace evidence pending at this baseline |
| A6 Lua 5.5 compiled profile | `codex/a6-lua55-profile` / `cb88d7d` (stacked on `03303d7`) | Experimental implementation | Separate exact Lua 5.4.9/5.5.1 compiled profiles; macOS arm64 CLI execution and opposite-version rejection pass |
| A6 linked Lua Linux validation | `codex/a6-lua-linux-validation` / `8b6eb1f` (stacked on `cb88d7d`; evidence bundle follows) | Controlled observation | macOS/Linux arm64: 118/119 Rust tests for `lua54`/`lua55`, all-target Clippy clean for both; both relocated Linux profiles exit 0 with exact output and full trace checks; 27 Python policy tests pass |
| A6 C-owned Lua error boundary | `codex/a6-lua-c-boundary` / `ee7c9d3` (from merged `db2c271`) | Experimental implementation | macOS/Linux arm64: 142/143 Rust tests for `lua54`/`lua55`, Clippy clean for both; 50/51 optimized macOS boundary tests; both relocated Linux fixtures pass exact output and full no-extraction trace checks |
| A5/A6 Linux native Lua closure | `codex/a6-linux-native-lua` / `3a24833`, fixture cleanup `fb61e5e` (from merged `7853282`) | Experimental implementation; controlled observation | Mac/Linux source workspaces: 181/182 tests; GNU Linux native workspaces: 178/179; 37 portable native tests and 54 Python policy tests; Clippy clean for all profiles; both Lua versions match ordinary loading and pass complete two-memfd/no-payload-write traces; twelve ELF rejection traces pass before any memfd attempt |
| A1 signed macOS arm64 Mach-O probe | `codex/a1-macos-macho-probe` / `346b2f0` (from merged `a596305`) | Controlled signed observation; acceptance evidence incomplete | 31 portable/optimized parser tests; 212/213 source workspace tests for Lua 5.4/5.5 and Clippy on Mac/Linux; ad-hoc hardened-runtime/allow-jit debug and optimized launchers match ordinary loading; fourteen native rejections, four signing controls and two memory-policy controls pass; full trace and distribution signing remain open |
| A7/A10 pinned stock PBS inputs | `codex/a7-pbs-artifact-inspection` / `886a415` (from merged `1425d6d`) | Experimental build-time inspection; controlled observation | Mac/Linux: 268/269 source workspace tests, Clippy, 56 optimized inspector tests; 71 Python policy tests; byte-identical inventories of independently pinned stock PBS inputs and exact 4,526-entry install-only projection; full inspector trace passes |
| A7 stock PBS frozen startup | `codex/a7-linux-pbs-bootstrap` / `30a1526` (from merged `8b56f7c`; evidence bundle follows) | Experimental bootstrap fixture; controlled GNU Linux arm64 observation | Mac/Linux: 291/292 source workspace tests and Clippy; 64 inspector tests, 15 portable bundle/profile tests and 16 GNU opt-in release tests; 89 Python policy tests; unchanged stock libpython starts with frozen encodings and built-in math/_ssl; baseline output agrees and all four complete traces pass |
| A7 explicit host Python startup | `codex/a7-linux-host-python` / `a50ae86` (from merged `06b92ea`; evidence bundle follows) | Experimental host fixture; controlled GNU Linux arm64 observation | Mac/Linux: 308/309 source workspace tests and Clippy; 32 portable bootstrap/host tests and 34 GNU opt-in release tests; 112 Python policy tests; all eight clean host traces and four frozen-bootstrap regression traces pass |
| A7 Python archive source/resources | `codex/a7-python-archive-imports` / `94da8de` (from merged `29b3f76`; evidence bundle follows) | Experimental bundled source/resource adapter; controlled GNU Linux arm64 observation | Mac/Linux: 316/317 source workspace tests and Clippy; 40 portable Python tests and 45 GNU opt-in release tests; 141 Python policy tests and 16 importer protocol tests; all three clean import traces plus four frozen/eight installed-host startup regressions pass |
| A7 host Python archive source/resources | `codex/a7-host-python-archive-imports` / `9aababa` (from merged `f99bb51`; evidence bundle follows) | Experimental host source/resource adapter; controlled GNU Linux arm64 observation | Mac/Linux 327/328 workspace tests, Clippy, 51 portable/56 GNU Python tests; 161 trace-policy and 16 importer protocol tests; seven host-import and fifteen prior regression traces pass |
| A7 registered Python native initializers | `codex/a7-python-extension-init-bridge` / `b784c99` (from merged `a50b654`; evidence bundle follows) | Experimental registered-initializer profile; controlled GNU Linux arm64 observation | Mac/Linux 338/339 workspace tests and Clippy for Lua 5.4/5.5; 59 portable/65 GNU Python tests; 191 policy and 16 importer protocol tests; all eleven native and twenty-two prior regression traces pass; 37 hostile trace edits reject |
| A7 controlled Python product route | `codex/a7-python-runner-profile` / `32a9562` (from merged `f92ac34`; evidence bundle follows) | Experimental launcher integration; controlled GNU Linux arm64 observation | Mac/Linux 350/351 workspace tests and Clippy; 68 portable/73 GNU Python tests, 14 GNU runner CLI tests, 209 policy and 16 importer tests; all nine product and 33 earlier traces pass; 30 CLI controls match and 185 hostile trace edits reject |
| A7 bundled Python source applications | `codex/a7-python-source-apps` / `d3ddac3` (from merged `90c4a10`; evidence bundle follows) | Experimental bounded source applications; controlled GNU Linux arm64 observation | Mac/Linux 366/367 workspace tests and Clippy; 87 GNU Python/probe and 14 runner tests; 238 policy, 16 importer and 7 byte-entry tests; all six new and 42 regression traces pass/replay; 34 new and 30 existing CLI controls match; 198 hostile source-app edits reject |
| A7 explicit-host Python source applications | `codex/a7-host-source-apps` / `dd6274f` (from merged `cb3cae4`) | Experimental bounded host source applications; controlled GNU Linux arm64 observation | Full pinned snapshot and startup guards; Mac/Linux 381/382 tests and Clippy; 102 GNU Python/probe and 14 runner tests; 261 policy and 11 host protocol tests (2 Mac skips); all 13 new and 48 regression traces pass/replay; 51 new/34 bundled/30 original controls match; all 567 hostile edits reject |
| A7 install-only host Python source applications | `codex/a7-install-only-host-source-apps` / `7a8e32c` (from merged `442d9eb`) | Experimental stock install-only host applications; controlled GNU Linux arm64 observation | Exact 1,037-source/three-cache prerequisites; complete provider audit; Mac/Linux 395/396 tests and Clippy; 116 GNU Python/probe and 14 runner tests; 288 policies; all 16 new/61 regression traces pass/replay; 60/51/34/30 product controls match; all 894 hostile edits reject |
| A9 worker-message foundation | `codex/a9-worker-protocol` / `42197bb` (from merged `aae69ef`) | Experimental codec and controller ledger; synthetic workers | Mac/Linux source workspaces pass 432/433 tests for Lua 5.4/5.5 and Clippy; 37 optimized IPC/ledger/real-pipe tests per platform; complete Linux trace confirms 18 anonymous pipes, six synthetic child launches and exact crash/truncation controls; [evidence](evidence/worker-protocol-2026-10-12/README.md) |
| A7 Python distribution metadata | `codex/a7-python-distribution-metadata` / `80c4b33` (from merged `6cd8f96`) | Experimental bounded `.dist-info` applications through all three providers | Mac/Linux 441/442 workspace tests and Clippy; 125 optimized GNU Python/probe and 14 runner tests; 32 adapter and 227 Python policy tests; all nine new/35 source-profile regression traces pass/replay; 42 new CLI controls agree; all 189 hostile edits reject |
| A7/A10 Python installed-package ingestion | `codex/a7-python-venv-ingestion` / `35dae52` (from merged `6afed9a`) | Experimental source-only build adapter with explicit provider template | Mac/Linux source workspaces 452/453 tests and Clippy; Mac packaging workspace 465; 33 pack/129 GNU Python/16 runner tests; 235 Python policies; real offline pip installation; Mac/GNU both input modes and all 30 hostile build controls pass; all six new/nine metadata regression traces pass/replay; 27 product controls and 126 hostile trace mutations pass/reject |
| A7/A10 Python runtime templates | `codex/a7-python-runtime-templates` / `3d15bf9`, checker strengthening `525da19` (from merged `c0ddaa4`) | Experimental portable preparation of the three pinned metadata providers | Mac/GNU source workspaces 460/461 tests and Clippy; Mac packaging workspace 482; optimized GNU 135 Python/41 pack/19 CLI tests; both builders pass eight template generations, 45 hostile controls and three installed-package builds; all six runtime traces replay under unchanged policy and retain prior archive hashes; 27 product controls and 126 hostile mutations pass/reject; strengthened oracle passes 21 tests on Mac/stock GNU |
| A7/A10 Python host prerequisites | `codex/a7-python-host-prerequisites` / `42c5abe`, strict evidence checks `3f3f31a` (from merged `c4a901e`) | Experimental product preparation of both admitted host prerequisite trees | Mac/GNU source workspaces 476/477 tests and Clippy; Mac packaging workspace 506; optimized GNU 142 Python/49 pack/21 CLI tests; both builders pass four generations and 63 hostile controls; two complete preparation/six runtime traces pass/replay; 46 oracle/241 policy tests; 27 product checks and 149 hostile trace mutations pass/reject; [evidence](evidence/pbs-linux-arm64-python-host-prerequisites-2026-10-13/README.md) |
| A7/A10 Real Python package compatibility | `codex/a7-python-real-packages` / `e525db8` (from merged `fce3dad`) | Experimental Requires-Python admission and three unmodified upstream pure-Python wheels | Mac/GNU source workspaces 484/485 and Clippy; Mac packaging workspace 518; optimized GNU 150 Python/53 pack/21 CLI; clean matrix passes three providers and three first-entry CRC rejections; both builders pass 32 requirement controls/two compatible builds; 21 oracle/253 policy tests and 229 hostile mutations; 27 product commands/5,273 valid members; [evidence](evidence/pbs-linux-arm64-python-real-packages-2026-10-14/README.md) |
| A7/A10 Pinned installed Python runtime trees | `codex/a7-python-installed-runtime-trees` / `b8fdbd1`, identity fix `801cbf6`, fixture staging `6b4499c` (merged `a52424c`) | Experimental selected-tree admission; controlled GNU Linux arm64 observation | Mac/GNU source 489/490 and Clippy; Mac packaging 533; GNU 154 Python/63 packaging/22 CLI; five valid preparations per builder, Mac20/GNU19 hostile controls; 24 tree/15 process-oracle/253 policy tests; all six raw/compressed runtime traces pass and archives retain previous hashes; 69 actual preparation mutations reject; [evidence](evidence/pbs-linux-arm64-python-runtime-trees-2026-10-14/README.md) |
| A7/A10 Pinned stripped host Python | `codex/a7-python-stripped-host` / `aef2f71` (stacked on runtime-tree evidence `421b24f`) | Experimental separate host-install metadata image; controlled GNU Linux arm64 observation | Mac packaging workspace 541 and source workspaces 496/497, Clippy clean; GNU optimized Python160/pack63/CLI23 and Clippy; four valid/twenty hostile preparations per builder; 20 preparation/23 process/5 runtime/11 trace units; seven native runtime traces pass; all 350 runtime/69 tree/21 artifact trace mutations reject; independent paired tar/ELF inspection and identical 1,037 sources/three caches; 38,093,257-byte prerequisites; [evidence](evidence/pbs-linux-arm64-python-stripped-host-2026-10-14/README.md) |
| A7 Registered Python native lifecycle | `codex/a7-python-native-lifecycle` / `9b1c386` (from merged `3f6bf8f`) | Experimental separate custom-create/owned-state profile; controlled GNU Linux arm64 observation | GNU source 501/502, Mac source Lua5.5 502/Mac packaging Lua5.4 546 and Clippy; GNU optimized Python165 and Clippy; independent stock baseline/seven ledger controls; all eleven new and eleven historical native traces pass; 22 Mac/stock-Python units and 264 historical units; all 33 hostile trace edits reject; five states freed/five references released after finalization on success and app error; [evidence](evidence/pbs-linux-arm64-python-native-lifecycle-2026-10-14/README.md) |
| A7 Python native package members | `codex/a7-python-native-package-imports` / `dd8cdd3` (from merged `478ebcd`) | Experimental stock dynamic-loader route for three dotted native children of an archive source package | Mac packaging Lua5.4 550/source Lua5.5 506 and GNU source 505/506, Clippy clean; GNU optimized Python170; independent stock descriptor-loader proof; eleven new and 22 historical native cases pass/replay; 300 policy units and all 20 hostile edits reject; exact unchanged native images and API4 boundary; five states freed/five references released after finalization; [evidence](evidence/pbs-linux-arm64-python-native-packages-2026-10-15/README.md) |
| Review hygiene and evidence retention | `claude/hygiene-and-evidence-policy` (from merged `a4e6ec1`) | Implemented | CONTRIBUTING toolchain guidance verified to select Rust 1.88.0 on the development Mac; 31 merged local branches pruned; [decision 0030](decisions/0030-evidence-retention.md) moves new evidence payloads to verified release assets; dry run packs the 2026-10-15 native-package bundle and verifies its inventory |
| A7/A1 macOS host Python product harness | `claude/relaxed-torvalds-a9df39` (from `108b4d0` on `claude/distracted-wozniak-c2a76a`) | Checked-in product harness and exact checker for the macOS arm64 cell; controlled observation on one cell | `run-product-macos.sh` runs the default-feature checks, the feature-enabled build, tests and lints, the no-boundary build, the six control installations, the seven macOS archives and a portably staged GNU Linux declaration, then records doctor, inspect, verify and run receipts from the poisoned environment; `check-product-results.py` matches every status and stream exactly; doctor Ready and run PASS, six installation rejections and the loader override at status 1, the GNU Linux declaration and the no-boundary build at status 2; workspace 514, runtime 177 and runner 23 tests and Clippy clean; installation snapshot unchanged; [decision 0034](decisions/0034-macos-python-product-harness.md); [evidence](evidence/macos-arm64-python-product-harness-2026-10-15/README.md) |
| A7/A1 macOS host Python product route | `claude/distracted-wozniak-c2a76a` (from merged `28b0cab`) | Product `glue doctor`/`glue run` route for the explicit macOS arm64 host startup profile; controlled observation on one cell | Portable admission of `stock-pbs-host-startup-macos`; macOS readiness from the declared Darwin arm64 target, observed `kern.osproductversion` and 16 KiB page size; archive-backed payload read with re-applied bounds; doctor Ready and run PASS on the cell; six installation rejections, loader override, GNU Linux declarations and the no-boundary Mac build report their expected statuses; GNU Linux readiness unchanged; [decision 0032](decisions/0032-macos-python-product-route.md) |
| A7/A1 Explicit macOS host Python startup | `claude/macos-python-host` (from merged `0c9b522`) | Experimental macOS arm64 host provider for the pinned startup subset; controlled observation without a tracer | Pinned PBS 20261009 macOS install-only artifact and 264 verified headers; C boundary compiled with Apple clang; dyld path loading with LC_UUID binding; one success, one app error, six installation rejections, one loader-override rejection and one unsupported-mode status match exactly; 173 feature tests and Clippy clean; read-only installation snapshot unchanged; bundled macOS requirements measured in [decision 0031](decisions/0031-macos-python-host-startup.md) |
| A5 native capability survey and proposed contract | `claude/competent-keller-668fef` (from merged `0c9b522`) | Static survey; proposed contract; no loader change | 24 shared objects from four pinned cp313 manylinux aarch64 wheels (markupsafe 3.0.4, numpy 2.5.4, pydantic-core 2.50.1, cryptography 50.0.2) read statically and cross-checked against llvm-readelf with zero disagreements; all 444 distinct Python API imports exported by the pinned runtime; the current inspector rejects all 24 images before any import policy; Mac workspace 505 tests and Clippy clean on Rust 1.88.0; [decision 0033](decisions/0033-native-capability-contract.md) |

## Legacy gate status before the plan revision

G0, G1 and G2 are open. Linked official Lua 5.4.9 and 5.5.1 have explicit,
version-specific source-only profiles and optional GNU Linux arm64 native
profiles. This is partial A5/A6/G2 work; four-OS acceptance remains open.
The original Linux memfd spike remains a separate historical observation.
The product now integrates a controlled native Lua closure. General native
backends, general runtime/package compatibility, Node adapters, workers,
approved system-library profiles and signed deployment remain pending.
The archive and manifest are version 0. Lua is pinned to `lua-src` 551.0.2
with int64/float64 configuration. Stock conventional-GIL CPython 3.13.16 / PBS
`20261009` full, unstripped install-only and separately identified stripped
install-only inputs are pinned for the GNU Linux
arm64 inspection and separate frozen/installed-host startup experiments; other runtime pins and Python execution profiles still
depend on platform experiments. The logical Lua build ID is not a compiler
configuration or artifact hash. See [the base profile decision](decisions/0005-linked-lua-source-profile.md)
and [version selection](decisions/0006-versioned-linked-lua-profiles.md).

The profile branch added mutually exclusive compiled `lua54` (default) and
`lua55` profiles with exact manifest identities. Supporting both versions through
separate launchers does not provide simultaneous multi-runtime acquisition or
worker execution.

The new C boundary replaces `mlua` in the source adapter. C owns the Lua state,
allocator, protected execution and result construction. Rust only serves archive
requests and catches callback panics; it never receives a Lua state. Replies are
released before C propagates an error, including allocation failures. Logical build
IDs now select source-v2/c-boundary-1, so v1 archives require rebuilding.
See [the boundary decision](decisions/0007-lua-c-error-boundary.md).

## Local test environments

The initial host is macOS arm64. Rust 1.88.0 is installed through Rustup; its
toolchain directory was placed first in PATH to avoid the Homebrew Rust 1.99
executables. `scripts/test-linux.sh` vendors the locked dependencies and runs
tests offline in a read-only Podman container with build outputs in memory.
Its default Linux arm64 image is Rust 1.88.0 / Debian bookworm, pinned by digest
`sha256:93717e495a1029ba94b9b4a5768cf14d5376077d26cfad3354cbe70be27c2b1d`.
This cell does not supply Linux x86_64 execution evidence.

The native fixture ran from clean commit `447a339` on Linux
`7.1.4-200.fc44.aarch64`, glibc `2.36-9+deb12u10`, GCC 12.2.0, 4 KiB pages and
`vm.memfd_noexec=0`. It returned 42/7/1 for function/data/constructor observations
with ordinary loading and archive memfds, and passed the full trace checker.
The [evidence record](evidence/linux-arm64-memfd-2026-10-08/README.md) retains the
commands, image identity, source and artifact hashes, test logs and raw trace.
The [probe decision](decisions/0004-linux-memfd-probe.md) lists its limits.

The synthetic resource fixture produces 1,469 archive bytes for 57 uncompressed
resource bytes, with SHA-256
`e2fa199105c8cffde55ec2dd403f27d3e1dc334c399aa334afba133c64be7d85`.
It is a packaging/resource fixture and contains no actual Lua runtime.
Its selected `host` provider still returns status 2; the linked runtime is never
used as a fallback. Separate [linked fixtures](../fixtures/lua-linked/README.md)
declare the exact source/build/ABI and macOS arm64 or GNU Linux arm64 target.
At the Lua 5.4 baseline, the macOS arm64 fixture was built through the CLI, reported ready through
`doctor`, and printed its expected nested-import/asset result. The complete
workspace passed 111 Rust tests and Clippy with warnings denied on this host.
The final validation branch passed 118 Rust tests with `lua54` and 119 with
`lua55` on macOS and GNU Linux arm64, and all-target Clippy with warnings denied
for both. Lua 5.5 built
through the CLI, reported ready for 5.5.1, and printed the expected `Lua 5.5`
result. Its fixture archive SHA-256 is
`4c0d21b1e8b2bec3bd146280958f0ddf958c03f7177451eb2049b9e3570a0094`.
Opposite-version archives return 1 without executing source; 27 Python
trace-policy tests pass.

The final Linux captures used clean commit `8b6eb1f` on
`codex/a6-lua-linux-validation`, stacked on source profiles `cb88d7d`. Both
relocated Lua fixtures exited 0 with exactly the expected stdout and empty
stderr, and passed full `strace` checks. The observed arm64 cell used Linux
`7.1.4-200.fc44.aarch64`, glibc `2.36-9+deb12u10`, Rust 1.88.0, GCC 12.2.0,
strace 6.1 and 4 KiB pages. Direct Podman commands were used because the
sandboxed wrapper could not access its socket. The
[retained evidence](evidence/linux-arm64-lua-2026-10-08/README.md) contains
commands, source/fixture/artifact identities, all build-provenance instances,
feature trees, test/Clippy logs and raw traces. These debug source-only
observations remain separate from the native probe and do not establish the
declared minimum kernel/glibc versions or other platforms/architectures.

The C-owned source adapter was captured from clean implementation `ee7c9d3` on
2026-10-09 using the same pinned Linux image and observed arm64 environment.
Both workspace profiles pass 142/143 Rust tests and all-target Clippy on macOS
and GNU Linux; the optimized macOS boundary suites pass 50/51 tests. Both new
relocated, read-only Linux fixtures produce exactly 55 stdout bytes, empty stderr,
exit 0 and pass the full trace checker. The
[boundary evidence](evidence/linux-arm64-lua-c-boundary-2026-10-09/README.md)
retains the fresh source/artifact identities, all provenance records, raw traces
and Mac/Linux test logs. The strict C-only error boundary is implemented for
this source profile; general native and platform/release acceptance remain pending.

The native Lua closure was captured from clean `fb61e5e` on 2026-10-09 using
the same immutable image and observed GNU Linux arm64 environment. Both source
workspace profiles pass 181/182 tests on Mac and Linux; native-feature profiles
pass 178/179 on GNU Linux and 177/178 on Mac, where the loader is unsupported.
All four profiles pass all-target Clippy with warnings denied on both systems.
Optimized Mac native C-boundary suites pass 53/54 tests. Both relocated native
fixtures match ordinary loading of the same compiled Lua core, exit 0 with
exact output and empty stderr, and pass full traces proving two completely
sealed memfds before loading and no payload filesystem mutation. All six
adversarial ELF cases per version reject with exact diagnostics and statuses
before any memfd attempt. The
[native evidence](evidence/linux-arm64-native-lua-2026-10-09/README.md)
retains all fourteen traces, source/artifact hashes, build provenance and
Mac/Linux validation logs. This completes the controlled Linux native Lua
slice, with the platform, release and general compatibility gates still open.

The signed macOS arm64 probe was captured from clean `346b2f0` on 2026-10-09.
Debug and optimized launchers use only the allow-jit entitlement under hardened
runtime and match ordinary dyld loading after PID normalization. All seven
native rejections per launcher and signing/memory-policy controls pass with
exact results. Source workspaces pass 212/213 tests and Clippy on Mac/Linux;
the parser has 31 tests, also passing in optimized Mac builds. The
[macOS evidence](evidence/macos-arm64-macho-2026-10-09/README.md)
retains source/artifact identities, signatures, inspections and tool denials.
This is a native-only fixture with an unacquired Lua scaffold. Full independent
filesystem/VM tracing is unavailable under current rights and no Developer ID
identity is available; A1 release acceptance and G0/G1 remain open.

The PBS inspector was captured from clean `886a415` on 2026-10-09. It pins stock
conventional-GIL CPython 3.13.16 / PBS `20261009` for GNU Linux arm64 and verifies
full and unstripped install-only inputs without extraction. All 6,574 full and
4,526 retained install-only member identities agree with independent inventories;
Mac/Linux optimized reports are byte-identical. Both source workspaces pass
268/269 tests and Clippy; both optimized inspector suites pass 56 tests and
all 71 Python policy tests pass. The complete Linux inspector trace passes
read-only input, no-payload-mapping/no-mutation and sole-process checks.
[The evidence](evidence/pbs-linux-arm64-inspection-2026-10-09/README.md) retains
pins, upstream records, complete compressed reports/trace, source/artifact
identities, candidate metadata, independent file research and validation logs.
The actual libpython registers `math`/`_ssl` in its file table, but its size and
ABS64/TLSDESC relocations exceed the current Lua loader profile. This is A7/A10
build-time input work; that inspection did not acquire or execute Python and
G0/G1 remain open. See [the decision](decisions/0010-pinned-pbs-inspection.md).

The separate stock PBS bootstrap uses the exact unchanged shared library and
public `PyImport_FrozenModules` before isolated public-API initialization. Six
pinned startup sources are compiled by the matching stock producer at build time;
the C bridge owns configuration, Python references, error buffers and finalization.
Actual GNU Linux arm64 execution imports frozen `encodings` and built-in `math`
and `_ssl`, returns 42, and agrees with ordinary loading of the same library and
bundle. This is a startup subset, rather than a complete Python stdlib/importer
or a host provider. The generic Lua loader limits remain unchanged; the probe
admits one exact larger stock runtime image through the system loader and sealed
memfd. The clean optimized capture from `30a1526` on 2026-10-10 passes success,
missing-encodings, corrupt-bytecode and app-error traces after removing the stock
producer/stdlib/headers. The unprivileged runtime container has read-only inputs,
no workspace mount and unavailable temporary paths. All four complete traces
prove archive byte coverage, one fully sealed private image, exact diagnostics
and exits, and no payload filesystem mutation or extra process. The
[bootstrap evidence](evidence/pbs-linux-arm64-bootstrap-2026-10-10/README.md)
retains the compiled bundle, commands, source/artifact/provenance identities,
complete compressed traces, controls and validation logs. See
[the bootstrap decision](decisions/0011-stock-pbs-frozen-bootstrap.md).

The explicit host startup fixture selects that exact stock library with its own
installed stdlib, and the archive contains only the shared app. Rust verifies
the library and all six startup sources before loading and rejects symlinks,
missing/altered inputs and existing startup bytecode caches. C uses the installed
prefixes and one stdlib search path without inserting a custom frozen table.
The library/stdlib mount is immutable and read-only; the verified source subset
does not certify arbitrary mutable installations or the complete stdlib. The
shared app proves version/ABI mode, isolation, UTF-8 and installed encodings with
built-in math/_ssl. Product host discovery, application imports and native
extension integration remain open. See
[the host startup decision](decisions/0012-explicit-host-python-startup.md).

The clean optimized host capture from `a50ae86` passes all eight complete traces,
including six prerequisite rejections before Python loading and a controlled
application error. The 2,741-byte successful archive contains only the app.
The same clean source also passes four fresh frozen-bootstrap regression traces.
The [host evidence](evidence/pbs-linux-arm64-host-python-2026-10-10/README.md)
retains both captures, installed input/archive identities, commands, C provenance,
test logs and independently replayed compressed traces.

The archive source/resource fixture extends bundled frozen startup with a
Rust-owned immutable source index and a small C request boundary. The unchanged
stock runtime imports modules, packages and one-portion namespaces from source,
with virtual origins and normal import-cache/reload/failure behavior. Actual
`importlib.resources` supplies read-only streams; archive Traversables reject
`as_file` and legacy `path` before temporary-file attempts. All 2,174 pinned
stdlib `.py` members are retained as a source-only projection, without claiming
complete stdlib/package compatibility. This remains a controlled bundled adapter;
host-provider archive imports and product integration still need evidence. See
[the source/resource decision](decisions/0013-python-archive-source-resources.md).

The clean optimized capture from `94da8de` matches ordinary loading and passes
all three complete import traces after removing producer/stdlib/library/headers.
Its 83,092,207-byte archive declares 2,194 resources. Syntax errors retain virtual
origins without compiler diagnostic source lookups in the observed UTF-8 cell;
an `atexit` callback reads resources during finalization. Corrupt stored source
rejects before memfd creation. The same implementation also passes four fresh
frozen and eight installed-host startup regression traces. The
[import evidence](evidence/pbs-linux-arm64-python-imports-2026-10-10/README.md)
retains all fifteen independently replayed compressed traces, exact manifests,
input/source/artifact identities, C provenance and validation logs. Host-provider
archive imports, general diagnostic source consumers and product integration
remain pending.

The next A7 implementation, on `codex/a7-host-python-archive-imports` from merged
`f99bb51`, shares the source/resource adapter with an explicit installed host
runtime. Its exact 18-resource archive holds only application/helper/assets;
the host owns the stdlib. Six startup plus 63 supplemental sources are pinned,
and all relevant bytecode caches must be absent before loading. Reserved names
cover stock built-ins, frozen aliases, bridge modules and stdlib roots. Host
module/namespace lures exercise fallback blocking. The unchanged C API revision 3
and shared invocation retain all owners through finalization. See
[the host archive-import decision](decisions/0014-host-python-archive-imports.md).

The clean optimized host-import capture from `9aababa` passes all seven complete
traces and agrees with ordinary loading. Its 13,932-byte archive contains only
18 app/helper/resource entries. All 69 installed sources are verified before
loading; Python subsequently reopens 67 for this workload. Corrupt archive
source rejects before host lookup; altered/missing supplemental sources and a
nested cache reject before Python mapping. The same clean implementation passes
three bundled-import, four frozen-startup and eight installed-host startup
regressions. All 22 retained compressed traces independently replay, and 29
hostile actual-trace mutations reject. Mac/Linux source assemblies pass 327/328
tests and Clippy for Lua 5.4/5.5; every fresh GNU opt-in build passes 56 tests and
Clippy. All 161 Python policy tests and both 16-test importer protocol cells pass.
The [host-import evidence](evidence/pbs-linux-arm64-host-imports-2026-10-10/README.md)
retains exact source/artifact/input identities, manifests, C provenance,
commands, validation logs and complete traces. At that checkpoint, product
Python integration, native extension initialization and general diagnostic
consumers remained open.

The registered native A7 slice, implemented as `b784c99` on
`codex/a7-python-extension-init-bridge` from merged `a50b654`, registers reviewed `PyInit_*` addresses through public
`PyImport_AppendInittab` before initialization. Stock `BuiltinImporter` owns
single-phase (`m_size=-1`) and multi-phase protocols, cache/reload/removal and
failure cleanup. Runtime and native providers vary independently over four
bundled/explicit-host and archived/explicit-host cells. The runtime stays
`RTLD_LOCAL`; every function/data relocation and initializer address is checked
against its admitted image owner before Python starts. C boundary API4 has 29
public exports/240 bytes and pins copied registration names through process exit.
The source/resource conformance app and its finalization callback are reused.
See [the registered initializer decision](decisions/0015-python-registered-extensions.md).
The [clean native evidence](evidence/pbs-linux-arm64-python-extensions-2026-10-10/README.md)
retains all eleven native cases and twenty-two earlier Python regressions from
the same implementation commit, plus exact native files, manifests, source/input
identities, commands and validation logs. All 37 independent hostile trace edits
reject. This profile does not implement generic extension-file discovery or
close the platform/product gates.

The controlled Python route moves the existing provider/import/registration
mechanisms into `glue-runtime-python`, with the historical preparer/probe as a
thin experimental wrapper. `glue run` dispatches by the selected component ABI
and transfers the same opened archive into the opaque, synchronous executor.
Python remains optional through `python-pbs`; the build verifies the matching
stock headers only on the exact supported GNU Linux arm64 target. `doctor`
checks admitted declarations and build/target readiness; execution checks the
selected archive bounds, content and explicit host prerequisites. Default Lua
execution retains its original 64 MiB member bound while inspection can admit
the pinned 73,563,968-byte Python runtime. See
[the integration decision](decisions/0016-controlled-python-runner.md).
The [clean runner evidence](evidence/pbs-linux-arm64-python-runner-2026-10-11/README.md)
retains all nine actual product traces and 33 earlier regression traces from
`32a9562`. Every compressed trace replays, all 30 CLI controls match exact
archive contents/statuses, and an independent audit rejects all 185 hostile
actual-trace edits. Mac/Linux source profiles pass 350/351 tests and Clippy;
Mac Python-enabled workspace checks also pass, while GNU execution remains
opt-in and limited to the controlled registry. General application/host-stdlib
admission, runtime version selection and other platforms remained later steps
at that checkpoint.

The next bundled source profile accepts application-owned source and assets,
with a declared script entry below `app/` and imports below `app/python/`.
Runtime, all 2,174 stdlib sources, importer and frozen-startup identities stay
pinned. Portable admission checks bounded inventories, runtime-name collisions,
module layout and source-only payload paths before acquisition. A trusted entry
launcher compiles verified bytes through the existing importer and runs them
as `__main__` with virtual metadata. The C bridge and loader remain unchanged.
`glue build` selects the larger pinned-runtime policy from its same parsed
manifest before looking up input resources. See
[the source application decision](decisions/0017-bundled-python-source-apps.md).

The [clean source-app evidence](evidence/pbs-linux-arm64-python-source-apps-2026-10-12/README.md)
retains six actual application invocations and 42 fresh prior-route regressions
from `d3ddac3`. All 48 compressed traces replay. Independent controls agree with
the actual build/inventory/entry bytes and expected statuses; all 198 hostile
actual-source-app trace edits reject. Source workspaces pass 366/367 tests and
Clippy on Mac/Linux, the Mac Python-enabled workspace passes 366, and optimized
GNU Python/probe builds pass 87. Policy/importer/entry suites pass 238/16/7 on
both Mac and the pinned stock Linux interpreter. The C bridge, API4 table and
Linux loader mechanisms remain byte-identical to the merged parent. This expands
bundled application source admission while preserving the exact runtime/stdlib
pins; general host-stdlib admission, version selection and other platforms remain
open.

The paired explicit-host source profile uses the same admitted applications
with a full verified host source snapshot. All 2,174 sources (39,158,056 bytes)
and the selected library verify before loading; derived caches and startup
shadows reject. Snapshot sources close promptly into owned bytes, while startup
and directory owners remain live through finalization. A trusted prelude removes
ordinary filesystem import fallback before the unchanged importer runs. Host
startup still requires immutable read-only installed paths, and the mapped
library requires immutable backing for process life. See
[decision 0018](decisions/0018-host-python-source-apps.md).

The [clean host source-app evidence](evidence/pbs-linux-arm64-python-host-source-apps-2026-10-12/README.md)
retains 13 new and 48 fresh regression traces from `dd6274f`, all replayed.
All 51 new, 34 bundled-app and 30 original product controls match; all 567
hostile actual-trace edits reject. Mac/Linux source workspaces pass 381/382
tests and Clippy, the Mac Python-enabled workspace passes 381, and optimized
GNU Python/probe builds pass 102. Policy/importer/entry protocols pass 261/16/7
on both interpreters; host source protocol tests pass all 11 on stock Linux
and run 11 with two stock-only skips on Mac. The C bridge, API4 table and
selected GNU library mapping implementation remain unchanged. This supports the
exact full projection; broader installation/package compatibility and version
selection remain open.

The separate install-only host identity uses all 1,037 source files and the
three exact encoding caches shipped by the independently pinned distribution.
Closed cache admission and byte/hash verification precede runtime loading;
all other derived caches and startup shadows reject. Source bytes are owned
before initialization, while cache/startup/directory owners remain live through
finalization. A separate total-descriptor cap prevents the smaller inventory
from implicitly widening prefix depth. The full-source host identity retains
its own inventory and cache rejection; no provider subset is selected silently.
See [decision 0019](decisions/0019-install-only-host-python-source-apps.md).

The [clean install-only host evidence](evidence/pbs-linux-arm64-python-install-host-source-apps-2026-10-12/README.md)
retains 16 new and 61 fresh regression traces from `7a8e32c`, all replayed.
Stock normalized mtimes make the three observed caches stale; traces read each
cache completely, close it and read its matching source. Runtime admission
checks bytes/path identity without imposing those exact mtimes on every host.
An independent post-runtime audit verifies all ten complete stock/control trees
on a case-sensitive Linux volume before cleanup. Mac/Linux workspaces pass
395/396 tests and Clippy; optimized GNU builds pass 116 Python/probe and 14 CLI
tests. Policy/importer/entry protocols pass 288/16/7; host protocol runs 11 with
two Mac skips and passes all 11 on stock Linux. All 60 new and 51/34/30 prior
product controls agree; all 894 hostile actual-trace edits reject. The C bridge
and selected GNU library mapping implementation remain unchanged. Broader host
installations, runtime versions and package/platform compatibility remain open.

The A9 foundation captured from clean `42197bb` freezes bounded version-0
messages, integer tags and controller ordering. Independent byte vectors and
real anonymous-pipe tests cover values, errors, cancellation/draining and
crash-versus-framing EOF. Mac/Linux source workspaces pass 432/433 tests and
Clippy for both Lua profiles; both optimized IPC suites pass all 37 tests.
The [retained evidence](evidence/worker-protocol-2026-10-12/README.md) includes
the full Linux pipe-test trace, source/artifact identities and validation logs.
No product/runtime worker or cross-language invocation is implemented; G4
remains open. See [decision 0020](decisions/0020-worker-message-protocol.md).

The [clean metadata evidence](evidence/pbs-linux-arm64-python-metadata-2026-10-13/README.md)
retains nine new and 35 fresh source-profile regression traces from `80c4b33`,
all replayed. Three metadata-aware build identities expose bounded `.dist-info`
through stock public metadata APIs, including plugin loading and virtual RECORD
files. Malformed RECORD paths and CRC damage reject before provider acquisition;
actual physical host metadata lures remain invisible. All 42 new product controls
agree, 6,615 valid archive members verify independently, and all 189 hostile
trace edits reject. Mac/Linux workspaces pass 441/442 tests and Clippy; optimized
GNU builds pass 125 Python/probe and 14 runner tests. Metadata/importer/entry
protocols pass 32/16/7; the Python policy suite passes 227 on both interpreters.
The legacy importer, C boundary and selected GNU library mapping files remain
unchanged. Generic wheel/venv ingestion and wider package/provider/platform
compatibility remain open. See [decision 0021](decisions/0021-python-distribution-metadata.md).

The [clean installed-package evidence](evidence/pbs-linux-arm64-python-venv-2026-10-13/README.md)
retains six new and nine fresh metadata-profile regression traces from `35dae52`,
all replayed. `glue build-python` normalizes a complete source-only package tree
or conventional Python 3.13 venv against an explicit admitted provider template.
It verifies original RECORD ownership/integrity, preserves retained bytes and
reports omitted caches/generated wrappers and deterministic RECORD rewriting.
A genuine offline pip installation exercises all three providers. Mac/GNU
controls pass both input modes and all 30 hostile cases; the Mac venv interpreter
target is absent, and three GNU build process traces show no child/interpreter
execution. Independent checks verify 4,427 valid members, three CRC controls,
27 product commands and all transformation reports; all 126 hostile trace
mutations reject. Workspaces pass 452/453 tests and Clippy, the Mac packaging
workspace passes 465, optimized GNU suites pass 129 Python/33 pack/16 runner,
and Python policies pass 235 on both interpreters. Runtime/helper/loader bodies
are unchanged. General runtime-template provisioning, package compatibility,
dependency solving and native/platform support remain open. See
[decision 0022](decisions/0022-python-installed-package-ingestion.md).

The [clean runtime-template evidence](evidence/pbs-linux-arm64-python-runtime-templates-2026-10-13/README.md)
retains portable Mac preparation and six GNU runtime traces from `3d15bf9`.
`glue python-template` now supplies `build-python` directly with the pinned
bundled library/source/frozen inputs or explicit unverified full/install-only
host declarations. Eight successful generations, 45 hostile controls and three
genuine installed-package builds pass on both builders. Every resulting archive
retains its previous byte identity, and runtime/helper/loader bodies and the
six-mode trace policy are unchanged. The strengthened preparation-process oracle
from `525da19` passes all 21 tests and actual/compressed trace replays. Product
runtime installation, uv discovery, version selection and broader package/native
compatibility remain open; preparation does not close runtime/platform gates.

The [clean host-prerequisite evidence](evidence/pbs-linux-arm64-python-host-prerequisites-2026-10-13/README.md)
adds `glue python-host` for both pinned PBS host projections on Unix builders.
Complete artifact inspection and selected payload identities precede exclusive
publication; all files/directories receive fixed permissions and mtimes, and
provenance records complete/selected/omitted inventory facts. Mac/GNU each pass
four preparations and 63 hostile controls, while a closed 46-test process oracle
checks two complete native preparation traces. Six runtime traces and all 149
hostile mutations pass/reject; all archive hashes retain their previous identity.
An isolated strict adapter derives the install-only root's 191 entries from the
exact source/cache pins, replacing the prior complete stock tree's 193 for this
workload only. Historical policies, product runtime/loader/helper bodies and
template bodies remain unchanged. The 241-test policy suite and independent
27-command/4,427-member product audit pass. Complete installation/discovery,
version selection and broader package/native/platform compatibility remain open.
See [decision 0024](decisions/0024-python-host-prerequisites.md).

The [clean real-package evidence](evidence/pbs-linux-arm64-python-real-packages-2026-10-14/README.md)
uses unmodified markdown-it-py 4.2.0, mdit-py-plugins 0.6.1 and mdurl 0.1.2 wheels.
Stock offline pip installs 261 files; the independently verified projection
retains 152 application resources, omits 110 caches/one generated wrapper and
rewrites only RECORD. Ordinary stock Python and all three archive providers agree
on rendering/tokens, real metadata, resources/licenses and a loaded console
callable. Mac/GNU each pass 32 requirement rejection commands and two compatible
builds, with provider files/input interpreters absent and existing outputs
protected. Shared Requires-Python admission rejects incompatible/unsupported
release constraints before provider reads/publication; explicit application
metadata receives the same early check. Six complete runtime traces replay;
all 229 hostile mutations reject. Historical policies/C/helper/loader bodies
remain unchanged; narrowly scoped new predicates cover five failed terminal
queries and one install-only anonymous growth/release. See
[decision 0025](decisions/0025-python-real-package-compatibility.md).

## Next critical-path assignments

Use [the MVP queue](plans/mvp-tasks.md), whose dependencies and acceptance checks
replace the former platform-first and Python-before-Node assignments:

1. C01: translate compact/runtime contracts into versioned shared types.
2. V01: automate existing portable checks; V02 then establishes target receipts.
3. L01: expose both existing Lua families as selectable helpers.
4. P00: prove stock multi-version Python bootstrap with archived stdlib.
5. N00: prove stock Node archive hooks and an existing native addon now.

Then implement compact distribution writing, Linux/macOS native collection and
the three independent input adapters. The exact pinned Python/native profiles
remain regression evidence, not the admission model for new project inputs.
No native-capable MVP is complete without all three languages. Node can proceed
alongside Python; Windows, BSD and general mixed-language workers are deferred.

The macOS native memory loader remains substantial work: actual runtime TLS,
unwinding, image identity and signed deployment are not established by the small
spike or host-startup route. Follow the [separate roadmap](plans/memory-roadmap.md)
instead of blocking compact packaging on general dyld replacement. Decision 0033
remains useful static-corpus evidence, not a completed dynamic loader contract.

## MVP implementation — C01 (15 October 2026)

- Branch `codex/mvp-c01-contracts`, based on `6b49cc5`; result: branch tip.
- Added explicit schema one distribution/runtime/native/launch/report/lock and
  stable diagnostic APIs; schema zero fixtures retain their interpretation.
- `cargo test -p glue-format --locked`: 55 tests passed on macOS arm64,
  Rust 1.88.0. `cargo clippy -p glue-format --all-targets --locked -- -D warnings`
  passed. Examples round-trip all three language descriptors, reject ambiguous
  modes, path collisions, escapes, cycles and runtime mismatches.
- Decision 0036 describes the schema change. Runtime execution is subsequent work.

## MVP implementation — C02 (15 October 2026)

- Branch `codex/mvp-c02-distribution`, based on C01 `c599587`; result: branch tip.
- Added bounded shared staging/build API, deterministic archive/lock/report,
  launcher and notices, payload modes/internal links, exclusive atomic directory
  publication and output/staging traversal exclusion. Native bytes stay deployed.
- Product bounds: 100,000 archive entries, 1 GiB archived input, 8 GiB deployed
  payload and 100,000 deployed files (configurable); original archive decode,
  per-entry and central-directory bounds remain enforced.
- `cargo test -p glue-pack --locked`: 24 tests passed on macOS arm64/Rust 1.88.0,
  including deterministic distinct roots, overlap, collisions, missing/escaped
  input, output preservation, safe links, modes and complete size accounting.
- The exclusive rename boundary uses the platform's no-replace primitive.
  Linux native execution remains a target-cell check; no release gate is claimed.

## MVP implementation — C03 (15 October 2026)

- Branch `codex/mvp-c03-linux-native`, based on C02 `74308df`; result: branch tip.
- Added ELF64 dynamic inspection and deterministic explicit-root native closure
  collection. Preserves relative paths, records SONAME/dependency/version/feature
  facts, rejects missing edges, target mismatch, path escape and identity conflicts.
  TLS, unwind and GNU hash facts do not inherit memory-mapper restrictions.
- macOS arm64 parser/closure tests and pinned Clippy passed. A separate Linux-only
  test compiles independent fixture inputs, compares readelf and executes the
  relocated module plus secondary library through dlopen with TLS state.
- Absolute/cwd-dependent load paths produce transformation-required diagnostics;
  optional normalization tooling and x86_64 native execution remain pending.
  This card is implemented partially until those acceptance requirements pass.

## MVP implementation — C04 (15 October 2026)

- Branch `codex/mvp-c04-macos-native`, based on C03 `bdc186e`; result: branch tip.
- Added bounded thin/universal Mach-O inspection, actual loader-chain rpath
  resolution, native target/OS-floor checks, preserved relative closure paths,
  explicit metadata normalization with input/output hashes and verified ad-hoc
  re-signing. Host-prefix paths reject without explicit normalization.
- `cargo test -p glue-pack --test native_macos --locked`: 3 passed on macOS arm64,
  including ordinary independently compiled bundle + secondary dylib, copied to
  Unicode/space path, original input deleted, native dlopen execution and final
  codesign verification for unchanged and normalized paths. otool independently
  confirms the dependency. Missing edges, slice mismatch and OS floor reject.
- Pinned Clippy passed. C03's separate offline Linux arm64 run passed all 3 tests,
  including real relocation/TLS execution and readelf comparison. x86_64 native
  execution remains unexecuted. Public Developer ID/notarization is R02 evidence.

## MVP implementation — V01 (15 October 2026)

- Branch `codex/mvp-v01-portable-ci`, based on C04 `25eb646`; result: branch tip.
- Added native Linux x86_64/Linux arm64/macOS arm64 GitHub jobs for baseline,
  Lua55 and packaging suites. Rust/Clippy 1.88.0, expected native host and locked
  dependencies are checked explicitly. Lua features run separately.
- `scripts/ci-portable.sh baseline` passed locally on macOS arm64 (workspace
  tests, formatting and all-target Clippy); raw log is local at
  `/private/tmp/glue-mvp-v01-baseline.log`. `sh -n` passed.
- Hosted jobs are configured, not yet executed. No signing/evidence assets are
  required; portable checks do not substitute for target product receipts.

## MVP implementation — C05 (15 October 2026)

- Branch `codex/mvp-c05-builder-cli`, based on V01 `dc8e659` plus reviewed task
  handoffs L01 `f78cdd5`, L02 `8ee9e76`, L03 `9f00c96`; result: branch tip.
- Added high-level language dispatch slots and working Lua compact build/run,
  TOML defaults with CLI precedence, compact inspection/size/doctor, sibling
  integrity verification, literal placeholder expansion and direct Unix exec.
  Payload write bits may be removed for immutable deployment; required read/exec
  bits and hashes remain checked. No shell or missing-payload recovery exists.
- Pinned runner tests passed (21 legacy + 3 new CLI tests); new tests execute a
  relocated read-only distribution with deleted project, unrelated cwd, Unicode,
  spaces and placeholder-looking path; stdin/out/err, literal argv, exit 7,
  SIGINT/SIGTERM, config errors and missing sibling rejection pass. Clippy passed.
- Reproduce: build/install the glue-owned Lua helpers, then
  `glue build lua fixtures/mvp/lua-projects/first --lua 5.4 --output /tmp/lua-app`;
  `/tmp/lua-app/glue run /tmp/lua-app/app.glue -- argument`.
- Python and Node slots are intentionally integrated in R01 after their provider
  handoffs. This is source/native Lua functionality, not M2 closure.

## MVP native acceptance update (15 October 2026)

Native Linux x86_64 [run 38800548172](https://github.com/JBlaschke/glue_rs/actions/runs/38800548172)
tested [source e3962701](https://github.com/JBlaschke/glue_rs/commit/e3962701f558c287515508c97df4679e08d64ed2)
and passed all 24 acceptance cases: both Lua families, twelve Python
3.12.15/3.13.16/3.14.8 cases and eight Node 24.22.0/26.10.0 cases. The supplied
3.14 conda runtime includes a compatible prebuilt compiler-runtime closure;
packaging neither rebuilt native inputs nor relaxed conflicting-identity checks.
All five reviewed R03 budgets, measured with 10,000 added entries at 1 and 32
ranks, passed in enforcement mode. Independent replay verified all receipts,
fifteen benchmark-variant traces, negative controls and 990 rank results.

The run explicitly inherits
[`traceable-native-syscalls-v1`](decisions/mvp-v02-ci-trace-environment.md),
which returns ENOSYS for asynchronous kernel I/O in the complete stock/reference,
packaged, control and rank trees. Fixed structure/I/O/scaling limits apply across
hosts; time/RSS remain scoped to the recorded host fingerprint. No controlled
cold-cache result or unrestricted ring-enabled-host acceptance is claimed.

[Artifact 12005186009](https://github.com/JBlaschke/glue_rs/actions/runs/38800548172/artifacts/12005186009)
retains the raw evidence, ZIP SHA256
`c1cc519d76e73888ed0339714deec1e97eea816c1f8861ab551da4579644e7a4`.
Local replay is
`/private/tmp/glue-native-x86-evidence-38800548172/independent-replay.json`.
The artifact currently expires on 29 October; durable evidence publication
remains open. The complete Darwin decoder/oracle is still unimplemented and
unvalidated, so Mac R02 corpus/controls/budgets and M2 remain open. Developer ID
and notarization are later public-release gates. Current task refs, commands and
remaining work are recorded in the [implementation ledger](plans/mvp-implementation.md).
